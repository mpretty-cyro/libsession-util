#include <sqlite3.h>

#include "common.hpp"

// ── The suspend contract ────────────────────────────────────────────────────────────────────────

namespace {

constexpr auto PEER = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

// The files a Client keeps parked send outcomes in, beside the database.
std::vector<std::filesystem::path> journals(const std::filesystem::path& db) {
    std::vector<std::filesystem::path> found;
    auto prefix = db.filename().string() + "-send-status-";
    for (const auto& entry : std::filesystem::directory_iterator{db.parent_path()})
        if (entry.path().filename().string().starts_with(prefix))
            found.push_back(entry.path());
    return found;
}

// The bytes a swarm holds for a plain v1 DM to `to`.
std::vector<std::byte> dm_bytes(
        Client& to, const SenderKeys& from, std::string_view body, sys_ms ts) {
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
    content.mutable_datamessage()->set_body(std::string{body});
    auto plaintext = content.SerializeAsString();
    return encode_dm_v1(
            std::as_bytes(std::span{plaintext}), from.ed_sk, ts, own_sid(to), std::nullopt);
}

// A storage server's answer to a batch of retrieves: `messages` in the one asking for `ns`.
std::string retrieve_answer(
        std::span<const std::byte> request_body,
        int16_t ns,
        const std::vector<std::pair<std::string, std::vector<std::byte>>>& messages) {
    auto batch = parse_json(request_body);
    auto results = nlohmann::json::array();
    for (const auto& r : batch["requests"]) {
        nlohmann::json body;
        body["messages"] = nlohmann::json::array();
        if (r["params"]["namespace"] == ns)
            for (const auto& [hash, data] : messages)
                body["messages"].push_back({{"data", oxenc::to_base64(data)}, {"hash", hash}});
        results.push_back({{"code", 200}, {"body", std::move(body)}});
    }
    return nlohmann::json{{"results", std::move(results)}}.dump();
}

// A message on its way out: both of its stores captured and unanswered.
int64_t start_send(TempClient& c, MockNetwork& net) {
    TestHelper::seed_pfs_nak(c->core, PEER);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));
    auto id = c->send_message(ConversationId::dm(PEER), {.body = "out it goes"}, await);
    REQUIRE(stores(net).size() == 2);
    return id;
}

}  // namespace

TEST_CASE("Client: suspended storage holds no lock on the database", "[client][suspend]") {
    // What iOS checks before it kills a suspended app: whether the process holds a lock on a file
    // in the shared container.  Another process able to take the exclusive lock, and to checkpoint
    // and truncate the WAL, at once and without waiting, is what holding none looks like.
    TempClient c;
    SenderKeys sender;
    approve(*c, sender.session_id);
    deliver(*c, sender, "before", from_epoch_ms(5000), "h1");

    auto result = c->suspend_storage(5s, false, true);
    CHECK(result.closed);
    CHECK(result.checkpointed);
    CHECK(c->core.storage_suspended());

    sqlite3* other;
    REQUIRE(sqlite3_open_v2(c.path.c_str(), &other, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    sqlite3_busy_timeout(other, 0);
    CHECK(sqlite3_exec(other, "BEGIN EXCLUSIVE", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_exec(other, "ROLLBACK", nullptr, nullptr, nullptr);
    int log = -1, done = -1;
    CHECK(sqlite3_wal_checkpoint_v2(other, nullptr, SQLITE_CHECKPOINT_TRUNCATE, &log, &done) ==
          SQLITE_OK);
    sqlite3_close(other);

    c->resume_storage();
    CHECK_FALSE(c->core.storage_suspended());
    deliver(*c, sender, "after", from_epoch_ms(6000), "h2");
    CHECK(c->conversation(ConversationId::dm(sender.session_id), await)->messages(await).size() ==
          2);
}

TEST_CASE("Client: work while storage is suspended is refused", "[client][suspend]") {
    TempClient c;
    c->suspend_storage(1s);
    CHECK_THROWS_AS(c->conversations(await), sqlite::database_suspended);
    c->resume_storage();
    CHECK_NOTHROW(c->conversations(await));
}

TEST_CASE(
        "Client: a poll answered while suspended stores nothing and is retrieved again",
        "[client][suspend][poll]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);
    net->current_node.remote_pubkey[0] = std::byte{0x01};
    const auto& node = net->current_node.remote_pubkey;
    constexpr int16_t dm_ns = static_cast<int16_t>(config::Namespace::Default);

    SenderKeys sender;
    approve(*c, sender.session_id);
    std::vector<std::pair<std::string, std::vector<std::byte>>> batch{
            {"h1", dm_bytes(*c, sender, "one", from_epoch_ms(5000))}};

    // A poll goes out, and storage is suspended before its answer arrives.
    net->sent_requests.clear();
    TestHelper::poll(c->core);
    REQUIRE(net->sent_requests.size() == 1);
    auto first = net->sent_requests[0];
    c->suspend_storage(1s);

    first.callback(true, false, 200, {}, retrieve_answer(*first.request.body, dm_ns, batch));
    TestHelper::drain(c->core);
    CHECK(net->sent_requests.size() == 1);

    // Resuming polls at once, and nothing had been stored or the cursor moved, so it asks from
    // where it was and the message arrives.
    c->resume_storage();
    CHECK(TestHelper::namespace_last_hash(c->core, dm_ns, node) == std::nullopt);
    // Among what resuming sent -- the configs a new account has to push go out too -- the poll.
    auto is_retrieve = [](const MockNetwork::SentRequest& r) {
        auto body = parse_json(*r.request.body);
        return body.contains("requests") && body["requests"][0]["method"] == "retrieve";
    };
    auto polls = std::ranges::count_if(net->sent_requests, is_retrieve);
    REQUIRE(polls == 2);
    auto second = *std::ranges::find_if(
            net->sent_requests.begin() + 1, net->sent_requests.end(), is_retrieve);
    second.callback(true, false, 200, {}, retrieve_answer(*second.request.body, dm_ns, batch));
    TestHelper::drain(c->core);

    auto convo = c->conversation(ConversationId::dm(sender.session_id), await);
    REQUIRE(convo);
    CHECK(convo->messages(await).size() == 1);
    CHECK(TestHelper::namespace_last_hash(c->core, dm_ns, node) == "h1");
}

TEST_CASE(
        "Client: a send that completes while suspended is recorded when storage resumes",
        "[client][suspend][send]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto id = start_send(c, *net);

    c->suspend_storage(1s);
    CHECK(accept_stores(*net) == 2);
    // Kept, in memory and in a file beside the database.
    CHECK(journals(c.path).size() == 1);

    c->resume_storage();
    auto msg = c->message(id, await);
    CHECK(msg->send_state == SendState::sent);
    CHECK(msg->sync_send_state == SendState::sent);
    CHECK(msg->hash == store_hash_for(oxenc::to_hex(own_sid(*c))));
    CHECK(journals(c.path).empty());
}

TEST_CASE(
        "Client: a send outcome kept while suspended outlives the process",
        "[client][suspend][send]") {
    // A suspended app is the one iOS kills, and the next launch would otherwise call a message that
    // did go out interrupted.  Ending the Client while suspended stands in for that.
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto id = start_send(c, *net);

    c->suspend_storage(1s);
    CHECK(accept_stores(*net) == 2);
    REQUIRE(journals(c.path).size() == 1);

    c.reopen();
    auto msg = c->message(id, await);
    CHECK(msg->send_state == SendState::sent);
    CHECK(msg->sync_send_state == SendState::sent);
    CHECK(journals(c.path).empty());
}

TEST_CASE(
        "Client: an in-flight send unanswered while suspended is still interrupted after a restart",
        "[client][suspend][send]") {
    // The case nothing can know: no answer reached the process before it ended.
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto id = start_send(c, *net);

    c->suspend_storage(1s);
    CHECK(journals(c.path).empty());
    c.reopen();
    CHECK(c->message(id, await)->send_state == SendState::interrupted);
}

TEST_CASE(
        "Client: a download that completes while suspended finishes when storage resumes",
        "[client][suspend][attachments]") {
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    std::vector<std::byte> plaintext(9000);
    for (size_t i = 0; i < plaintext.size(); i++)
        plaintext[i] = static_cast<std::byte>(i * 31 % 256);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(1);
                a->set_url("http://fs.example/file/1#d");
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_filename("payload.bin");
            },
            42);
    sync(*c);
    auto msg_id =
            c->conversation(ConversationId::dm(peer.session_id), await)->messages(await).at(0).id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_suspend", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "saved.bin";
    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(msg_id, 0, dest, nullptr, [&](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });
    sync(*c);
    REQUIRE(net->downloads.size() == 1);

    // The file arrives while suspended.  Recording it needs the database, so it is kept rather
    // than finished -- or dropped, which would leave the save waiting for ever.
    c->suspend_storage(1s);
    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    sync(*c);
    CHECK(waiter.wait_for(200ms) == std::future_status::timeout);

    c->resume_storage();
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());
    CHECK(std::filesystem::file_size(dest) == plaintext.size());
    CHECK(c->message(msg_id, await)->attachments.at(0).saved_at.has_value());

    std::filesystem::remove_all(dir);
}
