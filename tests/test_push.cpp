#include <oxenc/bt_producer.h>
#include <sodium/crypto_sign.h>

#include <session/push/notifications.hpp>
#include <session/push/payload.hpp>
#include <session/session_encrypt.hpp>

#include "test_client/common.hpp"

using push::FetchedMessage;
using push::FetchResult;
using push::Notifications;

namespace {

/// Long enough past the retry delay for the second round to have been sent.
constexpr auto PAST_THE_RETRY = Notifications::FETCH_RETRY_DELAY + 300ms;

std::vector<network::service_node> swarm_of(size_t n) {
    std::vector<network::service_node> swarm(n);
    for (size_t i = 0; i < n; i++)
        swarm[i].remote_pubkey[0] = std::byte(i + 1);
    return swarm;
}

/// The retrieves the fetch has sent since the last call, taken away so the next call sees only new
/// ones.  Filtered because a network also sends requests of its own.
std::vector<MockNetwork::SentRequest> take_retrieves(MockNetwork& net) {
    std::vector<MockNetwork::SentRequest> found, others;
    for (auto& r : std::exchange(net.sent_requests, {}))
        (r.request.endpoint == "batch" ? found : others).push_back(std::move(r));
    net.sent_requests = std::move(others);
    return found;
}

network::ed25519_pubkey member_of(const MockNetwork::SentRequest& r) {
    return std::get<network::service_node>(r.request.destination).remote_pubkey;
}

/// The one retrieve in a request's batch.
nlohmann::json retrieve_params(const MockNetwork::SentRequest& r) {
    auto batch = parse_json(*r.request.body);
    REQUIRE(batch["requests"].size() == 1);
    return batch["requests"][0]["params"];
}

/// A member's answer holding `messages`, each a (data, hash) pair.
std::string answer_with(
        std::vector<std::pair<std::vector<std::byte>, std::string>> messages, bool more = false) {
    nlohmann::json body;
    body["messages"] = nlohmann::json::array();
    for (auto& [data, hash] : messages)
        body["messages"].push_back({{"data", oxenc::to_base64(data)}, {"hash", hash}});
    body["more"] = more;
    return nlohmann::json{{"results", {{{"code", 200}, {"body", std::move(body)}}}}}.dump();
}

/// A member's answer holding messages under `hashes`.  Their contents are not a message anything
/// can decrypt, which the default namespace's handler logs and skips: only the hashes matter here.
std::string answer(std::vector<std::string> hashes, bool more = false) {
    std::vector<std::pair<std::vector<std::byte>, std::string>> messages;
    for (auto& h : hashes)
        messages.emplace_back(to_vector<std::byte>("not a message"sv), std::move(h));
    return answer_with(std::move(messages), more);
}

/// A one-shot Client with a mock swarm of `members`, and the fetch under test.
struct Setup {
    TempClient c{core::one_shot{}};
    MockNetwork* net;
    Notifications notifications{*c};
    std::vector<Expected<FetchedMessage>> results;

    explicit Setup(size_t members) {
        net = attach_mock_network(c->core);
        net->current_swarm = swarm_of(members);
    }

    void fetch(std::string hash, std::chrono::milliseconds deadline) {
        notifications.fetch_message(
                config::Namespace::Default, std::move(hash), deadline, [this](auto r) {
                    results.push_back(std::move(r));
                });
        TestHelper::drain(c->core);
    }

    void reply(MockNetwork::SentRequest& to, std::string body) {
        to.callback(true, false, 200, {}, std::move(body));
        TestHelper::drain(c->core);
    }

    void reply_error(MockNetwork::SentRequest& to) {
        to.callback(false, false, 500, {}, "nope");
        TestHelper::drain(c->core);
    }

    void wait(std::chrono::milliseconds how_long) {
        std::this_thread::sleep_for(how_long);
        TestHelper::drain(c->core);
    }

    /// The results so far, as FetchResults; every one must have succeeded in being reported.
    std::vector<FetchResult> outcomes() {
        std::vector<FetchResult> out;
        for (auto& r : results) {
            REQUIRE(r.has_value());
            out.push_back(r->result);
        }
        return out;
    }
};

}  // namespace

TEST_CASE("Push fetch: the first member holding it ends the fetch", "[push_notifications]") {
    Setup s{5};
    s.fetch("h-target", 10s);

    // Distinct members, each asked for the default namespace alone.
    auto sent = take_retrieves(*s.net);
    REQUIRE(sent.size() == Notifications::FETCH_MEMBERS);
    CHECK(member_of(sent[0]) != member_of(sent[1]));
    CHECK(member_of(sent[1]) != member_of(sent[2]));
    CHECK(member_of(sent[0]) != member_of(sent[2]));
    for (auto& r : sent)
        CHECK(retrieve_params(r)["namespace"] == static_cast<int16_t>(config::Namespace::Default));

    s.reply(sent[0], answer({}));
    CHECK(s.results.empty());

    s.reply(sent[1], answer({"h-before", "h-target"}));
    CHECK(s.outcomes() == std::vector{FetchResult::found});

    // A late answer is still taken in, and changes nothing about the result.
    s.reply(sent[2], answer({"h-target"}));
    CHECK(s.results.size() == 1);

    // The member that had it is where the next retrieve of the namespace resumes.
    CHECK(TestHelper::namespace_last_hash(
                  s.c->core,
                  static_cast<int16_t>(config::Namespace::Default),
                  member_of(sent[1])) == "h-target");
}

TEST_CASE("Push fetch: asks again once when no member has it yet", "[push_notifications]") {
    Setup s{3};
    s.fetch("h-target", 10s);
    for (auto& r : take_retrieves(*s.net))
        s.reply(r, answer({"h-other"}));
    CHECK(s.results.empty());

    // The retry waits for the swarm to propagate rather than asking straight away.
    CHECK(take_retrieves(*s.net).empty());
    s.wait(PAST_THE_RETRY);

    SECTION("and finds it") {
        auto again = take_retrieves(*s.net);
        REQUIRE(again.size() == 3);
        s.reply(again[2], answer({"h-target"}));
        CHECK(s.outcomes() == std::vector{FetchResult::found});
    }

    SECTION("and stops after that one retry") {
        for (auto& r : take_retrieves(*s.net))
            s.reply(r, answer({}));
        CHECK(s.outcomes() == std::vector{FetchResult::not_found});

        s.wait(PAST_THE_RETRY);
        CHECK(take_retrieves(*s.net).empty());
    }
}

TEST_CASE("Push fetch: no retry when the deadline leaves no room", "[push_notifications]") {
    Setup s{3};
    s.fetch("h-target", 1s);
    for (auto& r : take_retrieves(*s.net))
        s.reply(r, answer({}));
    CHECK(s.outcomes() == std::vector{FetchResult::not_found});
}

TEST_CASE("Push fetch: the deadline ends a fetch nobody answers", "[push_notifications]") {
    Setup s{3};
    s.fetch("h-target", 200ms);
    auto sent = take_retrieves(*s.net);
    REQUIRE(sent.size() == 3);

    SECTION("no answers at all") {
        s.wait(300ms);
        CHECK(s.outcomes() == std::vector{FetchResult::failed});
    }

    SECTION("only errors") {
        for (auto& r : sent)
            s.reply_error(r);
        CHECK(s.outcomes() == std::vector{FetchResult::failed});
    }

    SECTION("one empty answer before the deadline") {
        s.reply(sent[0], answer({}));
        s.wait(300ms);
        CHECK(s.outcomes() == std::vector{FetchResult::not_found});
    }
}

TEST_CASE(
        "Push fetch: a member holding more continues from where it stopped",
        "[push_notifications]") {
    Setup s{1};
    s.fetch("h-target", 10s);
    auto sent = take_retrieves(*s.net);
    REQUIRE(sent.size() == 1);
    CHECK_FALSE(retrieve_params(sent[0]).contains("last_hash"));

    s.reply(sent[0], answer({"h-1", "h-2"}, /*more=*/true));
    CHECK(s.results.empty());

    // Back to the same member, resuming after what it has already handed over.
    auto next = take_retrieves(*s.net);
    REQUIRE(next.size() == 1);
    CHECK(member_of(next[0]) == member_of(sent[0]));
    CHECK(retrieve_params(next[0])["last_hash"] == "h-2");

    s.reply(next[0], answer({"h-target"}));
    CHECK(s.outcomes() == std::vector{FetchResult::found});
}

TEST_CASE("Push fetch: the stored message is handed back", "[push_notifications]") {
    Setup s{1};
    SenderKeys sender;
    auto ts = clock_now_ms();

    SECTION("when the fetch brings it in") {
        s.fetch("h-pushed", 10s);
        auto sent = take_retrieves(*s.net);
        REQUIRE(sent.size() == 1);
        s.reply(sent[0],
                answer_with(
                        {{encode_incoming_dm(*s.c, sender, "too long for a push", ts),
                          "h-pushed"}}));

        REQUIRE(s.outcomes() == std::vector{FetchResult::found});
        auto& got = *s.results[0];
        REQUIRE(got.message);
        CHECK(got.message->body == "too long for a push");
        CHECK(got.message->sender == sender.session_id);
        CHECK(got.message->hash == "h-pushed");
    }

    SECTION("when a poll got there first, even if the members asked no longer have it") {
        // The push and the poll race, and the poll can win.
        deliver(*s.c, sender, "already here", ts, "h-pushed");

        s.fetch("h-pushed", 1s);
        for (auto& r : take_retrieves(*s.net))
            s.reply(r, answer({}));

        REQUIRE(s.outcomes() == std::vector{FetchResult::not_found});
        auto& got = *s.results[0];
        REQUIRE(got.message);
        CHECK(got.message->body == "already here");
    }
}

TEST_CASE("Push fetch: without a network it says so at once", "[push_notifications]") {
    TempClient c{core::one_shot{}};
    Notifications notifications{*c};

    std::optional<Expected<FetchedMessage>> result;
    notifications.fetch_message(
            config::Namespace::Default, "h", 10s, [&](auto r) { result = std::move(r); });
    TestHelper::drain(c->core);

    REQUIRE(result);
    REQUIRE(result->has_value());
    CHECK((*result)->result == FetchResult::no_network);
    CHECK_FALSE((*result)->message);
}

// ── Decoding a push's payload ───────────────────────────────────────────────────────────────────

namespace {

constexpr auto SWARM_HEX = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"sv;

b32 push_key() {
    b32 key;
    random::fill(key);
    return key;
}

/// What the push server sends: the bencoded list padded to a multiple of 256, encrypted with the
/// subscription's key, nonce first.
std::vector<std::byte> seal(const b32& key, std::string_view plain) {
    std::string padded{plain};
    if (auto over = padded.size() % 256)
        padded.append(256 - over, '\0');
    return encrypt_xchacha20(to_span(padded), key);
}

/// The push server's JSON metadata, with `extra` added.
std::string metadata_json(nlohmann::json extra = nlohmann::json::object()) {
    nlohmann::json m{
            {"@", SWARM_HEX},
            {"#", "h-pushed"},
            {"n", 0},
            {"t", 1'700'000'000'123},
            {"z", 1'701'000'000'456}};
    m.update(extra);
    return m.dump();
}

std::string list_of(
        std::string_view metadata, std::optional<std::string_view> body = std::nullopt) {
    oxenc::bt_list_producer l;
    l.append(metadata);
    if (body)
        l.append(*body);
    return std::string{l.view()};
}

}  // namespace

TEST_CASE("Push payload: a push carrying its message", "[push_notifications]") {
    auto key = push_key();
    auto p = push::decode(seal(key, list_of(metadata_json({{"l", 5}}), "hello")), key);

    CHECK(p.swarm == SWARM_HEX);
    CHECK(p.hash == "h-pushed");
    CHECK(p.ns == config::Namespace::Default);
    CHECK(p.timestamp == from_epoch_ms(1'700'000'000'123));
    CHECK(p.expiry == from_epoch_ms(1'701'000'000'456));
    REQUIRE(p.data);
    CHECK(to_string_view(*p.data) == "hello");
    CHECK(p.length == 5);
    CHECK_FALSE(p.too_large);
}

TEST_CASE("Push payload: a message too large for the push", "[push_notifications]") {
    auto key = push_key();

    SECTION("with JSON metadata") {
        auto p = push::decode(seal(key, list_of(metadata_json({{"l", 4000}, {"B", true}}))), key);
        CHECK(p.too_large);
        CHECK(p.length == 4000);
        CHECK_FALSE(p.data);
    }

    SECTION("with the bencoded metadata APNs gets when there is no body") {
        oxenc::bt_list_producer l;
        {
            auto d = l.append_dict();
            d.append("#", "h-pushed");
            d.append("@", SWARM_HEX);
            d.append("B", 1);
            d.append("l", 4000);
            d.append("n", 0);
            d.append("t", 1'700'000'000'123);
            d.append("z", 1'701'000'000'456);
        }
        auto p = push::decode(seal(key, l.view()), key);
        CHECK(p.swarm == SWARM_HEX);
        CHECK(p.hash == "h-pushed");
        CHECK(p.too_large);
        CHECK(p.length == 4000);
        CHECK(p.expiry == from_epoch_ms(1'701'000'000'456));
        CHECK_FALSE(p.data);
    }
}

TEST_CASE("Push payload: a subscription without message data", "[push_notifications]") {
    auto key = push_key();
    auto p = push::decode(seal(key, list_of(metadata_json({{"n", 5}}))), key);
    CHECK(p.ns == config::Namespace::UserGroups);
    CHECK_FALSE(p.data);
    CHECK_FALSE(p.length);
    CHECK_FALSE(p.too_large);
}

TEST_CASE("Push payload: the base64 text the push arrives as", "[push_notifications]") {
    auto key = push_key();
    auto sealed = seal(key, list_of(metadata_json(), "hello"));
    auto p = push::decode(oxenc::to_base64(sealed), key);
    CHECK(p.hash == "h-pushed");
    CHECK_THROWS_AS(push::decode("not base64!"sv, key), push::malformed);
}

TEST_CASE("Push payload: what will not decode", "[push_notifications]") {
    auto key = push_key();

    // Another key: a push meant for a subscription made with a different one.
    CHECK_THROWS_AS(
            push::decode(seal(push_key(), list_of(metadata_json())), key), push::undecryptable);
    CHECK_THROWS_AS(push::decode(to_span("short"), key), push::undecryptable);

    CHECK_THROWS_AS(push::decode(seal(key, "not bencoded"), key), push::malformed);
    CHECK_THROWS_AS(push::decode(seal(key, list_of("{not json")), key), push::malformed);
    CHECK_THROWS_AS(
            push::decode(seal(key, list_of(R"({"@":"05ab","#":"h","n":0,"t":1,"z":2})")), key),
            push::malformed);
    CHECK_THROWS_AS(
            push::decode(seal(key, list_of(metadata_json({{"#", ""}}))), key), push::malformed);
    CHECK_THROWS_AS(
            push::decode(seal(key, list_of(metadata_json({{"B", true}}), "body")), key),
            push::malformed);
}

// ── Subscribing ─────────────────────────────────────────────────────────────────────────────────

namespace {

/// Requests the subscription code has sent to `endpoint`, taken away.
std::vector<MockNetwork::SentRequest> take_sent_to(MockNetwork& net, std::string_view endpoint) {
    std::vector<MockNetwork::SentRequest> found, others;
    for (auto& r : std::exchange(net.sent_requests, {}))
        (r.request.endpoint == endpoint ? found : others).push_back(std::move(r));
    net.sent_requests = std::move(others);
    return found;
}

nlohmann::json body_of(const MockNetwork::SentRequest& r) {
    return parse_json(*r.request.body);
}

/// Whether `req` is signed by the account it names over `signed_value`.
bool signature_valid(const nlohmann::json& req, std::string_view signed_value) {
    auto pk = oxenc::from_hex(req["session_ed25519"].get<std::string>());
    auto sig = oxenc::from_hex(req["signature"].get<std::string>());
    if (pk.size() != 32 || sig.size() != 64)
        return false;
    return crypto_sign_verify_detached(
                   reinterpret_cast<const unsigned char*>(sig.data()),
                   reinterpret_cast<const unsigned char*>(signed_value.data()),
                   signed_value.size(),
                   reinterpret_cast<const unsigned char*>(pk.data())) == 0;
}

std::string accepted(size_t n = 1) {
    auto a = nlohmann::json::array();
    for (size_t i = 0; i < n; i++)
        a.push_back({{"success", true}, {"added", true}});
    return a.dump();
}

/// An application's Client (not one-shot: subscribing is the application's job) with a mock
/// network, and its push handling.
struct Subscriber {
    TempClient c;
    MockNetwork* net;
    std::optional<Notifications> notifications;
    std::vector<Expected<push::SubscribeResult>> results;

    Subscriber() {
        net = attach_mock_network(c->core);
        notifications.emplace(*c);
    }

    void subscribe(std::string token, bool force = false) {
        notifications->subscribe(
                {push::Service::apns, std::move(token)},
                [this](auto r) { results.push_back(std::move(r)); },
                force);
        TestHelper::drain(c->core);
    }

    void reply(MockNetwork::SentRequest& r, std::string body) {
        r.callback(true, false, 200, {}, std::move(body));
        TestHelper::drain(c->core);
    }

    /// Subscribes with `token` and accepts it.
    void subscribed(std::string token) {
        subscribe(std::move(token));
        auto sent = take_sent_to(*net, "subscribe");
        REQUIRE(sent.size() == 1);
        reply(sent[0], accepted());
        REQUIRE(results.back().has_value());
        REQUIRE(*results.back() == push::SubscribeResult::subscribed);
    }
};

}  // namespace

TEST_CASE("Push subscribe: a signed request for the account's namespaces", "[push_notifications]") {
    Subscriber s;
    s.subscribe("token-1");

    auto sent = take_sent_to(*s.net, "subscribe");
    REQUIRE(sent.size() == 1);
    auto& dest = std::get<network::ServerDestination>(sent[0].request.destination);
    CHECK(dest.host == "push.getsession.org");
    CHECK(dest.method == "POST");

    auto body = body_of(sent[0]);
    REQUIRE(body.is_array());
    REQUIRE(body.size() == 1);
    auto& req = body[0];
    CHECK(req["pubkey"] == s.c->core.globals.session_id_hex());
    CHECK(req["service"] == "apns");
    CHECK(req["service_info"]["token"] == "token-1");
    CHECK(req["data"] == true);
    auto key = s.notifications->encryption_key();
    CHECK(req["enc_key"] == oxenc::to_hex(key.begin(), key.end()));

    // Everything the account polls but its own published keys (-21), in ascending order.
    CHECK(req["namespaces"] == std::vector<int16_t>{0, 2, 3, 4, 5, 21});

    CHECK(signature_valid(
            req,
            "MONITOR{}{}10,2,3,4,5,21"_format(
                    req["pubkey"].get<std::string>(), req["sig_ts"].get<int64_t>())));

    CHECK(s.results.empty());
    s.reply(sent[0], accepted());
    REQUIRE(s.results.size() == 1);
    REQUIRE(s.results[0].has_value());
    CHECK(*s.results[0] == push::SubscribeResult::subscribed);
}

TEST_CASE(
        "Push subscribe: sends only when something changed or it is due", "[push_notifications]") {
    Subscriber s;
    s.subscribed("token-1");

    SECTION("the same device again") {
        s.subscribe("token-1");
        CHECK(take_sent_to(*s.net, "subscribe").empty());
        REQUIRE(s.results.back().has_value());
        CHECK(*s.results.back() == push::SubscribeResult::unchanged);
    }

    SECTION("forced") {
        s.subscribe("token-1", /*force=*/true);
        CHECK(take_sent_to(*s.net, "subscribe").size() == 1);
    }

    SECTION("a day later") {
        auto recorded = nlohmann::json::parse(*s.c->core.globals.get_text("push_subscription"));
        recorded["at"] = recorded["at"].get<int64_t>() - 25 * 60 * 60 * 1000;
        s.c->core.globals.set("push_subscription", recorded.dump());

        s.subscribe("token-1");
        CHECK(take_sent_to(*s.net, "subscribe").size() == 1);
    }

    SECTION("a new token, which also unsubscribes the old one") {
        s.subscribe("token-2");
        auto sent = take_sent_to(*s.net, "subscribe");
        REQUIRE(sent.size() == 1);
        CHECK(body_of(sent[0])[0]["service_info"]["token"] == "token-2");
        CHECK(take_sent_to(*s.net, "unsubscribe").empty());

        s.reply(sent[0], accepted());
        auto old = take_sent_to(*s.net, "unsubscribe");
        REQUIRE(old.size() == 1);
        auto req = body_of(old[0])[0];
        CHECK(req["service_info"]["token"] == "token-1");
        CHECK(signature_valid(
                req,
                "UNSUBSCRIBE{}{}"_format(
                        req["pubkey"].get<std::string>(), req["sig_ts"].get<int64_t>())));
    }
}

TEST_CASE(
        "Push subscribe: a refusal or failure is reported and not recorded",
        "[push_notifications]") {
    Subscriber s;
    s.subscribe("token-1");
    auto sent = take_sent_to(*s.net, "subscribe");
    REQUIRE(sent.size() == 1);

    SECTION("refused") {
        s.reply(sent[0], R"([{"error": 3, "message": "invalid signature"}])");
        REQUIRE(s.results.size() == 1);
        REQUIRE_FALSE(s.results[0].has_value());
        CHECK(s.results[0].error().code == push::err::rejected);
    }

    SECTION("not reached") {
        sent[0].callback(false, true, 0, {}, std::nullopt);
        TestHelper::drain(s.c->core);
        REQUIRE(s.results.size() == 1);
        REQUIRE_FALSE(s.results[0].has_value());
        CHECK(s.results[0].error().code == push::err::request_failed);
    }

    // Nothing was recorded, so the next attempt sends again.
    s.subscribe("token-1");
    CHECK(take_sent_to(*s.net, "subscribe").size() == 1);
}

TEST_CASE("Push subscribe: unsubscribing", "[push_notifications]") {
    Subscriber s;
    std::vector<Expected<bool>> results;
    auto unsubscribe = [&] {
        s.notifications->unsubscribe([&](auto r) { results.push_back(std::move(r)); });
        TestHelper::drain(s.c->core);
    };

    // Nothing to remove.
    unsubscribe();
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].has_value());
    CHECK(*results[0]);
    CHECK(take_sent_to(*s.net, "unsubscribe").empty());

    s.subscribed("token-1");
    unsubscribe();
    auto sent = take_sent_to(*s.net, "unsubscribe");
    REQUIRE(sent.size() == 1);
    CHECK(body_of(sent[0])[0]["service_info"]["token"] == "token-1");
    s.reply(sent[0], R"([{"success": true, "removed": true}])");
    REQUIRE(results.size() == 2);
    REQUIRE(results[1].has_value());
    CHECK(*results[1]);

    // Gone, so subscribing again sends.
    s.subscribe("token-1");
    CHECK(take_sent_to(*s.net, "subscribe").size() == 1);
}

TEST_CASE("Push subscribe: the encryption key is kept", "[push_notifications]") {
    TempClient c;
    auto key = Notifications{*c}.encryption_key();
    CHECK(Notifications{*c}.encryption_key() == key);

    // And read by a one-shot Client on the same database, as an extension would.
    c.reopen(core::one_shot{});
    CHECK(Notifications{*c}.encryption_key() == key);
}

TEST_CASE("Push subscribe: without a network", "[push_notifications]") {
    TempClient c;
    Notifications notifications{*c};
    std::optional<Expected<push::SubscribeResult>> result;
    notifications.subscribe({push::Service::firebase, "t"}, [&](auto r) { result = std::move(r); });
    TestHelper::drain(c->core);
    REQUIRE(result);
    REQUIRE_FALSE(result->has_value());
    CHECK(result->error().code == client::err::network_unavailable);
}

// ── Handling a push ─────────────────────────────────────────────────────────────────────────────

namespace {

/// A one-shot Client as a notification extension opens it, with a swarm of one member.
struct Extension : Setup {
    std::vector<Expected<push::HandledPush>> handled;

    Extension() : Setup{1} {}

    std::string sid() { return c->core.globals.session_id_hex(); }

    /// A push for our account, in namespace `ns`, as the push server would send it.
    std::string push_for(
            int16_t ns,
            std::optional<std::vector<std::byte>> body,
            nlohmann::json extra = nlohmann::json::object()) {
        extra["@"] = sid();
        extra["n"] = ns;
        if (body)
            extra["l"] = body->size();
        auto meta = metadata_json(extra);
        auto key = notifications.encryption_key();
        return oxenc::to_base64(
                seal(key, body ? list_of(meta, to_string_view(*body)) : list_of(meta)));
    }

    void handle(std::string enc_payload) {
        notifications.handle(enc_payload, 10s, [this](auto r) { handled.push_back(std::move(r)); });
        TestHelper::drain(c->core);
    }

    push::HandledPush only() {
        REQUIRE(handled.size() == 1);
        REQUIRE(handled[0].has_value());
        return *handled[0];
    }
};

}  // namespace

TEST_CASE("Push handle: a push carrying its message", "[push_notifications]") {
    Extension x;
    SenderKeys sender;
    auto data = encode_incoming_dm(*x.c, sender, "short enough", clock_now_ms());
    x.handle(x.push_for(0, data));

    auto h = x.only();
    CHECK(h.outcome == push::Handled::received);
    REQUIRE(h.payload);
    CHECK(h.payload->hash == "h-pushed");
    REQUIRE(h.message);
    CHECK(h.message->body == "short enough");
    CHECK(h.message->hash == "h-pushed");

    // Nothing fetched, and no member's cursor moved: a push is not a position in a retrieve.
    CHECK(take_retrieves(*x.net).empty());
    CHECK_FALSE(
            TestHelper::namespace_last_hash(x.c->core, 0, x.net->current_swarm[0].remote_pubkey));
}

TEST_CASE("Push handle: a message too large for the push is fetched", "[push_notifications]") {
    Extension x;
    SenderKeys sender;
    x.handle(x.push_for(0, std::nullopt, {{"l", 4000}, {"B", true}}));
    CHECK(x.handled.empty());

    auto sent = take_retrieves(*x.net);
    REQUIRE(sent.size() == 1);
    x.reply(sent[0],
            answer_with(
                    {{encode_incoming_dm(*x.c, sender, "too long", clock_now_ms()), "h-pushed"}}));

    auto h = x.only();
    CHECK(h.outcome == push::Handled::fetched);
    REQUIRE(h.message);
    CHECK(h.message->body == "too long");
}

TEST_CASE("Push handle: a push without data", "[push_notifications]") {
    Extension x;

    SECTION("for a config that can wait for the next poll") {
        x.handle(x.push_for(static_cast<int16_t>(config::Namespace::UserGroups), std::nullopt));
        CHECK(x.only().outcome == push::Handled::nothing_to_do);
        CHECK(take_retrieves(*x.net).empty());
    }

    SECTION("for the device group, which is fetched now") {
        x.handle(x.push_for(static_cast<int16_t>(config::Namespace::Devices), std::nullopt));
        auto sent = take_retrieves(*x.net);
        REQUIRE(sent.size() == 1);
        CHECK(retrieve_params(sent[0])["namespace"] == 21);
        // Empty both times: the first round and its retry.
        x.reply(sent[0], answer({}));
        x.wait(PAST_THE_RETRY);
        auto again = take_retrieves(*x.net);
        REQUIRE(again.size() == 1);
        x.reply(again[0], answer({}));
        CHECK(x.only().outcome == push::Handled::not_found);
    }

    SECTION("for the read state, which is fetched now") {
        x.handle(x.push_for(
                static_cast<int16_t>(config::Namespace::ConvoInfoVolatile), std::nullopt));
        CHECK(take_retrieves(*x.net).size() == 1);
    }
}

TEST_CASE("Push handle: pushes that are not handled", "[push_notifications]") {
    Extension x;

    SECTION("another swarm") {
        x.handle(oxenc::to_base64(
                seal(x.notifications.encryption_key(), list_of(metadata_json(), "hello"))));
        CHECK(x.only().outcome == push::Handled::not_ours);
    }

    SECTION("another key, which makes the subscription due") {
        // The application's side: a subscription recorded as current.
        Subscriber app;
        app.subscribed("token-1");
        Notifications on_app_db{*app.c};

        std::optional<Expected<push::HandledPush>> got;
        on_app_db.handle(
                oxenc::to_base64(seal(push_key(), list_of(metadata_json()))), 10s, [&](auto r) {
                    got = std::move(r);
                });
        TestHelper::drain(app.c->core);
        REQUIRE(got);
        REQUIRE(got->has_value());
        CHECK((*got)->outcome == push::Handled::undecryptable);

        app.subscribe("token-1");
        CHECK(take_sent_to(*app.net, "subscribe").size() == 1);
    }

    SECTION("not a payload") {
        x.handle(oxenc::to_base64(seal(x.notifications.encryption_key(), "nonsense")));
        CHECK(x.only().outcome == push::Handled::malformed);
    }
}
