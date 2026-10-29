#include <session/push/notifications.hpp>

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
