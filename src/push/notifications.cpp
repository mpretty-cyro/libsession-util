#include "session/push/notifications.hpp"

#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <session/network/session_network.hpp>

#include "client_access.hpp"
#include "core_access.hpp"
#include "internal.hpp"

namespace session::push {

namespace log = oxen::log;
static auto cat = log::Cat("push");

using detail::ClientAccess;
using detail::CoreAccess;

namespace {

    /// How far a fetch has got.
    ///
    /// Shared between its in-flight requests and its timers, and touched only on Core's job queue:
    /// the answers arrive on the network's threads and the swarm request marshals them across
    /// before any of this is read.  Holds the Core and Client by pointer rather than holding the
    /// Notifications, which may be gone by the time an answer lands; both outlive anything on
    /// Core's queue, which is cancelled as Core goes.
    struct Fetch {
        core::Core* core;
        client::Client* client;
        config::Namespace ns;
        std::string hash;
        result_function<FetchedMessage> cb;
        std::chrono::steady_clock::time_point deadline;

        /// Members still being asked in the current round.
        size_t outstanding = 0;
        /// Rounds started: the first, and the one retry.
        int attempts = 0;
        /// Whether any member answered usably, which separates not_found from failed.
        bool answered = false;
        bool concluded = false;
    };

    // The least time worth starting another round with: a request given less cannot resolve a node,
    // connect and get an answer.
    constexpr auto MIN_ROUND_BUDGET = 2s;

    void ask(
            const std::shared_ptr<Fetch>& op, std::optional<network::service_node> node, int round);
    void member_done(const std::shared_ptr<Fetch>& op);

    // Reports once, with whatever is now stored under the hash: a poll may have brought the message
    // in even when the members asked did not have it.
    void conclude(Fetch& op, FetchResult result) {
        if (op.concluded)
            return;
        op.concluded = true;

        log::info(
                cat,
                "Pushed message fetch concluded: {}",
                result == FetchResult::found       ? "found"
                : result == FetchResult::not_found ? "not yet on the members asked"
                : result == FetchResult::failed    ? "no member answered"
                                                   : "no network");

        op.client->message_by_hash(op.hash, [result, cb = std::move(op.cb)](auto stored) mutable {
            if (!cb)
                return;
            if (!stored)
                return cb(Expected<FetchedMessage>{unexpected{stored.error()}});
            cb(Expected<FetchedMessage>{FetchedMessage{result, std::move(*stored)}});
        });
    }

    void start_round(const std::shared_ptr<Fetch>& op) {
        auto* net = op->core->network();
        if (!net || op->concluded)
            return;

        op->attempts++;
        net->get_swarm(op->core->globals.pubkey_x25519(), false, [op](auto, auto swarm) {
            op->core->call([op, swarm = std::move(swarm)] {
                if (op->concluded)
                    return;
                if (swarm.empty()) {
                    log::warning(cat, "Cannot fetch a pushed message: no swarm members available");
                    op->outstanding = 1;
                    return member_done(op);
                }

                // Distinct members to start from: get_swarm hands them back least-struck first and
                // shuffled among equals, so the front of the list is the right choice.  One that
                // turns out to be wrong or unreachable is walked past by the swarm request itself,
                // which may land on one another branch is asking; the answers then arrive twice.
                auto n = std::min(swarm.size(), Notifications::FETCH_MEMBERS);
                op->outstanding = n;
                for (size_t i = 0; i < n; i++)
                    ask(op, swarm[i], 0);
            });
        });
    }

    void answer(const std::shared_ptr<Fetch>& op, CoreAccess::SwarmResponse res, int round) {
        auto& core = *op->core;

        std::optional<core::retrieved_namespace> got;
        if (res.ok() && res.body) {
            try {
                auto json = nlohmann::json::parse(*res.body);
                auto it = json.find("results");
                if (it != json.end() && it->is_array() && !it->empty())
                    got = core::decode_retrieved((*it)[0], static_cast<int16_t>(op->ns));
            } catch (const std::exception& e) {
                log::warning(cat, "Failed to parse pushed message fetch response: {}", e.what());
            }
        } else {
            log::warning(
                    cat,
                    "Pushed message fetch from {} failed: {}",
                    res.node.remote_pubkey.hex(),
                    res.timeout ? "timed out" : "request failed");
        }

        if (!got)
            return member_done(op);

        op->answered = true;

        // Received whether or not the fetch has already concluded: it came from our own swarm, and
        // dropping it would only leave the next poll to fetch it again.  The cursor is recorded
        // because this is an ordinary retrieve from it; see the TODO on fetch_message.
        {
            auto configs_held = core.configs.batch();
            core.receive_messages(got->messages, op->ns, !got->more);
        }
        CoreAccess::record_cursor(core, res.node.remote_pubkey, op->ns, got->messages);

        if (op->concluded)
            return;

        if (std::ranges::any_of(
                    got->messages, [&](const core::SwarmMessage& m) { return m.hash == op->hash; }))
            return conclude(*op, FetchResult::found);

        // Not yet, but this member says it holds more past what it returned, so the message may
        // still be among it.  The continuation goes back to the same member, whose cursor it
        // resumes from.
        if (got->more && round + 1 < core::POLL_MAX_ROUNDS)
            return ask(op, res.node, round + 1);

        member_done(op);
    }

    void
    ask(const std::shared_ptr<Fetch>& op, std::optional<network::service_node> node, int round) {
        CoreAccess::swarm_request(
                *op->core,
                "batch",
                [core = op->core, ns = op->ns](const network::service_node& n) {
                    return CoreAccess::retrieve_body(*core, n, ns);
                },
                [op, round](CoreAccess::SwarmResponse res) { answer(op, std::move(res), round); },
                std::move(node));
    }

    void member_done(const std::shared_ptr<Fetch>& op) {
        if (op->concluded || --op->outstanding > 0)
            return;

        // Every member of this round has answered without it.  Ask again once, after giving the
        // swarm a moment to propagate, if the deadline leaves room for that and a request after it.
        auto retry_at = std::chrono::steady_clock::now() + Notifications::FETCH_RETRY_DELAY;
        if (op->attempts < 2 && retry_at + MIN_ROUND_BUDGET < op->deadline) {
            op->core->call_later(Notifications::FETCH_RETRY_DELAY, [op] { start_round(op); });
            return;
        }

        conclude(*op, op->answered ? FetchResult::not_found : FetchResult::failed);
    }

}  // namespace

bool Notifications::fetch_on_push(config::Namespace ns) {
    switch (ns) {
        // A change to the device group may be a key rotation, without whose keys later messages
        // will not decrypt, or a link request the user is waiting on.
        case config::Namespace::Devices: return true;
        // What was read on another device, so that its notifications here can be removed.
        case config::Namespace::ConvoInfoVolatile: return true;
        default: return false;
    }
}

void Notifications::handle(
        std::string_view enc_payload,
        std::chrono::milliseconds deadline,
        result_function<HandledPush> cb) {
    auto* core = &_client.core;
    auto* client = &_client;

    // Reports an outcome that has no stored message to look up.
    auto report = [core, client](
                          result_function<HandledPush> cb,
                          Handled outcome,
                          std::optional<Payload> payload) {
        core->call([client, cb = std::move(cb), outcome, payload = std::move(payload)]() mutable {
            ClientAccess::report(
                    *client,
                    cb,
                    Expected<HandledPush>{HandledPush{outcome, std::move(payload), std::nullopt}});
        });
    };

    Payload p;
    try {
        p = decode(enc_payload, encryption_key());
    } catch (const undecryptable&) {
        log::warning(cat, "A push did not decrypt with our key; renewing the subscription");
        core->call([core] { detail::mark_subscription_due(*core); });
        return report(std::move(cb), Handled::undecryptable, std::nullopt);
    } catch (const malformed& e) {
        log::warning(cat, "Malformed push: {}", e.what());
        return report(std::move(cb), Handled::malformed, std::nullopt);
    }

    // TODO: a group's swarm, once Core holds groups; until then every push is for the account.
    if (!core->globals.have_account() || p.swarm != core->globals.session_id_hex())
        return report(std::move(cb), Handled::not_ours, std::move(p));

    if (p.data) {
        core->call([core, client, p = std::move(p), cb = std::move(cb)]() mutable {
            core::SwarmMessage m{*p.data, p.hash, p.timestamp, p.expiry};
            {
                auto configs_held = core->configs.batch();
                core->receive_messages({&m, 1}, p.ns, true);
            }
            auto hash = p.hash;
            client->message_by_hash(
                    std::move(hash), [p = std::move(p), cb = std::move(cb)](auto stored) mutable {
                        if (!stored)
                            return cb(Expected<HandledPush>{unexpected{stored.error()}});
                        cb(Expected<HandledPush>{
                                HandledPush{Handled::received, std::move(p), std::move(*stored)}});
                    });
        });
        return;
    }

    if (!p.too_large && !fetch_on_push(p.ns))
        return report(std::move(cb), Handled::nothing_to_do, std::move(p));

    auto ns = p.ns;
    auto hash = p.hash;
    fetch_message(
            ns,
            std::move(hash),
            deadline,
            [p = std::move(p), cb = std::move(cb)](Expected<FetchedMessage> fetched) mutable {
                if (!fetched)
                    return cb(Expected<HandledPush>{unexpected{fetched.error()}});
                auto outcome = fetched->result == FetchResult::found     ? Handled::fetched
                             : fetched->result == FetchResult::not_found ? Handled::not_found
                                                                         : Handled::fetch_failed;
                cb(Expected<HandledPush>{
                        HandledPush{outcome, std::move(p), std::move(fetched->message)}});
            });
}

void Notifications::fetch_message(
        config::Namespace ns,
        std::string hash,
        std::chrono::milliseconds deadline,
        result_function<FetchedMessage> cb) {
    auto& core = _client.core;
    auto op = std::make_shared<Fetch>();
    op->core = &core;
    op->client = &_client;
    op->ns = ns;
    op->hash = std::move(hash);
    op->cb = std::move(cb);
    op->deadline = std::chrono::steady_clock::now() + deadline;

    if (!core.network() || !core.globals.have_account())
        return conclude(*op, FetchResult::no_network);

    core.call_later(deadline, [op] {
        conclude(*op, op->answered ? FetchResult::not_found : FetchResult::failed);
    });
    core.call([op] { start_round(op); });
}

}  // namespace session::push
