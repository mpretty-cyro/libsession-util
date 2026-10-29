#pragma once

#include <chrono>
#include <optional>
#include <session/client.hpp>
#include <session/config/namespaces.hpp>
#include <string>

/// Push notification handling: what a device needs to receive Session messages through its
/// platform's push service (APNs, FCM) while the application isn't running.
///
/// Built as its own library (`libsession::push`, `ENABLE_PUSH`) because only mobile clients receive
/// pushes; a desktop or command-line build leaves it out.  It sits on a Client, and so on the Core
/// beneath it, and adds nothing to either: the account, its swarm and its messages are theirs, and
/// this is the layer that knows how a push names them.
///
/// The usual shape is a notification extension (or Android's push receiver) opening a Client with
/// `core::one_shot` and a network with `network::opt::one_shot`, handing it one push, and exiting.

namespace session::push {

using namespace std::literals;

/// What `Notifications::fetch_message` found in the swarm.
enum class FetchResult {
    /// A swarm member had the message, and it has been received exactly as a poll would have
    /// received it.
    found,

    /// Every member asked answered, and none had it.  The push server can notify before a message
    /// has reached every member of the swarm, so this usually means it had not reached the ones
    /// asked yet; the application's next poll picks it up.
    not_found,

    /// No member answered usably within the deadline.
    failed,

    /// No network is attached, or the account has no identity yet.
    no_network,
};

struct FetchedMessage {
    FetchResult result;

    /// What is stored under the message's hash once the fetch is over: set whenever the message is
    /// one the Client keeps and is there -- including when a poll got it first, which a push racing
    /// a poll makes ordinary, whatever `result` says.  Nullopt for anything else: a config message,
    /// say, or one dropped as coming from someone blocked.
    std::optional<client::Message> message;
};

class Notifications {
  public:
    /// How many swarm members `fetch_message` asks at once.
    static constexpr size_t FETCH_MEMBERS = 3;

    /// How long `fetch_message` waits before asking again, when every member it asked answered
    /// without the message.
    static constexpr auto FETCH_RETRY_DELAY = 2s;

    /// Must not outlive `client`.
    explicit Notifications(client::Client& client) : _client{client} {}

    /// Fetches a message that a push announced but could not carry: the push server leaves out a
    /// body too large for a notification, and sends its namespace and swarm hash instead.  What is
    /// found is received exactly as a poll would receive it, so its handlers -- and the Client's
    /// message storage and notifications -- run as usual.
    ///
    /// The push server can notify before a message has reached every member of the swarm, so a
    /// single member may not have it yet.  This asks FETCH_MEMBERS members at once, and the first
    /// that has it ends the fetch.  If every one answers without it, it asks again once, after
    /// FETCH_RETRY_DELAY, provided that leaves time before `deadline`.  Reaching `deadline` ends it
    /// with whatever it has: not_found if any member answered, failed if none did.
    ///
    /// Answers arriving after `cb` are still received, as they came from our own swarm.
    ///
    /// `cb` is called exactly once, through the Client's dispatcher like its other results.
    ///
    /// TODO: ask for the message by its hash once storage servers can retrieve one.  Until then
    /// each member is asked for `ns` from that member's own retrieve cursor, as a poll would, and
    /// "found" means the hash was among what came back.  That is correct today, at the cost of
    /// fetching whatever else arrived since that member was last polled.  A retrieve by hash says
    /// nothing about a member's position, so once it replaces this, its answer must no longer
    /// advance the cursor.
    void fetch_message(
            config::Namespace ns,
            std::string hash,
            std::chrono::milliseconds deadline,
            result_function<FetchedMessage> cb);

  private:
    client::Client& _client;
};

}  // namespace session::push
