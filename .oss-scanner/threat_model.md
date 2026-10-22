# libsession-util threat model

## What this project does

libsession-util is the C++20 core of the Session messenger's clients (iOS, Android, Desktop, and
the Session 2.0 app). It implements the Session protocol: message encryption and decryption,
encrypted config sync between a user's devices, closed groups, the linked-device group and its
account keys (perfect forward secrecy and post-quantum encryption for one-to-one messages), onion
requests through Session service nodes, file and community server clients, and the persistent
client state (SQLite) behind the `core` and `client` layers. Clients use it through a C++ API and a
paired C API (`include/session/**/*.h`) for FFI.

Session's promise to users is that message content, contact lists and account data are readable
only by the user's own devices and the intended recipients, and that the network learns as little
metadata as possible. A bug matters in proportion to how much of that promise it breaks.

## Where untrusted input enters

Treat every byte that arrives from outside the local device as attacker-controlled. In particular:

- **Messages from other users** — one-to-one, closed-group and community messages: the poll and
  push handling in `src/core.cpp` (`Core::_handle_poll_response`, `_handle_server_push`),
  `session_protocol` (`decode_dm_envelope`, `decode_group_envelope`, `decode_for_community`; the v1
  envelope and the v2 PFS message with ML-KEM), `session_encrypt`, `multi_encrypt`, protobuf
  `Content` (`proto/`), and `src/client/client.cpp`, which turns decoded messages into stored rows
  (attachment URL, key and size, replies, reactions, deletions).
- **Contacts' published account keys** (PFS) — `Core::_handle_pfs_response` and `_store_pfs_keys`:
  signature checks, binding to the Session ID, and anything that substitutes or downgrades a
  contact's keys.
- **Config messages from the user's other devices, and from other members of a closed group** —
  `config::*` merge and `config/encrypt.cpp` (`decrypt_inplace`), bt-encoded dicts merged by
  `bt_merge`, and group keys/info/members (`src/config/groups/`). Any member of a group can push.
- **Device-group messages and link requests** (Session 2.0, namespace 21) —
  `core::Devices::receive_device_group_message`, `receive_link_request`, `parse_device_messages`,
  `parse_account_pubkeys` in `src/core/devices.cpp`, and the link SAS (`src/core/link_sas.cpp`). A
  removed device, or anyone holding the account's root seed, is an adversary here; see "Adversaries".
- **Swarm and service-node responses** — storage-server retrieve results (message bodies *and* their
  metadata: hashes, timestamps and expiries are reported by the node and are not signed), the
  service-node list (`process_snode_cache_bin` and `from_json` in `src/network/service_node.cpp`),
  swarm and 421 swarm-change lists, the snode pool (`src/network/snode_pool.cpp`: a malicious node
  poisoning the pool, path and subnet diversity), and onion-request responses
  (`src/onionreq/response_parser.cpp`, `src/network/routing/`).
- **File server, community (SOGS) server and Pro backend responses** — `src/network/backends/`,
  `pro_backend.cpp` (`parse_pro_proof`, `parse_pro_status`, `parse_revocations`, ...) and the Pro
  signature checks in `src/core/pro.cpp`.
- **Attachments and images** — attacker-supplied ciphertext and stream-encrypted attachments
  (`attachments.cpp`, including the URL-fragment format flags and size handling), the download
  cache (`src/client/download_cache.cpp`), and thumbhash decoding (`src/image/thumbhash.cpp`).
  libsession does not decode full images.
- **Strings a user is given by someone else** — community URLs (`config::community::parse_*`),
  Session IDs and conversation IDs (`client::ConversationId::parse`), and recovery phrases
  (`src/mnemonics/`).

## Adversaries

In scope:

- **Any other Session user**, including members of a group the victim is in.
- **A malicious service node**, including one in the victim's swarm or on an onion path. It can
  drop, delay, replay, reorder and re-date stored messages, and return arbitrary responses, but it
  cannot sign as a user.
- **A malicious file, community or Pro server**, or anything able to answer in its place.
- **A removed or replaced linked device.** The device-group design treats a removed device as hostile
  (`docs/protocol-v2.md`, "Removed devices"); anything that lets it keep or regain access to the
  group, its account keys, or future messages is a real finding.
- **A holder of the account's root seed, for the specific things the protocol promises to withstand
  it**: decrypting past one-to-one messages (the PFS goal stated at the top of
  `docs/protocol-v2.md`) and joining a device group without the user noticing the SAS mismatch.
- **A passive network observer or storage-server operator** logging everything for later
  decryption.

Out of scope:

- A fully compromised local device or process: an attacker who can read the app's memory, its
  SQLite database or its key storage, or call the library directly. (Key material leaking *out* of
  the protected places, into logs, temporary files or unlocked memory, is in scope.)
- SQL injection through session-sqlite: every query is prepared. What the library itself wrote to
  its database is trusted when read back; what it stores from the network is not.
- What a root-seed holder can do beyond the promises above, such as impersonating the account to
  contacts. Holding the seed *is* holding the account.
- Denial of service that the protocol cannot prevent: a swarm withholding all messages, a server
  refusing to answer, flooding with valid traffic.

## Components that matter most / least

Most:
- Decryption, signature verification and decoding of anything received: `session_encrypt`,
  `session_protocol`, `multi_encrypt`, `config/encrypt.cpp`, `onionreq/`, `attachments.cpp`.
- The Session 2.0 code in `src/core/` (device groups, account keys, link requests) and
  `src/client/`. It is new, and its trust rules are the least exercised.
- Config merge and closed-group keys (`src/config/`), since a poisoned config is stored and
  re-processed on every start.

Least:
- `tests/`, `utils/`, `docs/`: test drivers, build scripts and documentation. A defect in test code
  (a test that leaks the C API objects it creates, or misuses a temporary) is not a finding; the
  same defect in `src/` on a path reachable from untrusted input is.
- `external/`: vendored third-party and sibling projects (protobuf, session-router, oxen-libquic,
  session-sqlite, Catch2, date, ios-cmake). Report a bug there to its own project; it is in scope
  here only when the defect is in how libsession-util uses it.
- iOS, Android and macOS build tooling.

## How to exercise it

- The image is built in `/src/build`: Debian trixie, gcc, a Debug build (libsession's threading and
  state checks are asserts), shared libraries, system dependencies. `cmake --build /src/build`
  rebuilds after a change.
- `/src/build/tests/testAll` is the Catch2 suite (about 460 cases, under a minute); filter by tag or
  name, for example `testAll "[config]"`. The network layer is mocked, so it needs no network.
  `testLogging` is separate because it changes global logging state. The `[pro_live]` cases, which
  need a running Pro backend, are compiled out of this build.
- The live-network tests (`BUILD_LIVE_TESTS`) are not built: they need the real Session network.
- A sanitizer build works offline. The dependency tarballs a fresh build directory would download
  are kept in `/opt/session-deps-sources`:

  ```sh
  mkdir -p /src/build-asan/static-deps-sources/src
  cp /opt/session-deps-sources/* /src/build-asan/static-deps-sources/src/
  cmake -S /src -B /src/build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_LIVE_TESTS=OFF \
      -DBUILD_SHARED_LIBS=ON -DBUILD_STATIC_DEPS=OFF -DUSE_LTO=OFF \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined \
      -DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address,undefined
  cmake --build /src/build-asan -j2
  ```

  Keep `-j` small: `nproc` reports the host's cores rather than the container's share, and
  sanitized C++ compiles need over 1 GB each, so the default parallelism runs out of memory.
- New reproducers fit best as a Catch2 `TEST_CASE` in the matching `tests/test_*.cpp`. The
  existing tests show how to build valid messages, configs and keys to mutate from.

## How we rate severity

**PROPOSAL — not yet agreed by the maintainers.** Rate by what an in-scope adversary achieves, not
by bug class alone.

- **Critical**
  - Code execution, or a memory-corruption bug with a credible path to it, reachable remotely
    without user interaction (a received message, config, swarm or server response).
  - Disclosure of message plaintext, or of private key material (root seed, device keys, account
    keys, group keys), to a party not entitled to it.
  - Forging a message, config, device-group message or link request that the victim accepts as
    authentic from someone else; joining a closed group or device group without being admitted.
  - Breaking the PFS guarantee: a root-seed holder or passive logger can decrypt past one-to-one
    messages.
- **High**
  - Memory-safety bugs (out-of-bounds read or write, use-after-free, double free, uninitialised
    read) reachable from untrusted input, without a demonstrated exploit.
  - A removed device keeping or regaining access to new account keys or group content; a swarm
    node or group member changing device-group or closed-group membership or keys.
  - Persistent denial of service: input that crashes or wedges the client on every start (a stored
    config or database state), or permanently breaks a conversation, group or device link.
- **Medium**
  - Transient remote denial of service: a crash, hang or excessive memory or CPU use that a restart
    clears.
  - Metadata disclosure beyond what the protocol documents: who a user talks to, group or device
    membership, IP address leaks around onion routing.
  - State a malicious service node can corrupt by replaying or re-dating messages, when the client
    recovers on its own.
- **Low**
  - Bugs reachable only through the local API with arguments no client passes, or only by a
    local attacker; leaks of non-secret data to logs; hardening gaps with no demonstrated impact.

## How we would like reports

- A reproducer that runs in this image, ideally as a Catch2 test that fails before the fix and
  passes after it. Say which adversary from the list above can deliver the input.
- A minimal patch in the style of the surrounding code (the project formats with clang-format 19
  via `./utils/format.sh`; it is not installed in this image). When a C++ API changes, update the
  paired C API in `include/session/**/*.h` too.
- For protocol-level findings, cite the section of `docs/protocol-v2.md` the behaviour contradicts.
