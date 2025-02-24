#include "session/session_encrypt.hpp"

#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <session/session_encrypt.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <array>
#include <cassert>
#include <cstring>
#include <sstream>
#include <stdexcept>

#include "session/blinding.hpp"
#include "session/sodium_array.hpp"

using namespace std::literals;

namespace session {

namespace detail {
    inline int64_t to_epoch_ms(std::chrono::system_clock::time_point t) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
    }

    // detail::to_hashable takes either an integral type, system_clock::time_point, or a string
    // type and converts it to a string_view by writing an integer value (using std::to_chars)
    // into the buffer space (which should be at least 20 bytes), and returning a string_view
    // into the written buffer space.  For strings/string_views the string_view is returned
    // directly from the argument. system_clock::time_points are converted into integral
    // milliseconds since epoch then treated as an integer value.
    template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    std::string_view to_hashable(const T& val, char*& buffer) {
        std::ostringstream ss;
        ss << val;

        std::string str = ss.str();
        std::copy(str.begin(), str.end(), buffer);
        std::string_view s(buffer, str.length());
        buffer += str.length();
        return s;
    }
    inline std::string_view to_hashable(
            const std::chrono::system_clock::time_point& val, char*& buffer) {
        return to_hashable(to_epoch_ms(val), buffer);
    }
    template <typename T, std::enable_if_t<std::is_convertible_v<T, std::string_view>, int> = 0>
    std::string_view to_hashable(const T& value, char*&) {
        return value;
    }

}  // namespace detail

// Version tag we prepend to encrypted-for-blinded-user messages.  This is here so we can detect if
// some future version changes the format (and if not even try to load it).
inline constexpr unsigned char BLINDED_ENCRYPT_VERSION = 0;

std::vector<unsigned char> sign_for_recipient(
        uspan ed25519_privkey, uspan recipient_pubkey, uspan message) {
    cleared_uc64 ed_sk_from_seed;
    if (ed25519_privkey.size() == 32) {
        uc32 ignore_pk;
        crypto_sign_ed25519_seed_keypair(
                ignore_pk.data(), ed_sk_from_seed.data(), ed25519_privkey.data());
        ed25519_privkey = {ed_sk_from_seed.data(), ed_sk_from_seed.size()};
    } else if (ed25519_privkey.size() != 64) {
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    }
    // If prefixed, drop it (and do this for the caller, too) so that everything after this
    // doesn't need to worry about whether it is prefixed or not.
    if (recipient_pubkey.size() == 33 && recipient_pubkey.front() == 0x05)
        recipient_pubkey = recipient_pubkey.subspan(1);
    else if (recipient_pubkey.size() != 32)
        throw std::invalid_argument{
                "Invalid recipient_pubkey: expected 32 bytes (33 with 05 prefix)"};

    std::vector<unsigned char> buf;
    buf.reserve(message.size() + 96);  // 32+32 now, but 32+64 when we reuse it for the sealed box
    buf.insert(buf.end(), message.begin(), message.end());
    buf.insert(buf.end(), ed25519_privkey.subspan(32).begin(), ed25519_privkey.subspan(32).end());  // [32:] of a libsodium full seed value is the *pubkey*
    buf.insert(buf.end(), recipient_pubkey.begin(), recipient_pubkey.end());

    uc64 sig;
    if (0 != crypto_sign_ed25519_detached(
                     sig.data(), nullptr, buf.data(), buf.size(), ed25519_privkey.data()))
        throw std::runtime_error{"Failed to sign; perhaps the secret key is invalid?"};

    // We have M||A||Y for the sig, but now we want M||A||SIG so drop Y then append SIG:
    buf.resize(buf.size() - 32);
    buf.insert(buf.end(), sig.begin(), sig.end());

    return buf;
}

static const uspan BOX_HASHKEY = to_unsigned_sv("SessionBoxEphemeralHashKey"sv);

std::vector<unsigned char> encrypt_for_recipient(
        uspan ed25519_privkey, uspan recipient_pubkey, uspan message) {

    auto signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message);

    if (recipient_pubkey.size() == 33)
        recipient_pubkey = recipient_pubkey.subspan(1);  // sign_for_recipient already checked that this is the proper 0x05 prefix when present.

    std::vector<unsigned char> result;
    result.resize(signed_msg.size() + crypto_box_SEALBYTES);
    if (0 != crypto_box_seal(
                     result.data(), signed_msg.data(), signed_msg.size(), recipient_pubkey.data()))
        throw std::runtime_error{"Sealed box encryption failed"};

    return result;
}

std::vector<unsigned char> encrypt_for_recipient_deterministic(
        uspan ed25519_privkey, uspan recipient_pubkey, uspan message) {

    auto signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message);

    if (recipient_pubkey.size() == 33)
        recipient_pubkey = recipient_pubkey.subspan(1);  // sign_for_recipient already checked that this is the proper 0x05 when present.

    // To make our ephemeral seed we're going to hash: SENDER_SEED || RECIPIENT_PK || MESSAGE with a
    // keyed blake2b hash.
    cleared_array<crypto_box_SEEDBYTES> seed;
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, BOX_HASHKEY.data(), BOX_HASHKEY.size(), seed.size());
    crypto_generichash_blake2b_update(&st, ed25519_privkey.data(), 32);
    crypto_generichash_blake2b_update(&st, recipient_pubkey.data(), 32);
    crypto_generichash_blake2b_update(&st, message.data(), message.size());
    crypto_generichash_blake2b_final(&st, seed.data(), seed.size());

    cleared_array<crypto_box_SECRETKEYBYTES> eph_sk;
    cleared_array<crypto_box_PUBLICKEYBYTES> eph_pk;

    crypto_box_seed_keypair(eph_pk.data(), eph_sk.data(), seed.data());

    // The nonce for a sealed box is not passed but is implicitly defined as the (unkeyed) blake2b
    // hash of:
    //     EPH_PUBKEY || RECIPIENT_PUBKEY
    cleared_array<crypto_box_NONCEBYTES> nonce;
    crypto_generichash_blake2b_init(&st, nullptr, 0, nonce.size());
    crypto_generichash_blake2b_update(&st, eph_pk.data(), eph_pk.size());
    crypto_generichash_blake2b_update(&st, recipient_pubkey.data(), recipient_pubkey.size());
    crypto_generichash_blake2b_final(&st, nonce.data(), nonce.size());

    // A sealed box is a regular box (using the ephermal keys and nonce), but with the ephemeral
    // pubkey prepended:
    static_assert(crypto_box_SEALBYTES == crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES);

    std::vector<unsigned char> result;
    result.resize(crypto_box_SEALBYTES + signed_msg.size());
    std::memcpy(result.data(), eph_pk.data(), crypto_box_PUBLICKEYBYTES);
    if (0 != crypto_box_easy(
                     result.data() + crypto_box_PUBLICKEYBYTES,
                     signed_msg.data(),
                     signed_msg.size(),
                     nonce.data(),
                     recipient_pubkey.data(),
                     eph_sk.data()))
        throw std::runtime_error{"Crypto box encryption failed"};

    return result;
}

// Calculate the shared encryption key, sending from blinded sender kS (k = S's blinding factor) to
// blinded receiver jR (j = R's blinding factor).
//
// The sender knows s, k, S, and jR, but not j/R individually.
// The receiver knows r, j, R, and kS, but not k/S individually.
//
// From the sender's perspective, then, we compute:
//
// BLAKE2b(s k[jR] || kS || [jR])
//
// The receiver can calulate the same value via:
//
// BLAKE2b(r j[kS] || [kS] || jR)
//
// (which will be the same because sR = rS, and so skjR = kjsR = kjrS = rjkS).
//
// For 15 blinding, however, the blinding factor depended only on the SOGS server pubkey, and so `j
// = k`, and so for *15* keys we don't do the double-blinding (i.e. the first terms above drop the
// double-blinding factors and become just sjR and rkS).
//
// Arguments.  "A" and "B" here are either sender and receiver, or receiver and sender, depending on
// the value of `sending`.
//
// seed -- A's 32-byte secret key (can also be 64 bytes; only the first 32 are used).
// kA -- A's 33-byte blinded id, beginning with 0x15 or 0x25
// jB -- A's 33-byte blinded id, beginning with 0x15 or 0x25 (must be the same prefix as kA).
// server_pk -- the server's pubkey (needed to compute A's `k` value)
// sending -- true if this for a message from A to B, false if this is from B to A.
static cleared_uc32 blinded_shared_secret(
        uspan seed, uspan kA, uspan jB, uspan server_pk, bool sending) {

    // Because we're doing this generically, we use notation a/A/k for ourselves and b/jB for the
    // other person; this notion keeps everything exactly as above *except* for the concatenation in
    // the BLAKE2b hashed value: there we have to use kA || jB if we are the sender, but reverse the
    // order to jB || kA if we are the receiver.

    std::pair<uc32, cleared_uc32> blinded_key_pair;
    cleared_uc32 k;

    if (seed.size() != 64 && seed.size() != 32)
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    if (server_pk.size() != 32)
        throw std::invalid_argument{"Invalid server_pk: expected 32 bytes"};
    if (kA.size() != 33)
        throw std::invalid_argument{"Invalid local blinded id: expected 33 bytes"};
    if (jB.size() != 33)
        throw std::invalid_argument{"Invalid remote blinded id: expected 33 bytes"};
    if (kA[0] == 0x15 && jB[0] == 0x15)
        blinded_key_pair = blind15_key_pair(seed, server_pk, &k);
    else if (kA[0] == 0x25 && jB[0] == 0x25)
        blinded_key_pair = blind25_key_pair(seed, server_pk, &k);
    else
        throw std::invalid_argument{"Both ids must start with the same 0x15 or 0x25 prefix"};

    bool blind25 = kA[0] == 0x25;

    kA = kA.subspan(1);
    jB = jB.subspan(1);

    cleared_uc32 ka;
    // Not really switching to x25519 here, this is just an easy way to compute `a`
    crypto_sign_ed25519_sk_to_curve25519(ka.data(), seed.data());

    if (blind25)
        // Multiply a by k, so that we end up computing kajB = kjaB, which the other side can
        // compute as jkbA.
        crypto_core_ed25519_scalar_mul(ka.data(), ka.data(), k.data());
    // Else for 15 blinding we leave "ka" as just a, because j=k and so we don't need the
    // double-blind.

    cleared_uc32 shared_secret;
    if (0 != crypto_scalarmult_ed25519_noclamp(shared_secret.data(), ka.data(), jB.data()))
        throw std::runtime_error{"Shared secret generation failed"};

    auto& sender = sending ? kA : jB;
    auto& recipient = sending ? jB : kA;

    // H(kjsR || kS || jR):
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, nullptr, 0, 32);
    crypto_generichash_blake2b_update(&st, shared_secret.data(), shared_secret.size());
    crypto_generichash_blake2b_update(&st, sender.data(), sender.size());
    crypto_generichash_blake2b_update(&st, recipient.data(), recipient.size());
    crypto_generichash_blake2b_final(&st, shared_secret.data(), shared_secret.size());

    return shared_secret;
}

std::vector<unsigned char> encrypt_for_blinded_recipient(
        uspan ed25519_privkey,
        uspan server_pk,
        uspan recipient_blinded_id,
        uspan message) {
    if (ed25519_privkey.size() != 64 && ed25519_privkey.size() != 32)
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    if (server_pk.size() != 32)
        throw std::invalid_argument{"Invalid server_pk: expected 32 bytes"};
    if (recipient_blinded_id.size() != 33)
        throw std::invalid_argument{"Invalid recipient_blinded_id: expected 33 bytes"};

    // Generate the blinded key pair & shared encryption key
    std::pair<uc32, cleared_uc32> blinded_key_pair;
    switch (recipient_blinded_id[0]) {
        case 0x15: blinded_key_pair = blind15_key_pair(ed25519_privkey, server_pk); break;

        case 0x25: blinded_key_pair = blind25_key_pair(ed25519_privkey, server_pk); break;

        default:
            throw std::invalid_argument{
                    "Invalid recipient_blinded_id: must start with 0x15 or 0x25"};
    }
    std::vector<unsigned char> blinded_id;
    blinded_id.reserve(33);
    blinded_id.insert(blinded_id.end(), recipient_blinded_id.begin(), recipient_blinded_id.begin() + 1);
    blinded_id.insert(blinded_id.end(), blinded_key_pair.first.begin(), blinded_key_pair.first.end());

    auto enc_key = blinded_shared_secret(
            ed25519_privkey, blinded_id, recipient_blinded_id, server_pk, true);

    // Inner data: msg || A (i.e. the sender's ed25519 master pubkey, *not* kA blinded pubkey)
    std::vector<unsigned char> buf;
    buf.reserve(message.size() + 32);
    buf.insert(buf.end(), message.begin(), message.end());

    // append A (pubkey)
    if (ed25519_privkey.size() == 64) {
        buf.insert(buf.end(), ed25519_privkey.subspan(32).begin(), ed25519_privkey.subspan(32).end());
    } else {
        cleared_uc64 ed_sk_from_seed;
        uc32 ed_pk_buf;
        crypto_sign_ed25519_seed_keypair(
                ed_pk_buf.data(), ed_sk_from_seed.data(), ed25519_privkey.data());
        buf.insert(buf.end(), ed_pk_buf.begin(), ed_pk_buf.end());
    }

    // Encrypt using xchacha20-poly1305
    cleared_array<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> ciphertext;
    unsigned long long outlen = 0;
    ciphertext.resize(
            1 + buf.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES +
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // Prepend with a version byte, so that the recipient can reliably detect if a future version is
    // no longer encrypting things the way it expects.
    ciphertext[0] = BLINDED_ENCRYPT_VERSION;

    if (0 != crypto_aead_xchacha20poly1305_ietf_encrypt(
                     ciphertext.data() + 1,
                     &outlen,
                     buf.data(),
                     buf.size(),
                     nullptr,
                     0,
                     nullptr,
                     nonce.data(),
                     enc_key.data()))
        throw std::runtime_error{"Crypto aead encryption failed"};

    assert(outlen == ciphertext.size() - 1 - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // append the nonce, so that we have: data = b'\x00' + ciphertext + nonce
    std::memcpy(ciphertext.data() + (1 + outlen), nonce.data(), nonce.size());

    return ciphertext;
}

std::pair<std::vector<unsigned char>, std::string> decrypt_incoming_session_id(
        uspan ed25519_privkey, uspan ciphertext) {
    auto [buf, sender_ed_pk] = decrypt_incoming(ed25519_privkey, ciphertext);

    // Convert the sender_ed_pk to the sender's session ID
    std::array<unsigned char, 32> sender_x_pk;

    if (0 != crypto_sign_ed25519_pk_to_curve25519(sender_x_pk.data(), sender_ed_pk.data()))
        throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

    // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
    // the sender session ID
    std::string sender_session_id;
    sender_session_id.reserve(66);
    sender_session_id += "05";
    oxenc::to_hex(sender_x_pk.begin(), sender_x_pk.end(), std::back_inserter(sender_session_id));

    return {buf, sender_session_id};
}

std::pair<std::vector<unsigned char>, std::string> decrypt_incoming_session_id(
        uspan x25519_pubkey, uspan x25519_seckey, uspan ciphertext) {
    auto [buf, sender_ed_pk] = decrypt_incoming(x25519_pubkey, x25519_seckey, ciphertext);

    // Convert the sender_ed_pk to the sender's session ID
    std::array<unsigned char, 32> sender_x_pk;

    if (0 != crypto_sign_ed25519_pk_to_curve25519(sender_x_pk.data(), sender_ed_pk.data()))
        throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

    // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
    // the sender session ID
    std::string sender_session_id;
    sender_session_id.reserve(66);
    sender_session_id += "05";
    oxenc::to_hex(sender_x_pk.begin(), sender_x_pk.end(), std::back_inserter(sender_session_id));

    return {buf, sender_session_id};
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> decrypt_incoming(
        uspan ed25519_privkey, uspan ciphertext) {
    cleared_uc64 ed_sk_from_seed;
    if (ed25519_privkey.size() == 32) {
        uc32 ignore_pk;
        crypto_sign_ed25519_seed_keypair(
                ignore_pk.data(), ed_sk_from_seed.data(), ed25519_privkey.data());
        ed25519_privkey = {ed_sk_from_seed.data(), ed_sk_from_seed.size()};
    } else if (ed25519_privkey.size() != 64) {
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    }

    cleared_uc32 x_sec;
    uc32 x_pub;
    crypto_sign_ed25519_sk_to_curve25519(x_sec.data(), ed25519_privkey.data());
    crypto_scalarmult_base(x_pub.data(), x_sec.data());

    return decrypt_incoming({x_pub.data(), 32}, {x_sec.data(), 32}, ciphertext);
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> decrypt_incoming(
        uspan x25519_pubkey, uspan x25519_seckey, uspan ciphertext) {

    if (ciphertext.size() < crypto_box_SEALBYTES + 32 + 64)
        throw std::runtime_error{"Invalid incoming message: ciphertext is too small"};
    const size_t outer_size = ciphertext.size() - crypto_box_SEALBYTES;
    const size_t msg_size = outer_size - 32 - 64;

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> result;
    auto& [buf, sender_ed_pk] = result;

    buf.resize(outer_size);
    if (0 != crypto_box_seal_open(
                     buf.data(),
                     ciphertext.data(),
                     ciphertext.size(),
                     x25519_pubkey.data(),
                     x25519_seckey.data()))
        throw std::runtime_error{"Decryption failed"};

    uc64 sig;
    sender_ed_pk.resize(32);
    std::copy(buf.begin() + msg_size, buf.begin() + msg_size + 32, sender_ed_pk.begin());
    std::memcpy(sig.data(), buf.data() + msg_size + 32, 64);
    buf.resize(buf.size() - 64);  // Remove SIG, then append Y so that we get M||A||Y to verify
    buf.insert(buf.end(), x25519_pubkey.begin(), x25519_pubkey.begin() + 32);

    if (0 != crypto_sign_ed25519_verify_detached(
                     sig.data(), buf.data(), buf.size(), sender_ed_pk.data()))
        throw std::runtime_error{"Signature verification failed"};

    // Everything is good, so just drop A and Y off the message
    buf.resize(buf.size() - 32 - 32);

    return result;
}

std::pair<std::vector<unsigned char>, std::string> decrypt_from_blinded_recipient(
        uspan ed25519_privkey,
        uspan server_pk,
        uspan sender_id,
        uspan recipient_id,
        uspan ciphertext) {
    uc32 ed_pk_from_seed;
    cleared_uc64 ed_sk_from_seed;
    if (ed25519_privkey.size() == 32) {
        crypto_sign_ed25519_seed_keypair(
                ed_pk_from_seed.data(), ed_sk_from_seed.data(), ed25519_privkey.data());
        ed25519_privkey = {ed_sk_from_seed.data(), ed_sk_from_seed.size()};
    } else if (ed25519_privkey.size() == 64)
        std::memcpy(ed_pk_from_seed.data(), ed25519_privkey.data() + 32, 32);
    else
        throw std::invalid_argument{"Invalid ed25519_privkey: expected 32 or 64 bytes"};
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 1 +
                                    crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{
                "Invalid ciphertext: too short to contain valid encrypted data"};

    cleared_uc32 dec_key;
    auto blinded_id = recipient_id[0] == 0x25
                            ? blinded25_id_from_ed(to_sv(ed_pk_from_seed), server_pk)
                            : blinded15_id_from_ed(to_sv(ed_pk_from_seed), server_pk);

    if (sender_id == blinded_id)
        dec_key = blinded_shared_secret(ed25519_privkey, sender_id, recipient_id, server_pk, true);
    else
        dec_key = blinded_shared_secret(ed25519_privkey, recipient_id, sender_id, server_pk, false);

    std::pair<std::vector<unsigned char>, std::string> result;
    auto& [buf, sender_session_id] = result;

    // v, ct, nc = data[0], data[1:-24], data[-24:]
    if (ciphertext[0] != BLINDED_ENCRYPT_VERSION)
        throw std::invalid_argument{
                "Invalid ciphertext: version is not " + std::to_string(BLINDED_ENCRYPT_VERSION)};

    std::vector<unsigned char> nonce;
    const size_t msg_size =
            (ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES - 1 -
             crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (msg_size < 32)
        throw std::invalid_argument{"Invalid ciphertext: innerBytes too short"};
    buf.resize(msg_size);

    unsigned long long buf_len = 0;

    nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::memcpy(
            nonce.data(),
            ciphertext.data() + msg_size + 1 + crypto_aead_xchacha20poly1305_ietf_ABYTES,
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     buf.data(),
                     &buf_len,
                     nullptr,
                     ciphertext.data() + 1,
                     msg_size + crypto_aead_xchacha20poly1305_ietf_ABYTES,
                     nullptr,
                     0,
                     nonce.data(),
                     dec_key.data()))
        throw std::invalid_argument{"Decryption failed"};

    assert(buf_len == buf.size());

    // Split up: the last 32 bytes are the sender's *unblinded* ed25519 key
    uc32 sender_ed_pk;
    std::memcpy(sender_ed_pk.data(), buf.data() + (buf.size() - 32), 32);

    // Convert the sender_ed_pk to the sender's session ID
    uc32 sender_x_pk;
    if (0 != crypto_sign_ed25519_pk_to_curve25519(sender_x_pk.data(), sender_ed_pk.data()))
        throw std::runtime_error{"Sender ed25519 pubkey to x25519 pubkey conversion failed"};

    std::vector<unsigned char> session_id;  // Gets populated by the following ..._from_ed calls

    // Verify that the inner sender_ed_pk (A) yields the same outer kA we got with the message
    auto extracted_sender =
            recipient_id[0] == 0x25
                    ? blinded25_id_from_ed(to_sv(sender_ed_pk), server_pk, &session_id)
                    : blinded15_id_from_ed(to_sv(sender_ed_pk), server_pk, &session_id);

    bool matched = sender_id == extracted_sender;
    if (!matched && extracted_sender[0] == 0x15) {
        // With 15-blinding we might need the negative instead:
        extracted_sender[31] ^= 0x80;
        matched = sender_id == extracted_sender;
    }
    if (!matched)
        throw std::runtime_error{"Blinded sender id does not match the actual sender"};

    // Everything is good, so just drop the sender_ed_pk off the message and prepend the '05' prefix
    // to the sender session ID
    buf.resize(buf.size() - 32);
    sender_session_id.reserve(66);
    sender_session_id += "05";
    oxenc::to_hex(sender_x_pk.begin(), sender_x_pk.end(), std::back_inserter(sender_session_id));

    return result;
}

std::string decrypt_ons_response(
        std::string_view lowercase_name,
        uspan ciphertext,
        std::optional<uspan> nonce) {
    // Handle old Argon2-based encryption used before HF16
    if (!nonce) {
        if (ciphertext.size() < crypto_secretbox_MACBYTES)
            throw std::invalid_argument{"Invalid ciphertext: expected to be greater than 16 bytes"};

        uc32 key;
        std::array<unsigned char, crypto_pwhash_SALTBYTES> salt = {0};

        if (0 != crypto_pwhash(
                         key.data(),
                         key.size(),
                         lowercase_name.data(),
                         lowercase_name.size(),
                         salt.data(),
                         crypto_pwhash_OPSLIMIT_MODERATE,
                         crypto_pwhash_MEMLIMIT_MODERATE,
                         crypto_pwhash_ALG_ARGON2ID13))
            throw std::runtime_error{"Failed to generate key"};

        std::vector<unsigned char> msg;
        msg.resize(ciphertext.size() - crypto_secretbox_MACBYTES);
        std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce = {0};

        if (0 !=
            crypto_secretbox_open_easy(
                    msg.data(), ciphertext.data(), ciphertext.size(), nonce.data(), key.data()))
            throw std::runtime_error{"Failed to decrypt"};

        std::string session_id = oxenc::to_hex(msg.begin(), msg.end());
        return session_id;
    }

    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{"Invalid ciphertext: expected to be greater than 16 bytes"};
    if (nonce->size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
        throw std::invalid_argument{"Invalid nonce: expected to be 24 bytes"};

    // Hash the ONS name using BLAKE2b
    //
    // xchacha-based encryption
    // key = H(name, key=H(name))
    uc32 key;
    uc32 name_hash;
    auto name_bytes = session::str_to_uspan(lowercase_name);
    crypto_generichash_blake2b(
            name_hash.data(), name_hash.size(), name_bytes.data(), lowercase_name.size(), nullptr, 0);
    crypto_generichash_blake2b(
            key.data(),
            key.size(),
            name_bytes.data(),
            lowercase_name.size(),
            name_hash.data(),
            name_hash.size());

    std::vector<unsigned char> buf;
    unsigned long long buf_len = 0;
    buf.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);

    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     buf.data(),
                     &buf_len,
                     nullptr,
                     ciphertext.data(),
                     ciphertext.size(),
                     nullptr,
                     0,
                     nonce->data(),
                     key.data()))
        throw std::runtime_error{"Failed to decrypt"};

    if (buf_len != 33)
        throw std::runtime_error{"Invalid decrypted value: expected to be 33 bytes"};

    std::string session_id = oxenc::to_hex(buf.begin(), buf.end());
    return session_id;
}

std::vector<unsigned char> decrypt_push_notification(uspan payload, uspan enc_key) {
    if (payload.size() <
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::invalid_argument{"Invalid payload: too short to contain valid encrypted data"};
    if (enc_key.size() != 32)
        throw std::invalid_argument{"Invalid enc_key: expected 32 bytes"};

    std::vector<unsigned char> buf;
    std::vector<unsigned char> nonce;
    const size_t msg_size =
            (payload.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES -
             crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    unsigned long long buf_len = 0;
    buf.resize(msg_size);
    nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::memcpy(nonce.data(), payload.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     buf.data(),
                     &buf_len,
                     nullptr,
                     payload.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                     payload.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                     nullptr,
                     0,
                     nonce.data(),
                     enc_key.data()))
        throw std::runtime_error{"Failed to decrypt; perhaps the secret key is invalid?"};

    // Removing any null padding bytes from the end
    if (auto pos = find_last_not_of(buf, (unsigned char)0); pos != std::string::npos)
        buf.resize(pos + 1);

    return buf;
}

template <typename Func, typename... T>
std::string compute_hash(Func hasher, const T&... args) {
    // Allocate a buffer of 20 bytes per integral value (which is the largest the any integral
    // value can be when stringified).
    std::array<
            char,
            (0 + ... +
             (std::is_integral_v<T> || std::is_same_v<T, std::chrono::system_clock::time_point>
                      ? 20
                      : 0))>
            buffer;
    auto* b = buffer.data();
    return hasher({detail::to_hashable(args, b)...});
}

std::string compute_hash_blake2b_b64(std::vector<std::string_view> parts) {
    constexpr size_t HASH_SIZE = 32;
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, HASH_SIZE);
    for (const auto& s : parts)
        crypto_generichash_update(
                &state, reinterpret_cast<const unsigned char*>(s.data()), s.size());
    std::array<unsigned char, HASH_SIZE> hash;
    crypto_generichash_final(&state, hash.data(), HASH_SIZE);

    std::string b64hash = oxenc::to_base64(hash.begin(), hash.end());
    // Trim padding:
    while (!b64hash.empty() && b64hash.back() == '=')
        b64hash.pop_back();
    return b64hash;
}

std::string compute_message_hash(
        const std::string_view pubkey_hex, int16_t ns, std::string_view data) {
    if (pubkey_hex.size() != 66)
        throw std::invalid_argument{
                "Invalid pubkey_hex: Expecting 66 character hex-encoded pubkey"};

    // This function is based on the `computeMessageHash` function on the storage-server used to
    // generate a message hash:
    // https://github.com/oxen-io/oxen-storage-server/blob/dev/oxenss/rpc/request_handler.cpp
    auto pubkey = oxenc::from_hex(pubkey_hex.substr(2));
    uint8_t netid_raw;
    oxenc::from_hex(pubkey_hex.begin(), pubkey_hex.begin() + 2, &netid_raw);
    char netid = static_cast<char>(netid_raw);

    std::array<char, 20> ns_buf;
    char* ns_buf_ptr = ns_buf.data();
    std::string_view ns_for_hash = ns != 0 ? detail::to_hashable(ns, ns_buf_ptr) : ""sv;

    auto decoded_data = oxenc::from_base64(data);

    return compute_hash(
            compute_hash_blake2b_b64,
            std::string_view{&netid, 1},
            pubkey,
            ns_for_hash,
            decoded_data);
}

}  // namespace session

using namespace session;

LIBSESSION_C_API bool session_encrypt_for_recipient_deterministic(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* recipient_pubkey,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    try {
        auto ciphertext = session::encrypt_for_recipient_deterministic(
                uspan{ed25519_privkey, 64},
                uspan{recipient_pubkey, 32},
                uspan{plaintext_in, plaintext_len});

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_encrypt_for_blinded_recipient(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* open_group_pubkey,
        const unsigned char* recipient_blinded_id,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    try {
        auto ciphertext = session::encrypt_for_blinded_recipient(
                uspan{ed25519_privkey, 64},
                uspan{open_group_pubkey, 32},
                uspan{recipient_blinded_id, 33},
                uspan{plaintext_in, plaintext_len});

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_incoming(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_incoming_session_id(
                uspan{ed25519_privkey, 64}, uspan{ciphertext_in, ciphertext_len});
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_incoming_legacy_group(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* x25519_pubkey,
        const unsigned char* x25519_seckey,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_incoming_session_id(
                uspan{x25519_pubkey, 32},
                uspan{x25519_seckey, 32},
                uspan{ciphertext_in, ciphertext_len});
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_for_blinded_recipient(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* open_group_pubkey,
        const unsigned char* sender_id,
        const unsigned char* recipient_id,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_from_blinded_recipient(
                uspan{ed25519_privkey, 64},
                uspan{open_group_pubkey, 32},
                uspan{sender_id, 33},
                uspan{recipient_id, 33},
                uspan{ciphertext_in, ciphertext_len});
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_ons_response(
        const char* name_in,
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* nonce_in,
        char* session_id_out) {
    try {
        std::optional<std::vector<unsigned char>> nonce;
        if (nonce_in)
            nonce.emplace(nonce_in, nonce_in + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        auto session_id = session::decrypt_ons_response(
                name_in, uspan{ciphertext_in, ciphertext_len}, nonce);

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_push_notification(
        const unsigned char* payload_in,
        size_t payload_len,
        const unsigned char* enc_key_in,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto plaintext = session::decrypt_push_notification(
                uspan{payload_in, payload_len}, uspan{enc_key_in, 32});

        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_compute_message_hash(
        const char* pubkey_hex_in, int16_t ns, const char* base64_data_in, char* hash_out) {
    try {
        auto hash = session::compute_message_hash(pubkey_hex_in, ns, base64_data_in);

        std::memcpy(hash_out, hash.c_str(), hash.size() + 1);
        return true;
    } catch (...) {
        return false;
    }
}
