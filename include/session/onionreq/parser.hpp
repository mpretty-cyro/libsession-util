#pragma once

#include <session/types.hpp>

#include "hop_encryption.hpp"

namespace session::onionreq {

/// The default maximum size of an onion request accepted by the OnionReqParser constructor.
constexpr size_t DEFAULT_MAX_SIZE = 10'485'760;  // 10 MiB

class OnionReqParser {
  private:
    x25519_keypair keys;
    HopEncryption enc;
    EncryptType enc_type = EncryptType::aes_gcm;
    x25519_pubkey remote_pk;
    uspan payload_;

  public:
    /// Constructs a parser, parsing the given request sent to us.  Throws if parsing or decryption
    /// fails.
    OnionReqParser(
            uspan x25519_pubkey,
            uspan x25519_privkey,
            uspan req,
            size_t max_size = DEFAULT_MAX_SIZE);

    /// plaintext payload, decrypted from the incoming request during construction.
    uspan payload() const { return payload_; }

    uspan remote_pubkey() const { return span_to_span<unsigned char>(remote_pk.view()); }

    /// Encrypts a reply using the appropriate encryption as determined when parsing the
    /// request.
    uspan encrypt_reply(uspan reply) const;
};

}  // namespace session::onionreq
