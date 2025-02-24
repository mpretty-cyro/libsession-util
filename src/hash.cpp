#include "session/hash.hpp"

#include <sodium/crypto_generichash_blake2b.h>

#include "session/export.h"
#include "session/util.hpp"

namespace session::hash {

ustring hash(const size_t size, uspan msg, std::optional<uspan> key) {
    if (size < crypto_generichash_blake2b_BYTES_MIN || size > crypto_generichash_blake2b_BYTES_MAX)
        throw std::invalid_argument{"Invalid size: expected between 16 and 64 bytes (inclusive)"};

    if (key && key->size() > crypto_generichash_blake2b_BYTES_MAX)
        throw std::invalid_argument{"Invalid key: expected less than 65 bytes"};

    auto result_code = 0;
    ustring result;
    result.resize(size);

    result_code = crypto_generichash_blake2b(
            result.data(),
            size,
            msg.data(),
            msg.size(),
            key ? key->data() : nullptr,
            key ? key->size() : 0);

    if (result_code != 0)
        throw std::runtime_error{"Hash generation failed"};

    return result;
}

}  // namespace session::hash

using session::ustring;
using session::uspan;

extern "C" {

LIBSESSION_C_API bool session_hash(
        size_t size,
        const unsigned char* msg_in,
        size_t msg_len,
        const unsigned char* key_in,
        size_t key_len,
        unsigned char* hash_out) {
    try {
        std::optional<uspan> key;

        if (key_in && key_len)
            key = {key_in, key_len};

        ustring result = session::hash::hash(size, {msg_in, msg_len}, key);
        std::memcpy(hash_out, result.data(), size);
        return true;
    } catch (...) {
        return false;
    }
}

}  // extern "C"
