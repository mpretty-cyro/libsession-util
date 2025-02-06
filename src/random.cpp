#include "session/random.hpp"

#include <sodium/randombytes.h>

#include <algorithm>

#include "session/export.h"
#include "session/util.hpp"

namespace session {
// make this once, and only once, and use it where needed
CSRNG csrng = CSRNG{};
}  //  namespace session

namespace session::random {

constexpr char base32_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567";

ustring random(size_t size) {
    ustring result;
    result.resize(size);
    randombytes_buf(result.data(), size);

    return result;
}

std::string random_base32(size_t size) {
    std::string charset = base32_charset;
    std::string result;

    for (size_t i = 0; i < size; ++i) {
        std::shuffle(charset.begin(), charset.end(), csrng);
        result.push_back(charset[0]);
    }

    return result;
}

}  // namespace session::random

extern "C" {

LIBSESSION_C_API unsigned char* session_random(size_t size) {
    auto result = session::random::random(size);
    auto* ret = static_cast<unsigned char*>(malloc(size));
    std::memcpy(ret, result.data(), result.size());
    return ret;
}

}  // extern "C"
