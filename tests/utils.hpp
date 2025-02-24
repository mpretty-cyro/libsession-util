#pragma once

#include <oxenc/hex.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "session/config/base.h"

inline ustring operator""_bytes(const char* x, size_t n) {
    return {reinterpret_cast<const unsigned char*>(x), n};
}
inline ustring operator""_hexbytes(const char* x, size_t n) {
    ustring bytes;
    oxenc::from_hex(x, x + n, std::back_inserter(bytes));
    return bytes;
}

inline std::string to_hex(uspan bytes) {
    std::string hex;
    oxenc::to_hex(bytes.begin(), bytes.end(), std::back_inserter(hex));
    return hex;
}

inline constexpr auto operator""_kiB(unsigned long long kiB) {
    return kiB * 1024;
}

inline int64_t get_timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
}

inline std::string_view to_sv(uspan x) {
    return {reinterpret_cast<const char*>(x.data()), x.size()};
}
inline uspan to_usv(std::string_view x) {
    return {reinterpret_cast<const unsigned char*>(x.data()), x.size()};
}
template <size_t N>
uspan to_usv(const std::array<unsigned char, N>& data) {
    return {data.data(), N};
}

inline std::string printable(uspan x) {
    std::string p;
    for (auto c : x) {
        if (c >= 0x20 && c <= 0x7e)
            p += c;
        else
            p += "\\x" + oxenc::to_hex(&c, &c + 1);
    }
    return p;
}
inline std::string printable(std::string_view x) {
    return printable(to_usv(x));
}
std::string printable(const unsigned char* x) = delete;
inline std::string printable(const unsigned char* x, size_t n) {
    return printable({x, n});
}

template <typename Container>
std::set<typename Container::value_type> as_set(const Container& c) {
    return {c.begin(), c.end()};
}

template <typename... T>
std::set<std::common_type_t<T...>> make_set(T&&... args) {
    return {std::forward<T>(args)...};
}

template <typename C>
std::vector<std::basic_string_view<C>> view_vec(std::vector<std::basic_string<C>>&& v) = delete;
template <typename C>
std::vector<std::basic_string_view<C>> view_vec(const std::vector<std::basic_string<C>>& v) {
    std::vector<std::basic_string_view<C>> vv;
    vv.reserve(v.size());
    std::copy(v.begin(), v.end(), std::back_inserter(vv));
    return vv;
}

template <std::invocable Call, std::invocable<typename std::invoke_result_t<Call>> Validator>
auto eventually_impl(std::chrono::milliseconds timeout, Call&& f, Validator&& isValid)
        -> std::invoke_result_t<Call> {
    using ResultType = std::invoke_result_t<Call>;

    // If we already have a value then don't bother with the loop
    if (auto result = f(); isValid(result))
        return result;

    auto start = std::chrono::steady_clock::now();
    auto sleep_duration = std::chrono::milliseconds{10};
    while (std::chrono::steady_clock::now() - start < timeout) {
        std::this_thread::sleep_for(sleep_duration);

        if (auto result = f(); isValid(result))
            return result;
    }

    return ResultType{};
}

template <std::invocable Call, std::invocable<typename std::invoke_result_t<Call>> Validator>
bool always_impl(std::chrono::milliseconds duration, Call&& f, Validator&& isValid) {
    auto start = std::chrono::steady_clock::now();
    auto sleep_duration = std::chrono::milliseconds{10};
    while (std::chrono::steady_clock::now() - start < duration) {
        if (auto result = f(); !isValid(result))
            return false;
        std::this_thread::sleep_for(sleep_duration);
    }
    return true;
}

template <std::invocable Call>
    requires std::is_same_v<std::invoke_result_t<Call>, bool>
bool eventually_impl(std::chrono::milliseconds timeout, Call&& f) {
    return eventually_impl(timeout, f, [](bool result) { return result; });
}

template <std::invocable Call>
    requires std::is_same_v<
            std::invoke_result_t<Call>,
            std::vector<typename std::invoke_result_t<Call>::value_type>>
auto eventually_impl(std::chrono::milliseconds timeout, Call&& f) -> std::invoke_result_t<Call> {
    using ResultType = std::invoke_result_t<Call>;
    return eventually_impl(timeout, f, [](const ResultType& result) { return !result.empty(); });
}

template <std::invocable Call>
    requires std::is_same_v<std::invoke_result_t<Call>, bool>
bool always_impl(std::chrono::milliseconds duration, Call&& f) {
    return always_impl(duration, f, [](bool result) { return result; });
}

template <std::invocable Call>
    requires std::is_same_v<
            std::invoke_result_t<Call>,
            std::vector<typename std::invoke_result_t<Call>::value_type>>
bool always_impl(std::chrono::milliseconds duration, Call&& f) {
    using ResultType = std::invoke_result_t<Call>;
    return always_impl(duration, f, [](const ResultType& result) { return !result.empty(); });
}

#define EVENTUALLY(timeout, ...) eventually_impl(timeout, [&]() { return (__VA_ARGS__); })
#define ALWAYS(duration, ...) always_impl(duration, [&]() { return (__VA_ARGS__); })
