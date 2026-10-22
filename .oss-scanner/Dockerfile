# Build image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
#
# The scanner builds this with network access, then audits the finished image with none. Everything
# the build or the test suite needs has to be fetched here: submodules, packages and any dependency
# CMake would otherwise download at configure time.

FROM debian:trixie@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308

ENV DEBIAN_FRONTEND=noninteractive

# The same system libraries CI's Debian builds link against. deb.session.foundation supplies the
# ones Debian lacks or ships too old (liboxen-quic, liboxenc); its signing key is the one in
# utils/, so it is copied in on its own ahead of the full checkout to keep this layer cacheable.
# deb.session.foundation redirects to https, which the bare image cannot verify until
# ca-certificates is installed from Debian's own mirror.
COPY utils/deb.session.foundation.gpg /etc/apt/trusted.gpg.d/
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && echo "deb https://deb.session.foundation trixie main" >/etc/apt/sources.list.d/session.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        git cmake make ninja-build pkg-config g++ \
        nlohmann-json3-dev libgnutls28-dev libprotobuf-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev \
        libevent-dev libfmt-dev liboxen-quic-dev liboxenc-dev libsodium-dev libspdlog-dev \
        libsqlite3-dev libutf8proc-dev libzstd-dev nettle-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# The scanner clones without submodules. All of them are needed, not only the ones this
# configuration compiles: external/CMakeLists.txt refuses to configure if any is missing or stale.
RUN git submodule update --init --recursive --depth 1 --jobs 8

# Debug, because libsession's threading and state checks are asserts that a release build drops.
# Live tests are left out: they talk to the real Session network, which the audit cannot reach.
# Warnings are not errors, so a newer compiler in the base image cannot fail the build outright.
#
# Even with system libraries, session-deps downloads a few tarballs (libsodium, zstd, simdutf,
# sqlite3mc) into the build tree at build time. They are kept in /opt/session-deps-sources so a
# fresh build directory, e.g. a sanitizer build, can be configured offline: copy them into
# <builddir>/static-deps-sources/src/ first and the hash-checked download is skipped.
RUN cmake -S /src -B /src/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="-fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer" \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_STATIC_DEPS=OFF \
        -DUSE_LTO=OFF \
        -DWARNINGS_AS_ERRORS=OFF \
        -DBUILD_LIVE_TESTS=OFF \
    && cmake --build /src/build -j"$(nproc)" \
    && mkdir -p /opt/session-deps-sources \
    && cp /src/build/static-deps-sources/src/*.tar.* /opt/session-deps-sources/

# A smoke test, not a gate: a failing test should reach the maintainers as a report, not as a
# build failure that stops the scan.
RUN cd /src/build \
    && (timeout 900 ./tests/testLogging && timeout 900 ./tests/testAll \
        || echo "WARNING: libsession tests reported failures")
