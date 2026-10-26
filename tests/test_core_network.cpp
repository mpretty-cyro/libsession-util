#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>
#include <thread>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;

TEST_CASE("Core can hold an optional Network interface", "[core][network]") {
    core::callbacks callbacks;
    auto db_path = std::filesystem::temp_directory_path() / "test_core_network.db";
    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);

    core::Core core{db_path, callbacks};

    SECTION("Network is initially null") {
        CHECK(core.network() == nullptr);
    }

    SECTION("Network can be set and retrieved") {
        auto network = std::make_unique<network::Network>(network::config::Config{});
        auto* attached = network.get();
        core.set_network(std::move(network));
        CHECK(core.network() == attached);
    }

    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);
}

TEST_CASE("A Network's hooks are set on its loop", "[network][hooks]") {
    MockNetwork net;
    using network::ConnectionStatus;

    std::vector<ConnectionStatus> seen;
    std::thread::id called_on;
    net.set_on_status_changed([&](ConnectionStatus status) {
        seen.push_back(status);
        called_on = std::this_thread::get_id();
    });

    TestHelper::network_status(net, ConnectionStatus::connecting);
    REQUIRE(seen == std::vector{ConnectionStatus::connecting});
    CHECK(called_on != std::this_thread::get_id());

    SECTION("a hook can replace itself from inside, without waiting on its own loop") {
        std::vector<ConnectionStatus> replaced;
        net.set_on_status_changed([&](ConnectionStatus) {
            net.set_on_status_changed([&](ConnectionStatus status) { replaced.push_back(status); });
        });
        TestHelper::network_status(net, ConnectionStatus::connected);
        TestHelper::network_status(net, ConnectionStatus::disconnected);
        CHECK(replaced == std::vector{ConnectionStatus::disconnected});
    }

    SECTION("an empty hook clears it") {
        net.set_on_status_changed(nullptr);
        TestHelper::network_status(net, ConnectionStatus::connected);
        CHECK(seen == std::vector{ConnectionStatus::connecting});
    }
}
