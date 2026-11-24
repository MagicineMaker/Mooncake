// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

namespace mooncake::tcp_sockmap {

using Socket = asio::ip::tcp::socket;
using Ready = std::function<void(const std::string&)>;

inline bool enabled() {
    const char* dir = std::getenv("MC_SOCKMAP_DIR");
    return dir && *dir;
}

// Each run has one pool on 127.0.0.1. For its fixed listening endpoint,
// simultaneous client connections have distinct local TCP port numbers.
// Dual-stack listeners report the same address as ::ffff:127.0.0.1.
inline bool replayAddress(const asio::ip::address& address) {
    const auto loopback = asio::ip::address_v4::loopback();
    if (address.is_v4()) return address.to_v4() == loopback;
    const auto v6 = address.to_v6();
    return v6.is_v4_mapped() &&
           asio::ip::make_address_v4(asio::ip::v4_mapped, v6) == loopback;
}

class PinnedMap {
   public:
    explicit PinnedMap(const char* name) {
        const std::string path =
            std::string(std::getenv("MC_SOCKMAP_DIR")) + "/" + name;
        union bpf_attr attr{};
        attr.pathname = reinterpret_cast<uintptr_t>(path.c_str());
        fd_ = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
        if (fd_ < 0)
            throw std::system_error(errno, std::generic_category(), path);

        // In particular, check value_size before LOOKUP writes a cookie.
        struct bpf_map_info info{};
        union bpf_attr query{};
        query.info.bpf_fd = fd_;
        query.info.info_len = sizeof(info);
        query.info.info = reinterpret_cast<uintptr_t>(&info);
        if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &query, sizeof(query)) <
            0) {
            const int error = errno;
            close(fd_);
            throw std::system_error(error, std::generic_category(), path);
        }
        if (info.type != BPF_MAP_TYPE_SOCKMAP || info.max_entries != 65536 ||
            info.key_size != sizeof(uint32_t) ||
            info.value_size != sizeof(uint64_t)) {
            close(fd_);
            throw std::runtime_error("Unexpected SOCKMAP layout: " + path);
        }
    }

    PinnedMap(const PinnedMap&) = delete;
    PinnedMap& operator=(const PinnedMap&) = delete;
    ~PinnedMap() { close(fd_); }

    void insert(uint32_t port, int socket_fd) const {
        uint64_t value = socket_fd;
        union bpf_attr attr{};
        attr.map_fd = fd_;
        attr.key = reinterpret_cast<uintptr_t>(&port);
        attr.value = reinterpret_cast<uintptr_t>(&value);
        attr.flags = BPF_NOEXIST;
        if (syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0)
            throw std::system_error(errno, std::generic_category(),
                                    "insert Mooncake data socket into SOCKMAP");
        // sock_map_close/unhash removes this socket's map links. Deleting by
        // numeric port during a late teardown could remove a new connection.
    }

    bool contains(uint32_t port) const {
        uint64_t cookie;
        union bpf_attr attr{};
        attr.map_fd = fd_;
        attr.key = reinterpret_cast<uintptr_t>(&port);
        attr.value = reinterpret_cast<uintptr_t>(&cookie);
        if (syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0)
            return true;
        if (errno == ENOENT) return false;
        throw std::system_error(errno, std::generic_category(),
                                "lookup peer in SOCKMAP");
    }

   private:
    int fd_;
};

inline uint32_t enroll(Socket& socket, bool initiator) {
    const char* role = std::getenv("MC_SOCKMAP_ROLE");
    if (!role || std::string(role) != (initiator ? "requester" : "owner"))
        throw std::runtime_error(
            "Unexpected MC_SOCKMAP_ROLE for this data socket");
    const auto local = socket.local_endpoint();
    const auto peer = socket.remote_endpoint();
    if (!replayAddress(local.address()) || !replayAddress(peer.address()))
        throw std::runtime_error(
            "Mooncake replay SOCKMAP requires 127.0.0.1 on both endpoints");
    const uint32_t key = initiator ? local.port() : peer.port();
    PinnedMap(initiator ? "client_socks" : "server_socks")
        .insert(key, socket.native_handle());
    return key;
}

// The pool enrolls at accept and cannot send until it has received a request.
// Delay making a connected lane available until both sockets are in their maps.
// Timers run on the lane's executor, leaving its I/O thread free between
// probes.
class PeerWait : public std::enable_shared_from_this<PeerWait> {
   public:
    PeerWait(std::shared_ptr<Socket> socket, uint32_t key, Ready ready)
        : socket_(std::move(socket)),
          key_(key),
          ready_(std::move(ready)),
          timer_(socket_->get_executor()) {}

    void check() {
        std::string error;
        try {
            if (!socket_->is_open()) {
                error = "SOCKMAP data socket closed before peer enrollment";
            } else if (!peer_map_.contains(key_)) {
                if (std::chrono::steady_clock::now() < deadline_) {
                    timer_.expires_after(std::chrono::milliseconds(1));
                    timer_.async_wait(
                        [self = shared_from_this()](asio::error_code ec) {
                            if (ec)
                                self->ready_(ec.message());
                            else
                                self->check();
                        });
                    return;
                }
                error = "Timed out waiting for SOCKMAP pool socket";
            }
        } catch (const std::exception& e) {
            error = e.what();
        }
        ready_(error);
    }

   private:
    PinnedMap peer_map_{"server_socks"};
    std::shared_ptr<Socket> socket_;
    uint32_t key_;
    Ready ready_;
    asio::steady_timer timer_;
    const std::chrono::steady_clock::time_point deadline_ =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
};

}  // namespace mooncake::tcp_sockmap
