#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <primitives/sw/main.h>

#include <iostream>
#include <print>
#include <ranges>
#include <variant>

using namespace std::literals;
namespace ip = boost::asio::ip;

template <typename T = void>
using task = boost::asio::awaitable<T>;

struct socket_pump {
    ip::tcp::socket s1, s2;
    int n_closed{};

    void run(auto &ctx) {
        auto stop_f = [&](auto eptr) {
            /*if (eptr) {
                std::cerr << std::format("socket s {} is out\n", (uintptr_t)s.native_handle());
                std::cerr << std::format("socket dst {} is out\n", (uintptr_t)dst.native_handle());
                try {
                    std::rethrow_exception(eptr);
                } catch (std::exception &e) {
                    std::cerr << e.what() << "\n";
                }
            }*/
            s1.close();
            s2.close();
            if (++n_closed == 2) {
                delete this;
            }
        };
        boost::asio::co_spawn(ctx, run(s1, s2), stop_f);
        boost::asio::co_spawn(ctx, run(s2, s1), stop_f);
    }

    task<> run(auto &s_from, auto &s_to) {
        uint8_t buffer[100*1024];
        uint64_t m{};
        while (1) {
            std::cerr << std::format("socket op recv {}\n", (uintptr_t)s_from.native_handle());
            auto n = co_await s_from.async_read_some(boost::asio::buffer(buffer, sizeof(buffer)), boost::asio::use_awaitable);
            if (!s_to.is_open()) {
                //break;
            }
            if (n > m) {
                m = n;
                std::cerr << std::format("max packet size = {}\n", m);
            }
            std::cerr << 5 << "\n";
            std::cerr << std::format("socket op send {}\n", (uintptr_t)s_to.native_handle());
            co_await s_to.async_send(boost::asio::buffer(buffer, n), boost::asio::use_awaitable);
        }
    }
};

// https://datatracker.ietf.org/doc/html/rfc1928
// https://datatracker.ietf.org/doc/html/rfc1929 user:password auth
struct socks5_server {
    enum auth_type : uint8_t {
        no_auth,
        gssapi,
        username_password,

        no_acceptable_auth = 0xff,
    };
    enum command_type : uint8_t {
        connect = 1,
        bind,
        udp_associate,
    };
    enum address_type : uint8_t {
        ipv4 = 1,
        domain_name = 3,
        ipv6 = 4,
    };
    struct request_head {
        uint8_t ver;
        command_type cmd;
        uint8_t reserved;
        address_type atype;
    };
    struct request {
        using ipv4 = std::array<uint8_t, 4>;
        using ipv6 = std::array<uint8_t, 16>;
        using domain_name = std::string;

        request_head h;
        std::variant<ipv4, ipv6, domain_name> dst_address;
        uint16_t port;
    };

    std::string ip;
    uint16_t port;

    void start(boost::asio::io_context &ctx) {
        boost::asio::co_spawn(ctx, run(), [](auto eptr) {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        });
    }

private:
    task<> run() {
        auto ex = co_await boost::asio::this_coro::executor;
        ip::tcp::endpoint e(ip::address_v4::from_string(ip), port);
        ip::tcp::acceptor a{ex, e};
        while (1) {
            auto c = co_await a.async_accept(boost::asio::use_awaitable);
            auto p = (uintptr_t)c.native_handle();
            std::cerr << std::format("new socket {}\n", p);
            boost::asio::co_spawn(ex, run(std::move(c)), [=](auto eptr) {
                std::cerr << std::format("socket {} is out\n", p);
                if (eptr) {
                    try {
                        //std::rethrow_exception(eptr);
                    } catch (std::exception &e) {
                        //std::cerr << e.what() << "\n";
                    }
                }
            });
        }
    }
    task<> run(ip::tcp::socket s) {
        constexpr uint8_t proxy_version = 0x05;
        auto ex = co_await boost::asio::this_coro::executor;
        std::vector<boost::asio::const_buffer> buffers;
        uint8_t c;
        co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
        if (c != proxy_version) {
            co_return;
        }
        co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
        constexpr auto auth_types_max = 10;
        if (c == 0 || c > auth_types_max) {
            auto ver = proxy_version;
            auto auth = auth_type::no_acceptable_auth;
            buffers.clear();
            buffers.emplace_back(boost::asio::buffer(&ver, sizeof(ver)));
            buffers.emplace_back(boost::asio::buffer(&auth, sizeof(auth)));
            std::cerr << 1 << "\n";
            co_await s.async_send(buffers, boost::asio::use_awaitable);
            co_return;
        }
        auth_type atypes[auth_types_max];
        co_await boost::asio::async_read(s, boost::asio::buffer(atypes, c), boost::asio::use_awaitable);
        bool ok{};
        for (int i = 0; i < c; ++i) {
            if (atypes[i] == auth_type::username_password) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            co_return;
        }

        // reply
        {
            auto ver = proxy_version;
            auto auth = auth_type::username_password;
            buffers.clear();
            buffers.emplace_back(boost::asio::buffer(&ver, sizeof(ver)));
            buffers.emplace_back(boost::asio::buffer(&auth, sizeof(auth)));
            std::cerr << 2 << "\n";
            co_await s.async_send(buffers, boost::asio::use_awaitable);
        }

        // ver
        co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
        if (c != 1) {
            co_return;
        }
        // ulen
        co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
        char uname[255]{};
        co_await boost::asio::async_read(s, boost::asio::buffer(uname, c), boost::asio::use_awaitable);
        // plen
        co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
        char passwd[255]{};
        co_await boost::asio::async_read(s, boost::asio::buffer(passwd, c), boost::asio::use_awaitable);

        // check
        bool auth_ok{1};

        // auth reply
        {
            uint8_t auth_ver = 1;
            uint8_t auth_result = auth_ok ? 0 : 1;
            buffers.clear();
            buffers.emplace_back(boost::asio::buffer(&auth_ver, sizeof(auth_ver)));
            buffers.emplace_back(boost::asio::buffer(&auth_result, sizeof(auth_result)));
            std::cerr << 3 << "\n";
            co_await s.async_send(buffers, boost::asio::use_awaitable);
        }
        if (!auth_ok) {
            co_return;
        }

        request r;
        co_await boost::asio::async_read(s, boost::asio::buffer(&r.h, sizeof(r.h)), boost::asio::use_awaitable);

        switch (r.h.atype) {
        case address_type::ipv4: {
            request::ipv4 a;
            co_await boost::asio::async_read(s, boost::asio::buffer(&a, sizeof(a)), boost::asio::use_awaitable);
            r.dst_address = a;
            break;
        }
        case address_type::ipv6: {
            request::ipv6 a;
            co_await boost::asio::async_read(s, boost::asio::buffer(&a, sizeof(a)), boost::asio::use_awaitable);
            r.dst_address = a;
            break;
        }
        case address_type::domain_name: {
            request::domain_name a;
            co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
            a.resize(c);
            co_await boost::asio::async_read(s, boost::asio::buffer(a.data(), a.size()), boost::asio::use_awaitable);
            r.dst_address = a;
            break;
        }
        default:
            co_return;
        }
        co_await boost::asio::async_read(s, boost::asio::buffer(&r.port, sizeof(r.port)), boost::asio::use_awaitable);

        switch (r.h.cmd) {
        case command_type::connect:
            break;
        default:
            co_return;
        }

        if (auto p = std::get_if<request::domain_name>(&r.dst_address)) {
            ip::tcp::resolver res{ex};
            auto resp = co_await res.async_resolve(*p, std::to_string(std::byteswap(r.port)), boost::asio::use_awaitable);
            if (resp.empty()) {
                co_return;
            }
            for (auto &&re1 : resp) {
                r.dst_address = re1.endpoint().address().to_v4().to_bytes();
                break;
            }
        }

        auto &addr = std::get<request::ipv4>(r.dst_address);
        ip::tcp::endpoint e(ip::address_v4{addr}, std::byteswap(r.port));
        //ip::tcp::endpoint e2(ip::address_v6{std::get<request::ipv6>(r.dst_address)}, std::byteswap(r.port));
        ip::tcp::socket dst{ex};
        bool err{};
        try {
            co_await dst.async_connect(e, boost::asio::use_awaitable);
            std::cerr << std::format("new socket {}\n", (uintptr_t)dst.native_handle());
        } catch (std::exception &e) {
            err = true;
        }

        struct response_head {
            enum reply_type : uint8_t {
                success,
                socks_server_failure,
                connection_not_allowed_by_ruleset,
                network_unreachable,
                host_unreachable,
                connection_refused,
                ttl_expired,
                command_not_supported,
            };

            uint8_t ver{proxy_version};
            reply_type reply;
            uint8_t reserved;
            address_type atype;
        };
        response_head rh{};
        rh.reply = err ? response_head::reply_type::host_unreachable : response_head::reply_type::success;
        rh.atype = address_type::ipv4;
        auto raddr = std::byteswap(dst.local_endpoint().address().to_v4().to_uint());
        auto rport = std::byteswap(dst.local_endpoint().port());
        buffers.clear();
        buffers.emplace_back(boost::asio::buffer(&rh, sizeof(rh)));
        buffers.emplace_back(boost::asio::buffer(&raddr, sizeof(raddr)));
        buffers.emplace_back(boost::asio::buffer(&rport, sizeof(rport)));
        std::cerr << 4 << "\n";
        co_await s.async_send(buffers, boost::asio::use_awaitable);

        if (err) {
            co_return;
        }

        std::cerr << std::format("starting pumps: {} <-> {}\n", (uintptr_t)s.native_handle(), (uintptr_t)dst.native_handle());

        auto p = new socket_pump{std::move(s), std::move(dst)};
        p->run(ex);
    }
};

int main(int argc, char *argv[]) {
    boost::asio::io_context ctx;
    socks5_server serv{"0.0.0.0", 55001};
    serv.start(ctx);
    ctx.run();
    return 0;
}
