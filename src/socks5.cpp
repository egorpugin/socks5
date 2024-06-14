#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <primitives/sw/main.h>

#include <chrono>
#include <format>
#include <fstream>
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

    void run(auto &ctx, uint64_t &tx, uint64_t &rx) {
        auto stop_f = [&](auto &s) {
            return [&](auto eptr) {
                if (!eptr) {
                    return;
                }
                s.close();
                if (++n_closed == 2) {
                    delete this;
                }
            };
        };
        boost::asio::co_spawn(ctx, run(s1, s2, tx), stop_f(s1));
        boost::asio::co_spawn(ctx, run(s2, s1, rx), stop_f(s2));
    }
    task<> run(auto &s_from, auto &s_to, uint64_t &bytes) {
        uint8_t buffer[100*1024];
        while (1) {
            auto n = co_await s_from.async_read_some(boost::asio::buffer(buffer, sizeof(buffer)), boost::asio::use_awaitable);
            bytes += n;
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

        uint8_t ver{socks_version};
        reply_type reply;
        uint8_t reserved;
        address_type atype;
    };
    struct user_data {
        std::string password;
        uint64_t tx{};
        uint64_t rx{};
    };

    static inline constexpr uint8_t socks_version = 5; // socks5

    std::string ip;
    uint16_t port;
    std::unordered_map<std::string, user_data> auth;
    std::chrono::system_clock::time_point tp{std::chrono::system_clock::now()};

    void start(boost::asio::io_context &ctx) {
        boost::asio::co_spawn(ctx, run(), boost::asio::detached);
    }

private:
    task<> run() {
        auto ex = co_await boost::asio::this_coro::executor;
        ip::tcp::endpoint e(ip::address_v4::from_string(ip), port);
        ip::tcp::acceptor a{ex, e};
        while (1) {
            auto c = co_await a.async_accept(boost::asio::use_awaitable);
            auto p = (uintptr_t)c.native_handle();
            boost::asio::co_spawn(ex, run(std::move(c)), boost::asio::detached);
        }
    }
    task<> run(ip::tcp::socket s) {
        auto ex = co_await boost::asio::this_coro::executor;
        std::vector<boost::asio::const_buffer> buffers;
        uint8_t c;
        co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
        if (c != socks_version) {
            co_return;
        }
        co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
        if (c == 0) {
            auto ver = socks_version;
            auto auth = auth_type::no_acceptable_auth;
            buffers.clear();
            buffers.emplace_back(boost::asio::buffer(&ver, sizeof(ver)));
            buffers.emplace_back(boost::asio::buffer(&auth, sizeof(auth)));
            co_await s.async_send(buffers, boost::asio::use_awaitable);
            co_return;
        }
        constexpr auto auth_types_max = std::numeric_limits<uint8_t>::max();
        auth_type atypes[auth_types_max];
        auth_type atype = auth_type::no_acceptable_auth;
        co_await boost::asio::async_read(s, boost::asio::buffer(atypes, c), boost::asio::use_awaitable);
        for (int i = 0; i < c; ++i) {
            // disabled
            /*if (atypes[i] == auth_type::no_auth) {
                atype = atypes[i];
                break;
            }*/
            if (atypes[i] == auth_type::username_password) {
                atype = atypes[i];
                break;
            }
        }

        // reply
        {
            auto ver = socks_version;
            buffers.clear();
            buffers.emplace_back(boost::asio::buffer(&ver, sizeof(ver)));
            buffers.emplace_back(boost::asio::buffer(&atype, sizeof(atype)));
            co_await s.async_send(buffers, boost::asio::use_awaitable);
        }

        if (atype == auth_type::no_acceptable_auth) {
            co_return;
        }

        decltype(auth.find("")) it_user;

        if (atype == auth_type::username_password) {
            // ver
            co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
            if (c != 1) {
                co_return;
            }
            // ulen
            co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
            char uname[std::numeric_limits<uint8_t>::max() + 1]{};
            co_await boost::asio::async_read(s, boost::asio::buffer(uname, c), boost::asio::use_awaitable);
            // plen
            co_await boost::asio::async_read(s, boost::asio::buffer(&c, sizeof(c)), boost::asio::use_awaitable);
            char passwd[std::numeric_limits<uint8_t>::max() + 1]{};
            co_await boost::asio::async_read(s, boost::asio::buffer(passwd, c), boost::asio::use_awaitable);

            // check
            it_user = auth.find(uname);
            bool auth_ok = it_user != auth.end() && it_user->second.password == passwd;

            // auth reply
            {
                uint8_t auth_ver = 1;
                uint8_t auth_result = auth_ok ? 0 : 1;
                buffers.clear();
                buffers.emplace_back(boost::asio::buffer(&auth_ver, sizeof(auth_ver)));
                buffers.emplace_back(boost::asio::buffer(&auth_result, sizeof(auth_result)));
                co_await s.async_send(buffers, boost::asio::use_awaitable);
            }
            if (!auth_ok) {
                std::cerr << std::format("bad auth\n");
                co_return;
            }
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
            std::cerr << std::format("bad atype\n");
            co_return;
        }
        co_await boost::asio::async_read(s, boost::asio::buffer(&r.port, sizeof(r.port)), boost::asio::use_awaitable);

        switch (r.h.cmd) {
        case command_type::connect:
            break;
        default:
            std::cerr << std::format("unhandled command {}\n", (uint8_t)r.h.cmd);
            co_return;
        }

        if (auto p = std::get_if<request::domain_name>(&r.dst_address)) {
            ip::tcp::resolver res{ex};
            auto resp = co_await res.async_resolve(*p, std::to_string(std::byteswap(r.port)), boost::asio::use_awaitable);
            if (resp.empty()) {
                std::cerr << std::format("cannot resolve {}\n", *p);
                co_return;
            }
            for (auto &&re1 : resp) {
                auto &&a = re1.endpoint().address();
                if (a.is_v6()) {
                    continue;
                }
                r.dst_address = a.to_v4().to_bytes();
                break;
            }
            // no v4 found
            if (auto p = std::get_if<request::domain_name>(&r.dst_address)) {
                for (auto &&re1 : resp) {
                    r.dst_address = re1.endpoint().address().to_v6().to_bytes();
                    break;
                }
            }
        }
        if (auto p = std::get_if<request::ipv6>(&r.dst_address)) {
            std::cerr << std::format("cannot connect to ipv6\n");
            co_return; // not impl
        }

        auto &addr = std::get<request::ipv4>(r.dst_address);
        ip::tcp::endpoint e(ip::address_v4{addr}, std::byteswap(r.port));
        //ip::tcp::endpoint e2(ip::address_v6{std::get<request::ipv6>(r.dst_address)}, std::byteswap(r.port));
        ip::tcp::socket dst{ex};
        bool err{};
        try {
            co_await dst.async_connect(e, boost::asio::use_awaitable);
        } catch (std::exception &e) {
            err = true;
        }

        response_head rh{};
        rh.reply = err ? response_head::reply_type::host_unreachable : response_head::reply_type::success;
        rh.atype = address_type::ipv4;
        auto raddr = std::byteswap(dst.local_endpoint().address().to_v4().to_uint());
        auto rport = std::byteswap(dst.local_endpoint().port());
        buffers.clear();
        buffers.emplace_back(boost::asio::buffer(&rh, sizeof(rh)));
        buffers.emplace_back(boost::asio::buffer(&raddr, sizeof(raddr)));
        buffers.emplace_back(boost::asio::buffer(&rport, sizeof(rport)));
        co_await s.async_send(buffers, boost::asio::use_awaitable);

        if (err) {
            std::cerr << std::format("cannot connect to dest\n");
            co_return;
        }

        auto p = new socket_pump{std::move(s), std::move(dst)};
        p->run(ex, it_user->second.tx, it_user->second.rx);

        auto now = std::chrono::system_clock::now();
        if (now - tp > 10min) {
            tp = now;
            static const std::string fn = std::format("{:%F_%H-%M-%S}", now);
            if (std::ofstream ofile("socks5_stats_" + fn + ".txt"); ofile) {
                std::map<std::string, user_data> users(auth.begin(), auth.end());
                for (auto &[n,u] : users) {
                    ofile << std::format("{:10}: {}\n", n, u.rx);
                }
            }
        }
    }
};

int main(int argc, char *argv[]) {
    boost::asio::io_context ctx;
    socks5_server serv{"0.0.0.0", 55001,
    {
#if __has_include("../auth.txt")
#include "../auth.txt"
#endif
    }
    };
    serv.start(ctx);
    ctx.run();
    return 0;
}
