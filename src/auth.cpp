#include "auth.h"

#include "date.h"

extern "C"
{
#include "logger.h"
#include "socks5.h"
}

#include <algorithm>
#include <chrono>
#include <fstream>
#include <map>
#include <string>
#include <vector>

char g_auth_db[4096];

struct user
{
    std::string name;
    std::string password;
    size_t traffic{0};
};

using auth_map = std::map<std::string, user>;

const auth_map &get_auth()
{
    static const auth_map auth = []()
    {
        auth_map auth;
        std::ifstream ifile(g_auth_db);
        if (!ifile)
        {
            logger_fatal("cannot read auth db\n");
            exit(1);
        }
        while (1)
        {
            std::string n, p;
            ifile >> n;
            if (!ifile)
                break;
            ifile >> p;
            auth[n].name = n;
            auth[n].password = p;
        }
        return auth;
    }();
    return auth;
}

extern "C"
int auth_check(struct socks5_userpass_req *req, struct socks5_client_conn *client)
{
    auto &m = get_auth();
    auto i = m.find(req->username);
    if (i == m.end() || i->second.password != req->password)
        return 0;
    client->u = (user*)&i->second;
    return 1;
}

extern "C"
void add_traffic(struct socks5_client_conn *client, int len)
{
    using namespace std::chrono;
    using namespace std::chrono_literals;

    auto now = steady_clock::now();
    static auto cl = now;
    if (now - cl > 1min)
    {
        cl = now;
        static const std::string fn = date::format("%F %T", floor<milliseconds>(system_clock::now()));
        std::ofstream ofile("/tmp/socks5_stats_" + fn + ".txt");
        if (ofile)
        {
            std::vector<user> users;
            for (auto &[_, u] : get_auth())
                users.push_back(u);
            /*std::sort(users.begin(), users.end(), [](const auto &u1, const auto &u2) {
                return u1.traffic > u2.traffic;
            });*/
            for (auto &u : users)
            {
                ofile.width(10);
                ofile << u.name << ": " << u.traffic << "\n";
            }
        }
        logger_fatal("cannot write to stats file\n");
        //exit(1);
    }

    client->u->traffic += len;
}
