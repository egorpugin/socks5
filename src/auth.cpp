extern "C"
{
#include "logger.h"
#include "socks5.h"
}

#include <fstream>
#include <map>
#include <string>

char g_auth_db[4096];

using auth_map = std::map<std::string, std::string>;

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
            std::string l, p;
            ifile >> l;
            if (!ifile)
                break;
            ifile >> p;
            auth[l] = p;
        }
        return auth;
    }();
    return auth;
}

extern "C"
int auth_check(struct socks5_userpass_req *req)
{
    auto &m = get_auth();
    auto i = m.find(req->username);
    if (i == m.end() || i->second != req->password)
        return 0;
    return 1;
}
