#pragma once

extern "C"
{
int auth_check(struct socks5_userpass_req *req, struct socks5_client_conn *client);
void add_traffic(struct socks5_client_conn *client, int len);
}
