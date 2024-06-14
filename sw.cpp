void build(Solution &s) {
    auto &socks5 = s.addExecutable("socks5");
    {
        auto &t = socks5;
        t.PackageDefinitions = true;
        t += cpplatest;
        t += "src/.*"_rr;
        t += "pub.egorpugin.primitives.sw.main"_dep;
        t += "org.sw.demo.boost.asio"_dep;
        t += "pub.egorpugin.primitives.templates2"_dep;
    }
}
