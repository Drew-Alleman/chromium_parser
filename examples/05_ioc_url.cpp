// 06_iocs.cpp   [moderate]
//
// Pull every unique URL the parser saw across the whole installation (history,
// bookmarks, downloads, logins, cache, ...) into a flat indicator list -- the kind
// of artifact you'd feed to a threat-intel lookup. Optionally keep only URLs whose
// host contains a given substring, and write the result to iocs.txt.

#include <chromium_parser/profile.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// Crude host extractor: strip scheme, take up to the next '/'.
static std::string hostOf(const std::string& url) {
    auto p = url.find("://");
    std::size_t s = (p == std::string::npos) ? 0 : p + 3;
    auto e = url.find('/', s);
    return url.substr(s, (e == std::string::npos ? url.size() : e) - s);
}

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    if (argc < 2) {
        std::cerr << "usage: 06_iocs <User Data dir> [host-substring]\n";
        return 2;
    }

    Installation inst = CaptureInstallation(argv[1]);
    std::vector<std::string> urls = ListUniqueUrls(inst);

    const std::string filter = (argc >= 3) ? argv[2] : "";
    std::ofstream out("iocs.txt");
    std::size_t kept = 0;
    for (const auto& u : urls) {
        if (!filter.empty() && hostOf(u).find(filter) == std::string::npos)
            continue;
        out << u << "\n";
        ++kept;
    }

    std::cout << kept << " of " << urls.size() << " unique URLs written to iocs.txt";
    if (!filter.empty()) std::cout << "  (host contains \"" << filter << "\")";
    std::cout << "\n";
    return 0;
}