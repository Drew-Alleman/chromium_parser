// 05_cache_hunt.cpp   [complex]
//
// Advanced cache hunting. Builds a CacheFilter with several constraints at once
// (text-only responses, an optional URL substring, 2xx status, and a needle that
// must appear in the decompressed body), runs SearchCache per profile, and prints
// each hit with a one-line body snippet plus the search statistics -- how many
// entries were eliminated cheaply vs. how many bodies actually had to be read.

#include <chromium_parser/profile.h>

#include <algorithm>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    if (argc < 3) {
        std::cerr << "usage: 05_cache_hunt <path to \"User Data\" dir> <needle> [url-substring]\n";
        return 2;
    }

    Installation inst = CaptureInstallation(argv[1]);

    CacheFilter f;
    f.dataOnly = true;          // only text-like responses (HTML/JSON/XML/text)
    f.needle = argv[2];       // must appear in the decompressed body
    f.statusMin = 200;           // 2xx only
    f.statusMax = 299;
    f.maxBodyBytes = 256 * 1024;    // cap per-entry decompression
    if (argc >= 4) f.urlContains = argv[3];  // optional URL narrowing

    for (const auto& prof : inst.profiles()) {
        CacheSearchResult r = SearchCache(prof, f);

        std::cout << "profile [" << prof.identity().key << "]: "
            << r.hits.size() << " hit(s)  ("
            << r.preFiltered << " pre-filtered, "
            << r.bodiesRead << " bodies read, "
            << r.needleMiss << " needle misses)\n";

        for (const auto& h : r.hits) {
            std::cout << "  " << h.statusCode << "  " << h.url << "\n";
            if (!h.body.empty()) {
                std::string snip = h.body.substr(0, std::min<std::size_t>(h.body.size(), 120));
                for (char& c : snip)
                    if (c == '\n' || c == '\r' || c == '\t') c = ' ';
                std::cout << "      " << snip << "\n";
            }
        }
    }
    return 0;
}