// 02_limits.cpp   [simple]
//
// How to control how many rows each large store returns, via CaptureOptions.
// You do NOT need to set any of these -- a plain CaptureInstallation(dir) uses the
// defaults. `history` and `downloads` default to 200 rows (the History DB can be
// enormous); the rest are uncapped. Set a field to 0 for "everything", or to N to
// cap at N.

#include <chromium_parser/profile.h>

#include <iostream>

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    if (argc < 2) {
        std::cerr << "usage: 02_limits <path to \"User Data\" dir>\n";
        return 2;
    }

    CaptureOptions opts;
    opts.history = 1000;  // raise the history cap from the default 200
    opts.downloads = 0;     // 0 = no cap: every download row

    Installation inst = CaptureInstallation(argv[1], opts);

    for (const auto& p : inst.profiles())
        std::cout << "profile [" << p.identity().key << "]  "
        << p.history().entries.size() << " history rows, "
        << p.downloads().size() << " downloads\n";
    return 0;
}