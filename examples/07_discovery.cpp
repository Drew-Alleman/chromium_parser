// 11_discover.cpp   [moderate]
//
// Auto-discover Chromium-family browser profiles instead of passing a path by hand.
// With no argument it scans the LIVE machine for the current user; pass a path to treat
// it as a mounted image / acquired tree and enumerate every user under it. Each install
// that's found is then captured and summarized -- discovery only locates profiles, so
// CaptureInstallation does the actual parsing.

#include <chromium_parser/discover.h>
#include <chromium_parser/profile.h>

#include <filesystem>
#include <iostream>
#include <vector>

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    // No arg -> live machine, current user. One arg -> a mounted image / acquired root.
    std::filesystem::path root;
    if (argc >= 2) root = argv[1];

    std::vector<BrowserInstall> installs = DiscoverInstalls(root);

    if (installs.empty()) {
        std::cout << "No Chromium-family profiles found"
            << (root.empty() ? " on this machine.\n" : " under that path.\n");
        return 0;
    }

    std::cout << "Found " << installs.size() << " browser install(s):\n\n";
    for (const auto& in : installs) {
        std::cout << "== " << in.browser;
        if (!in.user.empty()) std::cout << "  (user: " << in.user << ")";
        std::cout << " ==\n   " << in.userDataDir.string() << "\n";

        // Hand the discovered path straight to CaptureInstallation. Wrapped in try/catch
        // because an unusual layout (e.g. Opera) may not parse cleanly.
        try {
            Installation inst = CaptureInstallation(in.userDataDir);
            std::cout << "   " << inst.profiles().size() << " profile(s)";
            if (!inst.chromeVersion().empty())
                std::cout << ", version " << inst.chromeVersion();
            std::cout << "\n";
            for (const auto& p : inst.profiles())
                std::cout << "     - [" << p.identity().key << "] "
                << (p.identity().name.empty() ? "(unnamed)" : p.identity().name)
                << (p.isSignedIn() ? "  (signed in)" : "") << "\n";
        }
        catch (const std::exception& e) {
            std::cout << "   (capture failed: " << e.what() << ")\n";
        }
        std::cout << "\n";
    }
    return 0;
}