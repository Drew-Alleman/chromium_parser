// 09_accounts.cpp   [moderate]
//
// Account overview across all profiles: who is signed in, with which Google account,
// and whether the profile is enterprise-managed (a non-empty hosted domain means the
// account belongs to a managed Workspace org) or a supervised/child account. None of
// this requires decrypting anything -- it's all plaintext profile metadata.

#include <chromium_parser/profile.h>

#include <iostream>

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    if (argc < 2) {
        std::cerr << "usage: 09_accounts <User Data dir>\n";
        return 2;
    }

    Installation inst = CaptureInstallation(argv[1]);
    std::cout << inst.brand() << "  (" << inst.profiles().size() << " profile(s))\n";

    for (const auto& p : inst.profiles()) {
        const auto& id = p.identity();
        std::cout << "\n[" << id.key << "] "
            << (id.name.empty() ? "(unnamed)" : id.name) << "\n";

        if (!p.isSignedIn()) {
            std::cout << "    not signed in\n";
            continue;
        }

        std::cout << "    signed in: "
            << (id.userName.empty() ? "(no email on record)" : id.userName) << "\n"
            << "    gaia id:   " << id.gaiaId << "\n";
        if (id.isConsentedPrimaryAccount)
            std::cout << "    primary (sync-consented) account\n";
        if (!id.hostedDomain.empty())
            std::cout << "    [!] enterprise-managed domain: " << id.hostedDomain << "\n";
        if (!id.managedUserID.empty())
            std::cout << "    [!] supervised / managed user\n";
        if (id.isEphemeral)
            std::cout << "    ephemeral (guest-like) profile\n";
    }
    return 0;
}