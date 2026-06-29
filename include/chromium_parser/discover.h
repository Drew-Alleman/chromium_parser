#ifndef CHROMIUM_PARSER_DISCOVER_H_
#define CHROMIUM_PARSER_DISCOVER_H_
//
// Optional helper: locate Chromium-family browser profiles on a system so callers
// don't have to hard-code paths. Each result points at a "User Data" directory that
// can be handed straight to CaptureInstallation(). Discovery is lightweight -- it only
// finds WHERE profiles live; it does not parse them.
//
#include <chromium_parser/profile.h>

#include <filesystem>
#include <string>
#include <vector>

namespace chromiumprofile {

    // A discovered browser profile location (not yet captured). Deliberately small --
    // it's just a labeled path, not the heavyweight Installation that CaptureInstallation
    // returns.
    struct BrowserInstall {
        std::string           browser;      // "Google Chrome", "Google Chrome (Beta)", "Brave", ...
        std::string           user;         // OS account it belongs to ("" if unknown / live single-user)
        std::filesystem::path userDataDir;  // pass straight to CaptureInstallation()
    };

    // Find Chromium-family "User Data" directories.
    //   systemRoot empty -> scan the LIVE machine for the current user (host OS only).
    //   systemRoot set    -> treat it as a mounted image / acquired tree: enumerate every
    //                        user under it, trying BOTH Windows and Linux layouts.
    // Only directories that exist and look like a Chromium profile are returned. One entry
    // per browser install; use CaptureInstallation() to expand it into individual profiles.
    std::vector<BrowserInstall> DiscoverInstalls(const std::filesystem::path& systemRoot = {});

}  // namespace chromiumprofile

#endif  // CHROMIUM_PARSER_DISCOVER_H_