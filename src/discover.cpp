//
// Chromium-family browser-profile discovery. See discover.h.
//
// Each browser/channel is a rule: a per-user base directory plus the path segments that
// lead to its "User Data" directory. To add a browser, add a row to the table -- no other
// code changes. (macOS is intentionally omitted for now; it would be a third table.)
//
#include <chromium_parser/discover.h>

#include <cstdlib>
#include <string>
#include <system_error>
#include <vector>

namespace chromiumprofile {
    namespace fs = std::filesystem;
    namespace {

        std::string GetEnv(const char* name) {
#ifdef _MSC_VER
            char* buf = nullptr; size_t len = 0;
            if (_dupenv_s(&buf, &len, name) == 0 && buf) {
                std::string v(buf); std::free(buf); return v;
            }
            return {};
#else
            const char* v = std::getenv(name);
            return v ? std::string(v) : std::string{};
#endif
        }

        // Which per-user base directory a rule hangs off.
        enum class Base { WinLocal, WinRoaming, LinuxConfig, LinuxHome };

        struct BrandRule {
            const char* browser;
            const char* channel;  // "" for none
            Base                      base;
            std::vector<const char*>  seg;       // appended to the resolved base dir
        };

        // ---- Windows (LocalAppData unless noted) ------------------------------------
        const std::vector<BrandRule>& WindowsRules() {
            static const std::vector<BrandRule> r = {
                {"Google Chrome",  "",        Base::WinLocal,   {"Google", "Chrome", "User Data"}},
                {"Google Chrome",  "Beta",    Base::WinLocal,   {"Google", "Chrome Beta", "User Data"}},
                {"Google Chrome",  "Dev",     Base::WinLocal,   {"Google", "Chrome Dev", "User Data"}},
                {"Google Chrome",  "Canary",  Base::WinLocal,   {"Google", "Chrome SxS", "User Data"}},
                {"Chromium",       "",        Base::WinLocal,   {"Chromium", "User Data"}},
                {"Microsoft Edge", "",        Base::WinLocal,   {"Microsoft", "Edge", "User Data"}},
                {"Microsoft Edge", "Beta",    Base::WinLocal,   {"Microsoft", "Edge Beta", "User Data"}},
                {"Microsoft Edge", "Dev",     Base::WinLocal,   {"Microsoft", "Edge Dev", "User Data"}},
                {"Microsoft Edge", "Canary",  Base::WinLocal,   {"Microsoft", "Edge SxS", "User Data"}},
                {"Brave",          "",        Base::WinLocal,   {"BraveSoftware", "Brave-Browser", "User Data"}},
                {"Brave",          "Beta",    Base::WinLocal,   {"BraveSoftware", "Brave-Browser-Beta", "User Data"}},
                {"Brave",          "Nightly", Base::WinLocal,   {"BraveSoftware", "Brave-Browser-Nightly", "User Data"}},
                {"Vivaldi",        "",        Base::WinLocal,   {"Vivaldi", "User Data"}},
                {"Yandex",         "",        Base::WinLocal,   {"Yandex", "YandexBrowser", "User Data"}},
                // Opera keeps its profile under Roaming and the folder itself IS the profile
                // dir (no User Data/Default nesting) -- discovery finds it, but capture may
                // need Opera-specific handling.
                {"Opera",          "",        Base::WinRoaming, {"Opera Software", "Opera Stable"}},
                {"Opera GX",       "",        Base::WinRoaming, {"Opera Software", "Opera GX Stable"}},
            };
            return r;
        }

        // ---- Linux (~/.config unless noted) -----------------------------------------
        const std::vector<BrandRule>& LinuxRules() {
            static const std::vector<BrandRule> r = {
                {"Google Chrome",  "",        Base::LinuxConfig, {"google-chrome"}},
                {"Google Chrome",  "Beta",    Base::LinuxConfig, {"google-chrome-beta"}},
                {"Google Chrome",  "Dev",     Base::LinuxConfig, {"google-chrome-unstable"}},
                {"Chromium",       "",        Base::LinuxConfig, {"chromium"}},
                {"Microsoft Edge", "",        Base::LinuxConfig, {"microsoft-edge"}},
                {"Microsoft Edge", "Beta",    Base::LinuxConfig, {"microsoft-edge-beta"}},
                {"Microsoft Edge", "Dev",     Base::LinuxConfig, {"microsoft-edge-dev"}},
                {"Brave",          "",        Base::LinuxConfig, {"BraveSoftware", "Brave-Browser"}},
                {"Brave",          "Beta",    Base::LinuxConfig, {"BraveSoftware", "Brave-Browser-Beta"}},
                {"Vivaldi",        "",        Base::LinuxConfig, {"vivaldi"}},
                {"Opera",          "",        Base::LinuxConfig, {"opera"}},
                {"Yandex",         "",        Base::LinuxConfig, {"yandex-browser"}},
                // Snap relocates everything under ~/snap/<app>/...
                {"Chromium (Snap)", "",       Base::LinuxHome,   {"snap", "chromium", "common", "chromium"}},
                // Flatpak relocates under ~/.var/app/<app-id>/config/...
                {"Google Chrome (Flatpak)", "", Base::LinuxHome, {".var", "app", "com.google.Chrome", "config", "google-chrome"}},
                {"Chromium (Flatpak)", "",    Base::LinuxHome,   {".var", "app", "org.chromium.Chromium", "config", "chromium"}},
                {"Brave (Flatpak)", "",       Base::LinuxHome,   {".var", "app", "com.brave.Browser", "config", "BraveSoftware", "Brave-Browser"}},
                {"Microsoft Edge (Flatpak)", "", Base::LinuxHome,{".var", "app", "com.microsoft.Edge", "config", "microsoft-edge"}},
            };
            return r;
        }

        // A directory counts as a Chromium profile root if it has a Local State file
        // (Chrome/Edge/Brave/Opera) or a Default profile subdirectory.
        bool LooksLikeUserData(const fs::path& p) {
            std::error_code ec;
            if (!fs::is_directory(p, ec)) return false;
            if (fs::exists(p / "Local State", ec)) return true;
            if (fs::is_directory(p / "Default", ec)) return true;
            return false;
        }

        std::string DisplayName(const BrandRule& r) {
            std::string n = r.browser;
            if (r.channel && r.channel[0]) { n += " ("; n += r.channel; n += ")"; }
            return n;
        }

        fs::path ResolveBase(Base b, const fs::path& winLocal, const fs::path& winRoaming,
            const fs::path& linuxConfig, const fs::path& linuxHome) {
            switch (b) {
            case Base::WinLocal:    return winLocal;
            case Base::WinRoaming:  return winRoaming;
            case Base::LinuxConfig: return linuxConfig;
            case Base::LinuxHome:   return linuxHome;
            }
            return {};
        }

        // Apply a rule table against one user's set of base directories. Empty bases are
        // skipped, so the Linux table is a no-op when only Windows bases are supplied and
        // vice versa.
        void Apply(const std::vector<BrandRule>& rules,
            const fs::path& winLocal, const fs::path& winRoaming,
            const fs::path& linuxConfig, const fs::path& linuxHome,
            const std::string& user, std::vector<BrowserInstall>& out) {
            for (const auto& r : rules) {
                fs::path base = ResolveBase(r.base, winLocal, winRoaming, linuxConfig, linuxHome);
                if (base.empty()) continue;
                fs::path p = base;
                for (const char* s : r.seg) p /= s;
                if (LooksLikeUserData(p))
                    out.push_back({ DisplayName(r), user, p });
            }
        }

        // Immediate subdirectories of dir (the per-user folders), permission-safe.
        std::vector<fs::path> Subdirs(const fs::path& dir) {
            std::vector<fs::path> v;
            std::error_code ec;
            if (!fs::is_directory(dir, ec)) return v;
            for (const auto& e : fs::directory_iterator(
                dir, fs::directory_options::skip_permission_denied, ec)) {
                std::error_code ec2;
                if (e.is_directory(ec2)) v.push_back(e.path());
            }
            return v;
        }

    }  // namespace

    std::vector<BrowserInstall> DiscoverInstalls(const fs::path& systemRoot) {
        std::vector<BrowserInstall> out;

        if (systemRoot.empty()) {
            // ---- LIVE machine, current user, host OS only ----
#ifdef _WIN32
            fs::path    local = GetEnv("LOCALAPPDATA");
            fs::path    roaming = GetEnv("APPDATA");
            std::string user = GetEnv("USERNAME");
            Apply(WindowsRules(), local, roaming, {}, {}, user, out);
#else
            fs::path    home = GetEnv("HOME");
            std::string xdg = GetEnv("XDG_CONFIG_HOME");
            fs::path    config = !xdg.empty() ? fs::path(xdg)
                : (home.empty() ? fs::path{} : home / ".config");
            std::string user = GetEnv("USER");
            Apply(LinuxRules(), {}, {}, config, home, user, out);
#endif
        }
        else {
            // ---- Mounted image / acquired tree: try BOTH layouts, every user ----
            // Windows: <root>/Users/<user>/AppData/{Local,Roaming}
            for (const fs::path& u : Subdirs(systemRoot / "Users")) {
                std::string user = u.filename().string();
                if (user == "Public" || user == "Default" ||
                    user == "Default User" || user == "All Users") continue;
                Apply(WindowsRules(),
                    u / "AppData" / "Local", u / "AppData" / "Roaming",
                    {}, {}, user, out);
            }
            // Linux: <root>/home/<user>  (+ /root)
            std::vector<fs::path> homes = Subdirs(systemRoot / "home");
            std::error_code ec;
            if (fs::exists(systemRoot / "root", ec)) homes.push_back(systemRoot / "root");
            for (const fs::path& h : homes) {
                std::string user = h.filename().string();
                Apply(LinuxRules(), {}, {}, h / ".config", h, user, out);
            }
        }
        return out;
    }

}  // namespace chromiumprofile