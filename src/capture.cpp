//
// Orchestration plus the JSON-sourced readers: Local State (installation-wide
// state + the per-profile identities), Preferences (extensions), Bookmarks, and
// credential-store presence. This TU depends only on nlohmann; the SQLite,
// protobuf, and filesystem-copy concerns live in sibling TUs and are reached
// through internal.h.
//
#include <chromium_parser/profile.h>
#include "internal.h"
#include <algorithm>
#include <array>
#include <fstream>
#include <ostream>
#include <stdexcept>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <set>

#include <vector>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace chromiumprofile {

    namespace {

        std::string ReadFile(const fs::path& p) {
            std::ifstream f(p, std::ios::binary);
            return std::string((std::istreambuf_iterator<char>(f)),
                std::istreambuf_iterator<char>());
        }

        Timestamp ToTime(double unix_seconds) {
            return Timestamp(std::chrono::milliseconds(
                static_cast<int64_t>(unix_seconds * 1000.0)));
        }

        std::string GuessBrand(const fs::path& dir) {
            std::string s = ToLower(dir.string());  // ToLower from internal.h
            if (s.find("chromium") != std::string::npos) return "Chromium";
            if (s.find("edge") != std::string::npos) return "Edge";
            if (s.find("brave") != std::string::npos) return "Brave";
            if (s.find("chrome") != std::string::npos) return "Chrome";
            return "Unknown";
        }

        // Accept whatever the user points at and find the User Data root -- the dir
        // that actually contains 'Local State'. Handles: the root itself; a profile
        // dir under it (Default, "Profile 1", ...); the browser dir whose child is
        // "User Data"; or the 'Local State' file itself. Also strips a stray trailing
        // quote/space that PowerShell leaves when a quoted path ends in a backslash
        // (`"...\User Data\"` -> the \" is an escaped quote, so the arg keeps a
        // literal trailing ").
        fs::path ResolveUserDataRoot(const fs::path& input) {
            std::string raw = input.string();
            auto strip = [](char c) {
                return c == '"' || c == '\'' || c == ' ' ||
                    c == '\t' || c == '\r' || c == '\n';
                };
            while (!raw.empty() && strip(raw.back()))  raw.pop_back();
            while (!raw.empty() && strip(raw.front())) raw.erase(raw.begin());
            fs::path p(raw);
            std::error_code ec;

            if (p.filename() == "Local State" && fs::is_regular_file(p, ec))
                return p.parent_path();                         // the file itself
            if (fs::exists(p / "Local State", ec))
                return p;                                       // already the root
            if (fs::exists(p / "User Data" / "Local State", ec))
                return p / "User Data";                         // the browser dir
            if (fs::exists(p.parent_path() / "Local State", ec))
                return p.parent_path();                         // a profile dir
            return p;                                           // caller emits the error
        }

        // Local State JSON -> installation-wide fields + one Profile per info_cache
        // entry, with the full ProfileIdentity populated.
        void ReadLocalState(const json& ls, Installation& inst) {
            if (auto m = ls.find("user_experience_metrics"); m != ls.end()) {
                auto& mi = inst.mutableMetrics();
                mi.clientId = m->value("client_id", "");
                if (m->contains("low_entropy_source") && (*m)["low_entropy_source"].is_number())
                    mi.lowEntropySource = (*m)["low_entropy_source"].get<int>();
                if (m->contains("stability") && (*m)["stability"].is_object()) {
                    const auto& st = (*m)["stability"];
                    mi.statsVersion = st.value("stats_version", "");
                    // The saved system profile: OS version, CPU, RAM, GPU, board.
                    // base64 -> raw protobuf; decoded in readers_sysprofile.cpp.
                    // Always read (the decoder needs no protobuf lib).
                    if (st.contains("saved_system_profile") &&
                        st["saved_system_profile"].is_string())
                        inst.mutableHost() = DecodeSystemProfile(
                            st["saved_system_profile"].get<std::string>());
                }
            }

            // os_crypt key: presence + size only, never the key itself.
            if (auto oc = ls.find("os_crypt");
                oc != ls.end() && oc->contains("encrypted_key") &&
                (*oc)["encrypted_key"].is_string()) {
                auto& k = inst.mutableOsCryptKey();
                k.present = true;
                k.keySize = (*oc)["encrypted_key"].get<std::string>().size();  // base64 length
            }

            json info_cache = json::object();
            if (ls.contains("profile") && ls["profile"].is_object()) {
                const auto& p = ls["profile"];
                if (p.contains("info_cache") && p["info_cache"].is_object())
                    info_cache = p["info_cache"];
                if (p.contains("last_active_profiles") && p["last_active_profiles"].is_array())
                    inst.mutableLastActiveProfiles() =
                    p["last_active_profiles"].get<std::vector<std::string>>();
            }

            for (auto& [key, info] : info_cache.items()) {
                Profile prof;
                auto& id = prof.mutableIdentity();
                id.key = key;
                id.name = info.value("name", "");
                id.gaiaId = info.value("gaia_id", "");
                id.gaiaGivenName = info.value("gaia_given_name", "");
                id.gaiaPictureFilename = info.value("gaia_picture_file_name", "");
                id.userName = info.value("user_name", "");
                id.hostedDomain = info.value("hosted_domain", "");
                id.avatarIcon = info.value("avatar_icon", "");
                id.managedUserID = info.value("managed_user_id", "");
                id.shortcutName = info.value("shortcut_name", "");
                id.backgroundApps = info.value("background_apps", false);
                id.isEphemeral = info.value("is_ephemeral", false);
                id.isConsentedPrimaryAccount = info.value("is_consented_primary_account", false);
                id.forceSigninProfileLockout = info.value("force_signin_profile_locked", false);
                if (info.contains("active_time") && info["active_time"].is_number())
                    id.activeTime = ToTime(info["active_time"].get<double>());

                prof.setDir(inst.userDataDir() / key);
                inst.mutableProfiles().push_back(std::move(prof));
            }
        }

        // Preferences + Secure Preferences JSON -> extensions (with permissions).
        // Modern Chrome keeps extension state in "Secure Preferences" (HMAC-protected);
        // older/other builds use "Preferences". Read whichever exist and merge.
        void ReadPreferences(Profile& prof, const CaptureCtx& diag) {
            auto ingest = [&](const fs::path& prefs_path) {
                std::error_code ec;
                if (!fs::exists(prefs_path, ec)) return;

                json prefs;
                try {
                    prefs = json::parse(ReadFile(prefs_path));
                }
                catch (...) {
                    diag.warn("preferences",
                        "could not parse " + prefs_path.filename().string());
                    return;
                }

                if (!prefs.contains("extensions")) return;
                const auto& exts = prefs["extensions"];
                if (!exts.contains("settings") || !exts["settings"].is_object()) return;

                for (auto& [id, e] : exts["settings"].items()) {
                    bool seen = false;
                    for (const auto& x : prof.extensions())
                        if (x.id == id) { seen = true; break; }
                    if (seen) continue;

                    Extension x;
                    x.id = id;
                    if (e.contains("manifest") && e["manifest"].is_object()) {
                        const auto& m = e["manifest"];
                        x.name = m.value("name", "");
                        x.version = m.value("version", "");
                        x.updateUrl = m.value("update_url", "");
                        auto collect = [&](const char* field) {
                            if (m.contains(field) && m[field].is_array())
                                for (const auto& p : m[field])
                                    if (p.is_string()) x.permissions.push_back(p.get<std::string>());
                            };
                        collect("permissions");
                        collect("host_permissions");  // MV3
                    }
                    x.state = e.value("state", 1);
                    x.location = e.value("location", 0);
                    // 5 = COMPONENT, 10 = EXTERNAL_COMPONENT -> shipped with the browser
                    x.isComponent = (x.location == 5 || x.location == 10);
                    x.enabled = (x.state == 1);
                    x.fromWebStore = e.value("from_webstore", false);
                    x.installedByDefault = e.value("was_installed_by_default", false);
                    x.installedByOem = e.value("was_installed_by_oem", false);
                    prof.mutableExtensions().push_back(std::move(x));
                }
                };

            ingest(prof.dir() / "Preferences");
            ingest(prof.dir() / "Secure Preferences");
        }

        // Bookmarks JSON -> flattened bookmark list.
        void ReadBookmarks(Profile& prof, const CaptureCtx& diag) {
            fs::path bm_path = prof.dir() / "Bookmarks";
            std::error_code ec;
            if (!fs::exists(bm_path, ec)) return;

            json doc;
            try {
                doc = json::parse(ReadFile(bm_path));
            }
            catch (...) {
                diag.warn("bookmarks", "could not parse Bookmarks file");
                return;
            }
            if (!doc.contains("roots") || !doc["roots"].is_object()) return;

            // date_added is microseconds since 1601-01-01 (NOT Unix), as a string.
            // Convert to Unix ms: subtract the 1601->1970 gap (11644473600 s).
            auto chromeTimeToTs = [](const json& node) -> std::optional<Timestamp> {
                if (!node.contains("date_added") || !node["date_added"].is_string())
                    return std::nullopt;
                try {
                    long long micros = std::stoll(node["date_added"].get<std::string>());
                    long long unix_ms = micros / 1000 - 11644473600000LL;
                    // date_added=0 (default/imported bookmarks) produces a pre-1970
                    // timestamp (~year 1601). Treat as absent rather than storing
                    // a bogus date that crashes localtime on Windows.
                    if (unix_ms < 0) return std::nullopt;
                    return Timestamp(std::chrono::milliseconds(unix_ms));
                }
                catch (...) { return std::nullopt; }
                };

            // recursive walk: url nodes -> Bookmark, folders -> recurse children
            std::function<void(const json&)> walk = [&](const json& node) {
                if (!node.is_object()) return;
                const std::string type = node.value("type", "");
                if (type == "url") {
                    Bookmark b;
                    b.title = node.value("name", "");
                    b.url = node.value("url", "");
                    b.dateAdded = chromeTimeToTs(node);
                    prof.mutableBookmarks().push_back(std::move(b));
                }
                else if (type == "folder" && node.contains("children") &&
                    node["children"].is_array()) {
                    for (const auto& child : node["children"]) walk(child);
                }
                };

            for (const char* root : { "bookmark_bar", "other", "synced" }) {
                if (doc["roots"].contains(root)) walk(doc["roots"][root]);
            }
        }

        // Security-relevant Preferences flags. Reads Preferences and Secure
        // Preferences and takes whichever defines each key (Secure is authoritative).
        // optional<bool> keeps an absent key (Chrome default) distinct from a false.
        void ReadSecurityPosture(Profile& prof, const CaptureCtx&) {
            auto& sp = prof.mutableSecurity();
            auto scan = [&](const fs::path& prefs_path) {
                std::error_code ec;
                if (!fs::exists(prefs_path, ec)) return;
                json prefs;
                try { prefs = json::parse(ReadFile(prefs_path)); }
                catch (...) { return; }
                auto getBool = [&](std::initializer_list<const char*> path,
                    std::optional<bool>& dst) {
                        const json* cur = &prefs;
                        for (const char* k : path) {
                            if (!cur->is_object() || !cur->contains(k)) return;
                            cur = &(*cur)[k];
                        }
                        if (cur->is_boolean()) dst = cur->get<bool>();
                    };
                getBool({ "safebrowsing", "enabled" }, sp.safeBrowsingEnabled);
                getBool({ "safebrowsing", "enhanced" }, sp.safeBrowsingEnhanced);
                getBool({ "credentials_enable_service" }, sp.passwordSavingEnabled);
                getBool({ "profile", "password_manager_leak_detection" }, sp.leakDetectionEnabled);
                };
            scan(prof.dir() / "Preferences");
            scan(prof.dir() / "Secure Preferences");
        }

        // Network Persistent State (under <profile>/Network) -> the server inventory
        // Chrome keeps for HTTP/2 + QUIC. Each entry is a recent origin with protocol
        // hints and smoothed RTT. FORENSIC: plaintext, and survives both "clear
        // browsing history" and "clear cache" -- the History db being empty does not
        // empty this. JSON, so it stays in this nlohmann-only TU.
        void ReadNetworkState(Profile& prof, const CaptureCtx&) {
            fs::path p = prof.dir() / "Network" / "Network Persistent State";
            std::error_code ec;
            if (!fs::exists(p, ec)) return;
            json doc;
            try { doc = json::parse(ReadFile(p)); }
            catch (...) { return; }

            auto net = doc.find("net");
            if (net == doc.end() || !net->is_object()) return;
            auto hsp = net->find("http_server_properties");
            if (hsp == net->end() || !hsp->is_object()) return;

            auto& ns = prof.mutableNetworkState();
            ns.present = true;
            if (auto it = hsp->find("servers"); it != hsp->end() && it->is_array()) {
                for (const auto& srv : *it) {
                    if (!srv.is_object()) continue;
                    NetworkServer s;
                    s.server = srv.value("server", "");
                    s.supportsSpdy = srv.value("supports_spdy", false);
                    if (auto a = srv.find("alternative_service");
                        a != srv.end() && a->is_array() && !a->empty())
                        s.hasAltSvc = true;
                    if (auto st = srv.find("network_stats");
                        st != srv.end() && st->is_object() &&
                        st->contains("srtt") && (*st)["srtt"].is_number())
                        s.srttMicros = (*st)["srtt"].get<int>();
                    if (!s.server.empty()) ns.servers.push_back(std::move(s));
                }
            }
            if (auto it = hsp->find("broken_alternative_services");
                it != hsp->end() && it->is_array()) {
                for (const auto& b : *it)
                    if (b.is_object()) {
                        std::string h = b.value("host", "");
                        if (!h.empty()) ns.brokenQuicHosts.push_back(std::move(h));
                    }
            }
        }

        // Credential-store presence/size only (Login Data / Cookies / Web Data).
        void ReadCredentialPresence(Profile& prof) {
            auto& cred = prof.mutableCredentials();
            for (const auto& s : CredStores())  // CredStores() from internal.h
                for (const char* rel : s.pathCandidates) {
                    fs::path p = prof.dir() / rel;
                    std::error_code ec;
                    if (fs::exists(p, ec)) { cred.*s.has = true; cred.*s.size = fs::file_size(p, ec); break; }
                }
        }

    }  // namespace

    // Credential-store descriptor table (declared in internal.h; the one definition
    // lives here, where ReadCredentialPresence is its primary consumer; dump.cpp
    // reads the same table).
    const std::vector<CredStoreDesc>& CredStores() {
        static const std::vector<CredStoreDesc> k = {
            {"Login Data", "login_data", {"Login Data"},
                &CredentialPresence::hasLoginData, &CredentialPresence::loginDataSize},
            {"Cookies",    "cookies",    {"Network/Cookies", "Cookies"},
                &CredentialPresence::hasCookies,  &CredentialPresence::cookiesSize},
            {"Web Data",   "web_data",   {"Web Data"},
                &CredentialPresence::hasWebData,  &CredentialPresence::webDataSize},
        };
        return k;
    }

    const Profile* Installation::findProfile(std::string_view key) const {
        for (const auto& p : profiles_)
            if (p.identity().key == key) return &p;
        return nullptr;
    }

    // === orchestrator ===========================================================

    std::vector<std::string> ListUniqueUrls(const Installation& inst) {
        std::set<std::string> uniq;
        for (const auto& p : inst.profiles())
            for (const auto& e : p.cacheEntries())
                if (!e.url.empty())
                    uniq.insert(e.url);
        return { uniq.begin(), uniq.end() };
    }

    Installation CaptureInstallation(const fs::path& input_dir,
        const CaptureOptions& opts) {
        const fs::path user_data_dir = ResolveUserDataRoot(input_dir);

        Installation inst;
        inst.setUserDataDir(user_data_dir);
        inst.setCapturedAt(std::chrono::system_clock::now());
        inst.setBrand(GuessBrand(user_data_dir));

        // Diagnostic context: always buffers into inst; also fires opts.onDiagnostic
        // in real time if the caller set one.  Passed by const-ref to every reader so
        // the library never touches std::cerr.
        const CaptureCtx diag{ inst.mutableDiagnostics(), &opts.onDiagnostic, &opts };

        // Chrome records the version that last wrote this profile in a plain-text
        // "Last Version" file. Read it early and log it: when a future Chrome changes
        // a schema and a reader starts returning nothing, this version is the single
        // most useful piece of context for diagnosing the drift.
        {
            std::error_code vec;
            const fs::path lv_path = user_data_dir / "Last Version";
            if (fs::exists(lv_path, vec)) {
                std::string ver = ReadFile(lv_path);
                const auto b = ver.find_first_not_of(" \t\r\n");
                const auto e = ver.find_last_not_of(" \t\r\n");
                ver = (b == std::string::npos) ? std::string() : ver.substr(b, e - b + 1);
                if (!ver.empty()) {
                    inst.setChromeVersion(ver);
                    diag.info("version", "Chrome Last Version: " + ver);
                }
            }
        }

        fs::path ls_path = user_data_dir / "Local State";
        if (!fs::exists(ls_path))
            throw std::runtime_error(
                "no 'Local State' found. Point at the 'User Data' dir (it contains "
                "'Local State'), a profile dir under it, the browser dir, or the "
                "'Local State' file itself. Tried: " + ls_path.string() +
                ".  (PowerShell: a trailing backslash before the closing quote, e.g. "
                "\"...\\User Data\\\", becomes an escaped quote and corrupts the "
                "path -- drop the trailing backslash.)");
        // Deliberate exception policy: the root is essential, so a bad Local State
        // aborts the whole capture. Per-profile readers below are best-effort.
        json ls = json::parse(ReadFile(ls_path));

        ReadLocalState(ls, inst);

        if (opts.decodeVariations) {
            if (auto it = ls.find("variations_compressed_seed");
                it != ls.end() && it->is_string())
                inst.mutableVariations() = DecodeVariations(it->get<std::string>());
        }

        for (auto& prof : inst.mutableProfiles()) {
            std::error_code ec;
            if (!fs::exists(prof.dir(), ec)) continue;
            ReadPreferences(prof, diag);
            ReadSecurityPosture(prof, diag);
            ReadBookmarks(prof, diag);
            ReadNetworkState(prof, diag);
            ReadCredentialPresence(prof);
            ReadLoginData(prof, diag);
            ReadHistory(prof, diag);
            ReadCookies(prof, diag);
            ReadDownloads(prof, diag);
            ReadWebData(prof, diag);
            ReadTopSites(prof, diag);
            ReadCache(prof, diag);
            ReadSyncData(prof, diag);
        }
        return inst;
    }



}  // namespace chromiumprofile