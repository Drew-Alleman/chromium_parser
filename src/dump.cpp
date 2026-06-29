//
// Serialization: the human-readable text dump and the machine-readable JSON dump,
// plus the extension-risk classification both of them surface. Depends only on
// nlohmann; reads the captured model, writes nothing back.
//
#include <chromium_parser/profile.h>
#include "internal.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace chromiumprofile {
    namespace {

        // ---- formatting helpers ----
        std::string FormatTime(const std::optional<Timestamp>& t) {
            if (!t) return "(unknown)";
            std::time_t tt = std::chrono::system_clock::to_time_t(*t);
            // Windows CRT localtime_s aborts on negative time_t (pre-1970).
            // Chrome stores some timestamps as 0 (default/imported bookmarks)
            // which converts to ~year 1601 after the epoch offset -- clamp those.
            if (tt < 0) return "(pre-1970)";
            std::tm tm{};
#ifdef _MSC_VER
            if (localtime_s(&tm, &tt) != 0) return "(invalid time)";
#else
            if (!localtime_r(&tt, &tm)) return "(invalid time)";
#endif
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
            return buf;
        }
        std::string FormatTime(Timestamp t) {
            return FormatTime(std::optional<Timestamp>(t));
        }

        std::string HumanBytes(std::uintmax_t n) {
            static const char* kU[] = { "B", "KB", "MB", "GB", "TB" };
            double d = static_cast<double>(n);
            int i = 0;
            while (d >= 1024.0 && i < 4) { d /= 1024.0; ++i; }
            char buf[40];
            if (i == 0) std::snprintf(buf, sizeof(buf), "%ju B", static_cast<std::uintmax_t>(n));
            else        std::snprintf(buf, sizeof(buf), "%.1f %s", d, kU[i]);
            return buf;
        }

        // ---- per-type JSON emitters: one field list per type, used by DumpJson ----
        json toJson(const DeviceInfo& d) {
            json j = { {"guid", d.guid}, {"client_name", d.clientName}, {"model", d.model},
                       {"manufacturer", d.manufacturer}, {"form_factor", d.formFactor},
                       {"hardware_class", d.hardwareClass},
                       {"chrome_version", d.chromeVersion}, {"os_type", d.osType} };
            if (d.lastUpdated) j["last_updated"] = FormatTime(d.lastUpdated);
            return j;
        }
        json toJson(const Extension& e) {
            json j = { {"id", e.id}, {"name", e.name}, {"version", e.version},
                       {"enabled", e.enabled}, {"state", e.state}, {"location", e.location},
                       {"is_component", e.isComponent},
                       {"from_webstore", e.fromWebStore},
                       {"installed_by_default", e.installedByDefault},
                       {"installed_by_oem", e.installedByOem} };
            if (!e.updateUrl.empty()) j["update_url"] = e.updateUrl;
            j["permissions"] = e.permissions;
            return j;
        }
        json toJson(const CookieDomain& c) {
            return { {"host", c.host}, {"cookie_count", c.cookieCount},
                     {"secure_count", c.secureCount}, {"http_only_count", c.httpOnlyCount},
                     {"session_count", c.sessionCount} };
        }
        json toJson(const DownloadEntry& d) {
            json j = { {"target_path", d.targetPath}, {"source_url", d.sourceUrl},
                       {"tab_url", d.tabUrl}, {"mime_type", d.mimeType},
                       {"danger_type", d.dangerType}, {"state", d.state},
                       {"total_bytes", d.totalBytes}, {"received_bytes", d.receivedBytes},
                       {"by_ext_id", d.byExtId}, {"by_ext_name", d.byExtName},
                       {"opened", d.opened} };
            if (d.startTime) j["start_time"] = FormatTime(d.startTime);
            return j;
        }
        json toJson(const Bookmark& b) {
            json j = { {"title", b.title}, {"url", b.url} };
            if (b.dateAdded) j["date_added"] = FormatTime(b.dateAdded);
            return j;
        }
        json toJson(const SavedLogin& s) {
            json j = { {"url", s.url}, {"username", s.username},
                       {"signon_realm", s.signonRealm}, {"times_used", s.timesUsed} };
            if (s.dateLastUsed) j["date_last_used"] = FormatTime(s.dateLastUsed);
            if (s.dateCreated)  j["date_created"] = FormatTime(s.dateCreated);
            return j;
        }
        json toJson(const HistoryEntry& h) {
            json j = { {"url", h.url}, {"title", h.title}, {"visit_count", h.visitCount},
                       {"typed_count", h.typedCount} };
            if (h.lastVisit) j["last_visit"] = FormatTime(h.lastVisit);
            return j;
        }
        json toJson(const NetworkServer& s) {
            json j = { {"server", s.server}, {"supports_spdy", s.supportsSpdy},
                       {"has_alt_svc", s.hasAltSvc} };
            if (s.srttMicros) j["srtt_micros"] = *s.srttMicros;
            return j;
        }
        json toJson(const AutofillAddress& a) {
            return { {"guid", a.guid}, {"full_name", a.fullName}, {"email", a.email},
                     {"phone", a.phone}, {"company_name", a.companyName},
                     {"street_address", a.streetAddress}, {"city", a.city},
                     {"state", a.state}, {"zip_code", a.zipCode},
                     {"country_code", a.countryCode} };
        }
        json toJson(const SavedCard& c) {
            return { {"name_on_card", c.nameOnCard}, {"last_four", c.lastFour},
                     {"network", c.network},
                     {"expiration_month", c.expirationMonth},
                     {"expiration_year", c.expirationYear}, {"nickname", c.nickname},
                     {"server_synced", c.serverSynced} };
        }
        json toJson(const SearchEngine& e) {
            return { {"short_name", e.shortName}, {"keyword", e.keyword},
                     {"url", e.searchUrl} };
        }
        json toJson(const TopSite& s) {
            return { {"url", s.url}, {"title", s.title}, {"rank", s.rank} };
        }
        json toJson(const CacheEntry& e) {
            json j = { {"url", e.url}, {"status", e.statusCode},
                       {"mime_type", e.mimeType},
                       {"response_body_size", e.responseBodySize} };
            if (e.requestTime)  j["request_time"] = FormatTime(e.requestTime);
            if (e.responseTime) j["response_time"] = FormatTime(e.responseTime);
            // All response headers as a flat array of {name, value} objects so
            // duplicate names (Set-Cookie, Link, etc.) are preserved.
            json hdrs = json::array();
            for (const auto& [k, v] : e.headers)
                hdrs.push_back({ {"name", k}, {"value", v} });
            j["headers"] = std::move(hdrs);
            // Body included as a string for text content; absent for binary/oversized.
            if (!e.body.empty()) j["body"] = e.body;
            return j;
        }

        bool IsSensitivePermission(std::string_view p) {
            static constexpr std::array<std::string_view, 12> kSensitive = {
                "<all_urls>",  "tabs",        "webRequest",  "webRequestBlocking",
                "cookies",     "history",     "debugger",    "proxy",
                "downloads",   "nativeMessaging", "management", "privacy" };
            return std::find(kSensitive.begin(), kSensitive.end(), p) != kSensitive.end();
        }

        // Provenance label from location + flags. Sideloaded / unpacked / policy
        // installs are the ones worth flagging; "webstore" is the benign baseline.
        // Manifest::Location: 2 external-pref, 3 external-registry, 4 unpacked(dev),
        // 5/10 component, 7/9 policy, 8 command-line.
        std::string ExtSource(const Extension& e) {
            switch (e.location) {
            case 4:           return "UNPACKED(dev)";
            case 3:           return "external-registry";
            case 2:           return "external-pref";
            case 7: case 9:   return "policy";
            case 5: case 10:  return "component";
            case 8:           return "command-line";
            default:          break;
            }
            if (e.fromWebStore) return "webstore";
            const bool cws = e.updateUrl.empty() ||
                e.updateUrl.find("clients2.google.com") != std::string::npos ||
                e.updateUrl.find("chrome.google.com") != std::string::npos;
            return cws ? "internal" : "sideloaded?";
        }

        // ---- CSV (RFC 4180) -------------------------------------------------------
        // Quote a field iff it contains a comma, double-quote, CR, or LF; double any
        // embedded quotes. CSV is byte-oriented, so (unlike the JSON path) a mangled-
        // UTF-8 title just passes through rather than throwing.
        std::string CsvField(const std::string& s) {
            if (s.find_first_of(",\"\r\n") == std::string::npos) return s;
            std::string out = "\"";
            for (char ch : s) { if (ch == '"') out += "\"\""; else out += ch; }
            out += '"';
            return out;
        }
        std::string CsvTime(const std::optional<Timestamp>& t) {
            return t ? FormatTime(*t) : std::string();   // empty cell when absent
        }

        // Per-record CSV rows: the record's own fields only, no header and no trailing
        // newline. DumpCsv prepends the profile column and emits the matching header.
        std::string toCsv(const DeviceInfo& d) {
            std::string r;
            r += CsvField(d.guid);          r += ',';
            r += CsvField(d.clientName);    r += ',';
            r += CsvField(d.model);         r += ',';
            r += CsvField(d.manufacturer);  r += ',';
            r += CsvField(d.formFactor);    r += ',';
            r += CsvField(d.hardwareClass); r += ',';
            r += CsvField(d.chromeVersion); r += ',';
            r += CsvField(d.osType);        r += ',';
            r += CsvTime(d.lastUpdated);
            return r;
        }
        std::string toCsv(const Extension& e) {
            std::string perms;
            for (std::size_t i = 0; i < e.permissions.size(); ++i)
                perms += (i ? ";" : "") + e.permissions[i];   // ';' separates perms in one cell
            std::string r;
            r += CsvField(e.id);            r += ',';
            r += CsvField(e.name);          r += ',';
            r += CsvField(e.version);       r += ',';
            r += e.enabled ? "true" : "false";      r += ',';
            r += std::to_string(e.state);   r += ',';
            r += std::to_string(e.location);r += ',';
            r += e.isComponent ? "true" : "false";  r += ',';
            r += e.fromWebStore ? "true" : "false"; r += ',';
            r += e.installedByDefault ? "true" : "false"; r += ',';
            r += e.installedByOem ? "true" : "false"; r += ',';
            r += CsvField(e.updateUrl);             r += ',';
            r += CsvField(perms);
            return r;
        }
        std::string toCsv(const CookieDomain& c) {
            std::string r;
            r += CsvField(c.host);                r += ',';
            r += std::to_string(c.cookieCount);   r += ',';
            r += std::to_string(c.secureCount);   r += ',';
            r += std::to_string(c.httpOnlyCount); r += ',';
            r += std::to_string(c.sessionCount);
            return r;
        }
        std::string toCsv(const DownloadEntry& d) {
            std::string r;
            r += CsvField(d.targetPath);          r += ',';
            r += CsvField(d.sourceUrl);           r += ',';
            r += CsvField(d.tabUrl);              r += ',';
            r += CsvField(d.mimeType);            r += ',';
            r += std::to_string(d.dangerType);    r += ',';
            r += std::to_string(d.state);         r += ',';
            r += std::to_string(d.totalBytes);    r += ',';
            r += std::to_string(d.receivedBytes); r += ',';
            r += CsvField(d.byExtId);             r += ',';
            r += CsvField(d.byExtName);           r += ',';
            r += d.opened ? "true" : "false";     r += ',';
            r += CsvTime(d.startTime);
            return r;
        }
        std::string toCsv(const HistoryEntry& h) {
            std::string r;
            r += CsvField(h.url);           r += ',';
            r += CsvField(h.title);         r += ',';
            r += std::to_string(h.visitCount); r += ',';
            r += std::to_string(h.typedCount); r += ',';
            r += CsvTime(h.lastVisit);
            return r;
        }
        std::string toCsv(const Bookmark& b) {
            std::string r;
            r += CsvField(b.title);         r += ',';
            r += CsvField(b.url);           r += ',';
            r += CsvTime(b.dateAdded);
            return r;
        }
        std::string toCsv(const SavedLogin& s) {
            std::string r;
            r += CsvField(s.url);           r += ',';
            r += CsvField(s.username);      r += ',';
            r += CsvField(s.signonRealm);   r += ',';
            r += std::to_string(s.timesUsed); r += ',';
            r += CsvTime(s.dateLastUsed);   r += ',';
            r += CsvTime(s.dateCreated);
            return r;
        }
        std::string toCsv(const NetworkServer& s) {
            std::string r;
            r += CsvField(s.server);                r += ',';
            r += s.supportsSpdy ? "true" : "false"; r += ',';
            r += s.hasAltSvc ? "true" : "false";    r += ',';
            r += s.srttMicros ? std::to_string(*s.srttMicros) : "";
            return r;
        }
        std::string toCsv(const AutofillAddress& a) {
            std::string r;
            r += CsvField(a.fullName);      r += ',';
            r += CsvField(a.email);         r += ',';
            r += CsvField(a.phone);         r += ',';
            r += CsvField(a.companyName);   r += ',';
            r += CsvField(a.streetAddress); r += ',';
            r += CsvField(a.city);          r += ',';
            r += CsvField(a.state);         r += ',';
            r += CsvField(a.zipCode);       r += ',';
            r += CsvField(a.countryCode);
            return r;
        }
        std::string toCsv(const SavedCard& c) {
            std::string r;
            r += CsvField(c.nameOnCard);            r += ',';
            r += CsvField(c.network);               r += ',';
            r += CsvField(c.lastFour);              r += ',';
            r += std::to_string(c.expirationMonth); r += ',';
            r += std::to_string(c.expirationYear);  r += ',';
            r += CsvField(c.nickname);              r += ',';
            r += c.serverSynced ? "true" : "false";
            return r;
        }
        std::string toCsv(const SearchEngine& e) {
            std::string r;
            r += CsvField(e.shortName); r += ',';
            r += CsvField(e.keyword);   r += ',';
            r += CsvField(e.searchUrl);
            return r;
        }
        std::string toCsv(const TopSite& s) {
            std::string r;
            r += std::to_string(s.rank); r += ',';
            r += CsvField(s.url);        r += ',';
            r += CsvField(s.title);
            return r;
        }
        std::string toCsv(const CacheEntry& e) {
            std::string r;
            r += CsvField(e.url);                          r += ',';
            r += std::to_string(e.statusCode);             r += ',';
            r += CsvField(e.mimeType);                     r += ',';
            r += CsvField(e.header("server"));             r += ',';
            r += std::to_string(e.responseBodySize);       r += ',';
            r += CsvTime(e.requestTime);                   r += ',';
            r += CsvTime(e.responseTime);
            return r;
        }

    }  // namespace

    // === Profile behavior =======================================================
    // Lives here (rather than capture.cpp) because the risk heuristic is a reporting
    // concern: it is consumed only by the two dumps below.
    std::vector<const Extension*> Profile::riskyExtensions() const {
        std::vector<const Extension*> out;
        for (const auto& e : extensions_) {
            if (e.isComponent) continue;   // a built-in being privileged isn't a finding
            for (const auto& perm : e.permissions) {
                if (IsSensitivePermission(perm) || perm.find("://") != std::string::npos) {
                    out.push_back(&e);
                    break;
                }
            }
        }
        return out;
    }

    // === dumps ==================================================================

    void DumpText(const Installation& inst, std::ostream& out) {
        out << "== Chromium installation snapshot ==\n"
            << "user_data_dir : " << inst.userDataDir() << "\n"
            << "brand (guess) : " << inst.brand() << "\n"
            << "chrome_version: " << (inst.chromeVersion().empty() ? "(unknown)" : inst.chromeVersion()) << "\n"
            << "captured_at   : " << FormatTime(inst.capturedAt()) << "\n"
            << "client_id     : "
            << (inst.metrics().clientId.empty() ? "(none -- UMA likely off)"
                : inst.metrics().clientId)
            << "\n";
        if (inst.metrics().lowEntropySource)
            out << "low_entropy   : " << *inst.metrics().lowEntropySource << "\n";
        out << "stats_version : " << inst.metrics().statsVersion << "\n"
            << "os_crypt_key  : "
            << (inst.osCryptKey().present
                ? "present (opaque, " + std::to_string(inst.osCryptKey().keySize) +
                " b64 chars)"
                : "absent")
            << "\n"
            << "variations    : "
            << (inst.variations().present
                ? std::to_string(inst.variations().studyCount) + " studies"
                : "not decoded")
            << "\n";
        if (inst.host().present) {
            const auto& h = inst.host();
            out << "-- host --\n"
                << "os            : " << h.osName << " " << h.osVersion;
            if (!h.osKernelVersion.empty() && h.osKernelVersion != h.osVersion)
                out << "  (kernel " << h.osKernelVersion << ")";
            out << "\n"
                << "cpu           : " << h.cpuArch
                << (h.cpuVendor.empty() ? "" : " (" + h.cpuVendor + ")") << "\n";
            if (!h.cpuModelName.empty())  out << "cpu_model     : " << h.cpuModelName << "\n";
            if (h.cpuNumCores)            out << "cpu_cores     : " << h.cpuNumCores
                << " physical / " << h.cpuNumLogical << " logical\n";
            if (h.cpuSpeedMhz)            out << "cpu_mhz       : " << h.cpuSpeedMhz << "\n";
            if (h.cpuIsHypervisor)        out << "hypervisor    : YES (running in VM)\n";
            if (h.ramMb)                  out << "ram_mb        : " << h.ramMb << "\n";
            if (!h.boardModel.empty())    out << "board         : " << h.boardModel << "\n";
            if (!h.formFactor.empty())    out << "form_factor   : " << h.formFactor << "\n";
            if (!h.gpuRenderer.empty())   out << "gpu           : " << h.gpuRenderer << "\n";
            if (!h.gpuDriver.empty())     out << "gpu_driver    : " << h.gpuDriver << "\n";
            if (h.gpuVendorId) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "0x%04x / 0x%04x", h.gpuVendorId, h.gpuDeviceId);
                out << "gpu_ids       : " << buf << "\n";
            }
            if (!h.gpuGlVendor.empty())   out << "gl_vendor     : " << h.gpuGlVendor << "\n";
            if (h.screenCount)            out << "screen        : " << h.screenCount << "x  "
                << static_cast<int>(h.screenWidth) << "x"
                << static_cast<int>(h.screenHeight) << " px\n";
            if (!h.channel.empty())       out << "channel       : " << h.channel << "\n";
            if (!h.locale.empty())        out << "locale        : " << h.locale << "\n";
            if (!h.brandCode.empty())     out << "brand_code    : " << h.brandCode << "\n";
            if (h.installWeeks)           out << "install_weeks : " << h.installWeeks << "\n";
            if (!h.appVersion.empty())    out << "app_version   : " << h.appVersion << "\n";
        }
        if (!inst.lastActiveProfiles().empty()) {
            out << "last_active   : ";
            for (std::size_t i = 0; i < inst.lastActiveProfiles().size(); ++i)
                out << (i ? ", " : "") << inst.lastActiveProfiles()[i];
            out << "\n";
        }
        out << "profiles      : " << inst.profiles().size() << "\n";

        for (const auto& p : inst.profiles()) {
            const auto& id = p.identity();
            auto field = [&](const char* label, const std::string& v) {
                out << "  " << label << " : " << (v.empty() ? "(none)" : v) << "\n";
                };

            out << "\nprofile [" << id.key << "]\n";
            field("name           ", id.name);
            field("user_name      ", id.userName);
            field("gaia_id        ", id.gaiaId);
            field("gaia_given_name", id.gaiaGivenName);
            field("hosted_domain  ", id.hostedDomain);
            field("managed_user_id", id.managedUserID);
            field("shortcut_name  ", id.shortcutName);
            field("avatar_icon    ", id.avatarIcon);
            field("gaia_picture   ", id.gaiaPictureFilename);
            out << "  signed_in       : " << (p.isSignedIn() ? "yes" : "no") << "\n"
                << "  ephemeral       : " << (id.isEphemeral ? "yes" : "no") << "\n"
                << "  consented_acct  : " << (id.isConsentedPrimaryAccount ? "yes" : "no") << "\n"
                << "  force_signin_lock: " << (id.forceSigninProfileLockout ? "yes" : "no") << "\n"
                << "  background_apps : " << (id.backgroundApps ? "yes" : "no") << "\n"
                << "  active_time     : " << FormatTime(id.activeTime) << "\n"
                << "  dir             : " << p.dir() << "\n";

            const auto& c = p.credentials();
            out << "  credentials:\n";
            for (const auto& s : CredStores())  // CredStores() from internal.h
                out << "    " << std::left << std::setw(10) << s.textLabel << " : "
                << (c.*s.has ? "yes (" + HumanBytes(c.*s.size) + ")" : "no") << "\n";

            out << "  saved logins (" << p.logins().size() << "):\n";
            for (const auto& l : p.logins())
                out << "    - " << (l.username.empty() ? "(no username)" : l.username)
                << "  @  " << l.url
                << (l.timesUsed > 0 ? "  (used " + std::to_string(l.timesUsed) + "x)" : "")
                << "\n";

            out << "  extensions (" << p.extensions().size() << "):\n";
            if (p.extensions().empty())
                out << "    (none found in Preferences)\n";
            for (const auto& e : p.extensions())
                out << "    - " << (e.name.empty() ? e.id : e.name) << " v" << e.version
                << (e.enabled ? " [enabled]" : " [disabled]")
                << "  perms:" << e.permissions.size()
                << "  src:" << ExtSource(e) << "\n";

            auto risky = p.riskyExtensions();
            if (!risky.empty()) {
                out << "  risky extensions (" << risky.size() << "):\n";
                for (const auto* e : risky)
                    out << "    ! " << (e->name.empty() ? e->id : e->name) << "\n";
            }

            out << "  devices (" << p.devices().size() << "):\n";
            if (p.devices().empty())
                out << "    (none -- sync off, no synced devices, or Chrome was running)\n";
            for (const auto& d : p.devices())
                out << "    - " << (d.clientName.empty() ? d.guid : d.clientName)
                << " [" << (d.osType.empty() ? "?" : d.osType)
                << (d.formFactor.empty() ? "" : "/" + d.formFactor) << "]"
                << (d.chromeVersion.empty() ? "" : "  chrome " + d.chromeVersion)
                << (d.manufacturer.empty() ? "" : "  " + d.manufacturer)
                << (d.model.empty() ? "" : " " + d.model)
                << "  updated " << FormatTime(d.lastUpdated) << "\n";

            // Bookmarks: full flat list.
            out << "  bookmarks (" << p.bookmarks().size() << "):\n";
            for (const auto& b : p.bookmarks())
                out << "    - " << (b.title.empty() ? "(untitled)" : b.title)
                << "  " << b.url << "\n";

            // History: most-recent visits (show a handful; --json carries the rest).
            const auto& hist = p.history().entries;
            out << "  history (" << hist.size() << " most recent visits)";
            if (hist.empty()) {
                out << "\n";
            }
            else {
                out << ":\n";
                std::size_t cap = std::min<std::size_t>(hist.size(), 15);
                for (std::size_t i = 0; i < cap; ++i)
                    out << "    - " << (hist[i].title.empty() ? "(no title)" : hist[i].title)
                    << "  " << hist[i].url << "\n";
                if (cap < hist.size())
                    out << "    (+" << (hist.size() - cap)
                    << " more; use --json for the full list)\n";
            }

            // Security posture (Safe Browsing + password-manager flags).
            const auto& sec = p.security();
            auto tri = [](const std::optional<bool>& b, const char* yes, const char* no) {
                return !b ? "(default)" : (*b ? yes : no);
                };
            auto sbLabel = [&](const SecurityPosture& sp) -> std::string {
                if (sp.safeBrowsingEnhanced && *sp.safeBrowsingEnhanced) return "enhanced";
                if (sp.safeBrowsingEnabled)  return *sp.safeBrowsingEnabled ? "standard" : "OFF";
                return "(default: standard)";
                };
            out << "  security:\n"
                << "    safe_browsing  : " << sbLabel(sec) << "\n"
                << "    pw_saving      : " << tri(sec.passwordSavingEnabled, "on", "OFF") << "\n"
                << "    leak_detection : " << tri(sec.leakDetectionEnabled, "on", "off") << "\n";

            // Cookie domains: services with stored cookies (logged-in surface).
            const auto& cd = p.cookieDomains();
            out << "  cookie domains (" << cd.size() << ")";
            if (cd.empty()) out << "\n";
            else {
                out << ":\n";
                std::size_t cap = std::min<std::size_t>(cd.size(), 15);
                for (std::size_t i = 0; i < cap; ++i)
                    out << "    - " << cd[i].host << "  (" << cd[i].cookieCount << " cookies"
                    << (cd[i].sessionCount ? ", " + std::to_string(cd[i].sessionCount)
                        + " session" : "") << ")\n";
                if (cap < cd.size())
                    out << "    (+" << (cd.size() - cap)
                    << " more; use --json for the full list)\n";
            }

            // Downloads: files pulled to disk (source -> target, danger flag).
            const auto& dls = p.downloads();
            out << "  downloads (" << dls.size() << ")";
            if (dls.empty()) out << "\n";
            else {
                out << ":\n";
                std::size_t cap = std::min<std::size_t>(dls.size(), 15);
                for (std::size_t i = 0; i < cap; ++i) {
                    const auto& d = dls[i];
                    out << "    - " << (d.targetPath.empty() ? "(no path)" : d.targetPath)
                        << (d.dangerType != 0
                            ? "  [DANGER type " + std::to_string(d.dangerType) + "]" : "")
                        << (d.byExtName.empty() ? "" : "  (via ext: " + d.byExtName + ")")
                        << "\n        from "
                        << (d.sourceUrl.empty() ? d.tabUrl : d.sourceUrl) << "\n";
                }
                if (cap < dls.size())
                    out << "    (+" << (dls.size() - cap)
                    << " more; use --json for the full list)\n";
            }

            // Network Persistent State: origins recently contacted (HTTP/2 + QUIC).
            // FORENSIC: plaintext, survives clearing history AND cache.
            const auto& net = p.networkState();
            if (net.present) {
                out << "  network servers (" << net.servers.size()
                    << ", survives history/cache clear)";
                if (net.servers.empty()) out << "\n";
                else {
                    out << ":\n";
                    std::size_t cap = std::min<std::size_t>(net.servers.size(), 20);
                    for (std::size_t i = 0; i < cap; ++i) {
                        const auto& sv = net.servers[i];
                        out << "    - " << sv.server
                            << (sv.supportsSpdy ? "  h2" : "")
                            << (sv.hasAltSvc ? "  quic" : "")
                            << (sv.srttMicros ? "  srtt=" + std::to_string(*sv.srttMicros)
                                + "us" : "")
                            << "\n";
                    }
                    if (cap < net.servers.size())
                        out << "    (+" << (net.servers.size() - cap)
                        << " more; use --json for the full list)\n";
                }
                if (!net.brokenQuicHosts.empty()) {
                    out << "    broken-quic: ";
                    for (std::size_t i = 0; i < net.brokenQuicHosts.size(); ++i)
                        out << (i ? ", " : "") << net.brokenQuicHosts[i];
                    out << "\n";
                }
            }

            // Autofill addresses (Web Data).
            const auto& addrs = p.autofillAddresses();
            out << "  autofill (" << addrs.size() << ")";
            if (addrs.empty()) { out << "\n"; }
            else {
                out << ":\n";
                for (const auto& a : addrs) {
                    out << "    - ";
                    if (!a.fullName.empty()) out << a.fullName;
                    if (!a.email.empty())    out << " <" << a.email << ">";
                    if (!a.phone.empty())    out << "  " << a.phone;
                    if (!a.city.empty()) {
                        out << "\n        ";
                        if (!a.streetAddress.empty()) out << a.streetAddress << ", ";
                        out << a.city;
                        if (!a.state.empty())       out << ", " << a.state;
                        if (!a.zipCode.empty())      out << " " << a.zipCode;
                        if (!a.countryCode.empty())  out << "  " << a.countryCode;
                    }
                    out << "\n";
                }
            }

            // Saved cards (Web Data, plaintext metadata only).
            const auto& cards = p.savedCards();
            out << "  saved cards (" << cards.size() << ")";
            if (cards.empty()) { out << "\n"; }
            else {
                out << ":\n";
                for (const auto& c : cards) {
                    out << "    - " << (c.nameOnCard.empty() ? "(no name)" : c.nameOnCard);
                    if (!c.network.empty())  out << "  " << c.network;
                    if (!c.lastFour.empty()) out << "  ****" << c.lastFour;
                    if (c.expirationMonth || c.expirationYear)
                        out << "  exp " << c.expirationMonth << "/" << c.expirationYear;
                    if (!c.nickname.empty()) out << "  \"" << c.nickname << "\"";
                    out << (c.serverSynced ? "  [synced]\n" : "\n");
                }
            }

            // Search engines (Web Data keywords table).
            const auto& engines = p.searchEngines();
            out << "  search engines (" << engines.size() << ")";
            if (engines.empty()) { out << "\n"; }
            else {
                out << ":\n";
                for (const auto& e : engines)
                    out << "    - " << e.shortName << " [" << e.keyword << "]\n";
            }

            // Top Sites (Default/Top Sites db).
            const auto& tops = p.topSites();
            out << "  top sites (" << tops.size() << ")";
            if (tops.empty()) { out << "\n"; }
            else {
                out << ":\n";
                for (const auto& s : tops)
                    out << "    " << s.rank << ". "
                    << (s.title.empty() ? s.url : s.title) << "\n";
            }

            // Cache (Default/Cache/Cache_Data).
            // Persists after history clear — forensic timeline of every fetched resource.
            const auto& cache = p.cacheEntries();
            out << "  cache (" << cache.size() << " HTTP/S entries";
            if (!cache.empty()) {
                out << ", survives history clear):\n";
                std::size_t cap = std::min<std::size_t>(cache.size(), 15);
                for (std::size_t i = 0; i < cap; ++i) {
                    const auto& ce = cache[i];
                    out << "    - " << ce.statusCode
                        << (ce.mimeType.empty() ? "" : "  " + ce.mimeType)
                        << "  " << ce.url;
                    if (ce.requestTime)
                        out << "  [" << FormatTime(ce.requestTime) << "]";
                    out << "\n";
                    // Show forensically useful headers inline
                    auto hv = ce.header("server");
                    if (!hv.empty()) out << "        server: " << hv << "\n";
                    hv = ce.header("location");
                    if (!hv.empty()) out << "        location: " << hv << "\n";
                    // Count Set-Cookie headers
                    int cookies = 0;
                    for (const auto& [k, v] : ce.headers)
                        if (k == "set-cookie") ++cookies;
                    if (cookies) out << "        set-cookie: (" << cookies << " cookie(s) set)\n";
                    // Body preview for text content
                    if (!ce.body.empty()) {
                        constexpr std::size_t kPreview = 200;
                        std::size_t plen = std::min(ce.body.size(), kPreview);
                        // Replace control chars with spaces for display
                        std::string preview(ce.body.data(), plen);
                        for (char& c : preview)
                            if (c == '\r' || c == '\n' || c == '\t') c = ' ';
                        out << "        body: " << preview;
                        if (ce.body.size() > kPreview)
                            out << "  [+" << (ce.body.size() - kPreview) << " bytes]";
                        out << "\n";
                    }
                }
                if (cap < cache.size())
                    out << "    (+" << (cache.size() - cap)
                    << " more; use --json for the full list)\n";
            }
            else {
                out << ")\n";
            }
        }
    }

    std::string DumpJson(const Installation& inst) {
        json j;
        j["user_data_dir"] = inst.userDataDir().string();
        j["brand_guess"] = inst.brand();
        j["chrome_version"] = inst.chromeVersion();
        j["captured_at"] = FormatTime(inst.capturedAt());
        j["metrics"] = { {"client_id", inst.metrics().clientId},
                        {"stats_version", inst.metrics().statsVersion} };
        if (inst.metrics().lowEntropySource)
            j["metrics"]["low_entropy_source"] = *inst.metrics().lowEntropySource;
        j["os_crypt_key"] = { {"present", inst.osCryptKey().present},
                             {"size", inst.osCryptKey().keySize} };  // never the key
        j["variations"] = { {"present", inst.variations().present},
                           {"study_count", inst.variations().studyCount},
                           {"study_names", inst.variations().studyNames} };
        if (inst.host().present) {
            const auto& h = inst.host();
            j["host"] = {
                {"os_name", h.osName}, {"os_version", h.osVersion},
                {"os_kernel_version", h.osKernelVersion},
                {"cpu_arch", h.cpuArch}, {"cpu_vendor", h.cpuVendor},
                {"cpu_model_name", h.cpuModelName},
                {"cpu_num_cores", h.cpuNumCores},
                {"cpu_num_logical", h.cpuNumLogical},
                {"cpu_speed_mhz", h.cpuSpeedMhz},
                {"cpu_is_hypervisor", h.cpuIsHypervisor},
                {"ram_mb", h.ramMb}, {"board_model", h.boardModel},
                {"form_factor", h.formFactor},
                {"gpu_renderer", h.gpuRenderer}, {"gpu_driver", h.gpuDriver},
                {"gpu_vendor_id", h.gpuVendorId}, {"gpu_device_id", h.gpuDeviceId},
                {"gpu_gl_vendor", h.gpuGlVendor},
                {"screen_count", h.screenCount},
                {"screen_width", static_cast<int>(h.screenWidth)},
                {"screen_height", static_cast<int>(h.screenHeight)},
                {"channel", h.channel}, {"locale", h.locale},
                {"brand_code", h.brandCode}, {"install_weeks", h.installWeeks},
                {"app_version", h.appVersion}
            };
        }
        j["last_active_profiles"] = inst.lastActiveProfiles();

        for (const auto& p : inst.profiles()) {
            const auto& id = p.identity();
            json jp = { {"key", id.key},
                       {"name", id.name},
                       {"gaia_id", id.gaiaId},
                       {"gaia_given_name", id.gaiaGivenName},
                       {"user_name", id.userName},
                       {"hosted_domain", id.hostedDomain},
                       {"avatar_icon", id.avatarIcon},
                       {"managed_user_id", id.managedUserID},
                       {"shortcut_name", id.shortcutName},
                       {"background_apps", id.backgroundApps},
                       {"is_ephemeral", id.isEphemeral},
                       {"is_consented_primary_account", id.isConsentedPrimaryAccount},
                       {"signed_in", p.isSignedIn()},
                       {"dir", p.dir().string()},
                       {"extension_count", p.extensions().size()},
                       {"device_count", p.devices().size()},
                       {"history_count", p.history().entries.size()},
                       {"cookie_domain_count", p.cookieDomains().size()},
                       {"download_count", p.downloads().size()} };
            if (id.activeTime) jp["active_time"] = FormatTime(id.activeTime);

            const auto& c = p.credentials();
            jp["credentials"] = json::object();
            for (const auto& s : CredStores()) {
                jp["credentials"][s.jsonKey] = c.*s.has;
                jp["credentials"][std::string(s.jsonKey) + "_size"] = c.*s.size;
            }

            for (const auto& e : p.extensions()) jp["extensions"].push_back(toJson(e));
            for (const auto* e : p.riskyExtensions()) jp["risky_extensions"].push_back(e->id);
            for (const auto& d : p.devices())    jp["devices"].push_back(toJson(d));
            for (const auto& b : p.bookmarks())  jp["bookmarks"].push_back(toJson(b));
            for (const auto& l : p.logins())     jp["saved_logins"].push_back(toJson(l));
            for (const auto& h : p.history().entries) jp["history"].push_back(toJson(h));
            for (const auto& c : p.cookieDomains()) jp["cookie_domains"].push_back(toJson(c));
            for (const auto& d : p.downloads())     jp["downloads"].push_back(toJson(d));
            {
                json sj = json::object();
                const auto& sp = p.security();
                auto put = [&](const char* k, const std::optional<bool>& b) {
                    if (b) sj[k] = *b; else sj[k] = nullptr;
                    };
                put("safe_browsing_enabled", sp.safeBrowsingEnabled);
                put("safe_browsing_enhanced", sp.safeBrowsingEnhanced);
                put("password_saving_enabled", sp.passwordSavingEnabled);
                put("leak_detection_enabled", sp.leakDetectionEnabled);
                jp["security"] = std::move(sj);
            }
            if (p.networkState().present) {
                for (const auto& sv : p.networkState().servers)
                    jp["network"]["servers"].push_back(toJson(sv));
                jp["network"]["broken_quic_hosts"] = p.networkState().brokenQuicHosts;
            }
            for (const auto& a : p.autofillAddresses()) jp["autofill"].push_back(toJson(a));
            for (const auto& c : p.savedCards())        jp["saved_cards"].push_back(toJson(c));
            for (const auto& e : p.searchEngines())     jp["search_engines"].push_back(toJson(e));
            for (const auto& s : p.topSites())          jp["top_sites"].push_back(toJson(s));
            for (const auto& e : p.cacheEntries())      jp["cache"].push_back(toJson(e));

            j["profiles"].push_back(std::move(jp));
        }
        // error_handler::replace keeps a single mangled byte (common in page titles or
        // extension names, which come straight from arbitrary sites) from throwing and
        // discarding the entire JSON output.
        return j.dump(2, ' ', false, json::error_handler_t::replace);
    }

    // CSV is inherently one record type per file (devices and history can't share
    // columns), so export takes a section. The header + profile column + row loop is
    // identical for every type, so it lives once in `emit`; each section supplies only
    // its header and how to reach its records (toCsv resolves per type by overload).
    void DumpCsv(const Installation& inst, std::string_view what, std::ostream& out) {
        const std::string section = ToLower(std::string(what));  // ToLower from internal.h

        auto emit = [&](const char* header, auto pick) {
            out << "profile," << header << '\n';
            for (const auto& p : inst.profiles())
                for (const auto& rec : pick(p))
                    out << CsvField(p.identity().key) << ',' << toCsv(rec) << '\n';
            };

        if (section == "devices")      emit("guid,client_name,model,manufacturer,form_factor,hardware_class,chrome_version,os_type,last_updated",
            [](const Profile& p) -> const auto& { return p.devices(); });
        else if (section == "extensions")   emit("id,name,version,enabled,state,location,is_component,from_webstore,installed_by_default,installed_by_oem,update_url,permissions",
            [](const Profile& p) -> const auto& { return p.extensions(); });
        else if (section == "history")      emit("url,title,visit_count,typed_count,last_visit",
            [](const Profile& p) -> const auto& { return p.history().entries; });
        else if (section == "bookmarks")    emit("title,url,date_added",
            [](const Profile& p) -> const auto& { return p.bookmarks(); });
        else if (section == "logins" ||
            section == "saved_logins") emit("url,username,signon_realm,times_used,date_last_used,date_created",
                [](const Profile& p) -> const auto& { return p.logins(); });
        else if (section == "cookies")      emit("host,cookie_count,secure_count,http_only_count,session_count",
            [](const Profile& p) -> const auto& { return p.cookieDomains(); });
        else if (section == "downloads")    emit("target_path,source_url,tab_url,mime_type,danger_type,state,total_bytes,received_bytes,by_ext_id,by_ext_name,opened,start_time",
            [](const Profile& p) -> const auto& { return p.downloads(); });
        else if (section == "network")       emit("server,supports_spdy,has_alt_svc,srtt_micros",
            [](const Profile& p) -> const auto& { return p.networkState().servers; });
        else if (section == "autofill")      emit("full_name,email,phone,company_name,street_address,city,state,zip_code,country_code",
            [](const Profile& p) -> const auto& { return p.autofillAddresses(); });
        else if (section == "cards")         emit("name_on_card,network,last_four,expiration_month,expiration_year,nickname,server_synced",
            [](const Profile& p) -> const auto& { return p.savedCards(); });
        else if (section == "search_engines") emit("short_name,keyword,url",
            [](const Profile& p) -> const auto& { return p.searchEngines(); });
        else if (section == "top_sites")     emit("rank,url,title",
            [](const Profile& p) -> const auto& { return p.topSites(); });
        else if (section == "cache")         emit("url,status,mime_type,server,response_body_size,request_time,response_time",
            [](const Profile& p) -> const auto& { return p.cacheEntries(); });
        else throw std::runtime_error(
            "unknown --csv section '" + std::string(what) +
            "' (use one of: devices, extensions, history, bookmarks, logins, cookies,"
            " downloads, network, autofill, cards, search_engines, top_sites, cache)");
    }
}  // namespace chromiumprofile