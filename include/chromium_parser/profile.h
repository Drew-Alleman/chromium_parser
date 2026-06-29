#ifndef CHROMIUMPROFILE_PROFILE_H_
#define CHROMIUMPROFILE_PROFILE_H_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace chromiumprofile {

    using Timestamp = std::chrono::system_clock::time_point;

    // ===========================================================================
    // Value types. All format-free: a JSON reader, SQLite reader, or protobuf
    // decoder fills these, but the types themselves don't know which.
    // ===========================================================================

    // From the profile's Preferences JSON (extensions.settings).
    struct Extension {
        std::string id;
        std::string name;
        std::string version;
        int state = 1;
        int location = 0;              // Chrome Manifest::Location enum
        bool isComponent = false;      // baked into the browser, not installed on disk
        bool enabled = false;
        std::vector<std::string> permissions;
        // provenance -- separates user-from-store installs from sideloaded / dev /
        // policy ones (the malware-relevant distinction).
        bool fromWebStore = false;       // from_webstore
        std::string updateUrl;           // manifest update_url; non-CWS host = sideload signal
        bool installedByDefault = false; // was_installed_by_default
        bool installedByOem = false;     // was_installed_by_oem
    };

    // From the Bookmarks JSON. Flat for now (no folder tree); extend if needed.
    struct Bookmark {
        std::string title;
        std::string url;
        std::optional<Timestamp> dateAdded;
    };

    // From the History SQLite db (urls table). Populated by ReadHistory.
    struct HistoryEntry {
        std::string url;
        std::string title;
        int visitCount = 0;
        int typedCount = 0;            // typed_count: times the URL was hand-typed (intent)
        std::optional<Timestamp> lastVisit;
    };
    struct History {
        std::vector<HistoryEntry> entries;
    };

    // Credential-store PRESENCE and size only. This type never holds secrets.
    // Actually decrypting Login Data / Cookies / Web Data is a separate, much
    // heavier reader (DPAPI / Keychain / libsecret, App-Bound Encryption) and is
    // deliberately NOT part of this inventory path.
    struct CredentialPresence {
        bool hasLoginData = false;
        std::uintmax_t loginDataSize = 0;
        bool hasCookies = false;
        std::uintmax_t cookiesSize = 0;
        bool hasWebData = false;
        std::uintmax_t webDataSize = 0;
    };

    // From the Login Data SQLite db (logins table). USERNAME ONLY -- the password_value
    // column is OSCrypt-encrypted and is never read by this tool.
    struct SavedLogin {
        std::string url;       // origin_url
        std::string username;  // username_value (plaintext in the db)
        std::string signonRealm;               // signon_realm (the auth scope)
        int timesUsed = 0;                     // times_used
        std::optional<Timestamp> dateLastUsed; // date_last_used (active-account signal)
        std::optional<Timestamp> dateCreated;  // date_created
    };

    // From the Cookies SQLite db (cookies table), aggregated per host. METADATA
    // ONLY: the cookie value is OSCrypt-encrypted and is never read. The set of
    // hosts is the map of services with stored cookies -- i.e. where the user has
    // (or recently had) a session. Security recon: this is the account surface.
    struct CookieDomain {
        std::string host;        // host_key, e.g. ".github.com"
        int cookieCount = 0;
        int secureCount = 0;     // is_secure
        int httpOnlyCount = 0;   // is_httponly (not JS-readable)
        int sessionCount = 0;    // non-persistent (browser-session) cookies
    };

    // From the History SQLite db (downloads + downloads_url_chains). Every file
    // pulled to disk: where from, to where, and Chrome's own danger classification.
    // All columns here are plaintext.
    struct DownloadEntry {
        std::string targetPath;  // target_path on disk
        std::string sourceUrl;   // final URL in the redirect chain (byte source)
        std::string tabUrl;      // page the download was started from
        std::string mimeType;
        int dangerType = 0;      // Chrome DownloadDangerType (0 = not dangerous)
        int state = 0;           // Chrome DownloadState (1 = complete)
        std::int64_t totalBytes = 0;
        std::int64_t receivedBytes = 0;  // received_bytes (< total => interrupted)
        std::string byExtId;             // by_ext_id: extension that started the download
        std::string byExtName;           // by_ext_name
        bool opened = false;
        std::optional<Timestamp> startTime;
    };

    // Security-relevant flags from the profile's Preferences. optional<bool> so an
    // absent key (Chrome default) is distinguishable from an explicit user choice.
    struct SecurityPosture {
        std::optional<bool> safeBrowsingEnabled;    // safebrowsing.enabled
        std::optional<bool> safeBrowsingEnhanced;   // safebrowsing.enhanced
        std::optional<bool> passwordSavingEnabled;  // credentials_enable_service
        std::optional<bool> leakDetectionEnabled;   // profile.password_manager_leak_detection
    };

    // A server Chrome has recently spoken to, from Network Persistent State (its
    // HTTP/2 + QUIC property cache). FORENSIC VALUE: the origin is PLAINTEXT and this
    // store is NOT touched by "clear browsing history" or "clear cache" -- so it can
    // place the browser at a host after the History db has been wiped.
    struct NetworkServer {
        std::string server;             // origin: "https://accounts.google.com[:443]"
        bool supportsSpdy = false;      // HTTP/2 was negotiated for this origin
        bool hasAltSvc = false;         // advertised a QUIC/H3 alternative service
        std::optional<int> srttMicros;  // smoothed round-trip time (network_stats.srtt)
    };
    struct NetworkState {
        bool present = false;
        std::vector<NetworkServer> servers;        // origins recently contacted
        std::vector<std::string> brokenQuicHosts;  // hosts where QUIC was tried and broke
    };

    // --- protobuf side (per profile, from the sync store) ----------------------
    // Decoded from sync DeviceInfoSpecifics.
    struct DeviceInfo {
        std::string guid;
        std::string clientName;
        std::string model;
        std::string manufacturer;   // manufacturer
        std::string formFactor;     // DESKTOP / PHONE / TABLET (device_form_factor)
        std::string hardwareClass;  // full_hardware_class
        std::string chromeVersion;
        std::string osType;
        std::optional<Timestamp> lastUpdated;
    };
    // The canonical identity. Parsed from User Data/Local State -> profile.info_cache.
    struct ProfileIdentity {
        std::string key;
        std::optional<Timestamp> activeTime;
        std::string avatarIcon;
        bool backgroundApps = false;
        bool forceSigninProfileLockout = false;
        std::string gaiaGivenName;
        std::string gaiaId;
        std::string gaiaPictureFilename;
        std::string hostedDomain;
        bool isConsentedPrimaryAccount = false;
        bool isEphemeral = false;
        std::string managedUserID;
        std::string name;
        std::string shortcutName;
        std::string userName;
    };

    // --- installation-wide state (from Local State, at the User Data root) ------
    struct MetricsInfo {
        std::string clientId;
        std::optional<int> lowEntropySource;
        std::string statsVersion;
    };

    // Host / OS / hardware, decoded from the metrics SystemProfileProto stashed
    // (base64, raw) in Local State user_experience_metrics.stability.
    // saved_system_profile. Installation-wide (describes the machine, not a
    // profile). `present` is false when the blob is absent or unparsable.
    struct HostInfo {
        bool present = false;
        // OS (proto field 5)
        std::string osName;           // "Windows NT"
        std::string osVersion;        // "10.0.26200"
        std::string osKernelVersion;  // kernel_version (finer build on Linux/Android)
        // CPU (hardware.cpu, proto hw field 13)
        std::string cpuArch;          // "x86_64"
        std::string cpuVendor;        // "AuthenticAMD"
        std::string cpuModelName;     // full model, e.g. "AMD Ryzen 9 7900X..."
        std::uint32_t cpuNumCores = 0;
        std::uint32_t cpuNumLogical = 0;
        std::uint32_t cpuSpeedMhz = 0;
        bool cpuIsHypervisor = false; // true when Chrome runs inside a VM
        // Memory / board
        std::int64_t ramMb = 0;
        std::string boardModel;       // "B650 GAMING X AX V2"
        std::string formFactor;       // DESKTOP / LAPTOP / TABLET / HANDSET / ...
        // GPU (hardware.gpu, proto hw field 8)
        std::string gpuRenderer;      // ANGLE renderer string
        std::string gpuDriver;        // "32.0.16.1047"
        std::uint32_t gpuVendorId = 0;// PCI vendor (0x10DE=NVIDIA, 0x1002=AMD, 0x8086=Intel)
        std::uint32_t gpuDeviceId = 0;// PCI device ID
        std::string gpuGlVendor;      // GL vendor string
        // Screen (proto hw fields 9-11)
        std::uint32_t screenCount = 0;
        float screenWidth = 0.f;     // primary screen pixels
        float screenHeight = 0.f;
        // Installation metadata (top-level proto fields)
        std::string channel;          // STABLE / BETA / DEV / CANARY
        std::string locale;           // "en-US"
        std::string brandCode;        // 4-char distribution code, e.g. "GGRV"
        std::uint32_t installWeeks = 0; // weeks since 2003-01-07 (install age)
        std::string appVersion;       // "149.0.7827.199-64"
    };

    // From Web Data: autofill_profiles+join tables (legacy) and
    // contact_info_type_tokens (Chrome 114+). All columns plaintext.
    struct AutofillAddress {
        std::string guid;
        std::string fullName;
        std::string email;
        std::string phone;
        std::string companyName;
        std::string streetAddress;
        std::string city;
        std::string state;
        std::string zipCode;
        std::string countryCode;
    };

    // From Web Data credit_cards (local) and masked_credit_cards (server/synced).
    // card_number_encrypted is NEVER read.
    struct SavedCard {
        std::string nameOnCard;
        std::string lastFour;     // plaintext in masked_credit_cards; empty for local cards
        std::string network;      // "visa", "mastercard", etc. (masked_credit_cards only)
        int expirationMonth = 0;
        int expirationYear = 0;
        std::string nickname;
        bool serverSynced = false; // true if from masked_credit_cards
    };

    // From Web Data keywords table (user-configured search engines).
    struct SearchEngine {
        std::string shortName;
        std::string keyword;
        std::string searchUrl;    // template URL containing {searchTerms}
    };

    // From Default/Top Sites SQLite (browser's ranked new-tab-page sites).
    struct TopSite {
        std::string url;
        std::string title;
        int rank = 0;
    };

    // From Default/Cache/Cache_Data (blockfile HTTP cache).
    // This store persists after "clear browsing history" unless the user also
    // explicitly clears "Cached images and files". Every HTTP/HTTPS resource the
    // browser fetched -- page HTML, images, scripts, JSON API responses -- leaves
    // an entry here, making it a timeline that survives a history wipe.
    struct CacheEntry {
        std::string url;
        int         statusCode = 0;
        std::string mimeType;                  // Content-Type stripped of params (convenience)
        std::optional<Timestamp> requestTime;
        std::optional<Timestamp> responseTime;
        std::int64_t responseBodySize = 0;     // size of the cached response body

        // All response headers in the order Chrome stored them.
        // Name is lowercased; duplicate names (e.g. Set-Cookie) appear as separate entries.
        // Note: HTTP request method is NOT cached — Chrome stores responses only.
        std::vector<std::pair<std::string, std::string>> headers;

        // Response body (stream 1). Populated for text-based MIME types
        // (text/html, application/json, text/plain, text/xml, etc.) that are
        // under kBodySizeLimit bytes. Empty for images, large JS bundles, etc.
        std::string body;

        // Convenience lookup — first value for a given lowercase header name, or "".
        std::string header(std::string_view name) const {
            for (const auto& [k, v] : headers)
                if (k == name) return v;
            return {};
        }

        // ---- Internal — set by the reader, consumed by SearchCache ----------
        // Treat as opaque; do not depend on these values in calling code.
        uint32_t    _stream1Addr = 0;  // CacheAddr of the response body (stream 1)
        int32_t     _stream1Size = 0;  // encoded (on-disk) body size
        std::string _cacheDataDir;     // path to Cache_Data/ for lazy reads
    };

    // ---- Cache search --------------------------------------------------------

    // MIME content categories used by CacheFilter. Lets you say "data only"
    // without enumerating every individual MIME type you want to skip.
    enum class ContentCategory {
        Data,    // text/html, application/json, text/plain, text/xml, ...
        Script,  // text/javascript, application/javascript
        Style,   // text/css
        Image,   // image/*
        Font,    // font/*, application/font-*
        Media,   // audio/*, video/*
        Binary,  // application/octet-stream, wasm, and anything unrecognised
    };

    // Returns the ContentCategory for a MIME type string (lowercased, no params).
    ContentCategory ClassifyMime(const std::string& mime);

    // Controls which cache entries SearchCache inspects and how.
    // Checks are applied cheapest-first: MIME → URL → status → size →
    // header → body read → decompress → needle. Any filter left at its
    // zero/empty default is skipped entirely.
    struct CacheFilter {
        // ---- MIME / content category (no I/O) --------------------------------
        // dataOnly = true: keep ONLY ContentCategory::Data entries
        // (text/html, application/json, text/xml, text/plain, etc.).
        // This is the recommended investigation mode — fonts/images/CSS/JS
        // are noise for content searches.
        bool dataOnly = false;

        // Fine-grained skips (independent of dataOnly):
        bool skipScripts = false;  // text/javascript, application/javascript
        bool skipStyles = false;  // text/css
        bool skipImages = false;  // image/*
        bool skipFonts = false;  // font/*, application/font-*
        bool skipMedia = false;  // audio/*, video/*
        bool skipBinary = false;  // application/octet-stream, wasm, etc.

        // ---- URL filter (no I/O) ---------------------------------------------
        std::string urlContains;   // case-sensitive substring, "" = no filter
        std::string urlPrefix;     // starts-with match, "" = no filter

        // ---- Response metadata filters (no I/O) ------------------------------
        int     statusMin = 0;   // 0 = no lower bound  (e.g. 200)
        int     statusMax = 0;   // 0 = no upper bound  (e.g. 299)
        int64_t bodySizeMax = 0;   // 0 = no cap; skip entries larger than this

        // ---- Header filter (in-memory, before body read) ---------------------
        // Pass only if headerName is present AND its value contains headerValueContains.
        std::string headerName;           // lowercased header name, "" = no filter
        std::string headerValueContains;  // "" = just require header presence

        // ---- Body search (triggers block-file read + decompression) ----------
        // Empty needle: return all metadata matches without reading bodies.
        // Non-empty: return only entries whose decompressed body contains needle,
        //            with entry.body populated on each hit.
        std::string needle;
        int maxBodyBytes = 512 * 1024;  // per-entry decompressed cap (0 = unlimited)
    };

    // os_crypt key recorded as presence + size only -- never the key itself.
    struct OsCryptKey {
        bool present = false;
        std::size_t keySize = 0;       // base64 length of the encrypted_key field
    };

    // Decoded from variations_compressed_seed (base64 -> gunzip -> protobuf).
    struct VariationsSummary {
        bool present = false;          // true only when the proto actually parsed
        int studyCount = 0;
        std::vector<std::string> studyNames;
    };

    // A non-fatal event emitted during capture: a store that was locked, a schema
    // that wasn't recognised, a file that couldn't be copied, etc.  The library
    // never writes to std::cerr; callers receive these instead.
    struct Diagnostic {
        enum class Level { Info, Warning, Error };
        Level       level;
        std::string source;   // which reader produced this ("logins", "history", ...)
        std::string message;
    };

    struct CaptureOptions {
        bool decodeVariations = false; // requires protobuf wired into the build

        int history = 200;   // capped by default (History DB can be huge); 0 = unlimited
        int downloads = 200; // capped by default; 0 = unlimited
        int cookies = 0;
        int topSites = 0;
        int searchEngines = 0;

        // Optional real-time callback.  Called once per Diagnostic as capture runs.
        // If null, diagnostics are still buffered in Installation::diagnostics() and
        // available after CaptureInstallation returns.
        std::function<void(const Diagnostic&)> onDiagnostic;
    };

    // ===========================================================================
    // Aggregates.
    // ===========================================================================

    // One profile: identity + on-disk location + collected data.
    // This is the former ProfileSnapshot, now built on ProfileIdentity.
    class Profile {
    public:
        const ProfileIdentity& identity() const { return identity_; }
        const std::filesystem::path& dir() const { return dir_; }  // profile subdir
        const History& history() const { return history_; }
        const std::vector<Extension>& extensions() const { return extensions_; }
        const std::vector<Bookmark>& bookmarks() const { return bookmarks_; }
        const std::vector<SavedLogin>& logins() const { return logins_; }
        const CredentialPresence& credentials() const { return credentials_; }
        const std::vector<DeviceInfo>& devices() const { return devices_; }
        const std::vector<CookieDomain>& cookieDomains() const { return cookieDomains_; }
        const std::vector<DownloadEntry>& downloads() const { return downloads_; }
        const SecurityPosture& security() const { return security_; }
        const NetworkState& networkState() const { return networkState_; }
        const std::vector<AutofillAddress>& autofillAddresses() const { return autofillAddresses_; }
        const std::vector<SavedCard>& savedCards() const { return savedCards_; }
        const std::vector<SearchEngine>& searchEngines() const { return searchEngines_; }
        const std::vector<TopSite>& topSites() const { return topSites_; }
        const std::vector<CacheEntry>& cacheEntries() const { return cacheEntries_; }

        // behavior that belongs with the data
        bool isSignedIn() const { return !identity_.gaiaId.empty(); }
        std::vector<const Extension*> riskyExtensions() const;  // by permission heuristic

        // population hooks for readers
        ProfileIdentity& mutableIdentity() { return identity_; }
        void setDir(std::filesystem::path p) { dir_ = std::move(p); }
        History& mutableHistory() { return history_; }
        std::vector<Extension>& mutableExtensions() { return extensions_; }
        std::vector<Bookmark>& mutableBookmarks() { return bookmarks_; }
        std::vector<SavedLogin>& mutableLogins() { return logins_; }
        CredentialPresence& mutableCredentials() { return credentials_; }
        std::vector<DeviceInfo>& mutableDevices() { return devices_; }
        std::vector<CookieDomain>& mutableCookieDomains() { return cookieDomains_; }
        std::vector<DownloadEntry>& mutableDownloads() { return downloads_; }
        SecurityPosture& mutableSecurity() { return security_; }
        NetworkState& mutableNetworkState() { return networkState_; }
        std::vector<AutofillAddress>& mutableAutofillAddresses() { return autofillAddresses_; }
        std::vector<SavedCard>& mutableSavedCards() { return savedCards_; }
        std::vector<SearchEngine>& mutableSearchEngines() { return searchEngines_; }
        std::vector<TopSite>& mutableTopSites() { return topSites_; }
        std::vector<CacheEntry>& mutableCacheEntries() { return cacheEntries_; }

    private:
        ProfileIdentity identity_;
        std::filesystem::path dir_;
        History history_;
        std::vector<Extension> extensions_;
        std::vector<Bookmark> bookmarks_;
        std::vector<SavedLogin> logins_;
        CredentialPresence credentials_;
        std::vector<DeviceInfo> devices_;
        std::vector<CookieDomain> cookieDomains_;
        std::vector<DownloadEntry> downloads_;
        SecurityPosture security_;
        NetworkState networkState_;
        std::vector<AutofillAddress> autofillAddresses_;
        std::vector<SavedCard> savedCards_;
        std::vector<SearchEngine> searchEngines_;
        std::vector<TopSite> topSites_;
        std::vector<CacheEntry> cacheEntries_;
    };

    // The whole User Data root: installation-wide state + N profiles.
    // This is the parent the single-Profile model never had.
    class Installation {
    public:
        const std::filesystem::path& userDataDir() const { return userDataDir_; }
        Timestamp capturedAt() const { return capturedAt_; }
        const std::string& brand() const { return brand_; }  // Chrome/Chromium/Edge/Brave (guess)
        const std::string& chromeVersion() const { return chromeVersion_; }  // from the "Last Version" file
        const MetricsInfo& metrics() const { return metrics_; }
        const HostInfo& host() const { return host_; }
        const OsCryptKey& osCryptKey() const { return osCryptKey_; }
        const VariationsSummary& variations() const { return variations_; }
        const std::vector<std::string>& lastActiveProfiles() const { return lastActiveProfiles_; }
        const std::vector<Profile>& profiles() const { return profiles_; }
        // All diagnostics emitted during capture (locked stores, missing schemas, etc.).
        const std::vector<Diagnostic>& diagnostics() const { return diagnostics_; }

        const Profile* findProfile(std::string_view key) const;

        // population hooks for readers
        void setUserDataDir(std::filesystem::path p) { userDataDir_ = std::move(p); }
        void setCapturedAt(Timestamp t) { capturedAt_ = t; }
        void setBrand(std::string b) { brand_ = std::move(b); }
        void setChromeVersion(std::string v) { chromeVersion_ = std::move(v); }
        MetricsInfo& mutableMetrics() { return metrics_; }
        HostInfo& mutableHost() { return host_; }
        OsCryptKey& mutableOsCryptKey() { return osCryptKey_; }
        VariationsSummary& mutableVariations() { return variations_; }
        std::vector<std::string>& mutableLastActiveProfiles() { return lastActiveProfiles_; }
        std::vector<Profile>& mutableProfiles() { return profiles_; }
        std::vector<Diagnostic>& mutableDiagnostics() { return diagnostics_; }

    private:
        std::filesystem::path userDataDir_;
        Timestamp capturedAt_{};
        std::string brand_;
        std::string chromeVersion_;
        MetricsInfo metrics_;
        HostInfo host_;
        OsCryptKey osCryptKey_;
        VariationsSummary variations_;
        std::vector<std::string> lastActiveProfiles_;
        std::vector<Profile> profiles_;
        std::vector<Diagnostic> diagnostics_;
    };

    // ===========================================================================
    // Capture + dump API. The reader split (Local State / Preferences / filesystem
    // / variations) is realized inside snapshot.cpp.
    // ===========================================================================
    Installation CaptureInstallation(const std::filesystem::path& userDataDir,
        const CaptureOptions& opts = {});

    // ---- profile copy / clone ------------------------------------------------
    // Filesystem-level duplication of a profile directory. Cache is excluded by
    // default (a migration wants data, not regenerable cache). Encrypted stores
    // (Login Data / Cookies / Web Data) are copied byte-for-byte but only stay
    // DECRYPTABLE on the same OS user + machine -- DPAPI/App-Bound keys don't move.
    struct CopyProfileOptions {
        bool skipCache = true;        // skip Cache / Code Cache / GPUCache / ML models / ...
        bool overwrite = false;       // overwrite files already present at the destination
        bool continueOnError = true;  // skip locked/unreadable files instead of aborting
    };
    struct CopyProfileResult {
        bool ok = false;                        // true iff nothing failed
        std::uintmax_t filesCopied = 0;
        std::uintmax_t bytesCopied = 0;
        std::uintmax_t entriesSkipped = 0;      // cache / excluded subtrees
        std::uintmax_t filesFailed = 0;         // locked (browser running) or unreadable
        std::vector<std::string> failedPaths;   // first ~50, for reporting
    };
    // Recursively copy profile dir `src` to `dst`. Pass a profile subdir ("Default")
    // to clone one profile, or the "User Data" root to clone the whole browser dir.
    // Close the browser first for a consistent copy; if it is running, locked files
    // are skipped and counted in filesFailed. ok == (filesFailed == 0).
    CopyProfileResult CopyProfile(const std::filesystem::path& src,
        const std::filesystem::path& dst,
        const CopyProfileOptions& opts = {});
    void DumpText(const Installation& inst, std::ostream& out);
    std::vector<std::string> ListUniqueUrls(const Installation& inst);
    std::string DumpJson(const Installation& inst);


    // ---- Cache search (Profile and Installation are now defined above) ----------

    struct CacheSearchResult {
        std::vector<CacheEntry> hits;
        int preFiltered = 0;  // eliminated by MIME/URL/status/header filters (no I/O)
        int bodiesRead = 0;  // entries that required block-file read + decompression
        int needleMiss = 0;  // bodies decompressed but needle not found
    };

    // Search the cache index already captured in `prof` using a cascade of filters.
    // Checks are applied cheapest-first so expensive I/O only happens for survivors.
    // filter.needle empty → return all metadata matches without reading bodies.
    // filter.needle set   → return only entries whose decompressed body contains it.
    CacheSearchResult SearchCache(const Profile& prof, const CacheFilter& filter);
    // CSV export of ONE record type: "devices", "extensions", "history",
    // "bookmarks", or "logins". Writes a header row then one row per record, with a
    // leading "profile" column so multi-profile exports stay unambiguous. Fields are
    // escaped per RFC 4180. Throws std::runtime_error on an unknown section name.
    void DumpCsv(const Installation& inst, std::string_view what, std::ostream& out);

}  // namespace chromiumprofile

#endif  // CHROMIUMPROFILE_PROFILE_H_