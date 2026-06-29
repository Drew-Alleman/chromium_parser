#ifndef CHROMIUMPROFILE_INTERNAL_H_
#define CHROMIUMPROFILE_INTERNAL_H_
//
// PRIVATE implementation header. Holds the declarations shared across the reader
// and dump translation units. It is NOT part of the public API: anything that
// embeds this library includes only <chromium_parser/profile.h> and never this.
// Do not install or ship this header.
//
#include <chromium_parser/profile.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace chromiumprofile {

    // Lower-case a copy. Shared by the brand guess (capture.cpp) and the
    // case-insensitive sync-key matching (readers_proto.cpp).
    inline std::string ToLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }

    // Chrome/WebKit timestamps are microseconds since 1601-01-01 (base::Time internal
    // value). Convert to a Timestamp; returns nullopt for non-positive or pre-Unix
    // values (Chrome stores 0 / imported defaults that map to ~1601). Single source
    // of truth for every reader that decodes a Chrome time column.
    inline std::optional<Timestamp> FromChromeMicros(long long micros1601) {
        if (micros1601 <= 0) return std::nullopt;
        long long unixMs = micros1601 / 1000 - 11644473600000LL;
        if (unixMs < 0) return std::nullopt;
        return Timestamp(std::chrono::milliseconds(unixMs));
    }

    // Thin non-owning diagnostic context threaded through all readers.
    // Always buffers into the Installation's diagnostics vector; also fires
    // the optional real-time callback from CaptureOptions::onDiagnostic.
    // The library never touches std::cerr -- all messages come through here.
    struct CaptureCtx {
        std::vector<Diagnostic>& buf;
        const std::function<void(const Diagnostic&)>* cb;  // null when not set
        const CaptureOptions* opts = nullptr;

        void emit(Diagnostic::Level lv,
            std::string_view src, std::string_view msg) const {
            Diagnostic d{ lv, std::string(src), std::string(msg) };
            buf.push_back(d);
            if (cb && *cb) (*cb)(d);
        }
        void info(std::string_view s, std::string_view m) const
        {
            emit(Diagnostic::Level::Info, s, m);
        }
        void warn(std::string_view s, std::string_view m) const
        {
            emit(Diagnostic::Level::Warning, s, m);
        }
        void error(std::string_view s, std::string_view m) const
        {
            emit(Diagnostic::Level::Error, s, m);
        }
    };

    // Single source of truth for the credential stores. Defined in capture.cpp.
    struct CredStoreDesc {
        const char* textLabel;
        const char* jsonKey;
        std::vector<const char*> pathCandidates;
        bool CredentialPresence::* has;
        std::uintmax_t CredentialPresence::* size;
    };
    const std::vector<CredStoreDesc>& CredStores();

    // Copy-on-lock helper shared by all db-backed readers. Defined in store_copy.cpp.
    void ReadLockedStore(
        const std::filesystem::path& live, const std::string& tag,
        const std::function<bool(const std::filesystem::path&)>& tryRead,
        const std::function<std::filesystem::path(
            const std::filesystem::path&, const std::filesystem::path&)>& copyStore,
        const CaptureCtx& ctx);

    // SQLite readers — readers_sqlite.cpp
    void ReadLoginData(Profile& prof, const CaptureCtx& ctx);
    void ReadHistory(Profile& prof, const CaptureCtx& ctx);
    void ReadCookies(Profile& prof, const CaptureCtx& ctx);
    void ReadDownloads(Profile& prof, const CaptureCtx& ctx);
    void ReadWebData(Profile& prof, const CaptureCtx& ctx);
    void ReadTopSites(Profile& prof, const CaptureCtx& ctx);
    void ReadCache(Profile& prof, const CaptureCtx& ctx); // readers_cache.cpp

    // SystemProfileProto wire decoder — readers_sysprofile.cpp (no protobuf lib needed)
    HostInfo DecodeSystemProfile(const std::string& b64Profile);

    void ReadSyncData(Profile& prof, const CaptureCtx& ctx);   // readers_proto.cpp
    VariationsSummary DecodeVariations(const std::string& b64Seed);

}  // namespace chromiumprofile

#endif  // CHROMIUMPROFILE_INTERNAL_H_