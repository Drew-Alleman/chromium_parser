//
// Filesystem plumbing, no parsers. Two things live here:
//   - ReadLockedStore: the copy-on-lock dance shared by every db-backed reader
//     (Login Data, History, sync LevelDB), so the "browser is running, grab a
//     copy" logic exists once.
//   - CopyProfile: the standalone profile/User-Data clone.
// Depends only on <filesystem> -- no JSON, SQLite, or protobuf.
//
#include <chromium_parser/profile.h>
#include "internal.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>

namespace fs = std::filesystem;

namespace chromiumprofile {
    namespace {

        // Create an unpredictably-named temp dir, made fresh by us (which closes the
        // pre-created-path/symlink window). Returns empty on failure. Used only by
        // ReadLockedStore, so it stays private to this TU.
        fs::path MakeRandomTempDir(const std::string& prefix) {
            std::random_device rd;
            std::mt19937_64 gen(rd());
            for (int attempt = 0; attempt < 8; ++attempt) {
                std::ostringstream name;
                name << prefix << std::hex << gen() << gen();  // 128 random bits
                fs::path candidate = fs::temp_directory_path() / name.str();
                std::error_code ec;
                if (fs::create_directory(candidate, ec) && !ec)
                    return candidate;
            }
            return {};
        }

    }  // namespace

    void ReadLockedStore(const fs::path& live, const std::string& tag,
        const std::function<bool(const fs::path&)>& tryRead,
        const std::function<fs::path(const fs::path&, const fs::path&)>& copyStore,
        const CaptureCtx& diag) {
        std::error_code ec;
        if (!fs::exists(live, ec)) return;

        // WAL-mode: skip in-place when a non-empty WAL exists (SQLite needs write
        // access to the wal-index even for reads; ?mode=ro silently skips WAL replay).
        fs::path walPath = fs::path(live.string() + "-wal");
        auto walSize = fs::file_size(walPath, ec);
        bool walPresent = (!ec && walSize > 0);

        if (!walPresent && tryRead(live)) return;

        fs::path tmp = MakeRandomTempDir("chrome_enum_" + tag + "_");
        if (tmp.empty()) {
            diag.error(tag, "could not create temp dir for locked store copy");
            return;
        }
        fs::path target = copyStore(live, tmp);
        if (target.empty()) {
            diag.warn(tag, "store is locked and could not be copied "
                           "(close the browser for a complete read)");
        } else {
            diag.info(tag, "browser is running; data read from a live copy");
            tryRead(target);
        }
        fs::remove_all(tmp, ec);
    }

    // === profile copy / clone ===================================================

    CopyProfileResult CopyProfile(const fs::path& src, const fs::path& dst,
        const CopyProfileOptions& opts) {
        CopyProfileResult r;
        std::error_code ec;
        if (!fs::is_directory(src, ec)) return r;

        // Large, regenerable, browser-rebuilt directories. When opts.skipCache (the
        // default) any path containing one of these components is pruned -- this is the
        // bulk of a profile's size and none of it is worth migrating.
        auto isCacheName = [](const std::string& name) {
            static constexpr std::string_view kCache[] = {
                "Cache", "Code Cache", "GPUCache", "GrShaderCache", "ShaderCache",
                "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GraphiteDawnCache",
                "CacheStorage", "ScriptCache", "blob_storage",
                "optimization_guide_model_store", "component_crx_cache", "extensions_crx_cache" };
            for (auto c : kCache) if (c == name) return true;
            return false;
            };

        fs::create_directories(dst, ec);
        const auto copyFlags = opts.overwrite ? fs::copy_options::overwrite_existing
            : fs::copy_options::skip_existing;

        fs::recursive_directory_iterator it(
            src, fs::directory_options::skip_permission_denied, ec), end;
        for (; it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            std::error_code fe;
            const fs::path from = it->path();
            const fs::path rel = fs::relative(from, src, fe);
            if (rel.empty()) continue;

            if (opts.skipCache) {
                bool inCache = false;
                for (const auto& part : rel) if (isCacheName(part.string())) { inCache = true; break; }
                if (inCache) {
                    if (it->is_directory(fe)) it.disable_recursion_pending();  // prune the subtree
                    ++r.entriesSkipped;
                    continue;
                }
            }

            const fs::path to = dst / rel;
            if (it->is_directory(fe)) { fs::create_directories(to, fe); continue; }
            if (!it->is_regular_file(fe)) continue;  // skip symlinks / sockets / etc.

            const std::uintmax_t sz = it->file_size(fe);
            fs::create_directories(to.parent_path(), fe);
            std::error_code ce;
            fs::copy_file(from, to, copyFlags, ce);
            if (ce) {
                ++r.filesFailed;  // locked while the browser runs, or unreadable
                if (r.failedPaths.size() < 50) r.failedPaths.push_back(rel.string());
                if (!opts.continueOnError) return r;  // ok stays false
            }
            else {
                ++r.filesCopied;
                r.bytesCopied += sz;
            }
        }
        r.ok = (r.filesFailed == 0);
        return r;
    }

}  // namespace chromiumprofile