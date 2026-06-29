//
// The ONLY translation unit that pulls protobuf, LevelDB, and zlib. It decodes the
// two protobuf-backed sources: synced devices (DeviceInfoSpecifics over the sync
// LevelDB) and the variations seed (base64 -> gunzip -> VariationsSeed).
//
// It #includes pre-generated protobuf C++ (committed under third_party/gen), so the
// build needs neither a chromium source checkout nor a protoc step -- just the
// protobuf + LevelDB runtimes from vcpkg.
//
#include <chromium_parser/profile.h>
#include "internal.h"

#include <array>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

#include <zlib.h>
#include <leveldb/db.h>
#include "components/sync/protocol/device_info_specifics.pb.h"
#include "components/variations/proto/variations_seed.pb.h"

namespace fs = std::filesystem;

namespace chromiumprofile {
    namespace {

        // ---- base64 (standard alphabet) ----
        std::string Base64Decode(const std::string& in) {
            static const std::string T =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::array<int, 256> rev{};
            rev.fill(-1);
            for (int i = 0; i < 64; ++i) rev[(unsigned char)T[i]] = i;
            std::string out;
            int val = 0, bits = -8;
            for (unsigned char c : in) {
                if (c == '=' || rev[c] == -1) continue;
                val = (val << 6) + rev[c];
                bits += 6;
                if (bits >= 0) {
                    out.push_back(char((val >> bits) & 0xFF));
                    bits -= 8;
                }
            }
            return out;
        }

        std::string Gunzip(const std::string& in) {
            z_stream zs{};
            if (inflateInit2(&zs, 15 + 16) != Z_OK) return {};
            zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
            zs.avail_in = static_cast<uInt>(in.size());
            std::string out;
            char buf[64 * 1024];
            int rc;
            do {
                zs.next_out = reinterpret_cast<Bytef*>(buf);
                zs.avail_out = sizeof(buf);
                rc = inflate(&zs, Z_NO_FLUSH);
                if (rc != Z_OK && rc != Z_STREAM_END) { inflateEnd(&zs); return {}; }
                out.append(buf, sizeof(buf) - zs.avail_out);
            } while (rc != Z_STREAM_END);
            inflateEnd(&zs);
            return out;
        }

        // Copy a LevelDB store directory file-by-file (skip LOCK). A recursive copy can
        // silently drop the locked current ".log" on Windows, and a running browser's
        // device records often live ONLY in that .log (store too small to have flushed
        // to a .ldb). Returns dst if any usable file came along, else {}. This is the
        // copyStore callback handed to ReadLockedStore by ReadSyncData.
        fs::path CopyLevelDbDir(const fs::path& src, const fs::path& dst) {
            std::error_code ec;
            bool any = false;
            for (const auto& de : fs::directory_iterator(src, ec)) {
                if (ec) break;
                const std::string fn = de.path().filename().string();
                if (fn == "LOCK") continue;                  // never copy the lock file
                std::error_code fe;
                fs::copy_file(de.path(), dst / fn, fs::copy_options::overwrite_existing, fe);
                if (!fe) any = true;                          // tolerate unreadable files
            }
            return any ? dst : fs::path{};
        }

    }  // namespace

    // Local State variations_compressed_seed (already base64) -> VariationsSummary.
    // capture.cpp extracts the seed string and passes it here so this TU never sees
    // JSON. base64 -> gunzip -> parse the serialized variations::VariationsSeed.
    VariationsSummary DecodeVariations(const std::string& b64Seed) {
        VariationsSummary out;
        std::string raw = Gunzip(Base64Decode(b64Seed));
        if (raw.empty()) return out;  // not gzipped / decode failed

        variations::VariationsSeed seed;
        if (seed.ParseFromString(raw)) {
            out.present = true;
            out.studyCount = seed.study_size();
            out.studyNames.reserve(seed.study_size());
            for (const auto& study : seed.study()) out.studyNames.push_back(study.name());
        }
        return out;
    }

    // Sync DataTypeStore LevelDB -> DeviceInfo. DeviceInfoSyncBridge stores bare
    // DeviceInfoSpecifics (no EntitySpecifics wrapper); filter by key prefix and
    // try-parse. Uses the same shared copy-on-lock helper as the SQLite readers.
    void ReadSyncData(Profile& prof, const CaptureCtx& diag) {
        ReadLockedStore(
            prof.dir() / "Sync Data" / "LevelDB", "sync",
            [&](const fs::path& path) -> bool {
                leveldb::Options opts;
                opts.create_if_missing = false;
                opts.paranoid_checks = false;
                leveldb::DB* raw = nullptr;
                if (!leveldb::DB::Open(opts, path.string(), &raw).ok()) return false; // locked/corrupt
                std::unique_ptr<leveldb::DB> db(raw);
                std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));
                for (it->SeekToFirst(); it->Valid(); it->Next()) {
                    // Device records live under "device_info-dt-"; skip metadata (-md-)
                    // and the per-type GlobalMetadata. Filtering by key avoids the
                    // false positives a permissive parse yields on other datatypes.
                    std::string key_lc = ToLower(it->key().ToString());  // ToLower from internal.h
                    if (key_lc.find("device_info") == std::string::npos) continue;
                    if (key_lc.find("-md-") != std::string::npos) continue;
                    if (key_lc.find("globalmetadata") != std::string::npos) continue;

                    sync_pb::DeviceInfoSpecifics dev;
                    if (dev.ParseFromString(it->value().ToString()) && !dev.cache_guid().empty()) {
                        DeviceInfo d;
                        d.guid = dev.cache_guid();
                        d.clientName = dev.client_name();
                        d.model = dev.model();
                        if (d.model.empty())
                            d.model = dev.server_determined_model_name();  // deprecated -> modern
                        d.manufacturer = dev.manufacturer();
                        if (dev.has_device_form_factor())
                            d.formFactor = std::string(sync_pb::SyncEnums::DeviceFormFactor_Name(
                                dev.device_form_factor()));
                        d.hardwareClass = dev.full_hardware_class();
                        d.chromeVersion = dev.chrome_version();
                        if (d.chromeVersion.empty() && dev.has_chrome_version_info())
                            d.chromeVersion = dev.chrome_version_info().version_number();
                        if (dev.has_os_type())
                            d.osType = std::string(sync_pb::SyncEnums::OsType_Name(dev.os_type()));
                        else if (dev.has_device_type())
                            d.osType = std::string(sync_pb::SyncEnums::DeviceType_Name(dev.device_type()));
                        if (dev.has_last_updated_timestamp())
                            d.lastUpdated = Timestamp(
                                std::chrono::milliseconds(dev.last_updated_timestamp()));
                        prof.mutableDevices().push_back(std::move(d));
                    }
                }
                return true;  // opened + iterated; db closes as this scope exits
            },
            CopyLevelDbDir, diag);
    }

}  // namespace chromiumprofile