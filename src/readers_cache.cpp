//
// Chromium blockfile HTTP cache reader.
//
// Reads Default/Cache/Cache_Data (index + data_0..data_N + f_XXXXXX) and
// extracts every HTTP/HTTPS entry: URL, status code, Content-Type, request /
// response timestamps, and body size. Non-HTTP entries (chrome-extension://,
// sparse media chunks, etc.) are silently skipped.
//
// The format is defined in net/disk_cache/blockfile/disk_format*.h and addr.h
// in the Chromium source tree. No Chromium headers are needed here; the
// structs are small enough to redeclare.
//
// On-disk layout of Cache_Data/:
//   index        - IndexHeader + CacheAddr hash table
//   data_0       - 36-byte RankingsNode blocks  (LRU metadata)
//   data_1       - 256-byte EntryStore blocks   (entry metadata + short keys)
//   data_2       - 1 KB data blocks             (stream payloads)
//   data_3       - 4 KB data blocks             (stream payloads)
//   f_XXXXXX     - external files for payloads > 16 KB
//
// Stream 0 of each entry holds a base::Pickle-serialized HttpResponseInfo:
//   [0..3]   Pickle header (payload_size, skip)
//   [4..7]   flags  (low byte = version, bit 31 = HAS_EXTRA_FLAGS)
//   [8..11]  extra_flags  (present when bit 31 of flags is set)
//   [12..19] request_time  (int64, base::Time::ToInternalValue)
//   [20..27] response_time (int64)
//   [28..35] original_response_time (int64, added in version 3)
//   [36..39] headers string length (int32)
//   [40..]   raw_headers_: null-delimited "HTTP/1.1 200 OK\0name: value\0...\0"
//
#include <chromium_parser/profile.h>
#include "internal.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <zlib.h>
#include <brotli/decode.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace chromiumprofile {
    namespace {

        // ---- on-disk constants (from disk_format*.h / addr.h) ----------------------

        static constexpr uint32_t kIndexMagic = 0xC103CAC3;
        static constexpr uint32_t kBlockMagic = 0xC104CAC3;
        static constexpr int      kBlockHdrSize = 8192;       // block file header
        static constexpr int      kIndexHdrSize = 368;        // sizeof(IndexHeader)
        static constexpr int      kDefaultTable = 0x10000;    // default hash table size
        static constexpr int      kEntryNormal = 0;          // EntryState::ENTRY_NORMAL

        // RESPONSE_INFO flags (from http_response_info.cc)
        static constexpr int kResponseInfoVersionMask = 0xFF;
        static constexpr int kResponseInfoVersion3 = 3;
        static constexpr int kHasExtraFlags = 1 << 31;

        // ---- CacheAddr decoding (from addr.h) --------------------------------------

        enum FileType { EXTERNAL = 0, RANKINGS = 1, BLOCK_256 = 2, BLOCK_1K = 3, BLOCK_4K = 4 };

        struct AddrInfo {
            bool     ok = false;
            bool     external = false;
            FileType type = EXTERNAL;
            int      fileNum = 0;   // N in "data_N"  or  XXXXXX in "f_XXXXXX"
            int      block = 0;   // starting block index within the file
            int      nblocks = 1;   // contiguous blocks allocated
            int      blockSize = 0;   // bytes per block for this type
        };

        static int BlockSizeFor(FileType t) {
            switch (t) {
            case RANKINGS:  return 36;
            case BLOCK_256: return 256;
            case BLOCK_1K:  return 1024;
            case BLOCK_4K:  return 4096;
            default:        return 0;
            }
        }

        static AddrInfo DecodeAddr(uint32_t raw) {
            AddrInfo a;
            if (!(raw & 0x80000000u)) return a;   // not initialized
            a.ok = true;
            a.type = static_cast<FileType>((raw >> 28) & 7);
            a.external = (a.type == EXTERNAL);
            a.nblocks = ((raw >> 24) & 3) + 1;
            a.fileNum = (int)((raw >> 16) & 0xFF);
            a.block = (int)(raw & 0xFFFF);
            a.blockSize = BlockSizeFor(a.type);
            if (a.external) {
                a.fileNum = (int)(raw & 0x0FFFFFFFu);
                a.nblocks = 1;
            }
            return a;
        }

        // ---- on-disk structs (packed to match Chromium's layout) -------------------

#pragma pack(push, 1)

// Minimal IndexHeader: we only need magic, version, num_entries, table_len.
// Full size is 368 bytes (verified empirically: index_file_size - table_len*4).
        struct IndexHeader {
            uint32_t magic;
            uint32_t version;
            int32_t  num_entries;
            int32_t  old_v2_num_bytes;
            int32_t  last_file;
            int32_t  this_id;
            uint32_t stats;
            int32_t  table_len;
            // rest of the 368 bytes are crash/experiment/timestamps/LRU — not needed
        };

        // EntryStore: 256 bytes (BLOCK_256).
        // For keys > 160 bytes, num_blocks > 1 and the key continues in the next blocks.
        // For keys > 927 bytes, long_key points to a separate data block / external file.
        struct EntryStore {
            uint32_t hash;
            uint32_t next;            // CacheAddr of next entry in this hash bucket
            uint32_t rankings_node;   // CacheAddr of the RankingsNode
            int32_t  reuse_count;
            int32_t  refetch_count;
            int32_t  state;           // 0=NORMAL, 1=EVICTED, 2=DOOMED
            uint64_t creation_time;
            int32_t  key_len;
            uint32_t long_key;        // CacheAddr for keys > 4 blocks
            int32_t  data_size[4];
            uint32_t data_addr[4];    // CacheAddr for each stream
            uint32_t flags;
            int32_t  pad[4];
            uint32_t self_hash;
            char     key[160];        // 256 - 96 = 160 bytes; null-terminated if key fits
        };
        static_assert(sizeof(EntryStore) == 256, "EntryStore layout mismatch");

#pragma pack(pop)

        // ---- file loader -----------------------------------------------------------
        // Chrome opens cache files with FILE_SHARE_READ|FILE_SHARE_WRITE (memory-mapped
        // write access). std::ifstream only requests FILE_SHARE_READ back, which the OS
        // rejects because Chrome's write access isn't covered.  On Windows we open with
        // full sharing (READ|WRITE|DELETE) to read Chrome's live cache files directly.

        static std::vector<uint8_t> LoadFile(const fs::path& p) {
            std::vector<uint8_t> buf;
#ifdef _WIN32
            HANDLE h = CreateFileW(p.wstring().c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) return buf;
            LARGE_INTEGER sz{};
            if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0) { CloseHandle(h); return buf; }
            buf.resize(static_cast<size_t>(sz.QuadPart));
            DWORD got = 0;
            if (!ReadFile(h, buf.data(), static_cast<DWORD>(sz.QuadPart), &got, nullptr)
                || got != static_cast<DWORD>(sz.QuadPart))
                buf.clear();
            CloseHandle(h);
#else
            std::error_code ec;
            if (!fs::exists(p, ec)) return buf;
            std::ifstream f(p, std::ios::binary);
            if (!f) return buf;
            f.seekg(0, std::ios::end);
            auto fsz = (std::streamoff)f.tellg();
            if (fsz <= 0) return buf;
            f.seekg(0);
            buf.resize(static_cast<size_t>(fsz));
            f.read(reinterpret_cast<char*>(buf.data()), fsz);
            if (!f.good() && !f.eof()) buf.clear();
#endif
            return buf;
        }

        // Lightweight wrapper around a loaded block file.
        struct BlockFile {
            std::vector<uint8_t> data;
            bool ok() const { return !data.empty(); }

            // Read `nblocks` consecutive blocks of `bsize` bytes starting at `idx`.
            bool read(int idx, int nblocks, int bsize, void* out) const {
                size_t off = (size_t)kBlockHdrSize + (size_t)idx * bsize;
                size_t len = (size_t)nblocks * bsize;
                if (off + len > data.size()) return false;
                std::memcpy(out, data.data() + off, len);
                return true;
            }
        };

        // ---- base::Pickle reader ---------------------------------------------------
        // Format: 4-byte payload_size header, then 4-byte-aligned fields.

        class Pickle {
        public:
            Pickle(const uint8_t* data, size_t len)
                : cur_(data + 4), end_(data + len) {
            }  // skip 4-byte pickle header

            bool i32(int32_t& v) {
                if (cur_ + 4 > end_) return false;
                std::memcpy(&v, cur_, 4); cur_ += 4; return true;
            }
            bool i64(int64_t& v) {
                if (cur_ + 8 > end_) return false;
                std::memcpy(&v, cur_, 8); cur_ += 8; return true;
            }
            // WriteString(): int32 length + bytes + alignment padding to 4 bytes
            bool str(std::string& out) {
                int32_t len = 0;
                if (!i32(len) || len < 0) return false;
                if (cur_ + len > end_) return false;
                out.assign(reinterpret_cast<const char*>(cur_), static_cast<size_t>(len));
                cur_ += (static_cast<size_t>(len) + 3) & ~3u;  // advance with padding
                return true;
            }
            bool skip64() { int64_t v; return i64(v); }

        private:
            const uint8_t* cur_;
            const uint8_t* const end_;
        };

        // ---- stream-0 (HttpResponseInfo) parser ------------------------------------

        static std::optional<Timestamp> ChromeTime(int64_t v) {
            if (v <= 0) return std::nullopt;
            // base::Time::ToInternalValue() = microseconds since 1601-01-01.
            // Subtract the 1601→1970 gap; guard against pre-Unix-epoch results
            // (e.g. default/zero timestamps) that crash localtime on Windows.
            long long unix_ms = v / 1000 - 11644473600000LL;
            if (unix_ms < 0) return std::nullopt;
            return Timestamp(std::chrono::milliseconds(unix_ms));
        }

        // Parse the pickled HttpResponseInfo from stream 0.
        // Fills out, returns false if stream 0 doesn't look like a valid HTTP response.
        static bool ParseStream0(const uint8_t* data, size_t len, CacheEntry& out) {
            if (len < 40) return false;
            Pickle p(data, len);

            int32_t flags = 0;
            if (!p.i32(flags)) return false;

            int version = flags & kResponseInfoVersionMask;
            if (flags & kHasExtraFlags) { int32_t x; if (!p.i32(x)) return false; }

            int64_t rqt = 0, rst = 0;
            if (!p.i64(rqt) || !p.i64(rst)) return false;
            out.requestTime = ChromeTime(rqt);
            out.responseTime = ChromeTime(rst);

            if (version >= kResponseInfoVersion3) { if (!p.skip64()) return false; }

            // Headers: WriteString(raw_headers_)
            std::string raw;
            if (!p.str(raw) || raw.empty()) return false;

            // raw_headers_ format: "HTTP/1.1 200 OK\0name: value\0...\0"
            // First token is the status line; remaining tokens are "name: value" pairs.
            bool first = true;
            size_t pos = 0;
            while (pos < raw.size()) {
                size_t end = raw.find('\0', pos);
                if (end == std::string::npos) end = raw.size();

                std::string_view tok(raw.data() + pos, end - pos);
                if (!tok.empty()) {
                    if (first) {
                        auto s1 = tok.find(' ');
                        if (s1 != std::string_view::npos) {
                            auto s2 = tok.find(' ', s1 + 1);
                            auto code = tok.substr(s1 + 1,
                                s2 == std::string_view::npos ? std::string_view::npos : s2 - s1 - 1);
                            try { out.statusCode = std::stoi(std::string(code)); }
                            catch (...) {}
                        }
                        first = false;
                    }
                    else {
                        auto colon = tok.find(':');
                        if (colon != std::string_view::npos) {
                            std::string name(tok.substr(0, colon));
                            for (char& c : name) c = (char)std::tolower((unsigned char)c);

                            std::string_view val = tok.substr(colon + 1);
                            while (!val.empty() && val[0] == ' ') val.remove_prefix(1);
                            std::string valStr(val);

                            out.headers.emplace_back(name, valStr);

                            if (name == "content-type" && out.mimeType.empty()) {
                                auto semi = val.find(';');
                                out.mimeType = std::string(
                                    semi == std::string_view::npos ? val : val.substr(0, semi));
                                while (!out.mimeType.empty() && out.mimeType.back() == ' ')
                                    out.mimeType.pop_back();
                            }
                        }
                    }
                }
                pos = end + 1;
            }

            return out.statusCode > 0;
        }

        // ---- body helpers ----------------------------------------------------------

        // Returns true for MIME types whose body is human-readable text and
        // forensically interesting. Binary types (images, fonts, wasm, video) are
        // excluded — they're large and useless as raw bytes.
        static bool IsTextMime(const std::string& mime) {
            if (mime.empty()) return false;
            // Exact matches
            static const char* const kText[] = {
                "text/html", "text/plain", "text/xml", "text/csv",
                "application/json", "application/ld+json",
                "application/xml", "application/xhtml+xml",
                "application/javascript", "text/javascript",
                "application/x-javascript", "application/graphql",
            };
            for (const char* t : kText)
                if (mime == t) return true;
            // Prefix match: text/* covers text/css, text/calendar, etc.
            if (mime.size() > 5 && mime.compare(0, 5, "text/") == 0) return true;
            return false;
        }

        // ---- cache reader ----------------------------------------------------------

        static void ReadCacheDir(const fs::path& cacheDir,
            Profile& prof, const CaptureCtx& diag) {
            // Index
            auto indexData = LoadFile(cacheDir / "index");
            if (indexData.size() < (size_t)kIndexHdrSize + 4) {
                diag.warn("cache", "index file missing or too small");
                return;
            }

            IndexHeader idxHdr;
            std::memcpy(&idxHdr, indexData.data(), sizeof(idxHdr));
            if (idxHdr.magic != kIndexMagic) {
                diag.warn("cache", "index magic mismatch — not a blockfile cache");
                return;
            }

            diag.info("cache", "blockfile index v" + std::to_string(idxHdr.version) +
                " (" + std::to_string(idxHdr.num_entries) + " entries on disk)");
            int tableLen = idxHdr.table_len > 0 ? idxHdr.table_len : kDefaultTable;
            if (indexData.size() < (size_t)kIndexHdrSize + (size_t)tableLen * 4) {
                diag.warn("cache", "index file truncated");
                return;
            }
            const uint32_t* table = reinterpret_cast<const uint32_t*>(
                indexData.data() + kIndexHdrSize);

            // Block file cache: load on demand, keyed by file number
            std::unordered_map<int, BlockFile> bfCache;
            auto getBlockFile = [&](int n) -> BlockFile* {
                auto it = bfCache.find(n);
                if (it != bfCache.end()) return it->second.ok() ? &it->second : nullptr;
                BlockFile bf;
                bf.data = LoadFile(cacheDir / ("data_" + std::to_string(n)));
                if (bf.ok()) {
                    uint32_t magic = 0;
                    std::memcpy(&magic, bf.data.data(), 4);
                    if (magic != kBlockMagic) bf.data.clear();
                }
                bfCache[n] = std::move(bf);
                return bfCache[n].ok() ? &bfCache[n] : nullptr;
                };

            // Read a data stream: could be in a block file or an f_XXXXXX external file
            auto readStream = [&](uint32_t addrRaw, int dataSize) -> std::vector<uint8_t> {
                std::vector<uint8_t> buf;
                if (!addrRaw || dataSize <= 0) return buf;
                AddrInfo a = DecodeAddr(addrRaw);
                if (!a.ok) return buf;

                if (a.external) {
                    char name[16];
                    std::snprintf(name, sizeof(name), "f_%06x", a.fileNum);
                    buf = LoadFile(cacheDir / name);
                    if ((int)buf.size() > dataSize) buf.resize(dataSize);
                    return buf;
                }

                BlockFile* bf = getBlockFile(a.fileNum);
                if (!bf) return buf;
                buf.resize((size_t)a.nblocks * a.blockSize);
                if (!bf->read(a.block, a.nblocks, a.blockSize, buf.data())) {
                    buf.clear();
                    return buf;
                }
                if ((int)buf.size() > dataSize) buf.resize(dataSize);
                return buf;
                };

            int parsed = 0, skipped = 0, malformed = 0;

            for (int i = 0; i < tableLen; ++i) {
                uint32_t addr = table[i];
                while (addr) {
                    AddrInfo a = DecodeAddr(addr);
                    if (!a.ok || a.type != BLOCK_256) { ++malformed; break; }

                    BlockFile* bf = getBlockFile(a.fileNum);
                    if (!bf) { ++malformed; break; }

                    // Read the EntryStore — may span multiple 256-byte blocks for long keys
                    std::vector<uint8_t> esBuf((size_t)a.nblocks * 256);
                    if (!bf->read(a.block, a.nblocks, 256, esBuf.data())) { ++malformed; break; }

                    const EntryStore* es = reinterpret_cast<const EntryStore*>(esBuf.data());
                    uint32_t nextAddr = es->next;

                    // Skip evicted / doomed entries
                    if (es->state != kEntryNormal) { addr = nextAddr; continue; }

                    // Extract the raw key from the EntryStore
                    std::string rawKey;
                    if (es->key_len > 0) {
                        size_t inlineAvail = esBuf.size() - 96;  // offsetof(EntryStore, key) = 96
                        if (es->key_len <= (int)inlineAvail) {
                            rawKey.assign(reinterpret_cast<const char*>(esBuf.data() + 96),
                                static_cast<size_t>(es->key_len));
                        }
                        else if (es->long_key) {
                            auto keyBuf = readStream(es->long_key, es->key_len);
                            if (!keyBuf.empty())
                                rawKey.assign(reinterpret_cast<const char*>(keyBuf.data()),
                                    static_cast<size_t>(es->key_len));
                        }
                    }

                    // Chrome 85+ double-keyed cache format:
                    //   "1/0/_dk_<top-level-site> <initiator-site> <resource-url>"
                    // The resource URL is always the last space-separated token.
                    // Older entries store the raw URL directly without a prefix.
                    std::string url;
                    {
                        // Find the last occurrence of http:// or https:// — that is the resource URL.
                        auto hs = rawKey.rfind("https://");
                        auto hp = rawKey.rfind("http://");
                        size_t start = std::string::npos;
                        if (hs != std::string::npos) start = hs;
                        if (hp != std::string::npos && (start == std::string::npos || hp > start))
                            start = hp;
                        if (start != std::string::npos)
                            url = rawKey.substr(start);
                    }

                    // Only HTTP and HTTPS
                    bool isHttp = !url.empty();

                    if (!isHttp) { ++skipped; addr = nextAddr; continue; }

                    if (es->data_size[0] > 0 && es->data_addr[0]) {
                        auto s0 = readStream(es->data_addr[0], es->data_size[0]);
                        if (!s0.empty()) {
                            CacheEntry ce;
                            ce.url = std::move(url);
                            ce.responseBodySize = es->data_size[1];
                            // Store block address for SearchCache lazy body reads
                            ce._stream1Addr = es->data_addr[1];
                            ce._stream1Size = es->data_size[1];
                            ce._cacheDataDir = cacheDir.string();
                            if (ParseStream0(s0.data(), s0.size(), ce)) {
                                // Read the response body (stream 1) for text-based content
                                // under the size cap. Skips images, large JS bundles, etc.
                                // Note: Chrome stores bodies with their Content-Encoding intact
                                // (gzip/br/zstd). We only store the body when it is uncompressed
                                // (no Content-Encoding header or "identity"), so callers always
                                // get readable text. Compressed bodies are flagged but not stored.
                                static constexpr int kBodySizeLimit = 256 * 1024; // 256 KB
                                int bodySize = es->data_size[1];
                                if (bodySize > 0 && bodySize <= kBodySizeLimit
                                    && es->data_addr[1] && IsTextMime(ce.mimeType)) {
                                    std::string enc = ce.header("content-encoding");
                                    bool compressed = !enc.empty() && enc != "identity";
                                    if (!compressed) {
                                        auto s1 = readStream(es->data_addr[1], bodySize);
                                        if (!s1.empty())
                                            ce.body.assign(
                                                reinterpret_cast<const char*>(s1.data()), s1.size());
                                    }
                                    // If compressed: body stays empty; responseBodySize still
                                    // tells the caller how many bytes are on disk.
                                }
                                prof.mutableCacheEntries().push_back(std::move(ce));
                                ++parsed;
                            }
                        }
                    }

                    addr = nextAddr;
                }
            }

            if (parsed > 0 || skipped > 0 || malformed > 0)
                diag.info("cache",
                    std::to_string(parsed) + " HTTP/S entries parsed" +
                    (skipped > 0
                        ? " (" + std::to_string(skipped) + " non-HTTP skipped)" : ""));
            if (malformed > 0)
                diag.warn("cache",
                    std::to_string(malformed) + " entr" + (malformed == 1 ? "y" : "ies") +
                    " abandoned mid-bucket (corrupt or truncated cache)");
        }

    }  // namespace

    void ReadCache(Profile& prof, const CaptureCtx& diag) {
        std::error_code ec;
        fs::path dir = prof.dir() / "Cache" / "Cache_Data";
        if (!fs::exists(dir, ec)) {
            dir = prof.dir() / "Cache";
            if (!fs::exists(dir, ec)) return;
        }
        ReadCacheDir(dir, prof, diag);
    }

    // ============================================================================
    // ContentCategory classification
    // ============================================================================

    ContentCategory ClassifyMime(const std::string& mime) {
        if (mime.empty()) return ContentCategory::Binary;
        if (mime == "text/html" || mime == "application/json" ||
            mime == "application/ld+json" || mime == "text/plain" ||
            mime == "application/xml" || mime == "text/xml" ||
            mime == "application/xhtml+xml" || mime == "text/csv" ||
            mime == "application/graphql" || mime == "application/x-ndjson")
            return ContentCategory::Data;
        if (mime == "text/javascript" || mime == "application/javascript" ||
            mime == "application/x-javascript" || mime == "text/x-javascript")
            return ContentCategory::Script;
        if (mime == "text/css")
            return ContentCategory::Style;
        if (mime.size() > 6 && mime.compare(0, 6, "image/") == 0)
            return ContentCategory::Image;
        if (mime.size() > 5 && mime.compare(0, 5, "font/") == 0)
            return ContentCategory::Font;
        if (mime.size() > 12 && mime.compare(0, 12, "application/") == 0) {
            std::string_view sub(mime.data() + 12, mime.size() - 12);
            if (sub == "font-woff" || sub == "font-woff2" || sub == "x-font-ttf" ||
                sub == "x-font-woff" || sub == "x-font-otf" || sub == "vnd.ms-fontobject")
                return ContentCategory::Font;
        }
        if (mime.size() > 6 && (mime.compare(0, 6, "audio/") == 0 ||
            mime.compare(0, 6, "video/") == 0))
            return ContentCategory::Media;
        return ContentCategory::Binary;
    }

    // ============================================================================
    // Decompression helpers
    // ============================================================================

    namespace {

        static std::string GzipDecompress(const uint8_t* in, size_t inLen, int maxBytes) {
            std::string out;
            z_stream zs{};
            if (inflateInit2(&zs, 15 + 16) != Z_OK) return out;
            zs.next_in = const_cast<Bytef*>(in);
            zs.avail_in = static_cast<uInt>(inLen);
            char buf[65536];
            int rc;
            do {
                zs.next_out = reinterpret_cast<Bytef*>(buf);
                zs.avail_out = sizeof(buf);
                rc = inflate(&zs, Z_NO_FLUSH);
                if (rc == Z_STREAM_ERROR || rc == Z_DATA_ERROR || rc == Z_MEM_ERROR) {
                    inflateEnd(&zs); out.clear(); return out;
                }
                out.append(buf, sizeof(buf) - zs.avail_out);
                if (maxBytes > 0 && (int)out.size() >= maxBytes) {
                    out.resize(maxBytes); break;
                }
            } while (rc != Z_STREAM_END);
            inflateEnd(&zs);
            return out;
        }

        static std::string BrotliDecompress(const uint8_t* in, size_t inLen, int maxBytes) {
            std::string out;
            // Brotli has no streaming API in the simple decoder — estimate output size.
            // Start at 3× input and grow if needed (up to maxBytes).
            size_t cap = maxBytes > 0
                ? static_cast<size_t>(maxBytes)
                : std::min(inLen * 10, static_cast<size_t>(4 * 1024 * 1024));
            out.resize(cap);
            size_t decoded = cap;
            BrotliDecoderResult r = BrotliDecoderDecompress(
                inLen, in, &decoded,
                reinterpret_cast<uint8_t*>(&out[0]));
            if (r != BROTLI_DECODER_RESULT_SUCCESS) { out.clear(); return out; }
            out.resize(decoded);
            return out;
        }

        // Decompress `raw` according to the Content-Encoding value `enc`.
        // Returns the plaintext body, or empty on failure / unsupported encoding.
        static std::string Decompress(const std::vector<uint8_t>& raw,
            const std::string& enc, int maxBytes) {
            if (enc == "gzip" || enc == "x-gzip")
                return GzipDecompress(raw.data(), raw.size(), maxBytes);
            if (enc == "br")
                return BrotliDecompress(raw.data(), raw.size(), maxBytes);
            if (enc.empty() || enc == "identity") {
                std::string s(reinterpret_cast<const char*>(raw.data()), raw.size());
                if (maxBytes > 0 && (int)s.size() > maxBytes) s.resize(maxBytes);
                return s;
            }
            return {};  // zstd / deflate / unknown: skip for now
        }

        // ============================================================================
        // MIME filter helper
        // ============================================================================

        static bool PassesMimeFilter(const std::string& mime, const CacheFilter& f) {
            // No MIME filtering active at all → fast pass
            if (!f.dataOnly && !f.skipScripts && !f.skipStyles &&
                !f.skipImages && !f.skipFonts && !f.skipMedia && !f.skipBinary)
                return true;

            ContentCategory cat = ClassifyMime(mime);
            if (f.dataOnly) return cat == ContentCategory::Data;
            switch (cat) {
            case ContentCategory::Script: return !f.skipScripts;
            case ContentCategory::Style:  return !f.skipStyles;
            case ContentCategory::Image:  return !f.skipImages;
            case ContentCategory::Font:   return !f.skipFonts;
            case ContentCategory::Media:  return !f.skipMedia;
            case ContentCategory::Binary: return !f.skipBinary;
            default:                      return true;  // Data always passes
            }
        }

    }  // namespace

    // ============================================================================
    // SearchCache — cascade filter engine
    // ============================================================================

    CacheSearchResult SearchCache(const Profile& prof, const CacheFilter& filter) {
        CacheSearchResult result;
        auto& results = result.hits;
        auto& preFiltered = result.preFiltered;
        auto& bodyRead = result.bodiesRead;
        auto& needleMiss = result.needleMiss;

        // Block file cache shared across all entries that reach body-read stage
        std::unordered_map<std::string, BlockFile> bfCache;
        auto getBF = [&](const fs::path& path) -> BlockFile* {
            auto it = bfCache.find(path.string());
            if (it != bfCache.end()) return it->second.ok() ? &it->second : nullptr;
            BlockFile bf;
            bf.data = LoadFile(path);
            if (bf.ok()) {
                uint32_t magic = 0;
                std::memcpy(&magic, bf.data.data(), 4);
                if (magic != kBlockMagic) bf.data.clear();
            }
            bfCache[path.string()] = std::move(bf);
            return bfCache[path.string()].ok() ? &bfCache[path.string()] : nullptr;
            };

        for (const auto& e : prof.cacheEntries()) {

            // ---- 1. MIME / content category (no I/O) ----------------------------
            if (!PassesMimeFilter(e.mimeType, filter)) { ++preFiltered; continue; }

            // ---- 2. URL filter (no I/O) -----------------------------------------
            if (!filter.urlContains.empty() &&
                e.url.find(filter.urlContains) == std::string::npos)
            {
                ++preFiltered; continue;
            }
            if (!filter.urlPrefix.empty() &&
                e.url.compare(0, filter.urlPrefix.size(), filter.urlPrefix) != 0)
            {
                ++preFiltered; continue;
            }

            // ---- 3. Status code filter (no I/O) ---------------------------------
            if (filter.statusMin > 0 && e.statusCode < filter.statusMin)
            {
                ++preFiltered; continue;
            }
            if (filter.statusMax > 0 && e.statusCode > filter.statusMax)
            {
                ++preFiltered; continue;
            }

            // ---- 4. Body size filter (no I/O) -----------------------------------
            if (filter.bodySizeMax > 0 && e.responseBodySize > filter.bodySizeMax)
            {
                ++preFiltered; continue;
            }

            // ---- 5. Header filter (in-memory, no I/O) ---------------------------
            if (!filter.headerName.empty()) {
                std::string hv = e.header(filter.headerName);
                if (hv.empty()) { ++preFiltered; continue; }
                if (!filter.headerValueContains.empty() &&
                    hv.find(filter.headerValueContains) == std::string::npos)
                {
                    ++preFiltered; continue;
                }
            }

            // ---- No needle → metadata match; body not needed --------------------
            if (filter.needle.empty()) {
                results.push_back(e);
                continue;
            }

            // ---- 6. Body read (I/O) + 7. Decompress (CPU) + 8. Needle ----------
            if (!e._stream1Addr || e._stream1Size <= 0) continue;

            // Locate the block file
            AddrInfo a = DecodeAddr(e._stream1Addr);
            if (!a.ok) continue;

            std::vector<uint8_t> rawBody;
            if (a.external) {
                char fname[16];
                std::snprintf(fname, sizeof(fname), "f_%06x", a.fileNum);
                rawBody = LoadFile(fs::path(e._cacheDataDir) / fname);
            }
            else {
                BlockFile* bf = getBF(
                    fs::path(e._cacheDataDir) / ("data_" + std::to_string(a.fileNum)));
                if (!bf) continue;
                rawBody.resize((size_t)a.nblocks * a.blockSize);
                if (!bf->read(a.block, a.nblocks, a.blockSize, rawBody.data()))
                {
                    rawBody.clear(); continue;
                }
            }
            if (rawBody.size() > (size_t)e._stream1Size)
                rawBody.resize(e._stream1Size);
            if (rawBody.empty()) continue;

            ++bodyRead;

            std::string body = Decompress(rawBody, e.header("content-encoding"),
                filter.maxBodyBytes);
            if (body.empty()) continue;  // compression unsupported or failed

            if (body.find(filter.needle) == std::string::npos)
            {
                ++needleMiss; continue;
            }

            CacheEntry hit = e;
            hit.body = std::move(body);
            results.push_back(std::move(hit));
        }

        return result;
    }

}  // namespace chromiumprofile