//
// System-profile reader. Decodes the metrics SystemProfileProto that Chrome
// stashes (base64, RAW -- no gzip) in
//   Local State -> user_experience_metrics.stability.saved_system_profile
// into HostInfo (OS name/version, CPU arch/vendor, RAM, board model, GPU).


#include <chromium_parser/profile.h>
#include "internal.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace chromiumprofile {
    namespace {

        using Byte = unsigned char;

        // ---- base64 (standard alphabet; tolerates whitespace / padding) -------
        std::string Base64Decode(const std::string& in) {
            auto sextet = [](unsigned char c) -> int {
                if (c >= 'A' && c <= 'Z') return c - 'A';
                if (c >= 'a' && c <= 'z') return c - 'a' + 26;
                if (c >= '0' && c <= '9') return c - '0' + 52;
                if (c == '+') return 62;
                if (c == '/') return 63;
                return -1;
                };
            std::string out;
            unsigned acc = 0;
            int bits = -8;
            for (unsigned char c : in) {
                if (c == '=') break;
                int v = sextet(c);
                if (v < 0) continue;
                acc = (acc << 6) | static_cast<unsigned>(v);
                bits += 6;
                if (bits >= 0) {
                    out.push_back(static_cast<char>((acc >> bits) & 0xFF));
                    bits -= 8;
                }
            }
            return out;
        }

        // ---- minimal protobuf wire reader -------------------------------------
        bool ReadVarint(const Byte*& p, const Byte* end, std::uint64_t& out) {
            std::uint64_t result = 0;
            int shift = 0;
            while (p < end) {
                Byte b = *p++;
                result |= static_cast<std::uint64_t>(b & 0x7F) << shift;
                if (!(b & 0x80)) { out = result; return true; }
                shift += 7;
                if (shift >= 64) return false;
            }
            return false;
        }

        // Skip the payload of the field whose wire type is `wt`. Returns false on
        // malformed input. (Used to step over fields we don't want.)
        bool SkipField(const Byte*& p, const Byte* end, std::uint32_t wt) {
            if (wt == 0) { std::uint64_t d; return ReadVarint(p, end, d); }
            if (wt == 1) { if (end - p < 8) return false; p += 8; return true; }
            if (wt == 2) {
                std::uint64_t l;
                if (!ReadVarint(p, end, l)) return false;
                if (static_cast<std::uint64_t>(end - p) < l) return false;
                p += l; return true;
            }
            if (wt == 5) { if (end - p < 4) return false; p += 4; return true; }
            return false;  // group / unknown
        }

        // Find length-delimited field `want` in [b,end); point (data,len) at its
        // payload on success.
        bool FindLen(const Byte* b, const Byte* end, std::uint32_t want,
            const Byte*& data, std::size_t& len) {
            const Byte* p = b;
            while (p < end) {
                std::uint64_t tag;
                if (!ReadVarint(p, end, tag)) return false;
                std::uint32_t field = static_cast<std::uint32_t>(tag >> 3);
                std::uint32_t wt = static_cast<std::uint32_t>(tag & 7);
                if (field == 0) return false;
                if (wt == 2) {
                    std::uint64_t l;
                    if (!ReadVarint(p, end, l)) return false;
                    if (static_cast<std::uint64_t>(end - p) < l) return false;
                    if (field == want) { data = p; len = static_cast<std::size_t>(l); return true; }
                    p += l;
                }
                else if (!SkipField(p, end, wt)) {
                    return false;
                }
            }
            return false;
        }

        // Find varint field `want` in [b,end).
        bool FindVarint(const Byte* b, const Byte* end, std::uint32_t want, std::uint64_t& out) {
            const Byte* p = b;
            while (p < end) {
                std::uint64_t tag;
                if (!ReadVarint(p, end, tag)) return false;
                std::uint32_t field = static_cast<std::uint32_t>(tag >> 3);
                std::uint32_t wt = static_cast<std::uint32_t>(tag & 7);
                if (field == 0) return false;
                if (wt == 0) {
                    std::uint64_t v;
                    if (!ReadVarint(p, end, v)) return false;
                    if (field == want) { out = v; return true; }
                }
                else if (!SkipField(p, end, wt)) {
                    return false;
                }
            }
            return false;
        }

        std::string Str(const Byte* d, std::size_t l) {
            return std::string(reinterpret_cast<const char*>(d), l);
        }

        // Find a fixed-32 field (wire type 5) and return its raw bytes as uint32.
        // Used to read float fields: caller does memcpy(&f, &bits, 4).
        bool FindFixed32(const Byte* b, const Byte* end, std::uint32_t want, std::uint32_t& out) {
            const Byte* p = b;
            while (p < end) {
                std::uint64_t tag;
                if (!ReadVarint(p, end, tag)) return false;
                std::uint32_t field = static_cast<std::uint32_t>(tag >> 3);
                std::uint32_t wt    = static_cast<std::uint32_t>(tag & 7);
                if (field == 0) return false;
                if (wt == 5) {
                    if (end - p < 4) return false;
                    if (field == want) { std::memcpy(&out, p, 4); return true; }
                    p += 4;
                } else if (!SkipField(p, end, wt)) {
                    return false;
                }
            }
            return false;
        }

    }  // namespace

    // SystemProfileProto wire layout (fields extracted; numbers verified against
    // a real Local State blob and cross-checked with Chromium proto source):
    //   2  app_version
    //   3  channel  (enum: 0=unknown,1=canary,2=dev,3=beta,4=stable)
    //   4  application_locale
    //   5  os       { 1 name, 2 version, 3 kernel_version }
    //   6  hardware { 1 cpu_architecture, 2 system_ram_mb, 4 board_model,
    //                 7 form_factor (enum),
    //                 8 gpu { 1 vendor_id, 2 device_id, 3 driver,
    //                         5 gl_vendor, 7 gl_renderer },
    //                 9 screen_count, 10 primary_screen_width (float/I32),
    //                 11 primary_screen_height (float/I32),
    //                 13 cpu { 1 vendor_name, 3 num_cores, 4 num_logical,
    //                          5 max_speed_mhz, 6 is_hypervisor, 7 model_name } }
    //  14  brand_code
    //  22  install_date (weeks since 2003-01-07)
    HostInfo DecodeSystemProfile(const std::string& b64Profile) {
        HostInfo h;
        if (b64Profile.empty()) return h;
        const std::string raw = Base64Decode(b64Profile);
        if (raw.empty()) return h;

        const Byte* B = reinterpret_cast<const Byte*>(raw.data());
        const Byte* E = B + raw.size();
        const Byte* d; std::size_t l; std::uint64_t v;

        if (FindLen(B, E, 2, d, l)) h.appVersion = Str(d, l);

        // channel (3): enum varint
        if (FindVarint(B, E, 3, v)) {
            static const char* kCh[] = { "UNKNOWN","CANARY","DEV","BETA","STABLE" };
            h.channel = (v <= 4) ? kCh[v] : "UNKNOWN";
        }
        if (FindLen(B, E, 4, d, l))  h.locale    = Str(d, l);
        if (FindLen(B, E, 14, d, l)) h.brandCode = Str(d, l);
        if (FindVarint(B, E, 22, v)) h.installWeeks = static_cast<std::uint32_t>(v);

        // os { name, version, kernel_version }
        if (FindLen(B, E, 5, d, l)) {
            const Byte* ob = d; const Byte* oe = d + l;
            const Byte* dd; std::size_t ll;
            if (FindLen(ob, oe, 1, dd, ll)) h.osName          = Str(dd, ll);
            if (FindLen(ob, oe, 2, dd, ll)) h.osVersion       = Str(dd, ll);
            if (FindLen(ob, oe, 3, dd, ll)) h.osKernelVersion = Str(dd, ll);
        }

        // hardware { ... }
        if (FindLen(B, E, 6, d, l)) {
            const Byte* hb = d; const Byte* he = d + l;
            const Byte* dd; std::size_t ll;
            if (FindLen(hb, he, 1, dd, ll)) h.cpuArch    = Str(dd, ll);
            if (FindVarint(hb, he, 2, v))   h.ramMb      = static_cast<std::int64_t>(v);
            if (FindLen(hb, he, 4, dd, ll)) h.boardModel = Str(dd, ll);

            // form_factor (7): enum varint
            if (FindVarint(hb, he, 7, v)) {
                static const char* kFF[] = {
                    "UNKNOWN","DESKTOP","LAPTOP","TABLET","HANDSET",
                    "CONVERTIBLE","DETACHABLE","CHROMEBOX","CHROMEBASE",
                    "CHROMEBIT","CHROMEBOOK" };
                h.formFactor = (v <= 10) ? kFF[v] : "UNKNOWN";
            }

            // gpu { vendor_id, device_id, driver, gl_vendor, gl_renderer }
            if (FindLen(hb, he, 8, dd, ll)) {
                const Byte* gb = dd; const Byte* ge = dd + ll;
                const Byte* gg; std::size_t gl;
                if (FindVarint(gb, ge, 1, v)) h.gpuVendorId = static_cast<std::uint32_t>(v);
                if (FindVarint(gb, ge, 2, v)) h.gpuDeviceId = static_cast<std::uint32_t>(v);
                if (FindLen(gb, ge, 3, gg, gl)) h.gpuDriver   = Str(gg, gl);
                if (FindLen(gb, ge, 5, gg, gl)) h.gpuGlVendor = Str(gg, gl);
                if (FindLen(gb, ge, 7, gg, gl)) h.gpuRenderer = Str(gg, gl);
            }

            // screen_count (9), primary_screen_width (10, float), height (11, float)
            if (FindVarint(hb, he, 9, v)) h.screenCount = static_cast<std::uint32_t>(v);
            {
                std::uint32_t bits = 0;
                if (FindFixed32(hb, he, 10, bits)) std::memcpy(&h.screenWidth,  &bits, 4);
                if (FindFixed32(hb, he, 11, bits)) std::memcpy(&h.screenHeight, &bits, 4);
            }

            // cpu { vendor_name, num_cores, num_logical, speed_mhz, is_hypervisor, model_name }
            if (FindLen(hb, he, 13, dd, ll)) {
                const Byte* cb = dd; const Byte* ce = dd + ll;
                const Byte* cc; std::size_t cl;
                if (FindLen(cb, ce,  1, cc, cl)) h.cpuVendor     = Str(cc, cl);
                if (FindVarint(cb, ce, 3, v))    h.cpuNumCores   = static_cast<std::uint32_t>(v);
                if (FindVarint(cb, ce, 4, v))    h.cpuNumLogical = static_cast<std::uint32_t>(v);
                if (FindVarint(cb, ce, 5, v))    h.cpuSpeedMhz   = static_cast<std::uint32_t>(v);
                if (FindVarint(cb, ce, 6, v))    h.cpuIsHypervisor = (v != 0);
                if (FindLen(cb, ce,  7, cc, cl)) h.cpuModelName  = Str(cc, cl);
            }
        }

        h.present = !(h.osName.empty() && h.osVersion.empty() && h.cpuArch.empty() &&
            h.boardModel.empty() && h.appVersion.empty());
        return h;
    }

}  // namespace chromiumprofile