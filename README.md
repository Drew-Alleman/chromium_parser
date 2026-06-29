# chromium_parser

Native **C++17 forensic library** for Chrome / Chromium / Brave profiles — history, cookies, cache, extensions, autofill, downloads, synced devices, and more.

It is a **library first**: the parsing logic lives in `chromium_parser`, and the programs under [`examples/`](examples/) are thin drivers you can read, copy, and adapt.

---

## Scope
Today `chromium_parser` reads the **plaintext** portions of a profile. It does not decrypt protected values. 

Decryption of OS-protected blobs (Windows DPAPI / App-Bound) is on the [roadmap](#roadmap) for authorized analysis of profiles you control. The tool is intended for **lawful forensic and incident-response work onsystems and data you are authorized to examine**. YADADA you don't even care.

---

## Features

- **Identity & account** — profile key/name, signed-in Google account, gaia id, hosted (Workspace) domain, supervised/managed flags, ephemeral status.
- **History** — URLs, titles, visit and typed counts, last-visit times.
- **Bookmarks** — the full bookmark tree.
- **Downloads** — target path, source/tab URL, MIME type, byte counts, danger type, the extension that initiated it, and open state.
- **Logins** — site, username, signon realm, usage counts and dates (no passwords).
- **Cookies** — per-domain counts (total / secure / httpOnly / session), no values.
- **Extensions** — id, name, version, state, install location, permissions, update URL, plus a heuristic "risky extensions" view (broad host access / sensitive permissions).
- **Synced devices** — other machines signed into the account (name, model, OS, form factor, Chrome version).
- **Security posture** — Safe Browsing (standard/enhanced), password saving, leak detection — each reported only when the profile explicitly set it.
- **Autofill** — saved addresses and saved-card metadata (no full numbers).
- **Search engines** and **top sites**.
- **HTTP cache** — the disk (blockfile) cache: cached URLs, status codes, headers, and decompressed response bodies, with a filterable search.

Output as plain text, JSON, or CSV.

---

## Requirements

- **CMake 3.21+**
- **A C++17 MSVC toolchain** (Visual Studio 2022 or newer)
- **[vcpkg](https://vcpkg.io)**, with `VCPKG_ROOT` set to your vcpkg checkout

All third-party libraries are declared in [`vcpkg.json`](vcpkg.json) and installed
automatically on configure: `sqlite3` · `nlohmann-json` · `zlib` · `brotli` ·
`protobuf` · `snappy` · `leveldb[snappy]`.

> The protobuf/LevelDB readers (synced devices + variations) are **always built**. The
> generated protobuf C++ is vendored under [`third_party/gen/`](third_party/gen/), so
> the build needs **no chromium source checkout and no `protoc` step** — just the
> runtimes above from vcpkg.

---

## Building

```powershell
git clone https://github.com/Drew-Alleman/chromium_parser.git
cd chromium_parser

# configure + build (Debug) using the bundled presets
cmake --preset x64-debug
cmake --build --preset x64-debug
```

Or without presets:

```powershell
cmake -B out/build/x64-Debug -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake
cmake --build out/build/x64-Debug
```

This produces the static library `chromium_parser` plus one executable per file in
`examples/` (binaries land in `out/build/<preset>/`). The example folder is globbed, so
**adding a `.cpp` there and reconfiguring builds it automatically** — no CMake edits.

---

## Repository layout

```
chromium_parser/
├─ include/chromium_parser/profile.h   Public API (the only header you include)
├─ src/                                 Library implementation
│  ├─ capture.cpp                       Orchestrator: walks User Data, fills the model
│  ├─ dump.cpp                          Text / JSON / CSV exporters
│  ├─ readers_sqlite.cpp               History, logins, cookies, downloads, autofill...
│  ├─ readers_cache.cpp                Blockfile HTTP-cache reader + search
│  ├─ readers_sysprofile.cpp           Self-contained protobuf wire reader (no deps)
│  ├─ readers_proto.cpp                Synced devices + variations (protobuf/LevelDB)
│  └─ store_copy.cpp                   Copy-on-lock profile snapshotting
├─ third_party/gen/                     Vendored protoc output (committed)
├─ examples/                            One driver program per file
├─ CMakeLists.txt
├─ CMakePresets.json
└─ vcpkg.json
```

---

## Usage

Include the single public header and call `CaptureInstallation`:

```cpp
#include <chromium_parser/profile.h>
#include <iostream>

int main() {
    using namespace chromiumprofile;
    Installation inst = CaptureInstallation(
        R"(C:\Users\you\AppData\Local\Google\Chrome\User Data)");

    DumpText(inst, std::cout);                 // human-readable report
    for (const auto& p : inst.profiles())
        std::cout << p.identity().key << ": "
                  << p.history().entries.size() << " history rows\n";
}
```

Link against the `chromium_parser` target — it carries its include directories and all
dependency links as `PUBLIC`, so nothing else needs configuring:

```cmake
target_link_libraries(your_tool PRIVATE chromium_parser)
```

### Capture options

`CaptureInstallation` takes an optional `CaptureOptions`. Row caps are optional (a plain
call uses the defaults); `history` and `downloads` default to **200** rows, the rest are
uncapped. Set a field to **0** for "no limit".

```cpp
CaptureOptions opts;
opts.history      = 0;     // 0 = unlimited
opts.downloads    = 500;
opts.onDiagnostic = [](const Diagnostic& d) {
    if (d.level != Diagnostic::Level::Info)
        std::cerr << "[" << d.source << "] " << d.message << "\n";
};
Installation inst = CaptureInstallation(userDataDir, opts);
```

---

## Examples

### Quickstart (profile dump)

The smallest possible program: point it at a Chrome `User Data` directory and it prints
the full human-readable report. No options, no loops — the "hello world" of the library.

```cpp
// 01_quickstart.cpp   [simple]
#include <chromium_parser/profile.h>
#include <iostream>

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    if (argc < 2) {
        std::cerr << "usage: 01_quickstart <path to \"User Data\" dir>\n";
        return 2;
    }

    Installation inst = CaptureInstallation(argv[1]);  // default options
    DumpText(inst, std::cout);
    return 0;
}
```

Truncated, anonymized output (autofill, HTTP cache, and credit-card sections omitted;
account/host identifiers randomized):

<details>
<summary>Sample <code>01_quickstart</code> output</summary>

```
PS C:\Users\jdoe\chromium_parser> 01_quickstart.exe "C:\Users\jdoe\AppData\Local\Google\Chrome\User Data"
== Chromium installation snapshot ==
user_data_dir : "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data"
brand (guess) : Chrome
chrome_version: 149.0.7827.199
captured_at   : 2026-06-28 21:03:02
client_id     : (none -- UMA likely off)
stats_version : 149.0.7827.199-64
os_crypt_key  : present (opaque, 392 b64 chars)
variations    : not decoded
-- host --
os            : Windows NT 10.0.26200
cpu           : x86_64 (AuthenticAMD)
cpu_cores     : 16 physical / 1 logical
ram_mb        : 32582
board         : PRIME B650M-A WIFI II
form_factor   : UNKNOWN
gpu           : ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 (0x00002484) Direct3D11 vs_5_0 ps_5_0, D3D11-31.0.15.3713)
gpu_driver    : 31.0.15.3713
gpu_ids       : 0x10de / 0x2484
channel       : UNKNOWN
locale        : en-US
install_weeks : 1
app_version   : 149.0.7827.199-64
profiles      : 1
profile [Default]
  name            : Your Chrome
  user_name       : john.doe@gmail.com
  gaia_id         : 848192038698205056259
  gaia_given_name : John
  hosted_domain   : NO_HOSTED_DOMAIN
  managed_user_id : (none)
  shortcut_name   : John
  avatar_icon     : chrome://theme/IDR_PROFILE_AVATAR_26
  gaia_picture    : Google Profile Picture.png
  signed_in       : yes
  ephemeral       : no
  consented_acct  : yes
  force_signin_lock: no
  background_apps : no
  active_time     : 2026-06-28 17:14:30
  dir             : "C:\\Users\\jdoe\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
  credentials:
    Login Data : yes (80.0 KB)
    Cookies    : yes (96.0 KB)
    Web Data   : yes (192.0 KB)
  saved logins (26):
    - john.doe@gmail.com  @  android://2jmj7l5rSw0yVb_vlWAYkK_YBwk=@com.spotify.music/
    - jdoe  @  https://login.example.org/signin
  extensions (9):
    - Screen Recorder for Google Chrome™ v4.3.7 [enabled]  perms:3  src:webstore
    - Google Network Speech v1.0 [enabled]  perms:5  src:component
    - Google Docs Offline v1.107.1 [enabled]  perms:6  src:webstore
    - Chrome PDF Viewer v1 [enabled]  perms:7  src:component
    - Google Hangouts v1.3.26 [enabled]  perms:4  src:component
    - Chrome Web Store Payments v1.0.0.6 [enabled]  perms:6  src:component
  devices (3):
    - jdoe-pixel [OS_TYPE_ANDROID/DEVICE_FORM_FACTOR_PHONE]  Google Pixel 7  updated 2026-06-23 00:48:33
    - desktop-q7k2 [OS_TYPE_WINDOWS/DEVICE_FORM_FACTOR_DESKTOP]  ASUSTeK COMPUTER INC. PRIME B650M-A WIFI II  updated 2026-06-28 07:27:30
  bookmarks (2):
    - Wikipedia  https://www.wikipedia.org/
    - Inbox (1,432) - john.doe@gmail.com - Gmail  https://mail.google.com/mail/u/0/#inbox
  security:
    safe_browsing  : (default: standard)
    pw_saving      : (default)
    leak_detection : (default)
  cookie domains (36):
    - .google.com  (30 cookies)
    - .youtube.com  (28 cookies)
    (+21 more; use 03_export for the full list as JSON)
  downloads (1):
    - C:\Users\jdoe\Downloads\ChromeSetup (1).exe
        from https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B722A5C4F-CD8A-4EB8-AFA2-84E21CABD293%7D%26lang%3Den%26browser%3D4%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3D-arch_x64-statsdef_1%26installdataindex%3Dempty%26brand%3DTDXG/update2/installers/ChromeSetup.exe
```

</details>

### Limiting rows

`CaptureOptions` controls how many rows each large store returns. You don't need to set
any of these — a plain `CaptureInstallation(dir)` uses the defaults. `history` and
`downloads` default to 200 rows (the History DB can be enormous); the rest are uncapped.
Set a field to 0 for "everything", or to N to cap at N.

```cpp
// 02_limits.cpp   [simple]
#include <chromium_parser/profile.h>
#include <iostream>

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    if (argc < 2) {
        std::cerr << "usage: 02_limits <path to \"User Data\" dir>\n";
        return 2;
    }

    CaptureOptions opts;
    opts.history   = 1000;  // raise the history cap from the default 200
    opts.downloads = 0;     // 0 = no cap: every download row

    Installation inst = CaptureInstallation(argv[1], opts);

    for (const auto& p : inst.profiles())
        std::cout << "profile [" << p.identity().key << "]  "
                  << p.history().entries.size() << " history rows, "
                  << p.downloads().size() << " downloads\n";
    return 0;
}
```

```
PS C:\Users\jdoe\chromium_parser> 02_limits.exe "C:\Users\jdoe\AppData\Local\Google\Chrome\User Data"
profile [Default]  135 history rows, 1 downloads
```

### More examples

The rest of [`examples/`](examples/) covers the wider API.

## API overview
Everything lives in namespace `chromiumprofile`, declared in
[`include/chromium_parser/profile.h`](include/chromium_parser/profile.h).

```cpp
// Capture
Installation CaptureInstallation(const std::filesystem::path& userDataDir,
                                 const CaptureOptions& opts = {});

// Output
void        DumpText(const Installation&, std::ostream&);
std::string DumpJson(const Installation&);
void        DumpCsv (const Installation&, std::string_view section, std::ostream&);
// sections: devices, extensions, history, bookmarks, logins, cookies, downloads,
//           network, autofill, cards, search_engines, top_sites, cache

// Search & extract
std::vector<std::string> ListUniqueUrls(const Installation&);
CacheSearchResult        SearchCache(const Profile&, const CacheFilter&);
CopyProfileResult        CopyProfile(const std::filesystem::path& src,
                                     const std::filesystem::path& dst = {},
                                     const CopyProfileOptions& = {});
```

Data model:

```
Installation
├─ userDataDir() · capturedAt() · brand() · chromeVersion()
├─ metrics() · host() · variations() · lastActiveProfiles() · diagnostics()
└─ profiles() → Profile
   ├─ identity()  ProfileIdentity { key, name, userName, gaiaId, hostedDomain, ... }
   ├─ isSignedIn()
   ├─ logins() · cookieDomains() · downloads() · history() · bookmarks()
   ├─ extensions() · riskyExtensions() · devices()
   ├─ security() · autofillAddresses() · savedCards()
   ├─ searchEngines() · topSites() · networkState()
   └─ cacheEntries()
```

---

## Forensic notes

- **Timestamps.** Chrome stores times as microseconds since 1601-01-01; the library
  converts to `std::chrono::system_clock::time_point` and the exporters render
  wall-clock strings.
- **Locked databases.** Chrome holds an exclusive lock on its live SQLite stores while
  running. Readers detect this and fall back to a copy-on-lock read rather than failing;
  `CopyProfile` (see `07_snapshot`) exposes the same mechanism for full snapshots.
- **Cache contents.** The disk cache only contains what Chrome has flushed; recent
  activity may still be in memory. An empty result usually means a lightly used profile
  or freshly cleared data, not a parse failure.
- **Console encoding.** Output is UTF-8. On Windows, run `chcp 65001` first if you want
  non-ASCII (™, emoji, IDN) to render correctly in the console.

---

## Roadmap

- **DPAPI / App-Bound decryption** of encrypted blobs, for authorized analysis of
  profiles you control.
- **Browser-installation discovery** — auto-locate Chrome/Chromium/Brave user-data
  directories instead of passing a path.

---

## License

`chromium_parser` is released under the terms in the [`LICENSE`](LICENSE) file.

## Disclaimer

This software is intended for **lawful forensic analysis, incident response, and
research on systems and data you are authorized to examine**. You are responsible for
complying with all applicable laws and policies. The authors accept no liability for
misuse.
