//
// SQLite-backed readers: saved usernames (Login Data) and recent history. These
// read ONLY plaintext columns -- origin_url/username_value and the history urls
// table -- and never touch the OSCrypt/DPAPI-encrypted password or value blobs.
// Depends only on sqlite3, plus the shared copy-on-lock helper in store_copy.cpp.
//
#include <chromium_parser/profile.h>
#include "internal.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include <sqlite3.h>

namespace fs = std::filesystem;

namespace chromiumprofile {
    namespace {

        // Column-text helper, declared up front so every query below can use it.
        static std::string ColText(sqlite3_stmt* stmt, int col);

        // Copy a SQLite db plus its -wal/-shm sidecars into dst. Returns the copied
        // db path (dst/<name>), or {} if the main file could not be copied. This is
        // the copyStore callback handed to ReadLockedStore by both readers below.
        fs::path CopySqliteDb(const fs::path& src, const fs::path& dst) {
            std::error_code ec;
            bool mainCopied = false;
            for (const char* suffix : { "", "-wal", "-shm" }) {
                fs::path s = src; s += suffix;             // "History" -> "History-wal"
                if (!fs::exists(s, ec)) continue;
                std::error_code fe;
                fs::copy_file(s, dst / s.filename(), fs::copy_options::overwrite_existing, fe);
                if (!fe && suffix[0] == '\0') mainCopied = true;
            }
            return mainCopied ? (dst / src.filename()) : fs::path{};
        }

        // Open a SQLite database read-only. Returns true on success; returns false
        // (and leaves db == nullptr) when the open fails OR when a lock probe detects
        // that Chrome holds an exclusive lock.
        //
        // Chrome uses PRAGMA locking_mode=EXCLUSIVE on sensitive databases (Login Data,
        // History, etc.) while running. sqlite3_open_v2 ?mode=ro succeeds regardless
        // (no lock at open time), but the first sqlite3_step returns SQLITE_BUSY.
        // Without the probe, the query loop exits silently with 0 rows, the function
        // returns true, and ReadLockedStore never reaches the copy path. The probe
        // returns false on SQLITE_BUSY, so the caller sees failure and ReadLockedStore
        // copies the database (which is not locked by Chrome) and reads from the copy.
        //
        // WAL replay note: ?mode=ro prevents writing to the wal-index, so SQLite reads
        // only the main database file when a WAL is present. ReadLockedStore handles
        // this separately via WAL-file detection before calling tryRead.
        bool OpenSqliteRO(const fs::path& dbPath, sqlite3*& db) {
            db = nullptr;
            std::string uri = "file:" + dbPath.generic_string() + "?mode=ro";
            if (sqlite3_open_v2(uri.c_str(), &db,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
                if (db) { sqlite3_close(db); db = nullptr; }
                return false;
            }
            // Probe for exclusive lock: acquire a shared lock with a minimal read.
            // SQLITE_BUSY / SQLITE_LOCKED → Chrome holds the database → caller copies.
            sqlite3_stmt* probe = nullptr;
            int pr = sqlite3_prepare_v2(db,
                "SELECT 1 FROM sqlite_master LIMIT 1", -1, &probe, nullptr);
            if (pr == SQLITE_BUSY || pr == SQLITE_LOCKED) {
                sqlite3_close(db); db = nullptr; return false;
            }
            if (pr == SQLITE_OK) {
                int sr = sqlite3_step(probe);
                sqlite3_finalize(probe);
                if (sr == SQLITE_BUSY || sr == SQLITE_LOCKED) {
                    sqlite3_close(db); db = nullptr; return false;
                }
            }
            return true;
        }

        // ---- query helpers -------------------------------------------------------
        bool QuerySqliteLogins(const fs::path& dbPath, std::vector<SavedLogin>& out) {
            sqlite3* db = nullptr;
            if (!OpenSqliteRO(dbPath, db)) return false;
            sqlite3_stmt* stmt = nullptr;
            const char* sql =
                "SELECT origin_url, username_value, signon_realm, times_used, "
                "       date_last_used, date_created "
                "FROM logins WHERE username_value <> '' ORDER BY origin_url;";
            auto micros = [&](int col) { return FromChromeMicros(sqlite3_column_int64(stmt, col)); };
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    SavedLogin s;
                    s.url = ColText(stmt, 0);
                    s.username = ColText(stmt, 1);
                    s.signonRealm = ColText(stmt, 2);
                    s.timesUsed = sqlite3_column_int(stmt, 3);
                    s.dateLastUsed = micros(4);
                    s.dateCreated = micros(5);
                    out.push_back(std::move(s));
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
            return true;
        }

        // Most-recent visits from the History db's urls table
        bool QuerySqliteHistory(const fs::path& dbPath, History& hist, int limit) {
            sqlite3* db = nullptr;
            if (!OpenSqliteRO(dbPath, db)) return false;
            sqlite3_stmt* stmt = nullptr;
            // Static SQL; the cap is bound, not concatenated. SQLite treats LIMIT -1 as
            // "no limit", so caller's 0 ("unlimited") maps to -1.
            const char* sql =
                "SELECT url, title, visit_count, typed_count, last_visit_time FROM urls "
                "WHERE visit_count > 0 ORDER BY last_visit_time DESC LIMIT ?;";
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, limit > 0 ? limit : -1);   // 0 -> -1 (unlimited)
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    HistoryEntry h;
                    h.url = ColText(stmt, 0);
                    h.title = ColText(stmt, 1);
                    h.visitCount = sqlite3_column_int(stmt, 2);
                    h.typedCount = sqlite3_column_int(stmt, 3);
                    h.lastVisit = FromChromeMicros(sqlite3_column_int64(stmt, 4));
                    hist.entries.push_back(std::move(h));
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
            return true;
        }

        // Cookies db -> per-host aggregate. METADATA ONLY: host_key and the flag
        // columns are plaintext; value/encrypted_value are never selected. (yet)
        bool QuerySqliteCookies(const fs::path& dbPath, std::vector<CookieDomain>& out, int limit) {
            sqlite3* db = nullptr;
            if (!OpenSqliteRO(dbPath, db)) return false;
            sqlite3_stmt* stmt = nullptr;
            const char* sql =
                "SELECT host_key, COUNT(*), "
                "       SUM(is_secure), SUM(is_httponly), "
                "       SUM(CASE WHEN is_persistent=0 THEN 1 ELSE 0 END) "
                "FROM cookies GROUP BY host_key ORDER BY COUNT(*) DESC LIMIT ?;";
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, limit > 0 ? limit : -1);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    CookieDomain c;
                    c.host = ColText(stmt, 0);
                    c.cookieCount = sqlite3_column_int(stmt, 1);
                    c.secureCount = sqlite3_column_int(stmt, 2);
                    c.httpOnlyCount = sqlite3_column_int(stmt, 3);
                    c.sessionCount = sqlite3_column_int(stmt, 4);
                    out.push_back(std::move(c));
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
            return true;
        }

        // History db -> recent downloads. target_path/tab_url/danger_type are
        // plaintext; the final URL of the redirect chain is the actual byte source.
        bool QuerySqliteDownloads(const fs::path& dbPath, std::vector<DownloadEntry>& out, int limit) {
            sqlite3* db = nullptr;
            if (!OpenSqliteRO(dbPath, db)) return false;
            sqlite3_stmt* stmt = nullptr;
            const char* sql =
                "SELECT d.target_path, d.tab_url, d.mime_type, d.danger_type, d.state, "
                "       d.total_bytes, d.received_bytes, d.by_ext_id, d.by_ext_name, "
                "       d.opened, d.start_time, "
                "       (SELECT url FROM downloads_url_chains c WHERE c.id=d.id "
                "        ORDER BY chain_index DESC LIMIT 1) "
                "FROM downloads d ORDER BY d.start_time DESC LIMIT ?;";
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, limit > 0 ? limit : -1);
                auto txt = [&](int col) { return ColText(stmt, col); };
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    DownloadEntry d;
                    d.targetPath = txt(0);
                    d.tabUrl = txt(1);
                    d.mimeType = txt(2);
                    d.dangerType = sqlite3_column_int(stmt, 3);
                    d.state = sqlite3_column_int(stmt, 4);
                    d.totalBytes = sqlite3_column_int64(stmt, 5);
                    d.receivedBytes = sqlite3_column_int64(stmt, 6);
                    d.byExtId = txt(7);
                    d.byExtName = txt(8);
                    d.opened = sqlite3_column_int(stmt, 9) != 0;
                    d.startTime = FromChromeMicros(sqlite3_column_int64(stmt, 10));
                    d.sourceUrl = txt(11);
                    out.push_back(std::move(d));
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
            return true;
        }

        // Column text helper shared by the Web Data queries below.
        static std::string ColText(sqlite3_stmt* stmt, int col) {
            const unsigned char* v = sqlite3_column_text(stmt, col);
            return v ? reinterpret_cast<const char*>(v) : "";
        }

        // Find-or-create an AutofillAddress by guid (linear search; sets are small).
        static AutofillAddress& FindOrCreate(std::vector<AutofillAddress>& v,
            const std::string& guid) {
            for (auto& a : v) if (a.guid == guid) return a;
            v.push_back({});
            v.back().guid = guid;
            return v.back();
        }

        // Web Data SQLite -> autofill addresses + credit cards + search engines.
        // Two schemas tried for autofill:
        //   1. autofill_profiles + join tables (legacy, Chrome <114; also server profiles)
        //   2. contact_info_type_tokens (Chrome 114+, locally-created addresses)
        // Credit cards and search engines are stable across all versions.
        bool QuerySqliteWebData(const fs::path& dbPath,
            std::vector<AutofillAddress>& addrsOut,
            std::vector<SavedCard>& cardsOut,
            std::vector<SearchEngine>& enginesOut,
            int searchEngineLimit) {
            sqlite3* db = nullptr;
            if (!OpenSqliteRO(dbPath, db)) return false;

            // --- autofill_profiles + join tables (modern schema has street_address) ---
            {
                sqlite3_stmt* stmt = nullptr;
                const char* kModern =
                    "SELECT ap.guid,"
                    " COALESCE(n.full_name,''),"
                    " COALESCE(e.email,''),"
                    " COALESCE(ph.number,''),"
                    " COALESCE(ap.company_name,''),"
                    " COALESCE(ap.street_address,''),"
                    " COALESCE(ap.city,''),"
                    " COALESCE(ap.state,''),"
                    " COALESCE(ap.zipcode,''),"
                    " COALESCE(ap.country_code,'')"
                    " FROM autofill_profiles ap"
                    " LEFT JOIN autofill_profile_names n ON ap.guid=n.guid"
                    " LEFT JOIN autofill_profile_emails e ON ap.guid=e.guid"
                    " LEFT JOIN autofill_profile_phones ph ON ap.guid=ph.guid"
                    " ORDER BY COALESCE(ap.use_count,0) DESC";
                if (sqlite3_prepare_v2(db, kModern, -1, &stmt, nullptr) != SQLITE_OK) {
                    // Fallback: older schema without street_address column
                    const char* kLegacy =
                        "SELECT ap.guid,"
                        " COALESCE(n.full_name,''),"
                        " COALESCE(e.email,''),"
                        " COALESCE(ph.number,''),"
                        " COALESCE(ap.company_name,''),"
                        " '',"
                        " COALESCE(ap.city,''),"
                        " COALESCE(ap.state,''),"
                        " COALESCE(ap.zipcode,''),"
                        " COALESCE(ap.country_code,'')"
                        " FROM autofill_profiles ap"
                        " LEFT JOIN autofill_profile_names n ON ap.guid=n.guid"
                        " LEFT JOIN autofill_profile_emails e ON ap.guid=e.guid"
                        " LEFT JOIN autofill_profile_phones ph ON ap.guid=ph.guid"
                        " ORDER BY COALESCE(ap.use_count,0) DESC";
                    sqlite3_prepare_v2(db, kLegacy, -1, &stmt, nullptr);
                }
                if (stmt) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        auto& a = FindOrCreate(addrsOut, ColText(stmt, 0));
                        if (a.fullName.empty())      a.fullName = ColText(stmt, 1);
                        if (a.email.empty())          a.email = ColText(stmt, 2);
                        if (a.phone.empty())          a.phone = ColText(stmt, 3);
                        if (a.companyName.empty())    a.companyName = ColText(stmt, 4);
                        if (a.streetAddress.empty())  a.streetAddress = ColText(stmt, 5);
                        if (a.city.empty())           a.city = ColText(stmt, 6);
                        if (a.state.empty())          a.state = ColText(stmt, 7);
                        if (a.zipCode.empty())        a.zipCode = ColText(stmt, 8);
                        if (a.countryCode.empty())    a.countryCode = ColText(stmt, 9);
                    }
                    sqlite3_finalize(stmt);
                }
            }

            // --- contact_info_type_tokens (Chrome 114-148) and address_type_tokens
            // (Chrome 149+): both use the same type-value schema for local addresses.
            // ServerFieldType codes: NAME_FULL=7, EMAIL_ADDRESS=9,
            // PHONE_HOME_WHOLE_NUMBER=14, ADDRESS_HOME_CITY=33, ADDRESS_HOME_STATE=34,
            // ADDRESS_HOME_ZIP=35, ADDRESS_HOME_COUNTRY=36, ADDRESS_HOME_STREET_ADDRESS=88
            auto ingestTypeTokens = [&](const char* tableName) {
                std::string sql = std::string("SELECT guid, type, value FROM ") + tableName +
                    " WHERE type IN (7,9,14,33,34,35,36,88) AND value != ''"
                    " ORDER BY guid, type";
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        std::string guid = ColText(stmt, 0);
                        int type = sqlite3_column_int(stmt, 1);
                        std::string val = ColText(stmt, 2);
                        auto& a = FindOrCreate(addrsOut, guid);
                        switch (type) {
                        case  7: if (a.fullName.empty())      a.fullName = val; break;
                        case  9: if (a.email.empty())         a.email = val; break;
                        case 14: if (a.phone.empty())         a.phone = val; break;
                        case 33: if (a.city.empty())          a.city = val; break;
                        case 34: if (a.state.empty())         a.state = val; break;
                        case 35: if (a.zipCode.empty())       a.zipCode = val; break;
                        case 36: if (a.countryCode.empty())   a.countryCode = val; break;
                        case 88: if (a.streetAddress.empty()) a.streetAddress = val; break;
                        }
                    }
                    sqlite3_finalize(stmt);
                }
                };
            ingestTypeTokens("contact_info_type_tokens");  // Chrome 114-148
            ingestTypeTokens("address_type_tokens");        // Chrome 149+

            // Drop empty entries (guid only, no useful fields).
            addrsOut.erase(
                std::remove_if(addrsOut.begin(), addrsOut.end(),
                    [](const AutofillAddress& a) {
                        return a.fullName.empty() && a.email.empty() && a.city.empty();
                    }),
                addrsOut.end());

            // --- masked_credit_cards (server/Google-Wallet-synced; last_four plaintext) ---
            {
                sqlite3_stmt* stmt = nullptr;
                const char* kSql =
                    "SELECT COALESCE(name_on_card,''), COALESCE(network,''),"
                    "       COALESCE(last_four,''), COALESCE(exp_month,0),"
                    "       COALESCE(exp_year,0), COALESCE(nickname,'')"
                    " FROM masked_credit_cards"
                    " WHERE name_on_card != '' OR last_four != ''";
                if (sqlite3_prepare_v2(db, kSql, -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        SavedCard c;
                        c.nameOnCard = ColText(stmt, 0);
                        c.network = ColText(stmt, 1);
                        c.lastFour = ColText(stmt, 2);
                        c.expirationMonth = sqlite3_column_int(stmt, 3);
                        c.expirationYear = sqlite3_column_int(stmt, 4);
                        c.nickname = ColText(stmt, 5);
                        c.serverSynced = true;
                        cardsOut.push_back(std::move(c));
                    }
                    sqlite3_finalize(stmt);
                }
            }

            // --- credit_cards (locally-stored; no last_four column in Chrome 149+) ---
            {
                sqlite3_stmt* stmt = nullptr;
                // last_four was removed in Chrome 149; don't reference it.
                const char* kSql =
                    "SELECT name_on_card, expiration_month, expiration_year,"
                    "       COALESCE(nickname,'')"
                    " FROM credit_cards"
                    " WHERE name_on_card != ''"
                    " ORDER BY use_count DESC";
                if (sqlite3_prepare_v2(db, kSql, -1, &stmt, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        SavedCard c;
                        c.nameOnCard = ColText(stmt, 0);
                        c.expirationMonth = sqlite3_column_int(stmt, 1);
                        c.expirationYear = sqlite3_column_int(stmt, 2);
                        c.nickname = ColText(stmt, 3);
                        cardsOut.push_back(std::move(c));
                    }
                    sqlite3_finalize(stmt);
                }
            }

            // --- keywords / search engines ---
            {
                sqlite3_stmt* stmt = nullptr;
                const char* kSql =
                    "SELECT short_name, keyword, url"
                    " FROM keywords"
                    " WHERE url != ''"
                    " ORDER BY usage_count DESC"
                    " LIMIT ?";
                if (sqlite3_prepare_v2(db, kSql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_int(stmt, 1, searchEngineLimit > 0 ? searchEngineLimit : -1);
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        SearchEngine e;
                        e.shortName = ColText(stmt, 0);
                        e.keyword = ColText(stmt, 1);
                        e.searchUrl = ColText(stmt, 2);
                        enginesOut.push_back(std::move(e));
                    }
                    sqlite3_finalize(stmt);
                }
            }

            sqlite3_close(db);
            return true;
        }

        // Default/Top Sites SQLite -> ranked new-tab-page sites.
        bool QuerySqliteTopSites(const fs::path& dbPath, std::vector<TopSite>& out, int limit) {
            sqlite3* db = nullptr;
            if (!OpenSqliteRO(dbPath, db)) return false;
            sqlite3_stmt* stmt = nullptr;
            const char* kSql =
                "SELECT url, title, url_rank"
                " FROM top_sites"
                " WHERE url != ''"
                " ORDER BY url_rank ASC"
                " LIMIT ?";
            if (sqlite3_prepare_v2(db, kSql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int(stmt, 1, limit > 0 ? limit : -1);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    TopSite s;
                    s.url = ColText(stmt, 0);
                    s.title = ColText(stmt, 1);
                    s.rank = sqlite3_column_int(stmt, 2);
                    out.push_back(std::move(s));
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
            return true;
        }

    }  // namespace

    // Login Data SQLite -> saved (url, username). Reads ONLY the plaintext
    // username_value column; the password_value blob is OSCrypt/DPAPI-encrypted and
    // is deliberately never read.
    void ReadLoginData(Profile& prof, const CaptureCtx& diag) {
        ReadLockedStore(
            prof.dir() / "Login Data", "logins",
            [&](const fs::path& path) {
                return QuerySqliteLogins(path, prof.mutableLogins());
            },
            CopySqliteDb, diag);
    }

    // History SQLite -> most-recent visits (url, title, visit count, last visit).
    void ReadHistory(Profile& prof, const CaptureCtx& diag) {
        int limit = diag.opts ? diag.opts->history : 0;
        ReadLockedStore(
            prof.dir() / "History", "history",
            [&](const fs::path& path) {
                return QuerySqliteHistory(path, prof.mutableHistory(), limit);
            },
            CopySqliteDb, diag);
    }

    // Cookies SQLite -> per-host cookie inventory. The store may live at
    // Network/Cookies (modern) or Cookies (older); first existing wins.
    void ReadCookies(Profile& prof, const CaptureCtx& diag) {
        int limit = diag.opts ? diag.opts->cookies : 0;
        fs::path p = prof.dir() / "Network" / "Cookies";
        std::error_code ec;
        if (!fs::exists(p, ec)) p = prof.dir() / "Cookies";
        ReadLockedStore(
            p, "cookies",
            [&](const fs::path& path) {
                return QuerySqliteCookies(path, prof.mutableCookieDomains(), limit);
            },
            CopySqliteDb, diag);
    }

    // History SQLite -> recent downloads (separate tables in the same db).
    void ReadDownloads(Profile& prof, const CaptureCtx& diag) {
        int limit = diag.opts ? diag.opts->downloads : 0;
        ReadLockedStore(
            prof.dir() / "History", "downloads",
            [&](const fs::path& path) {
                return QuerySqliteDownloads(path, prof.mutableDownloads(), limit);
            },
            CopySqliteDb, diag);
    }

    // Web Data SQLite -> autofill addresses, saved cards, search engines.
    void ReadWebData(Profile& prof, const CaptureCtx& diag) {
        int seLimit = diag.opts ? diag.opts->searchEngines : 0;
        ReadLockedStore(
            prof.dir() / "Web Data", "webdata",
            [&](const fs::path& path) {
                bool ok = QuerySqliteWebData(path,
                    prof.mutableAutofillAddresses(),
                    prof.mutableSavedCards(),
                    prof.mutableSearchEngines(),
                    seLimit);
                if (ok && prof.autofillAddresses().empty() && prof.savedCards().empty()
                    && prof.searchEngines().empty())
                    diag.info("webdata", "Web Data opened but no autofill/card/keyword rows found");
                return ok;
            },
            CopySqliteDb, diag);
    }

    // Top Sites SQLite -> browser's ranked new-tab-page sites.
    void ReadTopSites(Profile& prof, const CaptureCtx& diag) {
        int limit = diag.opts ? diag.opts->topSites : 0;
        ReadLockedStore(
            prof.dir() / "Top Sites", "topsites",
            [&](const fs::path& path) {
                return QuerySqliteTopSites(path, prof.mutableTopSites(), limit);
            },
            CopySqliteDb, diag);
    }

}  // namespace chromiumprofile