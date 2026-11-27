/* SPDX-License-Identifier: Apache-2.0
 * ref/sqlite_bench.c: Native C libsqlite3.so.0 head-to-head benchmark (zero Python overhead).
 * Supports :memory:, WAL synchronous=NORMAL, and WAL synchronous=FULL.
 * Uses prepared statements + BEGIN/COMMIT batching + SQL rollup & Top-8 queries.
 * NOTE: SQLite3 computes ZERO cryptographic Merkle hashes or inclusion proofs.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

#define SQLITE_OK   0
#define SQLITE_ROW  100
#define SQLITE_DONE 101

typedef int (*fn_open)(const char *, sqlite3 **);
typedef int (*fn_close)(sqlite3 *);
typedef int (*fn_exec)(sqlite3 *, const char *, int (*)(void*,int,char**,char**), void *, char **);
typedef int (*fn_prep)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
typedef int (*fn_bind64)(sqlite3_stmt *, int, int64_t);
typedef int (*fn_step)(sqlite3_stmt *);
typedef int (*fn_reset)(sqlite3_stmt *);
typedef int (*fn_fin)(sqlite3_stmt *);
typedef int (*fn_changes)(sqlite3 *);
typedef int64_t (*fn_col64)(sqlite3_stmt *, int);
typedef const char *(*fn_errmsg)(sqlite3 *);
typedef const char *(*fn_libver)(void);

static fn_open s_open;
static fn_close s_close;
static fn_exec s_exec;
static fn_prep s_prep;
static fn_bind64 s_bind64;
static fn_step s_step;
static fn_reset s_reset;
static fn_fin s_fin;
static fn_changes s_changes;
static fn_col64 s_col64;
static fn_errmsg s_errmsg;
static fn_libver s_libver;

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static inline uint64_t prng_next(void) {
    rng_state += 0x9e3779b97f4a7c15ULL;
    uint64_t z = rng_state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static inline int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static void die_sql(sqlite3 *db, const char *ctx) {
    fprintf(stderr, "SQLite error (%s): %s\n", ctx, db ? s_errmsg(db) : "no db");
    exit(1);
}

static void must_exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (s_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL exec failed (%s): %s\n", sql, err ? err : "unknown");
        exit(1);
    }
}

int main(int argc, char **argv) {
    const char *kind = (argc >= 2) ? argv[1] : "mem";
    uint64_t mode = (argc >= 3) ? (uint64_t)strtoull(argv[2], NULL, 10) : 0u;
    const char *db_path = (argc >= 4) ? argv[3] : "/tmp/omega_ledger_sqlite.db";

    void *lib = dlopen("/usr/lib/aarch64-linux-gnu/libsqlite3.so.0", RTLD_NOW);
    if (!lib) lib = dlopen("libsqlite3.so.0", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen libsqlite3 failed: %s\n", dlerror()); return 1; }

    s_open = (fn_open)dlsym(lib, "sqlite3_open");
    s_close = (fn_close)dlsym(lib, "sqlite3_close");
    s_exec = (fn_exec)dlsym(lib, "sqlite3_exec");
    s_prep = (fn_prep)dlsym(lib, "sqlite3_prepare_v2");
    s_bind64 = (fn_bind64)dlsym(lib, "sqlite3_bind_int64");
    s_step = (fn_step)dlsym(lib, "sqlite3_step");
    s_reset = (fn_reset)dlsym(lib, "sqlite3_reset");
    s_fin = (fn_fin)dlsym(lib, "sqlite3_finalize");
    s_changes = (fn_changes)dlsym(lib, "sqlite3_changes");
    s_col64 = (fn_col64)dlsym(lib, "sqlite3_column_int64");
    s_errmsg = (fn_errmsg)dlsym(lib, "sqlite3_errmsg");
    s_libver = (fn_libver)dlsym(lib, "sqlite3_libversion");

    const char *open_target = ":memory:";
    if (strcmp(kind, "mem") != 0) {
        unlink(db_path);
        char wal_p[512], shm_p[512];
        snprintf(wal_p, sizeof(wal_p), "%s-wal", db_path);
        snprintf(shm_p, sizeof(shm_p), "%s-shm", db_path);
        unlink(wal_p); unlink(shm_p);
        open_target = db_path;
    }

    sqlite3 *db = NULL;
    if (s_open(open_target, &db) != SQLITE_OK) die_sql(db, "open");

    if (strcmp(kind, "wal_normal") == 0) {
        must_exec(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
    } else if (strcmp(kind, "wal_full") == 0) {
        must_exec(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
    }

    must_exec(db,
        "CREATE TABLE accounts ("
        "id INTEGER PRIMARY KEY, "
        "bal INTEGER NOT NULL, "
        "floor_lim INTEGER NOT NULL, "
        "risk_w INTEGER NOT NULL, "
        "cls INTEGER NOT NULL, "
        "sec INTEGER NOT NULL) WITHOUT ROWID;");

    /* Seed exact same 4,096 accounts */
    must_exec(db, "BEGIN IMMEDIATE;");
    sqlite3_stmt *st_ins = NULL;
    if (s_prep(db, "INSERT INTO accounts(id,bal,floor_lim,risk_w,cls,sec) VALUES(?,?,?,?,?,?)", -1, &st_ins, NULL) != SQLITE_OK)
        die_sql(db, "prep ins");
    static const int64_t rws[5] = {0, 2000, 5000, 10000, 15000};
    for (uint64_t i = 0; i < 4096; i++) {
        uint64_t cls = i & 3u;
        uint64_t sec = (i >> 2) & 15u;
        int64_t rw = rws[(i * 7u + 3u) % 5u];
        int64_t bv = 10000000LL + (int64_t)((i * 7919ULL) % 5000000ULL);
        int64_t flv = (cls == 1u) ? -5000000LL : 0LL;
        s_bind64(st_ins, 1, (int64_t)i);
        s_bind64(st_ins, 2, bv);
        s_bind64(st_ins, 3, flv);
        s_bind64(st_ins, 4, rw);
        s_bind64(st_ins, 5, (int64_t)cls);
        s_bind64(st_ins, 6, (int64_t)sec);
        if (s_step(st_ins) != SQLITE_DONE) die_sql(db, "step ins");
        s_reset(st_ins);
    }
    s_fin(st_ins);
    must_exec(db, "COMMIT;");

    /* Prepare hot transfer & rollup statements */
    sqlite3_stmt *st_deb = NULL, *st_crd = NULL;
    sqlite3_stmt *st_cls = NULL, *st_sec = NULL, *st_agg = NULL, *st_top = NULL;
    if (s_prep(db, "UPDATE accounts SET bal = bal - ?1 WHERE id = ?2 AND bal - ?1 >= floor_lim", -1, &st_deb, NULL) != SQLITE_OK)
        die_sql(db, "prep deb");
    if (s_prep(db, "UPDATE accounts SET bal = bal + ?1 WHERE id = ?2", -1, &st_crd, NULL) != SQLITE_OK)
        die_sql(db, "prep crd");
    if (s_prep(db, "SELECT cls, SUM(bal) FROM accounts GROUP BY cls", -1, &st_cls, NULL) != SQLITE_OK)
        die_sql(db, "prep cls");
    if (s_prep(db, "SELECT sec, SUM(bal) FROM accounts GROUP BY sec", -1, &st_sec, NULL) != SQLITE_OK)
        die_sql(db, "prep sec");
    if (s_prep(db, "SELECT SUM(bal), SUM(bal * risk_w), "
                   "SUM(CASE WHEN bal > 14500000 THEN 1 ELSE 0 END), "
                   "SUM(CASE WHEN bal > 14500000 THEN bal - 14500000 ELSE 0 END) "
                   "FROM accounts", -1, &st_agg, NULL) != SQLITE_OK)
        die_sql(db, "prep agg");
    if (s_prep(db, "SELECT id, bal - 14500000 AS ex FROM accounts "
                   "WHERE bal > 14500000 ORDER BY ex DESC, id ASC LIMIT 8", -1, &st_top, NULL) != SQLITE_OK)
        die_sql(db, "prep top");

    rng_state = 0x9e3779b97f4a7c15ULL;
    uint64_t committed = 0, refused = 0;
    int64_t cls_sum[4] = {0}, sec_sum[16] = {0};
    int64_t net_sum = 0, w_risk = 0, b_cnt = 0, b_exc = 0;
    uint64_t top_id[8] = {0};
    int64_t top_val[8] = {0};

    int64_t tx_ns = 0, cm_ns = 0;
    int64_t t_start = now_ns();
    for (uint64_t b = 0; b < 100; b++) {
        uint64_t csize = (mode == 1) ? 41u : ((mode == 2) ? 4096u : 204u);
        uint64_t cbase = (mode == 2) ? 0u : ((b * 41u) & 4095u);
        uint64_t cm1 = csize - 1u;

        int64_t t0 = now_ns();
        must_exec(db, "BEGIN IMMEDIATE;");
        for (int t = 0; t < 1000; t++) {
            uint64_t rv = prng_next();
            uint64_t i1 = rv % csize;
            uint64_t i2 = (rv >> 20) % cm1;
            if (i2 >= i1) i2++;
            uint64_t fa = (cbase + i1 * 197u) & 4095u;
            uint64_t ta = (cbase + i2 * 197u) & 4095u;
            int64_t amt = 100LL + (int64_t)((rv >> 40) % 50000ULL);

            s_bind64(st_deb, 1, amt);
            s_bind64(st_deb, 2, (int64_t)fa);
            if (s_step(st_deb) != SQLITE_DONE) die_sql(db, "step deb");
            s_reset(st_deb);
            if (s_changes(db) == 1) {
                s_bind64(st_crd, 1, amt);
                s_bind64(st_crd, 2, (int64_t)ta);
                if (s_step(st_crd) != SQLITE_DONE) die_sql(db, "step crd");
                s_reset(st_crd);
                committed++;
            } else {
                refused++;
            }
        }
        must_exec(db, "COMMIT;");
        int64_t t1 = now_ns();

        /* Rollup query (ZERO cryptographic Merkle hashing!) */
        while (s_step(st_cls) == SQLITE_ROW) {
            cls_sum[s_col64(st_cls, 0)] = s_col64(st_cls, 1);
        }
        s_reset(st_cls);
        while (s_step(st_sec) == SQLITE_ROW) {
            sec_sum[s_col64(st_sec, 0)] = s_col64(st_sec, 1);
        }
        s_reset(st_sec);
        if (s_step(st_agg) == SQLITE_ROW) {
            net_sum = s_col64(st_agg, 0);
            w_risk = s_col64(st_agg, 1);
            b_cnt = s_col64(st_agg, 2);
            b_exc = s_col64(st_agg, 3);
        }
        s_reset(st_agg);
        memset(top_id, 0, sizeof(top_id));
        memset(top_val, 0, sizeof(top_val));
        int r = 0;
        while (s_step(st_top) == SQLITE_ROW && r < 8) {
            top_id[r] = (uint64_t)s_col64(st_top, 0);
            top_val[r] = s_col64(st_top, 1);
            r++;
        }
        s_reset(st_top);

        int64_t t2 = now_ns();
        tx_ns += (t1 - t0);
        cm_ns += (t2 - t1);
    }
    int64_t t_end = now_ns();
    (void)sec_sum;

    printf("ENGINE=sqlite3_c_%s SQLITE_VER=%s MODE=%llu TOTAL_NS=%lld TX_NS=%lld COMMIT_NS=%lld "
           "MERKLE_HASHES=0 COMMITTED=%llu REFUSED=%llu NET_SUM=%lld ASSETS=%lld LIABILITIES=%lld "
           "EQUITY=%lld REVENUE=%lld WEIGHTED_RISK=%lld BREACH_CNT=%lld BREACH_EXCESS=%lld TOPK=",
           kind, s_libver(), (unsigned long long)mode,
           (long long)(t_end - t_start), (long long)tx_ns, (long long)cm_ns,
           (unsigned long long)committed, (unsigned long long)refused,
           (long long)net_sum, (long long)cls_sum[0], (long long)cls_sum[1],
           (long long)cls_sum[2], (long long)cls_sum[3],
           (long long)w_risk, (long long)b_cnt, (long long)b_exc);
    for (int r = 0; r < 8; r++) {
        printf("%s%llu:%lld", r ? "," : "", (unsigned long long)top_id[r], (long long)top_val[r]);
    }
    printf(" MERKLE_ROOT=NONE\n");

    s_fin(st_deb); s_fin(st_crd);
    s_fin(st_cls); s_fin(st_sec); s_fin(st_agg); s_fin(st_top);
    s_close(db);
    if (strcmp(kind, "mem") != 0) {
        unlink(db_path);
        char wal_p[512], shm_p[512];
        snprintf(wal_p, sizeof(wal_p), "%s-wal", db_path);
        snprintf(shm_p, sizeof(shm_p), "%s-shm", db_path);
        unlink(wal_p); unlink(shm_p);
    }
    return 0;
}
