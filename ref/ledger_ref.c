/* SPDX-License-Identifier: Apache-2.0
 * ref/ledger_ref.c: Portable C11 (gcc -O3 -mcpu=native) reference implementation
 * of omega-ledger for bit-exact SHA-256 parity oracle & native speed comparison.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUM_ACCTS   4096
#define TREE_NODES  8192
#define TOP_K       8
#define BREACH_LIM  14500000LL
#define LIAB_FLOOR  (-5000000LL)

#define TAG_LEAF_0  0x004f4d4cu
#define TAG_LEAF_1  0x314c4541u
#define TAG_NODE_0  0x014f4d4cu
#define TAG_NODE_1  0x314e4f44u

static const uint32_t SHA_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static inline void sha_set_iv(uint32_t st[8]) {
    st[0] = 0x6a09e667u; st[1] = 0xbb67ae85u;
    st[2] = 0x3c6ef372u; st[3] = 0xa54ff53au;
    st[4] = 0x510e527fu; st[5] = 0x9b05688cu;
    st[6] = 0x1f83d9abu; st[7] = 0x5be0cd19u;
}

static void sha_compress(uint32_t st[8], uint32_t w[64]) {
    for (int i = 0; i < 48; i++) {
        uint32_t x = w[i + 1];
        uint32_t y = w[i + 14];
        uint32_t s0 = rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
        uint32_t s1 = rotr32(y, 17) ^ rotr32(y, 19) ^ (y >> 10);
        w[i + 16] = w[i] + s0 + w[i + 9] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = g ^ (e & (f ^ g));
        uint32_t t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) | (c & (a | b));
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

static void hash_leaf_vals(uint64_t aid, int64_t bv, int64_t flv, int64_t rwv, uint64_t mv, uint32_t dst[8]) {
    uint32_t w[64];
    uint64_t u;
    w[0] = TAG_LEAF_0;
    w[1] = TAG_LEAF_1;
    w[2] = (uint32_t)(aid >> 32);
    w[3] = (uint32_t)(aid & 0xffffffffu);
    u = (uint64_t)bv;
    w[4] = (uint32_t)(u >> 32);
    w[5] = (uint32_t)(u & 0xffffffffu);
    u = (uint64_t)flv;
    w[6] = (uint32_t)(u >> 32);
    w[7] = (uint32_t)(u & 0xffffffffu);
    u = (uint64_t)rwv;
    w[8] = (uint32_t)(u >> 32);
    w[9] = (uint32_t)(u & 0xffffffffu);
    w[10] = (uint32_t)(mv >> 32);
    w[11] = (uint32_t)(mv & 0xffffffffu);
    w[12] = 0x80000000u;
    w[13] = 0; w[14] = 0; w[15] = 384u;
    sha_set_iv(dst);
    sha_compress(dst, w);
}

static void hash_pair_vals(const uint32_t lhs[8], const uint32_t rhs[8], uint32_t dst[8]) {
    uint32_t w[64];
    sha_set_iv(dst);
    w[0] = TAG_NODE_0;
    w[1] = TAG_NODE_1;
    for (int j = 0; j < 8; j++) w[2 + j] = lhs[j];
    for (int j = 0; j < 6; j++) w[10 + j] = rhs[j];
    sha_compress(dst, w);
    w[0] = rhs[6];
    w[1] = rhs[7];
    w[2] = 0x80000000u;
    for (int j = 3; j < 15; j++) w[j] = 0;
    w[15] = 576u;
    sha_compress(dst, w);
}

static int64_t acct_bal[NUM_ACCTS];
static int64_t acct_floor[NUM_ACCTS];
static int64_t acct_rw[NUM_ACCTS];
static uint8_t acct_cls[NUM_ACCTS];
static uint8_t acct_sec[NUM_ACCTS];

static int64_t roll_cls[4], roll_sec[16], roll_scalars[4];
static int64_t cold_cls[4], cold_sec[16], cold_scalars[4];

static int64_t seg_val[TREE_NODES];
static uint64_t seg_idx[TREE_NODES];
static uint64_t top_id[TOP_K], cold_top_id[TOP_K];
static int64_t top_val[TOP_K], cold_top_val[TOP_K];
static uint64_t top_cnt, cold_top_cnt;

static uint32_t mhash[TREE_NODES][8];
static uint32_t cold_mhash[TREE_NODES][8];
static uint64_t dirty_acct[NUM_ACCTS];
static uint64_t dirty_node[TREE_NODES];
static uint64_t q_buf_a[NUM_ACCTS], q_buf_b[NUM_ACCTS];
static uint64_t batch_gen, q_a_len, merkle_hashes_total, committed_tx, refused_tx, rng_state;

static uint32_t proof_sib[12][8];
static uint32_t saved_root[8];

static inline int64_t calc_excess(int64_t b) {
    return b > BREACH_LIM ? (b - BREACH_LIM) : 0;
}

static void seg_update(uint64_t acct, int64_t ex) {
    uint64_t u = NUM_ACCTS + acct;
    seg_val[u] = ex;
    seg_idx[u] = acct;
    for (int step = 0; step < 12; step++) {
        u >>= 1;
        uint64_t lc = u << 1, rc = lc | 1;
        int64_t lv = seg_val[lc], rv = seg_val[rc];
        uint64_t li = seg_idx[lc], ri = seg_idx[rc];
        if (lv > rv || (lv == rv && li < ri)) {
            seg_val[u] = lv; seg_idx[u] = li;
        } else {
            seg_val[u] = rv; seg_idx[u] = ri;
        }
    }
}

static void seg_build_all(void) {
    for (uint64_t i = 0; i < NUM_ACCTS; i++) {
        seg_val[NUM_ACCTS + i] = calc_excess(acct_bal[i]);
        seg_idx[NUM_ACCTS + i] = i;
    }
    for (uint64_t u = NUM_ACCTS - 1; u > 0; u--) {
        uint64_t lc = u << 1, rc = lc | 1;
        int64_t lv = seg_val[lc], rv = seg_val[rc];
        uint64_t li = seg_idx[lc], ri = seg_idx[rc];
        if (lv > rv || (lv == rv && li < ri)) {
            seg_val[u] = lv; seg_idx[u] = li;
        } else {
            seg_val[u] = rv; seg_idx[u] = ri;
        }
    }
}

static void extract_topk_delta(void) {
    uint64_t sid[TOP_K];
    int64_t sval[TOP_K];
    uint64_t cnt = 0;
    for (int r = 0; r < TOP_K; r++) {
        int64_t bv = seg_val[1];
        uint64_t bi = seg_idx[1];
        if (bv <= 0) {
            top_id[r] = 0; top_val[r] = 0;
        } else {
            top_id[r] = bi; top_val[r] = bv;
            sid[cnt] = bi; sval[cnt] = bv;
            cnt++;
            seg_update(bi, -1);
        }
    }
    top_cnt = cnt;
    for (uint64_t r = 0; r < cnt; r++) seg_update(sid[r], sval[r]);
}

static int64_t init_rw_for(uint64_t acct) {
    static const int64_t rws[5] = {0, 2000, 5000, 10000, 15000};
    return rws[(acct * 7u + 3u) % 5u];
}

static void init_ledger(void) {
    memset(roll_cls, 0, sizeof(roll_cls));
    memset(roll_sec, 0, sizeof(roll_sec));
    memset(roll_scalars, 0, sizeof(roll_scalars));
    memset(dirty_acct, 0, sizeof(dirty_acct));
    memset(dirty_node, 0, sizeof(dirty_node));
    batch_gen = 1; q_a_len = 0; merkle_hashes_total = 0;
    committed_tx = 0; refused_tx = 0;
    rng_state = 0x9e3779b97f4a7c15ULL;

    int64_t net_sum = 0, w_risk = 0, b_cnt = 0, b_exc = 0;
    for (uint64_t i = 0; i < NUM_ACCTS; i++) {
        uint64_t cls = i & 3u;
        uint64_t sec = (i >> 2) & 15u;
        int64_t rw = init_rw_for(i);
        int64_t bv = 10000000LL + (int64_t)((i * 7919ULL) % 5000000ULL);
        int64_t flv = (cls == 1u) ? LIAB_FLOOR : 0LL;
        acct_cls[i] = (uint8_t)cls;
        acct_sec[i] = (uint8_t)sec;
        acct_rw[i] = rw;
        acct_bal[i] = bv;
        acct_floor[i] = flv;
        roll_cls[cls] += bv;
        roll_sec[sec] += bv;
        net_sum += bv;
        w_risk += bv * rw;
        int64_t ex = calc_excess(bv);
        if (ex > 0) { b_cnt++; b_exc += ex; }
    }
    roll_scalars[0] = net_sum;
    roll_scalars[1] = w_risk;
    roll_scalars[2] = b_cnt;
    roll_scalars[3] = b_exc;
    seg_build_all();
    extract_topk_delta();
    for (uint64_t i = 0; i < NUM_ACCTS; i++) {
        uint64_t mv = ((uint64_t)acct_cls[i] << 8) | acct_sec[i];
        hash_leaf_vals(i, acct_bal[i], acct_floor[i], acct_rw[i], mv, mhash[NUM_ACCTS + i]);
    }
    for (uint64_t u = NUM_ACCTS - 1; u > 0; u--) {
        hash_pair_vals(mhash[u << 1], mhash[(u << 1) | 1], mhash[u]);
    }
}

static inline void apply_acct_delta(uint64_t acct, int64_t dlt) {
    int64_t old_b = acct_bal[acct];
    int64_t new_b = old_b + dlt;
    acct_bal[acct] = new_b;
    uint64_t cls = acct_cls[acct], sec = acct_sec[acct];
    int64_t rw = acct_rw[acct];
    roll_cls[cls] += dlt;
    roll_sec[sec] += dlt;
    roll_scalars[0] += dlt;
    roll_scalars[1] += dlt * rw;
    int64_t old_ex = calc_excess(old_b);
    int64_t new_ex = calc_excess(new_b);
    if (old_ex != new_ex) {
        if (old_ex > 0) { roll_scalars[2]--; roll_scalars[3] -= old_ex; }
        if (new_ex > 0) { roll_scalars[2]++; roll_scalars[3] += new_ex; }
    }
    if (dirty_acct[acct] != batch_gen) {
        dirty_acct[acct] = batch_gen;
        q_buf_a[q_a_len++] = acct;
    }
}

static inline uint64_t post_transfer(uint64_t from_id, uint64_t to_id, int64_t amt) {
    if (amt <= 0) { refused_tx++; return 1; }
    if (from_id >= NUM_ACCTS || to_id >= NUM_ACCTS) { refused_tx++; return 2; }
    if (from_id == to_id) { refused_tx++; return 3; }
    if (acct_bal[from_id] - amt < acct_floor[from_id]) { refused_tx++; return 4; }
    apply_acct_delta(from_id, -amt);
    apply_acct_delta(to_id, amt);
    committed_tx++;
    return 0;
}

static void commit_batch_delta(void) {
    uint64_t gen = batch_gen;
    uint64_t qlen = q_a_len;
    if (qlen == 0) { extract_topk_delta(); return; }
    uint64_t nlen = 0, hashes = 0;
    for (uint64_t i = 0; i < qlen; i++) {
        uint64_t acct = q_buf_a[i];
        seg_update(acct, calc_excess(acct_bal[acct]));
        uint64_t mv = ((uint64_t)acct_cls[acct] << 8) | acct_sec[acct];
        hash_leaf_vals(acct, acct_bal[acct], acct_floor[acct], acct_rw[acct], mv, mhash[NUM_ACCTS + acct]);
        hashes++;
        uint64_t p = (NUM_ACCTS + acct) >> 1;
        if (dirty_node[p] != gen) { dirty_node[p] = gen; q_buf_b[nlen++] = p; }
    }
    uint64_t *cur = q_buf_b, *nxt = q_buf_a;
    for (int lvl = 0; lvl < 12; lvl++) {
        uint64_t n2 = 0;
        for (uint64_t i = 0; i < nlen; i++) {
            uint64_t u = cur[i];
            hash_pair_vals(mhash[u << 1], mhash[(u << 1) | 1], mhash[u]);
            hashes++;
            if (u > 1) {
                uint64_t p = u >> 1;
                if (dirty_node[p] != gen) { dirty_node[p] = gen; nxt[n2++] = p; }
            }
        }
        uint64_t *tmp = cur; cur = nxt; nxt = tmp;
        nlen = n2;
    }
    extract_topk_delta();
    merkle_hashes_total += hashes;
    batch_gen = gen + 1;
    q_a_len = 0;
}

static void cold_topk_insert(uint64_t aid, int64_t ex) {
    uint64_t pos = cold_top_cnt;
    if (pos == TOP_K) {
        if (ex < cold_top_val[7] || (ex == cold_top_val[7] && aid > cold_top_id[7])) return;
        pos = 7;
    } else {
        cold_top_cnt++;
    }
    while (pos > 0) {
        int64_t pv = cold_top_val[pos - 1];
        uint64_t pi = cold_top_id[pos - 1];
        if (ex > pv || (ex == pv && aid < pi)) {
            cold_top_val[pos] = pv; cold_top_id[pos] = pi;
            pos--;
        } else break;
    }
    cold_top_val[pos] = ex;
    cold_top_id[pos] = aid;
}

static void commit_batch_full(void) {
    memset(cold_cls, 0, sizeof(cold_cls));
    memset(cold_sec, 0, sizeof(cold_sec));
    memset(cold_top_id, 0, sizeof(cold_top_id));
    memset(cold_top_val, 0, sizeof(cold_top_val));
    cold_top_cnt = 0;
    int64_t net_sum = 0, w_risk = 0, b_cnt = 0, b_exc = 0;
    for (uint64_t i = 0; i < NUM_ACCTS; i++) {
        int64_t bv = acct_bal[i];
        cold_cls[acct_cls[i]] += bv;
        cold_sec[acct_sec[i]] += bv;
        net_sum += bv;
        w_risk += bv * acct_rw[i];
        int64_t ex = calc_excess(bv);
        if (ex > 0) { b_cnt++; b_exc += ex; cold_topk_insert(i, ex); }
    }
    cold_scalars[0] = net_sum;
    cold_scalars[1] = w_risk;
    cold_scalars[2] = b_cnt;
    cold_scalars[3] = b_exc;
    for (uint64_t i = 0; i < NUM_ACCTS; i++) {
        uint64_t mv = ((uint64_t)acct_cls[i] << 8) | acct_sec[i];
        hash_leaf_vals(i, acct_bal[i], acct_floor[i], acct_rw[i], mv, cold_mhash[NUM_ACCTS + i]);
    }
    for (uint64_t u = NUM_ACCTS - 1; u > 0; u--) {
        hash_pair_vals(cold_mhash[u << 1], cold_mhash[(u << 1) | 1], cold_mhash[u]);
    }
    merkle_hashes_total += 8191;
    batch_gen++;
    q_a_len = 0;
}

static inline uint64_t prng_next(void) {
    rng_state += 0x9e3779b97f4a7c15ULL;
    uint64_t z = rng_state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void run_batch_tx(uint64_t batch_idx, uint64_t mode) {
    uint64_t csize = (mode == 1) ? 41u : ((mode == 2) ? 4096u : 204u);
    uint64_t cbase = (mode == 2) ? 0u : ((batch_idx * 41u) & 4095u);
    uint64_t cm1 = csize - 1u;
    for (int t = 0; t < 1000; t++) {
        uint64_t rv = prng_next();
        uint64_t i1 = rv % csize;
        uint64_t i2 = (rv >> 20) % cm1;
        if (i2 >= i1) i2++;
        uint64_t fa = (cbase + i1 * 197u) & 4095u;
        uint64_t ta = (cbase + i2 * 197u) & 4095u;
        int64_t amt = 100LL + (int64_t)((rv >> 40) % 50000ULL);
        post_transfer(fa, ta, amt);
    }
}

static inline int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static void generate_proof(uint64_t acct) {
    uint64_t u = NUM_ACCTS + acct;
    for (int d = 0; d < 12; d++) {
        uint64_t sib = u ^ 1u;
        memcpy(proof_sib[d], mhash[sib], 32);
        u >>= 1;
    }
}

static uint64_t verify_proof_vals(uint64_t acct, int64_t bv, int64_t flv, int64_t rwv, uint64_t mv) {
    uint32_t cur[8], nxt[8];
    hash_leaf_vals(acct, bv, flv, rwv, mv, cur);
    uint64_t idx = acct;
    for (int d = 0; d < 12; d++) {
        if ((idx & 1u) == 0) hash_pair_vals(cur, proof_sib[d], nxt);
        else hash_pair_vals(proof_sib[d], cur, nxt);
        memcpy(cur, nxt, 32);
        idx >>= 1;
    }
    return memcmp(cur, saved_root, 32) == 0 ? 1u : 0u;
}

int main(int argc, char **argv) {
    const char *eng = (argc >= 2) ? argv[1] : "delta";
    uint64_t mode = (argc >= 3) ? (uint64_t)strtoull(argv[2], NULL, 10) : 0u;

    if (eng[0] == 'p') {
        init_ledger();
        for (uint64_t b = 0; b < 10; b++) { run_batch_tx(b, 0); commit_batch_delta(); }
        memcpy(saved_root, mhash[1], 32);
        uint64_t aid = 1337;
        generate_proof(aid);
        int64_t bv = acct_bal[aid], flv = acct_floor[aid], rwv = acct_rw[aid];
        uint64_t mv = ((uint64_t)acct_cls[aid] << 8) | acct_sec[aid];
        for (int w = 0; w < 200; w++) {
            if (verify_proof_vals(aid, bv, flv, rwv, mv) != 1) return 2;
        }
        volatile uint64_t ver = 0;
        int64_t t0 = now_ns();
        for (int it = 0; it < 10000; it++) ver += verify_proof_vals(aid, bv, flv, rwv, mv);
        int64_t t1 = now_ns();
        printf("PROOF_BENCH count=10000 total_ns=%lld verified=%llu\n",
               (long long)(t1 - t0), (unsigned long long)ver);
        return 0;
    }

    int is_full = (eng[0] == 'f');
    init_ledger();
    merkle_hashes_total = 0;
    int64_t tx_ns = 0, cm_ns = 0;
    int64_t t_start = now_ns();
    for (uint64_t b = 0; b < 100; b++) {
        int64_t t0 = now_ns();
        run_batch_tx(b, mode);
        int64_t t1 = now_ns();
        if (!is_full) commit_batch_delta();
        else commit_batch_full();
        int64_t t2 = now_ns();
        tx_ns += (t1 - t0);
        cm_ns += (t2 - t1);
    }
    int64_t t_end = now_ns();
    const int64_t *sc = is_full ? cold_scalars : roll_scalars;
    const int64_t *cl = is_full ? cold_cls : roll_cls;
    const uint64_t *tid = is_full ? cold_top_id : top_id;
    const int64_t *tv = is_full ? cold_top_val : top_val;
    const uint32_t *rt = is_full ? cold_mhash[1] : mhash[1];

    printf("ENGINE=%s MODE=%llu TOTAL_NS=%lld TX_NS=%lld COMMIT_NS=%lld MERKLE_HASHES=%llu "
           "COMMITTED=%llu REFUSED=%llu NET_SUM=%lld ASSETS=%lld LIABILITIES=%lld EQUITY=%lld "
           "REVENUE=%lld WEIGHTED_RISK=%lld BREACH_CNT=%lld BREACH_EXCESS=%lld TOPK=",
           is_full ? "c_o3_full" : "c_o3_delta",
           (unsigned long long)mode, (long long)(t_end - t_start),
           (long long)tx_ns, (long long)cm_ns, (unsigned long long)merkle_hashes_total,
           (unsigned long long)committed_tx, (unsigned long long)refused_tx,
           (long long)sc[0], (long long)cl[0], (long long)cl[1], (long long)cl[2], (long long)cl[3],
           (long long)sc[1], (long long)sc[2], (long long)sc[3]);
    for (int r = 0; r < TOP_K; r++) {
        printf("%s%llu:%lld", r ? "," : "", (unsigned long long)tid[r], (long long)tv[r]);
    }
    printf(" MERKLE_ROOT=");
    for (int j = 0; j < 8; j++) printf("%08x", rt[j]);
    printf("\n");
    return 0;
}
