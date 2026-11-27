# Hardware Evidence Receipt — `omega-ledger`

- **Evidence Class:** `MEASURED_DGX_SPARK_GRACE_A64`
- **Claim State:** `IMPLEMENTED`, `EXERCISED`, `VERIFIED` (single-core host benchmark & gate verification; NOT multi-node or bare-metal qualified)
- **Timestamp (UTC):** `2026-11-27T00:32:52Z`
- **Machine / Kernel:** `Linux 7.0.0-1019-nvidia aarch64` (NVIDIA DGX Spark Grace)
- **Pinned CPU:** `taskset -c 7` (`ARM Cortex-X925`, `scaling_max_freq = 3,900,000 kHz`)
- **Pinned Omega Compiler:** `seed/out/omc`, SHA-256 `28fca13d44054e26f78c33d1753fd5c005d08e9144d95985c90bd75b60885072`
- **C Compiler:** `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` (`c_hw_sha256_insns = 0` verified via `objdump -d`)
- **SQLite3:** `3.45.1 2024-01-30 16:01:20 e876e51a0ed5c5b3126f52e532044363a014bc594cfefa87ffb5b82257ccalt1 (64-bit)` (`/usr/lib/aarch64-linux-gnu/libsqlite3.so.0.8.6`)
- **Python:** `3.12.3`
- **Structured Data:** [`results.json`](./results.json)
- **Checksums:** [`SHA256SUMS.txt`](./SHA256SUMS.txt) (verify from repo root with `shasum -a 256 -c docs/evidence/SHA256SUMS.txt`)

---

## 1. Exact Commands Executed on DGX Spark

```bash
bash scripts/gate.sh
python3 scripts/run_benchmarks.py
```

---

## 2. Gate & Negative-Control Verdicts (CPU `7`)

| Check | Expected | Observed | Verdict |
|---|---|---|---|
| Compiler pin (`seed/out/omc`) | `28fca13d44054e26f78c33d1753fd5c005d08e9144d95985c90bd75b60885072` | Exact match | **PASS** |
| `bin/omega-ledger-bench` static ELF size | `< 40,960 B` (`< 40 KB`) | `39,000 B` (`38.09 KB`) | **PASS** |
| `bin/omega-ledger-gate` static ELF size | `< 40,960 B` (`< 40 KB`) | `35,064 B` (`34.24 KB`) | **PASS** |
| `test-sha256-parity` vs `seed/ng/sha256.om` | Exit `0`, `PASS SHA256_PARITY_VS_SEED_NG_SHA256_OM` | Exit `0`, exact match | **PASS** |
| Independent Python `hashlib.sha256` KAT | 48B leaf & 72B node preimages match FIPS 180-4 | Leaf `1337`: `f1619fd3...`, Node: `15142360...` | **PASS** |
| `test-overflow-trap` (`INT64_MAX - 10 + 100`) | Hardware signed overflow trap 1 (`exit 101`) | `OVERFLOW_TRAP_EXIT=101` | **PASS** |
| `omega-ledger-gate` T1–T5 (valid, unbalanced, non-pos, self/bad-id, overdraft) | Refusals return exact error codes with zero state mutation | `PASS T1`..`PASS T5` | **PASS** |
| `omega-ledger-gate` T6 (single-bit balance & sibling tamper) | `verify_proof_vals == 0` and root mismatch on 1-bit flip | `PASS T6_SINGLE_BIT_TAMPER_DETECTED` | **PASS** |
| `omega-ledger-gate` T7 (100k tx mixed batches, checked after EVERY batch) | `0` mismatches vs cold full-table rollup + Merkle rebuild | `PASS T7_100K_DELTA_VS_FULL_PARITY_0_MISMATCHES` | **PASS** |
| `omega-ledger-gate` T8 (64 sampled inclusion proofs post-100k tx) | All 64 proofs verify against published root | `PASS T8_PROOF_VERIFY_POST_100K`, root `0bf9ca974f760a2c352ed7fab88bf1f5ee7bff1fc7e3e7b810c25b9d5765d917` | **PASS** |

---

## 3. Binary Footprint Comparison

| Binary / Library | Bytes | KiB | Notes |
|---|---:|---:|---|
| `bin/omega-ledger-bench` | `39,000` | `38.09` | Static AArch64 ELF, zero libc, no section header |
| `bin/omega-ledger-gate` | `35,064` | `34.24` | Static AArch64 ELF, zero libc |
| `bin/test-overflow-trap` | `29,312` | `28.63` | Static AArch64 ELF, zero libc |
| `bin/test-sha256-parity` | `36,576` | `35.72` | Static AArch64 ELF (includes `seed/ng/sha256.om`) |
| `bin/c_ledger_ref` | `72,088` | `70.40` | Dynamically linked against `libc.so.6` |
| `bin/c_ledger_ref_unroll` | `72,088` | `70.40` | Dynamically linked against `libc.so.6` |
| `bin/sqlite_bench_c` | `71,536` | `69.86` | Harness only; dynamically loads `libsqlite3.so.0.8.6` |
| `libsqlite3.so.0.8.6` | `1,526,192` | `1,490.42` | Shared library (`1.46 MiB`) + glibc runtime |

---

## 4. Measured Head-to-Head Benchmark Results (Medians across Interleaved Trials, CPU `7`)

### 4.1 Mode 0 — 5.0% Scattered Hot Cohort (`204` active accts/batch, stride `197`, `100,000` transfers)

- **Canonical State (10/10 engines identical):** `COMMITTED=100000`, `REFUSED=0`, `NET_SUM=50803168640`, `ASSETS=12693567629`, `LIABILITIES=12705399191`, `EQUITY=12697603603`, `REVENUE=12706598217`, `WEIGHTED_RISK=325280516375000`, `BREACH_CNT=385`, `BREACH_EXCESS=112372306`
- **Canonical Top-8 Breaches:** `1853:1014003, 1886:1001837, 2519:920197, 1236:855163, 587:824526, 1878:815160, 1211:808869, 3773:806943`
- **Canonical SHA-256 Merkle Root (6/6 Merkle engines bit-exact):** `c9045831d844871e124ebe7472076bb88a3d46fcbad8826805400108c4c843e1`

| Engine | Durability | Merkle Hashes | Total Median (ms) | Min–Max (ms) | E2E tx/s | Posting-Only tx/s | Batch Commit+Hash (us) |
|---|---|---:|---:|---:|---:|---:|---:|
| **`om2_delta`** | In-memory slab | `122,228` | **`45.486`** | `45.445–45.524` | **`2,198,467`** | `30,489,367` | **`421.93`** |
| `om2_full` | In-memory slab | `819,100` | `234.222` | `233.625–235.886` | `426,946` | `30,558,117` | `2,309.38` |
| `c_o3_delta` | In-memory slab | `122,228` | `72.305` | `72.228–72.678` | `1,383,027` | `86,157,505` | `711.37` |
| `c_o3_full` | In-memory slab | `819,100` | `387.700` | `386.267–388.545` | `257,932` | `86,017,288` | `3,865.35` |
| `c_o3_unroll_delta` | In-memory slab | `122,228` | `45.122` | `45.106–45.454` | `2,216,228` | `85,944,248` | `439.55` |
| `c_o3_unroll_full` | In-memory slab | `819,100` | `237.477` | `237.114–238.151` | `421,093` | `85,882,911` | `2,363.10` |
| `sqlite3_c_mem` | In-memory SQLite | `0` (none) | `191.998` | `191.535–193.957` | `520,839` | `1,300,775` | `1,154.39` |
| `sqlite3_c_wal_normal` | Disk WAL `NORMAL` | `0` (none) | `231.767` | `228.772–231.923` | `431,469` | `864,559` | `1,160.38` |
| `sqlite3_c_wal_full` | Disk WAL `FULL` (fsync) | `0` (none) | `617.038` | `601.235–628.414` | `162,065` | `201,191` | `1,206.91` |
| `sqlite3_py_mem` | In-memory SQLite (Py) | `0` (none) | `305.899` | `305.461–306.738` | `326,905` | `527,447` | `1,162.85` |

- **Speedups (`om2_delta`):** `5.15×` vs `om2_full` (`5.47×` on commit), `4.22×` vs `sqlite3_c_mem`, `5.10×` vs `sqlite3_c_wal_normal`*, `13.57×` vs `sqlite3_c_wal_full`*, `6.73×` vs `sqlite3_py_mem`, `1.59×` vs `c_o3_delta`, `0.992×` E2E / `1.042×` commit vs `c_o3_unroll_delta`.

### 4.2 Mode 1 — 1.0% Scattered Clearing Cohort (`41` active accts/batch, stride `197`, `100,000` transfers)

- **Canonical State (10/10 engines identical):** `COMMITTED=100000`, `REFUSED=0`, `NET_SUM=50803168640`, `ASSETS=12698021827`, `LIABILITIES=12704677067`, `EQUITY=12700689032`, `REVENUE=12699780714`, `WEIGHTED_RISK=325249517295000`, `BREACH_CNT=385`, `BREACH_EXCESS=107118036`
- **Canonical Top-8 Breaches:** `3151:1133061, 2502:841596, 3135:792040, 1262:759751, 1893:758903, 2510:737934, 1871:731688, 1894:721250`
- **Canonical SHA-256 Merkle Root (6/6 Merkle engines bit-exact):** `67eee8803c44924ff3a801a3cdf1c8c3b31a8f64a8b52342d79d1a4328082ba0`

| Engine | Durability | Merkle Hashes | Total Median (ms) | Min–Max (ms) | E2E tx/s | Posting-Only tx/s | Batch Commit+Hash (us) |
|---|---|---:|---:|---:|---:|---:|---:|
| **`om2_delta`** | In-memory slab | `33,821` | **`15.103`** | `15.081–15.111` | **`6,621,304`** | `31,735,655` | **`119.23`** |
| `om2_full` | In-memory slab | `819,100` | `233.510` | `233.310–234.836` | `428,247` | `31,741,910` | `2,303.30` |
| `c_o3_delta` | In-memory slab | `33,821` | `21.237` | `21.230–21.258` | `4,708,685` | `95,918,293` | `201.91` |
| `c_o3_full` | In-memory slab | `819,100` | `386.676` | `386.146–386.826` | `258,614` | `95,289,552` | `3,856.25` |
| `c_o3_unroll_delta` | In-memory slab | `33,821` | `13.523` | `13.502–13.534` | `7,394,646` | `95,806,823` | `124.77` |
| `c_o3_unroll_full` | In-memory slab | `819,100` | `237.128` | `237.056–237.569` | `421,713` | `95,543,014` | `2,360.78` |
| `sqlite3_c_mem` | In-memory SQLite | `0` (none) | `187.080` | `186.274–187.566` | `534,532` | `1,396,917` | `1,151.60` |
| `sqlite3_c_wal_normal` | Disk WAL `NORMAL` | `0` (none) | `226.824` | `226.690–229.902` | `440,870` | `900,705` | `1,161.14` |
| `sqlite3_c_wal_full` | Disk WAL `FULL` (fsync) | `0` (none) | `606.355` | `597.674–630.216` | `164,920` | `205,382` | `1,194.48` |
| `sqlite3_py_mem` | In-memory SQLite (Py) | `0` (none) | `301.044` | `300.854–301.872` | `332,177` | `541,815` | `1,164.66` |

- **Speedups (`om2_delta`):** `15.46×` vs `om2_full` (`19.32×` on commit), `12.39×` vs `sqlite3_c_mem`, `15.02×` vs `sqlite3_c_wal_normal`*, `40.15×` vs `sqlite3_c_wal_full`*, `19.93×` vs `sqlite3_py_mem`, `1.406×` vs `c_o3_delta`, `0.895×` E2E / `1.046×` commit vs `c_o3_unroll_delta`.

### 4.3 Mode 2 — Uniform Random Stress (`~1,580` dirty accts/batch = `~39%`, `100,000` transfers)

- **Canonical State (10/10 engines identical):** `COMMITTED=100000`, `REFUSED=0`, `NET_SUM=50803168640`, `ASSETS=12702067171`, `LIABILITIES=12695752891`, `EQUITY=12698569609`, `REVENUE=12706778969`, `WEIGHTED_RISK=325257928997000`, `BREACH_CNT=366`, `BREACH_EXCESS=110405477`
- **Canonical Top-8 Breaches:** `3153:1115221, 1261:895928, 629:894304, 3155:844430, 1248:802058, 1868:793912, 1243:790056, 615:780926`
- **Canonical SHA-256 Merkle Root (6/6 Merkle engines bit-exact):** `7adae69ed5d0cb65edf5008ddc6fa3317105c3951f90cb3b261bacfdd5c999f9`

| Engine | Durability | Merkle Hashes | Total Median (ms) | Min–Max (ms) | E2E tx/s | Posting-Only tx/s | Batch Commit+Hash (us) |
|---|---|---:|---:|---:|---:|---:|---:|
| **`om2_delta`** | In-memory slab | `475,261` | **`156.533`** | `156.502–157.626` | **`638,841`** | `31,691,894` | **`1,533.65`** |
| `om2_full` | In-memory slab | `819,100` | `233.566` | `233.544–234.211` | `428,144` | `31,851,445` | `2,304.14` |
| `c_o3_delta` | In-memory slab | `475,261` | `252.862` | `252.714–253.872` | `395,472` | `97,761,840` | `2,518.38` |
| `c_o3_full` | In-memory slab | `819,100` | `386.260` | `386.155–387.046` | `258,893` | `99,081,220` | `3,852.49` |
| `c_o3_unroll_delta` | In-memory slab | `475,261` | `158.215` | `157.808–158.931` | `632,051` | `98,093,648` | `1,571.94` |
| `c_o3_unroll_full` | In-memory slab | `819,100` | `238.116` | `237.424–238.225` | `419,963` | `98,774,407` | `2,371.02` |
| `sqlite3_c_mem` | In-memory SQLite | `0` (none) | `202.632` | `202.172–202.835` | `493,505` | `1,147,774` | `1,152.21` |
| `sqlite3_c_wal_normal` | Disk WAL `NORMAL` | `0` (none) | `249.981` | `248.476–253.147` | `400,030` | `745,720` | `1,159.00` |
| `sqlite3_c_wal_full` | Disk WAL `FULL` (fsync) | `0` (none) | `644.457` | `635.933–649.482` | `155,170` | `193,050` | `1,208.95` |
| `sqlite3_py_mem` | In-memory SQLite (Py) | `0` (none) | `317.723` | `317.497–318.043` | `314,739` | `496,324` | `1,160.75` |

- **Speedups (`om2_delta`):** `1.49×` vs `om2_full`, `1.29×` vs `sqlite3_c_mem`, `1.60×` vs `sqlite3_c_wal_normal`*, `4.12×` vs `sqlite3_c_wal_full`*, `2.03×` vs `sqlite3_py_mem`, `1.615×` vs `c_o3_delta`, `1.011×` E2E / `1.025×` commit vs `c_o3_unroll_delta`.

### 4.4 Cryptographic Inclusion Proof Verification (`10,000` proofs × 5 trials, CPU `7`)

| Engine | Median Total (ms) | Median ns/proof | Median us/proof | Proofs/sec |
|---|---:|---:|---:|---:|
| **Pure OM-2 `omega-ledger`** | **`46.038`** | **`4,603.8`** | **`4.604`** | **`217,214`** |
| C `gcc -O3 -mcpu=native -funroll-loops` | `48.994` | `4,899.4` | `4.899` | `204,105` |
| C `gcc -O3 -mcpu=native` | `79.536` | `7,953.6` | `7.954` | `125,728` |

---

## 5. Honest Caveats

1. **Durability Boundary:** `om2_delta`, `om2_full`, `c_o3_*`, `sqlite3_c_mem`, and `sqlite3_py_mem` are **in-memory** (zero disk `fsync`s per batch). `sqlite3_c_wal_normal` writes WAL frames to NVMe page cache, and `sqlite3_c_wal_full` forces `fsync` per batch commit. Ratios marked `*` compare an in-memory cryptographic ledger against disk-backed SQLite WAL and are NOT equal crash-durability comparisons.
2. **Engine Generality:** `omega-ledger` is a single-threaded, schema-specialized fixed-slab double-entry engine (`N = 4,096` accounts) without ad-hoc SQL parsing, dynamic schemas, MVCC, or multi-writer concurrency.
3. **Cryptographic Work Asymmetry:** All SQLite3 variants compute **zero** cryptographic Merkle hashes (`MERKLE_HASHES=0`), whereas all `om2_*` and `c_o3_*` runs compute full FIPS 180-4 SHA-256 Merkle roots and maintain exact Top-8 breach structures after every batch.
4. **Scalar SHA-256 Implementation:** Both pure OM-2 and the portable C11 reference execute scalar integer SHA-256 without ARMv8 `SHA256H` hardware crypto instructions (`objdump -d` confirmed `0` `sha256` instructions in `c_ledger_ref` and `c_ledger_ref_unroll`).
5. **Posting vs. Hashing Breakdown:** On the transfer-posting loop (`TX_NS`), `gcc -O3` is ~`2.8–3.1×` faster (`1.04–1.16 ms` vs `3.15–3.28 ms`) because OM-2 enforces checked array bounds (`trap 3`) and hardware signed-64 overflow traps (`trap 1`) on every operation. On SHA-256 Merkle commits and inclusion proof verification, pure OM-2's explicit `for ... unroll` + register-pinned `sha_k` outperforms `gcc -O3 -mcpu=native -funroll-loops` by `2.5–6.4%` and default `gcc -O3 -mcpu=native` by `1.59–1.73×`.
6. **Hardware Scope:** Single-core (`taskset -c 7`, Cortex-X925), single DGX Spark host.
