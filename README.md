# `omega-ledger`

**A pure seeded OM-2 fixed-slab double-entry financial ledger & analytical rollup engine with Exact Algebraic Delta Rollups and an Incremental FIPS 180-4 SHA-256 Merkle Tree (`39.0 KB` static AArch64 ELF, zero C, zero libc, zero heap allocations).**

- **Claim status:** `IMPLEMENTED`, `EXERCISED`, and `VERIFIED` on DGX Spark Grace AArch64 (`MEASURED_DGX_SPARK_GRACE_A64`, H2H benchmarks on Cortex-X925 CPU `7`; CWE/CVE security & corruption-survival gate on Cortex-A725 CPU `11`). Not multi-node or bare-metal qualified.
- **Security receipt:** [**`docs/evidence/CWE-CVE-SECURITY-RECEIPT.md`**](docs/evidence/CWE-CVE-SECURITY-RECEIPT.md) — MITRE CWE Top 25 (`CWE-190`, `CWE-787`/`125`, `CWE-345`, `CWE-840`, `CWE-20`) refusal matrix + live `4,096`-account / 256-bit Merkle-root corruption-survival gate (`10/10 PASS`, `21` hostile transactions refused, `0` balances corrupted).
- **Compiler provenance:** Built with the pinned seeded Omega compiler `seed/out/omc` (`sha256: 28fca13d44054e26f78c33d1753fd5c005d08e9144d95985c90bd75b60885072`).

---

## Architecture

1. **Fixed-Slab Double-Entry Accounting (Zero Heap, Zero Floats):**
   - `4,096` accounts in fixed static slabs with exact 64-bit signed integer minor units (cents/satoshis — zero floating-point rounding drift).
   - Hardware signed 64-bit overflow traps (`exit 101`, verified via `om/test_overflow_trap.om`) and runtime bounds checks (`exit 103`) on every transfer and rollup.
   - Strict atomic debit+credit posting (`post_transfer`) and multi-leg journal entries (`post_journal`, 2–8 legs) enforcing `sum(debits) == sum(credits)`, positive amounts, distinct valid account IDs, and per-account minimum floor limits (non-negative asset/equity/revenue floors + configurable liability credit lines).

2. **Exact Algebraic Delta Rollups + `O(log N)` Top-K Risk Breaches:**
   - Every committed transfer updates exact 64-bit algebraic accumulators in `O(1)`:
     - Class totals (`ASSETS`, `LIABILITIES`, `EQUITY`, `REVENUE`)
     - Conservation invariant (`NET_SUM` — constant across all double-entry mutations)
     - 16 sector exposures (`roll_sec[0..15]`)
     - Basel-style integer risk-weighted exposure (`WEIGHTED_RISK = sum(bal[i] * risk_w[i])`)
     - Breach count & total excess above `BREACH_LIMIT` (`14,500,000` cents)
   - A 4,096-leaf **Max-Tournament Tree** (`seg_val[8192]`, `seg_idx[8192]`) maintains exact **Top-8 risk breaches** (deterministic tie-break by lowest account ID) in `O(log N)` per dirty account and `O(K log N)` pop-and-restore extraction — guaranteeing **100% bit-exact parity** with a cold full-table scan even when balances decrease.

3. **Batch-Coalesced Incremental FIPS 180-4 SHA-256 Merkle Tree & Inclusion Proofs:**
   - Domain-separated canonical preimages (RFC 6962 style):
     - **Leaf (`48` bytes, 1 SHA-256 block):** `0x00 "OML1LEA" || be64(id) || be64(bal) || be64(floor) || be64(risk_w) || be64((cls<<8)|sec)`
     - **Internal Node (`72` bytes, 2 SHA-256 blocks):** `0x01 "OML1NOD" || left_hash[32] || right_hash[32]`
   - Batch-coalesced generation-stamped dirty tracking (`dirty_acct[4096]`, `dirty_node[8192]`) updates **only** the `k` modified leaves and their unique dirty ancestor nodes bottom-up level-by-level (`O(k log N)`), producing a **100% bit-exact identical 256-bit Merkle root** to a cold 4,096-leaf rebuild.
   - Any account's exact balance can be proven against the published root with a 384-byte (12-sibling) inclusion proof (`verify_proof_vals`) in **`4.60 us`** (`217,214 proofs/sec`).

---

## Head-to-Head Benchmarks (`MEASURED_DGX_SPARK_GRACE_A64`, `taskset -c 7`)

**Platform:** NVIDIA DGX Spark (`Linux 7.0.0-1019-nvidia aarch64`), pinned strictly to **ARM Cortex-X925 CPU `7` @ 3.90 GHz**.  
**Workload:** `4,096` accounts, `100,000` deterministic double-entry transfers (`SplitMix64`) in `100` batches of `1,000` transfers + exact algebraic rollups (4 classes, 16 sectors, weighted risk, breach count/excess, Top-8 breaches) + state integrity Merkle root after **every batch**.  
**Adversarial scatter:** Locality modes (`1%` and `5%`) use prime stride `197` (`gcd(197, 4096) = 1`) so active accounts scatter uniformly across all Merkle subtrees rather than clustering in contiguous leaves.  
**Trials:** Warmup + 5 interleaved trials per in-memory engine (3 trials for disk WAL & Python), reporting **medians**.  
**Parity:** **0 mismatches** across all 10 engines on all rollup fields & all 8 Top-K breaches; **100% bit-exact 64-hex SHA-256 Merkle root parity** across `om2_delta`, `om2_full`, `c_o3_delta`, `c_o3_full`, `c_o3_unroll_delta`, and `c_o3_unroll_full`.

### Binary Footprint

| Artifact | Size | Linking / Dependencies |
|---|---:|---|
| **`bin/omega-ledger-bench` (Pure OM-2)** | **`39,000 B` (`38.09 KB`)** | Static AArch64 ELF, **zero libc**, zero deps |
| **`bin/omega-ledger-gate` (Pure OM-2)** | **`35,064 B` (`34.24 KB`)** | Static AArch64 ELF, **zero libc**, zero deps |
| `bin/c_ledger_ref` (`gcc -O3 -mcpu=native`) | `72,088 B` (`70.40 KB`) | Dynamic ELF (`libc.so.6`) |
| `bin/sqlite_bench_c` + `libsqlite3.so.0.8.6` | `1,597,728 B` (`1,560.28 KB`) | `71.5 KB` harness + `1,490.4 KB` `libsqlite3` + `libc` |

### Mode 1 — 1.0% Scattered Clearing Cohort (`41` active accounts/batch, `33,821` vs `819,100` Merkle hashes)

| Engine | Durability | Merkle Proofs | Total (ms) | E2E tx/s | Batch Commit+Hash (us) | vs `om2_delta` |
|---|---|---:|---:|---:|---:|---:|
| **`om2_delta` (Pure OM-2)** | In-memory slab | **Yes (SHA-256)** | **`15.10`** | **`6,621,304`** | **`119.23`** | `1.00×` |
| `om2_full` (Pure OM-2 Full-Scan) | In-memory slab | Yes (SHA-256) | `233.51` | `428,247` | `2,303.30` | `15.46×` slower (`19.32×` commit) |
| `c_o3_delta` (`gcc -O3 -mcpu=native`) | In-memory slab | Yes (SHA-256) | `21.24` | `4,708,685` | `201.91` | `1.41×` slower |
| `c_o3_unroll_delta` (`gcc -O3 -funroll-loops`) | In-memory slab | Yes (SHA-256) | `13.52` | `7,394,646` | `124.77` | `0.90×` (`om2_delta` is `1.05×` faster on commit!) |
| `sqlite3_c_mem` (`libsqlite3` `:memory:`) | In-memory SQLite | **None** | `187.08` | `534,532` | `1,151.60` | **`12.39×` slower** |
| `sqlite3_c_wal_normal` (WAL `NORMAL`) | Disk WAL (page cache) | **None** | `226.82` | `440,870` | `1,161.14` | `15.02×` slower* |
| `sqlite3_c_wal_full` (WAL `FULL` fsync) | Disk WAL (fsync) | **None** | `606.36` | `164,920` | `1,194.48` | `40.15×` slower* |
| `sqlite3_py_mem` (Python `sqlite3` `:memory:`) | In-memory SQLite | **None** | `301.04` | `332,177` | `1,164.66` | `19.93×` slower |

### Mode 0 — 5.0% Scattered Hot Cohort (`204` active accounts/batch, `122,228` vs `819,100` Merkle hashes)

| Engine | Durability | Merkle Proofs | Total (ms) | E2E tx/s | Batch Commit+Hash (us) | vs `om2_delta` |
|---|---|---:|---:|---:|---:|---:|
| **`om2_delta` (Pure OM-2)** | In-memory slab | **Yes (SHA-256)** | **`45.49`** | **`2,198,467`** | **`421.93`** | `1.00×` |
| `om2_full` (Pure OM-2 Full-Scan) | In-memory slab | Yes (SHA-256) | `234.22` | `426,946` | `2,309.38` | `5.15×` slower (`5.47×` commit) |
| `c_o3_delta` (`gcc -O3 -mcpu=native`) | In-memory slab | Yes (SHA-256) | `72.31` | `1,383,027` | `711.37` | `1.59×` slower |
| `c_o3_unroll_delta` (`gcc -O3 -funroll-loops`) | In-memory slab | Yes (SHA-256) | `45.12` | `2,216,228` | `439.55` | `0.99×` (`om2_delta` is `1.04×` faster on commit!) |
| `sqlite3_c_mem` (`libsqlite3` `:memory:`) | In-memory SQLite | **None** | `192.00` | `520,839` | `1,154.39` | **`4.22×` slower** |
| `sqlite3_c_wal_normal` (WAL `NORMAL`) | Disk WAL (page cache) | **None** | `231.77` | `431,469` | `1,160.38` | `5.10×` slower* |
| `sqlite3_c_wal_full` (WAL `FULL` fsync) | Disk WAL (fsync) | **None** | `617.04` | `162,064` | `1,206.91` | `13.57×` slower* |
| `sqlite3_py_mem` (Python `sqlite3` `:memory:`) | In-memory SQLite | **None** | `305.90` | `326,905` | `1,162.85` | `6.73×` slower |

### Mode 2 — Uniform Random Stress (`~1,580` dirty accounts/batch = `~39%`, `475,261` vs `819,100` Merkle hashes)

| Engine | Durability | Merkle Proofs | Total (ms) | E2E tx/s | Batch Commit+Hash (us) | vs `om2_delta` |
|---|---|---:|---:|---:|---:|---:|
| **`om2_delta` (Pure OM-2)** | In-memory slab | **Yes (SHA-256)** | **`156.53`** | **`638,841`** | **`1,533.65`** | `1.00×` |
| `om2_full` (Pure OM-2 Full-Scan) | In-memory slab | Yes (SHA-256) | `233.57` | `428,144` | `2,304.14` | `1.49×` slower |
| `c_o3_delta` (`gcc -O3 -mcpu=native`) | In-memory slab | Yes (SHA-256) | `252.86` | `395,472` | `2,518.38` | `1.62×` slower |
| `c_o3_unroll_delta` (`gcc -O3 -funroll-loops`) | In-memory slab | Yes (SHA-256) | `158.22` | `632,051` | `1,571.94` | `1.01×` slower |
| `sqlite3_c_mem` (`libsqlite3` `:memory:`) | In-memory SQLite | **None** | `202.63` | `493,505` | `1,152.21` | `1.29×` slower |
| `sqlite3_c_wal_normal` (WAL `NORMAL`) | Disk WAL (page cache) | **None** | `249.98` | `400,030` | `1,159.00` | `1.60×` slower* |
| `sqlite3_c_wal_full` (WAL `FULL` fsync) | Disk WAL (fsync) | **None** | `644.46` | `155,169` | `1,208.95` | `4.12×` slower* |

*\*Durability caveat: SQLite WAL rows write to NVMe (`wal_full` invokes `fsync` per batch); see Honest Caveats below.*

### Cryptographic Inclusion Proof Verification (`10,000` proofs, 12-level SHA-256 Merkle path)

| Implementation | Latency / Proof | Throughput |
|---|---:|---:|
| **Pure OM-2 `omega-ledger`** | **`4,603.8 ns` (`4.604 us`)** | **`217,214 proofs/sec`** |
| C `gcc -O3 -mcpu=native -funroll-loops` | `4,899.4 ns` (`4.899 us`) | `204,105 proofs/sec` |
| C `gcc -O3 -mcpu=native` | `7,953.6 ns` (`7.954 us`) | `125,728 proofs/sec` |

---

## Verification & Negative Controls

Run the full pure OM-2 gate suite on Linux AArch64:

```bash
bash scripts/gate.sh
```

Verified controls (see [**`docs/evidence/CWE-CVE-SECURITY-RECEIPT.md`**](docs/evidence/CWE-CVE-SECURITY-RECEIPT.md) for the full MITRE CWE Top 25 / CVE mapping and raw logs):
- **`test-sha256-parity`:** Exact 48-byte leaf & 72-byte node SHA-256 parity against `seed/ng/sha256.om` (`PASS`), independently cross-checked via Python `hashlib.sha256` and C.
- **`test-overflow-trap` (`CWE-190`):** Crediting an account near `INT64_MAX` triggers Omega hardware signed overflow trap `1` (`exit 101`).
- **`test-oob-trap` (`CWE-787`/`CWE-125`):** Dynamic out-of-bounds slab write (`idx=4096`) triggers Omega mandatory bounds trap `3` (`exit 103`).
- **`test-security-survival` (`10/10 PASS`, `CWE-840`/`CWE-345`/`CWE-20`/`CWE-125`/`CWE-787`):** Fires `21` hostile financial/OOB/atomic-rollback attacks and `4` single-bit Merkle proof forgeries against a live 50,000-tx ledger and verifies **`0 / 4,096` balances altered**, all `24` rollups & Top-8 breaches unchanged, and **bit-identical 256-bit Merkle root** (`0b206c9d...46ada`), followed by valid post-attack clearing & proof verification.
- **`omega-ledger-gate` (`8/8 PASS, mismatches=0`):**
  - `T1`: Valid 2-leg transfer + 3-leg balanced journal + balance conservation.
  - `T2`: Refuses unbalanced multi-leg journal (`ST_ERR_UNBALANCED`), zero state mutation.
  - `T3`: Refuses zero & negative transfer amounts (`ST_ERR_NONPOS`), zero state mutation.
  - `T4`: Refuses self-transfer (`ST_ERR_SELF`) and out-of-range account IDs (`ST_ERR_BAD_ACCT`).
  - `T5`: Refuses overdraft below asset floor (`0`) and liability floor (`-5,000,000`) (`ST_ERR_OVERDRAFT`), zero state mutation.
  - `T6`: Single-bit database tamper (`bal[1337] += 1`) AND single-bit proof sibling tamper both immediately fail `verify_proof_vals` and cold Merkle root check.
  - `T7`: `100,000` transfers across `100` mixed locality/uniform batches compared against cold full-table recomputation after **every single batch** (`0` mismatches).
  - `T8`: `64` sampled inclusion proofs verified against final root post-100,000 transfers.

---

## Honest Caveats

1. **In-Memory vs. Disk-Fsynced Durability:** `omega-ledger`, the C references, and `sqlite3_c_mem`/`sqlite3_py_mem` operate strictly in-memory (`0` disk `fsync`s per batch). SQLite `wal_normal` and `wal_full` write WAL frames to NVMe storage (`wal_full` calls `fsync` on every batch commit). Only the **in-memory** rows are equal-durability apples-to-apples comparisons; WAL rows are reported separately and explicitly labeled.
2. **Scope & Concurrency:** `omega-ledger` is a single-threaded, schema-specialized fixed-slab engine (`4,096` accounts) with no SQL parser, dynamic DDL, MVCC, or multi-writer concurrency, whereas SQLite3 is a general-purpose embedded SQL RDBMS.
3. **Why Pure OM-2 vs. `gcc -O3` Differs by Phase:** On transfer posting (`TX_NS`), C `-O3` runs at `1.04–1.16 ms` (`86–98M tx/s`) vs. pure OM-2 at `3.15–3.28 ms` (`30.5–31.8M tx/s`) because OM-2 enforces runtime array bounds checks and signed-64 hardware overflow traps on every operation (C leaves signed overflow as UB with no bounds checks). Conversely, on unrolled SHA-256 Merkle hashing (`COMMIT_NS` & `verify_proof`), pure OM-2's explicit `for ... unroll` with register-pinned `sha_k` runs `2.5–6.4%` faster than `gcc -O3 -mcpu=native -funroll-loops` and `1.59–1.73×` faster than default `gcc -O3 -mcpu=native`.
4. **Scalar SHA-256 (No ARMv8 Crypto ISA):** Both pure OM-2 and the portable C11 reference execute scalar integer SHA-256 (`0` `sha256*` hardware instructions verified via `objdump`). Hardware `SHA256H` intrinsics would accelerate both Merkle engines further.
5. **Hardware Scope:** Single-core (`taskset -c 7`), single-machine (`DGX Spark Grace AArch64`) evidence (`docs/evidence/RECEIPT.md`, `docs/evidence/results.json`, `docs/evidence/SHA256SUMS.txt`).
