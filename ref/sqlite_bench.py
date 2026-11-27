#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Python sqlite3 reference benchmark (exact same deterministic workload, ZERO Merkle proofs)."""
import sqlite3
import sys
import time

MASK64 = (1 << 64) - 1


def splitmix64(state: int):
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return state, (z ^ (z >> 31)) & MASK64


def main():
    mode = int(sys.argv[1]) if len(sys.argv) >= 2 else 0
    conn = sqlite3.connect(":memory:", isolation_level=None)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE accounts ("
        "id INTEGER PRIMARY KEY, bal INTEGER NOT NULL, floor_lim INTEGER NOT NULL, "
        "risk_w INTEGER NOT NULL, cls INTEGER NOT NULL, sec INTEGER NOT NULL) WITHOUT ROWID"
    )
    rws = (0, 2000, 5000, 10000, 15000)
    rows = []
    for i in range(4096):
        cls = i & 3
        sec = (i >> 2) & 15
        rw = rws[(i * 7 + 3) % 5]
        bv = 10000000 + ((i * 7919) % 5000000)
        flv = -5000000 if cls == 1 else 0
        rows.append((i, bv, flv, rw, cls, sec))
    cur.execute("BEGIN IMMEDIATE")
    cur.executemany("INSERT INTO accounts VALUES (?,?,?,?,?,?)", rows)
    cur.execute("COMMIT")

    rng = 0x9E3779B97F4A7C15
    committed = 0
    refused = 0
    tx_ns = 0
    cm_ns = 0
    cls_sum = [0, 0, 0, 0]
    net_sum = w_risk = b_cnt = b_exc = 0
    top = []

    t_start = time.monotonic_ns()
    for b in range(100):
        csize = 41 if mode == 1 else (4096 if mode == 2 else 204)
        cbase = 0 if mode == 2 else ((b * 41) & 4095)
        cm1 = csize - 1

        t0 = time.monotonic_ns()
        cur.execute("BEGIN IMMEDIATE")
        for _ in range(1000):
            rng, rv = splitmix64(rng)
            i1 = rv % csize
            i2 = (rv >> 20) % cm1
            if i2 >= i1:
                i2 += 1
            fa = (cbase + i1 * 197) & 4095
            ta = (cbase + i2 * 197) & 4095
            amt = 100 + ((rv >> 40) % 50000)
            cur.execute(
                "UPDATE accounts SET bal = bal - ? WHERE id = ? AND bal - ? >= floor_lim",
                (amt, fa, amt),
            )
            if cur.rowcount == 1:
                cur.execute("UPDATE accounts SET bal = bal + ? WHERE id = ?", (amt, ta))
                committed += 1
            else:
                refused += 1
        cur.execute("COMMIT")
        t1 = time.monotonic_ns()

        for c, s in cur.execute("SELECT cls, SUM(bal) FROM accounts GROUP BY cls"):
            cls_sum[c] = s
        _ = list(cur.execute("SELECT sec, SUM(bal) FROM accounts GROUP BY sec"))
        net_sum, w_risk, b_cnt, b_exc = cur.execute(
            "SELECT SUM(bal), SUM(bal * risk_w), "
            "SUM(CASE WHEN bal > 14500000 THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN bal > 14500000 THEN bal - 14500000 ELSE 0 END) FROM accounts"
        ).fetchone()
        top = list(
            cur.execute(
                "SELECT id, bal - 14500000 AS ex FROM accounts "
                "WHERE bal > 14500000 ORDER BY ex DESC, id ASC LIMIT 8"
            )
        )
        t2 = time.monotonic_ns()
        tx_ns += t1 - t0
        cm_ns += t2 - t1

    t_end = time.monotonic_ns()
    while len(top) < 8:
        top.append((0, 0))
    topk_str = ",".join(f"{aid}:{ex}" for aid, ex in top)
    print(
        f"ENGINE=sqlite3_py_mem SQLITE_VER={sqlite3.sqlite_version} MODE={mode} "
        f"TOTAL_NS={t_end - t_start} TX_NS={tx_ns} COMMIT_NS={cm_ns} MERKLE_HASHES=0 "
        f"COMMITTED={committed} REFUSED={refused} NET_SUM={net_sum} "
        f"ASSETS={cls_sum[0]} LIABILITIES={cls_sum[1]} EQUITY={cls_sum[2]} REVENUE={cls_sum[3]} "
        f"WEIGHTED_RISK={w_risk} BREACH_CNT={b_cnt} BREACH_EXCESS={b_exc} "
        f"TOPK={topk_str} MERKLE_ROOT=NONE"
    )


if __name__ == "__main__":
    main()
