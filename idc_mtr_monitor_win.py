#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDC MTR 全路由節點 24 小時監測工具（Windows 10/11 版）
使用 Windows 內建的 tracert + ping 指令，
自動掃描來源到目的地所有路由跳點，記錄品質並產生 HTML 報告。
不需要安裝任何第三方工具。
"""

import subprocess
import sqlite3
import time
import re
import os
import sys
import signal
import logging
import argparse
import threading
import locale
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Any, Callable, cast
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import escape as html_escape

# 取得系統實際編碼（中文 Windows = cp950，英文 = cp1252）
SYS_ENCODING = locale.getpreferredencoding(False)

# Windows 背景執行不跳出 cmd 視窗的旗標
CREATE_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)

# ─────────────────────────── 設定區 ───────────────────────────
DEFAULT_TARGET   = "8.8.8.8"         # 預設目標 IP (Google DNS)
DEFAULT_INTERVAL = 300               # 監測間隔（秒）
DEFAULT_CYCLES   = 10                # 每個跳點 ping 幾次
TRACERT_TIMEOUT  = 3000             # tracert 每跳逾時（ms）
PING_TIMEOUT     = 2000             # ping 每封包逾時（ms）
ALERT_LOSS       = 5.0              # 封包遺失警報閾值（%）
ALERT_LATENCY    = 150.0            # 延遲警報閾值（ms）
MAX_HOPS         = 30               # tracert 最大跳數
LOG_PATH         = "idc_mtr_win.log"

def _safe_ip(target_ip):
    """將 IP 轉換為安全的檔名片段，如 210.64.216.94 → 210-64-216-94"""
    return target_ip.replace(".", "-").replace(":", "-")

def make_db_path(target_ip):
    """根據目標 IP 產生資料庫檔名，如 idc_mtr_win_210-64-216-94.db"""
    return "idc_mtr_win_{}.db".format(_safe_ip(target_ip))

def make_report_path(target_ip):
    """根據目標 IP 產生報告檔名，如 idc_mtr_win_report_210-64-216-94.html"""
    return "idc_mtr_win_report_{}.html".format(_safe_ip(target_ip))
# ───────────────────────────────────────────────────────────────

running = True

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(LOG_PATH, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

def init_db(db_path):
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target    TEXT NOT NULL,
                hops      INTEGER NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hop_stats (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                target    TEXT NOT NULL,
                hop_num   INTEGER NOT NULL,
                hop_ip    TEXT NOT NULL,
                loss_pct  REAL NOT NULL,
                sent      INTEGER,
                recv      INTEGER,
                last_ms   REAL,
                avg_ms    REAL,
                best_ms   REAL,
                worst_ms  REAL,
                stdev_ms  REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target    TEXT NOT NULL,
                hop_num   INTEGER,
                hop_ip    TEXT,
                type      TEXT NOT NULL,
                value     REAL,
                message   TEXT NOT NULL
            )
        """)
        # 建立索引加速查詢
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hop_stats_target_ts ON hop_stats(target, timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hop_stats_scan_id ON hop_stats(scan_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_target_ts ON alerts(target, timestamp)")
        conn.commit()

# ─────────────────── tracert 路由探測 ───────────────────

def run_tracert(target, max_hops=MAX_HOPS, timeout_ms=TRACERT_TIMEOUT):
    """
    執行 Windows tracert -d，回傳各跳點 IP 列表。
    -d 不解析 hostname（更快）
    """
    # 偵測 IPv6 位址（含 : 字元）
    is_ipv6 = ":" in target
    cmd = ["tracert", "-d"]
    if is_ipv6:
        cmd.append("-6")
    cmd += ["-h", str(max_hops), "-w", str(timeout_ms), target]
    try:
        r = subprocess.run(
            cmd, capture_output=True,
            timeout=max_hops * (timeout_ms / 1000) * 3 + 30,
            creationflags=CREATE_NO_WINDOW
        )
        # 使用系統預設編碼（中文 Windows = cp950）
        output = r.stdout.decode(SYS_ENCODING, errors="replace") + \
                 r.stderr.decode(SYS_ENCODING, errors="replace")
        return parse_tracert(output)
    except subprocess.TimeoutExpired:
        logging.warning("tracert 逾時")
        return []
    except FileNotFoundError:
        logging.error("找不到 tracert 指令（應為 Windows 內建）")
        return []

def parse_tracert(output):
    """
    解析 Windows tracert -d 輸出（支援英文和中文繁體）
      英文逾時: Request timed out.
      中文逾時: 要求等候逾時。
    回傳 [(hop_num, hop_ip), ...]，逾時節點 ip 為 '???'
    """
    TIMEOUT_STRINGS = (
        "Request timed out",
        "Host unreachable",
        "要求等候逾時",   # 中文繁體
        "請求等候逾時",   # 備用
        "無法連線到目標主機",  # 備用
    )
    hops = []
    pattern = re.compile(
        r'^\s*(\d+)\s+'           # hop number
        r'(?:(?:\s*<?\.?\d+\s*ms|\s*\*)\s+){3}'  # 3 組 RTT（如 <1 ms、3 ms）或 *
        r'(.+)$'                  # 剩餘內容（IP 或逾時訊息）
    )
    for line in output.splitlines():
        m = pattern.match(line)
        if m:
            hop_num  = int(m.group(1))
            remainder = m.group(2).strip().rstrip(".")
            # 判斷是否為逾時訊息
            is_timeout = any(t in remainder for t in TIMEOUT_STRINGS)
            if is_timeout or remainder == "*":
                hop_ip = "???"
            else:
                # 提取 IP：支援 IPv4 和 IPv6，可能是純 IP 或 "hostname [IP]" 格式
                ip_m = re.search(r'\[?([\da-fA-F.:]+)\]?\s*$', remainder)
                hop_ip = ip_m.group(1) if ip_m else remainder
            hops.append((hop_num, hop_ip))
    return hops

# ─────────────────── Windows ping 測量 ───────────────────

def ping_host(hop_num, hop_ip, cycles, timeout_ms):
    """
    對單一跳點執行 Windows ping -n，回傳品質統計 dict。
    """
    if hop_ip == "???":
        return {
            "hop_num": hop_num, "hop_ip": hop_ip,
            "loss_pct": 100.0, "sent": cycles, "recv": 0,
            "last_ms": None, "avg_ms": None,
            "best_ms": None, "worst_ms": None, "stdev_ms": None,
        }

    # IPv6 位址使用 ping -6
    is_ipv6 = ":" in hop_ip
    cmd = ["ping"]
    if is_ipv6:
        cmd.append("-6")
    cmd += ["-n", str(cycles), "-w", str(timeout_ms), hop_ip]
    try:
        r = subprocess.run(
            cmd, capture_output=True,
            timeout=cycles * (timeout_ms / 1000) + 10,
            creationflags=CREATE_NO_WINDOW
        )
        # 使用系統實際編碼（中文 Windows = cp950）
        output = r.stdout.decode(SYS_ENCODING, errors="replace") + \
                 r.stderr.decode(SYS_ENCODING, errors="replace")
        return parse_ping(hop_num, hop_ip, output, cycles)
    except subprocess.TimeoutExpired:
        return {"hop_num": hop_num, "hop_ip": hop_ip, "loss_pct": 100.0,
                "sent": cycles, "recv": 0, "last_ms": None, "avg_ms": None,
                "best_ms": None, "worst_ms": None, "stdev_ms": None}

def parse_ping(hop_num, hop_ip, output, expected_count):
    """
    解析 Windows ping 輸出（同時支援英文版與繁體中文版 Windows）

    英文格式：
      Packets: Sent = 10, Received = 9, Lost = 1 (10% loss)
      Minimum = 1ms, Maximum = 5ms, Average = 2ms

    中文格式（繁體）：
      封包: 已傳送 = 4，已收到 = 4, 已遺失 = 0 (0% 遺失)
      最小值 = 5ms，最大值 = 7ms，平均 = 6ms
      回覆自 x.x.x.x: 位元組=32 時間=7ms TTL=116
    """
    result = {
        "hop_num":  hop_num,
        "hop_ip":   hop_ip,
        "loss_pct": 100.0,
        "sent":     expected_count,
        "recv":     0,
        "last_ms":  None,
        "avg_ms":   None,
        "best_ms":  None,
        "worst_ms": None,
        "stdev_ms": None,
    }

    # ── 封包統計（英文）──
    pkt_m = re.search(
        r'Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+).*?Lost\s*=\s*\d+\s*\((\d+)%',
        output, re.IGNORECASE | re.DOTALL
    )
    if not pkt_m:
        # 封包統計（中文繁體）: 已傳送 = 4，已收到 = 4, 已遺失 = 0 (0% 遺失)
        pkt_m = re.search(
            r'已傳送\s*=\s*(\d+)[，,].*?已收到\s*=\s*(\d+)[，,].*?已遺失\s*=\s*\d+\s*\((\d+)%',
            output, re.DOTALL
        )
    if pkt_m:
        result["sent"]     = int(pkt_m.group(1))
        result["recv"]     = int(pkt_m.group(2))
        result["loss_pct"] = float(pkt_m.group(3))

    # ── 延遲統計（英文）──
    lat_m = re.search(
        r'Minimum\s*=\s*(\d+)ms.*?Maximum\s*=\s*(\d+)ms.*?Average\s*=\s*(\d+)ms',
        output, re.IGNORECASE | re.DOTALL
    )
    if not lat_m:
        # 延遲統計（中文繁體）: 最小值 = 5ms，最大值 = 7ms，平均 = 6ms
        lat_m = re.search(
            r'最小值\s*=\s*(\d+)ms[，,].*?最大值\s*=\s*(\d+)ms[，,].*?平均\s*=\s*(\d+)ms',
            output, re.DOTALL
        )
    if lat_m:
        result["best_ms"]  = float(lat_m.group(1))
        result["worst_ms"] = float(lat_m.group(2))
        result["avg_ms"]   = float(lat_m.group(3))

    # ── 收集每筆 RTT（英文 time=7ms / 中文 時間=7ms）──
    reply_times = re.findall(r'(?:time|時間)[=<](<?\d+)ms', output, re.IGNORECASE)
    if reply_times:
        rtt_values = [float(re.sub(r'[<>]', '', t)) for t in reply_times]
        result["last_ms"] = rtt_values[-1]
        # 計算真正的標準差
        if len(rtt_values) >= 2:
            mean = sum(rtt_values) / len(rtt_values)
            variance = sum((x - mean) ** 2 for x in rtt_values) / len(rtt_values)
            result["stdev_ms"] = round(variance ** 0.5, 1)
        elif len(rtt_values) == 1:
            result["stdev_ms"] = 0.0

    return result


# ─────────────────── 完整 MTR 一輪掃描 ───────────────────

def run_mtr_scan(target, cycles, tracert_timeout, ping_timeout, max_workers=8):
    """
    1. tracert 找出所有跳點
    2. 對每個跳點平行 ping
    回傳 list of hop 統計 dict
    """
    logging.info("  Step 1：tracert 探測路由...")
    hops = run_tracert(target, timeout_ms=tracert_timeout)
    if not hops:
        logging.warning("  tracert 未取得任何跳點")
        return []

    logging.info("  發現 {} 個跳點，Step 2：平行 ping 每個節點...".format(len(hops)))

    results_dict: dict = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {
            ex.submit(cast(Callable[..., Any], ping_host), hop_num, hop_ip, cycles, ping_timeout): idx
            for idx, (hop_num, hop_ip) in enumerate(hops)
        }
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                results_dict[idx] = future.result()
            except Exception as e:
                hop_num, hop_ip = hops[idx]
                logging.warning("  Hop {} ping 失敗：{}".format(hop_num, e))
                results_dict[idx] = {
                    "hop_num": hop_num, "hop_ip": hop_ip,
                    "loss_pct": 100.0, "sent": cycles, "recv": 0,
                    "last_ms": None, "avg_ms": None,
                    "best_ms": None, "worst_ms": None, "stdev_ms": None,
                }
    return [results_dict[i] for i in sorted(results_dict.keys())]

# ─────────────────── 資料庫存取 ───────────────────

def save_scan(db_path, target, hops_data, ts):
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO scans (timestamp, target, hops) VALUES (?,?,?)",
                    (ts, target, len(hops_data)))
        scan_id = cur.lastrowid
        for h in hops_data:
            cur.execute("""
                INSERT INTO hop_stats
                  (scan_id,timestamp,target,hop_num,hop_ip,
                   loss_pct,sent,recv,last_ms,avg_ms,best_ms,worst_ms,stdev_ms)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (scan_id, ts, target,
                  h["hop_num"], h["hop_ip"],
                  h["loss_pct"], h.get("sent"), h.get("recv"),
                  h.get("last_ms"), h.get("avg_ms"),
                  h.get("best_ms"), h.get("worst_ms"), h.get("stdev_ms")))
        conn.commit()
    return scan_id

def check_alerts(db_path, target, hops_data, ts):
    # 判斷最終目標是否可達（用來過濾中繼節點的假警報）
    final_ok = False
    if hops_data:
        last = hops_data[-1]
        if last["hop_ip"] != "???" and last["loss_pct"] < ALERT_LOSS:
            final_ok = True

    with sqlite3.connect(db_path) as conn:
        for h in hops_data:
            if h["hop_ip"] == "???":
                continue
            is_final = (h == hops_data[-1])
            # 中繼節點 100% loss 且目標正常 → 判定為 ICMP 禁用，跳過告警
            if not is_final and h["loss_pct"] >= 100.0 and final_ok:
                logging.info("  ℹ️  Hop{} ({}) 100% loss，但目標可達，判定為 ICMP 禁用，跳過告警".format(
                    h["hop_num"], h["hop_ip"]))
                continue
            if h["loss_pct"] >= ALERT_LOSS:
                msg = "Hop{} ({}) 封包遺失 {:.1f}% 超過閾值 {}%".format(
                    h["hop_num"], h["hop_ip"], h["loss_pct"], ALERT_LOSS)
                logging.warning("⚠️  " + msg)
                conn.execute(
                    "INSERT INTO alerts (timestamp,target,hop_num,hop_ip,type,value,message)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (ts, target, h["hop_num"], h["hop_ip"], "loss", h["loss_pct"], msg))
            if h.get("avg_ms") and h["avg_ms"] >= ALERT_LATENCY:
                msg = "Hop{} ({}) 延遲 {:.1f}ms 超過閾值 {}ms".format(
                    h["hop_num"], h["hop_ip"], h["avg_ms"], ALERT_LATENCY)
                logging.warning("⚠️  " + msg)
                conn.execute(
                    "INSERT INTO alerts (timestamp,target,hop_num,hop_ip,type,value,message)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (ts, target, h["hop_num"], h["hop_ip"], "latency", h["avg_ms"], msg))
        conn.commit()

# ─────────────────── 資料庫清理 ───────────────────

def cleanup_old_data(db_path, keep_days=7):
    """清理超過 keep_days 天的舊資料，避免資料庫無限膨脹"""
    cutoff = (datetime.now() - timedelta(days=keep_days)).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(db_path) as conn:
        # 先刪除 hop_stats（依賴 scan_id 的子資料）
        conn.execute("""
            DELETE FROM hop_stats WHERE scan_id IN (
                SELECT id FROM scans WHERE timestamp < ?
            )
        """, (cutoff,))
        conn.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
        conn.commit()
        deleted = conn.total_changes
    if deleted > 0:
        logging.info("🗑️  已清理 {} 天前的舊資料（共 {} 筆）".format(keep_days, deleted))

# ─────────────────── HTML 報告產生 ───────────────────

def generate_report(db_path, target, report_path, hours=24):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(db_path) as conn:
        # 動態計算時間範圍：取 DB 中最早的掃描時間，若超過 hours 則自動擴展
        first_scan_ts = conn.execute(
            "SELECT MIN(timestamp) FROM scans WHERE target=?", (target,)
        ).fetchone()[0]
        if first_scan_ts:
            first_time = datetime.strptime(first_scan_ts, "%Y-%m-%d %H:%M:%S")
            actual_hours = (datetime.now() - first_time).total_seconds() / 3600
            effective_hours = max(hours, actual_hours)
        else:
            effective_hours = hours
        since = (datetime.now() - timedelta(hours=effective_hours)).strftime("%Y-%m-%d %H:%M:%S")
        display_hours = round(effective_hours, 1)
        # 開始時間顯示格式：YYYY/MM/DD HH:MM
        if first_scan_ts:
            display_since = datetime.strptime(first_scan_ts, "%Y-%m-%d %H:%M:%S").strftime("%Y/%m/%d %H:%M")
        else:
            display_since = "尚未開始"
        # 最新快照
        last_scan = conn.execute(
            "SELECT id FROM scans WHERE target=? ORDER BY id DESC LIMIT 1", (target,)
        ).fetchone()
        latest_hops = []
        if last_scan:
            latest_hops = conn.execute(
                "SELECT hop_num,hop_ip,loss_pct,sent,recv,last_ms,avg_ms,best_ms,worst_ms,stdev_ms"
                " FROM hop_stats WHERE scan_id=? ORDER BY hop_num", (last_scan[0],)
            ).fetchall()

        # 歷史統計（各跳點 24h 平均，包含 ??? 節點）
        hop_history = conn.execute("""
            SELECT hop_num, hop_ip,
                   COUNT(*) as cnt,
                   AVG(loss_pct)  as avg_loss,
                   AVG(avg_ms)    as avg_lat,
                   MAX(worst_ms)  as max_lat,
                   AVG(stdev_ms)  as avg_jitter
            FROM hop_stats
            WHERE target=? AND timestamp>=?
            GROUP BY hop_num, hop_ip ORDER BY hop_num
        """, (target, since)).fetchall()

        # 最終節點圖表時序
        final_ip = latest_hops[-1][1] if latest_hops else None
        chart_rows = []
        if final_ip and final_ip != "???":
            chart_rows = conn.execute("""
                SELECT timestamp, avg_ms, loss_pct FROM hop_stats
                WHERE target=? AND hop_ip=? AND timestamp>=?
                ORDER BY timestamp ASC
            """, (target, final_ip, since)).fetchall()

        scan_count = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE target=? AND timestamp>=?", (target, since)
        ).fetchone()[0]

        alert_rows = conn.execute("""
            SELECT timestamp,hop_num,hop_ip,type,value,message
            FROM alerts WHERE target=? AND timestamp>=?
            ORDER BY id DESC LIMIT 30
        """, (target, since)).fetchall()

    # ── 判斷整體狀態 ──
    overall_status = "normal"  # normal / warning / critical
    overall_label  = "正常"
    overall_color  = "#3fb950"
    if latest_hops:
        final = latest_hops[-1]
        final_loss = final[2]
        final_avg  = final[6]
        if final_loss >= ALERT_LOSS or (final_avg is not None and final_avg >= ALERT_LATENCY):
            overall_status = "critical"
            overall_label  = "異常"
            overall_color  = "#f85149"
        else:
            # 檢查中繼節點（排除 ???、ICMP 禁用節點、和最終節點）
            final_reachable = final_loss < ALERT_LOSS
            has_mid_issue = False
            for h in latest_hops[:-1]:
                if h[1] == "???":
                    continue
                # 中繼 100% loss 但目標可達 → ICMP 禁用，不算異常
                if h[2] >= 100.0 and final_reachable:
                    continue
                if h[2] >= ALERT_LOSS or (h[6] is not None and h[6] >= ALERT_LATENCY):
                    has_mid_issue = True
                    break
            if has_mid_issue:
                overall_status = "warning"
                overall_label  = "注意"
                overall_color  = "#d29922"

    # ── 判斷最終目標是否可達（供快照、歷史表格共用）──
    final_ok = False
    if latest_hops:
        final_ok = latest_hops[-1][1] != "???" and latest_hops[-1][2] < ALERT_LOSS

    # ── 快照表格 ──
    if not latest_hops:
        snapshot_html = "<p style='color:#484f58;padding:12px'>尚無資料，等待第一次掃描完成...</p>"
    else:
        def fmt_ms(v: object) -> str:
            return "{:.1f}".format(v) if v is not None else "???"

        rows = ""
        for idx, h in enumerate(latest_hops):
            hop_num,hop_ip,loss,sent,recv,last,avg,best,worst,stdev = h
            is_final = (idx == len(latest_hops) - 1)
            loss_cls = "green" if loss==0 else ("yellow" if loss<ALERT_LOSS else "red")

            # 對 ??? 或中繼節點 100% loss 且目標正常，標註 ICMP 禁用
            ip_display = html_escape(str(hop_ip))
            if hop_ip == "???":
                ip_display = "<span style='color:#484f58'>???</span> <span style='color:#484f58;font-size:.75rem'>(不回應 ICMP)</span>"
                loss_cls = "dim"
            elif not is_final and loss >= 100.0 and final_ok:
                ip_display += " <span style='color:#484f58;font-size:.75rem'>(ICMP 禁用)</span>"
                loss_cls = "dim"

            rows += ("<tr><td>{}</td><td class='ip'>{}</td>"
                     "<td class='{}'>{:.1f}%</td>"
                     "<td>{}/{}</td>"
                     "<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>").format(
                hop_num, ip_display, loss_cls, loss,
                sent or "?", recv or "?",
                fmt_ms(last), fmt_ms(avg), fmt_ms(best), fmt_ms(worst), fmt_ms(stdev))
        snapshot_html = (
            "<table><tr><th>Hop</th><th>IP 位址</th><th>Loss%</th>"
            "<th>Snt/Rcv</th><th>Last(ms)</th><th>Avg(ms)</th>"
            "<th>Best(ms)</th><th>Worst(ms)</th><th>Jitter</th></tr>"
            "{}</table>".format(rows))

    # ── 歷史統計表格 ──
    if not hop_history:
        history_html = "<p style='color:#484f58;padding:12px'>統計資料累積中...</p>"
    else:
        def fmt_val(v: object, precision: str = ".1f") -> str:
            return ("{:" + precision + "}").format(v) if v is not None else "N/A"

        rows = ""
        for h in hop_history:
            hop_num,hop_ip,cnt,avg_loss,avg_lat,max_lat,avg_jitter = h
            # ??? 節點特別處理
            if hop_ip == "???":
                rows += ("<tr><td>{}</td><td class='ip'><span style='color:#484f58'>???</span>"
                         " <span style='color:#484f58;font-size:.75rem'>(不回應 ICMP)</span></td>"
                         "<td>{}</td><td class='dim'>100.00%</td>"
                         "<td class='dim'>N/A</td><td class='dim'>N/A</td><td class='dim'>N/A</td></tr>").format(
                    hop_num, cnt)
                continue
            # ICMP 禁用節點：非最終跳、100% loss、但目標可達
            is_last_hop = (h == hop_history[-1]) if hop_history else False
            if not is_last_hop and (avg_loss or 0) >= 100.0 and final_ok:
                rows += ("<tr><td>{}</td><td class='ip'>{}"
                         " <span style='color:#484f58;font-size:.75rem'>(ICMP 禁用)</span></td>"
                         "<td>{}</td><td class='dim'>100.00%</td>"
                         "<td class='dim'>N/A</td><td class='dim'>N/A</td><td class='dim'>N/A</td></tr>").format(
                    hop_num, html_escape(str(hop_ip)), cnt)
                continue
            loss_cls = "green" if (avg_loss or 0)==0 else ("yellow" if (avg_loss or 0)<ALERT_LOSS else "red")
            lat_cls  = "green" if (avg_lat  or 0)<50 else ("yellow" if (avg_lat  or 0)<ALERT_LATENCY else "red")
            rows += ("<tr><td>{}</td><td class='ip'>{}</td><td>{}</td>"
                     "<td class='{}'>{}</td><td class='{}'>{}</td>"
                     "<td>{}</td><td>{}</td></tr>").format(
                hop_num, html_escape(str(hop_ip)), cnt,
                loss_cls, fmt_val(avg_loss, ".2f") + "%" if avg_loss is not None else "N/A",
                lat_cls,  fmt_val(avg_lat)  + "ms" if avg_lat  is not None else "N/A",
                fmt_val(max_lat)    + "ms" if max_lat    is not None else "N/A",
                fmt_val(avg_jitter) + "ms" if avg_jitter is not None else "N/A",
            )
        history_html = (
            "<table><tr><th>Hop</th><th>IP 位址</th><th>掃描次數</th>"
            "<th>平均遺失%</th><th>平均延遲</th><th>最大延遲</th><th>平均Jitter</th></tr>"
            "{}</table>".format(rows))

    # ── 警報表格 ──
    if not alert_rows:
        alert_html = "<p style='color:#484f58;padding:12px'>最近 {} 小時無警報</p>".format(display_hours)
    else:
        rows = ""
        for r in alert_rows:
            ts_a, hop_num, hop_ip, atype, aval, amsg = r
            badge = "badge-yellow" if atype == "latency" else "badge-red"
            rows += ("<tr><td>{}</td><td>Hop{}</td><td class='ip'>{}</td>"
                     "<td><span class='badge {}'>{}</span></td>"
                     "<td>{:.1f}</td><td>{}</td></tr>").format(
                html_escape(str(ts_a)), hop_num, html_escape(str(hop_ip)),
                badge, html_escape(str(atype)), aval, html_escape(str(amsg)))
        alert_html = (
            "<table><tr><th>時間</th><th>Hop</th><th>IP</th>"
            "<th>類型</th><th>數值</th><th>訊息</th></tr>{}</table>".format(rows))

    # ── Chart.js 資料 ──
    labels_js = "[{}]".format(",".join('"{}"'.format(r[0]) for r in chart_rows))
    lat_js    = "[{}]".format(",".join(str(r[1]) if r[1] is not None else "null" for r in chart_rows))
    loss_js   = "[{}]".format(",".join(str(r[2]) for r in chart_rows))
    final_label = final_ip or "目標"

    # ── 最終 HTML ──
    html = """<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="120">
<title>MTR 監測（Windows）- {target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:1.2rem}}
header{{background:linear-gradient(135deg,#161b22,#21262d);padding:24px 36px;border-bottom:1px solid #30363d}}
header h1{{font-size:2.1rem;color:#58a6ff}}
header p{{color:#8b949e;font-size:1.15rem;margin-top:8px}}
.container{{max-width:1450px;margin:0 auto;padding:26px}}
.kpi-grid{{display:grid;grid-template-columns:1fr 1fr 2fr 1fr 1fr 1fr;gap:16px;margin-bottom:26px}}
.kpi{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;text-align:center}}
.kpi .v{{font-size:2.3rem;font-weight:bold;margin:8px 0}}
.kpi .l{{color:#8b949e;font-size:1.1rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:22px;margin-bottom:20px}}
.card h2{{font-size:1.25rem;color:#8b949e;margin-bottom:16px}}
canvas{{max-height:280px}}
table{{width:100%;border-collapse:collapse;font-size:1.15rem}}
th,td{{padding:12px 15px;text-align:left;border-bottom:1px solid #21262d}}
th{{color:#8b949e;font-weight:600;font-size:1.15rem}}
tr:hover{{background:#1c2128}}
td.ip{{font-family:monospace;color:#79c0ff;font-size:1.15rem}}
.green{{color:#3fb950}}.yellow{{color:#d29922}}.red{{color:#f85149}}.dim{{color:#484f58}}
.badge{{display:inline-block;padding:4px 12px;border-radius:12px;font-size:1.05rem}}
.badge-red{{background:#3d1f1f;color:#f85149}}
.badge-yellow{{background:#2d2208;color:#d29922}}
.sec{{font-size:1.3rem;color:#58a6ff;margin:10px 0 16px;border-left:4px solid #58a6ff;padding-left:14px}}
.footer{{text-align:center;color:#484f58;font-size:1.05rem;padding:20px}}
.os-badge{{display:inline-block;background:#21262d;border:1px solid #58a6ff;border-radius:6px;padding:4px 14px;font-size:1.05rem;color:#58a6ff;margin-left:10px}}
.status-pill{{display:inline-block;padding:6px 18px;border-radius:14px;font-size:1.3rem;font-weight:bold}}
.ip-fit{{font-size:clamp(1.1rem,3.5vw,2.3rem);word-break:break-all;overflow-wrap:break-word}}
</style>
</head>
<body>
<header>
  <h1>🛰️ MTR 全路由節點監測 <span class="os-badge">Windows 版</span></h1>
  <p>目標：{target} | 從 {display_since} 開始 | 掃描 {scan_count} 次 | 工具：tracert + ping | 更新：{now_str}</p>
</header>
<div class="container">
  <div class="kpi-grid">
    <div class="kpi"><div class="l">整體狀態</div><div class="v"><span class="status-pill" style="background:{status_bg};color:{status_color}">{status_label}</span></div></div>
    <div class="kpi"><div class="l">路由跳點數</div><div class="v" style="color:#58a6ff">{hop_count}</div></div>
    <div class="kpi"><div class="l">最終節點</div><div class="v ip-fit" style="color:#79c0ff">{final_label}</div></div>
    <div class="kpi"><div class="l">掃描間隔</div><div class="v">{interval}<span style="font-size:1rem">s</span></div></div>
    <div class="kpi"><div class="l">遺失警報閾值</div><div class="v red">&gt;{alert_loss}%</div></div>
    <div class="kpi"><div class="l">延遲警報閾值</div><div class="v yellow">&gt;{alert_lat}ms</div></div>
  </div>

  <div class="card">
    <div class="sec">📡 最新路由快照（tracert + ping 結果）</div>
    {snapshot_html}
  </div>

  <div class="card">
    <h2>📈 目標節點延遲趨勢（{final_label}）</h2>
    <canvas id="latChart"></canvas>
  </div>
  <div class="card">
    <h2>📉 目標節點封包遺失率（{final_label}）</h2>
    <canvas id="lossChart"></canvas>
  </div>

  <div class="card">
    <div class="sec">📊 各跳點 {display_hours} 小時統計</div>
    {history_html}
  </div>

  <div class="card">
    <div class="sec">⚠️ 警報記錄</div>
    {alert_html}
  </div>
</div>
<div class="footer">MTR Monitor Windows v2.0 | tracert + ping | 目標：{target}</div>

<script>
const rawLabels={labels_js},latData={lat_js},lossData={loss_js};
const multiDay=(function(){{if(rawLabels.length<2)return false;return rawLabels[0].slice(0,10)!==rawLabels[rawLabels.length-1].slice(0,10)}})();
const labels=rawLabels.map(function(s){{if(!multiDay)return s.slice(11,16);var m=s.slice(5,7),d=s.slice(8,10),t=s.slice(11,16);return m+'/'+d+' '+t}});
const baseOpt={{responsive:true,animation:false,
  plugins:{{legend:{{labels:{{color:'#8b949e',font:{{size:16}}}}}}}},
  scales:{{x:{{ticks:{{color:'#484f58',maxTicksLimit:12,font:{{size:14}}}},grid:{{color:'#21262d'}}}},
           y:{{beginAtZero:true,ticks:{{color:'#8b949e',font:{{size:15}}}},grid:{{color:'#21262d'}}}}}}}};
new Chart(document.getElementById('latChart'),{{type:'line',
  data:{{labels,datasets:[{{label:'Avg Latency(ms)',data:latData,
    borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,0.1)',fill:true,tension:0.3,pointRadius:2}}]}},
  options:baseOpt}});
const lossOpt=JSON.parse(JSON.stringify(baseOpt));
lossOpt.scales.y.max=100;
new Chart(document.getElementById('lossChart'),{{type:'bar',
  data:{{labels,datasets:[{{label:'Packet Loss(%)',data:lossData,
    backgroundColor:'rgba(248,81,73,0.6)',borderColor:'#f85149',borderWidth:1}}]}},
  options:lossOpt}});
</script>
</body>
</html>""".format(
        target=html_escape(target), display_since=display_since, display_hours=display_hours, scan_count=scan_count, now_str=now_str,
        hop_count=len(latest_hops), final_label=html_escape(final_label),
        interval=DEFAULT_INTERVAL,
        alert_loss=ALERT_LOSS, alert_lat=ALERT_LATENCY,
        status_label=overall_label,
        status_color=overall_color,
        status_bg={
            "normal": "#0d2818", "warning": "#2d2208", "critical": "#3d1f1f"
        }.get(overall_status, "#0d2818"),
        snapshot_html=snapshot_html,
        history_html=history_html,
        alert_html=alert_html,
        labels_js=labels_js, lat_js=lat_js, loss_js=loss_js,
    )

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info("📊 報告已更新：{}".format(os.path.abspath(report_path)))

# ─────────────────── 主程式 ───────────────────

def signal_handler(sig, frame):
    global running
    logging.info("收到終止訊號，正在結束...")
    running = False


def show_config_dialog():
    """
    啟動時彈出設定對話框，讓使用者輸入監測參數。
    回傳 dict 或 None（使用者按取消）
    """
    result: dict = {}

    root = tk.Tk()
    root.title("🛰️ IDC MTR 監測設定")
    root.resizable(True, True)
    root.minsize(580, 480)
    root.geometry("620x520")
    root.configure(bg="#1a1a2e")

    # ── 讓內容隨視窗縮放 ──
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)   # 表單區域可伸縮

    # 標題區域（固定高度）
    header = tk.Frame(root, bg="#1a1a2e")
    header.grid(row=0, column=0, sticky="ew", pady=(20, 0))
    tk.Label(header, text="🛰️",
             font=("Segoe UI Emoji", 32),
             bg="#1a1a2e", fg="#58a6ff").pack()
    tk.Label(header, text="IDC MTR 全路由節點監測",
             font=("Microsoft JhengHei", 20, "bold"),
             bg="#1a1a2e", fg="#58a6ff").pack(pady=(4, 4))
    tk.Label(header, text="Windows 版 | tracert + ping",
             font=("Microsoft JhengHei", 11),
             bg="#1a1a2e", fg="#8b949e").pack()

    # 表單區域（置中、隨視窗伸縮）
    form_outer = tk.Frame(root, bg="#1a1a2e")
    form_outer.grid(row=1, column=0, sticky="nsew")
    form_outer.columnconfigure(0, weight=1)
    form_outer.rowconfigure(0, weight=1)

    frame = tk.Frame(form_outer, bg="#1a1a2e")
    frame.grid(row=0, column=0, padx=50, pady=10)
    # 讓欄位隨寬度伸展
    frame.columnconfigure(1, weight=1)

    def row(label, default, row_num, tip=""):
        tk.Label(frame, text=label, bg="#1a1a2e", fg="#c9d1d9",
                 font=("Microsoft JhengHei", 13, "bold"), anchor="w"
                 ).grid(row=row_num, column=0, pady=10, padx=(0, 16), sticky="w")
        var = tk.StringVar(value=str(default))
        entry = tk.Entry(frame, textvariable=var, width=20,
                         bg="#21262d", fg="#c9d1d9",
                         insertbackground="white",
                         relief="flat", font=("Consolas", 14))
        entry.grid(row=row_num, column=1, pady=10, sticky="ew")
        if tip:
            tk.Label(frame, text=tip, bg="#1a1a2e", fg="#484f58",
                     font=("Microsoft JhengHei", 9)
                     ).grid(row=row_num, column=2, padx=(10, 0), sticky="w")
        return var

    v_target   = row("目標 IP",    DEFAULT_TARGET,   0, "必填")
    v_interval = row("掃描間隔(秒)", DEFAULT_INTERVAL, 1, "建議 300")
    v_cycles   = row("Ping 次數",  DEFAULT_CYCLES,   2, "建議 10~30")
    v_loss     = row("遺失警報%",  ALERT_LOSS,       3, "0~100")
    v_lat      = row("延遲警報ms", ALERT_LATENCY,    4, "ms")

    def on_start():
        target = v_target.get().strip()
        if not target:
            messagebox.showwarning("警告", "請輸入目標 IP！", parent=root)
            return
        try:
            result["target"]   = target
            result["interval"] = int(v_interval.get())
            result["cycles"]   = int(v_cycles.get())
            result["loss"]     = float(v_loss.get())
            result["latency"]  = float(v_lat.get())
        except ValueError:
            messagebox.showwarning("警告", "數字格式錯誤，請重新輸入！", parent=root)
            return
        root.destroy()

    def on_cancel():
        root.destroy()

    # 按鈕區域（固定在底部）
    btn_frame = tk.Frame(root, bg="#1a1a2e")
    btn_frame.grid(row=2, column=0, pady=(10, 20))
    tk.Button(btn_frame, text="  開始監測  ",
              command=on_start,
              bg="#238636", fg="white", font=("Microsoft JhengHei", 13, "bold"),
              relief="flat", padx=18, pady=8, cursor="hand2"
              ).pack(side="left", padx=12)
    tk.Button(btn_frame, text="  取  消  ",
              command=on_cancel,
              bg="#484f58", fg="white", font=("Microsoft JhengHei", 13),
              relief="flat", padx=18, pady=8, cursor="hand2"
              ).pack(side="left", padx=12)

    def _focus_first():
        children = frame.winfo_children()
        if len(children) > 1:
            children[1].focus_set()
    root.after(100, cast(Callable[..., Any], _focus_first))
    root.mainloop()
    return result if result else None

def main():
    import sys
    global ALERT_LOSS, ALERT_LATENCY  # 宣告全局變數修改權限
    # ── 預先宣告型別（避免 Pyre2 無法從 if/else 兩分支推斷型別）──
    target:       str = DEFAULT_TARGET
    interval:     int = DEFAULT_INTERVAL
    cycles:       int = DEFAULT_CYCLES
    workers:      int = 8
    hours:        int = 24
    db:           str = ""
    report:       str = ""
    report_every: int = 1

    if len(sys.argv) <= 1:
        # ── GUI 模式：彈出設定視窗 ──
        cfg = show_config_dialog()
        if cfg is None:
            return   # 使用者按取消
        target       = str(cfg["target"])
        interval     = int(cfg["interval"])
        cycles       = int(cfg["cycles"])
        workers      = 8
        hours        = 24
        db           = make_db_path(target)
        report       = make_report_path(target)
        report_every = 1
        ALERT_LOSS    = float(cfg["loss"])
        ALERT_LATENCY = float(cfg["latency"])
    else:
        # ── 命令列模式 ──
        parser = argparse.ArgumentParser(description="IDC MTR 全路由節點監測工具（Windows 版）")
        parser.add_argument("target",  nargs="?", default=DEFAULT_TARGET)
        parser.add_argument("-i", "--interval",     type=int, default=DEFAULT_INTERVAL)
        parser.add_argument("-c", "--cycles",       type=int, default=DEFAULT_CYCLES)
        parser.add_argument("-w", "--workers",      type=int, default=8)
        parser.add_argument("-r", "--report-every", type=int, default=1)
        parser.add_argument("--hours",  type=int, default=24)
        parser.add_argument("--db",     default="")
        parser.add_argument("--report", default="")
        args         = parser.parse_args()
        target       = str(args.target)
        interval     = int(args.interval)
        cycles       = int(args.cycles)
        workers      = int(args.workers)
        hours        = int(args.hours)
        db           = str(args.db) if args.db else make_db_path(target)
        report       = str(args.report) if args.report else make_report_path(target)
        report_every = int(args.report_every)

    setup_logging()
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    init_db(db)

    logging.info("=" * 65)
    logging.info("🛰️  MTR 全路由節點監測啟動（Windows 版）")
    logging.info("   目標 IP   : {}".format(target))
    logging.info("   掃描間隔  : {} 秒".format(interval))
    logging.info("   Ping 次數 : {} 封包/跳點".format(cycles))
    logging.info("   平行執行緒 : {} 個".format(workers))
    logging.info("   工具      : tracert + ping（Windows 內建）")
    logging.info("   警報閾值  : 遺失 > {}%  延遲 > {}ms".format(ALERT_LOSS, ALERT_LATENCY))
    logging.info("   資料庫    : {}".format(os.path.abspath(db)))
    logging.info("   報告路徑  : {}".format(os.path.abspath(report)))
    logging.info("=" * 65)

    counter = 0
    while running:
        start_t = time.time()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logging.info("▶  開始掃描 → {}".format(target))

        hops = run_mtr_scan(
            target, cycles,
            TRACERT_TIMEOUT, PING_TIMEOUT, workers
        )

        if not hops:
            logging.warning("本次掃描未取得資料，跳過")
        else:
            save_scan(db, target, hops, ts)
            check_alerts(db, target, hops, ts)

            logging.info("  Hop  {:<18} Loss%   Last    Avg   Best  Worst  Jitter".format("IP"))
            logging.info("  " + "-" * 68)
            for h in hops:
                def fmt_v(v: object) -> str:
                    return "{:>6.1f}".format(v) if v is not None else "   ???"
                logging.info("  {:>3}  {:<18} {:>5.1f}%  {}  {}  {}  {}  {}".format(
                    h["hop_num"], h["hop_ip"], h["loss_pct"],
                    fmt_v(h.get("last_ms")), fmt_v(h.get("avg_ms")),
                    fmt_v(h.get("best_ms")), fmt_v(h.get("worst_ms")), fmt_v(h.get("stdev_ms"))))

        counter += 1
        if counter % int(report_every) == 0:
            generate_report(db, target, report, hours)

        # 每 50 次掃描清理一次舊資料
        if counter % 50 == 0:
            cleanup_old_data(db, keep_days=7)

        elapsed = time.time() - start_t
        wait_t  = max(0.0, float(interval) - elapsed)
        logging.info("◷  下次掃描倒數 {:.0f} 秒...".format(wait_t))
        # 用小段 sleep 輪詢，讓 SIGINT 能即時中斷
        end_time = time.time() + wait_t
        while running and time.time() < end_time:
            time.sleep(1)

    generate_report(db, target, report, hours)
    logging.info("監測已停止。")

if __name__ == "__main__":
    main()
