#!/usr/bin/env python3
"""
analyze_mpegts.py — ffprobe-based analysis of dontlookup.py MPEG-TS outputs.

For each .mpegts file produced by dontlookup.py, this script:
  - Runs ffprobe to extract program and stream metadata
  - Scans every TS packet to read the transport_scrambling_control field
  - Determines each service's encryption status (clear / scrambled / mixed)
  - Writes a program metadata CSV and a scrambling status CSV

Usage:
    python3 analyze_mpegts.py <input.mpegts> [<input2.mpegts> ...]
    python3 analyze_mpegts.py *.mpegts

Outputs:
    mpegts_programs.csv    — one row per program/stream found by ffprobe
    mpegts_scrambling.csv  — scrambling status per file
    mpegts_summary.csv     — one row per input file combining both

Requirements:
    ffprobe must be installed and on PATH (part of ffmpeg).
    Python 3.8+, no extra libraries needed beyond stdlib.
"""

import sys
import csv
import json
import os
import subprocess
import struct
from collections import Counter


# ---------------------------------------------------------------------------
# ffprobe helpers
# ---------------------------------------------------------------------------

TS_PACKET_SIZE = 188
TS_SYNC_BYTE = 0x47


def run_ffprobe(path: str) -> dict | None:
    """
    Run ffprobe on a .mpegts file and return parsed JSON.
    Returns None if ffprobe fails or is not installed.
    """
    cmd = [
        "ffprobe",
        "-v", "quiet",
        "-print_format", "json",
        "-show_programs",
        "-show_streams",
        path
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            print(f"    ffprobe error: {result.stderr.strip()}")
            return None
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("    ERROR: ffprobe not found. Install ffmpeg and ensure it is on PATH.")
        return None
    except subprocess.TimeoutExpired:
        print("    ERROR: ffprobe timed out.")
        return None
    except json.JSONDecodeError as e:
        print(f"    ERROR: Could not parse ffprobe output: {e}")
        return None


def extract_program_rows(ffprobe_data: dict, filename: str) -> list[dict]:
    """
    Flatten ffprobe programs/streams output into one row per stream.
    """
    rows = []
    programs = ffprobe_data.get("programs", [])

    # Build a stream index for quick lookup
    streams_by_index = {
        s["index"]: s
        for s in ffprobe_data.get("streams", [])
    }

    for prog in programs:
        prog_id = prog.get("program_id", "")
        prog_num = prog.get("program_num", "")
        service_name = prog.get("tags", {}).get("service_name", "")
        service_provider = prog.get("tags", {}).get("service_provider", "")

        for stream_ref in prog.get("streams", []):
            idx = stream_ref.get("index", stream_ref) if isinstance(stream_ref, dict) else stream_ref
            stream = streams_by_index.get(idx, stream_ref if isinstance(stream_ref, dict) else {})

            rows.append({
                "file": filename,
                "program_id": prog_id,
                "program_num": prog_num,
                "service_name": service_name,
                "service_provider": service_provider,
                "stream_index": idx,
                "codec_type": stream.get("codec_type", ""),
                "codec_name": stream.get("codec_name", ""),
                "width": stream.get("width", ""),
                "height": stream.get("height", ""),
                "avg_frame_rate": stream.get("avg_frame_rate", ""),
                "sample_rate": stream.get("sample_rate", ""),
                "language": stream.get("tags", {}).get("language", ""),
            })

    if not programs:
        # No program map — still record what streams were found
        for stream in ffprobe_data.get("streams", []):
            rows.append({
                "file": filename,
                "program_id": "",
                "program_num": "",
                "service_name": "",
                "service_provider": "",
                "stream_index": stream.get("index", ""),
                "codec_type": stream.get("codec_type", ""),
                "codec_name": stream.get("codec_name", ""),
                "width": stream.get("width", ""),
                "height": stream.get("height", ""),
                "avg_frame_rate": stream.get("avg_frame_rate", ""),
                "sample_rate": stream.get("sample_rate", ""),
                "language": stream.get("tags", {}).get("language", ""),
            })

    return rows


# ---------------------------------------------------------------------------
# Transport scrambling scan
# ---------------------------------------------------------------------------

def scan_scrambling(path: str) -> dict:
    """
    Read every 188-byte TS packet and tally transport_scrambling_control values.

    The transport_scrambling_control field occupies bits 6-7 of the 4th byte
    of every TS packet header:
      00 = not scrambled
      01 = reserved (treated as clear in practice)
      10 = scrambled with even key
      11 = scrambled with odd key

    Returns a dict with counts and a derived status string.
    """
    counts = Counter()
    total_packets = 0
    sync_errors = 0

    try:
        with open(path, "rb") as f:
            while True:
                pkt = f.read(TS_PACKET_SIZE)
                if len(pkt) < TS_PACKET_SIZE:
                    break
                if pkt[0] != TS_SYNC_BYTE:
                    sync_errors += 1
                    continue
                total_packets += 1
                # transport_scrambling_control = top 2 bits of byte 3
                tsc = (pkt[3] >> 6) & 0x03
                counts[tsc] += 1
    except OSError as e:
        return {"error": str(e)}

    n = total_packets or 1
    clear_count = counts[0] + counts[1]       # 00 and 01 = not scrambled
    scrambled_count = counts[2] + counts[3]   # 10 and 11 = scrambled

    pct_scrambled = round(scrambled_count / n * 100, 2)

    if pct_scrambled == 0:
        status = "clear"
    elif pct_scrambled == 100:
        status = "fully scrambled"
    elif pct_scrambled > 90:
        status = "mostly scrambled"
    elif pct_scrambled < 10:
        status = "mostly clear"
    else:
        status = "mixed"

    return {
        "total_ts_packets": total_packets,
        "sync_errors": sync_errors,
        "clear_packets": clear_count,
        "scrambled_packets": scrambled_count,
        "pct_scrambled": pct_scrambled,
        "tsc_00": counts[0],
        "tsc_01": counts[1],
        "tsc_10": counts[2],
        "tsc_11": counts[3],
        "encryption_status": status,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mpegts_files = sys.argv[1:]
    all_program_rows = []
    all_scrambling_rows = []
    all_summary_rows = []

    for path in mpegts_files:
        if not os.path.isfile(path):
            print(f"[!] File not found: {path}")
            continue

        filename = os.path.basename(path)
        print(f"\n[*] Analyzing {filename}")

        # --- ffprobe ---
        ffprobe_data = run_ffprobe(path)
        program_rows = []
        if ffprobe_data:
            program_rows = extract_program_rows(ffprobe_data, filename)
            all_program_rows.extend(program_rows)
            n_programs = len(ffprobe_data.get("programs", []))
            n_streams = len(ffprobe_data.get("streams", []))
            print(f"    Programs : {n_programs}")
            print(f"    Streams  : {n_streams}")
            for row in program_rows:
                if row["codec_type"]:
                    print(f"      [{row['program_id']}] {row['service_name'] or '(unnamed)'} "
                          f"— {row['codec_type']} / {row['codec_name']}")
        else:
            n_programs = 0
            n_streams = 0

        # --- Scrambling scan ---
        print(f"    Scanning transport_scrambling_control field ...")
        scram = scan_scrambling(path)
        if "error" in scram:
            print(f"    ERROR scanning file: {scram['error']}")
            continue

        print(f"    Total TS packets : {scram['total_ts_packets']}")
        print(f"    Scrambled        : {scram['pct_scrambled']}%")
        print(f"    Status           : {scram['encryption_status'].upper()}")

        scrambling_row = {"file": filename, **scram}
        all_scrambling_rows.append(scrambling_row)

        summary_row = {
            "file": filename,
            "n_programs": n_programs,
            "n_streams": n_streams,
            "total_ts_packets": scram["total_ts_packets"],
            "sync_errors": scram["sync_errors"],
            "pct_scrambled": scram["pct_scrambled"],
            "encryption_status": scram["encryption_status"],
        }
        all_summary_rows.append(summary_row)

    # --- Write CSVs ---
    if all_program_rows:
        prog_csv = "mpegts_programs.csv"
        with open(prog_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_program_rows[0].keys()))
            writer.writeheader()
            writer.writerows(all_program_rows)
        print(f"\n[+] Program metadata written to {prog_csv}")

    if all_scrambling_rows:
        scram_csv = "mpegts_scrambling.csv"
        with open(scram_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_scrambling_rows[0].keys()))
            writer.writeheader()
            writer.writerows(all_scrambling_rows)
        print(f"[+] Scrambling detail written to {scram_csv}")

    if all_summary_rows:
        summ_csv = "mpegts_summary.csv"
        with open(summ_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_summary_rows[0].keys()))
            writer.writeheader()
            writer.writerows(all_summary_rows)
        print(f"[+] Summary written to {summ_csv}")

    # Console summary
    print("\n=== Summary ===")
    for row in all_summary_rows:
        print(f"  {row['file']:40s}  {row['encryption_status'].upper():20s}  "
              f"{row['pct_scrambled']}% scrambled  |  "
              f"{row['n_programs']} programs, {row['n_streams']} streams")


if __name__ == "__main__":
    main()
