---
name: dvbs2-analysis
description: Use this skill whenever the user wants to analyze DVB-S2 satellite transponder captures using the dontlookup.py pipeline. Covers running analyze_ip.py on .ip.pcap files (Scapy-based IP traffic validation, address tagging, plaintext detection) and analyze_mpegts.py on .mpegts files (ffprobe program metadata, transport_scrambling_control scanning). Use when the user mentions satellite captures, DVB-S2, Ku-band traffic, pcap analysis, MPEG-TS scrambling, or asks to interpret analysis_summary.csv or mpegts_summary.csv outputs.
---

# DVB-S2 Traffic Analysis Skill

## Overview

This skill covers the full analysis pipeline for raw DVB-S2 satellite transponder captures. The pipeline has two stages:

1. **Decapsulation** — `dontlookup.py` converts raw `.ts` captures into `.ip.pcap` and `.mpegts` files
2. **Analysis** — `analyze_ip.py` and `analyze_mpegts.py` process those outputs into CSVs

This skill covers Stage 2 only. For Stage 1 (running dontlookup.py), see the dontlookup GitHub repository at https://github.com/ucsdsysnet/dontlookup.

---

## Pipeline Overview

```
capture.ts  (raw DVB-S2 baseband — NOT a standard transport stream)
     │
     ▼
dontlookup.py  (runs all parsers independently)
     │
     ├── *.ip.pcap      ──►  analyze_ip.py      ──►  analysis_summary.csv
     │                                                <file>_packets.csv
     │
     └── *.mpegts       ──►  analyze_mpegts.py  ──►  mpegts_programs.csv
                                                      mpegts_scrambling.csv
                                                      mpegts_summary.csv
```

---

## Environment Setup

### Local
```bash
pip install scapy
# ffmpeg must be installed and on PATH
# macOS:   brew install ffmpeg
# Ubuntu:  sudo apt-get install ffmpeg
# Windows: https://ffmpeg.org/download.html
```

### Google Colab (run once per session)
```python
!pip install scapy -q
!apt-get install -y ffmpeg -q
```

### Mount Google Drive (Colab only)
```python
from google.colab import drive
drive.mount('/content/drive')
```

---

## Script 1: analyze_ip.py

Validates IP pcap outputs from dontlookup and tags surviving traffic.

### What it does
- Checks each `.ip.pcap` for signs of real traffic vs false positives from the blind header search
- Tags each packet by source address type: `link-local`, `private`, or `public`
- Estimates plaintext fraction of each packet's payload (0.0 = fully encrypted, 1.0 = fully readable)
- Writes a per-packet CSV and an overall summary CSV

### False-positive detection logic
A file is flagged `valid = False` if any of these are true:
- Fewer than 10 IP packets total
- No repeating source/destination address pairs
- No recognised IP protocol values (TCP=6, UDP=17, ICMP=1, etc.)

### Running locally
```bash
python3 analyze_ip.py capture.ts.dvbs2.ip.pcap
python3 analyze_ip.py *.ip.pcap   # batch — all pcap files at once
```

### Running on Colab (handles spaces in paths)
```python
import glob, subprocess

files = glob.glob("/content/drive/MyDrive/Satellite Project/DATASET 2/PCAP/*.ip.pcap")
print(f"Found {len(files)} files")
subprocess.run(["python3", "/content/analyze_ip.py"] + files)
```

### Outputs

**`analysis_summary.csv`** — one row per input file

| Column | Meaning |
|--------|---------|
| `file` | Input filename |
| `total_packets` | All packets in file |
| `ip_packets` | Packets with valid IP headers |
| `valid` | True = real traffic, False = false positive |
| `validation_reason` | Why it passed or failed |
| `unique_src_ips` | Number of distinct source IPs |
| `unique_dst_ips` | Number of distinct destination IPs |
| `unique_pairs` | Number of distinct src/dst pairs |
| `pct_link_local_src` | Fraction of packets with link-local source |
| `pct_private_src` | Fraction of packets with private source |
| `pct_public_src` | Fraction of packets with public source |
| `mean_plaintext_fraction` | Average payload readability (0–1) |
| `tcp_packets` | TCP packet count |
| `udp_packets` | UDP packet count |
| `other_proto_packets` | Other protocol packet count |

**`<file>_packets.csv`** — one row per IP packet (only written for valid files)

| Column | Meaning |
|--------|---------|
| `src_ip` / `dst_ip` | Source and destination IP addresses |
| `src_type` / `dst_type` | `link-local`, `private`, or `public` |
| `protocol` | `TCP`, `UDP`, `ICMP`, or numeric |
| `src_port` / `dst_port` | Port numbers (blank for non-TCP/UDP) |
| `payload_bytes` | Raw payload size in bytes |
| `plaintext_fraction` | Fraction of payload in printable ASCII range |

### Interpreting results
```python
import pandas as pd

# Check which files passed validation
df = pd.read_csv("analysis_summary.csv")
print(df[["file", "ip_packets", "valid", "validation_reason"]])

# Inspect a specific transponder's per-packet detail
pkt = pd.read_csv("97.0W_11866.986_V_25714_packets.csv")
print(pkt[["src_ip", "dst_ip", "src_type", "protocol", "plaintext_fraction"]].head(20))

# Summarise across all surviving flows
print(pkt.groupby("src_type")["plaintext_fraction"].mean())
high_pt = pkt[pkt["plaintext_fraction"] > 0.7]
print(f"{len(high_pt)} packets ({len(high_pt)/len(pkt)*100:.1f}%) are >70% plaintext")
```

### What to look for
- `valid = True` with high `mean_plaintext_fraction` (>0.3) → unencrypted IP traffic, worth investigating
- `pct_public_src > 0` → publicly routable traffic exposed in the clear
- `pct_link_local_src` close to 1.0 → internal network traffic leaking over satellite
- All `valid = False` → transponder carries broadcast content, not IP; check MPEG-TS side

---

## Script 2: analyze_mpegts.py

Analyses MPEG-TS outputs from dontlookup for program metadata and encryption status.

### What it does
- Runs `ffprobe` to extract program and service metadata (service names, codecs, languages, resolution)
- Scans every 188-byte TS packet and reads the `transport_scrambling_control` (TSC) field directly
- Classifies each file's encryption status
- Writes program metadata, scrambling detail, and summary CSVs

### Running locally
```bash
python3 analyze_mpegts.py capture.ts.dvbs2.mpegts
python3 analyze_mpegts.py *.mpegts   # batch
```

### Running on Colab
```python
import glob, subprocess

files = glob.glob("/content/drive/MyDrive/Satellite Project/DATASET 2/MPEGTS/*.mpegts")
print(f"Found {len(files)} files")
subprocess.run(["python3", "/content/analyze_mpegts.py"] + files)
```

### Outputs

**`mpegts_summary.csv`** — one row per file

| Column | Meaning |
|--------|---------|
| `file` | Input filename |
| `n_programs` | Number of programs found by ffprobe |
| `n_streams` | Number of streams found by ffprobe |
| `total_ts_packets` | Total 188-byte TS packets scanned |
| `sync_errors` | Packets without 0x47 sync byte (parsing quality indicator) |
| `pct_scrambled` | Percentage of packets with nonzero TSC |
| `encryption_status` | See status table below |

**Encryption status values**

| Status | Meaning |
|--------|---------|
| `clear` | 0% scrambled — fully unencrypted |
| `mostly clear` | <10% scrambled — effectively unencrypted |
| `mixed` | 10–90% scrambled — some services encrypted, some not |
| `mostly scrambled` | >90% scrambled |
| `fully scrambled` | 100% scrambled |

**`mpegts_programs.csv`** — one row per stream

| Column | Meaning |
|--------|---------|
| `program_id` | DVB program ID |
| `service_name` | Broadcast service name (e.g. channel name) |
| `service_provider` | Network/operator name |
| `codec_type` | `video` or `audio` |
| `codec_name` | e.g. `h264`, `hevc`, `mp2`, `aac` |
| `width` / `height` | Video resolution |
| `language` | Audio language tag |

**`mpegts_scrambling.csv`** — per-file TSC field breakdown

| Column | Meaning |
|--------|---------|
| `tsc_00` | Packets with TSC = 00 (not scrambled) |
| `tsc_01` | Packets with TSC = 01 (reserved — treat as clear) |
| `tsc_10` | Packets with TSC = 10 (scrambled, even key) |
| `tsc_11` | Packets with TSC = 11 (scrambled, odd key) |

### transport_scrambling_control field explained
The TSC is a 2-bit flag in every MPEG-TS packet header. Real CA scrambling only uses values `10` (even key) and `11` (odd key), alternating at crypto-period boundaries. Value `01` is reserved and never used by legitimate scrambling systems. A high proportion of `01` values alongside isolated `10`/`11` hits is a sign of bit errors in the physical channel, not intentional encryption.

### Interpreting results
```python
import pandas as pd

# Overview of all transponders
df = pd.read_csv("mpegts_summary.csv")
print(df[["file", "n_programs", "pct_scrambled", "encryption_status"]])

# Find unencrypted multiplexes with programs
clear = df[(df["pct_scrambled"] < 10) & (df["n_programs"] > 0)]
print(f"\n{len(clear)} transponders: unencrypted with identified programs")

# Look up what services those transponders carry
progs = pd.read_csv("mpegts_programs.csv")
for fname in clear["file"]:
    services = progs[progs["file"] == fname]["service_name"].dropna().unique()
    print(f"{fname[:30]}... → {list(services)}")
```

### What to look for
- `encryption_status = clear` or `mostly clear` with `n_programs > 0` → named services broadcasting without encryption
- `n_programs = 0` but `n_streams > 0` → streams found but no Program Map Table; parser may have partially decoded
- `sync_errors = 0` → clean capture, results are reliable
- High `pct_scrambled` with no CA descriptors → likely noise in TSC field from channel errors, not real encryption (cross-check with `mpegts_scrambling.csv` for `tsc_01` presence)

---

## Saving Results to Google Drive (Colab)

```python
import glob, shutil, os

output_dir = "/content/drive/MyDrive/Satellite Project/DATASET 2/Results/"
os.makedirs(output_dir, exist_ok=True)

# Copy all CSVs produced in /content/ to Drive
for f in glob.glob("/content/*.csv"):
    shutil.copy(f, output_dir)
    print(f"Saved: {os.path.basename(f)}")
```

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: No module named 'scapy'` | Scapy not installed | Run `!pip install scapy -q` |
| `ffprobe not found` | ffmpeg not installed | Run `!apt-get install -y ffmpeg -q` |
| `No files found` | Path has spaces, glob not expanding | Use `glob.glob()` in Python instead of shell glob |
| `*_packets.csv` not written | All files failed validation | Check `valid` column in `analysis_summary.csv` for reason |
| `n_programs = 0` in mpegts | No PAT/PMT in stream | Parser may have partially decoded; check `n_streams` |

---

## Quick Reference — What Each Output Tells You

| Question | File to open | Column to check |
|----------|-------------|-----------------|
| Which transponders had real IP traffic? | `analysis_summary.csv` | `valid` |
| Was the IP traffic readable? | `analysis_summary.csv` | `mean_plaintext_fraction` |
| What kind of IP addresses were exposed? | `analysis_summary.csv` | `pct_link_local_src`, `pct_public_src` |
| Packet-level detail for one transponder | `<file>_packets.csv` | `src_type`, `plaintext_fraction` |
| Were broadcast services encrypted? | `mpegts_summary.csv` | `encryption_status`, `pct_scrambled` |
| What services were broadcasting? | `mpegts_programs.csv` | `service_name`, `service_provider` |
| Is the scrambling real or channel noise? | `mpegts_scrambling.csv` | `tsc_01` count vs `tsc_10`/`tsc_11` |
