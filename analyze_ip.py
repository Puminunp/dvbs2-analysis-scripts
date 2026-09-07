#!/usr/bin/env python3
"""
analyze_ip.py — Scapy-based analysis of dontlookup.py IP pcap outputs.

For each .ip.pcap file produced by dontlookup.py, this script:
  - Validates whether the output looks like real IP traffic
  - Tags each packet by address type (link-local, private, public)
  - Estimates plaintext fraction of each packet's payload
  - Writes a per-packet CSV and a per-file summary CSV

Usage:
    python3 analyze_ip.py <input.ip.pcap> [<input2.ip.pcap> ...]
    python3 analyze_ip.py *.ip.pcap

Outputs:
    <input>_packets.csv   — one row per packet
    analysis_summary.csv  — one row per input file
"""

import sys
import csv
import ipaddress
import os
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, Raw


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify_address(ip_str: str) -> str:
    """Return 'link-local', 'private', or 'public' for a given IP string."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_link_local:
            return "link-local"
        if addr.is_private:
            return "private"
        return "public"
    except ValueError:
        return "unknown"


def plaintext_fraction(payload: bytes) -> float:
    """
    Return the fraction of payload bytes that fall in the printable ASCII
    range (0x20–0x7E plus common whitespace). Encrypted or compressed data
    distributes uniformly; plaintext clusters in this range.
    """
    if not payload:
        return 0.0
    printable = sum(
        1 for b in payload
        if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    return round(printable / len(payload), 4)


def is_likely_real_traffic(packets) -> tuple[bool, str]:
    """
    Heuristic check for whether a pcap looks like real IP traffic vs a
    false positive from the blind header search.

    Returns (bool, reason_string).
    """
    ip_packets = [p for p in packets if IP in p]

    if len(ip_packets) < 10:
        return False, f"too few IP packets ({len(ip_packets)})"

    pairs = [(p[IP].src, p[IP].dst) for p in ip_packets]
    pair_counts = Counter(pairs)
    top_pair_count = pair_counts.most_common(1)[0][1] if pair_counts else 0

    if top_pair_count < 3:
        return False, "no repeating src/dst pairs — likely false positive"

    # Check that at least some protocol values are recognisable
    known_protos = {1, 6, 17, 41, 47, 50, 51, 58, 89, 132}
    protos = {p[IP].proto for p in ip_packets}
    if not protos & known_protos:
        return False, f"no recognised IP protocols (found: {protos})"

    return True, "ok"


# ---------------------------------------------------------------------------
# Per-packet analysis
# ---------------------------------------------------------------------------

def analyze_pcap(pcap_path: str) -> dict:
    """
    Analyze a single .ip.pcap file.

    Returns a summary dict and writes a per-packet CSV alongside the input.
    """
    print(f"\n[*] Reading {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"    ERROR reading file: {e}")
        return {"file": pcap_path, "error": str(e)}

    ip_packets = [p for p in packets if IP in p]
    valid, reason = is_likely_real_traffic(packets)

    print(f"    Total packets : {len(packets)}")
    print(f"    IP packets    : {len(ip_packets)}")
    print(f"    Validation    : {'PASS' if valid else 'FAIL'} — {reason}")

    if not valid:
        return {
            "file": os.path.basename(pcap_path),
            "total_packets": len(packets),
            "ip_packets": len(ip_packets),
            "valid": False,
            "validation_reason": reason,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "unique_pairs": 0,
            "pct_link_local_src": 0,
            "pct_private_src": 0,
            "pct_public_src": 0,
            "mean_plaintext_fraction": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "other_proto_packets": 0,
        }

    # Write per-packet CSV
    out_csv = pcap_path.replace(".pcap", "_packets.csv")
    src_types = []
    plaintext_fracs = []

    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "packet_num", "src_ip", "dst_ip", "src_type", "dst_type",
            "protocol", "src_port", "dst_port",
            "payload_bytes", "plaintext_fraction"
        ])

        for i, pkt in enumerate(ip_packets):
            src = pkt[IP].src
            dst = pkt[IP].dst
            src_type = classify_address(src)
            dst_type = classify_address(dst)
            proto_num = pkt[IP].proto
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num))

            src_port = dst_port = ""
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            pt_frac = plaintext_fraction(payload)

            src_types.append(src_type)
            plaintext_fracs.append(pt_frac)

            writer.writerow([
                i, src, dst, src_type, dst_type,
                proto, src_port, dst_port,
                len(payload), pt_frac
            ])

    print(f"    Per-packet CSV: {out_csv}")

    # Aggregate summary stats
    type_counts = Counter(src_types)
    n = len(ip_packets) or 1

    unique_srcs = len({p[IP].src for p in ip_packets})
    unique_dsts = len({p[IP].dst for p in ip_packets})
    unique_pairs = len({(p[IP].src, p[IP].dst) for p in ip_packets})
    tcp_count = sum(1 for p in ip_packets if TCP in p)
    udp_count = sum(1 for p in ip_packets if UDP in p)
    other_count = len(ip_packets) - tcp_count - udp_count
    mean_pt = round(sum(plaintext_fracs) / len(plaintext_fracs), 4) if plaintext_fracs else 0

    return {
        "file": os.path.basename(pcap_path),
        "total_packets": len(packets),
        "ip_packets": len(ip_packets),
        "valid": True,
        "validation_reason": reason,
        "unique_src_ips": unique_srcs,
        "unique_dst_ips": unique_dsts,
        "unique_pairs": unique_pairs,
        "pct_link_local_src": round(type_counts["link-local"] / n, 4),
        "pct_private_src": round(type_counts["private"] / n, 4),
        "pct_public_src": round(type_counts["public"] / n, 4),
        "mean_plaintext_fraction": mean_pt,
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "other_proto_packets": other_count,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    pcap_files = sys.argv[1:]
    summaries = []

    for path in pcap_files:
        if not os.path.isfile(path):
            print(f"[!] File not found: {path}")
            continue
        summary = analyze_pcap(path)
        summaries.append(summary)

    # Write summary CSV
    summary_path = "analysis_summary.csv"
    if summaries:
        fieldnames = list(summaries[0].keys())
        with open(summary_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(summaries)
        print(f"\n[+] Summary written to {summary_path}")

    # Print quick console summary
    print("\n=== Summary ===")
    for s in summaries:
        status = "PASS" if s.get("valid") else "FAIL"
        print(f"  {s['file']:40s}  {status}  —  {s.get('ip_packets', 0)} IP packets")


if __name__ == "__main__":
    main()
