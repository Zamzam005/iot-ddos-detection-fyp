#!/usr/bin/env python3
"""
extract_features.py - Convert PCAP files to CSV with 15 features
Reads all 5 PCAP files, extracts the 15 features from Chapter 3.5.3,
labels each flow, and saves to one combined CSV.

Run:
    python3 extract_features.py
"""

import os
import pandas as pd
from nfstream import NFStreamer

# Path to PCAPs and where to save the CSV
PCAP_DIR = "/home/vynox/fyp/simulation/pcaps"
OUTPUT_CSV = "/home/vynox/fyp/simulation/iot_dataset.csv"

# Each PCAP gets a label:
#   0 = Benign
#   1 = DDoS attack (we keep all 4 attack types together for binary classification)
PCAP_FILES = {
    "benign.pcap":     0,
    "syn_flood.pcap":  1,
    "udp_flood.pcap":  1,
    "icmp_flood.pcap": 1,
    "http_flood.pcap": 1,
}


def extract_from_pcap(pcap_path, label):
    """Extract per-flow features from one PCAP file."""
    print(f"[+] Processing {os.path.basename(pcap_path)} (label={label})...")

    # NFStreamer reads the PCAP and groups packets into flows
    streamer = NFStreamer(
        source=pcap_path,
        statistical_analysis=True,   # we want flow statistics
        n_dissections=0,              # skip deep packet inspection (faster)
    )

    rows = []
    for flow in streamer:
        # Extract the 15 features matching Chapter 3.5.3 Table 3.6
        row = {
            # Flow features
            "flow_duration":           flow.bidirectional_duration_ms / 1000.0,
            "total_fwd_packets":       flow.src2dst_packets,
            "total_bwd_packets":       flow.dst2src_packets,
            "total_length_fwd_packets": flow.src2dst_bytes,
            "bwd_bytes_per_second":    flow.dst2src_bytes / max(flow.bidirectional_duration_ms / 1000.0, 0.001),

            # Packet features
            "packet_length_mean":      flow.bidirectional_mean_ps,
            "fwd_packet_length_max":   flow.src2dst_max_ps,

            # Flag features
            "syn_flag_count":          flow.bidirectional_syn_packets,
            "ack_flag_count":          flow.bidirectional_ack_packets,
            "rst_flag_count":          flow.bidirectional_rst_packets,
            "fin_flag_count":          flow.bidirectional_fin_packets,

            # Rate features
            "fwd_packets_per_second":  flow.src2dst_packets / max(flow.bidirectional_duration_ms / 1000.0, 0.001),
            "bwd_packets_per_second":  flow.dst2src_packets / max(flow.bidirectional_duration_ms / 1000.0, 0.001),

            # Temporal
            "flow_iat_mean":           flow.bidirectional_mean_piat_ms,

            # Protocol
            "protocol_type":           flow.protocol,
            "service":                 flow.dst_port,

            # Label
            "class": label,
        }
        rows.append(row)

    print(f"    -> Extracted {len(rows)} flows")
    return rows


def main():
    all_rows = []

    # Process each PCAP file
    for pcap_name, label in PCAP_FILES.items():
        pcap_path = os.path.join(PCAP_DIR, pcap_name)
        if not os.path.exists(pcap_path):
            print(f"[!] {pcap_path} not found, skipping")
            continue
        rows = extract_from_pcap(pcap_path, label)
        all_rows.extend(rows)

    # Create the dataset
    print(f"\n[+] Total flows extracted: {len(all_rows)}")
    df = pd.DataFrame(all_rows)

    # Show class distribution
    print("\n[+] Class distribution:")
    print(df["class"].value_counts())
    print(f"\n    Benign ratio: {(df['class'] == 0).sum() / len(df) * 100:.1f}%")
    print(f"    Attack ratio: {(df['class'] == 1).sum() / len(df) * 100:.1f}%")

    # Save to CSV
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n[+] Saved dataset to {OUTPUT_CSV}")
    print(f"    File size: {os.path.getsize(OUTPUT_CSV) / 1024 / 1024:.1f} MB")
    print(f"    Total rows: {len(df)}")
    print(f"    Total columns: {len(df.columns)}")


if __name__ == "__main__":
    main()
