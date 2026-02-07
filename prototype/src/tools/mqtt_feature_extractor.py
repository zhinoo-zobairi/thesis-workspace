#!/usr/bin/env python3
"""
MQTT Feature Extractor for ML Training

This script extracts features from MQTT PCAPs using EXACTLY the same logic
as the C++ implementation in mqtt_ml.cc. This ensures the model is trained
on the same features it will receive during inference in Snort.

Author: Zhinoo Zobairi
Date: February 2026

Usage:
    python mqtt_feature_extractor.py --pcap_dir /path/to/mqttset/pcaps --output features.csv
"""

import argparse
import csv
import math
import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from scapy.all import rdpcap, TCP, IP, Raw
from scapy.layers.inet6 import IPv6

# =============================================================================
# Constants - MUST MATCH mqtt_ml.cc exactly!
# =============================================================================

MQTT_ML_NUM_FEATURES = 28

# Max values for log normalization (from mqtt_ml.cc lines 46-53)
MAX_REMAINING_LEN = 268435455.0   # MQTT max (4 bytes, 7 bits each)
MAX_KEEP_ALIVE = 65535.0          # 2 bytes
MAX_STRING_LEN = 65535.0          # MQTT string length is 2 bytes
MAX_PAYLOAD_LEN = 268435455.0     # Same as remaining_len
MAX_TIME_DELTA_US = 60000000.0    # 60 seconds in microseconds
MAX_FAILED_AUTH_RATE = 100.0      # 100 failures/sec is extreme
MAX_PKT_COUNT = 10000.0           # Packets per flow

# MQTT Message Types
MQTT_CONNECT = 1
MQTT_CONNACK = 2
MQTT_PUBLISH = 3
MQTT_PUBACK = 4
MQTT_PUBREC = 5
MQTT_PUBREL = 6
MQTT_PUBCOMP = 7
MQTT_SUBSCRIBE = 8
MQTT_SUBACK = 9
MQTT_UNSUBSCRIBE = 10
MQTT_UNSUBACK = 11
MQTT_PINGREQ = 12
MQTT_PINGRESP = 13
MQTT_DISCONNECT = 14


# =============================================================================
# Normalization Functions - MUST MATCH mqtt_ml.cc exactly!
# =============================================================================

def normalize_minmax(value: float, min_val: float, max_val: float) -> float:
    """Min-max normalization: (value - min) / (max - min)"""
    if max_val <= min_val:
        return 0.0
    result = (value - min_val) / (max_val - min_val)
    # Clamp to [0, 1]
    return max(0.0, min(1.0, result))


def normalize_log(value: float, max_val: float) -> float:
    """Log normalization: log(value + 1) / log(max + 1)"""
    if value <= 0.0:
        return 0.0
    if max_val <= 0.0:
        return 0.0
    log_val = math.log(value + 1.0)
    log_max = math.log(max_val + 1.0)
    result = log_val / log_max
    return min(1.0, result)


def normalize_flag(value: int) -> float:
    """Boolean/flag to float: 0 → 0.0, non-zero → 1.0"""
    return 1.0 if value else 0.0


# =============================================================================
# MQTT Packet Data Structures
# =============================================================================

@dataclass
class MqttPacketData:
    """Parsed MQTT packet data - mirrors mqtt_session_data_t in mqtt.h"""
    # Fixed header
    msg_type: int = 0
    dup_flag: int = 0
    qos: int = 0
    retain: int = 0
    remaining_len: int = 0
    
    # CONNECT fields
    protocol_version: int = 0
    connect_flags: int = 0
    conflag_clean_session: int = 0
    conflag_will_flag: int = 0
    conflag_will_qos: int = 0
    conflag_will_retain: int = 0
    conflag_passwd: int = 0
    conflag_uname: int = 0
    keep_alive: int = 0
    client_id_len: int = 0
    username_len: int = 0
    passwd_len: int = 0
    will_topic_len: int = 0
    will_msg_len: int = 0
    
    # CONNACK fields
    conack_return_code: int = 0
    conack_session_present: int = 0
    
    # PUBLISH fields
    topic_len: int = 0
    payload_len: int = 0
    msg_id: int = 0


@dataclass
class FlowTimingData:
    """Timing data per flow - mirrors mqtt_timing_data_t in mqtt.h"""
    first_pkt_time: float = 0.0       # First packet timestamp (seconds)
    prev_pkt_time: float = 0.0        # Previous/current packet timestamp
    pkt_count: int = 0
    failed_auth_count: int = 0
    failed_auth_window_count: int = 0
    failed_auth_window_start: float = 0.0


# =============================================================================
# MQTT Parser - Mirrors parse_*_packet() functions in mqtt.cc
# =============================================================================

class MqttParser:
    """MQTT packet parser that mirrors the C++ implementation in mqtt.cc"""
    
    @staticmethod
    def parse_remaining_length(data: bytes, offset: int) -> Tuple[int, int]:
        """Parse MQTT remaining length field (1-4 bytes with continuation bit)"""
        remaining_len = 0
        shift = 0
        start_offset = offset
        
        while offset < len(data) and offset < start_offset + 4:
            byte = data[offset]
            remaining_len |= (byte & 0x7F) << shift
            shift += 7
            offset += 1
            if (byte & 0x80) == 0:
                break
        
        return remaining_len, offset
    
    @staticmethod
    def parse_fixed_header(data: bytes) -> Optional[MqttPacketData]:
        """Parse MQTT fixed header - mirrors parse_fixed_header() in mqtt.cc"""
        if len(data) < 2:
            return None
        
        pkt = MqttPacketData()
        first_byte = data[0]
        
        pkt.msg_type = first_byte >> 4
        pkt.dup_flag = (first_byte >> 3) & 0x01
        pkt.qos = (first_byte >> 1) & 0x03
        pkt.retain = first_byte & 0x01
        pkt.remaining_len, _ = MqttParser.parse_remaining_length(data, 1)
        
        return pkt
    
    @staticmethod
    def parse_connect_packet(data: bytes, pkt: MqttPacketData) -> bool:
        """Parse CONNECT packet - mirrors parse_connect_packet() in mqtt.cc"""
        if len(data) < 12:
            return False
        
        _, offset = MqttParser.parse_remaining_length(data, 1)
        
        # Protocol name length
        if offset + 2 > len(data):
            return False
        proto_len = (data[offset] << 8) | data[offset + 1]
        offset += 2 + proto_len
        
        # Protocol version, connect flags, keep alive
        if offset + 4 > len(data):
            return False
        pkt.protocol_version = data[offset]
        pkt.connect_flags = data[offset + 1]
        pkt.conflag_clean_session = (pkt.connect_flags >> 1) & 0x01
        pkt.conflag_will_flag = (pkt.connect_flags >> 2) & 0x01
        pkt.conflag_will_qos = (pkt.connect_flags >> 3) & 0x03
        pkt.conflag_will_retain = (pkt.connect_flags >> 5) & 0x01
        pkt.conflag_passwd = (pkt.connect_flags >> 6) & 0x01
        pkt.conflag_uname = (pkt.connect_flags >> 7) & 0x01
        pkt.keep_alive = (data[offset + 2] << 8) | data[offset + 3]
        offset += 4
        
        # Client ID
        if offset + 2 > len(data):
            return True
        pkt.client_id_len = (data[offset] << 8) | data[offset + 1]
        offset += 2 + pkt.client_id_len
        
        # Will Topic/Message (if will_flag set)
        if pkt.conflag_will_flag:
            if offset + 2 <= len(data):
                pkt.will_topic_len = (data[offset] << 8) | data[offset + 1]
                offset += 2 + pkt.will_topic_len
            if offset + 2 <= len(data):
                pkt.will_msg_len = (data[offset] << 8) | data[offset + 1]
                offset += 2 + pkt.will_msg_len
        
        # Username
        if pkt.conflag_uname and offset + 2 <= len(data):
            pkt.username_len = (data[offset] << 8) | data[offset + 1]
            offset += 2 + pkt.username_len
        
        # Password
        if pkt.conflag_passwd and offset + 2 <= len(data):
            pkt.passwd_len = (data[offset] << 8) | data[offset + 1]
        
        return True
    
    @staticmethod
    def parse_connack_packet(data: bytes, pkt: MqttPacketData) -> bool:
        """Parse CONNACK packet - mirrors parse_connack_packet() in mqtt.cc"""
        if len(data) < 4:
            return False
        
        _, offset = MqttParser.parse_remaining_length(data, 1)
        if offset + 2 > len(data):
            return False
        
        pkt.conack_session_present = data[offset] & 0x01
        pkt.conack_return_code = data[offset + 1]
        
        return True
    
    @staticmethod
    def parse_publish_packet(data: bytes, pkt: MqttPacketData) -> bool:
        """Parse PUBLISH packet - mirrors parse_publish_packet() in mqtt.cc"""
        _, offset = MqttParser.parse_remaining_length(data, 1)
        
        if offset + 2 > len(data):
            return False
        pkt.topic_len = (data[offset] << 8) | data[offset + 1]
        offset += 2 + pkt.topic_len
        
        # Packet ID if QoS > 0
        if pkt.qos > 0:
            if offset + 2 > len(data):
                return False
            pkt.msg_id = (data[offset] << 8) | data[offset + 1]
            offset += 2
        
        # Payload is remaining bytes
        if offset < len(data):
            pkt.payload_len = len(data) - offset
        
        return True


# =============================================================================
# Feature Extractor - Mirrors build_feature_vector() in mqtt_ml.cc
# =============================================================================

def build_feature_vector(pkt: MqttPacketData, timing: FlowTimingData, 
                         current_time: float) -> List[float]:
    """
    Build normalized feature vector - MUST MATCH mqtt_ml.cc exactly!
    
    Returns list of 28 normalized features.
    """
    features = []
    
    # ========== Fixed Header Fields ==========
    
    # Feature 0: msg_type (bounded 1-14) → min-max
    features.append(normalize_minmax(float(pkt.msg_type), 1.0, 14.0))
    
    # Feature 1: dup_flag (boolean) → one-hot
    features.append(normalize_flag(pkt.dup_flag))
    
    # Feature 2: qos (bounded 0-2) → min-max
    features.append(normalize_minmax(float(pkt.qos), 0.0, 2.0))
    
    # Feature 3: retain (boolean) → one-hot
    features.append(normalize_flag(pkt.retain))
    
    # Feature 4: remaining_len (unbounded) → log normalization
    features.append(normalize_log(float(pkt.remaining_len), MAX_REMAINING_LEN))
    
    # ========== CONNECT Fields ==========
    
    # Feature 5: protocol_version (bounded 3-5) → min-max
    features.append(normalize_minmax(float(pkt.protocol_version), 3.0, 5.0))
    
    # Features 6-11: Connection flags
    features.append(normalize_flag(pkt.conflag_clean_session))   # 6
    features.append(normalize_flag(pkt.conflag_will_flag))       # 7
    features.append(normalize_minmax(float(pkt.conflag_will_qos), 0.0, 2.0))  # 8
    features.append(normalize_flag(pkt.conflag_will_retain))     # 9
    features.append(normalize_flag(pkt.conflag_passwd))          # 10
    features.append(normalize_flag(pkt.conflag_uname))           # 11
    
    # Feature 12: keep_alive → log normalization
    features.append(normalize_log(float(pkt.keep_alive), MAX_KEEP_ALIVE))
    
    # Features 13-17: String lengths → log normalization
    features.append(normalize_log(float(pkt.client_id_len), MAX_STRING_LEN))    # 13
    features.append(normalize_log(float(pkt.username_len), MAX_STRING_LEN))    # 14
    features.append(normalize_log(float(pkt.passwd_len), MAX_STRING_LEN))      # 15
    features.append(normalize_log(float(pkt.will_topic_len), MAX_STRING_LEN))  # 16
    features.append(normalize_log(float(pkt.will_msg_len), MAX_STRING_LEN))    # 17
    
    # ========== CONNACK Fields ==========
    
    # Feature 18: conack_return_code (bounded 0-5) → min-max
    features.append(normalize_minmax(float(pkt.conack_return_code), 0.0, 5.0))
    
    # Feature 19: conack_session_present (boolean) → one-hot
    features.append(normalize_flag(pkt.conack_session_present))
    
    # ========== PUBLISH Fields ==========
    
    # Feature 20: topic_len → log normalization
    features.append(normalize_log(float(pkt.topic_len), MAX_STRING_LEN))
    
    # Feature 21: payload_len → log normalization
    features.append(normalize_log(float(pkt.payload_len), MAX_PAYLOAD_LEN))
    
    # Feature 22: msg_id → log normalization
    features.append(normalize_log(float(pkt.msg_id), 65535.0))
    
    # ========== Timing Features ==========
    
    # Calculate time_delta_us (microseconds since first packet)
    if timing.pkt_count >= 2:
        time_delta_us = (current_time - timing.first_pkt_time) * 1_000_000
    else:
        time_delta_us = 0.0
    
    # Feature 23: time_delta_us → log normalization
    features.append(normalize_log(time_delta_us, MAX_TIME_DELTA_US))
    
    # Feature 24: time_relative_us (same as delta)
    features.append(normalize_log(time_delta_us, MAX_TIME_DELTA_US))
    
    # ========== Brute Force Detection Features ==========
    
    # Calculate failed_auth_per_second
    if timing.failed_auth_window_count > 0:
        window_elapsed = current_time - timing.failed_auth_window_start
        if window_elapsed > 0:
            failed_auth_rate = timing.failed_auth_window_count / window_elapsed
        else:
            failed_auth_rate = float(timing.failed_auth_window_count)
    else:
        failed_auth_rate = 0.0
    
    # Feature 25: failed_auth_per_second → log normalization
    features.append(normalize_log(failed_auth_rate, MAX_FAILED_AUTH_RATE))
    
    # Feature 26: failed_auth_count → log normalization
    features.append(normalize_log(float(timing.failed_auth_count), 100.0))
    
    # ========== Flow Statistics ==========
    
    # Feature 27: pkt_count → log normalization
    features.append(normalize_log(float(timing.pkt_count), MAX_PKT_COUNT))
    
    assert len(features) == MQTT_ML_NUM_FEATURES, f"Expected {MQTT_ML_NUM_FEATURES} features, got {len(features)}"
    
    return features


# =============================================================================
# Flow Tracking - Mirrors MqttFlowData logic in mqtt.cc
# =============================================================================

class FlowTracker:
    """Track per-flow timing data across packets"""
    
    def __init__(self):
        # Key: (src_ip, dst_ip, src_port, dst_port) -> FlowTimingData
        self.flows: Dict[Tuple, FlowTimingData] = {}
    
    def get_flow_key(self, pkt) -> Optional[Tuple]:
        """Extract 4-tuple flow key from packet (supports IPv4 and IPv6)"""
        if TCP not in pkt:
            return None
        
        # Handle both IPv4 and IPv6
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return None
        
        return (src_ip, dst_ip, pkt[TCP].sport, pkt[TCP].dport)
    
    def update_flow(self, flow_key: Tuple, timestamp: float, 
                    is_auth_failure: bool = False) -> FlowTimingData:
        """Update flow timing and return current timing data"""
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowTimingData(
                first_pkt_time=timestamp,
                prev_pkt_time=timestamp,
                pkt_count=0
            )
        
        timing = self.flows[flow_key]
        timing.pkt_count += 1
        timing.prev_pkt_time = timestamp
        
        # Handle auth failures (for brute force detection)
        if is_auth_failure:
            timing.failed_auth_count += 1
            if timing.failed_auth_window_count == 0:
                timing.failed_auth_window_start = timestamp
                timing.failed_auth_window_count = 1
            else:
                window_elapsed = timestamp - timing.failed_auth_window_start
                if window_elapsed > 1.0:  # 1 second window
                    timing.failed_auth_window_start = timestamp
                    timing.failed_auth_window_count = 1
                else:
                    timing.failed_auth_window_count += 1
        
        return timing


# =============================================================================
# PCAP Processing
# =============================================================================

def extract_mqtt_payload(pkt) -> Optional[bytes]:
    """Extract MQTT payload from TCP packet"""
    if TCP not in pkt or Raw not in pkt:
        return None
    
    # Check if it's MQTT port (1883 or 8883)
    tcp = pkt[TCP]
    if tcp.dport not in (1883, 8883) and tcp.sport not in (1883, 8883):
        return None
    
    return bytes(pkt[Raw].load)


def process_pcap(pcap_path: Path, flow_tracker: FlowTracker, 
                 label: int) -> List[Tuple[List[float], int]]:
    """
    Process a single PCAP file and extract features.
    
    Returns list of (feature_vector, label) tuples.
    """
    results = []
    
    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return results
    
    for pkt in packets:
        # Get MQTT payload
        mqtt_data = extract_mqtt_payload(pkt)
        if mqtt_data is None or len(mqtt_data) < 2:
            continue
        
        # Get flow key
        flow_key = flow_tracker.get_flow_key(pkt)
        if flow_key is None:
            continue
        
        # Parse fixed header
        mqtt_pkt = MqttParser.parse_fixed_header(mqtt_data)
        if mqtt_pkt is None or mqtt_pkt.msg_type < 1 or mqtt_pkt.msg_type > 14:
            continue
        
        # Parse type-specific fields
        if mqtt_pkt.msg_type == MQTT_CONNECT:
            MqttParser.parse_connect_packet(mqtt_data, mqtt_pkt)
        elif mqtt_pkt.msg_type == MQTT_CONNACK:
            MqttParser.parse_connack_packet(mqtt_data, mqtt_pkt)
        elif mqtt_pkt.msg_type == MQTT_PUBLISH:
            MqttParser.parse_publish_packet(mqtt_data, mqtt_pkt)
        
        # Get packet timestamp
        timestamp = float(pkt.time)
        
        # Check for auth failure (CONNACK with non-zero return code)
        is_auth_failure = (mqtt_pkt.msg_type == MQTT_CONNACK and 
                          mqtt_pkt.conack_return_code != 0)
        
        # Update flow timing
        timing = flow_tracker.update_flow(flow_key, timestamp, is_auth_failure)
        
        # Build feature vector
        features = build_feature_vector(mqtt_pkt, timing, timestamp)
        
        results.append((features, label))
    
    return results


def process_dataset(pcap_dirs: Dict[str, int], output_path: Path):
    """
    Process all PCAPs in directories and write features to CSV.
    
    Args:
        pcap_dirs: Dict mapping directory path to label (0=normal, 1=attack)
        output_path: Path to output CSV file
    """
    flow_tracker = FlowTracker()
    all_samples = []
    
    # Feature names for CSV header
    feature_names = [
        "msg_type", "dup_flag", "qos", "retain", "remaining_len",
        "protocol_version", "conflag_clean_session", "conflag_will_flag",
        "conflag_will_qos", "conflag_will_retain", "conflag_passwd", "conflag_uname",
        "keep_alive", "client_id_len", "username_len", "passwd_len",
        "will_topic_len", "will_msg_len", "conack_return_code", "conack_session_present",
        "topic_len", "payload_len", "msg_id", "time_delta_us", "time_relative_us",
        "failed_auth_per_second", "failed_auth_count", "pkt_count"
    ]
    
    for pcap_dir, label in pcap_dirs.items():
        pcap_path = Path(pcap_dir)
        if not pcap_path.exists():
            print(f"Warning: Directory not found: {pcap_dir}")
            continue
        
        label_name = "normal" if label == 0 else "attack"
        pcap_files = list(pcap_path.glob("*.pcap")) + list(pcap_path.glob("*.pcapng"))
        print(f"Processing {len(pcap_files)} PCAP files from {pcap_dir} (label: {label_name})")
        
        for pcap_file in pcap_files:
            samples = process_pcap(pcap_file, flow_tracker, label)
            all_samples.extend(samples)
            print(f"  {pcap_file.name}: {len(samples)} samples")
    
    # Write to CSV
    print(f"\nWriting {len(all_samples)} samples to {output_path}")
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(feature_names + ["label"])
        for features, label in all_samples:
            writer.writerow(features + [label])
    
    print("Done!")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Extract MQTT features from PCAPs for ML training"
    )
    parser.add_argument(
        "--benign_dir",
        type=str,
        help="Directory containing benign (normal) PCAP files"
    )
    parser.add_argument(
        "--attack_dir", 
        type=str,
        help="Directory containing attack PCAP files"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="mqtt_features.csv",
        help="Output CSV file path (default: mqtt_features.csv)"
    )
    
    args = parser.parse_args()
    
    pcap_dirs = {}
    if args.benign_dir:
        pcap_dirs[args.benign_dir] = 0  # Label 0 = benign
    if args.attack_dir:
        pcap_dirs[args.attack_dir] = 1  # Label 1 = attack
    
    if not pcap_dirs:
        print("Error: Please specify at least one PCAP directory (--benign_dir or --attack_dir)")
        return 1
    
    process_dataset(pcap_dirs, Path(args.output))
    return 0


if __name__ == "__main__":
    exit(main())
