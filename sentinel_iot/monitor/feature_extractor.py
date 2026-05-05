import scapy.all as scapy
from collections import defaultdict
import sys
import json


def _safe_int(value, default=0):
    """Convert packet fields to ints without letting mocks split flows."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return default

def extract_features(pcap_file=None, packets=None):
    """Extract 5-tuple flow-based features from packets for behavioral analysis."""
    flows = defaultdict(lambda: {
        'count': 0,
        'bytes': 0,
        'start_time': None,
        'end_time': None,
        'last_time': None,
        'iats': [],
        'protocols': set()
    })
    
    if pcap_file:
        try:
            packets = scapy.rdpcap(pcap_file)
        except Exception as e:
            print(f"[-] Error reading PCAP: {e}")
            return []
            
    if not packets:
        return []
        
    for pkt in packets:
        if pkt.haslayer(scapy.IP):
            src_ip = pkt[scapy.IP].src
            dst_ip = pkt[scapy.IP].dst
            proto = _safe_int(pkt[scapy.IP].proto)
            
            src_port = 0
            dst_port = 0
            if pkt.haslayer(scapy.TCP):
                src_port = _safe_int(getattr(pkt[scapy.TCP], "sport", 0))
                dst_port = _safe_int(getattr(pkt[scapy.TCP], "dport", 0))
            elif pkt.haslayer(scapy.UDP):
                src_port = _safe_int(getattr(pkt[scapy.UDP], "sport", 0))
                dst_port = _safe_int(getattr(pkt[scapy.UDP], "dport", 0))
                
            pkt_len = len(pkt)
            timestamp = pkt.time
            
            # 5-tuple flow key: (src_ip, dst_ip, src_port, dst_port, proto)
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            
            flow = flows[key]
            flow['count'] += 1
            flow['bytes'] += pkt_len
            flow['protocols'].add(int(proto))
            
            if flow['start_time'] is None or timestamp < flow['start_time']:
                flow['start_time'] = float(timestamp)
            if flow['end_time'] is None or timestamp > flow['end_time']:
                flow['end_time'] = float(timestamp)
                
            if flow['last_time'] is not None:
                iat = float(timestamp) - flow['last_time']
                if iat >= 0:
                    flow['iats'].append(iat)
            flow['last_time'] = float(timestamp)
                
    features = []
    import statistics
    for (src_ip, dst_ip, src_port, dst_port, proto), data in flows.items():
        duration = data['end_time'] - data['start_time'] if data['start_time'] else 0
        iats = data['iats']
        mean_iat = round(float(statistics.mean(iats)), 6) if len(iats) > 0 else 0.0
        var_iat = round(float(statistics.variance(iats)), 6) if len(iats) > 1 else 0.0
        
        # Unique ID for UI matching (can use a hash or composite string)
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port} [{proto}]"
        
        features.append({
            'flow_id': flow_id,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto,
            'packet_count': data['count'],
            'byte_count': data['bytes'],
            'duration': round(float(duration), 4),
            'avg_packet_size': round(data['bytes'] / data['count'] if data['count'] > 0 else 0, 2),
            'mean_iat': mean_iat,
            'var_iat': var_iat,
            'target': dst_ip, # for compatibility with existing detection logic
            'type': 'flow_metrics'
        })
        
    return features

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python feature_extractor.py <pcap_file>")
        sys.exit(1)
        
    pcap_path = sys.argv[1]
    flow_features = extract_features(pcap_file=pcap_path)
    
    print(f"\n[+] Extracted {len(flow_features)} flows from {pcap_path}:")
    print(json.dumps(flow_features, indent=2))
