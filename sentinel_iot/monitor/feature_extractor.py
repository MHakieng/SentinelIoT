import scapy.all as scapy
from collections import defaultdict
import sys
import json
import statistics


def _safe_int(value, default=0):
    """Convert packet fields to ints without letting mocks split flows."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return default


def _safe_div(numerator, denominator, default=0.0):
    """Sıfıra bölme korumalı bölme işlemi."""
    if denominator == 0:
        return default
    return numerator / denominator


def extract_features(pcap_file=None, packets=None):
    """Extract 5-tuple flow-based features from packets for behavioral analysis.
    
    Live CICIoT2023 RF feature schema:
      packet_count, byte_count, avg_packet_size, mean_iat, var_iat, packet_rate
    Legacy IsolationForest fields are kept for baseline compatibility.
      TCP (2):    tcp_syn_ratio, tcp_synack_ratio
      Bağlantı (3): unique_dst_ip_count, unique_dst_port_count, rst_syn_ratio
      DNS (2):    dns_query_response_ratio, unique_domain_count
      Türetilmiş (4): pkt_size_variance, bytes_per_second, small_pkt_ratio, large_pkt_ratio
    """
    flows = defaultdict(lambda: {
        'count': 0,
        'bytes': 0,
        'start_time': None,
        'end_time': None,
        'last_time': None,
        'iats': [],
        'protocols': set(),
        # ── Yeni izleme alanları ──
        'pkt_sizes': [],          # Her paketin boyutu (varyans hesabı için)
        'tcp_total': 0,           # Toplam TCP paketi
        'tcp_syn_count': 0,       # SYN (ACK olmadan) sayısı
        'tcp_synack_count': 0,    # SYN+ACK sayısı
        'tcp_rst_count': 0,       # RST sayısı
        'dns_query_count': 0,     # DNS sorgu sayısı
        'dns_response_count': 0,  # DNS cevap sayısı
        'dns_domains': set(),     # Eşsiz domain adları
        'small_pkt_count': 0,     # < 128 byte paket sayısı
        'large_pkt_count': 0,     # > 1024 byte paket sayısı
    })

    if pcap_file:
        try:
            packets = scapy.rdpcap(pcap_file)
        except Exception as e:
            print(f"[-] Error reading PCAP: {e}")
            return []

    if not packets:
        return []

    # ── Kaynak IP bazlı cross-flow istatistikleri ──
    src_ip_stats = defaultdict(lambda: {'dst_ips': set(), 'dst_ports': set()})

    for pkt in packets:
        if not pkt.haslayer(scapy.IP):
            continue

        src_ip = pkt[scapy.IP].src
        dst_ip = pkt[scapy.IP].dst
        proto = _safe_int(pkt[scapy.IP].proto)

        src_port = 0
        dst_port = 0
        is_tcp = pkt.haslayer(scapy.TCP)
        is_udp = pkt.haslayer(scapy.UDP)

        if is_tcp:
            src_port = _safe_int(getattr(pkt[scapy.TCP], "sport", 0))
            dst_port = _safe_int(getattr(pkt[scapy.TCP], "dport", 0))
        elif is_udp:
            src_port = _safe_int(getattr(pkt[scapy.UDP], "sport", 0))
            dst_port = _safe_int(getattr(pkt[scapy.UDP], "dport", 0))

        pkt_len = len(pkt)
        timestamp = pkt.time

        # 5-tuple flow key
        key = (src_ip, dst_ip, src_port, dst_port, proto)

        flow = flows[key]
        flow['count'] += 1
        flow['bytes'] += pkt_len
        flow['protocols'].add(int(proto))
        flow['pkt_sizes'].append(pkt_len)

        # Küçük / büyük paket sınıflandırması
        if pkt_len < 128:
            flow['small_pkt_count'] += 1
        if pkt_len > 1024:
            flow['large_pkt_count'] += 1

        # Zaman damgası takibi
        if flow['start_time'] is None or timestamp < flow['start_time']:
            flow['start_time'] = float(timestamp)
        if flow['end_time'] is None or timestamp > flow['end_time']:
            flow['end_time'] = float(timestamp)

        if flow['last_time'] is not None:
            iat = float(timestamp) - flow['last_time']
            if iat >= 0:
                flow['iats'].append(iat)
        flow['last_time'] = float(timestamp)

        # ── TCP bayrak analizi ──
        if is_tcp:
            flow['tcp_total'] += 1
            try:
                flags = pkt[scapy.TCP].flags
                flag_int = int(flags) if not isinstance(flags, int) else flags
                is_syn = bool(flag_int & 0x02)
                is_ack = bool(flag_int & 0x10)
                is_rst = bool(flag_int & 0x04)

                if is_syn and not is_ack:
                    flow['tcp_syn_count'] += 1
                if is_syn and is_ack:
                    flow['tcp_synack_count'] += 1
                if is_rst:
                    flow['tcp_rst_count'] += 1
            except Exception:
                pass

        # ── DNS analizi ──
        if pkt.haslayer(scapy.DNS):
            try:
                dns_layer = pkt[scapy.DNS]
                qr = _safe_int(getattr(dns_layer, 'qr', 0), 0)
                if qr == 0:  # Sorgu
                    flow['dns_query_count'] += 1
                    qd = getattr(dns_layer, 'qd', None)
                    if qd is not None:
                        qname = getattr(qd, 'qname', b'')
                        if isinstance(qname, bytes):
                            qname = qname.decode('utf-8', errors='ignore')
                        domain = str(qname).rstrip('.')
                        if domain:
                            flow['dns_domains'].add(domain)
                else:  # Cevap
                    flow['dns_response_count'] += 1
            except Exception:
                pass

        # Cross-flow istatistikleri
        src_ip_stats[src_ip]['dst_ips'].add(dst_ip)
        if dst_port > 0:
            src_ip_stats[src_ip]['dst_ports'].add(dst_port)

    # ── Feature vektörlerini oluştur ──
    features = []
    for (src_ip, dst_ip, src_port, dst_port, proto), data in flows.items():
        count = data['count']
        duration = data['end_time'] - data['start_time'] if data['start_time'] else 0
        iats = data['iats']

        # Temel istatistikler
        mean_iat = round(float(statistics.mean(iats)), 6) if len(iats) > 0 else 0.0
        var_iat = round(float(statistics.variance(iats)), 6) if len(iats) > 1 else 0.0
        avg_pkt_size = round(_safe_div(data['bytes'], count), 2)

        # TCP protokol oranları
        tcp_syn_ratio = round(_safe_div(data['tcp_syn_count'], data['tcp_total']), 6)
        tcp_synack_ratio = round(_safe_div(data['tcp_synack_count'], data['tcp_total']), 6)

        # Bağlantı istatistikleri
        rst_syn_ratio = round(_safe_div(data['tcp_rst_count'], max(data['tcp_syn_count'], 1)), 6)
        unique_dst_ip = len(src_ip_stats[src_ip]['dst_ips'])
        unique_dst_port = len(src_ip_stats[src_ip]['dst_ports'])

        # DNS istatistikleri
        dns_total_responses = max(data['dns_response_count'], 1)
        dns_qr_ratio = round(_safe_div(data['dns_query_count'], dns_total_responses), 6) \
            if (data['dns_query_count'] + data['dns_response_count']) > 0 else 0.0
        unique_domains = len(data['dns_domains'])

        # Paket boyutu varyansı
        pkt_sizes = data['pkt_sizes']
        pkt_size_var = round(float(statistics.variance(pkt_sizes)), 4) if len(pkt_sizes) > 1 else 0.0

        # Türetilmiş öznitelikler
        bps = round(_safe_div(data['bytes'], max(duration, 0.0001)), 2)
        packet_rate = round(_safe_div(count, duration), 6) if duration > 0 else 0.0
        small_ratio = round(_safe_div(data['small_pkt_count'], count), 6)
        large_ratio = round(_safe_div(data['large_pkt_count'], count), 6)

        # Unique ID for UI matching
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port} [{proto}]"

        features.append({
            'flow_id': flow_id,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto,
            # ── 6 temel ──
            'packet_count': count,
            'byte_count': data['bytes'],
            'duration': round(float(duration), 4),
            'avg_packet_size': avg_pkt_size,
            'mean_iat': mean_iat,
            'var_iat': var_iat,
            'packet_rate': packet_rate,
            # ── TCP protokol oranları (2) ──
            'tcp_syn_ratio': tcp_syn_ratio,
            'tcp_synack_ratio': tcp_synack_ratio,
            # ── Bağlantı istatistikleri (3) ──
            'unique_dst_ip_count': unique_dst_ip,
            'unique_dst_port_count': unique_dst_port,
            'rst_syn_ratio': rst_syn_ratio,
            # ── DNS istatistikleri (2) ──
            'dns_query_response_ratio': dns_qr_ratio,
            'unique_domain_count': unique_domains,
            # ── Türetilmiş / zaman serisi (4) ──
            'pkt_size_variance': pkt_size_var,
            'bytes_per_second': bps,
            'small_pkt_ratio': small_ratio,
            'large_pkt_ratio': large_ratio,
            # ── Uyumluluk alanları ──
            'target': dst_ip,
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
