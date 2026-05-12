import random
import pandas as pd
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.ml.feature_schema import FEATURE_SCHEMA, validate_features


def _jitter(value, pct=0.15):
    """Değere ±pct oranında rastgele gürültü ekle."""
    delta = abs(value) * pct
    return value + random.uniform(-delta, delta)


def generate_normal_heartbeat():
    """Senaryo 4: Normal IoT heartbeat. Küçük, periyodik paketler.
    
    Bazı normal akışlar sınır değerlerine yaklaşarak modelin
    trivial ayrım yapmasını engeller.
    """
    duration = round(random.uniform(0.1, 5.0), 2)
    pkt_count = random.randint(5, 50)
    byte_count = random.randint(300, 5000)
    mean_iat = round(duration / max(pkt_count - 1, 1), 6)
    var_iat = round(random.uniform(0.0001, 0.01), 6)
    avg_pkt = round(byte_count / max(pkt_count, 1), 2)

    # %10 olasılıkla "gürültülü normal" üret — anomali sınırına yakın ama normal
    noisy = random.random() < 0.10
    return {
        'packet_count': pkt_count if not noisy else random.randint(40, 120),
        'byte_count': byte_count if not noisy else random.randint(4000, 15000),
        'duration': duration,
        'avg_packet_size': avg_pkt if not noisy else random.randint(80, 250),
        'mean_iat': mean_iat,
        'var_iat': var_iat if not noisy else round(random.uniform(0.005, 0.05), 6),
        # TCP: normal handshake — gürültülü olunca biraz yükselir
        'tcp_syn_ratio': round(random.uniform(0.02, 0.20 if not noisy else 0.40), 6),
        'tcp_synack_ratio': round(random.uniform(0.02, 0.20 if not noisy else 0.35), 6),
        # Bağlantı: düşük çeşitlilik — gürültülü olunca biraz artar
        'unique_dst_ip_count': random.randint(1, 5 if not noisy else 12),
        'unique_dst_port_count': random.randint(1, 4 if not noisy else 15),
        'rst_syn_ratio': round(random.uniform(0.0, 0.08 if not noisy else 0.20), 6),
        # DNS: dengeli veya yok
        'dns_query_response_ratio': round(random.uniform(0.0, 1.5), 6),
        'unique_domain_count': random.randint(0, 3 if not noisy else 6),
        # Türetilmiş
        'pkt_size_variance': round(random.uniform(50, 5000 if not noisy else 15000), 4),
        'bytes_per_second': round(byte_count / max(duration, 0.001), 2),
        'small_pkt_ratio': round(random.uniform(0.20, 0.75), 6),
        'large_pkt_ratio': round(random.uniform(0.0, 0.15 if not noisy else 0.30), 6),
        'dst_ip': f'192.168.1.{random.randint(2, 50)}',
        'label': 0
    }

def generate_idle_background_traffic():
    """Senaryo 5: Arka plan gürültüsü / Boşta bekleme trafiği.
    
    Canlı izlemede karşılaşılan 1-3 paketlik çok küçük iletişimleri
    temsil eder. Bu sayede model canlı trafiği anomali sanmaz.
    """
    duration = round(random.uniform(0.001, 1.0), 4)
    pkt_count = random.randint(1, 4)
    byte_count = random.randint(40, 250)
    
    return {
        'packet_count': pkt_count,
        'byte_count': byte_count,
        'duration': duration,
        'avg_packet_size': round(byte_count / max(pkt_count, 1), 2),
        'mean_iat': round(duration / max(pkt_count - 1, 1), 6),
        'var_iat': round(random.uniform(0.0, 0.0001), 6),
        'tcp_syn_ratio': round(random.uniform(0.0, 0.5), 6),
        'tcp_synack_ratio': round(random.uniform(0.0, 0.5), 6),
        'unique_dst_ip_count': 1,
        'unique_dst_port_count': 1,
        'rst_syn_ratio': 0.0,
        'dns_query_response_ratio': 0.0,
        'unique_domain_count': 0,
        'pkt_size_variance': round(random.uniform(0, 10), 4),
        'bytes_per_second': round(byte_count / max(duration, 0.0001), 2),
        'small_pkt_ratio': 1.0,
        'large_pkt_ratio': 0.0,
        'dst_ip': f'192.168.1.{random.randint(2, 50)}',
        'label': 0
    }

def generate_port_scan_scenario():
    """Senaryo 1: Port scan. Kısa sürede çok sayıda porta giden trafik.
    
    Hafif port taramaları dahil — normal trafiğe yakın sınır vakalar.
    """
    # %20 olasılıkla "hafif tarama" — daha az belirgin
    light = random.random() < 0.20
    duration = round(random.uniform(0.1, 2.0 if not light else 4.0), 2)
    pkt_count = random.randint(30 if light else 100, 200 if light else 500)
    byte_count = random.randint(500, 10000)
    return {
        'packet_count': pkt_count,
        'byte_count': byte_count,
        'duration': duration,
        'avg_packet_size': random.randint(40, 80 if not light else 120),
        'mean_iat': round(random.uniform(0.0001, 0.01 if not light else 0.05), 6),
        'var_iat': round(random.uniform(0.0, 0.001 if not light else 0.01), 6),
        # TCP: yüksek SYN — hafif taramada daha düşük
        'tcp_syn_ratio': round(random.uniform(0.35 if light else 0.55, 0.75 if light else 1.0), 6),
        'tcp_synack_ratio': round(random.uniform(0.0, 0.10), 6),
        # Bağlantı: çeşitlilik yüksek — hafif taramada daha az
        'unique_dst_ip_count': random.randint(5 if light else 15, 40 if light else 100),
        'unique_dst_port_count': random.randint(10 if light else 30, 80 if light else 500),
        'rst_syn_ratio': round(random.uniform(0.25 if light else 0.40, 0.70 if light else 0.95), 6),
        # DNS: yok veya çok az
        'dns_query_response_ratio': round(random.uniform(0.0, 0.3), 6),
        'unique_domain_count': random.randint(0, 1),
        # Türetilmiş
        'pkt_size_variance': round(random.uniform(0, 500 if not light else 2000), 4),
        'bytes_per_second': round(byte_count / max(duration, 0.001), 2),
        'small_pkt_ratio': round(random.uniform(0.70 if not light else 0.50, 1.0), 6),
        'large_pkt_ratio': round(random.uniform(0.0, 0.05), 6),
        'dst_ip': f'192.168.1.{random.randint(2, 254)}',
        'label': 1
    }

def generate_ddos_scenario():
    """Senaryo 2: DDoS flood. Aynı hedefe çok yüksek packet_count, düşük IAT.
    
    Yoğunluk spektrumu geniş tutuldu — hafif flood'dan şiddetli flood'a.
    """
    intensity = random.choice(['low', 'medium', 'high'])
    if intensity == 'low':
        pkt_count = random.randint(500, 2000)
        byte_count = random.randint(50000, 200000)
    elif intensity == 'medium':
        pkt_count = random.randint(2000, 8000)
        byte_count = random.randint(200000, 800000)
    else:
        pkt_count = random.randint(8000, 20000)
        byte_count = random.randint(800000, 2000000)

    duration = round(random.uniform(0.5, 3.0), 2)
    return {
        'packet_count': pkt_count,
        'byte_count': byte_count,
        'duration': duration,
        'avg_packet_size': random.randint(50, 200),
        'mean_iat': round(random.uniform(0.00001, 0.002), 6),
        'var_iat': round(random.uniform(0.0, 0.0005), 6),
        # TCP: SYN flood — yoğunluğa göre değişen oran
        'tcp_syn_ratio': round(random.uniform(0.35, 0.95), 6),
        'tcp_synack_ratio': round(random.uniform(0.0, 0.05), 6),
        # Bağlantı: tek veya çok az hedef
        'unique_dst_ip_count': random.randint(1, 3),
        'unique_dst_port_count': random.randint(1, 5),
        'rst_syn_ratio': round(random.uniform(0.0, 0.15), 6),
        # DNS: genelde yok
        'dns_query_response_ratio': round(random.uniform(0.0, 0.2), 6),
        'unique_domain_count': random.randint(0, 1),
        # Türetilmiş
        'pkt_size_variance': round(random.uniform(0, 1000), 4),
        'bytes_per_second': round(byte_count / max(duration, 0.001), 2),
        'small_pkt_ratio': round(random.uniform(0.50, 0.95), 6),
        'large_pkt_ratio': round(random.uniform(0.0, 0.08), 6),
        'dst_ip': '192.168.1.100',
        'label': 1
    }

def generate_exfiltration_scenario():
    """Senaryo 3: Data exfiltration. Uzun süreli, yüksek byte_count, orta packet_count.
    
    Yavaş sızma (slow exfil) dahil — normal trafiğe yakın sınır vakalar.
    """
    slow = random.random() < 0.25
    duration = round(random.uniform(5.0 if slow else 10.0, 30.0 if slow else 60.0), 2)
    pkt_count = random.randint(50, 200 if slow else 500)
    byte_count = random.randint(500000 if slow else 5000000, 5000000 if slow else 20000000)
    return {
        'packet_count': pkt_count,
        'byte_count': byte_count,
        'duration': duration,
        'avg_packet_size': random.randint(500 if slow else 1000, 1200 if slow else 1500),
        'mean_iat': round(random.uniform(0.05, 0.8 if slow else 0.5), 6),
        'var_iat': round(random.uniform(0.05, 1.0), 6),
        # TCP: düşük SYN (bağlantı kurulu)
        'tcp_syn_ratio': round(random.uniform(0.01, 0.10), 6),
        'tcp_synack_ratio': round(random.uniform(0.01, 0.10), 6),
        # Bağlantı: az hedef
        'unique_dst_ip_count': random.randint(1, 4),
        'unique_dst_port_count': random.randint(1, 3),
        'rst_syn_ratio': round(random.uniform(0.0, 0.08), 6),
        # DNS: C2 için olası DNS aktivitesi
        'dns_query_response_ratio': round(random.uniform(0.3, 2.5), 6),
        'unique_domain_count': random.randint(1, 8 if not slow else 4),
        # Türetilmiş
        'pkt_size_variance': round(random.uniform(10000 if slow else 50000, 100000 if slow else 250000), 4),
        'bytes_per_second': round(byte_count / max(duration, 0.001), 2),
        'small_pkt_ratio': round(random.uniform(0.02, 0.25), 6),
        'large_pkt_ratio': round(random.uniform(0.40 if slow else 0.55, 0.80 if slow else 0.95), 6),
        'dst_ip': f'10.0.0.{random.randint(1, 10)}',
        'label': 1
    }

def generate_iot_traffic(num_samples=5000, anomaly_ratio=0.05):
    """Generates a realistic synthetic IoT traffic dataset using modular scenarios."""
    data = []
    num_anomalies = int(num_samples * anomaly_ratio)
    num_normal = num_samples - num_anomalies
    # Dengeli bir veri seti üretimi: %60 normal, %40 senaryolar
    scenarios = [
        generate_normal_heartbeat,
        generate_normal_heartbeat,
        generate_idle_background_traffic,  # Arka plan gürültüsü normal trafiğe eklendi
        generate_idle_background_traffic,
        generate_port_scan_scenario,
        generate_ddos_scenario,
        generate_exfiltration_scenario,
    ]
    
    for _ in range(num_normal):
        # Normal taraf için senaryoları seç
        scenario = random.choice(scenarios[:4])
        data.append(scenario())
        
    for _ in range(num_anomalies):
        # Anomali taraf için senaryoları seç
        scenario = random.choice(scenarios[4:])
        data.append(scenario())
            
    random.shuffle(data)
    return data


if __name__ == "__main__":
    print("[*] Generating synthetic IoT traffic dataset...")
    traffic_data = generate_iot_traffic(num_samples=10000, anomaly_ratio=0.05)
    
    # Save to CSV just for inspection/record
    df = pd.DataFrame(traffic_data)
    df.to_csv('iot_traffic_dataset.csv', index=False)
    print("[+] Dataset generated and saved to 'iot_traffic_dataset.csv'")
    
    print("[*] Training Isolation Forest Anomaly Model on generated dataset...")
    validate_features(traffic_data, source="generate_dataset")
    print("[+] FEATURE_SCHEMA doğrulaması başarılı.")
    model = AnomalyModel()
    model.train(traffic_data)
    
    # Validation output
    m = model.metrics
    if m["validation_status"] == "validated":
        print(f"[+] Final: F1={m['f1_score']}, Precision={m['precision']}, Recall={m['recall']}, AP={m['average_precision']}")
    else:
        print(f"[+] Final: validation {m['validation_status']}")
