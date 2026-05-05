import random
import pandas as pd
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.ml.feature_schema import FEATURE_SCHEMA, validate_features

def generate_normal_heartbeat():
    """Senaryo 4: Normal IoT heartbeat. Küçük, periyodik paketler."""
    duration = round(random.uniform(0.1, 5.0), 2)
    pkt_count = random.randint(5, 50)
    mean_iat = round(duration / max(pkt_count - 1, 1), 6)
    var_iat = round(random.uniform(0.0001, 0.01), 6)
    return {
        'packet_count': pkt_count,
        'byte_count': random.randint(300, 5000),
        'duration': duration,
        'avg_packet_size': random.randint(40, 150),
        'mean_iat': mean_iat,
        'var_iat': var_iat,
        'dst_ip': f'192.168.1.{random.randint(2, 50)}',
        'label': 0
    }

def generate_port_scan_scenario():
    """Senaryo 1: Port scan. Kısa sürede çok sayıda porta giden trafik."""
    return {
        'packet_count': random.randint(100, 500), # Her IP/Port çifti için
        'byte_count': random.randint(1000, 10000),
        'duration': round(random.uniform(0.1, 1.0), 2), # Çok kısa
        'avg_packet_size': random.randint(40, 64), # Syn paketleri küçük olur
        'mean_iat': round(random.uniform(0.0001, 0.005), 6),
        'var_iat': round(random.uniform(0.0, 0.0001), 6),
        'dst_ip': f'192.168.1.{random.randint(2, 254)}',
        'label': 1
    }

def generate_ddos_scenario():
    """Senaryo 2: DDoS flood. Aynı hedefe çok yüksek packet_count, düşük IAT."""
    return {
        'packet_count': random.randint(5000, 20000),
        'byte_count': random.randint(500000, 2000000),
        'duration': round(random.uniform(0.5, 2.0), 2),
        'avg_packet_size': random.randint(50, 200),
        'mean_iat': round(random.uniform(0.00001, 0.0005), 6),
        'var_iat': round(random.uniform(0.0, 0.00001), 6),
        'dst_ip': f'192.168.1.100', # Tek hedef
        'label': 1
    }

def generate_exfiltration_scenario():
    """Senaryo 3: Data exfiltration. Uzun süreli, yüksek byte_count, orta packet_count."""
    return {
        'packet_count': random.randint(100, 500),
        'byte_count': random.randint(5000000, 20000000),
        'duration': round(random.uniform(10.0, 60.0), 2),
        'avg_packet_size': random.randint(1000, 1500), # Büyük paketler
        'mean_iat': round(random.uniform(0.05, 0.5), 6),
        'var_iat': round(random.uniform(0.1, 1.0), 6), # Bursty trafik
        'dst_ip': f'10.0.0.{random.randint(1, 10)}',
        'label': 1
    }

def generate_iot_traffic(num_samples=5000, anomaly_ratio=0.05):
    """Generates a realistic synthetic IoT traffic dataset using modular scenarios."""
    data = []
    num_anomalies = int(num_samples * anomaly_ratio)
    num_normal = num_samples - num_anomalies
    
    for _ in range(num_normal):
        data.append(generate_normal_heartbeat())
        
    for _ in range(num_anomalies):
        scenario = random.choice([
            generate_port_scan_scenario, 
            generate_ddos_scenario, 
            generate_exfiltration_scenario
        ])
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
