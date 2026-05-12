import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score, average_precision_score
import joblib
import os
import threading
from pathlib import Path
from sentinel_iot.ml.feature_schema import FEATURE_SCHEMA, validate_features
from sentinel_iot.ml.ciciot2023_inference import predict_flow_anomaly

class AnomalyModel:
    """Anomaly detection model for IoT traffic using Isolation Forest with performance metrics."""
    
    def __init__(self, model_path=None):
        self.model_path = str(model_path or Path(__file__).resolve().parents[1] / "anomaly_model.joblib")
        self.features = FEATURE_SCHEMA
        self.model = None
        self.scaler = StandardScaler()
        self.threshold = 0.6  # Anomali eşiği artırıldı (Canlı trafiğe tolerans)
        self.retrain_threshold = 100  # Yeniden eğitim için gereken yeni veri sayısı
        self.retrain_buffer = []  # Yeni gelen veriler için buffer
        self.prefer_ciciot_rf = True
        self.metrics_lock = threading.Lock()
        self.metrics = {
            "f1_score": 0,
            "precision": 0,
            "recall": 0,
            "average_precision": None,
            "validation_status": "unavailable"
        }
        self.load_model()

    def load_model(self):
        """Load the model and scaler from disk if they exist.
        
        Feature uyumluluk kontrolü: Kayıtlı scaler'ın beklediği feature sayısı
        mevcut FEATURE_SCHEMA ile uyuşmuyorsa eski model atılır.
        """
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                if isinstance(data, dict):
                    loaded_model = data.get("model")
                    loaded_scaler = data.get("scaler", StandardScaler())

                    # Feature sayısı uyumluluk kontrolü
                    expected_n = len(self.features)
                    scaler_n = getattr(loaded_scaler, 'n_features_in_', None)
                    if scaler_n is not None and scaler_n != expected_n:
                        print(
                            f"[!] Kaydedilmiş model {scaler_n} feature bekliyor, "
                            f"ancak mevcut FEATURE_SCHEMA {expected_n} feature içeriyor. "
                            f"Eski model atıldı — yeniden eğitim gerekiyor."
                        )
                        self.model = None
                        self.scaler = StandardScaler()
                        return None

                    self.model = loaded_model
                    self.scaler = loaded_scaler
                    with self.metrics_lock:
                        self.metrics = data.get("metrics", self.metrics)
                else:
                    self.model = data  # Fallback for old style
                return self.model
            except Exception as e:
                print(f"[-] Error loading model: {e}")
        return None

    def _select_model_features(self, flow_features):
        """Strip UI/runtime metadata and keep only model feature columns."""
        model_features = {feature: flow_features.get(feature) for feature in self.features}
        validate_features([model_features], source="anomaly_model.model_features")
        return model_features

    def train(self, flow_data, freeze_scaler=False):
        """Deterministic eğitim hattı."""
        if not flow_data:
            return
        self.prefer_ciciot_rf = False
        
        # 1. FEATURE_SCHEMA ile doğrula
        validate_features(flow_data, source="anomaly_model.train")
        
        # 2. Veriyi yükle
        df = pd.DataFrame(flow_data)
        X = df[self.features].copy()
        
        # 3. Tip dönüşümlerini yap (tüm feature'lar float64 olmalı)
        X = X.astype(np.float64)
        
        # 4. Eksik değerleri işle (NaN, inf → 0.0)
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(0.0)
        
        # 5. Temizle (duplicate satırları kaldır)
        before = len(X)
        X = X.drop_duplicates()
        after = len(X)
        if before != after:
            print(f"[*] {before - after} duplicate satır temizlendi.")
        
        if len(X) < 2:
            print("[-] Eğitim için yeterli veri yok (min 2 satır).")
            return
        
        print(f"[*] Normalizing and training model on {len(X)} samples...")
        
        # 6. Normalizasyon (StandardScaler)
        # Eger scaler dondurulduysa (freeze_scaler) ve onceden fit edildiyse, sadece transform yap
        is_fitted = hasattr(self.scaler, 'mean_') and self.scaler.mean_ is not None
        if freeze_scaler and is_fitted:
            X_scaled = self.scaler.transform(X)
            print("[*] Scaler frozen, applying existing scaling parameters.")
        else:
            self.scaler = StandardScaler() # Re-initialize scaler for fresh fit
            X_scaled = self.scaler.fit_transform(X)
            print("[*] Scaler re-initialized and fitted on new data.")
        
        np.random.seed(42)
        self.model = IsolationForest(contamination="auto", random_state=42)
        self.model.fit(X_scaled)
        
        # 8. Eğitim metriklerini hesapla
        if 'label' in df.columns:
            # label sütunu da temizlenmiş X ile aynı index'e sahip olmalı
            labels = df.loc[X.index, 'label'].reset_index(drop=True)
            self._evaluate_with_labels(X_scaled, labels)
        else:
            with self.metrics_lock:
                self.metrics = {
                    "f1_score": None,
                    "precision": None,
                    "recall": None,
                    "average_precision": None,
                    "validation_status": "unavailable"
                }
            print("[!] Etiketli veri yok — validation unavailable.")
        
        # 9. Modeli ve Scaler'ı kaydet
        try:
            with self.metrics_lock:
                metrics_to_save = self.metrics.copy()
            joblib.dump({
                "model": self.model, 
                "scaler": self.scaler,
                "metrics": metrics_to_save
            }, self.model_path)
            with self.metrics_lock:
                if self.metrics["validation_status"] == "validated":
                    print(f"[+] Model trained. F1={self.metrics['f1_score']}, "
                          f"Precision={self.metrics['precision']}, "
                          f"Recall={self.metrics['recall']}, "
                          f"AP={self.metrics['average_precision']}")
                else:
                    print(f"[+] Model trained. Validation: {self.metrics['validation_status']}")
        except Exception as e:
            print(f"[-] Error saving model: {e}")

    def _evaluate_with_labels(self, X, labels):
        """Etiketli veri ile gerçek precision, recall, F1 ve average precision hesapla."""
        # label: 0=normal, 1=anomaly → Isolation Forest: 1=normal, -1=anomaly
        y_true = np.where(labels == 1, -1, 1)
        y_pred = self.model.predict(X)
        
        # Decision scores (daha negatif = daha anomali)
        scores = self.model.decision_function(X)
        # Anomaly score: negatife çeviriyoruz ki yüksek = anomali olsun
        anomaly_scores = -scores
        
        # Calculate outside the lock to avoid hanging /metrics API
        # AP requires a binary representation where Anomaly is the positive class (1).
        y_true_binary = np.where(labels == 1, 1, 0)
        
        p = round(float(precision_score(y_true, y_pred, pos_label=-1, zero_division=0)), 3)
        r = round(float(recall_score(y_true, y_pred, pos_label=-1, zero_division=0)), 3)
        f1 = round(float(f1_score(y_true, y_pred, pos_label=-1, zero_division=0)), 3)
        ap = round(float(average_precision_score(y_true_binary, anomaly_scores)), 3)

        with self.metrics_lock:
            self.metrics["precision"] = p
            self.metrics["recall"] = r
            self.metrics["f1_score"] = f1
            self.metrics["average_precision"] = ap
            self.metrics["validation_status"] = "validated"

    def batch_retraining(self, new_flow_data, n_samples_window=5000):
        """Controlled batch retraining as per EMİR.
        
        Accumulates data in a buffer. When threshold is met, trains on the 
        last n_samples_window and resets the buffer.
        """
        if not new_flow_data:
            return

        # Filter: Do not include obvious/critical anomalies in the retraining buffer.
        # This prevents an active flood/botnet attack from poisoning the model.
        safe_data = []
        for flow in new_flow_data:
            res = self.detect_anomaly(flow)
            # Modelin canlı trafiğe adapte olabilmesi için başlangıçta esnek bir eşik (0.65) kullanıyoruz.
            # Aksi halde tüm canlı trafik anomali sanılıp reddedilir ve model asla öğrenemez.
            if res["score"] < 0.65:
                safe_data.append(flow)

        self.retrain_buffer.extend(safe_data)
        
        # EĞER buffer boyutu >= retrain_threshold ise
        if len(self.retrain_buffer) >= self.retrain_threshold:
            print(f"[*] Retrain threshold met ({len(self.retrain_buffer)} >= {self.retrain_threshold}). Starting batch retraining...")
            
            # 1. Mevcut (baseline) veri setini yükle
            baseline_data = []
            if os.path.exists('iot_traffic_dataset.csv'):
                try:
                    baseline_data = pd.read_csv('iot_traffic_dataset.csv').to_dict('records')
                except Exception as e:
                    print(f"[-] Error loading baseline: {e}")
                    baseline_data = []
            
            # 2. Model zehirlenmesini önlemek için baseline oranını koru (örn: %80 baseline, %20 yeni veri)
            import random
            max_new_samples = int(n_samples_window * 0.20)
            recent_new_data = self.retrain_buffer[-max_new_samples:]
            
            required_baseline = n_samples_window - len(recent_new_data)
            if len(baseline_data) > required_baseline:
                # Rastgele örneklem alarak baseline veri setinin genel karakteristiğini koru
                sampled_baseline = random.sample(baseline_data, required_baseline)
            else:
                sampled_baseline = baseline_data
            
            # 3. Yeni eğitim penceresini oluştur (Baseline ağırlıklı)
            training_window = sampled_baseline + recent_new_data
            
            # 4. Modeli yeniden eğit (Batch Retraining)
            self.train(training_window, freeze_scaler=True)
            
            # 5. Buffer sıfırla
            self.retrain_buffer = []
            print("[+] Batch retraining complete. Baseline integrity preserved. Buffer reset.")

    @staticmethod
    def normalize_anomaly_score(raw_score):
        """Raw Isolation Forest score'u [0.0, 1.0] standardına zorla.
        
        Isolation Forest decision_function:
          - Negatif değerler = anomali
          - Pozitif değerler = normal
          - 0 civarı = sınır
        
        Dönüşüm: (0.5 - raw_score) ile ölçekle, sonra [0.0, 1.0] aralığına sıkıştır.
        """
        normalized = (0.5 - raw_score)
        return round(float(max(0.0, min(1.0, normalized))), 3)

    def detect_anomaly(self, flow_features):
        """Standardized inference with confidence score.
        
        Returns:
            dict: {"label": "anomaly"|"normal", "score": float, "confidence": float}
        """
        rf_result = None
        if self.prefer_ciciot_rf:
            try:
                rf_result = predict_flow_anomaly(flow_features)
                if rf_result.get("model_available"):
                    attack_probability = float(rf_result.get("attack_probability") or 0.0)
                    return {
                        "label": "anomaly" if rf_result.get("is_anomaly") else "normal",
                        "score": attack_probability,
                        "raw_score": attack_probability,
                        "confidence": attack_probability,
                        "model": rf_result,
                    }
            except Exception as e:
                print(f"[-] CICIoT2023 RF inference unavailable for this flow: {e}")

            if rf_result and rf_result.get("model_available") is False:
                missing_legacy_features = [feature for feature in self.features if feature not in flow_features]
                if missing_legacy_features:
                    return {
                        "label": "normal",
                        "score": 0.0,
                        "raw_score": 0.0,
                        "confidence": 0.0,
                        "model": rf_result,
                    }

        # 1. Feature sözleşmesini doğrula
        model_features = self._select_model_features(flow_features)
        
        if self.model is None:
            return {"label": "normal", "score": 0.0, "raw_score": 0.0, "confidence": 0.0}
            
        # 2. DataFrame'e çevir ve temizle
        df = pd.DataFrame([model_features])
        X = df[self.features].copy().fillna(0.0)
        
        # 3. Normalize et (Train ile aynı scaler)
        try:
            X_scaled = self.scaler.transform(X)
        except Exception as e:
            print(f"[-] Inference scaling error: {e}")
            return {"label": "normal", "score": 0.0, "raw_score": 0.0, "confidence": 0.0}
            
        # 4. Model ile skor hesapla
        raw_score = self.model.decision_function(X_scaled)[0]
        
        # 5. Skoru normalize et
        anomaly_score = self.normalize_anomaly_score(raw_score)
        
        # 6. Confidence: Decision function'un mutlak değeri arttıkça güven artar
        # Raw scores typically range from -0.5 to 0.5. 0 is the boundary.
        # Simple normalization: min(1.0, abs(raw_score) * 2)
        confidence = round(float(min(1.0, abs(raw_score) * 2.5)), 3)
        
        # 7. Eşik ile karşılaştır ve etiket üret
        label = "anomaly" if anomaly_score >= self.threshold else "normal"
        
        return {"label": label, "score": anomaly_score, "raw_score": float(raw_score), "confidence": confidence}

    def detect(self, flow_data):
        """Analyze a list of flow features for anomalies."""
        if self.model is None:
            return []

        results = []
        for flow in flow_data:
            analysis = self.detect_anomaly(flow)
            
            if analysis["label"] == "anomaly":
                results.append({
                    'flow_id': flow.get('flow_id'),
                    'target': flow.get('dst_ip', 'unknown'),
                    'type': 'statistical_anomaly',
                    'score': analysis["score"],
                    'confidence': analysis["confidence"],
                    'model': analysis.get("model"),
                    'reasons': [f"Statistical anomaly (Score: {analysis['score']}, Conf: {analysis['confidence']})"],
                    'metrics': self.metrics
                })
                
        return results

if __name__ == "__main__":
    # Test data with all 17 features (normal IoT vs Botnet flood)
    _base_normal = {
        'tcp_syn_ratio': 0.05, 'tcp_synack_ratio': 0.05,
        'unique_dst_ip_count': 1, 'unique_dst_port_count': 1, 'rst_syn_ratio': 0.0,
        'dns_query_response_ratio': 0.0, 'unique_domain_count': 0,
        'pkt_size_variance': 200.0, 'bytes_per_second': 1000.0,
        'small_pkt_ratio': 0.5, 'large_pkt_ratio': 0.0,
    }
    _base_anomaly = {
        'tcp_syn_ratio': 0.9, 'tcp_synack_ratio': 0.0,
        'unique_dst_ip_count': 1, 'unique_dst_port_count': 1, 'rst_syn_ratio': 0.0,
        'dns_query_response_ratio': 0.0, 'unique_domain_count': 0,
        'pkt_size_variance': 10.0, 'bytes_per_second': 10000000.0,
        'small_pkt_ratio': 0.8, 'large_pkt_ratio': 0.0,
    }
    test_data = [
        {'packet_count': 10, 'byte_count': 1000, 'duration': 1.0, 'avg_packet_size': 100, 'mean_iat': 0.1, 'var_iat': 0.002, 'dst_ip': '1.1.1.1', **_base_normal},
        {'packet_count': 12, 'byte_count': 1100, 'duration': 1.1, 'avg_packet_size': 91, 'mean_iat': 0.11, 'var_iat': 0.003, 'dst_ip': '1.1.1.1', **_base_normal},
        {'packet_count': 8, 'byte_count': 900, 'duration': 0.9, 'avg_packet_size': 112, 'mean_iat': 0.09, 'var_iat': 0.001, 'dst_ip': '1.1.1.1', **_base_normal},
        # Flood / Botnet anomaly (extremely low variance, high count)
        {'packet_count': 5000, 'byte_count': 1000000, 'duration': 0.1, 'avg_packet_size': 200, 'mean_iat': 0.00002, 'var_iat': 0.0, 'dst_ip': '9.9.9.9', **_base_anomaly}
    ]
    model = AnomalyModel()
    model.train(test_data)
    print(f"Metrics: {model.metrics}")
