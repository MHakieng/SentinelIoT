import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score, average_precision_score
import joblib
import os
import threading
from sentinel_iot.ml.feature_schema import FEATURE_SCHEMA, validate_features

class AnomalyModel:
    """Anomaly detection model for IoT traffic using Isolation Forest with performance metrics."""
    
    def __init__(self, model_path="anomaly_model.joblib"):
        self.model_path = model_path
        self.features = FEATURE_SCHEMA
        self.model = None
        self.scaler = StandardScaler()
        self.threshold = 0.5  # Anomali eşiği (0.0 - 1.0 aralığında)
        self.retrain_threshold = 100  # Yeniden eğitim için gereken yeni veri sayısı
        self.retrain_buffer = []  # Yeni gelen veriler için buffer
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
        """Load the model and scaler from disk if they exist."""
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                if isinstance(data, dict):
                    self.model = data.get("model")
                    self.scaler = data.get("scaler", StandardScaler())
                    with self.metrics_lock:
                        self.metrics = data.get("metrics", self.metrics)
                else:
                    self.model = data # Fallback for old style
                return self.model
            except Exception as e:
                print(f"[-] Error loading model: {e}")
        return None

    def _select_model_features(self, flow_features):
        """Strip UI/runtime metadata and keep only model feature columns."""
        model_features = {feature: flow_features.get(feature) for feature in self.features}
        validate_features([model_features], source="anomaly_model.model_features")
        return model_features

    def train(self, flow_data):
        """Deterministic eğitim hattı."""
        if not flow_data:
            return
        
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
        self.scaler = StandardScaler() # Re-initialize scaler for fresh fit
        X_scaled = self.scaler.fit_transform(X)
        
        # 7. Random state sabitle (deterministic)
        np.random.seed(42)
        self.model = IsolationForest(contamination=0.05, random_state=42)
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
        p = round(float(precision_score(y_true, y_pred, pos_label=-1, zero_division=0)), 3)
        r = round(float(recall_score(y_true, y_pred, pos_label=-1, zero_division=0)), 3)
        f1 = round(float(f1_score(y_true, y_pred, pos_label=-1, zero_division=0)), 3)
        ap = round(float(average_precision_score(y_true, anomaly_scores)), 3)

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

        self.retrain_buffer.extend(new_flow_data)
        
        # EĞER buffer boyutu >= retrain_threshold ise
        if len(self.retrain_buffer) >= self.retrain_threshold:
            print(f"[*] Retrain threshold met ({len(self.retrain_buffer)} >= {self.retrain_threshold}). Starting batch retraining...")
            
            # 1. Mevcut veri setini yükle (N veriyi almak için)
            all_data = []
            if os.path.exists('iot_traffic_dataset.csv'):
                try:
                    all_data = pd.read_csv('iot_traffic_dataset.csv').to_dict('records')
                except:
                    all_data = []
            
            # 2. Yeni veriyi ekle
            all_data.extend(self.retrain_buffer)
            
            # 3. Son N veriyi al
            training_window = all_data[-n_samples_window:]
            
            # 4. Modeli yeniden eğit (Batch Retraining)
            self.train(training_window)
            
            # 5. Buffer sıfırla
            self.retrain_buffer = []
            print("[+] Batch retraining complete. Buffer reset.")

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
        # 1. Feature sözleşmesini doğrula
        model_features = self._select_model_features(flow_features)
        
        if self.model is None:
            return {"label": "normal", "score": 0.0}
            
        # 2. DataFrame'e çevir ve temizle
        df = pd.DataFrame([model_features])
        X = df[self.features].copy().fillna(0.0)
        
        # 3. Normalize et (Train ile aynı scaler)
        try:
            X_scaled = self.scaler.transform(X)
        except Exception as e:
            print(f"[-] Inference scaling error: {e}")
            return {"label": "normal", "score": 0.0}
            
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
        
        return {"label": label, "score": anomaly_score, "confidence": confidence}

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
                    'reasons': [f"Statistical anomaly (Score: {analysis['score']}, Conf: {analysis['confidence']})"],
                    'metrics': self.metrics
                })
                
        return results

if __name__ == "__main__":
    # Test data with new IAT features (normal IoT vs Botnet flood)
    test_data = [
        {'packet_count': 10, 'byte_count': 1000, 'duration': 1.0, 'avg_packet_size': 100, 'mean_iat': 0.1, 'var_iat': 0.002, 'dst_ip': '1.1.1.1'},
        {'packet_count': 12, 'byte_count': 1100, 'duration': 1.1, 'avg_packet_size': 91, 'mean_iat': 0.11, 'var_iat': 0.003, 'dst_ip': '1.1.1.1'},
        {'packet_count': 8, 'byte_count': 900, 'duration': 0.9, 'avg_packet_size': 112, 'mean_iat': 0.09, 'var_iat': 0.001, 'dst_ip': '1.1.1.1'},
        # Flood / Botnet anomaly (extremely low variance, high count)
        {'packet_count': 5000, 'byte_count': 1000000, 'duration': 0.1, 'avg_packet_size': 200, 'mean_iat': 0.00002, 'var_iat': 0.0, 'dst_ip': '9.9.9.9'}
    ]
    model = AnomalyModel()
    model.train(test_data)
    print(f"Metrics: {model.metrics}")
