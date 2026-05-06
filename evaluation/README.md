# Sentinel-IoT Evaluation Modulu

Bu modul Sentinel-IoT projesinde final sunumu ve rapor icin olculebilir dogrulama ciktisi uretir. Kapsam; flow tabanli anomali modeli, risk engine formulu ve scanner sonucunun manuel dogrulanmasidir.

Bu projede harici veri seti kullanilmamistir; kontrollu dogrulama verisi kullanilmistir.

## Veri Formati

Anomali dogrulamasi `evaluation/flow_validation_dataset.csv` dosyasini bekler.

Zorunlu kolonlar:

```text
packet_count,byte_count,duration,avg_packet_size,mean_iat,var_iat,label,attack_type
```

`label` degerleri:

```text
0 = normal
1 = anomaly
```

`attack_type` ornekleri:

```text
normal
port_scan
flood
data_exfiltration
```

Gercek veriniz hazir degilse once `evaluation/flow_validation_dataset.example.csv` dosyasindaki formati inceleyin. Sahte basari metrigi uretmeyin; sadece kontrollu olarak topladiginiz veya onceden etiketlediginiz flow feature verisini kullanin.

## Dataset Export

Projede bulunan `sentinel_iot/iot_traffic_dataset.csv` feature dosyasini evaluation formatina aktarmak icin:

```powershell
.\sentinel_iot\.venv\Scripts\python.exe evaluation\export_flow_dataset.py
```

Sanal ortam aktifse ayni komut kisa sekilde de calisir:

```powershell
python evaluation\export_flow_dataset.py
```

Kaynak dosyada `attack_type` kolonu yoksa normal kayitlar `normal`, anomali kayitlari `unlabeled_anomaly` olarak isaretlenir.

## Anomali Modeli Dogrulama

```powershell
.\sentinel_iot\.venv\Scripts\python.exe evaluation\validate_anomaly_model.py
```

Sanal ortam aktifse:

```powershell
python evaluation\validate_anomaly_model.py
```

Script:

- CSV kolonlarini ve sayisal feature degerlerini dogrular.
- Normal trafik kayitlarini train set olarak kullanir.
- Tum veri setini test set olarak kullanir.
- `StandardScaler` ve `IsolationForest(random_state=42)` ile metrikleri hesaplar.

Uretilen ciktilar:

```text
evaluation/results/evaluation_summary.json
evaluation/results/classification_report.csv
evaluation/results/confusion_matrix.png
```

## Risk Engine Dogrulama

```powershell
.\sentinel_iot\.venv\Scripts\python.exe evaluation\validate_risk_engine.py
```

Sanal ortam aktifse:

```powershell
python evaluation\validate_risk_engine.py
```

Uretilen cikti:

```text
evaluation/results/risk_engine_validation.json
```

## Scanner Dogrulama

Manuel dogrulama template dosyasi:

```text
evaluation/scanner_validation_template.csv
```

Kullanim aciklamasi:

```text
evaluation/SCANNER_VALIDATION_GUIDE.md
```

## Sunuma Ekleme

Final sunumunda su dosyalar kullanilabilir:

- `evaluation/results/evaluation_summary.json`: accuracy, precision, recall, F1, FPR, FNR
- `evaluation/results/classification_report.csv`: sinif bazli metrikler
- `evaluation/results/confusion_matrix.png`: gorsel confusion matrix
- `evaluation/results/risk_engine_validation.json`: risk formulu testleri
- `evaluation/presentation_summary.md`: rapor/sunum ozet sablonu

Sonuclari yorumlarken veri kaynaginin kontrollu dogrulama verisi oldugunu acikca belirtin.
