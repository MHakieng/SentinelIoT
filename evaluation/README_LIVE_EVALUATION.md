# Canli Sistem Evaluation Altyapisi

Bu altyapi Sentinel-IoT canli monitor akisini bozmadan, pasif olarak flow snapshot toplamak ve final demoda canli sistemin nasil dogrulanacagini gostermek icin eklendi.

Onemli not: N-BaIoT supervised modeli canli Sentinel-IoT flow semasina dogrudan baglanmaz. N-BaIoT modelinde yaklasik 115 feature vardir; canli Sentinel-IoT monitor akisi su temel flow feature'larini uretir:

```text
packet_count
byte_count
duration
avg_packet_size
mean_iat
var_iat
```

Bu nedenle canli demo icin iki ayri seyi anlatmak gerekir:

- N-BaIoT: Offline, etiketli benchmark ve model kapasitesi.
- Canli Sentinel-IoT: Runtime scanner/monitor entegrasyonu ve pasif flow toplama.

## 1. Backend'i Baslat

```powershell
powershell -ExecutionPolicy Bypass -File .\run_backend.ps1
```

Dashboard gerekiyorsa:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_frontend.ps1
```

## 2. Canli Monitor'u Baslat ve Flow Topla

Guvenli pasif toplama icin:

```powershell
.\sentinel_iot\.venv\Scripts\python.exe evaluation\collect_live_flows.py --start-monitor --duration-seconds 60 --interval-seconds 5
```

Uretilen dosya:

```text
evaluation/live/live_flow_snapshots.csv
```

Bu dosyada modelin runtime tahmini `model_label`, elle doldurulacak dogrulama etiketi ise `manual_label` kolonudur.

## 3. Manuel Etiketleme

Canli ortamda gercek saldiri uretilmez. Demo icin kontrollu normal trafik izlenebilir. CSV icindeki `manual_label` su sekilde doldurulur:

```text
0 = normal
1 = anomaly
```

`attack_type` icin ornek degerler:

```text
normal
manual_live
known_test_event
```

## 4. Canli Validation Dataset Hazirla

Elle etiketleme tamamlandiktan sonra:

```powershell
.\sentinel_iot\.venv\Scripts\python.exe evaluation\prepare_live_validation_dataset.py
```

Uretilen dosya:

```text
evaluation/live/live_validation_dataset.csv
```

Bu dosya mevcut Sentinel-IoT anomaly validation scriptiyle uyumludur:

```powershell
.\sentinel_iot\.venv\Scripts\python.exe evaluation\validate_anomaly_model.py --dataset evaluation\live\live_validation_dataset.csv
```

## 5. N-BaIoT Modeli Canli Akisa Dogrudan Uygun mu Kontrol Et

```powershell
.\sentinel_iot\.venv\Scripts\python.exe evaluation\shadow_predict_nbaiot_live.py
```

Beklenen sonuc: N-BaIoT modeli ile canli flow semasi dogrudan uyumlu degilse script bunu acikca raporlar.

Rapor:

```text
evaluation/results/live_nbaiot_shadow_check.json
```

Bu rapor sunumda su noktayi kanitlamak icin kullanilabilir:

> N-BaIoT benchmark modeli offline dogrulama icindir. Canli Sentinel-IoT akisi farkli feature semasi kullandigi icin model dogrudan production path'e baglanmamistir.

## Sunumda Anlatim

Canli sistemde yapilan deneme su sekilde anlatilabilir:

1. Sentinel-IoT backend baslatildi.
2. Monitor pasif modda yerel ag flow snapshotlarini topladi.
3. Toplanan flow'lar `evaluation/live/live_flow_snapshots.csv` dosyasina yazildi.
4. Gerekiyorsa manuel etiketleme ile `live_validation_dataset.csv` hazirlandi.
5. N-BaIoT modeli ile canli feature semasi arasindaki fark shadow check ile raporlandi.

Bu yaklasim ana sistemi bozmaz, gercek saldiri uretmez ve akademik olarak benchmark ile canli demo ayrimini net tutar.
