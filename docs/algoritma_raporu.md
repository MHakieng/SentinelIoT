# Sentinel-IoT Algoritma Raporu

Bu rapor mevcut kod davranisina gore hazirlanmistir. Kodda olmayan ozellikler gelecek calisma veya sinirlilik olarak belirtilmistir.

## 1. Ag Kesfi

Host discovery `sentinel_iot/scanner/network_scan.py` icinde Nmap ile yapilir. Otomatik hedef verilmezse `get_local_network()` local IP adresini bulur ve son okteti `.0/24` yaparak varsayilan CIDR uretir. Bu bir /24 varsayimidir; farkli subnet yapilari icin hedef aralik kullanici tarafindan verilmelidir.

Discovery argumanlari:

```text
-sn -n -T4 --max-retries 1 --host-timeout 8s -PE -PS22,80,443,445,554,1883,8080 -PA80,443,502,1883
```

## 2. Servis ve CVE Gorunurlugu

Servis taramasi `sentinel_iot/scanner/vulnerability_scan.py` icinde Nmap profilleriyle yapilir. `vulnerability` profili su scriptleri kullanir:

```text
banner,http-title,http-headers,ssl-cert,vulners
```

CVE ID'leri Nmap script ciktilarindan regex ile cekilir. Bu nedenle CVE gorunurlugu Nmap ve script ciktisinin kalitesine baglidir. Scanner tarafinda her CVE icin CVSS skoru garanti edilmez. RiskEngine icinde dict formatli CVE item'larinda `cvss`, `cvss_score`, `cvss_base` veya `score` alani varsa kullanilir; yoksa bu path icin 7.0 fallback degeri vardir. Scanner'in string CVE listesi ile CVSS fallback davranisi ayrica dogrulanmalidir.

## 3. Device Fingerprinting

Fingerprinting zenginlestirmesi su kaynaklardan gelir:

- Nmap addresses/vendor/hostname bilgisi
- Local OUI sozlugu fallback'i
- SSDP M-SEARCH ile UPnP/SSDP server bilgisi
- HTTP/HTTPS title ve Server header bilgisi

Bu mekanizma heuristik cihaz tanima/zenginlestirme saglar; kesin vendor veya model tespiti garantisi vermez.

## 4. Paket Yakalama ve Flow Extraction

Pasif izleme `sentinel_iot/monitor/packet_capture.py` icinde Scapy `sniff` ile yapilir. Capture islemi yonetici/root yetkisi gerektirebilir. Sistem yalnizca calistigi network interface'in gorebildigi trafiği yakalar; switched network, Wi-Fi istemci izolasyonu veya SPAN/mirror olmayan ortamlarda tum ag trafiği gorulmeyebilir.

Flow key `sentinel_iot/monitor/feature_extractor.py` icinde 5-tuple olarak olusturulur:

```text
src_ip, dst_ip, src_port, dst_port, protocol
```

Canli runtime model icin kullanilan numeric feature sayisi 6'dir:

```text
packet_count
byte_count
duration
avg_packet_size
mean_iat
var_iat
```

UI icin `flow_id`, IP, port ve protocol alanlari da tasinir; bunlar model feature'i degildir.

## 5. Runtime Anomali Modeli

Runtime model `sentinel_iot/ml/anomaly_model.py` icinde Isolation Forest kullanir. Egitim ve inference sirasinda `StandardScaler` kullanilir. Isolation Forest raw score'u su basit clamp formulu ile 0-1 araligina cekilir:

```text
anomaly_score = clamp(0.5 - raw_score, 0.0, 1.0)
```

Bu skor kalibre edilmis olasilik degildir; anomali sinyali olarak yorumlanmalidir.

Kodda gercek zamanli incremental ogrenme akisi yoktur. Mevcut mekanizma `batch_retraining()` ile yeni verileri buffer'da biriktirir ve esik asilinca periodic batch retraining yapar.

## 6. Risk Engine

Risk engine `sentinel_iot/core/risk_engine.py` icinde tanimlidir. Base agirliklar:

```text
vulnerability_weight = 0.6
anomaly_weight = 0.4
```

Kodda final skor yalnizca bu iki agirliktan olusmaz. Port modifiers, asset type multiplier, anomaly confidence ve CVE/CVSS baglami da hesaba katilir:

```text
risk_base = vulnerability_component * 0.6 + anomaly_component * 0.4
final_risk = min(100, risk_base * asset_multiplier)
```

Bu nedenle raporlarda yalnizca `0.6 + 0.4` formulu verilirse eksik kalir; baglamsal carpimlar da belirtilmelidir.

## 7. N-BaIoT Offline Benchmark

N-BaIoT pipeline canli sisteme entegre edilmis model degildir. Bu pipeline `evaluation/` altinda offline benchmark olarak calisir. N-BaIoT modelleri 115 numeric feature uzerinde egitilir. Canli Sentinel-IoT runtime modeli ise 6 numeric live feature uretir.

Bu nedenle N-BaIoT random split, device split, attack split ve device+attack split sonuclari canli sistem basarisi olarak degil, offline model dogrulama ciktisi olarak sunulmalidir.

## 8. Sinirliliklar ve Gelecek Calisma

- Auth/JWT/OAuth2 yoktur; gelecek calisma olarak tutulmustur.
- Production deployment yapilmamistir.
- Packet capture tum ag trafiğini garanti etmez.
- Nmap ve packet capture izinli aglarda ve gerekli yetkilerle calistirilmalidir.
- CVSS skoru her Nmap CVE sonucunda garanti degildir.
- N-BaIoT benzeri 115 feature live extractor gelecekte gelistirilebilir.
- Alternatif olarak mevcut 6 live feature ile ayri supervised model egitilebilir.
