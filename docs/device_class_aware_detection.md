# Device-Class-Aware Detection

SentinelIoT'nin ilk canlı anomali akışı tek bir IoT odaklı modeli tüm trafik tiplerine uyguluyordu. Bu yaklaşım IoT kamera, sensör veya MQTT cihazları için anlamlı olsa da Windows laptop, telefon veya tarayıcı trafiği gibi client davranışlarında false positive üretebilir. Device-class-aware detection mimarisi bu domain mismatch riskini azaltmak için tasarlanmıştır.

## Hedef Mimari

Planlanan akış:

```text
Device Discovery
-> Device Feature Builder
-> Device Classifier
-> Model Router
-> Device-Class-Aware Flow Scoring
-> Final Risk / Dashboard
```

İlk aşamada bağımsız bir rule-based classifier eklendi. Sonraki aşamalarda scanner metadata enrichment ve monitor class-aware scoring entegrasyonu geriye uyumlu şekilde bağlandı. Classifier DB'ye yazmaz ve mevcut ML modellerini değiştirmez.

## Cihaz Sınıfları

- `iot_device`: kamera, sensör, smart plug, MQTT/RTSP/CoAP/Modbus kullanan cihazlar.
- `client_device`: laptop, desktop, telefon, tablet ve normal browser trafiği üreten cihazlar.
- `network_infrastructure`: router, gateway, modem, access point ve benzeri altyapı cihazları.
- `unknown`: yeterli veya tutarlı kanıt olmayan cihazlar.

## Classifier Output

Örnek çıktı:

```json
{
  "device_class": "client_device",
  "confidence": 0.72,
  "evidence": [
    "Vendor or hostname suggests PC/mobile client device",
    "High HTTPS/DNS/QUIC traffic ratio without IoT-specific ports"
  ],
  "method": "rule_based"
}
```

`confidence` değeri 0.0-1.0 aralığındadır. Evidence listesi kararın hangi sinyallerden geldiğini açıklar. Veri yetersizse classifier `unknown` döndürür.

## Kullanılan Sinyaller

Feature builder, device dict ve opsiyonel flow summary içinden şu sinyalleri normalize eder:

- vendor ve hostname metni
- service, product, HTTP title, server header metni
- açık port seti
- MQTT, RTSP, CoAP, Modbus, DNS, DHCP, SNMP, SSDP/mDNS gibi port/service ipuçları
- HTTPS, DNS, QUIC, MQTT ve RTSP oranları
- unique destination IP/port sayıları
- toplam flow, packet ve byte sayıları

Bozuk veya eksik input değerleri classifier'ı düşürmez; güvenli fallback kullanılır.

## Metrik Değildir

Bu classifier runtime accuracy, precision, recall veya F1 metriği üretmez. Cihaz sınıfı, daha sonraki aşamalarda bağlam farkındalığı sağlamak için kullanılan açıklanabilir bir tahmindir. Etiketli validation datası olmadan başarı metriği iddia edilmemelidir.

## Bu Aşamada Yapılmayanlar

- DB migration yapılmadı.
- `/monitor/flows` ve runtime scoring response'ları geriye uyumlu kalacak şekilde opsiyonel device class context alanlarıyla genişletildi.
- `/devices` response'u yalnızca opsiyonel device class metadata ile geriye uyumlu şekilde zenginleştirildi.
- Model router eklenmedi.
- Yeni model eğitilmedi.
- Mevcut CICIoT2023 veya IsolationForest artifact'leri değiştirilmedi.

## Scanner Integration Phase

Scanner integration aşamasında cihaz sınıflandırması, discovery ve vulnerability scan verileri birleştirildikten sonra çalıştırılır. Classifier input'u IP, MAC, vendor, hostname, discovery source ve `open_ports` verilerinden oluşur.

Bu aşamada DB migration yapılmadı. `database/models.py` ve `database/db.py` değiştirilmedi. Classification metadata scanner runtime sırasında in-memory device kaydına eklenir ve `/devices` response'u aynı IP için bu in-memory metadata'yı bulursa opsiyonel olarak zenginleştirir.

Eklenen opsiyonel alanlar:

```json
{
  "device_class": "client_device",
  "device_class_confidence": 0.72,
  "device_class_evidence": [
    "Vendor or hostname suggests PC/mobile client device"
  ],
  "device_class_method": "rule_based"
}
```

`asset_type` legacy risk engine alanı olarak korunur ve bu aşamada değiştirilmez. `device_class` ise detection/model routing bağlamı için ayrı bir metadata alanıdır.

`device_class_confidence` accuracy, precision, recall veya F1 değildir. Bu değer yalnızca rule-based classifier'ın kendi evidence gücünü ifade eder. Runtime metric olarak yorumlanmamalıdır.

Metadata in-memory taşındığı için uygulama restart sonrası kalıcı olmayabilir. Kalıcı persistence için sonraki aşamada açık DB migration planlanmalıdır.

Scanner integration metadata alanları `DeviceResult` schema'sında opsiyonel alanlar olarak belgelenir. Bu, `/devices` ve `/devices/{ip}` response contract'ını açık tutar; metadata olmayan cihazlarda eski response alanları korunur.

## Sonraki Aşamalar

1. Scanner integration: discovery sonrası cihaz record'una opsiyonel `device_class` metadata eklemek.
2. Monitor class-aware scoring: live flow scoring sırasında source/destination device class bilgisini kullanmak.
3. Model router: cihaz sınıfına göre model, threshold ve scoring profile seçmek.
4. Dataset export: SQLite device kayıtları ve live flow özetlerinden etiketlenebilir CSV üretmek.
5. Client/network model training: yeterli manuel etiketli veri oluşursa ayrı client veya infrastructure modeli eğitmek.

## Monitor Class-Aware Scoring Phase

Monitor integration uses optional `device_class` metadata from `devices_db` to enrich live flow scoring with source and destination device class context. When available, flow responses and scoring breakdowns can include `source_device_class`, `source_device_class_confidence`, `destination_device_class`, and `destination_device_class_confidence`.

This phase does not retrain the ML model, does not change CICIoT2023 inference output, and does not fabricate runtime metrics. Device class context only adds explainable reward/penalty calibration for `final_flow_risk`.

Implementation note: class-aware calibration is isolated in `sentinel_iot/ml/device_class_scoring.py`. The base `flow_scorer.py` remains the generic ML-score-to-risk scorer. Live monitor responses can optionally include `class_aware_adjustment`, `class_aware_reasons`, `decision`, and `decision_source`. These fields are runtime explanation fields, not validation metrics.
