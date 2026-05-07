# Algorithm Consistency Audit

Bu dosya dokumantasyondaki algoritmik ifadeler ile kodda gorulen gercek davranisi karsilastirir.

| Alan | Dokumanda yazan | Kodda gorulen | Risk seviyesi | Oneri |
| --- | --- | --- | --- | --- |
| Host discovery | Nmap tabanli cihaz kesfi | `network_scan.py` `DISCOVERY_ARGUMENTS = -sn -n -T4 ... -PE -PS... -PA...` ile Nmap discovery yapiyor. | Low | Uyumlu. Nmap kurulum/izin gereksinimi korunmali. |
| Local subnet tespiti | Yerel ag otomatik tespit edilir | `get_local_network()` UDP socket ile local IP bulup son okteti `.0/24` yapiyor. | Medium | Dokumanda otomatik tespitin /24 varsayimi oldugu acik yazilmali. |
| Nmap servis profilleri | Quick, IoT discovery, full, vulnerability profilleri | `PROFILE_ARGUMENTS` icinde profiller var; `vulnerability` profili `banner,http-title,http-headers,ssl-cert,vulners` calistiriyor. | Low | Uyumlu. `vulners` scriptinin ortamda bulunmasi gerektigi not edilmeli. |
| CVE extraction | CVE/CVSS analizi | `vulnerability_scan.py` CVE ID'lerini regex ile `vulners` script output'undan cekiyor; CVSS cikarmiyor. | High | "CVE ID extraction" ile "CVSS scoring" ayrilmali. CVSS ancak baska normalize contextlerde dict alan olarak varsa kullaniliyor. |
| CVE fallback 7.0 | Fallback CVSS uygulanir | `RiskEngine._extract_cvss()` dict CVE item icinde skor yoksa 7.0 donduruyor; scanner CVE'leri string olarak verdigi icin bu fallback path aktif olmayabilir. | High | Rapor "CVE score yoksa fallback 7.0 varsayimi risk engine dict-CVE path'inde vardir" diye sinirlandirilmali. Scanner string CVE icin dogrulanmali. |
| Fallback audit/log | Fallback audit/log var | Kodda CVSS fallback kullanimini ayrica audit eden log/field gorulmedi. | Medium | "Fallback audit/log" iddiasi varsa kaldirilmali veya `context_factors` icinde acik alan eklenmeli. |
| Device fingerprinting sirasi | OUI, SSDP, HTTP title/server header ile zenginlestirme | Discovery: Nmap vendor/hostname -> OUI fallback -> SSDP vendor enrichment. Service scan: HTTP title/server header enrich. | Low | Uyumlu; sira dokumanda bu sekilde netlestirilmeli. |
| SSDP kullanimi | SSDP kullaniliyor | `discover_ssdp()` multicast M-SEARCH gonderiyor ve server header topluyor. | Low | Uyumlu. Aktif SSDP broadcast oldugu belirtilmeli. |
| HTTP title scraping | HTTP title/server header kullaniliyor | `get_http_title()` HTTP/HTTPS title ve Server header okuyor, sadece HTTP_PORTS icin cagriliyor. | Low | Uyumlu. Timeout ve SSL verify-disabled notu eklenebilir. |
| Flow key | Flow key 5-tuple | `feature_extractor.py` key `(src_ip, dst_ip, src_port, dst_port, proto)`. | Low | Uyumlu. |
| Live feature count | Canli sistem feature'lari | `FEATURE_SCHEMA` 6 numeric feature: `packet_count`, `byte_count`, `duration`, `avg_packet_size`, `mean_iat`, `var_iat`. UI metadata ekstra. | Low | "6 live numeric feature" olarak yazilmali. |
| N-BaIoT feature count | 115 N-BaIoT feature | Evaluation preprocessing/training 115 numeric feature uzerinden calisiyor. | Low | Uyumlu. |
| Isolation Forest scaler | StandardScaler kullaniliyor | `AnomalyModel.train()` `StandardScaler.fit_transform`, inference `scaler.transform`; evaluation baseline da StandardScaler kullaniyor. | Low | Uyumlu. |
| Isolation Forest normalization | Raw score normalize edilir | `normalize_anomaly_score(raw_score)` formulu `max(0,min(1,0.5-raw_score))`. | Medium | Raporlarda bu formulu aynen yazin; probability veya kalibre skor gibi anlatmayin. |
| Online incremental learning | Online/incremental learning | Kodda `batch_retraining()` buffer dolunca yeniden egitiyor. Test dosyasi da "formerly online learning" diyor. | High | "Online incremental learning" ifadesi kullanilmamali; "batch retraining buffer" denmeli. |
| Risk formulu | `0.6 vulnerability + 0.4 anomaly` | `calculate_device_risk()` bu agirliklari kullanir, ancak asset multiplier ile tekrar carpar. `evaluate_device()` port modifiers ve contextual confidence de kullanir. | Medium | Basit formulu tek basina sunmayin; "base formula + asset/port/context modifiers" olarak anlatin. |
| Contextual analysis | Acik port sayisi/servis kritikligi kullanilir | `evaluate_device()` acik port sayisi, kritik port multipliers, CVE count, anomaly confidence ve asset type kullaniyor. | Low | Uyumlu. |
| Plaintext heuristic | Plaintext/protocol heuristic | `MonitorService._parse_packets_for_ui()` Raw payload ilk 50 ascii karakteri UI bilgisi olarak gosteriyor; risk veya detection heuristic olarak kullanilmiyor. | Medium | "Plaintext heuristic detection" iddiasi varsa kaldirilmali; "packet preview" denmeli. |
| Promiscuous mode | Tum trafiği yakalar | Scapy `sniff` var ama explicit promiscuous mode veya switch mirroring garantisi yok. | High | "Tüm ağ trafiği" iddiasindan kacinin; switched/Wi-Fi sinirlarini yazin. |
| Metrics endpoint | Gercek dunya metrikleri | `MLService.get_metrics()` `true_positives=10`, `false_positives=2`, `system_uptime=99.9%` gibi statik alanlar donduruyor. | Critical | Bu alanlar "real_world_metrics" olarak sunulmamali; demo placeholder veya kaldirilmali. |

## En Riskli Algoritmik Bulgular

1. `/metrics` icindeki statik "real_world_metrics" alanlari gercek metrik gibi algilanabilir.
2. CVE ID extraction ile CVSS skorlama ayni sey gibi anlatilmamali.
3. Scanner string CVE listesi ile RiskEngine dict-CVE CVSS path'i arasinda sema farki var; fallback 7.0 her scan sonucunda beklendigi gibi calismayabilir, dogrulanmali.
4. Packet capture icin "tum trafik" veya "real-time protection" iddialari teknik olarak fazla genis olur.
