# Project Scope Audit

Bu denetim Sentinel-IoT projesinin hedef, kod ve dokumantasyon uyumunu incelemek icin hazirlanmistir. Kodda buyuk degisiklik yapilmamistir.

| Hedeflenen ozellik | Kodda mevcut durum | Durum | Onerilen duzeltme |
| --- | --- | --- | --- |
| IoT aglarinda cihaz kesfi | `sentinel_iot/scanner/network_scan.py` Nmap host discovery calistiriyor; `/scanner/scans` ile background job olarak tetikleniyor. | Uyumlu | README'deki ifade korunabilir; izinli/yerel ag siniri vurgulanmali. |
| Servis/zafiyet gorunurlugu ve CVE analizi | `vulnerability_scan.py` Nmap `-sV`, scriptler ve `vulners` ciktilarindan CVE regex extraction yapiyor. CVSS her zaman gelmiyor. | Kismi | "CVE analizi" ifadesi "Nmap script ciktilarindan CVE gorunurlugu" olarak yumuşatilmali. |
| Device fingerprinting | OUI lookup, Nmap vendor, hostname, SSDP ve HTTP title/server header kullaniliyor. | Uyumlu | Fingerprinting "heuristic/enrichment" olarak anlatilmali. |
| Pasif trafik izleme | `packet_capture.py` Scapy sniff ile capture yapiyor; aktif monitorde per-window capture var. | Uyumlu | Switched network/Wi-Fi sinirlari dokumana eklenmeli. |
| Flow-based feature extraction | `feature_extractor.py` 5-tuple flow key kullaniyor, model semasi 6 numeric feature. | Uyumlu | "6 live numeric feature" net yazilmali. |
| ML tabanli anomali tespiti | Runtime Isolation Forest, `StandardScaler`, 6 feature semasi ve batch retraining buffer var. | Uyumlu | "Online incremental learning" denmemeli; "controlled batch retraining" denmeli. |
| Hybrid risk scoring | `RiskEngine` CVE/port/anomaly/asset multiplier kullanarak skor uretiyor. | Uyumlu | Basit 0.6/0.4 formulu anlatilirken asset multiplier ve port modifiers da belirtilmeli. |
| React dashboard ve interaktif topoloji | v6 Command Center tabanli operasyon kokpiti; scan/monitor/topology/validation/LLM panellerini iceriyor. | Uyumlu | Topoloji "runtime visualization" olarak anlatilmali, otomatik enterprise topology discovery gibi sunulmamali. |
| N-BaIoT offline benchmark | `evaluation/` altinda preprocessing, supervised modeller, split testleri, leakage analizi ve karsilastirma scriptleri var. | Uyumlu | N-BaIoT'nin canli sisteme dogrudan entegre edilmedigi korunmali. |
| LLM destekli analiz | `/llm/*` endpointleri var; env uzerinden provider/key/model okunuyor. | Uyumlu | LLM'in "grounded assistant" oldugu, guvenlik karari vermedigi belirtilmeli. |
| Production/deployment | README production deployment yapilmadigini soyluyor. Docker/JWT yok. | Uyumlu | "Production-ready" veya "profesyonel urun" dili kullanilmamali. |
| Authentication/JWT | Kodda JWT/OAuth2 yok; README kapsam disi diyor. | Uyumlu | Bu sinirlilik korunmali. |
| Test ve release dogrulamasi | `verify_release.ps1` backend testleri ve frontend lint/build calistiriyor. Son denetimde 66 passed, 3 skipped. | Uyumlu | "Full test suite" denirse tarih/komut ile desteklenmeli. |

## Genel Karar

Proje hedefinden uzaklasmamis. Cekirdek hedef; ag gorunurlugu, servis/CVE gorunurlugu, pasif monitoring, anomali sinyali, risk skoru, dashboard ve offline ML benchmark olarak tutarli. Onceki `/metrics` statik `real_world_metrics` riski giderildi; en buyuk kapsam riski artik N-BaIoT benchmark sonuclarinin canli sistem basarisi gibi algilanmasidir.

## Hemen Duzeltilmesi Onerilen Kapsam Dili

- "CVE analizi" yerine "Nmap script ciktilarindan CVE gorunurlugu ve risk baglami".
- "Canli sistem basarisi" yerine "runtime demo sinyali".
- "N-BaIoT model dogrulama kaniti" ifadesi korunabilir; "canli sisteme entegre model" denmemeli.
- "Gercek dunya metrikleri" ifadesi kullanilmamali; mevcut `/metrics` runtime TP/FP/F1 icin `not_available` durumunu dondurur.
