# Final Acceptance Test Report

## Ozet

Denetim tarihi: 2026-05-07  
Denetim modu: Final acceptance / QA kontrolu  
Genel karar: Final savunmaya hazir. Onceki iki FAIL giderildi: `/metrics` artik statik `real_world_metrics` dondurmuyor ve frontend bu degerleri gercek operasyon ozeti gibi gostermiyor.

## Calistirilan Komutlar

| Komut | Sonuc | Not |
| --- | --- | --- |
| `git status --short --branch` | Passed | Repo durumunda yalnizca beklenen kod/dokuman degisiklikleri var. |
| `.\\sentinel_iot\\.venv\\Scripts\\python.exe -m pytest --basetemp=.pytest_tmp` | Passed | Test suite gecti. |
| `.\\sentinel_iot\\.venv\\Scripts\\python.exe -m compileall -q evaluation` | Passed | Evaluation scriptleri compile oldu. |
| `npm run build` | Passed | Build basarili; Vite chunk size warning var. |
| TestClient smoke checks | Passed | `/metrics` statik `real_world_metrics` dondurmuyor; `/health` local DB path dondurmuyor. |

## Passed

- FastAPI uygulamasi import edilebiliyor.
- `/`, `/health`, `/devices`, `/scanner/status`, `/scanner/jobs`, `/monitor/live/status`, `/monitor/flows`, `/monitor/topology` endpointleri JSON response donuyor.
- `/metrics` statik operasyon metrigi dondurmuyor.
- `/metrics.runtime_detection_metrics` etiketli canli veri olmadigi icin `null`.
- `/metrics.runtime_metrics_metadata.source` degeri `not_available`.
- Frontend runtime karti `Runtime Metrics Status` olarak degistirildi.
- Frontend TP/FP/F1 icin etiketli canli olay gerektigini acikca gosteriyor.
- `/health` response'u local SQLite absolute path dondurmuyor; `database_status`, `database_type`, `path_exposed=false` ozetini donduruyor.
- Pytest basarili.
- Evaluation scriptleri compile oluyor.
- Frontend build basarili.
- `.gitignore` `.env`, `.venv`, `node_modules`, DB, PCAP, raw/processed evaluation datasets ve evaluation models klasorlerini disliyor.
- N-BaIoT raw/processed dataset ve model klasorleri ignored durumda.
- Canli ML feature semasi 6 numeric feature ile uyumlu: `packet_count`, `byte_count`, `duration`, `avg_packet_size`, `mean_iat`, `var_iat`.
- N-BaIoT sonucu offline benchmark olarak konumlandiriliyor.

## Failed

Aktif FAIL kalmadi.

## Warning

- `py_compile evaluation\\*.py` Windows'ta wildcard nedeniyle kullanisli degil; `compileall -q evaluation` kullanilmali.
- Scanner CVE extraction string CVE listesi uretirken RiskEngine CVSS fallback'i dict CVE item path'inde calisiyor. Bu sema farki dokumante edildi ama entegrasyon testi eklenmeli.
- CVSS fallback'in response/log'da fallback olarak isaretlenmesi daha seffaf olur.
- Packet capture invalid interface senaryosu manuel veya testle dogrulanmadi.
- Nmap yok/yetki yok senaryosu kodda yakalaniyor, ancak bu ortamda bilerek Nmap kaldirilip denenmedi.
- Bos scan sonucu gercek agda manuel denenmedi.
- Frontend build chunk size warning veriyor; teslimi engellemez ama performans iyilestirme alanidir.
- Dashboard empty state kodda var, ancak Playwright/gorsel smoke test bu turda calistirilmadi.
- Runtime TP/FP/F1 metrikleri etiketli canli olay olmadigi icin mevcut degil; bu bilincli sinirlilik olarak kalir.

## Not Tested

- Gercek Nmap scan job'unun aktif agda uctan uca tamamlanmasi.
- Nmap kurulu degilken veya PATH'te degilken API response'unun UI'da gorunumu.
- Packet capture icin admin yetkisi olmayan ortamda UI/response davranisi.
- Switched/Wi-Fi izole agda monitor gorunurluk siniri.
- Frontend icin tarayici uzerinde gorsel/manuel click-through testi.

## Sayisal Sonuc

| Durum | Sayi |
| --- | ---: |
| Passed | 45 |
| Failed | 0 |
| Warning | 9 |
| Not tested | 5 |

## En Onemli Kalan Bulgular

1. Runtime TP/FP/F1 metrikleri etiketli canli olay olmadigi icin mevcut degil.
2. Scanner CVE string semasi ile RiskEngine dict-CVE CVSS fallback path'i ayrica entegrasyon testi gerektiriyor.
3. Packet capture invalid interface/yetki senaryolari otomatik test edilmedi.
4. Gercek Nmap scan bu QA turunda calistirilmadi.
5. Build basarili ama JS chunk buyuklugu uyarisi var.
6. Repo temizligi iyi, ancak raw dataset ve model dosyalari localde bulundugu icin upload oncesi `git status --ignored` kontrolu zorunlu.

