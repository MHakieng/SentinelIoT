# Sentinel-IoT Proje Dokumantasyonu

## 1. Projenin Mevcut Asamasi

Sentinel-IoT su anda calisan bir FastAPI + React tabanli IoT ag guvenligi prototipidir. Proje; yerel agdaki cihazlari kesfetme, acik servisleri goruntuleme, canli trafik akislarini izleme, davranissal anomali sinyali uretme, risk skoru hesaplama ve LLM destekli cihaz/CVE baglami sunma asamasina gelmistir.

Bu asamada proje sadece arayuz demosu degil, test ve benchmark ciktisi uretebilen olculebilir bir akademik prototip haline getirilmistir. Backend testleri, frontend build/lint kontrolu, risk engine dogrulamasi, N-BaIoT offline benchmark calismasi ve canli sistem evaluation altyapisi eklenmistir.

## 2. Projenin Amaci

Sentinel-IoT'un amaci, yerel agdaki IoT cihazlari icin asagidaki guvenlik gorunurlugunu tek bir panelde sunmaktir:

- Cihaz envanteri
- Nmap tabanli ag ve servis taramasi
- Canli paket ve flow izleme
- Anomali tespiti
- Risk skorlama
- Nmap script ciktilarindan servis/CVE gorunurlugu
- LLM destekli cihaz analizi
- Offline akademik dogrulama ve benchmark ciktisi

Proje, ozellikle bitirme projesi baglaminda "calisan sistem + olculebilir dogrulama" hedefiyle ilerletilmistir.

## 3. Genel Mimari

| Katman | Teknoloji / Modul | Gorev |
| --- | --- | --- |
| Backend API | FastAPI | Dashboard ve servisler icin REST API |
| Scanner | Nmap / python-nmap | Yerel ag ve servis kesfi |
| Monitor | Scapy | Canli paket yakalama ve flow feature uretimi |
| ML | scikit-learn | Runtime Isolation Forest ve offline benchmark modelleri |
| Risk Engine | Python servis katmani | Servis/CVE gorunurlugu, port baglami ve anomali sinyallerini risk skoruna cevirme |
| Database | SQLite + SQLAlchemy | Cihaz, risk gecmisi ve anomali loglari |
| Dashboard | React + Vite | Operasyon, topoloji, metrik ve analiz arayuzu |
| LLM Katmani | Provider API | Cihaz/CVE baglamli aciklama ve aksiyon onerisi |
| Evaluation | Python scriptleri | Model, risk ve scanner dogrulama ciktisi |

## 4. Backend Yetkinlikleri

Backend tarafinda yapilan ana isler:

- FastAPI router yapisi moduler hale getirildi.
- Scanner endpointleri `/scanner/*` altinda toplandi.
- Monitor endpointleri `/monitor/*` altinda toplandi.
- Eski endpoint isimleri temizlendi.
- Startup yapisi FastAPI lifespan mekanizmasina tasindi.
- Database modeli SQLAlchemy 2.0 uyumlu hale getirildi.
- Runtime durum bilgileri daha kararli hale getirildi.
- Job yapisi ile scanner/monitor islemlerinin durumu izlenebilir hale getirildi.

Onemli endpoint gruplari:

```text
/devices
/scanner/scans
/scanner/status
/scanner/jobs
/monitor/packets
/monitor/flows
/monitor/history
/monitor/topology
/monitor/live/start
/monitor/live/status
/monitor/live/stop
/metrics
```

## 5. Scanner Yetkinlikleri

Scanner modulu Nmap tabanli calisir. Amaci yerel agdaki cihazlari bulmak ve servis gorunurlugu saglamaktir.

Desteklenen kabiliyetler:

- Hedef IP/CIDR araligi ile tarama baslatma
- Tarama profili secme
- Acik port ve servis bilgisi toplama
- Vendor ve cihaz bilgisi kaydetme
- Nmap script ciktilarindan CVE ID baglami varsa risk engine'e tasima
- Dashboard topoloji ve envanter ekranlarini guncelleme

Sinirlar:

- Proje aktif saldiri araci degildir.
- Taramalar Nmap'in izin verilen ve kontrollu aglarda calistirilmasi gereken servis kesif islemleridir.
- Nmap scriptleri ve `vulners` ciktisi ortama baglidir; her servis icin CVE veya CVSS skoru garanti edilmez.
- Gercek kurum aglarinda izinsiz kullanilmamalidir.

## 6. Monitor ve Flow Analizi

Monitor tarafi Scapy ile canli paketleri yakalar ve flow bazli feature uretir. Flow key kodda 5-tuple olarak tutulur:

```text
src_ip, dst_ip, src_port, dst_port, protocol
```

Canli sistemde modele verilen 6 numeric feature sunlardir:

```text
packet_count
byte_count
duration
avg_packet_size
mean_iat
var_iat
```

Bu feature'lar dashboard'da canli akislar, paket onizlemesi ve topoloji etkilesimi icin kullanilir. Runtime anomaly model de bu kisa sema uzerinden calisir.

Sinirlar:

- Canli sistem N-BaIoT veri setindeki 115 feature'li semayi dogrudan uretmez.
- Bu nedenle N-BaIoT supervised modeli canli path'e dogrudan baglanmamistir.
- Packet capture islemi yonetici/root yetkisi gerektirebilir.
- Sistem yalnizca calistigi network interface'in gorebildigi trafigi yakalar; switched network, Wi-Fi istemci izolasyonu veya SPAN/mirror olmayan ortamlarda tum ag trafigi gorulmeyebilir.

## 7. ML ve Anomali Tespiti

Projede iki farkli ML yaklasimi vardir.

### 7.1 Runtime Anomali Modeli

Canli Sentinel-IoT sistemi Isolation Forest tabanli hafif bir runtime anomaly detection yapisi kullanir. Bu model `StandardScaler` ile normalize edilen 6 numeric live flow feature semasina gore calisir.

Amac:

- Canli akislar icin anomali sinyali uretmek
- Risk engine'e anomali bileseni saglamak
- Dashboard'da izleme ve uyarilari gostermek

Kodda gercek zamanli incremental ogrenme akisi yoktur. Mevcut mekanizma, yeni ornekleri buffer'da biriktirip belirli esiklerde periodic batch retraining yapacak sekilde tasarlanmistir.

### 7.2 Offline N-BaIoT Benchmark

N-BaIoT veri seti ile supervised benchmark pipeline kurulmustur. Bu benchmark canli sisteme dogrudan baglanan model degil, ML tarafinin etiketli IoT botnet verisi uzerinde offline olarak olculebilmesini saglayan akademik dogrulama calismasidir.

Calistirilan modeller:

- Random Forest
- Extra Trees
- HistGradientBoosting
- Device Split Random Forest
- Attack Split Random Forest
- Device + Attack Split Random Forest
- Isolation Forest contamination tuning

N-BaIoT processed dataset ozeti:

| Deger | Sonuc |
| --- | ---: |
| Toplam satir | 1,772,641 |
| Feature sayisi | 115 |
| Normal kayit | 172,641 |
| Anomaly kayit | 1,600,000 |

Model dogrulama ozeti:

| Deney | F1-score | Yorum |
| --- | ---: | --- |
| Random Forest random split | 0.999994 | Model kapasitesini gosterir; tek basina genelleme kaniti degildir. |
| Balanced RF | 0.999913 | Sinif dengesi azaltildiginda ayrimin korundugunu gosterir. |
| Device Split RF | 0.999206 | Farkli cihaz ayriminda yuksek performans gosterir; saldiri ailesi genellemesini tek basina olcmez. |
| Attack Split RF average | 0.803536 | Gormedigi saldiri ailesinde daha gercekci performans sinirini gosterir. |
| Device + Attack Split RF average | 0.806298 | Hem cihaz hem saldiri ailesi ayrildiginda genelleme sinirini gosterir. |
| Isolation Forest best | 0.991886 | Unsupervised baseline icin destekleyici sonuc; FPR 0.149999 olarak yorumlanmalidir. |

Random split sonuclari cok yuksek oldugu icin tek basina canli sistem basarisi olarak sunulmamalidir. Final raporda Random Split model kapasitesi, Device Split cihaz genellemesi, Attack Split ve Device + Attack Split ise yeni saldiri ailesine genelleme siniri olarak anlatilmalidir.

## 8. Risk Engine

Risk engine, servis/CVE gorunurlugu ve anomali sinyallerini tek bir risk skoruna cevirir. Basit dogrulama senaryolarinda base risk formulu sudur:

```text
risk_base = vulnerability * 0.6 + anomaly * 0.4
```

Kodda final skor yalnizca bu iki agirliktan olusmaz. Acik port sayisi, kritik port modifier'lari, asset type multiplier, anomaly confidence ve varsa CVE/CVSS baglami da dikkate alinir:

```text
final_risk = min(100, risk_base * asset_multiplier)
```

Risk engine test senaryolari:

| Senaryo | Vulnerability | Anomaly | Beklenen | Sonuc |
| --- | ---: | ---: | ---: | --- |
| Temiz cihaz | 0 | 0 | 0 | Passed |
| Sadece zafiyet | 80 | 0 | 48 | Passed |
| Sadece anomali | 0 | 90 | 36 | Passed |
| Iki sinyal de yuksek | 90 | 90 | 90 | Passed |
| Dengeli orta seviye | 50 | 50 | 50 | Passed |

Bu dogrulama `evaluation/results/risk_engine_validation.json` dosyasinda tutulur.

## 9. Dashboard Yetkinlikleri

React dashboard su ana ekranlari sunar:

- Envanter
- Servis gorunurlugu
- Izleme
- Paket akisi
- Canli akislar
- Ag topolojisi
- Dogrulama ve Ozet
- Cihaz detaylari
- Guvenlik asistani

Yapilan UI/UX gelistirmeleri:

- Topoloji ekrani daha okunabilir ve operasyon odakli hale getirildi.
- Tarama hedefi ve profil secimi eklendi.
- Yenileme sureleri daha kontrollu hale getirildi.
- Console log kalintilari temizlendi.
- Eski endpoint kullanimlari kaldirildi.
- Dogrulama ve Ozet sayfasina offline akademik benchmark paneli eklendi.

Dogrumlama ve Ozet sayfasinda gosterilen akademik dogrulama ciktisi:

- N-BaIoT offline benchmark metrikleri
- Device split sonucu
- Attack split ve device + attack split genelleme sonuclari
- Isolation Forest baseline sonucu
- Model comparison grafigi
- Random Forest confusion matrix
- Random split skorunun neden yuksek cikabilecegine dair yorum

Bu metrikler canli Sentinel-IoT runtime basarisi olarak degil, offline benchmark ve model dogrulama ciktisi olarak yorumlanmalidir.

## 10. LLM Destekli Analiz

Projede LLM katmani cihaz ve CVE baglami icin aciklama uretmek amaciyla kullanilir.

Yetkinlikler:

- Secilen cihazin risk skorunu aciklama
- Risk bilesenlerini yorumlama
- Anomali gecmisini ozetleme
- Sonraki aksiyon onerileri uretme
- Kayitli CVE baglami varsa daha anlasilir teknik aciklama sunma

Guvenlik ve pratiklik acisindan API key `.env` dosyasindan okunur. `.env` Git'e eklenmez.

## 11. Evaluation ve Dogrulama Altyapisi

Proje icin ayri bir `evaluation/` klasoru kurulmustur.

Baslica scriptler:

| Script | Gorev |
| --- | --- |
| `validate_anomaly_model.py` | Sentinel flow validation dataset ile Isolation Forest dogrulama |
| `validate_risk_engine.py` | Risk engine formul senaryolarini dogrulama |
| `inspect_nbaiot.py` | N-BaIoT raw CSV dosyalarini inceleme |
| `preprocess_nbaiot.py` | N-BaIoT CSV dosyalarini binary benchmark datasetine cevirme |
| `train_nbaiot_model.py` | Supervised model egitimi |
| `train_nbaiot_device_split.py` | Cihaz bazli train/test ayrimi |
| `train_nbaiot_attack_split.py` | Saldiri ailesi bazli genelleme testi |
| `train_nbaiot_device_attack_split.py` | Cihaz + saldiri ailesi bazli genelleme testi |
| `train_nbaiot_balanced.py` | Dengeli sinif dagilimi ile benchmark |
| `analyze_nbaiot_feature_leakage.py` | Feature leakage / tek feature ayrim analizi |
| `tune_nbaiot_isolation_forest.py` | Isolation Forest contamination tuning |
| `compare_nbaiot_models.py` | Model karsilastirma tablosu ve grafigi |
| `collect_live_flows.py` | Canli monitor flow snapshot toplama |
| `prepare_live_validation_dataset.py` | Canli flow snapshotlarini validation formatina cevirme |
| `shadow_predict_nbaiot_live.py` | N-BaIoT modeli ile canli feature semasi uyumlulugunu kontrol etme |

Canli sistem ile N-BaIoT arasindaki fark bilincli olarak dokumante edilmistir. N-BaIoT offline benchmark, canli Sentinel-IoT ise runtime entegrasyon demosudur.

## 12. Test Durumu

Backend ve frontend dogrulama komutu:

```powershell
powershell -ExecutionPolicy Bypass -File .\verify_release.ps1
```

Son dogrulama sonucu:

```text
Backend: 66 passed, 3 skipped
Frontend lint: passed
Frontend production build: passed
```

Vite build sirasinda sadece bundle boyutu uyarisi verir. Bu build hatasi degildir.

## 13. Paketleme ve Calistirma

Kurulum:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Tek komutla gelistirme ortami:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_dev.ps1
```

Backend:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_backend.ps1
```

Frontend:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_frontend.ps1
```

Paketleme:

```powershell
powershell -ExecutionPolicy Bypass -File .\package_release.ps1
```

Paket ciktisi:

```text
release/SentinelIoT-release.zip
```

Raw dataset, processed dataset, `.env`, `.venv`, `node_modules`, build ciktisi ve lokal veritabani pakete dahil edilmez.

## 14. Guclu Noktalar

Projenin guclu yonleri:

- Uctan uca calisan FastAPI + React mimarisi
- Nmap tabanli cihaz ve servis gorunurlugu
- Canli paket/flow izleme
- Risk engine ile servis/CVE gorunurlugu ve anomali sinyallerini birlestirme
- LLM destekli cihaz analizi
- Offline akademik benchmark ve metrik uretimi
- N-BaIoT gibi etiketli IoT botnet veri setiyle supervised model karsilastirmasi
- Device split, attack split ve device + attack split ile genelleme analizi
- Sunuma hazir confusion matrix, model comparison ve feature importance ciktisi
- Windows ortaminda calistirma scriptleri
- `.env.example`, kurulum, dogrulama ve paketleme otomasyonu

## 15. Sinirlar ve Bilincli Tasarim Kararlari

Projenin sinirlari:

- Sistem bir IDS/IPS urunu degil, arastirma ve prototip seviyesinde bir guvenlik gorunurlugu sistemidir.
- Gercek saldiri uretmez.
- N-BaIoT modeli canli sisteme dogrudan baglanmamistir; feature semalari farklidir.
- N-BaIoT benchmark 115 numeric feature kullanir; canli anomaly modeli 6 numeric live flow feature semasiyla calisir.
- Nmap taramalari kontrollu ve izinli aglarda calistirilmalidir.
- Packet capture islemi yetki gerektirebilir ve sadece interface'in gorebildigi trafigi yakalar.
- CVE/CVSS gorunurlugu Nmap script ciktilarina baglidir; her sonuc icin garanti degildir.
- Auth/JWT/OAuth2 ve production deployment bu asamada kapsam disidir.
- LLM ciktisi karar verici degil, analist yardimcisi olarak konumlandirilmistir.
- Dataset ve model artifact dosyalari buyuk oldugu icin Git/release paketine dahil edilmemelidir.

Bu sinirlar hata degil, projenin akademik olarak dogru konumlandirilmasi icin bilincli ayrimlardir.

## 16. Hocalara Sunumda Nasil Anlatilmali?

Kisa anlatim:

> Sentinel-IoT, yerel agdaki IoT cihazlarini kesfeden, servis gorunurlugu saglayan, canli trafik akisini izleyen, anomali sinyallerini risk skoru ile birlestiren ve LLM destekli analiz sunan bir guvenlik gorunurlugu prototipidir. Proje sadece calisan bir dashboard olarak birakilmamis, risk engine testleri, canli flow toplama altyapisi ve N-BaIoT etiketli veri seti uzerinde offline ML benchmark ile olculebilir hale getirilmistir.

Vurgulanmasi gereken teknik ayrim:

> Canli sistem runtime monitoring demosudur. N-BaIoT benchmark ise model kapasitesini etiketli IoT botnet verisiyle gosteren offline dogrulama calismasidir. Bu iki katman bilincli olarak ayrilmistir cunku feature semalari farklidir: canli sistem 6 numeric live feature, N-BaIoT benchmark ise 115 numeric feature kullanir.

One cikarilacak sonuc:

> Random split modelleri cok yuksek F1-score vermektedir; ancak bu sonuclar tek basina genelleme kaniti degildir. Final savunmada Random Split model kapasitesi, Device Split cihaz genellemesi, Attack Split ve Device + Attack Split ise yeni saldiri ailesine genelleme siniri olarak anlatilmalidir.

## 17. Bundan Sonraki Gelistirme Adimlari

Bir sonraki teknik adimlar:

1. Canli sistem icin daha zengin feature extractor gelistirmek.
2. Canli flow semasi ile supervised model egitmek.
3. N-BaIoT benzeri 115 feature ureten extractor yazmak veya mevcut canli semaya uygun etiketli veri seti olusturmak.
4. Dashboard'da evaluation sonuclarini JSON'dan dinamik okuyan endpoint eklemek.
5. Daha fazla dataset ile karsilastirma yapmak: CICIoT2023, TON_IoT, BoT-IoT.
6. Model drift ve periodic batch retraining stratejisini gelistirmek.
7. LLM yanitlari icin daha kapsamli hallucination/groundedness evaluation yapmak.
8. Auth/JWT/OAuth2, HTTPS ve Docker tabanli deployment eklemek.

## 18. Son Durum Ozeti

Sentinel-IoT su anda:

- Calistirilabilir
- Test edilebilir
- Paketlenebilir
- Offline benchmark ile akademik olarak degerlendirilebilir
- Sunumda metrik ve grafiklerle savunulabilir

durumdadir.

Projenin temel degeri; canli ag gorunurlugu, risk skorlama, LLM destekli analiz ve N-BaIoT offline benchmark ciktisini tek bir bitirme projesi kapsaminda birlestirmesidir.
