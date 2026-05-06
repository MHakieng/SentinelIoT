# Sentinel-IoT Proje Dokumantasyonu

## 1. Projenin Mevcut Asamasi

Sentinel-IoT su anda calisan bir FastAPI + React tabanli IoT ag guvenligi prototipidir. Proje; yerel agdaki cihazlari kesfetme, acik servisleri goruntuleme, canli trafik akislarini izleme, davranissal anomali sinyali uretme, risk skoru hesaplama ve LLM destekli cihaz/CVE analizi sunma asamasina gelmistir.

Bu asamada proje sadece arayuz demosu degil, test ve benchmark ciktisi uretebilen olculebilir bir sistem haline getirilmistir. Backend testleri, frontend build/lint kontrolu, risk engine dogrulamasi, N-BaIoT benchmark calismasi ve canli sistem evaluation altyapisi eklenmistir.

## 2. Projenin Amaci

Sentinel-IoT'un amaci, yerel agdaki IoT cihazlari icin asagidaki guvenlik gorunurlugunu tek bir panelde sunmaktir:

- Cihaz envanteri
- Nmap tabanli ag ve servis taramasi
- Canli paket ve flow izleme
- Anomali tespiti
- Risk skorlama
- Servis/CVE baglami
- LLM destekli cihaz analizi
- Akademik dogrulama ve benchmark ciktisi

Proje, ozellikle bitirme projesi baglaminda "calisan sistem + olculebilir dogrulama" hedefiyle ilerletilmistir.

## 3. Genel Mimari

Proje ana olarak su katmanlardan olusur:

| Katman | Teknoloji / Modul | Gorev |
| --- | --- | --- |
| Backend API | FastAPI | Dashboard ve servisler icin REST API |
| Scanner | Nmap / python-nmap | Yerel ag ve servis kesfi |
| Monitor | Scapy | Canli paket yakalama ve flow feature uretimi |
| ML | scikit-learn | Isolation Forest ve benchmark modelleri |
| Risk Engine | Python servis katmani | Zafiyet ve anomali sinyallerini risk skoruna cevirme |
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
- Runtime durum bilgileri daha kararlı hale getirildi.
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
- CVE baglami varsa risk engine'e tasima
- Dashboard topoloji ve envanter ekranlarini guncelleme

Sinir:

- Proje aktif saldiri araci degildir.
- Taramalar Nmap'in izin verilen ve kontrollu aglarda calistirilmasi gereken servis kesif islemleridir.
- Gercek kurum aglarinda izinsiz kullanilmamalidir.

## 6. Monitor ve Flow Analizi

Monitor tarafi Scapy ile canli paketleri yakalar ve flow bazli feature uretir.

Canli sistemde uretilen temel feature'lar:

```text
packet_count
byte_count
duration
avg_packet_size
mean_iat
var_iat
```

Bu feature'lar dashboard'da canli akislar, paket onizlemesi ve topoloji etkilesimi icin kullanilir. Runtime anomaly model de bu kisa sema uzerinden calisir.

Sinir:

- Canli sistem N-BaIoT veri setindeki 115 feature'li semayi dogrudan uretmez.
- Bu nedenle N-BaIoT supervised modeli canli path'e dogrudan baglanmamistir.
- Canli sistem ile N-BaIoT benchmark akademik olarak ayri degerlendirilir.

## 7. ML ve Anomali Tespiti

Projede iki farkli ML yaklasimi vardir.

### 7.1 Runtime Anomali Modeli

Canli Sentinel-IoT sistemi Isolation Forest tabanli hafif bir runtime anomaly detection yapisi kullanir. Bu model canli flow feature semasina gore calisir.

Amac:

- Canli akislar icin anomali sinyali uretmek
- Risk engine'e anomali bileseni saglamak
- Dashboard'da izleme ve uyarilari gostermek

### 7.2 Offline N-BaIoT Benchmark

N-BaIoT veri seti ile supervised benchmark pipeline kurulmustur. Bu benchmark canli sisteme dogrudan baglanan model degil, ML tarafinin gercek etiketli IoT botnet verisi uzerinde olculebilir basarimini gosteren akademik kanittir.

Calistirilan modeller:

- Random Forest
- Extra Trees
- HistGradientBoosting
- Device Split Random Forest
- Isolation Forest contamination tuning

N-BaIoT processed dataset ozeti:

| Deger | Sonuc |
| --- | ---: |
| Toplam satir | 1,772,641 |
| Feature sayisi | 115 |
| Normal kayit | 172,641 |
| Anomaly kayit | 1,600,000 |

Model karsilastirma ozeti:

| Model | Accuracy | Precision | Recall | F1-score | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Random Forest | 0.999989 | 1.000000 | 0.999988 | 0.999994 | 0.000000 | 0.000012 |
| Extra Trees | 0.999983 | 1.000000 | 0.999981 | 0.999991 | 0.000000 | 0.000019 |
| HistGradientBoosting | 0.999977 | 0.999997 | 0.999978 | 0.999987 | 0.000029 | 0.000022 |
| Device Split RF | 0.998539 | 0.998419 | 0.999993 | 0.999206 | 0.017886 | 0.000007 |
| Isolation Forest 0.15 | 0.985236 | 0.984070 | 0.999827 | 0.991886 | 0.149999 | 0.000172 |

Akademik olarak en guvenilir sunulacak sonuc Device Split RF sonucudur. Cunku random split, ayni cihaza ve saldiri ailesine ait benzer ornekleri train ve test setlerine dagitabilir. Device split ise bazi cihazlari tamamen test setine ayirarak daha gercekci genelleme sinavi yapar.

## 8. Risk Engine

Risk engine, zafiyet ve anomali sinyallerini tek bir risk skoruna cevirir.

Temel formul:

```text
risk = min(100, vulnerability * 0.6 + anomaly * 0.4)
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
- Dogrulama ve Ozet sayfasina akademik benchmark paneli eklendi.

Dogrumlama ve Ozet sayfasinda gosterilen akademik kanitlar:

- N-BaIoT benchmark metrikleri
- Device split sonucu
- Isolation Forest baseline sonucu
- Model comparison grafiği
- Random Forest confusion matrix
- Random split skorunun neden yuksek cikabilecegine dair yorum

## 10. LLM Destekli Analiz

Projede LLM katmani cihaz ve CVE baglami icin aciklama uretmek amaciyla kullanilir.

Yetkinlikler:

- Secilen cihazin risk skorunu aciklama
- Risk bilesenlerini yorumlama
- Anomali gecmisini ozetleme
- Sonraki aksiyon onerileri uretme
- CVE baglaminda daha anlasilir teknik aciklama sunma

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
- Gercek Nmap tabanli cihaz ve servis gorunurlugu
- Canli paket/flow izleme
- Risk engine ile zafiyet ve anomali sinyallerini birlestirme
- LLM destekli cihaz analizi
- Akademik benchmark ve metrik uretimi
- N-BaIoT gibi etiketli IoT botnet veri setiyle supervised model karsilastirmasi
- Device split validation ile daha guvenilir genelleme testi
- Sunuma hazir confusion matrix, model comparison ve feature importance ciktisi
- Windows ortaminda calistirma scriptleri
- `.env.example`, kurulum, dogrulama ve paketleme otomasyonu

## 15. Sinirlar ve Bilincli Tasarim Kararlari

Projenin sinirlari:

- Sistem bir IDS/IPS urunu degil, arastirma ve prototip seviyesinde bir guvenlik gorunurlugu sistemidir.
- Gercek saldiri uretmez.
- N-BaIoT modeli canli sisteme dogrudan baglanmamistir; feature semalari farklidir.
- Canli anomaly modeli daha hafif 6 feature'li flow semasiyla calisir.
- Nmap taramalari kontrollu ve izinli aglarda calistirilmalidir.
- LLM ciktisi karar verici degil, analist yardimcisi olarak konumlandirilmistir.
- Dataset ve model artifact dosyalari buyuk oldugu icin Git/release paketine dahil edilmemelidir.

Bu sinirlar hata degil, projenin akademik olarak dogru konumlandirilmasi icin bilincli ayrimlardir.

## 16. Hocalara Sunumda Nasil Anlatilmali?

Kisa anlatim:

> Sentinel-IoT, yerel agdaki IoT cihazlarini kesfeden, servis gorunurlugu saglayan, canli trafik akisini izleyen, anomali sinyallerini risk skoru ile birlestiren ve LLM destekli analiz sunan bir guvenlik gorunurlugu prototipidir. Proje sadece calisan bir dashboard olarak birakilmamis, risk engine testleri, canli flow toplama altyapisi ve N-BaIoT etiketli veri seti uzerinde offline ML benchmark ile olculebilir hale getirilmiştir.

Vurgulanmasi gereken teknik ayrim:

> Canli sistem runtime monitoring demosudur. N-BaIoT benchmark ise model kapasitesini etiketli IoT botnet verisiyle gosteren offline dogrulama calismasidir. Bu iki katman bilincli olarak ayrilmistir cunku feature semalari farklidir.

One cikarilacak sonuc:

> Random split modelleri cok yuksek F1-score vermektedir; ancak akademik olarak daha guvenilir sonuc Device Split RF sonucudur. Device Split RF, egitimde gorulmeyen cihazlarda F1-score 0.999206 elde etmistir.

## 17. Bundan Sonraki Gelistirme Adimlari

Bir sonraki teknik adimlar:

1. Canli sistem icin daha zengin feature extractor gelistirmek.
2. Canli flow semasi ile supervised model egitmek.
3. N-BaIoT benzeri 115 feature ureten extractor yazmak veya mevcut canli semaya uygun etiketli veri seti olusturmak.
4. Dashboard'da evaluation sonuclarini JSON'dan dinamik okuyan endpoint eklemek.
5. Daha fazla dataset ile karsilastirma yapmak: CICIoT2023, TON_IoT, BoT-IoT.
6. Model drift ve retraining stratejisi eklemek.
7. LLM yanitlari icin daha kapsamli hallucination/groundedness evaluation yapmak.

## 18. Son Durum Ozeti

Sentinel-IoT su anda:

- Calistirilabilir
- Test edilebilir
- Paketlenebilir
- Akademik olarak dogrulanabilir
- Sunumda metrik ve grafiklerle savunulabilir

durumdadir.

Projenin temel degeri; canli ag gorunurlugu, risk skorlama, LLM destekli analiz ve N-BaIoT benchmark kanitini tek bir bitirme projesi kapsaminda birlestirmesidir.
