# Sentinel-IoT Detayli Proje Dokumantasyonu

Bu dokuman Sentinel-IoT projesinin final savunma ve rapor surecinde kullanilabilecek ana teknik referansidir. Amaci projenin ne yaptigini, nasil calistigini, hangi sinirlara sahip oldugunu, hangi muhendislik calismalarinin yapildigini ve hangi sonuclarin nasil yorumlanmasi gerektigini tek yerde aciklamaktir.

## 1. Kisa Proje Ozeti

Sentinel-IoT; yerel agdaki IoT ve ag cihazlari icin cihaz kesfi, servis gorunurlugu, pasif trafik izleme, flow tabanli anomali sinyali, risk skorlama, LLM destekli analiz ve React dashboard sunan akademik bir full-stack guvenlik prototipidir.

Proje bir production IDS/IPS urunu degildir. Paket engelleme, saldiri durdurma, sertifikali guvenlik korumasi veya tum ag trafigini garanti etme iddiasi yoktur. Dogru konumlandirma sudur:

```text
Calisan akademik IoT guvenlik gorunurlugu prototipi
+ offline ML benchmark ve model dogrulama calismasi
```

## 2. Projenin Amaci

Projenin ana hedefi, yerel agdaki cihazlari daha gorunur hale getirerek kullaniciya su sorularin cevabini vermektir:

- Agda hangi cihazlar var?
- Bu cihazlarda hangi servisler/acik portlar gorunuyor?
- Nmap script ciktilarinda CVE ID baglami var mi?
- Canli trafikte hangi flow'lar olusuyor?
- Runtime anomaly modeli bu flow'lar icin anomali sinyali uretiyor mu?
- Servis/CVE gorunurlugu ve anomali sinyali birlikte nasil risk skoruna donusuyor?
- Akademik olarak model dogrulamasi hangi veri ve metriklerle yapildi?
- LLM, cihaz ve CVE baglamini kullanarak analiste nasil yardimci olabilir?

Bu hedefler dogrultusunda proje hem calisan bir demo hem de olculebilir dogrulama ciktisi uretebilen bir bitirme projesi haline getirildi.

## 3. Kapsam Disi Alanlar

Asagidaki alanlar bilincli olarak kapsam disi veya gelecek calisma olarak tutuldu:

- Production deployment
- Auth/JWT/OAuth2 kullanici kimlik dogrulamasi
- HTTPS/TLS terminasyonu
- Paket engelleme veya otomatik aksiyon alma
- Gercek saldiri trafigi uretme
- N-BaIoT supervised modelini canli sisteme dogrudan baglama
- Tum ag trafigini garanti ederek yakalama
- CVSS skorunu her CVE icin kesin olarak cikarma
- LLM yanitlarini karar verici mekanizma olarak kullanma

Bu sinirlar projenin eksigi olarak saklanmadi; README, raporlar ve acceptance dokumanlarinda acik sekilde yazildi.

## 4. Genel Mimari

Sentinel-IoT su katmanlardan olusur:

| Katman | Klasor / Modul | Teknoloji | Gorev |
| --- | --- | --- | --- |
| Backend API | `sentinel_iot/api/` | FastAPI | Dashboard ve servisler icin REST API |
| Scanner | `sentinel_iot/scanner/` | Nmap, python-nmap | Cihaz kesfi, servis taramasi, CVE ID gorunurlugu |
| Monitor | `sentinel_iot/monitor/` | Scapy | Paket yakalama, flow olusturma, feature extraction |
| ML Runtime | `sentinel_iot/ml/` | scikit-learn | 6 live feature ile Isolation Forest anomali sinyali |
| Risk Engine | `sentinel_iot/core/risk_engine.py` | Python | Servis/CVE gorunurlugu + anomali sinyalinden risk skoru |
| Database | `sentinel_iot/database/` | SQLite, SQLAlchemy | Cihaz, risk gecmisi, anomali loglari |
| Services | `sentinel_iot/services/` | Python servis katmani | Scanner, monitor, LLM, ML ve job orchestration |
| Dashboard | `sentinel_iot/dashboard/react_app/` | React, Vite | Envanter, topoloji, monitor, metrics, LLM UI |
| Evaluation | `evaluation/` | Python scripts | N-BaIoT benchmark, risk/scanner/model dogrulama |
| Docs | `docs/` | Markdown | Audit, acceptance, sunum ve final rapor metinleri |

## 5. Klasor Yapisi ve Sorumluluklar

```text
.
|-- sentinel_iot/
|   |-- api/                    # FastAPI app, routerlar, dependency injection
|   |-- core/                   # Risk engine gibi cekirdek algoritmalar
|   |-- database/               # SQLAlchemy modelleri ve SQLite yardimcilari
|   |-- dashboard/react_app/    # React/Vite frontend
|   |-- evaluation/             # LLM evaluation harness ve eski lokal evaluation kayitlari
|   |-- ml/                     # Feature schema, anomaly model, dataset generator
|   |-- monitor/                # Packet capture ve flow feature extraction
|   |-- scanner/                # Nmap discovery, service scan, fingerprint enrichment
|   |-- schemas/                # Pydantic response/request semalari
|   |-- services/               # Scanner/monitor/ml/llm orchestration servisleri
|   `-- tests/                  # Backend unit/integration testleri
|-- evaluation/                 # Final ML/evaluation pipeline ve N-BaIoT scriptleri
|-- docs/                       # Audit, acceptance, model validation ve sunum dokumanlari
|-- setup.ps1                   # Windows kurulum otomasyonu
|-- run_backend.ps1             # Backend calistirma
|-- run_frontend.ps1            # Frontend calistirma
|-- run_dev.ps1                 # Backend + frontend birlikte calistirma
|-- verify_release.ps1          # Test/build dogrulama
|-- package_release.ps1         # Release zip paketleme
|-- README.md                   # GitHub ana dokuman
`-- PROJE_DOKUMANTASYONU.md    # Bu detayli proje dokumani
```

## 6. Veri Akisi

### 6.1 Scanner Akisi

1. Kullanici dashboard'dan hedef IP/CIDR ve scan profili secer.
2. Frontend `/scanner/scans` endpointine istek atar.
3. Backend bir scan job olusturur.
4. ScannerService, Nmap host discovery calistirir.
5. Bulunan cihazlar icin servis taramasi yapilir.
6. Servis, port, banner, HTTP title/server header, TLS ve varsa `vulners` script ciktisi toplanir.
7. CVE ID'leri Nmap script text ciktisindan regex ile cekilir.
8. RiskEngine servis/CVE gorunurlugu ve varsa anomali sinyalini kullanarak risk skorunu hesaplar.
9. Cihaz bilgileri SQLite veritabanina yazilir.
10. Dashboard envanter, cihaz detaylari ve topoloji ekranlarini gunceller.

### 6.2 Monitor Akisi

1. Kullanici live monitor baslatir.
2. Backend `/monitor/live/start` ile monitor job olusturur.
3. Scapy `sniff` belirli surelik capture pencereleri calistirir.
4. Paketlerden flow key olusturulur.
5. Flow key kodda 5-tuple seklindedir:

```text
src_ip, dst_ip, src_port, dst_port, protocol
```

6. Her flow icin 6 numeric live feature uretilir:

```text
packet_count
byte_count
duration
avg_packet_size
mean_iat
var_iat
```

7. Runtime Isolation Forest modeli bu feature'lar uzerinden anomali sinyali uretir.
8. Anomali sinyali RiskEngine'e aktarilir.
9. Dashboard paket listesi, flow listesi, topoloji ve anomali ekranlarini gunceller.

### 6.3 LLM Analiz Akisi

1. Kullanici cihaz detayindan guvenlik asistani panelini acar.
2. Frontend LLM endpointine cihaz IP'si ve istenen analiz bolumlerini gonderir.
3. Backend cihaz, risk, servis, CVE ve anomali baglamini toplar.
4. LLM provider ayari `.env` dosyasindan okunur.
5. LLM yaniti cihaz riski, anomali ozeti ve sonraki aksiyon onerileri olarak UI'da gosterilir.

LLM yanitlari karar verici degildir; analiste yardimci aciklama olarak konumlandirilir.

## 7. Backend API

Onemli endpoint gruplari:

| Endpoint | Amac |
| --- | --- |
| `GET /` | API durum ve versiyon ozeti |
| `GET /health` | API, DB ve LLM konfigurasyon saglik ozeti |
| `GET /devices` | Cihaz envanteri |
| `GET /devices/{ip}` | Tek cihaz detayi |
| `GET /devices/{ip}/history` | Risk gecmisi |
| `GET /devices/{ip}/anomalies` | Anomali loglari |
| `POST /scanner/scans` | Yeni scan job baslatma |
| `GET /scanner/status` | Scanner runtime status |
| `GET /scanner/jobs` | Son scan job ozeti |
| `GET /scanner/jobs/{job_id}` | Job detaylari |
| `GET /monitor/packets` | Son paket snapshot'i |
| `GET /monitor/flows` | Son flow snapshot'i |
| `GET /monitor/history` | Trafik gecmisi |
| `GET /monitor/topology` | Topoloji nodes/links |
| `POST /monitor/live/start` | Live monitor baslatma |
| `GET /monitor/live/status` | Live monitor runtime status |
| `POST /monitor/live/stop` | Live monitor durdurma |
| `GET /metrics` | Runtime model metric status ve synthetic training metric ozeti |
| `POST /train` | PCAP dosyasindan runtime model egitimi |
| `GET /llm/status` | LLM konfigurasyon durumu |
| `POST /llm/device-analysis` | Cihaz baglamli LLM analizi |
| `POST /llm/cve-explanation` | CVE baglamli LLM aciklamasi |

### /metrics Davranisi

`/metrics` endpointi canli sistem icin TP/FP/F1 gibi etiketli operasyon basari metrikleri uretmez. Bunun nedeni bu metriklerin etiketli canli olay gerektirmesidir.

Mevcut guvenli davranis:

```json
{
  "runtime_detection_metrics": null,
  "runtime_metrics_metadata": {
    "source": "not_available",
    "is_placeholder": false,
    "note": "Runtime TP/FP/F1 metrics require labelled production events and are not available in this prototype."
  }
}
```

Bu sayede statik demo degerler gercek operasyon basarisi gibi sunulmaz.

### /health Davranisi

`/health` endpointi local SQLite absolute path dondurmez. Yalnizca ozet durum dondurur:

```json
{
  "database": {
    "database_status": "connected",
    "database_type": "sqlite",
    "path_exposed": false
  }
}
```

## 8. Scanner Tasarimi

Scanner tarafinda iki ana dosya vardir:

- `sentinel_iot/scanner/network_scan.py`
- `sentinel_iot/scanner/vulnerability_scan.py`

Host discovery Nmap ile yapilir. Varsayilan local network tespiti local IP'nin son oktetini `.0/24` yapar; farkli subnetler icin kullanici hedef aralik girebilir.

Servis taramasinda Nmap profilleri kullanilir. Vulnerability profili su scriptleri calistirabilir:

```text
banner,http-title,http-headers,ssl-cert,vulners
```

CVE gorunurlugu Nmap script ciktisina baglidir. Kod CVE ID'lerini regex ile yakalar; her CVE icin CVSS skoru garanti edilmez. RiskEngine dict formatli CVE item'larinda CVSS benzeri alan varsa kullanir, yoksa o path icin fallback uygulayabilir. Scanner string CVE listesi ile CVSS fallback ayrimi dokumante edilmis ve gelecek test konusu olarak birakilmistir.

## 9. Device Fingerprinting

Device fingerprinting zenginlestirme amaciyla kullanilir. Kaynaklar:

- Nmap vendor/hostname
- MAC OUI lookup
- SSDP response bilgisi
- HTTP title
- HTTP Server header
- Servis banner bilgisi

Bu mekanizma heuristic zenginlestirme saglar; kesin vendor/model tespiti garantisi vermez.

## 10. Monitor ve Feature Extraction

Canli sistemin model girdisi 6 numeric feature ile sinirlidir:

| Feature | Aciklama |
| --- | --- |
| `packet_count` | Flow icindeki paket sayisi |
| `byte_count` | Flow icindeki toplam byte |
| `duration` | Flow suresi |
| `avg_packet_size` | Ortalama paket boyutu |
| `mean_iat` | Paketler arasi ortalama zaman |
| `var_iat` | Paketler arasi zaman varyansi |

UI icin IP, port, protocol ve flow id gibi metadata da tasinir; bunlar model feature'i degildir.

Packet capture sinirlari:

- Admin/root yetkisi gerekebilir.
- Sadece calisan interface'in gorebildigi trafik yakalanir.
- Switched network, Wi-Fi client isolation veya SPAN/mirror olmayan ortamlarda tum ag trafigi gorulmeyebilir.
- Capture bos donebilir; bu durumda sistem crash etmemeli, bos state ile devam etmelidir.

## 11. Runtime ML Modeli

Runtime model `sentinel_iot/ml/anomaly_model.py` icinde bulunur.

Teknik ozellikler:

- Model: `IsolationForest`
- Normalizasyon: `StandardScaler`
- Feature schema: `sentinel_iot/ml/feature_schema.py`
- Feature sayisi: 6 live numeric feature
- NaN/inf temizligi: training ve inference tarafinda ele alinir
- Model artefact yoksa crash yerine normal/0 skor davranisi vardir
- Anomaly score 0-1 araligina clamp edilir

Runtime modelin amaci canli flow icin anomali sinyali uretmektir. Bu model, N-BaIoT supervised benchmark modeliyle ayni sey degildir.

## 12. N-BaIoT Offline Benchmark

N-BaIoT, Sentinel-IoT'un canli veri kaynagi degildir. Offline benchmark ve akademik dogrulama icin kullanilan etiketli IoT botnet veri setidir.

N-BaIoT pipeline dosyalari `evaluation/` altindadir:

| Script | Gorev |
| --- | --- |
| `inspect_nbaiot.py` | Raw CSV dosyalarini inceler |
| `preprocess_nbaiot.py` | Binary processed dataset uretir |
| `train_nbaiot_model.py` | Random Forest, Extra Trees, HistGradientBoosting egitir |
| `train_nbaiot_device_split.py` | Cihaz bazli split testi |
| `train_nbaiot_attack_split.py` | Saldiri ailesi split testi |
| `train_nbaiot_device_attack_split.py` | Cihaz + saldiri ailesi split testi |
| `train_nbaiot_balanced.py` | Dengeli benchmark |
| `analyze_nbaiot_feature_leakage.py` | Feature leakage / tek feature analizi |
| `tune_nbaiot_isolation_forest.py` | Isolation Forest contamination tuning |
| `compare_nbaiot_models.py` | Model karsilastirma tablosu ve grafikleri |

### Bilinen Sonuclar

| Deney | F1-score | Yorum |
| --- | ---: | --- |
| Random Forest random split | 0.999994 | Model kapasitesini gosterir; tek basina genelleme kaniti degildir. |
| Balanced RF | 0.999913 | Sinif dengesi azaltildiginda ayrimin korundugunu gosterir. |
| Device Split RF | 0.999206 | Cihaz ayrimi testidir; saldiri ailesi genellemesini tek basina olcmez. |
| Attack Split RF average | 0.803536 | Gormedigi saldiri ailesinde daha gercekci siniri gosterir. |
| Device + Attack Split RF average | 0.806298 | Daha zor genelleme testidir. |
| Isolation Forest best | 0.991886 | Unsupervised baseline; FPR 0.149999 ile birlikte yorumlanmalidir. |

Leakage supheli feature:

```text
HH_jit_L0.01_mean
single-feature F1: 0.958079
```

Bu feature'in tek basina yuksek sonuc vermesi, dataset'e ozgu guclu sinyal riskini gosterir. Feature silinmedi; analiz ve rapor bulgusu olarak tutuldu.

### 115 Feature vs 6 Live Feature Ayrimi

N-BaIoT benchmark 115 numeric feature kullanir. Canli Sentinel-IoT runtime sistemi ise 6 numeric live feature uretir. Bu nedenle N-BaIoT modeli canli sisteme dogrudan entegre edilmedi.

Canli entegrasyon icin iki teknik yol vardir:

1. N-BaIoT benzeri 115 feature ureten live extractor gelistirmek.
2. Mevcut 6 live feature ile ayri etiketli veri toplayip supervised model egitmek.

## 13. Risk Engine

RiskEngine `sentinel_iot/core/risk_engine.py` icindedir.

Temel sozlesme:

- CVSS-like vulnerability input 0-10 araligindadir.
- Anomaly score 0-1 araligindadir.
- Final risk 0-100 araligina clamp edilir.
- Sonuc status alanina donusturulur: Safe, Medium Risk, High Risk, Critical Risk.

Basit base formul:

```text
risk_base = vulnerability * 0.6 + anomaly * 0.4
```

Kodda ek baglamsal etkiler de vardir:

- Kritik port modifier'lari
- Asset type multiplier
- Anomaly confidence
- CVE/CVSS baglami
- Acik port sayisi

Risk engine testleri `sentinel_iot/tests/test_risk_engine.py` ve `evaluation/validate_risk_engine.py` ile desteklenir.

## 14. Dashboard

SentinelIoT v6 dashboard'u klasik bir "genel dashboard" yaklasimindan ziyade **SOC-style security operations cockpit** olarak kurgulanmistir. Ana anlatim/akış su sekildedir:

```text
Command Center → Security Event Timeline → Device Detail / Analyst Investigation → AI Analysis → Validation
```

### v6 Ana Ekranlar

- **Command Center**: Topoloji ozetleri, scan/monitor durumlari, canli akis snapshot'lari ve metrik ozetlerini tek operasyon panelinde toplar.
- **Security Event Timeline**: Scan job, monitor runtime ve cihaz kanitlarini "olay" olarak toplayip analist akisini hizlandirir.
- **Device Detail / Analyst Investigation**: Secili cihazin servis kanitlari (port/banner/http title/tls/cve listesi), risk breakdown'i, risk gecmisi ve anomali loglarini tek sayfada analist odakli duzende sunar.
- **AI Analysis (opsiyonel)**: Cihaza ozel "grounded" aciklama ve sonraki adim onerileri uretir; serbest sohbet veya karar verici mekanizma degildir.
- **Validation**: Synthetic Model Validation ile Runtime Detection ayrimini tek ekranda ve durust sinirlarla gosterir.

### Frontend v6 Yapisi (Okunabilirlik + Anlatim)

Frontend icinde v6 anlatimini tasiyan ana yapilar:

- `sentinel_iot/dashboard/react_app/src/components/command/CommandCenterView.jsx`
- `sentinel_iot/dashboard/react_app/src/components/command/SecurityEventTimeline.jsx`
- `sentinel_iot/dashboard/react_app/src/components/command/eventTimelineUtils.js`
- `sentinel_iot/dashboard/react_app/src/components/DeviceDetailView.jsx` (analyst investigation layout)
- `sentinel_iot/dashboard/react_app/src/components/MetricsView.jsx` (synthetic/runtime ayrimi)

### Onemli UI/UX Kararlari (Durustluk ve Empty State)

- UI, "operasyon basarisi" gibi gorunebilecek **sahte runtime metrikleri** gostermez. Etiketli canli olay olmadigi icin Runtime Detection metrikleri **uretmez**; bu durum `Runtime Metrics Status` / `not_available` aciklamasi ile sunulur.
- Topoloji ve timeline ekranlari veri yokken **empty state** gosterir; bos capture/scan durumlari crash yerine bos state ile yonetilir.
- Device Detail secili cihaz yokken acilmaz; analist akisi cihaz secimine dayanir.
- Offline benchmark (N-BaIoT) sayisal sonuclari, canli runtime cikarim metrikleri ile **karistirilmaz**; offline referans olarak ayrica konumlandirilir.

## 15. LLM Katmani

LLM katmani opsiyoneldir. `.env` dosyasi ile ayarlanir:

```text
SENTINEL_LLM_PROVIDER=
SENTINEL_LLM_API_KEY=
SENTINEL_LLM_MODEL=
SENTINEL_LLM_TIMEOUT_SECONDS=20
```

Gercek API key repoya eklenmez. `.env.example` sadece placeholder icerir.

LLM analizleri:

- Cihaz riskini aciklar
- Risk bilesenlerini yorumlar
- Varsa CVE baglamini kullanir
- Sonraki aksiyon onerileri uretir
- Eksik veri varsa warning ile belirtir

## 16. Evaluation ve Dogrulama Ciktilari

Evaluation klasoru iki ana amaca hizmet eder:

1. Sentinel-IoT runtime model/risk/scanner dogrulama altyapisi.
2. N-BaIoT offline benchmark pipeline.

Uretilen buyuk dataset/model/result dosyalari Git'e eklenmez. Kucuk sunum gorselleri ve ozet tablolar `docs/evaluation_results/` altinda tutulabilir.

Onemli dokumanlar:

| Dosya | Amac |
| --- | --- |
| `docs/model_validation_summary.md` | Model dogrulama ve genelleme analizi |
| `docs/slides_model_validation_text.md` | Slayta uygun kisa metinler |
| `docs/final_acceptance_test_report.md` | Final QA/acceptance raporu |
| `docs/demo_readiness_checklist.md` | Demo gunu kontrol listesi |
| `docs/remaining_risks_before_defense.md` | Savunma oncesi kalan riskler |
| `docs/final_project_technical_audit.md` | Teknik audit karari |
| `docs/algoritma_raporu.md` | Kodla uyumlu algoritma raporu |

## 17. Kurulum

Onerilen kurulum:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Manuel backend kurulumu:

```powershell
cd sentinel_iot
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Manuel frontend kurulumu:

```powershell
cd sentinel_iot\dashboard\react_app
npm install
```

Nmap sistemde kurulu ve PATH'te olmalidir:

```powershell
nmap --version
```

## 18. Calistirma

Backend:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_backend.ps1
```

Frontend:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_frontend.ps1
```

Backend + frontend birlikte:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_dev.ps1
```

Adresler:

```text
API:       http://127.0.0.1:8000
API Docs:  http://127.0.0.1:8000/docs
Frontend:  http://127.0.0.1:5173
```

## 19. Test ve Build

Backend testleri:

```powershell
.\sentinel_iot\.venv\Scripts\python.exe -m pytest --basetemp=.pytest_tmp
```

Evaluation compile:

```powershell
.\sentinel_iot\.venv\Scripts\python.exe -m compileall -q evaluation
```

Frontend build:

```powershell
cd sentinel_iot\dashboard\react_app
npm run build
```

Son dogrulama sonucu:

```text
Backend: 66 passed, 3 skipped
Frontend build: passed
Evaluation compile: passed
```

Vite build chunk size warning verebilir. Bu teslimi engelleyen hata degildir; gelecek calismada code splitting ile iyilestirilebilir.

## 20. Paketleme ve GitHub Hazirligi

Release paketi:

```powershell
powershell -ExecutionPolicy Bypass -File .\package_release.ps1
```

Git'e eklenmemesi gerekenler:

- `.env`
- `.venv`
- `node_modules`
- `*.db`
- `*.pcap`
- `evaluation/datasets/raw/`
- `evaluation/datasets/processed/`
- `evaluation/models/`
- `evaluation/results/`
- `*.pkl`, `*.joblib`

Bu kurallar `.gitignore` icinde tanimlidir.

## 21. Guclu Taraflar

- Uctan uca FastAPI + React mimarisi calisiyor.
- Scanner, monitor, risk engine, ML runtime, dashboard ve LLM katmani ayni projede birlesti.
- Nmap ve Scapy gibi gercek araclarla calisan ag gorunurlugu var.
- Runtime feature schema merkezi tanimlandi.
- Risk engine testlerle dogrulandi.
- N-BaIoT benchmark random split ile sinirli kalmadi; device split, attack split, device+attack split ve leakage analizi eklendi.
- Acceptance test raporlari ve demo checklist hazirlandi.
- Repo temizligi yapildi; dataset/model/secret dosyalari Git'e alinmiyor.

## 22. Bilinen Sinirlar

- Canli runtime TP/FP/F1 metrikleri yoktur; etiketli canli olay gerektirir.
- Runtime model 6 live feature kullanir; N-BaIoT supervised model 115 feature kullanir.
- N-BaIoT modeli canli sisteme dogrudan bagli degildir.
- Packet capture tum agi garanti etmez.
- Nmap ve packet capture yetki gerektirebilir.
- CVE/CVSS ciktilari Nmap scriptlerine baglidir.
- Auth/JWT/OAuth2 yoktur.
- Production deployment yapilmamistir.
- LLM yanitlari analist yardimcisidir, otomatik karar mekanizmasi degildir.

## 23. Final Savunma Icin Anlatim

Kisa savunma metni:

> Sentinel-IoT, yerel agdaki IoT cihazlarini kesfeden, servis gorunurlugu saglayan, canli flow metrikleri ureten ve bu sinyalleri risk skoru ile birlestiren akademik bir guvenlik gorunurlugu prototipidir. Canli sistem 6 numeric flow feature ile runtime Isolation Forest anomali sinyali uretir. N-BaIoT ise canli sisteme dogrudan bagli olmayan, etiketli IoT botnet verisi uzerinde yapilmis offline ML benchmark calismasidir. Random split sonuclari model kapasitesini, attack split ve device+attack split sonuclari ise genelleme sinirlarini gostermek icin kullanilmistir.

Mutlaka soylenmesi gereken ayrim:

```text
Canli sistem basarisi != N-BaIoT offline benchmark basarisi
```

## 24. Gelecek Calismalar

1. Canli sistem icin etiketli veri toplama ve runtime TP/FP/F1 hesaplama.
2. Mevcut 6 live feature ile supervised model egitimi.
3. N-BaIoT benzeri 115 feature live extractor gelistirme.
4. Scanner CVE semasini CVSS bilgisiyle daha net normalize etme.
5. JWT/OAuth2, HTTPS ve deployment altyapisi.
6. Docker tabanli calistirma.
7. SIEM entegrasyonu.
8. Daha genis gercek ag testleri.
9. LLM groundedness/hallucination evaluation kapsamını genisletme.
10. Frontend code splitting ve performans iyilestirme.

## 25. Son Durum

Sentinel-IoT final savunma icin su durumda:

- Calistirilabilir
- Test edilebilir
- Paketlenebilir
- Dokumante edilmis
- Audit ve acceptance raporlari hazir
- Offline benchmark sonuclari sunuma hazir
- Sinirlilikleri acikca belirtilmis

Aktif acceptance FAIL kalmamistir. Kalan noktalar warning veya gelecek calisma niteligindedir.
