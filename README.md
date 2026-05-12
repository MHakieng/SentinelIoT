# Sentinel-IoT

SentinelIoT v6; IoT aglarinda cihaz kesfi, servis/CVE gorunurlugu, davranissal anomali sinyali ve aciklanabilir risk analizini birlestiren **Command Center tabanli** bir guvenlik operasyon prototipidir.

Proje bir production IDS/IPS urunu degildir; paket engelleme/otomatik aksiyon alma, sertifikali koruma veya tum ag trafigini garanti etme iddiasi yoktur. Amaç, **görünürlük + kanıt + analist iş akışı** uzerinden savunulabilir bir akademik demo sunmaktir.

N-BaIoT veri seti bu projede **canli sistemin veri kaynagi olarak degil**, yalnizca **offline model dogrulama/benchmark** amaciyla kullanilmistir.

Detayli mimari, veri akisi, endpointler, model dogrulama yaklasimi, demo hazirligi ve bilinen sinirlar icin ana teknik referans:

```text
PROJE_DOKUMANTASYONU.md
```

## Temel Ozellikler

- Network scan ve kalici cihaz envanteri
- Device fingerprinting (heuristic zenginlestirme)
- Nmap script ciktilarindan **CVE gorunurlugu** (CVE ID baglami; CVSS her zaman mevcut degildir)
- Pasif trafik izleme (Scapy) ve 5-tuple flow cikarma
- 6 live numeric feature ile Isolation Forest tabanli **anomali sinyali**
- Servis/CVE gorunurlugu + anomali sinyali ile **hybrid risk scoring**
- React/Vite **SOC-style security operations cockpit**:
  - Command Center
  - Security Event Timeline
  - Device Detail / Analyst Investigation
  - AI Analysis (opsiyonel, grounded)
  - Validation (synthetic/runtime ayrimi)
- Interaktif ag topolojisi (gorsellestirme)
- Offline N-BaIoT benchmark (canli sistem basarisi degildir)

## Mimari

- Backend: FastAPI
- Scanner: Nmap host/service discovery, OUI, SSDP, HTTP title/server header enrichment
- Monitor: Scapy ile paket/flow izleme
- ML: Isolation Forest tabanli anomali sinyali
- Risk Engine: servis/CVE gorunurlugu, port baglami, asset type ve anomali skorunu birlestiren weighted score
- Frontend: React + Vite
- Database: SQLite
- Evaluation: N-BaIoT offline benchmark ve dogrulama scriptleri

## Klasor Yapisi

```text
.
|-- sentinel_iot/
|   |-- api/                 # FastAPI app ve routerlar
|   |-- scanner/             # Ag tarama ve cihaz kesfi
|   |-- monitor/             # Paket izleme ve flow cikarma
|   |-- ml/                  # Anomali modeli yardimcilari
|   |-- database/            # SQLAlchemy modelleri ve DB baglantisi
|   |-- services/            # LLM ve is mantigi servisleri
|   |-- schemas/             # Pydantic semalari
|   |-- tests/               # Backend testleri
|   `-- dashboard/react_app/ # React/Vite dashboard
|-- evaluation/              # Offline dogrulama ve N-BaIoT benchmark scriptleri
|-- docs/                    # Rapor, sunum ve GitHub hazirlik dokumanlari
`-- *.ps1                    # Windows kurulum/calistirma yardimci scriptleri
```

## Gereksinimler

- Python 3.10+
- Node.js 18+
- Nmap
- Windows veya Linux

Packet capture ve active scan islemleri icin isletim sistemine gore yonetici/root yetkisi gerekebilir. Pasif izleme sadece calistigi makinenin gorebildigi trafiği yakalar; switched network, Wi-Fi istemci izolasyonu veya SPAN/mirror olmayan ortamlarda tum ag trafigi gorulemeyebilir.

## Kurulum

Backend bagimliliklari:

```powershell
cd sentinel_iot
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Frontend bagimliliklari:

```powershell
cd sentinel_iot\dashboard\react_app
npm install
```

Alternatif olarak proje kokunden yardimci kurulum scripti calistirilabilir:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

## Calistirma

Backend:

```powershell
cd sentinel_iot
.\.venv\Scripts\activate
uvicorn sentinel_iot.api.main:app --reload
```

Frontend:

```powershell
cd sentinel_iot\dashboard\react_app
npm run dev
```

Dashboard varsayilan olarak `http://127.0.0.1:5173` adresinde acilir. API varsayilan olarak `http://127.0.0.1:8000` adresinde calisir.

Proje kokunden tek komutla calistirma:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_dev.ps1
```

## Kullanim Akisi

1. Backend'i baslat.
2. Frontend'i baslat.
3. Dashboard'u ac (v6 Command Center).
4. **Command Center** uzerinden ag taramasini baslat (scan job).
5. **Security Event Timeline** uzerinden tarama/izleme olaylarini takip et.
6. Bir cihaz secerek **Device Detail / Analyst Investigation** ekraninda servis kanitlarini, risk breakdown'i ve gecmisi incele.
7. Opsiyonelse **AI Analysis** ile (yalnizca mevcut baglam uzerinden) aciklama ve sonraki adim onerilerini al.
8. **Validation** ekraninda:
   - Synthetic Model Validation (etiketli/sentetik dogrulama) metriklerini gor
   - Runtime Detection icin etiket olmadigindan **TP/FP/F1 uretilmedigini** ve `not_available` aciklamasini teyit et.

## LLM Ayari

LLM ozelligi opsiyoneldir. Gercek API key repoya eklenmemelidir.

```powershell
copy .env.example .env
notepad .env
```

`.env` icinde `SENTINEL_LLM_PROVIDER`, `SENTINEL_LLM_API_KEY` ve `SENTINEL_LLM_MODEL` alanlari doldurulabilir. `.env` dosyasi `.gitignore` ile dislanir.

## Offline Evaluation / N-BaIoT Benchmark (Akademik Referans)

N-BaIoT raw dataset, processed dataset ve model dosyalari repoya dahil edilmez. Raw veri seti manuel olarak su klasore yerlestirilmelidir:

```text
evaluation/datasets/raw/n_baiot/
```

Uretilen processed dataset ve model dosyalari su klasorlerde tutulur ve GitHub'a eklenmez:

```text
evaluation/datasets/processed/
evaluation/models/
evaluation/results/
```

N-BaIoT benchmark, canli Sentinel-IoT sistemine dogrudan entegre edilmis bir model degildir. Sadece offline model dogrulama ve akademik benchmark amaciyla kullanilmistir.

Calistirma sirasi:

```powershell
python evaluation/inspect_nbaiot.py
python evaluation/preprocess_nbaiot.py --max-rows-per-file 20000
python evaluation/train_nbaiot_model.py --model random_forest --test-size 0.2
python evaluation/train_nbaiot_attack_split.py
python evaluation/train_nbaiot_device_attack_split.py
python evaluation/train_nbaiot_balanced.py --model random_forest
python evaluation/analyze_nbaiot_feature_leakage.py
python evaluation/compare_nbaiot_models.py
```

## Validation Anlatimi (Dürüst Ayrim)

SentinelIoT'da iki farkli dogrulama katmani vardir ve karistirilmamalidir:

1. **Synthetic Model Validation**: Etiketli/sentetik veya kontrollu dogrulama verisiyle hesaplanan metrikler (akademik dogrulama ciktisi).
2. **Runtime Detection (Canli Cikarim)**: Canli agda etiket olmadigi icin TP/FP/F1 gibi etiketli operasyon basari metrikleri **uretilmez**. `/metrics` endpointi bu durumu `runtime_detection_metrics: null` ve `runtime_metrics_metadata.source: not_available` ile belirtir.

Offline N-BaIoT benchmark sonuclari canli sistem basarisi degildir. Sayisal sonuclar ve genelleme analizi icin:

```text
docs/model_validation_summary.md
docs/slides_model_validation_text.md
```

## Sinirliliklar

- N-BaIoT modeli canli Sentinel-IoT sistemine dogrudan entegre edilmemistir.
- N-BaIoT modeli 115 feature bekler; mevcut canli sistem 6 numeric flow feature uretir.
- Runtime model dosyasi repo disinda tutulur; yeni kurulumda model yoksa runtime anomaly sonucu sinirli kalabilir veya yeniden egitim gerekebilir.
- Packet capture ve Nmap scan islemleri yetki gerektirebilir; Nmap yalnizca izinli/kontrollu aglarda calistirilmalidir.
- Packet capture tum agi garanti etmez; sadece cihaz/interfacenin gorebildigi paketleri yakalar.
- CVE gorunurlugu Nmap script ciktilarina baglidir; CVSS skoru her CVE icin garanti degildir.
- JWT/OAuth2 tabanli kullanici kimlik dogrulama bu asamada kapsam disidir.
- Gercek production deployment yapilmamistir.
- Offline benchmark sonuclari canli ag performansi olarak sunulmamalidir.

## Gelecek Calismalar

- Mevcut 6 live feature ile supervised model egitimi
- N-BaIoT benzeri 115 feature live extractor gelistirme
- Runtime model icin periodic batch retraining akisini daha acik yonetmek
- JWT/OAuth2 kimlik dogrulama
- Docker deployment
- Daha genis gercek ag testleri
- SIEM entegrasyonu

## Test ve Paketleme

Backend test ve frontend build kontrolu:

```powershell
powershell -ExecutionPolicy Bypass -File .\verify_release.ps1
```

Release paketi:

```powershell
powershell -ExecutionPolicy Bypass -File .\package_release.ps1
```

## Lisans

License: TBD. Bu proje akademik/egitsel kullanim icin hazirlanmistir.
