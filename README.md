# Sentinel-IoT

Sentinel-IoT; IoT aglari icin cihaz kesfi, servis/zafiyet gorunurlugu, pasif trafik analizi, ML tabanli anomali sinyali, risk skorlama ve React dashboard sunan akademik bir full-stack guvenlik prototipidir.

N-BaIoT veri seti bu projede canli sistemin veri kaynagi olarak degil, offline model dogrulama ve benchmark amaciyla kullanilmistir.

## Temel Ozellikler

- Network scan ve cihaz envanteri
- Device fingerprinting
- Nmap script ciktilarindan CVE gorunurlugu
- Passive traffic monitoring
- Flow-based feature extraction
- Isolation Forest anomali sinyali
- Servis/CVE gorunurlugu + anomaly agirlikli hybrid risk scoring
- React/Vite dashboard
- Interaktif ag topolojisi
- N-BaIoT offline evaluation benchmark

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
uvicorn api.main:app --reload
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
3. Dashboard'u ac.
4. Scanner sayfasindan hedef ag veya IP icin scan baslat.
5. Envanter ve cihaz detaylarini incele.
6. Topoloji ekraninda ag yapisini kontrol et.
7. Monitor/anomaly tarafinda flow ve risk bilgilerini takip et.

## LLM Ayari

LLM ozelligi opsiyoneldir. Gercek API key repoya eklenmemelidir.

```powershell
copy .env.example .env
notepad .env
```

`.env` icinde `SENTINEL_LLM_PROVIDER`, `SENTINEL_LLM_API_KEY` ve `SENTINEL_LLM_MODEL` alanlari doldurulabilir. `.env` dosyasi `.gitignore` ile dislanir.

## Evaluation / N-BaIoT Benchmark

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

## Model Dogrulama Ozeti

Bu sonuclar offline N-BaIoT benchmark sonucudur; canli Sentinel-IoT sistem basarisi olarak yorumlanmamalidir.

| Deney | F1-score |
| --- | ---: |
| Random Split RF | 0.999994 |
| Device Split RF | 0.999206 |
| Attack Split Ortalama | 0.803536 |
| Device + Attack Split Ortalama | 0.806298 |
| Isolation Forest Best | 0.991886 |

Leakage supheli feature: `HH_jit_L0.01_mean`.

Canli Sentinel-IoT runtime modeli 6 numeric flow feature kullanir: `packet_count`, `byte_count`, `duration`, `avg_packet_size`, `mean_iat`, `var_iat`. N-BaIoT benchmark modelleri ise 115 numeric feature uzerinde egitilmistir. Bu nedenle N-BaIoT modeli dogrudan canli sisteme baglanmamistir.

`/metrics` endpointi canli sistem icin TP/FP/F1 gibi etiketli operasyon basari metrikleri uretmez. Bu metrikler etiketli canli olay gerektirir; prototipte bu alan `runtime_detection_metrics: null` ve `source: not_available` metadata ile doner. Offline N-BaIoT benchmark sonuclari ayri tutulur ve canli sistem basarisi olarak yorumlanmamalidir.

Detayli analiz icin:

```text
docs/model_validation_summary.md
docs/slides_model_validation_text.md
docs/evaluation_results/
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
