# Demo Readiness Checklist

## Demo Oncesi Teknik Kontrol

- [ ] Repo kokunde calistigini dogrula:
  ```powershell
  git status --short
  ```
- [ ] `.env` dosyasi varsa gercek API key Git'e staged degil.
- [ ] Raw/processed N-BaIoT datasetleri staged degil:
  ```powershell
  git status --ignored evaluation\datasets evaluation\models
  ```
- [ ] Backend sanal ortami var:
  ```powershell
  Test-Path .\sentinel_iot\.venv\Scripts\python.exe
  ```
- [ ] Backend testleri repo ici temp ile geciyor:
  ```powershell
  $env:TMP="$PWD\.pytest-tmp"; $env:TEMP=$env:TMP
  .\sentinel_iot\.venv\Scripts\python.exe -m pytest --basetemp .pytest-tmp\base -o cache_dir=.pytest-tmp\cache
  ```
- [ ] Evaluation scriptleri compile oluyor:
  ```powershell
  .\sentinel_iot\.venv\Scripts\python.exe -m compileall -q evaluation
  ```
- [ ] Frontend build geciyor:
  ```powershell
  cd sentinel_iot\dashboard\react_app
  npm run build
  cd ..\..\..
  ```

## Backend Demo Kontrolu

- [ ] Backend basliyor:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\run_backend.ps1
  ```
- [ ] API aciliyor:
  ```text
  http://127.0.0.1:8000/docs
  ```
- [ ] `/health` 200 donuyor.
- [ ] `/devices` 200 donuyor.
- [ ] `/scanner/status` 200 donuyor.
- [ ] `/monitor/live/status` 200 donuyor.
- [ ] `/metrics` `real_world_metrics` dondurmuyor; runtime TP/FP/F1 alanlari etiketli canli olay olmadigi icin `not_available` olarak anlatiliyor.

## Frontend Demo Kontrolu

- [ ] Frontend basliyor:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\run_frontend.ps1
  ```
- [ ] Dashboard aciliyor:
  ```text
  http://127.0.0.1:5173
  ```
- [ ] Envanter sayfasi bos veya dolu durumda bozulmuyor.
- [ ] Topoloji sayfasi bos veriyle bozulmuyor.
- [ ] Device detail secimi calisiyor.
- [ ] Scan loading/error state gorunuyor.
- [ ] Dogrulama ve Ozet sayfasinda N-BaIoT offline benchmark olarak anlatiliyor.

## Scanner Demo Kontrolu

- [ ] Nmap kurulu:
  ```powershell
  nmap --version
  ```
- [ ] Nmap PATH'te.
- [ ] Demo aginda tarama izni var.
- [ ] Kisa hedef araligi secildi.
- [ ] Scan fallback plani hazir:
  - Onceki DB kayitlari.
  - Screenshot/grafik.
  - N-BaIoT offline benchmark sayfasi.
- [ ] Bos scan sonucunda "cihaz bulunamadi / envanter bos" anlatimi hazir.

## Monitor Demo Kontrolu

- [ ] Gerekirse PowerShell/terminal admin olarak acildi.
- [ ] Dogru network interface secimi kontrol edildi.
- [ ] Packet capture tum agi garanti etmez siniri savunmada soyleniyor.
- [ ] Live monitor bos donerse fallback anlatim hazir:
  - "Bu ortamda interface'in gordugu trafik sinirli olabilir."
  - "Offline benchmark ve test suite sistemin dogrulama kismidir."

## Evaluation / N-BaIoT Demo Kontrolu

- [ ] N-BaIoT raw dataset Git'e ekli degil.
- [ ] Processed dataset Git'e ekli degil.
- [ ] Model PKL/JOBLIB Git'e ekli degil.
- [ ] Sunumda kullanilacak kucuk gorseller `docs/evaluation_results/` altinda hazir.
- [ ] Sonuclar su sekilde anlatiliyor:
  - Random Split RF F1: `0.999994` = model kapasitesi.
  - Balanced RF F1: `0.999913` = sinif dengesi azaltildiginda ayrim.
  - Device Split RF F1: `0.999206` = cihaz ayrimi testi.
  - Attack Split RF average F1: `0.803536` = yeni saldiri ailesi genelleme siniri.
  - Device + Attack Split RF average F1: `0.806298` = daha zor genelleme siniri.
  - Isolation Forest best F1: `0.991886` = unsupervised baseline.
  - Leakage suspect: `HH_jit_L0.01_mean`, single-feature F1 `0.958079`.
- [ ] N-BaIoT modeli canli sisteme entegre edilmis gibi anlatilmiyor.
- [ ] 115 N-BaIoT feature / 6 live feature ayrimi acik soyleniyor.

## Savunma Dili

- [ ] "Production-ready urun" denmiyor.
- [ ] "Tum ag trafigini gorur" denmiyor.
- [ ] "N-BaIoT modeli canli sistemde calisiyor" denmiyor.
- [ ] "Random split sonucu canli sistem basarisidir" denmiyor.
- [ ] "CVE/CVSS her zaman kesin cikarilir" denmiyor.
- [ ] "Bu proje akademik prototip + offline benchmark calismasi" olarak konumlandiriliyor.
