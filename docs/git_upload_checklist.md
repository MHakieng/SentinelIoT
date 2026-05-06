# GitHub Yukleme Kontrol Listesi

Bu kontrol listesi Sentinel-IoT reposunu GitHub'a yuklemeden once kullanilmalidir.

## Yukleme Oncesi Kontrol

- `.gitignore` dosyasinin aktif oldugunu kontrol et.
- `.env` dosyasi staged olmamali.
- Sanal ortam klasorleri staged olmamali: `.venv/`, `venv/`, `env/`.
- `node_modules/`, `dist/`, `build/` staged olmamali.
- Dataset ve model artefaktlari staged olmamali:
  - `evaluation/datasets/raw/`
  - `evaluation/datasets/processed/`
  - `evaluation/models/`
  - `*.pkl`
  - `*.joblib`
- Local database ve capture dosyalari staged olmamali:
  - `*.db`
  - `*.sqlite`
  - `*.pcap`
  - `*.pcapng`
- N-BaIoT sonuclari README'de offline benchmark olarak anlatilmali; canli sistem basarisi gibi sunulmamali.

## Kontrol Komutlari

```powershell
git status
git add .
git status
```

`git status` ciktisinda dataset, model, `.env`, veritabani, pcap veya `node_modules` gorunuyorsa commit atma. Once `.gitignore` veya staged dosyalari duzelt.

## Commit ve Push

```powershell
git commit -m "Prepare Sentinel-IoT final project repository"
git branch -M main
git remote add origin <repo-url>
git push -u origin main
```

Eger remote daha once eklenmisse:

```powershell
git remote -v
git remote set-url origin <repo-url>
git push -u origin main
```

## Son Manuel Kontrol

- GitHub'da `.env` gorunmuyor.
- GitHub'da raw/processed N-BaIoT datasetleri gorunmuyor.
- GitHub'da `.pkl`, `.joblib`, `.db`, `.pcap`, `.pcapng` dosyalari gorunmuyor.
- README kurulum ve calistirma komutlari relative path kullaniyor.
- `docs/evaluation_results/` sadece kucuk rapor gorselleri ve ozet CSV dosyalari iceriyor.
