# SentinelIoT Calistirma

## Ilk kurulum

```powershell
cd <repo-root>
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Nmap kurulu olmali ve `nmap` komutu PATH uzerinden calismali. Ag taramasi ve zafiyet profilleri buna bagli.

## Tek komutla calistirma

```powershell
cd <repo-root>
powershell -ExecutionPolicy Bypass -File .\run_dev.ps1
```

Bu komut iki PowerShell penceresi acar:

- API: `http://127.0.0.1:8000`
- Dashboard: `http://127.0.0.1:5173`

## LLM API key ayari

API key'i koda yazmayin. Proje kokunde `.env` dosyasi olusturun:

```powershell
copy .env.example .env
notepad .env
```

OpenAI icin:

```text
SENTINEL_LLM_PROVIDER=openai
SENTINEL_LLM_API_KEY=<your_api_key>
SENTINEL_LLM_MODEL=gpt-4o-mini
SENTINEL_LLM_TIMEOUT_SECONDS=20
```

Gemini icin:

```text
SENTINEL_LLM_PROVIDER=gemini
SENTINEL_LLM_API_KEY=<your_api_key>
SENTINEL_LLM_MODEL=gemini-2.0-flash
SENTINEL_LLM_TIMEOUT_SECONDS=20
```

`run_backend.ps1` ve `run_dev.ps1` backend baslarken `.env` dosyasini otomatik yukler. `.env` git'e eklenmez.

## Ayri ayri calistirma

Backend:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_backend.ps1
```

Frontend:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_frontend.ps1
```

## Test ve build

Backend testleri, frontend lint ve production build kontrolu:

```powershell
powershell -ExecutionPolicy Bypass -File .\verify_release.ps1
```

Sadece backend testlerini calistirmak icin:

```powershell
powershell -ExecutionPolicy Bypass -File .\verify_release.ps1 -SkipFrontend
```

Frontend build/lint komutlarini ayri calistirmak icin:

```powershell
cd .\sentinel_iot\dashboard\react_app
npm run check
```

Sadece build almak icin `npm run build`, sadece lint icin `npm run lint` kullanilabilir. Dashboard'u yerel agdan acmak gerekirse `npm run dev:lan` calistirin.

## Paketleme

Teslim paketi olusturmak icin:

```powershell
powershell -ExecutionPolicy Bypass -File .\package_release.ps1
```

Cikti: `release\SentinelIoT-release.zip`

Paket; kaynak kodu, README, calistirma scriptleri, `.env.example`, testler ve model dosyasini icerir. `.env`, `.venv`, `node_modules`, build ciktisi, lokal veritabani ve cache dosyalari dahil edilmez.
