# SentinelIoT Dashboard

React + Vite tabanli SentinelIoT arayuzu.

## Komutlar

```powershell
npm install
npm run dev
npm run build
npm run lint
npm run check
```

- `npm run dev`: dashboard'u `http://127.0.0.1:5173` uzerinden baslatir.
- `npm run dev:lan`: dashboard'u yerel agdan erisilebilir sekilde baslatir.
- `npm run check`: lint ve production build kontrolunu birlikte calistirir.

API adresi varsayilan olarak `http://127.0.0.1:8000` kabul edilir. Farkli backend adresi icin:

```powershell
$env:VITE_API_BASE_URL="http://127.0.0.1:8000"
npm run dev
```
