# Security and Deployment Audit

Bu denetim guvenlik, secret yonetimi ve deployment gercekciligini inceler.

## Bulgular

| Alan | Mevcut durum | Risk seviyesi | Oneri |
| --- | --- | --- | --- |
| JWT/Auth | Kodda JWT/OAuth2 yok; README bunu kapsam disi/gelecek calisma olarak belirtiyor. | Low | Korunmali. Dashboard guvenli yerel ag/prototip varsayimiyla anlatilmali. |
| LLM API key | `run_backend.ps1` `.env` dosyasini process env'e aktarir. `.env.example` placeholder icerir. | Low | Uyumlu. Gercek key repoda yok. |
| `.env` ve secrets | `.gitignore` `.env`, `.env.*`, key/pem/credentials dosyalarini disliyor. | Low | Uyumlu. |
| Local DB/dataset/model | `.gitignore` DB, PCAP, CSV, PKL/JOBLIB, N-BaIoT raw/processed/model klasorlerini disliyor. | Low | Uyumlu. |
| Nmap yetkisi | README Nmap gereksinimini ve izinli ag sinirini belirtiyor. | Low | Yetki ve yasal izin vurgusu korunmali. |
| Packet capture yetkisi | `packet_capture.py` PermissionError logluyor; README yetki gerekebilir diyor. | Medium | README'ye switched network/Wi-Fi siniri eklenmeli. |
| Switched network/Wi-Fi siniri | Dokumanda yeterince acik degil. | Medium | "Monitor sadece makinenin gorebildigi trafiği yakalar; switch mirror/SPAN yoksa tum ag trafiği gorulmeyebilir" eklenmeli. |
| Promiscuous mode | Kod explicit promiscuous mode garantisi vermiyor. | Medium | "Promiscuous mode ile tum trafik gorulur" gibi iddialar kullanilmamali. |
| Deployment | Docker/production deployment yok; README bunu belirtiyor. | Low | Uyumlu. |
| HTTPS/TLS/API auth | Local API HTTP calisir; auth yok. | Medium | "Yerel demo/prototip" siniri net tutulmali. |
| LLM output safety | Promptlar LLM'in CVSS/patch/vendor guidance uydurmamasini istiyor. | Low | Uyumlu; yine de LLM ciktilari karar destek olarak sunulmali. |
| Static metrics | `/metrics` statik `real_world_metrics` donduruyor. | High | Guvenlik veya operasyon metrikleri gibi sunulmamali; demo placeholder olarak etiketlenmeli. |

## Deployment Karari

Proje GitHub ve akademik demo icin hazir gorunuyor. Production deployment icin hazir degil; auth, HTTPS, role-based access, secrets management, Docker/infra, network permission model ve real telemetry validation gerektirir.

## Acik Yazilmasi Gereken Sinirliliklar

- Dashboard/API yerel demo varsayimiyla calisir.
- Nmap ve packet capture izinli agda ve gerekli yetkilerle calistirilmalidir.
- Packet capture tum ag trafiğini garanti etmez.
- N-BaIoT benchmark offline dogrulamadir.
- LLM karar verici degil, aciklama/yardimci katmandir.
