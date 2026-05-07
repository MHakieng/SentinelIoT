# Final Acceptance Criteria

Bu belge Sentinel-IoT final teslimi oncesi kabul kriterlerini ve kontrol yontemlerini listeler. Sonuclar `docs/final_acceptance_test_report.md` icindeki gercek kosum bulgulariyla birlikte okunmalidir.

| Kategori | Kriter | Beklenen durum | Kontrol yöntemi | Sonuç | Risk | Öneri |
| --- | --- | --- | --- | --- | --- | --- |
| Repo / kurulum | README backend kurulum komutlari | Sanal ortam ve `requirements.txt` kurulumu calismali | README ve import kontrolu | Passed | Low | Script tabanli `setup.ps1` onerisi korunmali |
| Repo / kurulum | README frontend kurulum komutlari | `npm install` ve `npm run dev/build` yolu dogru olmali | README ve package.json kontrolu | Passed | Low | Mevcut hali yeterli |
| Repo / kurulum | `.env.example` | Secret icermeyen placeholder konfigurasyon olmali | Dosya icerigi kontrolu | Passed | Low | Gercek key eklenmemeli |
| Repo / kurulum | `.gitignore` kritik yerel dosyalari dislar | `.env`, `.venv`, `node_modules`, DB, PCAP, evaluation datasets/models dislanmali | `.gitignore` ve ignored status kontrolu | Passed | Low | Kural korunmali |
| Backend API | FastAPI app import edilebilir | Import crash olmamali | `import sentinel_iot.api.main` | Passed | Low | Yok |
| Backend API | Health endpoint | `/health` 200 JSON donmeli ve local path sizdirmamali | TestClient GET `/health` | Passed | Low | `path_exposed=false` |
| Backend API | Temel endpointler | `/devices`, `/metrics`, `/scanner/status`, `/monitor/live/status`, `/monitor/flows`, `/monitor/topology` 200 donmeli | TestClient GET kontrolleri | Passed | Low | Yok |
| Backend API | `/metrics` statik veri kullanimi | Demo/statik metrikler gercek operasyon metrigi gibi sunulmamali | `MLService.get_metrics()` ve TestClient `/metrics` | Passed | Low | `real_world_metrics` kaldirildi; runtime TP/FP/F1 `not_available` metadata ile donuyor |
| Scanner | Nmap bagimliligi kontrolu | Nmap yoksa erken, anlasilir hata olmali | `ensure_nmap_available()` kod inceleme | Passed | Low | Yok |
| Scanner | CVE extraction | String/dict CVE semasi risk engine ile tutarli olmali | Scanner + RiskEngine inceleme | Warning | Medium | Scanner string CVE ile CVSS fallback path'i entegrasyon testi eklenmeli |
| Monitor | Live start/stop akisi | Start/status/stop endpointleri olmali | Route listesi ve router inceleme | Passed | Low | Yok |
| Monitor | Packet capture sinirlari | Tum trafik garantisi verilmemeli | README/PROJE docs kontrolu | Passed | Low | Yok |
| ML runtime | Live feature schema | 6 numeric feature olmali | `FEATURE_SCHEMA` kontrolu | Passed | Low | Yok |
| ML runtime | StandardScaler + IsolationForest | Training/inference akisi bu ikisini kullanmali | `anomaly_model.py` inceleme | Passed | Low | Yok |
| ML runtime | Runtime TP/FP/F1 | Etiketli canli olay yoksa unavailable olmali | `/metrics` smoke test | Passed | Low | Etiketli veri olmadan metrik uretilmiyor |
| Risk engine | Risk 0-100 | Skor clamp edilmeli | Tests + code | Passed | Low | Yok |
| Frontend | Build | `npm run build` basarili olmali | Komut kosumu | Passed | Low | Chunk size warning var |
| Frontend | Runtime metrics statik veri | UI gercek sanabilecegi statik operasyon metriklerini gostermemeli | App.jsx + `/metrics` | Passed | Low | `Runtime Metrics Status` empty state etiketli canli veri gereksinimini acikliyor |
| Frontend | Runtime vs offline ayrimi | Offline N-BaIoT canli basari gibi sunulmamali | App.jsx ve docs | Passed | Low | Metin korunmali |
| Evaluation | Raw/processed dataset Git'te yok | Dataset klasorleri ignored olmali | `git status --ignored` | Passed | Low | Yok |
| Evaluation | Offline benchmark ayrimi | N-BaIoT canli sistem degil diye aciklanmali | README/docs/UI kontrolu | Passed | Low | Yok |
| Evaluation | 115 vs 6 feature ayrimi | Net yazilmali | README/docs kontrolu | Passed | Low | Yok |
| Evaluation | Random split yorumu | Canli sistem basarisi gibi sunulmamali | Docs/UI kontrolu | Passed | Low | Yok |
| Test | Pytest | Test suite gecmeli | Repo ici basetemp ile pytest | Passed | Low | Standart temp izni sorunu olursa `--basetemp` kullanilmali |
| Test | Py_compile/compile | Evaluation scriptleri compile olmali | `compileall -q evaluation` | Passed | Low | Windows'ta wildcard yerine compileall onerilir |
| Test | Frontend build | Build basarili olmali | `npm run build` | Passed | Low | Chunk warning var |
| Docs | Local path | Dokumanda veya health response'ta local path olmamali | `rg` ve TestClient kontrolu | Passed | Low | `/health` local path sizintisi kapatildi |
| Deployment | Auth/JWT | Kapsam disi/gelecek calisma diye yazilmali | Docs kontrolu | Passed | Low | Yok |

