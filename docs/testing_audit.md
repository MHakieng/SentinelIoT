# Testing Audit

Bu denetim test ve build iddialarinin repo ile uyumunu inceler.

## Test Altyapisi

| Kontrol | Durum |
| --- | --- |
| `sentinel_iot/tests/` klasoru | Var. |
| `test_compliance.py` | Var. |
| `test_end_to_end.py` | Var. |
| Backend test runner | `verify_release.ps1` icinde `pytest -q -p no:cacheprovider --basetemp .pytest-tmp`. |
| Frontend check | `npm run check` = lint + build. |
| Evaluation script syntax | `py_compile` ile kontrol edilebilir. |

## Calistirilan Komutlar ve Sonuclar

Denetim sirasinda calistirilan resmi release dogrulama komutu:

```powershell
powershell -ExecutionPolicy Bypass -File .\verify_release.ps1
```

Sonuc:

- Backend: `66 passed, 3 skipped`
- Frontend: ESLint basarili
- Frontend build: basarili
- Uyari: Vite chunk size warning, JS chunk yaklasik `925.95 kB`

Ek syntax kontrolu:

```powershell
Get-ChildItem evaluation -Filter *.py | ForEach-Object { .\sentinel_iot\.venv\Scripts\python.exe -m py_compile $_.FullName }
```

Sonuc: Hatasiz.

## Tutarlilik Bulgulari

| Alan | Dokumanda yazan | Kodda/testte gorulen | Risk seviyesi | Oneri |
| --- | --- | --- | --- | --- |
| "Full test suite" | Backend ve frontend kontrolu oldugu yaziliyor. | `verify_release.ps1` gercekten backend pytest + frontend lint/build calistiriyor. | Low | "Full test suite" ifadesi kullanilabilir; komut ve son durumla birlikte verilmeli. |
| Frontend production build | Passed olarak belirtilmis. | Denetimde `npm run build` basarili. | Low | Chunk warning notu eklenebilir. |
| Pytest | Calisiyor. | `66 passed, 3 skipped`. | Low | Uyumlu. |
| Evaluation scriptleri | Tek basina calisabilir deniyor. | Syntax kontrolu gecti; hepsi mevcut dataset olmadan tam run edilmeyebilir. | Medium | "Dataset gerektiren scriptler icin raw veri gereklidir" notu korunmali. |
| `npm install` | README kurulumda var. | `node_modules` lokal mevcut; `npm install` bu denetimde yeniden calistirilmadi. | Low | Sorun yok. |

## Kalan Test Riski

- Frontend bundle buyuk; bu fonksiyonel hata degil ama performans icin code splitting onerilir.
- Packet capture ve Nmap testleri unit seviyesinde mock agirlikli; gercek ag ortaminda yetki ve cihaz durumuna bagli olarak tekrar dogrulanmali.
- Evaluation N-BaIoT scriptleri buyuk veri gerektirir; CI icin default calismamalidir.
