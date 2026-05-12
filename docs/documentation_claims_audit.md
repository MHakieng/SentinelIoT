# Documentation Claims Audit

Bu denetim fazla iddiali veya kodla karisabilecek ifadeleri listeler.

| Ifade / iddia | Nerede goruldu | Kalmalı mı? | Kodla dogrulaniyor mu? | Risk seviyesi | Onerilen yeni ifade |
| --- | --- | --- | --- | --- | --- |
| "tamamen" | `docs/model_validation_summary.md`, `docs/slides_model_validation_text.md`, `evaluation/nbaiot_presentation_summary.md`, `evaluation/nbaiot_overfitting_analysis_summary.md` | Kismi | Cogu akademik split aciklamasinda kullaniliyor. | Low | "egitim ve test tarafinda ayrildi" veya "bu deneyde disarida tutuldu". |
| "kanıt/kanit" | Birden cok dokuman ve dashboard metni | Kismi | Test/evaluation ciktisi icin makul, ancak kesinlik ima etmemeli. | Medium | "dogrulama ciktisi", "destekleyici kanit", "benchmark kaniti". |
| "kanıtladı/kanitladi" | Kritik bir iddia olarak yaygin degil. | Kalmamali | Kesin bilimsel dil gerektirir. | Low | "gosterdi", "destekledi", "isaret etti". |
| "%100" | Belirgin kritik kullanim bulunmadi. | Hayir | Yok. | Low | Kullanilmamali. |
| "sertifikalı/sertifikali" | Bulunmadi. | Hayir | Yok. | Low | Kullanilmamali. |
| "profesyonel urun" | Bulunmadi. | Hayir | Yok. | Low | "akademik prototip" veya "bitirme projesi prototipi". |
| "production-ready" | README "production deployment yapilmamistir" diyor; dashboard "production modeli degildir" diyor. | Evet, olumsuz baglamda kalabilir. | Kod production-ready degil. | Low | Olumsuz baglam korunmali. |
| "real-time protection" | Bulunmadi; "real-time feedback" yorum satiri var. | Hayir | Kod koruma/engelleme yapmiyor. | Medium | "live monitoring" veya "runtime visibility". |
| "DPI" | Bulunmadi. | Hayir | Kodda DPI yok. | Low | "packet preview" veya "raw payload preview". |
| "online incremental learning" | Test yorumunda "formerly online learning"; dokumanda yaygin degil. | Hayir | Kod batch retraining yapiyor. | High | "batch retraining buffer". |
| "5-tuple" | `feature_extractor.py` docstring/comment. | Evet | Kod 5-tuple kullaniyor. | Low | Kalabilir. |
| "10+ feature" | Bulunmadi. | Hayir | Canli model 6 feature. | Medium | "6 live numeric feature; N-BaIoT 115 feature". |
| "10.000+ veri setiyle egitildi" | Bulunmadi. | Hayir | Dataset sayilari context gerektirir. | Low | Kullanilmamali. |
| "Full test suite" | Dokumanlarda test/build geciyor. | Kismi | `verify_release.ps1` geciyor. | Low | Komut ve sonuc ile birlikte yazilmali: `66 passed, 3 skipped`, frontend build passed. |
| "gercek dunya metrikleri" | Onceki kodda `real_world_metrics` alan adi vardi; mevcut kod statik operasyon metrigi dondurmuyor. | Hayir | TP/FP/F1 etiketli canli olay olmadigi icin `not_available` olarak sunuluyor. | Low | "runtime metrics not_available"; gercek metrik gibi gosterilmemeli. |
| "tamamlandı/tamamlandi" | UI scan durumunda ve script bitisinde kullaniliyor. | Evet | Islem durumunu anlatir. | Low | Kalabilir. |
| "tamamen thread-safe" | Bulunmadi. | Hayir | Kismi lock kullanimi var; tam garanti verilmemeli. | Medium | "thread lock ile temel runtime state korunur". |

## Dokumantasyon Temizligi Karari

Dokumantasyon genel olarak proje sinirlarini dogru anlatmaya baslamis. En onemli risk, akademik "kanit" dilinin fazla kesin algilanmasi ve runtime TP/FP/F1 metriklerinin etiketli canli veri olmadan mevcut olmadiginin unutulmasidir.
