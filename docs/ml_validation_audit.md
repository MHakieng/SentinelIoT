# ML Validation Audit

Bu denetim canli Sentinel-IoT ML akisi ile N-BaIoT offline benchmark arasindaki ayrimi inceler.

## Canli Sistem Feature Semasi

Kod referansi: `sentinel_iot/ml/feature_schema.py`

Canli runtime model 6 numeric feature bekler:

- `packet_count`
- `byte_count`
- `duration`
- `avg_packet_size`
- `mean_iat`
- `var_iat`

`feature_extractor.py` ayrica `flow_id`, IP/port/protocol ve UI metadata uretir, ancak model bu metadata alanlarini feature olarak kullanmaz.

## N-BaIoT Evaluation Feature Semasi

N-BaIoT pipeline `evaluation/datasets/processed/nbaiot_binary.csv` icindeki 115 numeric N-BaIoT feature ile calisir. `label`, `attack_type`, `source_file`, `source_device` feature listesinden cikarilir.

Durum: Canli sistem 6 feature, N-BaIoT benchmark 115 feature kullanir. Bu ayrim README ve model validation dokumanlarinda net sekilde yazilmis.

## Bilinen Gercek Sonuclar

| Deney | F1-score | Yorum |
| --- | ---: | --- |
| Random Forest random split | 0.999994 | Model kapasitesi; tek basina genelleme kaniti degil. |
| Balanced RF | 0.999913 | Sinif dengesi duzeltilince de dataset ici ayrim cok guclu. |
| Device Split RF | 0.999206 | Cihaz ayrimi yapilinca performans yuksek kaliyor. |
| Attack Split RF average | 0.803536 | Gormedigi saldiri ailesine gecince performans belirgin dusuyor. |
| Device + Attack Split RF average | 0.806298 | Daha zor genelleme testinde benzer seviyede kaliyor. |
| Isolation Forest best | 0.991886 | Unsupervised baseline guclu; FPR degerine dikkat edilmeli. |
| Leakage suspect feature | `HH_jit_L0.01_mean`, single-feature F1 0.958079 | Dataset-specific guclu sinyal riski. |

## Tutarlilik Bulgulari

| Alan | Durum | Risk seviyesi | Oneri |
| --- | --- | --- | --- |
| N-BaIoT canli sisteme entegre edilmedi mi? | README, docs ve dashboard metinleri bunu genel olarak net soyluyor. | Low | Bu ayrim korunmali. |
| 115 feature vs 6 feature ayrimi | README ve `PROJE_DOKUMANTASYONU.md` bunu acikca belirtiyor. | Low | Sunumda da bir tabloyla gosterilmeli. |
| Random split sonucu canli sistem basarisi gibi mi yazilmis? | README bunu offline benchmark olarak konumlandiriyor. Dashboard metni de ayrimi belirtiyor. | Low | "Model kapasitesi" dili korunmali. |
| Attack/device+attack split konumu | `docs/model_validation_summary.md` ve dashboard genel olarak dogru konumlandiriyor. | Low | "Genelleme siniri" vurgusu artirilabilir. |
| Feature leakage analizi | Leakage suspect feature belirtilmis, modelden feature silinmedigi acik. | Low | "Supheli" kelimesi korunmali; kesin leakage denmemeli. |
| Isolation Forest vs supervised benchmark | README ve docs ayiriyor; ancak dashboard metrics endpoint runtime metrikleriyle karisabilir. | Medium | UI'da offline benchmark ile runtime model metrikleri basliklarda ayrilmali. |
| Runtime model artefakti | `.joblib` GitHub'dan cikarildi. Yeni kurulumda model yoksa runtime anomaly normal doner veya egitim gerekir. | Medium | README'ye "runtime model dosyasi repo disidir; yeniden egitim gerekir" notu eklenebilir. |
| `MLService.get_metrics()` | Statik `real_world_metrics` donduruyor. | Critical | Canli basari metrikleri gibi sunulmamalı; "demo placeholder" olarak degistirilmeli veya kaldirilmali. |

## Sonuc

ML dogrulama katmani akademik olarak savunulabilir; cunku random split sonucuyla yetinilmemis, attack split, device+attack split ve feature leakage analizi yapilmis. Ancak canli runtime metrikleri ve offline benchmark ayni "dogrulama" ekraninda bulundugu icin sunumda ayrim cok net anlatilmali.
