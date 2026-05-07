# N-BaIoT Sunum Ozeti

## Kullanilan Veri Seti

N-BaIoT veri seti kullanildi. Bu veri seti IoT cihazlarindan toplanan benign trafik ile Mirai/Gafgyt botnet trafiklerini icerir.

## Binary Label Yapisi

```text
label=0 -> Normal / benign trafik
label=1 -> Anomaly / botnet trafik
```

Attack type dosya adindan turetilir:

```text
benign -> benign
mirai -> mirai
gafgyt -> gafgyt
bashlite -> bashlite
```

## Egitim/Test Yaklasimi

Birden fazla dogrulama yaklasimi kullanilir:

1. Stratified train/test split: Tum cihazlardan gelen veriler sinif oranlari korunarak train/test olarak ayrilir.
2. Device split validation: Bazi cihazlar test setine ayrilir; ayni cihaz hem train hem test icinde bulunmaz.
3. Attack split validation: Bir saldiri ailesi test tarafinda disarida tutulur.
4. Device + attack split validation: Hem cihaz hem saldiri ailesi ayrimi birlikte uygulanir.

## Kullanilan Modeller

- Random Forest
- Extra Trees
- HistGradientBoosting
- Isolation Forest baseline/tuning

## Hesaplanan Metrikler

- Accuracy
- Precision
- Recall
- F1-score
- False positive rate
- False negative rate
- Confusion matrix
- Classification report

## Sonuc Tablosu

| Model | Accuracy | Precision | Recall | F1-score | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Random Forest | TBD | TBD | TBD | TBD | TBD | TBD |
| Extra Trees | TBD | TBD | TBD | TBD | TBD | TBD |
| HistGradientBoosting | TBD | TBD | TBD | TBD | TBD | TBD |
| Device Split RF | TBD | TBD | TBD | TBD | TBD | TBD |
| Attack Split RF Avg | TBD | TBD | TBD | TBD | TBD | TBD |
| Device + Attack Split RF Avg | TBD | TBD | TBD | TBD | TBD | TBD |
| Isolation Forest Best | TBD | TBD | TBD | TBD | TBD | TBD |

## Confusion Matrix Yorumlama

Confusion matrix'te satirlar gercek etiketi, sutunlar model tahminini gosterir. Sol ust hucre dogru normal tespitlerini, sag alt hucre dogru anomaly tespitlerini gosterir. Sag ust false positive, sol alt false negative degeridir.

## Final Sunum Paragrafi

Sentinel-IoT'un canli ag akisi scanner ve monitor bilesenleriyle calisirken, N-BaIoT benchmark'i etiketli IoT botnet verisi uzerinde offline model dogrulamasi saglar. Bu calismada N-BaIoT CSV dosyalari temizlenip binary normal/anomaly formatina donusturuldu, supervised modeller ve Isolation Forest baseline'i ayni metriklerle karsilastirildi. Random split sonuclari model kapasitesi olarak, device/attack split sonuclari ise genelleme sinirlari olarak yorumlandi. Boylece proje yalnizca calisan bir demo degil, olculebilir ML dogrulama ciktisi ureten bir guvenlik prototipi olarak sunulabilir.
