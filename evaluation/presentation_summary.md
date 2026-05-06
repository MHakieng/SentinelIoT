# Sentinel-IoT Dogrulama Ozeti

## Dogrulama Yaklasimi

Sentinel-IoT dogrulamasi uc parcadan olusur:

- Flow feature verisi uzerinden anomali modeli dogrulamasi
- Risk engine formul testleri
- Scanner ciktisinin kontrollu yerel ag envanteriyle manuel karsilastirilmasi

Gercek saldiri araci veya zararli trafik uretilmez. Degerlendirme, onceden toplanmis veya kontrollu/simule edilmis flow feature verisi uzerinden yapilir.

## Kullanilan Feature'lar

```text
packet_count
byte_count
duration
avg_packet_size
mean_iat
var_iat
```

## Test Senaryolari

Risk engine icin dogrulanan senaryolar:

| Senaryo | Vulnerability | Anomaly | Beklenen Risk |
| --- | ---: | ---: | ---: |
| Temiz cihaz | 0 | 0 | 0 |
| Sadece zafiyet | 80 | 0 | 48 |
| Sadece anomali | 0 | 90 | 36 |
| Iki sinyal de yuksek | 90 | 90 | 90 |
| Dengeli orta seviye | 50 | 50 | 50 |

## Hesaplanan Metrikler

Anomali modeli icin:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix
- False positive rate
- False negative rate

Scanner icin:

- Device Detection Rate
- Port Detection Accuracy

## Sonuc Tablosu Sablonu

| Metrik | Deger | Yorum |
| --- | ---: | --- |
| Accuracy | TBD | Tum kayitlarda dogru siniflandirma orani |
| Precision | TBD | Anomali denen kayitlarin ne kadari gercek anomaly |
| Recall | TBD | Gercek anomalilerin ne kadari yakalandi |
| F1-score | TBD | Precision ve recall dengesi |
| False Positive Rate | TBD | Normal trafikte yanlis alarm orani |
| False Negative Rate | TBD | Kacirilan anomaly orani |

## Confusion Matrix Yorumlama Notu

Confusion matrix gorselinde satirlar gercek etiketi, sutunlar model tahminini gosterir. Sag alt hucre dogru anomaly tespitlerini, sol ust hucre dogru normal tespitlerini gosterir. Sag ust hucre false positive, sol alt hucre false negative degeridir.

## Gelecek Calisma

Bu dogrulama kontrollu proje verisiyle sinirlidir. Gelecek asamada CICIoT2023, TON_IoT veya N-BaIoT gibi harici veri setleriyle daha genis kapsamli test yapilabilir.
