# N-BaIoT Evaluation Pipeline

Bu klasor Sentinel-IoT projesi icin N-BaIoT veri seti uzerinde olculebilir ML benchmark calismasi uretir.

N-BaIoT, Sentinel-IoT'un canli ag modeline dogrudan baglanan veri kaynagi degil; IoT botnet trafigi uzerinde model dogrulama ve benchmark amaciyla kullanilan etiketli bir veri setidir.

## Neden N-BaIoT Kullanildi?

N-BaIoT IoT cihazlarindan toplanmis benign trafik ile Mirai/Gafgyt gibi botnet trafiklerini iceren etiketli bir veri setidir. Bu nedenle Sentinel-IoT'un anomali tespit yaklasimini final sunumunda olculebilir metriklerle anlatmak icin uygundur.

## Dosyalar Nereye Konulur?

Raw CSV dosyalari su klasorde olmalidir:

```text
evaluation/datasets/raw/n_baiot/
```

Ornek:

```text
evaluation/datasets/raw/n_baiot/1.benign.csv
evaluation/datasets/raw/n_baiot/1.gafgyt.combo.csv
evaluation/datasets/raw/n_baiot/1.mirai.syn.csv
```

Scriptler su klasorleri otomatik olusturur:

```text
evaluation/datasets/processed/
evaluation/results/
evaluation/models/
```

## Calistirma Sirasi

```powershell
python evaluation/inspect_nbaiot.py
python evaluation/preprocess_nbaiot.py --max-rows-per-file 20000
python evaluation/train_nbaiot_model.py --model random_forest --test-size 0.2
python evaluation/train_nbaiot_model.py --model extra_trees --test-size 0.2
python evaluation/train_nbaiot_model.py --model hist_gradient_boosting --test-size 0.2
python evaluation/train_nbaiot_device_split.py
python evaluation/train_nbaiot_attack_split.py
python evaluation/train_nbaiot_device_attack_split.py
python evaluation/train_nbaiot_balanced.py --model random_forest
python evaluation/train_nbaiot_balanced.py --model extra_trees
python evaluation/analyze_nbaiot_feature_leakage.py
python evaluation/tune_nbaiot_isolation_forest.py
python evaluation/compare_nbaiot_models.py
```

Sanal ortam aktif degilse `python` yerine sunu kullanin:

```powershell
.\sentinel_iot\.venv\Scripts\python.exe
```

## Inspection

```powershell
python evaluation/inspect_nbaiot.py
```

Uretilen dosya:

```text
evaluation/results/nbaiot_inspection_summary.csv
```

Bu rapor her CSV icin satir sayisi, kolon sayisi, ilk kolonlar, tahmini label, tahmini attack_type ve eksik deger oranini verir.

## Preprocessing

```powershell
python evaluation/preprocess_nbaiot.py --max-rows-per-file 20000
```

Preprocessing asamalari:

- Raw klasordeki trafik CSV dosyalari recursive okunur.
- `benign` dosyalari `label=0`, attack dosyalari `label=1` olarak etiketlenir.
- Numeric olmayan kolonlar feature disi birakilir.
- `Unnamed` ve index kolonlari temizlenir.
- NaN ve infinite degerler atilir.
- Her dosyadan varsayilan en fazla 20000 satir ornek alinir.
- Buyuk CSV dosyalari chunk tabanli okunur; bellek sorunu olursa `--max-rows-per-file` ve `--chunk-size` dusurulebilir.

Uretilen dosya:

```text
evaluation/datasets/processed/nbaiot_binary.csv
```

## Random Forest Egitimi

```powershell
python evaluation/train_nbaiot_model.py --model random_forest --test-size 0.2
```

Uretilen dosyalar:

```text
evaluation/results/nbaiot_random_forest_summary.json
evaluation/results/nbaiot_random_forest_classification_report.csv
evaluation/results/nbaiot_random_forest_confusion_matrix.png
evaluation/results/nbaiot_random_forest_feature_importance.csv
evaluation/models/nbaiot_random_forest.pkl
```

## Extra Trees Egitimi

```powershell
python evaluation/train_nbaiot_model.py --model extra_trees --test-size 0.2
```

Random Forest ile ayni metrikleri uretir, ancak Extra Trees algoritmasini kullanir.

## HistGradientBoosting Egitimi

```powershell
python evaluation/train_nbaiot_model.py --model hist_gradient_boosting --test-size 0.2
```

Bu model feature importance uretmeyebilir; bu normaldir.

## Device Split Validation

```powershell
python evaluation/train_nbaiot_device_split.py
```

Device split validation daha gercekci bir testtir. Ayni cihaz hem train hem test icinde bulunmaz. Cihazlarin yaklasik %70'i train, %30'u test olarak ayrilir.

Bu test yuksek skorlarin sadece ayni cihaza ait benzer patternleri ezberlemekten kaynaklanip kaynaklanmadigini anlamak icin kullanilir.

## Overfitting ve Genelleme Testleri

Random split sonuclari model kapasitesini gosterir; device split, attack-family split ve device+attack split sonuclari ise genelleme guvenilirligini degerlendirmek icin kullanilmistir.

Attack-family split:

```powershell
python evaluation/train_nbaiot_attack_split.py
```

Bu testte bir saldiri ailesi testte tutulur. Modelin yalnizca belirli saldiri ailesini ezberleyip ezberlemedigi incelenir.

Device + attack split:

```powershell
python evaluation/train_nbaiot_device_attack_split.py
```

Bu testte model hem gormedigi cihazlarda hem de gormedigi saldiri ailesinde degerlendirilir.

Balanced benchmark:

```powershell
python evaluation/train_nbaiot_balanced.py --model random_forest
python evaluation/train_nbaiot_balanced.py --model extra_trees
```

Bu test sinif dengesizligini azaltarak normal ve anomaly siniflarini esit sayida ornekle degerlendirir.

Feature leakage analizi:

```powershell
python evaluation/analyze_nbaiot_feature_leakage.py
```

Bu analiz top feature'larin tek basina cok yuksek ayirt edicilik gosterip gostermedigini raporlar. Feature silmez, sadece kanit uretir.

## Isolation Forest Tuning

```powershell
python evaluation/tune_nbaiot_isolation_forest.py
```

Bu script sadece benign kayitlarla Isolation Forest egitir ve farkli `contamination` degerlerini dener:

```text
0.01, 0.03, 0.05, 0.10, 0.15, 0.20
```

Uretilen dosya:

```text
evaluation/results/nbaiot_isolation_forest_tuning.csv
```

## Model Karsilastirma

```powershell
python evaluation/compare_nbaiot_models.py
```

Uretilen dosyalar:

```text
evaluation/results/nbaiot_model_comparison.csv
evaluation/results/nbaiot_model_comparison.png
```

Tablo F1-score degerine gore siralanir.

## Sunuma Eklenecek Dosyalar

- `evaluation/results/nbaiot_inspection_summary.csv`
- `evaluation/results/nbaiot_random_forest_summary.json`
- `evaluation/results/nbaiot_random_forest_confusion_matrix.png`
- `evaluation/results/nbaiot_random_forest_feature_importance.csv`
- `evaluation/results/nbaiot_device_split_summary.json`
- `evaluation/results/nbaiot_isolation_forest_tuning.csv`
- `evaluation/results/nbaiot_model_comparison.csv`
- `evaluation/results/nbaiot_model_comparison.png`
- `evaluation/results/nbaiot_generalization_comparison.csv`
- `evaluation/results/nbaiot_generalization_comparison.png`
- `evaluation/results/nbaiot_attack_split_results.csv`
- `evaluation/results/nbaiot_device_attack_split_results.csv`
- `evaluation/results/nbaiot_feature_leakage_analysis.csv`
- `evaluation/nbaiot_presentation_summary.md`
- `evaluation/nbaiot_overfitting_analysis_summary.md`

## Yuksek F1-score Nasil Yorumlanmali?

Yuksek F1-score, modelin bu etiketli benchmark veri setinde normal ve anomaly siniflarini iyi ayirdigini gosterir. Ancak bu sonuc canli Sentinel-IoT aginda ayni performansin garanti edildigi anlamina gelmez.

Sunumda su ayrim net soylenmelidir:

- Benchmark: Etiketli N-BaIoT CSV verisi uzerinde offline ML dogrulama.
- Canli Sentinel-IoT: Yerel agdan scanner/monitor ile toplanan runtime verisi uzerinde operasyonel tespit.

Bu nedenle N-BaIoT sonucu model kapasitesini gosteren bir benchmark, canli sistem ise entegrasyon ve operasyon demosudur.

## Canli Sistem Denemesi

Canli Sentinel-IoT monitor akisi uzerinde pasif flow toplamak ve N-BaIoT modeliyle feature uyumlulugunu kontrol etmek icin:

```text
evaluation/README_LIVE_EVALUATION.md
```

Bu akista gercek saldiri uretilmez; sadece mevcut `/monitor/flows` snapshotlari CSV'ye alinir.
