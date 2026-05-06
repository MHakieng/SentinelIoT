# N-BaIoT Overfitting ve Genelleme Analizi

## Problem: Random Split Sonuclari Neden Asiri Yuksek Olabilir?

Random split deneylerinde ayni cihazdan ve ayni saldiri ailesinden gelen cok benzer ornekler hem train hem test tarafina dagilabilir. Bu durumda model, genel anomali davranisindan daha fazla dataset'e ozgu cihaz/saldiri izlerini ogrenmis olabilir.

## Device Split Sonucu Ne Gosteriyor?

Device split deneyinde ayni cihaz hem train hem test icinde bulunmaz. Bu test, modelin egitimde gormedigi cihazlarda genelleme yapip yapmadigini olcer.

Sonuc:

```text
Device Split RF F1-score: 0.999206
FPR: 0.017886
FNR: 0.000007
```

## Attack-Family Split Sonucu Ne Gosteriyor?

Attack-family split deneyinde bir saldiri ailesi tamamen testte tutulur. Bu test, modelin sadece belirli saldiri ailesini ezberleyip ezberlemedigini analiz eder.

Sonuclar:

```text
Train benign + gafgyt, test benign + mirai  -> F1: 0.890434
Train benign + mirai,  test benign + gafgyt -> F1: 0.716638
Ortalama F1: 0.803536
```

Bu dusus, random split sonucunun model kapasitesini gosterse de genelleme guvenilirligini tek basina kanitlamadigini gosterir.

## Device + Attack Split Sonucu Ne Gosteriyor?

Device + attack split deneyinde model hem gormedigi cihazlarda hem de gormedigi saldiri ailesinde test edilir. Bu, en zor ve akademik olarak en guvenilir genelleme testlerinden biridir.

Sonuclar:

```text
Held-out mirai  F1: 0.886639
Held-out gafgyt F1: 0.725956
Ortalama F1: 0.806298
```

Bu sonuc, modelin tamamen ezberlemedigini ama saldiri ailesi degistiginde performansin belirgin dustugunu gosterir.

## Balanced Benchmark Sonucu Ne Gosteriyor?

Balanced benchmark normal ve anomaly siniflarini esit sayida ornekle temsil eder. Bu test, mevcut veri dengesizliginin metriklere etkisini azaltmak icin kullanilir.

Sonuc:

```text
Balanced Random Forest F1-score: 0.999913
Normal: 172641
Anomaly: 172641
```

Balanced random split skoru hala cok yuksek oldugu icin asil genelleme riski sinif dengesizliginden cok cihaz/saldiri ailesi benzerliginden kaynaklanmaktadir.

## Feature Leakage Analizinde Hangi Feature'lar One Cikti?

Feature leakage analizi `evaluation/results/nbaiot_feature_leakage_analysis.csv` dosyasinda tutulur. Top feature'lar icin normal/anomaly ortalama, standart sapma, effect size ve tek-feature F1 skoru hesaplanir.

Top bulgu:

```text
HH_jit_L0.01_mean single-feature F1: 0.958079
```

Bu feature tek basina cok yuksek ayirt edicilik gosterdigi icin `leakage_suspect=True` olarak isaretlenmistir. Bu feature silinmemistir; sadece akademik raporda dikkat edilmesi gereken bir kanit olarak tutulmustur.

## Model Projeye Dogrudan Entegre Edilebilir mi?

N-BaIoT supervised modeli su an canli Sentinel-IoT sistemine dogrudan entegre edilmemelidir. Sebep feature semasi uyumsuzlugudur.

## Neden N-BaIoT Modeli Canli Sentinel-IoT Sistemine Baglanamaz?

N-BaIoT benchmark modeli yaklasik 115 istatistiksel feature ile egitilmistir. Canli Sentinel-IoT monitor akisi ise su temel feature'lari uretir:

```text
packet_count
byte_count
duration
avg_packet_size
mean_iat
var_iat
```

Bu semalar farkli oldugu icin model dogrudan production path'e baglanamaz.

## Canli Entegrasyon Icin Iki Secenek

1. 115 feature'lik N-BaIoT benzeri live feature extractor gelistirmek.
2. Sentinel-IoT'un mevcut 6 live feature'i ile ayri supervised model egitmek.

## Final Oneri

N-BaIoT sonuclari offline benchmark ve akademik kanit olarak tutulmali; canli Sentinel-IoT entegrasyonu icin ise once feature semasi uyumlu hale getirilmelidir. Sunumda random split yerine device split, attack-family split ve device+attack split sonuclari genelleme kaniti olarak one cikarilmalidir.

Final yorum:

```text
Ezberleme riski azaldi degil, olculebilir hale getirildi.
Random split model kapasitesini gosterir.
Attack-family ve device+attack split genelleme sinirlarini gosterir.
Canli entegrasyon icin feature semasi uyumu zorunludur.
```
