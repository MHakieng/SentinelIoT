# Model Dogrulama ve Genelleme Analizi

Sentinel-IoT projesinde N-BaIoT veri seti, canli sistemin yerine gecen bir veri kaynagi olarak degil, ML/anomali tespit yaklasimini etiketli IoT botnet verisi uzerinde offline olarak degerlendirmek icin kullanilmistir. Bu bolumun amaci, modelin yalnizca egitim dagilimina cok benzeyen kayitlari mi ayirdigini yoksa daha zor genelleme senaryolarinda da makul sonuc verip vermedigini incelemektir.

## 1. Testler Neden Yapildi?

Ilk Random Forest random split deneyi cok yuksek bir sonuc vermistir: F1 = 0.999994. Bu deger modelin N-BaIoT veri setindeki ayrimi cok iyi ogrendigini gosterir; ancak tek basina genelleme kaniti olarak yeterli degildir. Bu nedenle ek olarak balanced benchmark, device split, attack split, device + attack split, Isolation Forest baseline ve feature leakage analizleri yapilmistir.

Bu testler uc soruya cevap vermek icin tasarlanmistir:

- Model sadece ayni dagilima sahip benzer kayitlari mi taniyor?
- Model daha once gormedigi cihazlarda veya saldiri ailesinde de basarili mi?
- Veri setinde modelin sinif ayrimini neredeyse dogrudan veren, leakage supheli feature var mi?

## 2. Random Split Neden Tek Basina Yeterli Degil?

Random split yaklasiminda ayni cihazlardan, ayni saldiri ailelerinden ve cok benzer trafik pencerelerinden gelen kayitlar hem egitim hem test tarafina dagilabilir. Bu durumda test seti gercek hayattaki yeni cihaz/yeni saldiri senaryosunu temsil etmek yerine, egitim dagilimina cok yakin bir orneklem haline gelebilir.

Bu projede random split sonuclari su sekildedir:

| Deney | F1-score |
| --- | ---: |
| Random Forest random split | 0.999994 |
| Balanced RF | 0.999913 |

Balanced RF sonucunun da yuksek kalmasi, sinif dengesizligi azaltildiginda model kapasitesinin korundugunu gosterir. Ancak bu sonuclar yine de modelin yeni cihaz veya yeni saldiri ailesi uzerindeki genelleme performansini tek basina kanitlamaz.

## 3. Device Split Ne Gosterdi?

Device split deneyinde ayni cihazlarin hem egitim hem test tarafinda bulunmasi engellenmistir. Bu sayede modelin cihaz kimligine veya cihaza ozgu trafik izlerine fazla bagimli olup olmadigi test edilmistir.

Device Split RF sonucu:

| Deney | F1-score |
| --- | ---: |
| Device Split RF | 0.999206 |

Bu sonuc, modelin farkli cihazlara ayrildiginda da N-BaIoT kapsaminda yuksek performans gosterdigini gosterir. Buna ragmen bu deneyde saldiri aileleri egitim ve test tarafinda ortak kalabildigi icin, modelin yeni saldiri turlerine genelleme kabiliyeti icin ek test gerekir.

## 4. Attack Split Ne Gosterdi?

Attack split deneyinde model bazi saldiri aileleri ile egitilip, egitimde gormedigi saldiri ailesi uzerinde test edilmistir. Bu test, random split ve device split'e gore daha zor bir genelleme senaryosudur.

Sonuclar:

| Deney | F1-score |
| --- | ---: |
| Attack Split RF average | 0.803536 |
| Device + Attack Split RF average | 0.806298 |

Bu dusus, random split sonucunun tek basina yorumlanmasinin riskli oldugunu gosterir. Model N-BaIoT icinde bilinen saldiri ailelerinde cok basarili olsa da, gormedigi saldiri ailesine gecildiginde performans daha gercekci bir seviyeye inmektedir. Device + Attack split sonucunun benzer seviyede cikmasi, en kritik genelleme sinirinin saldiri ailesi degisimi oldugunu gostermektedir.

## 5. Feature Leakage Analizi Ne Gosterdi?

Feature leakage analizinde Random Forest feature importance degerleri ve tek feature ile siniflandirma performansi incelenmistir. Amac, modelin sinif ayrimini dogrudan veya dataset'e ozgu bir ipucuyla yapip yapmadigini anlamaktir.

Leakage supheli feature:

| Feature | Tek feature F1-score | Yorum |
| --- | ---: | --- |
| HH_jit_L0.01_mean | 0.958079 | Tek basina cok yuksek ayirt edicilik gosterdigi icin leakage/dataset-specific sinyal suphelidir. |

Bu analiz feature'in mutlaka hatali oldugunu kanitlamaz; ancak modelin bazi N-BaIoT feature'larina fazla bagimli olabilecegini gosterir. Bu nedenle N-BaIoT sonuclari canli Sentinel-IoT sistemine dogrudan aktarilabilir uretim performansi olarak yorumlanmamalidir.

## 6. N-BaIoT Modeli Neden Canli Sentinel-IoT Sistemine Dogrudan Entegre Edilmedi?

N-BaIoT modeli 115 adet N-BaIoT feature'i ile egitilmistir. Canli Sentinel-IoT sistemi ise mevcut monitor akisinda 6 numeric live flow feature kullanir: `packet_count`, `byte_count`, `duration`, `avg_packet_size`, `mean_iat`, `var_iat`. Bu nedenle egitimde kullanilan feature semasi ile canli sistemin urettigi feature semasi ayni degildir.

Dogudan entegrasyon yapilmamasinin temel nedenleri:

- Feature sayisi ve anlamlari canli sistem ile birebir uyusmamaktadir: N-BaIoT 115 feature, canli Sentinel-IoT 6 live numeric feature kullanir.
- N-BaIoT etiketli bir benchmark veri setidir; Sentinel-IoT'un canli ag akisindan toplanmis veri kaynagi degildir.
- Random split sonuclari cok yuksek olsa da attack split ve feature leakage analizi genelleme riskini gostermistir.
- Canli sisteme dogrudan baglamak, teknik olarak yanlis guven algisi olusturabilir.

Bu nedenle N-BaIoT modeli bu asamada uretim modeli olarak degil, offline akademik benchmark ve dogrulama ciktisi olarak tutulmustur.

## 7. Gelecek Calisma ve Entegrasyon Yolu

Canli Sentinel-IoT sistemine supervised model entegrasyonu icin iki yol onerilmistir:

1. N-BaIoT benzeri 115 feature'lik live feature extractor gelistirmek.

Bu yaklasimda canli ag akisindan N-BaIoT ile uyumlu zaman penceresi feature'lari uretilir. Egitilen modelin bekledigi sema ile canli sistemin urettigi sema uyumlu hale gelir. Ancak bu yol daha fazla muhendislik calismasi ve ayrintili feature dogrulamasi gerektirir.

2. Sentinel-IoT'un mevcut live feature seti ile ayri supervised model egitmek.

Bu yaklasimda canli sistemde halihazirda uretilen feature'lar kullanilir. Kontrollu dogrulama verisi toplanir, etiketlenir ve bu feature setine uygun ayri bir model egitilir. Kisa vadede daha uygulanabilir ve proje mimarisine daha uyumlu yaklasim budur.

## Sonuc

N-BaIoT deneyleri, Sentinel-IoT projesinde ML dogrulamasinin yalnizca tek bir yuksek skorla sinirli tutulmadigini gostermektedir. Random split, balanced split ve device split sonuclari modelin veri seti icinde guclu ayrim yapabildigini; attack split ve device + attack split sonuclari ise yeni saldiri ailesine genelleme konusunda daha temkinli yorum yapilmasi gerektigini ortaya koymustur. Feature leakage analizi de bazi feature'larin dataset'e ozgu guclu sinyaller tasiyabilecegini gostermistir. Bu nedenle N-BaIoT modeli dogrudan canli sisteme entegre edilmemis, final raporda offline benchmark ve genelleme analizi olarak konumlandirilmistir.
