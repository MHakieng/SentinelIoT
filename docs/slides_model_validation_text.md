# Slayt Metni: Model Dogrulama ve Genelleme Analizi

## Slayt 1 - Neden Ek Dogrulama Yapildi?

N-BaIoT veri seti uzerinde ilk Random Forest random split sonucu cok yuksek cikti: F1 = 0.999994. Bu sonuc modelin veri seti icindeki ayrimi cok iyi ogrendigini gosteriyor; ancak tek basina genelleme kaniti degil. Bu nedenle modelin ezberleme riskini anlamak icin balanced split, device split, attack split, device + attack split, Isolation Forest baseline ve feature leakage analizleri yapildi.

## Slayt 2 - Random Split Yorumu

Random split sonucunda egitim ve test tarafinda ayni cihazlardan ve ayni saldiri ailelerinden cok benzer kayitlar bulunabilir. Bu nedenle Random Forest F1 = 0.999994 ve Balanced RF F1 = 0.999913 sonuclari model kapasitesini gosterir; fakat canli sistemde yeni cihaz veya yeni saldiri ailesi icin tek basina yeterli kanit sayilmaz.

## Slayt 3 - Device Split Sonucu

Device split deneyinde cihazlar egitim ve test tarafinda ayrildi. Random Forest bu senaryoda F1 = 0.999206 sonucunu verdi. Bu sonuc, modelin N-BaIoT kapsaminda farkli cihazlara karsi da yuksek performans gosterdigini gosteriyor. Ancak bu testte saldiri aileleri tamamen ayrilmadigi icin daha zor bir test olarak attack split uygulandi.

## Slayt 4 - Attack Split ve Device + Attack Split

Attack split deneyinde model bir saldiri ailesiyle egitilip egitimde gormedigi saldiri ailesinde test edildi. Ortalama F1 = 0.803536 cikti. Device + Attack split deneyinde hem cihaz hem saldiri ailesi ayrildi ve ortalama F1 = 0.806298 elde edildi. Bu dusus, random split sonucunun fazla iyimser oldugunu ve genelleme yorumunun bu daha zor testlerle yapilmasi gerektigini gosteriyor.

## Slayt 5 - Isolation Forest Baseline

Isolation Forest icin en iyi sonuc contamination = 0.15 degerinde elde edildi. F1 = 0.991886 ve FPR = 0.149999 olarak olculdu. Bu sonuc unsupervised baseline'in guclu oldugunu, ancak false positive oraninin supervised benchmarklara gore daha dikkatli yorumlanmasi gerektigini gosteriyor.

## Slayt 6 - Feature Leakage Analizi

Feature leakage analizinde `HH_jit_L0.01_mean` feature'i tek basina F1 = 0.958079 sonucuna ulasti. Bu, feature'in dataset'e ozgu cok guclu bir ayrim sinyali tasiyabilecegini gosteriyor. Bu bulgu, N-BaIoT sonuclarinin canli sistem performansi olarak dogrudan yorumlanmamasi gerektigini destekliyor.

## Slayt 7 - Neden Dogrudan Canli Sisteme Entegre Edilmedi?

N-BaIoT modeli 115 numeric feature ile egitildi. Canli Sentinel-IoT monitor akisi ise ayni feature semasini uretmiyor. Bu nedenle modeli dogrudan canli sisteme baglamak teknik olarak dogru degil. Bu model su an uretim modeli degil; final rapor ve sunum icin akademik benchmark ve dogrulama calismasi olarak kullanildi.

## Slayt 8 - Gelecek Entegrasyon Yolu

Canli entegrasyon icin iki yol onerildi. Birinci yol, N-BaIoT ile uyumlu 115 feature'lik live feature extractor gelistirmek. Ikinci ve daha uygulanabilir yol, Sentinel-IoT'un mevcut live feature setiyle kontrollu veri toplayip ayri bir supervised model egitmek. Bu asamada en dogru karar, N-BaIoT modelini dogrudan entegre etmek yerine benchmark olarak tutmak ve canli sisteme uygun ayri model egitimine gecmektir.

## Tek Paragraflik Sunum Metni

Bu projede N-BaIoT veri seti, Sentinel-IoT'un canli veri kaynagi olarak degil, model dogrulama ve benchmark amaciyla kullanilmistir. Random Forest random split F1 = 0.999994 gibi cok yuksek bir sonuc vermis olsa da, bu sonucun tek basina genelleme kaniti olmadigi gorulmustur. Bu nedenle device split, attack split, device + attack split ve feature leakage analizleri yapilmistir. Attack split ortalama F1 = 0.803536 ve device + attack split ortalama F1 = 0.806298 sonuclari, modelin yeni saldiri ailesine gectiginde performansinin daha gercekci seviyeye indigini gostermistir. Ayrica `HH_jit_L0.01_mean` feature'inin tek basina F1 = 0.958079 vermesi dataset'e ozgu guclu sinyal riskini ortaya koymustur. Bu nedenle N-BaIoT modeli canli sisteme dogrudan entegre edilmemis, akademik dogrulama kaniti olarak konumlandirilmistir.
