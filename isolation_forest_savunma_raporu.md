# Sentinel-IoT: Anomali Tespit Motoru Teknik Savunma Raporu

Bu rapor, Sentinel-IoT platformunda anomali tespiti için **Isolation Forest (iForest)** algoritmasının seçilme nedenlerini, diğer popüler yöntemlerle kıyaslayarak akademik ve teknik bir dille açıklar.

---

## 1. Algoritma Karşılaştırma Matrisi

| Kriter | One-Class SVM | Local Outlier Factor (LOF) | Autoencoder (Deep Learning) | **Isolation Forest (Seçilen)** |
| :--- | :--- | :--- | :--- | :--- |
| **Etiket İhtiyacı** | Yok (Unsupervised) | Yok (Unsupervised) | Yarı-Denetimli (Temiz Veri) | **Yok (Unsupervised)** |
| **Hesaplama Maliyeti** | Yüksek ($O(n^2)$ - $O(n^3)$) | Yüksek ($O(n^2)$ - Mesafe Matrisi) | Çok Yüksek (GPU/Eğitim Süresi) | **Düşük ($O(n \log n)$)** |
| **Gerçek Zamanlılık** | Orta (Kernel hesaplama yükü) | Düşük (Yavaş Prediction) | Orta (Forward Pass hızlı) | **Yüksek (Lineer Tahmin)** |
| **Veri Seti Boyutu** | Küçükte hassas | Yoğunluk tabanlı (Orta/Büyük) | Büyük veri seti şart | **Küçük/Orta veri setlerinde robust** |
| **Explainability** | Düşük (Kara kutu kernel) | Orta (Yoğunluk oranı) | Çok Düşük (Nöron aktivasyonu) | **Yüksek (Ağaç derinliği/Yol uzunluğu)** |

---

## 2. Neden Isolation Forest? (Teknik Savunma)

### A. IoT Kaynak Kısıtları (Resource Constraints)
IoT gateway cihazları (örn: Raspberry Pi, Edge Gateway) sınırlı CPU ve RAM kapasitesine sahiptir. **One-Class SVM** kernel hesaplamaları nedeniyle bellek yoğun çalışırken, **Autoencoder** modelleri eğitim için GPU gücü gerektirir. **Isolation Forest**, ağaç tabanlı (recursive partitioning) yapısı sayesinde lineer zaman karmaşıklığına yakındır ve düşük kaynak tüketimiyle yüksek performans verir.

### B. "Normal" Profilini Tanıma Zorunluluğu Yoktur
Diğer yöntemlerin çoğu (örn: Autoencoder veya OC-SVM), verideki "normal" olanı modellemeye çalışır ve bu modelden sapanları anomali sayar. **Isolation Forest** ise temel bir varsayıma dayanır: *"Anomaliler az sayıdadır ve özellik uzayında normal veriden farklıdır."* Bu sayede anomaliyi pasif olarak tespit etmek yerine, onu doğrudan "izole" eder (partitioning). Bu yaklaşım, karmaşık IoT ağlarında "normal" davranışın sürekli değiştiği (dynamic baseline) durumlar için daha esnektir.

### C. Zero-Day Saldırılarına Karşı Unsupervised Güç
Sistemimiz, daha önce hiç görülmemiş saldırı paternlerini (Data Exfiltration, New Botnet Command & Control) tespit etmek zorundadır. Isolation Forest etiketli veriye (label) ihtiyaç duymadığı için, saldırıların imzasını bilmeden sadece istatistiksel aykırılıklar üzerinden sıfırıncı gün saldırılarını yakalayabilir.

### D. İstatistiksel Açıklanabilirlik (Explainability)
Bir anomali tespit edildiğinde jürinin soracağı en önemli soru şudur: *"Neden bu trafiğe anomali dedin?"*. Isolation Forest'ta cevabımız nettir: *"Bu trafik örneği, karar ağaçlarında normal verilere göre çok daha sığ (shallow) bir derinlikte izole edilmiştir."* Yol uzunluğunun kısalığı, trafiğin istatistiksel olarak ne kadar aykırı olduğunun doğrudan ve matematiksel bir kanıtıdır.

---

## 3. Sonuç ve Proje Uygunluğu

Bitirme projesi kapsamında geliştirilen Sentinel-IoT için Isolation Forest seçimi; **hızlı prototipleme**, **gerçek zamanlı (real-time) trafik analizi** ve **etiketlenmemiş gerçek ağ verilerinde yüksek doğruluk** hedefleri doğrultusunda en optimize mühendislik kararıdır. Karmaşık derin öğrenme modellerinin aksine, anlaşılır, hızlı ve IoT gateway mimarisine tam uyumludur.

---

> [!TIP]
> **Jüri Sunumu İpucu:** "Neden Deep Learning (Autoencoder) kullanmadın?" sorusuna: *"IoT ağlarındaki trafik paternleri saniyeler içinde değişebilir. Autoencoder eğitimi çok uzun sürerken (retraining delay), Isolation Forest ile saniyeler içinde yeni trafik profillerine batch retraining yapabiliyoruz."* diyerek performansı vurgulayabilirsin.
