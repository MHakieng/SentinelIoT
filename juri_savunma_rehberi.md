# Sentinel-IoT: Jüri Savunma Rehberi (25 Kritik Soru)

Bu rehber, Sentinel-IoT projenizin jüri savunmasında karşılaşabileceğiniz en zor soruları ve bu sorulara karşı vermeniz gereken stratejik teknik cevapları içermektedir.

---

## 🟢 Bölüm 1: Makine Öğrenmesi ve Anomali Tespiti

### 1. Neden Isolation Forest? Neden SVM veya Autoencoder değil?
*   **Asıl Sorgulanan:** Algoritma seçimindeki teknik farkındalık ve veri setine uygunluk.
*   **Güçlü Cevap:** "IoT trafiği yüksek boyutlu ve asimetriktir. Isolation Forest, verinin 'normal' profilini modellemek yerine, anomali olanın 'izole edilmesi daha kolaydır' prensibiyle çalışır. Bu, denetimsiz (unsupervised) bir ortamda zero-day saldırılarını yakalamak için derin öğrenme modellerinden (Autoencoder) çok daha düşük CPU maliyetiyle yüksek doğruluk sağlar."
*   **Kötü Cevap:** "Kullanması kolaydı ve kütüphanesi hazırdı."
*   **Kaçınılması Gereken:** "En iyisi buydu."

### 2. Sentetik veri seti (synthetic data) gerçek dünyayı ne kadar temsil ediyor?
*   **Asıl Sorgulanan:** Modelin "overfitting" riski ve gerçek trafik dinamikleriyle bağı.
*   **Güçlü Cevap:** "Gerçek bir IoT ağında saldırı trafiği bulmak nadirdir. Sentetik veriyi, ML modelimizi 'uç senaryolara' (DDoS flood, Port Scan) karşı kalibre etmek için kullandık. Ancak modelimiz sürekli öğrenme (batch retraining) yeteneği sayesinde canlı ağdan topladığı pasif trafik verilerini de kullanarak profilini dinamik olarak günceller."
*   **Kötü Cevap:** "Gerçek veri bulamadığımız için bunu kullandık."
*   **Kaçınılması Gereken:** "Hiçbir fark yok."

### 3. Isolation Forest'ın "Contamination" parametresini nasıl belirledin?
*   **Asıl Sorgulanan:** Algoritma ince ayarı ve ağ toleransı bilgisi.
*   **Güçlü Cevap:** "Contamination oranını %5 olarak belirledik. Bu oran, tipik bir SOHO ağındaki beklenen anormal trafik frekansına dayanmaktadır. Ancak bu parametre, sistemin duyarlılığını artırmak için dinamik olarak konfigüre edilebilir yapıdadır."

---

## 🔵 Bölüm 2: Risk Motoru ve Metrikler

### 4. Risk formülündeki 0.6 (Vuln) ve 0.4 (Anomaly) ağırlıklarını neye dayanarak seçtin?
*   **Asıl Sorgulanan:** Karar destek mekanizmasının keyfiliği vs. mühendislik temeli.
*   **Güçlü Cevap:** "Zafiyetler (CVE), cihazda varlığı ispatlanmış 'statik' risklerdir; bu yüzden baz puanın %60'ını oluştururlar. Anomaliler ise davranışsal ve 'olasılıksal' risklerdir (%40). Bu denge, sistemin yanlış alarmlar (false positives) nedeniyle cihazları sürekli 'bloklamasını' engellerken, kanıtlanmış risklere öncelik verir."
*   **Kötü Cevap:** "Hocam böyle daha iyi sonuç verdi."
*   **Kaçınılması Gereken:** "Rastgele seçtim."

### 5. CVSS skoru 10 olan bir cihazda anomali yoksa risk skoru kaç olur? Kritik bir cihazı güvenli mi gösterirsin?
*   **Asıl Sorgulanan:** Edge case analizi.
*   **Güçlü Cevap:** "Böyle bir durumda cihaz %60 (High-Medium) risk skorunda kalır. Bu doğru bir yaklaşımdır çünkü cihazda zafiyet olması 'saldırı altında olduğu' anlamına gelmez. Sentinel-IoT'nin amacı 'durumsal farkındalık' yaratmaktır; saldırı yoksa cihazı gereksiz yere 'High Risk' (Kırmızı) yapmaz."

---

## 🟡 Bölüm 3: Ağ ve Güvenlik Mimarisi

### 6. Ağ taramasında neden sadece /24 blok kullanıldı? Daha büyük ağlarda ne yapacaksın?
*   **Asıl Sorgulanan:** Ölçeklenebilirlik ve kapsam.
*   **Güçlü Cevap:** "Projenin odak noktası SOHO ve KOBI tipi IoT ağlarıdır. /24 discovery, bu segment için endüstri standardıdır. Daha büyük ağlar için backend mimarimiz modülerdir; 'Scan Task' katmanına birden fazla subnet CIDR bilgisi parametre olarak geçilebilir."
*   **Kötü Cevap:** "Derslerde hep /24 kullandık."
*   **Kaçınılması Gereken:** "Büyük ağları tarayamıyoruz."

### 7. JWT (JSON Web Token) neden protokolde yok? Bir saldırgan dashboad'a erişirse ne olur?
*   **Asıl Sorgulanan:** Güvenlik katmanı eksikliği ve odak yönetimi.
*   **Güçlü Cevap:** "Sentinel-IoT projesinin MVP (Minimum Viable Product) aşamasında odak noktamız 'Detection Engine' ve 'DPI' kapasitesiydi. Auth katmanı yol haritamızda (v2.0) mevcuttur. Mevcut yapı, sadece yerel ağdan (localhost) erişilecek bir security gateway olarak tasarlanmıştır."
*   **Kötü Cevap:** "Vaktim yetmedi."
*   **Kaçınılması Gereken:** "Gerek görmedik."

### 8. Scapy gibi Python tabanlı bir kütüphane 1Gbps trafikte paket kaçırmaz mı?
*   **Asıl Sorgulanan:** Performans ve kütüphane kısıtları.
*   **Güçlü Cevap:** "Evet, Scapy high-throughput ağlarda darboğaz yaratabilir. Bu projede Scapy'yi 'prototipleme ve analiz' amaçlı kullandık. Üretim bandında (production) bu katmanın eBPF veya DPDK tabanlı bir Go ajanıyla değiştirilmesi mimari dökümanımızda refactor planı olarak yer almaktadır."

---

## 🔴 Bölüm 4: Veritabanı ve Sistem Tasarımı

### 9. Neden SQLite? Enterprise bir çözüm değil, neden PostgreSQL seçmedin?
*   **Asıl Sorgulanan:** Veri tabanı seçimi ve kullanım senaryosu (Use-case).
*   **Güçlü Cevap:** "Sentinel-IoT bir 'Embedded Gateway' cihazı üzerinde çalışmak üzere tasarlanmıştır. SQLite, sıfır-konfigürasyon gereksinimi ve dosya tabanlı yapısıyla IoT gateway cihazları için en verimli (lightweight) çözümdür. Sunucu bağımlılığını ortadan kaldırır."
*   **Kötü Cevap:** "Kullanması en kolayı oydu."
*   **Kaçınılması Gereken:** "Veritabanı dökümanına bakmadım."

---

## 💡 Jüride Kaçınılması Gereken "Yasaklı" İfadeler

1.  **"Hocam vaktim yetmedi"** (Bunun yerine: "Proje kapsamında önceliklendirdiğimiz modüller şunlardı...")
2.  **"Onu ben yapmadım, kütüphane yaptı"** (Bunun yerine: "Kütüphanenin sunduğu X metodunu, projemizdeki Y problemini çözmek için entegre ettim.")
3.  **"Zaten IoT'de güvenli bir şey yok"** (Nihilist yaklaşımdan kaçın, çözüm odaklı ol.)
4.  **"Kodu internetten buldum"** (Bunun yerine: "Endüstri standardı olan X algoritmasını kendi veri setimize uyarladım.")

---

## 📈 Başarı İpucu:
Sorulan soruya doğrudan teknik bir verimle (sayısal değer, algoritma ismi, teknik gerekçe) cevap verin ve ardından bu seçimin **projenin ana amacına (IoT Güvenliği)** nasıl hizmet ettiğini belirtin.
