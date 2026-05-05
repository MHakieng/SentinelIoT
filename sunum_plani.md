# Sentinel-IoT: Bitirme Projesi Sunum Planı (10 Slayt)

Bu plan, Sentinel-IoT platformunun teknik derinliğini ve yenilikçi yönlerini jüriye en etkili şekilde sunman için tasarlanmıştır.

---

## 1. Giriş ve Problem Tanımı
- **Başlık:** IoT Güvenliğinde Kritik Boşluklar
- **İçerik:**
    - IoT cihazlarının kontrolsüz artışı (Shadow IoT)
    - Zayıf varsayılan yapılandırmalar ve yamalanmamış zafiyetler (CVE)
    - Görünmez tehditler: Klasik firewall'ların kaçırdığı anomali trafikleri
    - Kritik altyapılardaki (Medikal/Endüstriyel) risklerin hayati boyutu
- **Görsel:** "IoT Security Gap" grafiği (Cihaz Sayısı vs Güvenlik Seviyesi)
- **Not:** "Jüriyi selamlayarak başlayın. Günümüzde IoT cihazlarının ağlardaki en zayıf halka olduğunu ve standart güvenlik araçlarının bu cihazların 'bağlamını' anlamadığını vurgulayın."

---

## 2. Sentinel-IoT: Hibrit Güvenlik Çözümü
- **Başlık:** Sentinel-IoT Nedir?
- **İçerik:**
    - **Hibrit Yaklaşım:** Statik zafiyet taraması + Dinamik anomali tespiti
    - **Varlık Farkındalığı:** Cihaz tipine göre özelleşmiş risk analizi
    - **Gerçek Zamanlı İzleme:** Canlı akış (flow) ve paket analizi
    - **Merkezi Yönetim:** Modern ve etkileşimli kullanıcı arayüzü
- **Görsel:** Çözümün 3 ana sütununu gösteren ikonografik diyagram (Scan, Monitor, Analyze)
- **Not:** "Sentinel-IoT'nin sadece bir scanner olmadığını, ağdaki cihazların davranışlarını da takip eden yaşayan bir sistem olduğunu belirtin."

---

## 3. Sistem Mimarisi
- **Başlık:** Modern ve Modüler Mimari
- **İçerik:**
    - **Backend:** FastAPI (Service-Layer mimarisi, Dependency Injection)
    - **Frontend:** React + Vite (Yüksek performanslı dashboard)
    - **Persistence:** SQLite + SQLAlchemy (Güvenilir veri saklama)
    - **Core Tools:** Scapy (Packet Capture) ve Nmap (Discovery) entegrasyonu
- **Görsel:** API, Servisler ve Motorlar (Engines) arasındaki ilişkiyi gösteren mimari şema
- **Not:** "Sistemin son aşamada refaktör edilerek modüler bir yapıya kavuştuğunu, servis katmanlarının ayrıştırıldığını anlatın."

---

## 4. Keşif ve Zafiyet Analizi Algoritmaları
- **Başlık:** Cihaz Keşfi ve Parmak İzi Tespiti
- **İçerik:**
    - Çok izlekli (Multi-threaded) ağ tarama ve servis tespiti
    - Servislerin otomatik CVE (Common Vulnerabilities and Exposures) eşleştirmesi
    - Port Kritiklik Matrisi: SSH, SMB, RDP gibi riskli portların önceliklendirilmesi
    - CVSS (Common Vulnerability Scoring System) entegrasyonu
- **Görsel:** "Ağ Taraması -> Servis Tespiti -> CVE Eşleşmesi" akış diyagramı
- **Not:** "Sadece 'cihaz var' demiyoruz; 'şu cihazın şu portunda şu CVE koduyla bilinen bir açık var' diyebildiğimizi vurgulayın."

---

## 5. Makine Öğrenmesi ile Anomali Tespiti
- **Başlık:** Isolation Forest ile Davranış Analizi
- **İçerik:**
    - **Algoritma:** Unsupervised Isolation Forest (Etiketsiz veride yüksek başarı)
    - **Özellik Çıkarımı:** Paket sayısı, IAT (Inter-Arrival Time), bayt oranı analizi
    - **Güven Puanı (Confidence):** Karar sınırına mesafeye göre dinamik doğruluk puanı
    - **Online Learning:** Yerel ağ trafiğine göre periyodik yeniden eğitim (retraining)
- **Görsel:** Normal ve anormal verilerin ayrışmasını gösteren "Partitioning" grafiği
- **Not:** "Neden Isolation Forest? IoT kaynakları için hafif olması ve etiketli veriye (label) ihtiyaç duymadan 'sıfırıncı gün' saldırılarını yakalayabilmesi."

---

## 6. Bağlam-Duyarlı (Context-Aware) Risk Motoru
- **Başlık:** Akıllı Risk Füzyonu
- **İçerik:**
    - **Formül:** Risk = min(100, (Vuln * 0.6 + Anomaly * 0.4) * Asset_Mult)
    - **Asset Criticality:** Medikal cihazlar (x1.6) vs Ev cihazları (x1.0) farkı
    - **Port Boost:** Kritik portlarda saptanan açıklara ek puan verilmesi
    - **Dinamik Sınıflandırma:** Critical, High, Medium, Safe durumları
- **Görsel:** Risk hesaplama formülünün ve örnek bir medikal cihaz risk skorunun görselleştirilmesi
- **Not:** "Burada projenin özgünlüğünü anlatın. Bir hastanedeki MRI cihazının anomalisi ile misafir Wi-Fi'daki bir telefonun anomalisi aynı risk skoruna sahip değildir."

---

## 7. Demo ve Kullanıcı Deneyimi
- **Başlık:** Canlı İzleme ve Dashboard
- **İçerik:**
    - **Topology View:** Etkileşimli ağ haritası ve riskli bağlantıların vurgulanması
    - **Live Packet Viewer:** Ham trafik seviyesinde derinlemesine inceleme
    - **Device Detail:** Her varlık için "Risk Breakdown" (Zafiyet vs Anomali) analizi
    - **Alerts:** Algılanan tehditlerin anlık bildirimi
- **Görsel:** Dashboard'dan 3 ekran görüntüsü (Topology, Packet View, Inventory)
- **Not:** "Kullanıcı arayüzünün modern tasarımını (React 19 + Vanilla CSS) ve verilerin anlık akışını jüriye gösterin."

---

## 8. Teknik Doğrulama ve Testler
- **Başlık:** Kalite Güvencesi ve Doğrulama
- **İçerik:**
    - Pytest tabanlı birim (Unit) ve entegrasyon testleri
    - Sentetik veri ile saldırı simülasyonları (DDoS, Port Scan, Exfiltration)
    - Risk motoru mantık doğrulaması (Verify Risk Script)
    - Servis katmanı (Service Layer) import ve DI doğrulama testleri
- **Görsel:** Testlerin başarı oranını gösteren bir tablo veya terminal çıktısı
- **Not:** "Sistemi sadece kodlamadık, her modülün uç durumlarını (edge cases) test ederek sistemin dayanıklılığını kanıtladık."

---

## 9. Sınırlılıklar ve Mühendislik Tercihleri
- **Başlık:** Mevcut Sınırlılıklar
- **İçerik:**
    - **Privileged Access:** Ham paket yakalama için gereken yönetici izinleri
    - **Encrypted Traffic:** HTTPS/TLS içerisindeki payload'ları analiz edememe sınırı
    - **Time-Series DB:** Yüksek yoğunluklu trafik için SQLite'ın yazma hızı sınırları
    - **Scalability:** Çok geniş ölçekli ağlarda (Class B) merkezi tarama yükü
- **Görsel:** "Sınırlılıklar" ikon listesi
- **Not:** "Dürüst bir mühendislik yaklaşımı sergileyin. Her tasarımın bir trade-off (ödünleşim) içerdiğini, mevcut yapının MVP için optimize edildiğini belirtin."

---

## 10. Gelecek Çalışmalar ve Yol Haritası
- **Başlık:** Sentinel-IoT v2.0 Vizyonu
- **İçerik:**
    - **Database:** PostgreSQL + TimescaleDB (Zaman serisi veri optimizasyonu)
    - **Agent Architecture:** eBPF tabanlı hafif yerel izleme ajanları
    - **Threat Intel:** Otomatik CVE ve tehdit istihbaratı feed entegrasyonu
    - **AI Chatbot:** Doğal dilde ağ güvenliği raporlaması (LLM entegrasyonu)
- **Görsel:** Gelecek çalışmaların zaman çizelgesi (Roadmap)
- **Not:** "Projenin ticari veya akademik olarak nereye evrilebileceğini anlatarak sunumu vizyoner bir şekilde bitirin."
