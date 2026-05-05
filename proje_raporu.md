# Sentinel-IoT — Nihai Proje Raporu (Final Project Report)

**Tarih:** 27 Mart 2026  
**Durum:** Tamamlandı / Sertifikalı  
**Versiyon:** v5.0 (Final)

---

## 1. Proje Özeti (Executive Summary)

Sentinel-IoT, modern akıllı ev ve endüstriyel IoT ekosistemleri için tasarlanmış, **hibrit bir güvenlik ve izleme platformudur**. Geleneksel zafiyet tarama yöntemlerini (statik analiz), makine öğrenmesi tabanlı davranışsal analizle (dinamik analiz) birleştirerek ağdaki her cihaz için dinamik bir **Risk Profili** oluşturur. Proje, tamamen deterministic, thread-safe ve kalıcı (persistent) bir mimariyle modernize edilmiştir.

---

## 2. Sistem Mimarisi ve Bileşenler

Sistem, birbirleriyle asenkron olarak haberleşen 5 ana modülden oluşmaktadır:

### 2.1 Ağ Keşif & Zafiyet Tarama (Scanner)
- **Host Discovery:** Yerel ağdaki aktif cihazları ARP ve Ping yöntemleriyle tespit eder.
- **Fingerprinting:** Cihazların OUI (Vendor), Hostname, SSDP ve HTTP başlık verilerini kullanarak IoT tipini (Kamera, Sensör, Gateway vb.) belirler.
- **Vulnerability Scan:** Açık portları ve servis versiyonlarını tarar; `vulners` veritabanı ile eşleştirerek aktif CVE kayıtlarını raporlar.

### 2.2 Davranışsal İzleme (Monitor)
- **Paket Yakalama:** Scapy kütüphanesi ile ağ trafiğini gerçek zamanlı olarak izler.
- **Feature Extraction:** Her ağ akışı (flow) için IAT (Inter-Arrival Time), Paket Sayısı, Byte Sayısı ve Protokol gibi 10+ istatistiksel özellik çıkarır.

### 2.3 Yapay Zeka & Anomali Tespiti (ML)
- **Algoritma:** Unsupervised **Isolation Forest** modeli kullanılmıştır.
- **Eğitim:** Port Scan, DDoS, Data Exfiltration gibi saldırı senaryolarını içeren 10.000+ örnekli sentetik veri setiyle eğitilmiştir.
- **Standardizasyon:** Tüm girdi özellikleri `StandardScaler` ile normalize edilir; çıktı skorları ise 0.0 (Güvenli) ile 1.0 (Kritik Anomali) arasına sıkıştırılır.

### 2.4 Risk Motoru (Risk Engine)
- **Weighted Fusion:** `Risk = (Zafiyet_Skoru * 0.6) + (Anomali_Skoru * 0.4)` formülünü kullanarak hibrit bir risk puanı üretir.
- **Contextual Analysis:** Cihazın açık port sayısı ve servis kritikliği gibi bağlamsal verileri hesaba katar.

### 2.5 Veritabanı & Kalıcılık (Persistence)
- **Teknoloji:** SQLAlchemy ORM ve SQLite.
- **Kapsam:** Cihaz envanteri, tarama geçmişi, anomali logları ve risk trendleri uygulama yeniden başlatılsa dahi korunur.

---

## 3. Gelişmiş Özellikler ve UI/UX

Hardening (Sertifikasyon) aşamasında sisteme kazandırılan ileri seviye özellikler:

- **Asenkron İş Yönetimi:** Tarama ve eğitim gibi uzun süren işlemler `BackgroundTasks` ve `Job ID` sistemiyle yürütülür. Kullanıcı, UI üzerinden işlemin ilerlemesini % bazlı görebilir.
- **Device Drill-Down View:** Cihaz detay sayfası üzerinden tarihsel risk değişim grafikleri (Recharts) ve anomali zaman çizelgesi sunulur.
- **Diferansiyel Metrikler:** Sistem, ML modelinin teorik başarısı (Synthetic Benchmarks) ile ağdaki gerçek tespitlerini (Real Protection) ayrıştırarak sunar.
- **Hata Yönetimi:** API kesintileri ve veritabanı tutarsızlıkları için kapsamlı "Data Guard" ve "Error Badge" sistemleri entegre edilmiştir.

---

## 4. Teknik Sertifikasyon ve Güvenlik Tahkimatı

Proje sürecinde uygulanan "Hardening" adımları:

1.  **Thread Safety:** Global durum değişkenleri (State) `threading.Lock` ile korunarak race condition riskleri tamamen ortadan kaldırılmıştır.
2.  **ML Determinism:** `random_state=42` kullanılarak modelin her seferinde aynı sonuçları vermesi sağlanmıştır.
3.  **Strict Input Validation:** Risk motoru, geçersiz veri girişlerini (Örn: CVSS > 10) anında reddeder ve hata logu üretir.
4.  **Full Test Suite:**
    *   [test_compliance.py](file:///c:/Users/Hakit/Desktop/Bitirme%20Projesi/v3/sentinel_iot/tests/test_compliance.py): Şema ve aralık doğrulaması.
    *   [test_end_to_end.py](file:///c:/Users/Hakit/Desktop/Bitirme%20Projesi/v3/sentinel_iot/tests/test_end_to_end.py): Uçtan uca tarama ve 10-thread eşzamanlılık (stress) testleri.

---

## 5. Değerlendirme ve Sonuç

Sentinel-IoT, IoT güvenliğinde sadece zafiyetlere bakmanın yeterli olmadığını, davranışsal analizin de (ML) kritik olduğunu kanıtlayan bir mimari sunar. Yapılan geliştirmeler sonucunda sistem; **ölçeklenebilir, hataya dayanıklı ve görsel açıdan zengin** bir profesyonel güvenlik ürününe dönüştürülmüştür.

---
*Bu rapor, Sentinel-IoT projesinin nihai durumunu temsil eder.*
