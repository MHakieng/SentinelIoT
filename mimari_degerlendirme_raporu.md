# Sentinel-IoT: Mimari Değerlendirme ve v6.0 Modernizasyon Raporu

Bu rapor, Sentinel-IoT platformunun mevcut teknik bileşenlerini sistem tasarımı ve siber güvenlik prensipleri çerçevesinde analiz etmekte ve gelecekteki ölçekleme ihtiyaçları için bir yol haritası sunmaktadır.

## 1. Mimari Analiz Özet Tablosu

| Kategori | Mevcut Durum | Değerlendirme | Risk / Etki |
| :--- | :--- | :--- | :--- |
| **İletişim Katmanı** | HTTP Polling (5s) | **Darboğaz** | Yüksek gecikme (latency), gereksiz network overhead. |
| **Veri Toplama** | Scapy (Python-native) | **Darboğaz** | High-throughput (1Gbps+) trafiklerde paket kaybı. |
| **Veri Depolama** | SQLite | **Ölçekleme Sorunu** | Eşzamanlı yazma (Single-writer) kilidi, zaman serisi verisi için yetersizlik. |
| **Anomali Tespit** | Isolation Forest | **Güçlü Yön** | Unsupervised öğrenme ile zero-day saldırı tespit potansiyeli. |
| **Risk Motoru** | Weighted Fusion (60/40) | **Güçlü Yön** | Hibrit yaklaşım ile false-positive oranını düşürür. |
| **Görev Yönetimi** | threading.Lock + Threading | **Güvenlik Riski** | Race condition riski, asenkron yapıda CPU-bound yüklerin bloklanması. |

---

## 2. Güçlü Yönler (Strengths)
*   **Hibrit Risk Füzyonu:** Zafiyet (Static) ve Davranış (Dynamic) verilerini birleştirmek, IoT sistemleri için en modern yaklaşımdır.
*   **FastAPI Entegrasyonu:** Tip güvenliği (Pydantic) ve otomatik dokümantasyon, hızlı iterasyon ve güvenilir API geliştirme sağlar.
*   **Isolation Forest Seçimi:** Denetimli veri setine ihtiyaç duymadan, IoT trafik paternlerindeki sapmaları (outliers) yakalamak için en verimli algoritmalardan biridir.

## 3. Mimari Darboğazlar ve Ölçekleme Sorunları
*   **Python GIL & Scapy:** Scapy, her paketi Python nesnesi olarak parse eder. Yüksek trafikli IoT ağlarında gateway modunda çalışırken CPU darboğazına girer ve paketleri kaçırır.
*   **SQLite Concurrency:** Canlı akış (flow) verileri saniyede yüzlerce kayıt üretebilir. SQLite'ın eşzamanlı yazma kısıtlaması, dashboard güncellemeleri ile sniffing loglarının çakışmasına (Database is locked) neden olur.
*   **Monolitik Görev Yapısı:** Tarama ve sniffing işlemleri ana API süreci içinde thread olarak çalışıyor. Bir modülün çökmesi tüm sistemi etkileyebilir.

## 4. Güvenlik ve Dayanıklılık Açıkları
*   **Root Yetki İhtiyacı:** Scapy ve Nmap çalışmak için `sudo` yetkisi gerektirir. Backend'in root yetkisiyle çalışması, bir RCE (Remote Code Execution) durumunda tüm sistemin ele geçilirilmesine yol açabilir.
*   **Veri Bütünlüğü:** Sniffing verilerinin in-memory (rolling buffer) tutulması, sistem yeniden başladığında geçmiş trafik analizinin (forensics) kaybolmasına neden olur.

---

## 5. v6.0 Önerilen Mimari Refactor Planı

v6.0 ile sistemin **Enterprise-Grade** bir yapıya taşınması için önerilen dönüşüm planı aşağıdadır:

### Aşama 1: Veri Toplama Katmanı (Capture Engine) Modernizasyonu
- **Öneri:** Scapy yerine **Go** diliyle yazılmış bir `capture-agent` veya Python tarafında **libpcap** native binding'leri kullanılmalı.
- **Teknoloji:** **AF_PACKET** veya **eBPF** (XDP) entegrasyonu ile paket kaybı %0'a indirilmeli.

### Aşama 2: Gerçek Zamanlı İletişim (WebSockets & Async)
- **Öneri:** Polling mekanizması tamamen kaldırılmalı.
- **Teknoloji:** **FastAPI WebSockets**. Paketler yakalandığı anda `broadcast` edilerek dashboard'da anlık (miliseviye) gecikmeyle gösterilmeli.

### Aşama 3: Veri Tabanı ve Zaman Serisi Analizi
- **Öneri:** Zaman serisi flow verileri için özel bir DB'ye geçilmeli.
- **Teknoloji:** **PostgreSQL + TimescaleDB**. Flow verileri zaman damgalı olarak saklanmalı, böylece geçmişe dönük saldırı analizi (Retrospective Analysis) yapılabilmeli.

### Aşama 4: Distributed Task Management (Microservices)
- **Öneri:** Tarama ve Capture süreçleri API'dan ayrılmalı.
- **Teknoloji:** **Async Worker (Celery/Kombu) + Redis**. Nmap taramaları arka planda izole worker'larda çalışmalı, API sadece statüsünü kontrol etmeli.

---

> [!TIP]
> **Hızlı Kazanç (Quick Win):** v6.0'a geçmeden önce yapılması gereken ilk hamle, **DPI Flow Buffer**'ın bir **Redis** kuyruğuna taşınmasıdır. Bu, API'yı capture-load baskısından anında kurtaracaktır.
