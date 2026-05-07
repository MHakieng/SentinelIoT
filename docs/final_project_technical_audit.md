# Final Project Technical Audit

Bu rapor Sentinel-IoT projesinin final savunma oncesi teknik tutarlilik denetimidir.

## Genel Karar: Proje Hedefinden Uzak Mi?

Hayir. Proje hedefinden uzaklasmamis. Sentinel-IoT; IoT ag gorunurlugu, scanner, servis/CVE baglami, pasif monitoring, flow feature extraction, Isolation Forest runtime anomaly detection, risk scoring, dashboard, LLM aciklama katmani ve offline N-BaIoT benchmark hatlariyla kendi hedefi icinde tutarli bir akademik prototip durumunda.

Ancak proje "production-ready guvenlik urunu" olarak sunulmamali. En dogru konumlandirma: calisan akademik IoT guvenlik gorunurlugu prototipi + offline ML benchmark calismasi.

## Guclu Taraflar

- FastAPI backend, React dashboard ve scanner/monitor/ML/evaluation ayrimi net.
- Nmap tabanli cihaz/servis gorunurlugu gercek araclarla yapiliyor.
- Flow extractor 5-tuple ve 6 numeric live feature semasi kullanıyor.
- Runtime Isolation Forest StandardScaler ile calisiyor.
- Risk engine port, CVE, anomaly, asset type ve confidence baglamlarini birlestiriyor.
- N-BaIoT benchmark random split ile sinirli kalmamis; device split, attack split, device+attack split ve leakage analizi eklenmis.
- Repo temizligi yapilmis; dataset/model/secret artefaktlari GitHub'a alinmiyor.
- Resmi dogrulama scripti calisiyor: backend `66 passed, 3 skipped`, frontend lint/build passed.

## Teknik Eksikler

- `/metrics` endpointinde statik `real_world_metrics` degerleri var; bunlar gercek operasyon metrikleri gibi sunulursa yaniltici olur.
- N-BaIoT supervised modeli canli sisteme entegre degil; feature semasi farkli.
- Scanner CVE extraction CVE ID regex agirlikli; CVSS skoru scanner tarafinda sistematik cikarilmiyor.
- Risk engine fallback CVSS mantigi dict-CVE semasi bekliyor; scanner'in string CVE listesiyle entegrasyonu dogrulanmali.
- Packet capture tum ag trafiğini garanti etmez; switched network/Wi-Fi siniri dokumanda daha acik olmalı.
- Auth/JWT, HTTPS, Docker ve production deployment yok.
- Runtime model artefakti repo disi; yeni kurulumda modelin nasil egitilecegi/temin edilecegi netlestirilmeli.

## Dokuman-Kod Tutarsizliklari

1. "CVE analizi" ifadesi fazla genis; kod CVE ID gorunurlugu sagliyor, CVSS her zaman yok.
2. Basit risk formulu anlatimi asset multiplier ve port/context modifiers'i eksik birakabilir.
3. Canli metrikler ve offline benchmark UI'da ayni dogrulama bolgesinde oldugu icin karisabilir.
4. "Kanıt" dili bazen kesinlik ima ediyor; "dogrulama ciktisi" daha guvenli.
5. Packet capture sinirlarinda "makinenin gorebildigi trafik" vurgusu eksik.

## Sunumda Durustce Soylenmesi Gereken Sinirliliklar

- Bu bir akademik prototiptir, production SIEM/IDS urunu degildir.
- Canli sistem N-BaIoT modelini dogrudan kullanmaz.
- Canli feature semasi 6 numeric feature; N-BaIoT benchmark 115 feature.
- Random split skorlari model kapasitesini gosterir; genelleme icin attack split ve device+attack split daha anlamlidir.
- Packet capture ortam ve yetkilere baglidir; tum ag trafiği garanti edilmez.
- CVE/CVSS baglami Nmap script ciktisinin kalitesine baglidir.
- Auth/JWT ve deployment bu asamada gelecek calismadir.

## Raporlarda Duzeltilmesi Gereken Ilk 10 Madde

1. "Gercek dunya metrikleri" ifadesini kaldir veya demo placeholder olarak etiketle.
2. "CVE analizi"ni "Nmap script ciktilarindan CVE gorunurlugu" diye yumuşat.
3. Risk formulu anlatimina asset multiplier, port modifiers ve contextual confidence ekle.
4. Packet capture sinirlarini switched network/Wi-Fi baglaminda yaz.
5. N-BaIoT benchmark sonuclarini canli sistem basarisi gibi sunma.
6. "Kanıtladı" veya kesinlik ima eden ifadeleri "gosterdi/destekledi" ile degistir.
7. Runtime anomaly modelin 6 feature, N-BaIoT'nin 115 feature kullandigini her ML bolumunde belirt.
8. Online learning yerine batch retraining yaz.
9. CVSS fallback'in scanner path'inde dogrulanmasi gerektigini belirt.
10. Production deployment yapilmadigini ve auth olmadigini acik tut.

## Kodda Kritik Duzeltme Gerektiren Ilk 10 Madde

1. `MLService.get_metrics()` icindeki statik `real_world_metrics` alanlarini kaldir veya `demo_metrics` olarak yeniden adlandir.
2. CVE string listesi ile RiskEngine CVSS dict semasini uyumlu hale getir; CVSS yoksa fallback kullanildigini raporla.
3. Runtime model yoksa UI'da "model not trained/unavailable" durumunu daha net goster.
4. Packet capture icin interface secimi ve izin hatalarini UI'ya daha acik tasiyin.
5. `verify_release.ps1` build chunk warning'i raporlayabilir; kritik degil.
6. Dashboard metrics ekraninda offline benchmark ve runtime metrikleri ayri bloklarda tutulmali.
7. Risk history/topology gateway IP gibi sabit varsayimlar config'e alinabilir.
8. `get_local_network()` /24 varsayimini opsiyonel subnet config ile destekleyebilir.
9. Nmap `vulners` script yoksa uyari ve fallback davranisi daha acik olabilir.
10. Production icin auth, TLS, deployment config ve secrets management eklenmeli.

## Final Savunma Icin Onerilen Anlatim Dili

"Sentinel-IoT, yerel agdaki IoT cihazlarini kesfeden, servis gorunurlugu saglayan, canli flow metrikleri ureten ve bu metrikleri risk skoru ile birlestiren akademik bir guvenlik gorunurlugu prototipidir. Canli sistem hafif 6 feature'li Isolation Forest runtime modeliyle calisir. N-BaIoT ise canli sisteme dogrudan bagli olmayan, etiketli IoT botnet verisi uzerinde yapilmis offline ML benchmark calismasidir. Random split sonuclari model kapasitesini, attack split ve device+attack split sonuclari ise genelleme sinirlarini gostermek icin kullanilmistir."

## Nihai Teknik Karar

Proje savunulabilir. En kritik risk kodun calismamasi degil, bazi metrik ve algoritma iddialarinin fazla genis yorumlanmasidir. Dokumantasyon dili yumuşatilir ve statik metrikler acikca demo/placeholder olarak ayrilirsa proje teknik olarak daha tutarli ve akademik olarak daha guclu sunulur.
