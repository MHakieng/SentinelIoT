# Remaining Risks Before Defense

## Kritik Riskler

Kritik seviyede, savunmayi dogrudan engelleyen uygulama crash'i tespit edilmedi. Backend testleri gecti ve frontend build basarili oldu.

## Yuksek Riskler

Yuksek seviyede aktif risk kalmadi. Onceki `/metrics` statik operasyon metrigi riski giderildi: backend `real_world_metrics` alanini artik dondurmuyor, runtime TP/FP/F1 metrikleri etiketli canli olay olmadigi icin `runtime_detection_metrics: null` ve `source: not_available` metadata ile sunuluyor. Frontend de bu durumu `Runtime Metrics Status` empty state olarak gosteriyor.

## Orta Riskler

1. Runtime TP/FP/F1 metrikleri mevcut degil.
   - Risk: Canli sistem basarisi sayisal olarak raporlanamaz.
   - Oneri: Bu metrikler icin etiketli canli olay toplama ve label sureci gerekir.

2. Scanner CVE string/dict sema ayrimi.
   - Risk: CVSS fallback her scanner CVE sonucunda calisiyor sanilabilir.
   - Oneri: Scanner CVE item'larini dict semasina normalize eden test ve kod duzeltmesi.

3. Packet capture ortam bagimli.
   - Risk: Demo gunu yetki/interface nedeniyle canli monitor bos donebilir.
   - Oneri: Admin yetkisi, dogru interface ve fallback demo verisi hazirlanmali.

4. Gercek Nmap scan bu QA turunda calistirilmadi.
   - Risk: Ortam/Nmap PATH/yetki sorunu demo sirasinda cikabilir.
   - Oneri: Demo oncesi kisa hedef araligi ile manuel scan provasi.

5. Frontend chunk size warning.
   - Risk: Build'i bozmaz; performans/ilk yuklenme uyarisi.
   - Oneri: Savunma sonrasi code splitting.

## Savunmada Durustce Soylenecek Sinirliliklar

- Sentinel-IoT bir production IDS/IPS urunu degil, akademik guvenlik gorunurlugu prototipidir.
- Runtime TP/FP/F1 metrikleri etiketli canli olay gerektirir ve bu prototipte mevcut degildir.
- Offline model validation metrikleri `evaluation/results` altindaki JSON raporlarindan gelir; live flow scoring ise runtime inference ciktisidir ve accuracy/F1 gibi gercek basari metrigi olarak sunulmaz.
- Reward/penalty katmani ML modelini egitmez veya yeniden egitmez; sadece mevcut model skorunu aciklanabilir operasyonel risk kalibrasyonuna donusturur.
- Device-class-aware scoring, cihaz sinifi bilgisini false positive riskini azaltmaya yardimci baglam olarak kullanir; bu mekanizma da runtime accuracy/F1 metrigi uretmez.
- N-BaIoT modeli canli sisteme dogrudan entegre edilmedi; offline benchmark olarak kullanildi.
- N-BaIoT benchmark 115 numeric feature kullanir, canli Sentinel-IoT runtime akisi 6 numeric feature uretir.
- Random split sonuclari model kapasitesini gosterir; genelleme siniri attack split ve device+attack split ile daha gercekci ortaya kondu.
- Packet capture tum ag trafigini garanti etmez; sadece interface'in gorebildigi trafigi yakalar.
- Nmap ve packet capture izin/yetki gerektirebilir.
- CVE/CVSS gorunurlugu Nmap script ciktisinin kalitesine baglidir.
- Auth/JWT/OAuth2, HTTPS ve production deployment gelecek calisma kapsamindadir.
- LLM yanitlari karar verici degil, analist yardimcisi olarak konumlandirilmistir.

## Savunma Aciklamasi: Live Flow Scoring

"Live flow tarafinda ham paketler dogrudan puanlanmaz. Paketler once flow seviyesinde gruplanir ve packet_count, byte_count, duration, avg_packet_size, mean_iat ve var_iat gibi ozellikler cikarilir. Bu ozellikler mevcut ML modeline verilerek normalize edilmis anomali skoru uretilir. Ardindan reward/penalty tabanli aciklanabilir kalibrasyon uygulanir. Boylece sistem yalnizca risk skoru uretmez, ayni zamanda bu riskin hangi davranislardan kaynaklandigini da gosterir."

## Savunma Aciklamasi: Device-Class-Aware Detection

"Tek bir IoT odakli modelin tum cihaz tiplerine ayni sekilde uygulanmasi Windows/browser gibi client trafiginde false positive riskini artirabilir. Bu nedenle SentinelIoT cihazlari once rule-based sinyallerle iot_device, client_device, network_infrastructure veya unknown olarak siniflandirir. Bu sinif bilgisi ML modelini yeniden egitmez; sadece live flow risk skorunu baglama gore aciklanabilir sekilde kalibre eder."

## Kod Duzeltmesi Gerektiren Alanlar

1. Scanner CVE semasi RiskEngine ile daha net normalize edilmeli.
2. Runtime TP/FP/F1 metrikleri icin etiketli canli olay akisina dayali ayri validation altyapisi eklenmeli.

## Sadece Dokumantasyonla Yonetilebilecek Alanlar

1. Nmap ve packet capture yetki sinirlari.
2. N-BaIoT offline benchmark ayrimi.
3. Random split vs genelleme splitleri yorumu.
4. JWT/production deployment gelecek calisma notu.
