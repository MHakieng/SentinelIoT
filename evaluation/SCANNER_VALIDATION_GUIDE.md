# Scanner Dogrulama Rehberi

Bu rehber Sentinel-IoT scanner sonucunu kontrollu yerel ag envanteriyle karsilastirmak icin kullanilir. Gercek saldiri araci veya zararli trafik gerekmez.

## Kontrollu Yerel Agda Cihaz Listesi

1. Test agindaki cihazlari onceden belirleyin: router, bilgisayar, telefon, IoT cihaz, yazici gibi.
2. Her cihaz icin beklenen IP adresini not edin.
3. Cihaz uzerinde bilinen acik servisleri guvenli yollarla dogrulayin. Ornek: router yonetim arayuzu, cihaz dokumantasyonu veya isletim sistemi servis listesi.
4. Sonuclari `evaluation/scanner_validation_template.csv` dosyasina yazin.

## Sentinel-IoT Sonucu ile Karsilastirma

1. Dashboard uzerinden veya API ile ag taramasi baslatin.
2. Envanter ekraninda bulunan IP adreslerini template dosyasindaki `expected_ip` degerleriyle karsilastirin.
3. Cihaz bulunduysa `detected=yes`, bulunamadiysa `detected=no` yazin.
4. Sentinel-IoT tarafindan bulunan portlari `detected_ports` alanina noktalivirgulle ayirarak yazin.
5. Vendor bilgisi dogru veya makul ise `vendor_detected=yes` yazin.

## Device Detection Rate

Formul:

```text
Device Detection Rate = detected=yes olan cihaz sayisi / beklenen cihaz sayisi
```

Ornek:

```text
8 beklenen cihazdan 7 tanesi bulunduysa: 7 / 8 = 87.5%
```

## Port Detection Accuracy

Her cihaz icin beklenen port kumesi ile tespit edilen port kumesini karsilastirin.

Basit formul:

```text
Port Detection Accuracy = dogru tespit edilen port sayisi / beklenen port sayisi
```

Ornek:

```text
Beklenen portlar: 80;443;1883
Tespit edilen portlar: 80;443
Accuracy: 2 / 3 = 66.7%
```

Yanlis pozitif portlar `notes` alaninda ayrica belirtilmelidir.
