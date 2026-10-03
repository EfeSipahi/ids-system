# CRS PL1 ve PL2: iki gerçek kuralın çalışma sırası

Tarih: 3 Ekim 2026

## 1. Kapsam

CRS 4.30.0 içindeki 930120 ve 930121 kurallarıyla açıklamalı yürütme örneği. Motor çalıştırılmadı; sonuçlar kaynak kurallardan türetilen beklentilerdir. Yalnız bu iki tespit kuralının katkısı gösteriliyor; tam CRS çalıştırmasında başka kurallar da eşleşebilir. Kuralların yapılandırmada etkin olduğu, gerekli hazırlık işlemlerinin yapıldığı ve tespit modunda incelemenin sürdüğü varsayılıyor.

Bu kurallar işletim sistemi dosyası erişimi kontrolleridir; demoda kullanılması ilk ürün kapsamımıza otomatik eklendikleri veya PL2'nin onaylandığı anlamına gelmez.

## 2. İki kural

Kaynak: [REQUEST-930-APPLICATION-ATTACK-LFI.conf](/home/esip/Documents/ids-system/coreruleset-4.30.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf:104).

| Özellik | 930120 | 930121 |
| --- | --- | --- |
| PL | 1 | 2 |
| İşleme aşaması | phase:2 | phase:1 |
| Hedefler | Cookie adları/değerleri, parametre adları/değerleri, XML hedefleri | Referer ve User-Agent başlık değerleri |
| Eşleştirme | `@pmFromFile lfi-os-files.data` | `@pmFromFile lfi-os-files.data` |
| Dönüşümler | `t:none,t:utf8toUnicode,t:urlDecodeUni,t:normalizePathWin` | Aynı dönüşümler |
| Skor güncelleme | `lfi_score` ve `inbound_anomaly_score_pl1` | `lfi_score` ve `inbound_anomaly_score_pl2` |

`lfi-os-files.data` içinde `etc/passwd` ifadesi bulunur. Dosyaya dayalı ifade eşleştirme, alınan isteğin herhangi bir sistem dosyasını açıp okuması değildir; metin listedeki ifadelerle karşılaştırılır.

930121'in kaynak açıklaması, onun 930120'nin daha sıkı bir kardeşi olduğunu ve iki ek başlığı kontrol ettiğini açıkça belirtir.

## 3. PL ile phase aynı şey değildir

1. PL, hangi kural grubunun çalışmaya dahil olacağını belirler. PL2 seçilince PL1 ve PL2 kontrolleri kapsanır.
2. Phase, kuralın hangi HTTP işleme aşamasında çalışacağını belirler. Phase 1 başlık aşaması, phase 2 gövde işleme aşamasıdır; phase 2'deki kurallar URI ve parametrelere de bakabilir, gövdesiz GET isteğinde de çalışabilir.
3. Yürütme önce aşamaya göre düzenlenir. Aynı aşamada yapılandırmadaki yükleme sırası ve `skipAfter`/zincirler gibi akış talimatları etkili olur. Kural kimliğinin küçük olması tek başına önce çalışacağı anlamına gelmez.
4. Bu yüzden örneğimizde PL2 kuralı 930121, etkin olduğunda PL1 kuralı 930120'den önce çalışır.

## 4. İlk yapay istek

```http
GET /download?file=docs/notes.txt HTTP/1.1
Host: demo.local
Referer: https://demo.local/etc/passwd
User-Agent: demo-client
```

Hiçbir ağ isteği gönderilmedi. Burada Referer içindeki ifade şüphelidir; diğer seçilen alanlar bu iki kurala göre eşleşme üretmez.

### PL1 seçilirse

```text
Phase 1:
  930013 kontrolü: DETECTION_PARANOIA_LEVEL < 2 ?
  1 < 2 → doğru → aynı aşamada dosyanın bitiş işaretine atla
  930121 → çalıştırılmaz

Phase 2:
  930120 → parametre/cookie hedeflerini inceler → eşleşme yok
  930014 kontrolü: 1 < 2 → doğru → bu aşamadaki üst seviye bölümü atlanır
```

Sonuç: Bu iki tespit kuralından bulgu çıkmaz. Bu, isteğin güvenli olduğu veya tam CRS'nin alarm üretmeyeceği anlamına gelmez. Çalıştırılmayan 930121 için “inceledi ve temiz buldu” denemez.

### PL2 seçilirse

```text
Phase 1:
  930013 kontrolü: 2 < 2 → yanlış → yürütme devam eder
  930121 → Referer'ı inceler → etc/passwd eşleşir → PL2 bulgusu

Phase 2:
  930120 → file=docs/notes.txt değerini inceler → eşleşme yok
  930014 kontrolü: 2 < 2 → yanlış → yürütme devam eder
```

Dosyadaki diğer kontrol kuralları ve diğer tespit kuralları okunabilirlik için bu şemalarda gösterilmemiştir. Atlama HTTP isteğini iptal etmez; yalnız ilgili aşamadaki kural akışını değiştirir.

## 5. İkinci örnek: iki kuralın da eşleşmesi

Aynı istekte query'yi `file=etc/passwd` yaparsak, PL2'de:

```text
Phase 1 → 930121 → Referer içinde eşleşme
Phase 2 → 930120 → file parametresinde eşleşme
```

Tek hedef eşleşmesi/kural ve kritik skor 5 varsayımıyla yalnız bu iki kuralın katkısı:

| Sayaç | İlk örnek PL1 | İlk örnek PL2 | İkinci örnek PL2 |
| --- | --- | --- | --- |
| inbound_anomaly_score_pl1 | 0 | 0 | 5 |
| inbound_anomaly_score_pl2 | 0 | 5 | 5 |
| lfi_score | 0 | 5 | 10 |

PL1 ve PL2 katkılarının toplamı ikinci örnekte 10'dur. `lfi_score` aynı olayları kategori bakımından izler; bu toplamın üzerine yeniden eklenip 20 yapılmaz. Bizim nihai IDS alarm politikamız henüz seçilmedi; bu tablo yalnız CRS kural katkılarını açıklar.

## 6. Motor açısından sonuç

Gerekli üç ayrı yetenek: yapılandırılmış PL bilgisini istek durumuna aktarmak; kuralları doğru phase içinde yürütmek; SecLang karşılaştırma ve `skipAfter` talimatlarını anlamak. Yalnız `tag:paranoia-level/2` satırını okuyup dosyadaki her kuralı sırayla işletmek yeterli değildir.

Referanslar: [PL2 kontrolü ve 930121](/home/esip/Documents/ids-system/coreruleset-4.30.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf:183), [ifade listesi](/home/esip/Documents/ids-system/coreruleset-4.30.0/rules/lfi-os-files.data:651), [CRS PL açıklaması](/home/esip/Documents/ids-system/coreruleset-4.30.0/crs-setup.conf.example:138).
