# CRS 930110: tek kural üzerinden motor gereksinimleri

Tarih: 3 Ekim 2026

## 1. Bu demonun kapsamı

CRS 4.30.0 içindeki gerçek 930110 kuralını yapay bir HTTP isteğiyle adım adım açıklıyoruz. Bu bir eğitim demosudur; çalışan Go IDS motoru veya tam CRS uyumluluk testi değildir. Kaynak CRS dosyaları değiştirilmedi. Mimari plandaki etkin kural kapsamı ve hassasiyet kararı bu demoyla onaylanmış sayılmaz.

## 2. Gerçek kural

Kuralın özgün metni aşağıda. Kaynak: [REQUEST-930-APPLICATION-ATTACK-LFI.conf](/home/esip/Documents/ids-system/coreruleset-4.30.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf:73).

```apacheconf
SecRule REQUEST_URI_RAW|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|FILES|XML:/*|XML://@* "@rx (?:^|[/;\x5c])\.{2,3}[/;\x5c]" \
    "id:930110,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:cmdLine,\
    msg:'Path Traversal Attack (/../) or (/.../)',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-lfi',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-LFI',\
    tag:'capec/1000/255/153/126',\
    ver:'OWASP_CRS/4.30.0',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}'"
```

## 3. Kuralı parçalara ayırma

| Kısım | Anlamı / motor gereksinimi |
| --- | --- |
| `SecRule` | Alan seçimi, eşleştirme işlemi ve eylemleri içeren kuralı ayrıştırabilmek |
| `REQUEST_URI_RAW` | İsteğin alınan URI gösterimine erişmek |
| `ARGS` | Ayrıştırılmış query ve uygun gövde parametre değerlerine erişmek; tekrarları korumak |
| `REQUEST_HEADERS` ve `!REQUEST_HEADERS:Referer` | Başlık değerlerini seçmek, Referer başlığını bu kuralın hedeflerinden çıkarmak |
| `FILES` | Yüklenen dosyaların adlarına erişmek; dosya içeriklerini taramak anlamına gelmez |
| `XML:/*`, `XML://@*` | XML hedeflerini seçebilmek; Faz 1'de yapısal XML desteğimiz olmadığı açıkça bildirilecek |
| `@rx` | Belirtilen düzenli ifadeyi hedef değerlerde aramak |
| `id:930110` | Bulguyu ve test sonucunu kararlı bir kural kimliğiyle ilişkilendirmek |
| `phase:2` | Kuralı istek gövdesi inceleme aşamasında yürütmek; bu aşama yalnız gövde alanlarına bakıldığı anlamına gelmez |
| `t:none` | Önceden miras alınmış dönüşüm listesini temizlemek; hiç dönüşüm yapılmayacağı anlamına gelmez |
| Sonraki `t:` işlemleri | Dönüşümleri yazıldıkları sırayla, ortak veriyi değiştirmeyen çalışma değeri üzerinde uygulamak |
| `multiMatch` | Operatörü dönüşümlerden önce ve girdiyi değiştiren dönüşümlerden sonra da çalıştırmak |
| `capture` | Eşleşen parçayı istek içi `TX.0` gibi alanlara aktarabilmek |
| `setvar` ve `%{...}` | İsteğe özel değişkenleri okumak, makro değerini çözmek ve skorları artırmak |
| `msg`, `tag`, `severity`, `ver` | Bulguyu açıklayan kimlik ve sınıflandırma bilgilerini taşımak |
| `logdata` | Eşleşme açıklamasını üretmek; ham değerleri kalıcı kayda geçirmeden M11 politikasını uygulamak |
| `block` | Yapılandırılmış engelleme davranışını temsil eder; bizim Faz 1 tespit modumuz korunan isteği engellemeyecek |

Dosyanın başındaki 930011/930012 kuralları hassasiyet düzeyine göre bu grubu atlayabilir. Dolayısıyla tek kuralın gövdesi dışında yürütme kontrolü de vardır. Bu örnekte kuralın etkin olduğu varsayılmıştır; hassasiyet düzeyi proje için henüz seçilmedi.

## 4. Yapay örnek istek

```http
GET /download HTTP/1.1
Host: demo.local
X-Demo-Path: %2e%2e%2fnotes.txt
```

Bu istek hiçbir sunucuya gönderilmedi. `X-Demo-Path` yalnız bu gösterim için uydurulmuş bir başlıktır. Gerçek uygulamanın bu başlığı kullanması gerekmez; örnek, kuralın başlık değerlerini nasıl incelediğini gösterir.

Alınan ortak veri içinde başlığın değeri `%2e%2e%2fnotes.txt` olarak kalır. Kural motoru `REQUEST_HEADERS:X-Demo-Path` alanını seçip ayrı çalışma değerini hazırlar. Referer olsaydı bu kural başlığın kendisini incelemeyecekti.

## 5. Dönüşüm ve eşleştirme izi

Regex:

```text
(?:^|[/;\x5c])\.{2,3}[/;\x5c]
```

Sade açıklaması: Metnin başında veya `/`, `;`, ters eğik çizgi sonrasında iki ya da üç nokta; ardından yine bu ayırıcılardan biri aranır. Bu, her `..` yazısının eşleşmesi demek değildir.

| Adım | Bu örnekte değer | Eşleştirme |
| --- | --- | --- |
| Başlangıç | `%2e%2e%2fnotes.txt` | Eşleşme yok |
| `utf8toUnicode` | `%2e%2e%2fnotes.txt` | Bu ASCII örneğinde değer değişmez |
| `urlDecodeUni` | `../notes.txt` | Değer değişir; `../` eşleşir |
| `removeNulls` | `../notes.txt` | Null byte yok; değer değişmez |
| `cmdLine` | `../notes.txt` | Bu örnekte değer değişmez |

`urlDecodeUni` genel olarak sıradan URL çözümlemeden daha kapsamlıdır; yüzde-u biçimlerini de ele alır. Bu tablodaki basit `%HH` örneği bütün davranışları sınamaz. `cmdLine` adı komut çalıştırıldığı anlamına gelmez; metin dönüşümüdür. `multiMatch` nedeniyle yalnız son dönüştürülmüş değeri inceleyen bir motor bu kuralın genel davranışını eksik uygular.

Dönüşümler bittiğinde ortak istekteki başlık hâlâ `%2e%2e%2fnotes.txt` olmalıdır. Diğer kurallar ve ML kendi tanımlarına göre bu içerikten çalışır.

## 6. Bulgu ve skor

Bu tek hedefteki tek başarılı eşleşme için `TX.0` değeri `../` olur. Başlangıçta iki skorun sıfır, `tx.critical_anomaly_score` değerinin 5 olduğunu varsayalım. Kuralın iki `setvar` eylemi şunu üretir:

```text
inbound_anomaly_score_pl1: 0 → 5
lfi_score:                 0 → 5
```

Bunlar iki ayrı sayaçtır; “toplam 10 saldırı puanı” veya “%5 saldırı olasılığı” demek değildir. Başlangıç değeri 5 bir demo varsayımıdır ve CRS'nin varsayılan kritik skoruyla uyumludur; bütün IDS için karar eşiği seçmiş olmuyoruz. Başka alanlarda ve kurallarda oluşacak eşleşmeler toplamı değiştirebilir.

Örnek maskelenmiş bulgu:

```text
katman: kural
kural_kimliği: 930110
alan: REQUEST_HEADERS:X-Demo-Path
açıklama: Path traversal örüntüsü eşleşti
alan_değeri: [kaydedilmedi]
```

Bu bir kural bulgusudur. Bizim karar mekanizmamız ML ve profil sonuçlarıyla birlikte nihai alarmı değerlendirecek. Örüntünün eşleşmesi, uygulamanın gerçekten dosya okuduğunu veya saldırının başarılı olduğunu kanıtlamaz.

## 7. Küçük doğrulama

Kaynak dosyadaki regex doğrudan okunup Python `re` ile aşağıdaki üç örnekte kontrol edildi. Yalnız bu ASCII girdilerinde standart yüzde çözümleme ve regex eşleşmesi doğrulandı; tam SecLang yürütmesi, bütün dönüşümler, `multiMatch`, skor eylemleri veya CRS regresyon paketi çalıştırılmış değildir.

| Alınan değer | Basit yüzde çözümleme sonrası | Önce eşleşme | Sonra eşleşme |
| --- | --- | --- | --- |
| `%2e%2e%2fnotes.txt` | `../notes.txt` | Yok | Var |
| `docs/notes.txt` | `docs/notes.txt` | Yok | Yok |
| `/get/foo../1234` | `/get/foo../1234` | Yok | Yok |

CRS'nin kendi [930110 regresyon dosyasında](/home/esip/Documents/ids-system/coreruleset-4.30.0/tests/regression/tests/REQUEST-930-APPLICATION-ATTACK-LFI/930110.yaml) da `/get/foo../1234` için bu kuralın eşleşmemesi bekleniyor. Eşleşmemek yalnız bu kural için sonuçtur; isteğin bütünüyle güvenli olduğunu göstermez.

## 8. Bu tek kural için geliştirmemiz gerekenler

1. Kural metnini okuyan ayrıştırıcı ve hazırlanmış kural yapısı.
2. Alanları seçen, tekrarları koruyan ve Referer gibi istisnaları uygulayan erişim katmanı.
3. Doğru sırada çalışan dönüşüm işlemleri ve ara eşleştirme desteği.
4. Uyumlu regex eşleştirme ve capture davranışı.
5. İsteğe özel değişkenler, makro çözümleme ve skor güncelleme.
6. Aşama, hassasiyet ve atlama davranışını yöneten yürütücü.
7. M17 kapsamını ve eksik analizi bildiren, kayıtları maskeleyen sonuç üretimi.

Bu altyapı bir kere geliştirildiğinde aynı işlemleri kullanan diğer CRS kuralları da bundan yararlanabilir. Her kural için ayrı bir Go fonksiyonu yazmak hedefimiz değil; kuralın tarif ettiği işlemleri anlayan ortak motor geliştireceğiz.

Davranış referansları: [multiMatch ve diğer eylemler](https://www.coraza.io/docs/seclang/actions/), [dönüşümler](https://www.coraza.io/docs/seclang/transformations/). Bu belgeler açıklama için kullanıldı; demo Coraza çalıştırmadı.
