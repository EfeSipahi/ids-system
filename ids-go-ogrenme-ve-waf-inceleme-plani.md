# Go öğrenme ve WAF inceleme planı

Tarih: 2 Ekim 2026

## 1. Amaç ve mevcut durum

1. Go'nun mantığını anlayıp yazdığımız kodun sorumluluğunu alabilecek seviyeye gelmek; ardından Coraza ve CrowdSec'i inceleyerek kendi IDS mimarimize gerekçeli kararlar çıkarmak.
2. Go şu an çekirdek için öne çıkan tercihimiz. Bu öğrenme planı, bütün teknoloji seçimlerinin veya Coraza entegrasyonunun kesinleştiği anlamına gelmez. Önceki `ids-development-plan-faze1.md` belgesindeki Python merkezli öneriler de tartışma taslağıdır.
3. Onaylı ürün kararlarının kaynağı `ids-system-plan-faze1.md`: ilk aşama HTTP tespiti, istek kopyası üzerinden analiz, TLS sonlandıran hazır proxy, ayrı katman bulguları ve maskelenmiş kayıtlar. Önleme ve trafikten profil öğrenme sonraki aşamalardır.
4. Bu belge bir öğrenme yoludur. Aşağıdaki çalışmalar henüz yapılmış değildir. Mevcut veri, model ve deney sonuçları bu çalışma kapsamında değiştirilmeyecek.
5. Önceki dil deneyimi henüz netleşmediği için temel programlama bilgisi varsayılmıştır. Değişken, fonksiyon ve döngü de yeniyse ilk iki oturumu genişleteceğiz. Oturumlar takvim zorunluluğu değil; konu anlaşılınca ilerleme noktalarıdır.

## 2. Birlikte çalışma prensipleri

1. **Bir oturum, bir ana konu:** Önce neden gerekli olduğunu konuşacağız, sonra küçük örneği okuyup çıktısını tahmin edeceğiz; ardından sen küçük bir değişiklik yapacaksın.
2. **Tek küçük alıştırmayı büyütmek:** Yapay HTTP kayıtlarını okuyup özetleyen bir komut satırı programı üzerinden ilerleyebiliriz. Bu bir öğrenme alıştırması olacak; gerçek saldırı tespit motoru veya ikinci bir IDS prototipi sayılmayacak.
3. **Önce anlaşılır ve doğru kod:** Hız için önce nerede süre harcandığını ölçeceğiz. Go seçimi tek başına gecikme hedefini garanti etmez.
4. **Sınırlı kaynak kullanımı:** Gövde boyutu, bekleme süresi, kuyruk ve eşzamanlı iş sayısının sınırlarını düşünmeyi alışkanlık yapacağız.
5. **Az bağımlılık, açık sorumluluk:** Öğrenirken standart kütüphaneyle başlayacağız. Her katmana başka dil seçmeyeceğiz. Mevcut Python ML çalışmasının Go ile nasıl konuşacağı ayrı bir mimari karar olacak.
6. **Anlamadan otomatik ilerlememek:** Bir bölümü, kodun ne yaptığını ve hata halinde ne olacağını kendi cümlelerinle anlatabildiğinde tamamlanmış sayacağız. Tam uygulamayı otomatik yazmak bu aşamanın amacı değil.

## 3. Go öğrenme sırası

Öneri: 10 çalışma oturumu; gerekirse bir oturum birkaç güne yayılabilir. İlk 6 oturum Go temeli, sonraki 3 oturum sistem incelemesi, son oturum kararların toparlanmasıdır.

| Oturum | Konu ve mantığı | Küçük çalışma | Anladığımızı nasıl anlayacağız? |
| --- | --- | --- | --- |
| 1 | Derleme, `main`, paket, modül, `go.mod`; `go run`, `go build`, `go fmt` | Sabit bir istek metodunu ve yolunu yazdırmak | Kaynak kod, bağımlılık tanımı ve çalıştırılabilir dosya farkını açıklamak |
| 2 | Tipler, sıfır değerleri, `if`, `for`, fonksiyonlar, slice ve map | Birkaç yapay kaydı metoda göre saymak | Boş liste ve bulunmayan map anahtarında ne olacağını açıklamak |
| 3 | `struct`, metot, pointer ve küçük interface; kalıtım yerine parçaları birleştirmek | İstek özeti için bir struct; değerle veya pointer ile değiştirmenin farkı | Hangi veri kopyalanıyor, hangi değişiklik çağırana yansıyor göstermek |
| 4 | Birden fazla dönüş değeri, `error`, `defer`, dosya/JSON okuma, `go test` | Aynı kayıtları dosyadan okumak; bozuk JSON için hata ve anlamlı test | Okuma hatasını normal kayıt gibi saymamak; kaynağın nasıl kapandığını anlatmak |
| 5 | `net/http`, `net/url`, `io.Reader`; header, query ve body farkı | Bellekte bir HTTP isteğini okuyup yalnız güvenli özet üretmek | Tekrarlanan parametrelerin kaybolmaması, body'nin okunması ve boyut sınırının etkisini açıklamak |
| 6 | Goroutine, channel, mutex, `context`; eşzamanlılık ve paralellik farkı | Aynı alıştırmada az sayıda işçi ve sınırlı kuyruk; iptal sinyalini ele almak | Kuyruk dolunca ne oluyor, işler nasıl bitiyor, paylaşılan veriyi kim değiştiriyor anlatmak |

Go'nun temel öğrenme rotası için [resmî başlangıç dersleri](https://go.dev/doc/tutorial/) ve [A Tour of Go](https://go.dev/tour/) kullanılacak. Önce temeller, sonra methods/interfaces, en son concurrency bölümleri okunacak. Bunlar öğrenme kaynağıdır; bütün örnekleri projeye taşımak gerekmiyor.

Go kodunu okurken özellikle şu düşünceleri yerleştireceğiz: tipler sözleşmeyi açıklar; struct veriyi bir arada tutar; interface gereken davranışı tarif eder; `error` çağıranın ele alacağı bir sonuçtur; `defer` fonksiyon çıkışındaki temizliği düzenler. [Effective Go](https://go.dev/doc/effective_go) bu konularda yardımcı okuma olacak; belge eski olduğu ve modüller gibi yeni konuları kapsamadığı için tek başına başlangıç rehberi olarak kullanılmayacak.

`context`, zaman sınırı ve iptal bilgisini taşır; başlatılmış her işi kendiliğinden zorla durdurmaz. İş yapan kodun veya kullandığı API'nin iptali dikkate alması gerekir. Bu ayrıntıyı 6. oturumda işleyeceğiz. [Go context belgeleri](https://pkg.go.dev/context)

İlk turda generics ayrıntıları, reflection, `unsafe`, özel web framework'leri ve mikroservis altyapıları önceliğimiz değil. Coraza kodunu okurken ihtiyaç duyduğumuz kadarına geri döneceğiz.

## 4. Coraza incelemesi — 7 ve 8. oturum

**Öğrenme sorumuz:** Tek bir HTTP isteği nasıl kurallara giriyor ve açıklanabilir bir bulguya dönüşüyor?

Coraza, uygulamaya gömülebilen bir Go WAF motorudur. OWASP CRS ise motor üzerinde çalıştırılabilen bir kural kümesidir; motor ve kuralların görevini ayrı öğreneceğiz. [Coraza giriş](https://www.coraza.io/docs/tutorials/introduction/)

1. **7. oturum — İstek yolunu takip et:** Giriş belgesini ve [Quick Start](https://www.coraza.io/docs/tutorials/quick-start/) örneğini oku. Ortak WAF yapılandırması ile her istek için oluşturulan transaction'ın farkını çıkar. Transaction, o isteğin inceleme durumunu taşır.
2. **Aşamaları ayır:** Header ve body işleme aşamalarını takip et. Coraza yanıt inceleme aşamaları da sunar; bizim ilk kapsamımız istek incelemesidir. Günlükleme aşamasının sorumluluğunu ayrıca not et. [İşleme akışı](https://www.coraza.io/docs/seclang/execution-flow/)
3. **8. oturum — Bir kuralı oku:** Basit bir kuralın hangi alana baktığını, neyi eşleştirdiğini ve ne sonuç ürettiğini açıkla. Sonra CRS içinden bir SQLi kuralını incele. Tüm kuralları ezberlemeye çalışma.
4. **Sınırları incele:** Desteklenmeyen veya büyük body, ayrıştırma hatası, dönüşümler, kural istisnaları ve hassas verinin audit kaydına taşınması için belgelerdeki davranışı ara. Bulamadığını varsaymak yerine açık soru olarak yaz.
5. **Kod okuma sınırı:** Önce [resmî deponun](https://github.com/corazawaf/coraza) README örneği ve dışarı açılan API; ardından yalnız bir isteğin geçtiği fonksiyonlar. İnceleme tarihinde bakılan sürümü veya commit'i not et; sitedeki örnekle kaynak kod farklıysa sürümü esas al.

**Oturum çıktısı:** Bir sayfada “istek → ayrıştırma → kural değerlendirmesi → bulgu → kayıt” akışı ve üç açık entegrasyon sorusu.

Bizim için kritik ayrım: Engellemeyi kapatmak, analiz işlemini kendiliğinden asenkron yapmaz. Coraza'yı kullanırsak istek kopyasını nerede değerlendireceğimizi ayrıca tasarlamamız gerekir. Hazır middleware örneğini doğrudan kullanmanın M09 kararını sağladığını varsaymayacağız.

## 5. CrowdSec incelemesi — 9. oturum

**Öğrenme sorumuz:** Tespit, karar ve kararı uygulama görevleri birbirinden nasıl ayrılıyor?

CrowdSec, WAF'tan daha geniş bir güvenlik sistemidir. Log Processor veriyi analiz eder; Local API bileşenler arasında karar iletişimini sağlar; remediation bileşenleri, yani bouncer'lar, kararları uygular. [CrowdSec mimarisi](https://docs.crowdsec.net/docs/intro/)

1. Önce veri toplama, parser ile olay çıkarma, senaryo ile davranış değerlendirme, alarm/karar ve uygulama bileşenlerinin görevlerini çiz. Bir HTTP isteğindeki içerik kontrolüyle zaman içindeki çok sayıda olayın değerlendirilmesini ayır.
2. Sonra [AppSec girişini](https://docs.crowdsec.net/docs/appsec/intro/) oku. AppSec WAF, HTTP isteklerini değerlendirir. In-band kurallar mevcut isteğin yanıtını etkileyebilir; out-of-band kurallar arka planda değerlendirilir. Bu iki yolun sırayla nasıl işletildiğini incele.
3. “Out-of-band var” bilgisinden tüm entegrasyonun gecikmesiz veya bizim kopya mimarimizle aynı olduğu sonucunu çıkarma. Web sunucusunun hangi cevabı beklediğini ayrıca göster.
4. [Resmî depoda](https://github.com/crowdsecurity/crowdsec) README ve bileşen girişlerini incele. Bütün depoyu okumak yerine tek bir olayın nereden gelip nereye gittiğini takip et.

**Oturum çıktısı:** Bileşenlerin görevlerini gösteren küçük bir çizim ve “şimdi faydalanırız / sonraki faza bırakırız” notu. Davranış senaryolarını incelemek, onları Faz 1 kapsamına eklemek anlamına gelmez.

## 6. İncelemeden kendi kararımıza — 10. oturum

Aşağıdaki tabloyu inceleme bittikten sonra dolduracağız. Bir ürünün özelliğiyle bizim için uygun olduğu sonucunu ayrı yazacağız.

| Konu | İncelemede kaydedilecek bilgi | Bizim karar sorumuz |
| --- | --- | --- |
| Kurallar | Motor, kural kümesi, bulgu alanları ve kullanım lisansı | Coraza + CRS kural katmanımız olabilir mi? |
| İstek aktarımı | Giriş biçimi, gövde sınırı, hangi bileşenin beklediği | Asenkron kopya incelemesini nasıl koruyoruz? |
| Katmanlar | Üretilen bulgular ve skorların anlamı | Kurallar, ML ve profil sonuçlarını nasıl ayrı tutuyoruz? |
| Gizlilik | Günlükleme, body saklama ve hata mesajları | Gerçek değerle analiz, maskelenmiş kayıt ilkesini nasıl uyguluyoruz? |
| Arıza ve yük | Süre sınırı, kuyruk, eksik analiz davranışı | Kapasite yetmediğinde durumu nasıl görünür kılıyoruz? |
| Dil sınırı | Go çekirdeği ile mevcut Python ML'nin sorumlulukları | Özellik çıkarımını iki dilde tekrarlamadan nasıl bağlanıyoruz? |

**Beklenen sonuç:** Bir sayfalık mimari karar taslağı. Hangi hazır bileşeni hangi gerekçeyle kullanacağımızı, kendi geliştireceğimiz kısmı ve açık kalan soruları yazacağız. Kararları yine tek tek konuşacağız.

Birden fazla motor veya alternatif uygulama geliştirmek planın parçası değil. Belgelerden çözülemeyen ve seçimi gerçekten etkileyen bir soru kalırsa, yalnız o soruya yönelik küçük bir doğrulama çalışmasının gerekip gerekmediğine karar vereceğiz.

## 7. Geliştirmeye başlamaya hazır olma ölçütü

1. Küçük bir Go programının veri ve hata akışını açıklayabiliyorum.
2. Bir HTTP isteğinin Coraza'da hangi aşamalardan geçtiğini anlatabiliyorum.
3. CrowdSec'te tespit, karar ve engellemeyi hangi bileşenlerin yaptığını ayırabiliyorum.
4. Bizim ilk sürümümüzde proxy, kural katmanı, ML, uygulama profili ve karar mekanizmasının görevlerini çizebiliyorum.
5. Henüz vermediğimiz kararları, öğrenilmiş gerçeklerden ayırabiliyorum.

Başlangıç işi yalnız 1. oturum: Go programı nasıl çalışır, paket/modül nedir, derleme ne demektir? Sonraki konuları bu temel oturduktan sonra ele alacağız.
