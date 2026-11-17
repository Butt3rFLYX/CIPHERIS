<p align="center"><img src="packaging/brand/logo.svg" width="96" alt="CIPHERIS logosu"></p>

<h1 align="center">CIPHERIS</h1>

<p align="center">Görsellerin içine gizlenmiş şifreli mesajlar. Çevrimdışı, kendi bilgisayarınızda.</p>

<p align="center"><a href="README.md">English</a> · <a href="README.de.md">Deutsch</a> · <b>Türkçe</b></p>

CIPHERIS bir metin mesajını şifreler ve bir görselin içine gizler. Görsel öncekiyle aynı görünür; mesajı yalnızca oluşturulan anahtara sahip olan kişi yeniden okuyabilir. Her şey yerel olarak çalışır: hesap yok, bulut yok, internet bağlantısı yok.

## Kurulum

**İndirme (önerilen):** sisteminize uygun dosyayı [Releases](../../releases) sayfasından indirin.

| Sistem | Dosya | İlk başlatma |
| --- | --- | --- |
| macOS (Apple Silicon ve Intel) | `CIPHERIS-macOS.zip` | zip'i açın, `CIPHERIS.app` uygulamasını *Uygulamalar* klasörüne sürükleyin, bir kez açın (aşağıya bakın) |
| Windows | `CIPHERIS-Windows.zip` | zip'i açın, `CIPHERIS.exe` dosyasına çift tıklayın; Windows uyarırsa *Ek bilgi*, ardından *Yine de çalıştır* seçin |
| Linux | `CIPHERIS-Linux.tar.gz` | arşivi açın ve `./cipheris` komutunu çalıştırın |

**macOS'ta ilk başlatma.** Uygulama Apple tarafından onaylanmadığı (notarize edilmediği) için macOS ilk açılışı engeller. macOS 15 ve sonrası: uygulamayı bir kez açmayı deneyin, ardından *Sistem Ayarları* → *Gizlilik ve Güvenlik* bölümüne gidin, aşağı kaydırın ve *Yine de Aç* düğmesine tıklayın. Daha eski sürümlerde: uygulamaya sağ tıklayın ve *Aç* seçin. Bu yalnızca bir kez gereklidir.

Her sürüm `SHA256SUMS.txt` dosyasında sağlama toplamları içerir. İlk başlatmadan önce indirdiğiniz dosyayı `shasum -a 256 <dosya>` (macOS, Linux) ya da `Get-FileHash <dosya>` (Windows) ile kontrol edin. Uygulamalar ücretli bir Apple veya Microsoft sertifikasıyla imzalanmadığı için ilk açılışta bir uyarı görünür.

**Kendiniz derleyin:** [İngilizce README](README.md#install) dosyasına bakın.

CIPHERIS macOS ve Windows'ta kendi penceresinde, Linux'ta ise tarayıcınızda açılır. Her iki durumda da yalnızca kendi bilgisayarınızla iletişim kurar. Pencerede kaydedilen görseller *İndirilenler* klasörüne gider ve ardından bu klasör açılır. Windows'ta pencere, Windows 10 ve 11'de yerleşik olan Microsoft Edge WebView2'yi kullanır; yoksa CIPHERIS bunun yerine tarayıcıda açılır. Arayüz Türkçe, Almanca ve İngilizce olarak kullanılabilir; sisteminizin dilini izler ve sağ üstten değiştirilebilir (DE, TR, EN). CIPHERIS *kapat* düğmesiyle ya da sekmeyi kapattıktan birkaç dakika sonra kendiliğinden durur.

## Kullanım

**Mesaj gizleme**

1. *görsel* alanına bir görsel sürükleyin. Fotoğraflar (JPEG, HEIC ve diğerleri) PNG'ye dönüştürülür.
2. Mesajı yazın. Gösterge, mesajın görselin ne kadarını kullandığını gösterir.
3. *mesajı gizle* düğmesine basın, ardından *görseli kaydet* düğmesine basın ve anahtarı kopyalayın.

**Mesaj okuma**

1. *çöz* sekmesine geçin ve CIPHERIS'in oluşturduğu PNG dosyasını sürükleyin.
2. Anahtarı yazın ya da yapıştırın. Büyük/küçük harf, boşluk ve tireler önemli değildir; yazım hataları algılanır.
3. *mesajı çöz* düğmesine basın.

**Unutmayın**

* Anahtar olmadan mesaj kaybolur. Kurtarma imkânı yoktur.
* Görseli ve anahtarı farklı kanallardan gönderin.
* Görseli **dosya** olarak gönderin (e-posta eki, AirDrop, USB bellek, bulut bağlantısı). Mesajlaşma uygulamaları ve sosyal ağlar görselleri sıkıştırır ve mesajı yok eder.
* Her görseli yalnızca bir kez kullanın ve orijinali yenisiyle birlikte paylaşmayın.
* Tarayıcıda (Linux) her sayfayı okuyabilen uzantılar CIPHERIS'i de okuyabilir. Hassas mesajlar için uzantısız bir tarayıcı profili kullanın. macOS ve Windows'taki uygulama penceresinde uzantı yoktur.

## CIPHERIS neyi korur, neyi korumaz

| Özellik | Durum |
| --- | --- |
| Anahtar olmadan mesaj okunamaz | Evet. Argon2id ve XChaCha20 Poly1305, her mesaj için yeni ve rastgele 128 bitlik bir anahtar. |
| Değiştirilmiş ya da bozulmuş bir görsel algılanır | Evet. Gizli verideki her değişiklik yanlış metin değil, "Mesaj bulunamadı" sonucunu verir. |
| Anahtar olmadan bulunabilecek bir işaret yoktur | Evet. Konumlar anahtara bağlıdır. |
| Orijinalin meta verileri (EXIF, GPS, kamera) | Yeni görselden kaldırılır. |
| Kimse gizli bir mesajdan şüphelenemez | **Garanti edilmez.** İstatistiksel analiz gizli verileri, özellikle küçük görsellerdeki uzun mesajları fark edebilir. CIPHERIS %5'in üzerindeki kullanımda uyarır. |
| Kötü amaçlı yazılım bulunan bir bilgisayarda koruma | Hayır. Bkz. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (İngilizce). |

CIPHERIS henüz bağımsız bir güvenlik denetiminden geçmedi. Ayrıntılar (İngilizce): [güvenlik politikası](SECURITY.md), [tehdit modeli](docs/THREAT_MODEL.md), [dosya biçimi](docs/FORMAT.md).

## Lisans

MIT, bkz. [LICENSE](LICENSE).
