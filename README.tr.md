> [!NOTE]
> Bu guvenlik aciklari yayinlanmadan once satici bilgilendirilmis ve detayli bir rapor sunulmustur. Yayinlanma tarihine kadar herhangi bir yanit alinamamistir.

# Ironshield anti-cheat statik analizi

Oyun studyolari, oyunlarinin ihtiyaclarina daha iyi cevap vermek ve hilecilere karsi daha hizli mudahale edebilmek icin kendi anti-cheat cozumlerini gelistirmeye baslamistir. Kaliteli bir ucuncu parti cozum, studyolara sifirdan gelistirme zahmetine girmeden olgun tespit mekanizmalarina erisim saglar. Ancak harici bir saglayiciya bagimli olmak, anti-cheat sistemini oyunun ozel ihtiyaclarina uyarlamayi veya hile yontemlerine istendigi kadar hizli yanit vermeyi zorlastirabilir. Gelistirmeyi sirket icinde yapmak, studyolara ne insa ettikleri ve ne zaman dagittiklari uzerinde dogrudan kontrol saglar; bu sayede onlemleri oyunlarina ozellestirebilir ve hile teknikleri gelistikce daha hizli adapte olabilirler[^nc][^eaac][^epic].

Daha fazla studyo kendi anti-cheat sistemlerini gelistirdikce, bu isin bir kismi sistem programlama ve guvenlik konusunda sinirli deneyime sahip gelistiricilere dusubilir. Bu durum ozellikle kernel-mode suruculerin dahil oldugu durumlarda risklidir; cunku uygunsuz bir implementasyon, oyuncularin sistemlerini saldirilara acik birakan guvenlik aciklari olusturabilir[^mhyprot2].

Daha once PUBG'nin anti-cheat sistemi Zakynthos'un ve AntiCheatExpert'teki Tencent VM'nin devirtualizasyonu uzerine calismalar paylasmistim. Simdi Ironshield'in kernel-mode surucusu `tvk.sys` icindeki tum virtualize edilmis fonksiyonlari statik olarak devirtualize ettim. Bu yazida, surucunun implementasyonunu inceliyor ve analizim sirasinda buldugum guvenlik aciklarini tartisiyorum.

![image](images/devirtualized-functions.png)

[^nc]: https://about.ncsoft.com/news/article/technology-push-the-boundaries-6
[^eaac]: https://www.ea.com/security/news/eaac-deep-dive
[^epic]: https://onlineservices.epicgames.com/news/epic-online-services-launches-two-new-free-services
[^mhyprot2]: https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html

# IOCTL

Analizim sirasinda surucude LPE'ye (Local Privilege Escalation) yol acabilecek birden fazla guvenlik acigi buldum.

Surucu, IOCTL payload'larini LEA sifreleme algoritmasi[^lea] ile sifreler ve surucuye baglanmaya calisan istemciler `IRP_MJ_CREATE` uzerinde yetkileri icin kontrol edilir. Ancak yalnizca `WIN_CERTIFICATE` buffer'inda `"IRONMACE Co., Ltd."` ve `"DigiCert Trusted Root G4"` string'lerinin bulunup bulunmadigini kontrol eder; PKCS blob'unu hicbir zaman parse etmez ve dogrulamaz. Bu nedenle bir saldirgan, bu string'leri iceren kendi imzaladigi (self-signed) bir sertifika olusturarak kontrolu atlatabilir ve IOCTL'ye tam erisim elde edebilir.

![image](images/certificate-check.png)

Bunu dogru sekilde uygulamak icin `CI.dll` export'lari olan `CiCheckSignedFile`, `CiValidateFileObject` ve `CiGetCertPublisherName` fonksiyonlarinin kullanilmasini siddetle oneriyorum. Ancak bir saldirgan yine de kodunu ele gecirilmis meşru bir surec uzerinden calistirabilir.

![image](images/request-decryption.png)

LEA anahtari kodda statik olarak gorunur durumdadir (devirtualize edilmis) ve her zaman ayni anahtara turetilir.

![image](images/lea-seed.png)
![image](images/lea-key-derivation.png)

Ayrica her IOCTL istegi, istek yapan surecin context'teki surecle eslesmesini dogrulamak icin bir kontrol yapar.

![image](images/client-owner-check.png)

Son olarak, admin haklari veya debug yetkisi gerektirmeyen IOCTL komutlarinin tam listesi asagidadir.

Bunlar sunlari icerir:

* Istemci tarafindan saglanan sembol offset'leri araciligiyla sinirli kernel okumalari (`g_CiOptions` sorgulamak icin)
* Rastgele surec handle'i (kernel handle'lari dahil)
* Rastgele surec sanal bellek okuma/yazma/sorgulama (`PsGetProcessSectionBaseAddress` araciligiyla taban adresi de sorgulanabilir)
* Kernel pointer sizintilari (object pre/post callback pointer'lari)

![image](images/open-process.png)

```c
#define IOCTL_TVK_POLICY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_PATH_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_PROCESS_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_SYMBOL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x842, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_OPEN_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x843, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_MODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_OPEN_PROCESS_KERNEL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x844, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_CLOSE_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x845, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_QUERY_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x846, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x847, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_IMAGE_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x848, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_CI_OPTIONS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x849, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84A, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_CREATE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_TVK_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x84C, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
```

[^lea]: https://github.com/enoma422/LEA-256/blob/ddb024e488c795e76211baed81ef8ca977d05779/LEA_C/lea.c

# Servis yapilandirmasi

Baslatma sirasinda surucu, driver entry'sine aktarilan registry yolundan servis adini cikarir ve surucu servis registry anahtarindan `Platform` ve `App` (`DWORD`) degerlerini okur. Mevcut oldugunda `RtlQueryRegistryValuesEx`, aksi halde `RtlQueryRegistryValues` kullanir. Her iki deger de okunamazsa veya kabul edilen aralik disinda kalirsa baslatma basarisiz olur.

![image](images/service-config.png)

Bu ornekte `Platform` degeri `1` ile `6` arasinda olmalidir. `App` icin kabul edilen aralik `1.0.0.165` surumunde `1`-`4`, 17 Eylul derlemesinde (`1.0.0.167`) ise `1`-`7`'dir.

Dogrulanan kimlikler surucu context'inde saklanir ve daha sonra adlandirilmis event isimleri ile object callback altitude'leri olusturmak icin kullanilir. Servis adi, device ve symbolic link adlarini olusturmak icin kullanilir.

![image](images/control-device.png)

# Dinamik kernel sembol offset'leri

Dahili kernel yapilari ve sembolleri icin offset'ler Windows derlemeleri arasinda degisiklik gosterebilir. Suruculer bu farkliliklari genellikle offset'leri hardcode ederek ve surum bazli dallanmalar araciligiyla uygun degerleri secerek yonetir; bu yontem siklikla hataya aciktir.

Bu surucu farkli bir yaklasim benimser. Surucu, IOCTL araciligiyla kullanici modu istemcisi tarafindan saglanan sembol adi hash'leri ve offset'lerinden olusan bir liste tutar. Her girdi 64-bit FNV1a hash'i ve 64-bit offset icerir. Liste dugum noktasi tahsisleri lookaside list'ten yapilir.

Bir offset'i almak icin surucu istenen adi hash'ler ve listede ilk eslesen girdiyi arar. Eslesme bulunamazsa `0` doner.

![image](images/symbol-lookup.png)

Tablo, `g_CiOptions`'i `CI.dll`'in yuklu taban adresine gore bulmak ve `_OBJECT_TYPE::CallbackList` uye offset'ini elde etmek icin kullanilir. CallbackList icin kayitli bir offset yoksa, callback numaralandirma rutini `0xC8` degerine geri doner. Offset'i mevcut degilse `g_CiOptions` sorgusu basarisiz olur.

![image](images/ci-options.png)
![image](images/callback-enumeration.png)

`g_CiOptions` icin istemci tarafindan saglanan bu sembol offset'i, sinirli (ancak yine de yeterince genis) bir kernel sanal bellek araliginin okunmasina izin verir. Adresin `CI.dll` imaj sinirlari disina cikip cikmadigi kontrol edilmez, dolayisiyla `CI.dll` tabaninin altindaki herhangi bir sey okunabilir.

![image](images/memory-copy.png)

# String kodlama

Surucu, API ve modul adlari dahil olmak uzere secili string'leri stack uzerinde yaygin bir XOR tabanli kodlama kullanarak kodlar. Her string, hardcode edilmis 32-bit bir seed kullanilarak decode edilir. Decode rutinleri her byte'i veya UTF-16 kod birimini mevcut durumun dusuk 8 veya 16 bit'i ile XOR'lar, ardindan durumu `state = 0xBC8F * state % 0x3832C5A6` olarak gunceller. Bu decode rutinleri virtualize edilmemistir.

![image](images/string-decoding.png)

# Anti-Debug kontrolu

Surucu, `KdDebuggerEnabled` degerini okuyarak tek bir hata ayiklama kontrolu yapar. Bu kontrol yalnizca surucu baslatma sirasinda gerceklestirilir.

Surucude herhangi bir anti-VM veya anti-hypervisor kontrolu bulamadim.

![image](images/debugger-check.png)

# Dinamik API tablosu

Surucunun kullandigi API'lerin cogu PE import tablosunda listelenmis olsa da bazilari surucu baslatma sirasinda dinamik olarak cozumlenir.

* `MmGetSystemRoutineAddress` 
* `ObRegisterCallbacks` 
* `ObUnRegisterCallbacks` 
* `SeLocateProcessImageName` 
* `PsGetCurrentProcessId` 
* `PsGetProcessWin32Process` 
* `PsLookupProcessByProcessId` 
* `PsGetProcessId` 
* `PsGetThreadProcessId` 
* `PsSetCreateProcessNotifyRoutineEx` 
* `ZwOpenProcess` 
* `ZwQueryInformationProcess` 
* `ZwCreateFile` 
* `ZwQueryInformationFile` 
* `ZwSetInformationFile` 
* `RtlHashUnicodeString` 
* `ZwQueryVirtualMemory` 
* `ObReferenceObjectByHandle` 
* `MmCopyVirtualMemory` 
* `PsGetProcessSectionBaseAddress` 

ntoskrnl.exe'nin taban adresi `ZwQuerySystemInformation(SystemModuleInformation)` kullanilarak elde edilir ve disk uzerindeki imajindaki export tablosu manuel olarak parse edilir.

![image](images/kernel-path.png)
![image](images/module-base.png)

API tablosu, girisleri lookaside list'ten[^lookaside] tahsis edilen bir bagli liste olarak uygulanmistir. Girdiler `api_id` degerleri ile aranir.

```c
struct TVK_API_ENTRY {
  uint32_t api_id;
  void *address;
  LIST_ENTRY links;
};
```

![image](images/api-lookup.png)

[^lookaside]: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-lookaside-lists

# Surec yonetimi

Surucu, `PsSetCreateProcessNotifyRoutineEx` kullanarak bir surec bildirim rutini kaydeder. Surec olusturma sirasinda callback, surec imaj yolunun buyuk/kucuk harf duyarsiz hash'ini hesaplar ve sifir olmayan sonuclari PID ile anahtarlanmis bir AVL tablosunda[^avl] onbellegine alir. Surec kapandiginda ilgili girdi kaldirilir. Surucu, baslatma sirasinda mevcut surecleri numaralandirmaz. Ancak imaj yolu hash'leri, sonraki bir yol kurali kontrolu onbellek kaybi ile karsilastiginda talep uzerine hesaplanabilir ve onbellege alinabilir.

![image](images/process-notify.png)
![image](images/process-path-hash.png)
![image](images/process-cache.png)

[^avl]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_rtl_avl_table

# Politika yonetimi

Yukarida aciklanan surec onbellegi, surucunun koruma kurallarini degerlendirirken kullanilir. Kullanici modu istemcisi, politika degerlerini ayarlamak, yol kurallari eklemek ve izin verilen PID ciftlerini eklemek icin ayri IOCTL istekleri araciligiyla surucuyu yapilandirir. Politika degerleri filtreleme davranisini kontrol ederken, kural kategorileri hedefleri ve istisnalari tanimlar.

![image](images/policy-functions.png)
![image](images/policy-lookup.png)

Politika kimlikleri ve kural kategori kimlikleri ayri anlamlara sahiptir; yol tabanli kurallar `RtlHashUnicodeString` kullanilarak hesaplanan buyuk/kucuk harf duyarsiz 32-bit hash'ler olarak saklanir. Izin verilen PID ciftleri siralanmis kaynak-hedef ciftleri olarak saklanir. Kural girdileri bagli listelerde tutulur ve lookaside list'lerden tahsis edilir. Asagidaki kural kategorileri kullanilmaktadir.

![image](images/protected-process.png)
![image](images/process-rule-match.png)

| Politika | Aciklama                                                                                                    |
| -------- | ----------------------------------------------------------------------------------------------------------- |
| 0        | Surec ve thread object callback'lerinin kaydedilmesini ve kaldirilmasini kontrol eder.                      |
| 1        | Bilinmiyor                                                                                                  |
| 2        | Bilinmiyor                                                                                                  |
| 3        | Engelleme, engellemeyen ve devre disi modlar dahil olmak uzere DLL filtreleme davranisini secer.             |
| 4        | Minifilter etkinlestirme kontrolune katilir. DLL filtreleme yine de aktif bir politika 3 degeri gerektirir. |

| Kategori | Aciklama                                          |
| -------- | ------------------------------------------------- |
| 1        | Korunan sureclerin hash'leri                      |
| 2        | Handle filtrelemesinden muaf arayanların hash'leri |
| 3        | Izin verilen kaynak-hedef PID ciftleri            |
| 4        | DLL filtrelemesine tabi sureclerin hash'leri       |
| 5        | Minifilter tarafindan kontrol edilen DLL yol hash'leri |

# Nesne yonetimi

Politika `0`, surec ve thread object callback'lerinin kaydedilmesini kontrol eder. Handle olusturma veya coglama sirasinda bu callback'ler, korunan hedefleri ve uygulanabilir istisnalari belirlemek icin 1-3 arasi kural kategorilerine basvurur.

![image](images/process-access-filter.png)
![image](images/thread-access-filter.png)

Korunan veya muaf sureclerin yanı sıra acikca izin verilen PID ciftlerinden gelen cagrilar filtrelemeden haric tutulur. Filtreleme kosullari karsilandiginda callback'ler handle'dan erisim haklarini cikarir.

# Minifilter

Politika `3`, bir minifilter araciligiyla DLL filtrelemesini kontrol eder. Calistirilabilir bolum olusturma sirasinda (`IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` olarak bilinir), filtre mevcut surecin kural kategorisi `4` ile eslesip eslesmedigini ve dosyanin `.dll` uzantisina sahip olup olmadigini ve yol hash'inin kategori `5` ile eslesip eslesmedigini kontrol eder.

![image](images/dll-filter-check.png)
![image](images/dll-path-match.png)

`0x5044424C` politika degeri ile eslesen istekler `STATUS_ACCESS_DENIED` ile tamamlanir. Alternatif aktif deger `0x50444445` ise kontrolleri islemi reddetmeden gerceklestirir.

![image](images/dll-block.png)

# Log sifreleme

Surucu, diske sifreli formda kaydedilen kendi ozel log mekanizmasini uygular. Log yazici, `\??\<taban yolu>\Tavern\tvk.bin` formunda bir hedef yol olusturur. Dosya yazma islemleri yalnizca `g_TvkLoggingInitialized` ayarlandiginda ve mevcut IRQL `PASSIVE_LEVEL` oldugunda gerceklestirilir.

Ancak analiz edilen binary icinde `g_TvkLoggingInitialized`, yol buffer'i veya log anahtarinin baslatilmasini tespit edemedim; bu nedenle bunlar buyuk olcude ve pratik olarak olukod (dead code) durumundadir.

![image](images/log-functions.png)
![image](images/log-path.png)

Log yazici, her mesaji 256 byte'lik bir ANSI buffer'da biclimlendirir ve UTF-16'ya donusturur. Yerel zaman damgasi ve mesaj, LEA-CBC kullanilarak ayri ayri sifrelenir. Her duz metin, nul sonlandiricisini icerir ve 16 byte'a sifir hizalanir. Her iki sifreleme de ayni hardcode edilmis IV (baslangic vektoru) ve log'a ozel bir LEA anahtari kullanir.

![image](images/log-encryption.png)

Her sifreli kayit, sifreli metin uzunlugunu `0x12C8BA67` ile XOR'lanmis olarak iceren dort byte'lik, little-endian bir degerle oneklenir. Dolayisiyla bir log girdisi, bir zaman damgasi kaydinin ardindan gelen bir mesaj kaydindan olusur. Kayitlar `ZwWriteFile` kullanilarak eklenir.

![image](images/log-append.png)

Eklemeden once yazici, mevcut log'un 5 MiB'a ulasip ulasmadigini kontrol eder. Ulastiysa dosyayi tvk.bin.001'e kopyalamayi dener ve ardindan orijinali siler.

![image](images/log-rotation.png)

# Sonuc

Oncu yapay zeka henuz karmasik binary'leri kendi basina guvenilir bir sekilde deobfuscate edemese de, hizli ilerlemesi hangi obfuscation'larin otomatik deobfuscation'a gercekten direncli oldugunu ve hangilerinin yalnizca karmasik gorundugun ortaya koymaktadir.

Devirtualizasyon calismami paylasarak, yazilim obfuscation'i icin cistayi yukseltmeyi ve neyin ise yarayip neyin yaramadigi hakkinda daha bilingli bir tartismaya katkida bulunmayi umuyorum. Bu cabalarin, alanin odagini obfuscate edilmis kodun ne kadar karmasik gorundugundan, pratikte deobfuscation'a ne kadar iyi dayandigi yonune kaydirmasina yardimci olmasini bekliyorum.

Bu calismaya devam edecek ve yol boyunca ogrendiklerimi paylasacagim.
