# PortableScan
Dosyaları çalıştırılmadan (statik analiz yaparak) inceleyen, içinde ne olduğunu ve ne amaçla yazıldığını sade bir dille açıklayan masaüstü güvenlik aracı.

---

### Ne İşe Yarar?

İnternetten indirdiğin veya güvenliğinden emin olmadığın betikleri ve programları riske atlamadan analiz etmeni sağlar. Kodu asla çalıştırmaz, içe aktarmaz veya diske zararlı bir şey yazmaz; tamamen statik okuma ve kalıp tespiti yapar.

---

### Öne Çıkan Özellikler

* Çalıştırmadan Analiz: PowerShell, Python, JavaScript, VBScript, Batch ve daha birçok formatı güvenle tarar.
* Gizlenmiş İçerik Çözücü: Base64, Hex, karakter kodları veya URL encoding ile gizlenmiş metinleri otomatik olarak çözer (hiçbir şey çalıştırmadan sadece metin katmanlarını açarak okunaklı hale getirir).
* Regex Kural Motoru: Şüpheli komutları (iex kullanımı, internetten dosya indirip çalıştırma, antivirüsü devre dışı bırakma, uzaktan kontrol/reverse shell izleri vb.) yakalar ve risk puanı hesaplar.
* VirusTotal & Windows Defender Entegrasyonu: SHA256 hash değerini VirusTotal'de sorgulayabilir veya yerleşik Windows Defender ile rapor modunda tarama yapabilir.
* Dijital İmza Kontrolü: Çalıştırılabilir dosyaların imza durumunu ve yayıncısını denetler[cite: 1].
* Modern Arayüz: CustomTkinter altyapısıyla geliştirilmiştir, sürükle-bırak desteği ve Windows sağ tık menü entegrasyonu sunar.

---

### Kurulum ve Çalıştırma

Releases kısmından ".exe" dosyasını indirip açmanız yeterlidir.
