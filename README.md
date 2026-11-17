# PortableScan
Dosyaları çalıştırılmadan (statik analiz yaparak) inceleyen, içinde ne olduğunu ve ne amaçla yazıldığını sade bir dille açıklayan masaüstü güvenlik aracı[cite: 1].

---

### Ne İşe Yarar?

İnternetten indirdiğin veya güvenliğinden emin olmadığın betikleri ve programları riske atlamadan analiz etmeni sağlar. Kodu asla çalıştırmaz, içe aktarmaz veya diske zararlı bir şey yazmaz; tamamen statik okuma ve kalıp tespiti yapar[cite: 1].

---

### Öne Çıkan Özellikler

* Çalıştırmadan Analiz: PowerShell, Python, JavaScript, VBScript, Batch ve daha birçok formatı güvenle tarar[cite: 1].
* Gizlenmiş İçerik Çözücü: Base64, Hex, karakter kodları veya URL encoding ile gizlenmiş metinleri otomatik olarak çözer (hiçbir şey çalıştırmadan sadece metin katmanlarını açarak okunaklı hale getirir)[cite: 1].
* Regex Kural Motoru: Şüpheli komutları (iex kullanımı, internetten dosya indirip çalıştırma, antivirüsü devre dışı bırakma, uzaktan kontrol/reverse shell izleri vb.) yakalar ve risk puanı hesaplar[cite: 1].
* VirusTotal & Windows Defender Entegrasyonu: SHA256 hash değerini VirusTotal'de sorgulayabilir veya yerleşik Windows Defender ile rapor modunda (-DisableRemediation) tarama yapabilir[cite: 1].
* Dijital İmza Kontrolü: Çalıştırılabilir dosyaların imza durumunu ve yayıncısını denetler[cite: 1].
* Modern Arayüz: CustomTkinter altyapısıyla geliştirilmiştir, sürükle-bırak desteği ve Windows sağ tık menü entegrasyonu sunar[cite: 1].

---

### Kurulum ve Çalıştırma

Releases kısmından ".exe" dosyasını indirip açmanız yeterlidir.
