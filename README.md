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

---

### Yasal Uyarı / Sorumluluk Reddi

Bu yazılım (`PortableScan`) yalnızca analiz, eğitim ve güvenlik denetimi amacıyla sağlanmaktadır. Yazılımın kullanımından doğabilecek hiçbir doğrudan veya dolaylı maddi/manevi zarardan, veri kaybından veya yasal sorumluluktan geliştirici sorumlu tutulamaz. Tüm sorumluluk tamamen kullanıcıya aittir.

---

## Öne Çıkan Özellikler ve Çalışma Mantığı

* **Güvenli Statik Analiz:** PowerShell, Python, JavaScript, VBScript, Batch ve arşiv dosyalarını hiçbir kodu yürütmeden, içe aktarmadan veya diske yazmadan tamamen güvenli bir şekilde inceler.
* **Gizlenmiş İçerik Çözücü:** Base64, Hex, karakter kodları ve URL encoding ile gizlenmiş metin katmanlarını otomatik olarak deşifre ederek okunabilir hale getirir.
* **Gelişmiş Kural Motoru:** Regex kalıpları ve YARA kuralları sayesinde şüpheli komutları, reverse shell (uzaktan kontrol) izlerini, antivirüs kapatma girişimlerini ve zararlı API çağrılarını yakalar.
* **VirusTotal & Windows Defender Entegrasyonu:** Dosya SHA256 hash değerini VirusTotal'de sorgular veya yerleşik Windows Defender ile rapor modunda (`-DisableRemediation`) tarama gerçekleştirir.
* **Dijital İmza & Entropi Kontrolü:** Çalıştırılabilir dosyaların yayıncı imzalarını doğrular, paketlenmiş (packer) veya şifrelenmiş içerikleri entropi analiziyle tespit eder.

---

## Kullanılan Kütüphaneler ve Teknolojiler

Projenin geliştirilmesinde kullanılan harici Python paketleri ve yerleşik modüller:

* **CustomTkinter:** Modern, şık ve koyu/aydınlık tema desteğine sahip arayüz altyapısı.
* **tkinterdnd2:** Pencereye dosya sürükleyip bırakma (`Drag & Drop`) işlevini sağlayan bileşen.
* **yara-python:** Gelişmiş imza ve kural tabanlı statik tarama desteği (`YARA` kuralları).
* **Pillow (PIL):** `.ico` simge formatlarını dönüştürmek ve yönetmek için kullanılan görsel işleme kütüphanesi.
* **Python Standart Modülleri:** `base64`, `hashlib`, `subprocess`, `zipfile`, `json`, `math`, `os`, `re`, `threading`, `urllib`, `webbrowser`, `winreg` (Windows kayıt defteri ve sistem işlemleri için).
