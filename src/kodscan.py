#!/usr/bin/env python3
"""kodscan - dosyayı ÇALIŞTIRMADAN inceleyen masaüstü uygulaması.
Kurulum: pip install customtkinter tkinterdnd2   |   Çalıştır: python kodscan_app.py"""
import base64, glob, hashlib, io, subprocess, sys, time, zipfile, json, math, os, re, threading, urllib.error, urllib.parse, urllib.request, webbrowser
from collections import Counter

PORT = 8765
MAX_UPLOAD = 32 * 1024 * 1024
TEXT_EXT = {".ps1", ".psm1", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".py", ".sh", ".hta",
            ".wsf", ".php", ".rb", ".pl", ".txt", ".reg", ".json", ".html", ".htm", ".lnk.txt"}

# (regex, ağırlık, başlık, düz dille açıklama)
RULES = [
    (r"-e(nc|ncodedcommand)\s+[A-Za-z0-9+/=]{20,}", 30, "Kodlanmış PowerShell komutu", "Komut base64 ile gizlenmiş. Gerçek amacı okunamıyor; zararlılar bunu sık kullanır."),
    (r"\b(iex|invoke-expression)\b", 20, "Metni kod olarak çalıştırma", "Bir metni alıp doğrudan komut olarak çalıştırıyor."),
    (r"(downloadstring|invoke-restmethod|invoke-webrequest|\biwr\b|net\.webclient|\bcurl(\.exe)?\b[^\n]{0,200}https?://|\bwget\b[^\n]{0,200}https?://)", 5, "İnternete bağlanıp veri okuyor", "Bir internet adresine bağlanıp içerik okuyor. Sürüm kontrolü, güncelleme sorgusu gibi meşru işlerde de böyle yapılır; önemli olan okuduğunu ne yaptığıdır."),
    (r"(downloadfile|-outfile|start-bitstransfer|urldownloadtofile|\bcurl(\.exe)?\b[^\n]{0,200}\s(-o|-O|--output)\s|\bwget\b[^\n]{0,200}\s(-O|-o)\s|certutil[^\n]{0,80}-urlcache|bitsadmin[^\n]{0,80}/transfer)", 15, "İnternetten dosya indirip kaydediyor", "Bir dosyayı internetten indirip bilgisayara kaydediyor. Güncelleyiciler de bunu yapar, ama indirilen dosyanın ne olduğuna bakmak gerekir."),
    (r"(downloadfile|-outfile|\bcurl(\.exe)?\b[^\n]{0,200}\s(-o|-O|--output)\s|\bwget\b[^\n]{0,200}\s(-O|-o)\s|certutil[^\n]{0,80}-urlcache|bitsadmin[^\n]{0,80}/transfer).{0,600}\b(start|call|invoke-item)\s+\"?[\w.\\/%-]+\.(exe|msi|bat|cmd|ps1|vbs|js)", 20, "İndirdiği dosyayı çalıştırıyor", "İnternetten indirdiği bir programı hemen çalıştırıyor. Kurulum/güncelleme araçları da yapar, ama indirilen kaynağa güvenilmiyorsa tehlikelidir."),
    (r"(\b(iex|invoke-expression)\b[^\n]{0,200}(downloadstring|invoke-restmethod|invoke-webrequest|\biwr\b|webclient)|(downloadstring|invoke-restmethod|invoke-webrequest|\biwr\b|webclient)[^\n]{0,200}\b(iex|invoke-expression)\b)", 20, "İndirdiği metni doğrudan çalıştırıyor", "Internetten aldığı içeriği hiç incelemeden komut olarak çalıştırıyor. Zararlılarda çok yaygın bir yöntemdir."),
    (r"(-w(indowstyle)?\s+hidden|-nop\b|-ep\s+bypass|executionpolicy\s+bypass)", 20, "Gizli çalışma / güvenlik kısıtı atlatma", "Pencereyi gizliyor veya PowerShell kısıtlarını devre dışı bırakıyor."),
    (r"\b(certutil|bitsadmin|mshta|regsvr32|rundll32|wmic)\b.{0,80}(http|-urlcache|-decode|scrobj|process\s+call)", 25, "Windows araçlarını kötüye kullanma", "Sistemdeki meşru bir aracı indirme/çalıştırma için kullanıyor."),
    (r"(currentversion\\run|schtasks\s+/create|\\startup\\|new-scheduledtask)", 20, "Açılışta kendini çalıştırma", "Bilgisayar her açıldığında kendini yeniden başlatacak bir kayıt ekliyor."),
    (r"(set-mppreference|add-mppreference.{0,40}exclusion|disableantispyware|netsh\s+advfirewall.{0,30}off)", 30, "Antivirüsü/güvenlik duvarını kapatma", "Windows Defender veya güvenlik duvarını devre dışı bırakmaya çalışıyor."),
    (r"(vssadmin.{0,20}delete\s+shadows|wbadmin\s+delete|bcdedit.{0,40}recoveryenabled)", 40, "Yedekleri silme", "Sistem geri yükleme noktalarını siliyor; fidye yazılımlarında görülür."),
    (r"(\beval\s*\(|new\s+function\s*\(|unescape\s*\(|fromcharcode)", 15, "Dinamik kod / karakter kodu ile gizleme", "Kod çalışma anında üretiliyor veya karakter kodlarıyla saklanıyor."),
    (r"(wscript\.shell|activexobject|shell\.application|adodb\.stream|msxml2\.xmlhttp)", 20, "Windows Script Host nesneleri", "Komut çalıştırma, dosya yazma veya indirme için kullanılan nesneler."),
    (r"\b(exec|eval)\s*\(\s*(base64|zlib|marshal|bytes|codecs)", 30, "Kodlanmış Python kodunu çalıştırma", "Gizlenmiş bir Python kodunu açıp çalıştırıyor."),
    (r"(base64\.b64decode|zlib\.decompress|marshal\.loads)", 12, "Veri çözme/açma", "Paketlenmiş veya kodlanmış veri çözülüyor (gizleme belirtisi olabilir)."),
    (r"(subprocess\.|os\.system|os\.popen)", 8, "Harici komut çalıştırma", "Sistemde başka programlar çalıştırıyor. Meşru araçlarda da yaygındır."),
    (r"(curl|wget)[^\n|]{0,200}\|\s*(ba)?sh", 30, "İndirip doğrudan çalıştırma", "İnternetten indirdiği betiği hiç incelemeden shell'e veriyor."),
    (r"(/dev/tcp/|nc\s+-e|bash\s+-i\s+>&|tcpclient)", 40, "Uzaktan kontrol (reverse shell) belirtisi", "Bilgisayarı başka bir makineden komutla yönetilebilir hale getirebilir."),
    (r"(login\s+data|cookies\.sqlite|\\local\s+state|leveldb|wallet\.dat|mimikatz|lsass|discord.{0,20}token)", 30, "Parola/çerez/token/cüzdan hedefleme", "Tarayıcı, Discord veya cüzdan verilerine dokunuyor."),
    (r"(getasynckeystate|setwindowshookex|pynput|keyboard\.on_press)", 25, "Klavye dinleme belirtisi", "Basılan tuşları kaydedebilecek bir yöntem kullanıyor."),
    (r"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|transfer\.sh)", 25, "Veri gönderebileceği servisler", "Verileri dışarı çıkarmak için sık kullanılan adreslere bağlanıyor."),
    (r"(amsiutils|amsiinitfailed|virtualprotect)", 35, "Güvenlik tarayıcısını atlatma", "Windows'un kötü amaçlı yazılım taramasını kandırmaya çalışıyor."),
    (r"(taskkill|stop-process|sc\s+(stop|delete)|net\s+stop).{0,60}(msmpeng|defender|windefend|avast|kaspersky|mbam|eset|norton|mcafee|bitdefender)", 30, "Antivirüs programını durdurma", "Çalışan bir antivirüs/güvenlik programını kapatmaya çalışıyor."),
    (r"net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators\s+\S+\s+/add", 30, "Yeni kullanıcı / yönetici ekleme", "Bilgisayara yeni bir kullanıcı veya yönetici hesabı ekliyor."),
    (r"\bformat\s+[a-z]:|cipher\s+/w", 30, "Disk biçimlendirme / silme", "Diski biçimlendirmeye veya boş alanı silmeye yarayan komut içeriyor."),
    (r"(\bdel\b|\brmdir\b|\brd\b)\s+(/[sfq]\s*)+.{0,60}(%userprofile%|%appdata%|c:\\users|c:\\windows|%systemroot%)", 20, "Toplu silme", "Kullanıcı veya sistem klasörlerinde toplu silme yapıyor."),
    (r"attrib\s+\+[hs]\s+.{0,60}(\.exe|\.dll|\.bat)|reg\s+add\s+.{0,120}(disabletaskmgr|disableregistrytools)", 20, "Dosya gizleme / sistem araçlarını kapatma", "Dosyaları gizliyor veya Görev Yöneticisi gibi araçları devre dışı bırakıyor."),
    (r"(ignore (all )?(previous|prior) instructions|önceki talimatları|analiz eden (yapay zek|ai|model)|this (file|code|script) is (safe|harmless|benign)|bu (dosya|kod) (güvenli|zararsız))", 35, "Analiz araçlarını kandırmaya yönelik metin", "Dosyanın içinde, inceleyen yazılıma/yapay zekaya 'güvenli de' diyen bir ifade var. Meşru dosyalarda bulunmaz."),
]
RX = [(re.compile(p, re.I | re.S), w, t, d) for p, w, t, d in RULES]

# Derlenmiş dosyalardaki şüpheli Windows API isimleri
BIN_APIS = re.compile(rb"(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|SetWindowsHookEx|NtUnmapViewOfSection|"
                      rb"URLDownloadToFile|IsDebuggerPresent|AdjustTokenPrivileges|CryptEncrypt|GetAsyncKeyState)")

URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+", re.I)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
MAGIC = [(b"MZ", "Windows programı (PE: .exe/.dll)"), (b"\x7fELF", "Linux programı (ELF)"), (b"PK\x03\x04", "ZIP tabanlı arşiv (zip/docx/jar/apk)"),
         (b"%PDF", "PDF belgesi"), (b"Rar!", "RAR arşivi"), (b"7z\xbc\xaf", "7-Zip arşivi"), (b"\xd0\xcf\x11\xe0", "Eski Office belgesi (makro içerebilir)")]


def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def vt_lookup(sha, key):
    if not key:
        return {"status": "yok", "msg": "VirusTotal anahtarı girilmedi, sorgu yapılmadı. Hash'i elle aratabilirsin.", "link": "https://www.virustotal.com/gui/file/" + sha}
    req = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + sha, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            a = json.load(r)["data"]["attributes"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "bilinmiyor", "msg": "Bu dosya VirusTotal'de kayıtlı değil (yeni veya nadir bir dosya olabilir)."}
        if e.code in (401, 403):
            return {"status": "hata", "msg": "VirusTotal anahtarı geçersiz."}
        if e.code == 429:
            return {"status": "hata", "msg": "VirusTotal sorgu limiti doldu, biraz bekleyip tekrar dene."}
        return {"status": "hata", "msg": "VirusTotal hatası: HTTP %d" % e.code}
    except Exception as e:
        return {"status": "hata", "msg": "VirusTotal'e ulaşılamadı: %s" % e}
    s = a.get("last_analysis_stats", {})
    flagged = {k: v.get("result") for k, v in a.get("last_analysis_results", {}).items() if v.get("category") in ("malicious", "suspicious")}
    return {"status": "var", "mal": s.get("malicious", 0), "sus": s.get("suspicious", 0),
            "clean": s.get("harmless", 0) + s.get("undetected", 0), "label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            "flagged": dict(list(flagged.items())[:12]), "link": "https://www.virustotal.com/gui/file/" + sha}


def _mpcmd():
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    c = sorted(glob.glob(os.path.join(pd, "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe")), reverse=True)
    c.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe"))
    return next((x for x in c if os.path.isfile(x)), None)


def parse_defender(out, rc):
    m = re.search(r"^\s*(?:Threat|Tehdit)[^:\n]*:\s*(.+)$", out, re.M | re.I)
    n = re.search(r"found\s+(\d+)\s+threats?", out, re.I)
    if m or (n and int(n.group(1)) > 0):
        return {"status": "tehdit", "name": (m.group(1).strip() if m else "adı alınamadı")}
    if n or re.search(r"found no threats", out, re.I) or rc == 0:
        return {"status": "temiz"}
    return {"status": "belirsiz", "msg": "Defender kesin bir sonuç vermedi (çıkış kodu %s). Dosya Defender'ın dışlama listesindeyse veya Defender kapalıysa böyle olur." % rc}


def defender_scan(path):
    """Windows Defender ile yalnızca rapor modunda tarar (-DisableRemediation). Windows dışında None döner."""
    if sys.platform != "win32":
        return None
    exe = _mpcmd()
    if not exe:
        return {"status": "yok", "msg": "Windows Defender bulunamadı (başka bir antivirüs kullanıyor olabilirsin)."}
    try:
        r = subprocess.run([exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"],
                           capture_output=True, timeout=120, creationflags=0x08000000)
    except subprocess.TimeoutExpired:
        return {"status": "belirsiz", "msg": "Defender taraması zaman aşımına uğradı."}
    except Exception as e:
        return {"status": "belirsiz", "msg": "Defender çalıştırılamadı: %s" % e}
    return parse_defender((r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace"), r.returncode)


YARA_BUILTIN = r"""
rule EICAR_Test {
  meta: title = "EICAR antivirüs test dosyası" desc = "Zararsız bir test dosyası. Antivirüslerin çalışıp çalışmadığını denemek için kullanılır, gerçek bir tehdit değildir." weight = 0
  strings: $a = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 }
  condition: $a
}
rule Attack_Tool_Traces {
  meta: title = "Bilinen saldırı aracı izleri" desc = "Mimikatz, Metasploit gibi saldırı araçlarına ait ifadeler var. Güvenlik uzmanları da bunları kullanır; beklemediğin bir dosyada şüphelidir." weight = 35
  strings: $a = "sekurlsa::" nocase $b = "Invoke-ReflectivePEInjection" nocase $c = "meterpreter" nocase $d = "metsrv" $e = "ReflectiveLoader"
  condition: any of them
}
rule Embedded_PE_Base64 {
  meta: title = "Metne gömülü Windows programı" desc = "Dosyanın içinde base64 ile kodlanmış bir .exe/.dll var gibi görünüyor. Zararlılar çalıştıracağı programı böyle saklar." weight = 30
  strings: $a = /TVqQAAMAAAAEAAAA/ $b = /TVpQAAIAAAAEAA8A/ $c = /TVoAAAAAAAAAAAAA/
  condition: any of them
}
rule PHP_Webshell_Pattern {
  meta: title = "PHP web shell kalıbı" desc = "Dışarıdan gelen veriyi doğrudan kod/komut olarak çalıştıran PHP kalıbı. Web sunucusuna uzaktan erişim sağlayan 'web shell'lerde görülür." weight = 40
  strings: $a = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)?\s*\(?\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase $b = /(system|passthru|shell_exec|exec)\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
  condition: any of them
}
rule UPX_Packed {
  meta: title = "UPX ile paketlenmiş program" desc = "Program UPX ile sıkıştırılmış; gerçek içeriği statik olarak görülemiyor. Zararsız yazılımlar da kullanır, zararlılar da." weight = 15
  strings: $a = "UPX0" $b = "UPX1"
  condition: uint16(0) == 0x5A4D and $a and $b
}
"""
_YARA = {"rules": None, "skipped": []}


def yara_scan(raw):
    """(bulgular, not). yara-python yoksa taramayı atlar. Ek kurallar: kodun yanındaki 'rules' klasöründeki .yar/.yara dosyaları."""
    try:
        import yara
    except ImportError:
        return [], "YARA taraması yapılmadı (eklemek için: pip install yara-python)."
    if _YARA["rules"] is None:
        comp = []
        try:
            comp.append(yara.compile(source=YARA_BUILTIN))
        except Exception:
            _YARA["skipped"].append("yerleşik kurallar")
        base = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
        for f in glob.glob(os.path.join(base, "rules", "*.yar")) + glob.glob(os.path.join(base, "rules", "*.yara")):
            try:
                comp.append(yara.compile(filepath=f))
            except Exception:
                _YARA["skipped"].append(os.path.basename(f))
        _YARA["rules"] = comp
    hits = []
    for r in _YARA["rules"]:
        try:
            for m in r.match(data=raw, timeout=20):
                ids = sorted({(s.identifier if hasattr(s, "identifier") else s[1]) for s in m.strings})[:6]
                hits.append({"title": "YARA: " + str(m.meta.get("title", m.rule)),
                             "why": str(m.meta.get("desc", "YARA kuralı eşleşti: " + m.rule)),
                             "w": int(m.meta.get("weight", 20)), "snip": "kural: %s  eşleşen: %s" % (m.rule, ", ".join(ids))})
        except Exception:
            continue
    note = "Bazı YARA kural dosyaları derlenemedi ve atlandı: " + ", ".join(_YARA["skipped"]) if _YARA["skipped"] else None
    return hits, note


def _printable(t):
    return len(t) >= 8 and sum(c.isprintable() or c in "\r\n\t" for c in t) / len(t) >= 0.9


def _bytes_to_text(b):
    if b[:2] == b"MZ":
        return "PE"
    if len(b) > 8 and b[1::2].count(0) > len(b) // 3:
        try:
            t = b.decode("utf-16le")
        except Exception:
            return None
    else:
        try:
            t = b.decode("utf-8")
        except Exception:
            return None
    return t if _printable(t) else None


def _decode_once(t):
    t = t[:2_000_000]
    for m in list(re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", t))[:20]:
        s = m.group()
        try:
            r = _bytes_to_text(base64.b64decode(s + "=" * (-len(s) % 4)))
        except Exception:
            continue
        if r:
            yield "base64", r
    for m in list(re.finditer(r"(?:\\x[0-9a-fA-F]{2}){8,}|(?:0x[0-9a-fA-F]{2}[,\s]*){8,}|\b(?:[0-9a-fA-F]{2}){20,}\b", t))[:20]:
        try:
            r = _bytes_to_text(bytes.fromhex(re.sub(r"0x|\\x|[,\s]", "", m.group())))
        except Exception:
            continue
        if r:
            yield "hex", r
    for m in list(re.finditer(r"(?:\[char\]\s*\d+\s*\+?\s*){4,}|(?:chr\(\d+\)\s*[&+]?\s*){4,}|fromcharcode\(\s*[\d,\s]+\)", t, re.I))[:20]:
        r = "".join(chr(int(n)) for n in re.findall(r"\d+", m.group()) if 9 <= int(n) < 0x110000)
        if _printable(r):
            yield "karakter kodu", r
    for m in list(re.finditer(r"(?:%[0-9a-fA-F]{2}){8,}", t))[:10]:
        r = urllib.parse.unquote(m.group())
        if _printable(r):
            yield "%XX", r


def deobfuscate(text, depth=4):
    """Yalnızca METİN dönüşümü (base64/hex/karakter kodu/%XX). Hiçbir şey çalıştırılmaz, içe aktarılmaz, diske yazılmaz."""
    layers, seen, frontier = [], set(), [text]
    for d in range(depth):
        nxt = []
        for t in frontier:
            for how, dec in _decode_once(t):
                if dec != "PE":
                    if dec[:300] in seen:
                        continue
                    seen.add(dec[:300])
                    nxt.append(dec)
                layers.append((how, dec, d + 1))
        frontier = nxt[:20]
        if not frontier or len(layers) >= 30:
            break
    return layers[:30]


def signature_check(path):
    """Dijital imza durumunu okur (Windows). Dosyayı çalıştırmaz."""
    if sys.platform != "win32":
        return None
    try:
        with open(path, "rb") as f:
            head = f.read(2)
    except Exception:
        return None
    if head != b"MZ" and not path.lower().endswith(".msi"):
        return None
    cmd = "$s=Get-AuthenticodeSignature -LiteralPath $env:KODSCAN_PATH;[pscustomobject]@{S=$s.Status.ToString();C=$s.SignerCertificate.Subject}|ConvertTo-Json -Compress"
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True, timeout=40,
                           creationflags=0x08000000, env=dict(os.environ, KODSCAN_PATH=path))
        j = json.loads(r.stdout.decode("utf-8", "replace").strip() or "{}")
    except Exception:
        return {"status": "Bilinmiyor", "signer": None}
    cn = re.search(r"CN=([^,]+)", j.get("C") or "")
    return {"status": j.get("S", "Bilinmiyor"), "signer": cn.group(1).strip('" ') if cn else None}


# EICAR imzası onaltılık yazıldı: kaynak dosyayı antivirüsler yanlışlıkla zararlı sanmasın
EICAR_SIG = bytes.fromhex("58354F2150254041505B345C505A58353428505E2937434329377D244549434152")


def decode(raw):
    for enc in (("utf-16",) if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else ()) + ("utf-8-sig", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeError:
            pass
    return ""


def analyze(name, raw, vt_key, av=None, sig=None):
    """Dosya yalnızca bayt olarak okunur; hiçbir koşulda çalıştırılmaz."""
    sha = hashlib.sha256(raw).hexdigest()
    ext = os.path.splitext(name)[1].lower()
    ftype = next((t for m, t in MAGIC if raw.startswith(m)), None)
    is_text = ftype is None and (ext in TEXT_EXT or b"\x00" not in raw[:4096] or raw[:2] in (b"\xff\xfe", b"\xfe\xff"))
    ent = round(entropy(raw[:2_000_000]), 2)
    findings, notes, limits, urls, ips, score = [], [], [], [], [], 0

    if is_text:
        ftype = "Metin / script dosyası (%s)" % (ext or "uzantısız")
        text = decode(raw[:2_000_000])
        if len(raw) > 2_000_000:
            limits.append("Dosya büyük olduğu için yalnızca ilk 2 MB incelendi.")
        for rx, w, title, why in RX:
            m = rx.search(text)
            if m:
                snip = re.sub(r"\s+", " ", text[max(0, m.start() - 25): m.end() + 45])[:170]
                findings.append({"title": title, "why": why, "w": w, "snip": snip})
                score += w
        layers = deobfuscate(text)
        if layers:
            first = next((t for _, t, _ in layers if t != "PE"), None)
            if first:
                findings.append({"title": "Gizlenmiş içerik çözüldü (%d katman)" % len(layers), "why": "Kod içinde kodlanmış metinler var. Aşağıda çözülmüş hali görünüyor (yalnızca okundu, hiçbir şey çalıştırılmadı).", "w": 0, "snip": re.sub(r"\s+", " ", first)[:300]})
            if any(dp >= 2 for _, _, dp in layers):
                score += 15
                findings.append({"title": "Çok katmanlı gizleme", "why": "Kodlanmış içeriğin içinde bir kodlama daha var. Meşru yazılımlarda nadirdir; zararlılar analizi zorlaştırmak için kullanır.", "w": 15, "snip": ""})
            if any(t == "PE" for _, t, _ in layers):
                score += 30
                findings.append({"title": "Gizlenmiş içinde Windows programı var", "why": "Kodlanmış bir metnin içinden .exe/.dll çıkıyor. Zararlılar çalıştıracağı programı böyle saklar.", "w": 30, "snip": ""})
            for how, dec, dp in layers:
                if dec == "PE":
                    continue
                for rx, w, title, why in RX:
                    if rx.search(dec) and not any(f["title"].startswith(title) for f in findings):
                        findings.append({"title": title + " (çözülen katmanda)", "why": why, "w": w, "snip": ""})
                        score += w
        if re.search(r"deflatestream|gzipstream|io\.compression|zlib\.decompress|gunzip|inflate", text, re.I):
            limits.append("Kodda sıkıştırma ile gizleme (gzip/deflate) olabilir; bu katmanlar açılmaz. İçerik hiçbir zaman çalıştırılmaz veya diske yazılmaz.")
        if any(f["title"].startswith("İnternetten dosya indirip") for f in findings):
            for f in [f for f in findings if f["title"].startswith("İnternete bağlanıp")]:
                findings.remove(f)
                score -= f["w"]
        urls = sorted(set(URL_RE.findall(text)))[:25]
        ips = sorted(set(IP_RE.findall(text)))[:25]
        nb = len(B64_RE.findall(text))
        if nb:
            score += 15
            findings.append({"title": "Çok uzun kodlanmış veri blokları", "why": "%d adet uzun base64 benzeri blok var; içine veri/kod gömülmüş olabilir." % nb, "w": 15, "snip": ""})
        if ent > 6.0 and len(raw) > 2000:
            score += 15
            notes.append("Entropi yüksek (%.2f): içerik sıkıştırılmış, şifrelenmiş veya gizlenmiş olabilir." % ent)
        if text.count("\n") < 10 and len(text) > 5000:
            score += 10
            notes.append("Çok az satırda çok uzun içerik: kod küçültülmüş (minify) veya gizlenmiş olabilir.")
    else:
        ftype = ftype or "Tanınmayan ikili dosya"
        limits.append("Bu bir derlenmiş/ikili dosya. İçindeki kod okunamadı; yalnızca hash, VirusTotal ve yüzeysel işaretler kullanıldı.")
        apis = sorted({m.decode() for m in BIN_APIS.findall(raw)})
        if apis:
            score += min(30, 6 * len(apis))
            findings.append({"title": "Dikkat çeken Windows API isimleri", "why": "Dosyada başka programların belleğine yazma, tuş dinleme gibi işlemlerde kullanılan fonksiyon adları geçiyor. Meşru yazılımlar da (oyun, hata ayıklayıcı) bunları kullanabilir.", "w": min(30, 6 * len(apis)), "snip": ", ".join(apis)})
        if ent > 7.2:
            score += 20
            notes.append("Entropi çok yüksek (%.2f): dosya büyük ihtimalle paketlenmiş (packer) veya şifreli. Gerçek içeriği statik olarak görülemiyor." % ent)
            limits.append("Paketlenmiş dosyalarda statik analiz kör kalır; yanlış 'temiz' sonucu verebilir.")
        if ftype.startswith("ZIP"):
            try:
                infos = zipfile.ZipFile(io.BytesIO(raw)).infolist()
                names = [x.filename for x in infos][:300]
                notes.append("Arşivde %d dosya var." % len(infos))
                risky = [n for n in names if re.search(r"\.(exe|scr|bat|cmd|ps1|vbs|js|jse|hta|lnk|dll|msi)$", n, re.I)]
                if risky:
                    score += 15
                    findings.append({"title": "Arşivde çalıştırılabilir dosyalar var", "why": "İçinde doğrudan çalışan dosya türleri bulunuyor. Yazılım paketlerinde normaldir, ama tanımadığın bir kaynaktan geldiyse dikkat et.", "w": 15, "snip": ", ".join(risky[:10])})
                if any(n.lower().endswith("vbaproject.bin") for n in names):
                    score += 25
                    findings.append({"title": "Belge makro (VBA) içeriyor", "why": "Office belgesi içinde makro var. Makrolar belgeyi açınca komut çalıştırabilir; beklemediğin bir belgede şüphelidir.", "w": 25, "snip": "vbaProject.bin"})
                if any(x.flag_bits & 1 for x in infos):
                    notes.append("Arşiv parola korumalı: içeriği incelenemedi.")
            except Exception:
                limits.append("Arşiv açılamadı veya bozuk.")
        if any(t in ftype for t in ("ZIP", "RAR", "7-Zip")):
            limits.append("Arşivin içindeki dosyaların içeriği taranmadı; yalnızca isimlerine bakıldı.")

    yhits, ynote = yara_scan(raw)
    for h in yhits:
        findings.append(h)
        score += h["w"]
    if ynote:
        limits.append(ynote)
    if "\u202e" in name:
        score += 40
        findings.append({"title": "Dosya adında gizli yön karakteri", "why": "Ad, uzantıyı ters göstermek için özel bir karakter içeriyor (örn. 'gpj.exe' dosyasını '.jpg' gibi gösterir). Bu, kandırma yöntemidir.", "w": 40, "snip": name.replace("\u202e", "[RLO]")})
    if re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp[34])\s*\.(exe|scr|bat|cmd|com|js|vbs|ps1|lnk|hta)$", name, re.I):
        score += 35
        findings.append({"title": "Çift uzantılı dosya adı", "why": "Dosya belge/resim gibi görünüyor ama gerçekte çalıştırılabilir bir dosya.", "w": 35, "snip": name})
    vt = vt_lookup(sha, vt_key)
    comments = []
    total = score
    level_floor = 0
    if vt["status"] == "var":
        total += vt["mal"] * 8 + vt["sus"] * 3
        if vt["mal"] >= 5:
            level_floor = 2
            comments.append("%d antivirüs motoru bu dosyayı zararlı olarak işaretledi." % vt["mal"])
        elif vt["mal"] >= 1:
            level_floor = 1
            if score < 25:
                comments.append("Yalnızca %d motor işaretledi ve kodda belirgin kötü davranış bulunamadı: yanlış alarm (false positive) olasılığı yüksek." % vt["mal"])
            else:
                comments.append("%d motor işaretledi ve kodda da şüpheli davranışlar var." % vt["mal"])
        elif score >= 25:
            comments.append("Antivirüsler işaretlemedi ama kodda şüpheli davranışlar var: yeni/hedefli bir zararlı veya yönetici aracı olabilir.")
    elif vt["status"] == "bilinmiyor":
        limits.append("Dosya VirusTotal'de yok; antivirüs motorlarının görüşü bilinmiyor.")
    elif vt["status"] in ("yok", "hata"):
        limits.append(vt["msg"])
    if av:
        if av["status"] == "tehdit":
            level_floor = 2
            total += 60
            comments.append("Windows Defender bu dosyada tehdit buldu: %s." % av["name"])
        elif av["status"] in ("belirsiz", "yok"):
            limits.append(av["msg"])
    if sig:
        st = sig["status"]
        if st == "Valid":
            total = max(0, total - 25)
            comments.append("Dosya dijital olarak imzalı: %s. Geçerli imza, yayıncının kimliğini ve dosyanın imzadan sonra değişmediğini doğrular; zararsız olduğunu garanti etmez." % (sig["signer"] or "yayıncı bilinmiyor"))
        elif st == "NotSigned":
            notes.append("Dosya dijital olarak imzalı değil. Bireysel veya kendi yazdığın yazılımlarda bu normaldir.")
        elif st == "HashMismatch":
            total += 40
            level_floor = max(level_floor, 1)
            findings.append({"title": "Dijital imza bozuk", "why": "Dosya imzalandıktan sonra değiştirilmiş. Bu, kurcalanmış bir dosyanın işaretidir.", "w": 40, "snip": sig["signer"] or ""})
        elif st == "NotTrusted":
            total += 20
            findings.append({"title": "İmza güvenilir bir yayıncıya bağlanamıyor", "why": "Dosyada imza var ama Windows'un güvendiği bir otoriteye zincirlenmiyor (kendinden imzalı veya süresi dolmuş olabilir).", "w": 20, "snip": sig["signer"] or ""})
    if any(f["title"].startswith("Analiz araçlarını") for f in findings):
        level_floor = max(level_floor, 1)
        comments.append("Dosya, inceleyen araçları kandırmaya çalışan bir ifade içeriyor; bu başlı başına kötü niyet işaretidir.")
    total = min(100, total)
    level = max(level_floor, 2 if total >= 60 else 1 if total >= 25 else 0)
    if level == 0 and not comments:
        comments.append("Bilinen şüpheli kalıplara rastlanmadı. Bu, dosyanın güvenli olduğunu kanıtlamaz.")
    is_archive = ext in {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".iso"} or (
        ftype is not None and any(t in ftype for t in ("ZIP", "RAR", "7-Zip"))
        and ext not in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".jar", ".apk", ".epub"})
    eicar = len(raw) <= 128 and EICAR_SIG in raw
    if eicar:
        total, level, comments = 0, 0, ["Bu, antivirüs yazılımlarını denemek için kullanılan zararsız EICAR test dosyasıdır. Antivirüslerin bunu 'virüs' diye işaretlemesi beklenen davranıştır."]
    return {"name": name, "size": len(raw), "sha256": sha, "type": ftype, "entropy": ent, "score": total, "level": level,
            "findings": findings, "notes": notes, "limits": limits, "urls": urls, "ips": ips, "vt": vt, "comments": comments, "archive": is_archive, "av": av, "sig": sig, "eicar": eicar}




APPDIR = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
if not os.access(APPDIR, os.W_OK):  # yazılamayan klasörlerde (örn. Program Files) kullanıcı klasörüne düş
    APPDIR = os.path.expanduser("~")
TRUST = os.path.join(APPDIR, "kodscan_trust.json")
HIST = os.path.join(APPDIR, "kodscan_history.json")
RK = r"Software\Classes\*\shell\kodscan"


def jload(p, default):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def jsave(p, data):
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception:
        pass


for _new, _old in ((TRUST, ".kodscan_trust.json"), (HIST, ".kodscan_history.json")):  # eski konumdan taşı
    _o = os.path.join(os.path.expanduser("~"), _old)
    if not os.path.exists(_new) and os.path.isfile(_o):
        jsave(_new, jload(_o, {} if _new == TRUST else []))


def trust_info(name, sha):
    t = jload(TRUST, {})
    if sha in t:
        return {"known": True, "changed": False, "date": t[sha].get("date", "")}
    return {"known": False, "changed": any(v.get("name") == name for v in t.values())}


def hist_add(d):
    h = jload(HIST, [])
    h.append({"t": time.strftime("%Y-%m-%d %H:%M"), "name": d["name"], "sha": d["sha256"], "level": d["level"], "score": d["score"]})
    jsave(HIST, h[-300:])


def ctx_installed():
    if sys.platform != "win32":
        return False
    import winreg
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, RK))
        return True
    except OSError:
        return False


def ctx_set(on):
    """Sağ tık menüsü (yalnızca bu kullanıcı için, yönetici izni gerekmez). Kaldırılabilir."""
    import winreg
    if on:
        exe = sys.executable
        if getattr(sys, "frozen", False):
            cmd = '"%s" "%%1"' % exe
        else:
            w = os.path.join(os.path.dirname(exe), "pythonw.exe")
            cmd = '"%s" "%s" "%%1"' % (w if os.path.isfile(w) else exe, os.path.abspath(__file__))
        for sub, val in ((RK, "Kodscan ile Dosyayı Tara"), (RK + r"\command", cmd)):
            k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, sub)
            winreg.SetValue(k, "", winreg.REG_SZ, val)
            if sub == RK:  # önceki sürümden kalmış simge kaydı varsa sil
                try:
                    winreg.DeleteValue(k, "Icon")
                except OSError:
                    pass
            winreg.CloseKey(k)
    else:
        for sub in (RK + r"\command", RK):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
            except OSError:
                pass


# ============================ ARAYÜZ ============================
import sys
import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk

if sys.platform == "win32":  # python.exe ile açılırsa konsol penceresini gizle
    try:
        import ctypes
        _h = ctypes.windll.kernel32.GetConsoleWindow()
        if _h:
            ctypes.windll.user32.ShowWindow(_h, 0)
    except Exception:
        pass

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES

    class Base(ctk.CTk, TkinterDnD.DnDWrapper):
        def __init__(self):
            super().__init__()
            self.TkdndVersion = TkinterDnD._require(self)
    DND = True
except Exception:
    DND = False

    class Base(ctk.CTk):
        pass

CFG = os.path.join(os.path.expanduser("~"), ".kodscan.json")
FONT = "Segoe UI"
BG, PANEL, SUB, LINE = ("#f2f4f8", "#10141a"), ("#ffffff", "#1a2029"), ("#eef1f6", "#232b36"), ("#e2e7ef", "#2b3440")
INK, MUTE = ("#16202b", "#e9eef5"), ("#64748b", "#8fa0b5")
ACC, ACC_H = ("#3557e0", "#5b7cff"), ("#2a46b8", "#4a69e6")
LV = ["#22a06b", "#e09a1a", "#e0474c"]
SOFT = [("#dcf3e8", "#16382b"), ("#faecd0", "#3d3115"), ("#fbe1e2", "#44201f")]


def col(c):
    """(açık, koyu) renk çiftini aktif temaya göre tek renge çevirir."""
    return c if isinstance(c, str) else (c[1] if ctk.get_appearance_mode() == "Dark" else c[0])


TITLE = ["Belirgin tehlike bulunamadı", "Şüpheli noktalar var", "Yüksek risk"]
THEMES = {"Aydınlık": "light", "Karanlık": "dark", "Sistem": "system"}
WRAP = 600


def build_report(d):
    L = ["kodscan raporu", "=" * 56, "Dosya : " + d["name"], "Tür   : " + d["type"], "SHA256: " + d["sha256"],
         "Sonuç : %s (%d/100)" % (TITLE[d["level"]], d["score"]), "(Bu rapor bir güvenlik garantisi değildir.)", ""]
    if d.get("archive"):
        L += ["", "UYARI: Bu bir arşiv dosyası. Sonuç her zaman doğru değildir; içindeki dosyalar taranmadı, yalnızca isimlerine bakıldı.", ""]
    v = d["vt"]
    L.append("VirusTotal: " + ("%d zararlı / %d şüpheli / %d temiz-tespitsiz" % (v["mal"], v["sus"], v["clean"]) if v["status"] == "var" else v["msg"]))
    a = d.get("av")
    if a:
        L.append("Windows Defender: " + ("Tehdit bulundu: " + a["name"] if a["status"] == "tehdit" else "Tehdit bulunamadı" if a["status"] == "temiz" else a["msg"]))
    sg = d.get("sig")
    if sg:
        L.append("Dijital imza: %s%s" % (sg["status"], " (%s)" % sg["signer"] if sg["signer"] else ""))
    for title, items in (("Değerlendirme", d["comments"]), ("Notlar", d["notes"]), ("Analizin sınırları", d["limits"])):
        if items:
            L += ["", title + ":"] + ["  - " + i for i in items]
    if d["findings"]:
        L += ["", "Bulgular:"]
        for f in d["findings"]:
            L += ["  * " + f["title"], "      " + f["why"]] + (["      > " + f["snip"]] if f["snip"] else [])
    if d["urls"] or d["ips"]:
        L += ["", "Adresler:"] + ["  - " + a for a in d["urls"] + d["ips"]]
    return "\n".join(L)


class App(Base):
    def __init__(self):
        super().__init__()
        self.cfg = {}
        try:
            with open(CFG, encoding="utf-8") as f:
                self.cfg = json.load(f)
        except Exception:
            pass
        ctk.set_appearance_mode(THEMES.get(self.cfg.get("theme", "Sistem"), "system"))
        self.title("kodscan")
        self.geometry("1100x740")
        self.minsize(960, 680)
        self.configure(fg_color=BG)
        self.last = None
        self.results, self.errs = [], []
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---- sol panel ----
        side = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=0, width=300)
        side.grid(row=0, column=0, sticky="ns")
        side.grid_propagate(False)
        ctk.CTkLabel(side, text="kodscan", font=(FONT, 28, "bold"), text_color=INK).pack(anchor="w", padx=24, pady=(28, 0))
        ctk.CTkLabel(side, text="Dosyayı çalıştırmadan inceler,\nne yaptığını sade dille anlatır.", font=(FONT, 13), text_color=MUTE,
                     justify="left").pack(anchor="w", padx=24, pady=(2, 14))
        self.drop = ctk.CTkFrame(side, fg_color=SUB, corner_radius=16, border_width=2, border_color=LINE, height=128)
        self.drop.pack(fill="x", padx=20)
        self.drop.pack_propagate(False)
        self.dl = ctk.CTkLabel(self.drop, text="Dosyayı buraya sürükle" if DND else "Dosya seç", font=(FONT, 15, "bold"), text_color=INK)
        self.dl.pack(pady=(26, 4))
        ctk.CTkLabel(self.drop, text="veya", font=(FONT, 12), text_color=MUTE).pack()
        ctk.CTkButton(self.drop, text="Dosya seç", height=36, corner_radius=10, fg_color=ACC, hover_color=ACC_H, font=(FONT, 14, "bold"),
                      command=self.pick).pack(pady=(6, 0), padx=24, fill="x")
        for w in (self.drop, self.dl):
            w.bind("<Enter>", lambda e: self.drop.configure(border_color=ACC))
            w.bind("<Leave>", lambda e: self.drop.configure(border_color=LINE))
        if DND:
            for w in (self, self.drop):
                w.drop_target_register(DND_FILES)
                w.dnd_bind("<<Drop>>", lambda e: self.run(list(self.tk.splitlist(e.data))))

        ctk.CTkLabel(side, text="VirusTotal anahtarı (isteğe bağlı)", font=(FONT, 13, "bold"), text_color=INK).pack(anchor="w", padx=24, pady=(20, 4))
        self.key = ctk.CTkEntry(side, show="•", height=36, corner_radius=10, placeholder_text="Anahtarı yapıştır", fg_color=SUB, border_color=LINE)
        self.key.pack(fill="x", padx=20)
        self.key.insert(0, self.cfg.get("vt", ""))
        self.key.bind("<FocusOut>", lambda e: self.save_cfg())
        ctk.CTkLabel(side, text="Dosyan gönderilmez; yalnızca\nhash'i VirusTotal'e sorulur.", font=(FONT, 12), text_color=MUTE,
                     justify="left").pack(anchor="w", padx=24, pady=(6, 0))

        if sys.platform == "win32":
            self.av_sw = ctk.CTkSwitch(side, text="Windows Defender ile de tara", progress_color=ACC, font=(FONT, 13), text_color=INK)
            if self.cfg.get("av", True):
                self.av_sw.select()
            self.av_sw.configure(command=self.save_cfg)
            self.av_sw.pack(anchor="w", padx=24, pady=(20, 0))
            ctk.CTkLabel(side, text="Tarama yalnızca rapor modunda yapılır.", font=(FONT, 12), text_color=MUTE).pack(anchor="w", padx=24, pady=(4, 0))

        ctk.CTkLabel(side, text="Tema", font=(FONT, 13, "bold"), text_color=INK).pack(anchor="w", padx=24, pady=(24, 4))
        self.theme = ctk.CTkSegmentedButton(side, values=list(THEMES), command=self.set_theme, selected_color=ACC, selected_hover_color=ACC_H)
        self.theme.set(self.cfg.get("theme", "Sistem"))
        self.theme.pack(fill="x", padx=20)
        row = ctk.CTkFrame(side, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(16, 0))
        ctk.CTkButton(row, text="Geçmiş", width=86, height=32, corner_radius=10, fg_color=SUB, hover_color=LINE, text_color=INK,
                      command=self.show_history).pack(side="left")
        if sys.platform == "win32":
            self.ctx_btn = ctk.CTkButton(row, text="", height=32, corner_radius=10, fg_color=SUB, hover_color=LINE, text_color=INK, command=self.toggle_ctx)
            self.ctx_btn.pack(side="left", padx=(8, 0), fill="x", expand=True)
            self.ctx_label()
            if ctx_installed():  # yeni ad/simge/yol değişikliklerini kayda yansıt
                try:
                    ctx_set(True)
                except Exception:
                    pass
        ctk.CTkLabel(side, text="Dosya hiçbir zaman çalıştırılmaz.", font=(FONT, 12), text_color=MUTE).pack(side="bottom", pady=18)

        # ---- sağ panel ----
        holder = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        holder.grid(row=0, column=1, sticky="nsew", padx=(14, 14), pady=14)
        holder.grid_rowconfigure(0, weight=1)
        holder.grid_columnconfigure(0, weight=1)
        self.cv = tk.Canvas(holder, highlightthickness=0, bd=0, yscrollincrement=20)
        self.cv.grid(row=0, column=0, sticky="nsew")
        sb = ctk.CTkScrollbar(holder, command=self.yview)
        sb.grid(row=0, column=1, sticky="ns", padx=(6, 0))
        self.cv.configure(yscrollcommand=sb.set)
        self.res = ctk.CTkFrame(self.cv, fg_color=BG, corner_radius=0)
        self.win = self.cv.create_window((0, 0), window=self.res, anchor="nw")
        self.res.bind("<Configure>", lambda e: self.cv.configure(scrollregion=self.cv.bbox("all")))
        self.cv.bind("<Configure>", lambda e: self.cv.itemconfigure(self.win, width=e.width))
        self.bind_all("<MouseWheel>", self.wheel)
        self.bind_all("<Button-4>", self.wheel)
        self.bind_all("<Button-5>", self.wheel)
        self.sync_bg()
        self.busy = None
        self.empty()

    # ---- kaydırma ----
    def yview(self, *a):
        self.cv.yview(*a)
        self.cv.update_idletasks()

    def sync_bg(self):
        self.cv.configure(bg=BG[1] if ctk.get_appearance_mode() == "Dark" else BG[0])

    def wheel(self, e):
        try:
            w = self.winfo_containing(e.x_root, e.y_root)
        except Exception:
            return
        while w is not None and w is not self.res and w is not self.cv:
            w = getattr(w, "master", None)
        if w is None or self.res.winfo_height() <= self.cv.winfo_height():
            return
        up = e.num == 4 or getattr(e, "delta", 0) > 0
        self.cv.yview_scroll(-3 if up else 3, "units")
        self.cv.update_idletasks()

    # ---- ayarlar ----
    def on_close(self):  # pencere kapanırken anahtar/ayarlar kesin kaydedilsin
        self.save_cfg()
        self.destroy()

    def save_cfg(self):
        self.cfg["vt"] = self.key.get().strip()
        if hasattr(self, "av_sw"):
            self.cfg["av"] = bool(self.av_sw.get())
        try:
            with open(CFG, "w", encoding="utf-8") as f:
                json.dump(self.cfg, f)
        except Exception:
            pass

    def set_theme(self, name):
        ctk.set_appearance_mode(THEMES[name])
        self.sync_bg()
        if getattr(self, "shown", False) and self.last:
            self.show(self.last)
        self.cfg["theme"] = name
        self.save_cfg()

    # ---- çizim yardımcıları ----
    def clear(self):
        self.sync_bg()
        self.shown = False
        for w in self.res.winfo_children():
            w.destroy()

    def empty(self, text="Bir dosya sürükle ya da soldan seç.\nSonuç burada görünecek."):
        self.clear()
        ctk.CTkLabel(self.res, text=text, font=(FONT, 18), text_color=MUTE, justify="center").pack(pady=(220, 0))

    def card(self, title=None):
        c = ctk.CTkFrame(self.res, fg_color=PANEL, corner_radius=16)
        c.pack(fill="x", padx=6, pady=6)
        if title:
            ctk.CTkLabel(c, text=title, font=(FONT, 16, "bold"), text_color=INK).pack(anchor="w", padx=22, pady=(16, 6))
        return c

    def lab(self, parent, text, size=13, color=INK, bold=False, mono=False, bg=None, px=22, py=2, wrap=WRAP, on=PANEL):
        l = tk.Label(parent, text=text, font=("Consolas" if mono else FONT, size, "bold" if bold else "normal"), fg=col(color),
                     bg=col(bg or on), wraplength=wrap, justify="left", anchor="w", bd=0, padx=10 if bg else 0, pady=6 if bg else 0)
        l.pack(anchor="w", padx=px, pady=py, fill="x" if bg else None)
        return l

    def btn(self, parent, text, cmd, primary=False):
        b = ctk.CTkButton(parent, text=text, command=cmd, height=34, corner_radius=10, font=(FONT, 13, "bold"),
                          fg_color=ACC if primary else SUB, hover_color=ACC_H if primary else LINE, text_color="white" if primary else INK)
        b.pack(side="left", padx=(0, 8))
        return b

    def pad(self, c, h=12):
        ctk.CTkFrame(c, height=h, fg_color="transparent").pack()

    # ---- akış ----
    def pick(self):
        p = filedialog.askopenfilenames(title="İncelenecek dosyaları seç")
        if p:
            self.run(list(p))

    def run(self, paths):
        paths = [paths] if isinstance(paths, str) else list(paths)
        files = [p for p in paths if os.path.isfile(p)]
        if not files:
            return self.empty("Dosya bulunamadı ya da klasör seçildi.\nAntivirüs dosyayı silmiş veya taşımış olabilir.")
        self.save_cfg()
        self.clear()
        self.prog = ctk.CTkLabel(self.res, text="İnceleniyor…", font=(FONT, 18), text_color=MUTE)
        self.prog.pack(pady=(220, 12))
        self.busy = ctk.CTkProgressBar(self.res, mode="indeterminate", width=260, progress_color=ACC)
        self.busy.pack()
        self.busy.start()
        key = self.key.get().strip() or os.environ.get("VT_API_KEY", "")
        use_av = hasattr(self, "av_sw") and bool(self.av_sw.get())
        hist = self.cfg.get("hist", True)

        def setp(n):
            try:
                self.prog.configure(text="İnceleniyor… %d/%d" % (n, len(files)))
            except Exception:
                pass

        def work():
            res, errs = [], []
            for n, path in enumerate(files, 1):
                self.after(0, setp, n)
                nm = os.path.basename(path)
                try:
                    if os.path.getsize(path) > MAX_UPLOAD:
                        raise ValueError("32 MB sınırından büyük")
                    with open(path, "rb") as f:  # yalnızca okunur, asla çalıştırılmaz
                        raw = f.read()
                    av = defender_scan(path) if use_av else None
                    d = analyze(nm, raw, key, av, signature_check(path))
                    d["trust"] = trust_info(d["name"], d["sha256"])
                    if hist:
                        hist_add(d)
                    res.append(d)
                except (FileNotFoundError, PermissionError):
                    errs.append("%s: dosya açılamadı (antivirüs silmiş veya engellemiş olabilir)" % nm)
                except Exception as e:
                    errs.append("%s: %s" % (nm, e))
            if res:
                self.after(0, self.show_many, res, errs)
            else:
                self.after(0, self.empty, "Analiz yapılamadı:\n" + "\n".join(errs))
        threading.Thread(target=work, daemon=True).start()

    def show_many(self, res, errs):
        self.results, self.errs = res, errs
        self.show(max(res, key=lambda r: (r["level"], r["score"])))  # en riskli olan önce gösterilir

    def toggle_trust(self, d):
        t = jload(TRUST, {})
        if d["sha256"] in t:
            del t[d["sha256"]]
        else:
            t[d["sha256"]] = {"name": d["name"], "date": time.strftime("%Y-%m-%d")}
        jsave(TRUST, t)
        d["trust"] = trust_info(d["name"], d["sha256"])
        self.show(d)

    def ctx_label(self):
        self.ctx_btn.configure(text="Sağ tık: kaldır" if ctx_installed() else "Sağ tık menüsüne ekle")

    def toggle_ctx(self):
        try:
            ctx_set(not ctx_installed())
        except Exception:
            pass
        self.ctx_label()

    def show_history(self):
        w = ctk.CTkToplevel(self)
        w.title("Tarama geçmişi")
        w.geometry("660x460")
        w.after(200, w.lift)

        def sv():
            self.cfg["hist"] = bool(sw.get())
            self.save_cfg()
        sw = ctk.CTkSwitch(w, text="Geçmişi kaydet", progress_color=ACC, command=sv)
        if self.cfg.get("hist", True):
            sw.select()
        sw.pack(anchor="w", padx=18, pady=(16, 6))
        tb = ctk.CTkTextbox(w, font=("Consolas", 12), wrap="none")
        tb.pack(fill="both", expand=True, padx=18, pady=6)

        def fill():
            tb.configure(state="normal")
            tb.delete("1.0", "end")
            h = jload(HIST, [])
            tb.insert("1.0", "\n".join("%s  %-6s %3d  %s  %s" % (x["t"], ["düşük", "orta", "YÜKSEK"][x["level"]], x["score"], x["sha"][:12], x["name"])
                                       for x in reversed(h)) or "Geçmiş boş.")
            tb.configure(state="disabled")

        def wipe():
            jsave(HIST, [])
            fill()
        ctk.CTkButton(w, text="Geçmişi temizle", fg_color=LV[2], hover_color="#b83a3e", command=wipe).pack(anchor="e", padx=18, pady=(0, 16))
        fill()

    def copy(self, text, b):
        self.clipboard_clear()
        self.clipboard_append(text)
        b.configure(text="Kopyalandı")

    def save_report(self):
        d = self.last
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=d["name"] + "_rapor.txt", filetypes=[("Metin", "*.txt")])
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(build_report(d))

    def show(self, d):
        self.last = d
        self.clear()
        lv, lcol = d["level"], LV[d["level"]]
        if len(self.results) > 1:
            names = ["%d.  %s  —  %s" % (i + 1, ["düşük", "orta", "YÜKSEK"][r["level"]], r["name"]) for i, r in enumerate(self.results)]
            om = ctk.CTkOptionMenu(self.res, values=names, width=440, fg_color=SUB, button_color=ACC, text_color=INK, dropdown_fg_color=PANEL,
                                   dropdown_text_color=INK, command=lambda v: self.show(self.results[int(v.split(".")[0]) - 1]))
            om.set(names[self.results.index(d)] if d in self.results else names[0])
            om.pack(anchor="w", padx=6, pady=(4, 2))
        c = self.card()
        top = ctk.CTkFrame(c, fg_color="transparent")
        top.pack(fill="x", padx=22, pady=(22, 10))
        ctk.CTkLabel(top, text=str(d["score"]), width=88, height=88, corner_radius=44, fg_color=lcol, text_color="white", font=(FONT, 32, "bold")).pack(side="left")
        info = ctk.CTkFrame(top, fg_color="transparent")
        info.pack(side="left", padx=18, fill="x", expand=True)
        self.lab(info, "Bu bir antivirüs test dosyası (zararsız)" if d.get("eicar") else TITLE[lv], 25, lcol, True, px=0, wrap=480)
        self.lab(info, d["name"], 14, INK, px=0, wrap=480)
        self.lab(info, "Bu bir güvenlik garantisi değildir. Yalnızca incelenen işaretleri gösterir.", 12, MUTE, px=0, wrap=480)
        bar = ctk.CTkProgressBar(c, height=10, corner_radius=5, progress_color=lcol, fg_color=SUB)
        bar.set(max(0.03, d["score"] / 100))
        bar.pack(fill="x", padx=22, pady=(8, 4))
        sc = ctk.CTkFrame(c, fg_color="transparent")
        sc.pack(fill="x", padx=22)
        for t, s in (("düşük risk", "left"), ("yüksek risk", "right")):
            ctk.CTkLabel(sc, text=t, font=(FONT, 11), text_color=MUTE).pack(side=s)
        row = ctk.CTkFrame(c, fg_color="transparent")
        row.pack(anchor="w", padx=22, pady=(12, 18))
        self.btn(row, "Raporu kaydet", self.save_report, True)
        hb = self.btn(row, "Hash'i kopyala", lambda: self.copy(d["sha256"], hb))
        tr = d.get("trust") or {}
        self.btn(row, "Güvenden çıkar" if tr.get("known") else "Güvendiğim dosya", lambda: self.toggle_trust(d))

        if d.get("archive"):
            w = self.card()
            w.configure(fg_color=SOFT[1], border_width=2, border_color=LV[1])
            amber = ("#8a5d0a", "#f0c46a")
            self.lab(w, "Arşiv dosyası: bu sonuç her zaman doğru değildir", 17, amber, True, py=(14, 4), wrap=640, on=SOFT[1])
            self.lab(w, "Arşivin içindeki dosyalar açılıp taranmadı, yalnızca isimlerine bakıldı. Parola korumalı veya iç içe arşivlerde "
                        "zararlı içerik gözden kaçabilir. \"Belirgin tehlike bulunamadı\" sonucuna güvenme; arşivi açıp içindeki dosyaları "
                        "ayrı ayrı incele.", 13, amber, wrap=640, on=SOFT[1])
            self.pad(w, 10)

        if tr.get("known") or tr.get("changed"):
            c = self.card("Senin işaretin")
            if tr.get("known"):
                self.lab(c, "Bu dosyayı %s tarihinde güvendiğin dosya olarak işaretledin. İçeriği (hash) aynı, yani değişmemiş." % (tr.get("date") or "daha önce"), 14)
            else:
                self.lab(c, "Aynı isimde, daha önce güvendiğin bir dosya var ama bu dosyanın içeriği farklı. Yeni sürüm olabilir, ama değiştirilmiş de olabilir; kaynağını kontrol et.", 14, ("#8a5d0a", "#f0c46a"))
            self.pad(c)

        if d["comments"]:
            c = self.card("Değerlendirme")
            for m in d["comments"]:
                self.lab(c, "•  " + m, 14)
            self.pad(c)

        c = self.card("Dosya")
        kb = "%.1f MB" % (d["size"] / 1048576) if d["size"] > 1048576 else "%d KB" % max(1, round(d["size"] / 1024))
        for k, v in (("Tür", d["type"]), ("Boyut", kb), ("Entropi", "%s / 8" % d["entropy"])):
            r = ctk.CTkFrame(c, fg_color="transparent")
            r.pack(fill="x", padx=22, pady=1)
            ctk.CTkLabel(r, text=k, width=70, anchor="w", font=(FONT, 13), text_color=MUTE).pack(side="left")
            ctk.CTkLabel(r, text=v, anchor="w", font=(FONT, 13), text_color=INK, wraplength=480, justify="left").pack(side="left")
        self.lab(c, d["sha256"], 12, MUTE, mono=True, bg=SUB, py=8, wrap=520)
        self.pad(c, 8)

        v = d["vt"]
        c = self.card("VirusTotal")
        if v["status"] == "var":
            r = ctk.CTkFrame(c, fg_color="transparent")
            r.pack(anchor="w", padx=22, pady=4)
            for t, i in (("%d zararlı" % v["mal"], 2 if v["mal"] else 0), ("%d şüpheli" % v["sus"], 1 if v["sus"] else 0), ("%d temiz/tespitsiz" % v["clean"], 0)):
                ctk.CTkLabel(r, text="  %s  " % t, fg_color=SOFT[i], text_color=LV[i], corner_radius=14, font=(FONT, 13, "bold"), height=30).pack(side="left", padx=(0, 8))
            if v["label"]:
                self.lab(c, "Önerilen etiket: " + v["label"], 13, MUTE)
            for k, x in v["flagged"].items():
                self.lab(c, "•  %s: %s" % (k, x), 12, MUTE)
        else:
            self.lab(c, v["msg"], 13, MUTE)
        if v.get("link"):
            r = ctk.CTkFrame(c, fg_color="transparent")
            r.pack(anchor="w", padx=22, pady=(8, 0))
            self.btn(r, "VirusTotal'de aç", lambda: webbrowser.open(v["link"]))
        self.pad(c)

        sg = d.get("sig")
        if sg:
            c = self.card("Dijital imza")
            i = {"Valid": 0, "NotTrusted": 1, "HashMismatch": 2}.get(sg["status"])
            if i is None:
                self.lab(c, "İmzalı değil veya imza durumu okunamadı.", 13, MUTE)
            else:
                t = {0: "Geçerli imza", 1: "İmza güvenilir değil", 2: "İmza bozuk"}[i] + (": " + sg["signer"] if sg["signer"] else "")
                ctk.CTkLabel(c, text="  %s  " % t, fg_color=SOFT[i], text_color=LV[i], corner_radius=14, font=(FONT, 13, "bold"), height=30).pack(anchor="w", padx=22, pady=4)
            self.pad(c)

        av = d.get("av")
        if av:
            c = self.card("Windows Defender")
            i = {"tehdit": 2, "temiz": 0}.get(av["status"])
            if i is None:
                self.lab(c, av["msg"], 13, MUTE)
            else:
                ctk.CTkLabel(c, text="  %s  " % ("Tehdit bulundu: " + av["name"] if i == 2 else "Tehdit bulunamadı"), fg_color=SOFT[i], text_color=LV[i],
                             corner_radius=14, font=(FONT, 13, "bold"), height=30).pack(anchor="w", padx=22, pady=4)
                if i == 0:
                    self.lab(c, "Defender'ın imzalarında bu dosya yok. Bu, dosyanın güvenli olduğunu kanıtlamaz.", 12, MUTE)
            self.pad(c)

        c = self.card("Kodda bulunanlar")
        if not d["findings"]:
            self.lab(c, "Bilinen şüpheli bir kalıp bulunamadı.", 13, MUTE)
        for f in d["findings"]:
            row = tk.Frame(c, bg=col(PANEL))
            row.pack(fill="x", padx=22, pady=7)
            stripe = LV[2] if f["w"] >= 25 else LV[1] if f["w"] >= 12 else ("#94a3b8", "#64748b")
            tk.Frame(row, width=4, bg=col(stripe)).pack(side="left", fill="y", padx=(0, 12))
            body = tk.Frame(row, bg=col(PANEL))
            body.pack(side="left", fill="x", expand=True)
            self.lab(body, f["title"], 14, INK, True, px=0, wrap=540)
            self.lab(body, f["why"], 13, MUTE, px=0, wrap=540)
            if f["snip"]:
                self.lab(body, f["snip"], 12, INK, mono=True, bg=SUB, px=0, py=4, wrap=540)
        for n in d["notes"]:
            self.lab(c, "•  " + n, 13, MUTE)
        self.pad(c)

        if d["urls"] or d["ips"]:
            c = self.card("Bağlanılan adresler")
            for a in d["urls"] + d["ips"]:
                self.lab(c, a, 12, mono=True)
            self.pad(c)
        if d["limits"]:
            c = self.card("Analizin sınırları")
            for l in d["limits"]:
                self.lab(c, "•  " + l, 13, ("#8a5d0a", "#e3b25a"))
            self.pad(c)
        if self.errs:
            c = self.card("Taranamayan dosyalar")
            for e in self.errs:
                self.lab(c, "•  " + e, 13, ("#8a5d0a", "#e3b25a"))
            self.pad(c)
        self.cv.yview_moveto(0)
        self.shown = True


if __name__ == "__main__":
    app = App()
    argv = [a for a in sys.argv[1:] if os.path.isfile(a)]  # sağ tık menüsünden gelen dosyalar
    if argv:
        app.after(400, lambda: app.run(argv))
    app.mainloop()