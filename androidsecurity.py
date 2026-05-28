#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
#
#   ██████╗ ██████╗ ██████╗ ███████╗ █████╗
#  ██╔════╝██╔═══██╗██╔══██╗╚══███╔╝██╔══██╗
#  ██║     ██║   ██║██║  ██║  ███╔╝ ███████║
#  ██║     ██║   ██║██║  ██║ ███╔╝  ██╔══██║
#  ╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
#   ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
#
#     — CODZA Edition
#   YouTube : @codza-404
#   GitHub  : github.com/404codza
#  
#
#   Çalıştır: python3 androidsecurity.py
#
# ═══════════════════════════════════════════════════════════════

import subprocess, os, sys, json, re, socket, struct
from datetime import datetime

# ─── RENKLER ───────────────────────────────────────────────────
R   = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C   = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"
BD  = "\033[1m";  RST = "\033[0m"

BANNER = f"""
{R}{BD}
 ██████╗ ██████╗ ██████╗ ███████╗ █████╗ 
██╔════╝██╔═══██╗██╔══██╗╚══███╔╝██╔══██╗
██║     ██║   ██║██║  ██║  ███╔╝ ███████║
██║     ██║   ██║██║  ██║ ███╔╝  ██╔══██║
╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝{RST}
{C}{BD}   Android Güvenlik Tarayıcı v1.0{RST}
{DIM}  YouTube : @codza-404  |  github.com/404codza{RST}
"""

# ═══════════════════════════════════════════════════════════════
#   VERİTABANLARI
# ═══════════════════════════════════════════════════════════════

MALICIOUS_DB = {
    "com.androrat.client":               ("RAT",        "Kritik", "AndroRAT uzaktan erişim"),
    "com.droidjack.server":              ("RAT",        "Kritik", "DroidJack RAT"),
    "org.thbz.rattrap":                  ("RAT",        "Kritik", "RatTrap RAT"),
    "com.omnirat":                       ("RAT",        "Kritik", "OmniRAT"),
    "com.ahmyth.mine":                   ("RAT",        "Kritik", "AhMyth Android RAT"),
    "com.spynote.client":                ("RAT",        "Kritik", "SpyNote RAT"),
    "com.metasploit.stage":              ("RAT",        "Kritik", "Metasploit payload"),
    "com.meterpreter.stage":             ("RAT",        "Kritik", "Meterpreter stage"),
    "com.hoverwatch":                    ("Stalkerware", "Kritik", "HoverWatch gizli izleme"),
    "com.spyzie":                        ("Stalkerware", "Kritik", "Spyzie"),
    "com.mspy.android":                  ("Stalkerware", "Kritik", "mSpy"),
    "com.flexispy":                      ("Stalkerware", "Kritik", "FlexiSpy"),
    "com.ispyoo":                        ("Stalkerware", "Kritik", "iSpyoo"),
    "com.highster.mobile":               ("Stalkerware", "Kritik", "Highster Mobile"),
    "com.cocospy":                       ("Stalkerware", "Kritik", "Cocospy"),
    "com.spyera":                        ("Stalkerware", "Kritik", "SpyEra"),
    "com.thetruthspy":                   ("Stalkerware", "Kritik", "TheTruthSpy"),
    "com.copy9":                         ("Stalkerware", "Kritik", "Copy9 spyware"),
    "com.minspy":                        ("Stalkerware", "Kritik", "MinSpy"),
    "com.ixspy":                         ("Stalkerware", "Kritik", "iXSpy"),
    "com.cerberusapp":                   ("Stalkerware", "Yüksek", "Cerberus izleme"),
    "com.trackview":                     ("Stalkerware", "Yüksek", "TrackView"),
    "com.ghost.push":                    ("Adware",      "Yüksek", "Ghost Push adware"),
    "com.locker.ransomware":             ("Ransomware",  "Kritik", "Android ransomware"),
    "com.android.locker":                ("Ransomware",  "Kritik", "Fake Android locker"),
    "com.keylogger.monitor":             ("Keylogger",   "Kritik", "Klavye izleme"),
    "com.wolfsoftware.androidkeylogger": ("Keylogger",   "Kritik", "Wolf Keylogger"),
    "com.whatsapp.update":               ("Fake",        "Yüksek", "Sahte WhatsApp güncellemesi"),
    "com.google.android.update":         ("Fake",        "Yüksek", "Sahte Google güncellemesi"),
    "com.android.systemupdate":          ("Fake",        "Yüksek", "Sahte sistem güncellemesi"),
}

# Şüpheli anahtar kelimeler — yalnızca gerçekten ayırt edici olanlar.
# "rat", "monitor", "track" gibi sistem paketlerinde sık geçen genel
# kelimeler ÇIKARILDI (federated, generated, volumemonitor gibi yanlış
# eşleşmeleri önlemek için). Bu kelimeler artık yalnızca tam kelime
# sınırıyla ve güvenilir yayıncı listesi dışındaki paketlerde aranır.
SUSPICIOUS_KEYWORDS = [
    "keylog", "stalkerware", "spyware", "rootkit", "backdoor",
    "trojan", "malware", "androrat", "droidjack", "spynote",
    "ahmyth", "metasploit", "meterpreter", "payload",
]

# Tam-kelime olarak aranan, daha riskli ama genel kelimeler.
# (kelime sınırı ile aranır: "spy" → "spyapp" eşleşir ama "display" eşleşmez)
SUSPICIOUS_WORD_TOKENS = [
    "spy", "rat", "stalk", "sniff", "intercept",
    "stealth", "ghost", "exploit", "phish",
]

# Güvenilir yayıncı önekleri — bu paketler şüpheli kelime taramasından
# tamamen muaf tutulur (Android sistemi, OEM'ler, bilinen büyük markalar).
TRUSTED_PUBLISHERS = [
    "android", "com.android", "com.google", "com.samsung", "com.sec",
    "com.qualcomm", "com.mediatek", "com.huawei", "com.xiaomi", "com.miui",
    "com.oneplus", "com.oppo", "com.vivo", "com.realme", "com.motorola",
    "com.lge", "com.sonymobile", "com.asus", "com.htc",
    "com.swiftkey", "com.microsoft", "com.facebook", "com.whatsapp",
    "com.instagram", "org.telegram", "com.spotify", "com.netflix",
    "com.twitter", "com.linkedin", "com.pinterest", "com.amazon",
    "org.mozilla", "org.torproject", "com.openai", "com.anthropic",
    "com.deepseek", "org.fdroid", "ch.protonvpn", "net.mullvad",
]

def is_trusted_publisher(pkg):
    """Paket güvenilir bir yayıncıdan mı? (sistem/OEM/bilinen marka)"""
    pl = pkg.lower()
    # auto_generated_rro = Android'in resource overlay sistemi, her zaman güvenli
    if "auto_generated_rro" in pl or pl.endswith("overlay"):
        return True
    return any(pl == p or pl.startswith(p + ".") for p in TRUSTED_PUBLISHERS)

def match_suspicious(pkg):
    """
    Paket adında gerçekten şüpheli bir işaret var mı?
    Güvenilir yayıncıları atlar, tam-kelime eşleşmesi kullanır.
    Eşleşirse (tetikleyen_kelime) döndürür, yoksa None.
    """
    if is_trusted_publisher(pkg):
        return None

    pl = pkg.lower()

    # 1. Kesin zararlı imza kelimeleri (substring yeterli — bunlar nadir)
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in pl:
            return kw

    # 2. Genel kelimeler — tam kelime VEYA bir parçanın başında
    #    ("spy" → "spyapp" ✓, "spyware" ✓ ama "display" ✗ çünkü
    #     "display" parçası "spy" ile başlamıyor, ortasında geçiyor)
    parts = re.split(r'[._\-]', pl)
    for token in SUSPICIOUS_WORD_TOKENS:
        for part in parts:
            # tam eşleşme veya parçanın token ile başlaması
            if part == token or part.startswith(token):
                # "rat" gibi kısa token'larda fazladan koruma:
                # "rating", "rate" gibi masum kelimeleri ele
                if token == "rat" and part in ("rate","rating","ratio","rational"):
                    continue
                if token == "ghost" and "ghostery" in part:
                    continue
                return token
    return None

DANGEROUS_PERMISSIONS = {
    "READ_SMS":                   ("Kritik", "SMS okur",                   30),
    "RECEIVE_SMS":                ("Kritik", "Gelen SMS yakalar",           30),
    "SEND_SMS":                   ("Kritik", "SMS gönderir",                25),
    "RECORD_AUDIO":               ("Kritik", "Mikrofon kaydeder",           35),
    "ACCESS_BACKGROUND_LOCATION":("Kritik", "Arka planda konum izler",     35),
    "BIND_ACCESSIBILITY_SERVICE": ("Kritik", "Her şeyi izleyebilir",        40),
    "BIND_DEVICE_ADMIN":          ("Kritik", "Cihaz yöneticisi",            40),
    "INSTALL_PACKAGES":           ("Kritik", "Uygulama yükler",             35),
    "MANAGE_EXTERNAL_STORAGE":    ("Kritik", "Tüm depolamayı yönetir",     30),
    "SYSTEM_ALERT_WINDOW":        ("Kritik", "Ekran üstüne çizer",          30),
    "READ_CONTACTS":              ("Yüksek", "Rehberi okur",                15),
    "READ_CALL_LOG":              ("Yüksek", "Arama geçmişi okur",          20),
    "PROCESS_OUTGOING_CALLS":     ("Yüksek", "Aramaları dinler",            25),
    "CAMERA":                     ("Yüksek", "Kameraya erişir",             25),
    "ACCESS_FINE_LOCATION":       ("Yüksek", "Hassas konum",                25),
    "USE_CREDENTIALS":            ("Yüksek", "Kimlik bilgisi kullanır",     20),
    "CALL_PHONE":                 ("Yüksek", "Otomatik arama yapar",        20),
    "DELETE_PACKAGES":            ("Yüksek", "Uygulama siler",              20),
    "DISABLE_KEYGUARD":           ("Yüksek", "Kilit ekranını kapatır",      25),
    "USE_BIOMETRIC":              ("Yüksek", "Biyometrik erişim",           20),
    "BODY_SENSORS":               ("Yüksek", "Sensör verileri",             20),
    "REQUEST_INSTALL_PACKAGES":   ("Yüksek", "Kurulum ister",               20),
    "READ_PHONE_STATE":           ("Orta",   "Telefon durumu",              15),
    "GET_ACCOUNTS":               ("Orta",   "Hesap listesi",               15),
    "READ_EXTERNAL_STORAGE":      ("Orta",   "Dosya okur",                  10),
    "WRITE_EXTERNAL_STORAGE":     ("Orta",   "Dosya yazar",                 10),
    "RECEIVE_BOOT_COMPLETED":     ("Orta",   "Açılışta başlar",             15),
    "FOREGROUND_SERVICE":         ("Orta",   "Ön planda çalışır",           10),
    "CHANGE_NETWORK_STATE":       ("Orta",   "Ağ değiştirir",               10),
    "READ_MEDIA_IMAGES":          ("Orta",   "Fotoğrafları okur",           15),
    "READ_MEDIA_VIDEO":           ("Orta",   "Videoları okur",              15),
    "ACTIVITY_RECOGNITION":       ("Orta",   "Aktivite takibi",             15),
    "INTERNET":                   ("Düşük",  "İnternet erişimi",             5),
    "WAKE_LOCK":                  ("Düşük",  "Ekranı açık tutar",            5),
}

# ═══════════════════════════════════════════════════════════════
#   GLOBAL DURUM
# ═══════════════════════════════════════════════════════════════

report_lines     = []
total_risk_score = 0
findings         = []

# ═══════════════════════════════════════════════════════════════
#   ÇALIŞMA ORTAMI TESPİTİ
# ═══════════════════════════════════════════════════════════════

def detect_env():
    """Termux, ADB shell, root shell veya Linux ortamını tespit et."""
    env = {
        "termux":   os.path.exists("/data/data/com.termux"),
        "root":     os.geteuid() == 0,
        "android":  os.path.exists("/proc/version") and "android" in open("/proc/version","r").read().lower() if os.path.exists("/proc/version") else False,
        "prefix":   os.environ.get("PREFIX", ""),
        "path":     os.environ.get("PATH", ""),
    }
    # Android araçlarının yolunu bul
    android_tool_paths = [
        "/system/bin", "/system/xbin", "/sbin",
        "/vendor/bin", "/product/bin",
    ]
    env["tool_path"] = next((p for p in android_tool_paths if os.path.isdir(p)), None)
    return env

ENV = detect_env()

def find_tool(name):
    """Aracı bul — önce PATH'de, sonra Android yollarında."""
    # PATH üzerinden
    result = subprocess.run(f"which {name} 2>/dev/null", shell=True,
                            capture_output=True, text=True).stdout.strip()
    if result:
        return result

    # Android özel yollar
    for base in ["/system/bin", "/system/xbin", "/sbin", "/vendor/bin",
                 "/product/bin", "/usr/bin", "/bin"]:
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    return None

# Araç önbellekleme
_tool_cache = {}
def tool(name):
    if name not in _tool_cache:
        _tool_cache[name] = find_tool(name)
    return _tool_cache[name]

def run(cmd, timeout=15, via_shell=True):
    """
    Komutu çalıştır. 'Failure calling service' gibi hata
    çıktılarını otomatik filtrele, None döndür.
    """
    try:
        r = subprocess.run(cmd, shell=via_shell, capture_output=True,
                           text=True, timeout=timeout)
        out = r.stdout.strip()
        # Android service hata mesajlarını filtrele
        bad = ["Failure calling service", "Failed transaction",
               "SecurityException", "Permission Denial"]
        if any(b in out for b in bad):
            return None
        return out if out else None
    except Exception:
        return None

def run_tool(name, args="", timeout=15):
    """Araç yolunu otomatik bul, çalıştır."""
    t = tool(name)
    if not t:
        return None
    return run(f"{t} {args}", timeout=timeout)

# ═══════════════════════════════════════════════════════════════
#   LOG & YARDIMCI
# ═══════════════════════════════════════════════════════════════

def log(text, save=True):
    clean = re.sub(r'\033\[[0-9;]*m', '', text)
    print(text)
    if save:
        report_lines.append(clean)

def add_risk(score, reason, level="warn"):
    global total_risk_score
    total_risk_score += score
    findings.append((level, score, reason))

def section(title, icon=""):
    log(f"\n{C}{BD}{'═'*57}{RST}")
    log(f"{C}{BD}  {icon} {title}{RST}")
    log(f"{C}{BD}{'═'*57}{RST}")

def ok(msg):      log(f"  {G}[+]{RST} {msg}")
def warn(msg):    log(f"  {Y}[!]{RST} {msg}")
def danger(msg):  log(f"  {R}{BD}[✗]{RST} {R}{msg}{RST}")
def info(msg):    log(f"  {C}[*]{RST} {msg}")
def sub(msg):     log(f"      {DIM}{msg}{RST}")
def head(msg):    log(f"\n  {BD}── {msg} ──{RST}")

def progress(i, total, label=""):
    pct = int((i / max(total, 1)) * 25)
    bar = "█" * pct + "░" * (25 - pct)
    label_clean = re.sub(r'\033\[[0-9;]*m', '', str(label))
    print(f"\r  {C}[{bar}]{RST} {i}/{total} {label_clean[:30]:<30}", end="", flush=True)

# ═══════════════════════════════════════════════════════════════
#   AKILLI PROP OKUMA (getprop yedeği)
# ═══════════════════════════════════════════════════════════════

def get_prop(key, fallback=""):
    """
    Önce getprop dene, sonra /system/build.prop'tan oku.
    """
    val = run_tool("getprop", key)
    if val:
        return val

    # /system/build.prop fallback
    for prop_file in ["/system/build.prop", "/vendor/build.prop",
                      "/product/build.prop", "/odm/build.prop"]:
        if os.path.exists(prop_file):
            try:
                for line in open(prop_file, "r", errors="ignore"):
                    line = line.strip()
                    if line.startswith(f"{key}="):
                        return line.split("=", 1)[1]
            except Exception:
                pass
    return fallback

# ═══════════════════════════════════════════════════════════════
#   AKILLI SETTINGS OKUMA
# ═══════════════════════════════════════════════════════════════

def get_setting(namespace, key):
    """
    settings get komutu başarısız olursa
    /data/system/settings_*.xml'den oku.
    """
    val = run_tool("settings", f"get {namespace} {key}")
    if val and val not in ("null", ""):
        return val

    # XML fallback
    xml_map = {
        "global":  "/data/system/settings_global.xml",
        "secure":  "/data/system/settings_secure.xml",
        "system":  "/data/system/settings_system.xml",
    }
    xml_file = xml_map.get(namespace)
    if xml_file and os.path.exists(xml_file):
        try:
            content = open(xml_file, "r", errors="ignore").read()
            m = re.search(rf'name="{key}"[^>]*value="([^"]*)"', content)
            if m:
                return m.group(1)
        except Exception:
            pass
    return None

# ═══════════════════════════════════════════════════════════════
#   AKILLI PAKET LİSTESİ
# ═══════════════════════════════════════════════════════════════

def get_packages(flags=""):
    """
    pm list packages dene, başarısız olursa
    /data/system/packages.xml'den parse et.
    """
    pm_out = run_tool("pm", f"list packages {flags}")
    if pm_out:
        return [p.replace("package:", "").strip()
                for p in pm_out.splitlines() if p.strip()]

    # packages.xml fallback
    pkg_xml = "/data/system/packages.xml"
    if os.path.exists(pkg_xml):
        try:
            content = open(pkg_xml, "r", errors="ignore").read()
            pkgs = re.findall(r'<package name="([\w.]+)"', content)
            return pkgs
        except Exception:
            pass

    # /data/app klasörünü tara
    app_dirs = ["/data/app", "/system/app", "/system/priv-app"]
    pkgs = []
    for d in app_dirs:
        if os.path.isdir(d):
            try:
                for item in os.listdir(d):
                    # paket adı formatı: com.example.app-xxxxx
                    m = re.match(r'([\w.]+)(?:-\w+)?$', item)
                    if m and "." in m.group(1):
                        pkgs.append(m.group(1))
            except Exception:
                pass
    return pkgs

# ═══════════════════════════════════════════════════════════════
#   AKILLI AĞ OKUMA (/proc/net/tcp)
# ═══════════════════════════════════════════════════════════════

def get_open_ports():
    """
    /proc/net/tcp ve /proc/net/tcp6'dan dinleyen portları oku.
    ss/netstat bulunamazsa fallback olarak kullan.
    """
    ports = set()
    for tcp_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
        if not os.path.exists(tcp_file):
            continue
        try:
            for line in open(tcp_file).readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                state = parts[3]
                if state != "0A":  # 0A = LISTEN
                    continue
                local_addr = parts[1]
                port_hex = local_addr.split(":")[1] if ":" in local_addr else local_addr[-4:]
                port = int(port_hex, 16)
                if port > 0:
                    ports.add(port)
        except Exception:
            pass
    return ports

def get_connections():
    """Kurulu bağlantıları /proc/net/tcp'den oku."""
    conns = []
    for tcp_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
        if not os.path.exists(tcp_file):
            continue
        try:
            for line in open(tcp_file).readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                state = parts[3]
                if state != "01":  # 01 = ESTABLISHED
                    continue
                local  = parts[1]
                remote = parts[2]

                def parse_addr(addr):
                    if ":" in addr:
                        parts2 = addr.rsplit(":", 1)
                        return parts2[0], int(parts2[1], 16)
                    return addr, 0

                _, lport = parse_addr(local)
                raddr, rport = parse_addr(remote)

                # Remote IP'yi çevir (little-endian hex)
                try:
                    if len(raddr) == 8:
                        ip_int = int(raddr, 16)
                        ip = socket.inet_ntoa(struct.pack("<I", ip_int))
                    else:
                        ip = raddr
                except Exception:
                    ip = raddr

                conns.append((lport, ip, rport))
        except Exception:
            pass
    return conns

# ═══════════════════════════════════════════════════════════════
#   MODÜL 1 — SİSTEM BİLGİSİ
# ═══════════════════════════════════════════════════════════════

def mod_system_info():
    section("SİSTEM BİLGİSİ", "📋")

    props = {
        "Marka":           get_prop("ro.product.brand"),
        "Model":           get_prop("ro.product.model"),
        "Cihaz Adı":       get_prop("ro.product.name"),
        "Android Sürümü":  get_prop("ro.build.version.release"),
        "SDK":             get_prop("ro.build.version.sdk"),
        "Yapı Türü":       get_prop("ro.build.type"),
        "Güvenlik Yaması": get_prop("ro.build.version.security_patch"),
        "CPU ABI":         get_prop("ro.product.cpu.abi"),
        "RAM":             "",
        "Çekirdek":        "",
    }

    # RAM bilgisi /proc/meminfo'dan
    try:
        for line in open("/proc/meminfo").readlines()[:1]:
            if "MemTotal" in line:
                kb = int(re.search(r'\d+', line).group())
                props["RAM"] = f"{kb // 1024} MB ({kb // 1048576} GB)"
    except Exception:
        pass

    # Çekirdek versiyonu
    try:
        props["Çekirdek"] = open("/proc/version").read().strip()[:60]
    except Exception:
        pass

    for k, v in props.items():
        if v:
            info(f"{k}: {W}{v}{RST}")

    # Güvenlik yaması yaşı kontrolü
    patch = props.get("Güvenlik Yaması", "")
    if patch and re.match(r'\d{4}-\d{2}', patch):
        try:
            py, pm = int(patch[:4]), int(patch[5:7])
            cy, cm = 2026, 5
            age = (cy - py) * 12 + (cm - pm)
            if age > 12:
                warn(f"Güvenlik yaması {age} ay eski — güncelleme önemli")
                add_risk(15, f"Güvenlik yaması {age} ay eski", "warn")
            elif age > 6:
                warn(f"Güvenlik yaması {age} ay eski — güncelleme önerilir")
                add_risk(10, f"Güvenlik yaması {age} ay eski", "warn")
            else:
                ok(f"Güvenlik yaması güncel ({age} ay önce)")
        except Exception:
            pass

    # SDK kontrolü
    sdk_str = props.get("SDK", "0")
    try:
        sdk = int(sdk_str)
        if sdk < 26:
            danger(f"Android SDK {sdk} — kritik açıklar mevcut, güncelle!")
            add_risk(25, f"Çok eski Android SDK {sdk}", "danger")
        elif sdk < 29:
            warn(f"Android SDK {sdk} — güncellenmeli")
            add_risk(10, f"Eski Android SDK {sdk}", "warn")
        else:
            ok(f"Android SDK {sdk} — yeterince güncel")
    except Exception:
        pass

    # Debug / release kontrolü
    build_type = props.get("Yapı Türü", "")
    if build_type == "user":
        ok("Yapı türü: user (üretim ROM — güvenli)")
    elif build_type in ("userdebug", "eng"):
        warn(f"Yapı türü: {build_type} — geliştirici ROM!")
        add_risk(15, f"Geliştirici ROM: {build_type}", "warn")

    # Test-keys
    tags = get_prop("ro.build.tags")
    if "test-keys" in tags:
        warn(f"Test-keys ROM: {tags}")
        add_risk(15, "Test-keys ROM", "warn")
    elif tags:
        ok(f"ROM imzası: {tags}")

    # Debug modu
    if get_prop("ro.debuggable") == "1":
        danger("ro.debuggable=1 — DEBUG MODU AÇIK!")
        add_risk(20, "Debug modu aktif", "danger")
    else:
        ok("Debug modu kapalı")

    # ADB root
    if get_prop("service.adb.root") == "1":
        danger("ADB root aktif — kablosuz tam erişim riski!")
        add_risk(30, "ADB root aktif", "danger")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 2 — ROOT KONTROLÜ
# ═══════════════════════════════════════════════════════════════

def mod_root_check():
    section("ROOT / JAILBREAK KONTROLÜ", "🔓")

    indicators = []

    # su binary taraması
    head("su Binary Taraması")
    su_paths = [
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/su/bin/su", "/magisk/.core/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
    ]
    found_su = [p for p in su_paths if os.path.exists(p)]
    if found_su:
        for p in found_su:
            danger(f"su binary bulundu: {p}")
        indicators.append("su binary")
        add_risk(25, "Root su binary", "danger")
    else:
        ok("su binary bulunamadı")

    # Magisk
    head("Magisk / SuperSU Taraması")
    magisk_paths = ["/data/adb/magisk", "/sbin/.magisk",
                    "/dev/.magisk.unblock", "/magisk",
                    "/cache/.disable_magisk"]
    found_magisk = [p for p in magisk_paths if os.path.exists(p)]
    if found_magisk:
        warn(f"Magisk tespit edildi: {found_magisk[0]}")
        indicators.append("Magisk")
        add_risk(20, "Magisk tespit edildi", "warn")
    else:
        ok("Magisk dizini bulunamadı")

    # Root yönetici uygulamaları
    root_apps = {
        "com.topjohnwu.magisk":       "Magisk Manager",
        "eu.chainfire.supersu":        "SuperSU",
        "com.koushikdutta.superuser":  "Superuser (CWM)",
        "com.noshufou.android.su":     "Superuser",
        "com.kingroot.kinguser":       "KingRoot",
        "com.kingo.root":              "KingoRoot",
        "me.phh.superuser":            "phh Superuser",
        "com.alephzain.framaroot":     "Framaroot",
    }
    all_pkgs = get_packages()
    for pkg, name in root_apps.items():
        if pkg in all_pkgs:
            warn(f"Root uygulaması: {name} ({pkg})")
            indicators.append(name)
            add_risk(15, f"Root uygulaması: {name}", "warn")

    # /system yazılabilirlik
    head("/system Bölümü")
    mount_out = run("mount 2>/dev/null | grep ' /system '")
    if mount_out:
        if "rw," in mount_out or " rw " in mount_out:
            danger("/system bölümü YAZILABILIR!")
            indicators.append("/system RW")
            add_risk(30, "/system yazılabilir", "danger")
        else:
            ok("/system salt okunur")
    else:
        # /proc/mounts fallback
        try:
            mounts = open("/proc/mounts").read()
            if "/system" in mounts:
                for line in mounts.splitlines():
                    if " /system " in line:
                        if " rw," in line or " rw " in line:
                            danger("/system bölümü YAZILABILIR!")
                            add_risk(30, "/system yazılabilir", "danger")
                        else:
                            ok("/system salt okunur")
                        break
        except Exception:
            info("/system mount bilgisi alınamadı")

    # SELinux — /sys/fs/selinux/enforce'dan oku
    head("SELinux Durumu")
    selinux_enforce = None
    try:
        selinux_enforce = open("/sys/fs/selinux/enforce").read().strip()
    except Exception:
        pass

    if selinux_enforce is None:
        selinux_enforce = run("getenforce 2>/dev/null")

    if selinux_enforce in ("1", "Enforcing"):
        ok("SELinux: Enforcing (güvenlik aktif)")
    elif selinux_enforce in ("0", "Permissive"):
        warn("SELinux: Permissive — uyarılar var ama engelleme yok")
        add_risk(15, "SELinux Permissive", "warn")
        indicators.append("SELinux Permissive")
    elif selinux_enforce == "Disabled":
        danger("SELinux DEVRE DIŞI!")
        add_risk(25, "SELinux devre dışı", "danger")
    else:
        info("SELinux durumu tespit edilemedi")

    # Busybox
    bb = run_tool("busybox") or run("which busybox 2>/dev/null")
    if bb:
        warn(f"Busybox mevcut (root aracı göstergesi)")
        indicators.append("Busybox")
        add_risk(10, "Busybox mevcut", "warn")
    else:
        ok("Busybox bulunamadı")

    if not indicators:
        ok("Root belirtisi tespit edilmedi ✓")
    else:
        log(f"\n  {Y}Root göstergeleri: {', '.join(indicators)}{RST}")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 3 — UYGULAMA ANALİZİ
# ═══════════════════════════════════════════════════════════════

def mod_app_analysis():
    section("YÜKLÜ UYGULAMA ANALİZİ", "📱")

    all_pkgs   = get_packages()
    third_pkgs = get_packages("-3")

    # Sistem uygulamalarını çıkar
    sys_pkgs = get_packages("-s")
    third_set = set(third_pkgs)

    info(f"Toplam uygulama   : {W}{len(all_pkgs)}{RST}")
    info(f"3. taraf uygulama : {W}{len(third_set)}{RST}")
    info(f"Sistem uygulaması : {W}{len(set(all_pkgs) - third_set)}{RST}")

    if not all_pkgs:
        warn("Uygulama listesi alınamadı — Termux'ta bazı komutlar kısıtlı")
        warn("Tam tarama için: adb shell python3 codza_security_scanner.py")
        return [], []

    malicious  = []
    suspicious = []

    head("Zararlı Yazılım DB Taraması")
    for pkg in all_pkgs:
        pl = pkg.lower()
        if pl in MALICIOUS_DB:
            cat, risk, desc = MALICIOUS_DB[pl]
            danger(f"[{cat.upper()}] {pkg}")
            sub(f"Risk: {risk} | {desc}")
            malicious.append(pkg)
            add_risk(50, f"Zararlı: {pkg} ({cat})", "danger")
            continue
        kw = match_suspicious(pkg)
        if kw:
            warn(f"Şüpheli paket: {pkg}  ('{kw}')")
            suspicious.append(pkg)
            add_risk(10, f"Şüpheli paket: {pkg}", "warn")

    head("Devre Dışı Uygulama Kontrolü")
    disabled = get_packages("-d")
    # Hata mesajlarını filtrele
    disabled = [p for p in disabled if "." in p and len(p) > 5] if disabled else []
    if disabled:
        info(f"Devre dışı uygulama: {len(disabled)}")
        for p in disabled[:8]:
            sub(p)
    else:
        ok("Devre dışı uygulama yok (veya alınamadı)")

    head("Özet")
    if malicious:
        danger(f"Zararlı yazılım: {len(malicious)} adet BULUNDU!")
    else:
        ok("Zararlı yazılım DB eşleşmesi yok")

    if suspicious:
        warn(f"Şüpheli paket adı: {len(suspicious)} adet")
    else:
        ok("Şüpheli paket adı yok")

    return all_pkgs, list(third_set)

# ═══════════════════════════════════════════════════════════════
#   MODÜL 4 — İZİN ANALİZİ
# ═══════════════════════════════════════════════════════════════

def mod_permission_analysis(pkg_list):
    section("UYGULAMA İZİN & RİSK ANALİZİ", "🔐")

    if not pkg_list:
        warn("Paket listesi boş — izin analizi yapılamıyor")
        info("Tam analiz için cihazda root veya ADB gerekli")
        return

    limit = min(len(pkg_list), 80)
    info(f"Analiz edilecek: {limit} uygulama...")

    app_risks = {}
    dumpsys_t = tool("dumpsys")

    for i, pkg in enumerate(pkg_list[:limit]):
        progress(i + 1, limit, pkg)

        if dumpsys_t:
            dump = run(f"{dumpsys_t} package {pkg} 2>/dev/null", timeout=6)
        else:
            dump = None

        # packages.xml'den izin okuma (fallback)
        if not dump:
            pkg_xml = "/data/system/packages.xml"
            if os.path.exists(pkg_xml):
                try:
                    content = open(pkg_xml, "r", errors="ignore").read()
                    # İlgili paketin bölümünü bul
                    m = re.search(
                        rf'<package name="{re.escape(pkg)}".*?</package>',
                        content, re.DOTALL
                    )
                    if m:
                        dump = m.group(0)
                except Exception:
                    pass

        if not dump:
            continue

        # Verilen izinleri parse et
        granted = set()
        for line in dump.splitlines():
            if "granted=true" in line or 'protection="dangerous"' in line:
                m = re.search(r'android\.permission\.(\w+)', line)
                if m:
                    granted.add(m.group(1))

        if not granted:
            continue

        score = 0
        matched = []
        for perm in granted:
            if perm in DANGEROUS_PERMISSIONS:
                rl, desc, pts = DANGEROUS_PERMISSIONS[perm]
                score += pts
                matched.append((perm, rl, desc, pts))

        if score > 0:
            app_risks[pkg] = (score, matched)

    print()

    top = sorted(app_risks.items(), key=lambda x: x[1][0], reverse=True)[:15]

    if top:
        head("En Riskli Uygulamalar (Risk Skoruna Göre)")
        for pkg, (score, perms) in top:
            if score < 20:   clr, tag = G, "Düşük"
            elif score < 50: clr, tag = Y, "Orta"
            elif score < 100:clr, tag = R, "Yüksek"
            else:            clr, tag = R+BD, "KRİTİK"

            log(f"\n  {clr}[{tag} | Skor:{score}] {pkg}{RST}")
            crit_p = [(p,r,d,s) for p,r,d,s in perms if r in ("Kritik","Yüksek")]
            for perm, risk, desc, pts in sorted(crit_p, key=lambda x: x[3], reverse=True)[:5]:
                pc = R if risk == "Kritik" else Y
                sub(f"{pc}[{risk}] {perm}{RST} — {desc} (+{pts})")

            if score >= 100:
                add_risk(15, f"Çok yüksek izin skoru: {pkg} ({score})", "warn")
    else:
        ok("Tehlikeli izin kombinasyonu bulunan uygulama yok")
        info("(Daha derin analiz için root/ADB önerilir)")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 5 — AĞ GÜVENLİĞİ (/proc/net/tcp tabanlı)
# ═══════════════════════════════════════════════════════════════

def mod_network_security():
    section("AĞ GÜVENLİĞİ ANALİZİ", "🌐")

    suspicious_ports = {
        4444:  "Metasploit varsayılan portu",
        1337:  "Hacker/backdoor portu",
        31337: "Elite backdoor portu",
        9999:  "Çeşitli RAT araçları",
        6666:  "IRC trojan",
        6667:  "IRC trojan",
        5555:  "ADB kablosuz erişim!",
        2222:  "Alternatif SSH",
        12345: "NetBus trojan",
        27374: "SubSeven trojan",
        65535: "Şüpheli yüksek port",
        8888:  "Çeşitli araçlar",
        9090:  "Weevely / web shell",
    }

    head("Dinleyen Portlar (/proc/net/tcp)")
    open_ports = get_open_ports()

    # ss veya netstat da dene
    ss_out = run("ss -tlnp 2>/dev/null") or run("netstat -tlnp 2>/dev/null")
    if ss_out:
        for m in re.finditer(r':(\d+)', ss_out):
            p = int(m.group(1))
            if p > 0:
                open_ports.add(p)

    info(f"Dinleyen port sayısı: {W}{len(open_ports)}{RST}")

    found_suspicious = False
    for port in sorted(open_ports):
        if port in suspicious_ports:
            danger(f"Şüpheli port {port} AÇIK — {suspicious_ports[port]}")
            add_risk(25, f"Şüpheli port {port}", "danger")
            found_suspicious = True
        elif port < 1024:
            info(f"Sistem portu: {port}")
        else:
            sub(f"Port {port} dinliyor")

    if not found_suspicious:
        ok("Şüpheli port bulunamadı")

    head("ADB Kablosuz (5555) Kontrolü")
    if 5555 in open_ports:
        danger("ADB kablosuz port 5555 DİNLİYOR! Uzaktan tam erişim riski!")
        add_risk(35, "ADB kablosuz 5555 açık", "danger")
    else:
        ok("ADB kablosuz (5555) kapalı")

    head("Aktif Dış Bağlantılar")
    conns = get_connections()
    # ss fallback
    if not conns:
        ss_estab = run("ss -tnp 2>/dev/null | grep ESTAB") or \
                   run("netstat -tnp 2>/dev/null | grep ESTABLISHED")
        if ss_estab:
            info(f"Aktif bağlantı ({len(ss_estab.splitlines())} adet):")
            for line in ss_estab.splitlines()[:8]:
                sub(line.strip()[:80])

    if conns:
        info(f"Aktif bağlantı: {W}{len(conns)}{RST}")
        # Yerel olmayan bağlantıları göster
        for lport, rip, rport in conns[:10]:
            if not rip.startswith(("127.", "10.", "192.168.", "172.")):
                sub(f"Yerel:{lport} → {rip}:{rport}")

    head("DNS Yapılandırması")
    trusted_dns = {"8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1",
                   "9.9.9.9","208.67.222.222","208.67.220.220"}

    # /proc/net/dns veya getprop
    dns_vals = []
    for key in ["net.dns1","net.dns2","dhcp.wlan0.dns1","dhcp.eth0.dns1"]:
        v = get_prop(key)
        if v and v not in dns_vals:
            dns_vals.append(v)

    # /etc/resolv.conf fallback
    if not dns_vals and os.path.exists("/etc/resolv.conf"):
        try:
            for line in open("/etc/resolv.conf"):
                if line.startswith("nameserver"):
                    dns_vals.append(line.split()[1])
        except Exception:
            pass

    if dns_vals:
        for dns in dns_vals:
            if dns in trusted_dns:
                ok(f"DNS: {dns} (güvenilir)")
            else:
                warn(f"DNS: {dns} (bilinmeyen — izleme riski?)")
                add_risk(10, f"Bilinmeyen DNS: {dns}", "warn")
    else:
        info("DNS bilgisi alınamadı")

    head("Sistem Proxy Kontrolü")
    # Hata mesajı içermeyenleri kabul et
    proxy = get_setting("global", "http_proxy")
    if proxy and proxy not in ("null", ":0", ""):
        warn(f"Sistem proxy aktif: {proxy}")
        sub("Tüm HTTP trafiğiniz bu sunucudan geçiyor!")
        add_risk(15, f"Sistem proxy: {proxy}", "warn")
    else:
        ok("Sistem proxy yok")

    head("WiFi Güvenliği")
    wifi_out = run_tool("dumpsys", "wifi 2>/dev/null | grep -E 'WEP|WPA|security|SSID' | head -8")
    if wifi_out:
        if "WEP" in wifi_out:
            danger("WEP şifreli ağ — çok zayıf şifreleme!")
            add_risk(20, "WEP ağ", "danger")
        elif "WPA3" in wifi_out:
            ok("WPA3 ağa bağlı (en güvenli)")
        elif "WPA" in wifi_out:
            ok("WPA/WPA2 ağa bağlı")
    else:
        info("WiFi bilgisi alınamadı")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 6 — SÜREÇ & SERVİS
# ═══════════════════════════════════════════════════════════════

def mod_process_analysis():
    section("ÇALIŞAN SÜREÇ & SERVİS ANALİZİ", "⚙️")

    head("Aktif Süreçler")
    # /proc klasöründen süreçleri oku (her zaman çalışır)
    proc_names = []
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                cmd_file = f"/proc/{pid}/cmdline"
                try:
                    cmdline = open(cmd_file, "rb").read().decode("utf-8", errors="ignore")
                    cmdline = cmdline.replace("\x00", " ").strip()
                    if cmdline:
                        proc_names.append((pid, cmdline[:80]))
                except Exception:
                    pass
    except Exception:
        pass

    # ps komutu fallback
    if not proc_names:
        ps_out = run("ps -A 2>/dev/null") or run("ps aux 2>/dev/null")
        if ps_out:
            for line in ps_out.splitlines():
                proc_names.append(("?", line.strip()[:80]))

    info(f"Tespit edilen süreç: {W}{len(proc_names)}{RST}")

    suspicious_procs = []
    for pid, cmd in proc_names:
        cmdl = cmd.lower()
        if "grep" in cmdl or "scanner" in cmdl or "codza" in cmdl:
            continue
        # Süreçlerde yalnızca kesin zararlı imzaları ara (genel kelimeler değil)
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in cmdl:
                suspicious_procs.append((pid, cmd, kw))
                break

    if suspicious_procs:
        warn(f"Şüpheli süreç: {len(suspicious_procs)}")
        for pid, cmd, kw in suspicious_procs[:5]:
            sub(f"[PID:{pid}] {cmd[:60]}  ('{kw}')")
            add_risk(15, f"Şüpheli süreç: {kw}", "warn")
    else:
        ok("Şüpheli isimli süreç yok")

    head("Açılışta Başlayan Uygulamalar")
    boot_xml = "/data/system/packages.xml"
    boot_pkgs = []
    if os.path.exists(boot_xml):
        try:
            content = open(boot_xml, "r", errors="ignore").read()
            # BOOT_COMPLETED receiver olan paketler
            receivers = re.findall(r'<package name="([\w.]+)"[^>]*>.*?BOOT_COMPLETED', content, re.DOTALL)
            boot_pkgs = receivers[:20]
        except Exception:
            pass

    if not boot_pkgs:
        boot_raw = run_tool("dumpsys", "package 2>/dev/null | grep -B5 'BOOT_COMPLETED' | grep 'packageName' | head -15")
        if boot_raw:
            boot_pkgs = re.findall(r'packageName=([\w.]+)', boot_raw)

    if boot_pkgs:
        info(f"Boot receiver: {len(boot_pkgs)}")
        legit = ["com.google","com.android","com.samsung","com.sec","android","com.huawei"]
        for pkg in set(boot_pkgs)[:12]:
            if not any(pkg.startswith(l) for l in legit):
                warn(f"3. taraf boot receiver: {pkg}")
                add_risk(5, f"Boot receiver: {pkg}", "warn")
            else:
                sub(pkg)
    else:
        info("Boot receiver bilgisi alınamadı")

    head("Arka Plan Hizmetleri")
    svc_raw = run_tool("dumpsys", "activity services 2>/dev/null | grep ServiceRecord | head -20")
    if svc_raw:
        svc_list = re.findall(r'([\w.]+)/([\w.$]+)', svc_raw)
        info(f"Aktif servis: {len(svc_list)}")
        for pkg, cls in svc_list:
            kw = match_suspicious(pkg)
            if kw:
                warn(f"Şüpheli servis: {pkg}/{cls}  ('{kw}')")
                add_risk(10, f"Şüpheli servis: {pkg}", "warn")
    else:
        info("Servis listesi alınamadı")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 7 — ERİŞİLEBİLİRLİK & CİHAZ YÖNETİCİSİ
# ═══════════════════════════════════════════════════════════════

def mod_accessibility_admin():
    section("ERİŞİLEBİLİRLİK & CİHAZ YÖNETİCİSİ", "♿")

    head("Erişilebilirlik Servisleri")

    # settings get fallback zinciri
    raw = get_setting("secure", "enabled_accessibility_services")

    if not raw or raw in ("null", "0", ""):
        ok("Etkin erişilebilirlik servisi yok")
    else:
        # Sadece pkg/sınıf formatındakileri al
        services = [s.strip() for s in raw.split(":") if "/" in s and "." in s]
        legit = ["com.google","com.samsung","com.android","com.sec","android",
                 "com.huawei","com.xiaomi","com.oneplus","com.miui"]
        info(f"Erişilebilirlik servisi: {len(services)}")
        for svc in services:
            pkg = svc.split("/")[0]
            if any(pkg.startswith(l) for l in legit):
                ok(f"Normal: {svc}")
            else:
                danger(f"BİLİNMEYEN SERVİS: {svc}")
                sub("Ekranınızı, klavyenizi, tüm uygulamalarınızı izleyebilir!")
                add_risk(40, f"Şüpheli erişilebilirlik: {svc}", "danger")

    head("Cihaz Yöneticileri")
    admin_raw = run_tool("dumpsys", "device_policy 2>/dev/null | head -60")
    if admin_raw:
        admin_pkgs = re.findall(r'packageName=([\w.]+)', admin_raw)
        legit_admin = ["com.google","com.samsung","com.android","com.sec",
                       "com.microsoft","com.blackberry","com.mobileiron"]
        if admin_pkgs:
            for pkg in set(admin_pkgs):
                if any(pkg.startswith(l) for l in legit_admin):
                    ok(f"Normal: {pkg}")
                else:
                    danger(f"ŞÜPHELI CİHAZ YÖNETİCİSİ: {pkg}")
                    sub("Cihazı kilitleyip tüm verilerini silebilir!")
                    add_risk(45, f"Şüpheli cihaz yöneticisi: {pkg}", "danger")
        else:
            ok("Şüpheli cihaz yöneticisi yok")
    else:
        info("Cihaz yöneticisi bilgisi alınamadı")

    head("Overlay (Ekran Üstü Çizim) İzinleri")
    overlay_raw = run("appops query-op SYSTEM_ALERT_WINDOW allow 2>/dev/null | head -15")
    if overlay_raw and "Error" not in overlay_raw and "not found" not in (overlay_raw or "").lower():
        pkgs = re.findall(r'([\w]{3,}\.[\w.]+)', overlay_raw)
        legit_ov = ["com.google","com.android","com.samsung","com.facebook",
                    "com.whatsapp","com.instagram","org.telegram","com.discord",
                    "com.sec","com.miui"]
        for pkg in set(pkgs):
            if not any(pkg.startswith(l) for l in legit_ov):
                warn(f"Overlay izni: {pkg}")
                add_risk(10, f"Overlay izni: {pkg}", "warn")
    else:
        ok("Overlay izni taraması tamamlandı")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 8 — DOSYA SİSTEMİ
# ═══════════════════════════════════════════════════════════════

def mod_filesystem():
    section("DOSYA SİSTEMİ ANALİZİ", "📁")

    head("Şüpheli Sistem Dizinleri")
    # Bazı dizinler her Android cihazda bulunur (normaldir) — bunların
    # sadece İÇİNDE dosya varsa uyarı veririz. Diğerleri (RAT verisi, gizli
    # klasörler) varlığı bile şüphelidir.
    # (yol, açıklama, "her_zaman_var_normal" bayrağı)
    suspicious_dirs = [
        ("/data/local/tmp",          "Exploit/payload deposu",  True),
        ("/data/local/xbin",         "Root araçları",           False),
        ("/system/xbin",             "Root araçları",           True),
        ("/data/adb",                "Magisk/ADB root verisi",  False),
        ("/magisk",                  "Magisk root",             False),
        ("/sbin/.magisk",            "Magisk çekirdek",         False),
        ("/data/data/com.androrat",  "AndroRAT verisi",         False),
        ("/data/data/com.droidjack", "DroidJack verisi",        False),
        ("/sdcard/.hidden",          "Gizli klasör",            False),
        ("/sdcard/.spy",             "Spyware klasörü",         False),
    ]
    for path, desc, normal_exists in suspicious_dirs:
        if not os.path.exists(path):
            ok(f"Yok: {path}")
            continue

        # Erişim kısıtlıysa içeriği göremeyiz — bu normaldir, risk ekleme
        try:
            contents = os.listdir(path)
        except PermissionError:
            if normal_exists:
                ok(f"{path} mevcut (içerik kısıtlı — normal)")
            else:
                info(f"{path} mevcut (içerik kısıtlı)")
            continue
        except Exception:
            info(f"{path} mevcut (okunamadı)")
            continue

        n = len(contents)
        if normal_exists:
            # Sistemde olması normal — sadece içinde şüpheli şey varsa uyar
            sus_files = [c for c in contents
                         if any(rf in c.lower() for rf in
                                ["payload","msf","rat","exploit","sh",".elf"])]
            if sus_files:
                warn(f"{path} içinde şüpheli dosya: {', '.join(sus_files[:3])}")
                add_risk(15, f"Şüpheli dosya: {path}", "warn")
            elif n > 0:
                info(f"{path} ({n} öğe — normal sistem dizini)")
            else:
                ok(f"{path} boş (normal)")
        else:
            # Bu dizinin varlığı tek başına şüpheli (RAT/spyware/root)
            warn(f"Mevcut: {path} ({n} öğe) — {desc}")
            add_risk(15, f"Şüpheli dizin: {path}", "warn")

    head("İndirilen APK Taraması")
    apk_paths = [
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/storage/downloads"),
        "/sdcard/Download", "/sdcard/Downloads",
    ]
    found_apks = []
    seen_paths = set()
    for path in apk_paths:
        if os.path.isdir(path):
            try:
                for f in os.listdir(path):
                    if f.lower().endswith(".apk"):
                        full = os.path.join(path, f)
                        # gerçek dosya yoluyla tekrarı önle (symlink/aynı klasör)
                        try:
                            real = os.path.realpath(full)
                        except Exception:
                            real = full
                        if real in seen_paths:
                            continue
                        seen_paths.add(real)
                        size = os.path.getsize(full) // 1024
                        found_apks.append((full, size, f))
            except Exception:
                pass

    if found_apks:
        info(f"Bulunan APK: {len(found_apks)} (benzersiz)")
        # Yalnızca gerçekten zararlı çağrışımlı isimler
        apk_red_flags = ["payload", "msfvenom", "metasploit", "androrat",
                         "spynote", "ahmyth", "backdoor", "keylog", "rat-"]
        for full, size, name in found_apks[:15]:
            name_l = name.lower()
            is_red = any(rf in name_l for rf in apk_red_flags)
            if is_red:
                warn(f"Şüpheli isimli APK: {name} ({size}KB)")
                add_risk(15, f"Şüpheli APK adı: {name}", "warn")
            elif size < 50:
                # Çok küçük APK — bazen payload olur ama çoğu zaman normal değil
                warn(f"Çok küçük APK: {name} ({size}KB) — içeriğini kontrol edin")
                add_risk(8, f"Çok küçük APK: {name}", "warn")
            else:
                sub(f"{name} ({size}KB)")

        # payload.apk özel kritik uyarı
        payload_apks = [n for _,_,n in found_apks if "payload" in n.lower()]
        if payload_apks:
            danger(f"'payload' isimli APK: {', '.join(set(payload_apks))}")
            sub("Bu bir Metasploit/RAT payload'ı olabilir — kaynağından emin değilseniz silin!")
            add_risk(20, "payload.apk bulundu", "danger")
    else:
        ok("İndirilmiş APK bulunamadı")

    head("Termux Araç Taraması")
    home = os.path.expanduser("~")
    bad_tools = ["metasploit","msfvenom","payload","backdoor",
                 "keylog","trojan","exploit","msfconsole"]
    found_bad = []
    try:
        for root_d, dirs, files in os.walk(home):
            depth = root_d.replace(home, "").count(os.sep)
            if depth > 4:
                dirs.clear()
                continue
            for f in files:
                fl = f.lower()
                for bt in bad_tools:
                    if bt in fl:
                        found_bad.append(os.path.join(root_d, f))
                        break
    except Exception:
        pass

    if found_bad:
        warn(f"Şüpheli araç/dosya: {len(found_bad)}")
        for fb in found_bad[:5]:
            sub(fb)
        add_risk(15, f"Şüpheli dosya: {len(found_bad)}", "warn")
    else:
        ok("Şüpheli araç/dosya bulunamadı")

    head("SELinux & Şifreleme")
    enc = get_prop("ro.crypto.state")
    if enc == "encrypted":
        ok("Cihaz şifreli ✓")
    elif enc == "unencrypted":
        warn("Cihaz şifreli DEĞİL — fiziksel erişimde veriler okunabilir!")
        add_risk(15, "Cihaz şifreli değil", "warn")
    else:
        info(f"Şifreleme: {enc or 'alınamadı'}")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 9 — PİL & DONANIM
# ═══════════════════════════════════════════════════════════════

def mod_battery():
    section("PİL & DONANIM ANALİZİ", "🔋")

    head("Pil Durumu")

    # 1. Termux API
    batt_j = run("termux-battery-status 2>/dev/null")
    if batt_j and batt_j.strip().startswith("{"):
        try:
            d = json.loads(batt_j)
            level  = d.get("percentage", "?")
            temp   = float(str(d.get("temperature", 0)))
            status = d.get("status", "?")
            health = d.get("health", "?")

            info(f"Seviye  : {W}{level}%{RST}")
            info(f"Durum   : {W}{status}{RST}")
            info(f"Sağlık  : {W}{health}{RST}")

            if temp > 50:
                danger(f"Sıcaklık: {temp}°C — AŞIRI ISINMA!")
                add_risk(25, f"Aşırı sıcaklık: {temp}°C", "danger")
            elif temp > 42:
                warn(f"Sıcaklık: {temp}°C — Yüksek")
                add_risk(10, f"Yüksek sıcaklık: {temp}°C", "warn")
            else:
                ok(f"Sıcaklık: {temp}°C — Normal")
        except Exception as e:
            warn(f"Pil JSON ayrıştırma hatası: {e}")

    else:
        # 2. /sys/class/power_supply doğrudan oku
        ps_base = "/sys/class/power_supply"
        found_battery = False
        try:
            supplies = os.listdir(ps_base) if os.path.isdir(ps_base) else []
        except (PermissionError, OSError):
            supplies = []  # erişim yoksa sessizce dumpsys'e geç

        if supplies:
            for supply in supplies:
                if "battery" in supply.lower() or "bat" == supply.lower():
                    base = os.path.join(ps_base, supply)
                    found_battery = True

                    def read_sys(f):
                        try:
                            return open(os.path.join(base, f)).read().strip()
                        except:
                            return None

                    capacity = read_sys("capacity")
                    status   = read_sys("status")
                    health   = read_sys("health")
                    temp_raw = read_sys("temp")

                    if capacity: info(f"Seviye  : {W}{capacity}%{RST}")
                    if status:   info(f"Durum   : {W}{status}{RST}")
                    if health:   info(f"Sağlık  : {W}{health}{RST}")

                    if temp_raw:
                        try:
                            temp_c = int(temp_raw) / 10.0
                            if temp_c > 50:
                                danger(f"Sıcaklık: {temp_c}°C — AŞIRI ISINMA!")
                                add_risk(25, f"Aşırı sıcaklık: {temp_c}°C", "danger")
                            elif temp_c > 42:
                                warn(f"Sıcaklık: {temp_c}°C — Yüksek")
                                add_risk(10, f"Yüksek sıcaklık: {temp_c}°C", "warn")
                            else:
                                ok(f"Sıcaklık: {temp_c}°C — Normal")
                        except:
                            pass
                    break

        if not found_battery:
            # 3. dumpsys battery
            batt_raw = run_tool("dumpsys", "battery 2>/dev/null")
            if batt_raw:
                for line in batt_raw.splitlines()[:10]:
                    if any(k in line for k in ["level","temperature","status","health"]):
                        if "temperature:" in line:
                            try:
                                t = int(re.search(r'\d+', line).group()) / 10
                                if t > 42:
                                    warn(f"Sıcaklık: {t:.1f}°C")
                                    add_risk(10, f"Yüksek sıcaklık: {t}°C", "warn")
                                else:
                                    ok(f"Sıcaklık: {t:.1f}°C")
                                continue
                            except:
                                pass
                        info(line.strip())
            else:
                warn("Pil bilgisi alınamadı. Termux API yükle: pkg install termux-api")

    head("CPU & Bellek")
    # CPU çekirdek sayısı
    try:
        cores = len([l for l in open("/proc/cpuinfo").readlines() if l.startswith("processor")])
        info(f"CPU Çekirdeği: {W}{cores}{RST}")
    except:
        pass

    # Yük ortalaması
    try:
        loadavg = open("/proc/loadavg").read().strip()
        parts = loadavg.split()
        load1 = float(parts[0])
        info(f"CPU Yükü (1dk): {W}{load1}{RST}")
        if load1 > 4.0:
            warn(f"Yüksek CPU yükü: {load1} — zararlı süreç olabilir!")
            add_risk(10, f"Yüksek CPU: {load1}", "warn")
    except:
        pass

    # Bellek
    try:
        mem = {}
        for line in open("/proc/meminfo").readlines()[:5]:
            k, v = line.split(":")
            mem[k.strip()] = int(re.search(r'\d+', v).group()) // 1024
        total = mem.get("MemTotal", 0)
        free  = mem.get("MemAvailable", 0)
        used  = total - free
        info(f"RAM: {W}{used}MB kullanılıyor / {total}MB toplam{RST}")
        if total > 0 and (used / total) > 0.92:
            warn("RAM kullanımı %92+ — arka planda yoğun aktivite!")
            add_risk(5, "Yüksek RAM kullanımı", "warn")
    except:
        pass

# ═══════════════════════════════════════════════════════════════
#   MODÜL 10 — GÜVENLİK AYARLARI
# ═══════════════════════════════════════════════════════════════

def mod_security_settings():
    section("GÜVENLİK AYARLARI KONTROLÜ", "🛡️")

    # settings get + XML fallback kullanan kontroller
    checks = [
        ("global",  "adb_enabled",                    "1",  15, "USB hata ayıklama AÇIK"),
        ("global",  "install_non_market_apps",         "1",  10, "Bilinmeyen kaynaklardan kurulum etkin"),
        ("global",  "development_settings_enabled",    "1",  10, "Geliştirici seçenekleri açık"),
        ("secure",  "mock_location",                   "1",   5, "Sahte konum aktif"),
        ("global",  "package_verifier_enable",         "0",  15, "Play Protect kapalı"),
        ("global",  "verifier_verify_adb_installs",    "0",   8, "ADB kurulum doğrulama kapalı"),
    ]

    unreadable = 0
    for ns, key, bad_val, pts, reason in checks:
        val = get_setting(ns, key)
        if val is None:
            unreadable += 1
        elif val == bad_val:
            warn(f"{reason}")
            add_risk(pts, reason, "warn")
        else:
            ok(f"{reason.split()[0]}: Güvenli")

    if unreadable:
        info(f"{unreadable} ayar okunamadı (root'suz Termux'ta normal — "
             f"tam tarama için ADB kullanın)")

    head("Cihaz Şifrelemesi")
    enc = get_prop("ro.crypto.state")
    if enc == "encrypted":
        ok("Cihaz şifreli ✓")
    elif enc == "unencrypted":
        danger("Cihaz şifreli DEĞİL — fiziksel saldırıya açık!")
        add_risk(20, "Cihaz şifreli değil", "danger")
    else:
        info(f"Şifreleme durumu: {enc or 'tespit edilemedi'}")

    head("Kullanıcı Sertifikaları (HTTPS İzleme Riski)")
    cert_dir = "/data/misc/user/0/cacerts-added"
    if os.path.exists(cert_dir):
        try:
            certs = os.listdir(cert_dir)
            if certs:
                danger(f"Kullanıcı tarafından {len(certs)} sertifika eklendi!")
                sub("Bu sertifikalar HTTPS trafiğinizi şifreli görünürken izleyebilir!")
                for c in certs[:5]:
                    sub(f"→ {c}")
                add_risk(35, f"Şüpheli kullanıcı sertifikası: {len(certs)}", "danger")
            else:
                ok("Kullanıcı sertifikası yok ✓")
        except PermissionError:
            info("Sertifika dizini var (erişim kısıtlı)")
        except Exception as e:
            info(f"Sertifika: {e}")
    else:
        ok("Kullanıcı sertifika dizini yok ✓")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 11 — HESAP & SERTİFİKA
# ═══════════════════════════════════════════════════════════════

def mod_accounts():
    section("HESAP & AĞIRLAMA ANALİZİ", "🔑")

    head("Kayıtlı Hesaplar")
    acc_raw = run_tool("dumpsys", "account 2>/dev/null | grep 'Account {' | head -15")
    if acc_raw:
        acc_list = re.findall(r'Account \{name=([\w@.+-]+), type=([\w.]+)\}', acc_raw)
        info(f"Kayıtlı hesap: {len(acc_list)}")
        for name, acc_type in acc_list[:10]:
            # Hassas hesap tiplerini işaretle
            if any(t in acc_type for t in ["google","samsung","microsoft","apple"]):
                sub(f"{name} ({acc_type})")
            else:
                warn(f"Bilinmeyen hesap tipi: {name} ({acc_type})")
    else:
        info("Hesap bilgisi alınamadı (izin gerekli)")

    head("Kayıtlı WiFi Ağları")
    wifi_xml = "/data/misc/wifi/WifiConfigStore.xml"
    if os.path.exists(wifi_xml):
        try:
            content = open(wifi_xml, "r", errors="ignore").read()
            ssids = re.findall(r'<string name="SSID">"?([^"<]+)"?</string>', content)
            info(f"Kayıtlı WiFi: {len(ssids)}")
            for s in ssids[:8]:
                sub(s)
        except Exception:
            info("WiFi yapılandırması okunamadı")
    else:
        info("WiFi yapılandırması bulunamadı (root gerekir)")

    head("VPN Profilleri")
    vpn_raw = run_tool("dumpsys", "connectivity 2>/dev/null | grep -i vpn | head -5")
    if vpn_raw:
        info(f"VPN bilgisi: {vpn_raw.strip()[:100]}")
    else:
        ok("Aktif VPN bağlantısı tespit edilmedi")

# ═══════════════════════════════════════════════════════════════
#   MODÜL 12 — FINAL RAPOR
# ═══════════════════════════════════════════════════════════════

def mod_final_report():
    section("GÜVENLİK TARAMA RAPORU", "📊")

    # Risk seviyesi belirle
    r_color, r_label, r_desc = G, "DÜŞÜK", "Cihaz güvende görünüyor"
    thresholds = [
        (0,  20,  G,    "DÜŞÜK",   "Cihaz güvende görünüyor"),
        (21, 40,  Y,    "ORTA",    "Dikkat gerektiren durumlar var"),
        (41, 70,  R,    "YÜKSEK",  "Ciddi güvenlik riskleri tespit edildi"),
        (71, 999, R+BD, "KRİTİK",  "Cihazınız tehlikede olabilir!"),
    ]
    for lo, hi, color, label, desc in thresholds:
        if lo <= total_risk_score <= hi:
            r_color, r_label, r_desc = color, label, desc
            break

    bar_fill = min(int(total_risk_score / 2.5), 40)
    bar = "█" * bar_fill + "░" * (40 - bar_fill)

    log(f"\n  {BD}Risk Skoru : {r_color}{total_risk_score} puan{RST}")
    log(f"  {r_color}[{bar}] {min(total_risk_score, 100)}%{RST}")
    log(f"  {r_color}{BD}Seviye     : {r_label}{RST}")
    log(f"  {DIM}{r_desc}{RST}")

    # Bulgular
    critical_f = [(l,s,r) for l,s,r in findings if l == "danger"]
    warning_f  = [(l,s,r) for l,s,r in findings if l == "warn"]

    if findings:
        head("Tespit Edilen Riskler")
        if critical_f:
            log(f"\n  {R}{BD}KRİTİK ({len(critical_f)}):{RST}")
            for _, sc, rs in critical_f:
                log(f"  {R}  ✗ [{sc:+3d}p] {rs}{RST}")
        if warning_f:
            log(f"\n  {Y}{BD}UYARILAR ({len(warning_f)}):{RST}")
            for _, sc, rs in warning_f:
                log(f"  {Y}  ! [{sc:+3d}p] {rs}{RST}")
    else:
        ok("Hiçbir risk bulunamadı — cihaz güvende! ✓")

    # Öneriler
    reasons = " ".join(r for _,_,r in findings).lower()
    recs = []
    if "usb" in reasons or "adb" in reasons:
        recs.append("USB hata ayıklamayı kapatın (Geliştirici Ayarları → ADB)")
    if "yama" in reasons:
        recs.append("Android güvenlik yamalarını güncelleyin")
    if "dns" in reasons:
        recs.append("Güvenilir DNS kullanın (8.8.8.8 veya 1.1.1.1)")
    if "sertifika" in reasons:
        recs.append("Şüpheli sertifikaları kaldırın (Ayarlar → Güven Listesi)")
    if "proxy" in reasons:
        recs.append("Sistem proxysi kapatın")
    if "root" in reasons:
        recs.append("Gerekli değilse root'u kaldırın")
    if "payload" in reasons:
        recs.append("İndirmeler klasöründeki payload.apk dosyasını inceleyin/silin")
    if "erişilebilirlik" in reasons:
        recs.append("Erişilebilirlik servislerini gözden geçirin")
    recs += [
        "Uygulamaları yalnızca Play Store'dan indirin",
        "Düzenli olarak uygulama izinlerini denetleyin",
        "VPN kullanmayı düşünün (özellikle halka açık WiFi'da)",
        "Ekran kilidini PIN/şifre/biyometri ile koruyun",
        "Play Protect'i etkin tutun",
    ]

    head("Güvenlik Önerileri")
    for i, rec in enumerate(recs[:8], 1):
        log(f"  {C}  {i}. {rec}{RST}")

    # Raporu dosyaya kaydet
    head("Rapor Kaydı")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.expanduser(f"~/codza_scan_{ts}.txt")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("=" * 57 + "\n")
            f.write("  CODZA Android Güvenlik Tarayıcı v1.0\n")
            f.write(f"  Tarih  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Skor   : {total_risk_score} puan\n")
            f.write(f"  Seviye : {r_label}\n")
            f.write("=" * 57 + "\n\n")
            f.write("\n".join(report_lines))
        ok(f"Rapor kaydedildi: {report_path}")
    except Exception as e:
        warn(f"Rapor kaydedilemedi: {e}")

    log(f"\n{C}{'─'*57}{RST}")
    log(f"{C}{BD}   YouTube: @codza-404  |  github.com/404codza{RST}")
    log(f"{DIM}   Güvenlik içerikleri için abone olmayı unutma!{RST}")
    log(f"{C}{'─'*57}{RST}\n")

# ═══════════════════════════════════════════════════════════════
#   ANA PROGRAM
# ═══════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    in_termux = ENV["termux"]
    is_root   = ENV["root"]

    if in_termux:
        info(f"Termux ortamı {G}✓{RST}")
    if is_root:
        info(f"Root yetkisi {G}✓ (tam tarama aktif){RST}")
    else:
        info(f"Root yok — bazı modüller sınırlı çalışır")
        info(f"Tam tarama: adb shell python3 $(pwd)/codza_security_scanner.py")

    log(f"  {Y}Tarama başlıyor — 11 modül...{RST}")
    log(f"  {DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}\n")

    all_pkgs   = []
    third_pkgs = []

    step_modules = [
        ("SİSTEM BİLGİSİ",             mod_system_info),
        ("ROOT KONTROLÜ",              mod_root_check),
        ("UYGULAMA ANALİZİ",           None),  # özel
        ("AĞ GÜVENLİĞİ",              mod_network_security),
        ("SÜREÇ & SERVİS",             mod_process_analysis),
        ("ERİŞİLEBİLİRLİK",           mod_accessibility_admin),
        ("DOSYA SİSTEMİ",              mod_filesystem),
        ("PİL & DONANIM",              mod_battery),
        ("GÜVENLİK AYARLARI",          mod_security_settings),
        ("HESAP & SERTİFİKA",          mod_accounts),
    ]

    for name, func in step_modules:
        try:
            if func is None:
                result = mod_app_analysis()
                if result:
                    all_pkgs, third_pkgs = result
            else:
                func()
        except KeyboardInterrupt:
            print(f"\n{Y}[!] Tarama durduruldu{RST}")
            break
        except Exception as e:
            warn(f"{name} hatası: {e}")

    # İzin analizi
    try:
        mod_permission_analysis(third_pkgs or all_pkgs)
    except Exception as e:
        warn(f"İzin analizi hatası: {e}")

    mod_final_report()

if __name__ == "__main__":
    main()
