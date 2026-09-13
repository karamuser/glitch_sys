#!/usr/bin/env python3
import os, sys, re, json, time, platform, subprocess, urllib.request
from pathlib import Path
from datetime import datetime

APP_NAME = "Glitch Sys"
APP_VERSION = "0.4"
APP_AUTHOR = "Karam Al-Bari"
APP_TEAM = "T STUDIO"

IS_ANDROID = "ANDROID_ROOT" in os.environ or "com.termux" in os.environ.get("PREFIX", "")
IS_LINUX = platform.system() == "Linux" and not IS_ANDROID
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

if IS_ANDROID:
    BASE_DIR = Path(os.environ.get("PREFIX", "/data/data/com.termux/files/usr")) / "etc" / "glitch_sys"
elif IS_WINDOWS:
    BASE_DIR = Path(os.environ.get("USERPROFILE", ".")) / ".glitch_sys"
else:
    BASE_DIR = Path.home() / ".glitch_sys"

BASE_DIR.mkdir(parents=True, exist_ok=True)
DB_FILE = BASE_DIR / "threat_db.json"
LOG_FILE = BASE_DIR / "glitch.log"
CONFIG_FILE = BASE_DIR / "config.json"

if IS_WINDOWS:
    HOSTS_FILE = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "drivers" / "etc" / "hosts"
else:
    HOSTS_FILE = Path("/etc/hosts")

VPN_LIST = ["proton", "nord", "express", "mullvad"]
DNS_CONFIG = {"cloudflare": "1.1.1.1", "google": "8.8.8.8", "quad9": "9.9.9.9"}
MARKER_START = "# ===== Glitch Sys Block START ====="
MARKER_END = "# ===== Glitch Sys Block END ====="

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
                   ".work", ".loan", ".download", ".review", ".zip", ".kim", ".country"]
SUSPICIOUS_KEYWORDS = ["login", "verify", "account", "update", "secure", "bank",
                       "paypal", "signin", "wallet", "crypto", "free", "prize",
                       "winner", "confirm", "validate", "recover", "unlock"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
                  "buff.ly", "adf.ly", "shorte.st", "bc.vc"]

DEFAULT_CONFIG = {"lang": "en", "theme": "dark"}

HAS_RICH = False
HAS_KIVY = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
    HAS_RICH = True
except ImportError:
    pass

try:
    from kivy.app import App
    from kivy.uix.screenmanager import ScreenManager, Screen
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.gridlayout import GridLayout
    from kivy.uix.button import Button
    from kivy.uix.label import Label
    from kivy.uix.textinput import TextInput
    from kivy.uix.scrollview import ScrollView
    from kivy.core.window import Window
    from kivy.utils import get_color_from_hex
    HAS_KIVY = True
except ImportError:
    pass


def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                return {**DEFAULT_CONFIG, **json.load(f)}
        except Exception:
            return dict(DEFAULT_CONFIG)
    return dict(DEFAULT_CONFIG)

def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass

def log(msg):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now()}] {msg}\n")
    except Exception:
        pass

def is_root():
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def analyze_domain(domain):
    score = 0
    reasons = []
    d = domain.lower().strip()
    for tld in SUSPICIOUS_TLDS:
        if d.endswith(tld):
            score += 30
            reasons.append(f"Suspicious TLD: {tld}")
            break
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in d:
            score += 15
            reasons.append(f"Danger keyword: {kw}")
    for s in URL_SHORTENERS:
        if s in d:
            score += 25
            reasons.append(f"URL shortener: {s}")
    if len(d) > 50:
        score += 10
        reasons.append("Very long domain")
    if d.count("-") > 3:
        score += 15
        reasons.append("Many hyphens")
    if re.search(r"(g00gle|paypa1|micr0soft|faceb00k)", d):
        score += 40
        reasons.append("Brand impersonation")
    label = "DANGEROUS" if score > 50 else "SUSPICIOUS" if score > 25 else "SAFE"
    return score, reasons, label

def fetch_threats():
    sources = [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt"
    ]
    domains = set()
    for url in sources:
        try:
            print(f"Fetching: {url[:60]}...")
            req = urllib.request.Request(url, headers={"User-Agent": "GlitchSys/0.4"})
            with urllib.request.urlopen(req, timeout=25) as r:
                data = r.read().decode("utf-8", errors="ignore")
            for line in data.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                p = line.split()
                if len(p) >= 2:
                    domains.add(p[1])
        except Exception as e:
            print(f"Failed: {e}")
    domains = sorted(domains)
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(domains, f)
    print(f"Loaded {len(domains)} threats")
    return domains

def load_threats():
    if DB_FILE.exists():
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def block_domains(domains):
    if not domains:
        return False, "No domains"
    try:
        existing = HOSTS_FILE.read_text(errors="ignore") if HOSTS_FILE.exists() else ""
        if MARKER_START in existing:
            before = existing.split(MARKER_START)[0]
            after = existing.split(MARKER_END)[-1]
            existing = before + after
        section = f"\n{MARKER_START}\n"
        for d in domains:
            section += f"0.0.0.0 {d}\n0.0.0.0 www.{d}\n"
        section += f"{MARKER_END}\n"
        HOSTS_FILE.write_text(existing + section, encoding="utf-8")
        log(f"Blocked {len(domains)}")
        return True, f"Blocked {len(domains)} domains"
    except PermissionError:
        return False, "Need root/admin"
    except Exception as e:
        return False, str(e)

def unblock_all():
    try:
        if not HOSTS_FILE.exists():
            return False, "No hosts file"
        c = HOSTS_FILE.read_text(errors="ignore")
        if MARKER_START not in c:
            return False, "Nothing to unblock"
        before = c.split(MARKER_START)[0]
        after = c.split(MARKER_END)[-1]
        HOSTS_FILE.write_text(before + after, encoding="utf-8")
        return True, "Unblocked all"
    except PermissionError:
        return False, "Need root/admin"
    except Exception as e:
        return False, str(e)

def start_vpn(name):
    if name not in VPN_LIST:
        return False, f"VPN {name} not found"
    if IS_ANDROID:
        return False, "On Android: use a VPN app"
    if IS_WINDOWS:
        return False, "On Windows: install OpenVPN GUI"
    try:
        subprocess.Popen(["sudo", "openvpn", "--config", f"{name}.ovpn"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        return True, f"VPN {name} started"
    except FileNotFoundError:
        return False, "openvpn not installed"
    except Exception as e:
        return False, str(e)

def stop_vpn(name):
    if name == ".all":
        try:
            subprocess.run(["sudo", "pkill", "-f", "openvpn"], check=True)
            return True, "All VPNs stopped"
        except Exception:
            return False, "No VPN running"
    try:
        subprocess.run(["sudo", "pkill", "-f", name], check=True)
        return True, f"VPN {name} stopped"
    except Exception:
        return False, f"{name} not running"

def set_dns(name):
    if name not in DNS_CONFIG:
        return False, f"DNS {name} not found"
    ip = DNS_CONFIG[name]
    try:
        if IS_ANDROID:
            return False, "On Android: change DNS from WiFi settings"
        if IS_WINDOWS:
            subprocess.run(["netsh", "interface", "ip", "set", "dns", "Wi-Fi", "static", ip], check=True)
        elif IS_MAC:
            subprocess.run(["networksetup", "-setdnsservers", "Wi-Fi", ip], check=True)
        else:
            subprocess.run(["sudo", "resolvectl", "dns", "default", ip], check=True)
        return True, f"DNS set to {name} ({ip})"
    except Exception as e:
        return False, str(e)

def reset_dns():
    try:
        if IS_ANDROID:
            return False, "On Android: reset from settings"
        if IS_WINDOWS:
            subprocess.run(["netsh", "interface", "ip", "set", "dns", "Wi-Fi", "dhcp"], check=True)
        elif IS_MAC:
            subprocess.run(["networksetup", "-setdnsservers", "Wi-Fi", "Empty"], check=True)
        else:
            subprocess.run(["sudo", "resolvectl", "revert", "default"], check=True)
        return True, "DNS reset"
    except Exception as e:
        return False, str(e)

def show_help():
    print("")
    print("=" * 55)
    print(f"{APP_NAME} {APP_VERSION} - Commands")
    print("=" * 55)
    print("glitch start                Start system")
    print("glitch open vpn             Show VPN list")
    print("glitch open dns             Show DNS list")
    print("glitch start vpn <name>     Start a VPN")
    print("glitch start vpn .all       Start all VPNs")
    print("glitch start dns <name>     Set DNS")
    print("glitch start dns .all       Apply all DNS")
    print("glitch rm vpn <name>        Stop a VPN")
    print("glitch rm vpn .all          Stop all VPNs")
    print("glitch rm dns               Reset DNS")
    print("glitch scan <domain>        Analyze a domain")
    print("glitch block                Block threats")
    print("glitch unblock              Unblock all")
    print("glitch status               System status")
    print("glitch update               Update threat DB")
    print("glitch gui                  Launch GUI")
    print("glitch ls commands          Show commands")
    print("glitch exit                 Exit")
    print("")
    print("Hidden: neofetch, cowsay, matrix, linux, ls")
    print("=" * 55)
    print("")

def egg_neofetch():
    return [
        "        .--.        " + f"{APP_NAME} {APP_VERSION}",
        "       |o_o |       OS: " + ("Android" if IS_ANDROID else "Windows" if IS_WINDOWS else "macOS" if IS_MAC else "Linux"),
        "       |:_/ |       Kernel: " + platform.release(),
        "      //   \\ \\      Arch: " + platform.machine(),
        "     (|     | )     Python: " + platform.python_version(),
        "    /'\\_   _/`\\     User: " + os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "    \\___)=(___/     Shell: Glitch Sys CLI"
    ]

def egg_cowsay(msg):
    top = " " + "_" * (len(msg) + 2)
    mid = f"< {msg} >"
    bot = " " + "-" * (len(msg) + 2)
    return [top, mid, bot,
            "        \\   ^__^",
            "         \\  (oo)\\_______",
            "            (__)\\       )\\/\\",
            "                ||----w |",
            "                ||     ||"]

def egg_matrix():
    import random, string
    return ["".join(random.choice(string.ascii_letters + string.digits) for _ in range(60)) for _ in range(10)]

def egg_linux():
    return ["        .--.", "       |o_o |", "       |:_/ |      Linux Tux",
            "      //   \\ \\ ", "     (|     | )", "    /'\\_   _/`\\", "    \\___)=(___/"]

def egg_ls():
    return ["total 42", "drwxr-xr-x  glitch_sys/", "drwxr-xr-x  core/", "drwxr-xr-x  ui/",
            "drwxr-xr-x  data/", "-rw-r--r--  main.py", "-rw-r--r--  README.md",
            "-rw-r--r--  requirements.txt", "-rw-r--r--  .secret_folder/  (hidden)"]


def run_command(cmd_str):
    parts = cmd_str.strip().split()
    if not parts:
        return []
    main = parts[0].lower()
    out = []

    if main == "help" or (main == "ls" and len(parts) > 1 and parts[1] == "commands"):
        show_help()
        return ["(see above)"]
    elif main == "open" and len(parts) > 1:
        if parts[1] == "vpn":
            out.append("VPN List:")
            for v in VPN_LIST:
                out.append(f"  {v} - Ready")
        elif parts[1] == "dns":
            out.append("DNS List:")
            for n, ip in DNS_CONFIG.items():
                out.append(f"  {n} - {ip}")
    elif main == "start" and len(parts) > 1:
        sub = parts[1].lower()
        if sub == "vpn":
            if len(parts) > 2 and parts[2] == ".all":
                for v in VPN_LIST:
                    ok, msg = start_vpn(v)
                    out.append(msg)
            elif len(parts) > 2:
                ok, msg = start_vpn(parts[2])
                out.append(msg)
        elif sub == "dns":
            if len(parts) > 2 and parts[2] == ".all":
                for n in DNS_CONFIG:
                    ok, msg = set_dns(n)
                    out.append(msg)
            elif len(parts) > 2:
                ok, msg = set_dns(parts[2])
                out.append(msg)
    elif main == "rm" and len(parts) > 1:
        sub = parts[1].lower()
        if sub == "vpn":
            name = parts[2] if len(parts) > 2 else ".all"
            ok, msg = stop_vpn(name)
            out.append(msg)
        elif sub == "dns":
            ok, msg = reset_dns()
            out.append(msg)
    elif main == "scan" and len(parts) > 1:
        score, reasons, label = analyze_domain(parts[1])
        out.append(f"{parts[1]}: {score}/100 [{label}]")
        for r in reasons:
            out.append(f"  - {r}")
    elif main == "block":
        threats = load_threats()
        if not threats:
            threats = fetch_threats()
        ok, msg = block_domains(threats)
        out.append(msg)
    elif main == "unblock":
        ok, msg = unblock_all()
        out.append(msg)
    elif main == "update":
        threats = fetch_threats()
        if threats:
            ok, msg = block_domains(threats)
            out.append(msg)
    elif main == "status":
        os_name = "Android" if IS_ANDROID else "Windows" if IS_WINDOWS else "macOS" if IS_MAC else "Linux"
        out.append(f"OS: {os_name}")
        out.append(f"Arch: {platform.machine()}")
        out.append(f"Root: {'yes' if is_root() else 'no'}")
        out.append(f"Threats: {len(load_threats())}")
        out.append(f"Hosts: {HOSTS_FILE}")
    elif main == "neofetch":
        out.extend(egg_neofetch())
    elif main == "cowsay":
        msg = " ".join(parts[1:]) if len(parts) > 1 else "Glitch Sys"
        out.extend(egg_cowsay(msg))
    elif main == "matrix":
        out.extend(egg_matrix())
    elif main == "linux":
        out.extend(egg_linux())
    elif main == "ls":
        out.extend(egg_ls())
    else:
        out.append(f"Unknown: {main}")
    return out


def cli_boot():
    print("")
    print("=" * 55)
    print(f"{APP_NAME} {APP_VERSION}")
    print(f"By {APP_AUTHOR} - {APP_TEAM}")
    print("=" * 55)
    print("")
    print("Loading threats...")
    threats = load_threats()
    if not threats:
        print("No local threats. Fetching online...")
        threats = fetch_threats()
    if threats:
        ok, msg = block_domains(threats)
        print(msg)
    print("System ready.")
    show_help()


if HAS_KIVY:
    BG_DARK = get_color_from_hex("#0a0a0a")
    BG_LIGHT = get_color_from_hex("#f0f0f0")
    FG_GREEN = get_color_from_hex("#00ff00")
    DG_GREEN = get_color_from_hex("#008800")
    Window.clearcolor = BG_DARK

    LANG = {
        "en": {
            "welcome": "Welcome to Glitch Sys",
            "terminal": "Terminal", "settings": "Settings", "about": "About",
            "team": "Team", "language": "Language", "blocking": "Blocking",
            "theme": "Theme", "back": "Back", "exit": "Exit", "start": "Start",
            "stop": "Stop", "scan": "Scan", "status": "Status",
            "team_text": "Karam Al-Bari\nT STUDIO\n\nAI used for development assistance only.",
            "about_text": "Glitch Sys 0.4\nVPN + DNS + Blocking\nBy Karam Al-Bari\nT STUDIO 2026"
        },
        "ar": {
            "welcome": "هلا بيك بـ Glitch Sys",
            "terminal": "التيرمينال", "settings": "الإعدادات", "about": "حول",
            "team": "الفريق", "language": "اللغة", "blocking": "الحجب",
            "theme": "الثيم", "back": "رجع", "exit": "طلع", "start": "شغل",
            "stop": "وقف", "scan": "افحص", "status": "الحالة",
            "team_text": "كرم الباري\nT STUDIO\n\nتم استخدام الذكاء الاصطناعي للمساعدة فقط.",
            "about_text": "Glitch Sys 0.4\nVPN + DNS + حجب\nمن كرم الباري\nT STUDIO 2026"
        }
    }

    _cfg = load_config()
    _lang = _cfg.get("lang", "en")

    def t(key):
        return LANG.get(_lang, LANG["en"]).get(key, key)

    class MainScreen(Screen):
        def __init__(self, **kw):
            super().__init__(**kw)
            root = BoxLayout(orientation="vertical", padding=20, spacing=10)
            root.add_widget(Label(text=f"{APP_NAME} {APP_VERSION}", font_size=32, color=FG_GREEN))
            grid = GridLayout(cols=2, spacing=10, size_hint_y=None, height=280)
            buttons = [
                ("Terminal", self.go_term), ("Settings", self.go_settings),
                ("Blocking", self.go_block), ("About", self.go_about),
                ("Start Block", self.do_start), ("Stop Block", self.do_stop),
                ("Scan", self.go_term), ("Exit", self.exit_app),
            ]
            for text, cb in buttons:
                b = Button(text=text, background_color=DG_GREEN, color=FG_GREEN)
                b.bind(on_press=cb)
                grid.add_widget(b)
            root.add_widget(grid)
            self.add_widget(root)

        def go_term(self, *a): self.manager.current = "terminal"
        def go_settings(self, *a): self.manager.current = "settings"
        def go_block(self, *a): self.manager.current = "blocking"
        def go_about(self, *a): self.manager.current = "about"
        def do_start(self, *a):
            threats = load_threats() or fetch_threats()
            block_domains(threats)
        def do_stop(self, *a): unblock_all()
        def exit_app(self, *a):
            unblock_all()
            App.get_running_app().stop()

    class TerminalScreen(Screen):
        def __init__(self, **kw):
            super().__init__(**kw)
            root = BoxLayout(orientation="vertical", padding=10, spacing=10)
            top = BoxLayout(size_hint_y=None, height=50)
            back = Button(text=t("back"), size_hint_x=0.3, background_color=DG_GREEN, color=FG_GREEN)
            back.bind(on_press=lambda *a: setattr(self.manager, "current", "main"))
            top.add_widget(back)
            top.add_widget(Label(text="Terminal", color=FG_GREEN))
            root.add_widget(top)
            self.output = Label(text="", color=FG_GREEN, size_hint_y=None, markup=False,
                                halign="left", valign="top")
            self.output.bind(texture_size=lambda *a: setattr(self.output, "height", self.output.texture_size[1]))
            self.output.bind(width=lambda *a: setattr(self.output, "text_size", (self.output.width, None)))
            scroll = ScrollView()
            scroll.add_widget(self.output)
            root.add_widget(scroll)
            self.input = TextInput(multiline=False, background_color=BG_DARK,
                                   foreground_color=FG_GREEN, cursor_color=FG_GREEN,
                                   hint_text="glitch>", size_hint_y=None, height=50)
            self.input.bind(on_text_validate=self.run_cmd)
            root.add_widget(self.input)
            self.add_widget(root)
            self.write("Type 'help'. Try: neofetch, cowsay, matrix, linux")

        def write(self, text):
            self.output.text += f"\n{text}"

        def run_cmd(self, inst):
            cmd = inst.text.strip()
            inst.text = ""
            if not cmd:
                return
            self.write(f"glitch> {cmd}")
            for line in run_command(cmd):
                self.write(line)

    class SettingsScreen(Screen):
        def __init__(self, **kw):
            super().__init__(**kw)
            root = BoxLayout(orientation="vertical", padding=20, spacing=10)
            root.add_widget(Label(text=t("settings"), font_size=28, color=FG_GREEN))
            grid = GridLayout(cols=2, spacing=10, size_hint_y=None, height=160)
            for name, cb in [(t("team"), self.go_team), (t("language"), self.go_lang),
                             (t("blocking"), self.go_block), (t("theme"), self.toggle_theme)]:
                b = Button(text=name, background_color=DG_GREEN, color=FG_GREEN)
                b.bind(on_press=cb)
                grid.add_widget(b)
            root.add_widget(grid)
            back = Button(text=t("back"), background_color=DG_GREEN, color=FG_GREEN,
                          size_hint_y=None, height=50)
            back.bind(on_press=lambda *a: setattr(self.manager, "current", "main"))
            root.add_widget(back)
            self.add_widget(root)

        def go_team(self, *a): self.manager.current = "team"
        def go_lang(self, *a): self.manager.current = "language"
        def go_block(self, *a): self.manager.current = "blocking"
        def toggle_theme(self, *a):
            global _cfg
            _cfg["theme"] = "light" if _cfg.get("theme", "dark") == "dark" else "dark"
            save_config(_cfg)
            Window.clearcolor = BG_LIGHT if _cfg["theme"] == "light" else BG_DARK

    class TeamScreen(Screen):
        def __init__(self, **kw):
            super().__init__(**kw)
            root = BoxLayout(orientation="vertical", padding=20, spacing=10)
            root.add_widget(Label(text=t("team"), font_size=28, color=FG_GREEN))
            root.add_widget(Label(text=t("team_text"), color=FG_GREEN, halign="center"))
            back = Button(text=t("back"), background_color=DG_GREEN, color=FG_GREEN,
                          size_hint_y=None, height=50)
            back.bind(on_press=lambda *a: setattr(self.manager, "current", "settings"))
            root.add_widget(back)
            self.add_widget(root)

    class LanguageScreen(Screen):
        def __init__(self, **kw):
            super().__init__(**kw)
            root = BoxLayout(orientation="vertical", padding=20, spacing=10)
            root.add_widget(Label(text=t("language"), font_size=28, color=FG_GREEN))
            for code, name in [("en", "English"), ("ar", "العربية")]:
                b = Button(text=name, background_color=DG_GREEN, color=FG_GREEN,
                           size_hint_y=None, height=50)
                b.bind(on_press=lambda inst, c=code: self.set_lang(c))
                root.add_widget(b)
            back = Button(text=t("back"), background_color=DG_GREEN, color=FG_GREEN,
                          size_hint_y=None, height=50)
            back.bind(on_press=lambda *a: setattr(self.manager, "current", "settings"))
            root.add_widget(back)
            self.add_widget(root)

        def set_lang(self, code):
            global _lang, _cfg
            _lang = code
            _cfg["lang"] = code
            save_config(_cfg)
            App.get_running_app().rebuild()

    class BlockingScreen(Screen):
        def __init__(self, **kw):
            super().__init__(**kw)
            root = BoxLayout(orientation="vertical", padding=20, spacing=10)
            root.add_widget(Label(text=t("blocking"), font_size=28, color=FG_GREEN))
            root.add_widget(Label(text=f"Threats in DB: {len(load_threats())}", color=FG_GREEN))
            for name, cb in [("Update DB", self.do_update),
                             ("Block All", self.do_block),
                             ("Unblock All", self.do_unblock)]:
                b = Button(text=name, background_color=DG_GREEN, color=FG_GREEN,
                           size_hint_y=None, height=50)
                b.bind(on_press=cb)
                root.add_widget(b)
            back = Button(text=t("back"), background_color=DG_GREEN, color=FG_GREEN,
                          size_hint_y=None, height=50)
            back.bind(on_press=lambda *a: setattr(self.manager, "current", "settings"))
            root.add_widget(back)
            self.add_widget(root)

        def do_update(self, *a): fetch_threats()
        def do_block(self, *a):
            threats = load_threats()
            if threats:
                block_domains(threats)
        def do_unblock(self, *a): unblock_all()

    class AboutScreen(Screen):
        def __init__(self, **kw):
            super().__init__(**kw)
            root = BoxLayout(orientation="vertical", padding=20, spacing=10)
            root.add_widget(Label(text=t("about"), font_size=28, color=FG_GREEN))
            root.add_widget(Label(text=t("about_text"), color=FG_GREEN, halign="center"))
            back = Button(text=t("back"), background_color=DG_GREEN, color=FG_GREEN,
                          size_hint_y=None, height=50)
            back.bind(on_press=lambda *a: setattr(self.manager, "current", "main"))
            root.add_widget(back)
            self.add_widget(root)

    class GlitchGUI(App):
        def build(self):
            self.sm = ScreenManager()
            self._add_all()
            return self.sm

        def _add_all(self):
            for cls, name in [(MainScreen, "main"), (TerminalScreen, "terminal"),
                              (SettingsScreen, "settings"), (TeamScreen, "team"),
                              (LanguageScreen, "language"), (BlockingScreen, "blocking"),
                              (AboutScreen, "about")]:
                self.sm.add_widget(cls(name=name))

        def rebuild(self):
            self.sm.clear_widgets()
            self._add_all()
            self.sm.current = "main"

    def run_gui():
        GlitchGUI().run()
else:
    def run_gui():
        print("Kivy not installed. Run: pip install kivy")


def main():
    if len(sys.argv) < 2:
        if HAS_KIVY:
            run_gui()
        else:
            cli_boot()
        return

    cmd = sys.argv[1].lower()

    if cmd == "gui":
        run_gui()
    elif cmd == "start" and len(sys.argv) == 2:
        cli_boot()
    elif cmd == "exit":
        unblock_all()
        print("Goodbye.")
        sys.exit(0)
    elif cmd in ("help", "--help", "-h"):
        show_help()
    else:
        for line in run_command(" ".join(sys.argv[1:])):
            print(line)


if __name__ == "__main__":
    main()
