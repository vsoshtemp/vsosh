import os
import platform
from pathlib import Path

CRITICAL_PERMISSIONS = {
    "cookies", "webRequest", "webRequestBlocking",
    "declarativeNetRequest", "declarativeNetRequestWithHostAccess",
    "scripting", "debugger", "nativeMessaging", "proxy",
}

HIGH_PERMISSIONS = {
    "tabs", "history", "bookmarks", "topSites",
    "browsingData", "pageCapture", "clipboardRead", "clipboardWrite",
}

MEDIUM_PERMISSIONS = {
    "storage", "notifications", "contextMenus",
    "alarms", "identity", "management",
}

DANGEROUS_CODE_PATTERNS = [
    {"name": "Обфускация: eval()",             "regex": r"\beval\s*\(",                                                    "score": 20, "mitre": ["TA0005 Defense Evasion"]},
    {"name": "Обфускация: atob()",             "regex": r"\batob\s*\(",                                                    "score": 15, "mitre": ["TA0005 Defense Evasion"]},
    {"name": "Обфускация: new Function()",     "regex": r"\bnew\s+Function\s*\(",                                          "score": 20, "mitre": ["TA0005 Defense Evasion"]},
    {"name": "Обфускация: String.fromCharCode","regex": r"String\.fromCharCode\s*\(",                                      "score": 10, "mitre": ["TA0005 Defense Evasion"]},
    {"name": "Кража куки: document.cookie",    "regex": r"document\.cookie",                                               "score": 25, "mitre": ["TA0006 Credential Access"]},
    {"name": "Chrome API: cookies",            "regex": r"chrome\.cookies\.(get|getAll|set|remove)",                       "score": 25, "mitre": ["TA0006 Credential Access"]},
    {"name": "Chrome API: webRequest",         "regex": r"chrome\.webRequest\.(onBeforeRequest|onBeforeSendHeaders)",      "score": 30, "mitre": ["TA0009 Collection"]},
    {"name": "Chrome API: executeScript",      "regex": r"chrome\.scripting\.executeScript|chrome\.tabs\.executeScript",   "score": 30, "mitre": ["TA0002 Execution"]},
    {"name": "Загрузка внешнего скрипта",      "regex": r"createElement\s*\(\s*['\"]script['\"]",                          "score": 20, "mitre": ["TA0002 Execution"]},
    {"name": "Обращение к внешнему URL",       "regex": r"(?:fetch|new\s+XMLHttpRequest|new\s+WebSocket)\s*\(\s*['\"]https?://", "score": 20, "mitre": ["TA0011 Command and Control"]},
    {"name": "Кража паролей из форм",          "regex": r"input\[type=['\"]?password['\"]?\]",                             "score": 25, "mitre": ["TA0006 Credential Access"]},
    {"name": "Доступ к истории браузера",      "regex": r"chrome\.history\.(search|getVisits)",                            "score": 15, "mitre": ["TA0009 Collection"]},
    {"name": "Снятие скриншота вкладки",       "regex": r"chrome\.tabs\.captureVisibleTab",                                "score": 20, "mitre": ["TA0009 Collection"]},
]

RISK_WEIGHTS = {
    "critical_permission": 30,
    "high_permission":     15,
    "medium_permission":   5,
    "all_urls":            25,
    "new_file":            10,
    "modified_file":       8,
}

RISK_LEVELS = {
    "LOW":    {"threshold": 0,  "label": "НИЗКИЙ",   "color": "\033[92m", "action": "Расширение допускается к использованию."},
    "MEDIUM": {"threshold": 30, "label": "СРЕДНИЙ",  "color": "\033[93m", "action": "Рекомендуется проверить расширение перед использованием."},
    "HIGH":   {"threshold": 60, "label": "ВЫСОКИЙ",  "color": "\033[91m", "action": "Расширение помещено в карантин. Требуется ручная проверка."},
}

RESET_COLOR = "\033[0m"

MITRE_MAPPING = {
    "cookies":       ["TA0006 Credential Access (T1539)"],
    "webRequest":    ["TA0009 Collection (T1185)", "TA0011 Command and Control (T1071.001)"],
    "scripting":     ["TA0002 Execution (T1059.007)"],
    "debugger":      ["TA0005 Defense Evasion (T1622)"],
    "nativeMessaging": ["TA0011 Command and Control (T1071)"],
    "proxy":         ["TA0011 Command and Control (T1090)"],
    "tabs":          ["TA0009 Collection (T1185)"],
    "history":       ["TA0009 Collection (T1217)"],
    "clipboardRead": ["TA0009 Collection (T1115)"],
    "pageCapture":   ["TA0009 Collection (T1113)"],
    "<all_urls>":    ["TA0009 Collection", "TA0006 Credential Access"],
    "*://*/*":       ["TA0009 Collection", "TA0006 Credential Access"],
}

BASE_DIR       = Path.home() / ".extension_analyzer"
QUARANTINE_DIR = BASE_DIR / "quarantine"
DB_DIR         = BASE_DIR / "db"
LOG_DIR        = BASE_DIR / "logs"
WORK_DIR       = BASE_DIR / "work"

def _is_wsl():
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except:
        return False

def _get_windows_username():
    # Пробуем найти реального пользователя Windows через /mnt/c/Users
    users_dir = Path("/mnt/c/Users")
    if not users_dir.exists():
        return None
    for entry in users_dir.iterdir():
        if entry.is_dir() and entry.name not in ("Public", "Default", "All Users", "Default User"):
            return entry.name
    return None

if platform.system() == "Windows":
    local_app = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    CHROME_EXTENSIONS_DIR = local_app / "Google" / "Chrome" / "User Data" / "Default" / "Extensions"
elif platform.system() == "Darwin":
    CHROME_EXTENSIONS_DIR = Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Extensions"
elif _is_wsl():
    win_user = _get_windows_username()
    if win_user:
        CHROME_EXTENSIONS_DIR = Path(f"/mnt/c/Users/{win_user}/AppData/Local/Google/Chrome/User Data/Default/Extensions")
    else:
        CHROME_EXTENSIONS_DIR = Path("/mnt/c/Users") / "User" / "AppData/Local/Google/Chrome/User Data/Default/Extensions"
else:
    CHROME_EXTENSIONS_DIR = Path.home() / ".config" / "google-chrome" / "Default" / "Extensions"
