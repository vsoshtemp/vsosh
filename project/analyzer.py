import json
import re
import zipfile
import hashlib
import shutil
from pathlib import Path

from config import (
    CRITICAL_PERMISSIONS, HIGH_PERMISSIONS, MEDIUM_PERMISSIONS,
    DANGEROUS_CODE_PATTERNS, RISK_WEIGHTS, RISK_LEVELS, MITRE_MAPPING,
)
from logger import get_logger

log = get_logger(__name__)


def parse_extension(path, work_dir):
    folder = work_dir / "unpacked"
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)

    path = Path(path)

    if path.is_file() and path.suffix.lower() == ".crx":
        ok = extract_crx(path, folder)
        if not ok:
            log.error(f"Не удалось распаковать CRX: {path}")
            return None
    elif path.is_dir():
        shutil.copytree(path, folder, dirs_exist_ok=True)
    else:
        log.error(f"Непонятный тип файла: {path}")
        return None

    manifest_path = folder / "manifest.json"
    if not manifest_path.exists():
        log.error("manifest.json не найден")
        return None

    try:
        f = open(manifest_path, "r", encoding="utf-8", errors="replace")
        manifest = json.load(f)
        f.close()
    except json.JSONDecodeError as e:
        log.error(f"Ошибка чтения manifest.json: {e}")
        return None

    js_files = list(folder.rglob("*.js"))

    perms = manifest.get("permissions", [])
    perms = [str(p) for p in perms if isinstance(p, (str, dict))]

    host_perms = list(manifest.get("host_permissions", []))
    for p in manifest.get("permissions", []):
        if isinstance(p, str) and ("*" in p or p.startswith("http")):
            if p not in host_perms:
                host_perms.append(p)

    name = manifest.get("name", path.stem)
    version = manifest.get("version", "0.0")
    mv = manifest.get("manifest_version", 2)

    result = {
        "id":               name,
        "version":          version,
        "manifest_version": mv,
        "permissions":      perms,
        "host_permissions": host_perms,
        "js_files":         js_files,
        "extract_dir":      folder,
        "manifest":         manifest,
    }

    log.info(f"Разобрано: {name} v{version}")
    return result


def extract_crx(crx_path, dest):
    try:
        f = open(crx_path, "rb")
        magic = f.read(4)

        if magic == b"Cr24":
            ver = int.from_bytes(f.read(4), "little")
            if ver == 3:
                hlen = int.from_bytes(f.read(4), "little")
                f.read(hlen)
            elif ver == 2:
                key_len = int.from_bytes(f.read(4), "little")
                sig_len = int.from_bytes(f.read(4), "little")
                f.read(key_len + sig_len)
        else:
            f.seek(0)

        zip_data = f.read()
        f.close()

        tmp = dest.parent / "_temp.zip"
        zf = open(tmp, "wb")
        zf.write(zip_data)
        zf.close()

        z = zipfile.ZipFile(tmp, "r")
        z.extractall(dest)
        z.close()
        tmp.unlink()
        return True

    except Exception as e:
        log.error(f"Ошибка распаковки: {e}")
        return False


def analyze_permissions(ext):
    found = []
    total = 0

    for p in ext["permissions"]:
        if p in CRITICAL_PERMISSIONS:
            found.append({
                "type":   "КРИТИЧНОЕ разрешение",
                "detail": p,
                "score":  RISK_WEIGHTS["critical_permission"],
                "mitre":  MITRE_MAPPING.get(p, []),
            })
            total += RISK_WEIGHTS["critical_permission"]

        elif p in HIGH_PERMISSIONS:
            found.append({
                "type":   "ВЫСОКОЕ разрешение",
                "detail": p,
                "score":  RISK_WEIGHTS["high_permission"],
                "mitre":  MITRE_MAPPING.get(p, []),
            })
            total += RISK_WEIGHTS["high_permission"]

        elif p in MEDIUM_PERMISSIONS:
            found.append({
                "type":   "СРЕДНЕЕ разрешение",
                "detail": p,
                "score":  RISK_WEIGHTS["medium_permission"],
                "mitre":  [],
            })
            total += RISK_WEIGHTS["medium_permission"]

    bad_hosts = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*"]
    for hp in ext["host_permissions"]:
        if hp in bad_hosts:
            found.append({
                "type":   "ШИРОКИЙ доступ к хостам",
                "detail": hp,
                "score":  RISK_WEIGHTS["all_urls"],
                "mitre":  ["TA0009 Collection", "TA0006 Credential Access"],
            })
            total += RISK_WEIGHTS["all_urls"]

    return {"findings": found, "score": total}


def analyze_code(ext):
    found = []
    total = 0

    for js_file in ext["js_files"]:
        try:
            text = js_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = js_file.relative_to(ext["extract_dir"])

        for pat in DANGEROUS_CODE_PATTERNS:
            matches = re.findall(pat["regex"], text)
            if len(matches) > 0:
                examples = list(dict.fromkeys(matches))[:3]
                found.append({
                    "type":   pat["name"],
                    "detail": f"Файл: {rel}  |  примеры: {examples}",
                    "score":  pat["score"],
                    "mitre":  pat["mitre"],
                })
                total += pat["score"]

    return {"findings": found, "score": total}


def diff_versions(ext, db_path):
    name = re.sub(r"[^\w\-]", "_", ext["id"])[:80]
    saved_file = db_path / f"{name}.json"

    hashes = {}
    for js_file in ext["js_files"]:
        try:
            rel = str(js_file.relative_to(ext["extract_dir"]))
            hashes[rel] = hashlib.sha256(js_file.read_bytes()).hexdigest()
        except OSError:
            pass

    try:
        data = (ext["extract_dir"] / "manifest.json").read_bytes()
        hashes["manifest.json"] = hashlib.sha256(data).hexdigest()
    except OSError:
        pass

    current = {
        "id":               ext["id"],
        "version":          ext["version"],
        "permissions":      ext["permissions"],
        "host_permissions": ext["host_permissions"],
        "file_hashes":      hashes,
    }

    if not saved_file.exists():
        db_path.mkdir(parents=True, exist_ok=True)
        f = open(saved_file, "w", encoding="utf-8")
        json.dump(current, f, ensure_ascii=False, indent=2)
        f.close()
        log.info(f"Первый запуск, сохранили эталон: {ext['id']}")
        return {"findings": [], "score": 0, "is_new": True}

    f = open(saved_file, "r", encoding="utf-8")
    old = json.load(f)
    f.close()

    found = []
    total = 0
    old_ver = old.get("version", "?")
    new_ver = current["version"]

    old_perms = set(old.get("permissions", []))
    new_perms = set(current["permissions"])
    added   = new_perms - old_perms
    removed = old_perms - new_perms

    for p in added:
        if p in CRITICAL_PERMISSIONS:
            w = RISK_WEIGHTS["critical_permission"]
        elif p in HIGH_PERMISSIONS:
            w = RISK_WEIGHTS["high_permission"]
        else:
            w = RISK_WEIGHTS["medium_permission"]

        found.append({
            "type":   "ДОБАВЛЕНО разрешение (обновление)",
            "detail": f"'{p}' не было в v{old_ver}",
            "score":  w,
            "mitre":  MITRE_MAPPING.get(p, ["TA0001 Initial Access"]),
        })
        total += w

    old_hashes = old.get("file_hashes", {})
    for fname in hashes:
        if fname not in old_hashes:
            found.append({
                "type":   "НОВЫЙ файл в обновлении",
                "detail": f"Не было в v{old_ver}: {fname}",
                "score":  RISK_WEIGHTS["new_file"],
                "mitre":  ["TA0002 Execution"],
            })
            total += RISK_WEIGHTS["new_file"]
        elif old_hashes[fname] != hashes[fname]:
            found.append({
                "type":   "ИЗМЕНЁН существующий файл",
                "detail": f"Отличается от v{old_ver}: {fname}",
                "score":  RISK_WEIGHTS["modified_file"],
                "mitre":  ["TA0002 Execution", "TA0003 Persistence"],
            })
            total += RISK_WEIGHTS["modified_file"]

    f = open(saved_file, "w", encoding="utf-8")
    json.dump(current, f, ensure_ascii=False, indent=2)
    f.close()

    return {
        "findings":            found,
        "score":               total,
        "is_new":              False,
        "version_changed":     old_ver != new_ver,
        "old_version":         old_ver,
        "new_version":         new_ver,
        "added_permissions":   list(added),
        "removed_permissions": list(removed),
    }


def calculate_risk(perms, code, diff):
    total = perms["score"] + code["score"] + diff["score"]
    all_found = perms["findings"] + code["findings"] + diff["findings"]

    if total >= 60:
        level = "HIGH"
    elif total >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    tactics = []
    for item in all_found:
        for t in item.get("mitre", []):
            if t not in tactics:
                tactics.append(t)
    tactics.sort()

    return {
        "total_score":   total,
        "level":         level,
        "label":         RISK_LEVELS[level]["label"],
        "color":         RISK_LEVELS[level]["color"],
        "all_findings":  all_found,
        "mitre_tactics": tactics,
    }
