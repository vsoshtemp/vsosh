import json
import re
import shutil
from datetime import datetime
from pathlib import Path

from logger import get_logger

log = get_logger(__name__)


def quarantine_extension(extension_data, risk_result, quarantine_dir):
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^\w\-]", "_", extension_data["id"])[:60]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = quarantine_dir / f"{safe_name}__{timestamp}"

    shutil.copytree(extension_data["extract_dir"], dest)

    report = {
        "quarantined_at": datetime.now().isoformat(),
        "extension_id":   extension_data["id"],
        "version":        extension_data["version"],
        "risk_level":     risk_result["level"],
        "risk_label":     risk_result["label"],
        "total_score":    risk_result["total_score"],
        "mitre_tactics":  risk_result["mitre_tactics"],
        "findings": [
            {
                "type":   f["type"],
                "detail": f["detail"],
                "score":  f["score"],
                "mitre":  f.get("mitre", []),
            }
            for f in risk_result["all_findings"]
        ],
    }

    report_path = quarantine_dir / f"{safe_name}__{timestamp}__report.json"
    with open(report_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, ensure_ascii=False, indent=2)

    log.warning(f"Расширение '{extension_data['id']}' помещено в карантин: {dest}")
    return dest


def restore_from_quarantine(quarantine_path, restore_dir):
    if not quarantine_path.exists():
        log.error(f"Путь не найден: {quarantine_path}")
        return False

    restore_dir.mkdir(parents=True, exist_ok=True)
    dest = restore_dir / quarantine_path.name
    shutil.copytree(quarantine_path, dest)
    log.info(f"Восстановлено в: {dest}")
    return True


def list_quarantine(quarantine_dir):
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    items = []

    for report_file in sorted(quarantine_dir.glob("*__report.json")):
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                items.append(json.load(f))
        except Exception as e:
            log.warning(f"Не удалось прочитать {report_file}: {e}")

    return items
