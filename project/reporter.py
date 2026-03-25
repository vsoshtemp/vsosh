from config import RISK_LEVELS, RESET_COLOR


def print_report(extension_data, risk_result, diff_result, is_new_extension):
    level   = risk_result["level"]
    color   = RISK_LEVELS[level]["color"]
    label   = risk_result["label"]
    score   = risk_result["total_score"]
    action  = RISK_LEVELS[level]["action"]
    findings = risk_result["all_findings"]
    tactics  = risk_result["mitre_tactics"]

    separator()
    print("  ОТЧЁТ ОБ АНАЛИЗЕ РАСШИРЕНИЯ")
    separator()

    print(f"  Название:  {extension_data['id']}")
    print(f"  Версия:    {extension_data['version']}")
    print(f"  Manifest:  v{extension_data['manifest_version']}")

    if not is_new_extension and diff_result.get("version_changed"):
        print(f"  Обновление: v{diff_result['old_version']} → v{diff_result['new_version']}")

    if is_new_extension:
        print("  Статус:    Новое расширение (эталон сохранён)")
    else:
        print("  Статус:    Обновление проанализировано")

    print()
    print(f"  Итоговый рейтинг риска: {color}{label} ({score} баллов){RESET_COLOR}")
    print(f"  Рекомендация: {action}")

    if findings:
        print()
        print("  ── ВЫЯВЛЕННЫЕ ФАКТОРЫ РИСКА ─────────────────────────────")
        for i, f in enumerate(findings, 1):
            if f["score"] >= 25:
                c = "\033[91m"
            elif f["score"] >= 10:
                c = "\033[93m"
            else:
                c = "\033[97m"
            print(f"  {i:2}. {c}[+{f['score']:3}]{RESET_COLOR} {f['type']}")
            print(f"       {f['detail']}")
            if f.get("mitre"):
                print(f"       MITRE: {', '.join(f['mitre'])}")
    else:
        print()
        print("  ✓ Подозрительных факторов не обнаружено.")

    if tactics:
        print()
        print("  ── ЗАТРОНУТЫЕ ТАКТИКИ MITRE ATT&CK ─────────────────────")
        for t in tactics:
            print(f"  • {t}")

    if not is_new_extension and diff_result.get("added_permissions"):
        print()
        print("  ── НОВЫЕ РАЗРЕШЕНИЯ В ОБНОВЛЕНИИ ────────────────────────")
        for p in diff_result["added_permissions"]:
            print(f"  + {p}")

    if not is_new_extension and diff_result.get("removed_permissions"):
        print()
        print("  ── УДАЛЁННЫЕ РАЗРЕШЕНИЯ ─────────────────────────────────")
        for p in diff_result["removed_permissions"]:
            print(f"  - {p}  (снижение привилегий)")

    separator()


def print_quarantine_list(items):
    if not items:
        print("  Карантин пуст.")
        return

    separator()
    print("  РАСШИРЕНИЯ В КАРАНТИНЕ")
    separator()
    for i, item in enumerate(items, 1):
        color = RISK_LEVELS[item.get("risk_level", "HIGH")]["color"]
        print(f"  {i}. {item['extension_id']} v{item['version']}")
        print(f"     Риск: {color}{item['risk_label']}{chr(27)}[0m | Дата: {item['quarantined_at'][:19]}")
    separator()


def separator():
    print("  " + "─" * 60)
