import os
import shutil
import sys
import time
from pathlib import Path
import config
from logger import init_logging, get_logger
from analyzer import parse_extension, analyze_permissions, analyze_code, diff_versions, calculate_risk
from quarantine import quarantine_extension, restore_from_quarantine, list_quarantine
from reporter import print_report, print_quarantine_list
from watchdog_monitor import ChromeExtensionWatchdog

log = get_logger(__name__)

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"


def init_workspace():
    dirs = [config.BASE_DIR, config.QUARANTINE_DIR, config.DB_DIR, config.LOG_DIR, config.WORK_DIR]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    init_logging(config.LOG_DIR)


def print_header():
    print()
    print(f"  {BOLD}{CYAN}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"  {BOLD}{CYAN}║   Анализатор браузерных расширений Chrome            ║{RESET}")
    print(f"  {BOLD}{CYAN}║   Blue Team                                          ║{RESET}")
    print(f"  {BOLD}{CYAN}╚══════════════════════════════════════════════════════╝{RESET}")
    print()


def print_menu():
    print(f"  {BOLD}Выберите действие:{RESET}")
    print()
    print(f"  {GREEN}[1]{RESET}  Анализировать расширение")
    print(f"  {GREEN}[2]{RESET}  Запустить мониторинг Chrome (Watchdog)")
    print(f"  {GREEN}[3]{RESET}  Просмотреть карантин")
    print(f"  {GREEN}[4]{RESET}  Восстановить расширение из карантина")
    print(f"  {RED}[0]{RESET}  Выход")
    print()


def ask(prompt):
    try:
        ans = input(f"  {prompt}").strip()
        return ans
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def pause():
    ask("Нажмите Enter для продолжения...")


def menu_analyze():
    print()
    print(f"  {BOLD}Анализ расширения{RESET}")
    print(f"  {GRAY}Укажите путь к CRX-файлу или папке расширения.{RESET}")
    print(f"  {GRAY}Примеры:{RESET}")
    print(f"  {GRAY}  ../test_extensions/safe_extension{RESET}")
    print(f"  {GRAY}  C:\\Downloads\\extension.crx{RESET}")
    print()

    user_input = ask("Путь: ")
    if not user_input:
        print(f"  {YELLOW}Путь не указан.{RESET}")
        pause()
        return

    path = Path(user_input)
    if not path.exists():
        print(f"  {RED}[ОШИБКА]{RESET} Путь не найден: {path}")
        pause()
        return

    run_analysis(path)
    pause()


def run_analysis(path):
    print(f"\n  Анализируется: {Path(path).resolve()}")

    ext = parse_extension(path, config.WORK_DIR)
    if ext is None:
        print(f"  {RED}[ОШИБКА]{RESET} Не удалось разобрать расширение.")
        print("  Файл повреждён или не является расширением Chrome.")
        print("  Файл помещён в карантин для ручной проверки.")
        quarantine_broken(path)
        cleanup()
        return 2

    perms  = analyze_permissions(ext)
    code   = analyze_code(ext)
    diff   = diff_versions(ext, config.DB_DIR)
    is_new = diff.get("is_new", True)
    risk   = calculate_risk(perms, code, diff)

    print_report(ext, risk, diff, is_new)

    level = risk["level"]

    if level == "HIGH":
        q_path = quarantine_extension(ext, risk, config.QUARANTINE_DIR)
        print(f"\n  Расширение помещено в карантин:\n  {q_path}\n")
        ask_quarantine_action(q_path)
        cleanup()
        return 2

    elif level == "MEDIUM":
        ans = ask("Продолжить использование несмотря на риски? [y/N]: ")
        if ans.lower() not in ("y", "yes", "д", "да"):
            q_path = quarantine_extension(ext, risk, config.QUARANTINE_DIR)
            print(f"  Расширение помещено в карантин:\n  {q_path}\n")
        else:
            print("  Расширение допущено к использованию по выбору пользователя.\n")
        cleanup()
        return 1

    else:
        print(f"  {GREEN}✓ Расширение безопасно. Анализ завершён.{RESET}\n")
        cleanup()
        return 0


def menu_watch():
    print()
    print(f"  {BOLD}Автоматический мониторинг Chrome{RESET}")
    print(f"  {GRAY}Утилита будет следить за папкой расширений Chrome{RESET}")
    print(f"  {GRAY}и анализировать каждое новое расширение.{RESET}")
    print()
    print(f"  Папка по умолчанию:")
    print(f"  {CYAN}{config.CHROME_EXTENSIONS_DIR}{RESET}")
    print()

    custom = ask("Другой путь (Enter — использовать путь выше): ")
    if custom:
        watch_dir = Path(custom)
    else:
        watch_dir = config.CHROME_EXTENSIONS_DIR

    def on_change(ext_dir):
        print(f"\n  {YELLOW}[Watchdog]{RESET} Обнаружено изменение: {ext_dir.name}")
        run_analysis(ext_dir)

    dog = ChromeExtensionWatchdog(watch_dir, on_change)
    dog.start()

    print(f"  {GREEN}Мониторинг запущен.{RESET} Для остановки нажмите Ctrl+C.")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        dog.stop()
        print()

    pause()


def menu_quarantine():
    print()
    print(f"  {BOLD}Расширения в карантине{RESET}")
    print()
    items = list_quarantine(config.QUARANTINE_DIR)
    print_quarantine_list(items)
    pause()


def menu_restore():
    print()
    print(f"  {BOLD}Восстановление расширения из карантина{RESET}")
    print()

    items = list_quarantine(config.QUARANTINE_DIR)
    if not items:
        print(f"  {GRAY}Карантин пуст.{RESET}")
        pause()
        return

    print_quarantine_list(items)

    q_dirs = sorted([d for d in config.QUARANTINE_DIR.iterdir() if d.is_dir()])

    if not q_dirs:
        print(f"  {GRAY}Папки карантина не найдены.{RESET}")
        pause()
        return

    choice = ask(f"Введите номер расширения (1–{len(q_dirs)}) или Enter для отмены: ")
    if not choice:
        return

    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(q_dirs):
            raise ValueError
    except ValueError:
        print(f"  {RED}Неверный номер.{RESET}")
        pause()
        return

    q_path = q_dirs[idx]
    restore_dir = config.BASE_DIR / "restored"

    confirm = ask(f"Восстановить '{q_path.name}'? Я осознаю риски [y/N]: ")
    if confirm.lower() not in ("y", "yes", "д", "да"):
        print("  Отменено.")
        pause()
        return

    ok = restore_from_quarantine(q_path, restore_dir)
    if ok:
        print(f"  {GREEN}✓ Восстановлено в: {restore_dir}{RESET}")
    else:
        print(f"  {RED}[ОШИБКА]{RESET} Не удалось восстановить.")

    pause()


def quarantine_broken(path):
    config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    dest = config.QUARANTINE_DIR / f"BROKEN__{Path(path).name}"
    try:
        if Path(path).is_file():
            shutil.copy2(path, dest)
        elif Path(path).is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(path, dest)
    except Exception as e:
        log.error(f"Не удалось поместить в карантин: {e}")


def cleanup():
    tmp = config.WORK_DIR / "unpacked"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)


def ask_quarantine_action(q_path):
    print("  Что делать с расширением?")
    print(f"  {GREEN}[1]{RESET} Оставить в карантине (рекомендуется)")
    print(f"  {YELLOW}[2]{RESET} Восстановить  (я осознаю риски)")
    print(f"  {RED}[3]{RESET} Удалить из карантина")

    choice = ask("Ваш выбор [1/2/3]: ")

    if choice == "2":
        restore_dir = config.BASE_DIR / "restored"
        ok = restore_from_quarantine(q_path, restore_dir)
        if ok:
            print(f"  {GREEN}✓ Восстановлено в: {restore_dir}{RESET}\n")
        else:
            print(f"  {RED}Не удалось восстановить.{RESET}\n")
    elif choice == "3":
        shutil.rmtree(q_path, ignore_errors=True)
        report = q_path.parent / f"{q_path.name}__report.json"
        if report.exists():
            report.unlink()
        print(f"  {RED}Расширение удалено из карантина.{RESET}\n")
    else:
        print("  Расширение оставлено в карантине.\n")


def main():
    init_workspace()

    while True:
        os.system("cls" if sys.platform == "win32" else "clear")
        print_header()
        print_menu()

        choice = ask("Ваш выбор: ")

        if choice == "1":
            menu_analyze()
        elif choice == "2":
            menu_watch()
        elif choice == "3":
            menu_quarantine()
        elif choice == "4":
            menu_restore()
        elif choice == "0":
            print(f"\n  {GRAY}До свидания.{RESET}\n")
            sys.exit(0)
        else:
            print(f"\n  {YELLOW}Неверный выбор.{RESET}")
            time.sleep(1)


if __name__ == "__main__":
    main()
