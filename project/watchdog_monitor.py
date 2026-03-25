import os
import time
import threading
from pathlib import Path
from datetime import datetime

from logger import get_logger

log = get_logger(__name__)

POLL_INTERVAL = 5


class ChromeExtensionWatchdog:

    def __init__(self, extensions_dir, on_change):
        self.extensions_dir = Path(extensions_dir)
        self.on_change = on_change
        self.running = False
        self.snapshot = {}
        self.thread = None

    def start(self):
        if not self.extensions_dir.exists():
            print(f"\n  [!] Папка расширений Chrome не найдена:\n      {self.extensions_dir}")
            log.warning(f"Папка не найдена: {self.extensions_dir}")
            return

        self.snapshot = self.take_snapshot()
        self.running = True

        self.thread = threading.Thread(target=self.run_loop, daemon=True, name="Watchdog")
        self.thread.start()

        print(f"\n  [Watchdog] Мониторинг запущен.")
        print(f"  Отслеживается: {self.extensions_dir}")
        print(f"  Интервал: {POLL_INTERVAL} сек. Нажмите Ctrl+C для остановки.\n")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)
        log.info("Watchdog остановлен.")
        print("\n  [Watchdog] Остановлен.")

    def run_loop(self):
        while self.running:
            try:
                self.check_changes()
            except Exception as e:
                log.error(f"Watchdog ошибка: {e}")
            time.sleep(POLL_INTERVAL)

    def check_changes(self):
        current = self.take_snapshot()

        for key in current:
            if key not in self.snapshot:
                ext_id, version = key
                ext_dir = self.extensions_dir / ext_id / version
                ts = datetime.now().strftime("%H:%M:%S")

                print(f"\n  [{ts}] [Watchdog] Новое расширение:")
                print(f"          ID:     {ext_id}")
                print(f"          Версия: {version}")
                print(f"          Путь:   {ext_dir}")
                log.info(f"Watchdog: {ext_id} версия {version}")

                try:
                    self.on_change(ext_dir)
                except Exception as e:
                    log.error(f"Ошибка в callback: {e}")
                    print(f"  [!] Ошибка при анализе: {e}")

        self.snapshot = current

    def take_snapshot(self):
        snapshot = {}
        if not self.extensions_dir.exists():
            return snapshot

        try:
            ext_list = list(self.extensions_dir.iterdir())
        except OSError as e:
            log.warning(f"Нет доступа: {e}")
            return snapshot

        for ext_dir in ext_list:
            if not ext_dir.is_dir():
                continue
            try:
                ver_list = list(ext_dir.iterdir())
            except OSError:
                continue

            for version_dir in ver_list:
                if not version_dir.is_dir():
                    continue
                manifest = version_dir / "manifest.json"
                try:
                    mtime = os.stat(manifest).st_mtime
                    snapshot[(ext_dir.name, version_dir.name)] = mtime
                except OSError:
                    pass

        return snapshot
