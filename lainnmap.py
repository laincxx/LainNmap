import subprocess
import sys
import re
import os
import shutil

def check_nmap():
    if shutil.which("nmap") is None:
        print("Утилита nmap не найдена.")
        sys.exit(1)

def is_valid_target(target):
    patterns = [
        r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$",
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})?$",
    ]
    return any(re.fullmatch(p, target) for p in patterns)

def main():
    check_nmap()
    print("===LainNmap===")

    target = input("\nВведите цель (IP, домен или подсеть, например 192.168.1.1): ").strip()
    if not target:
        print("Цель не может быть пустой.")
        return
    if target.startswith("-") or " " in target:
        print("Цель не должна начинаться с '-' и содержать пробелы.")
        return
    if not is_valid_target(target):
        print("Цель не похожа на IP, домен или подсеть.")
        return

    scan_types = {
        "1": ("Быстрое сканирование (топ-100 портов)", ["-F"]),
        "2": ("Стандартное сканирование с определением версий сервисов", ["-sV"]),
        "3": ("Агрессивное сканирование (ОС, версии, скрипты, трассировка)", ["-A"]),
        "4": ("Сканирование всех 65535 портов (медленно)", ["-p-"]),
        "5": ("Тихое SYN-сканирование", ["-sS"]),
        "6": ("Поиск уязвимостей базовыми скриптами", ["--script", "vuln"]),
        "7": ("Проверка доступности хостов в сети (Ping Scan)", ["-sn"]),
    }

    print("\nВыберите тип сканирования:")
    for key, (desc, _) in scan_types.items():
        print(f"  [{key}] {desc}")

    choice = input("\nВаш выбор (1-7): ").strip()
    if choice not in scan_types:
        print("Неверный выбор.")
        return

    desc, flags = scan_types[choice]

    if choice == "5" and os.name == "posix" and os.geteuid() != 0:
        print("SYN-сканирование требует прав root. Запустите скрипт через sudo.")
        return

    filename = input("\nВведите имя файла для отчёта (без расширения): ").strip()
    if not filename:
        filename = "nmap_report"
    filename = re.sub(r"[^\w\-.]", "_", os.path.basename(filename))
    if not filename.endswith(".txt"):
        filename += ".txt"

    command = ["nmap"] + flags + ["-oN", filename, target]

    print(f"\nВыбрано: {desc}")
    print(f"Выполняется команда: {' '.join(command)}")
    print("Сканирование запущено...\n")

    try:
        result = subprocess.run(command)
        if result.returncode == 0:
            print(f"\nРезультаты сохранены в файл: {filename}")
        else:
            print(f"\nNmap завершился с кодом {result.returncode}. "
                  f"Текст ошибки смотрите выше (nmap пишет её в stdout).")
    except KeyboardInterrupt:
        print("\nСканирование прервано пользователем.")

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nВыход.")

