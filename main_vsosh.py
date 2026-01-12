import tkinter as tk
from tkinter import scrolledtext
import os
import threading
import time
import math
import shutil
from pathlib import Path

scanning = False
program_dir = Path(__file__).parent
file_to_check = program_dir / "presentation.mode"

SIGNATURES = {
    'MZ': [b'MZ', ['.exe', '.dll', '.sys', '.scr'], "Заголовок Windows PE"],
    'ELF': [b'\x7fELF', ['.elf', '.so', '.bin', '.out'], "Заголовок Linux ELF"],
    'PDF': [b'%PDF', ['.pdf'], "Документ PDF"],
    'ZIP': [b'PK\x03\x04', ['.zip', '.jar', '.docx', '.xlsx'], "Архив ZIP"],
    'PNG': [b'\x89PNG', ['.png'], "Изображение PNG"],
    'JPEG': [b'\xff\xd8\xff', ['.jpg', '.jpeg'], "Изображение JPEG"],
    'GIF': [b'GIF89a', ['.gif'], "Изображение GIF"],
}

DANGER_PATTERNS = {
    'CreateProcess': [b'CreateProcess', "Создание процесса", "high"],
    'ShellExecute': [b'ShellExecute', "Запуск шелла", "high"],
    'WinExec': [b'WinExec', "Выполнение Windows", "high"],
    'system': [b'system', "Системная команда", "medium"],
    'popen': [b'popen', "Открытие канала", "medium"],
    'cmd.exe': [b'cmd.exe', "Командная строка", "high"],
    'powershell': [b'powershell', "PowerShell", "high"],
    'UPX': [b'UPX', "Упаковщик EXE", "suspicious"],
    'ASPack': [b'ASPack', "Упаковщик EXE", "suspicious"],
}

def entropy_calc(data):
    if not data:
        return 0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    entropy_val = 0
    total_len = len(data)
    for count in counts.values():
        p_val = count / total_len
        if p_val > 0:
            entropy_val -= p_val * math.log2(p_val)
    return entropy_val

def get_ext(fname):
    _, ext_val = os.path.splitext(fname)
    return ext_val.lower()

def sig_check(data_bytes, fname):
    results_list = []
    susp_list = []
    fext = get_ext(fname)
    for sig_name, (sig_bytes, normal_exts, desc_text) in SIGNATURES.items():
        if sig_bytes in data_bytes:
            if fext in normal_exts:
                results_list.append(f"[OK] {sig_name}: Норма для {fext}")
            else:
                susp_list.append(f"[!] {sig_name} в {fext}: {desc_text}")
    danger_list = []
    for pat_name, (pat_bytes, desc_text, level_text) in DANGER_PATTERNS.items():
        if pat_bytes in data_bytes:
            danger_list.append(f"[{level_text.upper()}] {pat_name}: {desc_text}")
    return results_list, susp_list, danger_list

def move_from_downloads():
    dl_path = Path("C:/Users")
    user_list = [d for d in os.listdir(dl_path) 
                if os.path.isdir(dl_path / d) and 
                d not in ["Public", "Default", "All Users"]]
    if user_list:
        downloads_folder = dl_path / user_list[0] / "Downloads"
        source_file = downloads_folder / "presentation.mode"
        if source_file.exists():
            try:
                shutil.move(str(source_file), str(file_to_check))
                log_text("Файл перемещен из загрузок", "RawScanner")
                return True
            except Exception as move_err:
                log_text(f"Ошибка перемещения: {move_err}", "RawScanner")
                return False
    log_text("Файл не найден в загрузках", "RawScanner")
    return False

def file_check():
    global scanning
    if scanning:
        return
    scanning = True
    download_btn.config(state=tk.DISABLED, text="Проверка...")
    try:
        log_text("Запуск сканирования", "RawScanner")
        time.sleep(1)
        if not file_to_check.exists():
            log_text("Файл не найден в папке программы", "RawScanner")
            log_text("Поиск в папке загрузок...", "RawScanner")
            if not move_from_downloads():
                log_text("Файл не найден", "RawScanner")
                log_text("Итог: файл безопасен (не найден)", "RawScanner")
                download_btn.config(state=tk.NORMAL, text="Скачать")
                scanning = False
                return
        filename_val = file_to_check.name
        file_ext_val = get_ext(filename_val)
        file_size_val = file_to_check.stat().st_size
        log_text(f"Файл: {filename_val}", "RawScanner")
        log_text(f"Расширение: {file_ext_val}", "RawScanner")
        log_text(f"Размер: {file_size_val} байт", "RawScanner")
        with open(file_to_check, 'rb') as file_obj:
            file_data = file_obj.read(min(32768, file_size_val))
        entropy_val = entropy_calc(file_data)
        log_text(f"Энтропия: {entropy_val:.2f}", "RawScanner")
        log_text("Raw-bytes проверка паттернов", "RawScanner")
        norm_results, susp_results, danger_results = sig_check(file_data, filename_val)
        for msg_line in norm_results:
            log_text(msg_line, "RawScanner")
        for msg_line in susp_results:
            log_text(msg_line, "RawScanner")
        for msg_line in danger_results:
            log_text(msg_line, "RawScanner")
        time.sleep(0.5)
        final_result = "Безопасный"
        if danger_results:
            log_text("Найдены опасные паттерны!", "RawScanner")
            final_result = "Подозрительный, загрузка отменена"
        elif susp_results:
            log_text("Найдены подозрительные сигнатуры!", "RawScanner")
            final_result = "Подозрительный, загрузка отменена"
        elif entropy_val > 7.3:
            log_text("Высокая энтропия", "RawScanner")
            final_result = "Подозрительный, загрузка отменена"
        elif entropy_val < 6.0:
            log_text("Низкая энтропия", "RawScanner")
            if not susp_results and not danger_results:
                final_result = "Безопасный"
        time.sleep(0.5)
        if final_result == "Безопасный":
            log_text("Файл безопасен", "RawScanner")
            log_text("Загрузка разрешена", "RawScanner")
        else:
            log_text("Файл подозрительный", "RawScanner")
            log_text("Загрузка заблокирована", "RawScanner")
            try:
                file_to_check.unlink()
                log_text("Файл удален", "RawScanner")
            except:
                pass
    except Exception as err:
        log_text(f"Ошибка: {str(err)}", "RawScanner")
    finally:
        scanning = False
        download_btn.config(state=tk.NORMAL, text="Скачать")

def log_text(msg_text, sender_text="Чат"):
    chat_text.insert(tk.END, f"{sender_text}: {msg_text}\n")
    chat_text.see(tk.END)

def check_start():
    if scanning:
        return
    thread_obj = threading.Thread(target=file_check)
    thread_obj.daemon = True
    thread_obj.start()

def send_msg():
    msg_val = input_field.get()
    if msg_val and msg_val != "Введите текст":
        log_text(msg_val, "Вы")
        input_field.delete(0, tk.END)

def clear_placeholder(event):
    if input_field.get() == "Введите текст":
        input_field.delete(0, tk.END)

root = tk.Tk()
root.title("CommonMessenger")
root.geometry("500x500")
root.configure(bg='black')

chat_frame = tk.Frame(root, bg='black')
chat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

chat_text = scrolledtext.ScrolledText(chat_frame, height=20, bg='#0a0a0a', fg='#00ff00', 
                                     font=('Courier New', 10), wrap=tk.WORD)
chat_text.pack(fill=tk.BOTH, expand=True)

chat_text.insert(tk.END, "Василий_Алибабаевич: Смотри, новый мод на Майнкрафт\n")
chat_text.insert(tk.END, f"  Прикреплен файл: presentation.mode\n\n")

file_frame = tk.Frame(chat_frame, bg='#0a0a0a')
chat_text.window_create(tk.END, window=file_frame)

file_label = tk.Label(file_frame, text=f"presentation.mode", 
                      fg='#00ff00', bg='#0a0a0a', font=('Courier New', 10), cursor="hand2")
file_label.pack(side=tk.LEFT)

download_btn = tk.Button(file_frame, text="Скачать", 
                         command=check_start, padx=10,
                         bg='#003300', fg='#00ff00', font=('Courier New', 9),
                         relief=tk.RAISED)
download_btn.pack(side=tk.LEFT, padx=10)

chat_text.insert(tk.END, "\n")

bottom_frame = tk.Frame(root, bg='black')
bottom_frame.pack(fill=tk.X, padx=10, pady=5)

input_field = tk.Entry(bottom_frame, width=30, bg='#1a1a1a', fg='#00ff00', 
                       font=('Courier New', 10), relief=tk.SUNKEN, insertbackground='#00ff00')
input_field.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
input_field.insert(0, "Введите текст")
input_field.bind("<FocusIn>", clear_placeholder)
input_field.bind("<Return>", lambda e: send_msg())

send_btn = tk.Button(bottom_frame, text=">>", command=send_msg,
                     bg='#003300', fg='#00ff00', font=('Courier New', 10),
                     relief=tk.RAISED, width=3)
send_btn.pack(side=tk.LEFT)

if __name__ == "__main__":
    program_dir.mkdir(exist_ok=True)
    root.mainloop()
