import tkinter as tk
from tkinter import scrolledtext
import os
import threading
import time
import math

FILE_TO_CHECK = r"C:\Users\batya228_2017\AppData\Local\Programs\Python\Python314\projects\presentation.mode"

# Сигнатуры и их нормальные расширения
SIGNATURES = {
    'MZ': [b'MZ', ['.exe', '.dll', '.sys', '.scr'], "Заголовок Windows PE"],
    'ELF': [b'\x7fELF', ['.elf', '.so', '.bin', '.out'], "Заголовок Linux ELF"],
    'PDF': [b'%PDF', ['.pdf'], "Документ PDF"],
    'ZIP': [b'PK\x03\x04', ['.zip', '.jar', '.docx', '.xlsx'], "Архив ZIP"],
    'PNG': [b'\x89PNG', ['.png'], "Изображение PNG"],
    'JPEG': [b'\xff\xd8\xff', ['.jpg', '.jpeg'], "Изображение JPEG"],
    'GIF': [b'GIF89a', ['.gif'], "Изображение GIF"],
}

# Опасные паттерны для любых файлов
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

scanning = False

def log(message, sender="CH4T"):
    chat_text.insert(tk.END, f"{sender}: {message}\n")
    chat_text.see(tk.END)

def calculate_entropy(data):
    if not data or len(data) == 0:
        return 0
    
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    
    entropy = 0
    total = len(data)
    
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

def get_file_extension(filename):
    """Получить расширение файла"""
    _, ext = os.path.splitext(filename)
    return ext.lower()

def check_signatures(data, filename):
    """Проверить сигнатуры файла"""
    results = []
    suspicious = []
    file_ext = get_file_extension(filename)
    
    # 1. Проверка стандартных сигнатур
    for name, (signature, normal_exts, desc) in SIGNATURES.items():
        if signature in data:
            if file_ext in normal_exts:
                results.append(f"[OK] {name}: Норма для {file_ext}")
            else:
                suspicious.append(f"[!] {name} в {file_ext}: {desc}")
    
    # 2. Проверка опасных паттернов
    danger_found = []
    for name, (pattern, desc, level) in DANGER_PATTERNS.items():
        if pattern in data:
            danger_found.append(f"[{level.upper()}] {name}: {desc}")
    
    return results, suspicious, danger_found

def check_file():
    global scanning
    
    if scanning:
        return
    
    scanning = True
    download_btn.config(state=tk.DISABLED, text="Проверка...")
    
    try:
        log("Запуск сканирования", "RawScanner")
        time.sleep(1)
        
        if not os.path.exists(FILE_TO_CHECK):
            log("Файл не найден", "RawScanner")
            log("Итог: файл безопасен (не найден)", "RawScanner")
            download_btn.config(state=tk.NORMAL, text="Скачать")
            scanning = False
            return
        
        filename = os.path.basename(FILE_TO_CHECK)
        file_ext = get_file_extension(filename)
        file_size = os.path.getsize(FILE_TO_CHECK)
        
        log(f"Файл: {filename}", "RawScanner")
        log(f"Расширение: {file_ext}", "RawScanner")
        log(f"Размер: {file_size} байт", "RawScanner")
        
        # Читаем файл
        with open(FILE_TO_CHECK, 'rb') as f:
            data = f.read(min(32768, file_size))
        
        # 1. Анализ энтропии
        entropy = calculate_entropy(data)
        log(f"Энтропия: {entropy:.2f}", "RawScanner")
        # 2. Проверка сигнатур
        log("Raw-bytes проверка паттернов", "RawScanner")
        normal, suspicious, danger = check_signatures(data, filename)
        
        for msg in normal:
            log(msg, "RawScanner")
        
        for msg in suspicious:
            log(msg, "RawScanner")
        
        for msg in danger:
            log(msg, "RawScanner")
        
        # 3. Анализ результатов
        time.sleep(0.5)
        
        final_verdict = "Безопасный"
        
        # Если нашли опасные паттерны
        if danger:
            log("Найдены опасные паттерны!", "RawScanner")
            final_verdict = "Подозрительный, загрузка отменена"
        
        # Если нашли подозрительные сигнатуры
        elif suspicious:
            log("Найдены подозрительные сигнатуры!", "RawScanner")
            final_verdict = "Подозрительный, загрузка отменена"
        
        # Анализ энтропии
        elif entropy > 7.3:
            log("Высокая энтропия", "RawScanner")
            final_verdict = "Подозрительный, загрузка отменена"
        elif entropy < 6.0:
            log("Низкая энтропия", "RawScanner")
            if not suspicious and not danger:
                final_verdict = "Безопасный"
        
        # 4. Финальный вердикт
        time.sleep(0.5)
        
        if final_verdict == "Безопасный":
            log("Файл безопасен", "RawScanner")
        else:
            log("Файл подозрительный", "RawScanner")
        
    except Exception as e:
        log(f"Ошибка: {str(e)}", "RawScanner")
    
    finally:
        scanning = False
        download_btn.config(state=tk.NORMAL, text="Скачать")

def start_check():
    if scanning:
        return
    
    thread = threading.Thread(target=check_file)
    thread.daemon = True
    thread.start()

def fake_send():
    msg = input_field.get()
    if msg and msg != "Введите текст":
        log(msg, "Вы")
        input_field.delete(0, tk.END)

def clear_placeholder(event):
    if input_field.get() == "Введите текст":
        input_field.delete(0, tk.END)

# Создаем окно
root = tk.Tk()
root.title("CommonMessenger")
root.geometry("500x500")
root.configure(bg='black')

# Чат
chat_frame = tk.Frame(root, bg='black')
chat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

chat_text = scrolledtext.ScrolledText(chat_frame, height=20, bg='#0a0a0a', fg='#00ff00', font=('Impact', 10))
chat_text.pack(fill=tk.BOTH, expand=True)

# Фейковые сообщения
chat_text.insert(tk.END, "Василий_Алибабаевич: Смотри, новый мод на Майнкрафт\n")

# Фрейм для файла и кнопки
file_frame = tk.Frame(chat_frame, bg='#0a0a0a')
chat_text.window_create(tk.END, window=file_frame)

file_label = tk.Label(file_frame, text=f"{os.path.basename(FILE_TO_CHECK)}", 
                      fg='#00ff00', bg='#0a0a0a', font=('Impact', 10), cursor="hand2")
file_label.pack(side=tk.LEFT)

download_btn = tk.Button(file_frame, text="Скачать", 
                         command=start_check, padx=5,
                         bg='#003300', fg='#00ff00', font=('Impact', 9),
                         relief=tk.FLAT)
download_btn.pack(side=tk.LEFT, padx=5)

chat_text.insert(tk.END, "\n")

# Панель ввода
bottom_frame = tk.Frame(root, bg='black')
bottom_frame.pack(fill=tk.X, padx=10, pady=5)

input_field = tk.Entry(bottom_frame, width=30, bg='#1a1a1a', fg='#00ff00', 
                       font=('Impact', 10), relief=tk.FLAT, insertbackground='#00ff00')
input_field.pack(side=tk.LEFT, padx=5)
input_field.insert(0, "Введите текст")
input_field.bind("<FocusIn>", clear_placeholder)
input_field.bind("<Return>", lambda e: fake_send())

send_btn = tk.Button(bottom_frame, text=">>", command=fake_send,
                     bg='#003300', fg='#00ff00', font=('Impact', 10),
                     relief=tk.FLAT)
send_btn.pack(side=tk.LEFT)

root.mainloop()
