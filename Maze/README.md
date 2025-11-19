[English](#english) · [Russian](#russian)

## English

**Name -** Maze

**Category -** Reversing

**Difficulty -** Medium

**Link -** https://app.hackthebox.com/challenges/Maze

---

### Summary

The challenge description says, "I am stuck in a maze. Can you lend me a hand to find the way out?" We are given `maze.exe`, `maze.png`, and an encrypted archive `enc_maze.zip`. The path to the flag is a multi-stage quest: first, you need to correctly unpack the PyInstaller application, realizing that without Python 3.8, you're going nowhere. Then, you have to unravel obfuscated code to find the true logic for decrypting the archive. It turns out `maze.png` is not a red herring but the source of a seed for key generation. After obtaining a working ELF file, we face the final boss: reverse-engineering the binary to reconstruct the flag generation algorithm from an array of numbers.

---

### Recon (how I inspected the format)

Alright, let's get started. We have `maze.exe` (5 MB), `maze.png` (which I immediately assumed was a red herring), and `enc_maze.zip`, which probably needs to be decrypted by the executable.

Opening up the patient named `maze.exe`. The first thing that catches the eye is the obfuscation of most functions. No big deal. I ran `strings` on it and immediately realized it was a PyInstaller executable. So, the first step is to unpack its inner code.

No sooner said than done.
`python pyinstxtractor.py maze.exe`

And right away, the first warning from fate:
`[!] Warning: This script is running in a different Python version than the one used to build the executable.`
`[!] Please run this script in Python 3.8 to prevent extraction errors during unmarshalling`

Of course, I ignored it. Why read boring warnings? In the end, I found `maze.pyc` and decompiled it. The analysis showed it used the password `"Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH"` for `enc_maze.zip`, followed by some weird byte manipulation where the key was an array of zeros. Or so I thought...

---

### Strategy

My plan was simple as a brick, but, as it turned out, full of wrong turns:
1.  Unpack `maze.exe` with `pyinstxtractor`.
2.  Decompile `maze.pyc` and understand the logic.
3.  Write a script to unpack `enc_maze.zip` and apply the discovered byte transformation.
4.  Wonder why the resulting ELF file is corrupted and suffer.
5.  Remember the warning about Python 3.8, accept my fate, install it, and re-unpack the executable.
6.  Find the hidden `obf_path.pyc` file and deobfuscate its code to find the *real* key generation logic using `maze.png`.
7.  Write a final script to get the working ELF.
8.  Reverse the ELF, find the flag-building algorithm, and write one last script to extract it.

---

### Script and Patching Evolution (how I iterated and fixed bugs)

**Stage 1: Confidence and the First Fiasco**

First, I unpacked `maze.exe` carelessly and got `maze.pyc`. Decompiling it gave me this code:
```python
import sys, obf_path
ZIPFILE = "enc_maze.zip"
print("Look who comes to me :)")
print()
inp = input("Now There are two paths from here. Which path will u choose? => ")
if inp == "Y0u_St1ll_1N_4_M4z3":
    obf_path.obfuscate_route()
else:
    print("Unfortunately, this path leads to a dead end.")
    sys.exit(0)
import pyzipper

def decrypt(file_path, word):
    with pyzipper.AESZipFile(file_path, "r", compression=(pyzipper.ZIP_LZMA), encryption=(pyzipper.WZ_AES)) as extracted_zip:
        try:
            extracted_zip.extractall(pwd=word)
        except RuntimeError as ex:
            try:
                try:
                    print(ex)
                finally:
                    ex = None
                    del ex

            finally:
                ex = None
                del ex


decrypt(ZIPFILE, "Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH".encode())
with open("maze", "rb") as file:
    content = file.read()
data = bytearray(content)
data = [x for x in data]
key = [0] * len(data)
for i in range(0, len(data), 10):
    data[i] = (data[i] + 80) % 256
else:
    for i in range(0, len(data), 10):
        data[i] = (data[i] ^ key[i % len(key)]) % 256
    else:
        with open("dec_maze", "wb") as f:
            for b in data:
                f.write(bytes([b]))
```
The key mistake in my analysis was here: `key = [0] * len(data)`. I decided that XORing with zero was a trick, and wrote a script that only did the `+ 80` part.
```python
import pyzipper
import os

zip_filename = "enc_maze.zip"
password = b"Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH"
output_filename = "dec_maze_solved"

print(f"Opening {zip_filename}...")
try:
    with pyzipper.AESZipFile(zip_filename, "r", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.extractall(pwd=password)
    print("'maze' file extracted from the archive.")
except FileNotFoundError:
    print(f"What the... File not found!")
    exit()
except Exception as e:
    print(f"Error unpacking 0_0 - {e}")
    exit()
print("Starting byte transformation...")
try:
    with open("maze", "rb") as f:
        content = bytearray(f.read())
    for i in range(0, len(content), 10):
        content[i] = (content[i] + 80) % 256
    with open(output_filename, "wb") as f:
        f.write(content)
    print(f"Result: {output_filename}")
    header = content[:8].hex().upper()
    print(f"[*] File Header (Magic Bytes): {header}")
except FileNotFoundError:
    print("[-] Error: 'maze' file not found after unpacking.")
```
The result was predictable: `[*] File Header (Magic Bytes): 3F454C4602010100`. A corrupted ELF! I even wrote a script to fix the first byte from `3F` to `7F`, but the file was still broken. A dead end.

**Stage 2: Acceptance and Enlightenment**

Then it hit me. `import sys, obf_path`... But where exactly is `obf_path.pyc`? It wasn't there, because `pyinstxtractor` failed to unpack the PYZ archive due to the wrong Python version. I had to download Python 3.8.
```bash
C:\...\Python38\python.exe pyinstxtractor.py maze.exe
...
[+] Found 75 files in PYZ archive
[+] Successfully extracted pyinstaller archive: maze.exe
```
And lo and behold, `obf_path.pyc` appeared in the `PYZ-00.pyz_extracted` folder. Let's decompile it:
```python
def obfuscate_route():
    from marshal import loads
    exec(loads(b'\xe3\x00\x00\x00\x00\x00...'))
```
Aha, `marshal.loads` with a huge blob of bytes. A classic. Time to write a deobfuscation script.
```python
import marshal
import zlib
import lzma
import sys

blob = (
    b'\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00@\x00\x00\x00s(\x00\x00\x00d\x00d\x01l\x00Z\x00d\x00d\x01l\x01Z\x01e\x02e\x00\xa0\x03e\x01\xa0\x03d\x02\xa1\x01\xa1\x01\x83\x01\x01\x00d\x01S\x00)\x03\xe9\x00\x00\x00\x00Ns4\x03\x00\x00\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F\x02\x00!\x01\x16\x00\x00\x00t/\xe5\xa3\x01\x02\xf6x\x9c\xedV[o\xd30\x14\xfe+^_\xd6\x02+Kz\xdf\x18\x9a\xe0\x01\x8d\x07@\x82\xa7)R\xe5\xc4\'\xa9\xb7\xd4\x8elgk#~<\xc7\x8e=\xba\xb6\x13\x9ax\xe9C#\xc5\xf9\xce\xfd\xf8\xf3q\xd5\xf9\\A\x91J\xad\xe7\xf8\x1c*\xbc\xea\x1cB\x17\xff\x84\x9d\xcbC\xe8\xe2\xc8\xe6\x91\xcd}l\xc2\n\xb2n))\xd3\xdd\xb4\x93\xac`\x90\xac\xce\xcf\xff\xf3\x1do\xca\xd7\x9b\x82\xc6\n\xd3M\x05\x0bKTZt\xbb\xab\x8b\xac.z\xd2\xc5V\x17/q\x19X\x83m7\xb26\xb0\xe0\x0e\x97!ksG\xb3\x90p\x04\xad\x86\xfa\xdeh\x14,\x13\x16\xf2L-\x1aZ\xc7\xd1\xbd\xf5R\xbf 1V7JV\xd3P\xc4\x17r\xfa\xf1\xae\xde\x01,"|\x074\xda\xb6\x9f\xdf\xb5\x19]\'\xe9\x8e&\xb3\x9a\x89]\xa6>:\x0eY\xf4o_w\xf2\xfa\xba\n\xc2\x06\xa7>8\xf6\x05a\x93\x8c\xdc\xba\xe5,1\x81;/\x8b \xe3w\xb2\xa1\xc7\x1d\xbch\xc9\xb6-X j\xa9S/\x10\n\xfb66\xb0\x96|\x7f\x84\xcd\x87K\xb2\x9a\xa5~8"\xb4\xceX;\x15{#\xe2\xd7\x92\xe7\xa6\xf0\xa7E=\x0c\xc7P\x98m\xcf\xfb\xb7^\xeb\xcc\xa8=I]\x02T\x8d\xa5zI\x1b\xe8W\xa2\xb0\xc2\xa0_\xad\x9b\xb3\x9bBH\xc5EA\xcc\x02H\xa5dZ\xc2\x92<Jqj\xc8\x92\xde\x03\xe1\x860\xaeiU\x01U\x97\xcdU&E\xae\xa406\x82\nF(c\n\xb4\xb6"zr\xed\xd2\x18Uc.j\x16\xc4H\x82fY\xd6\x86K\xd1o\xbe~\xbfG\x07jN5)\xa4d$\xad\r\xb9!E\x8d\x19\x9c\x9e\xd4D/d]2"\xe4#F\x9aZ\t\x82\xf5\x96\xbe;x\xe0\xb2\xd6.\xb5\xdf[\xacR\x8e0jyl7\xcf\af\xedxx\xfcc\x03\xb7\x9c\x06\xb19C,\xbe \x9f\'\'d-k\x92\xb9\xca\xa03Z\x81+(\xd3\xbcF\xc9\x00s%\x91\xb4(5\x96\x14\xb3\xc0\x9dr\xcb\xd0\x9a,\xa0\xacl\xf8\x05\xf1\x07\x11o\x1eD\xe3n\xa5\xd0\x00\xac\xdb\xbc\xed%"\x97\x8ap\xc2\x05QT\x14\xd0\x1d\xe0!^$\x82\xe0\x83\n\xc6\x85\xe9\x0e\xe2wQ<B\xd7\xe6\xfd\' \x9f\xa9\x82\xbc.O\xf0q=)Y\x1bh9Y\x80\x02K\xb9\x90\x86h\x9aC\xbf\xd7N[K\x8c\xd4\x1e\r\xf4:\xc0\xa1\xe1KP\xdb=\x06#U\xc5C\xc0\x1b\x14\x8f\x0b0\xd9#\xb3\x97%\xcaj\xa5@\x989\xe3\n2#\xd5\xfa6\x11\\0X\xcds^B\x98\xb7\n\x07\xca\x84L\xb0\xe2\x01\x8f\x11k\xf3\xd4\xcc\x9d\xe4"`Y\xc1\x13V@YH\xe5\x92\x07\x83e\x11\xcf\xd0M\xbbjG\xff\xef.v\x14>j\x92I\x86\x94)/N?,Q.\xe1c\xb8M\xe1\xd5o\x9e\x07\xdbK\xec<2\xc7\x97\xf0\xd2\xd4\x7f\x87\x9e\xc5\xe9\x96\xbe\xfdz\xefh\xbcO\xdb^p\xb27\xf0y\x01\xffk\x9b\xe7.t\x14\xac\x9d^\xef\xf8\x87\xe3\xf8\xf7\xed@a\xe7\x0f\xdc9\x01G\x00\x00(\xe3\xdf}\x13\x01@\xad\x00\x01\x8f\x06\xf7\x05\x00\x00\x85k\x89\xbe\xb1\xc4g\xfb\x02\x00\x00\x00\x00\x04YZ)\x04\xda\x04zlib\xda\x04lzma\xda\x04exec\xda\ndecompress\xa9\x00r\x06\x00\x00\x00r\x06\x00\x00\x00\xda\x07coduter\xda\x08<module>\x01\x00\x00\x00s\x02\x00\x00\x00\x10\x01'
)
try:
    print("[*] Demarshalling the code...")
    code_obj = marshal.loads(blob)
    compressed_data = None
    for const in code_obj.co_consts:
        if isinstance(const, bytes) and len(const) > 10:
            compressed_data = const
            break
    if not compressed_data:
        print("[-] Couldn't find compressed data inside the object.")
        sys.exit()
    print(f"[+] Found data: {len(compressed_data)} bytes")
    print("[*] Stage 1: LZMA decompression...")
    step1 = lzma.decompress(compressed_data)
    print("[*] Stage 2: ZLIB decompression...")
    final_code = zlib.decompress(step1)
    print("\n" + "="*40)
    print(" INNER CODE ")
    print("="*40 + "\n")
    print(final_code.decode('utf-8'))
    print("\n" + "="*40)
except Exception as e:
    print(f"[-] Error: {e}")
```
And there it was, the real logic! It turns out `maze.png` wasn't a red herring. The script reads bytes from it at offsets 4817, 2624, 2640, 2720, sums them up, and uses the result as a `seed` for `random`. Then it generates a key from 300 random numbers. What a twist!

**Stage 3: Putting It All Together**

Now, knowing the whole truth, it's time to write the correct decryptor.
```python
import random

def solve():
    print("Reading maze.png to generate the seed...")
    try:
        with open("maze.png", "rb") as f:
            img_data = f.read()
    except FileNotFoundError:
        print("maze.png not found 0_0!")
        return
    s = img_data[4817] + img_data[2624] + img_data[2640] + img_data[2720]
    print(f"[*] Calculated seed: {s}")
    random.seed(s)
    key = [random.randint(32, 125) for _ in range(300)]
    print("Key generated.")
    print("Reading the encrypted 'maze' file...")
    try:
        with open("maze", "rb") as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        print("Error: 'maze' file not found (extracted from enc_maze.zip)!")
        return
    print("Applying decryption...")
    for i in range(0, len(data), 10):
        data[i] = (data[i] + 80) % 256
    for i in range(0, len(data), 10):
        xor_val = key[i % len(key)]
        data[i] = (data[i] ^ xor_val)
    header = data[:4]
    print(f"Header of the resulting file: {header.hex().upper()}")
    if header == b'\x7fELF':
        print("Header is correct.")
        with open("maze_solved.elf", "wb") as f:
            f.write(data)
        print("File saved as 'maze_solved.elf'")
    else:
        print("Something went wrong...")
if __name__ == "__main__":
    solve()
```
Running this... gives us a working `maze_solved.elf`. Time to fire up IDA.

**Stage 4: The Final Boss - The ELF**

After opening the ELF, I found some interesting strings in `.rodata`, and right next to them, an array of numbers. The string `"You're going deeper..."` and the array `unk_2060` were `0x30` bytes apart. The logic was: `flag[i] = arr[i-1] - flag[i-1] - flag[i-2]`. Essentially, each subsequent character of the flag is calculated based on the two previous ones and a value from the array. The only thing left was to write the final script.
```python
import struct

def solve_flag():
    filename = "maze_solved.elf"
    try:
        with open(filename, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] File {filename} not found.")
        return
    anchor_string = b"You're going deeper into the maze..."
    start_index = content.find(anchor_string)
    if start_index == -1:
        print("Couldn't find the anchor string in the file. Strange...")
        return
    array_offset = start_index + 0x30
    print(f"Data array found at offset: {hex(array_offset)}")
    target_values = []
    for i in range(60):
        bytes_val = content[array_offset + i*4 : array_offset + (i+1)*4]
        val = struct.unpack("<I", bytes_val)[0]
        target_values.append(val)
    flag = [ord('H'), ord('T'), ord('B')]
    print("Starting decryption...")
    if sum(flag) != target_values[0]:
        print(f"That's suspicious...")
    else:
        print("HTB check passed (sum matched).")
    for i in range(1, len(target_values)):    
        current_char = flag[-1]
        prev_char = flag[-2]  
        target_sum = target_values[i]
        next_char_code = target_sum - current_char - prev_char
        if next_char_code <= 0 or next_char_code > 255:
            break
        flag.append(next_char_code)
    final_flag = "".join(chr(c) for c in flag)
    print(f"\n[*] Flag: {final_flag}")
if __name__ == "__main__":
    solve_flag()
```

---

### Result

Running the final script, and...
```
C:\Users\vt72983\Downloads\Maze\rev_maze>"C:\... \Python38\python.exe" 3.py
Data array found at offset: 0x2060
Starting decryption...
HTB check passed (sum matched).

[*] Flag: HTB{***********************}
```
Hooray, a miracle happened. Now the world can sleep peacefully =)

![flag proof](flag.png)

---

## Русский

[Перейти к английской версии](#english)

**Название -** Maze

**Категория -** Reversing

**Сложность -** Medium

**Ссылка -** https://app.hackthebox.com/challenges/Maze

---

## Краткое описание

Описание челенджа гласит: «I am stuck in a maze. Can you lend me a hand to find the way out?» (Я застрял в лабиринте. Поможешь найти выход?). Нам дают `maze.exe`, `maze.png` и зашифрованный архив `enc_maze.zip`. Путь к флагу — это многоэтапный квест: сначала нужно правильно распаковать PyInstaller-приложение, поняв, что без Python 3.8 мы никуда. Затем — распутать обфусцированный код, чтобы найти истинную логику дешифровки архива. Оказывается, `maze.png` — это не красная селедка, а источник сида для генерации ключа. После получения рабочего ELF-файла нас ждет финальный босс: реверс-инжиниринг бинарника, чтобы восстановить алгоритм генерации флага из массива чисел.

---

## Разведка (как я смотрел формат)

Итак, приступим. У нас имеется `maze.exe` на 5 МБ, `maze.png` (сразу подумал, что это красная селедка) и `enc_maze.zip`, который, наверное, нужно расшифровать через `exe`.

Вскрываем пациента по имени `maze.exe`. Первое, что бросается в глаза, — это обфускация большинства функций. Но это ничего страшного. Глянул `strings` и сразу понял, что это PyInstaller. Поэтому нам нужно просто распокавать внутреннее содержимое его кода.

Сказано — сделано.
`python pyinstxtractor.py maze.exe`

И тут же первое предупреждение от судьбы:
`[!] Warning: This script is running in a different Python version than the one used to build the executable.`
`[!] Please run this script in Python 3.8 to prevent extraction errors during unmarshalling`

Я, конечно же, проигнорировал это. Зачем читать скучные предупреждения? В итоге я нашел `maze.pyc` и декомпилировал его. Анализ показал, что там используется пароль `"Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH"` для `enc_maze.zip`, а затем идет какая-то странная манипуляция с байтами, где ключ — это массив нулей. Ну, я так думал...

---

## Стратегия

Мой план был прост, как валенок, но, как оказалось, полон ложных поворотов:
1.  Распаковать `maze.exe` с помощью `pyinstxtractor`.
2.  Декомпилировать `maze.pyc` и понять логику.
3.  Написать скрипт, который распаковывает `enc_maze.zip` и применяет найденную байтовую трансформацию.
4.  Понять, почему полученный ELF-файл битый, и страдать.
5.  Вспомнить про предупреждение о Python 3.8, смириться, установить его и перераспаковать `exe` заново.
6.  Найти спрятанный файл `obf_path.pyc` и деобфусцировать его код, чтобы найти *настоящую* логику генерации ключа из `maze.png`.
7.  Написать финальный скрипт для получения рабочего ELF.
8.  Отреверсить ELF, найти алгоритм сборки флага и написать последний скрипт для его извлечения.

---

## Изменения скриптов и патчинга (как я думал и исправлял ошибки)

**Этап 1: Уверенность и первое фиаско**

Сначала я распаковал `maze.exe` как попало и получил `maze.pyc`. Декомпиляция дала мне такой код:
```python
import sys, obf_path
ZIPFILE = "enc_maze.zip"
print("Look who comes to me :)")
print()
inp = input("Now There are two paths from here. Which path will u choose? => ")
if inp == "Y0u_St1ll_1N_4_M4z3":
    obf_path.obfuscate_route()
else:
    print("Unfortunately, this path leads to a dead end.")
    sys.exit(0)
import pyzipper

def decrypt(file_path, word):
    with pyzipper.AESZipFile(file_path, "r", compression=(pyzipper.ZIP_LZMA), encryption=(pyzipper.WZ_AES)) as extracted_zip:
        try:
            extracted_zip.extractall(pwd=word)
        except RuntimeError as ex:
            try:
                try:
                    print(ex)
                finally:
                    ex = None
                    del ex

            finally:
                ex = None
                del ex


decrypt(ZIPFILE, "Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH".encode())
with open("maze", "rb") as file:
    content = file.read()
data = bytearray(content)
data = [x for x in data]
key = [0] * len(data)
for i in range(0, len(data), 10):
    data[i] = (data[i] + 80) % 256
else:
    for i in range(0, len(data), 10):
        data[i] = (data[i] ^ key[i % len(key)]) % 256
    else:
        with open("dec_maze", "wb") as f:
            for b in data:
                f.write(bytes([b]))
```
Ключевая ошибка моего анализа была тут: `key = [0] * len(data)`. Я решил, что XOR с нулем — это обманка, и написал скрипт, который делает только `+ 80`.
```python
import pyzipper
import os

zip_filename = "enc_maze.zip"
password = b"Y0u_Ar3_W4lkiNG_t0_Y0uR_D34TH"
output_filename = "dec_maze_solved"

print(f"Открываем {zip_filename}...")
try:
    with pyzipper.AESZipFile(zip_filename, "r", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.extractall(pwd=password)
    print("Файл 'maze' извлечен из архива.")
except FileNotFoundError:
    print(f"ЧАво")
    exit()
except Exception as e:
    print(f"Ошибка распаковки 0_0 - {e}")
    exit()
print("Начинаем преобразование байтов...")
try:
    with open("maze", "rb") as f:
        content = bytearray(f.read())
    for i in range(0, len(content), 10):
        content[i] = (content[i] + 80) % 256
    with open(output_filename, "wb") as f:
        f.write(content)
    print(f"Результат: {output_filename}")
    header = content[:8].hex().upper()
    print(f"[*] Заголовок файла (Magic Bytes): {header}")
except FileNotFoundError:
    print("[-] Ошибка: Файл 'maze' не найден после распаковки.")
```
Результат был предсказуем: `[*] Заголовок файла (Magic Bytes): 3F454C4602010100`. Поврежденный ELF! Я даже написал скрипт, чтобы исправить первый байт `3F` на `7F`, но файл всё равно был битым. Тупик.

**Этап 2: Смирение и озарение**

Тут до меня дошло. `import sys, obf_path`... А где, собственно, `obf_path.pyc`? А его нет, потому что `pyinstxtractor` из-за неверной версии Python не смог распаковать PYZ-архив. Пришлось скачать Python 3.8.
```bash
C:\...\Python38\python.exe pyinstxtractor.py maze.exe
...
[+] Found 75 files in PYZ archive
[+] Successfully extracted pyinstaller archive: maze.exe
```
И, о чудо, в папке `PYZ-00.pyz_extracted` появился `obf_path.pyc`. Декомпилируем его:
```python
def obfuscate_route():
    from marshal import loads
    exec(loads(b'\xe3\x00\x00\x00\x00\x00...'))
```
Ага, `marshal.loads` с огромным блобом байтов. Классика. Пишем скрипт для деобфускации.
```python
import marshal
import zlib
import lzma
import sys

blob = (
    b'\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00@\x00\x00\x00s(\x00\x00\x00d\x00d\x01l\x00Z\x00d\x00d\x01l\x01Z\x01e\x02e\x00\xa0\x03e\x01\xa0\x03d\x02\xa1\x01\xa1\x01\x83\x01\x01\x00d\x01S\x00)\x03\xe9\x00\x00\x00\x00Ns4\x03\x00\x00\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F\x02\x00!\x01\x16\x00\x00\x00t/\xe5\xa3\x01\x02\xf6x\x9c\xedV[o\xd30\x14\xfe+^_\xd6\x02+Kz\xdf\x18\x9a\xe0\x01\x8d\x07@\x82\xa7)R\xe5\xc4\'\xa9\xb7\xd4\x8elgk#~<\xc7\x8e=\xba\xb6\x13\x9ax\xe9C#\xc5\xf9\xce\xfd\xf8\xf3q\xd5\xf9\\A\x91J\xad\xe7\xf8\x1c*\xbc\xea\x1cB\x17\xff\x84\x9d\xcbC\xe8\xe2\xc8\xe6\x91\xcd}l\xc2\n\xb2n))\xd3\xdd\xb4\x93\xac`\x90\xac\xce\xcf\xff\xf3\x1do\xca\xd7\x9b\x82\xc6\n\xd3M\x05\x0bKTZt\xbb\xab\x8b\xac.z\xd2\xc5V\x17/q\x19X\x83m7\xb26\xb0\xe0\x0e\x97!ksG\xb3\x90p\x04\xad\x86\xfa\xdeh\x14,\x13\x16\xf2L-\x1aZ\xc7\xd1\xbd\xf5R\xbf 1V7JV\xd3P\xc4\x17r\xfa\xf1\xae\xde\x01,"|\x074\xda\xb6\x9f\xdf\xb5\x19]\'\xe9\x8e&\xb3\x9a\x89]\xa6>:\x0eY\xf4o_w\xf2\xfa\xba\n\xc2\x06\xa7>8\xf6\x05a\x93\x8c\xdc\xba\xe5,1\x81;/\x8b \xe3w\xb2\xa1\xc7\x1d\xbch\xc9\xb6-X j\xa9S/\x10\n\xfb66\xb0\x96|\x7f\x84\xcd\x87K\xb2\x9a\xa5~8"\xb4\xceX;\x15{#\xe2\xd7\x92\xe7\xa6\xf0\xa7E=\x0c\xc7P\x98m\xcf\xfb\xb7^\xeb\xcc\xa8=I]\x02T\x8d\xa5zI\x1b\xe8W\xa2\xb0\xc2\xa0_\xad\x9b\xb3\x9bBH\xc5EA\xcc\x02H\xa5dZ\xc2\x92<Jqj\xc8\x92\xde\x03\xe1\x860\xaeiU\x01U\x97\xcdU&E\xae\xa406\x82\nF(c\n\xb4\xb6"zr\xed\xd2\x18Uc.j\x16\xc4H\x82fY\xd6\x86K\xd1o\xbe~\xbfG\x07jN5)\xa4d$\xad\r\xb9!E\x8d\x19\x9c\x9e\xd4D/d]2"\xe4#F\x9aZ\t\x82\xf5\x96\xbe;x\xe0\xb2\xd6.\xb5\xdf[\xacR\x8e0jyl7\xcf\af\xedxx\xfcc\x03\xb7\x9c\x06\xb19C,\xbe \x9f\'\'d-k\x92\xb9\xca\xa03Z\x81+(\xd3\xbcF\xc9\x00s%\x91\xb4(5\x96\x14\xb3\xc0\x9dr\xcb\xd0\x9a,\xa0\xacl\xf8\x05\xf1\x07\x11o\x1eD\xe3n\xa5\xd0\x00\xac\xdb\xbc\xed%"\x97\x8ap\xc2\x05QT\x14\xd0\x1d\xe0!^$\x82\xe0\x83\n\xc6\x85\xe9\x0e\xe2wQ<B\xd7\xe6\xfd\' \x9f\xa9\x82\xbc.O\xf0q=)Y\x1bh9Y\x80\x02K\xb9\x90\x86h\x9aC\xbf\xd7N[K\x8c\xd4\x1e\r\xf4:\xc0\xa1\xe1KP\xdb=\x06#U\xc5C\xc0\x1b\x14\x8f\x0b0\xd9#\xb3\x97%\xcaj\xa5@\x989\xe3\n2#\xd5\xfa6\x11\\0X\xcds^B\x98\xb7\n\x07\xca\x84L\xb0\xe2\x01\x8f\x11k\xf3\xd4\xcc\x9d\xe4"`Y\xc1\x13V@YH\xe5\x92\x07\x83e\x11\xcf\xd0M\xbbjG\xff\xef.v\x14>j\x92I\x86\x94)/N?,Q.\xe1c\xb8M\xe1\xd5o\x9e\x07\xdbK\xec<2\xc7\x97\xf0\xd2\xd4\x7f\x87\x9e\xc5\xe9\x96\xbe\xfdz\xefh\xbcO\xdb^p\xb27\xf0y\x01\xffk\x9b\xe7.t\x14\xac\x9d^\xef\xf8\x87\xe3\xf8\xf7\xed@a\xe7\x0f\xdc9\x01G\x00\x00(\xe3\xdf}\x13\x01@\xad\x00\x01\x8f\x06\xf7\x05\x00\x00\x85k\x89\xbe\xb1\xc4g\xfb\x02\x00\x00\x00\x00\x04YZ)\x04\xda\x04zlib\xda\x04lzma\xda\x04exec\xda\ndecompress\xa9\x00r\x06\x00\x00\x00r\x06\x00\x00\x00\xda\x07coduter\xda\x08<module>\x01\x00\x00\x00s\x02\x00\x00\x00\x10\x01'
)
try:
    print("[*] Демаршализация кода...")
    code_obj = marshal.loads(blob)
    compressed_data = None
    for const in code_obj.co_consts:
        if isinstance(const, bytes) and len(const) > 10:
            compressed_data = const
            break
    if not compressed_data:
        print("[-] Не нашел сжатые данные внутри объекта.")
        sys.exit()
    print(f"[+] Найдены данные: {len(compressed_data)} байт")
    print("[*] Этап 1: LZMA декомпрессия...")
    step1 = lzma.decompress(compressed_data)
    print("[*] Этап 2: ZLIB декомпрессия...")
    final_code = zlib.decompress(step1)
    print("\n" + "="*40)
    print(" ВНУТРЕННИЙ КОД ")
    print("="*40 + "\n")
    print(final_code.decode('utf-8'))
    print("\n" + "="*40)
except Exception as e:
    print(f"[-] Ошибка: {e}")
```
И вот она, настоящая логика! Оказывается, картинка `maze.png` — это не селедка. Скрипт читает байты из нее по смещениям 4817, 2624, 2640, 2720, суммирует их и использует как `seed` для `random`. А потом генерирует ключ из 300 случайных чисел. Вот так поворот!

**Этап 3: Собираем всё вместе**

Теперь, зная всю правду, пишем правильный дешифровщик.
```python
import random

def solve():
    print("Читаем maze.png для генерации сида...")
    try:
        with open("maze.png", "rb") as f:
            img_data = f.read()
    except FileNotFoundError:
        print("где maze.png 0_0!")
        return
    s = img_data[4817] + img_data[2624] + img_data[2640] + img_data[2720]
    print(f"[*] Рассчитанный seed: {s}")
    random.seed(s)
    key = [random.randint(32, 125) for _ in range(300)]
    print("Ключ сгенерирован.")
    print("Читаем зашифрованный файл 'maze'...")
    try:
        with open("maze", "rb") as f:
            data = bytearray(f.read())
    except FileNotFoundError:
        print("Ошибка: не найден файл 'maze' (извлеченный из enc_maze.zip)!")
        return
    print("Применяем дешифровку...")
    for i in range(0, len(data), 10):
        data[i] = (data[i] + 80) % 256
    for i in range(0, len(data), 10):
        xor_val = key[i % len(key)]
        data[i] = (data[i] ^ xor_val)
    header = data[:4]
    print(f"Заголовок полученного файла: {header.hex().upper()}")
    if header == b'\x7fELF':
        print("Заголовок верный.")
        with open("maze_solved.elf", "wb") as f:
            f.write(data)
        print("Файл сохранен 'maze_solved.elf'")
    else:
        print("0_0")
if __name__ == "__main__":
    solve()
```
Запускаем... и получаем рабочий `maze_solved.elf`. Теперь можно открывать его в IDA.

**Этап 4: Финальный босс — ELF**

Открыв ELF, я нашел интересные строки в `.rodata`, а рядом с ними — массив чисел. Строка `"You're going deeper..."` и массив `unk_2060` находились на расстоянии `0x30` байт. Логика была такой: `flag[i] = arr[i-1] - flag[i-1] - flag[i-2]`. По сути, каждый следующий символ флага вычисляется на основе двух предыдущих и значения из массива. Осталось написать финальный скрипт.
```python
import struct

def solve_flag():
    filename = "maze_solved.elf"
    try:
        with open(filename, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] Файл {filename} не найден.")
        return
    anchor_string = b"You're going deeper into the maze..."
    start_index = content.find(anchor_string)
    if start_index == -1:
        print("Не удалось найти якорную строку в файле. Странно...")
        return
    array_offset = start_index + 0x30
    print(f"Массив данных найден по смещению: {hex(array_offset)}")
    target_values = []
    for i in range(60):
        bytes_val = content[array_offset + i*4 : array_offset + (i+1)*4]
        val = struct.unpack("<I", bytes_val)[0]
        target_values.append(val)
    flag = [ord('H'), ord('T'), ord('B')]
    print("Начинаем расшифровку...")
    if sum(flag) != target_values[0]:
        print(f"сомнительно")
    else:
        print("Проверка HTB пройдена (сумма совпала).")
    for i in range(1, len(target_values)):    
        current_char = flag[-1]
        prev_char = flag[-2]  
        target_sum = target_values[i]
        next_char_code = target_sum - current_char - prev_char
        if next_char_code <= 0 or next_char_code > 255:
            break
        flag.append(next_char_code)
    final_flag = "".join(chr(c) for c in flag)
    print(f"\n[{final_flag}")
if __name__ == "__main__":
    solve_flag()
```

---

## Результат

Запускаем последний скрипт, и...
```
C:\Users\vt72983\Downloads\Maze\rev_maze>"C:\... \Python38\python.exe" 3.py
Массив данных найден по смещению: 0x2060
Начинаем расшифровку...
Проверка HTB пройдена (сумма совпала).

[HTB{***********************}
```
Ура, чудо случилось. Теперь мир может спать спокойно =)

![flag proof](flag.png)
