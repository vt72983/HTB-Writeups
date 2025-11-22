[English](#english) · [Русский](#русский)

---

## English

**Name -** Not Posixtive

**Category -** Misc

**Difficulty -** Easy

**Link -** https://app.hackthebox.com/challenges/Not%2520Posixtive

### Summary

The challenge description says: "Luigi is not posixtive we can challenge his scripting abilities. He's convinced we cannot understand the secret hidden inside his l33t coding abilities. We can't let that slide!"
Let's go help Luigi =)

This challenge relies on a very specific quirk (or "feature") of the Python language involving hash collisions of small negative integers, combined with manipulating Linux exit codes.

---

### Recon (how I inspected the format)

Let's analyze the `server.py` code to find the vulnerability.

The most critical part of the code is here:

```python
if debug[0] != debug[1] and str(debug[0]) != str(debug[1]) and hash(debug[0]) == hash(debug[1]) and isinstance(debug[0], type(debug[1])):
    # WIN: print flag
```

We need to generate two values, `z1` (`debug[0]`) and `z2` (`debug[1]`), which are the results of executing two commands.
The conditions are:
1.  `z1 != z2` (values are different)
2.  `str(z1) != str(z2)` (string representations are different)
3.  `type(z1) == type(z2)` (types are the same)
4.  **`hash(z1) == hash(z2)`** (Hashes are identical!)

In Python, for integers (`int`), the rule is usually `hash(x) == x`. Meaning `hash(5) == 5`. If `x != y`, their hashes are usually not equal.
**HOWEVER!** There is one exception.
In Python, `hash(-1)` returns `-2`. And `hash(-2)` also returns `-2`.

Let's verify:
```python
>>> hash(-1)
-2
>>> hash(-2)
-2
>>> -1 != -2
True
```

This is the **hash collision** we need to exploit.
Our goal: make one command return a result of **`-1`**, and the second command return **`-2`**.

The command result is calculated in the `execute` function:
```python
return result.returncode * mode, partial_output
```
So `z = (program_return_code) * mode`.

We need:
1.  `ExitCode1 * mode = -1`
2.  `ExitCode2 * mode = -2`

Since exit codes in Linux (where the server runs) are positive numbers (0-255), we need **`mode` to be equal to -1**.

---

### Strategy

Now let's bypass the filters.

**1. Setting the `mode`**
The `check_operands` function checks the input for `mode`.
*   Max length: 2 chars.
*   Forbidden: `+ - * / % = x o b`.
*   It runs `eval()`.

How do we get `-1` without a minus sign?
Python has the bitwise inversion operator `~`.
`~0` equals `-1`.
The `~` character is not forbidden, and the string length of `~0` is 2. Perfect.

**2. Choosing the program (`bin`)**
The `check_stricter_values` function.
*   Max length: 4 chars.
*   Allowed: only letters and dots.

We need a program that can return **code 1** (error/not found) and **code 2** (critical error/misuse).
The ideal candidate is **`grep`**.
*   If `grep` finds a match -> code 0.
*   If `grep` does NOT find a match -> code 1.
*   If `grep` tries to open a non-existent file -> code 2.

`grep` is 4 letters long. Fits.

**3. Setting the arguments (`args` and `switches`)**
The `check_values` function.
*   Max length: 13 chars.
*   Allowed: letters and dots.

The command is run like this: `subprocess.run([bin, switch, compl])`
Which means: `grep <switch> <compl>`

We need two runs:
1.  **For result -1:** We need Exit Code 1.
    *   Command: `grep <something_not_in_file> <existing_file>`
    *   `switch` (pattern): `Nomatch` (just a word that isn't in the file).
    *   `compl` (file): `server.py` or `flag.txt` (they definitely exist on the server).

2.  **For result -2:** We need Exit Code 2.
    *   Command: `grep <anything> <NON_EXISTENT_FILE>`
    *   `switch` (pattern): `Nomatch`
    *   `compl` (file): `fakefile`

---

### Result and proofs

We connect to the server `nc <ip> <port>` and enter the following step-by-step:

1.  Select **1** (Create your mode).
    *   Enter: `~0`
    *   *(This sets mode to -1)*

2.  Select **2** (Add it to the bin).
    *   Enter: `grep`

3.  Select **4** (Let go of your beliefs) — this sets `switches` (the first argument for grep, the search pattern).
    *   We are asked for two separated by a comma.
    *   Enter: `No,No`
    *   *(We will search for string "No" in files. It's better to use something rare, like `ZZZ,ZZZ`. Let's use that XD).*
    *   Reliable input: `ZZZ,ZZZ`

4.  Select **3** (Research your arguments) — this sets `args` (the second argument for grep, the filename).
    *   The first file must exist (so grep returns 1 - "not found"). Use `flag.txt`.
    *   The second file must NOT exist (so grep returns 2 - "error"). Use `fake`.
    *   Enter: `flag.txt,fake`

5.  Select **5** (! Beat the competitor !).
    *   The script runs the checks, gets `-1` and `-2`.
    *   `hash(-1)` == -2, `hash(-2)` == -2.
    *   The condition is met, the flag is yours!

Now we just enter this via nc:

```
┌──(vt729830㉿vt72983)-[~/5/2/test/test2]
└─$ nc 1.1.1.1 365


 ███▄    █  ▒█████  ▄▄▄█████▓    ██▓███   ▒█████    ██████  ██▓▒██   ██▒▄▄▄█████▓ ██▓ ██▒   █▓▓█████
 ██ ▀█   █ ▒██▒  ██▒▓  ██▒ ▓▒   ▓██░  ██▒▒██▒  ██▒▒██    ▒ ▓██▒▒▒ █ █ ▒░▓  ██▒ ▓▒▓██▒▓██░   █▒▓█   ▀
▓██  ▀█ ██▒▒██░  ██▒▒ ▓██░ ▒░   ▓██░ ██▓▒▒██░  ██▒░ ▓██▄   ▒██▒░░  █   ░▒ ▓██░ ▒░▒██▒ ▓██  █▒░▒███
▓██▒  ▐▌██▒▒██   ██░░ ▓██▓ ░    ▒██▄█▓▒ ▒▒██   ██░  ▒   ██▒░██░ ░ █ █ ▒ ░ ▓██▓ ░ ░██░  ▒██ █░░▒▓█  ▄
▒██░   ▓██░░ ████▓▒░  ▒██▒ ░    ▒██▒ ░  ░░ ████▓▒░▒██████▒▒░██░▒██▒ ▒██▒  ▒██▒ ░ ░██░   ▒▀█░  ░▒████▒
░ ▒░   ▒ ▒ ░ ▒░▒░▒░   ▒ ░░      ▒▓▒░ ░  ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓  ▒▒ ░ ░▓ ░  ▒ ░░   ░▓     ░ ▐░  ░░ ▒░ ░
░ ░░   ░ ▒░  ░ ▒ ▒░     ░       ░▒ ░       ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░░░   ░▒ ░    ░     ▒ ░   ░ ░░   ░ ░  ░
   ░   ░ ░ ░ ░ ░ ▒    ░         ░░       ░ ░ ░ ▒  ░  ░  ░   ▒ ░ ░    ░    ░       ▒ ░     ░░     ░
         ░     ░ ░                           ░ ░        ░   ░   ░    ░            ░        ░     ░  ░
                                                                                          ░


1. Create your mode
2. Add it to the bin
3. Research your arguments
4. Let go of your beliefs
5. ! Beat the competitor !

> 1
(mode)> ~0

> 2
(bin)> grep

> 4
(switch1,switch2)> ZZZ,ZZZ

> 3
(arg1,arg2)> flag.txt,fake

> 5
What an awesome player! You have beaten the competitor, you deserve this: HTB{***_********_***_***_*****_*****}
```

And just like that, we got another easy-peasy flag.

![flag proof](flag.png)

---

## Русский

[Перейти к английской версии](#english)

**Название -** Not Posixtive

**Категория -** Misc

**Сложность -** Easy

**Ссылка -** https://app.hackthebox.com/challenges/Not%2520Posixtive

---

## Краткое описание

Описание гласит: "Луиджи не уверен, что мы сможем проверить его навыки написания скриптов. Он убеждён, что мы не поймём секрет, скрытый в его умелом кодировании. Мы не можем это так оставить!"
Пойдем помогать луиджи =)

В этом задании используется одна очень специфичная особенность (или "фича") языка Python, связанная с коллизией хэшей, и манипуляция кодами возврата Linux.

---

## Разведка (как я смотрел формат)

Давай разберем код `server.py` и найдем уязвимость.

Самая важная часть кода находится здесь:

```python
if debug[0] != debug[1] and str(debug[0]) != str(debug[1]) and hash(debug[0]) == hash(debug[1]) and isinstance(debug[0], type(debug[1])):
    # WIN: print flag
```

Нам нужно получить два значения `z1` (debug[0]) и `z2` (debug[1]), которые являются результатами выполнения двух команд.
Условия:
1.  `z1 != z2` (значения разные)
2.  `str(z1) != str(z2)` (строки разные)
3.  `type(z1) == type(z2)` (типы одинаковые)
4.  **`hash(z1) == hash(z2)`** (Хэши одинаковые!)

В Python для целых чисел (int) обычно выполняется правило `hash(x) == x`. То есть `hash(5) == 5`. Если `x != y`, то и их хэши обычно не равны.
**НО!** Есть одно исключение.
В Python `hash(-1)` возвращает `-2`. И `hash(-2)` тоже возвращает `-2`.

Проверим:
```python
>>> hash(-1)
-2
>>> hash(-2)
-2
>>> -1 != -2
True
```

Это **коллизия хэшей**, которую нам нужно использовать.
Наша цель: сделать так, чтобы одна команда вернула результат **`-1`**, а вторая — **`-2`**.

Результат команды вычисляется в функции `execute`:
```python
return result.returncode * mode, partial_output
```
То есть `z = (код_возврата_программы) * mode`.

Нам нужно:
1.  `ExitCode1 * mode = -1`
2.  `ExitCode2 * mode = -2`

Поскольку коды возврата в Linux (где крутится сервер) — это положительные числа (0-255), нам нужно, чтобы **`mode` был равен -1**.

---

## Стратегия

А теперь обходим фильтры.

**1. Настраиваем `mode`**
Функция `check_operands` проверяет ввод для `mode`.
*   Длина макс: 2 символа.
*   Запрещены: `+ - * / % = x o b`.
*   Выполняется `eval()`.

Как получить `-1` без минуса?
В Python есть побитовая инверсия `~`.
`~0` равно `-1`.
Символ `~` не запрещен, длина строки `~0` равна 2. Идеально.

**2. Выбираем программу (`bin`)**
Функция `check_stricter_values`.
*   Длина макс: 4 символа.
*   Разрешены только буквы и точка.

Нам нужна программа, которая может вернуть **код 1** (ошибка/не найдено) и **код 2** (критическая ошибка/неверное использование).
Идеальный кандидат — **`grep`**.
*   Если `grep` нашел совпадение -> код 0.
*   Если `grep` НЕ нашел совпадение -> код 1.
*   Если `grep` пытался открыть несуществующий файл -> код 2.

`grep` состоит из 4 букв. Подходит.

**3. Настраиваем аргументы (`args` и `switches`)**
Функция `check_values`.
*   Длина макс: 13 символов.
*   Разрешены буквы и точка.

Команда запускается так: `subprocess.run([bin, switch, compl])`
То есть: `grep <switch> <compl>`

Нам нужно два запуска:
1.  **Для результата -1:** Нам нужен Exit Code 1.
    *   Команда: `grep <что-то_чего_нет_в_файле> <существующий_файл>`
    *   `switch` (паттерн): `Nomatch` (просто слово, которого нет в файле).
    *   `compl` (файл): `server.py` или `flag.txt` (они точно есть на сервере).

2.  **Для результата -2:** Нам нужен Exit Code 2.
    *   Команда: `grep <что-угодно> <НЕСУЩЕСТВУЮЩИЙ_ФАЙЛ>`
    *   `switch` (паттерн): `Nomatch`
    *   `compl` (файл): `fakefile`

---

## Результат

Подключаемся к серверу `nc <ip> <port>` и вводим по пунктам:

1.  Выбираем **1** (Create your mode).
    *   Вводим: `~0`
    *   *(Это установит mode в -1)*

2.  Выбираем **2** (Add it to the bin).
    *   Вводим: `grep`

3.  Выбираем **4** (Let go of your beliefs) — это `switches` (первый аргумент grep, паттерн поиска).
    *   Нас просят ввести два значения через запятую.
    *   Вводим: `ZZZ,ZZZ`
    *   *(Мы будем искать строку "ZZZ" в файлах. Главное, чтобы ее там не было XD).*

4.  Выбираем **3** (Research your arguments) — это `args` (второй аргумент grep, имя файла).
    *   Первый файл должен существовать (чтобы grep вернул 1 - "не найдено"). Используем `flag.txt`.
    *   Второй файл НЕ должен существовать (чтобы grep вернул 2 - "ошибка"). Используем `fake`.
    *   Вводим: `flag.txt,fake`

5.  Выбираем **5** (! Beat the competitor !).
    *   Скрипт выполнит проверки, получит `-1` и `-2`.
    *   `hash(-1)` == -2, `hash(-2)` == -2.
    *   Условие выполнится, флаг наш!

А теперь просто вводим это через nc:

```
┌──(vt729830㉿vt72983)-[~/5/2/test/test2]
└─$ nc 1.1.1.1 365


 ███▄    █  ▒█████  ▄▄▄█████▓    ██▓███   ▒█████    ██████  ██▓▒██   ██▒▄▄▄█████▓ ██▓ ██▒   █▓▓█████
 ██ ▀█   █ ▒██▒  ██▒▓  ██▒ ▓▒   ▓██░  ██▒▒██▒  ██▒▒██    ▒ ▓██▒▒▒ █ █ ▒░▓  ██▒ ▓▒▓██▒▓██░   █▒▓█   ▀
▓██  ▀█ ██▒▒██░  ██▒▒ ▓██░ ▒░   ▓██░ ██▓▒▒██░  ██▒░ ▓██▄   ▒██▒░░  █   ░▒ ▓██░ ▒░▒██▒ ▓██  █▒░▒███
▓██▒  ▐▌██▒▒██   ██░░ ▓██▓ ░    ▒██▄█▓▒ ▒▒██   ██░  ▒   ██▒░██░ ░ █ █ ▒ ░ ▓██▓ ░ ░██░  ▒██ █░░▒▓█  ▄
▒██░   ▓██░░ ████▓▒░  ▒██▒ ░    ▒██▒ ░  ░░ ████▓▒░▒██████▒▒░██░▒██▒ ▒██▒  ▒██▒ ░ ░██░   ▒▀█░  ░▒████▒
░ ▒░   ▒ ▒ ░ ▒░▒░▒░   ▒ ░░      ▒▓▒░ ░  ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓  ▒▒ ░ ░▓ ░  ▒ ░░   ░▓     ░ ▐░  ░░ ▒░ ░
░ ░░   ░ ▒░  ░ ▒ ▒░     ░       ░▒ ░       ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░░░   ░▒ ░    ░     ▒ ░   ░ ░░   ░ ░  ░
   ░   ░ ░ ░ ░ ░ ▒    ░         ░░       ░ ░ ░ ▒  ░  ░  ░   ▒ ░ ░    ░    ░       ▒ ░     ░░     ░
         ░     ░ ░                           ░ ░        ░   ░   ░    ░            ░        ░     ░  ░
                                                                                          ░

1. Create your mode
2. Add it to the bin
3. Research your arguments
4. Let go of your beliefs
5. ! Beat the competitor !

> 1
(mode)> ~0

> 2
(bin)> grep

> 4
(switch1,switch2)> ZZZ,ZZZ

> 3
(arg1,arg2)> flag.txt,fake

> 5
What an awesome player! You have beaten the competitor, you deserve this: HTB{***_********_***_***_*****_*****}
```

Вот и еще один флаг получили на изи :)

![flag proof](flag.png)
