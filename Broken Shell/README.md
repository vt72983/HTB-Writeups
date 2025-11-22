[English](#english) · [Русский](#русский)

---

## English

**Name -** Broken Shell

**Category -** Misc

**Difficulty -** Easy

**Link -** https://app.hackthebox.com/challenges/Broken%2520Shell

### Summary

The challenge description says: "We've built a secure sandbox environment that only allows specific symbols and numbers. It's designed to be inescapable—security at its best!"
Security, you say? Let's check that out.

This challenge is a "Bash Jail" escape. We are restricted to a very limited set of characters, specifically forbidden from using letters. The solution relies on using the `?` wildcard to match command names and using bash function argument expansion to execute them.

---

### Recon (how I inspected the format)

I connected to the server and checked the restrictions.

```
[*] Allowed characters: ^[0-9${}/?"[:space:]:&>_=()]+$
```

**What we have:**
*   Numbers: `0-9`
*   Paths: `/`
*   Variables: `$` `{` `}`
*   **The MVP:** `?` (Question mark).

**What we don't have:**
*   Letters! We cannot type `ls`, `cat`, `id`, or `flag.txt`.
*   Asterisk `*`.
*   Dot `.`.

**The Trick:**
In Bash, the `?` character is a wildcard that represents **"any single character"**.
Since we cannot type the word `cat` (3 letters), we can type `???` (3 marks), and the shell will try to find a file or command that fits this pattern.

If we try to blindly execute `/???/??`, the shell expands it to *every* matching file (like `/bin/cp`, `/bin/ls`, `/bin/rm`) and tries to run the first one with the others as arguments. This usually results in errors (like `cp` complaining).

---

### Strategy

To execute a specific command without knowing which one comes first in the alphabetical expansion, we can use a **Bash Function**.

The plan:
1.  Define a function named `_`.
2.  Pass the wildcard pattern (like `/???/??` for 2-letter binaries in `/bin`) as an argument to this function.
3.  The shell expands the wildcard *before* the function runs.
4.  Inside the function, `$1` will be the first match, `$2` the second, and so on.
5.  We can blindly execute specific arguments (like `$7`) until we hit the command we want (like `ls` or `cat`).

**Finding `ls`:**
The pattern `/???/??` matches files in `/bin/` with 2 letters.
Common matches: `cp`, `dd`, `df`, `du`, `id`, `ln`, `ls`.
In alphabetical order:
1. `cp`
2. `dd`
3. `df`
4. `du`
5. `id`
6. `ln`
7. `ls`

So, inside our function, `$7` should be `ls`.

**Finding `cat`:**
The pattern `/???/???` matches files in `/bin/` with 3 letters.
Common matches: `awk`, `cat`, `cmp`...
Usually, `cat` is very early in the list, likely `$2` or `$3`.

---

### Result and proofs

First, let's list the files to find the flag name. We use the logic derived above (`$7` is likely `ls`).

```bash
_(){ $7& } && _ /???/??
```
*Note: I used `&` to run it in background/subshell to avoid hanging or errors if the command expects input.*

Output:
```
Broken@Shell$ _(){ $7& } && _ /???/??
Broken@Shell$ broken_shell.sh  this_is_the_flag_gg
```
We found the file: `this_is_the_flag_gg`.
It has 19 characters. So we can represent it as 19 question marks: `???????????????????`.

Now we need to read it using `cat`. `cat` is usually the 2nd or 3rd match for `/???/???`. I tried `$3`.

```bash
_(){ $3 ???????????????????& } && _ /???/???
```

Output:
```
Broken@Shell$ _(){ $3 ???????????????????& } && _ /???/???
Broken@Shell$ 'This file contains the flag. The problem is that it is not on the first line so you have to read the whole file to get it :)
HTB{*************************}
```

And just like that, we got another easy-peasy flag.

![flag proof](flag.png)

---

## Русский

[Перейти к английской версии](#english)

**Название -** Broken Shell

**Категория -** Misc

**Сложность -** Easy

**Ссылка -** https://app.hackthebox.com/challenges/Broken%2520Shell

---

## Краткое описание

И так нам дали описание: "We've built a secure sandbox environment that only allows specific symbols and numbers. It's designed to be inescapable—security at its best!"

Безопасность говорите да?)
Щас проверим.

Это задание на побег из ограниченной оболочки Bash (Jail). Нам разрешен очень маленький набор символов, и полностью запрещены буквы. Решение строится на использовании wildcard-символа `?` для подбора имен команд и использовании аргументов bash-функции для их запуска.

---

## Разведка (как я смотрел формат)

Я подключился и посмотрел на разрешенные символы:
`^[0-9${}/?"[:space:]:&>_=()]+$`

**Что у нас есть:**
*   Цифры: `0-9`
*   Пути: `/`
*   Переменные: `$` `{` `}`
*   **Самое главное:** `?` (Вопросительный знак).

**Чего у нас нет:**
*   Букв! Мы не можем написать `ls`, `cat`, `id` или `flag.txt`.
*   Звездочки `*` (классический wildcard).
*   Точки `.`

**В чем трюк?**
В Bash символ `?` является подстановочным знаком (wildcard), который означает **"любой одиночный символ"**.
Если мы не можем написать слово `cat` (3 буквы), мы можем написать `???` (3 знака), и оболочка попытается найти файл или команду, которая подходит под этот шаблон.

Если просто ввести `/???/??`, оболочка раскроет это во все подходящие файлы (например, `/bin/cp /bin/ls /bin/rm`...) и попытается запустить первый, передав остальные как аргументы. Это обычно приводит к ошибкам.

---

## Стратегия

Чтобы запустить конкретную команду, не зная точно, какой она идет по порядку, мы можем использовать **Bash-функцию**.

План такой:
1.  Определяем функцию с именем `_`.
2.  Передаем шаблон (например, `/???/??` для двухбуквенных бинарников в `/bin`) как аргумент этой функции.
3.  Оболочка раскрывает шаблон *до* запуска функции.
4.  Внутри функции `$1` станет первым совпадением, `$2` вторым и так далее.
5.  Мы можем перебирать аргументы (например, `$7`), пока не попадем в нужную команду (типа `ls` или `cat`).

**Ищем `ls`:**
Шаблон `/???/??` ищет файлы в `/bin/` из 2 букв.
Типичные совпадения по алфавиту:
1. `cp`
2. `dd`
3. `df`
4. `du`
5. `id`
6. `ln`
7. `ls`

Значит, внутри функции переменная `$7` должна указывать на `ls`.

**Ищем `cat`:**
Шаблон `/???/???` ищет файлы в `/bin/` из 3 букв.
Типичные совпадения: `awk`, `cat`, `cmp`...
Обычно `cat` идет в самом начале, где-то вторым или третьим (`$2` или `$3`).

---

## Результат

Сначала получим список файлов, чтобы узнать имя флага. Используем логику выше (что `$7` это скорее всего `ls`).

```bash
_(){ $7& } && _ /???/??
```

Результат:
```
Broken@Shell$ _(){ $7& } && _ /???/??
Broken@Shell$ broken_shell.sh  this_is_the_flag_gg
```

Файл найден: `this_is_the_flag_gg`.
В имени 19 символов. Значит, мы можем заменить его на 19 знаков вопроса: `???????????????????`.

А теперь просто получаем флаг (фух XD). Для чтения используем `cat`. Методом тыка я предположил, что это `$3` из набора трехбуквенных команд (`/???/???`).

```bash
_(){ $3 ???????????????????& } && _ /???/???
```

Результат:
```
Broken@Shell$ _(){ $3 ???????????????????& } && _ /???/???
Broken@Shell$ 'This file contains the flag. The problem is that it is not on the first line so you have to read the whole file to get it :)
HTB{*************************}
```

Вот и еще один флажочечек наш :)

![flag proof](flag.png)
