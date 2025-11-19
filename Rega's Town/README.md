[English](#english) · [Русский](#русский)

---

## English

**Name -** Rega's Town

**Category -** Reversing

**Difficulty -** Medium

**Link -** https://app.hackthebox.com/challenges/Rega's%2520Town

### Summary

The challenge provides a large 19MB executable. While the category is Reversing and the difficulty is Medium, the solution doesn't actually require complex assembly analysis. By simply running `strings` on the binary, we discover a series of Regular Expressions (Regex) that define the flag's structure. The solution involves treating these regexes as a logic puzzle to reconstruct the flag character by character, rather than reversing the code flow.

---

### Recon (Finding the Rules)

I started by throwing the massive 19MB file into IDA Pro. There was a ton of code, which seemed suspicious. So, I decided to check the `strings` window first to see if there was anything obvious.

And there it was. I found a list of specific Regular Expressions:

```regex
^.{33}$
(?:^[\x48][\x54][\x42]).*
^.{3}(\x7b).*(\x7d)$
^[[:upper:]]{3}.[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{4}[[:upper:]].{2}[[:upper:]].{3}[[:upper:]].{4}$
(?:.*\x5f.*)
(?:.[^0-9]*\d.*){5}
.{24}\x54.\x65.\x54.*
^.{4}[X-Z]\d._[A]\D\d.................[[:upper:]][n-x]{2}[n|c].$
.{11}_T[h|7]\d_[[:upper:]]\dn[a-h]_[O]\d_[[:alpha:]]{3}_.{5}
```

These look like validation rules. Instead of debugging, we can just satisfy these rules to build the flag.

---

### The Logic Puzzle (Building the Flag)

Let's break down the rules one by one to construct the string.

**1. Length & Wrapper**
*   `^.{33}$`: The flag is exactly 33 characters long.
*   `(?:^[\x48][\x54][\x42]).*`: Starts with ASCII 48, 54, 42 -> **HTB**.
*   `^.{3}(\x7b).*(\x7d)$`: 4th char is `{`, last is `}`.
*   **Current State:** `HTB{___________________________}`

**2. Capitalization & Keywords**
*   `^[[:upper:]]{3}.[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{4}[[:upper:]].{2}[[:upper:]].{3}[[:upper:]].{4}$`: This tells us specific positions must be Uppercase letters.
*   `.{24}\x54.\x65.\x54.*`: Positions 25, 27, 29 are `T`, `e`, `T`.
*   Putting this together with a common sentence structure (since it's a "Town"), it looks like "You Are The ... Of The Town".

**3. Specific Character Constraints**
*   `^.{4}[X-Z]\d._[A]\D\d...`:
    *   Pos 5: `[X-Z]`. "Y" fits.
    *   Pos 6: `\d` (digit). "0" fits (Leet speak for 'o').
    *   Pos 9: `[A]`. "A" fits.
    *   Pos 11: `\d`. "3" fits (Leet speak for 'e').
    *   Guess so far: `HTB{Y0u_Ar3_...}`

*   `.{11}_T[h|7]\d_[[:upper:]]\dn[a-h]_[O]\d_...`:
    *   Pos 13: `T`.
    *   Pos 14: `h` or `7`. "h" makes sense.
    *   Pos 15: `\d`. "3" makes sense ("Th3").
    *   Pos 17: `[[:upper:]]`. Start of the next word.
    *   Pos 18: `\d`.
    *   Pos 19: `n`.
    *   Pos 20: `[a-h]`.
    *   Pos 22: `[O]`.
    *   Pos 23: `\d`.

**4. The "Of" and "Gang/King" Problem**
My initial guess was `HTB{Y0u_Ar3_Th3_G4ng_Of_The_Town}`.
*   **Failure 1:** Rule `(?:.[^0-9]*\d.*){5}` requires exactly 5 groups of digits.
*   **Failure 2:** The segment `_[O]\d_` (Of) requires a digit at position 23. "f" is not a digit. In leet-speak, 'f' often becomes '7'. So "Of" becomes **O7**.

My second guess was `HTB{Y0u_Ar3_Th3_G4ng_O7_The_Town}`.
*   This also failed. Let's look at the word "G4ng".
*   The rule is `_[[:upper:]]\dn[a-h]_`.
*   `G4ng` fits the mask (G=Upper, 4=Digit, n=n, g=a-h).
*   However, considering the context "You Are The [Something] Of The Town", another strong candidate is "King".
*   In leet-speak: **K1ng**.
*   `K1ng` fits the mask: K (Upper), 1 (Digit), n, g (a-h).

**5. Final Check**
Let's test: `HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}`

*   **Length:** 33 chars. (Check)
*   **Digits:** 0, 3, 3, 1, 7. Total 5 digits. (Check)
*   **Regex Matches:** All patterns align.

---

### Result

I entered the constructed string, and it worked!

```
HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}
```

Honestly, this was a huge "WTF" moment. I'm not sure why this is rated Medium or why the solve count is low, considering you can just read the rules from `strings` and solve it like a crossword puzzle without reversing a single function. But hey, another easy flag for the collection.

![flag proof](flag.png)

---

## Русский

[Перейти к английской версии](#english)

**Название -** Rega's Town

**Категория -** Reversing

**Сложность -** Medium

**Ссылка -** https://app.hackthebox.com/challenges/Rega's%2520Town

---

## Краткое описание

Челендж предоставляет нам увесистый файл размером 19 МБ. Несмотря на то, что категория — Reversing, а сложность — Medium, решение вообще не требует глубокого анализа ассемблера. Просто запустив `strings` на бинарнике, мы находим серию регулярных выражений (Regex), которые описывают структуру флага. Решение сводится к логической задачке по сбору флага на основе этих правил, вместо реального реверса кода.

---

## Разведка (Поиск правил)

И так, для начала я зашел в IDA Pro и закинул туда файл аж на 19 МБ. Там куча кода, но давай заглянем в окно `strings` и посмотрим туда. И мы находим там кое-что интересное — список регулярных выражений:

```regex
^.{33}$
(?:^[\x48][\x54][\x42]).*
^.{3}(\x7b).*(\x7d)$
^[[:upper:]]{3}.[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{3}[[:upper:]].{4}[[:upper:]].{2}[[:upper:]].{3}[[:upper:]].{4}$
(?:.*\x5f.*)
(?:.[^0-9]*\d.*){5}
.{24}\x54.\x65.\x54.*
^.{4}[X-Z]\d._[A]\D\d.................[[:upper:]][n-x]{2}[n|c].$
.{11}_T[h|7]\d_[[:upper:]]\dn[a-h]_[O]\d_[[:alpha:]]{3}_.{5}
```

Эти строки легко читаются как правила, и на базе этих правил можно на изи собрать флаг.

---

## Логическая задача (Сборка флага)

Разберем правила по порядку, чтобы восстановить строку.

**1. Длина и обертка**
*   `^.{33}$`: Флаг длиной ровно 33 символа.
*   `(?:^[\x48][\x54][\x42]).*`: Начало с ASCII 48, 54, 42 -> **HTB**.
*   `^.{3}(\x7b).*(\x7d)$`: 4-й символ `{`, последний `}`.
*   **Итог:** `HTB{___________________________}`

**2. Заглавные буквы и структура**
*   `^[[:upper:]]{3}.[[:upper:]].{3}...`: Это выражение задает жесткую структуру заглавных букв.
*   `.{24}\x54.\x65.\x54.*`: На позициях 25, 27, 29 стоят `T`, `e`, `T`.
*   Сопоставляя это с английским языком, похоже на фразу "You Are The ... Of The Town".

**3. Конкретные символы**
*   `^.{4}[X-Z]\d._[A]\D\d...`:
    *   Поз. 5: `[X-Z]`. Подходит "Y".
    *   Поз. 6: `\d` (цифра). Подходит "0" (Y0u).
    *   Поз. 9: `[A]`. Подходит "A".
    *   Поз. 11: `\d`. Подходит "3" (Ar3).
    *   Пока имеем: `HTB{Y0u_Ar3_...}`

*   `.{11}_T[h|7]\d_[[:upper:]]\dn[a-h]_[O]\d_...`:
    *   Поз. 13-15: `T`, `h` или `7`, `\d`. Логично, что это "Th3".
    *   Поз. 22-23: `[O]` и `\d`. Начало слова "Of", но нужна цифра.

**4. Проблема "Of" и "Gang/King"**
Моя первая догадка была: `HTB{Y0u_Ar3_Th3_G4ng_Of_The_Town}`. Неудачно.

Глянем на регулярку №9: `_[O]\d_` (слово из двух букв).
*   Там должна быть цифра на 23-й позиции. В моем варианте там `f`.
*   В leet-speak `f` часто заменяется на `7`. Значит, **O7**.
*   Также правило `(?:.[^0-9]*\d.*){5}` требует 5 групп цифр.

Вторая догадка: `HTB{Y0u_Ar3_Th3_G4ng_O7_The_Town}`. Снова мимо.
Посмотрим подробнее на слово "G4ng".
*   Правило: `_[[:upper:]]\dn[a-h]_`.
*   Разберем посимвольно (позиции 17-20): Заглавная, Цифра, буква 'n', буква a-h.
*   Слово должно подходить по смыслу к фразе "You Are The ... Of The Town".
*   Если "Gang" не подошел, пробуем "King". В leet-speak -> **K1ng**.
*   K (Upper) - ОК. 1 (Digit) - ОК. n - ОК. g (a-h) - ОК.

**5. Финальная проверка**
Пробуем: `HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}`

*   **Цифры:** 0 (Y0u), 3 (Ar3), 3 (Th3), 1 (K1ng), 7 (O7). Итого 5 штук. Правило выполнено.
*   Все маски совпадают.

---

## Результат

И... Оно сработало... 0_0

```
HTB{Y0u_Ar3_Th3_K1ng_O7_The_Town}
```

Честно, я хз, как это допустили в HTB на уровень Medium. Тут 100% возникает "WTF момент", потому что задачу можно решить как кроссворд, просто читая строки, даже не открывая декомпилятор. Но, получается еще один изичный флаг в копилку.

![flag proof](flag.png)
