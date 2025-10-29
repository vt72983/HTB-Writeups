# HTB Write-up: Nostalgia

Link - https://app.hackthebox.com/challenges/nostalgia

[English](#english) · [Русский](#русский)

---

## English

**Category:** GamePwn
**Difficulty:** Medium

### Summary

The challenge provides a Game Boy Advance (GBA) ROM file named `Nostalgia.gba`. When run in an emulator, the game presents a screen asking for a cheat code. The goal is to reverse engineer the ROM, find the logic that validates the cheat code, and patch the binary to bypass this check and reveal the flag.

The solution involves loading the ROM into IDA Pro, identifying the conditional branch responsible for the cheat code check, and modifying it to always treat the input as correct.

---

### Recon (how I inspected the format)

I was given two files: `instructions.txt` and `Nostalgia.gba`. The instructions confirmed my suspicion: run the ROM in a GBA emulator.

> Open the rom in a GBA emulator of your choice. Select is to clear the input on the screen and start is to submit it, if the cheatcode is wrong, nothing will happen.

I downloaded a GBA emulator - mGBA and launched the ROM. As expected, it was a simple input screen. Entering a random code and pressing Start did nothing, confirming the instructions.

Next, I opened `Nostalgia.gba` in IDA Pro. It's crucial to set the correct processor architecture for proper disassembly. I manually specified **ARM:LE:32:v4T** (ARM, Little-Endian, 32-bit, v4T instruction set). This allowed me to analyze the code correctly.

---

### Strategy

My plan was to patch the binary to bypass the cheat code validation.

1.  Load the ROM into IDA Pro with the correct ARM architecture settings.
2.  Identify the main game loop or the function responsible for handling user input and checking the cheat code.
3.  Locate the specific conditional branch instruction (e.g., `BNE` - Branch if Not Equal) that determines whether the entered code is correct or not.
4.  Modify this instruction to alter the program flow. The easiest way is often to invert the condition (e.g., change `BNE` to `BEQ` - Branch if Equal) so that any incorrect code is treated as the correct one.
5.  Apply the patch directly to the `.gba` file using IDA's patching functionality.
6.  Run the newly patched ROM in the emulator, enter any code, and get the flag.

---

### Patch evolution (how I iterated and fixed bugs)

**First attempt — breaking the game**

After some analysis in IDA, I identified `sub_15A8` as the main game loop and found the key instruction for the check at address `0x1638`:

```assembly
ROM:00001638   BNE             loc_161E
```

This instruction branches if the input does *not* match the correct cheat code. My first idea was to neutralize this check by replacing the instruction with a `NOP` (No Operation).

*   Original bytes: `F1 D1 80 23 58 4A DB 04 1A 80 08 23 C0 21 5B 44`
*   Attempted patch: `00 BF 80 23 58 4A DB 04 1A 80 08 23 C0 21 5B 44` (where `00 BF` is a `NOP` in Thumb mode)

**Result:** This broke the game. Simply removing the branch disrupted the program's logic flow more than I expected. I reverted the patch.

**Second attempt — the successful patch**

Instead of removing the branch, I decided to invert its logic. The original instruction was `BNE` (Branch if Not Equal), which has the opcode `D1`. The opposite instruction is `BEQ` (Branch if Equal), with opcode `D0`. By changing `BNE` to `BEQ`, an incorrect code (which results in a "not equal" state) would now cause the program to follow the path originally intended for the correct code.

I made a very subtle, one-byte change:

*   Original bytes: `F1 D1`
*   Patched bytes: `F1 D0`

I applied this change using IDA's patching feature ("Edit" -> "Patch program" -> "Apply patches to input file"). I saved the modified `Nostalgia.gba`.

---

### Final patch (short)

*   **File:** `Nostalgia.gba`
*   **Address:** `0x1638`
*   **Original Bytes:** `F1 D1` (Corresponds to `BNE`)
*   **Patched Bytes:** `F1 D0` (Corresponds to `BEQ`)
*   **Description:** This change inverts the cheat code validation logic, making any incorrect input pass the check.

---

### Result and proofs

After applying the final patch, I opened the modified ROM in the emulator. I pressed Start, and... success! A flag appeared on the screen, which I retyped XD

![flag proof](1.jpg)

---

## Русский

[Перейти к английской версии](#english)

**Категория:** GamePwn
**Сложность:** Medium

---

## Краткое описание

В этом задании нам предоставляется ROM-файл для Game Boy Advance (GBA) под названием `Nostalgia.gba`. При запуске в эмуляторе игра просит ввести чит-код. Цель — провести реверс-инжиниринг ROM-файла, найти логику проверки чит-кода и пропатчить бинарник, чтобы обойти эту проверку и получить флаг.

Решение заключается в загрузке ROM в IDA Pro, определении условного перехода, отвечающего за проверку кода, и его изменении таким образом, чтобы любой ввод считался правильным.

---

## Разведка (как я смотрел формат)

Мне предоставили два файла: `instructions.txt` и `Nostalgia.gba`. Инструкции подтвердили мои догадки: нужно запустить ROM в эмуляторе GBA.

> Откройте ROM в любом эмуляторе GBA. Кнопка Select очищает ввод, Start — отправляет его. Если чит-код неверный, ничего не произойдет.

Я скачал эмулятор mGBA и запустил ROM. Как и ожидалось, на экране было простое поле для ввода. Ввод случайного кода и нажатие Start ничего не давали, что соответствовало инструкции.

Далее я открыл `Nostalgia.gba` в IDA Pro. Для корректной дизассемблирования крайне важно было указать правильную архитектуру процессора. Я вручную выставил **ARM:LE:32:v4T** (ARM, Little-Endian, 32-бит, набор инструкций v4T). Это позволило мне правильно анализировать код.

---

## Стратегия

Мой план состоял в том, чтобы пропатчить бинарник для обхода проверки чит-кода.

1.  Загрузить ROM в IDA Pro с правильными настройками архитектуры ARM.
2.  Найти главный игровой цикл или функцию, ответственную за обработку пользовательского ввода и проверку кода.
3.  Обнаружить конкретную инструкцию условного перехода (например, `BNE` — Branch if Not Equal), которая определяет, верен ли введенный код.
4.  Изменить эту инструкцию, чтобы поменять логику программы. Самый простой способ — инвертировать условие (например, изменить `BNE` на `BEQ` — Branch if Equal), чтобы любой неверный код считался правильным.
5.  Применить патч непосредственно к файлу `.gba` с помощью функционала IDA.
6.  Запустить пропатченный ROM в эмуляторе, ввести любой код и получить флаг.

---

## Эволюция патчей (как я думал и исправлял ошибки)

### Первая попытка — сломать игру

После анализа в IDA я определил `sub_15A8` как основной игровой цикл и нашел ключевую инструкцию для проверки по адресу `0x1638`:

```assembly
ROM:00001638   BNE             loc_161E
```

Эта инструкция выполняет переход, если введенный код *не совпадает* с правильным. Моей первой идеей было нейтрализовать эту проверку, заменив инструкцию на `NOP` (No Operation).

*   Оригинальные байты: `F1 D1 80 23 58 4A DB 04 1A 80 08 23 C0 21 5B 44`
*   Попытка патча: `00 BF 80 23 58 4A DB 04 1A 80 08 23 C0 21 5B 44` (где `00 BF` — это `NOP` в режиме Thumb)

**Результат:** Это сломало игру. Простое удаление перехода нарушило логику программы сильнее, чем я ожидал. Я откатил изменения.

### Вторая попытка — успешный патч

Вместо удаления перехода я решил инвертировать его логику. Исходная инструкция была `BNE` (Branch if Not Equal), опкод которой `D1`. Противоположная ей инструкция — `BEQ` (Branch if Equal) с опкодом `D0`. Изменив `BNE` на `BEQ`, я добился того, что неверный код (который приводит к состоянию "не равен") теперь заставлял программу следовать по пути, изначально предназначенному для правильного кода.

Я внес очень маленькое, однобайтное изменение:

*   Оригинальные байты: `F1 D1`
*   Пропатченные байты: `F1 D0`

Я применил это изменение через IDA ("Edit" -> "Patch program" -> "Apply patches to input file") и сохранил измененный `Nostalgia.gba`.

---

## Итоговый патч (коротко)

*   **Файл:** `Nostalgia.gba`
*   **Адрес:** `0x1638`
*   **Оригинальные байты:** `F1 D1` (Соответствует `BNE`)
*   **Пропатченные байты:** `F1 D0` (Соответствует `BEQ`)
*   **Описание:** Это изменение инвертирует логику проверки чит-кода, в результате чего любой неверный ввод проходит проверку.

---

## Результат

После применения финального патча я открыл измененный ROM в эмуляторе. Я нажал Start, и... успех! На экране появился флаг, который я перепечатал XD

![flag proof](1.jpg)
