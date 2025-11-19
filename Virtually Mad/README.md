[English](#english) · [Русский](#русский)

---

## English

**Name -** Virtually Mad

**Category -** Reversing

**Difficulty -** Medium

**Link -** https://app.hackthebox.com/challenges/Virtually%2520Mad

### Summary

We are provided with a small executable `virtually.mad`. It implements a simple custom Virtual Machine (VM). The `main` function reads a hexadecimal string, parses it into 32-bit instructions, and executes them. The goal is to provide exactly 5 instructions that manipulate the VM's registers to reach a specific state, bypassing input constraints along the way.

---

### Recon (VM Architecture)

The binary is small (15KB). Opening it in IDA reveals the internal logic:

**Registers:**
The VM maintains an array `v8` representing the state:
*   `v8[0]`: Register A
*   `v8[1]`: Register B
*   `v8[2]`: Register C
*   `v8[3]`: Register D
*   `v8[12]`: Flags (Bit `0x10000000` is set if a comparison is true).

**Instruction Format (32-bit):**
The input string is split into 8-character blocks. Each block represents an instruction:
*   **Bits 24-31:** Opcode (Operation Code).
*   **Bits 20-23:** Validation Bit (Must be `1`).
*   **Bits 16-19:** Destination Register Index (0=A, 1=B, 2=C, 3=D).
*   **Bits 12-15:** Operand Type (0 = Immediate Value, 1 = Register Source).
*   **Bits 0-11:** Value. (If Type is Register, the Source Index is in bits 8-11 of this field).

**Constraints:**
1.  There is a global check: The immediate value (bits 0-11) must not exceed `0x100`.
2.  We must execute exactly 5 instructions.

**Winning Condition:**
At the end of execution, the state must be:
```c
if ( *v8 == 512 &&          // Register A == 512 (0x200)
     v8[1] == -1 &&         // Register B == -1
     v8[2] == -1 &&         // Register C == -1
     !v8[3] &&              // Register D == 0
     v8[12] == 0x10000000 && // Flag set
     v7 == 5 )              // Exactly 5 steps
```

---

### Strategy & Assembly

We need to construct 5 instructions to satisfy the condition `A=512, B=-1, C=-1, D=0, Flag=OK`.

**Instruction 1 & 2: Fix Register A (Target: 512)**
*   We need 512.
*   Constraint: Max immediate value is `0x100` (256).
*   Solution: Add 256 twice.
*   **Opcode:** `0x02` (ADD). **Dest:** `0` (A). **Val:** `0x100`.
*   Hex: `02100100` (Repeated twice).

**Instruction 3: Fix Register B (Target: -1)**
*   Initial value is 0.
*   Solution: Subtract 1. `0 - 1 = -1` (integer underflow).
*   **Opcode:** `0x03` (SUB). **Dest:** `1` (B). **Val:** `0x001`.
*   Hex: `03110001`.

**Instruction 4: Fix Register C (Target: -1)**
*   Problem: We cannot use `MOV C, -1` (Immediate) because `0xFFFFFFFF` is larger than the allowed `0x100`.
*   Solution: Register B already holds `-1`. Copy B to C using Register Mode.
*   **Opcode:** `0x01` (MOV). **Dest:** `2` (C). **Type:** `1` (Register).
*   **Val:** We need source Register B (Index 1). The source index is stored in bits 8-11. So we set bit 8. Value becomes `0x100`.
*   Hex: `01121100`.

**Instruction 5: Fix Flags (Target: 0x10000000)**
*   Register D is already 0. We need to set the flag.
*   Solution: Compare D with 0.
*   **Opcode:** `0x04` (CMP). **Dest:** `3` (D). **Val:** `0`.
*   Hex: `04130000`.

---

### Result

Concatenating the hex codes gives us the input string:

`02100100` + `02100100` + `03110001` + `01121100` + `04130000`

Input:
`0210010002100100031100010112110004130000`

Flag:
`HTB{0210010002100100031100010112110004130000}`

![flag](flag.png)

---

## Русский

[Перейти к английской версии](#english)

**Название -** Virtually Mad

**Категория -** Reversing

**Сложность -** Medium

**Ссылка -** https://app.hackthebox.com/challenges/Virtually%2520Mad

---

## Краткое описание

И так, нам дали файл `virtually.mad` весом 15 кб, который легко открылся в IDA Pro. Это реализация простой виртуальной машины (VM). Функция `main` считывает шестнадцатеричную строку, разбивает её на блоки по 8 символов (каждый блок — это 32-битная инструкция) и выполняет их. Задача — составить правильную последовательность команд.

---

## Разведка (Анализ VM)

**Состояние VM (sub_11C9):**
ВМ хранит регистры и флаги в массиве `v8`:
*   `v8[0]`: Регистр A
*   `v8[1]`: Регистр B
*   `v8[2]`: Регистр C
*   `v8[3]`: Регистр D
*   `v8[12]`: Флаги (бит `0x10000000` устанавливается при успешном сравнении).

**Формат инструкции (32 бита):**
Каждые 8 hex-символов парсятся в число.
*   Биты 24-31: Опкод.
*   Биты 20-23: Бит валидации (должен быть `1`).
*   Биты 16-19: Индекс целевого регистра (0=A, 1=B, 2=C, 3=D).
*   Биты 12-15: Тип операнда (0 = Число, 1 = Регистр).
*   Биты 0-11: Значение. (Если тип "Регистр", то индекс источника берется из битов 8-11 этого поля).

**Ограничения и Цель:**
В `main` есть проверка: если значение операнда (биты 0-11) больше `0x100`, инструкция пропускается.

Чтобы получить флаг, нужно выполнить ровно 5 инструкций и привести регистры в такое состояние:
*   `A == 512` (0x200)
*   `B == -1`
*   `C == -1`
*   `D == 0`
*   Флаг `0x10000000` установлен.

---

## Решение (Сборка инструкций)

Нужно составить 5 инструкций. Погнали собирать байткод.

**Инструкция 1 и 2 (Цель: A = 512)**
Нам нужно получить в A число 512. Но лимит значения — `0x100` (256).
*   Решение: `ADD A, 0x100` и еще раз `ADD A, 0x100`.
*   Сборка: Опкод 02, Валидность 1, Регистр 0 (A), Значение 100.
*   Hex: `02100100` (дважды).

**Инструкция 3 (Цель: B = -1)**
Изначально там 0.
*   Решение: `SUB B, 1` (0 - 1 = -1).
*   Сборка: Опкод 03, Регистр 1 (B), Значение 001.
*   Hex: `03110001`.

**Инструкция 4 (Цель: C = -1)**
Мы не можем сделать `MOV C, -1`, так как `-1` (0xFFFFFFFF) больше лимита `0x100`.
*   Решение: Скопировать значение из регистра B (где уже лежит -1). `MOV C, B`.
*   Сборка: Опкод 01, Регистр 2 (C), Тип 1 (Регистр).
*   Значение: Чтобы указать источник B (индекс 1), нужно положить 1 в биты 8-11. Это число `0x100`.
*   Hex: `01121100`.

**Инструкция 5 (Цель: Флаги)**
Нужно установить флаг успешного сравнения. В D сейчас 0.
*   Решение: `CMP D, 0`.
*   Сборка: Опкод 04, Регистр 3 (D), Значение 0.
*   Hex: `04130000`.

---

## Результат

Соединяем полученные hex-коды в одну строку:
`02100100` `02100100` `03110001` `01121100` `04130000`

Входная строка для программы:
`0210010002100100031100010112110004130000`

И наш флаг (он просто оборачивает ввод):
`HTB{0210010002100100031100010112110004130000}`

Еще один изичный флаг. =)
![flag](flag.png)
