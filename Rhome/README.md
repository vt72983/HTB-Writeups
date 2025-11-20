[English](#english) · [Русский](#русский)

---

## English

**Name -** Rhome

**Category -** Crypto

**Difficulty -** Easy

**Link -** https://app.hackthebox.com/challenges/Rhome

### Summary

The challenge description says, "I received this lovely letter but the sender put a seal on it. She said that can be opened only at our place, Rhome." We are given a `server.py` script that implements a Diffie-Hellman key exchange protocol. The core vulnerability lies in the parameter generation, specifically the generator `g`, which belongs to a very small subgroup. This allows us to efficiently solve the discrete logarithm problem, recover the shared secret, and decrypt the flag, which is encrypted with AES. This is a classic example of a small subgroup confinement attack.

---

### Recon (how I inspected the format)

I was given the `server.py` file, so the first step was to find a vulnerability in the Python code. The script implements a Diffie-Hellman (DH) key exchange, and then uses the resulting shared secret to encrypt the flag with AES. A closer look at the parameter generation in the `gen_params` method reveals the flaw:

*   **Choice of p:** `p` is a large prime, the modulus for all calculations. It's generated using the formula `p = 2 * q * r + 1`, where `q` is a 42-bit prime and `r` is a 512-bit prime. This structure makes `p` a "safe prime," which ensures that the order of the multiplicative group Z_p* is `p-1 = 2*q*r`.
*   **Choice of g:** `g` is the subgroup generator. It's calculated as `g = pow(h, 2 * r, p)`, where `h` is a random 42-bit prime.

The key vulnerability is in how `g` is generated. Let's determine the order of element `g` in the group. The order of an element must divide the order of the group, `p-1`.

Let's check `g` raised to the power of `q`:
`g^q = (h^(2*r))^q = h^(2*r*q) (mod p)`
Since `p = 2*q*r + 1`, we have `p-1 = 2*q*r`.
Therefore, `g^q = h^(p-1) (mod p)`.

According to Fermat's Little Theorem, for any `h` not divisible by `p`, `h^(p-1) ≡ 1 (mod p)`.
Thus, `g^q ≡ 1 (mod p)`.

This means the order of `g` divides `q`. Since `q` is a prime number and the code checks that `g != 1`, the order of `g` is exactly `q`.

The number `q` is a 42-bit prime. This is a very small number for cryptography. The Diffie-Hellman protocol operates in a subgroup of order `q`, not in the entire group Z_p*. Since the public keys `A = g^a (mod p)` and `B = g^b (mod p)` are based on `g`, they also belong to this small subgroup of order `q`. This means the discrete logarithm problem—finding `x` from `g^x = A (mod p)`—becomes easily solvable. We don't need to find the full secret key `a`; it's enough to find `a' = a mod q`.
`A = g^a = g^(k*q + a') = (g^q)^k * g^(a') = 1^k * g^(a') = g^(a') (mod p)`.

We can find `a'` in a reasonable amount of time because `q` is only 42 bits long. We can use algorithms like the Baby-step giant-step or Pollard's rho algorithm for this. Once we find `a'`, we can compute the shared secret `ss`:
`ss = B^a = B^(a') (mod p)`
With `ss`, we can generate the AES key and decrypt the flag.

---

### Strategy

My strategy was to exploit this small subgroup vulnerability:
1.  Connect to the server to receive the public DH parameters (`p`, `g`, `A`, `B`) and the encrypted flag.
2.  Disconnect and perform offline calculations.
3.  Factor `(p-1)/2` to find the small prime `q`, which is the order of our subgroup.
4.  Solve the discrete logarithm problem `A = g^(a') (mod p)` to find `a'` using the Baby-step giant-step algorithm within the subgroup of order `q`.
5.  Calculate the shared secret `ss = pow(B, a', p)`.
6.  Derive the AES key from `ss` using `sha256(long_to_bytes(ss)).digest()[:16]`.
7.  Decrypt the flag using AES in ECB mode.

---

### Script and Patching Evolution (how I iterated and fixed bugs)

The attack path was clear from the mathematical analysis of the protocol. The main task was to implement the solution in a script. I wrote a Python script to automate the entire process.
There were no significant bugs or iterations. The vulnerability was obvious, and the script was built to directly implement the attack strategy. It worked on the first try.

```python
import math
from hashlib import sha256
from pwn import *
from sympy import factorint
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = "1.1.1.1" # The IP was changed
PORT = 365 # The PORT was changed

def baby_step_giant_step(g, h, p, order):
    m = math.isqrt(order) + 1
    baby_steps = {}
    val = 1
    for j in range(m):
        baby_steps[val] = j
        val = (val * g) % p
    g_inv_m = pow(g, -m, p)
    giant_step_val = h
    for i in range(m):
        if giant_step_val in baby_steps:
            j = baby_steps[giant_step_val]
            return i * m + j
        giant_step_val = (giant_step_val * g_inv_m) % p
    return None

def solve():
    conn = remote(HOST, PORT)
    log.info(f"Connected to {HOST}:{PORT}")
    conn.sendlineafter(b"> ", b"1")
    conn.recvuntil(b"p = ")
    p = int(conn.recvline().strip())
    conn.recvuntil(b"g = ")
    g = int(conn.recvline().strip())
    conn.recvuntil(b"A = ")
    A = int(conn.recvline().strip())
    conn.recvuntil(b"B = ")
    B = int(conn.recvline().strip())
    log.success("DH parameters received:")
    log.info(f"p = {p}")
    log.info(f"g = {g}")
    log.info(f"A = {A}")
    log.info(f"B = {B}")
    conn.sendlineafter(b"> ", b"3")
    conn.recvuntil(b"encrypted = ")
    encrypted_hex = conn.recvline().strip().decode()
    log.success(f"Encrypted flag received: {encrypted_hex}")

    # Offline
    conn.close()

    log.info("Factoring (p-1)/2 to find the small order q...")
    n_to_factor = (p - 1) // 2
    factors = factorint(n_to_factor)
    q = min(factors.keys())
    log.success(f"Found small subgroup order: q = {q} ({q.bit_length()} bits)")
    log.info("Solving discrete logarithm (BSGS) to find a'...")
    a_prime = baby_step_giant_step(g, A, p, q)
    if a_prime is None:
        log.failure("Failed to find the private key. Attack failed.")
        return    
    log.success(f"Found private key (mod q): a' = {a_prime}")
    log.info("Calculating shared secret ss = B^a' (mod p)...")
    ss = pow(B, a_prime, p)
    log.success(f"Shared secret (ss): {ss}")
    log.info("Generating AES key from the shared secret...")
    key = sha256(long_to_bytes(ss)).digest()[:16]
    log.success(f"AES key (hex): {key.hex()}")
    log.info("Decrypting the message...")
    ct_bytes = bytes.fromhex(encrypted_hex)
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted_padded = cipher.decrypt(ct_bytes)
        flag = unpad(decrypted_padded, AES.block_size)
        log.success("FLAG FOUND!")
        print(f"\n>>>> {flag.decode()} <<<<\n")
    except ValueError as e:
        log.failure(f"Error?! {e}")

if __name__ == "__main__":
    solve()
```

---

### Result and proofs

Running the script gives us the flag.

```
┌──(vt729830㉿vt72983)-[~/5/2]
└─$ python3 1.py
[+] Opening connection to 1.1.1.1 on port 365: Done
[*] Connected to 1.1.1.1:365
[+] DH parameters received:
[*] p = 41732161398932248164224365390290167693052060766917039547169273746119699642315160432419607337558558447889278771575005714928620559960011390391526147741337629491770812987
[*] g = 14535447338562910308259563339325501271148303404990990031923212222703113628775850990430253965189733765292067080711916877687755833505840760878181110639631652286285736982
[*] A = 38976280391449531768314772990421498991917053535087208865553215709680425102010994330317335742540694912953180833715500058491720374320534940374522142410039134744139723382
[*] B = 24475136230532341842381540842349302565948004172332524877917239167018983718815043435003130288064092608128805660370902404962573731318602521116808273446327732411359980665
[+] Encrypted flag received: 11f73f707fa4f316a8b4477e6322548efb65033f026e2e328d9082d5eb30eb17
[*] Closed connection to 94.237.49.209 port 30758
[*] Factoring (p-1)/2 to find the small order q...
[+] Found small subgroup order: q = 2369232254507 (42 bits)
[*] Solving discrete logarithm (BSGS) to find a'...
[+] Found private key (mod q): a' = 145570788735
[*] Calculating shared secret ss = B^a' (mod p)...
[+] Shared secret (ss): 35827136107574915737325403457520305004533507692326153627111347094308856758069209244253809347133836716579730234767641889938957025052005291636101772156453557225150690771
[*] Generating AES key from the shared secret...
[+] AES key (hex): 7197fd1e9bd9ff1c295549190e0de742
[*] Decrypting the message...
[+] FLAG FOUND!

>>>> HTB{***************} <<<<
```
And just like that, another flag was successfully captured.

![flag proof](flag.png)

---

## Русский

[Go to English version](#english)

**Название -** Rhome

**Категория -** Crypto

**Сложность -** Easy

**Ссылка -** https://app.hackthebox.com/challenges/Rhome

---

## Краткое описание

Описание челенджа гласит: «I received this lovely letter but the sender put a seal on it. She said that can be opened only at our place, Rhome.» Нам дали файл `server.py`, который реализует протокол обмена ключами Диффи-Хеллмана. Ключевая уязвимость заключается в генерации параметров, а именно генератора `g`, который принадлежит очень маленькой подгруппе. Это позволяет нам эффективно решить задачу дискретного логарифмирования, восстановить общий секрет и расшифровать флаг, зашифрованный с помощью AES. Это классический пример атаки на малую подгруппу (small subgroup confinement attack).

---

## Разведка (как я смотрел формат)

Нам дали `server.py`, поэтому первым делом нужно было найти уязвимость в коде. Скрипт реализует протокол обмена ключами Диффи-Хеллмана (Diffie-Hellman, DH), а затем использует полученный общий секрет для шифрования флага с помощью AES. Давайте внимательно посмотрим на генерацию параметров в методе `gen_params`:

*   **Выбор p:** `p` — это большое простое число, модуль для всех вычислений. Оно генерируется по формуле `p = 2 * q * r + 1`, где `q` — 42-битное простое число, а `r` — 512-битное простое число. Такая конструкция `p` называется "безопасным простым числом" (safe prime), и она гарантирует, что порядок мультипликативной группы Z_p* равен `p-1 = 2*q*r`.
*   **Выбор g:** `g` — это генератор подгруппы. Он вычисляется как `g = pow(h, 2 * r, p)`, где `h` — случайное 42-битное простое число.

Ключевая уязвимость заключается в способе генерации `g`. Давайте определим порядок (order) элемента `g` в группе. Порядок элемента должен делить порядок группы `p-1`.
Проверим, чему равно `g` в степени `q`:
`g^q = (h^(2*r))^q = h^(2*r*q) (mod p)`
Поскольку `p = 2*q*r + 1`, то `p-1 = 2*q*r`.
Следовательно, `g^q = h^(p-1) (mod p)`.

Согласно Малой теореме Ферма, для любого `h`, не делящегося на `p`, `h^(p-1) ≡ 1 (mod p)`.
Таким образом, `g^q ≡ 1 (mod p)`.

Это означает, что порядок `g` делит `q`. Так как `q` — простое число, а код проверяет, что `g != 1`, то порядок `g` в точности равен `q`.

Число `q` — это 42-битное простое. Это очень маленькое число для криптографии. Протокол Диффи-Хеллмана работает в подгруппе порядка `q`, а не во всей группе Z_p*. Поскольку открытые ключи `A = g^a (mod p)` и `B = g^b (mod p)` вычисляются на основе `g`, они также принадлежат этой маленькой подгруппе порядка `q`. Это означает, что задача дискретного логарифмирования, т.е. нахождение `x` из `g^x = A (mod p)`, становится легко решаемой. Нам не нужно искать полный секретный ключ `a`, достаточно найти `a' = a mod q`.
`A = g^a = g^(k*q + a') = (g^q)^k * g^(a') = 1^k * g^(a') = g^(a') (mod p)`.

Мы можем найти `a'` за разумное время, так как `q` всего лишь 42-битное. Для этого можно использовать алгоритмы, такие как "Шаг младенца — шаг великана" (Baby-step giant-step) или ρ-алгоритм По́лларда. После того как мы найдем `a'`, мы можем вычислить общий секрет `ss`:
`ss = B^a = B^(a') (mod p)`
Получив `ss`, мы можем сгенерировать ключ AES и расшифровать флаг.

---

## Стратегия

Моя стратегия заключалась в эксплуатации уязвимости малой подгруппы:
1.  Подключиться к серверу, чтобы получить публичные параметры DH (`p`, `g`, `A`, `B`) и зашифрованный флаг.
2.  Отключиться и выполнить вычисления оффлайн.
3.  Факторизовать `(p-1)/2`, чтобы найти малое простое число `q`, которое является порядком нашей подгруппы.
4.  Решить задачу дискретного логарифмирования `A = g^(a') (mod p)`, чтобы найти `a'` с помощью алгоритма "Шаг младенца — шаг великана" в подгруппе порядка `q`.
5.  Вычислить общий секрет `ss = pow(B, a', p)`.
6.  Получить ключ AES из `ss` с помощью `sha256(long_to_bytes(ss)).digest()[:16]`.
7.  Расшифровать флаг, используя AES в режиме ECB.

---

## Изменения скриптов и патчинга (как я думал и исправлял ошибки)

План атаки был очевиден после математического анализа протокола. Основная задача заключалась в реализации решения в виде скрипта. Я написал скрипт на Python для автоматизации всего процесса.
Значительных багов или итераций не потребовалось. Уязвимость была ясна, и скрипт был написан для прямой реализации стратегии атаки. Он сработал с первой попытки.

```python
import math
from hashlib import sha256
from pwn import *
from sympy import factorint
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = "1.1.1.1" # IP был изменен
PORT = 365 # PORT был изменен

def baby_step_giant_step(g, h, p, order):
    m = math.isqrt(order) + 1
    baby_steps = {}
    val = 1
    for j in range(m):
        baby_steps[val] = j
        val = (val * g) % p
    g_inv_m = pow(g, -m, p)
    giant_step_val = h
    for i in range(m):
        if giant_step_val in baby_steps:
            j = baby_steps[giant_step_val]
            return i * m + j
        giant_step_val = (giant_step_val * g_inv_m) % p
    return None

def solve():
    conn = remote(HOST, PORT)
    log.info(f"Подключено к {HOST}:{PORT}")
    conn.sendlineafter(b"> ", b"1")
    conn.recvuntil(b"p = ")
    p = int(conn.recvline().strip())
    conn.recvuntil(b"g = ")
    g = int(conn.recvline().strip())
    conn.recvuntil(b"A = ")
    A = int(conn.recvline().strip())
    conn.recvuntil(b"B = ")
    B = int(conn.recvline().strip())
    log.success("Параметры DH получены:")
    log.info(f"p = {p}")
    log.info(f"g = {g}")
    log.info(f"A = {A}")
    log.info(f"B = {B}")
    conn.sendlineafter(b"> ", b"3")
    conn.recvuntil(b"encrypted = ")
    encrypted_hex = conn.recvline().strip().decode()
    log.success(f"Зашифрованный флаг получен: {encrypted_hex}")

    # оффлайн
    conn.close()

    log.info("Факторизуем (p-1)/2 для поиска малого порядка q...")
    n_to_factor = (p - 1) // 2
    factors = factorint(n_to_factor)
    q = min(factors.keys())
    log.success(f"Найден порядок малой подгруппы: q = {q} ({q.bit_length()} бит)")
    log.info("Решаем дискретный логарифм (BSGS) для нахождения a'...")
    a_prime = baby_step_giant_step(g, A, p, q)
    if a_prime is None:
        log.failure("Не удалось найти приватный ключ. Атака провалилась.")
        return    
    log.success(f"Найден приватный ключ (mod q): a' = {a_prime}")
    log.info("Вычисляем общий секрет ss = B^a' (mod p)...")
    ss = pow(B, a_prime, p)
    log.success(f"Общий секрет (ss): {ss}")
    log.info("Генерируем ключ AES из общего секрета...")
    key = sha256(long_to_bytes(ss)).digest()[:16]
    log.success(f"Ключ AES (hex): {key.hex()}")
    log.info("Расшифровываем сообщение...")
    ct_bytes = bytes.fromhex(encrypted_hex)
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decrypted_padded = cipher.decrypt(ct_bytes)
        flag = unpad(decrypted_padded, AES.block_size)
        log.success("ФЛАГ НАЙДЕН!")
        print(f"\n>>>> {flag.decode()} <<<<\n")
    except ValueError as e:
        log.failure(f"Ошибка?! {e}")
if __name__ == "__main__":
    solve()
```

---

## Результат

Запуск скрипта дает нам флаг.

```
┌──(vt729830㉿vt72983)-[~/5/2]
└─$ python3 1.py
[+] Opening connection to 1.1.1.1 on port 365: Done
[*] Подключено к 1.1.1.1:365
[+] Параметры DH получены:
[*] p = 41732161398932248164224365390290167693052060766917039547169273746119699642315160432419607337558558447889278771575005714928620559960011390391526147741337629491770812987
[*] g = 14535447338562910308259563339325501271148303404990990031923212222703113628775850990430253965189733765292067080711916877687755833505840760878181110639631652286285736982
[*] A = 38976280391449531768314772990421498991917053535087208865553215709680425102010994330317335742540694912953180833715500058491720374320534940374522142410039134744139723382
[*] B = 24475136230532341842381540842349302565948004172332524877917239167018983718815043435003130288064092608128805660370902404962573731318602521116808273446327732411359980665
[+] Зашифрованный флаг получен: 11f73f707fa4f316a8b4477e6322548efb65033f026e2e328d9082d5eb30eb17
[*] Closed connection to 94.237.49.209 port 30758
[*] Факторизуем (p-1)/2 для поиска малого порядка q...
[+] Найден порядок малой подгруппы: q = 2369232254507 (42 бит)
[*] Решаем дискретный логарифм (BSGS) для нахождения a'...
[+] Найден приватный ключ (mod q): a' = 145570788735
[*] Вычисляем общий секрет ss = B^a' (mod p)...
[+] Общий секрет (ss): 35827136107574915737325403457520305004533507692326153627111347094308856758069209244253809347133836716579730234767641889938957025052005291636101772156453557225150690771
[*] Генерируем ключ AES из общего секрета...
[+] Ключ AES (hex): 7197fd1e9bd9ff1c295549190e0de742
[*] Расшифровываем сообщение...
[+] ФЛАГ НАЙДЕН!

>>>> HTB{***************} <<<<
```
Вот и еще один флаг успешно забрали.

![flag proof](flag.png)
