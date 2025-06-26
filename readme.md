Tick-Based Encryption PoC(Teeth-gnashing)

Описание

Демонстрация PoC протокола потокового шифрования на основе tick массива с async handshake


Запуск

Сервер
```python
pip install fastapi uvicorn

python server.py
```
Клиент
```python
pip install aiohttp

python client.py
```


   КЛИЕНТ
1. Генерация функции

    Строит 8 случайных точек в 3D: (x, y, z, value)

    Создаёт функцию, но не передаёт её напрямую

2. Хэширует функцию

    Создаёт Blake2s-хэш от всех координат и значений

3. Отправляет хэш (handshake)

    POST-запрос на /handshake с полем hash: str

    Ждёт OK или reject

4. Запрашивает /snapshot

    Если handshake прошёл успешно

5. Получает от сервера:

    tick, seed, timestamp, signature (HMAC)

6. Проверяет:

    Время (abs(now - timestamp) <= 10)

    Подпись HMAC(secret, tick|seed|timestamp) совпадает

7. Генерирует ключ tick_key

    Используя tick, seed, salt (уникальная соль на сообщение)

8. Шифрует сообщение

    Побайтово: m[i] * tick_key[i % 64] % 256

9. Вычисляет Blake2s хэш

    От шифротекста + соли

10. Отправляет на сервер

    hash || salt || шифротекст

   СЕРВЕР
1. Принимает handshake

    Сохраняет hash в authenticated_hashes

    Не восстанавливает функцию

2. При запросе /snapshot

    Генерирует timestamp = now

    Подписывает tick|seed|timestamp через HMAC-SHA256

    Отдаёт:
    ```js
    {
      "tick": ...,
      "seed": ...,
      "timestamp": ...,
      "signature": "base64(hmac)"
    }
    ```

3. При получении зашифрованного сообщения (в будущем)

    Извлекает salt, tick_key, дешифрует побайтово

    Проверяет хэш на целостность

    При успехе → передаёт сообщение в приложение



TODO

L2 реализация, инкапсуляция/обфускация/stealth(когда нибудь)


Сквозное решение(возможно)


Licenced under MIT

Со всеми вытекающими

