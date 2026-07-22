# Skhoron Hadron Cipher

Официальное название: **Skhoron Hadron Cipher** (часть экосистемы Skhoron).
В коде класс называется `HadronCipher` (внутреннее кодовое имя компонента).

Личная криптосистема на основе собственной реализации сети Фейстеля.
256-битные блок/ключ, 20 раундов, 512-битная соль, Argon2id/PBKDF2
(1M итераций), HMAC-SHA256 (encrypt-then-MAC), потоковое шифрование файлов,
Double-Ratchet-подобная ключевая цепочка для сообщений.

## Структура

```
skhoron-hadron-cipher/
├── src/
│   └── orig_cipher.py       # цельный однофайловый вариант (референс/быстрый старт)
├── hadron_cipher/          # тот же код, разложенный по модулям для импорта
│   ├── __init__.py
│   └── cipher.py
├── tests/
│   └── test_cipher.py
├── examples/
│   └── quickstart.py
├── requirements.txt
├── LICENSE
├── NOTICE
└── .gitignore
```

`src/orig_cipher.py` можно просто скопировать в проект и импортировать —
он самодостаточен (кроме опционального `argon2-cffi`).

## Параметры безопасности

| Параметр | Значение | Обоснование |
|---|---|---|
| Блок / ключ | 256 бит | 2^128 пост-квантовая стойкость (Гровер) — соответствует NIST-рекомендациям для AES-256 |
| Раунды Фейстеля | 20 | диффузия с запасом |
| Соль | 512 бит | защита от rainbow tables, с большим запасом сверх минимума |
| KDF | Argon2id (128MB/t=4/p=4) → PBKDF2-SHA256 1M итераций (fallback) | растяжение низкоэнтропийных паролей |
| MAC | HMAC-SHA256, encrypt-then-MAC | целостность + аутентичность |

## ВАЖНО: что KDF не может дать

Число итераций KDF защищает только от **подбора неизвестного** пароля.
Если пароль **известен** атакующему (или он его получил другим способом —
кейлоггер, шантаж и т.п.) — расшифровка тривиальна **для любого шифра в
мире**, не только для этого. Единственная защита от такого сценария —
не дать пароль узнать (OPSEC), а не сила шифра.

## Быстрый старт

```python
from hadron_cipher import HadronCipher, generate_secure_password

cipher = HadronCipher()
password = generate_secure_password(32)

packet = cipher.encrypt(b"secret data", password)
plaintext = cipher.decrypt(packet, password)

# Файлы (потоково, без загрузки в память целиком)
cipher.encrypt_stream_file("big_file.bin", "big_file.enc", password)
cipher.decrypt_stream_file("big_file.enc", "big_file.bin", password)
```

## Тесты

```
pip install -r requirements.txt   # опционально: argon2-cffi
python -m pytest tests/ -v
# или напрямую:
python src/orig_cipher.py
```

## Известные ограничения / roadmap

- Sybil-защита / proof-of-work для идентификаторов — не реализована здесь
  (актуально при встраивании в P2P-контекст, не для самого шифра)
- Wordlist для `generate_passphrase()` — компактный (~100 слов), для честных
  129+ бит энтропии подставь полный EFF-словарь (7776 слов)
- Формат версионируется (`SUPPORTED_VERSIONS`), но апгрейд-путь между
  версиями пока не реализован — на будущее

## Лицензия

Apache License 2.0 (см. LICENSE и NOTICE). Пермиссивная, с явным patent grant —
можно встраивать в любые проекты, включая закрытые, при сохранении copyright-уведомлений.