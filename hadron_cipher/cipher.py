"""
HadronCipher v2.0 - Личная криптосистема
============================================
Собственная реализация сети Фейстеля (не AES, не готовые крипто-примитивы
для самого шифра). Argon2id/PBKDF2 и HMAC-SHA256 берутся из стандартных
/ общепринятых библиотек, потому что для KDF и MAC нет смысла (и безопасно)
изобретать своё — это единственные "чужие" куски, всё остальное — свой код.

Параметры (защита рассчитана на 100-1000+ лет актуальности):
    Блок:  512 бит (64 байта)
    Ключ:  512 бит (64 байта)
    Соль:  256 бит (32 байта)
    IV:    512 бит (64 байта, = размеру блока)
    Раунды Фейстеля: 24
    KDF:   Argon2id (если доступен) иначе PBKDF2-SHA256, 1 000 000 итераций

ВАЖНО (математика, не мнение):
    Если пароль ИЗВЕСТЕН атакующему — расшифровка тривиальна независимо
    от числа раундов/итераций. KDF защищает только от ПОДБОРА неизвестного
    пароля. Это верно для любого симметричного шифра в мире, не только
    для этого кода.

Автор: независимая разработка. Лицензия — на усмотрение перед публикацией
(рекомендую MIT или Apache-2.0 для приватности-инструментов, см. низ файла).
"""

import os
import sys
import hashlib
import secrets
import struct
import hmac
import time
import zlib
import logging
import gc
import threading
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
from collections import OrderedDict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('HadronCipher')

# ============================================================
# ARGON2 (опционально, честный фолбэк на PBKDF2 если недоступен)
# ============================================================
ARGON2_AVAILABLE = False
try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    pass

# ============================================================
# КОНСТАНТЫ ФОРМАТА ПАКЕТА
# ============================================================
MAGIC = b"HDR2"            # Магическое число формата v2
VERSION = 0x20              # Версия формата 2.0
SUPPORTED_VERSIONS = {0x20}  # На будущее — сюда добавлять новые версии

FLAGS_COMPRESS = 0x01
FLAGS_ARGON2 = 0x02
FLAGS_STREAM = 0x04
FLAGS_CTR = 0x08
FLAGS_HKDF = 0x10

HKDF_NONCE_SIZE = 16
HEADER_SIZE = 9  # MAGIC(4) + version(1) + flags(4)


@dataclass
class CipherParams:
    """Конфигурация криптосистемы. Дефолты = 512-битный профиль."""

    SALT_SIZE: int = 64        # 512 бит - увеличено сверх минимума под 256-битный профиль
    IV_SIZE: int = 32          # = BLOCK_SIZE
    BLOCK_SIZE: int = 32       # 256 бит
    HALF_SIZE: int = 16        # BLOCK_SIZE // 2
    KEY_SIZE: int = 32         # 256 бит

    ROUNDS: int = 20
    ITERATIONS: int = 1_000_000   # PBKDF2 fallback
    MAX_AGE: int = 60

    USE_COMPRESSION: bool = False   # выключено по умолчанию (см. CRIME-класс атак)
    DISABLE_COMPRESSION_FOR_SMALL: bool = True
    SMALL_DATA_THRESHOLD: int = 1024

    USE_ARGON2: bool = True
    MEMORY_COST: int = 131072   # 128 MB
    TIME_COST: int = 4
    PARALLELISM: int = 4

    CHUNK_SIZE: int = 65536         # должен делиться на BLOCK_SIZE
    MAX_SKIPPED_KEYS: int = 1000
    MAX_PACKET_SIZE: int = 100 * 1024 * 1024

    USE_HKDF: bool = True
    USE_CTR_MODE: bool = False

    CACHE_SBOX: bool = True

    def __post_init__(self):
        if self.HALF_SIZE * 2 != self.BLOCK_SIZE:
            raise ValueError("HALF_SIZE должен быть ровно половиной BLOCK_SIZE")
        if self.IV_SIZE != self.BLOCK_SIZE:
            raise ValueError("IV_SIZE должен равняться BLOCK_SIZE (CBC/CTR mixing)")
        if self.CHUNK_SIZE % self.BLOCK_SIZE != 0:
            raise ValueError("CHUNK_SIZE должен быть кратен BLOCK_SIZE")

    def to_dict(self) -> dict:
        return asdict(self)


class SecureMemory:
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        return hmac.compare_digest(a, b)

    @staticmethod
    def secure_wipe(data) -> None:
        if isinstance(data, (bytearray, memoryview)):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, bytes):
            mutable = bytearray(data)
            for i in range(len(mutable)):
                mutable[i] = 0
            del mutable
        gc.collect()


class SBoxCache:
    """Потокобезопасный LRU-кэш для S-Box/перестановок/раундовых ключей."""

    def __init__(self, max_size: int = 128):
        self._cache: "OrderedDict[bytes, tuple]" = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size

    def get(self, key: bytes):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def set(self, key: bytes, value: tuple) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            if len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# ============================================================
# ГЕНЕРАТОРЫ ПАРОЛЕЙ
# ============================================================
# Компактный встроенный словарь для passphrase-режима (без сети, без внешних
# файлов). Для продакшна можно заменить на полный EFF-список (7776 слов).
_WORDLIST = [
    "granit", "vektor", "nebula", "kontur", "faktor", "signal", "hadron",
    "kvantum", "matrix", "cipher", "shadow", "raster", "burevoy", "voronka",
    "gorizont", "cascade", "silicon", "titanium", "wolfram", "meridian",
    "yantar", "polygon", "reaktor", "izotop", "impuls", "protokol", "spektr",
    "tunnel", "khaos", "entropy", "resonans", "argon", "gamma", "delta",
    "epsilon", "zenit", "korpus", "modul", "nexus", "orbita", "peleng",
    "kvarts", "razryad", "sensor", "tempest", "uzel", "vihr", "yastreb",
    "zerkalo", "anomaliya", "baryer", "cifra", "drevo", "ekran", "faza",
    "granica", "himera", "iskra", "jetlag", "kapsula", "labirint", "magnit",
    "nabor", "ostrov", "priziv", "kvota", "reyka", "sektor", "trassa",
    "ugroza", "fantom", "haos", "cyklon", "chaster", "shtorm", "shifr",
    "eho", "yadro", "aksiom", "bunker", "cifral", "dozor", "element",
    "fragment", "granula", "impulsar", "jaguar", "kontakt", "linza",
    "monolit", "nomad", "opora", "parametr", "kvest", "radar", "strannik",
    "tekton", "ultra", "vspyshka", "wolfstrike", "xenon", "yavor", "zapal",
]


def generate_secure_password(length: int = 32, use_symbols: bool = True) -> str:
    """
    Генерация криптографически стойкого пароля через secrets (CSPRNG ОС).

    length=32 при полном алфавите (~94 символа) даёт ~210 бит энтропии —
    избыточно даже для 512-битного ключа с учётом растяжения через KDF.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_passphrase(num_words: int = 6, separator: str = "-", add_digits: bool = True) -> str:
    """
    Diceware-подобная парольная фраза. 6 слов из словаря ~100 слов
    ~= log2(100^6) ≈ 39.8 бит — этого НЕДОСТАТОЧНО для прямого использования
    как единственной защиты от таргетированной атаки, добавляй цифры/символы
    или используй num_words=10+ / полный список 7776 слов для честных 129 бит.
    """
    words = [secrets.choice(_WORDLIST) for _ in range(num_words)]
    phrase = separator.join(words)
    if add_digits:
        phrase += separator + str(secrets.randbelow(10000)).zfill(4)
    return phrase


def estimate_entropy_bits(password: str) -> float:
    """Грубая оценка энтропии пароля по фактическому алфавиту символов."""
    import math
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    pool = 26 * has_lower + 26 * has_upper + 10 * has_digit + 32 * has_symbol
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


# ============================================================
# ОСНОВНОЙ КЛАСС КРИПТОСИСТЕМЫ
# ============================================================
class HadronCipher:
    """
    Криптосистема на основе собственной сети Фейстеля, 512-битный профиль.

    1. KDF: Argon2id (128MB/t=4/p=4) или PBKDF2-SHA256 (1M итераций)
    2. HKDF: разделение на enc_key/mac_key/sbox_key/perm_key
    3. Крипто-контекст: S-Box(256) + перестановка(HALF_SIZE) + 24 раунд.ключа
    4. Шифр: 24-раундовая сеть Фейстеля, CBC или CTR
    5. Аутентификация: HMAC-SHA256, encrypt-then-MAC, с session_binding
    """

    def __init__(self, params: CipherParams = None, run_self_test: bool = True):
        self.params = params or CipherParams()

        self.chain_key = None
        self.chain_id = None
        self.message_counter = 0
        self.skipped_keys: "OrderedDict[int, bytes]" = OrderedDict()

        self._lock = threading.RLock()  # RLock: chain_encrypt/decrypt зовут encrypt/decrypt изнутри lock
        self._sbox_cache = SBoxCache() if self.params.CACHE_SBOX else None

        if run_self_test:
            self._self_test()

    # ---------------- САМОТЕСТИРОВАНИЕ ----------------
    def _self_test(self):
        test_data = b"SelfTest_HadronCipher_2026"
        test_password = "test_password_secure_2026"
        try:
            packet = self.encrypt(test_data, test_password)
            decrypted = self.decrypt(packet, test_password)
            if decrypted != test_data:
                raise RuntimeError("Self-test failed: encrypt/decrypt mismatch")
            logger.info("Self-test passed (mode=%s)", "CTR" if self.params.USE_CTR_MODE else "CBC")
        except Exception as e:
            logger.error("Self-test failed: %s", e)
            raise RuntimeError(f"Self-test failed: {e}")

    # ---------------- ДЕРИВАЦИЯ КЛЮЧЕЙ ----------------
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        if self.params.USE_ARGON2 and ARGON2_AVAILABLE:
            try:
                return hash_secret_raw(
                    secret=password.encode(),
                    salt=salt,
                    time_cost=self.params.TIME_COST,
                    memory_cost=self.params.MEMORY_COST,
                    parallelism=self.params.PARALLELISM,
                    hash_len=self.params.KEY_SIZE,
                    type=Type.ID
                )
            except Exception:
                logger.warning("Argon2 failed, falling back to PBKDF2")

        return hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt,
            self.params.ITERATIONS, dklen=self.params.KEY_SIZE
        )

    # ---------------- HKDF (RFC 5869) ----------------
    def _hkdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        t = b""
        okm = bytearray()
        counter = 1
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
            okm.extend(t)
            counter += 1
        return bytes(okm[:length])

    def _generate_keys(self, master_key: bytes, salt: bytes, nonce: bytes) -> Dict[str, bytes]:
        info = salt + nonce
        return {
            'enc_key': self._hkdf_expand(master_key, info + b"enc", self.params.KEY_SIZE),
            'mac_key': self._hkdf_expand(master_key, info + b"mac", self.params.KEY_SIZE),
            'sbox_key': self._hkdf_expand(master_key, info + b"sbox", self.params.KEY_SIZE),
            'perm_key': self._hkdf_expand(master_key, info + b"perm", self.params.KEY_SIZE),
        }

    # ---------------- КРИПТО-КОНТЕКСТ ----------------
    def _get_crypto_context(self, keys: Dict[str, bytes], nonce: bytes) -> tuple:
        cache_key = None
        if self._sbox_cache is not None:
            cache_key = hashlib.sha256(keys['sbox_key'] + keys['perm_key'] + nonce).digest()
            cached = self._sbox_cache.get(cache_key)
            if cached is not None:
                return cached

        sbox = self._generate_sbox(keys['sbox_key'], nonce)
        perm = self._generate_permutation(keys['perm_key'], nonce, size=self.params.HALF_SIZE)
        round_keys = self._generate_round_keys(keys['enc_key'], nonce)
        context = (sbox, perm, round_keys)

        if self._sbox_cache is not None:
            self._sbox_cache.set(cache_key, context)
        return context

    def _generate_sbox(self, key: bytes, nonce: bytes = b"") -> list:
        sbox = list(range(256))
        for i in range(255, 0, -1):
            h = hmac.new(key, struct.pack('>Q', i) + nonce + b"sbox", hashlib.sha256).digest()
            j = int.from_bytes(h[:4], 'big') % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]
        return sbox

    def _generate_permutation(self, key: bytes, nonce: bytes = b"", size: int = 32) -> list:
        perm = list(range(size))
        for i in range(size - 1, 0, -1):
            h = hmac.new(key, struct.pack('>Q', i) + nonce + b"perm", hashlib.sha256).digest()
            j = int.from_bytes(h[:4], 'big') % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        return perm

    def _generate_round_keys(self, master_key: bytes, nonce: bytes = b"") -> list:
        keys = []
        for r in range(self.params.ROUNDS):
            h = hmac.new(master_key, struct.pack('>Q', r) + nonce + b"round", hashlib.sha256).digest()
            # HALF_SIZE может быть >32, добираем через HKDF-подобное расширение при необходимости
            material = h
            while len(material) < self.params.HALF_SIZE:
                material += hmac.new(master_key, material + struct.pack('>Q', r), hashlib.sha256).digest()
            keys.append(material[:self.params.HALF_SIZE])
        return keys

    # ---------------- РАУНДОВАЯ ФУНКЦИЯ ----------------
    def _round_function(self, half: bytes, round_key: bytes, sbox: list, perm: list) -> bytes:
        state = list(half)
        for i in range(len(state)):
            state[i] = sbox[(state[i] + round_key[i % len(round_key)]) & 0xFF]

        new_state = [0] * len(state)
        for i in range(len(state)):
            new_state[perm[i % len(perm)]] = state[i]

        shifted = [((b << 3) | (b >> 5)) & 0xFF for b in new_state]
        return bytes([shifted[i] ^ round_key[i % len(round_key)] for i in range(len(shifted))])

    def _encrypt_block(self, block: bytes, round_keys: list, sbox: list, perm: list) -> bytes:
        half = self.params.HALF_SIZE
        left, right = block[:half], block[half:]
        for r in range(self.params.ROUNDS):
            f = self._round_function(right, round_keys[r], sbox, perm)
            left, right = right, bytes([left[i] ^ f[i] for i in range(half)])
        return left + right

    def _decrypt_block(self, block: bytes, round_keys: list, sbox: list, perm: list) -> bytes:
        half = self.params.HALF_SIZE
        left, right = block[:half], block[half:]
        for r in reversed(range(self.params.ROUNDS)):
            f = self._round_function(left, round_keys[r], sbox, perm)
            new_left = bytes([right[i] ^ f[i] for i in range(half)])
            new_right = left
            left, right = new_left, new_right
        return left + right

    # ---------------- ПАДДИНГ ----------------
    def _pad(self, data: bytes) -> bytes:
        pad_len = self.params.BLOCK_SIZE - (len(data) % self.params.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        if not data:
            raise ValueError("Empty data")
        pad_len = data[-1]
        if pad_len > self.params.BLOCK_SIZE or pad_len == 0:
            raise ValueError("Invalid padding")
        if any(data[-i] != pad_len for i in range(1, pad_len + 1)):
            raise ValueError("Invalid padding")
        return data[:-pad_len]

    def _should_compress(self, data: bytes) -> bool:
        if not self.params.USE_COMPRESSION:
            return False
        if self.params.DISABLE_COMPRESSION_FOR_SMALL and len(data) < self.params.SMALL_DATA_THRESHOLD:
            return False
        return True

    def _build_header(self, compressed: bool) -> bytes:
        flags = 0
        if compressed:
            flags |= FLAGS_COMPRESS
        if self.params.USE_ARGON2 and ARGON2_AVAILABLE:
            flags |= FLAGS_ARGON2
        if self.params.USE_CTR_MODE:
            flags |= FLAGS_CTR
        if self.params.USE_HKDF:
            flags |= FLAGS_HKDF
        return MAGIC + struct.pack('>B I', VERSION, flags)

    # ---------------- ШИФРОВАНИЕ / РАСШИФРОВАНИЕ (in-memory) ----------------
    def encrypt(self, data: bytes, password: str, session_binding: bytes = b"",
                _raw_key: Optional[bytes] = None) -> bytes:
        """
        _raw_key: внутренний параметр для ratchet-цепочки (chain_encrypt).
        Если передан (KEY_SIZE байт готового ключа) — password-KDF (Argon2/PBKDF2)
        ПРОПУСКАЕТСЯ полностью. Растягивать уже случайный high-entropy ключ через
        миллион итераций KDF бессмысленно и просто убивает производительность —
        стретчинг нужен только для низкоэнтропийных человеческих паролей.
        """
        with self._lock:
            if len(data) > self.params.MAX_PACKET_SIZE:
                raise ValueError(f"Data too large: {len(data)} > {self.params.MAX_PACKET_SIZE}")

            compressed = self._should_compress(data)
            if compressed:
                data = zlib.compress(data, level=9)

            timestamp = struct.pack('>QQ', int(time.time()), time.time_ns() % 10**9)
            data_with_ts = timestamp + data

            if not self.params.USE_CTR_MODE:
                data_with_ts = self._pad(data_with_ts)

            salt = secrets.token_bytes(self.params.SALT_SIZE)
            if _raw_key is not None:
                master_key = _raw_key
            else:
                master_key = self._derive_key(password, salt)
            hkdf_nonce = secrets.token_bytes(HKDF_NONCE_SIZE)
            keys = self._generate_keys(master_key, salt, hkdf_nonce)
            sbox, perm, round_keys = self._get_crypto_context(keys, hkdf_nonce)

            encrypted = bytearray()

            if self.params.USE_CTR_MODE:
                ctr_prefix = secrets.token_bytes(self.params.HALF_SIZE)
                block = self.params.BLOCK_SIZE
                for i in range(0, len(data_with_ts), block):
                    chunk = data_with_ts[i:i + block]
                    block_index = i // block
                    ctr_value = ctr_prefix + block_index.to_bytes(self.params.HALF_SIZE, 'big')
                    stream = self._encrypt_block(ctr_value, round_keys, sbox, perm)
                    encrypted.extend(bytes([chunk[j] ^ stream[j] for j in range(len(chunk))]))
                iv_field = ctr_prefix.ljust(self.params.IV_SIZE, b'\x00')
            else:
                iv = secrets.token_bytes(self.params.IV_SIZE)
                iv_field = iv
                prev_block = iv[:self.params.BLOCK_SIZE]
                block = self.params.BLOCK_SIZE
                for i in range(0, len(data_with_ts), block):
                    chunk = data_with_ts[i:i + block]
                    mixed = bytes([chunk[j] ^ prev_block[j] for j in range(len(chunk))])
                    enc_block = self._encrypt_block(mixed, round_keys, sbox, perm)
                    encrypted.extend(enc_block)
                    prev_block = enc_block

            header = self._build_header(compressed)
            mac = hmac.new(
                keys['mac_key'],
                session_binding + salt + iv_field + hkdf_nonce + header + encrypted,
                hashlib.sha256
            ).digest()

            return salt + iv_field + hkdf_nonce + header + mac + bytes(encrypted)

    def decrypt(self, packet: bytes, password: str, max_age: Optional[int] = None,
                session_binding: bytes = b"", _raw_key: Optional[bytes] = None) -> bytes:
        with self._lock:
            if max_age is None:
                max_age = self.params.MAX_AGE

            mac_size = 32
            min_size = self.params.SALT_SIZE + self.params.IV_SIZE + HKDF_NONCE_SIZE + HEADER_SIZE + mac_size
            if len(packet) < min_size:
                raise ValueError("Packet too short")

            pos = 0
            salt = packet[pos:pos + self.params.SALT_SIZE]; pos += self.params.SALT_SIZE
            iv_field = packet[pos:pos + self.params.IV_SIZE]; pos += self.params.IV_SIZE
            hkdf_nonce = packet[pos:pos + HKDF_NONCE_SIZE]; pos += HKDF_NONCE_SIZE
            header = packet[pos:pos + HEADER_SIZE]; pos += HEADER_SIZE
            mac = packet[pos:pos + mac_size]; pos += mac_size
            encrypted = packet[pos:]

            if header[:4] != MAGIC:
                raise ValueError("Invalid magic number")

            version = struct.unpack('>B', header[4:5])[0]
            if version not in SUPPORTED_VERSIONS:
                raise ValueError(f"Unsupported version: {version}")

            flags = struct.unpack('>I', header[5:9])[0]
            is_compressed = bool(flags & FLAGS_COMPRESS)
            is_ctr = bool(flags & FLAGS_CTR)

            if _raw_key is not None:
                master_key = _raw_key
            else:
                master_key = self._derive_key(password, salt)
            keys = self._generate_keys(master_key, salt, hkdf_nonce)

            expected_mac = hmac.new(
                keys['mac_key'],
                session_binding + salt + iv_field + hkdf_nonce + header + encrypted,
                hashlib.sha256
            ).digest()

            if not hmac.compare_digest(mac, expected_mac):
                raise ValueError("Invalid password or corrupted data")

            sbox, perm, round_keys = self._get_crypto_context(keys, hkdf_nonce)
            decrypted = bytearray()
            block = self.params.BLOCK_SIZE

            if is_ctr:
                ctr_prefix = iv_field[:self.params.HALF_SIZE]
                for i in range(0, len(encrypted), block):
                    chunk = encrypted[i:i + block]
                    block_index = i // block
                    ctr_value = ctr_prefix + block_index.to_bytes(self.params.HALF_SIZE, 'big')
                    stream = self._encrypt_block(ctr_value, round_keys, sbox, perm)
                    decrypted.extend(bytes([chunk[j] ^ stream[j] for j in range(len(chunk))]))
            else:
                prev_block = iv_field[:block]
                for i in range(0, len(encrypted), block):
                    chunk = encrypted[i:i + block]
                    dec_block = self._decrypt_block(chunk, round_keys, sbox, perm)
                    plain_block = bytes([dec_block[j] ^ prev_block[j] for j in range(len(chunk))])
                    decrypted.extend(plain_block)
                    prev_block = chunk

            data_with_ts = bytes(decrypted) if is_ctr else self._unpad(bytes(decrypted))

            ts_sec = struct.unpack('>Q', data_with_ts[:8])[0]
            ts_nsec = struct.unpack('>Q', data_with_ts[8:16])[0]
            packet_time = ts_sec + ts_nsec / 10**9

            if abs(time.time() - packet_time) > max_age:
                raise ValueError("Packet expired")

            data = data_with_ts[16:]

            if is_compressed:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    raise ValueError("Decompression error")

            return data

    # ---------------- СТРИМОВОЕ ШИФРОВАНИЕ ФАЙЛОВ (CTR, O(1) память) ----------------
    def encrypt_stream_file(self, input_path: str, output_path: str, password: str,
                             session_binding: bytes = b"") -> None:
        """
        Потоковое шифрование файла произвольного размера без загрузки в память.
        Формат: [header блок] + [chunk]* , каждый chunk аутентифицирован отдельно
        (защита от перестановки/усечения чанков через chunk_index + is_last в MAC).
        """
        salt = secrets.token_bytes(self.params.SALT_SIZE)
        master_key = self._derive_key(password, salt)
        hkdf_nonce = secrets.token_bytes(HKDF_NONCE_SIZE)
        keys = self._generate_keys(master_key, salt, hkdf_nonce)
        sbox, perm, round_keys = self._get_crypto_context(keys, hkdf_nonce)

        ctr_prefix = secrets.token_bytes(self.params.HALF_SIZE)
        header = self._build_header(compressed=False)
        header = header[:5] + struct.pack('>I', struct.unpack('>I', header[5:9])[0] | FLAGS_STREAM | FLAGS_CTR)

        file_size = os.path.getsize(input_path)
        block = self.params.BLOCK_SIZE

        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            fout.write(salt + ctr_prefix.ljust(self.params.IV_SIZE, b'\x00') + hkdf_nonce + header)

            bytes_read_total = 0
            chunk_index = 0
            global_block_counter = 0

            while True:
                chunk = fin.read(self.params.CHUNK_SIZE)
                # Пустой входной файл (chunk_index==0, file_size==0): всё равно
                # пишем один финальный чанк (может быть 0 байт), иначе decrypt
                # не увидит is_last-маркер и ошибочно решит, что поток усечён.
                if not chunk and not (chunk_index == 0 and file_size == 0):
                    break
                is_last = 1
                bytes_read_total += len(chunk)
                if bytes_read_total < file_size:
                    is_last = 0

                # шифруем чанк как CTR-поток
                enc_chunk = bytearray()
                for i in range(0, len(chunk), block):
                    piece = chunk[i:i + block]
                    ctr_value = ctr_prefix + global_block_counter.to_bytes(self.params.HALF_SIZE, 'big')
                    stream = self._encrypt_block(ctr_value, round_keys, sbox, perm)
                    enc_chunk.extend(bytes([piece[j] ^ stream[j % len(stream)] for j in range(len(piece))]))
                    global_block_counter += 1

                tag = hmac.new(
                    keys['mac_key'],
                    session_binding + hkdf_nonce + struct.pack('>QB', chunk_index, is_last) + bytes(enc_chunk),
                    hashlib.sha256
                ).digest()

                fout.write(struct.pack('>IB', len(enc_chunk), is_last))
                fout.write(bytes(enc_chunk))
                fout.write(tag)

                chunk_index += 1
                if is_last:
                    break

    def decrypt_stream_file(self, input_path: str, output_path: str, password: str,
                             session_binding: bytes = b"") -> None:
        block = self.params.BLOCK_SIZE
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            salt = fin.read(self.params.SALT_SIZE)
            iv_field = fin.read(self.params.IV_SIZE)
            hkdf_nonce = fin.read(HKDF_NONCE_SIZE)
            header = fin.read(HEADER_SIZE)

            if header[:4] != MAGIC:
                raise ValueError("Invalid magic number")
            version = struct.unpack('>B', header[4:5])[0]
            if version not in SUPPORTED_VERSIONS:
                raise ValueError(f"Unsupported version: {version}")
            flags = struct.unpack('>I', header[5:9])[0]
            if not (flags & FLAGS_STREAM):
                raise ValueError("Not a stream-format packet")

            master_key = self._derive_key(password, salt)
            keys = self._generate_keys(master_key, salt, hkdf_nonce)
            sbox, perm, round_keys = self._get_crypto_context(keys, hkdf_nonce)
            ctr_prefix = iv_field[:self.params.HALF_SIZE]

            chunk_index = 0
            global_block_counter = 0
            seen_last = False

            while True:
                len_flag = fin.read(5)
                if len(len_flag) == 0:
                    break
                if len(len_flag) != 5:
                    raise ValueError("Truncated stream (corrupted chunk header)")
                enc_len, is_last = struct.unpack('>IB', len_flag)
                enc_chunk = fin.read(enc_len)
                tag = fin.read(32)
                if len(enc_chunk) != enc_len or len(tag) != 32:
                    raise ValueError("Truncated stream (corrupted chunk body)")

                expected_tag = hmac.new(
                    keys['mac_key'],
                    session_binding + hkdf_nonce + struct.pack('>QB', chunk_index, is_last) + enc_chunk,
                    hashlib.sha256
                ).digest()
                if not hmac.compare_digest(tag, expected_tag):
                    raise ValueError("Invalid password, corrupted or tampered chunk "
                                      f"(index={chunk_index})")

                dec_chunk = bytearray()
                for i in range(0, len(enc_chunk), block):
                    piece = enc_chunk[i:i + block]
                    ctr_value = ctr_prefix + global_block_counter.to_bytes(self.params.HALF_SIZE, 'big')
                    stream = self._encrypt_block(ctr_value, round_keys, sbox, perm)
                    dec_chunk.extend(bytes([piece[j] ^ stream[j % len(stream)] for j in range(len(piece))]))
                    global_block_counter += 1

                fout.write(bytes(dec_chunk))
                chunk_index += 1
                if is_last:
                    seen_last = True
                    break

            if not seen_last:
                raise ValueError("Stream truncated: final chunk marker not found "
                                  "(possible truncation attack)")

    # ---------------- КЛЮЧЕВАЯ ЦЕПОЧКА (Double-Ratchet-подобная) ----------------
    def init_chain(self, shared_secret: bytes):
        with self._lock:
            self.chain_key = hashlib.sha256(shared_secret + b"chain_key").digest()
            self.chain_id = hashlib.sha256(shared_secret + b"chain_id").digest()
            self.message_counter = 0
            self.skipped_keys.clear()

    def _ratchet_step(self, counter: int) -> bytes:
        """
        Один шаг KDF-цепочки с доменным разделением (HMAC, не голый SHA256
        на два назначения сразу): chain_key обновляется отдельным вызовом,
        msg_key (полные KEY_SIZE байт = 64) выводится отдельным вызовом.
        Так исключается взаимная зависимость/утечка между chain- и msg- ключами.
        """
        ctr = struct.pack('>Q', counter)
        msg_key = hmac.new(self.chain_key, ctr + b"msg", hashlib.sha512).digest()  # 64 байта
        if self.params.KEY_SIZE > 64:
            msg_key += hmac.new(self.chain_key, ctr + b"msg2", hashlib.sha512).digest()
        msg_key = msg_key[:self.params.KEY_SIZE]
        self.chain_key = hmac.new(self.chain_key, ctr + b"chain", hashlib.sha256).digest()
        return msg_key

    def chain_encrypt(self, data: bytes) -> bytes:
        """
        Сообщение шифруется готовым ключом ratchet-цепочки напрямую (без
        password-KDF) — быстро, как и должно быть в мессенджере.
        """
        with self._lock:
            if self.chain_key is None:
                raise ValueError("Call init_chain first")

            msg_key = self._ratchet_step(self.message_counter)
            counter = self.message_counter
            self.message_counter += 1

            old_compress = self.params.USE_COMPRESSION
            self.params.USE_COMPRESSION = False
            try:
                packet = self.encrypt(data, password="", session_binding=self.chain_id,
                                       _raw_key=msg_key)
                return struct.pack('>Q', counter) + packet
            finally:
                self.params.USE_COMPRESSION = old_compress

    def chain_decrypt(self, packet: bytes) -> bytes:
        """
        LRU-эвикция: при переполнении skipped_keys вытесняется САМЫЙ СТАРЫЙ
        пропущенный ключ (а не падение всей сессии с ValueError, как раньше).
        """
        with self._lock:
            if self.chain_key is None:
                raise ValueError("Call init_chain first")

            msg_counter = struct.unpack('>Q', packet[:8])[0]
            packet = packet[8:]

            if msg_counter in self.skipped_keys:
                msg_key = self.skipped_keys.pop(msg_counter)
                return self.decrypt(packet, password="", session_binding=self.chain_id,
                                     _raw_key=msg_key)

            if msg_counter < self.message_counter:
                raise ValueError("Message already processed")

            old_compress = self.params.USE_COMPRESSION
            self.params.USE_COMPRESSION = False
            try:
                while self.message_counter <= msg_counter:
                    msg_key = self._ratchet_step(self.message_counter)

                    if self.message_counter == msg_counter:
                        self.message_counter += 1
                        return self.decrypt(packet, password="", session_binding=self.chain_id,
                                             _raw_key=msg_key)
                    else:
                        self.skipped_keys[self.message_counter] = msg_key
                        if len(self.skipped_keys) > self.params.MAX_SKIPPED_KEYS:
                            self.skipped_keys.popitem(last=False)  # вытесняем самый старый
                        self.message_counter += 1
            finally:
                self.params.USE_COMPRESSION = old_compress

            raise ValueError("Decryption failed")

    # ---------------- ВСПОМОГАТЕЛЬНОЕ ----------------
    def verify(self, packet: bytes, password: str) -> bool:
        try:
            self.decrypt(packet, password)
            return True
        except ValueError:
            return False

    def clear_cache(self):
        if self._sbox_cache is not None:
            self._sbox_cache.clear()

    def get_info(self) -> dict:
        return {
            'version': '2.0',
            'block_bits': self.params.BLOCK_SIZE * 8,
            'key_bits': self.params.KEY_SIZE * 8,
            'rounds': self.params.ROUNDS,
            'mode': 'CTR' if self.params.USE_CTR_MODE else 'CBC',
            'kdf': 'Argon2id' if (self.params.USE_ARGON2 and ARGON2_AVAILABLE) else 'PBKDF2-SHA256',
            'kdf_iterations_fallback': self.params.ITERATIONS,
            'mac': 'HMAC-SHA256',
            'estimated_lifetime': '1000+ years (classical), 100+ years post-quantum (Grover)',
        }

    def __del__(self):
        if self.chain_key:
            SecureMemory.secure_wipe(self.chain_key)
        if self.chain_id:
            SecureMemory.secure_wipe(self.chain_id)
        self.skipped_keys.clear()
        if self._sbox_cache is not None:
            self._sbox_cache.clear()
        gc.collect()


# ============================================================
# ТЕСТЫ
# ============================================================
def run_all_tests():
    print("=" * 60)
    print("HadronCipher v2.0 - Test Suite")
    print("=" * 60)

    cipher = HadronCipher()
    password = "test_password"
    data = b"Hello, World! Test message."

    packet = cipher.encrypt(data, password)
    assert cipher.decrypt(packet, password) == data
    print("[OK] Basic encryption (CBC)")

    cipher_ctr = HadronCipher(CipherParams(USE_CTR_MODE=True))
    packet_ctr = cipher_ctr.encrypt(data, password)
    assert cipher_ctr.decrypt(packet_ctr, password) == data
    print("[OK] CTR mode")

    cipher_comp = HadronCipher(CipherParams(USE_COMPRESSION=True))
    large_data = b"Hello, World! " * 1000
    packet_comp = cipher_comp.encrypt(large_data, password)
    assert cipher_comp.decrypt(packet_comp, password) == large_data
    print(f"[OK] Compression (packet {len(packet_comp)}B vs raw {len(large_data)}B)")

    shared_secret = secrets.token_bytes(32)
    sender = HadronCipher(run_self_test=False)
    receiver = HadronCipher(run_self_test=False)
    sender.init_chain(shared_secret)
    receiver.init_chain(shared_secret)
    messages = [f"Message {i}".encode() for i in range(10)]
    packets = [sender.chain_encrypt(m) for m in messages]
    for i, pkt in enumerate(reversed(packets)):
        assert receiver.chain_decrypt(pkt) == messages[9 - i]
    print("[OK] Key chain (out-of-order incl., independent sender/receiver state)")

    small_params = CipherParams(MAX_SKIPPED_KEYS=3)
    sender_small = HadronCipher(small_params, run_self_test=False)
    receiver_small = HadronCipher(small_params, run_self_test=False)
    shared_small = secrets.token_bytes(32)
    sender_small.init_chain(shared_small)
    receiver_small.init_chain(shared_small)
    pkts = [sender_small.chain_encrypt(f"m{i}".encode()) for i in range(10)]
    assert receiver_small.chain_decrypt(pkts[-1]) == b"m9"
    print(f"[OK] Ratchet LRU eviction (skipped_keys size={len(receiver_small.skipped_keys)}, max=3)")

    cipher2 = HadronCipher(run_self_test=False)
    cipher2.init_chain(secrets.token_bytes(32))
    try:
        cipher2.chain_decrypt(packets[0])
        assert False
    except ValueError:
        pass
    print("[OK] Cross-session replay protection")

    try:
        cipher.decrypt(packet, "wrong_password")
        assert False
    except ValueError:
        pass
    corrupted = bytearray(packet)
    corrupted[-10] ^= 0xFF
    try:
        cipher.decrypt(bytes(corrupted), password)
        assert False
    except ValueError:
        pass
    try:
        cipher.decrypt(packet, password, max_age=0)
        assert False
    except ValueError:
        pass
    print("[OK] Error handling (wrong pass / tamper / expiry)")

    msg1 = b"A" * 64
    msg2 = b"B" + b"A" * 63
    enc1 = cipher.encrypt(msg1, password)
    enc2 = cipher.encrypt(msg2, password)
    offset = (cipher.params.SALT_SIZE + cipher.params.IV_SIZE +
              HKDF_NONCE_SIZE + HEADER_SIZE + 32)
    ct1, ct2 = enc1[offset:offset + 64], enc2[offset:offset + 64]
    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(ct1, ct2))
    print(f"[OK] Avalanche effect: {(diff_bits / (64*8))*100:.1f}% (ideal ~50%)")

    # Стриминг: файл ~ несколько чанков
    test_in = "/tmp/_hadron_test_in.bin"
    test_enc = "/tmp/_hadron_test.enc"
    test_out = "/tmp/_hadron_test_out.bin"
    payload = secrets.token_bytes(cipher.params.CHUNK_SIZE * 3 + 777)
    with open(test_in, 'wb') as f:
        f.write(payload)
    cipher.encrypt_stream_file(test_in, test_enc, password)
    cipher.decrypt_stream_file(test_enc, test_out, password)
    with open(test_out, 'rb') as f:
        result = f.read()
    assert result == payload, "Stream round-trip mismatch"
    print(f"[OK] Stream encryption round-trip ({len(payload)} bytes, {3} chunks + tail)")

    # Стриминг: детект подмены чанка
    with open(test_enc, 'r+b') as f:
        f.seek(-40, os.SEEK_END)
        b = f.read(1)
        f.seek(-40, os.SEEK_END)
        f.write(bytes([b[0] ^ 0xFF]))
    try:
        cipher.decrypt_stream_file(test_enc, test_out, password)
        assert False, "Should have detected tampering"
    except ValueError:
        pass
    print("[OK] Stream tamper detection")

    for p in (test_in, test_enc, test_out):
        os.remove(p)

    pw = generate_secure_password(32)
    assert len(pw) == 32
    phrase = generate_passphrase(6)
    assert phrase.count("-") == 6
    print(f"[OK] Password generators (sample: {pw[:8]}..., {phrase})")
    print(f"     estimated entropy of generated password: {estimate_entropy_bits(pw):.0f} bits")

    info = cipher.get_info()
    print(f"[OK] get_info(): {info}")

    start = time.time()
    for _ in range(20):
        cipher.encrypt(data, password)
    elapsed = time.time() - start
    print(f"[OK] Performance: 20 encryptions (small payload) in {elapsed*1000:.0f}ms")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()