"""
Быстрый старт HadronCipher.
Запуск: python examples/quickstart.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hadron_cipher import HadronCipher, generate_secure_password, generate_passphrase


def main():
    # 1. Простое шифрование/расшифровка
    cipher = HadronCipher()
    password = generate_secure_password(32)
    print(f"Сгенерированный пароль: {password}")

    packet = cipher.encrypt(b"Secret message", password)
    print(f"Зашифрованный пакет: {len(packet)} байт")

    plaintext = cipher.decrypt(packet, password)
    print(f"Расшифровано: {plaintext}")

    # 2. Passphrase-вариант
    phrase = generate_passphrase(6)
    print(f"\nПарольная фраза: {phrase}")

    # 3. Ключевая цепочка (переписка sender -> receiver)
    print("\n--- Ratchet-цепочка ---")
    shared_secret = os.urandom(32)  # в реальности — результат X25519/Kyber обмена
    sender = HadronCipher()
    receiver = HadronCipher()
    sender.init_chain(shared_secret)
    receiver.init_chain(shared_secret)

    msg1 = sender.chain_encrypt(b"Privet")
    msg2 = sender.chain_encrypt(b"Kak dela?")
    print("Sender:", receiver.chain_decrypt(msg1))
    print("Sender:", receiver.chain_decrypt(msg2))

    # 4. Потоковое шифрование файла
    print("\n--- Стриминг файла ---")
    with open("/tmp/demo_plain.bin", "wb") as f:
        f.write(os.urandom(1024 * 1024))  # 1MB тестовых данных

    cipher.encrypt_stream_file("/tmp/demo_plain.bin", "/tmp/demo.enc", password)
    cipher.decrypt_stream_file("/tmp/demo.enc", "/tmp/demo_out.bin", password)

    with open("/tmp/demo_plain.bin", "rb") as f1, open("/tmp/demo_out.bin", "rb") as f2:
        assert f1.read() == f2.read()
    print("Файл зашифрован/расшифрован потоково без ошибок (1MB)")

    for p in ("/tmp/demo_plain.bin", "/tmp/demo.enc", "/tmp/demo_out.bin"):
        os.remove(p)


if __name__ == "__main__":
    main()