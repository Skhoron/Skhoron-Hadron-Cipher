"""
pytest-тесты. Используют ослабленный KDF (ITERATIONS/MEMORY_COST снижены)
только для скорости прогона тестов — в продакшн-коде (hadron_cipher.cipher)
дефолты остаются полными (1M итераций / Argon2id 128MB).
"""
import os
import sys
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hadron_cipher import HadronCipher, CipherParams, generate_secure_password, generate_passphrase


def fast_params(**overrides):
    base = dict(ITERATIONS=100, USE_ARGON2=False)
    base.update(overrides)
    return CipherParams(**base)


def test_basic_roundtrip_cbc():
    c = HadronCipher(fast_params(), run_self_test=False)
    data = b"hello world"
    pkt = c.encrypt(data, "password123")
    assert c.decrypt(pkt, "password123") == data


def test_basic_roundtrip_ctr():
    c = HadronCipher(fast_params(USE_CTR_MODE=True), run_self_test=False)
    data = b"hello world ctr mode"
    pkt = c.encrypt(data, "password123")
    assert c.decrypt(pkt, "password123") == data


def test_wrong_password_fails():
    c = HadronCipher(fast_params(), run_self_test=False)
    pkt = c.encrypt(b"secret", "correct")
    try:
        c.decrypt(pkt, "wrong")
        assert False, "should have raised"
    except ValueError:
        pass


def test_tamper_detected():
    c = HadronCipher(fast_params(), run_self_test=False)
    pkt = bytearray(c.encrypt(b"secret data here", "pw"))
    pkt[-5] ^= 0xFF
    try:
        c.decrypt(bytes(pkt), "pw")
        assert False, "should have raised"
    except ValueError:
        pass


def test_empty_data():
    c = HadronCipher(fast_params(), run_self_test=False)
    pkt = c.encrypt(b"", "pw")
    assert c.decrypt(pkt, "pw") == b""


def test_block_boundary_sizes():
    c = HadronCipher(fast_params(), run_self_test=False)
    for size in (1, 63, 64, 65, 127, 128, 129):
        data = secrets.token_bytes(size)
        pkt = c.encrypt(data, "pw")
        assert c.decrypt(pkt, "pw") == data


def test_ratchet_independent_sender_receiver():
    shared = secrets.token_bytes(32)
    sender = HadronCipher(fast_params(), run_self_test=False)
    receiver = HadronCipher(fast_params(), run_self_test=False)
    sender.init_chain(shared)
    receiver.init_chain(shared)

    messages = [f"msg{i}".encode() for i in range(5)]
    packets = [sender.chain_encrypt(m) for m in messages]
    for i, pkt in enumerate(reversed(packets)):
        assert receiver.chain_decrypt(pkt) == messages[4 - i]


def test_ratchet_cross_session_fails():
    sender = HadronCipher(fast_params(), run_self_test=False)
    sender.init_chain(secrets.token_bytes(32))
    pkt = sender.chain_encrypt(b"hello")

    stranger = HadronCipher(fast_params(), run_self_test=False)
    stranger.init_chain(secrets.token_bytes(32))
    try:
        stranger.chain_decrypt(pkt)
        assert False, "should have raised"
    except ValueError:
        pass


def test_stream_roundtrip(tmp_path):
    c = HadronCipher(fast_params(CHUNK_SIZE=4096), run_self_test=False)
    payload = secrets.token_bytes(4096 * 2 + 500)
    fin, fenc, fout = tmp_path / "in.bin", tmp_path / "enc.bin", tmp_path / "out.bin"
    fin.write_bytes(payload)
    c.encrypt_stream_file(str(fin), str(fenc), "pw")
    c.decrypt_stream_file(str(fenc), str(fout), "pw")
    assert fout.read_bytes() == payload


def test_stream_empty_file(tmp_path):
    c = HadronCipher(fast_params(CHUNK_SIZE=4096), run_self_test=False)
    fin, fenc, fout = tmp_path / "in.bin", tmp_path / "enc.bin", tmp_path / "out.bin"
    fin.write_bytes(b"")
    c.encrypt_stream_file(str(fin), str(fenc), "pw")
    c.decrypt_stream_file(str(fenc), str(fout), "pw")
    assert fout.read_bytes() == b""


def test_stream_tamper_detected(tmp_path):
    c = HadronCipher(fast_params(CHUNK_SIZE=4096), run_self_test=False)
    payload = secrets.token_bytes(500)
    fin, fenc, fout = tmp_path / "in.bin", tmp_path / "enc.bin", tmp_path / "out.bin"
    fin.write_bytes(payload)
    c.encrypt_stream_file(str(fin), str(fenc), "pw")

    data = bytearray(fenc.read_bytes())
    data[-1] ^= 0xFF
    fenc.write_bytes(bytes(data))

    try:
        c.decrypt_stream_file(str(fenc), str(fout), "pw")
        assert False, "should have raised"
    except ValueError:
        pass


def test_password_generators():
    pw = generate_secure_password(32)
    assert len(pw) == 32
    phrase = generate_passphrase(6)
    assert phrase.count("-") == 6