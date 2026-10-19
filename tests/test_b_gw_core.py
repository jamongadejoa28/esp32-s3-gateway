"""Stream B gw_core pure code: gw_json_writer.c (modes, grammar, numbers, escaping) and gw_ip4.c."""
import ctypes
import json
import random

from b_store.harness import b_lib, b_objs, run_c  # noqa: F401  (fixtures)


def test_json_writer_c(b_objs, tmp_path):
    run_c(b_objs, tmp_path, 't_json_writer')


def test_ip4_c(b_objs, tmp_path):
    run_c(b_objs, tmp_path, 't_ip4')


def _jw(lib, data: bytes):
    out = ctypes.create_string_buffer(len(data) * 6 + 16)
    rc = lib.t_jw_string(data, len(data), out, len(out))
    assert rc == 0
    return out.value


def test_json_writer_escaping_fuzz(b_lib):
    """Arbitrary bytes always produce valid JSON; valid UTF-8 round-trips exactly."""
    b_lib.t_jw_string.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    rnd = random.Random(0xB5)
    alphabet = [bytes([i]) for i in range(256)] + [s.encode() for s in ('현재', '°C', ' ', '😀', '</')]
    for _ in range(3000):
        data = b''.join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
        text = _jw(b_lib, data)
        parsed = json.loads(text.decode('utf-8'))  # must be valid UTF-8 and valid JSON
        assert isinstance(parsed, list) and len(parsed) == 1
        try:
            expect = data.decode('utf-8')
        except UnicodeDecodeError:
            assert '�' in parsed[0]
            continue
        assert parsed[0] == expect
        assert b'</' not in text  # never emits a closing-tag sequence


def test_json_writer_utf8_vs_python(b_lib):
    """Every single code point boundary class round-trips."""
    b_lib.t_jw_string.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
    for cp in [0x0, 0x1F, 0x20, 0x7F, 0x80, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFD, 0xFFFF, 0x10000, 0x10FFFF]:
        s = chr(cp)
        assert json.loads(_jw(b_lib, s.encode('utf-8')).decode())[0] == s
