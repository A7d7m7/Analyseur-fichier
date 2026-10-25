import struct

import pytest


@pytest.fixture
def pe_bytes():
    """PE32 synthétique pour tester le parseur, jamais exécuté et sans payload."""

    def build(imports=(), high_entropy=False, writable=False, section_name=b".text"):
        data = bytearray(0x1600)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 224, 0x102)
        opt = 0x98
        struct.pack_into(
            "<HBBIIIIII", data, opt, 0x10B, 14, 0, 0x1000, 0x400, 0, 0x1000, 0x1000, 0x3000
        )
        struct.pack_into("<III", data, opt + 28, 0x400000, 0x1000, 0x200)
        struct.pack_into("<HHHHHH", data, opt + 40, 6, 0, 0, 0, 6, 0)
        struct.pack_into("<III", data, opt + 56, 0x4000, 0x200, 0)
        struct.pack_into("<HH", data, opt + 68, 3, 0x140)
        struct.pack_into("<IIIIII", data, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        sections = opt + 224
        flags = 0x60000020 | (0x80000000 if writable else 0)
        struct.pack_into(
            "<8sIIIIIIHHI",
            data,
            sections,
            section_name,
            0x1000,
            0x1000,
            0x1000,
            0x200,
            0,
            0,
            0,
            0,
            flags,
        )
        struct.pack_into(
            "<8sIIIIIIHHI",
            data,
            sections + 40,
            b".idata",
            0x400,
            0x3000,
            0x400,
            0x1200,
            0,
            0,
            0,
            0,
            0xC0000040,
        )
        data[0x200:0x1200] = bytes(range(256)) * 16 if high_entropy else bytes(range(16)) * 256
        if imports:
            struct.pack_into("<II", data, opt + 104, 0x3000, 40)
            struct.pack_into("<IIIII", data, 0x1200, 0x3040, 0, 0, 0x3090, 0x3060)
            data[0x1290:0x129D] = b"KERNEL32.dll\x00"
            for index, name in enumerate(imports):
                offset = 0x100 + index * 0x40
                struct.pack_into("<I", data, 0x1240 + index * 4, 0x3000 + offset)
                struct.pack_into("<I", data, 0x1260 + index * 4, 0x3000 + offset)
                encoded = b"\x00\x00" + name.encode() + b"\x00"
                data[0x1200 + offset : 0x1200 + offset + len(encoded)] = encoded
        return bytes(data)

    return build
