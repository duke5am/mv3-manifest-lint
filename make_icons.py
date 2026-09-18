"""Generate the example icon PNGs (no third-party deps).

Placeholder art only: a solid rounded square with a lighter inner square, one
file per size. Kept in-process so the examples ship real image bytes with a
real PNG signature and no binary blobs pasted into the repo.
"""
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def chunk(tag: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + tag
        + payload
        + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    )


def png(size: int, background=(30, 90, 200), foreground=(240, 244, 255)) -> bytes:
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter: none
        for x in range(size):
            inner = (
                size // 4 <= x < size - size // 4 and size // 4 <= y < size - size // 4
            )
            colour = foreground if inner else background
            raw.extend(colour)
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def main() -> int:
    targets = []
    for size in (16, 32, 48, 128):
        targets.append(
            (os.path.join(HERE, "examples", "good", "icons", f"icon{size}.png"), size)
        )
    targets.append((os.path.join(HERE, "examples", "bad", "icons", "icon16.png"), 16))

    for path, size in targets:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(png(size))
        print(f"wrote {path} ({os.path.getsize(path)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
