import struct

def pkt(t, n):
    return struct.pack("<IHH", 0x12345678, t, n) + b"A" * (n - 1) + b"\x00"

seeds = [
    pkt(1, 16),
    pkt(1, 48),
    pkt(2, 4),
    pkt(1, 16) + pkt(2, 4),
]

for i, data in enumerate(seeds, 1):
    open(f"seeds/seed_net_{i}.bin", "wb").write(data)
