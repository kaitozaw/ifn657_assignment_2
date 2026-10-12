"""
Generate a file input for the sentinel_payload program.
"""

width = 2
height = 4
depth = 8
label = "E"

header_line = f"PAYLOAD_FRAME {width} {height} {depth} {label}\n"
payload = b"E" * 128

with open("seed_payload_5.bin", "wb") as f:
    f.write(header_line.encode("ascii"))
    f.write(payload)
