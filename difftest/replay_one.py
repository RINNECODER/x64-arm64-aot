#!/usr/bin/env python3
"""Run one differential replay case in its own process so a crashing ARM64 dylib
or x86 runner cannot take down the orchestrator. Prints one JSON object.

usage: replay_one.py <ir.ll> <image.elf> <address-hex>
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import replay  # noqa: E402


def main():
    ir_path, image_path, address = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3], 16)
    uniform = len(sys.argv) > 4 and sys.argv[4] == "uniform"
    ir = ir_path.read_text()
    image = image_path.read_bytes()
    name = f"sub_{address:x}" if uniform else f"func_{address:x}"
    registers = {item: 0 for item in replay.REGISTERS}
    if uniform:
        # A zeroed pointer register would segfault on the first dereference; give
        # every GPR a mapped zeroed scratch region so the body can read/write.
        registers = {item: replay.BASE + 0x60000000 for item in replay.UNIFORM_GPRS if item != "rsp"}
        registers["rsp"] = replay.BASE + 0x700FFFF8
    with tempfile.TemporaryDirectory(prefix="anyps5-replay-one-") as directory:
        outcome = replay.replay_case(Path(directory), ir, name, image, address,
                                     registers, bytes(1 << 16), uniform=uniform)
    print(json.dumps(outcome))


if __name__ == "__main__":
    main()
