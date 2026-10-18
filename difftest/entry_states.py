#!/usr/bin/env python3
"""Entry states recorded from a real run of the title, for seeding the differential harness.

The trace build can dump, for every guest function entry it reaches, the 16 GPRs at that point
(`ANYPS5_TRACE_ENTRIES`). Those are real values from a real run, so they are what the harness should
start a function from instead of random registers. The file is a stream of 144-byte records:
`<Q entry address>` followed by the 16 GPRs in `replay.REGISTERS` order.

The store is compacted to a small binary keyed by address, because the raw file is tens of
megabytes and the campaign forks many workers. Everything here is title-derived and lives under the
lane's `out/`, never in the repository.
"""
import struct
from pathlib import Path

import replay

RECORD = 144
MAX_PER_ADDRESS = 4
MINIMUM_ADDRESS = 0x80


def build(entries_path, out_path, limit=MAX_PER_ADDRESS):
    """Compact a raw entry-state stream into {address: [16-tuples]} and write it out."""
    states = {}
    with open(entries_path, "rb") as stream:
        while True:
            record = stream.read(RECORD)
            if len(record) < RECORD:
                break
            address, = struct.unpack_from("<Q", record, 0)
            if address < MINIMUM_ADDRESS:
                continue
            bucket = states.setdefault(address, [])
            if len(bucket) < limit:
                bucket.append(struct.unpack_from("<16Q", record, 8))
    payload = bytearray()
    for address in sorted(states):
        bucket = states[address]
        payload += struct.pack("<QB", address, len(bucket))
        for registers in bucket:
            payload += struct.pack("<16Q", *registers)
    Path(out_path).write_bytes(bytes(payload))
    return states


def load(path):
    """{address: [16-tuples]} from a compacted store, empty when the store is absent."""
    path = Path(path)
    if not path.exists():
        return {}
    raw = path.read_bytes()
    states, offset = {}, 0
    while offset < len(raw):
        address, count = struct.unpack_from("<QB", raw, offset)
        offset += 9
        states[address] = [struct.unpack_from("<16Q", raw, offset + 128 * index)
                           for index in range(count)]
        offset += 128 * count
    return states


def registers(states, address, seed):
    """The recorded registers as {name: value}, or None when the address has no recorded state."""
    bucket = states.get(address)
    if not bucket:
        return None
    values = bucket[seed % len(bucket)]
    return {name: value for name, value in zip(replay.REGISTERS, values)}


def coverage(states, addresses):
    """(with a recorded state, total) for a sample list."""
    addresses = list(addresses)
    return sum(1 for address in addresses if address in states), len(addresses)
