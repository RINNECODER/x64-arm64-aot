#!/usr/bin/env python3
"""Align two ANYPS5_HLE_LOG files and report the first divergence.

Both engines write the same records: a 2-word header, then per import call a
`(sequence, thread, name_length, flags, args[6], result, name)` record, and per return a record
with `name_length == 0` and `flags == 1` sharing the call's sequence. The Rosetta log is hundreds of
MB, so this streams both files and keeps only a bounded prefix of each thread; threads are paired by
the longest shared leading import-name sequence, each pair is aligned on its longest shared run of
call names, and the pair reports the first call after that alignment whose name, arguments or return
differs.

usage: hle_diff.py <left.log> <right.log> [--names contracts.json] [--per-thread N]
                   [--ignore-pointer-args]
"""
import argparse
import json
import struct
import sys
from pathlib import Path

MAGIC = 0x474F4C48
RECORD = 80


def read_log(path, per_thread):
    """Stream one log; return (calls, calls-per-thread, {thread: [(name, args, result)]}, names, note).

    A missing file is a result, not an error: an engine that never reached the HLE boundary leaves no
    log, and that is exactly what the comparison has to report.
    """
    try:
        handle = open(path, "rb")
    except FileNotFoundError:
        return 0, {}, {}, {}, "not recorded"
    header = handle.read(8)
    if len(header) < 8:
        handle.close()
        return 0, {}, {}, {}, "empty"
    magic, version = struct.unpack("<II", header)
    if magic != MAGIC:
        raise SystemExit(f"{path}: bad magic {magic:#x}")
    calls, counts, threads, names, pending = 0, {}, {}, {}, {}
    while True:
        head = handle.read(RECORD)
        if len(head) < RECORD:
            break
        sequence, thread, name_length, flags = struct.unpack_from("<QQII", head, 0)
        if name_length:
            name = handle.read(name_length).decode("utf-8", "replace")
            handle.read((8 - name_length % 8) % 8)
            calls += 1
            names[name] = names.get(name, 0) + 1
            counts[thread] = counts.get(thread, 0) + 1
            bucket = threads.setdefault(thread, [])
            if len(bucket) < per_thread:
                record = [name, struct.unpack_from("<6Q", head, 24), None]
                bucket.append(record)
                pending[sequence] = record
        else:
            record = pending.pop(sequence, None)
            if record is not None:
                record[2], = struct.unpack_from("<Q", head, 72)
    return calls, counts, threads, names, "ok"


def shared_prefix(left, left_start, right, right_start):
    """Length of the run of equal import names starting at the two positions."""
    count = 0
    while (left_start + count < len(left) and right_start + count < len(right)
           and left[left_start + count][0] == right[right_start + count][0]):
        count += 1
    return count


def align(left, right, minimum):
    """The offset of the right prefix inside the left prefix that matches longest.

    The two engines do not enter the title at the same point: Rosetta first runs the guest
    libkernel start-up, so its log opens with calls the native launcher never makes. Aligning on the
    longest shared name run finds where the two sequences meet instead of blaming call 0.
    """
    best_offset, best_run = 0, 0
    for offset in range(len(left)):
        run = shared_prefix(left, offset, right, 0)
        if run > best_run:
            best_offset, best_run = offset, run
    return (best_offset, best_run) if best_run >= minimum else (0, 0)


def pair_threads(left_counts, left_threads, right_counts, right_threads):
    """Greedy pairing: each left thread takes the free right thread with the longest name prefix."""
    free = sorted(right_threads, key=lambda thread: -right_counts.get(thread, 0))
    pairs = []
    for thread in sorted(left_threads, key=lambda thread: -left_counts.get(thread, 0)):
        best, best_score = None, -1
        for other in free:
            score = shared_prefix(left_threads[thread], 0, right_threads[other], 0)
            if score > best_score:
                best, best_score = other, score
        if best is not None:
            free.remove(best)
            pairs.append((thread, best, best_score))
    return pairs, free


def by_import(threads, counts, per_import):
    """The first `per_import` calls of every import, in the order the run first reached it."""
    result, order = {}, []
    for thread in sorted(threads, key=lambda thread: -counts.get(thread, 0)):
        for record in threads[thread]:
            bucket = result.setdefault(record[0], [])
            if not bucket:
                order.append(record[0])
            if len(bucket) < per_import:
                bucket.append(record)
    return order, result


def compare_by_import(args, left, right, label, norm, show):
    """Compare the first call of each import instead of the call sequence.

    When the two engines do not reach the same code at all (a bounded native boot against a full
    Rosetta run) the sequence diff can only say "call 0 differs". Comparing per import answers the
    question that is still meaningful: for each import the native run did reach, do the arguments
    and the return match what Rosetta passed and got?
    """
    left_order, left_calls = by_import(left[2], left[1], args.per_import)
    right_order, right_calls = by_import(right[2], right[1], args.per_import)
    differing, missing, matching = [], [], []
    for name in right_order:
        if name not in left_calls:
            missing.append(name)
            print(f"{label(name)}: reached by the right run only")
            continue
        first, second = left_calls[name][0], right_calls[name][0]
        reasons = []
        if norm(first[1]) != norm(second[1]):
            for index, (one, two) in enumerate(zip(first[1], second[1])):
                if norm((one,))[0] != norm((two,))[0]:
                    reasons.append(f"arg{index} {hex(one)} vs {hex(two)}")
        if first[2] is not None and second[2] is not None and first[2] != second[2]:
            reasons.append(f"result {show(first[2])} vs {show(second[2])}")
        if not reasons:
            matching.append(name)
            if not args.only_differences:
                print(f"{label(name)}: same")
            continue
        differing.append(name)
        print(f"{label(name)}")
        print(f"  left : args={[hex(v) for v in first[1]]} result={show(first[2])}")
        print(f"  right: args={[hex(v) for v in second[1]]} result={show(second[2])}")
        print(f"  -> {'; '.join(reasons)}")
    print(f"{len(differing)} of {len(right_order)} imports reached by the right run differ, "
          f"{len(matching)} match, {len(missing)} are not in the left log")
    return 1 if differing or missing else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--names", type=Path, help="contracts JSON mapping import NIDs to symbols")
    parser.add_argument("--per-thread", type=int, default=8192, help="calls kept per thread")
    parser.add_argument("--align-minimum", type=int, default=3,
                        help="shared calls needed before an alignment is trusted")
    parser.add_argument("--ignore-pointer-args", action="store_true", help="ignore handle/pointer args")
    parser.add_argument("--by-import", action="store_true",
                        help="compare the first call of each import instead of the call sequence")
    parser.add_argument("--per-import", type=int, default=1, help="calls kept per import in --by-import")
    parser.add_argument("--only-differences", action="store_true",
                        help="in --by-import, print only imports that differ")
    args = parser.parse_args()
    table = {}
    if args.names:
        names = json.loads(args.names.read_text())
        # A contracts file carries an "imports" mapping; a flat NID-to-name map is also accepted.
        entries = names["imports"].items() if "imports" in names else names.items()
        for key, value in entries:
            contract = value if isinstance(value, dict) else {"name": value}
            table[key.split("#", 1)[0]] = contract["name"].lstrip("_")
    left = read_log(args.left, args.per_thread)
    right = read_log(args.right, args.per_thread)
    print(f"left : {left[0]} calls, {len(left[1])} threads, {len(left[3])} distinct imports ({left[4]})")
    print(f"right: {right[0]} calls, {len(right[1])} threads, {len(right[3])} distinct imports ({right[4]})")
    if left[0] and not right[0]:
        print(f"the right log recorded no import call ({right[4]}); the left run made {left[0]} calls, so "
              f"every import the right run reached is unreached — the largest possible divergence")
        return 1
    pairs, unpaired = pair_threads(left[1], left[2], right[1], right[2])

    def label(name):
        return f"{table[name]} ({name})" if name in table else name

    def norm(values):
        if not args.ignore_pointer_args:
            return values
        return tuple(0 if value > 0x10000 else value for value in values)

    def show(value):
        return "unknown" if value is None else hex(value)

    if args.by_import:
        return compare_by_import(args, left, right, label, norm, show)

    divergences = []
    for thread, other, score in pairs:
        first, second = left[2][thread], right[2][other]
        offset, run = align(first, second, args.align_minimum)
        detail = None
        for position, (one, two) in enumerate(zip(first[offset:], second), start=offset):
            if one[0] != two[0]:
                detail = (position, "name", one, two)
            elif norm(one[1]) != norm(two[1]):
                detail = (position, "args", one, two)
            elif one[2] is not None and two[2] is not None and one[2] != two[2]:
                detail = (position, "return", one, two)
            if detail:
                break
        else:
            if len(first) != len(second):
                detail = (min(len(first), len(second)), "length", None, None)
        print(f"pair {thread}<->{other}: {left[1][thread]} vs {right[1][other]} calls, "
              f"common name prefix {score}, aligned at call {offset} ({run} calls)")
        if detail is None:
            print("  no divergence within the kept prefix")
            continue
        divergences.append((thread, other, detail))
        position, kind, one, two = detail
        if kind == "length":
            print(f"  first differing call {position}: call count {len(first)} vs {len(second)}")
            continue
        print(f"  first differing call {position}: {kind}")
        print(f"    left : {label(one[0])} args={[hex(v) for v in one[1]]} result={show(one[2])}")
        print(f"    right: {label(two[0])} args={[hex(v) for v in two[1]]} result={show(two[2])}")
    if unpaired:
        print(f"unpaired right threads: {unpaired[:8]}")
    print(f"{len(divergences)} of {len(pairs)} thread pairs diverge")
    return 1 if divergences else 0


if __name__ == "__main__":
    sys.exit(main())
