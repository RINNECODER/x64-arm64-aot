#!/usr/bin/env python3
"""Per-function dispatch replay driver.

For each recorded entry, write a one-function compile-results file and run
dispatch_replay.py on it, aggregating the outcomes. One function per dylib avoids
the batch image's body-extent decode failures.

usage: PYTHONPATH=core/aot:<work>/tools-py dispatch_driver.py <eboot.elf> <contracts.json> <compile-results.json> <entries> <pages> <fde-ranges.json> <out-dir>
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    elf, contracts, compile_results, entries, pages, ranges, out_dir = (Path(sys.argv[1]), Path(sys.argv[2]),
                                                                        Path(sys.argv[3]), Path(sys.argv[4]),
                                                                        Path(sys.argv[5]), Path(sys.argv[6]), Path(sys.argv[7]))
    snapshot = Path(sys.argv[8]) if len(sys.argv) > 8 else None
    out_dir.mkdir(parents=True, exist_ok=True)
    results = json.loads(compile_results.read_text())
    import struct
    recorded = set()
    data = entries.read_bytes()
    for offset in range(0, len(data), 136):
        recorded.add(struct.unpack_from("<Q", data, offset)[0])
    selected = {k: v for k, v in results.items() if int(k, 16) in recorded and v["status"] == "compiled"}
    print(f"recorded {len(recorded)}, compiled among them {len(selected)}", flush=True)
    aggregate = {"compiled": len(selected), "executed": 0, "matched": 0, "mismatched": 0,
                 "x86_fault": 0, "arm64_fault": 0, "mismatches": []}
    for index, (address_hex, _spec) in enumerate(sorted(selected.items())):
        single = out_dir / f"{address_hex}.compile.json"
        single.write_text(json.dumps({address_hex: results[address_hex]}))
        run_dir = out_dir / address_hex
        command = [sys.executable, str(HERE / "dispatch_replay.py"), str(elf), str(contracts),
                   str(single), str(run_dir), str(ranges), str(entries), str(pages)]
        if snapshot is not None:
            command.append(str(snapshot))
        completed = subprocess.run(command, capture_output=True, text=True)
        report_path = run_dir / "dispatch-replay.json"
        if completed.returncode != 0 or not report_path.exists():
            aggregate["arm64_fault"] += 1
            continue
        report = json.loads(report_path.read_text())
        for key in ("executed", "matched", "mismatched", "x86_fault", "arm64_fault"):
            aggregate[key] += report.get(key, 0)
        aggregate["mismatches"].extend(report.get("mismatches", []))
        print(f"  [{index + 1}/{len(selected)}] {address_hex}: executed={report.get('executed')} "
              f"matched={report.get('matched')} mismatched={report.get('mismatched')} "
              f"arm64_fault={report.get('arm64_fault')}", flush=True)
    (out_dir / "dispatch-driver.json").write_text(json.dumps(aggregate, indent=1))
    print(f"TOTAL executed={aggregate['executed']} matched={aggregate['matched']} "
          f"mismatched={aggregate['mismatched']} x86_fault={aggregate['x86_fault']} "
          f"arm64_fault={aggregate['arm64_fault']}", flush=True)


if __name__ == "__main__":
    main()
