#!/usr/bin/env python3
"""Compile the selected functions with the uniform ABI, one isolated child per
function so a compiler crash cannot take down the run. Writes per-function status.

usage: PYTHONPATH=core/aot uniform_compile.py <eboot.elf> <contracts.json> <selection.json> <out.json> [workers]
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core" / "aot"))
from compiler import Function, Image  # noqa: E402


def reason(error):
    text = str(error)
    if "): " in text:
        text = text.split("): ", 1)[1]
    return text.split("\n", 1)[0][:200]


def compile_spec(image, address):
    spec = image.functions.get(address)
    if spec is None:
        return {"status": "no-contract"}
    stage = "discover"
    try:
        function = Function(image, spec)
        stage = "analyze"
        function.analyze()
        stage = "lower"
        function.lower()
        return {"status": "compiled", "name": spec["name"]}
    except Exception as error:
        return {"status": "rejected", "stage": stage, "reason": reason(error)}


def main():
    elf, contracts_path, selection_path, out_path = sys.argv[1:5]
    workers = int(sys.argv[5]) if len(sys.argv) > 5 else 8
    contracts = json.loads(Path(contracts_path).read_text())
    selected = json.loads(Path(selection_path).read_text())
    image = Image(elf, contracts)
    work = tempfile.mkdtemp(prefix="uniform-compile-")
    pending = []

    def reap():
        pid, result_path = pending.pop(0)
        os.waitpid(pid, 0)
        return result_path

    for item in selected:
        while len(pending) >= workers:
            reap()
        address = int(item["function"], 16)
        result_path = os.path.join(work, f"{address:x}.json")
        pid = os.fork()
        if pid == 0:
            try:
                Path(result_path).write_text(json.dumps(compile_spec(image, address)))
                os._exit(0)
            except BaseException:
                os._exit(1)
        pending.append((pid, result_path))
        if len(pending) % 50 == 0:
            print(f"forked {len(pending)} (latest {item['function']})", flush=True)
    while pending:
        reap()

    results = {}
    for item in selected:
        address = int(item["function"], 16)
        path = os.path.join(work, f"{address:x}.json")
        outcome = json.loads(Path(path).read_text()) if os.path.exists(path) else {"status": "crash"}
        outcome["hits"] = item["hits"]
        results[item["function"]] = outcome
    Path(out_path).write_text(json.dumps(results, indent=1))
    compiled = sum(1 for r in results.values() if r["status"] == "compiled")
    print(f"selected={len(selected)} compiled={compiled} rejected={len(selected) - compiled}")


if __name__ == "__main__":
    main()
