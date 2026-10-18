#!/usr/bin/env python3
"""The real module profile: the per-function metadata and the shared indirect target-set pool
that the whole-title build uses.

The synthetic contract only knows the direct-call closure, so an indirect call has no declared
target set and a tail call into a non-closure function has no contract; both reject. Loading the
module profile lets the harness declare the same function set the census does.

The profile is read once per driver process. ``load`` accepts the module contracts JSON itself
(92 MB) or the compact cache ``compact`` writes (15 MB, same fields); the driver builds the cache
on first use. Nothing here is title-specific: the path comes from the caller.
"""
import json
from pathlib import Path


class Profile:
    def __init__(self, sizes, indirect, target_sets, raw=None):
        self.sizes = sizes
        self.indirect = indirect
        self.target_sets = target_sets
        self.raw = raw or {}

    @classmethod
    def load(cls, path):
        raw = json.loads(Path(path).read_text())
        if "functions" in raw:
            sizes, indirect = {}, {}
            for spec in raw["functions"]:
                address = spec["address"]
                sizes[address] = spec["size"]
                calls, jumps = spec.get("indirect_calls") or [], spec.get("indirect_jumps") or []
                if calls or jumps:
                    indirect[address] = ([(record["address"], record.get("target_set"), 0) for record in calls]
                                         + [(record["address"], record.get("target_set"), 1) for record in jumps])
            return cls(sizes, indirect, raw.get("target_sets") or [], raw)
        return cls({int(key): value for key, value in raw["sizes"].items()},
                   {int(key): [tuple(record) for record in value] for key, value in raw["indirect"].items()},
                   raw["target_sets"], raw)

    @classmethod
    def compact(cls, path, out):
        """Write the compact cache from the module contracts JSON."""
        profile = cls.load(path)
        payload = {"sizes": profile.sizes, "indirect": profile.indirect, "target_sets": profile.target_sets}
        for key in ("lifecycle", "max_segment_bytes", "module_image", "tls_model", "data", "imports",
                    "pointer_relocations", "data_bindings"):
            if key in profile.raw:
                payload[key] = profile.raw[key]
        Path(out).write_text(json.dumps(payload))
        return profile

    def has(self, address):
        return address in self.sizes

    def targets_of(self, index):
        if index is None or not isinstance(index, int) or not 0 <= index < len(self.target_sets):
            return []
        return self.target_sets[index]

    def indirect_records(self, address):
        """[(site, target_set_index, kind)] for a function, or () if it has none."""
        return self.indirect.get(address, ())

    @property
    def relocations(self):
        """[(slot, target)] pointer relocations the real image needs applied."""
        return [tuple(item) for item in (self.raw.get("pointer_relocations") or [])]

    @property
    def lifecycle(self):
        entry = self.raw.get("lifecycle") or {}
        return entry.get("init"), entry.get("fini")

    def spec(self, address, name, stub=False):
        """A minimal contract spec: the uniform ABI plus the real indirect annotations.

        A stub is a declared uniform function whose body the compiler replaces with a reporting
        trap: it satisfies an indirect target set without pulling the target's own closure in."""
        spec = {"name": name, "address": address, "size": self.sizes[address],
                "uniform": True, "result": "void", "parameters": []}
        if stub:
            spec["stub"] = True
        records = self.indirect.get(address)
        if records:
            spec["indirect_calls"] = [{"address": site, "target_set": index}
                                      for site, index, kind in records if kind == 0]
            spec["indirect_jumps"] = [{"address": site, "target_set": index}
                                      for site, index, kind in records if kind == 1]
        return spec
