TARGETS = {
    'apple-arm64': {'triple': 'arm64-apple-macosx13.0.0', 'readonly_section': '__DATA_CONST,__aot_imports'},
    'linux-arm64': {'triple': 'aarch64-unknown-linux-gnu', 'readonly_section': '.data.rel.ro.aot_imports'},
}


def target_spec(name):
    if name not in TARGETS:
        raise ValueError(f'unsupported native target: {name}')
    return TARGETS[name]
