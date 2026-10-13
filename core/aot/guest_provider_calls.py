CALLS = {
    'malloc': (1, 'Malloc', 1, True),
    'calloc': (2, 'Calloc', 2, True),
    'realloc': (3, 'Realloc', 2, True),
    'free': (4, 'Free', 1, False),
    'memcpy': (5, 'Memcpy', 3, True),
    'memmove': (6, 'Memmove', 3, True),
    'memset': (7, 'Memset', 3, True),
    'memcmp': (8, 'Memcmp', 3, True),
    'strlen': (9, 'Strlen', 1, True),
    'pthread_getspecific': (10, 'GetSpecific', 1, True),
    'pthread_once': (11, 'Once', 2, True),
}


def declarations():
    return ['declare i1 @NativeAotGlibcFastBinding(i64, i64)', 'declare i1 @NativeAotGlibcOnceReady(i64)'] + [
        f'declare i64 @NativeAotGlibcFast{name}({", ".join(["i64"] * count)})'
        for kind, name, count, _ in CALLS.values() if kind != 11]
