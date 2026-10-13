import re


def separate_multiply_add(source):
    count = 0

    def expand(match):
        nonlocal count
        name, typ, arguments = match.groups()
        depth, start = 0, 0
        parts = []
        for index, char in enumerate(arguments):
            if char in '(<[':
                depth += 1
            elif char in ')>]':
                depth -= 1
            elif char == ',' and depth == 0:
                parts.append(arguments[start:index].strip())
                start = index + 1
        parts.append(arguments[start:].strip())
        if depth != 0 or len(parts) != 3 or any(not part.startswith(typ + ' ') for part in parts):
            raise ValueError('unrecognized source reference multiply-add arguments')
        a, b, c = [part[len(typ) + 1:] for part in parts]
        count += 1
        temporary = f'%reference_separate_multiply_{count}'
        if temporary in source:
            raise ValueError('source reference temporary name collision')
        return f'  {temporary} = fmul {typ} {a}, {b}\n  {name} = fadd {typ} {temporary}, {c}'

    result = re.sub(r'^\s*(%\w+) = (?:tail )?call (float|<\d+ x float>) @llvm\.fmuladd\.[\w]+\((.*)\)$',
                    expand, source, flags=re.MULTILINE)
    if re.search(r'\bcall\b.*@llvm\.fm(?:uladd|a)\.', result) or re.search(r'\b(?:fadd|fmul|fsub)\s+(?:fast|contract|reassoc)\b', result):
        raise ValueError('unqualified floating point fusion remains in the source reference')
    if count == 0:
        raise ValueError('source reference no longer contains the expected multiply-add intrinsics')
    return result, count
