from elftools.elf.segments import Segment


def runtime_segments(elf):
    stream = elf.stream
    position = stream.tell()
    try:
        stream.seek(0, 2)
        length = stream.tell()
        offset, count, size = elf['e_phoff'], elf['e_phnum'], elf['e_phentsize']
        if elf.elfclass != 64 or size != 56 or not 0 < count < 0xffff:
            raise ValueError('unsupported runtime program header table')
        if offset > length or count * size > length - offset:
            raise ValueError('truncated runtime program header table')
        stream.seek(offset)
        headers = [elf.structs.Elf_Phdr.parse(stream.read(size)) for _ in range(count)]
        return [Segment(header, stream) for header in headers]
    finally:
        stream.seek(position)
