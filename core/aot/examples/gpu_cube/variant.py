REPLACEMENTS = (
    (
        'extern int sceAgcInit(void *state, unsigned int defaultsRevision);',
        (
            'extern int sceAgcInit(unsigned int defaultsRevision);'
        ),
    ),
    (
        'sceAgcInit(&agc_state, 8)',
        (
            'sceAgcInit(8)'
        ),
    ),
    (
        'unsigned char attr[64]; for (int i = 0; i < 64; i++) attr[i] = 0;',
        (
            'unsigned char attr[80]; for (int i = 0; i < 80; i++) attr[i] = 0;'
        ),
    ),
    (
        'CxRegister context[16 + 14 + 1 + 34 + 32 + 32];',
        (
            'CxRegister context[16 + 14 + 3 + 34 + 32 + 32];'
        ),
    ),
    (
        '        for (int i = 0; i < SHDR_CXCOUNT(ps_handle); i++) context[cx++] = SHDR_CXREGS(ps_handle)[i];',
        (
            '        for (int i = 0; i < SHDR_CXCOUNT(ps_handle); i++) context[cx++] = SHDR_CXREGS(ps_handle)[i];\n'
            '        {\n'
            '            unsigned int clip = 0;\n'
            '            for (unsigned int r = 0; r < cx_record_count; r++)\n'
            '                if (cx_records[r].offset == 0x204) { clip = cx_records[r].value; break; }\n'
            '            for (int i = 0; i < cx; i++)\n'
            '                if (context[i].offset == 0x204) clip = context[i].value;\n'
            '            context[cx].offset = 0x204; context[cx].pad = 0;\n'
            '            context[cx].value = clip | (1u << 19); cx++;\n'
            '        }'
        ),
    ),
    (
        'extern int sceVideoOutWaitVblank(int handle);',
        (
            '/* Explicit PS5 flip completion, matching public SDL and hbldr VideoOut callers. */\n'
            'typedef long long FixtureEqueue;\n'
            'typedef struct { unsigned long ident; short filter; unsigned short flags; unsigned int fflags; long data; void *udata; } FixtureEvent;\n'
            '_Static_assert(sizeof(FixtureEvent) == 32, "PS5 event ABI size");\n'
            'extern int sceKernelCreateEqueue(FixtureEqueue *queue, const char *name);\n'
            'extern int sceKernelDeleteEqueue(FixtureEqueue queue);\n'
            'extern int sceKernelWaitEqueue(FixtureEqueue queue, FixtureEvent *event, int capacity, int *count, const unsigned int *timeout);\n'
            'extern int sceVideoOutAddFlipEvent(FixtureEqueue queue, int handle, void *udata);\n'
            'extern int sceVideoOutDeleteFlipEvent(FixtureEqueue queue, int handle);'
        ),
    ),
    (
        '    for (int frame = 0; frame < FRAMES; frame++) {',
        (
            '    FixtureEqueue flip_queue = 0;\n'
            '    if (sceKernelCreateEqueue(&flip_queue, "gpu_cube completed flips") < 0) return 1;\n'
            '    if (sceVideoOutAddFlipEvent(flip_queue, vhandle, 0) < 0) return 1;\n'
            '\n'
            '    for (int frame = 0; frame < FRAMES; frame++) {'
        ),
    ),
    (
        '        sceVideoOutWaitVblank(vhandle);',
        (
            '        /* Vblank timing alone does not release a submitted frame slot. */\n'
            '        FixtureEvent completed_flip;\n'
            '        int completed_count = 0;\n'
            '        if (sceKernelWaitEqueue(flip_queue, &completed_flip, 1, &completed_count, 0) < 0 || completed_count != 1) return 1;'
        ),
    ),
    (
        '    notify("mesh_test: fin");',
        (
            '    if (sceVideoOutDeleteFlipEvent(flip_queue, vhandle) < 0) return 1;\n'
            '    if (sceKernelDeleteEqueue(flip_queue) < 0) return 1;\n'
            '    notify("mesh_test: fin");'
        ),
    ),
)


def source_variant(original):
    for before, after in REPLACEMENTS:
        if original.count(before) != 1:
            raise ValueError('gpu_cube source no longer matches the qualified variant')
        original = original.replace(before, after)
    return original
