import io
import subprocess
import unittest

from capstone.x86 import X86_OP_MEM
from elftools.elf.elffile import ELFFile

from compiler import Image
from debug_pointer_loads import candidates
import test_compiler


class DebugPointerLoadTests(unittest.TestCase):
    setUp = test_compiler.CompilerTests.setUp

    def test_inlined_pointer_scope_does_not_mark_later_scalar_reload(self):
        source=self.directory/'scope.c'
        source.write_text('struct Input { unsigned char *pointer; unsigned long number; unsigned int observed; };\nstatic inline unsigned int count(unsigned char *handle) { return handle[92]; }\nunsigned long test_entry(struct Input *input) { input->observed=count(input->pointer); return input->number; }\n')
        obj=self.directory/'scope.o'
        subprocess.run(['xcrun','clang','--target=x86_64-unknown-freebsd','-O2','-g','-gdwarf-4','-c',str(source),'-o',str(obj)],check=True,capture_output=True)
        elf=ELFFile(io.BytesIO(obj.read_bytes()))
        raw,contracts=test_compiler.fixture(elf.get_section_by_name('.text').data(),['ptr'])
        image_path=self.directory/'image.elf';image_path.write_bytes(raw);image=Image(image_path,contracts)
        found={record['address'] for record in candidates(image,obj)}
        instructions=list(image.decoder.disasm(image.read(0x1000,contracts['functions'][0]['size']),0x1000))
        scalar=[ins.address for ins in instructions if ins.mnemonic=='mov' and len(ins.operands)==2 and ins.operands[1].type==X86_OP_MEM and ins.reg_name(ins.operands[1].mem.base)=='rdi' and ins.operands[1].mem.disp==8]
        pointer=[ins.address for ins in instructions if ins.mnemonic=='mov' and len(ins.operands)==2 and ins.operands[1].type==X86_OP_MEM and ins.reg_name(ins.operands[1].mem.base)=='rdi' and ins.operands[1].mem.disp==0]
        self.assertTrue(scalar)
        self.assertTrue(pointer)
        self.assertTrue(set(pointer)<=found)
        self.assertFalse(set(scalar)&found)


if __name__=='__main__':
    unittest.main()
