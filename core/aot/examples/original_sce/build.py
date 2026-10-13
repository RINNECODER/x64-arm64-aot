import argparse
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path[:0] = [str(ROOT/'core/aot'), str(ROOT/'tools'), str(ROOT/'3rdparty/pyelftools'), str(ROOT/'3rdparty/capstone/bindings/python')]


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--app',type=Path,required=True)
    parser.add_argument('--module',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--native-library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    capstone = args.native_library.resolve().parents[3]/'core/aot/capstone'
    if capstone.is_dir():
        os.environ.setdefault('LIBCAPSTONE_PATH', str(capstone))
    import guest_lift
    import guest_emit
    from nid_names import compute_nid
    OUT=args.output.resolve()
    require(not OUT.exists(), 'choose a fresh output directory')
    OUT.mkdir(parents=True)
    app = args.app.resolve()
    shim = args.module.resolve()
    require(hashlib.sha256(app.read_bytes()).hexdigest() == '73f1258991f51bd61f9d1c74721ec65c5c02a8c5dfffbfe775a85e7fbb08144b', 'application input changed')
    require(hashlib.sha256(shim.read_bytes()).hexdigest() == '8ee6e124993e1af26420cb455890fd002f5d6c7e78883c860ce45734e7d002bb', 'module input changed')
    manifest = args.source_root.resolve()/'tooling/native/runtime/imports.txt'
    require(hashlib.sha256(manifest.read_bytes()).hexdigest() == 'ef8f04e17c355495ee8120ef28b1648f7d4380eb5b9baeb7ab50034ffacfe8ea', 'source import manifest changed')
    module_names = [line.split('|')[0] for line in manifest.read_text().splitlines() if line and not line.startswith('#')]
    app_names = ['_init_env', 'atexit', 'exit', 'malloc', 'posix_memalign', 'free', 'open', 'read', 'close', 'sceSystemServiceHideSplashScreen', 'sceVideoOutOpen', 'sceKernelGetDirectMemorySize', 'sceKernelAllocateDirectMemory', 'sceKernelMapDirectMemory', 'sceVideoOutSetFlipRate', 'sceVideoOutSetBufferAttribute2', 'sceVideoOutRegisterBuffers2', 'sceVideoOutSubmitFlip', 'sceVideoOutWaitVblank', 'sceKernelSendNotificationRequest', 'sceKernelUsleep', 'strlen']
    by_nid = {}
    for name in [*module_names, *app_names]:
        key=compute_nid(name)
        require(key not in by_nid or by_nid[key] == name, 'ambiguous API identifier')
        by_nid[key]=name
    native_library=args.native_library.resolve()
    listing=subprocess.check_output(['xcrun','nm','-gU',str(native_library)],text=True,stderr=subprocess.DEVNULL)
    native_symbols={line.split()[-1][1:] for line in listing.splitlines() if len(line.split())>=3 and line.split()[-1].startswith('_')}
    allowed={('libkernel',1,'libkernel',1),('libkernel',1,'libkernel',257),
             ('libSceLibcInternal',1,'libSceLibcInternal',1),('libSceLibcInternalExt',1,'libSceLibcInternal',257),
             ('libSceSysmodule',1,'libSceSysmodule',257),('libSceSystemService',1,'libSceSystemService',1),
             ('libSceVideoOut',1,'libSceVideoOut',1)}
    records={}
    programs={}
    reports={}
    for name,path,abi in [('app',app,'sce-app'),('shim',shim,'sce-module')]:
        program=guest_lift.Program(path.read_bytes(),abi=abi);programs[name]=program
        for symbol in program.dynamic['symbols']:
            if symbol['section'] or not symbol['name']:continue
            canonical=guest_emit.canonical_name(program,symbol)
            identity=json.loads(canonical)
            require(tuple(identity[2:]) in allowed, f'unqualified system identity: {identity}')
            raw=by_nid[symbol['name'].split('#')[0]]
            choices=[n for n in [raw,raw+'_nid_postfix',raw+'_nid_no_patch'] if n in native_symbols]
            require(len(choices)==1, f'missing or ambiguous native symbol: {raw}: {choices}')
            record={'identity':canonical,'native':choices[0],'data':symbol['info']&15==1,'api':raw}
            require(canonical not in records or records[canonical]==record, 'conflicting system binding')
            records[canonical]=record
        report=guest_emit.build(path,OUT/(name+'-ir'),shards=8,jobs=1,abi=abi,namespace=name+'_')
        require(not report['unsupported'], 'unqualified instruction sites remain')
        reports[name]=report
    objects=list(OUT.glob('*-ir/*.ll'))
    def compile_ir(path):
        subprocess.run(['xcrun','clang','-O2','-arch','arm64','-Wno-override-module','-c',str(path),'-o',str(path.with_suffix('.o'))],check=True)
    with ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(compile_ir,objects))
    names=sorted({r['native'] for r in records.values()})
    assembly=['.section __DATA_CONST,__const','.p2align 3','.globl _OriginalNativeBindings','_OriginalNativeBindings:']
    assembly += ['.quad _'+name for name in names]
    (OUT/'bindings.S').write_text('\n'.join(assembly)+'\n')
    rows=[]
    for record in sorted(records.values(),key=lambda r:r['identity']):
        rows.append('    {'+json.dumps(record['identity'])+', '+json.dumps(record['native'])+', OriginalNativeBindings['+str(names.index(record['native']))+'], '+str(record['data']).lower()+'},')
    process=next(s for s in programs['app'].view.segments if s['type']==0x61000001)
    init=programs['shim'].dynamic['tags']['DT_INIT'];fini=programs['shim'].dynamic['tags']['DT_FINI']
    require(programs['shim'].dynamic['tags'].get('DT_INIT_ARRAYSZ',0)==0, 'module initializer array changed')
    require(programs['shim'].dynamic['tags'].get('DT_FINI_ARRAYSZ',0)==0, 'module finalizer array changed')
    source=(HERE/'driver.cpp.in').read_text()
    source=source.replace('INIT_ADDRESS',str(init)).replace('FINI_ADDRESS',str(fini)).replace('PROCESS_ADDRESS',str(process['vaddr'])).replace('PROCESS_BYTES',str(process['memsz'])).replace('ROWS','\n'.join(rows))
    (OUT/'driver.cpp').write_text(source)
    receipt={'inputs':{name:{'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for name,path in [('app',app),('shim',shim)]},'binding_count':len(records),'native_symbols':names,'bindings':list(records.values()),'reports':reports,
             'lifecycle':{'main_owner':'original entry code','module_init':init,'module_fini':fini,'module_preinit_array':'retained as module data; not scheduled as executable preinit; DT_INIT performs the original call'},'frame_limit':'optional host test shutdown at completed provider boundary, not a claim that guest main returns'}
    receipt['native_library_sha256']=hashlib.sha256(native_library.read_bytes()).hexdigest()
    receipt['runtime_sources']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'core/libs/native/NativeAotGuest.cpp', ROOT/'core/libs/native/NativeAotGuest.hpp', ROOT/'core/libs/native/NativeAotSce.cpp', ROOT/'core/libs/native/NativeAotSce.hpp', ROOT/'core/libs/native/NativeAotBundle.cpp', ROOT/'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp']}
    receipt['compiler_sources']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'core/aot').glob('*.py'))}
    (OUT/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('ready',len(records),'bindings',len(objects),'objects',OUT)

if __name__ == '__main__':
    main()
