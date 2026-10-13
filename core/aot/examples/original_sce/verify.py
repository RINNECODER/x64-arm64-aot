import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'gpu_cube'))
from images import read_bmp


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--asset-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--missing-asset',action='store_true')
    args=parser.parse_args()
    output=args.output.resolve()
    require(not output.exists(),'choose a fresh output directory')
    run=output/'run'
    (run/'app0/assets').mkdir(parents=True)
    (run/'app0/sce_sys').mkdir()
    for source,target in [('sce_sys/param.json','app0/sce_sys/param.json'),('assets/banner.txt','app0/assets/banner.txt')]:
        if args.missing_asset and source=='assets/banner.txt':
            continue
        shutil.copy2(args.asset_root.resolve()/source,run/target)
    binary,reference=args.binary.resolve(),args.reference.resolve()
    require(subprocess.check_output(['xcrun','lipo','-archs',str(binary)],text=True).strip()=='arm64','consumer is not an ARM64-only executable')
    expected=output/'reference.rgba'
    environment=dict(os.environ,C5_REFERENCE_ROOT=str(run),C5_REFERENCE_OUTPUT=str(expected))
    with (output/'reference.log').open('wb') as log:
        subprocess.run([str(reference)],cwd=run,env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=20,check=True)
    environment=os.environ.copy()
    require(not any(k.startswith('APS5_') for k in environment),'remove inherited APS5 test overrides')
    environment.update(APS5_DUMP_FRAMES='1',APS5_DUMP_SCALE='1',APS5_CAPTURE_TRACE='1',
                       ANYPS5_REQUIRE_VULKAN='1',ANYPS5_TEST_FRAME_LIMIT='1')
    with (output/'aot.log').open('wb') as log:
        result=subprocess.run([str(binary)],cwd=run,env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=30)
    text=(output/'aot.log').read_text(errors='replace')
    require(result.returncode==0,f'original package failed with {result.returncode}; inspect aot.log')
    for marker in ('architecture=arm64 translated=0','original module initialized','original module finalized','original SCE bundle teardown completed'):
        require(text.count(marker)==1,f'lifecycle evidence missing or repeated: {marker}')
    require('Vulkan device ready' in text and 'read back on the GPU' in text and 'Destroyed VkDevice' in text, 'GPU execution/teardown evidence is missing')
    message='APP0 ASSET FAILED' if args.missing_asset else 'APP0 ASSET LOADED'
    require('[notification] '+message in text,'asset result differs from the qualified fixture')
    require(sorted(p.name for p in run.glob('frame_*.bmp'))==['frame_000.bmp'],'unexpected capture set')
    width,height,actual=read_bmp(run/'frame_000.bmp')
    raw=expected.read_bytes()
    require((width,height)==(1920,1080) and len(raw)==width*height*4,'reference/capture dimensions differ')
    bgr=bytearray(width*height*3)
    for channel in range(3):
        bgr[channel::3]=raw[2-channel::4]
    changed=sum(actual[p:p+3]!=bgr[p:p+3] for p in range(0,len(actual),3))
    receipt={'schema':'anyps5.original-sce-acceptance.v1','binary_sha256':digest(binary),
             'reference_sha256':digest(reference),'missing_asset':args.missing_asset,'exit':result.returncode,
             'dimensions':[width,height],'different_pixels':changed,'equal_rgb':actual==bytes(bgr),
             'aot_pixels_sha256':hashlib.sha256(actual).hexdigest(),'reference_pixels_sha256':hashlib.sha256(bgr).hexdigest(),
             'lifecycle':'module initialization/finalization and host teardown verified',
             'scope':'original app and supplied PRX; host test requests shutdown at a completed API boundary; not guest natural return or game compatibility'}
    (output/'acceptance.json').write_text(json.dumps(receipt,indent=2)+'\n')
    require(changed==0,'RGB comparison differs; no tolerance is applied')
    print(output/'acceptance.json')


if __name__=='__main__':
    main()
