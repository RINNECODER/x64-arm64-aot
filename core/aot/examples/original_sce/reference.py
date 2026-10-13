import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    source=args.source_root.resolve()
    out=args.output.resolve()
    if out.exists():
        parser.error('choose a fresh output directory')
    out.mkdir(parents=True)
    revision='c93771e0f9bf4f0993c3c317d7df4cc01888fb72'
    hashes={}
    for name in ['main.cpp','demo_renderer.cpp','demo_renderer.hpp']:
     raw=subprocess.check_output(['git','-C',str(source),'show',revision+':src/'+name]);(out/name).write_bytes(raw);hashes[name]=hashlib.sha256(raw).hexdigest()
    p=out/'demo_renderer.cpp';text=p.read_text();begin=text.index('[[noreturn]] void run(');end=text.rindex('} // namespace ps5::demo')
    text=text[:begin]+'''[[noreturn]] void run(DrawScene draw, std::string_view ready_message) noexcept {
        std::vector<std::uint32_t> pixels(frame_bytes / sizeof(std::uint32_t));
        Canvas canvas(pixels.data());
        draw(canvas);
        std::vector<std::uint32_t> linear(frame_width * frame_height);
        for (unsigned y=0;y<frame_height;++y)
            for (unsigned x=0;x<frame_width;++x) linear[y*frame_width+x]=pixels[tiled_byte_offset(x,y)/sizeof(std::uint32_t)];
        const auto path = std::getenv("C5_REFERENCE_OUTPUT");
        FILE* file = path ? std::fopen(path, "wb") : nullptr;
        if (!file || std::fwrite(linear.data(), sizeof(std::uint32_t), linear.size(), file) != linear.size()) std::exit(91);
        std::fclose(file);
        std::fprintf(stderr, "reference: %.*s\\n", static_cast<int>(ready_message.size()), ready_message.data());
        std::exit(0);
    }
    '''+text[end:]
    text='#include <vector>\n#include <cstdio>\n#include <cstdlib>\n'+text;p.write_text(text)
    (out/'io.cpp').write_text('''#include <fcntl.h>
    #include <unistd.h>
    #include <cstdlib>
    #include <string>
    #include <cstdarg>
    extern "C" int reference_open(const char* path, int flags, ...) {
        const auto root=std::getenv("C5_REFERENCE_ROOT");
        const auto file=std::string(root ? root : "") + path;
        int mode=0;
        if(flags & O_CREAT) { va_list values;va_start(values,flags);mode=va_arg(values,int);va_end(values); }
        return ::open(file.c_str(),flags,mode);
    }
    extern "C" long reference_read(int descriptor,void* data,std::size_t size) { return ::read(descriptor,data,size); }
    extern "C" int reference_close(int descriptor) { return ::close(descriptor); }
    ''')
    for name in ['main','demo_renderer']:
     subprocess.run(['xcrun','clang++','-std=c++20','-O2','-arch','arm64','-Dopen=reference_open','-Dread=reference_read','-Dclose=reference_close','-c',str(out/(name+'.cpp')),'-o',str(out/(name+'.o'))],check=True)
    subprocess.run(['xcrun','clang++','-std=c++20','-O2','-arch','arm64',str(out/'main.o'),str(out/'demo_renderer.o'),str(out/'io.cpp'),'-o',str(out/'reference')],check=True)
    (out/'receipt.json').write_text(json.dumps({'revision':revision,'source_hashes':hashes,'renderer_adapted_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'adaptations':['replace only presentation/loop function with raw RGBA output','prefix open/read/close with independent host file adapters','retain the source 16-MiB tiled allocation and linearize with its address function'],'unchanged':'draw_scene, Canvas drawing algorithms, font, colors and asset parsing','scope':'independent pixel oracle, not platform/runtime or binary-reproduction proof'},indent=2)+'\n')
    print(out/'reference')

if __name__ == '__main__':
    main()
