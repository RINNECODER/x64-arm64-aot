#ifndef CORE_LIBS_PRX_LIBKERNEL_PTHREAD_GUESTTLSMACOS_HPP
#define CORE_LIBS_PRX_LIBKERNEL_PTHREAD_GUESTTLSMACOS_HPP

#include <cstdint>

struct GuestTlsDescriptor {
    std::uint64_t version;
    std::uint64_t templateAddress;
    std::uint64_t templateSize;
    std::uint64_t blockSize;
    std::uint64_t alignment;
    std::uint64_t key;
};

static_assert(sizeof(GuestTlsDescriptor) == 48);

struct GuestTlsIndex {
    const GuestTlsDescriptor* module;
    std::uint64_t offset;
};

extern "C" {
void Aps5GuestTlsRegister_nid_no_patch(GuestTlsDescriptor* descriptor);
void* Aps5GuestTlsAllocateThreadPointer_nid_no_patch(const GuestTlsDescriptor* descriptor);
void* Aps5GuestTlsGetAddr_nid_no_patch(const GuestTlsIndex* index);
void Aps5GuestTlsReleaseCurrentThread_nid_no_patch(const GuestTlsDescriptor* descriptor);
}

#endif
