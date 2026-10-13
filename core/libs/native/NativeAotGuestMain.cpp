#include "native/NativeAotGlibc.hpp"
#include "native/NativeAotGuest.hpp"

extern "C" const NativeAotGuestImage __aps5_guest_image;

int main(int argc, char** argv, char** envp) {
    NativeAotGlibc::Register();
    NativeAotGuest::Start(__aps5_guest_image, argc, argv, envp);
}
