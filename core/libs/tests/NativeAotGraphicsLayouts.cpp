#include "SceTypes.hpp"
#include <cstddef>

static_assert(sizeof(Shader) == 96);
static_assert(offsetof(Shader, user_data) == 8);
static_assert(offsetof(Shader, cx_registers) == 24);
static_assert(offsetof(Shader, sh_registers) == 32);
static_assert(offsetof(Shader, num_cx_registers) == 0x5b);
static_assert(offsetof(Shader, num_sh_registers) == 0x5c);
static_assert(sizeof(ShaderUserData) == 56);
static_assert(offsetof(ShaderUserData, sharp_resource_offset) == 8);
static_assert(offsetof(ShaderUserData, sharp_resource_count) == 0x2e);
static_assert(sizeof(ShaderRegister) == 8);
static_assert(sizeof(CommandBuffer) == 56);
static_assert(offsetof(CommandBuffer, bottom) == 0);
static_assert(offsetof(CommandBuffer, cursor_up) == 16);
static_assert(offsetof(CommandBuffer, callback) == 32);
static_assert(offsetof(CommandBuffer, user_data) == 40);
static_assert(sizeof(VideoOutBufferAttribute2) == 80);
static_assert(sizeof(VideoOutBuffers) == 32);

int main() {
    CommandBuffer state{};
    std::uint32_t words[8]{};
    state.bottom = words;
    state.cursor_up = words + 3;
    return state.cursor_up - state.bottom == 3 ? 0 : 1;
}
