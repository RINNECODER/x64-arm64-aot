#pragma once

#include <array>
#include <cstdint>

namespace AgcDriver::Pm4 {
struct DrawParameters;
}

namespace AgcDriver::Graphics {

std::array<std::uint32_t, 4> MeshIndexBufferDescriptor(const Pm4::DrawParameters& draw, std::uint64_t unreadAddress);

}
