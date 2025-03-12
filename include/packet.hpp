#ifndef __PACKET_H__
#define __PACKET_H__

#include <cstddef>
#include <string>
#include <vector>

#include "fmt/format.h"

namespace traffic_analyzer {
struct Packet {
  std::string source_ip;
  std::string destination_ip;
  u_int16_t source_port;
  u_int16_t destination_port;
  std::vector<std::byte> payload;
  size_t sequence_number;
};
}  // namespace traffic_analyzer

// 让 fmt 直接格式化 Packet
template <>
struct fmt::formatter<traffic_analyzer::Packet> : fmt::formatter<std::string> {
  template <typename FormatContext>
  auto format(const traffic_analyzer::Packet& packet,
              FormatContext& ctx) const {
    // 格式化 Packet 中的成员
    return fmt::format_to(
        ctx.out(),
        "Packet{{source_ip: {}, destination_ip: {}, source_port: {}, "
        "destination_port: {}, sequence_number: {}}}",
        packet.source_ip, packet.destination_ip, packet.source_port,
        packet.destination_port, packet.sequence_number);
  }
};
#endif