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
  bool is_same_connection(const Packet& packet) {
    return this->destination_ip == packet.destination_ip &&
           this->destination_port == packet.destination_port &&
           this->source_ip == packet.source_ip &&
           this->source_port == packet.source_port;
  }
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
        "destination_port: {}, sequence_number: {}, payload_size: {}}}",
        packet.source_ip, packet.destination_ip, packet.source_port,
        packet.destination_port, packet.sequence_number, packet.payload.size());
  }
};
#endif