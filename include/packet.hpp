#ifndef __PACKET_H__
#define __PACKET_H__

#include <cstddef>
#include <string>
#include <vector>

#include "fmt/format.h"

namespace traffic_analyzer {
class Packet {
 public:
  std::string source_ip;
  std::string destination_ip;
  u_int16_t source_port;
  u_int16_t destination_port;
  // TCP包的序列号
  size_t sequence_number;
  // 这里是全部数据
  std::vector<std::byte> payload;
  // key是由source_ip, destination_ip, source_port, destination_port组成的字符串
  // 用于标识一个TCP连接
  std::string key;

  Packet(std::string source_ip, std::string destination_ip,
         u_int16_t source_port, u_int16_t destination_port,
         size_t sequence_number, std::vector<std::byte> payload)
      : source_ip(std::move(source_ip)),
        destination_ip(std::move(destination_ip)),
        source_port(source_port),
        destination_port(destination_port),
        sequence_number(sequence_number),
        payload(std::move(payload)) {
    this->key = this->source_ip + ":" + std::to_string(this->source_port) +
                " >>" + this->destination_ip + ":" +
                std::to_string(this->destination_port);
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
#endif // __PACKET_H__