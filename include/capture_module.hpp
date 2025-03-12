#ifndef __CAPTURE_MODULE_H__
#define __CAPTURE_MODULE_H__

#include <optional>
#include <packet.hpp>

namespace traffic_analyzer {
class PacketCaptureModule {
 public:
  virtual ~PacketCaptureModule() = default;
  virtual void start_capture(const std::string &interface_name) = 0;
  virtual void stop_capture() = 0;
  virtual std::optional<Packet> get_next_packet() = 0;
};
}  // namespace traffic_analyzer

#endif