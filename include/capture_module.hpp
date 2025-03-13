#include <optional>
#include <queue>
#include <string>

#include "packet.hpp"

namespace CaptureModule {

class CaptureModule {
 public:
  virtual void start(std::string& interface_name);  // 启动抓包
  virtual void stop();                              // 停止抓包
  virtual std::optional<Packet> get_packet();
};

class PcapCaptureModule : CaptureModule {
 private:
  std::queue<Packet> packe_buffer;

 public:  
  void start(std::string& interface_name) override;
  void stop();
  std::optional<Packet> get_packet() {
    if (this->packe_buffer.empty()) {
      return std::nullopt;
    } else {
      Packet result = this->packe_buffer.front();
      packe_buffer.pop();
      return result;
    }
  }
};
}  // namespace CaptureModule