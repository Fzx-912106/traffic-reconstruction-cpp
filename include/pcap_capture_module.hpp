#ifndef __PCAP_CAPTURE_MODULE_H__
#define __PCAP_CAPTURE_MODULE_H__

#include <pcap.h>

#include <atomic>
#include <mutex>
#include <queue>
#include <thread>

#include "capture_module.hpp"

namespace traffic_analyzer {
class PcapCaptureModule : public PacketCaptureModule {
private:
  std::atomic<bool> running = false;
  std::queue<Packet> packet_buffer;
  std::mutex buffer_mutex;
  size_t next_sequence_number = 0;
  std::thread capture_thread;
  pcap_t *handle = nullptr;

  static void packet_handle(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                            const u_char *packet);
  void capture_thread_func();

public:
  ~PcapCaptureModule() override;
  void start_capture(const std::string &interface_name) override;
  void stop_capture() override;
  std::optional<Packet> get_next_packet() override;
};
} // namespace traffic_analyzer

#endif