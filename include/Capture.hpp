#ifndef PCAP_CAPTURE_HPP
#define PCAP_CAPTURE_HPP

#include <pcap.h>
#include <functional>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

// 原始数据包结构体定义
struct RawPacket
{
  struct timeval timestamp;
  uint32_t caplen;
  std::vector<uint8_t> data;
  size_t storage_size() const;
};

class PcapCapture
{
public:
  using CallbackType = std::function<void(const struct pcap_pkthdr *, const u_char *)>;

  PcapCapture(const std::string &interface, const std::string &filter = "tcp or udp");
  ~PcapCapture();

  void start_capture(CallbackType callback);
  void stop_capture();
  pcap_t *get_pcap_handle() { return pcap_handle_; }

private:
  static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
  void process_packets();

  std::string interface_;
  std::string filter_;
  pcap_t *pcap_handle_;
  std::atomic<bool> is_capturing_;

  std::queue<RawPacket> packet_queue_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  size_t current_queue_size_;
  const size_t max_queue_size_;

  CallbackType user_callback_;
  std::thread capture_thread_;
  std::thread processing_thread_;
};

#endif // PCAP_CAPTURE_HPP