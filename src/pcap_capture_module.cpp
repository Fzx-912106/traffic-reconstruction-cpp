#include "pcap_capture_module.hpp"

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "spdlog/spdlog.h"

namespace traffic_analyzer {
void new_packet_handle(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                       const u_char *packet) {}

// 析构函数实现
PcapCaptureModule::~PcapCaptureModule() { stop_capture(); }

// 开始抓包
void PcapCaptureModule::start_capture(const std::string &interface_name) {
  if (this->running && this->handle != nullptr) {
    // 如果已经运行不做处理
    spdlog::info("已经在抓包");
    return;
  }
  // 打开网卡
  char errbuf[PCAP_BUF_SIZE];
  this->handle = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
  if (!this->handle) {
    spdlog::error("开启抓包失败");
    throw std::runtime_error("无法打开网卡");
  }
  spdlog::info("成功打开网卡");

  this->capture_thread =
      std::thread(&PcapCaptureModule::capture_thread_func, this);
  this->running = true;
  spdlog::info("开始在网卡{}上抓包", interface_name);
}

// 停止抓包
void PcapCaptureModule::stop_capture() {
  // 如果没有运行则不做处理
  if (!running) return;
  if (this->handle) {
    pcap_breakloop(this->handle);
    pcap_close(this->handle);
    this->handle = nullptr;
  }
  if (this->capture_thread.joinable()) {
    // 等待线程处理完成
    this->capture_thread.join();
  }
  this->running = false;
  spdlog::info("停止抓包");
}
// 获取抓到的包
std::optional<Packet> PcapCaptureModule::get_next_packet() {
  // 加锁防止多线程冲突
  std::lock_guard<std::mutex> lock(buffer_mutex);
  if (packet_buffer.empty()) {
    // 如果队列为空则返回空对象
    return std::nullopt;
  } else {
    // 队列不为空返回队列头部元素
    Packet packet = std::move(this->packet_buffer.front());
    this->packet_buffer.pop();
    return packet;
  }
}
// PCAP包处理回调函数
void PcapCaptureModule::packet_handle(u_char *user_data,
                                      const struct pcap_pkthdr *pkthdr,
                                      const u_char *packet) {
  // 把user_data转换为PcapCaptureModule对象
  auto *capture = reinterpret_cast<PcapCaptureModule *>(user_data);

  // 提取IP头
  const struct ip *ip_header =
      reinterpret_cast<const struct ip *>(packet + 14);  // 跳过以太网头
  if (ip_header->ip_p != IPPROTO_TCP) {
    return;  // 仅处理TCP数据包
  }

  // 提取TCP头
  int ip_header_length = ip_header->ip_hl * 4;
  const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(
      reinterpret_cast<const uint8_t *>(ip_header) + ip_header_length);

  // 创建数据包对象
  std::string source_ip = inet_ntoa(ip_header->ip_src);
  std::string destination_ip = inet_ntoa(ip_header->ip_dst);
  auto source_port = ntohs(tcp_header->th_sport);
  auto destination_port = ntohs(tcp_header->th_dport);

  // 复制数据包数据
  std::vector<std::byte> data;
  data.resize(pkthdr->len);
  for (size_t i = 0; i < pkthdr->len; i++) {
    data[i] = static_cast<std::byte>(packet[i]);
  }
  size_t sequence_number = tcp_header->seq;

  Packet pkt{source_ip,        destination_ip,  source_port,
             destination_port, sequence_number, std::move(data)};

  // 添加到缓冲区
  std::lock_guard<std::mutex> lock(capture->buffer_mutex);
  capture->packet_buffer.push(std::move(pkt));
}

// 抓包工作线程
void PcapCaptureModule::capture_thread_func() {
  spdlog::info("正在抓包");
  while (running && handle) {
    int ret = pcap_dispatch(this->handle, -1, packet_handle,
                            reinterpret_cast<u_char *>(this));
    if (ret == PCAP_ERROR_BREAK) {
      spdlog::info("停止抓包");
      break;
    } else if (ret == PCAP_ERROR) {
      spdlog::error("抓包错误");
      break;
    }
  }
  spdlog::info("抓包线程结束");
}
}  // namespace traffic_analyzer
