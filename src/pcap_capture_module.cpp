#include "pcap_capture_module.hpp"

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "spdlog/spdlog.h"

namespace traffic_analyzer {

// 析构函数实现
PcapCaptureModule::~PcapCaptureModule() { stop_capture(); }
// 开始抓包
void PcapCaptureModule::start_capture(const std::string& interface_name) {
  if (this->running && this->handle != nullptr) {
    // 如果已经运行不做处理
    spdlog::info("已经在抓包");
    return;
  } else {
    char errbuf[PCAP_BUF_SIZE];
    this->handle =
        pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
    if (!this->handle) {
      spdlog::error("开启抓包失败");
      exit(-1);
    } else {
      this->capture_thread =
          std::thread(&PcapCaptureModule::capture_thread_func, this);
      this->running = true;
      spdlog::info("开始在网卡{}上抓包", interface_name);
      return;
    }
    // 修改状态为运行状态
  }
}
// 停止抓包
void PcapCaptureModule::stop_capture() {
  this->running = false;
  this->handle = nullptr;
  pcap_breakloop(this->handle);
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

void PcapCaptureModule::packet_handler(u_char* user_data,
                                       const struct pcap_pkthdr* pkthdr,
                                       const u_char* packet) {
  spdlog::debug("开始处理包");
  auto* capture = reinterpret_cast<PcapCaptureModule*>(user_data);

  // 提取IP头
  const struct ip* ip_header =
      reinterpret_cast<const struct ip*>(packet + 14);  // 跳过以太网头
  if (ip_header->ip_p != IPPROTO_TCP) {
    return;  // 仅处理TCP数据包
  }

  // 提取TCP头
  int ip_header_length = ip_header->ip_hl * 4;
  const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(
      reinterpret_cast<const uint8_t*>(ip_header) + ip_header_length);

  // 创建数据包对象
  auto source_ip = inet_ntoa(ip_header->ip_src);
  auto destination_ip = inet_ntoa(ip_header->ip_dst);
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
             destination_port, std::move(data), sequence_number};

  // 添加到缓冲区
  std::lock_guard<std::mutex> lock(capture->buffer_mutex);
  capture->packet_buffer.push(std::move(pkt));
}

void PcapCaptureModule::capture_thread_func() {
  spdlog::info("正在抓包");
  pcap_loop(this->handle, 0, &PcapCaptureModule::packet_handler,
            reinterpret_cast<u_char*>(this));
}
}  // namespace traffic_analyzer
