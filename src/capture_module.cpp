// =========== 抓包模块实现 ===========
#include "capture_module.h"
#include "packet.h"

#include <arpa/inet.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <tins/ethernetII.h>
#include <tins/rawpdu.h>
#include <tins/sniffer.h>
#include <tins/tins.h>    //新增：Tins库

      

CaptureModule::CaptureModule(const std::string &iface,
                             const std::string &filter)
    : interface(iface), filter_expr(filter) {}

CaptureModule::~CaptureModule() {
  stop();
  // if (handle) {
  //   pcap_close(handle);
  // }

  // libtins的Sniffer会自动清理资源
}

bool CaptureModule::initialize() {

  try {
    using namespace Tins;
    // 新增：使用libtins库进行抓包
    SnifferConfiguration config;
    config.set_filter(filter_expr);
    config.set_promisc_mode(true);
    config.set_snap_len(MAX_PACKET_SIZE);

    // 创建嗅探器
    sniffer = std::make_unique<Tins::Sniffer>(interface, config);
    return true;
  } catch (const std::runtime_error &e) {
    std::cerr << "初始化抓包模块出错: " << e.what() << std::endl;
    return false;
  }
}

// 数据包处理回调函数

bool CaptureModule::packet_handler(Tins::PDU &pdu) {
  
  try {
    // 提取以太网、IP层和TCP层
    const Tins::EthernetII &eth = pdu.rfind_pdu<Tins::EthernetII>();
    const Tins::IP &ip = eth.rfind_pdu<Tins::IP>();
    const Tins::TCP &tcp = ip.rfind_pdu<Tins::TCP>();

    // 创建数据包对象
    Packet pkt;
    pkt.timestamp = std::chrono::system_clock::now();
    pkt.source_ip = ip.src_addr().to_string();
    pkt.dest_ip = ip.dst_addr().to_string();
    pkt.source_port = tcp.sport();
    pkt.dest_port = tcp.dport();
    pkt.seq_num = tcp.seq();
    pkt.ack_num = tcp.ack_seq();

    // 提取负载数据
    if (tcp.find_pdu<Tins::RawPDU>()) {
      const Tins::RawPDU &raw = tcp.rfind_pdu<Tins::RawPDU>();
      const Tins::RawPDU::payload_type &payload = raw.payload();
      
      //复制负载数据
      pkt.length = payload.size();
      pkt.data.resize(payload.size());

      //复制整个数据包，包括头部
      std::memcpy(pkt.data.data(), payload.data(), payload.size());

      //添加到缓冲区
      std::lock_guard<std::mutex> lock(packet_mutex);
      packet_buffer.push_back(std::move(pkt));
    }

    return true;
  } catch (const std::exception &e) {
    std::cerr << "处理数据包出错: " << e.what() << std::endl;
    return true; //继续处理下一个数据包
  }
}

void CaptureModule::capture_thread_func() {
  try {
    using namespace Tins;
    sniffer->sniff_loop([this](PDU &pdu) {
      return this->packet_handler(pdu);
    });
  } catch (const std::exception &e) {
    if (running) {
      std::cerr << "捕获线程出错: " << e.what() << std::endl;
    }
  }
}

void CaptureModule::start() {
  if (running) {
    return;
  }

  running = true;
  capture_thread = std::thread(&CaptureModule::capture_thread_func, this);
}

void CaptureModule::stop() {
  if (!running) {
    return;
  }

  running = false;
  if (sniffer) {
    sniffer->stop_sniff();
  }

  if (capture_thread.joinable()) {
    capture_thread.join();
  }
}

std::vector<Packet> CaptureModule::get_packets() {
  std::lock_guard<std::mutex> lock(packet_mutex);
  std::vector<Packet> packets = std::move(packet_buffer);
  packet_buffer.clear();
  return packets;
}
