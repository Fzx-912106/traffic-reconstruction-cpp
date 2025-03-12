#include <spdlog/spdlog.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>

#include "capture.hpp"
#include "capture_module.hpp"
#include "filter.hpp"
#include "pcap_capture_module.hpp"

int main() {
  auto capturer = traffic_analyzer::PcapCaptureModule();
  capturer.start_capture("eth1");
  while (1) {
    auto packet = capturer.get_next_packet();
    if (packet) {
      spdlog::debug("收到包{}", packet.value().destination_ip);
    } else {
      spdlog::debug("没有需要处理的数据包");
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }

  /*
  try {
    // //Capture
    // PcapCapture capture("tun0");

    // // 打开输出文件
    // pcap_dumper_t *dumper = pcap_dump_open(capture.get_pcap_handle(),
    // "capture.pcap"); if (!dumper)
    // {
    //   throw std::runtime_error("Failed to open output file");
    // }

    // // 启动捕获并同时保存文件
    // capture.start_capture([dumper](const struct pcap_pkthdr *hdr, const
    // u_char *data)
    //                       {
    //         // 打印包信息
    //         std::cout << "Received packet, len: " << hdr->caplen
    //                  << ", timestamp: " << hdr->ts.tv_sec << std::endl;

    //         // 保存到文件
    //         pcap_dump((u_char*)dumper, hdr, data); });

    // // 运行10秒后停止
    // std::this_thread::sleep_for(std::chrono::seconds(20));
    // capture.stop_capture();

    // // 关闭文件
    // pcap_dump_close(dumper);

    // 2.filter
    spdlog::info("开始包分析");

    // 检查文件是否存在
    std::string pcap_file_path = std::string(
        "/home/fzx/Documents/traffic-reconstruction-cpp/capture.pcap");
    std::ifstream pcap_file(pcap_file_path);
    if (!pcap_file.good()) {
      spdlog::error("未找到文件：{}", pcap_file_path);
      pcap_file.close();
      exit(-1);
    }

    PcapFilter filter;
    std::vector<ParsedPacket> http_packets;

    // 注册回调函数，收集HTTP数据包
    filter.register_callback([&http_packets](const ParsedPacket &packet) {
      if (packet.protocol == ProtocolType::HTTP) {  // 首先检查是否为HTTP数据包
        http_packets.push_back(packet);             // 直接添加到向量中

        std::string content_type_str;
        switch (packet.content_type) {
          case ContentType::TEXT:
            content_type_str = "TEXT";
            break;
          case ContentType::IMAGE:
            content_type_str = "IMAGE";
            break;
          case ContentType::VIDEO:
            content_type_str = "VIDEO";
            break;
          default:
            content_type_str = "UNKNOWN";
            break;
        }

        // 打印数据包信息
        std::cout << "\n=== HTTP Packet Details ===\n"
                  << "Source: " << packet.source_ip << ":" << packet.source_port
                  << "\n"
                  << "Destination: " << packet.dest_ip << ":"
                  << packet.dest_port << "\n"
                  << "Content Type: " << content_type_str << "\n"
                  << "Payload size: " << packet.payload.size() << "\n";

        // 打印HTTP内容预览
        std::cout << "Content preview: ";
        size_t preview_size = std::min(packet.payload.size(), size_t(100));
        for (size_t i = 0; i < preview_size; ++i) {
          char c = static_cast<char>(packet.payload[i]);
          if (isprint(c))
            std::cout << c;
          else
            std::cout << '.';
        }
        std::cout << "\n====================" << std::endl;
      }
    });

    std::cout << "Processing pcap file..." << std::endl;
    filter.process_pcap_file(pcap_file_path);
    std::cout << "Finished processing pcap file." << std::endl;

    if (http_packets.empty()) {
      std::cout << "No HTTP packets found in the capture file." << std::endl;
      return 0;
    }

    std::cout << "Writing " << http_packets.size()
              << " packets to http_packets.h" << std::endl;
    filter.save_packets_to_carray("http_packets.h", http_packets,
                                  "http_packet");
  }

  catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
  return 0;
  */
}