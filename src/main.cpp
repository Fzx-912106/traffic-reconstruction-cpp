#include "../include/Capture.hpp"
#include "../include/filter.hpp"

#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>

int main()
{
  try
  { 
    // //Capture
    // PcapCapture capture("tun0");

    // // 打开输出文件
    // pcap_dumper_t *dumper = pcap_dump_open(capture.get_pcap_handle(), "capture.pcap");
    // if (!dumper)
    // {
    //   throw std::runtime_error("Failed to open output file");
    // }

    // // 启动捕获并同时保存文件
    // capture.start_capture([dumper](const struct pcap_pkthdr *hdr, const u_char *data)
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
    std::cout << "Starting packet analysis..." << std::endl;

    // 检查文件是否存在
    std::ifstream pcap_file("capture.pcap");
    if (!pcap_file.good())
    {
      throw std::runtime_error("capture.pcap file not found!");
    }
    pcap_file.close();

    PcapFilter filter;
    std::vector<ParsedPacket> http_packets;

    // 注册回调函数，收集HTTP数据包
    filter.register_callback([&http_packets](const ParsedPacket &packet)
                             {
            std::cout << "\n=== Packet Details ===\n"
                     << "Source: " << packet.source_ip << ":" << packet.source_port << "\n"
                     << "Destination: " << packet.dest_ip << ":" << packet.dest_port << "\n"
                     << "Protocol: " << static_cast<int>(packet.protocol) << "\n"
                     << "Content Type: " << static_cast<int>(packet.content_type) << "\n"
                     << "Payload size: " << packet.payload.size() << "\n"
                     << "===================" << std::endl;
            
            if (packet.protocol == ProtocolType::HTTP && !packet.payload.empty()) {
                http_packets.push_back(packet);
                std::cout << "Found HTTP packet, total count: " << http_packets.size() << std::endl;
                
                // 打印HTTP包的前100个字节
                std::cout << "HTTP payload preview: ";
                size_t preview_size = std::min(packet.payload.size(), size_t(100));
                for (size_t i = 0; i < preview_size; ++i) {
                    char c = static_cast<char>(packet.payload[i]);
                    if (isprint(c)) std::cout << c;
                    else std::cout << '.';
                }
                std::cout << std::endl;
            } });

    std::cout << "Processing pcap file..." << std::endl;
    filter.process_pcap_file("capture.pcap");
    std::cout << "Finished processing pcap file." << std::endl;

    if (http_packets.empty())
    {
      std::cout << "No HTTP packets found in the capture file." << std::endl;
      return 0;
    }

    std::cout << "Writing " << http_packets.size() << " packets to http_packets.h" << std::endl;
    filter.save_packets_to_carray("http_packets.h", http_packets, "http_packet");
  }
  
  catch (const std::exception &e)
  {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}