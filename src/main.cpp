#include "../include/Capture.hpp"
#include "../include/filter.hpp"

#include <iostream>
#include <chrono>
#include <thread>

int main()
{
  try
  {
    PcapCapture capture("enp1s0");

    // 打开输出文件
    pcap_dumper_t *dumper = pcap_dump_open(capture.get_pcap_handle(), "capture.pcap");
    if (!dumper)
    {
      throw std::runtime_error("Failed to open output file");
    }

    // 启动捕获并同时保存文件
    capture.start_capture([dumper](const struct pcap_pkthdr *hdr, const u_char *data)
                          {
            // 打印包信息
            std::cout << "Received packet, len: " << hdr->caplen 
                     << ", timestamp: " << hdr->ts.tv_sec << std::endl;
            
            // 保存到文件
            pcap_dump((u_char*)dumper, hdr, data); });

    // 运行10秒后停止
    std::this_thread::sleep_for(std::chrono::seconds(10));
    capture.stop_capture();

    // 关闭文件
    pcap_dump_close(dumper);

    // 2. 解析保存的pcap文件
    PcapFilter filter;
    filter.register_callback([](const ParsedPacket &packet)
                             { std::cout << "Protocol: " << static_cast<int>(packet.protocol)
                                         << ", Content: " << static_cast<int>(packet.content_type)
                                         << ", From: " << packet.source_ip << ":" << packet.source_port
                                         << ", To: " << packet.dest_ip << ":" << packet.dest_port
                                         << ", Payload size: " << packet.payload.size()
                                         << std::endl; });

    filter.process_pcap_file("capture.pcap");
  }
  catch (const std::exception &e)
  {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}