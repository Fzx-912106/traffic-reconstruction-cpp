#include "../include/Capture.hpp"
    
int main()
{
  try
  {
    PcapCapture capture("enp1s0");

    capture.start_capture([](const struct pcap_pkthdr *hdr, const u_char *data)
                          {
                            std::cout << "Received packet, len: " << hdr->caplen
                                      << ", timestamp: " << hdr->ts.tv_sec << std::endl;
                            // 这里添加实际处理逻辑
                          });

    // 运行一段时间后停止
    std::this_thread::sleep_for(std::chrono::seconds(10));
    capture.stop_capture();
  }
  catch (const std::exception &e)
  {
    std::cerr << "Error: " << e.what() << std::endl;
  }
  return 0;
}