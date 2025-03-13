#include <spdlog/spdlog.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>

#include "packet.hpp"
#include "pcap_capture_module.hpp"

int main() {
  auto capturer = traffic_analyzer::PcapCaptureModule();
  capturer.start_capture("enp3s0");
  while (1) {
    std::optional<traffic_analyzer::Packet> packet = capturer.get_next_packet();
    if (packet) {
      spdlog::info("收到包{}", packet.value());
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
}
