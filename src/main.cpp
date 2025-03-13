#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>

#include "filter_module.hpp"
#include "packet.hpp"
#include "pcap_capture_module.hpp"
#include "spdlog/spdlog.h"
/*

void run(){


  // 抓包模块
  traffic_analyzer::PcapCaptureModule capturer =
      traffic_analyzer::PcapCaptureModule();
  // 开始抓包
  capturer.start_capture("eth1");



  // 过滤模块 负责把抓到的pcaket包重组成TCP Stream 并且从中提取HTTP响应
  traffic_analyzer::MyFilterModule filter = traffic_analyzer::MyFilterModule();
  // 开始过滤
  filter.start();



  // 循环从capturer 获取包，添加到filter
  std::thread capture_thread = std::thread([&capturer, &filter]() {
    while (1) {
      std::optional<traffic_analyzer::Packet> packet =
          capturer.get_next_packet();
      if (packet.has_value()) {
        spdlog::info("收到包{}", packet.value());
        filter.add_packet(packet.value());
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
  });


  // 新线程循环从filter 获取处理好的http响应
  std::thread filter_thread = std::thread([&filter]() {
    while (1) {
      std::optional<traffic_analyzer::HttpResponse> resp =
          filter.get_http_response();
      if (resp.has_value()) {
        spdlog::info("收到http响应：{}", resp.value());
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
  });
}
*/

void test_packet() {
  std::string http_data =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 4\r\n"
      "\r\n"
      "abcd";
  std::vector<std::byte> http_data_bytes;
  
  for (auto c : http_data) {
    http_data_bytes.push_back(std::byte{c});
  }

  std::string source_ip = "101.1.1.1";
  std::string destination_ip = "127.0.0.1";
  u_int16_t source_port = 1234;
  u_int16_t destination_port = 80;
  traffic_analyzer::Packet packet =
      traffic_analyzer::Packet(source_ip, destination_ip, source_port,
                               destination_port, 123, http_data_bytes);
  spdlog::info("packet:{}", packet.key);

  traffic_analyzer::MyFilterModule filter = traffic_analyzer::MyFilterModule();
  filter.add_packet(packet);
  std::optional<traffic_analyzer::HttpResponse> resp =
      filter.get_http_response();
  if (resp.has_value()) {
    spdlog::info("收到http响应：{}", resp.value());
  } else {
    spdlog::info("没有收到http响应");
  }
}

int main() {
  test_packet();
  return 0;
}