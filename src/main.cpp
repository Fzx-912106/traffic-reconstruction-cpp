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

// 测试用例：测试一个完整的HTTP响应
void test_packet() {
  std::string http_data =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 4\r\n"
      "\r\n"
      "a12341234123412341234!";
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
    spdlog::info("HTTP body: ");
    for (auto byte : resp.value().body) {
      spdlog::info("{}", static_cast<char>(byte));
    }
  } else {
    spdlog::info("没有收到http响应");
  }
}

using namespace traffic_analyzer;
// 测试用例1：测试一个完整的HTTP响应
int test_packet_one() {
  MyFilterModule filter;

  // 构造 HTTP 响应
  std::vector<std::vector<std::byte>> packets = {
      // 第一部分（HTTP 响应头部分）
      {
          std::byte('H'),  std::byte('T'),  std::byte('T'),  std::byte('P'),
          std::byte('/'),  std::byte('1'),  std::byte('.'),  std::byte('1'),
          std::byte(' '),  std::byte('2'),  std::byte('0'),  std::byte('0'),
          std::byte(' '),  std::byte('O'),  std::byte('K'),  std::byte('\r'),
          std::byte('\n'), std::byte('C'),  std::byte('o'),  std::byte('n'),
          std::byte('t'),  std::byte('e'),  std::byte('n'),  std::byte('t'),
          std::byte('-'),  std::byte('T'),  std::byte('y'),  std::byte('p'),
          std::byte('e'),  std::byte(':'),  std::byte(' '),  std::byte('t'),
          std::byte('e'),  std::byte('x'),  std::byte('t'),  std::byte('/'),
          std::byte('h'),  std::byte('t'),  std::byte('m'),  std::byte('l'),
          std::byte('\r'), std::byte('\n'), std::byte('\r'), std::byte('\n'),
      },

      // 第二部分（HTTP 响应体部分）
      {
          std::byte('H'),
          std::byte('e'),
          std::byte('l'),
          std::byte('l'),
          std::byte('o'),
          std::byte(','),
          std::byte(' '),
          std::byte('w'),
          std::byte('o'),
          std::byte('r'),
          std::byte('l'),
          std::byte('d'),
          std::byte('!'),
          std::byte('\r'),
          std::byte('\n'),
      }};

  // 使用相同的 key 代表同一个 TCP 连接
  std::string tcp_key = "192.168.1.1:12345->192.168.1.2:80";

  for (const auto& packet_data : packets) {
    Packet pkt;
    pkt.key = tcp_key;
    pkt.payload = packet_data;
    filter.add_packet(pkt);
  }

  // 获取解析后的 HTTP 响应
  auto response = filter.get_http_response();
  if (response) {
    std::cout << "HTTP Status Code: " << response->status_code << std::endl;
    std::cout << "Content-Type: " << response->content_type << std::endl;
    std::cout << "Content-Length: " << response->body.size() << std::endl;
    std::cout << "Body: ";
    for (auto byte : response->body) {
      std::cout << static_cast<char>(byte);
    }
    std::cout << std::endl;
  } else {
    std::cout << "No HTTP response detected!" << std::endl;
  }

  return 0;
}

int main() {
  test_packet();
  return 0;
}