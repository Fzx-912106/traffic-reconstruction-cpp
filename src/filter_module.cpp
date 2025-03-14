#include "filter_module.hpp"

#include <iostream>
namespace traffic_analyzer {
MyFilterModule::MyFilterModule() {
  tcp_streams = std::map<std::string, std::vector<std::byte>>();
  std::mutex streams_lock;
  resp_buffer = std::queue<HttpResponse>();
}
/**
 * 创建一个TCP流，将所有的包按照顺序放入其中
 */
void MyFilterModule::add_packet(Packet packet) {
  std::string key = packet.key;

  if (tcp_streams.find(key) == tcp_streams.end()) {
    tcp_streams[key] = std::vector<std::byte>();
  }

  for (auto byte : packet.payload) {
    tcp_streams[key].push_back(byte);
  }
  // 如果是HTTP响应，将其放入resp_buffer中
  if (is_http_response(packet)) {
    HttpResponse resp;

    std::string payload_str;
    for (auto byte : packet.payload) {
      payload_str.push_back(static_cast<char>(byte));
    }
    std::cout << "payload_str: " << payload_str << "end" << std::endl;
    /* 此处调试输出信息为：payload_str: HTTP/1.1 200 OK
    Content - Type : text /html

    end */
    // pos是HTTP响应头部结束的位置 截取响应头部
    size_t pos = payload_str.find("\r\n\r\n");
    if (pos != std::string::npos) {
      pos += 4;
    }
    // 解析content_length
    std::regex re("Content-Length: (\\d+)");
    std::smatch match;
    size_t content_length;
    if (std::regex_search(payload_str, match, re)) {
      content_length = std::stoi(match[1]);
      std::cout << "content_length: " << content_length << std::endl;
    } else
      std::cout << "no content_length" << std::endl;
    // 识别content-type
    re = std::regex("Content-Type: (.*?)[\r\n]");
    if (std::regex_search(payload_str, match, re)) {
      resp.content_type = match[1];
    }
    // 识别status code
    re = std::regex("HTTP/1.1 (\\d{3})");
    if (std::regex_search(payload_str, match, re)) {
      resp.status_code = std::stoi(match[1]);
    }
    // 识别url
    re = std::regex("GET (.*?) HTTP/1.1");
    if (std::regex_search(payload_str, match, re)) {
      resp.url = match[1];
    }
    // 识别filename
    re = std::regex("filename=\"(.*?)\"");
    if (std::regex_search(payload_str, match, re)) {
      resp.filename = match[1];
    }
    // 截取响应体,判断完整body是否已到达
    std::string body_str = payload_str.substr(pos, content_length);
    if (body_str.size() == content_length) {
      for (auto byte : body_str) {
        resp.body.push_back(std::byte(byte));
        std::cout << "Pushing byte: " << byte << std::endl;  // 没有输出调试信息
        std::cout << "Current body size: " << body_str
                  << std::endl;  // 调试发现该循环并未执行
      }
    }
    std::lock_guard<std::mutex> lock(streams_lock);
    // 输出调试信息检测resp.body是否在生成时就为空
    std::cout
        << "Pushing response, body size: " << resp.body.size()
        << std::endl;  // 此处存在问题 输出为Pushing response, body size: 0
    resp_buffer.push(resp);
  }
}
bool MyFilterModule::is_http_response(const Packet& packet) {
  // 一个HTTP响应的特征是包含“HTTP/1.1”字符串
  std::string payload_str;
  for (auto byte : packet.payload) {
    payload_str.push_back(static_cast<char>(byte));
  }
  return payload_str.find("HTTP/1.1") != std::string::npos;
}
std::optional<HttpResponse> MyFilterModule::get_http_response() {
  if (resp_buffer.empty()) {
    return std::nullopt;
  }
  HttpResponse resp;
  HttpResponse response = resp_buffer.front();
  resp_buffer.pop();
  std::cout << "Popping response, body size: " << resp.body.size()
            << std::endl;  // 此处存在问题 输出为Popping response, body size: 0
  return response;
}
}  // namespace traffic_analyzer