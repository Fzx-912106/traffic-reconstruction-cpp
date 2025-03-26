#ifndef FILTER_MODULE_H
#define FILTER_MODULE_H

#include "packet.h"
#include <map>
#include <regex>

class FilterModule {
private:
  std::map<std::string, std::vector<std::byte>> tcp_streams;
  std::map<std::string, std::string> url_paths; // 添加URL路径映射
  std::regex http_response_regex{R"(HTTP/\d\.\d\s+(\d+).*?)"};

public:
  FilterModule() = default;

  std::vector<HttpResponse> filter_http(const std::vector<Packet> &packets);

  void handle_packet(const Packet &packet,
                     std::vector<HttpResponse> &http_responses, int &retFlag);

  HttpResponse parse_http_response(const std::vector<std::byte> &data,
                                   const std::string &url);
  // 解码分块传输编码的函数
  std::vector<std::byte>
  decode_chunked_body(const std::vector<std::byte> &chunked_body);
  std::string determine_file_extension(const std::string &content_type,
                                       const std::vector<std::byte> &data,
                                       const std::string &url);

  std::string detect_by_magic_numbers(const std::vector<std::byte> &data);
  // 处理所有剩余的TCP流
  std::vector<HttpResponse> process_remaining_streams();
};

#endif // FILTER_MODULE_H