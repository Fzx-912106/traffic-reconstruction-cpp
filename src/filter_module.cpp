#include "../include/filter_module.h"

#include <algorithm>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <regex>
#include <sstream>

// =========== 过滤模块实现 ===========
std::vector<HttpResponse>
FilterModule::filter_http(const std::vector<Packet> &packets) {
  std::vector<HttpResponse> http_responses;

  // 处理每个数据包并更新TCP流
  for (const auto &packet : packets) {
    // 仅处理HTTP/HTTPS端口上的数据包
    if (packet.source_port != HTTP_PORT && packet.source_port != HTTPS_PORT &&
        packet.dest_port != HTTP_PORT && packet.dest_port != HTTPS_PORT) {
      continue;
    }

    // 提取IP和TCP头
    const auto *ethernetStart = packet.data.data();
    const struct ip *ip_header = reinterpret_cast<const struct ip *>(
        reinterpret_cast<const char *>(ethernetStart) + 14); // 跳过以太网头
    int ip_header_length = ip_header->ip_hl * 4;
    const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(
        reinterpret_cast<const char *>(ip_header) + ip_header_length);
    int tcp_header_length = tcp_header->th_off * 4;

    // 提取载荷
    auto payloadOffset = 14 + ip_header_length + tcp_header_length;
    if (payloadOffset >= packet.length) {
      continue; // 无载荷
    }

    int payload_length = packet.length - payloadOffset;
    if (payload_length <= 0) {
      continue;
    }

    // 创建流密钥（源IP:端口 -> 目标IP:端口）
    std::string stream_key;
    if (packet.source_port < packet.dest_port) {
      stream_key =
          packet.source_ip + ":" + std::to_string(packet.source_port) + "->" +
          packet.dest_ip + ":" + std::to_string(packet.dest_port);
    } else {
      stream_key =
          packet.dest_ip + ":" + std::to_string(packet.dest_port) + "->" +
          packet.source_ip + ":" + std::to_string(packet.source_port);
    }

    // 添加载荷到TCP流
    auto &stream = tcp_streams[stream_key];
    size_t old_size = stream.size();
    stream.resize(old_size + payload_length);

    // 复制载荷数据到流
    for (int i = 0; i < payload_length; i++) {
      stream[old_size + i] = packet.data[payloadOffset + i];
    }

    // 检查此流是否包含HTTP响应
    // 将前100字节转换为字符串进行检查
    std::string stream_start;
    size_t check_size = std::min(stream.size(), size_t(100));
    for (size_t i = 0; i < check_size; i++) {
      stream_start.push_back(
          static_cast<char>(std::to_integer<unsigned char>(stream[i])));
    }
    // 解析HTTP请求路径
    if (stream_start.find("GET ") == 0 || stream_start.find("POST ") == 0) {
      size_t first_space = stream_start.find(' ');
      size_t second_space = stream_start.find(' ', first_space + 1);
      if (first_space != std::string::npos &&
          second_space != std::string::npos) {
        std::string url_path = stream_start.substr(
            first_space + 1, second_space - first_space - 1);
        for (auto packet_copy : packets) {
          if (packet_copy.source_ip == packet.source_ip &&
              packet_copy.source_port == packet.source_port) {
            packet_copy.url_path = url_path; // 创建副本保存到Packet
          }
        }
      }
    }
    if (stream_start.find("HTTP/") == 0) {
      // 这看起来像一个HTTP响应
      std::string url = packet.source_ip + ":" +
                        std::to_string(packet.source_port) + packet.url_path;
      HttpResponse response = parse_http_response(stream, url);
      if (!response.body.empty()) {
        http_responses.push_back(response);
        // 处理后清除流以避免重复
        tcp_streams.erase(stream_key);
      }
    }
  }

  return http_responses;
}

HttpResponse
FilterModule::parse_http_response(const std::vector<std::byte> &data,
                                  const std::string &url) {
  HttpResponse response;
  response.url = url;

  // 转换为字符串以便于处理
  std::string data_str;
  data_str.reserve(data.size());
  for (const auto &b : data) {
    data_str.push_back(static_cast<char>(std::to_integer<unsigned char>(b)));
  }

  // 查找头部和正文之间的分隔符
  size_t header_end = data_str.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    header_end = data_str.find("\n\n"); // 允许单个换行符
  }
  if (header_end == std::string::npos) {
    return response; // 无效的HTTP响应
  }

  // 提取头部
  std::string headers_str = data_str.substr(0, header_end);

  std::cout << "headers_str: " << headers_str << std::endl;
  // 解析状态行
  std::smatch match;
  if (std::regex_search(headers_str, match, http_response_regex)) {
    response.status_code = std::stoi(match[1]);
  }

  // 解析头部
  std::istringstream headers_stream(headers_str);
  std::string line;
  std::getline(headers_stream, line); // 跳过状态行

  while (std::getline(headers_stream, line) && !line.empty()) {
    // 处理多行头字段（如折叠空格）
    if (!line.empty() && line[0] == ' ' || line[0] == '\t') {
      // 合并到前一个字段的值
      response.headers.rbegin()->second += line;
      continue;
    }
    // 移除回车符
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    size_t colon_pos = line.find(':');
    if (colon_pos != std::string::npos) {
      std::string name = line.substr(0, colon_pos);
      std::transform(name.begin(), name.end(), name.begin(),
                     ::tolower); // 新增：转换为小写
      std::string value = line.substr(colon_pos + 1);

      // 修剪值前面的空白
      value.erase(0, value.find_first_not_of(" \t"));

      response.headers[name] = value;

      // 提取内容类型
      if (name == "content-type") { // 统一使用小写比较
        response.content_type = value;
        // 提取不带参数的MIME类型
        size_t semicolon_pos = response.content_type.find(';');
        if (semicolon_pos != std::string::npos) {
          response.content_type =
              response.content_type.substr(0, semicolon_pos);
        }
        // 去除前后空格
        response.content_type.erase(
            response.content_type.begin(),
            std::find_if(response.content_type.begin(),
                         response.content_type.end(),
                         [](unsigned char ch) { return !std::isspace(ch); }));
        response.content_type.erase(
            std::find_if(response.content_type.rbegin(),
                         response.content_type.rend(),
                         [](unsigned char ch) { return !std::isspace(ch); })
                .base(),
            response.content_type.end());
      }
    }
  }

  // 提取正文
  size_t body_start = header_end + (data_str[header_end] == '\r' ? 4:2); // 跳过分隔符
  if (body_start < data.size()) {
    response.body.assign(data.begin() + body_start, data.end());
  }

  // 生成文件名
  std::string extension = determine_file_extension(response.content_type,
                                                   response.body, response.url);
  response.filename =
      "response_" +
      std::to_string(
          std::chrono::system_clock::now().time_since_epoch().count()) +
      extension;

  return response;
}

// 在FilterModule中添加文件类型签名检测（参考Suricata的magic模块）
std::string
FilterModule::detect_by_magic_numbers(const std::vector<std::byte> &data) {
  if (data.size() >= 4) {
    // 常见文件类型检测
    const std::byte *header = data.data();

    // PNG
    if (header[0] == std::byte{0x89} && header[1] == std::byte{0x50} &&
        header[2] == std::byte{0x4E} && header[3] == std::byte{0x47})
      return "image/png";

    // JPEG
    if (header[0] == std::byte{0xFF} && header[1] == std::byte{0xD8})
      return "image/jpeg";

    // GIF
    if (header[0] == std::byte{0x47} && header[1] == std::byte{0x49} &&
        header[2] == std::byte{0x46} && header[3] == std::byte{0x38})
      return "image/gif";

    // PDF
    if (header[0] == std::byte{0x25} && header[1] == std::byte{0x50} &&
        header[2] == std::byte{0x44} && header[3] == std::byte{0x46})
      return "application/pdf";

    // ZIP
    if (header[0] == std::byte{0x50} && header[1] == std::byte{0x4B} &&
        header[2] == std::byte{0x03} && header[3] == std::byte{0x04})
      return "application/zip";
    // gif
    if (data.size() >= 3) {
      // GIF87a/GIF89a
      if (header[0] == std::byte{0x47} && header[1] == std::byte{0x49} &&
          header[2] == std::byte{0x46})
        return "image/gif";
    }
    // mpeg
    if (data.size() >= 15) {
      // MPEG audio（MP3）
      if ((header[0] == std::byte{0xFF} &&
           (header[1] & std::byte{0xE0}) == std::byte{0xE0}) ||
          (header[0] == std::byte{0x49} && header[1] == std::byte{0x44} &&
           header[2] == std::byte{0x33}))
        return "audio/mpeg";
    }
    // 通过文件内容魔数识别JavaScript文件
    if (data.size() >= 2) {
      if (data[0] == std::byte{0xFE} &&
          data[1] == std::byte{0xFF}) { // UTF-16BE BOM
        return "text/javascript";
      }
      if (data[0] == std::byte{0xFF} &&
          data[1] == std::byte{0xFE}) { // UTF-16LE BOM
        return "text/javascript";
      }
      if (data[0] == std::byte{0xEF} && data[1] == std::byte{0xBB} &&
          data[2] == std::byte{0xBF}) { // UTF-8 BOM
        return "text/javascript";
      }
    }
  }
  return "application/octet-stream"; // 默认未知类型
}

std::string
FilterModule::determine_file_extension(const std::string &content_type,
                                       const std::vector<std::byte> &data,
                                       const std::string &url) {
  // 将内容类型映射到文件扩展名
  static const std::map<std::string, std::string> extensions = {
      {"text/html", ".html"},
      {"text/plain", ".txt"},
      {"text/css", ".css"},
      {"text/javascript", ".js"},
      {"application/javascript", ".js"},
      {"application/json", ".json"},
      {"image/jpeg", ".jpg"},
      {"image/png", ".png"},
      {"image/gif", ".gif"},
      {"image/svg+xml", ".svg"},
      {"image/webp", ".webp"},
      {"audio/mpeg", ".mp3"},
      {"audio/wav", ".wav"},
      {"video/mp4", ".mp4"},
      {"video/webm", ".webm"},
      {"application/pdf", ".pdf"},
      {"application/zip", ".zip"},
      {"application/x-www-form-urlencoded", ".form"}};
  // std::cout << "extensions.size" << extensions.size() << std::endl;
  std::cout << "content_type: " << content_type << std::endl;
  std::cout << "url: " << url << std::endl;
  // 优先级1：基于Content-Type的扩展名
  if (!content_type.empty()) {
    auto it = extensions.find(content_type);
    if (it != extensions.end())
      return it->second;
  }

  // 优先级2：基于魔数的扩展名检测
  std::string magic_type = detect_by_magic_numbers(data);
  if (magic_type != "application/octet-stream") {
    auto it = extensions.find(magic_type);
    if (it != extensions.end())
      return it->second;
  }

  // 优先级3：基于URL路径的扩展名猜测（如/download/file.exe）
  size_t last_dot = url.find_last_of('.');
  if (last_dot != std::string::npos) {
    std::string ext = url.substr(last_dot);
    if (ext.size() <= 5 && ext.find('?') == std::string::npos) {
      // 限制扩展名长度，防止类似“.html?param=1”的情况
      return ext;
    }
  }

  return ".bin"; // 最终默认值
}