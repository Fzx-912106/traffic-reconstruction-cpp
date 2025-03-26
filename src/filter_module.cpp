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
    // 调试
    std::cout << "处理数据包：源IP=" << packet.source_ip << ":"
              << packet.source_port << ",目标IP=" << packet.dest_ip << ":"
              << packet.dest_port << ", tcp确认号：" << packet.ack_num
              << ", tcp序列号：" << packet.seq_num << std::endl;
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
    if (packet.source_port < packet.dest_port ) {
      stream_key = packet.source_ip + ":" + std::to_string(packet.source_port) +
                   "->" + packet.dest_ip + ":" +
                   std::to_string(packet.dest_port);
    } else { 
      stream_key = packet.dest_ip + ":" + std::to_string(packet.dest_port) +
                   "->" + packet.source_ip + ":" +
                   std::to_string(packet.source_port);
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

        std::cout << "发现HTTP请求，URL路径: " << url_path << std::endl;

        // 创建流密钥，用于关联请求和响应
        std::string request_key =
            packet.source_ip + ":" + std::to_string(packet.source_port) + "->" +
            packet.dest_ip + ":" + std::to_string(packet.dest_port);

        // 存储URL路径以便后续响应使用
        url_paths[request_key] = url_path;
      }
    }

    if (stream_start.starts_with("HTTP/") != std::string::npos) {

        
        std::cout << "发现HTTP响应，前100字节: " << stream_start << std::endl;

        // 尝试找到对应的请求URL
        std::string response_key =
            packet.dest_ip + ":" + std::to_string(packet.dest_port) + "->" +
            packet.source_ip + ":" + std::to_string(packet.source_port);

        // 也尝试反向的键
        std::string alt_response_key =
            packet.source_ip + ":" + std::to_string(packet.source_port) + "->" +
            packet.dest_ip + ":" + std::to_string(packet.dest_port);

        std::string url_path = "/";
        if (url_paths.find(response_key) != url_paths.end()) {
          url_path = url_paths[response_key];
          std::cout << "找到对应的请求URL: " << url_path << std::endl;
        } else if (url_paths.find(alt_response_key) != url_paths.end()) {
          url_path = url_paths[alt_response_key];
          std::cout << "找到对应的请求URL(使用替代键): " << url_path
                    << std::endl;
        } else {
          std::cout << "未找到对应的请求URL，使用默认路径" << std::endl;
        }

        std::string url = packet.source_ip + ":" +
                          std::to_string(packet.source_port) + url_path;

        HttpResponse response = parse_http_response(stream, url);
        if (!response.body.empty()) {
          std::cout << "成功解析HTTP响应，正文大小: " << response.body.size()
                    << " 字节" << std::endl;

          // 检查响应是否完整
          bool is_complete = true;

          // 检查Content-Length头
          if (response.headers.find("content-length") !=
              response.headers.end()) {
            try {
              size_t expected_length =
                  std::stoul(response.headers["content-length"]);
              if (response.body.size() < expected_length) {
                std::cout << "响应体不完整: 当前大小 " << response.body.size()
                          << " 字节, 预期大小 " << expected_length << " 字节"
                          << std::endl;
                is_complete = false;
              } else {
                std::cout << "响应体完整: 大小符合Content-Length要求"
                          << std::endl;
              }
            } catch (const std::exception &e) {
              std::cerr << "解析Content-Length失败: " << e.what() << std::endl;
            }
          }

          // 处理分块传输编码
  if (response.headers.find("transfer-encoding") != response.headers.end() &&
      response.headers["transfer-encoding"].find("chunked") !=
          std::string::npos) {
    std::cout << "检测到分块传输编码，尝试解码..." << std::endl;
    try {
      response.body = decode_chunked_body(response.body);
      std::cout << "分块解码后的正文大小: " << response.body.size() << " 字节"
                << std::endl;
    } catch (const std::exception &e) {
      std::cerr << "分块解码失败: " << e.what() << std::endl;
    }
  }

// 如果是HTML内容，检查是否有结束标签
if (response.content_type.find("text/html") == 0) {
  std::string body_str(
      reinterpret_cast<const char *>(response.body.data()),
      response.body.size());
  if (body_str.find("</html>") == std::string::npos && 
      body_str.find("</HTML>") == std::string::npos) {
    std::cout << "HTML响应不完整: 未找到</html>结束标签" << std::endl;
    
    // 检查 Content-Length 是否匹配，如果匹配则认为响应完整
    if (response.headers.find("content-length") != response.headers.end()) {
      try {
        size_t expected_length = std::stoul(response.headers["content-length"]);
        if (response.body.size() >= expected_length) {
          std::cout << "但 Content-Length 匹配，认为响应完整" << std::endl;
          is_complete = true;
        }
      } catch (const std::exception &e) {
        // 解析错误，继续使用 is_complete = false
      }
    }
    
    // 如果响应体大于一定大小且包含明显的 HTML 内容，也认为完整
    if (!is_complete && response.body.size() > 500 && 
        (body_str.find("<body") != std::string::npos || 
         body_str.find("<BODY") != std::string::npos)) {
      std::cout << "响应体包含足够的 HTML 内容，认为响应完整" << std::endl;
      is_complete = true;
    }
  } else {
    std::cout << "HTML响应完整: 找到</html>结束标签" << std::endl;
  }
}

          if (is_complete) {
            http_responses.push_back(response);
            // 处理后清除流以避免重复
            tcp_streams.erase(stream_key);
          } else {
            // 不完整，保留流以便后续数据包可以继续添加
            std::cout << "保留不完整的响应流以等待更多数据" << std::endl;
          }
        } else {
          // 如果响应体为空，可能是头部不完整，保留流
          std::cout << "响应体为空，保留流以等待更多数据" << std::endl;
        }
      
    }
  }

  return http_responses;
}

std::vector<HttpResponse> FilterModule::process_remaining_streams() {
  std::vector<HttpResponse> http_responses;

  std::cout << "处理剩余的 " << tcp_streams.size() << " 个TCP流" << std::endl;

  // 处理所有剩余的TCP流
  for (auto &[stream_key, stream] : tcp_streams) {
    // 检查是否看起来像HTTP响应
    std::string stream_start;
    size_t check_size = std::min(stream.size(), size_t(100));
    for (size_t i = 0; i < check_size; i++) {
      stream_start.push_back(
          static_cast<char>(std::to_integer<unsigned char>(stream[i])));
    }

    if (stream_start.find("HTTP/") != std::string::npos) {
      std::cout << "处理剩余的HTTP响应流: " << stream_key << std::endl;

      // 尝试找到对应的URL路径
      std::string url_path = "/";
      for (const auto &[key, path] : url_paths) {
        if (key.find(stream_key) != std::string::npos ||
            stream_key.find(key) != std::string::npos) {
          url_path = path;
          break;
        }
      }

      // 构建URL
      std::string url = stream_key + url_path;

      // 解析响应
      HttpResponse response = parse_http_response(stream, url);
      if (!response.body.empty()) {
        std::cout << "成功解析剩余HTTP响应，正文大小: " << response.body.size()
                  << " 字节" << std::endl;
        http_responses.push_back(response);
      }
    }
  }

  // 清空所有流
  tcp_streams.clear();

  return http_responses;
}

// 实现分块传输解码函数
std::vector<std::byte>
FilterModule::decode_chunked_body(const std::vector<std::byte> &chunked_body) {
  std::vector<std::byte> decoded_body;

  // 将字节向量转换为字符串以便于处理
  std::string body_str;
  body_str.reserve(chunked_body.size());
  for (const auto &b : chunked_body) {
    body_str.push_back(static_cast<char>(std::to_integer<unsigned char>(b)));
  }

  size_t pos = 0;
  while (pos < body_str.size()) {
    // 查找块大小行的结束位置
    size_t line_end = body_str.find("\r\n", pos);
    if (line_end == std::string::npos) {
      std::cerr << "分块解码错误: 找不到块大小行结束" << std::endl;
      break;
    }

    // 提取块大小（十六进制）
    std::string chunk_size_hex = body_str.substr(pos, line_end - pos);
    // 移除可能的块扩展
    size_t semicolon_pos = chunk_size_hex.find(';');
    if (semicolon_pos != std::string::npos) {
      chunk_size_hex = chunk_size_hex.substr(0, semicolon_pos);
    }

    // 转换十六进制大小为整数
    size_t chunk_size = 0;
    try {
      chunk_size = std::stoul(chunk_size_hex, nullptr, 16);
    } catch (const std::exception &e) {
      std::cerr << "分块解码错误: 无法解析块大小 '" << chunk_size_hex
                << "': " << e.what() << std::endl;
      break;
    }

    // 如果块大小为0，表示结束
    if (chunk_size == 0) {
      std::cout << "分块解码: 找到结束块" << std::endl;
      break;
    }

    // 计算块数据的开始和结束位置
    size_t chunk_start = line_end + 2; // 跳过CRLF
    size_t chunk_end = chunk_start + chunk_size;

    // 检查是否超出范围
    if (chunk_end + 2 > body_str.size()) { // +2 是为了包含块后的CRLF
      std::cerr << "分块解码错误: 块数据超出范围" << std::endl;
      break;
    }

    // 复制块数据到解码后的正文
    for (size_t i = chunk_start; i < chunk_end; ++i) {
      decoded_body.push_back(std::byte(body_str[i]));
    }

    // 移动到下一个块
    pos = chunk_end + 2; // 跳过块后的CRLF
  }

  return decoded_body;
}

HttpResponse
FilterModule::parse_http_response(const std::vector<std::byte> &data,
                                  const std::string &url) {
  HttpResponse response;
  response.url = url;

  // 添加调试输出
  std::cout << "解析HTTP响应，数据大小: " << data.size() << " 字节"
            << std::endl;

  // 检查数据是否足够大，至少包含一个有效的 HTTP 响应头
  if (data.size() < 16) { // 至少需要 "HTTP/1.x 200 OK\r\n" 这么多字符
    std::cerr << "数据太小，无法包含有效的HTTP响应" << std::endl;
    return response;
  }

  // 转换为字符串以便于处理
  std::string data_str;
  data_str.reserve(data.size());
  for (const auto &b : data) {
    data_str.push_back(static_cast<char>(std::to_integer<unsigned char>(b)));
  }

  // 查找 HTTP 响应的开始位置
  size_t http_start = 0;
  if (data_str.substr(0, 5) != "HTTP/") {
    // 如果不是以 HTTP/ 开头，尝试查找 HTTP/ 的位置
    http_start = data_str.find("HTTP/");
    if (http_start == std::string::npos) {
      std::cerr << "找不到HTTP响应标记" << std::endl;
      return response;
    }

    // 确保 HTTP/ 是一行的开始或者是状态行的一部分
    size_t line_start = data_str.rfind("\n", http_start);
    if (line_start != std::string::npos && line_start < http_start) {
      // 检查这一行是否看起来像状态行
      std::string potential_status_line =
          data_str.substr(line_start + 1, http_start - line_start + 10);
      if (potential_status_line.find(" ") != std::string::npos) {
        // 可能是状态行的一部分，调整http_start到行首
        http_start = line_start + 1;
      } else {
        // 不像状态行，可能是请求头的一部分
        std::cerr << "HTTP/标记不是状态行的一部分" << std::endl;
        return response;
      }
    }

    std::cout << "HTTP响应开始于偏移量: " << http_start << std::endl;
  }

  // 从 HTTP 响应开始处理
  std::string http_data = data_str.substr(http_start);

  // 查找头部和正文之间的分隔符
  size_t header_end = http_data.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    header_end = http_data.find("\n\n"); // 允许单个换行符
    if (header_end != std::string::npos) {
      header_end += 2; // 调整分隔符长度
    }
  } else {
    header_end += 4; // 调整分隔符长度
  }

  if (header_end == std::string::npos) {
    std::cerr << "无效的HTTP响应: 找不到头部和正文分隔符" << std::endl;
    return response; // 无效的HTTP响应
  }

  // 提取状态行和头部
  std::string headers_section = http_data.substr(0, header_end);
  std::cout << "HTTP头部大小: " << headers_section.size() << " 字节"
            << std::endl;

  // 解析状态行
  size_t first_line_end = headers_section.find("\r\n");
  if (first_line_end == std::string::npos) {
    first_line_end = headers_section.find("\n");
  }

  if (first_line_end != std::string::npos) {
    std::string status_line = headers_section.substr(0, first_line_end);
    std::cout << "状态行: " << status_line << std::endl;

    // 使用更健壮的方式提取状态码
    size_t http_pos = status_line.find("HTTP/");
    if (http_pos != std::string::npos) {
      size_t space_pos = status_line.find(" ", http_pos);
      if (space_pos != std::string::npos) {
        size_t code_start = space_pos + 1;
        size_t code_end = status_line.find(" ", code_start);
        if (code_end != std::string::npos) {
          std::string status_code_str =
              status_line.substr(code_start, code_end - code_start);
          try {
            response.status_code = std::stoi(status_code_str);
            std::cout << "解析到状态码: " << response.status_code << std::endl;
          } catch (const std::exception &e) {
            std::cerr << "解析状态码失败: " << e.what() << std::endl;
          }
        }
      }
    }
  }

  // 提取头部
  std::string headers_str = data_str.substr(0, header_end);

  std::cout << "headers_str: " << headers_str << std::endl;
  // 在第一种方法未能解析状态码时使用正则表达式
  if (response.status_code == 0) {
    std::smatch match;
    if (std::regex_search(headers_str, match, http_response_regex)) {
      response.status_code = std::stoi(match[1]);
      std::cout << "通过正则表达式解析到状态码: " << response.status_code
                << std::endl;
    }
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
      value.erase(0, value.find_first_not_of(" \t")); // 去除前导空格
      value.erase(value.find_last_not_of(" \t") + 1); // 去除尾随空格

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
  size_t body_start = http_start + header_end;
  // if (data_str.substr(header_end - 4, 4) == "\r\n\r\n") {
  //   body_start = header_end; // 已经包含了分隔符的长度
  // } else if (data_str.substr(header_end - 2, 2) == "\n\n") {
  //   body_start = header_end; // 已经包含了分隔符的长度
  // }

  std::cout << "正文开始位置: " << body_start << ", 数据总长度: " << data.size()
            << std::endl;

  if (body_start < data.size()) {
    response.body.assign(data.begin() + body_start, data.end());
    std::cout << "提取到正文，大小: " << response.body.size() << " 字节"
              << std::endl;
  }
  else
    std::cout << "无法提取正文，body_start >= data.size()" << std::endl;

  // 获取文件扩展名
  // 只有当我们有有效的内容类型和状态码时才生成文件名
  if (!response.content_type.empty() && response.status_code > 0) {
    std::string extension =
        determine_file_extension(response.content_type, response.body, url);

    // 生成唯一文件名
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         now.time_since_epoch())
                         .count();

    // 确保文件名有正确的扩展名
    if (response.content_type.find("text/html") == 0) {
      response.filename = "response_" + std::to_string(timestamp) + extension;
    } else if (response.content_type.find("image/") == 0) {
      response.filename = "image_" + std::to_string(timestamp) + extension;
    } else if (response.content_type.find("video/") == 0) {
      response.filename = "video_" + std::to_string(timestamp) + extension;
    } else if (response.content_type.find("audio/") == 0) {
      response.filename = "audio_" + std::to_string(timestamp) + extension;
    } else {
      response.filename = "file_" + std::to_string(timestamp) + extension;
    }

    std::cout << "设置响应文件名: " << response.filename << std::endl;
  }
  // else {
  //   std::cout << "跳过文件名生成，无效的响应" << std::endl;
  // }
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
      // 检测HTML内容
      if (data.size() >= 15) {
        std::string start_str;
        for (size_t i = 0; i < std::min(size_t(100), data.size()); i++) {
          start_str.push_back(
              static_cast<char>(std::to_integer<unsigned char>(data[i])));
        }

        // 转换为小写进行比较
        std::string lower_start = start_str;
        std::transform(lower_start.begin(), lower_start.end(),
                       lower_start.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        // 检查HTML标记
        if (lower_start.find("<!doctype html") != std::string::npos ||
            lower_start.find("<html") != std::string::npos ||
            lower_start.find("<head") != std::string::npos ||
            lower_start.find("<body") != std::string::npos) {
          return "text/html";
        }
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
  // std::cout << "content_type: " << content_type << std::endl;
  // std::cout << "url: " << url << std::endl;
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
