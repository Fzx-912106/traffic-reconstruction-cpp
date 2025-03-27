#ifndef PACKET_H
#define PACKET_H

#include <chrono>
#include <map>
#include <string>
#include <vector>
#include "tins/tins.h"

// =========== 常量 ===========
constexpr int HTTP_PORT = 80;
constexpr int HTTPS_PORT = 443;
constexpr int MAX_PACKET_SIZE = 65535;

// =========== 数据包结构 ===========
struct Packet {
  Tins::PDU& pdu;
  std::chrono::time_point<std::chrono::steady_clock> time;
};

struct HttpResponse {
  int status_code;
  std::map<std::string, std::string> headers;
  std::vector<std::byte> body;
  std::string content_type;
  std::string url;
  std::string filename;
};

#endif // PACKET_H
