#ifndef PCAP_FILTER_HPP
#define PCAP_FILTER_HPP

#include <pcap.h>

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

// 协议类型枚举
enum class ProtocolType {
  UNKNOWN,
  HTTP,
  TCP,
  UDP,
  ICMP,
  OTHER  // 新增通用类型
};

// 内容类型枚举
enum class ContentType { UNKNOWN, TEXT, IMAGE, VIDEO };

// 解析后的数据包结构
struct ParsedPacket {
  struct timeval timestamp;
  std::string source_ip;
  std::string dest_ip;
  uint16_t source_port = 0;  // 显式初始化
  uint16_t dest_port = 0;
  ProtocolType protocol = ProtocolType::UNKNOWN;
  ContentType content_type = ContentType::UNKNOWN;
  std::vector<uint8_t> payload;
};

// 修复结构体定义，确保内存对齐
#pragma pack(push, 1)
struct PPPoEHeader {
  uint8_t ver_type;
  uint8_t code;
  uint16_t session_id;
  uint16_t length;
  uint16_t protocol;
};

struct PPPoEEtherHeader {
  uint8_t dest[6];
  uint8_t source[6];
  uint16_t ether_type;
};
#pragma pack(pop)

// 协议解析器接口
class ProtocolParser {
 public:
  virtual ~ProtocolParser() = default;
  virtual bool can_parse(const ParsedPacket &packet) = 0;
  virtual bool parse(ParsedPacket &packet) = 0;
};

// Filter类
class PcapFilter {
 public:
  using FilterCallback = std::function<void(const ParsedPacket &)>;

  PcapFilter();
  ~PcapFilter();

  void process_pcap_file(const std::string &filename);
  void register_callback(FilterCallback callback);
  void register_parser(std::unique_ptr<ProtocolParser> parser);

  static void save_to_carray(const std::string &filename,
                             const std::vector<uint8_t> &data,
                             const std::string &array_name);
  static void save_packets_to_carray(
      const std::string &filename, const std::vector<ParsedPacket> &packets,
      const std::string &array_prefix = "packet");

 private:
  ParsedPacket parse_packet(const struct pcap_pkthdr *header,
                            const u_char *packet);
  ContentType detect_content_type(const std::vector<uint8_t> &data);

  std::vector<std::unique_ptr<ProtocolParser>> parsers_;
  FilterCallback callback_;
  std::vector<ParsedPacket> filtered_packets_;
  pcap_t *handle_;
};

#endif  // PCAP_FILTER_HPP