#include "../include/filter.hpp"

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <stdexcept>

PcapFilter::PcapFilter() : handle_(nullptr) {}
PcapFilter::~PcapFilter() {
  if (handle_) pcap_close(handle_);
}

void PcapFilter::register_callback(FilterCallback callback) {
  callback_ = callback;
}

void PcapFilter::register_parser(std::unique_ptr<ProtocolParser> parser) {
  parsers_.push_back(std::move(parser));
}

void PcapFilter::process_pcap_file(const std::string &filename) {
  char errbuf[PCAP_ERRBUF_SIZE];
  handle_ = pcap_open_offline(filename.c_str(), errbuf);
  if (!handle_)
    throw std::runtime_error("Cannot open pcap file: " + std::string(errbuf));

  struct pcap_pkthdr header;
  const u_char *packet;
  while ((packet = pcap_next(handle_, &header)) != nullptr) {
    try {
      ParsedPacket parsed = parse_packet(&header, packet);
      if (parsed.protocol != ProtocolType::UNKNOWN) {
        std::cout << "[SUCCESS] Parsed: " << parsed.source_ip << ":"
                  << parsed.source_port << " -> " << parsed.dest_ip << ":"
                  << parsed.dest_port
                  << " Protocol=" << static_cast<int>(parsed.protocol)
                  << " Payload=" << parsed.payload.size() << " bytes\n";
        filtered_packets_.push_back(parsed);
      }
      for (auto &parser : parsers_) {
        if (parser->can_parse(parsed) && parser->parse(parsed)) {
          if (callback_) callback_(parsed);
          break;
        }
      }
    } catch (const std::exception &e) {
      std::cerr << "Error parsing packet: " << e.what() << std::endl;
    }
  }
  pcap_close(handle_);
  handle_ = nullptr;
}

ParsedPacket PcapFilter::parse_packet(const struct pcap_pkthdr *header,
                                      const u_char *packet) {
  ParsedPacket parsed;
  int linktype = pcap_datalink(handle_);
  size_t header_offset = 0;
  const u_char *ip_start = nullptr;

  // 处理链路层头部
  switch (linktype) {
    case DLT_EN10MB: {  // 以太网
      auto *eth = reinterpret_cast<const ether_header *>(packet);
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) return parsed;
      header_offset = sizeof(ether_header);
      ip_start = packet + header_offset;
      break;
    }
    case DLT_LINUX_SLL: {  // Linux cooked capture
      struct sll_header {  // 手动定义
        uint16_t packet_type;
        uint16_t arphrd_type;
        uint16_t ll_addr_len;
        uint8_t ll_addr[8];
        uint16_t protocol;
      };
      auto *sll = reinterpret_cast<const sll_header *>(packet);
      if (ntohs(sll->protocol) != ETHERTYPE_IP) return parsed;
      header_offset = 16;  // sll_header 固定长度
      ip_start = packet + header_offset;
      break;
    }
    case DLT_RAW: {       // 新增：原始 IP 数据包（链路类型 12）
      ip_start = packet;  // 直接指向 IP 头部
      header_offset = 0;
      break;
    }
    case 276: {  // PPPoE
      auto *pppoe_eth = reinterpret_cast<const PPPoEEtherHeader *>(packet);
      if (ntohs(pppoe_eth->ether_type) != 0x8864) return parsed;
      auto *pppoe = reinterpret_cast<const PPPoEHeader *>(
          packet + sizeof(PPPoEEtherHeader));
      if (ntohs(pppoe->protocol) != 0x0021) return parsed;  // IPv4
      header_offset = sizeof(PPPoEEtherHeader) + sizeof(PPPoEHeader);
      ip_start = packet + header_offset;
      break;
    }
    default:
      std::cerr << "[ERROR] Unsupported link type: " << linktype << std::endl;
      return parsed;
  }

  // 解析 IP 头部
  const struct ip *ip_header = reinterpret_cast<const struct ip *>(ip_start);
  if (ip_header->ip_v != 4) return parsed;               // 仅支持 IPv4
  if (ntohs(ip_header->ip_off) & 0x1FFF) return parsed;  // 丢弃分片包

  // 提取 IP 地址
  char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);
  parsed.source_ip = src_ip;
  parsed.dest_ip = dst_ip;

  // 解析传输层
  size_t ip_hlen = ip_header->ip_hl * 4;
  const u_char *transport = ip_start + ip_hlen;

  switch (ip_header->ip_p) {
    case IPPROTO_TCP: {
      auto *tcp = reinterpret_cast<const tcphdr *>(transport);
      parsed.source_port = ntohs(tcp->th_sport);
      parsed.dest_port = ntohs(tcp->th_dport);
      parsed.protocol = ProtocolType::TCP;

      // 提取 HTTP 负载
      size_t tcp_hlen = tcp->th_off * 4;
      const u_char *payload = transport + tcp_hlen;
      size_t payload_len = ntohs(ip_header->ip_len) - ip_hlen - tcp_hlen;

      if (payload_len > 0) {
        parsed.payload.assign(payload, payload + payload_len);
        // 检查 HTTP 特征
        bool is_http = (parsed.dest_port == 80 || parsed.source_port == 80 ||
                        parsed.dest_port == 8080 || parsed.source_port == 8080);
        if (!is_http && payload_len >= 4) {  // 检查负载内容
          std::string magic(parsed.payload.begin(), parsed.payload.begin() + 4);
          if (magic == "GET " || magic == "POST" ||
              magic.substr(0, 4) == "HTTP")
            is_http = true;
        }
        if (is_http) parsed.protocol = ProtocolType::HTTP;
      }
      break;
    }
    case IPPROTO_UDP: {
      auto *udp = reinterpret_cast<const udphdr *>(transport);
      parsed.source_port = ntohs(udp->uh_sport);
      parsed.dest_port = ntohs(udp->uh_dport);
      parsed.protocol = ProtocolType::UDP;
      break;
    }
    case IPPROTO_ICMP:
      parsed.protocol = ProtocolType::ICMP;
      break;
    default:
      parsed.protocol = ProtocolType::OTHER;
      break;
  }

  return parsed;
}

ContentType PcapFilter::detect_content_type(const std::vector<uint8_t> &data) {
  if (data.empty()) {
    return ContentType::UNKNOWN;
  }

  // 简单的文件特征码检测
  static const std::map<std::vector<uint8_t>, ContentType> signatures = {
      {{0xFF, 0xD8, 0xFF}, ContentType::IMAGE},        // JPEG
      {{0x89, 0x50, 0x4E, 0x47}, ContentType::IMAGE},  // PNG
      {{0x66, 0x74, 0x79, 0x70}, ContentType::VIDEO}   // MP4
  };

  for (const auto &sig : signatures) {
    if (data.size() >= sig.first.size() &&
        std::equal(sig.first.begin(), sig.first.end(), data.begin())) {
      return sig.second;
    }
  }

  // 检测文本内容
  if (std::all_of(data.begin(), data.end(), [](uint8_t c) {
        return c < 128;  // ASCII文本
      })) {
    return ContentType::TEXT;
  }

  return ContentType::UNKNOWN;
}

void PcapFilter::save_to_carray(const std::string &filename,
                                const std::vector<uint8_t> &data,
                                const std::string &array_name) {
  std::ofstream file(filename, std::ios::app);
  if (!file) {
    throw std::runtime_error("Cannot open output file: " + filename);
  }

  file << "const unsigned char " << array_name << "[] = {";
  for (size_t i = 0; i < data.size(); ++i) {
    if (i % 12 == 0) file << "\n    ";
    file << "0x" << std::hex << std::setw(2) << std::setfill('0')
         << static_cast<int>(data[i]);
    if (i < data.size() - 1) file << ", ";
  }
  file << "\n};\n";
  file << "const unsigned int " << array_name << "_len = " << std::dec
       << data.size() << ";\n\n";
}

void PcapFilter::save_packets_to_carray(
    const std::string &filename, const std::vector<ParsedPacket> &packets,
    const std::string &array_prefix) {
  std::cout << "Attempting to save " << packets.size() << " packets to "
            << filename << std::endl;

  std::ofstream file(filename);
  if (!file) {
    std::cerr << "Failed to open file: " << filename << std::endl;
    throw std::runtime_error("Cannot open output file: " + filename);
  }

  // 写入头部
  file << "// Auto-generated C arrays from filtered packets\n";
  file << "#ifndef FILTERED_PACKETS_H\n";
  file << "#define FILTERED_PACKETS_H\n\n";

  // 保存每个数据包
  for (size_t i = 0; i < packets.size(); ++i) {
    const auto &packet = packets[i];
    std::string array_name =
        array_prefix + "_" + std::to_string(packet.source_port) + "_" +
        std::to_string(packet.dest_port) + "_" + std::to_string(i);

    std::cout << "Writing packet " << i << " to array " << array_name
              << std::endl;
    save_to_carray(filename, packet.payload, array_name);
  }

  // 写入尾部
  file << "#endif // FILTERED_PACKETS_H\n";

  std::cout << "File writing completed" << std::endl;
}