#include "../include/filter.hpp"

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

PcapFilter::PcapFilter() {}

PcapFilter::~PcapFilter() {}

void PcapFilter::register_callback(FilterCallback callback) {
  callback_ = callback;
}

void PcapFilter::register_parser(std::unique_ptr<ProtocolParser> parser) {
  parsers_.push_back(std::move(parser));
}

void PcapFilter::process_pcap_file(const std::string &filename) {
  char errbuf[PCAP_ERRBUF_SIZE];
  handle_ = pcap_open_offline(filename.c_str(), errbuf);

  if (handle_ == nullptr) {
    throw std::runtime_error("Cannot open pcap file: " + std::string(errbuf));
  }

  struct pcap_pkthdr header;
  const u_char *packet;

  while ((packet = pcap_next(handle_, &header)) != nullptr) {
    try {
      ParsedPacket parsed = parse_packet(&header, packet);

      // 为HTTP协议的数据包保存到向量中
      if (parsed.protocol == ProtocolType::HTTP && !parsed.payload.empty()) {
        filtered_packets_.push_back(parsed);
      }

      // 尝试使用已注册的解析器解析数据包
      for (auto &parser : parsers_) {
        if (parser->can_parse(parsed) && parser->parse(parsed)) {
          if (callback_) {
            callback_(parsed);
          }
          break;
        }
      }
    } catch (const std::exception &e) {
      std::cerr << "Error parsing packet: " << e.what() << std::endl;
      continue;
    }
  }

  pcap_close(handle_);
  handle_ = nullptr;
}

ParsedPacket PcapFilter::parse_packet(const struct pcap_pkthdr *header,
                                      const u_char *packet) {
  ParsedPacket parsed;
  parsed.timestamp = header->ts;

  int linktype = pcap_datalink(handle_);
  const u_char *ip_start = packet;
  size_t header_offset = 0;

  switch (linktype) {
    case DLT_EN10MB:  // 以太网
    {
      const struct ether_header *eth =
          reinterpret_cast<const struct ether_header *>(packet);
      uint16_t eth_type = ntohs(eth->ether_type);

      // 只处理IPv4类型的以太网帧
      if (eth_type != ETHERTYPE_IP) {
        std::cout << "Non-IP Ethernet frame (0x" << std::hex << eth_type << ")"
                  << std::endl;
        return parsed;
      }

      header_offset = sizeof(struct ether_header);
      ip_start = packet + header_offset;
      break;
    }

    case 276:  // PPPoE（DSL连接常见）
    {
      const PPPoEEtherHeader *pppoe_eth =
          reinterpret_cast<const PPPoEEtherHeader *>(packet);
      uint16_t pppoe_type = ntohs(pppoe_eth->ether_type);

      // 检查是否为PPPoE会话阶段
      if (pppoe_type != 0x8864) {
        std::cout << "Non-PPPoE session frame (0x" << std::hex << pppoe_type
                  << ")" << std::endl;
        return parsed;
      }

      const PPPoEHeader *pppoe = reinterpret_cast<const PPPoEHeader *>(
          packet + sizeof(PPPoEEtherHeader));
      uint16_t ppp_proto = ntohs(pppoe->protocol);

      // 检查PPP负载是否为IPv4
      if (ppp_proto != 0x0021) {
        std::cout << "Non-IPv4 PPP payload (0x" << std::hex << ppp_proto << ")"
                  << std::endl;
        return parsed;
      }

      header_offset = sizeof(PPPoEEtherHeader) + sizeof(PPPoEHeader);
      ip_start = packet + header_offset;
      break;
    }

    default:
      std::cout << "Unsupported link type: " << linktype << std::endl;
      return parsed;
  }

  // 解析IP头
  const struct ip *ip_header = reinterpret_cast<const struct ip *>(ip_start);
  if (ip_header->ip_v != 4) {
    std::cout << "Invalid IP version: " << ip_header->ip_v << std::endl;
    return parsed;
  }

  // 提取IP地址
  char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);
  parsed.source_ip = src_ip;
  parsed.dest_ip = dst_ip;

  // 解析传输层协议
  size_t ip_header_len = ip_header->ip_hl * 4;
  const u_char *transport_header = ip_start + ip_header_len;

  if (ip_header->ip_p == IPPROTO_TCP) {
    const struct tcphdr *tcp_header =
        reinterpret_cast<const struct tcphdr *>(transport_header);
    parsed.source_port = ntohs(tcp_header->source);
    parsed.dest_port = ntohs(tcp_header->dest);
    parsed.protocol = ProtocolType::TCP;

    // HTTP检测逻辑
    if (parsed.dest_port == 80 || parsed.source_port == 80 ||
        parsed.dest_port == 8080 || parsed.source_port == 8080) {
      parsed.protocol = ProtocolType::HTTP;

      size_t tcp_header_len = tcp_header->th_off * 4;
      const u_char *payload = transport_header + tcp_header_len;
      size_t payload_len =
          ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;

      if (payload_len > 0) {
        parsed.payload.assign(payload, payload + payload_len);
      }
    }
  } else if (ip_header->ip_p == IPPROTO_UDP) {
    const struct udphdr *udp_header =
        reinterpret_cast<const struct udphdr *>(transport_header);
    parsed.source_port = ntohs(udp_header->source);
    parsed.dest_port = ntohs(udp_header->dest);
    parsed.protocol = ProtocolType::UDP;
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