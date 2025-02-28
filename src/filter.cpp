#include "../include/filter.hpp"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <iostream>
#include <cstring>

PcapFilter::PcapFilter() {}

PcapFilter::~PcapFilter() {}

void PcapFilter::register_callback(FilterCallback callback) {
    callback_ = callback;
}

void PcapFilter::register_parser(std::unique_ptr<ProtocolParser> parser) {
    parsers_.push_back(std::move(parser));
}

void PcapFilter::process_pcap_file(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
    
    if (handle == nullptr) {
        throw std::runtime_error("Cannot open pcap file: " + std::string(errbuf));
    }

    struct pcap_pkthdr header;
    const u_char* packet;
    
    while ((packet = pcap_next(handle, &header)) != nullptr) {
        try {
            ParsedPacket parsed = parse_packet(&header, packet);
            
            // 尝试使用已注册的解析器解析数据包
            for (auto& parser : parsers_) {
                if (parser->can_parse(parsed) && parser->parse(parsed)) {
                    if (callback_) {
                        callback_(parsed);
                    }
                    break;
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error parsing packet: " << e.what() << std::endl;
            continue;
        }
    }

    pcap_close(handle);
}

ParsedPacket PcapFilter::parse_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    ParsedPacket parsed;
    parsed.timestamp = header->ts;

    // 解析以太网头
    const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        throw std::runtime_error("Non-IP packet");
    }

    // 解析IP头
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    parsed.source_ip = src_ip;
    parsed.dest_ip = dst_ip;

    // 根据协议类型解析
    size_t ip_header_len = ip_header->ip_hl * 4;
    const u_char* transport_header = packet + sizeof(struct ether_header) + ip_header_len;

    if (ip_header->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(transport_header);
        parsed.source_port = ntohs(tcp_header->source);
        parsed.dest_port = ntohs(tcp_header->dest);
        
        // 提取负载数据
        size_t tcp_header_len = tcp_header->th_off * 4;
        const u_char* payload = transport_header + tcp_header_len;
        size_t payload_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;
        
        if (payload_len > 0) {
            parsed.payload.assign(payload, payload + payload_len);
        }
    }
    else if (ip_header->ip_p == IPPROTO_UDP) {
        const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(transport_header);
        parsed.source_port = ntohs(udp_header->source);
        parsed.dest_port = ntohs(udp_header->dest);
        
        // 提取负载数据
        const u_char* payload = transport_header + sizeof(struct udphdr);
        size_t payload_len = ntohs(udp_header->len) - sizeof(struct udphdr);
        
        if (payload_len > 0) {
            parsed.payload.assign(payload, payload + payload_len);
        }
    }

    // 检测协议类型
    if (parsed.dest_port == 80 || parsed.dest_port == 8080) {
        parsed.protocol = ProtocolType::HTTP;
    }
    else if (parsed.dest_port == 53) {
        parsed.protocol = ProtocolType::DNS;
    }
    else if (parsed.dest_port == 21) {
        parsed.protocol = ProtocolType::FTP;
    }
    else {
        parsed.protocol = ProtocolType::UNKNOWN;
    }

    // 检测内容类型
    parsed.content_type = detect_content_type(parsed.payload);

    return parsed;
}

ContentType PcapFilter::detect_content_type(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return ContentType::UNKNOWN;
    }

    // 简单的文件特征码检测
    static const std::map<std::vector<uint8_t>, ContentType> signatures = {
        {{0xFF, 0xD8, 0xFF}, ContentType::IMAGE},  // JPEG
        {{0x89, 0x50, 0x4E, 0x47}, ContentType::IMAGE},  // PNG
        {{0x66, 0x74, 0x79, 0x70}, ContentType::VIDEO}   // MP4
    };

    for (const auto& sig : signatures) {
        if (data.size() >= sig.first.size() && 
            std::equal(sig.first.begin(), sig.first.end(), data.begin())) {
            return sig.second;
        }
    }

    // 检测文本内容
    if (std::all_of(data.begin(), data.end(), [](uint8_t c) { 
        return c < 128; // ASCII文本
    })) {
        return ContentType::TEXT;
    }

    return ContentType::UNKNOWN;
}