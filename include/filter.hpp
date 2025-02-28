#ifndef PCAP_FILTER_HPP
#define PCAP_FILTER_HPP

#include <pcap.h>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <functional>

// 协议类型枚举
enum class ProtocolType {
    UNKNOWN,
    HTTP,
    FTP,
    DNS
};

// 内容类型枚举
enum class ContentType {
    UNKNOWN,
    TEXT,      // HTML, JSON等
    IMAGE,     // JPEG, PNG等
    VIDEO      // MP4, FLV等
};

// 解析后的数据包结构
struct ParsedPacket {
    struct timeval timestamp;
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    ProtocolType protocol;
    ContentType content_type;
    std::vector<uint8_t> payload;
};

// 协议解析器接口
class ProtocolParser {
public:
    virtual ~ProtocolParser() = default;
    virtual bool can_parse(const ParsedPacket& packet) = 0;
    virtual bool parse(ParsedPacket& packet) = 0;
};

// Filter类
class PcapFilter {
public:
    using FilterCallback = std::function<void(const ParsedPacket&)>;

    PcapFilter();
    ~PcapFilter();

    // 从pcap文件读取并解析
    void process_pcap_file(const std::string& filename);
    
    // 注册回调函数
    void register_callback(FilterCallback callback);
    
    // 注册协议解析器
    void register_parser(std::unique_ptr<ProtocolParser> parser);

private:
    // 基础包解析
    ParsedPacket parse_packet(const struct pcap_pkthdr* header, const u_char* packet);
    
    // 判断文件类型
    ContentType detect_content_type(const std::vector<uint8_t>& data);

    std::vector<std::unique_ptr<ProtocolParser>> parsers_;
    FilterCallback callback_;
};

#endif // PCAP_FILTER_HPP