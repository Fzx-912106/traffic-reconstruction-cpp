#include "filter_module.hpp"

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
            // 识别content-type
            std::string payload_str;
            for (auto byte : packet.payload) {
                payload_str.push_back(static_cast<char>(byte));
            }
            std::regex re("Content-Type: (.*?)[\r\n]");
            std::smatch match;
            if (std::regex_search(payload_str, match, re)) {
                resp.content_type = match[1];
            }
            // // 识别status code
            // re = std::regex("HTTP/1.1 (\\d{3})");
            // if (std::regex_search(payload_str, match, re)) {
            //     resp.status_code = std::stoi(match[1]);
            // }
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
            resp.body = tcp_streams[key];
            std::lock_guard<std::mutex> lock(streams_lock);
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
        HttpResponse resp = resp_buffer.front();
        resp_buffer.pop();
        return resp;
    }
}