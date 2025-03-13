#include <map>
#include <mutex>
#include <optional>
#include <regex>

#include "http_response.hpp"
#include "packet.hpp"
namespace traffic_analyzer {

// 过滤模块接口
// 过滤模块 负责把抓到的pcaket包重组成TCP Stream 并且从中提取HTTP响应
class FilterModule {
 public:
  virtual ~FilterModule() = default;
  // 开始过滤
  virtual void start();
  virtual void stop();
  virtual void add_packet(Packet packet);
  virtual std::optional<HttpResponse> get_http_response();
};

// 过滤模块 负责把抓到的pcaket包重组成TCP Stream 并且从中提取HTTP响应
class MyFilterModule : public FilterModule {
 private:
  std::map<std::string, std::vector<std::byte>> tcp_streams;
  std::mutex streams_lock;
  bool is_http_response(const Packet& packet);

 public:
  void start() override;
  void stop() override;
  void add_packet(Packet packet) override;
  std::optional<HttpResponse> get_http_response() override;
};

}  // namespace traffic_analyzer