#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <regex>

#include "http_response.hpp"
#include "packet.hpp"
namespace traffic_analyzer {

// 过滤模块接口
// 过滤模块 负责把抓到的pcaket包重组成TCP Stream 并且从中提取HTTP响应
class FilterModule {
 public:
  virtual ~FilterModule() = default;

  // virtual void start();
  // virtual void stop();
  virtual void add_packet(Packet packet) = 0;
  virtual std::optional<HttpResponse> get_http_response() = 0;
};

// 过滤模块 负责把抓到的pcaket包重组成TCP Stream 并且从中提取HTTP响应
class MyFilterModule : public FilterModule {
 private:
  // tcp_streams保存了所有的TCP流
  std::map<std::string, std::vector<std::byte>> tcp_streams;
  std::mutex streams_lock;
  std::queue<HttpResponse> resp_buffer;

 public:
  MyFilterModule();
  // void start() override;
  // void stop() override;
  void add_packet(Packet packet) override;
  bool is_http_response(const Packet& packet);
  std::optional<HttpResponse> get_http_response() override;
};

}  // namespace traffic_analyzer