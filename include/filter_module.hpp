#include <map>
#include <regex>

#include "http_response.hpp"
#include "packet.hpp"
namespace traffic_analyzer {

// 过滤模块接口
class FilterModule {
 public:
  virtual ~FilterModule() = default;
  virtual std::vector<Packet> filter(std::vector<const Packet> packets) = 0;
};

}  // namespace traffic_analyzer