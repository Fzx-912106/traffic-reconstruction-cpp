#include <map>
#include <string>
#include <vector>

#include "fmt/format.h"
namespace traffic_analyzer {
struct HttpResponse {
  int status_code;
  //std::map<std::string, std::string> headers;
  std::vector<std::byte> body;
  std::string content_type;
  std::string url;
  std::string filename;
};
}  // namespace traffic_analyzer
// 让 fmt 直接格式化 Packet
template <>
struct fmt::formatter<traffic_analyzer::HttpResponse>
    : fmt::formatter<std::string> {
  template <typename FormatContext>
  auto format(const traffic_analyzer::HttpResponse resp,
              FormatContext& ctx) const {
    // 格式化 Packet 中的成员
    return fmt::format_to(ctx.out(),
                          "HttpResponse{{status_code: {}, content_type: {}, "
                          "url: {}, filename: {}, headers: {{}}}}",
                          resp.status_code, resp.content_type, resp.url,
                          resp.filename);
  }
};
