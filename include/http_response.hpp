#include <map>
#include <string>
#include <vector>
namespace traffic_analyzer {
struct HttpResponse {
  int status_code;
  std::map<std::string, std::string> headers;
  std::vector<std::byte> body;
  std::string content_type;
  std::string url;
  std::string filename;
};
}  // namespace traffic_analyzer