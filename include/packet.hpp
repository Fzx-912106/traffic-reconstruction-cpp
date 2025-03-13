#include <string>
#include <vector>
struct Packet{
  std::string src_ip;
  std::string dest_ip;
  u_int16_t src_port;
  u_int16_t dest_port;
  std::string protocol;
  int seq_number;
  std::vector<std::byte> payload;
};
