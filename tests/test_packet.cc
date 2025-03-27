#include <gtest/gtest.h>
#include <tins/tins.h>

#include "packet.h"

TEST(PacketTest, packetInit) {
  Packet pkt{
      .length = 0,
      .timestamp = std::chrono::system_clock::now(),
      .source_ip = "1.1.1.1",
      .dest_ip = "",
      .source_port = 0,
      .dest_port = 0,
      .seq_num = 0,
      .ack_num = 0,
      .data = {},
  };
  EXPECT_EQ(pkt.length, 0);
  EXPECT_EQ(pkt.source_ip, "");
  EXPECT_EQ(pkt.dest_ip, "");
  EXPECT_EQ(pkt.source_port, 0);
  EXPECT_EQ(pkt.dest_port, 0);
  EXPECT_EQ(pkt.seq_num, 0);
  EXPECT_EQ(pkt.ack_num, 0);
  EXPECT_EQ(pkt.data.size(), 0);
}