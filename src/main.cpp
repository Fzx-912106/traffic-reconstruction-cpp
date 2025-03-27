// 流量分析还原程序
// 使用C++20特性，捕获、过滤和还原HTTP内容
// 使用std::byte代替uint8_t

#include "control_module.h"
#include "spdlog/spdlog.h"

#include <iostream>
#include <string>
#include <thread>

// =========== 主函数 ===========
int main(int argc, char *argv[]) {
  std::string interface = "enp1s0";               // 默认接口
  std::string output_dir = "./http_output";       // 默认输出目录
  std::string filter_expr = "tcp port 80"; // 默认过滤器

  // 解析命令行参数
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-i" && i + 1 < argc) {
      interface = argv[++i];
    } else if (arg == "-o" && i + 1 < argc) {
      output_dir = argv[++i];
    } else if (arg == "-f" && i + 1 < argc) {
      filter_expr = argv[++i];
    } else if (arg == "-h" || arg == "--help") {
      spdlog::info("用法: {} [-i 接口] [-o 输出目录] [-f 过滤表达式]", argv[0]);
      spdlog::info("  -i  要抓取的网络接口 (默认: eth0)");
      spdlog::info("  -o  保存文件的输出目录 (默认: ./http_output)");
      spdlog::info("  -f  PCAP过滤表达式 (默认: tcp port 80 or tcp port 443)");
      return 0;
    }
  }

  try {
    ControlModule control(interface, output_dir, filter_expr);
    control.initialize();
    spdlog::info("初始化完成");
    spdlog::info("==================");
    control.status();
    spdlog::info("按回车键开始抓包...");

    std::thread input_thread([&control]() {
      std::cin.get();
      control.start();

      spdlog::info("按回车键停止抓包...");
      std::cin.get();
      control.stop();
    });

    // 等待输入线程结束
    if (input_thread.joinable()) {
      input_thread.join();
    }
  } catch (const std::exception &e) {
    spdlog::error("错误: {}", e.what());
    return 1;
  }

  return 0;
}
