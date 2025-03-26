#include "../include/control_module.h"

#include <iostream> // 控制台输出
#include <memory>   // std::make_shared
#include <thread>

// =========== 控制模块实现 ===========
ControlModule::ControlModule(const std::string &iface,
                             const std::string &output,
                             const std::string &filter)
    : interface{iface}, output_dir{output}, filter_expr{filter} {}

void ControlModule::initialize() {
  capture_module = std::make_shared<CaptureModule>(interface, filter_expr);
  filter_module = std::make_shared<FilterModule>();
  save_module = std::make_shared<SaveModule>(output_dir);

  if (!capture_module->initialize()) {
    throw std::runtime_error("抓包模块初始化失败");
  }

  if (!save_module->initialize()) {
    throw std::runtime_error("保存模块初始化失败");
  }

  std::cout << "所有模块初始化成功" << std::endl;
}

void ControlModule::start() {
  if (running) {
    std::cout << "流量分析已在运行中" << std::endl;
    return;
  }

  running = true;
  capture_module->start();

  std::cout << "流量分析在接口 " << interface << " 上开始运行" << std::endl;

  // 循环处理数据包
  this->run_handle = std::thread([this]() {
    while (running) {
      // 从抓包模块获取数据包
      auto packets = capture_module->get_packets();
      if (!packets.empty()) {
        std::cout << "正在处理 " << packets.size() << " 个数据包" << std::endl;

        // 过滤HTTP响应
        auto http_responses = filter_module->filter_http(packets);
        std::cout << "发现 " << http_responses.size() << " 个HTTP响应"
                  << std::endl;

        // 保存HTTP响应
        for (const auto &response : http_responses) {
          if (save_module->save_response(response)) {
            std::cout << "已保存: " << response.filename << std::endl;
          }
        }
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  });
}

void ControlModule::stop() {
  if (!running) {
    std::cout << "流量分析未在运行" << std::endl;
    return;
  }

  running = false;
  capture_module->stop();
  std::cout << "流量分析已停止" << std::endl;
  // 处理最后的数据包
  auto final_packets = capture_module->get_packets();
  if (!final_packets.empty()) {
    auto responses = filter_module->filter_http(final_packets);
    for (const auto &response : responses) {
      save_module->save_response(response);
    }
  }

  // 添加：强制处理所有剩余的TCP流
  std::cout << "尝试处理所有剩余的TCP流..." << std::endl;
  auto remaining_responses = filter_module->process_remaining_streams();
  for (const auto &response : remaining_responses) {
    save_module->save_response(response);
  }
}

void ControlModule::status() const {
  std::cout << "流量分析状态:" << std::endl;
  std::cout << "  接口: " << interface << std::endl;
  std::cout << "  输出目录: " << output_dir << std::endl;
  std::cout << "  过滤表达式: " << filter_expr << std::endl;
  std::cout << "  运行状态: " << (running ? "运行中" : "已停止") << std::endl;
}
