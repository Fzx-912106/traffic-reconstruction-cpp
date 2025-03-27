#include "control_module.h"

#include "spdlog/spdlog.h"
#include <memory>

// =========== 控制模块实现 ===========
ControlModule::ControlModule(const std::string &iface,
                             const std::string &output,
                             const std::string &filter)
    : interface{iface}, output_dir{output}, filter_expr{filter} {}

void ControlModule::initialize() {
  capture_module = std::make_shared<CaptureModule>(interface, filter_expr);

  if (!capture_module->initialize()) {
    spdlog::error("抓包模块初始化失败");
  }
  spdlog::info("所有模块初始化成功");
}

void ControlModule::start() {
  if (running) {
    spdlog::warn("流量分析已在运行中");
    return;
  }

  running = true;
  capture_module->start();

  spdlog::info("流量分析在接口 {} 上开始运行", interface);
  // 循环处理数据包
  this->run_handle = std::thread(

      [this]() {
        while (running) {
          // 从抓包模块获取数据包
          auto packets = capture_module->get_packets();
          if (!packets.empty()) {
            spdlog::info("正在处理 {} 个数据包", packets.size());

          } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
          }
        }
      }

  );
}

void ControlModule::stop() {
  if (!running) {
    spdlog::warn("流量分析已停止");
    return;
  }

  running = false;
  capture_module->stop();
  this->run_handle.join();
  spdlog::info("流量分析在接口 {} 上停止运行", interface);
}

bool ControlModule::status() const { return this->running; }