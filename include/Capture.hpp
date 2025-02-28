#include <pcap.h>

#include <iostream>
#include <functional>
#include <string>
#include <stdexcept>
#include <vector>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

// 原始数据包结构体定义
struct RawPacket
{
  struct timeval timestamp;  // 数据包时间戳
  uint32_t caplen;           // 实际捕获长度
  std::vector<uint8_t> data; // 原始数据内容

  // 计算数据包在队列中的存储大小
  size_t storage_size() const
  {
    return sizeof(timestamp) + sizeof(caplen) + data.size();
  }
};

class PcapCapture
{
public:
  // 回调函数类型定义 (处理pcap_pkthdr和原始数据)
  using CallbackType = std::function<void(const struct pcap_pkthdr *, const u_char *)>;

  /**
   * 构造函数
   * @param interface 抓包网卡名称
   * @param filter BPF过滤规则，默认为"tcp or udp"
   * @throws std::runtime_error 初始化失败时抛出异常
   */
  PcapCapture(const std::string &interface, const std::string &filter = "tcp or udp")
      : interface_(interface), filter_(filter),
        pcap_handle_(nullptr), is_capturing_(false),
        current_queue_size_(0), max_queue_size_(2 * 1024 * 1024)
  { // 2MB队列容量
    char errbuf[PCAP_ERRBUF_SIZE];

    // 打开网络接口
    pcap_handle_ = pcap_open_live(interface.c_str(), 65535, 1, 1000, errbuf);
    if (!pcap_handle_)
    {
      throw std::runtime_error("pcap_open_live failed: " + std::string(errbuf));
    }

    // 设置BPF过滤器
    struct bpf_program fp;
    if (pcap_compile(pcap_handle_, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
      pcap_close(pcap_handle_);
      throw std::runtime_error("BPF compile error: " + std::string(pcap_geterr(pcap_handle_)));
    }

    if (pcap_setfilter(pcap_handle_, &fp) == -1)
    {
      pcap_close(pcap_handle_);
      pcap_freecode(&fp);
      throw std::runtime_error("BPF setfilter error: " + std::string(pcap_geterr(pcap_handle_)));
    }
    pcap_freecode(&fp);
  }

  ~PcapCapture()
  {
    stop_capture();
    if (pcap_handle_)
    {
      pcap_close(pcap_handle_);
    }
  }

  /**
   * 启动抓包线程
   * @param callback 数据包处理回调函数
   */
  void start_capture(CallbackType callback)
  {
    if (is_capturing_.exchange(true))
    {
      return; // 防止重复启动
    }

    user_callback_ = callback;

    // 启动抓包线程
    capture_thread_ = std::thread([this]()
                                  { pcap_loop(pcap_handle_, 0, &PcapCapture::packet_handler,
                                              reinterpret_cast<u_char *>(this)); });

    // 启动处理线程
    processing_thread_ = std::thread([this]()
                                     { process_packets(); });
  }

  // 停止抓包
  void stop_capture()
  {
    if (!is_capturing_.exchange(false))
    {
      return;
    }

    // 中断抓包循环
    pcap_breakloop(pcap_handle_);

    // 等待抓包线程结束
    if (capture_thread_.joinable())
    {
      capture_thread_.join();
    }

    // 唤醒并停止处理线程
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      queue_cv_.notify_all();
    }
    if (processing_thread_.joinable())
    {
      processing_thread_.join();
    }
  }

private:
  // libpcap回调处理函数（静态成员）
  static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
  {
    PcapCapture *self = reinterpret_cast<PcapCapture *>(user);
    if (!self || !self->is_capturing_)
      return;

    // 构造RawPacket
    RawPacket packet;
    packet.timestamp = h->ts;
    packet.caplen = h->caplen;
    packet.data.assign(bytes, bytes + h->caplen);

    // 加锁操作队列
    std::lock_guard<std::mutex> lock(self->queue_mutex_);

    // 队列容量控制
    const size_t packet_size = packet.storage_size();
    while (self->current_queue_size_ + packet_size > self->max_queue_size_ &&
           !self->packet_queue_.empty())
    {
      // 移除最旧的数据包
      const size_t removed_size = self->packet_queue_.front().storage_size();
      self->current_queue_size_ -= removed_size;
      self->packet_queue_.pop();
    }

    // 添加新数据包
    if (self->current_queue_size_ + packet_size <= self->max_queue_size_)
    {
      self->packet_queue_.push(std::move(packet));
      self->current_queue_size_ += packet_size;
      self->queue_cv_.notify_one();
    }
  }

  // 处理线程主循环
  void process_packets()
  {
    while (is_capturing_ || !packet_queue_.empty())
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);

      // 等待队列非空或停止信号
      queue_cv_.wait(lock, [this]()
                     { return !packet_queue_.empty() || !is_capturing_; });

      // 批量处理当前队列中的所有包
      while (!packet_queue_.empty())
      {
        RawPacket packet = std::move(packet_queue_.front());
        packet_queue_.pop();
        current_queue_size_ -= packet.storage_size();

        lock.unlock(); // 释放锁以便抓包线程可以继续填充队列

        // 构造pcap_pkthdr结构
        struct pcap_pkthdr hdr;
        hdr.ts = packet.timestamp;
        hdr.caplen = packet.caplen;
        hdr.len = packet.caplen; // 假设实际长度等于捕获长度

        // 执行用户回调
        if (user_callback_)
        {
          user_callback_(&hdr, packet.data.data());
        }

        lock.lock(); // 重新加锁处理下一个包
      }
    }
  }

  // 成员变量
  std::string interface_;          // 抓包网卡名称
  std::string filter_;             // BPF过滤规则
  pcap_t *pcap_handle_;            // libpcap句柄
  std::atomic<bool> is_capturing_; // 运行状态标志

  // 数据包队列相关
  std::queue<RawPacket> packet_queue_; // 数据包存储队列
  std::mutex queue_mutex_;             // 队列互斥锁
  std::condition_variable queue_cv_;   // 队列条件变量
  size_t current_queue_size_;          // 当前队列存储大小
  const size_t max_queue_size_;        // 队列最大容量（2MB）

  // 处理线程相关
  CallbackType user_callback_;    // 用户回调函数
  std::thread capture_thread_;    // 抓包线程
  std::thread processing_thread_; // 处理线程
};
