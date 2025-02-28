#include "../include/Capture.hpp"
#include <stdexcept>

size_t RawPacket::storage_size() const
{
  return sizeof(timestamp) + sizeof(caplen) + data.size();
}

PcapCapture::PcapCapture(const std::string &interface, const std::string &filter)
    : interface_(interface), filter_(filter), pcap_handle_(nullptr), is_capturing_(false), current_queue_size_(0), max_queue_size_(2 * 1024 * 1024)
{

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_handle_ = pcap_open_live(interface.c_str(), 65535, 1, 1000, errbuf);
  if (!pcap_handle_)
  {
    throw std::runtime_error("pcap_open_live failed: " + std::string(errbuf));
  }

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

PcapCapture::~PcapCapture()
{
  stop_capture();
  if (pcap_handle_)
  {
    pcap_close(pcap_handle_);
  }
}

void PcapCapture::start_capture(CallbackType callback)
{
  if (is_capturing_.exchange(true))
  {
    return;
  }

  user_callback_ = callback;

  capture_thread_ = std::thread([this]()
                                { pcap_loop(pcap_handle_, 0, &PcapCapture::packet_handler, reinterpret_cast<u_char *>(this)); });

  processing_thread_ = std::thread([this]()
                                   { process_packets(); });
}

void PcapCapture::stop_capture()
{
  if (!is_capturing_.exchange(false))
  {
    return;
  }

  pcap_breakloop(pcap_handle_);

  if (capture_thread_.joinable())
  {
    capture_thread_.join();
  }

  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    queue_cv_.notify_all();
  }
  if (processing_thread_.joinable())
  {
    processing_thread_.join();
  }
}

void PcapCapture::packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  PcapCapture *self = reinterpret_cast<PcapCapture *>(user);
  if (!self || !self->is_capturing_)
  {
    return;
  }

  RawPacket packet;
  packet.timestamp = h->ts;
  packet.caplen = h->caplen;
  packet.data.assign(bytes, bytes + h->caplen);

  std::lock_guard<std::mutex> lock(self->queue_mutex_);

  const size_t packet_size = packet.storage_size();
  while (self->current_queue_size_ + packet_size > self->max_queue_size_ &&
         !self->packet_queue_.empty())
  {
    self->current_queue_size_ -= self->packet_queue_.front().storage_size();
    self->packet_queue_.pop();
  }

  if (self->current_queue_size_ + packet_size <= self->max_queue_size_)
  {
    self->packet_queue_.push(std::move(packet));
    self->current_queue_size_ += packet_size;
    self->queue_cv_.notify_one();
  }
}

void PcapCapture::process_packets()
{
  while (is_capturing_ || !packet_queue_.empty())
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);

    queue_cv_.wait(lock, [this]()
                   { return !packet_queue_.empty() || !is_capturing_; });

    while (!packet_queue_.empty())
    {
      RawPacket packet = std::move(packet_queue_.front());
      packet_queue_.pop();
      current_queue_size_ -= packet.storage_size();

      lock.unlock();

      struct pcap_pkthdr hdr;
      hdr.ts = packet.timestamp;
      hdr.caplen = packet.caplen;
      hdr.len = packet.caplen;

      if (user_callback_)
      {
        user_callback_(&hdr, packet.data.data());
      }

      lock.lock();
    }
  }
}