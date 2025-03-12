cmake_minimum_required(VERSION 3.10.0)
project(reconstruction VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# 查找libpcap库
find_package(PkgConfig REQUIRED) #确保系统上安装了 pkg-config 工具。
pkg_check_modules(PCAP REQUIRED libpcap) #通过 pkg-config 查找 libpcap 库。
find_package(spdlog CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
include_directories("include")


add_executable(reconstruction src/main.cpp)
target_sources(reconstruction PRIVATE src/filter.cpp src/capture.cpp src/pcap_capture_module.cpp)
#链接libpcap库
target_link_libraries(reconstruction PRIVATE ${PCAP_LIBRARIES} spdlog::spdlog) #将 libpcap 库链接到可执行文件。
target_link_libraries(reconstruction PRIVATE spdlog::spdlog)
target_link_libraries(reconstruction PRIVATE fmt::fmt)
