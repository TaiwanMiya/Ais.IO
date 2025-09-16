cmake_minimum_required(VERSION 3.22)
project(Ais.IO.Gui LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# 建議用 vcpkg 管理 Qt：
# Windows 範例： vcpkg install qtbase:x64-windows
# Linux 範例： vcpkg install qtbase:x64-linux
# 用 CMake 工具鏈： -DCMAKE_TOOLCHAIN_FILE="<vcpkg>/scripts/buildsystems/vcpkg.cmake"


find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()


add_executable(Ais.IO.Gui
main.cpp
MainWindow.h
MainWindow.cpp
CryptoWorker.h
CryptoWorker.cpp
)


target_link_libraries(Ais.IO.Gui PRIVATE Qt6::Widgets)


if (WIN32)
add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
endif()


# 若日後直接連結 Ais.IO 原生庫（靜/動態）：
# target_link_libraries(Ais.IO.Gui PRIVATE aisio_native_lib)
# target_include_directories(Ais.IO.Gui PRIVATE <path-to-aisio-headers>)