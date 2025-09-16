cmake_minimum_required(VERSION 3.22)

# ⚠️ 盡量不要在 target 名稱用點號，VS/附加工具有時會誤判
project(aisio_gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Qt 6 基本設定 ──────────────────────────────────────────────
# 你用 vcpkg 的話，請確保用 Preset 或 -DCMAKE_TOOLCHAIN_FILE 指到 C:\vcpkg\scripts\buildsystems\vcpkg.cmake
find_package(Qt6 REQUIRED COMPONENTS Widgets)

# 某些 Qt 版本才有 qt_standard_project_setup()；保險做法是兩者擇一
if (COMMAND qt_standard_project_setup)
  qt_standard_project_setup()
else()
  set(CMAKE_AUTOMOC ON)
  set(CMAKE_AUTOUIC ON)
  set(CMAKE_AUTORCC ON)
endif()

# ── 原始碼清單 ────────────────────────────────────────────────
# 如果你的檔案其實在 src/ 資料夾，請把路徑加上 src/ 前綴
set(SOURCES
  src/main.cpp
  src/MainWindow.h
  src/MainWindow.cpp
  src/CryptoWorker.h
  src/CryptoWorker.cpp
)

# 如果你的檔案就在專案根目錄，就改成如下：
# set(SOURCES
#   main.cpp
#   MainWindow.h
#   MainWindow.cpp
#   CryptoWorker.h
#   CryptoWorker.cpp
# )

add_executable(aisio-gui ${SOURCES})

# 如果你仍想讓輸出檔名是 Ais.IO.Gui.exe，可以：
set_target_properties(aisio-gui PROPERTIES OUTPUT_NAME "Ais.IO.Gui")

target_link_libraries(aisio-gui PRIVATE Qt6::Widgets)

# 關掉 vcpkg applocal（避免和 windeployqt 打架）
set(VCPKG_APPLOCAL_DEPS OFF CACHE BOOL "Disable vcpkg applocal (we use windeployqt instead)" FORCE)

if (WIN32)
  add_definitions(-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
endif()

# ── 自動部署 Qt 平台外掛（解決 "Could not find the Qt platform plugin windows"）──
if (WIN32)
  # 先找 windeployqt：vcpkg 與官方 Qt 兩種可能位置
  find_program(WINDEPLOYQT_EXECUTABLE NAMES windeployqt windeployqt.exe
    HINTS "C:/vcpkg/installed/x64-windows/tools/qt6/bin" "C:/vcpkg/installed/x64-windows/tools/Qt6/bin")

    # 顯示找到的 windeployqt 路徑（你會在 CMake 輸出看到）
    if (WINDEPLOYQT_EXECUTABLE)
        message(STATUS "Using windeployqt: ${WINDEPLOYQT_EXECUTABLE}")
    endif()

    if (WINDEPLOYQT_EXECUTABLE)
        # 如果找到的是 .bat/.cmd，需要用 cmd /c 跑；exe 則可直跑
        set(_WINDEPLOY_IS_BAT FALSE)
        if (WINDEPLOYQT_EXECUTABLE MATCHES "\\.(bat|cmd)$")
        add_custom_command(TARGET aisio-gui POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E echo "Running windeployqt (Debug/Release aware)..."
            COMMAND cmd /c "${WINDEPLOYQT_EXECUTABLE}" $<$<CONFIG:Debug>:--debug> --verbose 2 "$<TARGET_FILE:aisio-gui>"
            COMMAND_EXPAND_LISTS
            VERBATIM)
        else()
        add_custom_command(TARGET aisio-gui POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E echo "Running windeployqt (Debug/Release aware)..."
            COMMAND "${WINDEPLOYQT_EXECUTABLE}" $<$<CONFIG:Debug>:--debug> --verbose 2 "$<TARGET_FILE:aisio-gui>"
            COMMAND_EXPAND_LISTS
            VERBATIM)
        endif()
    endif()
endif()

# ──（未來）直連你的原生庫而非跑 CLI ───────────────────────────
# target_link_libraries(aisio-gui PRIVATE aisio_native_lib)
# target_include_directories(aisio-gui PRIVATE <path-to-aisio-headers>)
