# cmake_minimum_required(VERSION 3.16)

# project(aisio-gui VERSION 0.1 LANGUAGES CXX)

# set(CMAKE_AUTOUIC ON)
# set(CMAKE_AUTOMOC ON)
# set(CMAKE_AUTORCC ON)

# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

# find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets LinguistTools)
# find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets LinguistTools)

# set(TS_FILES aisio-gui_trv_TW.ts)

# set(PROJECT_SOURCES
#         main.cpp
#         mainwindow.cpp
#         mainwindow.h
#         mainwindow.ui
#         ${TS_FILES}
# )

# if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
#     qt_add_executable(aisio-gui
#         MANUAL_FINALIZATION
#         ${PROJECT_SOURCES}
#         cryptoworker.h cryptoworker.cpp
#     )
# # Define target properties for Android with Qt 6 as:
# #    set_property(TARGET aisio-gui APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
# #                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# # For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation

#     qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
# else()
#     if(ANDROID)
#         add_library(aisio-gui SHARED
#             ${PROJECT_SOURCES}
#         )
# # Define properties for Android with Qt 5 after find_package() calls as:
# #    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
#     else()
#         add_executable(aisio-gui
#             ${PROJECT_SOURCES}
#         )
#     endif()

#     qt5_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
# endif()

# target_link_libraries(aisio-gui PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

# # Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# # If you are developing for iOS or macOS you should consider setting an
# # explicit, fixed bundle identifier manually though.
# if(${QT_VERSION} VERSION_LESS 6.1.0)
#   set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.aisio-gui)
# endif()
# set_target_properties(aisio-gui PROPERTIES
#     ${BUNDLE_ID_OPTION}
#     MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
#     MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
#     MACOSX_BUNDLE TRUE
#     WIN32_EXECUTABLE TRUE
# )

# include(GNUInstallDirs)
# install(TARGETS aisio-gui
#     BUNDLE DESTINATION .
#     LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#     RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
# )

# if(QT_VERSION_MAJOR EQUAL 6)
#     qt_finalize_executable(aisio-gui)
# endif()

cmake_minimum_required(VERSION 3.16)

project(aisio-gui VERSION 0.1 LANGUAGES CXX)

# ---------------- Qt 基本設定（沿用你現有的） ----------------
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets LinguistTools)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets LinguistTools)

set(TS_FILES aisio-gui_trv_TW.ts)

set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    ${TS_FILES}
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(aisio-gui
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        # 如需其他檔案在這邊加
        # aisio_adapter.h
        # aisio_adapter.cpp
    )
    qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
else()
    if(ANDROID)
        add_library(aisio-gui SHARED ${PROJECT_SOURCES})
    else()
        add_executable(aisio-gui ${PROJECT_SOURCES})
    endif()
    qt5_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
endif()

target_link_libraries(aisio-gui PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

# macOS/iOS 相關屬性（保留你原本設定）
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.aisio-gui)
endif()
set_target_properties(aisio-gui PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS aisio-gui
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(aisio-gui)
endif()

# ===================================================================
# ===============   Ais.IO 連結（相對路徑）段落   ===================
# ===================================================================

# Ais.IO 根目錄（相對於本 CMakeLists）
# 例：你的專案： <root>/
#                    Ais.IO/          ← 庫
#                    aisio-gui/       ← 這個 Qt 專案（本檔所在）
set(AISIO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../Ais.IO" CACHE PATH "Path to Ais.IO root")

# 選擇模式：
#   OFF → 走 add_subdirectory 直接編譯 Ais.IO（首選，最穩）
#   ON  → 連已編好的 .lib/.dll/.so（當你已經有預編譯庫）
option(AISIO_USE_PREBUILT "Link against prebuilt Ais.IO binaries instead of building from source" OFF)

# 若 Ais.IO 有自己的 CMakeLists 並且你選擇不使用預編譯庫，走「A 模式」
if(NOT AISIO_USE_PREBUILT AND EXISTS "${AISIO_DIR}/CMakeLists.txt")
    message(STATUS "[Ais.IO] Using source via add_subdirectory: ${AISIO_DIR}")
    # 你可以改變 build 目錄（避免汙染主 build）
    add_subdirectory("${AISIO_DIR}" "${CMAKE_BINARY_DIR}/Ais.IO_build")

    # Ais.IO 在它自己的 CMake 裡的 target 名稱（請依實際情況調整）
    # 例如可能叫 aisio / aisio_core / AisIO 等等
    set(AISIO_TARGET "aisio" CACHE STRING "Ais.IO CMake target name")
    target_link_libraries(aisio-gui PRIVATE ${AISIO_TARGET})

    # 如需公開頭檔且目標未自動公開，可自行補 include（依實際結構調整）
    target_include_directories(aisio-gui PRIVATE "${AISIO_DIR}" "${AISIO_DIR}/include")

# 否則走「B 模式」：連預編譯好的 .lib / .dll / .so
else()
    message(STATUS "[Ais.IO] Using prebuilt libraries in: ${AISIO_DIR}")

    # 一般你的目錄會長這樣（依你的實際路徑微調）：
    #   ${AISIO_DIR}/include/           ← 標頭
    #   ${AISIO_DIR}/lib/VC/x64/MD/     ← Windows 的 .lib / 對應 .dll 在 bin 或同層
    #   ${AISIO_DIR}/so/                ← Linux 的 .a/.so
    set(AISIO_INCLUDE_DIR "${AISIO_DIR}/include" CACHE PATH "Ais.IO include dir")
    target_include_directories(aisio-gui PRIVATE "${AISIO_INCLUDE_DIR}")

    if(WIN32)
        # Windows: 指定 .lib 位置（相對路徑）
        set(AISIO_LIB_DIR_WIN "${AISIO_DIR}/lib/VC/x64/MD" CACHE PATH "Ais.IO Windows lib dir (relative)")
        set(AISIO_LIB_NAME "Ais.IO" CACHE STRING "Ais.IO library base name (without extension)")

        # 匯入靜態庫或導入庫
        add_library(aisio STATIC IMPORTED GLOBAL)
        set_target_properties(aisio PROPERTIES
            IMPORTED_LOCATION "${AISIO_LIB_DIR_WIN}/${AISIO_LIB_NAME}.lib"
        )
        target_link_libraries(aisio-gui PRIVATE aisio)

        # 如果 Ais.IO 依賴 OpenSSL，順手把 libssl/libcrypto 也連進來（在同一資料夾找）
        # 你也可以改成 find_package(OpenSSL) 再連 OpenSSL::SSL / OpenSSL::Crypto
        find_library(OPENSSL_SSL     NAMES libssl ssl     PATHS "${AISIO_LIB_DIR_WIN}" NO_DEFAULT_PATH)
        find_library(OPENSSL_CRYPTO  NAMES libcrypto crypto PATHS "${AISIO_LIB_DIR_WIN}" NO_DEFAULT_PATH)
        if(OPENSSL_SSL)
            target_link_libraries(aisio-gui PRIVATE "${OPENSSL_SSL}")
        endif()
        if(OPENSSL_CRYPTO)
            target_link_libraries(aisio-gui PRIVATE "${OPENSSL_CRYPTO}")
        endif()

        # 若是動態庫（.dll），把執行時需要的 dll 拷貝到輸出資料夾（可選）
        # set(AISIO_DLL "${AISIO_LIB_DIR_WIN}/${AISIO_LIB_NAME}.dll")
        # if(EXISTS "${AISIO_DLL}")
        #     add_custom_command(TARGET aisio-gui POST_BUILD
        #         COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        #                 "${AISIO_DLL}" "$<TARGET_FILE_DIR:aisio-gui>/"
        #     )
        # endif()

    elseif(UNIX)
        # Linux / macOS：找 .so/.a（以 ./so 為例）
        set(AISIO_LIB_DIR_UNIX "${AISIO_DIR}/so" CACHE PATH "Ais.IO Unix lib dir (relative)")
        # 嘗試尋找共享庫
        find_library(AISIO_SO NAMES aisio PATHS "${AISIO_LIB_DIR_UNIX}" NO_DEFAULT_PATH)
        if(AISIO_SO)
            add_library(aisio SHARED IMPORTED GLOBAL)
            set_target_properties(aisio PROPERTIES IMPORTED_LOCATION "${AISIO_SO}")
            target_link_libraries(aisio-gui PRIVATE aisio)
        else()
            # 或者你也可以改成靜態庫 .a
            # set(AISIO_A "${AISIO_LIB_DIR_UNIX}/libaisio.a")
            # if(EXISTS "${AISIO_A}")
            #   add_library(aisio STATIC IMPORTED GLOBAL)
            #   set_target_properties(aisio PROPERTIES IMPORTED_LOCATION "${AISIO_A}")
            #   target_link_libraries(aisio-gui PRIVATE aisio)
            # endif()
        endif()

        # OpenSSL（建議用系統的）
        find_package(OpenSSL QUIET)
        if(OpenSSL_FOUND)
            target_link_libraries(aisio-gui PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        endif()
    endif()
endif()
