cmake_minimum_required(VERSION 3.20)

project(StatusSha1Bench)

enable_testing()

find_package(PkgConfig REQUIRED)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Test)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Test)
find_package(OpenSSL REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME} WIN32 MACOSX_BUNDLE
    tst_sha1bench.cpp git-sha1/git-sha1.c
)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

pkg_check_modules(LIBTOMCRYPT REQUIRED IMPORTED_TARGET libtomcrypt)

target_link_libraries(${PROJECT_NAME} PRIVATE Qt${QT_VERSION_MAJOR}::Test PkgConfig::LIBTOMCRYPT OpenSSL::SSL)
