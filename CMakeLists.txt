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
    tst_sha1bench.cpp
    git-sha1/git-sha1.c
    nayuki/nayuki-sha1-fast.c nayuki/bench-nayuki.c
    go-sqlcipher-libtomcrypt/sha1.c go-sqlcipher-libtomcrypt/zeromem.c go-sqlcipher-libtomcrypt/crypt_argchk.c go-sqlcipher-libtomcrypt/burn_stack.c
)

if (NOT APPLE)
    target_sources(${PROJECT_NAME} PRIVATE sha-intrinsics/sha1-x86.c)
else()
    target_sources(${PROJECT_NAME} PRIVATE sha-intrinsics/sha1-arm8.c)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC "./go-sqlcipher-libtomcrypt")
target_compile_definitions(${PROJECT_NAME} PUBLIC SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}" LTC_NO_ASM)
target_link_libraries(${PROJECT_NAME} PRIVATE Qt${QT_VERSION_MAJOR}::Test OpenSSL::SSL)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
