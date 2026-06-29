cmake_minimum_required(VERSION 3.21)
project(chromium_parser CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(unofficial-brotli CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
find_package(leveldb CONFIG REQUIRED)

# Pre-generated protobuf C++ for the chromium sync + variations messages, committed
# under third_party/gen (protoc output, vendored so the build needs neither a
# chromium checkout nor a protoc step). Regenerate only when the .proto definitions
# change or vcpkg bumps protobuf to an incompatible version.
file(GLOB_RECURSE CHROME_PROTO_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gen/*.pb.cc")

# ---- core library: every reader/dump source EXCEPT an entry point ----
add_library(chromium_parser STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/capture.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dump.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/store_copy.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/readers_sqlite.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/readers_sysprofile.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/readers_cache.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/readers_proto.cpp"
    ${CHROME_PROTO_SOURCES}
)

# PUBLIC: every example that links the library inherits these include dirs + libs.
target_include_directories(chromium_parser PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gen")

target_link_libraries(chromium_parser PUBLIC
    unofficial::sqlite3::sqlite3
    nlohmann_json::nlohmann_json
    ZLIB::ZLIB
    unofficial::brotli::brotlidec
    protobuf::libprotobuf
    leveldb::leveldb)

# ---- examples: one executable per examples/*.cpp, each linking the library ----
file(GLOB EXAMPLE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.cpp")
foreach(example_src ${EXAMPLE_SOURCES})
    get_filename_component(example_name "${example_src}" NAME_WE)
    add_executable(${example_name} "${example_src}")
    target_link_libraries(${example_name} PRIVATE chromium_parser)
endforeach()