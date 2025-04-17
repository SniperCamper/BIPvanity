cmake_minimum_required(VERSION 3.10)
project(BIPVanity)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(src)
add_subdirectory(trezor-crypto)
target_link_libraries(bipvanity-cli trezor-crypto pthread)
