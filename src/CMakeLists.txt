file(GLOB TREZOR_CRYPTO_SRC "trezor-crypto/*.c" "trezor-crypto/*.h")
add_executable(bipvanity-cli ${SOURCES} ${TREZOR_CRYPTO_SRC})
target_include_directories(bipvanity-cli PRIVATE trezor-crypto)
target_link_libraries(bipvanity-cli pthread)
