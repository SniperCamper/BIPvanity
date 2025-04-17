file(GLOB SOURCES "*.cpp")
add_executable(bipvanity-cli ${SOURCES})
target_link_libraries(bipvanity-cli trezor-crypto pthread)
