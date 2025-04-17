#pragma once
#include <string>
#include <mutex>

void save_found(const std::string& mnemonic, const std::string& address, std::mutex& file_mutex);
