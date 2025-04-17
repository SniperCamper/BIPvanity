#include "found_writer.h"
#include <fstream>

void save_found(const std::string& mnemonic, const std::string& address, std::mutex& file_mutex) {
    std::lock_guard<std::mutex> lock(file_mutex);
    std::ofstream file("../FOUND.txt", std::ios::app);
    file << address << " : " << mnemonic << std::endl;
}
