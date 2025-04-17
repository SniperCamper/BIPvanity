#pragma once
#include <string>
#include <vector>

std::vector<std::string> load_wordlist(const std::string& lang);
std::string generate_mnemonic(int words, const std::string& lang);
