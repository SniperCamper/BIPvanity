#include "bip39.h"
#include <fstream>
#include <random>
#include <stdexcept>

std::vector<std::string> load_wordlist(const std::string& lang) {
    std::string filename = "../wordlist/bip39-" + lang + ".txt";
    std::ifstream file(filename);
    std::vector<std::string> wordlist;
    std::string word;
    while (file >> word) {
        wordlist.push_back(word);
    }
    if (wordlist.size() != 2048) throw std::runtime_error("Wordlist inválida!");
    return wordlist;
}

std::string generate_mnemonic(int words, const std::string& lang) {
    auto wordlist = load_wordlist(lang);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, wordlist.size() - 1);
    std::string mnemonic;
    for (int i = 0; i < words; ++i) {
        mnemonic += wordlist[dis(gen)];
        if (i + 1 < words) mnemonic += " ";
    }
    return mnemonic;
}
