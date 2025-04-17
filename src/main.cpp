#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include "bip39.h"
#include "address_utils.h"
#include "filter.h"
#include "found_writer.h"

void print_usage() {
    std::cout << "BIPVanity CLI - Gerador de endereços BIP39 Vanity em C++\n";
    std::cout << "Uso: bipvanity-cli [opções]\n";
    std::cout << "  --lang <en|pt>         Idioma do mnemonic\n";
    std::cout << "  --words <12|24>        Quantidade de palavras\n";
    std::cout << "  --prefix <string>      Prefixo do endereço\n";
    std::cout << "  --coin <btc|eth|ltc>   Moeda\n";
    std::cout << "  --threads <n>          Número de threads\n";
    std::cout << "  --path <deriv_path>    Caminho de derivação\n";
    std::cout << "  --passphrase <str>     Passphrase opcional\n";
    std::cout << "  --clear                Limpa resultados\n";
    std::cout << "  --help                 Mostra esta ajuda\n";
}

int main(int argc, char* argv[]) {
    std::string lang = "en";
    int words = 12;
    std::string prefix = "1Van";
    std::string coin = "btc";
    int n_threads = 4;
    std::string deriv_path = "m/44'/0'/0'/0/0";
    std::string passphrase = "";
    bool clear = false;
    
    // Argumentos simples (não robusto, mas funcional)
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--lang" && i+1 < argc) lang = argv[++i];
        else if (arg == "--words" && i+1 < argc) words = std::stoi(argv[++i]);
        else if (arg == "--prefix" && i+1 < argc) prefix = argv[++i];
        else if (arg == "--coin" && i+1 < argc) coin = argv[++i];
        else if (arg == "--threads" && i+1 < argc) n_threads = std::stoi(argv[++i]);
        else if (arg == "--path" && i+1 < argc) deriv_path = argv[++i];
        else if (arg == "--passphrase" && i+1 < argc) passphrase = argv[++i];
        else if (arg == "--clear") clear = true;
        else if (arg == "--help") { print_usage(); return 0; }
    }
    if (clear) {
        std::ofstream("../FOUND.txt", std::ios::trunc).close();
        std::cout << "FOUND.txt limpo!\n";
        return 0;
    }
    std::atomic<bool> found_any(false);
    std::mutex file_mutex;
    auto worker = [&]() {
        while (!found_any.load()) {
            std::string mnemonic = generate_mnemonic(words, lang);
            std::string address = derive_address(mnemonic, deriv_path, coin, passphrase);
            if (matches_prefix(address, prefix)) {
                save_found(mnemonic, address, file_mutex);
                std::cout << "Encontrado: " << address << "\n";
                found_any = true;
            }
        }
    };
    std::vector<std::thread> threads;
    for (int i = 0; i < n_threads; ++i) {
        threads.emplace_back(worker);
    }
    for (auto& t : threads) t.join();
    std::cout << "Busca finalizada. Veja FOUND.txt.\n";
    return 0;
}
