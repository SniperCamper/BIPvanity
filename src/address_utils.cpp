#include "address_utils.h"
#include <string>
#include <stdexcept>
#include <cstring>
extern "C" {
#include "trezor-crypto/bip39.h"
#include "trezor-crypto/bip32.h"
#include "trezor-crypto/curves.h"
#include "trezor-crypto/ecdsa.h"
#include "trezor-crypto/base58.h"
#include "trezor-crypto/sha3.h"
#include "trezor-crypto/sha2.h"
#include "trezor-crypto/ripemd160.h"
#include "trezor-crypto/secp256k1.h"
}


// Helper para converter mnemonic+passphrase em seed
static void mnemonic_to_seed(const std::string& mnemonic, const std::string& passphrase, uint8_t* seed_out) {
    mnemonic_to_seed(mnemonic.c_str(), passphrase.c_str(), seed_out, NULL);
}

std::string derive_address(const std::string& mnemonic, const std::string& path, const std::string& coin, const std::string& passphrase) {
    uint8_t seed[64] = {0};
    mnemonic_to_seed(mnemonic, passphrase, seed);
    HDNode node;
    const ecdsa_curve* curve = get_curve_by_name(SECP256K1_NAME);
    if (!hdnode_from_seed(seed, 64, SECP256K1_NAME, &node))
        throw std::runtime_error("Erro ao gerar HDNode");
    if (!hdnode_private_ckd_prime(&node, 44)) // Exemplo: m/44'
        throw std::runtime_error("Erro ao derivar caminho");
    // TODO: Parse path string corretamente e derivar todos os níveis
    // Para simplificação, só m/44'/0'/0'/0/0
    // Derivar até o endereço final

    char address[128] = {0};
    if (coin == "btc" || coin == "ltc") {
        // Gerar endereço P2PKH (base58)
        uint8_t pubkey[33];
        hdnode_fill_public_key(&node);
        memcpy(pubkey, node.public_key, 33);
        uint8_t hash[20];
        ripemd160(sha256(pubkey, 33, NULL), 32, hash);
        uint8_t addr_bytes[21];
        addr_bytes[0] = (coin == "btc") ? 0x00 : 0x30; // BTC:0x00, LTC:0x30
        memcpy(addr_bytes+1, hash, 20);
        base58_encode_check(addr_bytes, 21, HASHER_SHA2D, address, sizeof(address));
        return std::string(address);
    } else if (coin == "eth") {
        // Gerar endereço ETH (keccak256 do pubkey, últimos 20 bytes)
        uint8_t pubkey[65];
        hdnode_fill_public_key(&node);
        ecdsa_uncompress_pubkey(curve, node.public_key, pubkey);
        uint8_t hash[32];
        keccak_256(pubkey+1, 64, hash);
        char eth_addr[43] = {0};
        snprintf(eth_addr, sizeof(eth_addr), "0x");
        for (int i = 12; i < 32; ++i) {
            snprintf(eth_addr+2+(i-12)*2, 3, "%02x", hash[i]);
        }
        return std::string(eth_addr);
    }
    return "";
}
