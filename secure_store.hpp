// Encrypted-at-rest template store.
// File: "FCS1" | salt(16) | nonce(24) | XChaCha20-Poly1305(ciphertext+tag)
// Key = Argon2id(passphrase, salt). Header (magic+salt) is authenticated as AD.
// Only embeddings are stored - never face images.
#pragma once
#include <sodium.h>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

using Embedding = std::vector<float>;
using Db = std::map<std::string, std::vector<Embedding>>;

class SecureStore {
  static constexpr size_t KEY = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  static constexpr size_t NONCE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  static constexpr size_t TAG = crypto_aead_xchacha20poly1305_ietf_ABYTES;
  static constexpr size_t SALT = crypto_pwhash_SALTBYTES;  // 16
  static constexpr char MAGIC[4] = {'F', 'C', 'S', '1'};

  std::string path_;
  uint8_t salt_[SALT];
  uint8_t* key_ = nullptr;  // sodium_malloc: guarded, mlock'd, zeroed on free

  template <class T> static void put(std::vector<uint8_t>& b, T v) {
    const auto* p = reinterpret_cast<const uint8_t*>(&v);
    b.insert(b.end(), p, p + sizeof(T));
  }
  struct Reader {
    const uint8_t* p; size_t n;
    template <class T> T get() {
      if (n < sizeof(T)) throw std::runtime_error("corrupt store");
      T v; std::memcpy(&v, p, sizeof(T)); p += sizeof(T); n -= sizeof(T); return v;
    }
    std::string str(size_t len) {
      if (n < len) throw std::runtime_error("corrupt store");
      std::string s(reinterpret_cast<const char*>(p), len); p += len; n -= len; return s;
    }
  };

public:
  SecureStore(std::string path, const std::string& passphrase) : path_(std::move(path)) {
    if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
    key_ = static_cast<uint8_t*>(sodium_malloc(KEY));
    if (!key_) throw std::runtime_error("sodium_malloc failed");
    if (std::filesystem::exists(path_)) {
      std::ifstream f(path_, std::ios::binary);
      char hdr[4 + SALT];
      if (!f.read(hdr, sizeof hdr) || std::memcmp(hdr, MAGIC, 4) != 0)
        throw std::runtime_error("not a valid store file");
      std::memcpy(salt_, hdr + 4, SALT);
    } else {
      randombytes_buf(salt_, SALT);
    }
    if (crypto_pwhash(key_, KEY, passphrase.data(), passphrase.size(), salt_,
                      crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
      throw std::runtime_error("key derivation failed (out of memory?)");
  }
  ~SecureStore() { sodium_free(key_); }
  SecureStore(const SecureStore&) = delete;
  SecureStore& operator=(const SecureStore&) = delete;

  Db load() const {
    Db db;
    if (!std::filesystem::exists(path_)) return db;
    std::ifstream f(path_, std::ios::binary);
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), {});
    const size_t ad = 4 + SALT, hdr = ad + NONCE;
    if (buf.size() < hdr + TAG) throw std::runtime_error("store too short");
    std::vector<uint8_t> pt(buf.size() - hdr - TAG);
    unsigned long long len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt.data(), &len, nullptr, buf.data() + hdr,
                                                   buf.size() - hdr, buf.data(), ad,
                                                   buf.data() + ad, key_) != 0)
      throw std::runtime_error("decryption failed: wrong passphrase or tampered file");
    try {
      Reader r{pt.data(), static_cast<size_t>(len)};
      uint32_t users = r.get<uint32_t>();
      for (uint32_t i = 0; i < users; ++i) {
        std::string name = r.str(r.get<uint16_t>());
        uint16_t nt = r.get<uint16_t>();
        for (uint16_t t = 0; t < nt; ++t) {
          uint16_t dim = r.get<uint16_t>();
          Embedding e(dim);
          for (auto& x : e) x = r.get<float>();
          db[name].push_back(std::move(e));
        }
      }
    } catch (...) { sodium_memzero(pt.data(), pt.size()); throw; }
    sodium_memzero(pt.data(), pt.size());
    return db;
  }

  void save(const Db& db) const {
    std::vector<uint8_t> pt;
    put<uint32_t>(pt, static_cast<uint32_t>(db.size()));
    for (const auto& [name, tmpls] : db) {
      put<uint16_t>(pt, static_cast<uint16_t>(name.size()));
      pt.insert(pt.end(), name.begin(), name.end());
      put<uint16_t>(pt, static_cast<uint16_t>(tmpls.size()));
      for (const auto& e : tmpls) {
        put<uint16_t>(pt, static_cast<uint16_t>(e.size()));
        for (float x : e) put<float>(pt, x);
      }
    }
    std::vector<uint8_t> out(4 + SALT + NONCE + pt.size() + TAG);
    std::memcpy(out.data(), MAGIC, 4);
    std::memcpy(out.data() + 4, salt_, SALT);
    uint8_t* nonce = out.data() + 4 + SALT;
    randombytes_buf(nonce, NONCE);  // fresh random nonce every save
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(nonce + NONCE, &clen, pt.data(), pt.size(),
                                               out.data(), 4 + SALT, nullptr, nonce, key_);
    sodium_memzero(pt.data(), pt.size());
    const std::string tmp = path_ + ".tmp";  // atomic replace
    { std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
      f.write(reinterpret_cast<const char*>(out.data()), 4 + SALT + NONCE + clen);
      if (!f) throw std::runtime_error("write failed"); }
    std::filesystem::permissions(tmp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    std::filesystem::rename(tmp, path_);
  }
};
