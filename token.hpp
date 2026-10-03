// Short-lived, Ed25519-signed access tokens issued ONLY after a successful live match.
#pragma once
#include <sodium.h>
#include <ctime>
#include <sstream>
#include <string>

class TokenIssuer {
  unsigned char pk_[crypto_sign_PUBLICKEYBYTES];
  unsigned char* sk_;  // guarded memory
  static std::string b64(const unsigned char* d, size_t n) {
    std::string s(sodium_base64_ENCODED_LEN(n, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    sodium_bin2base64(s.data(), s.size(), d, n, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    s.resize(std::strlen(s.c_str())); return s;
  }
  static bool unb64(const std::string& s, std::string& out) {
    out.assign(s.size(), '\0'); size_t len = 0;
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(out.data()), out.size(), s.data(), s.size(),
                          nullptr, &len, nullptr, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) return false;
    out.resize(len); return true;
  }
public:
  // NOTE: key lives only for this process. For persistence put it in TPM / Keychain / DPAPI / libsecret.
  TokenIssuer() {
    sk_ = static_cast<unsigned char*>(sodium_malloc(crypto_sign_SECRETKEYBYTES));
    crypto_sign_keypair(pk_, sk_);
  }
  ~TokenIssuer() { sodium_free(sk_); }

  std::string issue(const std::string& user, int ttlSec) const {
    unsigned char n[16]; randombytes_buf(n, sizeof n);
    char hex[33]; sodium_bin2hex(hex, sizeof hex, n, sizeof n);
    time_t now = time(nullptr);
    std::ostringstream p; p << user << '|' << now << '|' << now + ttlSec << '|' << hex;
    std::string payload = p.str();
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), sk_);
    return b64(reinterpret_cast<const unsigned char*>(payload.data()), payload.size()) + "." + b64(sig, sizeof sig);
  }

  bool verify(const std::string& token, std::string& userOut) const {
    auto dot = token.find('.'); if (dot == std::string::npos) return false;
    std::string payload, sig;
    if (!unb64(token.substr(0, dot), payload) || !unb64(token.substr(dot + 1), sig)) return false;
    if (sig.size() != crypto_sign_BYTES) return false;
    if (crypto_sign_verify_detached(reinterpret_cast<const unsigned char*>(sig.data()),
                                    reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), pk_) != 0)
      return false;
    std::istringstream in(payload); std::string user, iat, exp;
    std::getline(in, user, '|'); std::getline(in, iat, '|'); std::getline(in, exp, '|');
    if (time(nullptr) > std::stol(exp)) return false;
    userOut = user; return true;  // production: also track nonce to stop replay
  }
};
