// Usage:
//   facecred enroll <name>     facecred verify <name>     facecred identify     facecred list
// Env: FACE_DET (yunet .onnx)  FACE_REC (sface .onnx)  FACE_LIVE (minifasnet .onnx, optional but strongly advised)
#include <termios.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>
#include "face_engine.hpp"
#include "secure_store.hpp"
#include "token.hpp"

using namespace std::chrono;
static constexpr float kMatch = 0.40f;   // SFace cosine; default from OpenCV is 0.363. CALIBRATE on your own data.
static constexpr float kMargin = 0.05f;  // 1:N: best user must beat runner-up by this much
static constexpr float kLive = 0.80f;    // passive liveness average
static constexpr int kSamples = 5, kChallenges = 2, kTokenTtl = 300;

static std::string getenvOr(const char* k, const char* d) { const char* v = std::getenv(k); return v ? v : d; }

static std::string readPassphrase(const char* prompt) {
  std::cerr << prompt; termios o{}, n{}; tcgetattr(STDIN_FILENO, &o); n = o; n.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &n); std::string s; std::getline(std::cin, s);
  tcsetattr(STDIN_FILENO, TCSANOW, &o); std::cerr << "\n"; return s;
}

static bool validName(const std::string& s) {
  return !s.empty() && s.size() <= 64 && std::all_of(s.begin(), s.end(), [](char c) { return isalnum((unsigned char)c) || c == '_' || c == '-'; });
}

// Random-direction head-turn challenges + passive liveness + same-person continuity.
// Returns the embedding of the final frontal face, or nullopt on failure.
static std::optional<Embedding> liveCapture(cv::VideoCapture& cap, FaceEngine& eng, PassiveLiveness* pl) {
  enum { NEUTRAL, TURN, RETURN } ph = NEUTRAL;
  int step = 0; bool right = randombytes_uniform(2);
  std::optional<Embedding> first, last; double liveSum = 0; int liveN = 0;
  auto announce = [&] { std::cout << "Turn your head toward the " << (right ? "RIGHT" : "LEFT") << " of the screen, then face forward.\n"; };
  std::cout << "Face the camera.\n";
  auto deadline = steady_clock::now() + seconds(15); cv::Mat frame;
  while (steady_clock::now() < deadline && step < kChallenges) {
    if (!cap.read(frame)) continue;
    auto o = eng.observe(frame); if (!o) continue;
    if (pl) { liveSum += pl->realProb(frame, o->box); ++liveN; }
    float y = right ? o->yaw : -o->yaw;
    if (ph == NEUTRAL && std::fabs(o->yaw) < 0.08f) { if (!first) first = o->emb; ph = TURN; announce(); }
    else if (ph == TURN && y > 0.18f) ph = RETURN;
    else if (ph == RETURN && std::fabs(o->yaw) < 0.08f) {
      last = o->emb; ++step; right = randombytes_uniform(2); ph = TURN; if (step < kChallenges) announce();
    }
  }
  if (step < kChallenges || !first || !last) { std::cout << "Liveness challenge failed.\n"; return std::nullopt; }
  if (cosine(*first, *last) < kMatch) { std::cout << "Face changed during challenge.\n"; return std::nullopt; }
  if (pl) { if (liveN < 5 || liveSum / liveN < kLive) { std::cout << "Passive liveness failed.\n"; return std::nullopt; } }
  else std::cerr << "WARNING: passive liveness DISABLED - head-turn alone is NOT enough against video replay.\n";
  return last;
}

struct Match { std::string name; float score = -1, margin = 0; };
static Match identify(const Db& db, const Embedding& e) {
  std::vector<std::pair<float, std::string>> s;
  for (auto& [n, ts] : db) { float b = -1; for (auto& t : ts) b = std::max(b, cosine(t, e)); s.push_back({b, n}); }
  std::sort(s.rbegin(), s.rend()); Match m;
  if (!s.empty()) { m.name = s[0].second; m.score = s[0].first; m.margin = s.size() > 1 ? s[0].first - s[1].first : 1.f; }
  return m;
}

static void backoff(int& fails) { ++fails; std::this_thread::sleep_for(seconds(std::min(30, 1 << std::min(fails, 5)))); }

int main(int argc, char** argv) {
  if (argc < 2) { std::cerr << "usage: facecred enroll|verify <name> | identify | list\n"; return 2; }
  std::string cmd = argv[1], name = argc > 2 ? argv[2] : "";
  try {
    SecureStore store(getenvOr("FACE_DB", "faces.db"), readPassphrase("Store passphrase: "));
    Db db = store.load();
    if (cmd == "list") { for (auto& [n, t] : db) std::cout << n << " (" << t.size() << " templates)\n"; return 0; }

    FaceEngine eng(getenvOr("FACE_DET", "face_detection_yunet_2023mar.onnx"), getenvOr("FACE_REC", "face_recognition_sface_2021dec.onnx"));
    std::unique_ptr<PassiveLiveness> pl;
    if (const char* p = std::getenv("FACE_LIVE")) pl = std::make_unique<PassiveLiveness>(p);
    cv::VideoCapture cap(0); if (!cap.isOpened()) { std::cerr << "no camera\n"; return 1; }
    TokenIssuer issuer; int fails = 0;

    if (cmd == "enroll") {
      if (!validName(name)) { std::cerr << "bad name\n"; return 2; }
      if (db.count(name)) { std::cerr << "already enrolled\n"; return 2; }
      std::vector<Embedding> got;
      while ((int)got.size() < kSamples) {
        auto e = liveCapture(cap, eng, pl.get()); if (!e) { if (++fails > 5) return 1; continue; }
        if (!got.empty() && cosine(got[0], *e) < kMatch) { std::cout << "Inconsistent sample, retry.\n"; continue; }
        if (db.size()) { auto m = identify(db, *e); if (m.score >= kMatch) { std::cerr << "This face is already enrolled as '" << m.name << "'.\n"; return 1; } }
        got.push_back(*e); std::cout << "Sample " << got.size() << "/" << kSamples << " ok\n";
      }
      db[name] = got; store.save(db); std::cout << "Enrolled " << name << "\n"; return 0;
    }
    if (cmd == "verify" || cmd == "identify") {   // verify = 1:1 (preferred for credentials)
      if (cmd == "verify" && !db.count(name)) { std::cerr << "unknown user\n"; return 1; }
      for (;;) {
        auto e = liveCapture(cap, eng, pl.get());
        bool ok = false; std::string who;
        if (e && cmd == "verify") { float b = -1; for (auto& t : db[name]) b = std::max(b, cosine(t, *e)); ok = b >= kMatch; who = name; }
        else if (e) { auto m = identify(db, *e); ok = m.score >= kMatch && m.margin >= kMargin; who = m.name; }
        if (ok) { std::cout << "OK: " << who << "\ntoken: " << issuer.issue(who, kTokenTtl) << "\n"; return 0; }
        std::cout << "Denied.\n"; if (fails >= 5) { std::cerr << "Too many failures.\n"; return 1; } backoff(fails);
      }
    }
  } catch (const std::exception& ex) { std::cerr << "error: " << ex.what() << "\n"; return 1; }
  return 2;
}
