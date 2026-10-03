// Detection + alignment + embedding (YuNet + SFace via OpenCV), and passive liveness (MiniFASNet ONNX).
#pragma once
#include <opencv2/dnn.hpp>
#include <opencv2/objdetect/face.hpp>
#include <opencv2/opencv.hpp>
#include <cmath>
#include <optional>
#include "secure_store.hpp"

struct FaceObs {
  cv::Rect box;
  float yaw = 0;     // ~0 frontal; sign = which way the nose points in image coordinates
  Embedding emb;     // L2-normalised
};

inline float cosine(const Embedding& a, const Embedding& b) {
  if (a.size() != b.size()) return -1.f;
  float s = 0; for (size_t i = 0; i < a.size(); ++i) s += a[i] * b[i];
  return s;  // both unit length
}

class FaceEngine {
  cv::Ptr<cv::FaceDetectorYN> det_;
  cv::Ptr<cv::FaceRecognizerSF> rec_;
public:
  FaceEngine(const std::string& detModel, const std::string& recModel)
      : det_(cv::FaceDetectorYN::create(detModel, "", cv::Size(320, 320), 0.9f, 0.3f, 5000)),
        rec_(cv::FaceRecognizerSF::create(recModel, "")) {}

  // Exactly one sufficiently large face, or nullopt (rejects crowds / tiny faces).
  std::optional<FaceObs> observe(const cv::Mat& frame) {
    det_->setInputSize(frame.size());
    cv::Mat faces; det_->detect(frame, faces);
    if (faces.rows != 1) return std::nullopt;
    const float* p = faces.ptr<float>(0);  // x y w h | reye leye nose rmouth lmouth (x,y each) | score
    FaceObs o;
    o.box = cv::Rect(int(p[0]), int(p[1]), int(p[2]), int(p[3])) & cv::Rect(0, 0, frame.cols, frame.rows);
    if (o.box.width < 120) return std::nullopt;
    float d = p[6] - p[4];
    if (std::fabs(d) < 1.f) return std::nullopt;
    o.yaw = (p[8] - (p[4] + p[6]) / 2.f) / d;
    cv::Mat aligned, feat;
    rec_->alignCrop(frame, faces.row(0), aligned);
    rec_->feature(aligned, feat);
    cv::Mat f = feat.clone(); cv::normalize(f, f);
    o.emb.assign(f.ptr<float>(0), f.ptr<float>(0) + f.total());
    return o;
  }
};

// Single-frame anti-spoof CNN (print / screen replay). Supply your own ONNX export of MiniFASNet
// and verify its input size, scale factor and which output index is "real" for YOUR model.
class PassiveLiveness {
  cv::dnn::Net net_; float scale_;
public:
  explicit PassiveLiveness(const std::string& onnx, float scale = 2.7f)
      : net_(cv::dnn::readNetFromONNX(onnx)), scale_(scale) {}
  float realProb(const cv::Mat& frame, const cv::Rect& box) {
    float side = std::max(box.width, box.height) * scale_;
    cv::Point2f c(box.x + box.width / 2.f, box.y + box.height / 2.f);
    cv::Rect r(int(c.x - side / 2), int(c.y - side / 2), int(side), int(side));
    cv::Mat crop = frame(r & cv::Rect(0, 0, frame.cols, frame.rows));
    cv::Mat blob = cv::dnn::blobFromImage(crop, 1.0, cv::Size(80, 80), cv::Scalar(), false, false);
    net_.setInput(blob);
    cv::Mat out = net_.forward().reshape(1, 1);
    cv::Mat e; cv::exp(out - cv::mean(out)[0], e);           // softmax
    e /= cv::sum(e)[0];
    return e.at<float>(0, 1);                                // index 1 = "real" in Silent-Face-Anti-Spoofing
  }
};
