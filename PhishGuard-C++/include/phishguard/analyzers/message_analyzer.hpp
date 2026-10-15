// =============================================================================
// FILE: include/phishguard/analyzers/message_analyzer.hpp
// WHAT   Analyzes the TEXT of an SMS / WhatsApp / social / e-mail message.
// HOW    1. Validate (not empty, <= 10,000 characters, no control characters).
//        2. Phrase categories with KMP: urgency, credential request, financial request, prize,
//           delivery. One indicator per category, whatever the number of matches.
//        3. Single suspicious words with the Trie (capped later by the risk engine).
//        4. Writing style: many !/?, mostly CAPITALS, stretched words ("heyyyy"), long scrambled
//           strings.
//        5. Every link found (up to 5) goes through UrlAnalyzer.
// WHY    Scams are often TEXT ONLY (an OTP request has no link), so message analysis cannot depend
//        on URL analysis. Known weakness: scams with none of these signs are missed (a documented
//        false negative, demo 14).
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "phishguard/analyzers/url_analyzer.hpp"
#include "phishguard/common/types.hpp"
#include "phishguard/ds/trie.hpp"
#include "phishguard/security/detection_data.hpp"

namespace phishguard {

struct MessageAnalysis {
    std::vector<Indicator> indicators;
    std::vector<UrlAnalysis> urls;
    std::vector<KeywordMatch> keywords;
};

class MessageAnalyzer {
public:
    static constexpr std::size_t kMaxLength = 10000;
    static constexpr std::size_t kMaxUrls = 5;

    explicit MessageAnalyzer(const DetectionData& data) : data_(data), urlAnalyzer_(data) {}
    // Throws std::invalid_argument for empty or oversized input.
    MessageAnalysis analyze(const std::string& text) const;

private:
    const DetectionData& data_;
    UrlAnalyzer urlAnalyzer_;
};

}  // namespace phishguard
