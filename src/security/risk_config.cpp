// =============================================================================
// FILE: src/security/risk_config.cpp
// WHAT   Default weights and the loader for risk_config.txt.
// HOW    The loader starts from the defaults, then reads "key = value" lines (comments with '#'
//        allowed). A malformed line throws std::runtime_error naming the file AND line number, so
//        a typo is easy to find. Numbers are parsed with std::stoi and the whole token must be
//        consumed ("12abc" is rejected).
// BUG TO WATCH  A misspelt key is accepted as a new key and simply never used; validating key
//        names on load is a good future improvement.
// =============================================================================

#include "phishguard/security/risk_config.hpp"

#include <fstream>
#include <stdexcept>

namespace phishguard {

namespace {

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    const auto first = s.find_first_not_of(ws);
    if (first == std::string::npos) return "";
    const auto last = s.find_last_not_of(ws);
    return s.substr(first, last - first + 1);
}

}  // namespace

RiskConfig::RiskConfig() {
    const std::pair<const char*, int> defaults[] = {
        // indicator weights (points)
        {"weight.known_threat", 50},  {"weight.lookalike", 30},       {"weight.brand_embedded", 25},
        {"weight.ip_host", 20},       {"weight.credential_request", 15},
        {"weight.financial_request", 15}, {"weight.userinfo_trick", 15},
        {"weight.urgency", 10},       {"weight.prize", 10},           {"weight.delivery", 10},
        {"weight.suspicious_tld", 10}, {"weight.many_subdomains", 10}, {"weight.punycode", 10},
        {"weight.unusual_scheme", 10}, {"weight.malformed", 10},
        {"weight.url_shortener", 8},  {"weight.redirect_param", 8},
        {"weight.keyword", 5},        {"weight.long_url", 5},         {"weight.long_host", 5},
        {"weight.many_hyphens", 5},   {"weight.digits_in_domain", 5}, {"weight.encoded_chars", 5},
        {"weight.encoded_text", 5},   {"weight.excessive_punct", 5},  {"weight.all_caps", 5},
        {"weight.repeated_chars", 3},
        // caps
        {"cap.keyword", 25},
        // limits
        {"limit.long_url", 75},       {"limit.long_host", 30},        {"limit.many_subdomains", 3},
        {"limit.many_hyphens", 3},    {"limit.encoded_chars", 3},
        // level thresholds (inclusive upper bounds)
        {"threshold.low_max", 20},    {"threshold.medium_max", 40},   {"threshold.high_max", 70},
    };
    for (const auto& d : defaults) values_.insert(d.first, d.second);
}

int RiskConfig::weight(const std::string& key) const {
    const int* v = values_.find(key);
    if (!v) throw std::out_of_range("unknown config key: " + key);
    return *v;
}

bool RiskConfig::has(const std::string& key) const { return values_.contains(key); }

void RiskConfig::set(const std::string& key, int value) { values_.insert(key, value); }

RiskLevel RiskConfig::levelFor(int score) const {
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    if (score <= weight("threshold.low_max")) return RiskLevel::Low;
    if (score <= weight("threshold.medium_max")) return RiskLevel::Medium;
    if (score <= weight("threshold.high_max")) return RiskLevel::High;
    return RiskLevel::Critical;
}

RiskConfig RiskConfig::loadFromFile(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open config file: " + path);

    RiskConfig cfg;
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        const auto eq = line.find('=');
        const std::string where = path + ":" + std::to_string(lineNo);
        if (eq == std::string::npos) throw std::runtime_error("missing '=' at " + where);

        const std::string key = trim(line.substr(0, eq));
        const std::string val = trim(line.substr(eq + 1));
        if (key.empty() || val.empty()) throw std::runtime_error("empty key/value at " + where);

        try {
            std::size_t used = 0;
            const int n = std::stoi(val, &used);
            if (used != val.size()) throw std::invalid_argument("trailing characters");
            cfg.set(key, n);
        } catch (const std::exception&) {
            throw std::runtime_error("bad number at " + where);
        }
    }
    return cfg;
}

}  // namespace phishguard
