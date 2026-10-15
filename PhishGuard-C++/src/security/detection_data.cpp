// =============================================================================
// FILE: src/security/detection_data.cpp
// WHAT   Reads all data files and builds the in-memory structures.
// HOW    Each file has a tiny format (see the comment at the top of each file in data/).
//        Every parse error throws std::runtime_error with file and line, so a broken data file
//        stops the program with a clear message rather than giving silently wrong results.
// =============================================================================

#include "phishguard/security/detection_data.hpp"

#include <fstream>
#include <stdexcept>

#include "phishguard/common/text_utils.hpp"

namespace phishguard {

namespace {
void loadWordList(const std::string& path, CustomSet<std::string>& into) {
    for (const auto& line : text::readDataLines(path)) into.insert(text::toLower(line.text));
}
}  // namespace

DetectionData DetectionData::loadFromDirectory(const std::string& dir) {
    DetectionData d;
    d.dataDir = dir;
    auto p = [&](const char* name) { return dir + "/" + name; };

    d.config = RiskConfig::loadFromFile(p("risk_config.txt"));
    d.trusted = TrustedDomainStore::loadFromFile(p("trusted_domains.txt"));
    d.threats = ThreatDatabase::loadFromFile(p("sample_threats.txt"));

    for (const auto& line : text::readDataLines(p("suspicious_keywords.txt"))) {
        const auto parts = text::split(line.text, '|');
        const std::string where = p("suspicious_keywords.txt") + ":" + std::to_string(line.number);
        if (parts.size() < 3) throw std::runtime_error(where + ": expected word|category|weight");
        int weight = 0;
        try {
            weight = std::stoi(text::trim(parts[2]));
        } catch (const std::exception&) {
            throw std::runtime_error(where + ": bad weight");
        }
        d.keywords.insert(text::trim(parts[0]), {text::trim(parts[1]), weight});
    }
    for (const auto& line : text::readDataLines(p("suspicious_phrases.txt"))) {
        const auto parts = text::split(line.text, '|');
        if (parts.size() < 2)
            throw std::runtime_error(p("suspicious_phrases.txt") + ":" + std::to_string(line.number) + ": expected phrase|category");
        d.phrases.push_back({text::toLower(text::trim(parts[0])), text::toLower(text::trim(parts[1]))});
    }
    loadWordList(p("suspicious_tlds.txt"), d.suspiciousTlds);
    loadWordList(p("url_shorteners.txt"), d.urlShorteners);
    loadWordList(p("known_tlds.txt"), d.knownTlds);
    loadWordList(p("public_suffixes.txt"), d.publicSuffixes);
    return d;
}

std::string DetectionData::findDataDirectory(const std::string& hint) {
    const std::vector<std::string> candidates = {hint, "data", "../data", "../../data", "../../../data"};
    for (const auto& c : candidates) {
        if (c.empty()) continue;
        if (std::ifstream(c + "/risk_config.txt").good()) return c;
    }
    return "";
}

}  // namespace phishguard
