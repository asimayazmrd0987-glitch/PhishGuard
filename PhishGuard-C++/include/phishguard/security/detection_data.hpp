// =============================================================================
// FILE: include/phishguard/security/detection_data.hpp
// WHAT   One object that owns everything the analyzers need, loaded once at start-up:
//        config, trusted domains, threat DB, keyword trie, scam phrases, and word lists
//        (suspicious endings, URL shorteners, known endings, multi-part suffixes like co.uk).
// HOW    DetectionData::loadFromDirectory("data") reads each file in data/. findDataDirectory()
//        looks in ./data, ../data, ../../data so the program works when started from build/.
// WHY    Analyzers receive a const reference to this one object (dependency injection), so tests
//        can use the real data and the UI can edit lists without global variables.
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "phishguard/ds/custom_set.hpp"
#include "phishguard/ds/trie.hpp"
#include "phishguard/security/risk_config.hpp"
#include "phishguard/security/threat_database.hpp"
#include "phishguard/security/trusted_domains.hpp"

namespace phishguard {

struct Phrase {
    std::string text;      // lower-case phrase, e.g. "act now"
    std::string category;  // urgency | credential | financial | prize | delivery
};

// Everything the analyzers need, loaded once from the data/ folder.
struct DetectionData {
    RiskConfig config;
    TrustedDomainStore trusted;
    ThreatDatabase threats;
    Trie keywords;
    std::vector<Phrase> phrases;
    CustomSet<std::string> suspiciousTlds;
    CustomSet<std::string> urlShorteners;
    CustomSet<std::string> knownTlds;
    CustomSet<std::string> publicSuffixes;  // multi-part suffixes such as co.uk
    std::string dataDir;

    static DetectionData loadFromDirectory(const std::string& dir);  // throws std::runtime_error
    // Returns the first directory that contains risk_config.txt (hint, ./data, ../data ...), or "".
    static std::string findDataDirectory(const std::string& hint = "");
};

}  // namespace phishguard
