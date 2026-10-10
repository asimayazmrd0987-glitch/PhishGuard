// =============================================================================
// FILE: include/phishguard/security/risk_config.hpp
// WHAT   Holds every tunable number: indicator weights (points), caps, limits and the thresholds
//        that turn a score into LOW / MEDIUM / HIGH / CRITICAL.
// HOW    Keys look like "weight.lookalike", "limit.long_url", "threshold.high_max". Defaults are
//        built into the constructor; data/risk_config.txt can override any of them. Values live
//        in our own HashTable, so lookups are average O(1).
// WHY    No "magic numbers" in the logic: to change how strict the tool is, edit one text file,
//        not the code. levelFor() clamps a score into 0..100 first so a bad score cannot crash it.
// NOTE   The weights are expert judgement, NOT statistically trained. Treat the output as a
//        Risk Score, never as a probability.
// =============================================================================
#pragma once
#include <string>

#include "phishguard/common/types.hpp"
#include "phishguard/ds/hash_table.hpp"

namespace phishguard {

// Holds every tunable number (indicator weights + level thresholds).
// No magic numbers elsewhere: the engine asks this class.
// Backed by our own HashTable (average O(1) lookups).
class RiskConfig {
public:
    RiskConfig();  // loads documented defaults

    int  weight(const std::string& key) const;       // throws std::out_of_range
    int  value(const std::string& key) const { return weight(key); }  // alias for limits/caps
    bool has(const std::string& key) const;
    void set(const std::string& key, int value);

    // Maps a score to a level using threshold.low_max / medium_max / high_max.
    // Scores are clamped to [0,100] first.
    RiskLevel levelFor(int score) const;

    // Reads "key=value" lines ('#' comments, blank lines allowed).
    // Starts from defaults, so a file only needs to override some keys.
    // Throws std::runtime_error on unreadable file or malformed line.
    static RiskConfig loadFromFile(const std::string& path);

private:
    HashTable<std::string, int> values_;
};

}  // namespace phishguard
