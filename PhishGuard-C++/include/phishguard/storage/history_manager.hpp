// =============================================================================
// FILE: include/phishguard/storage/history_manager.hpp
// WHAT   The scan history: every scan is saved as a record (id, time, type, redacted input, score,
//        level, indicator ids) and can be viewed, sorted, filtered, inspected, removed and counted.
// HOW    Records live in a vector. sorted() uses our stable merge sort; topRisk(k) builds a max-heap
//        (heapify O(n), k pops O(k log n)); stats() counts indicator ids in a hash table. The file
//        format is one line per record separated by '|' (the input never contains '|').
// PRIVACY  The input is REDACTED before saving: passwords, PINs, OTPs, CVVs, digit runs of 4+, URL
//        query strings and "user:password@" parts are removed. Never store secrets.
// ROBUSTNESS  load() ignores a missing file and skips damaged lines instead of crashing.
// =============================================================================
#pragma once
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "phishguard/common/types.hpp"

namespace phishguard {

struct ScanRecord {
    int id = 0;
    std::string timestamp;
    InputType type = InputType::Url;
    std::string input;  // REDACTED copy: passwords/PINs/OTPs/long digit runs/query strings removed
    int score = 0;
    RiskLevel level = RiskLevel::Low;
    std::vector<std::string> indicatorIds;
};

enum class SortKey { Newest, Oldest, ScoreHigh, ScoreLow, Level };

struct HistoryStats {
    std::size_t total = 0;
    std::size_t perLevel[4] = {0, 0, 0, 0};
    double averageScore = 0.0;
    std::vector<std::pair<std::string, int>> topIndicators;  // up to 5
};

class HistoryManager {
public:
    int add(const AnalysisResult& result);  // returns the new record id
    bool remove(int id);
    const ScanRecord* find(int id) const;
    void clear() { records_.clear(); }
    std::size_t size() const { return records_.size(); }
    const std::vector<ScanRecord>& records() const { return records_; }

    std::vector<ScanRecord> sorted(SortKey key) const;  // merge sort, stable
    std::vector<ScanRecord> filter(std::optional<RiskLevel> minLevel, std::optional<InputType> type,
                                   const std::string& contains) const;
    std::vector<ScanRecord> topRisk(std::size_t k) const;  // max-heap
    HistoryStats stats() const;

    void save(const std::string& path) const;                 // throws std::runtime_error
    static HistoryManager load(const std::string& path);      // missing file => empty; bad lines skipped

private:
    std::vector<ScanRecord> records_;
    int nextId_ = 1;
};

}  // namespace phishguard
