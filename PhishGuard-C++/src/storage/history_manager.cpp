// =============================================================================
// FILE: src/storage/history_manager.cpp
// WHAT   Implementation of the history.
// HOW    ids keep growing (nextId_ continues after the highest loaded id), so removing a record
//        never re-uses an id. "Newest" sorts by id descending, which equals time order.
// =============================================================================

#include "phishguard/storage/history_manager.hpp"

#include <fstream>
#include <stdexcept>

#include "phishguard/algorithms/sorting.hpp"
#include "phishguard/common/text_utils.hpp"
#include "phishguard/ds/hash_table.hpp"
#include "phishguard/ds/heap.hpp"

namespace phishguard {

int HistoryManager::add(const AnalysisResult& r) {
    ScanRecord rec;
    rec.id = nextId_++;
    rec.timestamp = text::currentTimestamp();
    rec.type = r.type;
    rec.input = (r.type == InputType::Url) ? text::redactUrl(r.input) : text::redactSensitive(r.input);
    for (char& c : rec.input)
        if (c == '|' || c == '\n' || c == '\r') c = ' ';  // keep the file format safe
    rec.score = r.score;
    rec.level = r.level;
    for (const auto& ind : r.indicators) rec.indicatorIds.push_back(ind.id);
    records_.push_back(rec);
    return rec.id;
}

bool HistoryManager::remove(int id) {
    for (std::size_t i = 0; i < records_.size(); ++i) {
        if (records_[i].id == id) {
            records_.erase(records_.begin() + static_cast<std::ptrdiff_t>(i));
            return true;
        }
    }
    return false;
}

const ScanRecord* HistoryManager::find(int id) const {
    for (const auto& r : records_)
        if (r.id == id) return &r;
    return nullptr;
}

std::vector<ScanRecord> HistoryManager::sorted(SortKey key) const {
    std::vector<ScanRecord> out = records_;
    switch (key) {
        case SortKey::Newest:    mergeSort(out, [](const ScanRecord& a, const ScanRecord& b) { return a.id > b.id; }); break;
        case SortKey::Oldest:    mergeSort(out, [](const ScanRecord& a, const ScanRecord& b) { return a.id < b.id; }); break;
        case SortKey::ScoreHigh: mergeSort(out, [](const ScanRecord& a, const ScanRecord& b) { return a.score > b.score; }); break;
        case SortKey::ScoreLow:  mergeSort(out, [](const ScanRecord& a, const ScanRecord& b) { return a.score < b.score; }); break;
        case SortKey::Level:
            mergeSort(out, [](const ScanRecord& a, const ScanRecord& b) { return static_cast<int>(a.level) > static_cast<int>(b.level); });
            break;
    }
    return out;
}

std::vector<ScanRecord> HistoryManager::filter(std::optional<RiskLevel> minLevel, std::optional<InputType> type,
                                               const std::string& contains) const {
    std::vector<ScanRecord> out;
    const std::string needle = text::toLower(contains);
    for (const auto& r : records_) {
        if (minLevel && static_cast<int>(r.level) < static_cast<int>(*minLevel)) continue;
        if (type && r.type != *type) continue;
        if (!needle.empty() && text::toLower(r.input).find(needle) == std::string::npos) continue;
        out.push_back(r);
    }
    return out;
}

std::vector<ScanRecord> HistoryManager::topRisk(std::size_t k) const {
    auto cmp = [](const ScanRecord& a, const ScanRecord& b) {  // "less": lower score, or newer when tied
        if (a.score != b.score) return a.score < b.score;
        return a.id > b.id;
    };
    MaxHeap<ScanRecord, decltype(cmp)> heap(records_, cmp);  // heapify O(n), then k pops O(k log n)
    std::vector<ScanRecord> out;
    while (!heap.empty() && out.size() < k) out.push_back(heap.pop());
    return out;
}

HistoryStats HistoryManager::stats() const {
    HistoryStats s;
    s.total = records_.size();
    HashTable<std::string, int> counts;
    long sum = 0;
    for (const auto& r : records_) {
        ++s.perLevel[static_cast<int>(r.level)];
        sum += r.score;
        for (const auto& id : r.indicatorIds) {
            if (int* c = counts.find(id)) ++*c;
            else counts.insert(id, 1);
        }
    }
    if (s.total > 0) s.averageScore = static_cast<double>(sum) / static_cast<double>(s.total);
    std::vector<std::pair<std::string, int>> all;
    counts.forEach([&](const std::string& k, const int& v) { all.emplace_back(k, v); });
    mergeSort(all, [](const auto& a, const auto& b) { return a.second != b.second ? a.second > b.second : a.first < b.first; });
    if (all.size() > 5) all.resize(5);
    s.topIndicators = std::move(all);
    return s;
}

void HistoryManager::save(const std::string& path) const {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot write history file: " + path);
    for (const auto& r : records_) {
        std::string ids;
        for (std::size_t i = 0; i < r.indicatorIds.size(); ++i) ids += (i ? "," : "") + r.indicatorIds[i];
        out << r.id << '|' << r.timestamp << '|' << toString(r.type) << '|' << r.score << '|' << toString(r.level) << '|' << ids << '|' << r.input << '\n';
    }
}

HistoryManager HistoryManager::load(const std::string& path) {
    HistoryManager h;
    std::ifstream in(path);
    if (!in) return h;
    std::string line;
    while (std::getline(in, line)) {
        const auto parts = text::split(line, '|');
        if (parts.size() < 7) continue;
        ScanRecord r;
        try {
            r.id = std::stoi(parts[0]);
            r.score = std::stoi(parts[3]);
        } catch (const std::exception&) {
            continue;
        }
        r.timestamp = parts[1];
        if (!parseInputType(parts[2], r.type) || !parseRiskLevel(parts[4], r.level)) continue;
        if (!parts[5].empty()) r.indicatorIds = text::split(parts[5], ',');
        r.input = parts[6];
        h.records_.push_back(r);
        if (r.id >= h.nextId_) h.nextId_ = r.id + 1;
    }
    return h;
}

}  // namespace phishguard
