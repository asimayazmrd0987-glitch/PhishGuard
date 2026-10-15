// =============================================================================
// FILE: src/security/threat_database.cpp
// WHAT   Implementation of the threat database.
// HOW    * Keys are lower-cased/trimmed (normalized()). update() never changes the key.
//        * all() sorts by risk (highest first) then domain, using merge sort.
//        * loadFromFile() reports file:line for any bad row, including unknown risk words.
//        * saveToFile() rewrites the whole file (called after the user edits the list in the menu).
// =============================================================================

#include "phishguard/security/threat_database.hpp"

#include <fstream>
#include <stdexcept>

#include "phishguard/algorithms/sorting.hpp"
#include "phishguard/common/text_utils.hpp"

namespace phishguard {

namespace {
ThreatEntry normalized(ThreatEntry e) {
    e.domain = text::toLower(text::trim(e.domain));
    e.category = text::toLower(text::trim(e.category));
    if (e.domain.empty()) throw std::invalid_argument("threat domain must not be empty");
    return e;
}
}  // namespace

bool ThreatDatabase::add(const ThreatEntry& entry) {
    ThreatEntry e = normalized(entry);
    return table_.insert(e.domain, e);
}

bool ThreatDatabase::update(const std::string& domain, const ThreatEntry& entry) {
    ThreatEntry* existing = table_.find(text::toLower(text::trim(domain)));
    if (!existing) return false;
    ThreatEntry e = normalized(entry);
    e.domain = existing->domain;  // the key never changes on update
    *existing = e;
    return true;
}

bool ThreatDatabase::remove(const std::string& domain) { return table_.remove(text::toLower(text::trim(domain))); }

const ThreatEntry* ThreatDatabase::find(const std::string& domain) const { return table_.find(text::toLower(domain)); }

const ThreatEntry* ThreatDatabase::findForHost(const std::string& host) const {
    std::string candidate = text::toLower(host);
    for (;;) {
        if (const ThreatEntry* e = table_.find(candidate)) return e;
        const auto dot = candidate.find('.');
        if (dot == std::string::npos) return nullptr;
        candidate = candidate.substr(dot + 1);
    }
}

std::vector<ThreatEntry> ThreatDatabase::all() const {
    std::vector<ThreatEntry> out;
    table_.forEach([&](const std::string&, const ThreatEntry& e) { out.push_back(e); });
    mergeSort(out, [](const ThreatEntry& a, const ThreatEntry& b) {
        if (a.risk != b.risk) return static_cast<int>(a.risk) > static_cast<int>(b.risk);
        return a.domain < b.domain;
    });
    return out;
}

std::vector<ThreatEntry> ThreatDatabase::byCategory(const std::string& category) const {
    std::vector<ThreatEntry> out;
    const std::string c = text::toLower(text::trim(category));
    for (auto& e : all())
        if (e.category == c) out.push_back(e);
    return out;
}

ThreatDatabase ThreatDatabase::loadFromFile(const std::string& path) {
    ThreatDatabase db;
    for (const auto& line : text::readDataLines(path)) {
        const auto parts = text::split(line.text, '|');
        const std::string where = path + ":" + std::to_string(line.number);
        if (parts.size() < 4) throw std::runtime_error(where + ": expected domain|category|risk|note");
        ThreatEntry e;
        e.domain = parts[0];
        e.category = parts[1];
        if (!parseRiskLevel(parts[2], e.risk)) throw std::runtime_error(where + ": unknown risk level '" + parts[2] + "'");
        e.note = text::trim(parts[3]);
        db.add(e);
    }
    return db;
}

void ThreatDatabase::saveToFile(const std::string& path) const {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot write " + path);
    out << "# Threat list (SYNTHETIC SAMPLES ONLY: reserved .test domains, never real sites).\n"
           "# FORMAT  domain|category|risk|note   (risk = low, medium, high or critical)\n"
           "# Only add a real domain if you have a reliable source: a wrong entry accuses an innocent site.\n";
    for (const auto& e : all()) out << e.domain << '|' << e.category << '|' << toString(e.risk) << '|' << e.note << '\n';
}

}  // namespace phishguard
