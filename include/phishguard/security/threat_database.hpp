// =============================================================================
// FILE: include/phishguard/security/threat_database.hpp
// WHAT   The local list of known-bad domains: domain, category, risk level, note.
// HOW    A HashTable keyed by domain. findForHost("login.bad.test") also tries parent domains, so
//        listing "bad.test" covers all its subdomains. Supports add, update, remove, search,
//        list by category and file load/save.
// WHY    A match is the strongest single signal (+50 by default) and costs O(1).
// SAFETY The shipped data/sample_threats.txt is SYNTHETIC (reserved .test domains). Never put a
//        real domain here as "malicious" without a reliable source: a wrong entry would be an
//        accusation against an innocent site.
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "phishguard/common/types.hpp"
#include "phishguard/ds/hash_table.hpp"

namespace phishguard {

struct ThreatEntry {
    std::string domain;
    std::string category;  // credential, prize_scam, delivery_scam ...
    RiskLevel risk = RiskLevel::High;
    std::string note;
};

// Local threat list in a hash table keyed by domain. SAMPLE DATA ONLY is shipped
// (reserved .test domains); we never label a real domain as malicious without a source.
class ThreatDatabase {
public:
    bool add(const ThreatEntry& entry);                          // true if new
    bool update(const std::string& domain, const ThreatEntry& entry);  // false if missing
    bool remove(const std::string& domain);
    const ThreatEntry* find(const std::string& domain) const;
    const ThreatEntry* findForHost(const std::string& host) const;  // host or any parent domain
    std::vector<ThreatEntry> all() const;                            // risk desc, then domain
    std::vector<ThreatEntry> byCategory(const std::string& category) const;
    std::size_t size() const { return table_.size(); }
    double loadFactor() const { return table_.loadFactor(); }
    std::size_t bucketCount() const { return table_.bucketCount(); }

    static ThreatDatabase loadFromFile(const std::string& path);  // domain|category|risk|note
    void saveToFile(const std::string& path) const;

private:
    HashTable<std::string, ThreatEntry> table_;
};

}  // namespace phishguard
