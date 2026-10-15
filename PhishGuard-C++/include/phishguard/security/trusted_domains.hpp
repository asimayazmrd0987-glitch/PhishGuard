// =============================================================================
// FILE: include/phishguard/security/trusted_domains.hpp
// WHAT   The list of trusted websites (paypal.com, google.com ...) with their brand name
//        ("paypal") and category. Needed for look-alike detection and to avoid false alarms.
// HOW    A HashTable keyed by domain. isTrustedHost("accounts.google.com") walks UP the name by
//        dropping the leftmost label each time (accounts.google.com -> google.com) and checks
//        each candidate, so subdomains of trusted domains count as trusted but
//        "paypal.com.evil.test" or "notpaypal.com" do not.
// WHY    O(1) lookup per label; the user can add or remove entries from the menu.
// LIMITATION  A hijacked subdomain of a trusted site would still count as trusted.
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "phishguard/ds/hash_table.hpp"

namespace phishguard {

struct TrustedEntry {
    std::string domain;    // paypal.com
    std::string brand;     // paypal
    std::string category;  // payments
};

// Trusted domains in a hash table keyed by domain: lookup average O(1).
class TrustedDomainStore {
public:
    bool add(const TrustedEntry& entry);  // true if new, false if replaced
    bool remove(const std::string& domain);
    const TrustedEntry* find(const std::string& domain) const;
    // True if host is a trusted domain or a subdomain of one (walks up the labels: O(labels)).
    bool isTrustedHost(const std::string& host) const;
    std::vector<TrustedEntry> snapshot() const;  // unsorted
    std::vector<TrustedEntry> all() const;       // sorted by domain
    std::size_t size() const { return table_.size(); }

    static TrustedDomainStore loadFromFile(const std::string& path);  // domain|brand|category
    void saveToFile(const std::string& path) const;

private:
    HashTable<std::string, TrustedEntry> table_;
};

}  // namespace phishguard
