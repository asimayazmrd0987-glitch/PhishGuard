// =============================================================================
// FILE: src/security/trusted_domains.cpp
// WHAT   Implementation: add/remove/find, subdomain-aware trust check, load/save of
//        data/trusted_domains.txt (format  domain|brand|category).
// HOW    Domains are lower-cased and trimmed on the way in so "PayPal.com " and "paypal.com" are
//        the same key. all() returns entries sorted by domain with our merge sort for display.
// =============================================================================

#include "phishguard/security/trusted_domains.hpp"

#include <fstream>
#include <stdexcept>

#include "phishguard/algorithms/sorting.hpp"
#include "phishguard/common/text_utils.hpp"

namespace phishguard {

bool TrustedDomainStore::add(const TrustedEntry& entry) {
    TrustedEntry e = entry;
    e.domain = text::toLower(text::trim(e.domain));
    e.brand = text::toLower(text::trim(e.brand));
    if (e.domain.empty()) throw std::invalid_argument("trusted domain must not be empty");
    return table_.insert(e.domain, e);
}

bool TrustedDomainStore::remove(const std::string& domain) { return table_.remove(text::toLower(text::trim(domain))); }

const TrustedEntry* TrustedDomainStore::find(const std::string& domain) const {
    return table_.find(text::toLower(domain));
}

bool TrustedDomainStore::isTrustedHost(const std::string& host) const {
    std::string candidate = text::toLower(host);
    for (;;) {
        if (table_.contains(candidate)) return true;
        const auto dot = candidate.find('.');
        if (dot == std::string::npos) return false;
        candidate = candidate.substr(dot + 1);  // drop the leftmost label
    }
}

std::vector<TrustedEntry> TrustedDomainStore::snapshot() const {
    std::vector<TrustedEntry> out;
    table_.forEach([&](const std::string&, const TrustedEntry& e) { out.push_back(e); });
    return out;
}

std::vector<TrustedEntry> TrustedDomainStore::all() const {
    auto out = snapshot();
    mergeSort(out, [](const TrustedEntry& a, const TrustedEntry& b) { return a.domain < b.domain; });
    return out;
}

TrustedDomainStore TrustedDomainStore::loadFromFile(const std::string& path) {
    TrustedDomainStore store;
    for (const auto& line : text::readDataLines(path)) {
        const auto parts = text::split(line.text, '|');
        if (parts.size() < 3) throw std::runtime_error(path + ":" + std::to_string(line.number) + ": expected domain|brand|category");
        store.add({parts[0], parts[1], text::trim(parts[2])});
    }
    return store;
}

void TrustedDomainStore::saveToFile(const std::string& path) const {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot write " + path);
    out << "# Trusted websites: used to spot look-alikes and to avoid false alarms on the real sites.\n"
           "# FORMAT  domain|brand|category   e.g. paypal.com|paypal|payments\n";
    for (const auto& e : all()) out << e.domain << '|' << e.brand << '|' << e.category << '\n';
}

}  // namespace phishguard
