// =============================================================================
// FILE: include/phishguard/analyzers/url_parser.hpp
// WHAT   A hand-written URL parser (no regular expressions) plus a finder that pulls links out of
//        free text.
// HOW    scheme://userinfo@host:port/path?query#fragment is split in ONE left-to-right pass:
//        scheme -> authority (ends at the first / ? #) -> userinfo (before the LAST '@') -> host and
//        port -> path/query/fragment. Then the host is validated, split into labels on '.', checked
//        for an IPv4 address, and the registered domain is found (a small list of two-part suffixes
//        such as co.uk is used).
// WHY    Everything else (keywords, look-alikes, TLD checks) needs clean parts. The parser is
//        strict: spaces, empty labels, bad ports or bad IPs make the link "malformed" instead of
//        being guessed at.
// COMPLEXITY  O(length of the URL).
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "phishguard/ds/custom_set.hpp"

namespace phishguard {

struct ParsedUrl {
    bool valid = false;
    std::string error;
    std::string original;
    bool hadScheme = true;
    std::string scheme, userinfo, host, path, query, fragment;
    int port = -1;
    bool hostIsIp = false;
    std::vector<std::string> labels;  // host split on '.'
    std::string tld;                  // last label
    std::string registeredDomain;     // label + public suffix, e.g. example.co.uk
    std::string registeredLabel;      // the label just left of the suffix
    int subdomainCount = 0;
};

// Hand-written URL parser (no regex). O(n) in the URL length.
class UrlParser {
public:
    static constexpr std::size_t kMaxUrlLength = 2048;

    explicit UrlParser(const CustomSet<std::string>* publicSuffixes = nullptr) : suffixes_(publicSuffixes) {}
    ParsedUrl parse(const std::string& raw) const;

    // Finds link-like tokens in free text: http(s)://..., www..., or bare domains with a known TLD.
    static std::vector<std::string> extractUrls(const std::string& text, const CustomSet<std::string>& knownTlds);

private:
    const CustomSet<std::string>* suffixes_;
};

}  // namespace phishguard
