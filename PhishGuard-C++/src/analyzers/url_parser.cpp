// =============================================================================
// FILE: src/analyzers/url_parser.cpp
// WHAT   Implementation of parsing and link extraction.
// HOW    Tricky cases handled on purpose:
//        * "user:pw@host" : we use the LAST '@' so "http://google.com@evil.test" correctly has the
//          host evil.test (a classic disguise).
//        * no scheme ("example.com/x"): http is assumed and hadScheme is set to false.
//        * IPv6 in [brackets] and IPv4 with range checks (999.1.1.1 is rejected).
//        * extractUrls(): strips punctuation around each word, accepts http(s)://, www., or a bare
//          name whose ending is in the known-endings list (so "Hi.There" and e-mail addresses are
//          NOT treated as links).
// =============================================================================

#include "phishguard/analyzers/url_parser.hpp"

#include <cctype>

#include "phishguard/common/text_utils.hpp"

namespace phishguard {

namespace {

bool isSchemeChar(char c) { return text::isAlnumChar(c) || c == '+' || c == '-' || c == '.'; }

bool isHostChar(char c) {
    const auto u = static_cast<unsigned char>(c);
    return text::isAlnumChar(c) || c == '-' || c == '.' || u >= 0x80;  // >=0x80: UTF-8 (IDN) bytes
}

}  // namespace

ParsedUrl UrlParser::parse(const std::string& raw) const {
    ParsedUrl p;
    p.original = raw;
    auto fail = [&p](const std::string& msg) {
        p.valid = false;
        p.error = msg;
        return p;
    };

    const std::string s = text::trim(raw);
    if (s.empty()) return fail("nothing was entered");
    if (s.size() > kMaxUrlLength) return fail("the link is extremely long");
    for (unsigned char c : s)
        if (c <= 0x20 || c == 0x7f) return fail("the link contains spaces or control characters");

    // 1. scheme
    std::string rest;
    const auto sep = s.find("://");
    bool schemeOk = sep != std::string::npos && sep > 0;
    if (schemeOk)
        for (std::size_t i = 0; i < sep; ++i) schemeOk = schemeOk && isSchemeChar(s[i]);
    if (schemeOk) {
        p.scheme = text::toLower(s.substr(0, sep));
        rest = s.substr(sep + 3);
    } else {
        p.hadScheme = false;
        p.scheme = "http";  // assumed, flagged via hadScheme
        rest = s;
    }

    // 2. authority = userinfo@host:port, ends at first / ? #
    const auto authEnd = rest.find_first_of("/?#");
    const std::string authority = rest.substr(0, authEnd);
    const std::string remainder = (authEnd == std::string::npos) ? "" : rest.substr(authEnd);
    if (authority.empty()) return fail("the website name is missing");

    std::string hostPort = authority;
    const auto at = authority.rfind('@');
    if (at != std::string::npos) {
        p.userinfo = authority.substr(0, at);
        hostPort = authority.substr(at + 1);
    }
    if (hostPort.empty()) return fail("the website name is missing");

    std::string portText;
    if (hostPort[0] == '[') {  // IPv6 literal
        const auto close = hostPort.find(']');
        if (close == std::string::npos) return fail("the address is not formatted correctly");
        p.host = text::toLower(hostPort.substr(1, close - 1));
        p.hostIsIp = true;
        if (close + 1 < hostPort.size()) {
            if (hostPort[close + 1] != ':') return fail("the address is not formatted correctly");
            portText = hostPort.substr(close + 2);
        }
    } else {
        const auto colon = hostPort.rfind(':');
        if (colon == std::string::npos) {
            p.host = text::toLower(hostPort);
        } else {
            p.host = text::toLower(hostPort.substr(0, colon));
            portText = hostPort.substr(colon + 1);
        }
    }
    if (!portText.empty()) {
        if (!text::isAllDigits(portText) || portText.size() > 5 || std::stoi(portText) > 65535)
            return fail("the port number is not valid");
        p.port = std::stoi(portText);
    }
    while (!p.host.empty() && p.host.back() == '.' && !p.hostIsIp) p.host.pop_back();  // "example.com."
    if (p.host.empty()) return fail("the website name is missing");

    // 3. path / query / fragment
    std::string tail = remainder;
    const auto hash = tail.find('#');
    if (hash != std::string::npos) {
        p.fragment = tail.substr(hash + 1);
        tail = tail.substr(0, hash);
    }
    const auto qm = tail.find('?');
    if (qm != std::string::npos) {
        p.query = tail.substr(qm + 1);
        tail = tail.substr(0, qm);
    }
    p.path = tail;

    if (p.hostIsIp) {  // IPv6: nothing more to split
        p.registeredDomain = p.host;
        p.valid = true;
        return p;
    }

    // 4. validate the host
    for (char c : p.host)
        if (!isHostChar(c)) return fail("the website name contains unusual characters");
    if (p.host.size() > 253) return fail("the website name is too long");
    p.labels = text::split(p.host, '.');
    for (const auto& label : p.labels) {
        if (label.empty()) return fail("the website name has an empty section");
        if (label.size() > 63) return fail("part of the website name is too long");
        if (label.front() == '-' || label.back() == '-') return fail("part of the website name starts or ends with a hyphen");
    }

    // 5. IPv4 literal?
    if (p.labels.size() == 4) {
        bool allNumeric = true;
        bool inRange = true;
        for (const auto& l : p.labels) {
            if (!text::isAllDigits(l) || l.size() > 3) { allNumeric = false; break; }
            if (std::stoi(l) > 255) inRange = false;
        }
        if (allNumeric) {
            if (!inRange) return fail("the number address is not valid");
            p.hostIsIp = true;
            p.registeredDomain = p.host;
            p.registeredLabel = p.host;
            p.valid = true;
            return p;
        }
    }

    // 6. TLD, registered domain, subdomain count
    const std::size_t n = p.labels.size();
    p.tld = p.labels.back();
    std::size_t suffixLabels = 1;
    if (suffixes_ && n >= 3 && suffixes_->contains(p.labels[n - 2] + "." + p.labels[n - 1])) suffixLabels = 2;
    if (n > suffixLabels) {
        const std::size_t reg = n - suffixLabels - 1;
        p.registeredLabel = p.labels[reg];
        p.registeredDomain = text::join(p.labels, reg, '.');
        p.subdomainCount = static_cast<int>(reg);
    } else {
        p.registeredLabel = p.labels.front();
        p.registeredDomain = p.host;
        p.subdomainCount = 0;
    }
    p.valid = true;
    return p;
}

std::vector<std::string> UrlParser::extractUrls(const std::string& textIn, const CustomSet<std::string>& knownTlds) {
    std::vector<std::string> urls;
    CustomSet<std::string> seen;
    for (std::string tok : text::splitAny(textIn, " \t\r\n")) {
        while (!tok.empty() && std::string("([{<\"'").find(tok.front()) != std::string::npos) tok.erase(0, 1);
        while (!tok.empty() && std::string(".,;:!?)]}>\"'").find(tok.back()) != std::string::npos) tok.pop_back();
        if (tok.empty()) continue;
        const std::string lower = text::toLower(tok);

        bool accept = text::startsWith(lower, "http://") || text::startsWith(lower, "https://") || text::startsWith(lower, "www.");
        if (!accept && lower.find('@') == std::string::npos) {  // bare domain such as paypa1-login.xyz/verify
            const auto end = lower.find_first_of("/?#");
            const std::string host = lower.substr(0, end);
            const auto dot = host.rfind('.');
            if (dot != std::string::npos && dot > 0 && dot + 1 < host.size()) {
                bool chars = true;
                for (char c : host) chars = chars && (text::isAlnumChar(c) || c == '-' || c == '.');
                accept = chars && knownTlds.contains(host.substr(dot + 1)) && host.find("..") == std::string::npos;
            }
        }
        if (accept && seen.insert(lower)) urls.push_back(tok);
    }
    return urls;
}

}  // namespace phishguard
