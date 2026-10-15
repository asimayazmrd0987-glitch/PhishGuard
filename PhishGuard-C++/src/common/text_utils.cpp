// =============================================================================
// FILE: src/common/text_utils.cpp
// WHAT   Implementation of the text helpers.
// HOW    Notable details:
//        * Characters are cast to unsigned char before <cctype> calls (calling them with a
//          negative char is undefined behaviour in C++).
//        * redactSensitive() walks the words once. When it sees a secret word ("password",
//          "pin", "otp", "cvv") it hides the NEXT value: strongly if a connector like
//          "is" or ":" follows, weakly (only if it contains a digit) otherwise. That is why
//          "share your OTP and PIN" keeps its words but "OTP is 482913" loses the number.
//        * currentTimestamp() uses localtime_s on Windows and localtime_r elsewhere, because
//          plain localtime() is not thread-safe.
// COMPLEXITY  All helpers are O(length of input).
// =============================================================================

#include "phishguard/common/text_utils.hpp"

#include <cctype>
#include <ctime>
#include <fstream>
#include <stdexcept>

namespace phishguard::text {

std::string toLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    const auto first = s.find_first_not_of(ws);
    if (first == std::string::npos) return "";
    const auto last = s.find_last_not_of(ws);
    return s.substr(first, last - first + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const auto pos = s.find(delim, start);
        if (pos == std::string::npos) {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
}

std::vector<std::string> splitAny(const std::string& s, const std::string& delims) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (delims.find(c) != std::string::npos) {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool startsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}
bool endsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

bool isAllDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!isDigitChar(c)) return false;
    return true;
}

bool isAlnumChar(char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; }
bool isAlphaChar(char c) { return std::isalpha(static_cast<unsigned char>(c)) != 0; }
bool isDigitChar(char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; }

std::string join(const std::vector<std::string>& parts, std::size_t from, char sep) {
    std::string out;
    for (std::size_t i = from; i < parts.size(); ++i) {
        if (i > from) out += sep;
        out += parts[i];
    }
    return out;
}

std::string normalizeLookalikes(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        switch (c) {
            case '0': c = 'o'; break;
            case '1': c = 'l'; break;
            case '3': c = 'e'; break;
            case '4': c = 'a'; break;
            case '5': c = 's'; break;
            case '7': c = 't'; break;
            case '@': c = 'a'; break;
            case '$': c = 's'; break;
            default: break;
        }
    }
    return out;
}

namespace {

bool isSecretWord(std::string w) {
    while (!w.empty() && (w.back() == ':' || w.back() == '=' || w.back() == ',' || w.back() == '.'))
        w.pop_back();
    w = toLower(w);
    return w == "password" || w == "passcode" || w == "passwd" || w == "pwd" || w == "pin" ||
           w == "otp" || w == "cvv";
}

std::string maskDigitRuns(const std::string& s) {
    std::string out;
    std::size_t i = 0;
    while (i < s.size()) {
        if (isDigitChar(s[i])) {
            std::size_t j = i;
            while (j < s.size() && isDigitChar(s[j])) ++j;
            out += (j - i >= 4) ? std::string("[digits]") : s.substr(i, j - i);
            i = j;
        } else {
            out += s[i++];
        }
    }
    return out;
}

std::string clip(const std::string& s, std::size_t maxLen) {
    return s.size() <= maxLen ? s : s.substr(0, maxLen) + "...";
}

}  // namespace

std::string redactSensitive(const std::string& s, std::size_t maxLen) {
    const auto tokens = splitAny(s, " \t\r\n");
    std::string out;
    bool pendingWeak = false, pendingStrong = false;
    for (std::string tok : tokens) {
        const std::string lower = toLower(tok);
        const bool isUrl = lower.find("://") != std::string::npos || startsWith(lower, "www.");
        if (!isUrl) {
            const auto sep = tok.find_first_of(":=");
            if (sep != std::string::npos && sep + 1 < tok.size() && isSecretWord(tok.substr(0, sep))) {
                tok = tok.substr(0, sep + 1) + "[hidden]";
                pendingWeak = pendingStrong = false;
            } else if ((pendingWeak || pendingStrong) &&
                       (lower == "is" || lower == "are" || lower == ":" || lower == "=")) {
                pendingStrong = true;  // connector seen: next token is the secret
            } else if (pendingStrong) {
                tok = "[hidden]";
                pendingWeak = pendingStrong = false;
            } else if (pendingWeak) {
                bool hasDigit = false;
                for (char c : tok) hasDigit = hasDigit || isDigitChar(c);
                if (hasDigit) tok = "[hidden]";
                pendingWeak = false;
            } else {
                tok = maskDigitRuns(tok);
            }
            if (tok != "[hidden]" && isSecretWord(lower)) {
                const bool colon = !lower.empty() && (lower.back() == ':' || lower.back() == '=');
                pendingStrong = colon;
                pendingWeak = !colon;
            }
        }
        if (!out.empty()) out += ' ';
        out += tok;
    }
    return clip(out, maxLen);
}

std::string redactUrl(const std::string& url, std::size_t maxLen) {
    std::string s = trim(url);
    const auto scheme = s.find("://");
    const std::size_t authStart = (scheme == std::string::npos) ? 0 : scheme + 3;
    const auto authEnd = s.find_first_of("/?#", authStart);
    const auto at = s.rfind('@', authEnd == std::string::npos ? s.size() : authEnd);
    if (at != std::string::npos && at >= authStart) s = s.substr(0, authStart) + "[hidden]" + s.substr(at);
    const auto q = s.find_first_of("?#");
    if (q != std::string::npos) s = s.substr(0, q) + "?[query hidden]";
    return clip(s, maxLen);
}

std::string currentTimestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

std::vector<DataLine> readDataLines(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open data file: " + path);
    std::vector<DataLine> lines;
    std::string line;
    int n = 0;
    while (std::getline(in, line)) {
        ++n;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        lines.push_back({n, line});
    }
    return lines;
}

}  // namespace phishguard::text
