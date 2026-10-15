// =============================================================================
// FILE: include/phishguard/common/text_utils.hpp
// WHAT   Small string helpers used everywhere: trim, split, lower-case, startsWith ...
//        plus the PRIVACY helpers (redactSensitive / redactUrl) and the data-file reader.
// HOW    Everything is a free function in namespace phishguard::text. No regular
//        expressions are used on purpose: this is a DSA project, so we write the loops.
// KEY IDEAS
//        * normalizeLookalikes(): folds 0->o, 1->l, 3->e, 4->a, 5->s, 7->t, @->a, $->s so
//          that "paypa1" can be compared with "paypal" (typosquatting defence).
//        * redactSensitive()/redactUrl(): remove passwords, PINs, OTPs, long digit runs
//          and URL query strings BEFORE anything is saved to the history file.
//        * readDataLines(): reads a data file, skipping blank lines and '#' comments, and
//          remembers line numbers so error messages can say "file:12: bad number".
// WHY    One place for text handling avoids copy-pasted loops and makes privacy rules
//        easy to audit.
// =============================================================================
#pragma once
#include <cstddef>
#include <string>
#include <vector>

namespace phishguard::text {

std::string toLower(std::string s);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);                 // keeps empty parts
std::vector<std::string> splitAny(const std::string& s, const std::string& delims);  // skips empty parts
bool startsWith(const std::string& s, const std::string& prefix);
bool endsWith(const std::string& s, const std::string& suffix);
bool isAllDigits(const std::string& s);
bool isAlnumChar(char c);
bool isAlphaChar(char c);
bool isDigitChar(char c);
std::string join(const std::vector<std::string>& parts, std::size_t from, char sep);

// Look-alike character folding used against typosquatting: 0->o 1->l 3->e 4->a 5->s 7->t @->a $->s
std::string normalizeLookalikes(const std::string& s);

// Privacy helpers for scan history: never keep passwords, PINs, OTPs, long digit runs.
std::string redactSensitive(const std::string& s, std::size_t maxLen = 300);
std::string redactUrl(const std::string& url, std::size_t maxLen = 300);

std::string currentTimestamp();  // "YYYY-MM-DD HH:MM:SS" (local time)

struct DataLine {
    int number;
    std::string text;
};
// Reads a data file, trimming lines and skipping blanks and '#' comments.
// Throws std::runtime_error if the file cannot be opened.
std::vector<DataLine> readDataLines(const std::string& path);

}  // namespace phishguard::text
