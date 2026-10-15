// =============================================================================
// FILE: src/analyzers/message_analyzer.cpp
// WHAT   Implementation of message checks.
// HOW    infoFor() maps a phrase category to its weight key and the sentence shown to the user.
//        The message is lower-cased once and every phrase is searched in that copy. hasLongRun()
//        detects repeated characters (letters only for "heyyyy", any character for "!!!").
//        Encoded-looking text = a 24+ character token made only of letters, digits and + / = _ -
//        that contains both letters and digits and is not a link.
// =============================================================================

#include "phishguard/analyzers/message_analyzer.hpp"

#include <stdexcept>

#include "phishguard/algorithms/string_match.hpp"
#include "phishguard/common/text_utils.hpp"
#include "phishguard/ds/custom_set.hpp"

namespace phishguard {

namespace {

struct CategoryInfo {
    const char* weightKey;
    const char* explanation;
};

CategoryInfo infoFor(const std::string& category) {
    if (category == "urgency") return {"weight.urgency", "The message tries to rush you. Scammers create pressure so you act before thinking."};
    if (category == "credential") return {"weight.credential_request", "The message asks you to verify or share account details such as a password, PIN or code."};
    if (category == "financial") return {"weight.financial_request", "The message asks for money, fees or payment details."};
    if (category == "prize") return {"weight.prize", "The message says you won something. Unexpected prizes are a very common scam."};
    if (category == "delivery") return {"weight.delivery", "The message mentions a parcel or delivery problem, a very common scam theme."};
    return {"weight.keyword", "The message contains wording often used in scams."};
}

bool hasLongRun(const std::string& s, std::size_t minRun, bool lettersOnly) {
    std::size_t run = 1;
    for (std::size_t i = 1; i < s.size(); ++i) {
        const bool same = s[i] == s[i - 1] && (!lettersOnly || text::isAlphaChar(s[i]));
        run = same ? run + 1 : 1;
        if (run >= minRun) return true;
    }
    return false;
}

}  // namespace

MessageAnalysis MessageAnalyzer::analyze(const std::string& input) const {
    const std::string msg = text::trim(input);
    if (msg.empty()) throw std::invalid_argument("Nothing was entered.");
    if (msg.size() > kMaxLength) throw std::invalid_argument("The text is too long (limit is 10000 characters).");
    for (unsigned char c : msg)
        if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') throw std::invalid_argument("The text contains unreadable control characters.");

    const RiskConfig& cfg = data_.config;
    MessageAnalysis res;
    auto& out = res.indicators;
    const std::string lowered = text::toLower(msg);

    // 1. Phrase patterns (KMP, one pass over the text per phrase), one indicator per category.
    CustomSet<std::string> seenCategory;
    for (const auto& phrase : data_.phrases) {
        if (kmpSearch(lowered, phrase.text).empty() || !seenCategory.insert(phrase.category)) continue;
        const CategoryInfo ci = infoFor(phrase.category);
        out.push_back({"phrase_" + phrase.category, std::string(ci.explanation) + " (for example: \"" + phrase.text + "\")",
                       cfg.weight(ci.weightKey), IndicatorCategory::Message, phrase.text});
    }

    // 2. Suspicious single words (Trie).
    CustomSet<std::string> seenWord;
    for (auto& m : data_.keywords.scanText(msg)) {
        if (!seenWord.insert(m.word)) continue;
        const int w = m.info.weight > 0 ? m.info.weight : cfg.weight("weight.keyword");
        out.push_back({"keyword:" + m.word, "The text contains the word \"" + m.word + "\", often used in scams.", w,
                       IndicatorCategory::Keyword, m.word});
        res.keywords.push_back(std::move(m));
    }

    // 3. Writing style.
    int punct = 0;
    for (char c : msg) punct += (c == '!' || c == '?');
    if (punct >= 4 || msg.find("!!!") != std::string::npos || msg.find("???") != std::string::npos)
        out.push_back({"excessive_punct", "The message uses a lot of exclamation or question marks to grab attention.",
                       cfg.weight("weight.excessive_punct"), IndicatorCategory::Message, ""});

    int letters = 0, upper = 0;
    for (char c : msg) {
        if (text::isAlphaChar(c)) {
            ++letters;
            upper += (c >= 'A' && c <= 'Z');
        }
    }
    if (letters >= 15 && upper * 10 >= letters * 6)
        out.push_back({"all_caps", "Much of the message is written in capital letters, which is a pressure tactic.",
                       cfg.weight("weight.all_caps"), IndicatorCategory::Message, ""});
    if (hasLongRun(msg, 4, true))
        out.push_back({"repeated_chars", "The message has stretched-out words such as \"heyyyy\", common in spam.",
                       cfg.weight("weight.repeated_chars"), IndicatorCategory::Message, ""});

    for (const auto& tok : text::splitAny(msg, " \t\r\n")) {
        if (tok.size() < 24 || tok.find("://") != std::string::npos || text::startsWith(text::toLower(tok), "www.")) continue;
        bool letter = false, digit = false, allowed = true;
        for (char c : tok) {
            letter = letter || text::isAlphaChar(c);
            digit = digit || text::isDigitChar(c);
            allowed = allowed && (text::isAlnumChar(c) || c == '+' || c == '/' || c == '=' || c == '_' || c == '-');
        }
        if (allowed && letter && digit) {
            out.push_back({"encoded_text", "The message contains a long scrambled-looking string that may hide something.",
                           cfg.weight("weight.encoded_text"), IndicatorCategory::Message, ""});
            break;
        }
    }

    // 4. Links inside the message are analyzed one by one.
    std::size_t count = 0;
    for (const auto& url : UrlParser::extractUrls(msg, data_.knownTlds)) {
        if (count++ >= kMaxUrls) break;
        UrlAnalysis ua = urlAnalyzer_.analyze(url);
        for (const auto& ind : ua.indicators) out.push_back(ind);
        res.urls.push_back(std::move(ua));
    }
    return res;
}

}  // namespace phishguard
