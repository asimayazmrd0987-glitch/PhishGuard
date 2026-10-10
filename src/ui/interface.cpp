// =============================================================================
// FILE: src/ui/interface.cpp
// WHAT   Implementation of the menus and of the result screen.
// HOW    printResult() always shows: score, level, a one-line meaning, every reason with its points,
//        the look-alike box (if any), the recommendation, related items found by BFS on the graph,
//        and a closing disclaimer. Wording rules: never "safe" or "malicious", only "indicators".
//        handleBatch() pushes results into a max-heap so the riskiest line is printed first.
//        Every prompt tolerates end-of-input, so piped input cannot cause an endless loop.
// =============================================================================

#include "phishguard/ui/interface.hpp"

#include <fstream>
#include <iomanip>
#include <istream>
#include <ostream>
#include <stdexcept>

#include "phishguard/algorithms/levenshtein.hpp"
#include "phishguard/algorithms/sorting.hpp"
#include "phishguard/benchmark/benchmark.hpp"
#include "phishguard/common/text_utils.hpp"
#include "phishguard/ds/heap.hpp"
#include "phishguard/security/graph_builder.hpp"
#include "phishguard/ui/demo_scenarios.hpp"

namespace phishguard {

namespace {

constexpr int kWidth = 52;
std::string rule(char c = '-') { return std::string(kWidth, c); }
std::string center(const std::string& s) {
    const int pad = (kWidth - static_cast<int>(s.size())) / 2;
    return std::string(static_cast<std::size_t>(pad > 0 ? pad : 0), ' ') + s;
}
std::string clip(const std::string& s, std::size_t n) { return s.size() <= n ? s : s.substr(0, n - 3) + "..."; }
int toInt(const std::string& s) {
    try {
        std::size_t used = 0;
        const int v = std::stoi(s, &used);
        return used == s.size() ? v : -1;
    } catch (const std::exception&) {
        return -1;
    }
}

std::string levelMessage(RiskLevel l) {
    switch (l) {
        case RiskLevel::Low:      return "Probably safe based on available indicators, but you should still be careful.";
        case RiskLevel::Medium:   return "Some suspicious characteristics were detected.";
        case RiskLevel::High:     return "Multiple suspicious characteristics were detected.";
        case RiskLevel::Critical: return "Strong indicators of phishing or scam behavior were detected.";
    }
    return "";
}

bool looksLikeUrl(const std::string& line) {
    return line.find(' ') == std::string::npos && (line.find("://") != std::string::npos || line.find('.') != std::string::npos);
}

}  // namespace

Interface::Interface(DetectionData& data, std::istream& in, std::ostream& out, std::string historyPath)
    : data_(data), service_(data), in_(in), out_(out), historyPath_(std::move(historyPath)), history_(HistoryManager::load(historyPath_)) {}

bool Interface::readLine(const std::string& prompt, std::string& line) {
    out_ << prompt << std::flush;
    if (!std::getline(in_, line)) return false;
    line = text::trim(line);
    return true;
}

std::string Interface::readBlock(const std::string& prompt) {
    out_ << prompt << " (type END on its own line when finished)\n";
    std::string all, line;
    while (std::getline(in_, line)) {
        if (text::trim(line) == "END") break;
        all += line + "\n";
    }
    return text::trim(all);
}

void Interface::banner() {
    out_ << rule('=') << "\n" << center("PHISHGUARD") << "\n" << center("CYBERSECURITY FOR EVERYONE") << "\n" << rule('=') << "\n";
}

void Interface::menu() {
    out_ << "\n 1. Scan a link (URL)\n 2. Scan a message (SMS / WhatsApp / social)\n 3. Scan email text\n 4. View scan history\n"
         << " 5. View threat database\n 6. View trusted websites\n 7. View statistics\n 8. Exit\n"
         << " Extra tools: 9. Batch scan a file   10. Explore related indicators\n"
         << "              11. Keyword prefix search   12. Demo scenarios   13. Benchmarks\n";
}

void Interface::saveHistory() {
    try {
        history_.save(historyPath_);
    } catch (const std::exception& e) {
        out_ << "(Could not save history: " << e.what() << ")\n";
    }
}

void Interface::printResult(const AnalysisResult& r, int scanId) {
    out_ << "\nAnalyzing...\n\n";
    for (const char* step : {"Input checked", "Links extracted and split into parts", "Threat list checked", "Keyword analysis completed",
                             "Similarity analysis completed", "Risk engine completed"})
        out_ << "[OK] " << step << "\n";
    out_ << "\n" << rule() << "\n" << center("SECURITY RESULT") << "\n" << rule() << "\n\n";
    out_ << "Risk Score : " << r.score << " / 100\nRisk Level : " << toString(r.level) << "\n" << levelMessage(r.level) << "\n";

    if (r.indicators.empty()) {
        out_ << "\nNo suspicious signs were found by our checks.\n";
    } else {
        out_ << "\nWhy this score:\n";
        for (const auto& ind : r.indicators) out_ << " [+" << ind.weight << "] " << ind.description << "\n";
    }

    if (r.findings.impersonation) {
        const auto& m = r.findings.impersonation;
        int pts = 0;
        for (const auto& ind : r.indicators)
            if (ind.id == "lookalike_domain" || ind.id == "brand_embedded") pts = ind.weight;
        out_ << "\n" << (m->embedded ? "TRUSTED NAME HIDDEN IN ADDRESS" : "POSSIBLE DOMAIN IMPERSONATION") << "\n"
             << "Input:                      " << m->inputPart << "\nPossible legitimate domain: " << m->trustedDomain << "\n"
             << "Edit distance:              " << m->distance << "\nSimilarity:                 " << similarityLabel(m->similarity) << "\n"
             << "Risk contribution:          +" << pts << "\n"
             << "Reason: " << (m->embedded ? "The name of a trusted website is placed inside a different address."
                                           : "The name differs from a trusted website by a very small number of character changes.")
             << "\n(Similarity alone does not prove bad intent.)\n";
    }

    out_ << "\nRecommendation:\n" << r.recommendation << "\n";

    const int root = graph_.indexOf("Scan #" + std::to_string(scanId));
    if (root >= 0) {
        const auto visits = graph_.bfs(root, 3);
        if (visits.size() > 1) {
            out_ << "\nRelated items found (graph search):\n";
            std::size_t shown = 0;
            for (std::size_t i = 1; i < visits.size() && shown < 10; ++i, ++shown)
                out_ << std::string(static_cast<std::size_t>(visits[i].depth) * 2, ' ') << " - " << toString(graph_.node(visits[i].node).type) << ": "
                     << clip(graph_.node(visits[i].node).label, 60) << "\n";
        }
    }
    out_ << "\n" << rule() << "\nPhishGuard is an educational tool. A LOW result is not a guarantee of safety,\nand a high result is not proof of a scam.\n";
}

void Interface::scanOnce(InputType type, const std::string& input) {
    AnalysisResult r;
    try {
        r = (type == InputType::Url) ? service_.scanUrl(input) : service_.scanMessage(input, type);
    } catch (const std::invalid_argument& e) {
        out_ << "Sorry: " << e.what() << "\n";
        return;
    }
    const int id = history_.add(r);
    addScanToGraph(graph_, id, r);
    printResult(r, id);
    saveHistory();
}

void Interface::handleScan(InputType type) {
    std::string input;
    if (type == InputType::Email) {
        input = readBlock("Paste the email text");
    } else if (!readLine(type == InputType::Url ? "Enter link: " : "Enter message: ", input)) {
        return;
    }
    if (input.empty()) {
        out_ << "Nothing was entered.\n";
        return;
    }
    scanOnce(type, input);
}

void Interface::printRecordTable(const std::vector<ScanRecord>& rows) {
    if (rows.empty()) {
        out_ << "(no records)\n";
        return;
    }
    out_ << std::left << std::setw(5) << "ID" << std::setw(21) << "Time" << std::setw(9) << "Type" << std::setw(7) << "Score" << std::setw(10) << "Level" << "Input\n";
    for (const auto& r : rows)
        out_ << std::left << std::setw(5) << r.id << std::setw(21) << r.timestamp << std::setw(9) << toString(r.type) << std::setw(7) << r.score
             << std::setw(10) << toString(r.level) << clip(r.input, 40) << "\n";
}

void Interface::printRecord(const ScanRecord& r, bool) {
    out_ << "Scan #" << r.id << "  " << r.timestamp << "  " << toString(r.type) << "\nScore: " << r.score << " (" << toString(r.level) << ")\nInput (sensitive parts hidden): " << r.input << "\nIndicators:";
    if (r.indicatorIds.empty()) out_ << " none";
    out_ << "\n";
    for (const auto& id : r.indicatorIds) out_ << "  - " << id << "\n";
}

void Interface::handleHistory() {
    for (;;) {
        out_ << "\nHistory: 1) view  2) sort  3) filter  4) inspect  5) remove  6) clear all  0) back\n";
        std::string c;
        if (!readLine("> ", c) || c == "0") return;
        if (c == "1") {
            printRecordTable(history_.sorted(SortKey::Newest));
        } else if (c == "2") {
            std::string k;
            readLine("Sort by 1) newest 2) oldest 3) highest score 4) lowest score 5) risk level: ", k);
            const int n = toInt(k);
            if (n < 1 || n > 5) { out_ << "Please choose 1-5.\n"; continue; }
            printRecordTable(history_.sorted(static_cast<SortKey>(n - 1)));
        } else if (c == "3") {
            std::string lvl, ty, needle;
            readLine("Minimum level (low/medium/high/critical, blank = any): ", lvl);
            readLine("Type (url/message/email, blank = any): ", ty);
            readLine("Text contains (blank = anything): ", needle);
            std::optional<RiskLevel> ml;
            std::optional<InputType> mt;
            RiskLevel l;
            InputType t;
            if (!lvl.empty()) { if (parseRiskLevel(lvl, l)) ml = l; else { out_ << "Unknown level.\n"; continue; } }
            if (!ty.empty()) { if (parseInputType(ty, t)) mt = t; else { out_ << "Unknown type.\n"; continue; } }
            printRecordTable(history_.filter(ml, mt, needle));
        } else if (c == "4" || c == "5") {
            std::string s;
            readLine("Scan ID: ", s);
            const int id = toInt(s);
            const ScanRecord* rec = history_.find(id);
            if (!rec) { out_ << "No scan with that ID.\n"; continue; }
            if (c == "4") printRecord(*rec, true);
            else { history_.remove(id); saveHistory(); out_ << "Removed scan #" << id << ".\n"; }
        } else if (c == "6") {
            std::string yes;
            readLine("Delete ALL history? (yes/no): ", yes);
            if (yes == "yes") { history_.clear(); saveHistory(); out_ << "History cleared.\n"; }
        }
    }
}

void Interface::handleThreats() {
    for (;;) {
        out_ << "\nThreat database (" << data_.threats.size() << " synthetic sample entries)\n";
        for (const auto& e : data_.threats.all()) out_ << " " << std::left << std::setw(28) << e.domain << std::setw(16) << e.category << std::setw(10) << toString(e.risk) << e.note << "\n";
        out_ << "a) add  u) update  d) delete  s) search  c) by category  0) back\n";
        std::string c, dom;
        if (!readLine("> ", c) || c == "0") return;
        try {
            if (c == "a" || c == "u") {
                ThreatEntry e;
                std::string risk;
                readLine("Domain: ", dom);
                readLine("Category: ", e.category);
                readLine("Risk (low/medium/high/critical): ", risk);
                readLine("Note: ", e.note);
                if (!parseRiskLevel(risk, e.risk)) { out_ << "Unknown risk level.\n"; continue; }
                e.domain = dom;
                if (c == "a") out_ << (data_.threats.add(e) ? "Added.\n" : "Existing entry replaced.\n");
                else out_ << (data_.threats.update(dom, e) ? "Updated.\n" : "No such domain.\n");
            } else if (c == "d") {
                readLine("Domain: ", dom);
                out_ << (data_.threats.remove(dom) ? "Deleted.\n" : "No such domain.\n");
            } else if (c == "s") {
                readLine("Domain: ", dom);
                const ThreatEntry* e = data_.threats.findForHost(dom);
                if (e) out_ << "Found: " << e->domain << " (" << e->category << ", " << toString(e->risk) << ")\n";
                else out_ << "Not in the local list. (That does not mean a site is safe.)\n";
            } else if (c == "c") {
                readLine("Category: ", dom);
                for (const auto& e : data_.threats.byCategory(dom)) out_ << " " << e.domain << "  " << toString(e.risk) << "\n";
            } else {
                continue;
            }
            if (c == "a" || c == "u" || c == "d") data_.threats.saveToFile(data_.dataDir + "/sample_threats.txt");
        } catch (const std::exception& e) {
            out_ << "Error: " << e.what() << "\n";
        }
    }
}

void Interface::handleTrusted() {
    for (;;) {
        out_ << "\nTrusted websites (" << data_.trusted.size() << ")\n";
        for (const auto& e : data_.trusted.all()) out_ << " " << std::left << std::setw(22) << e.domain << std::setw(14) << e.brand << e.category << "\n";
        out_ << "a) add  d) delete  0) back\n";
        std::string c, dom, brand, cat;
        if (!readLine("> ", c) || c == "0") return;
        try {
            if (c == "a") {
                readLine("Domain (e.g. mybank.com): ", dom);
                readLine("Brand name (e.g. mybank): ", brand);
                readLine("Category: ", cat);
                out_ << (data_.trusted.add({dom, brand, cat}) ? "Added.\n" : "Existing entry replaced.\n");
            } else if (c == "d") {
                readLine("Domain: ", dom);
                out_ << (data_.trusted.remove(dom) ? "Deleted.\n" : "No such domain.\n");
            } else {
                continue;
            }
            data_.trusted.saveToFile(data_.dataDir + "/trusted_domains.txt");
        } catch (const std::exception& e) {
            out_ << "Error: " << e.what() << "\n";
        }
    }
}

void Interface::handleStats() {
    const HistoryStats s = history_.stats();
    out_ << "\n" << rule() << "\n" << center("STATISTICS") << "\n" << rule() << "\nTotal scans: " << s.total << "\n";
    const char* names[] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
    for (int i = 0; i < 4; ++i) out_ << " " << std::left << std::setw(9) << names[i] << std::setw(5) << s.perLevel[i] << std::string(s.perLevel[i] > 40 ? 40 : s.perLevel[i], '#') << "\n";
    out_ << std::fixed << std::setprecision(1) << "Average risk score: " << s.averageScore << "\n";
    if (!s.topIndicators.empty()) {
        out_ << "Most common indicators:\n";
        for (const auto& p : s.topIndicators) out_ << "  " << p.second << " x " << p.first << "\n";
    }
    const auto top = history_.topRisk(5);
    if (!top.empty()) {
        out_ << "Highest-risk scans (max-heap):\n";
        printRecordTable(top);
    }
    out_ << "\nSystem: " << data_.trusted.size() << " trusted sites, " << data_.threats.size() << " threat samples (hash load " << std::setprecision(2)
         << data_.threats.loadFactor() << "), " << data_.keywords.size() << " keywords in trie (" << data_.keywords.nodeCount() << " nodes), graph "
         << graph_.nodeCount() << " nodes / " << graph_.edgeCount() << " edges\n";
}

void Interface::handleBatch() {
    std::string path;
    if (!readLine("File with one link or message per line: ", path)) return;
    std::ifstream f(path);
    if (!f) { out_ << "Cannot open that file.\n"; return; }
    struct Item { int index; AnalysisResult r; std::string line; };
    std::vector<Item> items;
    std::string line;
    int idx = 0;
    while (std::getline(f, line)) {
        line = text::trim(line);
        if (line.empty() || line[0] == '#') continue;
        try {
            AnalysisResult r = looksLikeUrl(line) ? service_.scanUrl(line) : service_.scanMessage(line);
            const int id = history_.add(r);
            addScanToGraph(graph_, id, r);
            items.push_back({idx++, std::move(r), line});
        } catch (const std::exception&) {
        }
    }
    auto less = [](const Item& a, const Item& b) { return a.r.score != b.r.score ? a.r.score < b.r.score : a.index > b.index; };
    MaxHeap<Item, decltype(less)> heap(less);  // highest risk first
    for (auto& it : items) heap.push(std::move(it));
    out_ << "\nRanked by risk (priority queue):\n";
    int rank = 1;
    while (!heap.empty()) {
        const Item it = heap.pop();
        out_ << std::right << std::setw(3) << rank++ << ". " << std::left << std::setw(9) << toString(it.r.level) << std::right << std::setw(3) << it.r.score << "  " << clip(it.line, 60) << "\n";
    }
    saveHistory();
}

void Interface::handleGraph() {
    std::string label;
    readLine("Enter a website, link, keyword or 'Scan #N': ", label);
    int start = graph_.indexOf(label);
    if (start < 0) start = graph_.indexOf(text::toLower(label));
    if (start < 0) { out_ << "Nothing like that has been scanned in this session yet.\n"; return; }
    out_ << "\nNearest related items (breadth-first search):\n";
    for (const auto& v : graph_.bfs(start)) out_ << std::string(static_cast<std::size_t>(v.depth) * 2, ' ') << "- " << toString(graph_.node(v.node).type) << ": " << clip(graph_.node(v.node).label, 60) << "\n";
    out_ << "\nFull chain (depth-first search):\n";
    for (const auto& v : graph_.dfs(start)) out_ << std::string(static_cast<std::size_t>(v.depth) * 2, ' ') << "- " << clip(graph_.node(v.node).label, 60) << "\n";
}

void Interface::handleKeywords() {
    std::string prefix;
    readLine("Keyword prefix (e.g. verif): ", prefix);
    const auto words = data_.keywords.wordsWithPrefix(prefix);
    if (words.empty()) out_ << "No watched keywords start with that.\n";
    for (const auto& w : words) out_ << " - " << w << " (" << data_.keywords.find(w)->category << ")\n";
}

void Interface::runDemos() {
    banner();
    int matches = 0;
    for (const auto& d : demoScenarios()) {
        const AnalysisResult r = (d.type == InputType::Url) ? service_.scanUrl(d.input) : service_.scanMessage(d.input, d.type);
        const bool ok = static_cast<int>(r.level) >= static_cast<int>(d.minLevel) && static_cast<int>(r.level) <= static_cast<int>(d.maxLevel);
        matches += ok;
        out_ << "\n" << rule() << "\n" << d.title << "\nInput     : " << d.input << "\nAlgorithms: " << d.algorithms << "\nNote      : " << d.note << "\n";
        for (const auto& ind : r.indicators) out_ << "  [+" << ind.weight << "] " << ind.id << "\n";
        out_ << "Risk Score: " << r.score << " / 100   Level: " << toString(r.level) << "   (expected " << toString(d.minLevel)
             << (d.minLevel == d.maxLevel ? "" : std::string("-") + toString(d.maxLevel)) << (ok ? ": OK)" : ": DIFFERENT)") << "\nRecommendation: " << r.recommendation << "\n";
    }
    out_ << "\n" << rule() << "\n" << matches << " of " << demoScenarios().size() << " demo scenarios landed in their expected level range.\n";
}

int Interface::run() {
    banner();
    out_ << "Paste a link or message and PhishGuard will explain what looks suspicious.\n";
    for (;;) {
        menu();
        std::string c;
        if (!readLine("Choose an option: ", c)) break;
        const int n = toInt(c);
        if (n == 8) break;
        switch (n) {
            case 1: handleScan(InputType::Url); break;
            case 2: handleScan(InputType::Message); break;
            case 3: handleScan(InputType::Email); break;
            case 4: handleHistory(); break;
            case 5: handleThreats(); break;
            case 6: handleTrusted(); break;
            case 7: handleStats(); break;
            case 9: handleBatch(); break;
            case 10: handleGraph(); break;
            case 11: handleKeywords(); break;
            case 12: runDemos(); break;
            case 13: runBenchmarks(out_); break;
            default: out_ << "Please type a number from 1 to 13.\n";
        }
    }
    out_ << "Stay safe online. Goodbye!\n";
    return 0;
}

}  // namespace phishguard
