// =============================================================================
// FILE: include/phishguard/ui/interface.hpp
// WHAT   The text menu a user sees: scan link/message/e-mail, history, threat list, trusted list,
//        statistics, exit, plus extra tools (batch scan, explore related items, keyword prefix
//        search, demos, benchmarks).
// HOW    Input and output streams are PASSED IN (std::istream / std::ostream), not hard-wired to
//        the keyboard and screen. Tests feed a scripted session and read the output, and a future
//        GUI could reuse the same logic.
// WHY    The UI contains no detection logic: it only asks questions, calls ScanService and prints.
// =============================================================================
#pragma once
#include <iosfwd>
#include <string>

#include "phishguard/ds/graph.hpp"
#include "phishguard/security/detection_data.hpp"
#include "phishguard/security/scan_service.hpp"
#include "phishguard/storage/history_manager.hpp"

namespace phishguard {

// Menu-driven console UI. Streams are injected so the UI can be tested with scripted input.
class Interface {
public:
    Interface(DetectionData& data, std::istream& in, std::ostream& out, std::string historyPath);

    int run();                                           // interactive loop
    void runDemos();                                     // all demo scenarios, non-interactive
    void scanOnce(InputType type, const std::string& input);  // scan, record and print one input

private:
    bool readLine(const std::string& prompt, std::string& line);
    std::string readBlock(const std::string& prompt);
    void banner();
    void menu();
    void printResult(const AnalysisResult& r, int scanId);
    void printRecord(const ScanRecord& r, bool detailed);
    void printRecordTable(const std::vector<ScanRecord>& rows);
    void saveHistory();

    void handleScan(InputType type);
    void handleHistory();
    void handleThreats();
    void handleTrusted();
    void handleStats();
    void handleBatch();
    void handleGraph();
    void handleKeywords();

    DetectionData& data_;
    ScanService service_;
    std::istream& in_;
    std::ostream& out_;
    std::string historyPath_;
    HistoryManager history_;
    Graph graph_;
};

}  // namespace phishguard
