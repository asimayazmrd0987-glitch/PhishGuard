// =============================================================================
// FILE: src/main.cpp
// WHAT   The program's entry point: reads command-line options, finds and loads data/, then starts
//        the menu or runs one command.
// OPTIONS  (none) menu | --url <link> | --message <text> | --demo | --bench | --data <dir> |
//          --history <file> | --help
// HOW    Data problems (missing folder, bad file) print a clear message and exit with code 2 instead
//        of crashing. Exceptions are caught here so the user never sees a raw crash.
// =============================================================================

#include <iostream>
#include <string>

#include "phishguard/benchmark/benchmark.hpp"
#include "phishguard/security/detection_data.hpp"
#include "phishguard/ui/interface.hpp"

namespace {
void usage() {
    std::cout << "PhishGuard options:\n  (none)            interactive menu\n  --url <link>      scan one link\n  --message <text>  scan one message\n"
                 "  --demo            run all demo scenarios\n  --bench           run benchmarks\n  --data <dir>      data folder (default: auto-detect)\n"
                 "  --history <file>  history file (default: phishguard_history.txt)\n";
}
}  // namespace

int main(int argc, char** argv) {
    using namespace phishguard;
    std::string dataHint, historyPath = "phishguard_history.txt", url, message;
    bool demo = false, bench = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](std::string& dst) { if (i + 1 < argc) dst = argv[++i]; };
        if (a == "--data") next(dataHint);
        else if (a == "--history") next(historyPath);
        else if (a == "--url") next(url);
        else if (a == "--message") next(message);
        else if (a == "--demo") demo = true;
        else if (a == "--bench") bench = true;
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else { std::cerr << "Unknown option: " << a << "\n"; usage(); return 1; }
    }
    if (bench) { runBenchmarks(std::cout); return 0; }

    const std::string dir = DetectionData::findDataDirectory(dataHint);
    if (dir.empty()) {
        std::cerr << "Could not find the data/ folder (looked for risk_config.txt). Run from the project folder or use --data <dir>.\n";
        return 2;
    }
    try {
        DetectionData data = DetectionData::loadFromDirectory(dir);
        Interface ui(data, std::cin, std::cout, historyPath);
        if (demo) { ui.runDemos(); return 0; }
        if (!url.empty()) { ui.scanOnce(InputType::Url, url); return 0; }
        if (!message.empty()) { ui.scanOnce(InputType::Message, message); return 0; }
        return ui.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}
