// 03_export.cpp   [moderate]
//
// Machine-readable export with a live diagnostics callback. DumpJson writes the
// whole capture; DumpCsv writes one section. The onDiagnostic callback fires as the
// capture runs, so you see warnings/errors in real time instead of only afterward.

#include <chromium_parser/profile.h>

#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    if (argc < 2) {
        std::cerr << "usage: 03_export <path to \"User Data\" dir>\n";
        return 2;
    }

    CaptureOptions opts;
    // Print non-info diagnostics (warnings/errors) as they happen.
    opts.onDiagnostic = [](const Diagnostic& d) {
        if (d.level != Diagnostic::Level::Info)
            std::cerr << "  [" << d.source << "] " << d.message << "\n";
        };

    Installation inst = CaptureInstallation(argv[1], opts);

    // Full structured dump -> capture.json
    std::ofstream("capture.json") << DumpJson(inst);

    // One section -> history.csv (sections: devices, extensions, history, bookmarks,
    // logins, cookies, downloads, network, autofill, cards, search_engines,
    // top_sites, cache).
    std::ofstream csv("history.csv");
    DumpCsv(inst, "history", csv);

    std::cout << "wrote capture.json + history.csv\n";
    return 0;
}