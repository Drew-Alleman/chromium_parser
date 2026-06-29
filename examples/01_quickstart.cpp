// 01_quickstart.cpp   [simple]
//
// The smallest possible program: point it at a Chrome "User Data" directory and it
// prints the full human-readable report. No options, no loops -- this is the
// "hello world" of the library.

#include <chromium_parser/profile.h>

#include <iostream>

int main(int argc, char** argv) {
    using namespace chromiumprofile;

    if (argc < 2) {
        std::cerr << "usage: 01_quickstart <path to \"User Data\" dir>\n";
        return 2;
    }

    Installation inst = CaptureInstallation(argv[1]);  // default options
    DumpText(inst, std::cout);
    return 0;
}