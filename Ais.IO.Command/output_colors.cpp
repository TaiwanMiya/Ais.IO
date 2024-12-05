#include "output_colors.h"

#ifdef _WIN32
#include <windows.h>

void EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) {
        return;
    }

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}
#endif

std::string Hint(const std::string str) {
    return "\033[1;32m" + str + "\033[0m";
}

std::string Error(const std::string str) {
    return "\033[1;31m" + str + "\033[0m";
}

std::string Warn(const std::string str) {
    return "\033[1;33m" + str + "\033[0m";
}

std::string Ask(const std::string str) {
    return "\033[1;34m" + str + "\033[0m";
}