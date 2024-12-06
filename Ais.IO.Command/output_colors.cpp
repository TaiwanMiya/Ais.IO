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

void ListColorTable() {
    std::cout << "Shows 8 style colors:" << std::endl;

    for (int i = 1; i < 10; ++i) {
        for (int x = 0; x < 8; x++) {
            std::cout << "\033[" << std::to_string(i) << ";3" << std::to_string(x) << "m" << std::to_string(i) << ";3" << std::to_string(x) << "\033[0m\t";
        }
        std::cout << "\033[0m" << std::endl;
    }
    std::cout << "Display a 256-color color table:" << std::endl;
    for (int i = 0; i < 256; ++i) {
        if (i % 8 == 0)
            std::cout << "" << std::endl;
        std::cout << "\033[38;5;" << std::to_string(i) << "m" << std::to_string(i) << "\t";
    }
    std::cout << "\033[0m" << std::endl;
}

std::string Hint(const std::string str) {
    return "\033[1;32m" + str + "\033[0m"; // Green
}

std::string Error(const std::string str) {
    return "\033[1;31m" + str + "\033[0m"; // Red
}

std::string Warn(const std::string str) {
    return "\033[1;33m" + str + "\033[0m"; // Yellow
}

std::string Ask(const std::string str) {
    return "\033[1;34m" + str + "\033[0m"; // Blue
}

std::string Mark(const std::string str) {
    return "\033[1;35m" + str + "\033[0m"; // Purple
}

std::string Any(const std::string str, int colorInt) {
    return "\033[38;5;" + std::to_string(colorInt) + "m" + str + "\033[0m";
}

std::string Any(const std::string str, TERMINAL_STYLE style, int colorInt) {
    return "\033[" + std::to_string(style) + ";" + std::to_string(colorInt) + "m" + str + "\033[0m";
}