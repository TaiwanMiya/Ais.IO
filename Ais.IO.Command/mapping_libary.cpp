#include "mapping_libary.h"

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

void mapping_libary::ShowHexEditor(const char* fileName) {
    size_t file_size;
    char* map = mapFile(fileName, file_size);

    int cursorPos = 0;
    while (true) {
        displayHex(map, file_size, cursorPos);
        char key = getKeyPress();
        if (key == 'q') break;
        else if (key == 'h') cursorPos-=3;
        else if (key == 'l') cursorPos+=3;
#undef max
#undef min
        cursorPos = std::max(0, std::min((int)file_size - 1, cursorPos));
    }

    // Unmap file
#ifdef _WIN32
    unmapFile(map);
#else
    unmapFile(map, file_size);
#endif
}

#ifdef _WIN32
wchar_t* mapping_libary::convertToWideChar(const char* str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);

    wchar_t* wideStr = new wchar_t[len];

    MultiByteToWideChar(CP_UTF8, 0, str, -1, wideStr, len);

    return wideStr;
}
#endif

void mapping_libary::clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

char* mapping_libary::mapFile(const char* filename, size_t& file_size) {
#ifdef _WIN32
    // Windows code
    wchar_t* w_filename = convertToWideChar(filename);
    HANDLE hFile = CreateFile(w_filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    file_size = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, file_size, NULL);
    char* map = (char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, file_size);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return map;
#else
    // Linux code
    int fd = open(filename, O_RDONLY);
    file_size = lseek(fd, 0, SEEK_END);
    char* map = (char*)mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    return map;
#endif
}

#ifdef _WIN32
char mapping_libary::getKeyPress() {
    return _getch(); // Windows specific
}
#else
char mapping_libary::getKeyPress() {
    struct termios oldt, newt;
    char ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}
#endif

void mapping_libary::displayHex(char* data, size_t size, int cursorPos) {
    int SCREEN_WIDTH = 16;
    int lineNum = cursorPos / SCREEN_WIDTH;
    int posInLine = cursorPos % SCREEN_WIDTH;
    mapping_libary::clearScreen();
    for (size_t i = 0; i < size; i++) {
        if (i % SCREEN_WIDTH == 0) {
            std::cout << std::endl;
        }
        std::cout << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (0xFF & data[i]) << " ";
    }

    std::cout << std::endl;
    std::cout << "Cursor at line: " << lineNum << ", position in line: " << posInLine << std::endl;
}

#if _WIN32
void mapping_libary::unmapFile(char* map) {
    UnmapViewOfFile(map);
}
#else
void mapping_libary::unmapFile(char* map, size_t file_size) {
    munmap(map, file_size);
}
#endif