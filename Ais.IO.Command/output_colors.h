#pragma once
#include <string>
#include <iostream>
#include <fcntl.h>

#if _WIN32
void EnableVirtualTerminalProcessing();
#endif

enum TERMINAL_STYLE {
	STYLE_RESET = 0, // 重置
	STYLE_BOLD = 1, // 粗體
	STYLE_DIM = 2, // 黯淡
	STYLE_BASE = 3, // 斜體
	STYLE_UNDERLINE = 4, // 下劃線
	STYLE_FLASHING = 5, // 閃爍
	STYLE_FAST_FLASHING = 6, // 快速閃爍
	STYLE_REVERSE = 7, // 反顯
	STYLE_HIDE = 8, // 隱藏
	STYLE_BRIGHT = 9, // 劃線
};

extern bool IsRedirects;

bool CheckRedirects();
void MoveCursorUp(int lines);
void MoveCursorDown(int lines);
void ClearLine();
void ShowProgressBar(int progress, int total, int width = 50, char strip = '=', bool show_current = true);
void ListColorTable();
std::string Hide(std::string str);
std::string Error(std::string str);
std::string Warn(std::string str);
std::string Hint(std::string str);
std::string Ask(std::string str);
std::string Mark(std::string str);
std::string Info(std::string str);
std::string Common(std::string str);
std::string Any(std::string str, TERMINAL_STYLE style, int colorInt);
std::string Any(std::string str, int colorInt);