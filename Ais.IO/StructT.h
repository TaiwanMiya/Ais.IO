#pragma once
#include <vector>
#include <string>
#include <functional>

struct MyStruct {
    int id;
    float value;
};

struct WindowInfo {
    int id;
    const char* title;
};

typedef void(__stdcall* EnumCallback)(const WindowInfo*);

// 修改結構的函數
extern "C" __declspec(dllexport) void ModifyStruct(MyStruct* s);

extern "C" __declspec(dllexport) void EnumWindowsMock(EnumCallback callback);