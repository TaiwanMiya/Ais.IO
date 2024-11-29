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

// �קﵲ�c�����
extern "C" __declspec(dllexport) void ModifyStruct(MyStruct* s);

extern "C" __declspec(dllexport) void EnumWindowsMock(EnumCallback callback);