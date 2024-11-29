#include "pch.h"
#include "StructT.h"

void ModifyStruct(MyStruct* s) {
    if (s) {
        s->id += 100;
        s->value *= 2.0f;
    }
}

void EnumWindowsMock(EnumCallback callback) {
    if (!callback) return;

    // 模擬一些窗口數據
    WindowInfo windows[] = {
        {1, "Window 1"},
        {2, "Window 2"},
        {3, "Window 3"}
    };

    // 遍歷窗口並調用回調函數
    for (const auto& win : windows) {
        callback(&win);
    }
}