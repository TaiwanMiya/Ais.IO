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

    // �����@�ǵ��f�ƾ�
    WindowInfo windows[] = {
        {1, "Window 1"},
        {2, "Window 2"},
        {3, "Window 3"}
    };

    // �M�����f�ýեΦ^�ը��
    for (const auto& win : windows) {
        callback(&win);
    }
}