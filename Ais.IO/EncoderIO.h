#pragma once
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define BINARYIO_API __declspec(dllimport)
#else
#define BINARYIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

/* Base16 ���~�X�t�q�G

-1: ��J�ο�X���w���šC
-2: ��X�w�İϤ����C
-3: ��J���פ��X�k�A�ѽX�ɥ����O���ƪ��סC
-4: �D�k�r�ťX�{�b�ѽX�L�{���]���O Base16 ���Ħr�š^�C*/
EXT BINARYIO_API int Base16Encode(const char* input, char* output, int outputSize);
EXT BINARYIO_API int Base16Decode(const char* input, char* output, int outputSize);

/* Base32 ���~�X�t�q�G

-1: ��J�ο�X���w���šC
-2: ��X�w�İϤ����C
-3: ��J�ƾڪ��פ��X�k�ABase32 �ѽX�n�D���׬O 8 �����ơC
-4: �D�k�r�ťX�{�b�ѽX�L�{���]���O Base32 ���Ħr�š^�C*/
EXT BINARYIO_API int Base32Encode(const char* input, char* output, int outputSize);
EXT BINARYIO_API int Base32Decode(const char* input, char* output, int outputSize);

/* Base64 ���~�X�t�q�G

-1: ��J�ο�X���w���šC
-2: ��X�w�İϤ����A�L�k�s�x���G�C
-3: ��J�ƾڪ��פ��X�k�ABase64 �ѽX�n�D���׬O 4 �����ơC
-4: �D�k�r�ťX�{�b�ѽX�L�{���]���O Base64 ���Ħr�š^�C
*/
EXT BINARYIO_API int Base64Encode(const char* input, char* output, int outputSize);
EXT BINARYIO_API int Base64Decode(const char* input, char* output, int outputSize);

/* Base64 ���~�X�t�q�G

-1: ��J�ο�X���w���šC
-2: ��X�w�İϤ����A�L�k�s�x���G�C
-3: ��J�ƾڪ��פ��X�k�ABase85 �ѽX�n�D���׬O 5 �����ơC
-4: �D�k�r�ťX�{�b�ѽX�L�{���]���O Base85 ���Ħr�š^�C
*/
EXT BINARYIO_API int Base85Encode(const char* input, char* output, int outputSize);
EXT BINARYIO_API int Base85Decode(const char* input, char* output, int outputSize);