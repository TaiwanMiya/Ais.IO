#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#define BINARYIO_API __declspec(dllimport)
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

EXT {

	BINARYIO_API size_t NextLength(void* reader);

}
