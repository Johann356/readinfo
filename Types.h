#pragma once

#include <string>

#ifndef MIN
#define MIN(x,y)    (((x) <= (y))?(x):(y))
#endif

// 内存对齐
#define MEM_ALIGN(n, align) ((n + align - 1) & (~(align - 1)))
// DES算法对齐
#define DES_ALIGN(n, align) ((n + align) & (~(align - 1)))

#ifndef STD_TSTRING
#define STD_TSTRING

namespace std {
#ifdef UNICODE
	typedef basic_string<wchar_t, char_traits<wchar_t>, allocator<wchar_t> > tstring;
#else
	typedef basic_string<char, char_traits<char>, allocator<char> > tstring;
#endif
}

#endif