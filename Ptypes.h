/*
 * Ptypes.h
 *
 *  Created on: Sep 11, 2018
 *      Author: echo
 */

#ifndef PTYPES_H_
#define PTYPES_H_

#include <stdio.h>
#include <stdlib.h>
 //#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <string.h>
#include "glog\logging.h"
//#ifndef char
//#define char    bool
//#define unsigned char    unsigned char
//#define int   int
//#define SHORT   short
//#define unsigned short  unsigned short
//#define false   false
//#define true    true
//#endif

#ifndef MAX_SIZE
#define MAX_SIZE  256
#endif

#define USE_OPENJPEG  1
#define USE_USB_HID 1

#define USE_LOG_LEVEL1 0
#define USE_LOG_LEVEL2 0
#define USE_IDCARD_LOG_LEVEL2    0
#define USE_CHIPCARD_LOG_LEVEL2  0

#ifndef MIN
#define MIN(x, y)    (((x) <= (y))?(x):(y))
#endif

#define CHECK_OK(x)  if(!(x)) return false;
#define KLEN 16

// 内存对齐
#define MEM_ALIGN(n, align) ((n + align - 1) & (~(align - 1)))
// DES算法对齐
#define DES_ALIGN(n, align) ((n + align) & (~(align - 1)))

#define CARD_TYEP_ID       4
#define CARD_TYPE_ONE      1
#define CARD_TYPE_TWO       2
#define CARD_TYPE_THREE    3

#define CONTROL_RW_TIMEOUT_MS 100  //等待时间

#define DG2_FILE_NAME        "USB_TEMP/DG2.bmp"
#define DG1_FILE_NAME    "USB_TEMP/ChipMRZ.txt"

//linux 版本的不支持
#define IDINFO_FILE_NAME    "USB_TEMP/IDCardInfo.txt"
#define IDPIC_FILE_NAME     "USB_TEMP/id.bmp"


extern int MakeFullPath(char* fullpath, const char* path);
extern std::string ws2s(const std::wstring& ws);
extern std::wstring s2ws(const std::string& str);
extern std::string BinaryToHexString(const std::string& src);
extern unsigned short  HostToNetworkUINT16(unsigned short n);
extern void int2char(std::string& input, int startPos, int endPos);
extern void char2int(std::string& input, int startPos, int endPos);
extern std::string ws2s1(const wchar_t* pw);
std::string HexStringToBinary(const std::string & src);
#endif /* PTYPES_H_ */
