/*
 * Ptypes.cpp
 *
 *  Created on: Sep 11, 2018
 *      Author: echo
 */

 //#include <iostream>
#include "Ptypes.h"
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include "unistd.h"
#include <string.h>


//int MakeFullPath(char *fullpath, const char *path) {
//
//    char current_absolute_path[MAX_SIZE];
//    memset(current_absolute_path, 0, MAX_SIZE);
//    //获取当前程序绝对路径
//    int cnt = readlink("/proc/self/exe", current_absolute_path, MAX_SIZE);
//    if (cnt < 0 || cnt >= MAX_SIZE) {
//        LOGD("***Error***\n");
//        return (-1);
//    }
//    //获取当前目录绝对路径，即去掉程序名
//    int i;
//    for (i = cnt; i >= 0; --i) {
//        if (current_absolute_path[i] == '/') {
//            current_absolute_path[i + 1] = '\0';
//            break;
//        }
//    }
//
//    //创建当前路径
//    int len = strlen(current_absolute_path);
//    for (int i = 0; path[i] != '\0'; i++) {
//        current_absolute_path[i + len] = path[i];
//    }
//    len += i;
//
//    memcpy(fullpath, current_absolute_path, len);
//    fullpath[len] = '\0';
//    return len;
//}

std::string BinaryToHexString(const std::string& src) {
    unsigned int npos = 0;
    unsigned int loop = 0;

    if (src.size() == 0) {
        return "";
    }
    std::string dest(src.size() * 2 + 1, 0);
    for (loop = 0; loop < src.size(); loop++)
        npos += sprintf((char*)dest.data() + npos, "%02x", (unsigned char)src[loop]);
    return dest;
}

std::string HexStringToBinary(const std::string& src) {
    unsigned char nibble[2];
    unsigned int destlen = src.size() / 2;
    unsigned int i = 0, j = 0;
    std::string dest(src.size() / 2, 0);

    for (; i < destlen; i++) {
        nibble[0] = src[2 * i];
        nibble[1] = src[2 * i + 1];
        for (j = 0; j < 2; j++) {
            if (nibble[j] >= 'A' && nibble[j] <= 'F')
                nibble[j] = nibble[j] - 'A' + 10;
            else if (nibble[j] >= 'a' && nibble[j] <= 'f')
                nibble[j] = nibble[j] - 'a' + 10;
            else if (nibble[j] >= '0' && nibble[j] <= '9')
                nibble[j] = nibble[j] - '0';
            else
                return 0;
        }
        dest[i] = nibble[0] << 4;    // Set the high nibble
        dest[i] |= nibble[1];        // Set the low nibble
    }
    return dest;
}

// 本地和网络字节(BigEndian)顺序转换
unsigned short HostToNetworkUINT16(unsigned short n) {
    int k = 1;
    if (*((char*)&k)) {
        /*char la = 0;
        char Hb = 0;
        unsigned short a = 0;

        la = (n >> 8) & 0xff;
        Hb = n & 0xff;
        a = Hb << 8 | la;
        return a;*/
        unsigned short b = ((n & 0xFF) << 8) | ((n & 0xFF00) >> 8);
        return b;
    }
    return n;
}



void int2char(std::string& input, int startPos, int endPos) {
    //std::replace(input.begin() + startPos, input.begin() + endPos,'0','O');
    //std::replace(input.begin() + startPos, input.begin() + endPos,'1','I');
    //std::replace(input.begin() + startPos, input.begin() + endPos,'2','Z');
}

void char2int(std::string& input, int startPos, int endPos) {
    //std::replace(input.begin() + startPos, input.begin() + endPos,'O','0');
    //std::replace(input.begin() + startPos, input.begin() + endPos,'D','0');
    //std::replace(input.begin() + startPos, input.begin() + endPos,'I','1');
    //std::replace(input.begin() + startPos, input.begin() + endPos,'2','Z');
    //std::replace(input.begin() + startPos, input.begin() + endPos,'U','0');
    //std::replace(input.begin() + startPos, input.begin() + endPos,'S','5');
}

