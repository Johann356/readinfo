#include "MRTD.h"
#include "Ptypes.h"
//#include <iostream>
#include <fstream>


// #define LOG_DEBUG
//#include "internalLogging.h"

MRTD::MRTD() {
}

MRTD::~MRTD() {
}

std::vector<int> str2num(std::string s) {
    std::vector<int> num;

    for (int i = 0; i < s.size(); i++) {
        char c = s[i];
        if (c >= 48 && c <= 57) {
            num.push_back(c - 48);
        } else if (c >= 65 && c <= 90) {
            num.push_back(c - 45);
        } else if (60 == c) {
            num.push_back(0);
        } else {
            return std::vector<int>(0);
        }
    }
    return num;
}

static bool PassportCheck(std::string number, char checkBit) {
    int sum = 0;
    int check = (checkBit - 48) & 0x0f;
    int BaseWeight[] = {7, 3, 1};

    std::vector<int> intNumber = str2num(number);
    for (int i = 0, k = 0; i < intNumber.size(); i++) {
        sum += intNumber[i] * BaseWeight[k];
        k = (k + 1) % 3;
    }
    return ((sum % 10) == check);
}

static bool mrtCpy(char *dest, const char *src, int startPos, int len) {

    if (strlen(src) < startPos + len) {
        //std::cout << "mrtCpy len error" << std::endl;
        return false;
    }

    for (int i = 0; i < len; i++) {
        dest[i] = src[startPos + i];
    }
    return true;
}

bool mrtParseName(char *FirstName, char *LastName, const char *src, int startPos, int srcLen) {

    int fIndex = 0;
    int i = startPos;

    if (strlen(src) < srcLen) {
        //std::cout << "mrtParseName len error" << std::endl;
        return false;
    }

    //清除前面的'<'
    while ('<' == src[i] && i < srcLen) i++;

    for (; i < srcLen; i++) {
        if ('<' != src[i]) {
            LastName[fIndex++] = src[i];
        } else break;
    }
    LastName[fIndex] = '\0';

    //清除中间的‘<’
    while ('<' == src[i] && i < srcLen) i++;

    //读取剩余的名字
    int lIndex = 0;
    for (; i < srcLen; i++) {
        if ('<' != src[i]) {
            FirstName[lIndex++] = src[i];
        }
    }
    FirstName[lIndex] = '\0';
    return true;
}

char Public_ParseThreeCard(std::string &str, struct MrzInfoStruct *mrzInfo) {

    //清除前面的空格
    size_t iter = str.find(" ");
    while (iter != std::string::npos) {
        str = str.erase(iter, 1);
        iter = str.find(" ");
    }
    std::vector<std::string> splitstr;

    //将MRZ分成三行
    size_t location1 = str.find("\n");
    if (location1 < MRZ_THREE_LINE_LEN || location1 == std::string::npos) {
        //LOGD("location1 == %d\n", location1);
        return false;
    }
    splitstr.push_back(std::string(str, 0, MRZ_THREE_LINE_LEN));//机读码有三行，每一行机读码是30个字符

    size_t location2 = str.find("\n", location1);
    if (location2 < MRZ_THREE_LINE_LEN || location2 == std::string::npos) {
        //LOGD("location2 == %d\n", location2 + location1);
        return false;
    }
    splitstr.push_back(std::string(str, location1 + 1, MRZ_THREE_LINE_LEN));
    splitstr.push_back(std::string(str, location1 + 1 + location2 + 1, MRZ_THREE_LINE_LEN));

    if (splitstr[2].length() < MRZ_THREE_LINE_LEN) {
        //LOGD("location3 == %d\n", splitstr[2].length());
        return false;
    }
    //std::cout << "splitstr[0]: " << splitstr[0] << std::endl;
    //std::cout << "splitstr[1]: " << splitstr[1] << std::endl;
    //std::cout << "splitstr[2]: " << splitstr[2] << std::endl;

    //保存识别的MRZ到code中
    str = splitstr[0] + std::string("\r\n") + splitstr[1] + std::string("\r\n") + splitstr[2];
    for (int i = 0; i < str.size(); i++) {
        mrzInfo->code[i] = str[i];
    }
    mrzInfo->code[str.size()] = '\0';

    //获取护照的类型
    mrzInfo->Type = splitstr[0][0];
    std::string Ptype(splitstr[0], CR_MRZ_THREE_PASSPORT_TYPE_POS,
                      CR_MRZ_THREE_PASSPORT_TYPE_POS + MRZ_PASSPORT_TYPE_LEN);

    //LOGD ("Ptype: %s", Ptype.c_str());
    if (0 == Ptype.compare("CR") || 0 == Ptype.compare("CT")) {
        //对护照号码，出生日期，过期日期等强制转换成数字
        char2int(splitstr[0], CR_MRZ_THREE_PASS_NO_POS,
                 CR_MRZ_THREE_PASS_NO_POS + MRZ_PASS_NO_LEN + 1);
        char2int(splitstr[0], CR_MRZ_THREE_EXPIRE_DATE_POS,
                 CR_MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN + 1);
        char2int(splitstr[0], CR_MRZ_THREE_BIRTH_DATE_POS,
                 CR_MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN + 1);

        //港澳、台往来大陆
        mrtCpy(mrzInfo->PassportNo, splitstr[0].data(), CR_MRZ_THREE_PASS_NO_POS, MRZ_PASS_NO_LEN);
        mrtCpy(mrzInfo->DateOfBirth, splitstr[0].data(), CR_MRZ_THREE_BIRTH_DATE_POS,
               MRZ_BIRTH_DATE_LEN);
        mrtCpy(mrzInfo->ExpiryDate, splitstr[0].data(), CR_MRZ_THREE_EXPIRE_DATE_POS,
               MRZ_EXPIRE_DATE_LEN);
        mrzInfo->Gender = splitstr[0][CR_MRZ_THREE_SEX_POS];
        mrtCpy(mrzInfo->Issuer, "CHN", 0, 3);
        mrtCpy(mrzInfo->Country, "CHN", 0, 3);

        //MRZ Info
        //护照号码 + 校验位
        mrtCpy(mrzInfo->codetonfc, splitstr[0].data(), CR_MRZ_THREE_PASS_NO_POS, MRZ_PASS_NO_LEN);
        mrzInfo->codetonfc[MRZ_PASS_NO_LEN] = splitstr[0][CR_MRZ_THREE_PASS_NO_CHECK_POS];

        //出生日期 + 校验位
        mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1, splitstr[0].data(),
               CR_MRZ_THREE_BIRTH_DATE_POS, MRZ_BIRTH_DATE_LEN);
        mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN] = splitstr[0][
            CR_MRZ_THREE_BIRTH_DATE_CHECK_POS];
        //到期日期 + 校验位
        mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1,
               splitstr[0].data(), CR_MRZ_THREE_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
        mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1 +
            MRZ_EXPIRE_DATE_LEN] = splitstr[0][CR_MRZ_THREE_EXPIRE_DATE_CHECK_POS];

        //optinonal
        if (!Ptype.compare("CT")) {
            mrtCpy(mrzInfo->Opential_1, splitstr[1].data(), CR_MRZ_THREE_IDNUMBER_POS,
                   CR_MRZ_IDNUMBER_LEN);
        } else {
            mrtCpy(mrzInfo->Opential_1, splitstr[1].data(), CR_MRZ_THREE_IDNUMBER_POS,
                   CT_MRZ_IDNUMBER_LEN);
        }
        //姓名
        mrtParseName(mrzInfo->FirstName, mrzInfo->LastName, splitstr[2].data(),
                     CR_MRZ_THREE_NAME_POS, MRZ_THREE_LINE_LEN);
    } else if (0 == Ptype.compare("C<")) {
        //老版本港澳往来大陆
        //对护照号码，出生日期，过期日期等强制转换成数字
        char2int(splitstr[1], C__MRZ_THREE_PASS_NO_POS,
                 C__MRZ_THREE_PASS_NO_POS + C__MRZ_PASS_NO_LEN + 1);
        char2int(splitstr[1], C__MRZ_THREE_EXPIRE_DATE_POS,
                 C__MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN + 1);
        char2int(splitstr[1], C__MRZ_THREE_BIRTH_DATE_POS,
                 C__MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN + 1);

        //获取护照号码，出生日期，过期日期
        mrtCpy(mrzInfo->PassportNo, splitstr[1].data(), C__MRZ_THREE_PASS_NO_POS,
               C__MRZ_PASS_NO_LEN);
        mrtCpy(mrzInfo->DateOfBirth, splitstr[1].data(), C__MRZ_THREE_BIRTH_DATE_POS,
               MRZ_BIRTH_DATE_LEN);
        mrtCpy(mrzInfo->ExpiryDate, splitstr[1].data(), C__MRZ_THREE_EXPIRE_DATE_POS,
               MRZ_EXPIRE_DATE_LEN);
        //性别
        mrzInfo->Gender = splitstr[1][C__MRZ_THREE_SEX_POS];
        mrtCpy(mrzInfo->Issuer, "CHN", 0, 3);
        mrtCpy(mrzInfo->Country, "CHN", 0, 3);

        //MRZ Info
        //护照号码 + 校验位
        mrtCpy(mrzInfo->codetonfc, splitstr[1].data(), C__MRZ_THREE_PASS_NO_POS,
               C__MRZ_PASS_NO_LEN);
        mrzInfo->codetonfc[C__MRZ_PASS_NO_LEN] = splitstr[1][C__MRZ_THREE_PASS_NO_CHECK_POS];
        //出生日期 + 校验位
        mrtCpy(mrzInfo->codetonfc + C__MRZ_PASS_NO_LEN + 1, splitstr[1].data(),
               C__MRZ_THREE_BIRTH_DATE_POS, MRZ_BIRTH_DATE_LEN);
        mrzInfo->codetonfc[C__MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN] = splitstr[1][
            C__MRZ_THREE_BIRTH_DATE_CHECK_POS];
        //到期日期 + 校验位
        mrtCpy(mrzInfo->codetonfc + C__MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1,
               splitstr[1].data(), C__MRZ_THREE_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
        mrzInfo->codetonfc[C__MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1 +
            MRZ_EXPIRE_DATE_LEN] = splitstr[1][C__MRZ_THREE_EXPIRE_DATE_CHECK_POS];

        //姓名
        mrtParseName(mrzInfo->FirstName, mrzInfo->LastName, splitstr[2].data(),
                     C__MRZ_THREE_NAME_POS, MRZ_THREE_LINE_LEN);
    } else if ('P' == Ptype[0]) {

        char2int(splitstr[1], MRZ_THREE_PASS_NO_POS, MRZ_THREE_PASS_NO_POS + MRZ_PASS_NO_LEN + 1);
        char2int(splitstr[1], MRZ_THREE_BIRTH_DATE_POS,
                 MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN + 1);
        char2int(splitstr[1], MRZ_THREE_EXPIRE_DATE_POS,
                 MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN + 1);

        //获取护照号码，出生日期，过期日期
        mrtCpy(mrzInfo->PassportNo, splitstr[0].data(), MRZ_THREE_PASS_NO_POS, MRZ_PASS_NO_LEN);
        mrtCpy(mrzInfo->DateOfBirth, splitstr[1].data(), MRZ_THREE_BIRTH_DATE_POS,
               MRZ_BIRTH_DATE_LEN);
        mrtCpy(mrzInfo->ExpiryDate, splitstr[1].data(), MRZ_THREE_EXPIRE_DATE_POS,
               MRZ_EXPIRE_DATE_LEN);
        //性别
        mrzInfo->Gender = splitstr[1][MRZ_THREE_SEX_POS];
        mrtCpy(mrzInfo->Issuer, splitstr[1].data(), MRZ_THREE_ISSUER_POS, MRZ_ISSURE_LEN);
        mrtCpy(mrzInfo->Country, splitstr[1].data(), MRZ_THREE_NATION_POS, MRZ_ISSURE_LEN);

        //MRZ Info
        //护照号码 + 校验位
        mrtCpy(mrzInfo->codetonfc, splitstr[1].data(), MRZ_THREE_PASS_NO_POS, MRZ_PASS_NO_LEN);
        if (PassportCheck(mrzInfo->codetonfc, splitstr[1][MRZ_THREE_PASS_NO_CHECK_POS])) {
            mrzInfo->codetonfc[MRZ_PASS_NO_LEN] = splitstr[1][MRZ_THREE_PASS_NO_CHECK_POS];
        } else {
            //MRZ_PASS_NO_EXT_LEN
            mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN, splitstr[1].data(),
                   MRZ_THREE_PASS_NO_EXT_POS, MRZ_PASS_NO_EXT_LEN - MRZ_PASS_NO_LEN);
            if (!PassportCheck(mrzInfo->codetonfc, splitstr[1][MRZ_THREE_PASS_NO_EXT_CHECK_POS])) {
                return false;
            }
            mrzInfo->codetonfc[MRZ_PASS_NO_EXT_LEN] = splitstr[1][MRZ_THREE_PASS_NO_EXT_CHECK_POS];
        }

        //出生日期 + 校验位
        mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1, splitstr[1].data(),
               MRZ_THREE_BIRTH_DATE_POS, MRZ_BIRTH_DATE_LEN);
        mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN] = splitstr[1][
            MRZ_THREE_BIRTH_DATE_CHECK_POS];
        //到期日期 + 校验位
        mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1,
               splitstr[1].data(), MRZ_THREE_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
        mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1 +
            MRZ_EXPIRE_DATE_LEN] = splitstr[1][MRZ_THREE_EXPIRE_DATE_CHECK_POS];

        //姓名
        mrtParseName(mrzInfo->FirstName, mrzInfo->LastName, splitstr[2].data(), MRZ_THREE_NAME_POS,
                     MRZ_THREE_LINE_LEN);
    }
    //LOGD ("codetonfc: %s", mrzInfo->codetonfc);
    return true;
}

char Public_ParseOneCard(std::string &str, struct MrzInfoStruct *mrzInfo) {
    //清除前面的空格
    size_t iter = str.find(" ");
    while (iter != std::string::npos) {
        str = str.erase(iter, 1);
        iter = str.find(" ");
    }

    //判断长度
    if (str.size() < MRZ_ONE_LINE_LEN) return false;
    std::string splitstr(str);

    //对护照号码，出生日期，过期日期等强制转换成数字
    char2int(splitstr, MRZ_ONE_PASS_NO_POS, MRZ_ONE_PASS_NO_POS + MRZ_PASS_NO_LEN + 1);
    char2int(splitstr, MRZ_ONE_EXPIRE_DATE_POS, MRZ_ONE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN + 1);
    char2int(splitstr, MRZ_ONE_BIRTH_DATE_POS, MRZ_ONE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN + 1);

    //保存识别的MRZ到code中
    for (int i = 0; i < str.size(); i++) {
        mrzInfo->code[i] = str[i];
    }
    mrzInfo->code[str.size()] = '\0';

    //获取护照的类型
    std::string Ptype(splitstr, MRZ_ONE_PASSPORT_TYPE_POS, MRZ_PASSPORT_TYPE_LEN);
    mrzInfo->Type = splitstr[MRZ_ONE_PASSPORT_TYPE_POS];
    //护照号码
    mrtCpy(mrzInfo->PassportNo, splitstr.data(), MRZ_ONE_PASS_NO_POS, MRZ_PASS_NO_LEN);
    //出生日期
    mrtCpy(mrzInfo->DateOfBirth, splitstr.data(), MRZ_ONE_BIRTH_DATE_POS, MRZ_BIRTH_DATE_LEN);
    //到期日期
    mrtCpy(mrzInfo->ExpiryDate, splitstr.data(), MRZ_ONE_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
    //性别
    //	Gender = splitstr[C__MRZ_THREE_SEX_POS];
    //发行者
    mrtCpy(mrzInfo->Issuer, "CHN", 0, 3);
    //国籍
    mrtCpy(mrzInfo->Country, "CHN", 0, 3);

    //MRZ Info
    //护照号码 + 校验位
    mrtCpy(mrzInfo->codetonfc, splitstr.data(), MRZ_ONE_PASS_NO_POS, MRZ_PASS_NO_LEN);
    mrzInfo->codetonfc[MRZ_PASS_NO_LEN] = splitstr[MRZ_ONE_PASS_NO_CHECK_POS];
    //出生日期 + 校验位
    mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1, splitstr.data(), MRZ_ONE_BIRTH_DATE_POS,
           MRZ_BIRTH_DATE_LEN);
    mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 +
        MRZ_BIRTH_DATE_LEN] = splitstr[MRZ_ONE_BIRTH_DATE_CHECK_POS];
    //到期日期 + 校验位
    mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1, splitstr.data(),
           MRZ_ONE_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
    mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1 +
        MRZ_EXPIRE_DATE_LEN] = splitstr[MRZ_ONE_EXPIRE_DATE_CHECK_POS];
    return true;
}

char Public_ParseOneCardChip(std::string &str, struct MrzInfoStruct *mrzInfo) {
    //清除前面的空格
    size_t iter = str.find(" ");
    while (iter != std::string::npos) {
        str = str.erase(iter, 1);
        iter = str.find(" ");
    }

    //判断长度
    if (str.size() < MRZ_ONE_LINE_LEN) return false;
    std::string splitstr(str);

    //对护照号码，出生日期，过期日期等强制转换成数字
    char2int(splitstr, MRZ_ONE_PASS_NO_POS, MRZ_ONE_PASS_NO_POS + MRZ_PASS_NO_LEN + 1);
    char2int(splitstr, MRZ_ONE_EXPIRE_DATE_POS, MRZ_ONE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN + 1);
    char2int(splitstr, MRZ_ONE_BIRTH_DATE_POS, MRZ_ONE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN + 1);

    //保存识别的MRZ到code中
    for (int i = 0; i < str.size(); i++) {
        mrzInfo->code[i] = str[i];
    }
    mrzInfo->code[str.size()] = '\0';

    //获取护照的类型
    std::string Ptype(splitstr, MRZ_ONE_PASSPORT_TYPE_POS, MRZ_PASSPORT_TYPE_LEN);
    mrzInfo->Type = splitstr[MRZ_ONE_PASSPORT_TYPE_POS];
    //护照号码
    mrtCpy(mrzInfo->PassportNo, splitstr.data(), MRZ_ONE_PASS_NO_POS, MRZ_PASS_NO_LEN);
    //出生日期
    mrtCpy(mrzInfo->DateOfBirth, splitstr.data(), MRZ_ONE_BIRTH_DATE_POS, MRZ_BIRTH_DATE_LEN);
    //到期日期
    mrtCpy(mrzInfo->ExpiryDate, splitstr.data(), MRZ_ONE_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
    //性别
    mrzInfo->Gender = splitstr[OUT_MRZ_ONE_SEX_POS];
    //发行者
    mrtCpy(mrzInfo->Issuer, "CHN", 0, 3);
    //国籍
    mrtCpy(mrzInfo->Country, "CHN", 0, 3);

    //MRZ Info
    //护照号码 + 校验位
    mrtCpy(mrzInfo->codetonfc, splitstr.data(), MRZ_ONE_PASS_NO_POS, MRZ_PASS_NO_LEN);
    mrzInfo->codetonfc[MRZ_PASS_NO_LEN] = splitstr[MRZ_ONE_PASS_NO_CHECK_POS];
    //出生日期 + 校验位
    mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1, splitstr.data(), MRZ_ONE_BIRTH_DATE_POS,
           MRZ_BIRTH_DATE_LEN);
    mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 +
        MRZ_BIRTH_DATE_LEN] = splitstr[MRZ_ONE_BIRTH_DATE_CHECK_POS];
    //到期日期 + 校验位
    mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1, splitstr.data(),
           MRZ_ONE_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
    mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1 +
        MRZ_EXPIRE_DATE_LEN] = splitstr[MRZ_ONE_EXPIRE_DATE_CHECK_POS];

    //姓名
    mrtParseName(mrzInfo->FirstName, mrzInfo->LastName, splitstr.data(), OUT_MRZ_ONE_NAME_POS,
                 OUT_MRZ_ONE_SEX_POS);
    return true;
}

char Public_ParseTwoCard(std::string &str, struct MrzInfoStruct *mrzInfo) {

    //清除前面的空格
    size_t iter = str.find(" ");
    while (iter != std::string::npos) {
        str = str.erase(iter, 1);
        iter = str.find(" ");
    }

    //机读码分行
    std::vector<std::string> splitstr;
    size_t location = str.find("\n");
    if (location < MRZ_TWO_LINE_LEN || location == std::string::npos) {
        return false;
    }
    splitstr.push_back(std::string(str, 0, MRZ_TWO_LINE_LEN));
    splitstr.push_back(std::string(str, location + 1, MRZ_TWO_LINE_LEN));
    if (splitstr[1].length() < MRZ_TWO_LINE_LEN) {
        return false;
    }

    //保存识别的MRZ到code中
    str = splitstr[0] + std::string("\r\n") + splitstr[1] + std::string("\r\n");
    for (int i = 0; i < str.size(); i++) {
        mrzInfo->code[i] = str[i];
    }
    mrzInfo->code[str.size()] = '\0';

    //获取护照的类型
    mrzInfo->Type = splitstr[0][0];
    std::string Ptype(splitstr[0], MRZ_TWO_PASSPORT_TYPE_POS, MRZ_PASSPORT_TYPE_LEN);


    //护照号码
    mrtCpy(mrzInfo->PassportNo, splitstr[1].data(), MRZ_TWO_PASS_NO_POS, MRZ_PASS_NO_LEN);
    //出生日期
    mrtCpy(mrzInfo->DateOfBirth, splitstr[1].data(), MRZ_TWO_BIRTH_DATE_POS, MRZ_BIRTH_DATE_LEN);
    //到期日期
    mrtCpy(mrzInfo->ExpiryDate, splitstr[1].data(), MRZ_TWO_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
    //性别
    mrzInfo->Gender = splitstr[1][MRZ_TWO_SEX_POS];
    //发行者
    mrtCpy(mrzInfo->Issuer, splitstr[0].data(), MRZ_TWO_ISSUER_POS, MRZ_ISSURE_LEN);
    //国籍
    mrtCpy(mrzInfo->Country, splitstr[1].data(), MRZ_TWO_NATION_POS, MRZ_ISSURE_LEN);

    //MRZ Info
    //护照号码 + 校验位
    mrtCpy(mrzInfo->codetonfc, splitstr[1].data(), MRZ_TWO_PASS_NO_POS, MRZ_PASS_NO_LEN);
    if (PassportCheck(mrzInfo->codetonfc, splitstr[1][MRZ_TWO_PASS_NO_CHECK_POS])) {
        mrzInfo->codetonfc[MRZ_PASS_NO_LEN] = splitstr[1][MRZ_TWO_PASS_NO_CHECK_POS];
    } else {
        mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN, splitstr[1].data(), MRZ_TWO_PASS_NO_EXT_POS,
               MRZ_PASS_NO_EXT_LEN - MRZ_PASS_NO_LEN);
        if (!PassportCheck(mrzInfo->codetonfc, splitstr[1][MRZ_TWO_PASS_NO_EXT_CHECK_POS])) {
            return false;
        }
        mrzInfo->codetonfc[MRZ_PASS_NO_EXT_LEN] = splitstr[1][MRZ_TWO_PASS_NO_EXT_CHECK_POS];
    }

    //出生日期 + 校验位
    mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1, splitstr[1].data(), MRZ_TWO_BIRTH_DATE_POS,
           MRZ_BIRTH_DATE_LEN);
    mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN] = splitstr[1][
        MRZ_TWO_BIRTH_DATE_CHECK_POS];
    //到期日期 + 校验位
    mrtCpy(mrzInfo->codetonfc + MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1, splitstr[1].data(),
           MRZ_TWO_EXPIRE_DATE_POS, MRZ_EXPIRE_DATE_LEN);
    mrzInfo->codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1 +
        MRZ_EXPIRE_DATE_LEN] = splitstr[1][MRZ_TWO_EXPIRE_DATE_CHECK_POS];
    //codetonfc[MRZ_PASS_NO_LEN + 1 + MRZ_BIRTH_DATE_LEN + 1 + MRZ_EXPIRE_DATE_LEN + 1] = '\0';

    //姓名
    mrtParseName(mrzInfo->FirstName, mrzInfo->LastName, splitstr[0].c_str(), MRZ_TWO_NAME_POS,
                 MRZ_TWO_LINE_LEN);

    return true;
}

char MRTD::ParseThreeCard(std::string &str) {

    if (Public_ParseThreeCard(str, &mrzInfo)) {
        this->code.assign(mrzInfo.code);
        return true;
    }
    return false;
}

char MRTD::ParseOneCard(std::string &str) {
    if (Public_ParseOneCard(str, &mrzInfo)) {
        this->code.assign(mrzInfo.code);
        return true;
    }
    return false;
}

char MRTD::ParseTwoCard(std::string &str) {
    if (Public_ParseTwoCard(str, &mrzInfo)) {
        this->code.assign(mrzInfo.code);
        return true;
    }
    return false;
}

char MRTD::Parse(std::string &str) {
    int i = 0;
    size_t posArr[4];
    size_t position = 0;

    if (this->CardType == CARD_TYPE_ONE) {
        //LOGD("Parse == 1");
        //std::string strtmp1(str.begin(), str.begin());
        ParseOneCard(str);
        //ParseShowInfo();
    } else if (this->CardType == CARD_TYPE_TWO) {
        //LOGD("Parse == 2");

        ParseTwoCard(str);
        //ParseShowInfo();
    } else if (this->CardType == CARD_TYPE_THREE) {
        //LOGD("Parse == 3");
        //std::string strtmp2(str.begin(), str.begin());

        ParseThreeCard(str);
        //ParseShowInfo();
    }
    return true;
}

CHIPMRTD::CHIPMRTD() {
}

CHIPMRTD::~CHIPMRTD() {
}

char CHIPMRTD::Parse(std::string &code, unsigned char type) {
    char ret;
    switch (type) {
        case CARD_TYPE_ONE:ret = ParseOneCard(code);
            break;
        case CARD_TYPE_TWO:ret = ParseTwoCard(code);
            break;
        case CARD_TYPE_THREE:ret = ParseThreeCard(code);
            break;

    }
//	if(ret)
//		ParseShowInFile(DG1_FILE_NAME);
    return ret;
}

char CHIPMRTD::ParseThreeCard(std::string &str) {
    str.insert(MRZ_THREE_LINE_LEN, 1, '\n');
    str.insert(MRZ_THREE_LINE_LEN * 2 + 1, 1, '\n');
    if (Public_ParseThreeCard(str, &mrzInfo)) {
        this->code.assign(mrzInfo.code);
        return true;
    }
    return false;
}

char CHIPMRTD::ParseOneCard(std::string &str) {
    if (Public_ParseOneCardChip(str, &mrzInfo)) {
        this->code.assign(mrzInfo.code);
        return true;
    }
    return false;
}

char CHIPMRTD::ParseTwoCard(std::string &str) {
    str.insert(MRZ_TWO_LINE_LEN, 1, '\n');
    if (Public_ParseTwoCard(str, &mrzInfo)) {
        this->code.assign(mrzInfo.code);
        return true;
    }
    return false;
}
