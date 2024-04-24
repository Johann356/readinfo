#ifndef MRTD_H
#define MRTD_H

#include "Ptypes.h"

/*
Machine Readable Travel Documents (MRTD) Parser
校验位计算
步骤 1 从左到右，用相应顺序位置上的加权数乘相关数字数据元素的每一位数。
步骤 2 将每次乘法运算的乘积相加。
步骤 3 将得出的和除以 10（模数）。
步骤 4 余数即为校验数位。
对于数字没有占满所有可用字符位置的数据元素，应使用符号<填充空白位置，并且应确定它为零值，以便计算校验数位。
在对含有字母字符的数据元素进行校验数位计算时，字符 A 至 Z 的赋值应依次为 10 到 35，具体如下：
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35


证件类型：
CT  台湾往来大陆
C<  港澳往来大陆   老版本
CR  港澳往来大陆
CS  往来港澳通行证
CD  往来台湾通行证
P   护照


MRZ_information = 证件号码(携带校验位) + 出生日期(携带校验位) + 到期日期(携带校验位)
*/
#define MRZ_ONE_LINE_LEN        30
#define MRZ_TWO_LINE_LEN        44
#define MRZ_TWO_LINE_LEN2       36
#define MRZ_THREE_LINE_LEN      30

#define MRZ_PASSPORT_TYPE_LEN   2
#define MRZ_ISSURE_LEN          3
#define MRZ_PASS_NO_LEN         9
#define MRZ_PASS_NO_EXT_LEN     13
#define MRZ_EXPIRE_DATE_LEN     6
#define MRZ_BIRTH_DATE_LEN      6
#define MRZ_PARSE_LEN           MRZ_PASS_NO_LEN + MRZ_EXPIRE_DATE_LEN + MRZ_BIRTH_DATE_LEN + 3
#define MRZ_PARSE_EXT_LEN       MRZ_PASS_NO_EXT_LEN + MRZ_EXPIRE_DATE_LEN + MRZ_BIRTH_DATE_LEN + 3

//CS CD类型  卡片式护照
#define MRZ_ONE_PASSPORT_TYPE_POS       0
#define MRZ_ONE_PASS_NO_POS             2   // 索引
#define MRZ_ONE_PASS_NO_CHECK_POS       11
#define MRZ_ONE_EXPIRE_DATE_POS         13
#define MRZ_ONE_EXPIRE_DATE_CHECK_POS   19
#define MRZ_ONE_BIRTH_DATE_POS          21
#define MRZ_ONE_BIRTH_DATE_CHECK_POS    27

#define OUT_MRZ_ONE_NAME_POS                42
#define OUT_MRZ_ONE_SEX_POS                    60


//证件式护照  两行
//HIGH  LINE
#define MRZ_TWO_PASSPORT_TYPE_POS       0
#define MRZ_TWO_ISSUER_POS              2
#define MRZ_TWO_NAME_POS                5

//LOW   LINE
#define MRZ_TWO_PASS_NO_POS             0
#define MRZ_TWO_PASS_NO_CHECK_POS       MRZ_TWO_PASS_NO_POS + MRZ_PASS_NO_LEN
#define MRZ_TWO_NATION_POS              10
#define MRZ_TWO_BIRTH_DATE_POS          13
#define MRZ_TWO_BIRTH_DATE_CHECK_POS    MRZ_TWO_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN
#define MRZ_TWO_SEX_POS                 20
#define MRZ_TWO_EXPIRE_DATE_POS         21
#define MRZ_TWO_EXPIRE_DATE_CHECK_POS   MRZ_TWO_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN

//extern
#define MRZ_TWO_PASS_NO_EXT_POS        28
#define MRZ_TWO_PASS_NO_EXT_CHECK_POS  31

////////////////////////////////////////////////////////////////////////////////////////////////////
//证件式护照   三行
//第一行
#define MRZ_THREE_PASSPORT_TYPE_POS       0
#define MRZ_THREE_ISSUER_POS              2
#define MRZ_THREE_PASS_NO_POS             5
#define MRZ_THREE_PASS_NO_CHECK_POS       MRZ_THREE_PASS_NO_POS + MRZ_PASS_NO_LEN
//extern
#define MRZ_THREE_PASS_NO_EXT_POS        15
#define MRZ_THREE_PASS_NO_EXT_CHECK_POS  18

//第二行
#define MRZ_THREE_BIRTH_DATE_POS          0
#define MRZ_THREE_BIRTH_DATE_CHECK_POS    MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN
#define MRZ_THREE_SEX_POS                 7
#define MRZ_THREE_EXPIRE_DATE_POS         8
#define MRZ_THREE_EXPIRE_DATE_CHECK_POS   MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN
#define MRZ_THREE_NATION_POS              15

//第三行
#define MRZ_THREE_NAME_POS                  0


////////////////////////////////////////////////////////////////////////////////////////////////////


//CT CR 卡片式护照
//High Line
#define CR_MRZ_THREE_PASSPORT_TYPE_POS      0
#define CR_MRZ_THREE_PASS_NO_POS            2
#define CR_MRZ_THREE_PASS_NO_CHECK_POS      CR_MRZ_THREE_PASS_NO_POS + MRZ_PASS_NO_LEN
#define CR_MRZ_THREE_EXPIRE_DATE_POS        15
#define CR_MRZ_THREE_EXPIRE_DATE_CHECK_POS  CR_MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN
#define CR_MRZ_THREE_SEX_POS                22
#define CR_MRZ_THREE_BIRTH_DATE_POS         23
#define CR_MRZ_THREE_BIRTH_DATE_CHECK_POS   CR_MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN

//Middle Line
#define CR_MRZ_IDNUMBER_LEN                 9
#define CR_MRZ_THREE_IDNUMBER_POS           19
#define CR_MRZ_THREE_IDNUMBER_CHECK_POS     CR_MRZ_THREE_IDNUMBER_POS + CR_MRZ_IDNUMBER_LEN

#define CT_MRZ_IDNUMBER_LEN                 10
#define CT_MRZ_THREE_IDNUMBER_CHECK_POS     CR_MRZ_THREE_IDNUMBER_POS + CT_MRZ_IDNUMBER_LEN

//Low Line
#define CR_MRZ_THREE_NAME_POS                0

//C<    老版本港澳居民来往内地
#define C__MRZ_PASS_NO_LEN                   11

//High Line
#define C__MRZ_THREE_PASSPORT_TYPE_POS       0
#define C__MRZ_THREE_NATION_POS              2

//Middle Line
#define C__MRZ_THREE_BIRTH_DATE_POS          0
#define C__MRZ_THREE_BIRTH_DATE_CHECK_POS    C__MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN
#define C__MRZ_THREE_SEX_POS                 7

#define C__MRZ_THREE_EXPIRE_DATE_POS         8
#define C__MRZ_THREE_EXPIRE_DATE_CHECK_POS   C__MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN

#define C__MRZ_THREE_PASS_NO_POS             15  // 索引
#define C__MRZ_THREE_PASS_NO_CHECK_POS       C__MRZ_THREE_PASS_NO_POS  + C__MRZ_PASS_NO_LEN

//Last Line
#define C__MRZ_THREE_NAME_POS                0

struct MrzInfoStruct {
    char PassportNo[13] = {'\0'};//存储护照号码
    char DateOfBirth[7] = {'\0'};//存储护照出生年月日
    char Issuer[4] = {'\0'};//发行者
    char Gender;
    char Opential_1[16] = {'\0'};
    char ExpiryDate[7] = {'\0'};//有效日期
    char Type;
    char Country[4] = {'\0'};//国家

    char codetonfc[28] = {'\0'};
    char LastName[256] = {'\0'};
    char FirstName[256] = {'\0'};
    char MiddleName[256] = {'\0'};
    char code[256] = {'\0'};
};

class MRTD {
public:
    char CardType;
    std::string code;
    struct MrzInfoStruct mrzInfo;

public:
    MRTD();

    ~MRTD();

    char Parse(std::string &code);

    char ParseOneCard(std::string &code);

    char ParseTwoCard(std::string &code);

    char ParseThreeCard(std::string &code);

private:
    char ParseShowInfo();
};

class CHIPMRTD {
public:
    //char CardType;
    std::string code;
    struct MrzInfoStruct mrzInfo;

public:
    CHIPMRTD();

    ~CHIPMRTD();

    char Parse(std::string &code, unsigned char type);

private:
    char ParseTwoCard(std::string &code);

    char ParseOneCard(std::string &code);

    char ParseThreeCard(std::string &code);

    char ParseShowInFile(const char *path);
};

#endif

#if 0
#ifndef MRTD_H
#define MRTD_H

#include "Ptypes.h"

/*
Machine Readable Travel Documents (MRTD) Parser
校验位计算
步骤 1 从左到右，用相应顺序位置上的加权数乘相关数字数据元素的每一位数。
步骤 2 将每次乘法运算的乘积相加。
步骤 3 将得出的和除以 10（模数）。
步骤 4 余数即为校验数位。
对于数字没有占满所有可用字符位置的数据元素，应使用符号<填充空白位置，并且应确定它为零值，以便计算校验数位。
在对含有字母字符的数据元素进行校验数位计算时，字符 A 至 Z 的赋值应依次为 10 到 35，具体如下：
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35


证件类型：
CT  台湾往来大陆
C<  港澳往来大陆   老版本
CR  港澳往来大陆
CS  往来港澳通行证
CD  往来台湾通行证
P   护照


MRZ_information = 证件号码(携带校验位) + 出生日期(携带校验位) + 到期日期(携带校验位)
*/
#define MRZ_ONE_LINE_LEN        30
#define MRZ_TWO_LINE_LEN        44
#define MRZ_TWO_LINE_LEN2       36
#define MRZ_THREE_LINE_LEN      30

#define MRZ_PASSPORT_TYPE_LEN   2
#define MRZ_ISSURE_LEN          3
#define MRZ_PASS_NO_LEN         9
#define MRZ_PASS_NO_EXT_LEN     13
#define MRZ_EXPIRE_DATE_LEN     6
#define MRZ_BIRTH_DATE_LEN      6
#define MRZ_PARSE_LEN           MRZ_PASS_NO_LEN + MRZ_EXPIRE_DATE_LEN + MRZ_BIRTH_DATE_LEN + 3
#define MRZ_PARSE_EXT_LEN       MRZ_PASS_NO_EXT_LEN + MRZ_EXPIRE_DATE_LEN + MRZ_BIRTH_DATE_LEN + 3

//CS CD类型  卡片式护照
#define MRZ_ONE_PASSPORT_TYPE_POS       0
#define MRZ_ONE_PASS_NO_POS             2   // 索引
#define MRZ_ONE_PASS_NO_CHECK_POS       11
#define MRZ_ONE_EXPIRE_DATE_POS         13
#define MRZ_ONE_EXPIRE_DATE_CHECK_POS   19
#define MRZ_ONE_BIRTH_DATE_POS          21
#define MRZ_ONE_BIRTH_DATE_CHECK_POS    27


//证件式护照  两行
//HIGH  LINE
#define MRZ_TWO_PASSPORT_TYPE_POS       0
#define MRZ_TWO_ISSUER_POS              2
#define MRZ_TWO_NAME_POS                5

//LOW   LINE
#define MRZ_TWO_PASS_NO_POS             0
#define MRZ_TWO_PASS_NO_CHECK_POS       MRZ_TWO_PASS_NO_POS + MRZ_PASS_NO_LEN
#define MRZ_TWO_NATION_POS              10
#define MRZ_TWO_BIRTH_DATE_POS          13
#define MRZ_TWO_BIRTH_DATE_CHECK_POS    MRZ_TWO_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN
#define MRZ_TWO_SEX_POS                 20
#define MRZ_TWO_EXPIRE_DATE_POS         21
#define MRZ_TWO_EXPIRE_DATE_CHECK_POS   MRZ_TWO_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN

//extern
#define MRZ_TWO_PASS_NO_EXT_POS        28
#define MRZ_TWO_PASS_NO_EXT_CHECK_POS  31

////////////////////////////////////////////////////////////////////////////////////////////////////
//证件式护照   三行
//第一行
#define MRZ_THREE_PASSPORT_TYPE_POS       0
#define MRZ_THREE_ISSUER_POS              2
#define MRZ_THREE_PASS_NO_POS             5
#define MRZ_THREE_PASS_NO_CHECK_POS       MRZ_THREE_PASS_NO_POS + MRZ_PASS_NO_LEN
//extern
#define MRZ_THREE_PASS_NO_EXT_POS        15
#define MRZ_THREE_PASS_NO_EXT_CHECK_POS  18

//第二行
#define MRZ_THREE_BIRTH_DATE_POS          0
#define MRZ_THREE_BIRTH_DATE_CHECK_POS    MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN
#define MRZ_THREE_SEX_POS                 7
#define MRZ_THREE_EXPIRE_DATE_POS         8
#define MRZ_THREE_EXPIRE_DATE_CHECK_POS   MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN
#define MRZ_THREE_NATION_POS              15

//第三行
#define MRZ_THREE_NAME_POS				  0


////////////////////////////////////////////////////////////////////////////////////////////////////


//CT CR 卡片式护照
//High Line
#define CR_MRZ_THREE_PASSPORT_TYPE_POS      0
#define CR_MRZ_THREE_PASS_NO_POS            2
#define CR_MRZ_THREE_PASS_NO_CHECK_POS      CR_MRZ_THREE_PASS_NO_POS + MRZ_PASS_NO_LEN
#define CR_MRZ_THREE_EXPIRE_DATE_POS        15
#define CR_MRZ_THREE_EXPIRE_DATE_CHECK_POS  CR_MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN
#define CR_MRZ_THREE_SEX_POS                22
#define CR_MRZ_THREE_BIRTH_DATE_POS         23
#define CR_MRZ_THREE_BIRTH_DATE_CHECK_POS   CR_MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN

//Middle Line
#define CR_MRZ_IDNUMBER_LEN                 9
#define CR_MRZ_THREE_IDNUMBER_POS           19
#define CR_MRZ_THREE_IDNUMBER_CHECK_POS     CR_MRZ_THREE_IDNUMBER_POS + CR_MRZ_THREE_IDNUMBER_CHECK_POS

#define CT_MRZ_IDNUMBER_LEN                 10
#define CT_MRZ_THREE_IDNUMBER_CHECK_POS     CR_MRZ_THREE_IDNUMBER_POS + CT_MRZ_IDNUMBER_LEN

//Low Line
#define CR_MRZ_THREE_NAME_POS                0

//C<    老版本港澳居民来往内地
#define C__MRZ_PASS_NO_LEN                   11

//High Line
#define C__MRZ_THREE_PASSPORT_TYPE_POS       0
#define C__MRZ_THREE_NATION_POS              2

//Middle Line
#define C__MRZ_THREE_BIRTH_DATE_POS          0
#define C__MRZ_THREE_BIRTH_DATE_CHECK_POS    C__MRZ_THREE_BIRTH_DATE_POS + MRZ_BIRTH_DATE_LEN
#define C__MRZ_THREE_SEX_POS                 7

#define C__MRZ_THREE_EXPIRE_DATE_POS         8
#define C__MRZ_THREE_EXPIRE_DATE_CHECK_POS   C__MRZ_THREE_EXPIRE_DATE_POS + MRZ_EXPIRE_DATE_LEN

#define C__MRZ_THREE_PASS_NO_POS             15  // 索引
#define C__MRZ_THREE_PASS_NO_CHECK_POS       C__MRZ_THREE_PASS_NO_POS  + C__MRZ_PASS_NO_LEN

//Last Line
#define C__MRZ_THREE_NAME_POS                0



class MRTD
{
public:
    /*****解析护照序列码
    1、第1个字符代表类型Type
    2、第3到第5个字符代表国家码Country Code
    3、第6个字符到第一个'<'字符之间是Last Name
    4、第2个'<'字符到第3个'<'字符之间是First Name
    5、从'\n'字符起，往后数9个字符代表护照号码Passport No.
    6、之后3个字符代表国籍
    7、之后的6个字符代表出生年月

    *****/

    char PassportNo[13] = { '\0' };//存储护照号码
    char DateOfBirth[7] = { '\0' };//存储护照出生年月日
    char Issuer[4] = { '\0' };//发行者
    char Gender;
    char Opential_1[16] = { '\0' };
    char ExpiryDate[7] = { '\0' };//有效日期
    char Type;
    char Country[4] = { '\0' };//国家

    char codetonfc[28] = { '\0' };
    char LastName[256] = { '\0' };
    char FirstName[256] = { '\0' };
    char MiddleName[256] = { '\0' };
    std::string code;

    char CardType;

public:
    MRTD() {}
    ~MRTD(){}

    char Parse(std::string& code);

private:
    char ParseShowInfo();
    char ParseOneCard(std::string &code);
    char ParseTwoCard(std::string &code);
    char ParseThreeCard(std::string &code);
};

#endif
#endif
