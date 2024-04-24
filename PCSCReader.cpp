#define _CRT_SECURE_NO_WARNINGS
#define CHECK_OK(x)  if(!(x)) return false;
#include"PCSCReader.h"
#include "Ptypes.h"
#include "EFFile.h"
#include<atlstr.h>
#include<winscard.h>
#include<iostream>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/des.h>
#include<openssl/rsa.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include"wlString.h"
#include"utils.h"
#include"JP2.h"
#include <fstream>
#include <iomanip>

// DES算法对齐
#define DES_ALIGN(n, align) ((n + align) & (~(align - 1)))
#define DG15_LENGTH 165
#define SOD_LENGTH 2504
#define DG2_LENGTH 20591
using namespace std;
//Created by lcx on 2023/1/7

//Global Variables
SCARD_IO_REQUEST		ioRequest;

ULONG					retCode, ProtocolType;
char					cReaderName[256];

char ToLetter(byte bNum) {
	char cTemp;
	if (bNum < 10){
		cTemp = bNum + 0x30;
	}
	else{
		cTemp = bNum + 0x37;
	}
	return cTemp;
}
std::string BYTE2string(byte* bByte, UINT iLength) {
	UINT iIndex;
	std::string outStr;
	for (iIndex = 0; iIndex < iLength; iIndex++)
	{
		outStr += ToLetter(bByte[iIndex] >> 4 & 0x0F);
		outStr += ToLetter(bByte[iIndex] & 0x0F);
	}
	return outStr;
}

static void CheckParity(
	const std::string& srcChar,
	std::string& dstChar,
	int nLen) {
	unsigned char sinChar;
	short minBit = 0;
	short count = 0;

	if (dstChar.size() != srcChar.size())
		dstChar.resize(nLen);//分配内存

	for (int i = 0; i < nLen; i++) {
		count = 0;
		sinChar = srcChar[i];
		minBit = sinChar % 2;
		for (int j = 0; j < 8; j++) {
			if (sinChar % 2 == 1)
				count++;

			sinChar >>= 1;
		}
		if (count % 2 == 1)
			dstChar[i] = srcChar[i];
		else if (minBit == 1)
			dstChar[i] = srcChar[i] - 1;
		else
			dstChar[i] = srcChar[i] + 1;
	}
}

//生成指定长度的随机数,长度需要在调用resize方法之前甚至好
static void BuildRandomData(std::string& data) {
	srand((unsigned)time(NULL));
	for (size_t i = 0; i < data.size(); i++) {
		data[i] = rand() % 255 + 1;
	}
}

static void KencTDES(
	const std::string& strInputData,
	const std::string& Kenc,
	std::string& strOutputData,
	int enc) {
	DES_cblock IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	DES_cblock key1, key2, key3;
	DES_key_schedule schKey1, schKey2, schKey3;
	int byteNum = strInputData.size(), r = 0;
	unsigned char* inputData = (unsigned char*)strInputData.c_str();
	std::string hexKa1, hexKb1;

	hexKa1.append(Kenc.data(), 8);
	hexKb1.append(Kenc.data() + 8, 8);

	memcpy(key1, hexKa1.data(), hexKa1.size());
	memcpy(key2, hexKb1.data(), hexKb1.size());
	memcpy(key3, hexKa1.data(), hexKa1.size());

	if (-2 == (
		DES_set_key_checked(&key1, &schKey1) |
		DES_set_key_checked(&key2, &schKey2) |
		DES_set_key_checked(&key3, &schKey3))) {
		//throw std::exception("weak key");
	}

	strOutputData.resize(byteNum);
	//    LOGI("strOutputData byteNum:%d", byteNum);
	DES_ede3_cbc_encrypt(inputData, (unsigned char*)strOutputData.data(), strOutputData.size(),
		&schKey1, &schKey2, &schKey3, &IV, enc);
}

static void KmacDES(
	const std::string& inputData,
	const std::string& Kmac,
	std::string& encryptData) {
	int iter = inputData.size() / 8;
	std::string enKey, deKey;

	enKey.append(Kmac.data(), 8);
	deKey.append(Kmac.data() + 8, 8);
	std::string inBuffer(8, 0), outBuffer(8, 0);

	DES_cblock IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	DES_key_schedule enSchKey, deSchKey;

	DES_set_key_unchecked((const_DES_cblock*)enKey.data(), &enSchKey);
	DES_set_key_unchecked((const_DES_cblock*)deKey.data(), &deSchKey);

	for (int i = 0; i < iter; i++) {

		inBuffer.assign(inputData.data() + i * 8, 8);

		for (int j = 0; j < 8; j++) {
			inBuffer[j] ^= outBuffer[j];
		}

		DES_cbc_encrypt((unsigned char*)inBuffer.data(), (unsigned char*)outBuffer.data(),
			8, &enSchKey, &IV, DES_ENCRYPT);
	}

	encryptData.resize(8);

	DES_cbc_encrypt((unsigned char*)outBuffer.data(), (unsigned char*)inBuffer.data(), 8,
		&deSchKey, &IV, DES_DECRYPT);
	DES_cbc_encrypt((unsigned char*)inBuffer.data(), (unsigned char*)encryptData.data(), 8,
		&enSchKey, &IV, DES_ENCRYPT);
}

static void DesAddPaddingBytes(std::string& data) {
	size_t dsize = data.size();
	dsize = DES_ALIGN(dsize, 8);
	data.push_back('\x80');
	for (size_t i = data.size(); i < dsize; i++) {
		data.push_back(0x00);
	}
}



static void SHA1ToKencKmac(
	std::string& Kseed,
	std::string& Kenc,
	std::string& Kmac) {
	int byteNumOfKseed = Kseed.size();

	std::string c1("\x00\x00\x00\x01", 4);
	std::string c2("\x00\x00\x00\x02", 4);
	std::string D1, D2, HD1(20, 0), HD2(20, 0);

	D1.append(Kseed.data(), Kseed.size());
	D2.append(Kseed.data(), Kseed.size());
	D1.append(c1.data(), c1.size());
	D2.append(c2.data(), c2.size());

	SHA1((unsigned char*)D1.data(), D1.size(), (unsigned char*)HD1.data());
	SHA1((unsigned char*)D2.data(), D2.size(), (unsigned char*)HD2.data());
	CheckParity(HD1, Kenc, 16);
	CheckParity(HD2, Kmac, 16);
}

static void IncreaseSSC(std::string& ssc, int len) {
	int i = len - 1;
	if (i < 0) {
		return;
	}
	unsigned char b = ssc[i];
	if (b == 0xFF) {
		ssc[i] = 0x00;
		IncreaseSSC(ssc, i);
	}
	else {
		ssc[i] = b + 1;
	}
}

static void IncreaseSSC(std::string& ssc) {
	IncreaseSSC(ssc, ssc.size());
}

//按BER_TLV格式解析Length值,其中tlLen返回Tag-Length字段的字节数,从2到4
static char
ParseFileLengthIn4Bytes(const std::string& data, unsigned short* len, int* tlLen = NULL) {
	if (data.size() < 4) {
		return false;
	}
	unsigned char b = data[1];

	if (b == 0x82) {
		//20230711@leichengxiang,short修改为unsigned short,解决EF.SOD长度溢出问题
		unsigned short* nlen = (unsigned short*)((char*)data.data() + 2);
		*len = HostToNetworkUINT16(*nlen) + 4;
		if (tlLen) *tlLen = 4;
	}
	else if (b == 0x81) {
		*len = (unsigned char)data[2] + 3;
		if (tlLen) *tlLen = 3;
	}
	else if (b <= 0x7F) {
		*len = (unsigned char)data[1] + 2;
		if (tlLen) *tlLen = 2;
	}
	return true;
}

// 从RAPDU中解析DO的TLV数据
static std::string RAPDUParse(std::string& rapdu, unsigned char DO, int* tlLen = NULL) {
	// 按照TLV结构查找
	for (size_t i = 0; i < rapdu.size();) {
		if (i + 4 > rapdu.size() - 1) {
			break;
		}
		std::string head4bytes(rapdu.data() + i, 4);

		unsigned char b = rapdu[i];
		unsigned short nLen;
		ParseFileLengthIn4Bytes(head4bytes, &nLen, tlLen);

		if (b == DO) {
			return rapdu.substr(i, nLen);
		}
		else {
			i += nLen;
		}
	}
	//std::stringstream ss;
	//ss << "not found DO" << std::hex << std::setw(2) << std::setfill('0') << (short) DO;
	//throw std::exception(ss.str().c_str());
	return string();
}


static void DesRemovePaddingBytes(std::string& data) {
	size_t dsize = data.size();
	for (size_t i = dsize - 1; i >= 0; i--) {
		unsigned char c = data[i];
		if (c == 0x00) {
			continue;
		}
		else if (c == 0x80) {
			data.erase(i, dsize - i);
			break;
		}
		else {
			break;
		}
	}
}


char EFFileDummyParse(std::string& data, STEFFileSystem* fileSystem) {
	return false;
}

char EF_COM_FileParse(std::string& data, STEFFileSystem* fileSystem) {
	return true;
}

char EF_DG1_FileParse(std::string& data, STEFFileSystem* fileSystem) {
	std::string flag("\x5F\x1F", 2);
	size_t it = data.find(flag);
	if (it == std::string::npos) {
		//LOGE("EF_DG1_FileParse:it == std::string::npos\n");
		return false;
	}

	std::string mrz = data.substr(it + 3);
#if USE_LOG_LEVEL1
	LOGV("EF_DG1_File::FileParse: " << mrz);
#endif

	fileSystem->stEFFiles[EF_DG1].resultLen = 0;
	for (int i = 0; i < mrz.size(); i++) {
		fileSystem->stEFFiles[EF_DG1].result[i] = mrz[i];
		fileSystem->stEFFiles[EF_DG1].resultLen++;
	}
	fileSystem->stEFFiles[EF_DG1].result[mrz.size()] = '\0';
	//LOGV("EF_DG1_FileParse: resultLen  == %d\n",fileSystem->stEFFiles[EF_DG1].resultLen);
	//LOGV("EF_DG1_FileParse: result  == %s\n",fileSystem->stEFFiles[EF_DG1].result);
	return true;
}

char EF_DG2_FileParse(std::string& data, STEFFileSystem* fileSystem) {
	//	char path[256];
	//	int len = MakeFullPath(path,DG2_FILE_NAME);

#if USE_OPENJPEG
	//LOGV("DG2.bmp path == %s\n",fileSystem->stEFFiles[EF_DG2].resultPath);
	return jp2_to_bmp(data, fileSystem->stEFFiles[EF_DG2].resultPath);
#else
	return true;
#endif
}


char EF_DG11_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG11].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG11].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG11].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG11_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG11].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG11].result[data.size()] = '\0';

	return true;
}

char EF_DG15_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG15].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG15].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG15].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG15_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG15].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG15].result[data.size()] = '\0';

	return true;
}

char EF_SOD_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_SOD].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_SOD].result[i] = data[i];
		fileSystem->stEFFiles[EF_SOD].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_SOD_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_SOD].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG15].result[data.size()] = '\0';

	return true;
}

char EF_IDINFO_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_IDINFO].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_IDINFO].result[i] = data[i];
		fileSystem->stEFFiles[EF_IDINFO].resultLen++;
	}
	fileSystem->stEFFiles[EF_IDINFO].result[data.size()] = '\0';

	/*
	LOGV("EF_IDINFO: " << fileSystem->stEFFiles[EF_IDINFO].resultLen);
	for(int i = 0;i < fileSystem->stEFFiles[EF_IDINFO].resultLen ;i++){
		LOGV("%x ",fileSystem->stEFFiles[EF_IDINFO].result[i] & 0xff );
	}
	std::cout << std::endl;
	*/
	return true;
}

char EF_IDPIC_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_IDPIC].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_IDPIC].result[i] = data[i];
		fileSystem->stEFFiles[EF_IDPIC].resultLen++;
	}
	fileSystem->stEFFiles[EF_IDPIC].result[data.size()] = '\0';

	/*
		LOGV("EF_IDINFO: " << fileSystem->stEFFiles[EF_IDPIC].resultLen);
		for(int i = 0;i < fileSystem->stEFFiles[EF_IDPIC].resultLen ;i++){
			LOGV("%x ",fileSystem->stEFFiles[EF_IDPIC].result[i] & 0xff );
		}
		std::cout << std::endl;
		*/
	return true;
}
//char EF_DG3_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG3].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG3].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG3].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG3_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG3].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG3].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG4_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG4].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG4].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG4].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG4_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG4].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG4].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG5_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG5].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG5].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG5].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG5_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG5].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG5].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG6_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG6].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG6].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG6].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG6_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG6].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG6].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG7_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG7].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG7].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG7].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG7_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG7].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG7].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG8_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG8].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG8].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG8].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG8_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG8].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG8].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG9_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG9].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG9].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG9].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG9_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG9].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG9].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG10_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG10].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG10].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG10].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG10_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG10].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG10].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG12_FileParse(std::string & data, STEFFileSystem * fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG12].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG12].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG12].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG12_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG12].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG12].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG13_FileParse(std::string & data, STEFFileSystem * fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG13].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG13].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG13].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG13_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG13].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG13].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG14_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG14].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG14].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG14].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG14_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG14].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG14].result[data.size()] = '\0';
//
//	return true;
//}
//char EF_DG16_FileParse(std::string& data, STEFFileSystem* fileSystem) {
//
//	fileSystem->stEFFiles[EF_DG16].resultLen = 0;
//	for (int i = 0; i < data.size(); i++) {
//		fileSystem->stEFFiles[EF_DG16].result[i] = data[i];
//		fileSystem->stEFFiles[EF_DG16].resultLen++;
//	}
//#if OOXX_DEBUG_LOG
//	LOG(INFO) << "echip EF_DG16_FileParse datasize: " << data.size() << " resultLen:"
//		<< fileSystem->stEFFiles[EF_DG16].resultLen;
//#endif
//
//
//	fileSystem->stEFFiles[EF_DG16].result[data.size()] = '\0';
//
//	return true;
//}
char EF_CARDACCESS_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_CARDACCESS].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_CARDACCESS].result[i] = data[i];
		fileSystem->stEFFiles[EF_CARDACCESS].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_CARDACCESS_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_CARDACCESS].resultLen;
#endif


	fileSystem->stEFFiles[EF_CARDACCESS].result[data.size()] = '\0';

	return true;
}
char EFFileDummyValid() {
	return false;
}

char STDefaultValid() {
	return true;
}

// 解析EF.COM文件可用文件的Tag列表
static std::string EF_COM_TagsParse(std::string& ef_com_data) {
	size_t it = ef_com_data.rfind(0x5C);
	if (it == std::string::npos) {
		//throw std::exception("not found tag 0x5c in EF.COM");
	}
	int tagCount = ef_com_data.size() - it - 2;
	return ef_com_data.substr(it + 2, tagCount);
}

/////////////////////////////////////////////////////////////////////////////////////////
static void SelectFunc(STEFFile* stFile) {
	switch (stFile->Index) {
	case EF_COM:
		stFile->FileParse = EF_COM_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG1:
		stFile->FileParse = EF_DG1_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG2:
		stFile->FileParse = EF_DG2_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG11:
		stFile->FileParse = EF_DG11_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_IDINFO:
		stFile->FileParse = EF_IDINFO_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_IDPIC:
		stFile->FileParse = EF_IDPIC_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG15:
		stFile->FileParse = EF_DG15_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_SOD:
		stFile->FileParse = EF_SOD_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_CARDACCESS:
		stFile->FileParse = EF_CARDACCESS_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG3:
	case EF_DG4:
	case EF_DG5:
	case EF_DG6:
	case EF_DG7:
	case EF_DG8:
	case EF_DG9:
	case EF_DG10:
	case EF_DG12:
	case EF_DG13:
	case EF_DG14:
	case EF_DG16:
	case EF_UNKNOWN:
	default:
		stFile->FileParse = EFFileDummyParse;
		stFile->Valid = EFFileDummyValid;
		break;
	}
}




void PCSCReader::ChipReaderReadFileResultOperate(EF_NAME name, char* result, unsigned char type) {
	switch (name) {
	case EF_COM:
		break;
	case EF_DG1: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG1.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG1, result);
		ChipData_Doc9303_Result.iDG1 = strlen(result);

		if (Output) {
			Output.write(result, strlen(result));
			Output.close();
		}
		break;
	}
	case EF_DG2: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG2.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG2, result);
		ChipData_Doc9303_Result.iDG2 = DG2_LENGTH;

		if (Output) {
			Output.write(result, DG2_LENGTH);
			Output.close();
		}
		break;
	}
	case EF_DG11: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG11.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG11, result);
		ChipData_Doc9303_Result.iDG11 = strlen(result);

		if (Output) {
			Output.write(result, strlen(result));
			Output.close();
		}
		break;
	}
	case EF_DG15: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG15.der");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG15 = DG15_LENGTH;
		strncpy(ChipData_Doc9303_Result.pDG15, result, DG15_LENGTH);

		if (Output) {
			Output.write(result, DG15_LENGTH);
			Output.close();
		}
		break;
	}
	case EF_SOD: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\EF_SOD.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iSod = SOD_LENGTH;
		strncpy(ChipData_Doc9303_Result.pSOD, result, SOD_LENGTH);

		if (Output) {
			Output.write(result, SOD_LENGTH);
			Output.close();
		}
		break;
	}
	case EF_CARDACCESS:
	{
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\EF_CARDACCESS.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iSod = SOD_LENGTH;//
		strncpy(ChipData_Doc9303_Result.pSOD, result, SOD_LENGTH);//
		
		if (Output) {
			Output.write(result, SOD_LENGTH);
			Output.close();
		}
		break;
	}
	default:
		break;
	}
}
//void PCSCReader::ChipReaderReadFileResultOperate(EF_NAME name, char* result, unsigned char type) {
//	switch (name) {
//	case EF_COM:
//		break;
//	case EF_DG1: {
//		//MyNotifyShowMRZ(type, result, baseFolder);
//		//LOGV("DG1: %s", result);
//		break;
//	}
//
//	case EF_DG2: {
//		//LOGV("����ͷ�񱣴浽%s�ļ���", result);
//		break;
//	}
//	case EF_DG15: {
//		char mypath[256];
//		MakeFullPath1(mypath, "USB_TEMP\\DG15.der");
//		std::ofstream  Output(mypath, std::ios::binary);
//		ChipData_Doc9303_Result.iDG15 = DG15_LENGTH;
//		strncpy(ChipData_Doc9303_Result.pDG15, result, DG15_LENGTH);
//
//		if (Output) {
//			Output.write(result, DG15_LENGTH);
//			Output.close();
//		}
//		break;
//	}
//	case EF_SOD: {
//		char mypath[256];
//		MakeFullPath1(mypath, "USB_TEMP\\EF_SOD.dat");
//		std::ofstream  Output(mypath, std::ios::binary);
//		ChipData_Doc9303_Result.iSod = SOD_LENGTH;
//		strncpy(ChipData_Doc9303_Result.pSOD, result, SOD_LENGTH);
//
//		if (Output) {
//			Output.write(result, SOD_LENGTH);
//			Output.close();
//		}
//		break;
//	}
//	case EF_CARDACCESS:
//	{
//		char mypath[256];
//		MakeFullPath1(mypath, "USB_TEMP\\EF_CARDACCESS.dat");
//		std::ofstream  Output(mypath, std::ios::binary);
//		ChipData_Doc9303_Result.iSod = SOD_LENGTH;//
//		strncpy(ChipData_Doc9303_Result.pSOD, result, SOD_LENGTH);//
//
//		if (Output) {
//			Output.write(result, SOD_LENGTH);
//			Output.close();
//		}
//		break;
//	}
//	default:
//		break;
//	}
//}

char PCSCReader::GetResult(EF_NAME efName, string& retData) {

	if (efName == EF_DG2) return true;
	if (st_efs.stEFFiles[efName].resultLen > 0) {
		retData.assign(st_efs.stEFFiles[efName].result, st_efs.stEFFiles[efName].resultLen);
#if OOXX_DEBUG_LOG
		if (efName == EF_DG11) {
			LOG(INFO) << "echip GetResult  len: "
				<< st_efs.stEFFiles[efName].resultLen;
			LOG(INFO) << " retData: " << retData;
		}
#endif
		return true;
	}
	return false;
}

char PCSCReader::EF_DG2_SetResultPath(string path) {
	strcpy(st_efs.stEFFiles[EF_DG2].resultPath, path.c_str());
	baseFolder = path;
	return true;
}

PCSCReader::PCSCReader()
{
	hContext = 0x00000000;
	m_dAttrib = 0;
	STEFilesInit(&st_efs);
}

PCSCReader::~PCSCReader()
{
	
}

int PCSCReader::Initalize() {
	int i;
	DWORD size = 64;

	if (hContext != 0x00000000){
		SCardReleaseContext(hContext);
		hContext = 0x00000000;
	}
	retCode = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
	if (retCode == SCARD_S_SUCCESS)
	{
		size = 256;
		retCode = SCardListReaders(hContext, NULL, (LPTSTR)cReaderName, &size);

		if (retCode == SCARD_S_SUCCESS)
		{
			char* p = cReaderName;
			while (*p)
			{
				for (i = 0; p[i]; i++);
				i++;
				if (*p != 0)
				{
					ReaderName += p;
				}
				p = &p[i];
			}

		}
		else
		{
			std::cerr << "SCardListReaders failed" << std::endl;
			return -1;
		}
	}
	else {
		std::cerr << "SCardEstablishContext failed" << std::endl;
		return -2;
	}
	return 1;
}

int PCSCReader::Connect(string& atr) {
	DWORD  	 ActiveProtocol = 0;
	CString  sConCaption;
	CString  sTemp;
	ULONG ProtocolType;
	ProtocolType = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;

	retCode = SCardConnect(hContext, ReaderName, SCARD_SHARE_SHARED, ProtocolType, &hCard, &ActiveProtocol);
	if (retCode == SCARD_S_SUCCESS)
	{
		BYTE     pbAttr[32];
		DWORD    cByte = 32;
		retCode = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, (LPBYTE)&pbAttr, &cByte);

		if (retCode == SCARD_S_SUCCESS)
		{
			//std::cout << "Connect successfully" << std::endl;
			atr = BYTE2string(pbAttr, cByte);
			//std::cout << atr << std::endl;

		}
	}
	else
	{
		return -1;
		std::cerr << "Connect falied" << std::endl;

	}
	return 1;
}

int PCSCReader::Apdusend(string& sendData,  BYTE* RecvBuff, DWORD& RecvLen) {
	wlString sChangeSend;
	BYTE SendBuff[300];
	UINT SendLen;
	//CString sTempData;
	//UINT     iCount;
	//int i = 0;
	//CString m_sSendData = "FFB0000000";
	//retCode = sChangeSend.StringToByte(sendData, SendBuff, &SendLen);

	//string selectAPP("\x00\xA4\x04\x0C\x07\xA0\x00\x00\x02\x47\x10\x01", 12);
	SendLen = sendData.size();
	memcpy(SendBuff, sendData.data(), SendLen);

	retCode = SCardTransmit(hCard, NULL, SendBuff, SendLen, NULL, RecvBuff, &RecvLen);

	if (retCode == SCARD_S_SUCCESS)
	{
		//cout << "send data successfully" << endl;
		//cout << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;

	}
	else
	{
		//cout << "send data failed" << endl;
		return -1;
	}
	return 1;
}

int PCSCReader::Getatr(string& atr) {
	BYTE     pbAttr[32];
	DWORD    cByte = 32;
	//DWORD    dwState, dwProtocol;
	wlString sChange;
	//m_dAttrib

	retCode = SCardGetAttrib(hCard, SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, m_dAttrib), (LPBYTE)&pbAttr, &cByte);

	if (retCode == SCARD_S_SUCCESS)
	{
		atr = BYTE2string(pbAttr, cByte);;
	}
	else {
		return -1;
	}
	return 1;
}

int PCSCReader::DissConnect() {
	retCode = -1;
	retCode = SCardDisconnect(hCard, SCARD_EJECT_CARD);
	if (retCode == 0) {
		cout << "disconnect successfully" << endl;
		return 1;
	}
	else {
		cerr << "disconnect failed" << endl;
		return -1;
	}
}

char PCSCReader::BuildKencAndKmac(const std::string& mrzInfo,
	std::string& Kenc,
	std::string& Kmac) {

	std::string Kseed(16, 0);
	std::string mrzInfoSha1(20, 0);
	SHA1((unsigned char*)mrzInfo.data(), mrzInfo.size(), (unsigned char*)mrzInfoSha1.data());

	memcpy((unsigned char*)Kseed.data(), mrzInfoSha1.data(), Kseed.size());

	// SHA1 to Kenc Kmac
	std::string c1("\x00\x00\x00\x01", 4);
	std::string c2("\x00\x00\x00\x02", 4);
	std::string D1, D2, HD1(20, 0), HD2(20, 0);

	// Kseed concat c1,c2 into D1, D2
	D1.append(Kseed.data(), Kseed.size());
	D1.append(c1.data(), c1.size());
	D2.append(Kseed.data(), Kseed.size());
	D2.append(c2.data(), c2.size());


	// SHA D1 and D2
	SHA1((unsigned char*)D1.data(), D1.size(), (unsigned char*)HD1.data());
	SHA1((unsigned char*)D2.data(), D2.size(), (unsigned char*)HD2.data());

	CheckParity(HD1, Kenc, 16);
	CheckParity(HD2, Kmac, 16);
	return true;
}

char PCSCReader::BuildIFD(std::string& RND_IFD,
	std::string& Kifd) {
	RND_IFD.resize(8);
	Kifd.resize(16);
	BuildRandomData(RND_IFD);
	BuildRandomData(Kifd);

	if (RND_IFD.size() != 8 || Kifd.size() != 16) {
		return false;
	}
	return true;
}

char PCSCReader::ICCMutualAuthenticate(std::string& RND_IFD,
	std::string& RND_ICC,
	std::string& Kifd,
	std::string& Kenc,
	std::string& Kmac,
	std::string& KSenc,
	std::string& KSmac) {

	char ret = false;
	std::string S;
	S.append(RND_IFD);
	S.append(RND_ICC);
	S.append(Kifd);
	if (S.size() != 32) {
		return false;
	}

	// 用密钥Kenc对S进行CBC模式的3DES（TDES）加密
	std::string Eifd;
	KencTDES(S, Kenc, Eifd, DES_ENCRYPT);

	if (Eifd.size() != 32) {
		return false;
	}

	// 用密钥Kmac计算Eifd(填充)的MAC
	std::string Mifd;
	DesAddPaddingBytes(Eifd);

	if (Eifd.size() != 40) {
		return false;
	}

	KmacDES(Eifd, Kmac, Mifd);
	if (Mifd.size() != 8) {
		return false;
	}

	// 构建MUTUAL AUTHENTICATE命令数据
	std::string cmd;
	cmd.append(Eifd.data(), 32);
	cmd.append(Mifd.data(), 8);
	// 构建MUTUAL AUTHENTICATE命令
	std::string catHeader("\x00\x82\x00\x00\x28", 5);
	std::string APDU;
	APDU.append(catHeader);
	APDU.append(cmd);

	/*
	这里应该多加一个字节Le值，中国护照可以不需要，但是国外的护照如果不加
	这个字节，调用会失败
	*/
	APDU.push_back(0x28);
	BYTE  RecvBuff[300];
	DWORD RecvLen;
	unsigned char* buff = (unsigned char*)APDU.c_str();
	string temp = BYTE2string(buff, 46);
	
	CString m_Mutual = temp.c_str();
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	wlString wlstring;
	this->Apdusend(APDU, RecvBuff, RecvLen);
	if (RecvLen < 40) return false;
	std::string s((char*)&RecvBuff[0], RecvLen - 2);
	std::string RAPDU;
	RAPDU.append(s);
	std::string RAPDU_out = BYTE2string(RecvBuff, RecvLen).substr(0,40);
	//cout <<"RAPDU: "<< RAPDU_out << endl;
	/*byte rapdu[20];
	UINT len;
	CString CRAPDU = RAPDU.c_str();
	wlstring.StringToByte(CRAPDU, rapdu, &len);*/
	if (RAPDU.size() != 40) {
		return false;
	}
	
	std::string Eicc, Micc;
	Eicc.append(RAPDU.data(), 32);
	Micc.append(RAPDU.data() + 32, 8);

	// 用密钥Kenc对Eicc进行3DES解密得到R
	std::string R;
	KencTDES(Eicc, Kenc, R, DES_DECRYPT);

	std::string RNDifdr(R.data() + 8, 8);
	// R由RNDiCCN(已知)、RNDifd（已知）、KiCCN(未知）组成，KiCCN为后16个字节
	if (memcmp(RND_IFD.data(), RNDifdr.data(), RNDifdr.size()) != 0) {
		// 接收到的RNDifdr和生成的RNDifd不一致

		return false;
	}

	std::string Kicc(R.data() + 16, 16);
	// Kifd与Kicc按位异或得到SKseed
	std::string SKseed(16, 0);
	for (size_t i = 0; i < SKseed.size(); i++) {
		SKseed[i] = Kifd[i] ^ Kicc[i];
	}

	// 用SKseed分别并置c1与c2求SHA1取高位16字节，再调整奇偶校验位得到SKenc和SKmac
	KSenc.resize(16, 0);
	KSmac.resize(16, 0);
	SHA1ToKencKmac(SKseed, KSenc, KSmac);



	return true;
}

char PCSCReader::ActiveAuthentication(char* DG15_file_path) {

	std::string RND_IFD;
	std::string RSA_RES;
	RND_IFD.resize(8);
	BuildRandomData(RND_IFD);
	if (RND_IFD.size() != 8) return false;
	BYTE  RecvBuff[300];
	DWORD RecvLen;
	string m_RND_ICC("\x00\x88\x00\x00\x08", 5);
	m_RND_ICC += RND_IFD;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	Apdusend(m_RND_ICC, RecvBuff, RecvLen);
	if (RecvLen != 130) {
		return false;
	}
	else {
		for (int i = 0; i < 128; ++i) {
			RSA_RES += RecvBuff[i];
		}
	}
	std::ifstream file(DG15_file_path, std::ios::binary); // 打开文件	
	if (!file) {
		std::cerr << "无法打开文件" << std::endl;
		return 1;
	}

	std::stringstream hex_stream;
	char byte;

	// 以16进制格式读取文件内容到字符串流中
	while (file.read(&byte, 1)) {
		hex_stream << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)byte;
	}

	std::string hex_string = hex_stream.str(); // 获取16进制字符串
	hex_string = hex_string.substr(6);
	std::cout << hex_string << std::endl;

	file.close(); // 关闭文件
	std::string base64str = hexToBase64(hex_string);
	std::string pubKey1 = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";
	string cipherText = StringToHex(RSA_RES);
	std::string decStr = rsa_pub_decrypt(RSA_RES, pubKey1);
	std::string hexDecStr = StringToHex(decStr);
	if (hexDecStr.size() < 254) {
		return false;
	}
	std::string sha_D = hexDecStr.substr(214, 40);
	std::string M1 = hexDecStr.substr(2, 212);
	std::string M_ = M1 + StringToHex(RND_IFD);
	std::string D_(20, 0);
	std::string binaryM_ = HexToString(M_);
	SHA1((unsigned char*)binaryM_.c_str(), 114, (unsigned char*)D_.data());
	std::string origin_D = StringToHex(D_);
	cout << cipherText << endl;
	return sha_D == origin_D;
}

char PCSCReader::PassiveAuthentication(char* SOD_file_path) {

	string hex = ReadFileContentsAsHex(SOD_file_path);

	string hex_key = hex.substr(1342, 588);
	string base64str = hexToBase64(hex_key);
	string pubKey1 = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";

	string encryptedData = hex.substr(hex.size() - 512, 512);
	encryptedData = hexString2String(encryptedData);
	string decStr = rsa_pub_decrypt(encryptedData, pubKey1);
	string hexDecStr = StringToHex(decStr);
	if (hexDecStr.size() < 64) {
		return -1;
	}
	string signature_dec = hexDecStr.substr(hexDecStr.size() - 64, 64);
	//取出 signedAttrs 
	string signedAttrs = hex.substr(4244, 214);

	//复原成完整的der格式
	signedAttrs[0] = '3';
	signedAttrs[1] = '1';
	//计算签名
	string signature = sha256(hexString2String(signedAttrs));
	return (compare_ignore_case(signature, signature_dec));
}

char PCSCReader::BuildSSC(std::string& RND_IFD,
	std::string& RND_ICC,
	std::string& SSC) {
	SSC.resize(0);
	SSC.append(RND_ICC.data() + 4, 4);
	SSC.append(RND_IFD.data() + 4, 4);
	return true;
}

char PCSCReader::ICCReadEF(std::string& KSenc, std::string& KSmac, std::string& SSC, EF_NAME name,
	std::string& EF_Data) {
	STEFFile* stFile = StIndexFindEFFile(name, &st_efs);
	char ret = this->SecureCommunication(stFile, KSenc, KSmac, SSC, EF_Data);
	if (false == ret || EF_Data.size() == 0) {
		return false;
	}

	return true;
}

char PCSCReader::SecureCommunication(
	STEFFile* file,
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	std::string& data) {
	char ret = false;

	// 1. 选择要读取的文件
#if USE_LOG_LEVEL2
	LOGV("[ChipReader]正在选择文件 %s", file->name);
#endif

	ret = this->SecureCommunicationSelectFile(file, KSenc, KSmac, SSC);
	if (!ret) {
#if USE_LOG_LEVEL2
		LOGV("[ChipReader]选择文件 %s 失败", file->name);
#endif
		return false;
	}
#if USE_LOG_LEVEL2
	LOGV("[ChipReader]选择文件 %s 成功", file->name);
#endif
	// 2. 读取该文件的前4个字节
	std::string head4bytes;
#if USE_LOG_LEVEL2
	LOGV("[ChipReader]正在读取文件 %s 的前4个字节", file->name);
#endif
	ret = this->SecureCommunicationReadBinary(KSenc, KSmac, SSC, 0, 4, head4bytes);
	if (!ret) {
#if USE_LOG_LEVEL2
		LOGV("[ChipReader]读取失败");
#endif
		return false;
	}
#if USE_LOG_LEVEL2
	LOGV("[ChipReader]读取成功");
#endif
	/*
	  读文件有两种方式
	  (1)要先读头4字节获取文件大小，再循环读后续数据
	  (2)要先读头4字节获取文件大小，再从偏移0开始读数据，数据最大230字节
	  本方法的实现采用第2种方法
	*/
	// 3. 解析EF文件头4字节, 获取文件总大小(包括上面读的4个字节)
	unsigned short len = 0;
	ret = ParseFileLengthIn4Bytes(head4bytes, &len);
	if (!ret) {
#if USE_LOG_LEVEL2
		LOGV("[ChipReader]解析文件头4个字节失败");
#endif
		return false;
	}
#if OOXX_DEBUG_LOG
	std::ostringstream out;
	for (int i = 0; i < head4bytes.size(); ++i) {
		out << std::hex << setiosflags(std::ios::uppercase) << std::setw(2) << std::setfill('0')
			<< static_cast<unsigned short>(head4bytes[i]);
	}
	LOG(INFO) << "[ChipReader]解析文件头4个字节成功，文件长度 " << len << " 头内容: " << out.str();
#endif
#if USE_LOG_LEVEL1
	LOGV("[ChipReader]解析文件头4个字节成功，文件长度 %d 字节", len);
#endif
#if 0
	// 4. 计算剩余的未读文件长度
	len -= 4;
	data.append(head4bytes);
#endif

	// 5. 读取剩余的数据
	if (len > 0) {
		std::string rest;
#if USE_LOG_LEVEL2
		LOGV("[ChipReader]准备请求文件 %s 内容", file->name);
#endif
		ret = this->SecureCommunicationReadFile(KSenc, KSmac, SSC, 0, len, rest);
		if (!ret) {
			return false;
		}
		data.append(rest);
#if OOXX_DEBUG_LOG
		if (file->Index == EF_DG11) {
			out.str("");
			for (int i = 0; i < rest.size(); ++i) {
				out << std::hex << setiosflags(std::ios::uppercase) << std::setw(2)
					<< std::setfill('0') << static_cast<unsigned short>(rest[i]);
			}
			LOG(INFO) << "[ChipReader]文件 " << file->name << " 读取完毕，文件长度 " << data.size() << " 文件内容："
				<< out.str();
		}

#endif
	}
	else if (len < 0) {
		// 非法的文件长度
		//throw std::exception("invalid EF file length");
		return false;
	}

#if USE_LOG_LEVEL2
	LOGV("[ChipReader]文件 %s 读取完毕", file->name);
#endif
	return true;
}

char PCSCReader::SecureCommunicationSelectFile(
	STEFFile* file,
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC) {
	// 对未受保护的APDU命令进行填充
	std::string unprotectedAPDU("\x0C\xA4\x02\x0C", 4);
	std::string CmdHeader(unprotectedAPDU);
	DesAddPaddingBytes(CmdHeader);
	std::string strFillData;
	//if(strlen(file->Id) >= 2){
	//LOGV("file.Id.size() ==  %s", file.Id.size());
	//	LOGV("fild->Id:  %s", file->Id);
	//	LOGV("file->Id[0] == %02x;file->Id[1] == %02x\n",file->Id[0],file->Id[1]);
	strFillData.push_back(file->Id[0]);
	strFillData.push_back(file->Id[1]);
	/*}else{

		LOGV("file.Id.size() ==  %s", strlen(file->Id));
		LOGV("fild.Id:  %s", file->Id);
		return  false;
	}
*/

	DesAddPaddingBytes(strFillData);
	// 用SKenc加密数据
	std::string strEncData;
	KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);

	// 构建DO87,并置cmdheader和DO87得到M
	std::string DO87;
	unsigned char L = (unsigned char)strFillData.size() + 1;
	unsigned char x87 = 0x87;
	DO87.push_back(x87);
	DO87.push_back(L);
	DO87.push_back(0x01);
	DO87.append(strEncData);
	std::string M = CmdHeader + DO87;

	IncreaseSSC(SSC); //SSC += 1

	// 连接SSC和M，并增加填充得到N
	std::string N;
	N.append(SSC.data(), SSC.size());
	N.append(M.data(), M.size());
	DesAddPaddingBytes(N);

	// 用SKmac计算N的消息认证码MAC
	std::string CCN;
	KmacDES(N, KSmac, CCN);

#if USE_LOG_LEVEL1
	LOGV("CC_N= %s", BinaryToHexString(CCN));
#endif
	// 用CCN构建DO8E
	std::string DO8E("\x8E\x08", 2);
	DO8E.append(CCN.data(), CCN.size());

	// 构建受保护的APDU
	std::string APDU;
	std::string unprotectedAPDU2("\x0C\xA4\x02\x0C", 4);
	APDU.append(unprotectedAPDU2.data(), unprotectedAPDU2.size());
	APDU.append("\x15", 1);
	APDU.append(DO87.data(), DO87.size());
	APDU.append(DO8E.data(), DO8E.size());
	/*
	 这里应该多加一个字节，中国护照可以不需要，但是国外的护照如果不加
	 这个字节，调用会失败
	 */
	APDU.push_back(0);
	// 发送APDU
	int dwLen = APDU.size();
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	wlString wlstring;
	this->Apdusend(APDU, RecvBuff, RecvLen);
	//cout << "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s((char*)&RecvBuff[0], RecvLen);
	std::string RAPDU;
	RAPDU.append(s);
	//std::string RAPDU = BYTE2string(RecvBuff, RecvLen).substr(0, RecvLen - 2);
	IncreaseSSC(SSC); //SSC += 1
	// 连接SSC和DO99， 并填充得到K
	std::string DO99 = RAPDUParse(RAPDU, 0x99);
	std::string K(SSC);
	K += DO99;
	DesAddPaddingBytes(K);
	// 用SKmac计算K的消息认证码MAC
	std::string CCK;
	KmacDES(K, KSmac, CCK);
	// 从RAPDU中提取出DO8Er，验证是否等于CCK
	std::string RAPDU_DO8E = RAPDUParse(RAPDU, 0x8E);
	if (memcmp(RAPDU_DO8E.data() + 2, CCK.data(), 8) != 0) {
#if USE_LOG_LEVEL1
		LOGV("DO8E and CCK mismatch in Selecting file");
#endif
		return false;
	}
	return true;
}
char PCSCReader::DirectCommunicationSelectFile() {
	//std::string APDU("\x00\xA4\x02\x0C\x02\x01\x1E", 7);
	////std::string EF_ID("\x01\x1E", 2);
	//int dwLen = APDU.size();
	//1 直接读cardaccess
	//2 加密读cardaccess
	int dwLen;
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	//memset(RecvBuff, 0, sizeof(RecvBuff));
	//RecvLen = sizeof(RecvBuff);
	//this->Apdusend(APDU, RecvBuff, RecvLen);
	////cout << "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	//std::string s((char*)&RecvBuff[0], RecvLen);
	std::string RAPDU;
	//RAPDU.append(s);

	std::string APDU1("\x00\xB0\x1C\x00",4);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RAPDU.clear();
	dwLen = APDU1.size();
	RecvLen = sizeof(RecvBuff);
	this->Apdusend(APDU1, RecvBuff, RecvLen);
	//cout << "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s1((char*)&RecvBuff[0], RecvLen);
	RAPDU.append(s1);
	return true;
}

char PCSCReader::SecureCommunicationReadBinary(
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	unsigned short offset,
	unsigned short chunkSize,
	std::string& data) {
	// 创建未受保护的命令APDU, P1, P2未指定
	std::string unprotectedAPDU("\x0C\xB0\x00\x00", 4);

	// a.1设置读取偏移, 设置P1, P2
	unsigned short* apdu_len = (unsigned short*)(unprotectedAPDU.data() + 2);
	*apdu_len = HostToNetworkUINT16(offset);

	// a. 设置读取偏移， 创建并填充命令报头
	std::string CmdHeader(unprotectedAPDU);
	// a.2 创建并填充命令报头
	DesAddPaddingBytes(CmdHeader);

	// b. 建立DO97
	std::string DO97("\x97\x01", 2);
	DO97.push_back((unsigned char)chunkSize);

	// c. 并置CmdHeader和DO97为M
	std::string M(CmdHeader);
	M += DO97;

	// --------------------------------------------
	// d.计算M的MAC
	// d.1 用1为SSC增值
	IncreaseSSC(SSC);

	// d.2并置SSC和M，并增加填充
	std::string N(SSC);
	N.append(M);
	DesAddPaddingBytes(N);

	// d.3用KSmac计算N的MAC
	std::string CC;
	KmacDES(N, KSmac, CC);
	// ---------------------------------------------

	// e.建立DO8E
	std::string DO8E("\x8E\x08", 2);
	DO8E.append(CC);
	// f.建立保护的APDU
	std::string APDU(unprotectedAPDU);
	int size = DO97.size() + DO8E.size();
	APDU.push_back(size);
	APDU += DO97;
	APDU += DO8E;
	APDU.push_back(0);

	// g.接收机读旅行证件芯片的响应APDU
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	wlString wlstring;
	this->Apdusend(APDU, RecvBuff, RecvLen);
	//cout << "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s((char*)&RecvBuff[0], RecvLen);
	std::string RAPDU;
	RAPDU.append(s);
	//std::string RAPDU = BYTE2string(RecvBuff, RecvLen).substr(0, RecvLen - 2);
	//char ret = this->PostPassportCommand(RF_CMD_APP, APDU, RAPDU);

#define DO99_COMPATIBLE 1
	// ------------------------------------------------------------
	// h.通过计算DO87和DO99并置的MAC, 验证RAPDU CC
	int tlLen = 0;
	std::string RAPDU_DO87 = RAPDUParse(RAPDU, 0x87, &tlLen);
	//    LOGI("SecureCommunicationReadBinary tlLen:%d", tlLen);
		/* 有时候请求200字节的大包时，读写器返回的数据包里没有DO99 TLV标签，
		   只有DO87和DO8E，目前看来DO99是固定的4个字节\x99\E02\x90\x00，这里
		   直接使用4字节常量，而不去RAPDU中取DO99，以免失败。
		   按规范Doc9303 Part1 Vol2.PDF之第IV节公钥基础设施IV-45的描述，DO99
		   应该是必须强制存在的，这里提供兼容性处理
		   */
#ifdef DO99_COMPATIBLE
	std::string RAPDU_DO99("\x99\x02\x90\x00", 4);
#else
	std::string RAPDU_DO99 = RAPDUParse(RAPDU, 0x99);
#endif
	std::string RAPDU_DO8E = RAPDUParse(RAPDU, 0x8E);

	// h.1 用1为SSC增值
	IncreaseSSC(SSC);

	// h.2 并置SSC, DO87和DO99，并增加填充
	std::string K(SSC);
	K += RAPDU_DO87;
	K += RAPDU_DO99;
	DesAddPaddingBytes(K);
	// h.3 用KSmac计算MAC
	std::string CC2;
	KmacDES(K, KSmac, CC2);
	// h.4 将CC与RAPDU的DO8E数据作比较
	if (memcmp(CC2.data(), RAPDU_DO8E.data() + 2, 8) != 0) {
#if USE_LOG_LEVEL1
		LOGV("DO8E and CC2 mismatch in Reading binary");
#endif
		return false;
	}
	// i. 用KSenc解密DO87数据
	std::string RAPDU_DO87_DATA = RAPDU_DO87.substr(tlLen + 1);
	KencTDES(RAPDU_DO87_DATA, KSenc, data, DES_DECRYPT);
	DesRemovePaddingBytes(data);

	return true;
}

char PCSCReader::SecureCommunicationReadFile(
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	unsigned short offset,
	unsigned short len,
	std::string& data) {
	const int chunkSize = 230;

	//assert(chunkSize >0 && chunkSize <= 230);

	int lastBytes = len % chunkSize;
	int chunks = len / chunkSize;
#if OOXX_DEBUG_LOG
	LOG(INFO) << "[ChipReader]chunks " << chunks << " lastBytes " << lastBytes;
#endif
#if USE_LOG_LEVEL2
	int requestOffset = 1;
	LOGV("[ChipReader]开始读取文件全部内容，需要 %s", chunks + 1 << "次请求");
#endif

	for (int i = 0; i < chunks; i++) {
		std::string chunkData;

		//std::cout << ".";
#if USE_LOG_LEVEL2
		std::cout << "[ChipReader]正在读取第 %s", requestOffset << "个包，偏移为"
			<< offset << "开始的 %s", chunkSize << "个字节 %s", std::endl;
#endif
		char ret = this->SecureCommunicationReadBinary(KSenc, KSmac, SSC, offset, chunkSize,
			chunkData);
		if (!ret) {
#if USE_LOG_LEVEL2
			LOGV("[ChipReader]第 %s", requestOffset << "个包读取失败");
#endif
			return false;
		}
#if USE_LOG_LEVEL2
		LOGV("[ChipReader]第 %s", requestOffset << "个包读取成功，实际读取 %s", chunkData.size() << "字节");
		++requestOffset;
#endif
		data.append(chunkData);
		offset += (unsigned short)chunkData.size();
	}
	//std::cout << std::endl;

	if (lastBytes) {
		std::string chunkData;
#if USE_LOG_LEVEL2
		std::cout << "[ChipReader]正在读取第 %s", requestOffset << "个包，偏移为" <<
			offset << "开始的 %s", lastBytes << "个字节 %s", std::endl;
#endif
		char ret = this->SecureCommunicationReadBinary(KSenc, KSmac, SSC, offset, lastBytes,
			chunkData);
		if (!ret) {
#if USE_LOG_LEVEL2
			LOGV("[ChipReader]第 %s", requestOffset << "个包读取失败");
#endif
			return false;
		}
#if USE_LOG_LEVEL2
		LOGV("[ChipReader]第 %s", requestOffset << "个包读取成功，实际读取 %s", chunkData.size() << "字节");
#endif
		data.append(chunkData);
	}

	return true;
}

char PCSCReader::ReadEchipInfo(std::string& codetonfc) {

	std::string Kenc;
	std::string Kmac;
	std::string RND_ICC;
	std::string RND_IFD;
	std::string Kifd;
	std::string KSenc;
	std::string KSmac;
	std::string SSC;

	BYTE  RecvBuff[300];
	DWORD RecvLen;
	string selectAPP  ("\x00\xA4\x04\x0C\x07\xA0\x00\x00\x02\x47\x10\x01",12);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	Apdusend(selectAPP, RecvBuff, RecvLen);
	//cout << "选择签发者应用返回： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;

	
	//2.	生成Kenc和Kmac

	CHECK_OK(BuildKencAndKmac(codetonfc, Kenc, Kmac));
	// 3.	请求随机数
	//CString m_RND_ICC = "0084000008";
	string m_RND_ICC ("\x00\x84\x00\x00\x08",5);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	Apdusend(m_RND_ICC, RecvBuff, RecvLen);
	if (RecvLen != 10) {
		//cerr << "请求随机数失败" << endl;
		return -1;
	}
	else {
		for (int i = 0; i < 8; ++i) {
			RND_ICC += RecvBuff[i];
		}
		//cout << "随机数： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
		//cout << "RND_ICC: " << RND_ICC << endl;

	}

	// 4.	生成一个随机的8字节RNDifd和一个随机的16字节Kifd
	CHECK_OK(BuildIFD(RND_IFD, Kifd));

	//5.	发起Mutual认证
	CHECK_OK(ICCMutualAuthenticate(RND_IFD, RND_ICC, Kifd, Kenc, Kmac, KSenc, KSmac));

	//6.Build SSC
	CHECK_OK(BuildSSC(RND_IFD, RND_ICC, SSC));

	// 准备好 KSenc KSmac SSC 后，开始进行安全通信
	std::string EF_COM_Data;

	// 读取EF.COM文件，并检查该护照存在哪些文件
	CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, EF_COM, EF_COM_Data));
	//std::string tags = EF_COM_TagsParse(EF_COM_Data);
	std::string tags = EF_COM_TagsParse(EF_COM_Data);

	//EFFileSystem efs;
	STEFFile* stFile = NULL;

	// 读取其他文件
	for (size_t i = 0; i < tags.size(); i++) {
		unsigned char b = tags[i];
		//cout << "tag" << b << endl;
		stFile = StTagFindEFFile(b, &st_efs);
		if (NULL == stFile) {
			continue;
		}
		std::string ef_data;
		if (stFile->Index == EF_COM) {
			continue;
		}

		// 如果该类型EF解析器未实现则不读该文件
		SelectFunc(stFile);
		if (!stFile->Valid()) {
			continue;
		}
		// 读取文件
		CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, stFile->Index, ef_data));
		// 解析文件
		if (stFile->FileParse(ef_data, &st_efs)) {

			ChipReaderReadFileResultOperate(stFile->Index, stFile->result, 2);
			/*
				if (this->cb) {
					this->cb->OnChipReaderReadFileResult(stFile->Index, stFile->result,this->GetCardType());
				}*/
		}
	}
	std::string content;
	STEFFile* cardaccess = &(st_efs.stEFFiles[EF_CARDACCESS]);
	CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, cardaccess->Index, content));
	//DirectCommunicationSelectFile();



	//进行主动认证
	char mypath[256];
	MakeFullPath1(mypath, "USB_TEMP\\DG15.der");
	if (!ActiveAuthentication(mypath)) {
		std::cout << "ActiveAuthentication failed" << std::endl;
	}
	else {
		std::cout << "ActiveAuthentication success" << std::endl;
		ChipAuthenticResult.AA = 1;
	}

	// passive auth
	char SOD_file_path[256];
	MakeFullPath1(SOD_file_path, "USB_TEMP\\EF_SOD.dat");
	if (PassiveAuthentication(SOD_file_path)) {
		std::cout << "PassiveAuthentication success" << std::endl;
		ChipAuthenticResult.PA = 1;
	}
	else {
		std::cout << "PassiveAuthentication failed" << std::endl;
	}


	return true;
}