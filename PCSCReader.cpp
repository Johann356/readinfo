#define _CRT_SECURE_NO_WARNINGS
#define CHECK_OK(x)  if(!(x)) return false;
#include "PCSCReader.h"
#include "Ptypes.h"
#include "EFFile.h"
#include "PACEInfo.h"
#include <atlstr.h>
#include <winscard.h>
#include <iostream>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include "wlString.h"
#include "utils.h"
#include "JP2.h"
#include <fstream>
#include <iomanip>
#include <strstream>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/dh.h>
#include <regex>

// DES算法对齐
#define DES_ALIGN(n, align) ((n + align) & (~(align - 1)))
#define DG15_LENGTH 165
#define SOD_LENGTH 2504
#define DG2_LENGTH 20591
#define RF_ERR_SUCCESS				0x0001		// 成功
#define RF_ERR_FAILURE				0x0000		// 失败，数据收发成功，命令执行失败。
const static BYTE SW_SUCCESS[] = "\x90\x00";

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

static void aes_cbc_encode(const std::string& key, std::string& data, std::string& enc, std::string& iv_str) {

	unsigned char iv[AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	for (int i = 0; i < 16; ++i) {
		iv[i] = iv_str[i];
	}

	AES_KEY aes_key;
	if (AES_set_encrypt_key((const unsigned char*)key.c_str(), key.length() * 8, &aes_key) < 0)
	{
		return;
	}
	unsigned char out[AES_BLOCK_SIZE];
	unsigned char* inData = (unsigned char*)data.data();
	AES_cbc_encrypt(inData, out, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
	enc = std::string((const char*)out, AES_BLOCK_SIZE);
}

static void AESmac(const std::string& KSmac, std::string& inputData, std::string& mac, int keyLength)
{
	unsigned char mact[32] = { 0 };
	size_t mactlen;
	CMAC_CTX* ctx = CMAC_CTX_new();
	if(keyLength == 256)
		CMAC_Init(ctx, KSmac.c_str(), KSmac.size(), EVP_aes_256_cbc(), NULL);
	else if(keyLength == 192)
		CMAC_Init(ctx, KSmac.c_str(), KSmac.size(), EVP_aes_192_cbc(), NULL);
	else if(keyLength == 128)
		CMAC_Init(ctx, KSmac.c_str(), KSmac.size(), EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, inputData.c_str(), inputData.size());
	CMAC_Final(ctx, mact, &mactlen);
	std::string s((char*)&mact[0], mactlen);
	mac = s.substr(0, 8);
	CMAC_CTX_free(ctx);
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

static void AesAddPaddingBytes(std::string& data) {
	size_t dsize = data.size();
	dsize = DES_ALIGN(dsize, 16);
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
	// 
	//std::string path = fileSystem->stEFFiles[EF_DG2].resultPath;
	//path = path.substr(0, path.find("."));
	//path += ".dat";
	//std::ofstream w(path, std::ofstream::out|std::ofstream::binary);
	//w << data;
	//w.close();
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
char EF_DG12_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG12].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG12].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG12].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG12_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG12].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG12].result[data.size()] = '\0';

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
char EF_DG3_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG3].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG3].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG3].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG3_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG3].resultLen;
#endif
	fileSystem->stEFFiles[EF_DG3].result[data.size()] = '\0';
	return true;
}
char EF_DG4_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG4].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG4].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG4].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG4_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG4].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG4].result[data.size()] = '\0';

	return true;
}
char EF_DG5_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG5].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG5].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG5].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG5_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG5].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG5].result[data.size()] = '\0';

	return true;
}
char EF_DG6_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG6].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG6].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG6].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG6_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG6].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG6].result[data.size()] = '\0';

	return true;
}
char EF_DG7_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG7].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG7].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG7].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG7_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG7].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG7].result[data.size()] = '\0';

	return true;

}
char EF_DG8_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG8].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG8].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG8].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG8_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG8].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG8].result[data.size()] = '\0';

	return true;
	}
char EF_DG9_FileParse(std::string & data, STEFFileSystem * fileSystem) {

	fileSystem->stEFFiles[EF_DG9].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG9].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG9].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG9_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG9].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG9].result[data.size()] = '\0';

	return true;
	}
char EF_DG10_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG10].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG10].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG10].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG10_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG10].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG10].result[data.size()] = '\0';

	return true;
}
char EF_DG13_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG13].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG13].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG13].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG13_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG13].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG13].result[data.size()] = '\0';

	return true;
}
char EF_DG14_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG14].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG14].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG14].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG14_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG14].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG14].result[data.size()] = '\0';

	return true;
}
char EF_DG16_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG16].resultLen = 0;
	for (int i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG16].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG16].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG16_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG16].resultLen;
#endif


	fileSystem->stEFFiles[EF_DG16].result[data.size()] = '\0';

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
	case EF_DG12:
		stFile->FileParse = EF_DG12_FileParse;
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
	case EF_DG3:
		stFile->FileParse = EF_DG3_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG4:
		stFile->FileParse = EF_DG4_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG5:
		stFile->FileParse = EF_DG5_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG6:
		stFile->FileParse = EF_DG6_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG7:
		stFile->FileParse = EF_DG7_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG8:
		stFile->FileParse = EF_DG8_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG9:
		stFile->FileParse = EF_DG9_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG10:
		stFile->FileParse = EF_DG10_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG13:
		stFile->FileParse = EF_DG13_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG14:
		stFile->FileParse = EF_DG14_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_DG16:
		stFile->FileParse = EF_DG16_FileParse;
		stFile->Valid = STDefaultValid;
		break;
	case EF_UNKNOWN:
	default:
		stFile->FileParse = EFFileDummyParse;
		stFile->Valid = EFFileDummyValid;
		break;
	}
}




void PCSCReader::ChipReaderReadFileResultOperate(EF_NAME name, char* result, unsigned char type, int length) {
	switch (name) {
	case EF_COM:
		break;
	case EF_DG1: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG1.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG1, result);
		ChipData_Doc9303_Result.iDG1 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG2: {
		break;
	}
	case EF_DG3: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG3.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG3, result);
		ChipData_Doc9303_Result.iDG3 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG4: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG4.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG4, result);
		ChipData_Doc9303_Result.iDG4 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG5: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG5.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG5, result);
		ChipData_Doc9303_Result.iDG5 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG6: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG6.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG6, result);
		ChipData_Doc9303_Result.iDG6 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG7: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG7.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG7, result);
		ChipData_Doc9303_Result.iDG7 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG8: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG8.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG8, result);
		ChipData_Doc9303_Result.iDG8 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG9: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG9.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG9, result);
		ChipData_Doc9303_Result.iDG9 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG10: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG10.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		strcpy(ChipData_Doc9303_Result.pDG10, result);
		ChipData_Doc9303_Result.iDG10 = length;

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}


	case EF_DG11: {
		strcpy(ChipData_Doc9303_Result.pDG11, result);
		ChipData_Doc9303_Result.iDG11 = length;
		std::string flag("\x5F\x0E", 2);
		string info = result;

		size_t it = info.find(flag);
		if (it == std::string::npos) {
			return;
		}

		char mypath[512];
		MakeFullPath1(mypath, "USB_TEMP\\DG11.dat");
		std::ofstream  Output;
		Output.open(mypath);

		size_t it1 = info.find(flag, it + 2);
		int len = info[it1 + 2] & 0xff;//获取长度
		std::string name;
		for (int i = 0; i < len; i++) {
			if (info[i + it1 + 3] != '<') {
				name.push_back(info[i + it1 + 3]);//长度之后便是数据
			}
		}
		Output << name << std::endl;
		////////////////////////////////////////
		std::string flag2("\x5F\x10", 2);

		size_t it2 = info.find(flag2, it1 + len + 3);
		if (it2 == std::string::npos) {
			Output.close();
			return;
		}
		int len1 = info[it2 + 2] & 0xff;
		std::string ID;
		for (int i = 0; i < len1; i++) {
			if (info[i + it2 + 3] != '<') {
				ID.push_back(info[i + it2 + 3]);
			}
		}

		Output << ID << std::endl;
		Output.close();
		break;
	}
	case EF_DG12: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG12.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG12 = length;
		strncpy(ChipData_Doc9303_Result.pDG12, result, length);

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG13: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG13.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG13 = length;
		strncpy(ChipData_Doc9303_Result.pDG13, result, length);

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG14: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG14.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG14 = length;
		strncpy(ChipData_Doc9303_Result.pDG14, result, length);

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG15: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG15.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG15 = length;
		strncpy(ChipData_Doc9303_Result.pDG15, result, length);

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_DG16: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG16.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG16 = length;
		strncpy(ChipData_Doc9303_Result.pDG16, result, length);

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	case EF_SOD: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\EF_SOD.dat");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iSOD = length;
		strncpy(ChipData_Doc9303_Result.pSOD, result, length);

		if (Output) {
			Output.write(result, length);
			Output.close();
		}
		break;
	}
	default:
		break;
	}
}

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
	std::string ENC_RES;
	RND_IFD.resize(8);
	BuildRandomData(RND_IFD);
	if (RND_IFD.size() != 8) return false;
	string m_RND_ICC("\x00\x88\x00\x00\x08", 5);
	m_RND_ICC += RND_IFD;
	std::string RAPDU;
	int ret = PostPassportCommand(m_RND_ICC,RAPDU);
	if (!ret)
	{
		cout << "AA RND_IFD fail" << endl;
		return false;
	}
	else {
		ENC_RES = RAPDU;
	}
	std::ifstream file(DG15_file_path, std::ios::binary); // 打开文件	
	if (!file) {
		std::cerr << "DG15 not exists" << std::endl;
		return 1;
	}
	std::stringstream hex_stream;
	char byte;

	// 以16进制格式读取文件内容到字符串流中
	while (file.read(&byte, 1)) {
		hex_stream << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)byte;
	}
	file.close(); // 关闭文件
	std::string hex_string = hex_stream.str(); // 获取16进制字符串
	std::string bin_string = HexStringToBinary(hex_string);
	if (bin_string.find("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") != bin_string.npos)//RSA
	{
		cout << "AA:RSA\n";
		hex_string = hex_string.substr(6);
		std::cout << hex_string << std::endl;
		std::string base64str = hexToBase64(hex_string);
		std::string pubKey1 = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";
		string cipherText = StringToHex(ENC_RES);
		std::string decStr = rsa_pub_decrypt(ENC_RES, pubKey1,RSA_NO_PADDING);
		std::string hexDecStr = StringToHex(decStr);
		int D_length = -1;
		int t = 4;
		if (hexDecStr.substr(hexDecStr.length() - 2, 2) == "BC")
		{
			D_length = 2 * SHA_DIGEST_LENGTH;
			t = 2;
		}
		else if (hexDecStr.substr(hexDecStr.length() - 2, 2) == "CC")
		{
			if (hexDecStr.substr(hexDecStr.length() - 4, 2) == "38")
				D_length = 2 * SHA224_DIGEST_LENGTH;
			else if (hexDecStr.substr(hexDecStr.length() - 4, 2) == "34")
				D_length = 2 * SHA256_DIGEST_LENGTH;
			else if (hexDecStr.substr(hexDecStr.length() - 4, 2) == "36")
				D_length = 2 * SHA384_DIGEST_LENGTH;
			else if (hexDecStr.substr(hexDecStr.length() - 4, 2) == "35")
				D_length = 2 * SHA512_DIGEST_LENGTH;
		}
		std::string sha_D = hexDecStr.substr(hexDecStr.length() - D_length - t, D_length);
		std::string M1;
		if (hexDecStr.substr(0, 2) == "6A")
			M1 = hexDecStr.substr(2, hexDecStr.length() - 2 - D_length - t);
		else
		{
			cout << "head != 6A" << endl;
			return false;
		}
		std::string M_ = M1 + StringToHex(RND_IFD);
		std::string D_(D_length / 2, 0);
		std::string binaryM_ = HexToString(M_);
		if (D_length == 40)
			SHA1((unsigned char*)binaryM_.c_str(), binaryM_.length(), (unsigned char*)D_.data());
		else if (D_length == 2 * SHA224_DIGEST_LENGTH)
			SHA224((unsigned char*)binaryM_.c_str(), binaryM_.length(), (unsigned char*)D_.data());
		else if (D_length == 2 * SHA256_DIGEST_LENGTH)
			SHA256((unsigned char*)binaryM_.c_str(), binaryM_.length(), (unsigned char*)D_.data());
		else if (D_length == 2 * SHA384_DIGEST_LENGTH)
			SHA384((unsigned char*)binaryM_.c_str(), binaryM_.length(), (unsigned char*)D_.data());
		else if (D_length == 2 * SHA512_DIGEST_LENGTH)
			SHA512((unsigned char*)binaryM_.c_str(), binaryM_.length(), (unsigned char*)D_.data());
		std::string origin_D = StringToHex(D_);
		cout << cipherText << endl;
		bool result = (sha_D == origin_D);
		if (result)
			cout << "AA SUCCESS\n";
		else
			cout << "AA FAIL\n";
		return sha_D == origin_D;
	}
	else if (hex_string.find("2a8648ce3d0201") != hex_string.npos)//ECDSA
	{
		cout << "AA:ECDSA, not support";
		//TO DO: RECEIVE ECDSA SIGNATURE AND VERIFY IT
		return false;
	}
	
}

char PCSCReader::PassiveAuthentication(char* SOD_file_path) {
	std::string hash, signature;
	int hashLength;
	std::string hex = ReadFileContentsAsHex(SOD_file_path);
	int pos;
	if ((pos = hex.find("06096086480165030402")) != hex.npos)//0609608648016503040201
		hash = "SHA-2";
	else if (hex.find("06052B0E03021A") != hex.npos)
	{
		hash = "SHA-1";
		hashLength = SHA_DIGEST_LENGTH * 2;
	}

	if (hash == "SHA-2")
	{
		if (hex[pos + 21] == '1')
		{
			hash = "SHA-256";
			hashLength = SHA256_DIGEST_LENGTH * 2;
		}
		else if (hex[pos + 21] == '2')
		{
			hash = "SHA-384";
			hashLength = SHA384_DIGEST_LENGTH * 2;
		}
		else if (hex[pos + 21] == '3')
		{
			hash = "SHA-512";
			hashLength = SHA512_DIGEST_LENGTH * 2;
		}
		else if (hex[pos + 21] == '4')
		{
			hash = "SHA-224";
			hashLength = SHA224_DIGEST_LENGTH * 2;
		}
	}
	if (hex.find("06092A864886F70D010101") != hex.npos)
		signature = "RSA";
	else if (hex.find("06072A8648CE3D0201") != hex.npos)
		signature = "ECDSA";
	if (hex.size() < 1000) {
		return false;
	}
	cout << "PA:" << hash << ' ' << signature << endl;
	if (signature == "RSA")
	{
		//
		std::string RSA_Encryption_tag = "300D06092A864886F70D010101";
		pos = hex.find(RSA_Encryption_tag);
		std::string temp = hex.substr(0, pos);
		if (pos - temp.rfind("3082") == 8)
			pos = temp.rfind("3082");
		else if (pos - temp.rfind("3081") == 6)
			pos = temp.rfind("3081");
		else
		{
			while (pos - temp.rfind("30") != 4)
				temp = hex.substr(0, temp.rfind("30"));
			pos = temp.rfind("30");
		}//insure structure:sequence,sequence,objectidentifier,...
		std::string RSA_public_key = hex.substr(pos);

		std::string head;
		if(RSA_public_key.substr(2,2)=="82")
			head = RSA_public_key.substr(0, 8);
		else if(RSA_public_key.substr(2, 2) == "81")
			head = RSA_public_key.substr(0, 6);
		else 
			head = RSA_public_key.substr(0, 4);//insure head is right

		RSA_public_key = extractValueFromTLVHexString(RSA_public_key);
		RSA_public_key = head + RSA_public_key;
		std::string base64str = hexToBase64(RSA_public_key);
		std::string pubKey = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";

		std::string encryptedData_begin_tag = "0482";//assuming RSA public key length>=2048
		int encryptedData_begin = hex.rfind(encryptedData_begin_tag);
		encryptedData_begin += 8;
		std::string encryptedData = hex.substr(encryptedData_begin);
		encryptedData = hexString2String(encryptedData);
		std::string decStr = rsa_pub_decrypt(encryptedData, pubKey, RSA_NO_PADDING);

		std::string hexDecStr = StringToHex(decStr);
		std::string signature_dec = hexDecStr.substr(hexDecStr.size() - hashLength, hashLength);
		//
		std::string messageDigest;
		regex pattern("A0..30");
		std::vector<size_t> match_positions; // 用于存储匹配项的起始位置
		auto words_begin = std::sregex_iterator(hex.begin(), hex.end(), pattern);
		auto words_end = std::sregex_iterator();

		for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
			std::smatch match = *i;
			match_positions.push_back(match.position()); // 获取匹配的起始位置并存储
		}	
		for (int i = 0; i < match_positions.size(); i++)
			{
				messageDigest = hex.substr(match_positions[i]);
				messageDigest = extractValueFromTLVHexString(messageDigest);
				if (messageDigest.find("302F06092A864886F70D010904") != messageDigest.npos)
				{
					pos = match_positions[i];
					messageDigest = hex.substr(pos, 4) + messageDigest;
					break;
				}
			}
		if (pos == -1)
			return false;
		//复原成完整的der格式
		messageDigest[0] = '3';
		messageDigest[1] = '1';

		//计算签名
		//TODO:考虑RSA-PSS模式的签名
		std::string signature;
		std::string hashResult(hashLength / 2, 0);
		std::string binary_messageDigest = HexToString(messageDigest);
		if (hash == "SHA-1")
			SHA1((unsigned char*)binary_messageDigest.c_str(), binary_messageDigest.length(), (unsigned char*)hashResult.data());
		else if (hash == "SHA-256")
			SHA256((unsigned char*)binary_messageDigest.c_str(), binary_messageDigest.length(), (unsigned char*)hashResult.data());
		else if (hash == "SHA-384")
			SHA384((unsigned char*)binary_messageDigest.c_str(), binary_messageDigest.length(), (unsigned char*)hashResult.data());
		else if (hash == "SHA-512")
			SHA512((unsigned char*)binary_messageDigest.c_str(), binary_messageDigest.length(), (unsigned char*)hashResult.data());
		else if (hash == "SHA-244")
			SHA224((unsigned char*)binary_messageDigest.c_str(), binary_messageDigest.length(), (unsigned char*)hashResult.data());
		signature = StringToHex(hashResult);
		bool result = compare_ignore_case(signature, signature_dec);
		if (result)
			cout << "PA SUCCESS\n";
		else
			cout << "PA FAIL\n";
		return result;
	}
	else if (signature == "ECDSA")
	{
		//TODO:ECDSA
		cout << "PA ECDSA NOT SUPPORT\n";
		return false;
	}
	
	
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
	cout << "BAC success\n";
	//6.Build SSC
	CHECK_OK(BuildSSC(RND_IFD, RND_ICC, SSC));

	// 准备好 KSenc KSmac SSC 后，开始进行安全通信
	std::string EF_COM_Data;

	// 读取EF.COM文件，并检查该护照存在哪些文件
	CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, EF_COM, EF_COM_Data));
	char EF_COM_Path[512];
	MakeFullPath1(EF_COM_Path, EF_COM_FILENAME);
	std::ofstream  Output(EF_COM_Path, std::ios::binary);
	if (Output) {
		Output.write(EF_COM_Data.c_str(), EF_COM_Data.size());
		Output.close();
	}
	//std::string tags = EF_COM_TagsParse(EF_COM_Data);
	std::string tags = EF_COM_TagsParse(EF_COM_Data);

	//EFFileSystem efs;
	STEFFile* stFile = NULL;
	cout << "READING FILE, CONTAINS:\n";
	// 读取其他文件
	for (size_t i = 0; i < tags.size(); i++) {
		unsigned char b = tags[i];
		//cout << "tag" << b << endl;
		stFile = StTagFindEFFile(b, &st_efs);
		cout << stFile->name << '\n';
		if (NULL == stFile) {
			continue;
		}

		std::string ef_data;
		if (stFile->Index == EF_COM) {
			continue;
		}
		if (stFile->Index == EF_DG3)
			continue;
		// 如果该类型EF解析器未实现则不读该文件
		SelectFunc(stFile);
		if (!stFile->Valid()) {
			continue;
		}
		// 读取文件
		CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, stFile->Index, ef_data));
		// 解析文件
		if (stFile->FileParse(ef_data, &st_efs)) {

			ChipReaderReadFileResultOperate(stFile->Index, stFile->result, 2, stFile->resultLen);
			/*
				if (this->cb) {
					this->cb->OnChipReaderReadFileResult(stFile->Index, stFile->result,this->GetCardType());
				}*/
		}
	}
	//read SOD 必然存在
	std::string sod_data;

	CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, EF_SOD, sod_data));
	char EF_SOD_Path[512];
	MakeFullPath1(EF_COM_Path, EF_SOD_FILENAME);
	std::ofstream  Output_sod(EF_COM_Path, std::ios::binary);
	if (Output_sod) {
		Output_sod.write(sod_data.c_str(), sod_data.size());
		Output_sod.close();
	}
	ChipAuthenticResult.BAC = 1;

	//进行主动认证d
	char mypath[256];
	MakeFullPath1(mypath, "USB_TEMP\\DG15.dat");

	if (!ActiveAuthentication(mypath)) {
		std::cout << "ActiveAuthentication failed" << std::endl;
	}
	else {
		std::cout << "ActiveAuthentication success" << std::endl;
		ChipAuthenticResult.AA = 1;
	}
	
	//// passive auth
	//char SOD_file_path[256];
	//MakeFullPath1(SOD_file_path, "USB_TEMP\\EF_SOD.dat");
	//if (PassiveAuthentication(SOD_file_path)) {
	//	std::cout << "PassiveAuthentication success" << std::endl;
	//	ChipAuthenticResult.PA = 1;
	//}
	//else {
	//	std::cout << "PassiveAuthentication failed" << std::endl;
	//}

	return true;
}

char PCSCReader::PostPassportCommand(std::string& request, std::string& response)
{
	int ret = RF_ERR_FAILURE;
	int count = 0;
	unsigned char cpAPDU[512];
	unsigned int ipLen = request.size();
	unsigned int irLen = sizeof(cpAPDU);
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	wlString wlstring;

	

	try {
		
		ret = this->Apdusend(request, RecvBuff, RecvLen);
		//cout << "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
		
	}
	catch (std::exception& e) {
		return FALSE;
	}
	catch (...) {
		return FALSE;
	}
	if (RF_ERR_SUCCESS == ret) {
		std::string s((char*)&RecvBuff[0], RecvLen);
		
		response.append(s);
		char* sw = (char*)response.data() + response.size() - 2; //查看最后2个字节
		if (memcmp(sw, SW_SUCCESS, 2) != 0) {
			const char* sw = response.data();
			const short* ssw = (short*)sw;
			cout << "Post failed, SW=0x" << std::hex << std::setw(4) << std::setfill('0')
				<< HostToNetworkUINT16(*ssw) << "\n未找到成功标志" << std::endl;
			return FALSE;
		}
		response.erase(response.size() - 2, 2);
		return TRUE;
	}
	else {
		cout << "RF_14443_Apdu Return  : " << BinaryToHexString((const char*)cpAPDU) << std::endl;
	}
	return FALSE;
}

char PCSCReader::DirectReadEF(
	EF_NAME name,
	std::string& EF_Data) {
	STEFFile* stFile = StIndexFindEFFile(name, &st_efs);

	char ret = this->DirectCommunication(stFile, EF_Data);
	if (false == ret || EF_Data.size() == 0) {

		return false;
	}

	return true;
}

char PCSCReader::DirectCommunication(
	STEFFile* file,
	std::string& data) {
	char ret = false;

	// 1. 选择要读取的文件
	ret = this->DirectSelectFile(file);
	if (!ret) {
		return false;
	}
	// 2. 读取该文件的前4个字节
	std::string head4bytes;
	ret = this->DirectReadBinary(0, 4, head4bytes);
	if (!ret) {
		return false;
	}
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
		return false;
	}
	// 5. 读取剩余的数据
	if (len > 0) {
		std::string rest;
		ret = this->DirectReadFile(0, len, rest);
		if (!ret) {
			return false;
		}
		data.append(rest);
	}
	else if (len < 0) {
		// 非法的文件长度
		return false;
	}
	return true;
}

char PCSCReader::DirectSelectFile(
	STEFFile* file) {
	// 对未受保护的APDU命令进行填充
	std::string APDU("\x00\xA4\x02\x0C\x02", 5);
	APDU.push_back(file->Id[0]);
	APDU.push_back(file->Id[1]);

	// 发送APDU
	int dwLen = APDU.size();
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	wlString wlstring;
	int ret = this->Apdusend(APDU, RecvBuff, RecvLen);
	//cout << "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s((char*)&RecvBuff[0], RecvLen);
	std::string RAPDU;
	RAPDU.append(s);
	if (!ret) {
		return false;
	}
	return true;
}

char PCSCReader::DirectReadFile(
	unsigned short offset,
	unsigned short len,
	std::string& data) {
	const int chunkSize = 230;
	//assert(chunkSize >0 && chunkSize <= 230);

	int lastBytes = len % chunkSize;
	int chunks = len / chunkSize;

	for (int i = 0; i < chunks; i++) {
		std::string chunkData;
		char ret = this->DirectReadBinary(offset, chunkSize, chunkData);
		if (!ret) {

		}

		data.append(chunkData);
		offset += (unsigned short)chunkData.size();
	}

	if (lastBytes) {
		std::string chunkData;

		char ret = this->DirectReadBinary(offset, lastBytes, chunkData);
		if (!ret) {

			return false;
		}
		data.append(chunkData);
	}

	return true;
}

char PCSCReader::DirectReadBinary(
	unsigned short offset,
	unsigned short chunkSize,
	std::string& data) {
	// 创建未受保护的命令APDU, P1, P2未指定
	std::string APDU("\x00\xB0", 2);

	// a.1设置读取偏移, 设置P1, P2
	unsigned char p1p2[2];
	p1p2[0] = (unsigned char)(offset / 256);
	p1p2[1] = (unsigned char)(offset % 256);
	APDU.push_back(p1p2[0]);
	APDU.push_back(p1p2[1]);

	APDU.push_back((unsigned char)chunkSize);

	// g.接收机读旅行证件芯片的响应APDU
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	wlString wlstring;
	int ret = PostPassportCommand(APDU, data);
	if (!ret) {
		cout<<"Read Binary failed." << std::endl;
		return false;
	}
	//int ret = this->Apdusend(APDU, RecvBuff, RecvLen);
	////cout << "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	//std::string s((char*)&RecvBuff[0], RecvLen);
	//std::string RAPDU;
	//RAPDU.append(s);
	//if (!ret) {
	//	cout<<"Read Binary failed." << std::endl;
	//}
	//data.append(s);
	//char* sw = (char*)data.data() + data.size() - 2; //查看最后2个字节
	//if (memcmp(sw, SW_SUCCESS, 2) != 0) {
	//	const char* sw = data.data();
	//	const short* ssw = (short*)sw;
	//	cout << "Post failed, SW=0x" << std::hex << std::setw(4) << std::setfill('0')
	//		<< HostToNetworkUINT16(*ssw) << "\n未找到成功标志" << std::endl;
	//	return FALSE;
	//}
	//data.erase(data.size() - 2, 2);


	return true;
}

static void aes_cbc_decode(const std::string& key, std::string& inputdata, std::string& dec, std::string& iv_str, int keyLength) {

	unsigned char iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (int i = 0; i < 16; ++i) {
		iv[i] = iv_str[i];
	}
	std::string key_used;
	if (keyLength == 192)
		key_used = key.substr(0, 24);
	else
	key_used = key;
	AES_KEY aes_key;
	if (AES_set_decrypt_key((const unsigned char*)key_used.c_str(), key_used.length() * 8, &aes_key) < 0)
	{
		//assert(false);
		return;
	}
	std::string strRet;
	for (unsigned int i = 0; i < inputdata.length() / AES_BLOCK_SIZE; i++)
	{
		std::string str16 = inputdata.substr(i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		unsigned char out[AES_BLOCK_SIZE];
		::memset(out, 0, AES_BLOCK_SIZE);
		AES_cbc_encrypt((const unsigned char*)str16.c_str(), out, AES_BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);
		strRet += std::string((const char*)out, AES_BLOCK_SIZE);
	}
	dec = strRet;
	return ;
}

std::string int2Hex(int val) {
	std::stringstream ss;
	// 整数转换为大写的十六进制字符串，且每个字节占用两个字符的宽度
	ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << val;
	return ss.str();
}

BOOL PCSCReader::SelectPACE(std::string& oid)
{
	/// 选择PACE
	std::string selectPACECmd("\x00\x22\xC1\xA4\x0F\x80\x0A", 7);
	//std::string selectPACECmd("\x00\x22\xC1\xA4\x0F\x80\x0A\x04\x00\x7F\x00\x07\x02\x02\x04\x02\x04\x83\x01\x01", 20);

	selectPACECmd.append(oid);
	std::string tail("\x83\x01\x01", 3);
	selectPACECmd.append(tail);
	//00A4040C07A0000002471001
	std::string selectPACERAPDU;
	auto cmd_hex = BinaryToHexString(selectPACECmd);
	BYTE  RecvBuff[300];
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	BOOL ret = Apdusend(selectPACECmd, RecvBuff, RecvLen);
	//cout << "选择签发者应用返回： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;

	if (ret < 0) {
		return FALSE;
	}

	return TRUE;
}

BOOL PCSCReader::ICCRequestRandomNumberPACE(std::string& ICC_Z) {
	std::string randCmd("\x10\x86\x00\x00\x02\x7C\x00\x00", 8);


	std::string RAPDU;
	int ret = PostPassportCommand(randCmd, RAPDU);
	//cout << "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;

	if (!ret || RAPDU.size() != 20) {

		return FALSE;
	}
	ICC_Z = RAPDU.substr(4, 16);

	return TRUE;
}

BOOL PCSCReader::BuildKpai(
	__in const std::string& mrzInfo,
	__out std::string& Kpai,
	__out std::string& digestAlgorithm)
{
	std::string mrzInfoSha1(20, 0);

	SHA1((BYTE*)mrzInfo.data(), mrzInfo.size(), (BYTE*)mrzInfoSha1.data());

	// SHA1 to Kenc Kmac
	std::string c3("\x00\x00\x00\x03", 4);

	// Kseed concat c3 into D3 
	mrzInfoSha1.append(c3.data(), c3.size());
	// SHA mrzInfoSha1
	if (digestAlgorithm == "SHA-256")
	{
		std::string K_pi(32, 0);
		SHA256((BYTE*)mrzInfoSha1.data(), mrzInfoSha1.size(), (BYTE*)K_pi.data());
		if (K_pi.size() < 32) {
			return FALSE;
		}
		Kpai = K_pi;


		auto Kpaihex = BinaryToHexString(Kpai);
		cout << "kpai"<<endl<<Kpaihex << endl;
		
	}
	else if (digestAlgorithm == "SHA-1")
	{
		std::string K_pi(16, 0);
		SHA1((BYTE*)mrzInfoSha1.data(), mrzInfoSha1.size(), (BYTE*)K_pi.data());
		if (K_pi.size() < 16) {
			return FALSE;
		}
		Kpai = K_pi;


		auto Kpaihex = BinaryToHexString(Kpai);
		cout << "kpai" << endl << Kpaihex << endl;
	}
	

	return TRUE;
}

BOOL PCSCReader::BuildKencandKmacPACE(
	__in const std::string& KA,
	__in int keyLength,
	__in std::string cipherAlgorithm,
	__out std::string& KSenc,
	__out std::string& KSmac)
{
	// SHA1 to Kenc Kmac
	std::string c1("\x00\x00\x00\x01", 4);
	std::string c2("\x00\x00\x00\x02", 4);
	std::string D1, D2;
	std::string Kseed = HexStringToBinary(KA);
	// Kseed concat c3 into D3 
	D1.append(Kseed.data(), Kseed.size());
	D1.append(c1.data(), c1.size());
	D2.append(Kseed.data(), Kseed.size());
	D2.append(c2.data(), c2.size());
	if ( keyLength == 256|| keyLength == 192)
	{
		std::string HD1(32, 0), HD2(32, 0);
		// SHA256 HD1,HD2
		SHA256((BYTE*)D1.data(), D1.size(), (BYTE*)HD1.data());
		SHA256((BYTE*)D2.data(), D2.size(), (BYTE*)HD2.data());

		if (keyLength == 256)
		{
			KSenc = HD1;
			KSmac = HD2;
		}
		else if (keyLength == 192)
		{
			KSenc = HD1.substr(0, 24);
			KSmac = HD2.substr(0, 24);
		}
		
	}
	else if (keyLength == 128)
	{
		std::string HD1(20, 0), HD2(20, 0);
		// SHA-1 HD1,HD2
		SHA1((BYTE*)D1.data(), D1.size(), (BYTE*)HD1.data());
		SHA1((BYTE*)D2.data(), D2.size(), (BYTE*)HD2.data());
		if (cipherAlgorithm == "AES")
		{
			KSenc = HD1.substr(0, 16);
			KSmac = HD2.substr(0, 16);
		}
		else if (cipherAlgorithm == "DESede")
		{
			std::string HD11 = HD1.substr(0, 8);
			std::string HD12 = HD1.substr(8, 8);
			std::string HD21 = HD2.substr(0, 8);
			std::string HD22 = HD2.substr(8, 8);
			std::string HD11_checked = "";
			std::string HD12_checked = "";
			std::string HD21_checked = "";
			std::string HD22_checked = "";
			CheckParity(HD11, HD11_checked, 8);
			CheckParity(HD12, HD12_checked, 8);
			CheckParity(HD21, HD21_checked, 8);
			CheckParity(HD22, HD22_checked, 8);
			KSenc = HD11_checked + HD12_checked;
			KSmac = HD21_checked + HD22_checked;
		}
	}
	auto KSenc_hex = BinaryToHexString(KSenc);
	auto KSmac_hex = BinaryToHexString(KSmac);
	cout << "KSenc " << KSenc_hex << endl << "KSmac "<<KSmac_hex << endl;
	return TRUE;
}

BOOL PCSCReader::BuildMapKey(std::string& PKmap, std::string& SKmap, int ecc_id) {
	EC_GROUP* ec_group = EC_GROUP_new(EC_GFp_mont_method());
	DH* dh = DH_new();
	if (ecc_id > 2)
	{
		if(ecc_id != 12)
			ec_group = EC_GROUP_new_by_curve_name(ecc_id);
		else 
			int ret = Buildsecp256r1(ec_group);
		if (!ec_group) {
			cerr << "Failed to create EC group" << endl;
			return 1;
		}
		// 创建 EC_KEY 对象
		EC_KEY* ec_key = EC_KEY_new();
		if (!ec_key) {
			cerr << "Failed to create EC key" << endl;
			EC_GROUP_free(ec_group);
			return FALSE;
		}
		// 设置椭圆曲线参数
		if (!EC_KEY_set_group(ec_key, ec_group)) {
			cerr << "Failed to set EC group" << endl;
			EC_KEY_free(ec_key);
			return FALSE;
		}
		// 生成本地密钥
		if (!EC_KEY_generate_key(ec_key)) {
			cerr << "Failed to generate EC key" << endl;
			EC_KEY_free(ec_key);
			return 1;
		}

		// 获取终端映射密钥对
		const BIGNUM* private_key_out = EC_KEY_get0_private_key(ec_key);
		char* private_key_hex_char = BN_bn2hex(private_key_out);
		SKmap = private_key_hex_char;
		cout << "SKMAP " << SKmap << endl;
		SKmap = HexStringToBinary(SKmap);

		const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key);
		BIGNUM* public_key_bn = EC_POINT_point2bn(ec_group, public_key, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
		char* public_key_hex_char = BN_bn2hex(public_key_bn);
		PKmap = public_key_hex_char;
		cout << "PKMAP " << PKmap << endl;
		PKmap = HexStringToBinary(PKmap);
	}
	else if (ecc_id >= 0 && ecc_id <= 2)
	{
		int ret = BuildGFP(dh, ecc_id);
		ret = DH_generate_key(dh);
		const BIGNUM* priv= DH_get0_priv_key(dh);
		const BIGNUM* pub = DH_get0_pub_key(dh);
		char* PKmap_hex = BN_bn2hex(pub);
		char* SKmap_hex = BN_bn2hex(priv);
		cout << "pkmap " << PKmap_hex << "\nskmap " << SKmap_hex << endl;
		PKmap = HexStringToBinary(PKmap_hex);
		SKmap = HexStringToBinary(SKmap_hex);

	}
	
}

BOOL PCSCReader::RandomNumberMap(std::string& PKmap_IC, const std::string& PKmap, const std::string& SKmap) {
	std::string sendPKmapCmd("\x10\x86\x00\x00", 4);
	//终端向芯片发送 PKmap
		
	int PKmap_len = PKmap.size();
	int Auth_len, Cmd_len;
	if (PKmap_len == 129 || PKmap_len == 133)
	{
		Auth_len = PKmap_len + 3;
		Cmd_len = Auth_len + 3;
		sendPKmapCmd.push_back(Cmd_len);
		sendPKmapCmd.append("\x7C");
		sendPKmapCmd.push_back('\x81');
		sendPKmapCmd.push_back(Auth_len);
		sendPKmapCmd.append("\x81");
		sendPKmapCmd.append("\x81");
		sendPKmapCmd.push_back(PKmap_len);
		sendPKmapCmd.append(PKmap);
		sendPKmapCmd.push_back(0);
	}
	else
	{
		Auth_len = PKmap_len + 2;
		Cmd_len = Auth_len + 2;
		sendPKmapCmd.push_back(Cmd_len);
		sendPKmapCmd.append("\x7C");
		sendPKmapCmd.push_back(Auth_len);
		sendPKmapCmd.append("\x81");
		sendPKmapCmd.push_back(PKmap_len);
		sendPKmapCmd.append(PKmap);
		sendPKmapCmd.push_back(0);
	}

	auto sendPKmapCmd_str = BinaryToHexString(sendPKmapCmd);
	std::string RAPDU;

	int ret = PostPassportCommand(sendPKmapCmd, RAPDU);
	if (!ret || RAPDU.size() < Auth_len) {
		cout << "Failed to send PKmap,Return " << ret << endl;
		return FALSE;
	}
	if (PKmap_len == 129 || PKmap_len == 133)
	{
		PKmap_IC = RAPDU.substr(7, RAPDU.size() - 7);
		return TRUE;
	}
	PKmap_IC = RAPDU.substr(5, RAPDU.size() - 5);
	return TRUE;
}


BOOL PCSCReader::MutualAuthenticate(EC_POINT* G_hat, std::string& PKDH_IC, std::string& SKDH_IFD, std::string& PKDH_IFD, int ecc_id) {
	EC_GROUP* ec_group_temp;
	// 创建 EC_KEY 对象
	if (ecc_id != 12)
		ec_group_temp = EC_GROUP_new_by_curve_name(ecc_id);
	else
		Buildsecp256r1(ec_group_temp);
	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	const BIGNUM* order = EC_GROUP_get0_order(ec_group_temp);
	const BIGNUM* cofactor = EC_GROUP_get0_cofactor(ec_group_temp);
	EC_GROUP_get_curve(ec_group_temp, p, a, b, NULL);

	BN_CTX* ctx = BN_CTX_new();
	EC_GROUP* new_curve = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	EC_GROUP_set_generator(new_curve, G_hat, order, cofactor);

	EC_KEY* ec_key = EC_KEY_new();
	if (!ec_key) {
		cerr << "Failed to create EC key" << endl;
		EC_GROUP_free(ec_group_temp);
		return FALSE;
	}
	// 设置椭圆曲线参数
	if (!EC_KEY_set_group(ec_key, new_curve)) {
		cerr << "Failed to set EC group" << endl;
		EC_KEY_free(ec_key);
		return FALSE;
	}
	// 生成本地密钥
	if (!EC_KEY_generate_key(ec_key)) {
		cerr << "Failed to generate EC key" << endl;
		EC_KEY_free(ec_key);
		return 1;
	}
	// 生成终端公私钥对
	const BIGNUM* private_key_out = EC_KEY_get0_private_key(ec_key);
	char* private_key_hex_char = BN_bn2hex(private_key_out);
	SKDH_IFD = private_key_hex_char;
	cout << "SKDHIFD " << SKDH_IFD << endl;
	SKDH_IFD = HexStringToBinary(SKDH_IFD);

	const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key);
	BIGNUM* public_key_bn = EC_POINT_point2bn(new_curve, public_key, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
	char* public_key_hex_char = BN_bn2hex(public_key_bn);
	std::string PKDH_IFD_hex = public_key_hex_char;
	cout << "PKDFIFD_HEX " << PKDH_IFD_hex << endl;
	PKDH_IFD= HexStringToBinary(PKDH_IFD_hex);

	//终端向芯片发送公钥 PKDF_IFD
	std::string sendPKmapCmd("\x10\x86\x00\x00", 4);
	unsigned int PKmap_len = PKDH_IFD.size();
	int Auth_len, Cmd_len;
	if (PKmap_len == 129 || PKmap_len == 133)
	{
		Auth_len = PKmap_len + 3;
		Cmd_len = Auth_len + 3;
		sendPKmapCmd.push_back(Cmd_len);
		sendPKmapCmd.push_back('\x7C');
		sendPKmapCmd.push_back('\x81');
		sendPKmapCmd.push_back(Auth_len);
		sendPKmapCmd.push_back('\x83');
		sendPKmapCmd.push_back('\x81');
		sendPKmapCmd.push_back(PKmap_len);
		sendPKmapCmd.append(PKDH_IFD);
		sendPKmapCmd.push_back(0);
	}
	else
	{
		Auth_len = PKmap_len + 2;
		Cmd_len = Auth_len + 2;
		sendPKmapCmd.push_back(Cmd_len);
		sendPKmapCmd.push_back('\x7C');
		sendPKmapCmd.push_back(Auth_len);
		sendPKmapCmd.push_back('\x83');
		sendPKmapCmd.push_back(PKmap_len);
		sendPKmapCmd.append(PKDH_IFD);
		sendPKmapCmd.push_back(0);
	}

	auto sendPKmapCmd_str = BinaryToHexString(sendPKmapCmd);
	std::string RAPDU;

	int ret = PostPassportCommand(sendPKmapCmd, RAPDU);
	if (!ret || RAPDU.size() < Auth_len) {
		cout << "Failed to send PKmap,Return " << ret << endl;
		return FALSE;
	}
	cout << "RAPDU " << BinaryToHexString(RAPDU) << endl;
	if (PKmap_len == 129 || PKmap_len == 133)
		PKDH_IC = RAPDU.substr(7, RAPDU.size() - 7);
	else
		PKDH_IC = RAPDU.substr(5, RAPDU.size() - 5);
	//去除头部的"\x04"字节
	PKDH_IFD = PKDH_IFD.substr(1, PKDH_IFD.size() - 1);
	return TRUE;
}
BOOL PCSCReader::MutualAuthenticate(BIGNUM*& G_hat, std::string& PKDH_IC, std::string& SKDH_IFD, std::string& PKDH_IFD, BIGNUM*& prime)
{
	int ret = -1;
	DH* dh_temp = DH_new();
	ret = DH_set0_pqg(dh_temp,prime,NULL,G_hat);
	BN_CTX* ctx = BN_CTX_new();
	ret = DH_generate_key(dh_temp);
	if (!ret)
		cout << "fail to generate key pair" << endl;
	const BIGNUM* public_key = BN_new();
	const BIGNUM* private_key = BN_new();
	public_key = DH_get0_pub_key(dh_temp);
	private_key = DH_get0_priv_key(dh_temp);
	std::string PKDH_IFD_hex, SKDH_IFD_hex;
	PKDH_IFD_hex = BN_bn2hex(public_key);
	SKDH_IFD_hex = BN_bn2hex(private_key);
	cout << "PKDH_IFD_hex" << endl << PKDH_IFD_hex << endl;
	cout << "SKDH_IFD_hex" << endl << SKDH_IFD_hex << endl;
	PKDH_IFD = HexStringToBinary(PKDH_IFD_hex);
	SKDH_IFD = HexStringToBinary(SKDH_IFD_hex);
	
	std::string sendPKmapCmd("\x10\x86\x00\x00", 4);
	unsigned int PKmap_len = PKDH_IFD.size();
	cout << "PKmap_len " << PKmap_len << endl;
	if (PKmap_len == 128)
	{
		sendPKmapCmd.append("\x86");
		sendPKmapCmd.append("\x7C\x81\x83");
		sendPKmapCmd.append("\x81\x81\x80");
		sendPKmapCmd.append(PKDH_IFD);
		sendPKmapCmd.push_back(0);
	}
	else if (PKmap_len == 256)
	{
		sendPKmapCmd.append("\x00\x01\x08");
		sendPKmapCmd.append("\x7C\x82\x01\x04");
		sendPKmapCmd.append("\x81\x82\x01\x00");
		sendPKmapCmd.append(PKDH_IFD);
		sendPKmapCmd.push_back(0);
	}
	auto sendPKmapCmd_str = BinaryToHexString(sendPKmapCmd);
	std::string RAPDU;

	ret = PostPassportCommand(sendPKmapCmd, RAPDU);
	if (!ret) {
		cout << "Failed to send PKmap,Return " << ret << endl;
		return FALSE;
	}
	if (PKmap_len == 128)
	{
		PKDH_IC = RAPDU.substr(6, RAPDU.size() - 6);
	}
	else if (PKmap_len == 256)
	{
		PKDH_IC = RAPDU.substr(8, RAPDU.size() - 8);
	}
	cout << "PKDH_IC " << PKDH_IC << endl;
	return TRUE;
}
BOOL PCSCReader::ExchangeT(std::string& TIFD, std::string& TICC_my) {

	//终端向芯片发送 PKmap
	std::string sendTIFD("\x00\x86\x00\x00\x0C\x7C\x0A\x85\x08", 9);
	sendTIFD.append(TIFD);
	sendTIFD.push_back(0);

	auto sendTIFD_str = BinaryToHexString(sendTIFD);
	std::string RAPDU;

	int ret = PostPassportCommand(sendTIFD, RAPDU);
	if (!ret || RAPDU.size() < 8) {
		cout << "Failed to send TIFD,Return " << ret << endl;
		return FALSE;
	}
	std::string TICC = RAPDU.substr(4, RAPDU.size() - 4);
	if(memcmp(TICC.data(), TICC_my.data(), 8) != 0) {
		return FALSE;
	}
	
	return TRUE;
}

char PCSCReader::SecureCommunicationSeletAPPPACE(
	std::string& cmdData,
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	int keyLength,
	const std::string& cipherAlgorithm) {

	// 对未受保护的APDU命令进行填充
	std::string unprotectedAPDU("\x0C\xA4\x04\x0C", 4);
	std::string CmdHeader(unprotectedAPDU);
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(CmdHeader);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(CmdHeader);
	std::string strFillData;
	//if(strlen(file->Id) >= 2){
	//LOGV("file.Id.size() ==  %s", file.Id.size());
	//	LOGV("fild->Id:  %s", file->Id);
	//	LOGV("file->Id[0] == %02x;file->Id[1] == %02x\n",file->Id[0],file->Id[1]);
	strFillData.append(cmdData);
	/*}else{

		LOGV("file.Id.size() ==  %s", strlen(file->Id));
		LOGV("fild.Id:  %s", file->Id);
		return  false;
	}
*/
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(strFillData);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(strFillData);
	// 用SKenc加密数据
	std::string strEncData;
	//KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	//加密SSC
	std::string iv = "";
	if (cipherAlgorithm == "AES")
		iv = "00000000000000000000000000000000";
	iv = HexStringToBinary(iv);
	IncreaseSSC(SSC); //SSC += 1
	auto KSenc_hex = BinaryToHexString(KSenc);
	if (cipherAlgorithm == "AES")
	{
		std::string SSC_IV;
		aes_cbc_encode(KSenc, SSC, SSC_IV, iv);
		auto SSC_IV_hex = BinaryToHexString(SSC_IV);
		auto strFillData_hex = BinaryToHexString(strFillData);
		aes_cbc_encode(KSenc, strFillData, strEncData, SSC_IV);
		auto strEncData_hex = BinaryToHexString(strEncData);
	}
	else if (cipherAlgorithm == "DESede")
	{
		KencTDES(strFillData,KSenc, strEncData,DES_ENCRYPT);
	}
	// 构建DO87,并置cmdheader和DO87得到M
	std::string DO87;
	unsigned char L = (unsigned char)strFillData.size() + 1;
	unsigned char x87 = 0x87;
	DO87.push_back(x87);
	DO87.push_back(L);
	DO87.push_back(0x01);
	DO87.append(strEncData);
	std::string M = CmdHeader + DO87;


	// 连接SSC和M，并增加填充得到N
	std::string N;
	N.append(SSC.data(), SSC.size());
	N.append(M.data(), M.size());
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(N);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(N);
	// 用SKmac计算N的消息认证码MAC
	std::string CCN;
	//KmacDES(N, KSmac, CCN);
	if (cipherAlgorithm == "AES")
		AESmac(KSmac, N, CCN, keyLength);
	else if (cipherAlgorithm == "DESede")
		KmacDES(N,KSmac,CCN);
	// 用CCN构建DO8E
	std::string DO8E("\x8E\x08", 2);
	DO8E.append(CCN.data(), CCN.size());

	// 构建受保护的APDU
	std::string APDU;
	std::string unprotectedAPDU2("\x0C\xA4\x04\x0C", 4);
	APDU.append(unprotectedAPDU2.data(), unprotectedAPDU2.size());
	unsigned char le_ = (unsigned char)DO87.size() + (unsigned char)DO8E.size();
	APDU.push_back(le_);//DO87+DO8E
	APDU.append(DO87.data(), DO87.size());
	APDU.append(DO8E.data(), DO8E.size());
	/*
	 这里应该多加一个字节，中国护照可以不需要，但是国外的护照如果不加
	 这个字节，调用会失败
	 */
	APDU.push_back(0);
	// 发送APDU
	int dwLen = APDU.size();
	auto APDU_hex = BinaryToHexString(APDU);
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	this->Apdusend(APDU, RecvBuff, RecvLen);
	//cout << "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s((char*)&RecvBuff[0], RecvLen);
	std::string RAPDU;//无响应数据，只有SW1 SW2，DO99+8E+08+CC+SW1+SW2
	RAPDU.append(s);
	//std::string RAPDU = BYTE2string(RecvBuff, RecvLen).substr(0, RecvLen - 2);
	IncreaseSSC(SSC); //SSC += 1
	// 连接SSC和DO99， 并填充得到K
	std::string DO99 = RAPDUParse(RAPDU, 0x99);
	std::string K(SSC);
	K += DO99;
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(K);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(K);
	// 用SKmac计算K的消息认证码MAC
	std::string CCK;
	if (cipherAlgorithm == "AES")
		AESmac(KSmac, K, CCK, keyLength);
	else if (cipherAlgorithm == "DESede")
		KmacDES(K,KSmac,CCK);
	// 从RAPDU中提取出DO8Er，验证是否等于CCK
	std::string RAPDU_DO8E = RAPDUParse(RAPDU, 0x8E);
	if (memcmp(RAPDU_DO8E.data() + 2, CCK.data(), 8) != 0) {
		return false;
	}
	return true;
}

char PCSCReader::ICCReadEFPACE(std::string& KSenc, std::string& KSmac, std::string& SSC, EF_NAME name,
	std::string& EF_Data, int keyLength,const std::string& cipherAlgorithm) {
	STEFFile* stFile = StIndexFindEFFile(name, &st_efs);
	char ret = this->SecureCommunicationPACE(stFile, KSenc, KSmac, SSC, EF_Data, keyLength, cipherAlgorithm);
	if (false == ret || EF_Data.size() == 0) {
		return false;
	}

	return true;
}

char PCSCReader::SecureCommunicationPACE(
	STEFFile* file,
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	std::string& data,
	int keyLength,
	const std::string& cipherAlgorithm) {
	char ret = false;

	// 1. 选择要读取的文件
	ret = this->SecureCommunicationSelectFilePACE(file, KSenc, KSmac, SSC,keyLength,cipherAlgorithm);
	if (!ret) {
		return false;
	}
	// 2. 读取该文件的前4个字节
	std::string head4bytes;
	ret = this->SecureCommunicationReadBinaryPACE(KSenc, KSmac, SSC, 0, 4, head4bytes,keyLength,cipherAlgorithm);
	if (!ret) {
		return false;
	}
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
		return false;
	}
	// 5. 读取剩余的数据
	if (len > 0) {
		std::string rest;
		ret = this->SecureCommunicationReadFilePACE(KSenc, KSmac, SSC, 0, len, rest, keyLength, cipherAlgorithm);
		if (!ret) {
			return false;
		}
		data.append(rest);
		file->resultLen = data.length();
	}
	else if (len < 0) {
		// 非法的文件长度
		//throw std::exception("invalid EF file length");
		return false;
	}
	return true;
}

char PCSCReader::SecureCommunicationSelectFilePACE(
	STEFFile* file,
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	int keyLength,
	const std::string& cipherAlgorithm) {

	// 对未受保护的APDU命令进行填充
	std::string unprotectedAPDU("\x0C\xA4\x02\x0C", 4);
	std::string CmdHeader(unprotectedAPDU);
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(CmdHeader);
	else if (cipherAlgorithm == "DESede")
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
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(strFillData);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(strFillData);
	// 用SKenc加密数据
	std::string strEncData;
	//KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	//加密SSC
	std::string iv = "";
	if (cipherAlgorithm == "AES")
		iv = "00000000000000000000000000000000";
	iv = HexStringToBinary(iv);
	IncreaseSSC(SSC); //SSC += 1
	std::string SSC_IV;
	auto KSenc_hex = BinaryToHexString(KSenc);
	if (cipherAlgorithm == "AES")
	{
		aes_cbc_encode(KSenc, SSC, SSC_IV, iv);
		auto SSC_IV_hex = BinaryToHexString(SSC_IV);
		auto strFillData_hex = BinaryToHexString(strFillData);
		aes_cbc_encode(KSenc, strFillData, strEncData, SSC_IV);
	}
	else if (cipherAlgorithm == "DESede")
		KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	auto strEncData_hex = BinaryToHexString(strEncData);


	// 构建DO87,并置cmdheader和DO87得到M
	std::string DO87;
	unsigned char L = (unsigned char)strFillData.size() + 1;
	unsigned char x87 = 0x87;
	DO87.push_back(x87);
	DO87.push_back(L);
	DO87.push_back(0x01);
	DO87.append(strEncData);
	std::string M = CmdHeader + DO87;


	// 连接SSC和M，并增加填充得到N
	std::string N;
	N.append(SSC.data(), SSC.size());
	N.append(M.data(), M.size());
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(N);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(N);
	// 用SKmac计算N的消息认证码MAC
	std::string CCN;
	//KmacDES(N, KSmac, CCN);
	if (cipherAlgorithm == "AES")
		AESmac(KSmac, N, CCN, keyLength);
	else if (cipherAlgorithm == "DESede")
		KmacDES(N,KSmac,CCN);
	// 用CCN构建DO8E
	std::string DO8E("\x8E\x08", 2);
	DO8E.append(CCN.data(), CCN.size());

	// 构建受保护的APDU
	std::string APDU;
	std::string unprotectedAPDU2("\x0C\xA4\x02\x0C", 4);
	APDU.append(unprotectedAPDU2.data(), unprotectedAPDU2.size());
	int size = DO87.size() + DO8E.size();
	APDU.push_back(size);
	//APDU.append("\x1D", 1);
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
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(K);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(K);
	// 用SKmac计算K的消息认证码MAC
	std::string CCK;
	if (cipherAlgorithm == "AES")
		AESmac(KSmac, K, CCK, keyLength);
	else if (cipherAlgorithm == "DESede")
		KmacDES(K,KSmac,CCK);
	// 从RAPDU中提取出DO8Er，验证是否等于CCK
	std::string RAPDU_DO8E = RAPDUParse(RAPDU, 0x8E);
	if (memcmp(RAPDU_DO8E.data() + 2, CCK.data(), 8) != 0) {
		return false;
	}
	return true;
}

char PCSCReader::SecureCommunicationReadBinaryPACE(
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	unsigned short offset,
	unsigned short chunkSize,
	std::string& data,
	int keyLength,
	const std::string& cipherAlgorithm) {
	// 创建未受保护的命令APDU, P1, P2未指定
	std::string unprotectedAPDU("\x0C\xB0\x00\x00", 4);
	//没有DO85/DO87
	// a.1设置读取偏移, 设置P1, P2
	unsigned short* apdu_len = (unsigned short*)(unprotectedAPDU.data() + 2);
	*apdu_len = HostToNetworkUINT16(offset);

	// a. 设置读取偏移， 创建并填充命令报头
	std::string CmdHeader(unprotectedAPDU);
	// a.2 创建并填充命令报头
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(CmdHeader);
	else if (cipherAlgorithm == "DESede")
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
	N.append(M);//报文在SSC之前，实现时低位在前
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(N);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(N);

	// d.3用KSmac计算N的MAC
	std::string CC;
	if (cipherAlgorithm == "AES")
		AESmac(KSmac, N, CC, keyLength);
	else if (cipherAlgorithm == "DESede")
		KmacDES(N,KSmac,CC);
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
	RAPDU_DO99 = RAPDUParse(RAPDU, 0x99);

	// h.1 用1为SSC增值
	IncreaseSSC(SSC);

	// h.2 并置SSC, DO87和DO99，并增加填充
	std::string K(SSC);
	K += RAPDU_DO87;
	K += RAPDU_DO99;
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(K);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(K);
	// h.3 用KSmac计算MAC
	std::string CC2;
	if (cipherAlgorithm == "AES")
		AESmac(KSmac, K, CC2, keyLength);
	else if (cipherAlgorithm == "DESede")
		KmacDES(K,KSmac,CC2);
	// h.4 将CC与RAPDU的DO8E数据作比较
	if (memcmp(CC2.data(), RAPDU_DO8E.data() + 2, 8) != 0) {
#if USE_LOG_LEVEL1
		LOGV("DO8E and CC2 mismatch in Reading binary");
#endif
		return false;
	}
	// i. 用KSenc解密DO87数据
	std::string RAPDU_DO87_DATA = RAPDU_DO87.substr(tlLen + 1);
	//KencTDES(RAPDU_DO87_DATA, KSenc, data, DES_DECRYPT);
	std::string iv_hex = "";
	std::string SSC_IV;
	if (cipherAlgorithm == "AES")
	{
		iv_hex = "00000000000000000000000000000000";
		auto iv = HexStringToBinary(iv_hex);
		aes_cbc_encode(KSenc, SSC, SSC_IV, iv);
		auto RAPDU_DO87_DATA_hex = BinaryToHexString(RAPDU_DO87_DATA);
		auto KSenc_hex = BinaryToHexString(KSenc);
		auto SSC_IV_hex = BinaryToHexString(SSC_IV);
		aes_cbc_decode(KSenc, RAPDU_DO87_DATA, data, SSC_IV, keyLength);
	}
		
	else if (cipherAlgorithm == "DESede")
	{
		auto RAPDU_DO87_DATA_hex = BinaryToHexString(RAPDU_DO87_DATA);
		auto KSenc_hex = BinaryToHexString(KSenc);
		KencTDES(RAPDU_DO87_DATA, KSenc, data, DES_DECRYPT);
	}
	DesRemovePaddingBytes(data);

	return true;
}

char PCSCReader::SecureCommunicationReadFilePACE(
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	unsigned short offset,
	unsigned short len,
	std::string& data,
	int keyLength,
	const std::string& cipherAlgorithm) {
	//BAC是230,但是实测此处只能读出来223字节
	const int chunkSize = 223;
	int lastBytes = len % chunkSize;
	int chunks = len / chunkSize;

	for (int i = 0; i < chunks; i++) {
		std::string chunkData;

		char ret = this->SecureCommunicationReadBinaryPACE(KSenc, KSmac, SSC, offset, chunkSize,
			chunkData,keyLength,cipherAlgorithm);
		if (!ret) {
			return false;
		}
		data.append(chunkData);
		offset += (unsigned short)chunkData.size();
	}

	if (lastBytes) {
		std::string chunkData;
		char ret = this->SecureCommunicationReadBinaryPACE(KSenc, KSmac, SSC, offset, lastBytes,
			chunkData, keyLength, cipherAlgorithm);
		if (!ret) {
			return false;
		}
		data.append(chunkData);
	}
	return true;
}
BOOL PCSCReader::map_G_hat(BIGNUM*& G_hat, std::string& S_ICC, std::string& cipherAlgorithm, int keyLength)
{
	return true;
}

BOOL PCSCReader::map_G_hat(EC_POINT*& G_hat, std::string& S_ICC, std::string& cipherAlgorithm, int keyLength)
{
	return true;
}

BOOL PCSCReader::ReadEChipInfoPACE(std::string& codetonfc) {
	/*string Z_ICC = "65517B50789441DFC00701B3843D479D";
	Z_ICC = HexStringToBinary(Z_ICC);
	string Kpai = "1334577991abcde01334577991abcde0";
	Kpai = HexStringToBinary(Kpai);
	string hexstring1, hexstring2;
	CheckParity(Kpai.substr(0, 8), hexstring1, 8);
	CheckParity(Kpai.substr(8, 8), hexstring2, 8);
	string kpai1 = hexstring1 + hexstring2;
	cout << BinaryToHexString(hexstring1) << endl << BinaryToHexString(hexstring1) << endl;
	string S_ICC = "";
	KencTDES(Z_ICC, kpai1, S_ICC, DES_DECRYPT);
	cout << BinaryToHexString(S_ICC) << endl;
	return true;*/
	//jie mi sui ji shu ce shi dai ma 
	// 
	//
	//读取CardAccess确定加密参数
	/*string message = HexStringToBinary("1234567890ABCDE");
	size_t dsize = message.size();
	int iter = message.size() / 8;
	std::string enKey, deKey;
	string KS = HexStringToBinary("1334577991abcde01334577991abcde0");
	enKey.append(KS.data(), 8);
	deKey.append(KS.data() + 8, 8);
	std::string inBuffer(8, 0);
	DES_cblock out;
	DES_key_schedule enSchKey, deSchKey;
	DES_set_key_unchecked((const_DES_cblock*)enKey.data(), &enSchKey);
	DES_set_key_unchecked((const_DES_cblock*)deKey.data(), &deSchKey);
	inBuffer.assign(message.data() + (iter - 1) * 8, 8);
	DES_ecb3_encrypt((const_DES_cblock*)inBuffer.data(), &out, &enSchKey, &deSchKey, &enSchKey, DES_ENCRYPT);
	std::string strDesBlock(reinterpret_cast<char*>(out), sizeof(out));
	string T = strDesBlock;
	cout << BinaryToHexString(T) << endl;
	return 1;*/
	//3des ling shou mo shi ce shi dai ma
	//
	//

	std::string cardAccessData;
	CHECK_OK(DirectReadEF(EF_CardAccess, cardAccessData));

	char EF_CardAccess_Path[512];
	MakeFullPath1(EF_CardAccess_Path, EF_CARDACCESS_FILENAME);
	std::ofstream  OutputAccess(EF_CardAccess_Path, std::ios::binary);
	if (OutputAccess) {
		OutputAccess.write(cardAccessData.c_str(), cardAccessData.size());
		OutputAccess.close();
		cout << "cardAccess " << BinaryToHexString(cardAccessData) << endl;
	}

	std::string Access_hex = StringToHex(cardAccessData);
	int oid_begin = cardAccessData.find("\x30\x12\x06\x0A");
	if (oid_begin < 0) {
		return false;
	}
	std::string oid = cardAccessData.substr(oid_begin + 4, 10);
	auto oid_parse = parseOID(oid);
	char ecc_idx = cardAccessData[oid_begin + 19];
	PACEInfo paceInfo(oid_parse, cardAccessData[16], ecc_idx);
	auto mappingType = paceInfo.toMappingType(oid_parse);
	auto keyAgreementAlgorithm = paceInfo.toKeyAgreementAlgorithm(oid_parse);
	auto cipherAlgorithm = paceInfo.toCipherAlgorithm(oid_parse);
	auto digestAlgorithm = paceInfo.toDigestAlgorithm(oid_parse);
	auto keyLength = paceInfo.toKeyLength(oid_parse);
	cout << mappingType << ' ' << keyAgreementAlgorithm << ' ' << cipherAlgorithm << ' ' << digestAlgorithm << ' ' << keyLength << endl;
	//派生Kpai:TODO:需要传入参数 digestAlgorithm SHA-1 or SHA-256
	std::string mrzInfo(codetonfc.data());
	std::string Kpai;
	CHECK_OK(BuildKpai(mrzInfo, Kpai, digestAlgorithm));
	string selectAPP("\xA0\x00\x00\x02\x47\x10\x01", 7);
	//PACE初始化,true
	CHECK_OK(SelectPACE(oid));

	//请求秘密随机数 true
	std::string Z_ICC;
	CHECK_OK(ICCRequestRandomNumberPACE(Z_ICC));
	cout << "Z_ICC" << BinaryToHexString(Z_ICC) << endl;
	//使用Kpai解密随机数, 得到 S_ICC, 根据PACEinfo选择对称加密算法 AES/3DES true
	std::string S_ICC; 
	std::string iv_hex = "00000000000000000000000000000000";
	auto iv = HexStringToBinary(iv_hex);
	// TODO: 需要传入对称加密算法类型 AES or 3DES 同时传入密钥位数 128 192 256
	if (cipherAlgorithm == "AES")
		aes_cbc_decode(Kpai, Z_ICC, S_ICC, iv, keyLength);
	else if (cipherAlgorithm == "DESede")
	{
		std::string key1 = Kpai.substr(0, 8);
		std::string key2 = Kpai.substr(8, 8);
		std::string key1_check = "";
		std::string key2_check = "";
		CheckParity(key1, key1_check, 8);
		CheckParity(key2, key2_check, 8);
		std::string kpai_check = key1_check + key2_check;
		KencTDES(Z_ICC, kpai_check, S_ICC, DES_DECRYPT);
	}
	cout << "SICC " << BinaryToHexString(S_ICC) << endl;
	//映射随机数：随机选择私钥，生成公钥 true
	int ecc_id = getNID(ecc_idx);
	cout << "eccid "<<ecc_id << endl;
	if (ecc_id < 0) {
		std::cout << "unsupported curve nid, ecc_idx: " << ecc_idx << endl;
	}
	std::string SKmap_IFD, PKmap_IFD;
	EC_GROUP* ec_group = EC_GROUP_new(EC_GFp_mont_method());
	DH* dh = DH_new();
	if (ecc_id > 2 && ecc_id != 12)
	{
		ec_group = EC_GROUP_new_by_curve_name(ecc_id);
	}
	if (ecc_id == 12)
	{
		int ret = Buildsecp256r1(ec_group);
	}
	if (ecc_id >= 0 && ecc_id <= 2)
	{
		int ret = BuildGFP(dh,ecc_id);
	}
	std::string PKmap_IC;
	std::string KA_hex;
	std::string KA_X;
	std::string PKDH_IC, SKDH_IFD, PKDH_IFD;
	if (ecc_id > 2)
	{
		EC_POINT* G_hat = EC_POINT_new(ec_group);
		if (mappingType == "GM")
		{
			cout << "GM" << endl;
			CHECK_OK(BuildMapKey(PKmap_IFD, SKmap_IFD, ecc_id));
			//随机数映射，生成共享秘密值shared_secret
			CHECK_OK(RandomNumberMap(PKmap_IC, PKmap_IFD, SKmap_IFD));
			//协商会话密钥
			const EC_POINT* G = EC_GROUP_get0_generator(ec_group);
			EC_POINT* shared_secret = EC_POINT_new(ec_group);
			string PKmap_IC_hex = BinaryToHexString(PKmap_IC);
			string SKmap_IFD_hex = BinaryToHexString(SKmap_IFD);
			get_shared_secret(ec_group, SKmap_IFD_hex, PKmap_IC_hex, shared_secret);
			//映射基点G到G_hat true
			get_G_hat(ec_group, shared_secret, BinaryToHexString(S_ICC), G, G_hat);
		}
		else if (mappingType == "IM")
		{
			//TODO: INTEGRATED MAPPING
			cout << "IM" << endl;
			/*map_G_hat(G_hat,S_ICC,cipherAlgorithm,keyLength);*/
			return false;
		}
			
		CHECK_OK(MutualAuthenticate(G_hat, PKDH_IC, SKDH_IFD, PKDH_IFD, ecc_id));
		EC_POINT* KA = EC_POINT_new(ec_group);
		string PKDH_IC_hex = BinaryToHexString(PKDH_IC);
		string SKDH_IFD_hex = BinaryToHexString(SKDH_IFD);
		cout << "PKDH_IC_HEX " << PKDH_IC_hex << endl << "SKDH_IFD_HEX " << SKDH_IFD_hex << endl;
		get_shared_secret(ec_group, SKDH_IFD_hex, PKDH_IC_hex, KA);
		BIGNUM* KA_bn = EC_POINT_point2bn(ec_group, KA, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
		char* public_key_hex_char = BN_bn2hex(KA_bn);
		KA_hex = public_key_hex_char;
		cout << "KA_HEX " << KA_hex << endl;
		KA_X = KA_hex.substr(2, KA_hex.size() / 2 - 1);
		cout << "KA_X " << KA_X << endl;
	}
	else if(ecc_id <= 2)
	{
		BIGNUM* G_hat = BN_new();

		if (mappingType == "GM")
		{
			CHECK_OK(BuildMapKey(PKmap_IFD, SKmap_IFD, ecc_id));
			//随机数映射，生成共享秘密值shared_secret
			CHECK_OK(RandomNumberMap(PKmap_IC, PKmap_IFD, SKmap_IFD));
			//协商会话密钥
			const BIGNUM* G = DH_get0_g(dh);

			cout << "G" << BN_bn2hex(G) << endl;
			BIGNUM* shared_secret = BN_new();
			string PKmap_IC_hex = BinaryToHexString(PKmap_IC);
			string SKmap_IFD_hex = BinaryToHexString(SKmap_IFD);
			cout << "PKMAP IC " << PKmap_IC_hex << endl << "SKMAP IFD " << SKmap_IFD_hex << endl;
			get_shared_secret(dh, SKmap_IFD, PKmap_IC_hex, shared_secret);

			get_G_hat(dh, shared_secret, BinaryToHexString(S_ICC), G, G_hat);
		}
		else if (mappingType == "IM")
		{
			cout << "IM" << endl;
			map_G_hat(G_hat, S_ICC, cipherAlgorithm, keyLength);
			return false;
		}
			
		const BIGNUM* p = DH_get0_p(dh);
		BIGNUM* prime = BN_new();
		BN_copy(prime, p);
		cout << "prime new " << BN_bn2hex(prime) << endl;
		CHECK_OK(MutualAuthenticate(G_hat, PKDH_IC, SKDH_IFD, PKDH_IFD, prime));
		BIGNUM* KA = BN_new();
		string PKDH_IC_hex = BinaryToHexString(PKDH_IC);
		string SKDH_IFD_hex = BinaryToHexString(SKDH_IFD);
		get_shared_secret(dh, SKDH_IFD_hex, PKDH_IC_hex, KA);
		KA_hex = BN_bn2hex(KA);
		KA_X = KA_hex;
	}
	//派生KSenc和KSmac TODO:需要传入哈希算法的位数
	std::string KSenc, KSmac;
	CHECK_OK(BuildKencandKmacPACE(KA_X, keyLength, cipherAlgorithm, KSenc, KSmac));

	//计算认证令牌
	std::string TIFD;
	std::string TICC_my;
	computeTIFD(KSmac, PKDH_IC, oid, keyLength, cipherAlgorithm, TIFD, ecc_id);
	computeTIFD(KSmac, PKDH_IFD, oid, keyLength, cipherAlgorithm, TICC_my,ecc_id);
	//交换令牌
	CHECK_OK(ExchangeT(TIFD, TICC_my));	
	cout << "PACE success\n";
	std::string SSC;
	if (cipherAlgorithm == "AES")
		SSC.append("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);
	else if (cipherAlgorithm == "DESede")
		SSC.append("\x00\x00\x00\x00\x00\x00\x00\x00", 8);
	CHECK_OK(SecureCommunicationSeletAPPPACE(selectAPP, KSenc, KSmac, SSC,keyLength,cipherAlgorithm));
	std::string EF_COM_Data;
	// 读取EF.COM文件，并检查该护照存在哪些文件
	
	CHECK_OK(ICCReadEFPACE(KSenc, KSmac, SSC, EF_COM, EF_COM_Data, keyLength, cipherAlgorithm));
	char EF_COM_Path[512];
	MakeFullPath1(EF_COM_Path, EF_COM_FILENAME);
	std::ofstream  Output(EF_COM_Path, std::ios::binary);
	if (Output) {
		Output.write(EF_COM_Data.c_str(), EF_COM_Data.size());
		Output.close();
	}

	std::string tags = EF_COM_TagsParse(EF_COM_Data);

	//EFFileSystem efs;
	STEFFile* stFile = NULL;
	cout << "READING FILES,CONTAINS:\n";
	// 读取其他文件
	for (size_t i = 0; i < tags.size(); i++) {
		unsigned char b = tags[i];
		//cout << "tag" << b << endl;
		stFile = StTagFindEFFile(b, &st_efs);
		if (NULL == stFile) {
			continue;
		}
		cout << stFile->name << '\n';
		std::string ef_data;
		if (stFile->Index == EF_COM) {
			continue;
		}
		if (stFile->Index == EF_DG3) {
			continue;
		}
		// 如果该类型EF解析器未实现则不读该文件
		SelectFunc(stFile);
		if (!stFile->Valid()) {
			continue;
		}
		// 读取文件
		CHECK_OK(ICCReadEFPACE(KSenc, KSmac, SSC, stFile->Index, ef_data, keyLength, cipherAlgorithm));
		// 解析文件
		if (stFile->FileParse(ef_data, &st_efs)) {

			ChipReaderReadFileResultOperate(stFile->Index, stFile->result, 2, stFile->resultLen);
		}
	}
	std::string sod_data;
	CHECK_OK(ICCReadEFPACE(KSenc, KSmac, SSC, EF_SOD, sod_data, keyLength, cipherAlgorithm));
	ChipReaderReadFileResultOperate(EF_SOD, (char*)sod_data.c_str(), 2, sod_data.size());
	ChipAuthenticResult.PACE = 1;
	char mypath[256];
	MakeFullPath1(mypath, "USB_TEMP\\DG15.dat");
	if (!ActiveAuthentication(mypath)) {
		std::cout << "ActiveAuthentication failed" << std::endl;
	}
	else {
		std::cout << "ActiveAuthentication success" << std::endl;
		ChipAuthenticResult.AA = 1;
	}
	DissConnect();
	return TRUE;

}
int PCSCReader::Buildsecp256r1(EC_GROUP*& ec_group)
{
	int ret = -1;
	ec_group = EC_GROUP_new(EC_GFp_mont_method());
	// 设置椭圆曲线的参数
	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	ret = BN_hex2bn(&p, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
	ret = BN_hex2bn(&a, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
	ret = BN_hex2bn(&b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
	ec_group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	EC_POINT* G = EC_POINT_new(ec_group);
	BIGNUM* xG = BN_new();
	BIGNUM* yG = BN_new();
	ret = BN_hex2bn(&xG, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
	ret = BN_hex2bn(&yG, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
	ret = EC_POINT_set_affine_coordinates_GFp(ec_group, G, xG, yG, ctx);

	BIGNUM* order = BN_new();
	ret = BN_hex2bn(&order, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
	BIGNUM* cofactor = BN_new();
	ret = BN_hex2bn(&cofactor, "1");
	ret = EC_GROUP_set_generator(ec_group, G, order, cofactor);
	return 1;
}
int PCSCReader::BuildGFP(DH*& dh,int id)
{
	BIGNUM* p = BN_new();
	BIGNUM* g = BN_new();
	std::string p_hex, g_hex, order_hex;
	if (id == 0)
	{//1024-bit MODP Group with 160-bit Prime Order Subgroup
		p_hex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
		g_hex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
	}

	else if (id == 1)
	{
		p_hex = "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F";
		g_hex = "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA";
	}
	else if (id == 2)
	{
		p_hex = "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597";
		g_hex = "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659";
	}
	BN_hex2bn(&p, p_hex.c_str());
	BN_hex2bn(&g, g_hex.c_str());
	int ret = DH_set0_pqg(dh, p, NULL, g);
	BN_free(p);
	BN_free(g);
	return 1;
}