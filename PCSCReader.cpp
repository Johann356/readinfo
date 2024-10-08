#define CHECK_OK(x)  if(!(x)) return false;
#include "PCSCReader.h"
#include "Ptypes.h"
#include "EFFile.h"
#include "PACEInfo.h"
#include "CAInfo.h"
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
#include "ImageFormat.h"

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
	fileSystem->stEFFiles[EF_COM].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_COM].result[i] = data[i];
		fileSystem->stEFFiles[EF_COM].resultLen++;
	}
	fileSystem->stEFFiles[EF_COM].result[data.size()] = '\0';
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
	char myPath[256];
	MakeFullPath1(myPath,"USB_TEMP\\DG1.txt");
	std::ofstream Output(myPath, std::ios::binary);
	if (Output)
	{
		Output.write(mrz.c_str(), mrz.length());
		Output.close();
	}
#if USE_LOG_LEVEL1
	LOGV("EF_DG1_File::FileParse: " << mrz);
#endif

	fileSystem->stEFFiles[EF_DG1].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG1].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG1].resultLen++;
	}
	fileSystem->stEFFiles[EF_DG1].result[data.size()] = '\0';
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
	fileSystem->stEFFiles[EF_DG2].resultLen = data.size();
	//不填result,因为数据太大了
#if USE_OPENJPEG
	//LOGV("DG2.bmp path == %s\n",fileSystem->stEFFiles[EF_DG2].resultPath);
	return true;
#else
	return true;
#endif
}


char EF_DG11_FileParse(std::string& data, STEFFileSystem* fileSystem) {
	std::string data_hex = BinaryToHexString(data);
	std::string temp = extractValueFromTLVBinaryString(data);
	std::string remainder;
	temp = extractValueFromTLVBinaryString(temp, remainder);
	std::vector<std::string> tags;
	for (int i = 0; i < temp.size() / 2; i++)
		tags.push_back(temp.substr(2 * i, 2));
	std::vector<std::string>result;
	for (auto t : tags)
	{
		size_t pos = data.rfind(t) + 1;
		std::string temp = data.substr(pos);
		temp = extractValueFromTLVBinaryString(temp);
		for (int i = 0; i < temp.size(); i++)
			if (temp[i] == '<')
				temp[i] = ' ';
		result.push_back(temp);
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG11_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG11].resultLen;
#endif
	char myPath[256];
	MakeFullPath1(myPath, "USB_TEMP\\DG11.txt");
	std::ofstream Output(myPath, std::ios::binary);
	if (Output)
	{
		for (int i=0;i<result.size();i++)
		{
			if (tags[i] == "\x5f\x0e")
				Output << "全名 ";
			else if (tags[i] == "\x5f\x0f")
				Output << "姓名 ";
			else if (tags[i] == "\x5f\x10")
				Output << "个人号码 ";
			else if (tags[i] == "\x5f\x2b")
				Output << "出生日期 ";
			else if (tags[i] == "\x5f\x11")
				Output << "出生地 ";
			else if (tags[i] == "\x5f\x42")
				Output << "永久地址 ";
			else if (tags[i] == "\x5f\x12")
				Output << "电话 ";
			else if (tags[i] == "\x5f\x13")
				Output << "职业 ";
			else if (tags[i] == "\x5f\x14")
				Output << "职衔 ";
			else if (tags[i] == "\x5f\x15")
				Output << "个人简历 ";
			else if (tags[i] == "\x5f\x16")
				continue;
				//Output << "公民身份证明 ";
			else if (tags[i] == "\x5f\x17")
				Output << "其他有效旅行证件号 ";
			else if (tags[i] == "\x5f\x18")
				Output << "监护信息 ";
			Output << result[i];
			if (i != result.size() - 1)
				Output << '\n';
		}
		Output.close();
	}
	fileSystem->stEFFiles[EF_DG11].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG11].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG11].resultLen++;
	}
	fileSystem->stEFFiles[EF_DG11].result[data.size()] = '\0';

	return true;
}
char EF_DG12_FileParse(std::string& data, STEFFileSystem* fileSystem) {
	std::string data_hex = BinaryToHexString(data);
	std::string temp = extractValueFromTLVBinaryString(data);
	std::string remainder;
	temp = extractValueFromTLVBinaryString(temp, remainder);
	std::vector<std::string> tags;
	for (int i = 0; i < temp.size() / 2; i++)
		tags.push_back(temp.substr(2 * i, 2));
	std::vector<std::string>result;
	for (auto t : tags)
	{
		size_t pos = data.rfind(t) + 1;
		std::string temp = data.substr(pos);
		temp =extractValueFromTLVBinaryString(temp);
		for (int i = 0; i < temp.size(); i++)
			if (temp[i] == '<')
				temp[i] = ' ';
		result.push_back(temp);
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG12_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG12].resultLen;
#endif
	char myPath[256];
	MakeFullPath1(myPath, "USB_TEMP\\DG12.txt");
	std::ofstream Output(myPath, std::ios::binary);
	if (Output)
	{
		for (int i = 0; i < result.size(); i++)
		{
			if (tags[i] == "\x5f\x19")
				Output << "签发机构 ";
			else if (tags[i] == "\x5f\x26")
				Output << "签发日期 ";
			else if (tags[i] == "\x5f\x1A")
				Output << "其他姓名 ";
			else if (tags[i] == "\x5f\x1B")
				Output << "签注与意见 ";
			else if (tags[i] == "\x5f\x1C")
				Output << "税收/出境要求 ";
			else if (tags[i] == "\x5f\x1D")
				continue;
				//Output << "证件正面图像 ";
			else if (tags[i] == "\x5f\x1E")
				continue;
				//Output << "证件背面图像 ";
			else if (tags[i] == "\x5f\x55")
				Output << "证件个人化的日期和时间 ";
			else if (tags[i] == "\x5f\x56")
				Output << "个人化系统的序列号 ";
			Output << result[i];
			if (i != result.size() - 1)
				Output << '\n';
		}
		Output.close();
	}
	fileSystem->stEFFiles[EF_DG12].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG12].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG12].resultLen++;
	}
	fileSystem->stEFFiles[EF_DG12].result[data.size()] = '\0';

	return true;
}
char EF_DG15_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG15].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
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
	for (size_t i = 0; i < data.size(); i++) {
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
	for (size_t i = 0; i < data.size(); i++) {
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

	fileSystem->stEFFiles[EF_DG5].resultLen = data.length();
	fileSystem->stEFFiles[EF_DG5].result[0] = '\0';
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG5_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG5].resultLen;
#endif
#if USE_OPENJPEG
	//LOGV("DG2.bmp path == %s\n",fileSystem->stEFFiles[EF_DG2].resultPath);
	return true;
#else
	return true;
#endif
}
char EF_DG6_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG6].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
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

	fileSystem->stEFFiles[EF_DG7].resultLen = data.length();
	fileSystem->stEFFiles[EF_DG7].result[0] = '\0';
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG7_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG7].resultLen;
#endif
#if USE_OPENJPEG
	//LOGV("DG2.bmp path == %s\n",fileSystem->stEFFiles[EF_DG2].resultPath);
	return true;
#else
	return true;
#endif

}
char EF_DG8_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_DG8].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
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
	for (size_t i = 0; i < data.size(); i++) {
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
	for (size_t i = 0; i < data.size(); i++) {
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
	for (size_t i = 0; i < data.size(); i++) {
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
	for (size_t i = 0; i < data.size(); i++) {
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
	std::string data_hex = BinaryToHexString(data);
	std::string temp = extractValueFromTLVBinaryString(data);
	std::string remainder;
	temp = extractValueFromTLVBinaryString(temp, remainder);
	std::vector<std::string> tags;
	for (int i = 0; i < temp.size() / 2; i++)
		tags.push_back(temp.substr(2 * i, 2));
	std::vector<std::string>result;
	for (auto t : tags)
	{
		size_t pos = data.rfind(t) + 1;
		std::string temp = data.substr(pos);
		temp = extractValueFromTLVBinaryString(temp);
		for (int i = 0; i < temp.size(); i++)
			if (temp[i] == '<')
				temp[i] = ' ';
		result.push_back(temp);
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_DG16_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_DG16].resultLen;
#endif
	char myPath[256];
	MakeFullPath1(myPath, "USB_TEMP\\DG16.txt");
	std::ofstream Output(myPath, std::ios::binary);
	if (Output)
	{
		for (int i = 0; i < result.size(); i++)
		{
			if (tags[i] == "\x5f\x50")
				Output << "日期 ";
			else if (tags[i] == "\x5f\x51")
				Output << "姓名 ";
			else if (tags[i] == "\x5f\x52")
				Output << "电话 ";
			else if (tags[i] == "\x5f\x53")
				Output << "地址 ";
			if (i != result.size() - 1)
				Output << '\n';
		}
		Output.close();
	}
	fileSystem->stEFFiles[EF_DG16].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_DG16].result[i] = data[i];
		fileSystem->stEFFiles[EF_DG16].resultLen++;
	}
	fileSystem->stEFFiles[EF_DG16].result[data.size()] = '\0';

	return true;

}
char EF_SOD_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_SOD].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_SOD].result[i] = data[i];
		fileSystem->stEFFiles[EF_SOD].resultLen++;
	}
#if OOXX_DEBUG_LOG
	LOG(INFO) << "echip EF_SOD_FileParse datasize: " << data.size() << " resultLen:"
		<< fileSystem->stEFFiles[EF_SOD].resultLen;
#endif
	size_t pos = data.rfind("\xA0\x82");
	std::string temp = data.substr(pos);
	std::string temp_hex = BinaryToHexString(temp);
	temp = extractValueFromTLVBinaryString(temp);
	temp_hex = BinaryToHexString(temp);
	temp = data.substr(pos, 4) + temp;
	temp[0] = '\x31';
	char myPath[256];
	MakeFullPath1(myPath, "USB_TEMP\\DSC.cer");
	std::ofstream Output(myPath, std::ios::binary);
	if (Output.is_open())
	{
		Output.write(temp.c_str(), temp.size());
		Output.close();
	}
	fileSystem->DS = temp;
	fileSystem->iDS = temp.size();
	fileSystem->stEFFiles[EF_SOD].result[data.size()] = '\0';

	return true;
}

char EF_IDINFO_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_IDINFO].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_IDINFO].result[i] = data[i];
		fileSystem->stEFFiles[EF_IDINFO].resultLen++;
	}
	fileSystem->stEFFiles[EF_IDINFO].result[data.size()] = '\0';

	/*
	LOGV("EF_IDINFO: " << fileSystem->stEFFiles[EF_IDINFO].resultLen);
	for(int i = 0;i < fileSystem->stEFFiles[EF_IDINFO].resultLen ;i++){
		LOGV("%x ",fileSystem->stEFFiles[EF_IDINFO].result[i] & 0xff );
	}
	LOG(INFO)<< std::endl;
	*/
	return true;
}

char EF_IDPIC_FileParse(std::string& data, STEFFileSystem* fileSystem) {

	fileSystem->stEFFiles[EF_IDPIC].resultLen = 0;
	for (size_t i = 0; i < data.size(); i++) {
		fileSystem->stEFFiles[EF_IDPIC].result[i] = data[i];
		fileSystem->stEFFiles[EF_IDPIC].resultLen++;
	}
	fileSystem->stEFFiles[EF_IDPIC].result[data.size()] = '\0';

	/*
		LOGV("EF_IDINFO: " << fileSystem->stEFFiles[EF_IDPIC].resultLen);
		for(int i = 0;i < fileSystem->stEFFiles[EF_IDPIC].resultLen ;i++){
			LOGV("%x ",fileSystem->stEFFiles[EF_IDPIC].result[i] & 0xff );
		}
		LOG(INFO)<< std::endl;
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




void PCSCReader::ChipReaderReadFileResultOperate(EF_NAME name, std::string& result, unsigned char type, int length) {
	switch (name) {
	case EF_COM:{
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\COM.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		COM = "COM.bin";
		break;
	}
	case EF_DG1: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG1.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG1, result.c_str(),length);
		ChipData_Doc9303_Result.iDG1 = length;
		DG1 = "DG1.bin";
		std::string flag("\x5F\x1F", 2);
		size_t it = result.find(flag);
		if (it == std::string::npos) {
			//LOGE("EF_DG1_FileParse:it == std::string::npos\n");
			DG1detail = "";
		}
		else
			DG1detail = result.substr(it + 3);
		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		break;
	}
	case EF_DG2: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG2.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG2, result.c_str(),length);
		ChipData_Doc9303_Result.iDG2 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG2 = "DG2.bin";
		DG2Details.ImageTypeDeclare = "JPEG";
		MakeFullPath1(mypath, "USB_TEMP\\DG2.bmp");
		jp2_to_bmp(result, mypath,DG2Details.FaceImageWidth,DG2Details.FaceImageHeight,DG2Details.ImageBitSize,DG2Details.ImageTypeReal);
		//getImageFormat(DG2Details, result, mypath);
		break;
	}
	case EF_DG3: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG3.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG3, result.c_str(),length);
		ChipData_Doc9303_Result.iDG3 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG3 = "DG3.bin";
		break;
	}
	case EF_DG4: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG4.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG4, result.c_str(),length);
		ChipData_Doc9303_Result.iDG4 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG4 = "DG4.bin";
		break;
	}
	case EF_DG5: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG5.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG5, result.c_str(),length);
		ChipData_Doc9303_Result.iDG5 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG5 = "DG5.bin";
		break;
	}
	case EF_DG6: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG6.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG6, result.c_str(),length);
		ChipData_Doc9303_Result.iDG6 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG6 = "DG6.bin";
		break;
	}
	case EF_DG7: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG7.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG7, result.c_str(),length);
		ChipData_Doc9303_Result.iDG7 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG7 = "DG7.bin";
		DG7Details.ImageTypeDeclare = "JPEG";
		MakeFullPath1(mypath, "USB_TEMP\\DG7.bmp");
		jp2_to_bmp(result, mypath, DG7Details.FaceImageWidth, DG7Details.FaceImageHeight, DG7Details.ImageBitSize, DG7Details.ImageTypeReal);
		break;
	}
	case EF_DG8: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG8.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG8, result.c_str(),length);
		ChipData_Doc9303_Result.iDG8 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG8 = "DG8.bin";
		break;
	}
	case EF_DG9: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG9.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG9, result.c_str(),length);
		ChipData_Doc9303_Result.iDG9 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG9 = "DG9.bin";
		break;
	}
	case EF_DG10: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG10.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG10, result.c_str(),length);
		ChipData_Doc9303_Result.iDG10 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG10 = "DG10.bin";
		break;
	}


	case EF_DG11: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG11.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		memcpy(ChipData_Doc9303_Result.pDG11, result.c_str(),length);
		ChipData_Doc9303_Result.iDG11 = length;

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG11 = "DG11.bin";
		break;
	}
	case EF_DG12: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG12.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG12 = length;
		memcpy(ChipData_Doc9303_Result.pDG12, result.c_str(), length);

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG12 = "DG12.bin";
		break;
	}
	case EF_DG13: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG13.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG13 = length;
		memcpy(ChipData_Doc9303_Result.pDG13, result.c_str(), length);

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG13 = "DG13.bin";
		break;
	}
	case EF_DG14: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG14.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG14 = length;
		//memcpy(ChipData_Doc9303_Result.pDG14, result.c_str(), length);
		memcpy(ChipData_Doc9303_Result.pDG14, result.c_str(), length);
		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG14 = "DG14.bin";
		break;
	}
	case EF_DG15: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG15.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG15 = length;
		memcpy(ChipData_Doc9303_Result.pDG15, result.c_str(), length);

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG15 = "DG15.bin";
		break;
	}
	case EF_DG16: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\DG16.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iDG16 = length;
		memcpy(ChipData_Doc9303_Result.pDG16, result.c_str(), length);

		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		DG16 = "DG16.bin";
		break;
	}
	case EF_SOD: {
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\SOD.bin");
		std::ofstream  Output(mypath, std::ios::binary);
		ChipData_Doc9303_Result.iSOD = length;
		memcpy(ChipData_Doc9303_Result.pSOD, result.c_str(), length);
		if (Output) {
			Output.write(result.c_str(), length);
			Output.close();
		}
		SOD = "SOD.bin";
		DSC = "DSC.cer";
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
	char path_DG3[MAX_PATH];
	MakeFullPath1(path_DG3, "USB_TEMP//DG3.bmp");
	char path_DG4[MAX_PATH];
	MakeFullPath1(path_DG4, "USB_TEMP//DG4.bmp");
	char path_DG5[MAX_PATH];
	MakeFullPath1(path_DG5, "USB_TEMP//DG5.bmp");
	char path_DG7[MAX_PATH];
	MakeFullPath1(path_DG7, "USB_TEMP//DG7.bmp");
	strcpy(st_efs.stEFFiles[EF_DG3].resultPath, path_DG3);
	strcpy(st_efs.stEFFiles[EF_DG4].resultPath, path_DG4);
	strcpy(st_efs.stEFFiles[EF_DG5].resultPath, path_DG5);
	strcpy(st_efs.stEFFiles[EF_DG7].resultPath, path_DG7);
	baseFolder = path;
	return true;
}

PCSCReader::PCSCReader()
{
	hContext = 0x00000000;
	m_dAttrib = 0;
	STEFilesInit(&st_efs);
	InitalizeState();
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
			//LOG(INFO)<< "Connect successfully" << std::endl;
			atr = BYTE2string(pbAttr, cByte);
			//LOG(INFO)<< atr << std::endl;

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
		//LOG(INFO)<< "send data successfully" << endl;
		//LOG(INFO)<< BYTE2string(RecvBuff, (UINT)RecvLen) << endl;

	}
	else
	{
		//LOG(INFO)<< "send data failed" << endl;
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
		LOG(INFO)<< "disconnect successfully" << endl;
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
	LOG(INFO) << "MRZ HASH RESULT: " << BinaryToHexString(mrzInfoSha1) << '\n';
	LOG(INFO) << "D1: " << BinaryToHexString(D1) << " D2: " << BinaryToHexString(D2) << '\n';
	LOG(INFO) << "D1 HASH RESULT: " << BinaryToHexString(HD1) << " D2 HASH RESULT: " << BinaryToHexString(HD2) << '\n';
	LOG(INFO) << "AFTER CHECKPARITY: Kenc: " << BinaryToHexString(Kenc) << " Kmac: " << BinaryToHexString(Kmac) << '\n';

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
	//LOG(INFO)<<"RAPDU: "<< RAPDU_out << endl;
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
char PCSCReader::SecureCommunicationInternalAuthenticate(const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	std::string& data,
	std::string& RND_IFD,
	std::string& cipherAlgorithm,
	int keyLength,
	bool longCommand) {
	// 对未受保护的APDU命令进行填充
	longCommand = false;
	std::string unprotectedAPDU("\x0C\x88\x00\x00", 4);
	//std::string unprotectedAPDU("\x0C\x88\x00\x00\x00\x00", 6);
	std::string CmdHeader(unprotectedAPDU);
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(CmdHeader);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(CmdHeader);
	std::string strFillData = RND_IFD;


	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(strFillData);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(strFillData);
	// 用SKenc加密数据
	std::string strEncData;
	//KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	//加密SSC
	std::string iv = "";
	if (cipherAlgorithm == "AES") {
		iv = "00000000000000000000000000000000";
	}
	iv = HexStringToBinary(iv);
	IncreaseSSC(SSC); //SSC += 1
	auto SSC_hex = BinaryToHexString(SSC);
	if (cipherAlgorithm == "AES")
	{
		std::string SSC_IV;
		aes_cbc_encode(KSenc, SSC, SSC_IV, iv);
		auto SSC_IV_hex = BinaryToHexString(SSC_IV);
		auto strFillData_hex = BinaryToHexString(strFillData);
		aes_cbc_encode(KSenc, strFillData, strEncData, SSC_IV);
		//aes_cbc_encode(KSenc, strFillData, strEncData, iv);
		auto strEncData_hex = BinaryToHexString(strEncData);
	}
	else if (cipherAlgorithm == "DESede")
	{
		KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	}

	auto strEncData_hex = BinaryToHexString(strEncData);
	//构建d097
	std::string DO97;
	unsigned char x97 = 0x97;
	DO97.push_back(x97);
	if (longCommand)
	{
		DO97.push_back(2);
		DO97.push_back(0);
		DO97.push_back(0);
	}
	else
	{
		DO97.push_back(1);
		DO97.push_back(0);
	}
	//DO97.push_back(0);
	//DO97.push_back(0);

	// 构建DO87,并置cmdheader和DO87得到M
	std::string DO87;
	unsigned char L = (unsigned char)strFillData.size() + 1;
	unsigned char x87 = 0x87;
	DO87.push_back(x87);
	DO87.push_back(L);
	DO87.push_back(0x01);
	DO87.append(strEncData);
	std::string M = CmdHeader + DO87 + DO97;


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
		KmacDES(N, KSmac, CCN);
	// 用CCN构建DO8E
	std::string DO8E("\x8E\x08", 2);
	DO8E.append(CCN.data(), CCN.size());

	// 构建受保护的APDU
	std::string APDU;
	std::string unprotectedAPDU2("\x0C\x88\x00\x00", 4);
	//std::string unprotectedAPDU2("\x0C\x88\x00\x00\x00\x00", 6);
	APDU.append(unprotectedAPDU2.data(), unprotectedAPDU2.size());
	unsigned char le_ = (unsigned char)DO87.size() + (unsigned char)DO8E.size() + (unsigned char)DO97.size();
	//默认le不会超过256
	if (longCommand)
	{
		APDU.push_back(0);
		APDU.push_back(0);
	}
	APDU.push_back(le_);//DO87+DO8E
	APDU.append(DO87.data(), DO87.size());
	APDU.append(DO97.data(), DO97.size());
	APDU.append(DO8E.data(), DO8E.size());
	/*
	 这里应该多加一个字节，中国护照可以不需要，但是国外的护照如果不加
	 这个字节，调用会失败
	 */
	APDU.push_back(0);
	if(longCommand)
		APDU.push_back(0);
	// 发送APDU
	LOG(INFO) << "LONG COMMAND " << longCommand << " SEND APDU " << BinaryToHexString(APDU);
	int dwLen = APDU.size();
	auto APDU_hex = BinaryToHexString(APDU);
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	this->Apdusend(APDU, RecvBuff, RecvLen);
	//LOG(INFO)<< "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s((char*)&RecvBuff[0], RecvLen);
	std::string RAPDU;//无响应数据，只有SW1 SW2，DO99+8E+08+CC+SW1+SW2
	RAPDU.append(s);
	auto RAPDU_hex = BinaryToHexString(RAPDU);
#define DO99_COMPATIBLE 1
	// ------------------------------------------------------------
	// h.通过计算DO87和DO99并置的MAC, 验证RAPDU CC
	int tlLen = 0;
	std::string RAPDU_DO87 = RAPDUParse(RAPDU, 0x87, &tlLen);

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
char PCSCReader::ActiveAuthentication(char* DG15_file_path, const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	std::string& cipherAlgorithm,
	int keyLength) {
	std::string RND_IFD;
	std::string ENC_RES; 
	RND_IFD.resize(8);
	BuildRandomData(RND_IFD);
	std::string RND_IFD_hex = BinaryToHexString(RND_IFD);
	std::string m_RND_ICC("\x00\x88\x00\x00\x00\x00\x08", 7);
	m_RND_ICC += RND_IFD;
	std::string le("\x00\x00", 2);
	m_RND_ICC += le;
	std::string RAPDU;
	std::ifstream file(DG15_file_path, std::ios::binary); // 打开文件	
	if (!file.is_open()) {
		std::cerr << "DG15 not exists" << std::endl;
		AA = 2;
		ChipAuthenticResult.AA = 2;
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
	bool longCommand = false;
	if (bin_string.find("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") != bin_string.npos)
	{
		std::string temp = bin_string;
		temp = extractValueFromTLVBinaryString(temp);
		temp = extractValueFromTLVBinaryString(temp);
		extractValueFromTLVBinaryString(temp, temp);
		temp = extractValueFromTLVBinaryString(temp);
		temp = extractValueFromTLVBinaryString(temp);
		temp = extractValueFromTLVBinaryString(temp);
		if (temp[0] == '\x00')
			temp = temp.substr(1);
		LOG(INFO) << "AA PUBLICKEY LENGTH " << temp.size() * 8;
		if (temp.size() > 231 && cipherAlgorithm == "DESede" || temp.size() > 224 && cipherAlgorithm == "AES")
			longCommand = true;
	}
	AA = 1;
	ChipAuthenticResult.AA = 1;
	int ret = SecureCommunicationInternalAuthenticate(KSenc, KSmac, SSC, RAPDU, RND_IFD, cipherAlgorithm, keyLength, longCommand);
	std::string RAPDU_hex = BinaryToHexString(RAPDU);

	//int ret = PostPassportCommand(m_RND_ICC,RAPDU);
	if (!ret)
	{
		LOG(INFO) << "AA RND_IFD fail" << endl;
		AA = 1;
		return 2;
	}
	else {
		ENC_RES = RAPDU;
	}


	if (bin_string.find("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") != bin_string.npos)//RSA
	{
		LOG(INFO) << "AA:RSA\n";
		std::string rsa_tag = hex_string.substr(2, 2);
		if (rsa_tag == "81") {
			hex_string = hex_string.substr(6);
		}
		else {
			hex_string = hex_string.substr(8);
		}
		//LOG(INFO)<< hex_string << std::endl;
		std::string base64str = hexToBase64(hex_string);
		std::string pubKey1 = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";
		string cipherText = StringToHex(ENC_RES);
		std::string decStr = rsa_pub_decrypt(ENC_RES, pubKey1, RSA_NO_PADDING);
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
			LOG(INFO)<< "head != 6A" << endl;
			return 3;
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
		//LOG(INFO)<< cipherText << endl;
		bool result = (sha_D == origin_D);
		if (result)
		{
			LOG(INFO) << "AA SUCCESS\n";
			AA = 0;
			ChipAuthenticResult.AA = 0;
			return 0;
		}
		else
		{
			LOG(INFO) << "AA FAIL\n";
			AA = 1;
			ChipAuthenticResult.AA = 1;
			return 4;
		}
	}
	else if (hex_string.find("2a8648ce3d0201") != hex_string.npos)//ECDSA
	{
		LOG(INFO) << "AA:ECDSA";
		EC_KEY* ec_key = EC_KEY_new();
		ExtractECpkfromDG15(hex_string, ec_key);

		bool result = TestEcdsa(RAPDU_hex, RND_IFD, hex_string,ec_key);
		if (result)
		{
			LOG(INFO) << "AA SUCCESS\n";
			AA = 0;
			ChipAuthenticResult.AA = 0;
			return 0;
		}
		else
		{
			LOG(INFO) << "AA FAIL\n";
			AA = 1;
			ChipAuthenticResult.AA = 1;
			return 5;
		}
	}

}

char PCSCReader::PassiveAuthentication(char* SOD_file_path, std::unordered_map<int, std::string>& DGs) {
	std::string country;
	std::string hash, signature;
	int hashLength;
	char ret = 1;
	std::string hex = ReadFileContentsAsHex(SOD_file_path);
	if (!hex.length())
	{
		LOG(INFO) << "READ EF_SOD EMPTY.\n";
		SODCheck = 1;
		return 0;
	}
	SODCheck = 0;
	std::string countrynameTag = "0603550406";
	size_t pos = hex.find(countrynameTag);
	std::string temp = hex.substr(pos);
	std::string countryname;
	extractValueFromTLVHexString(temp, temp);
	country = extractValueFromTLVHexString(temp);
	char ch = 0;
	std::string name = "";
	for (int i = 0; i < country.length(); i++)
		country[i] = country[i] >= 'A' && country[i] <= 'Z' ? country[i] + 'a' - 'A' : country[i];
	for (int i = 0; i < country.length() / 2; i++)
	{
		if (country[i * 2] >= '0' && country[i * 2] <= '9')
			ch += (country[i * 2] - '0') * 16;
		else
			ch += (country[i * 2] - 'a' + 10) * 16;
		if (country[i * 2 + 1] >= '0' && country[i * 2 + 1] <= '9')
			ch += (country[i * 2 + 1] - '0');
		else
			ch += (country[i * 2 + 1] - 'a' + 10);
		name.push_back(ch);
		ch = 0;
	}
	for (int i = 0; i < name.size(); i++)
		if (name[i] >= 'a' && name[i] <= 'z')
			name[i] = name[i] + ('A' - 'a');
	country = name;
	LOG(INFO) << "PA COUNTRY NAME " << country;
	std::string mrzCountry = DGs[1].substr(7,3);
	std::unordered_map<std::string, std::string> CountryCodeMap = createCountryCodeMapReversed();
	if (CountryCodeMap[mrzCountry] == country)
	{
		LOG(INFO) << "PA COUNTRY NAME " << CountryCodeMap[mrzCountry];
		IssuingCountryCheck = 0;
	}
	size_t DGHashHead = hex.find("A082");
	size_t CSCAHead = hex.rfind("A082");
	size_t SODSignatureHead = hex.rfind("3182");
	if (SODSignatureHead == hex.npos)
		SODSignatureHead = hex.rfind("3181");
	//check DGs hash
	std::string hex_temp = hex.substr(DGHashHead, CSCAHead - DGHashHead);
	checkHashAndSignature(hex_temp, hash, signature, hashLength);
	LOG(INFO) << "DGs HASH ALGORITHM:" << hash << '\n';
	bool integrity = true;
	if (!checkDGs(DGs, hash, hex,integrity)) {
		LOG(INFO) << "PA, CHECK DGs HASH FAIL\n";
		ChipAuthenticResult.PADGHash = 1;
		ret = 0;
	}
	else
	{
		ChipAuthenticResult.PADGHash = 0;
	}
	if (integrity == true)
	{
		IntegrityCheck = 0;
		LOG(INFO) << "INTEGRITYCHECK " <<"SUCCESS";
	}
	else
	{
		IntegrityCheck = 1;
		LOG(INFO) << "INTEGRITYCHECK " << "FAIL";
	}
	hex_temp = hex.substr(SODSignatureHead);
	checkHashAndSignature(hex_temp, hash, signature, hashLength);
	if (hex.size() < 1000) {
		return 0;
	}
	LOG(INFO) << "PA, HASH ALGORITHM " << hash << ",SIGNATURE ALGORITHM " << signature << endl;


	if (signature == "RSA" || signature == "RSAPSS")
	{
		//get pk
		std::string RSA_Encryption_tag = "300D06092A864886F70D010101";
		size_t pos = hex.find(RSA_Encryption_tag);
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
		if (RSA_public_key.substr(2, 2) == "82")
			head = RSA_public_key.substr(0, 8);
		else if (RSA_public_key.substr(2, 2) == "81")
			head = RSA_public_key.substr(0, 6);
		else
			head = RSA_public_key.substr(0, 4);//insure head is right

		RSA_public_key = extractValueFromTLVHexString(RSA_public_key);
		RSA_public_key = head + RSA_public_key;
		std::string base64str = hexToBase64(RSA_public_key);
		std::string pubKey = "-----BEGIN PUBLIC KEY-----\n" + base64str + +"\n-----END PUBLIC KEY-----\n";
		LOG(INFO) << "GET SOD RSA PK " ;
		RSA* rsa = RSA_new();
		BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
		int len = RSA_size(rsa);

		//get signature
		std::string encryptedData = hex.substr(hex.length() - len * 2, len * 2);
		LOG(INFO) << "GET SOD SIGNATURE " ;
		encryptedData = hexString2String(encryptedData);
		std::string decStr = rsa_pub_decrypt(encryptedData, pubKey, RSA_NO_PADDING);
		LOG(INFO) << "GET SOD DECTRYPTED DATA" ;

		//get message
		std::string messageDigest;
		if (!getMsgfromSOD(hex, messageDigest))
		{
			LOG(INFO) << "MESSAGE DIGEST EXTRACTION FAIL";
			return 0;
		}
		else
			LOG(INFO) << "GET MESSAGE DIGEST";
		//LOG(INFO) << "SOD MESSAGE DIGEST " << messageDigest;
		bool result = false;
		if (signature == "RSAPSS")
		{
			LOG(INFO) << "CHECK SOD RSAPSS SIGNATURE";
			const EVP_MD* md = nullptr;
			checkmd(hash, md);
			std::string decStr_hex = BinaryToHexString(decStr);
			std::string message_hash(hashLength, 0);
			std::string binary_messageDigest = HexToString(messageDigest);
			SHA_X(hash, binary_messageDigest, message_hash);
			LOG(INFO) << "GET SOD MESSAGE DIGEST HASH RESULT ";
			try
			{
				result = RSA_verify_PKCS1_PSS_mgf1(rsa, (unsigned char*)message_hash.c_str(), md, md, (unsigned char*)decStr.c_str(), hashLength);
			}
			catch (const std::exception& e)
			{
				LOG(ERROR) << e.what();
			}
		}
		else
		{
			LOG(INFO) << "CHECK SOD RSA SIGNATURE";
			std::string hexDecStr = StringToHex(decStr);
			std::string signature_dec = hexDecStr.substr(hexDecStr.size() - 2 * hashLength, 2 * hashLength);
			std::string signature;
			std::string hashResult(hashLength, 0);
			std::string binary_messageDigest = HexToString(messageDigest);
			SHA_X(hash, binary_messageDigest, hashResult);
			signature = StringToHex(hashResult);
			LOG(INFO) << "GET SOD RSA HASHED SIGNATURE ";
			result = compare_ignore_case(signature, signature_dec);
		}
		if (result)
		{
			LOG(INFO) << "SOD VERIFY SIGNATURE SUCCESS\n";
			ChipAuthenticResult.PASOD = 0;
		}
			
		else
		{
			LOG(INFO) << "SOD VERIFY SIGNATURE FAIL\n";
			ChipAuthenticResult.PASOD = 1;
			ret = 0;
		}
			
	}
	else if (signature == "ECDSA")
	{
		EC_KEY* ec_key = EC_KEY_new();
		std::string pk;
		if (!ExtractECpkfromSOD(hex, ec_key, pk)) {
			LOG(ERROR) << "PA FAIL TO ExtractECpkfromSOD";
			return 0;
		}
		LOG(INFO) << "PA EXTRACTECPKFROMSOD";
		std::string messageDigest;
		if (!getMsgfromSOD(hex, messageDigest)) {
			LOG(ERROR) << "PA FAIL TO getMsgfromSOD";
			return 0;
		}
		LOG(INFO) << "PA GET MESSAGE";
		//get hash of messageDigest
		messageDigest = HexStringToBinary(messageDigest);
		std::string hash_res;
		SHA_X(hash, messageDigest, hash_res);

		std::string ecdsa_sig;
		std::string r, s;
		if (!getSigfromSOD(hex, s, r)) {
			LOG(ERROR) << "PA FAIL TO getSigfromSOD";
			return 0;
		}
		LOG(INFO) << "PA GET SIGNATURE FROM SOD";
		BIGNUM* r_bn = BN_new();
		BIGNUM* s_bn = BN_new();
		int ret = BN_hex2bn(&r_bn, r.c_str());
		ret = BN_hex2bn(&s_bn, s.c_str());

		ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();
		ret = ECDSA_SIG_set0(ecdsaSig, r_bn, s_bn);
		if (!ecdsaSig) {
			LOG(ERROR) << "PA INITIALIZE ECDSA_SIG FAIL";
			return 0;
		}
		// 验证签名
		ret = ECDSA_do_verify((const unsigned char*)hash_res.c_str(), hash_res.size(), ecdsaSig, ec_key);
		if (ret == 1)
		{
			LOG(INFO) << "SOD VERIFY ECDSA SIGNATURE SUCCESS\n";
			ChipAuthenticResult.PASOD = 0;
		}
		else
		{
			LOG(INFO) << "SOD VERIFY ECDSA SIGNATURE FAIL\n";
			ChipAuthenticResult.PASOD = 1;
			ret = 0;
		}
	}
	hex_temp = hex.substr(CSCAHead, SODSignatureHead - CSCAHead);
	checkHashAndSignature(hex_temp, hash, signature, hashLength);
	size_t pos1 = hex_temp.find("301E170D");
	if (pos1 == hex_temp.npos)
		pos1 = hex_temp.find("3022180F");
	if (pos1 == hex_temp.npos)
		pos1 = hex_temp.find("3020170D");
	std::string time1 = hex_temp.substr(pos1),time2;
	time1 = extractValueFromTLVHexString(time1);
	time1 = extractValueFromTLVHexString(time1,time2);
	time2 = extractValueFromTLVHexString(time2);
	time1 = HexStringToBinary(time1);
	time2 = HexStringToBinary(time2);
	if (time1.size() == 13)
		time1 = "\x32\x30" + time1;
	if (time2.size() == 13)
		time2 = "\x32\x30" + time2;
	std::string time_now = getCurrentDateTimeFormatted();
	if (time1 < time_now && time_now < time2)
		DSCDateCheck = 0;
	bool checkCSCAret = false;
	try
	{
		checkCSCAret = checkCSCA(hex, signature, hash, hashLength, country);
	}
	catch (const std::exception& e)
	{
		LOG(ERROR) << e.what();
	}
	if (!checkCSCAret)
	{
		LOG(INFO) << "ISSUER CERTIFICATE VERIFY FAIL\n";
		ChipAuthenticResult.PADS = 1;
		DSCCheck = 1;
	}
	else
	{
		LOG(INFO) << "ISSUER CERTIFICATE VERIFY SUCCESS\n";
		ChipAuthenticResult.PADS = 0;
		DSCCheck = 0;
	}
	if (ChipAuthenticResult.PADGHash == 0 && ChipAuthenticResult.PADS == 0 && ChipAuthenticResult.PASOD == 0)
		ChipAuthenticResult.PA = 0;
	return ret;
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
	//LOG(INFO)<< "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
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
	//LOG(INFO)<< "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
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

		//LOG(INFO)<< ".";
#if USE_LOG_LEVEL2
		LOG(INFO)<< "[ChipReader]正在读取第 %s", requestOffset << "个包，偏移为"
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
	//LOG(INFO)<< std::endl;

	if (lastBytes) {
		std::string chunkData;
#if USE_LOG_LEVEL2
		LOG(INFO)<< "[ChipReader]正在读取第 %s", requestOffset << "个包，偏移为" <<
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
bool PCSCReader::ReadCardAccessAndCardSecurity(std::string& CardAccess,std::string& CardSecurity)
{
	LOG(INFO) << "START TO READ CARDACCESS AND CARDSECURITY DIRECTLY";
	bool f1 = false, f2 = false;
	if (DirectReadEF(EF_CardAccess, CardAccess))
	{
		f1 = true;
		LOG(INFO) << "EF_CARDACCESS EXISTS";
		ChipData_Doc9303_Result.iCardAcess = CardAccess.length();
		memcpy(ChipData_Doc9303_Result.pCardAccess,CardAccess.c_str(), CardAccess.length());
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\EF_CardAccess.bin");
		ofstream Output(mypath, std::ios::binary);
		if(Output.is_open())
		{
			Output.write(CardAccess.c_str(), CardAccess.length());
			Output.close();
		}
	}
	else
	{
		LOG(INFO) << "EF_CARDACCESS DOESN'T EXIST";
		ChipData_Doc9303_Result.iCardAcess = 0;
		ChipData_Doc9303_Result.pCardAccess[0]='\0';
	}
	/*if (DirectReadEF(EF_CARDSECURITY, CardSecurity))
	{
		LOG(INFO) << "EF_CARDSECURITY EXISTS";
		f2 = true;
		ChipData_Doc9303_Result.iCardSecurity = CardSecurity.length();
		memcpy(ChipData_Doc9303_Result.pCardSecurity, CardSecurity.c_str(), CardSecurity.length());
		char mypath[256];
		MakeFullPath1(mypath, "USB_TEMP\\CardSecurity.bin");
		ofstream Output(mypath, std::ios::binary);
		if (Output.is_open())
		{
			Output.write(CardSecurity.c_str(), CardSecurity.length());
			Output.close();
		}
	}
	else 
	{
		LOG(INFO) << "EF_CARDSECURITY DOESN'T EXIST";
		ChipData_Doc9303_Result.iCardSecurity = 0;
		ChipData_Doc9303_Result.pCardSecurity[0] = '\0';
	}
	if (f1 && f2)
		return true;
	else
		return false;*/
	if (f1)
		return true;
}
bool PCSCReader::GetCAPK(std::vector<CAInfo>& CAinfo, std::string& dg14)
{
	std::string temp = dg14;
	std::string CATag("\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x03", 10);
	std::string CAECDHTag("\x06\x09\x04\x00\x7F\x00\x07\x02\x02\x01\x02", 11);
	std::string CADHTag("\x06\x09\x04\x00\x7F\x00\x07\x02\x02\x01\x01", 11);
	size_t pos = -1;
	std::vector<int>Id;
	std::vector<std::string>Oid;
	std::unordered_map<int, std::string>id_oid;
	while ((pos = temp.find(CATag)) != temp.npos)
	{
		pos -= 2;//sequence
		temp = temp.substr(pos);
		string temp_hex = BinaryToHexString(temp);
		std::string remainder;
		std::string oid;
		std::string sequence = extractValueFromTLVBinaryString(temp, temp);
		oid = extractValueFromTLVBinaryString(sequence, sequence);
		oid = "\x06\x0A" + oid;
		Oid.push_back(oid);
		sequence = extractValueFromTLVBinaryString(sequence, remainder);
		if (!remainder.size())
		{
			Id.push_back(0);
			id_oid[0] = oid;
			break;//PK只有一个
		}
		else
		{
			remainder = extractValueFromTLVBinaryString(remainder);
			int no = binaryStringToInt(remainder);
			Id.push_back(no);
			id_oid[no] = oid;
		}
	}
	temp = dg14;
	vector<CAInfo>cas;
	int id_int = 0;
	while ((pos = temp.find(CAECDHTag)) != temp.npos)
	{
		while (pos >= 0 && (temp.substr(pos, 2) != "\x30\x81" && temp.substr(pos, 2) != "\x30\x82"))
			pos--;
		temp = temp.substr(pos);
		std::string remainder = extractValueFromTLVBinaryString(temp, temp);
		extractValueFromTLVBinaryString(remainder, remainder);
		std::string id;
		std::string head;
		if (remainder.substr(0, 2) == "\x30\x81")
			head = remainder.substr(0, 3);
		else if (remainder.substr(0, 2) == "\x30\x82")
			head = remainder.substr(0, 4);
		else
			head = remainder.substr(0, 2);
		if (Id.size() != 1)
		{
			remainder = extractValueFromTLVBinaryString(remainder, id);
			id = extractValueFromTLVBinaryString(id);
			id_int = binaryStringToInt(id);
		}
		else
			remainder = extractValueFromTLVBinaryString(remainder);
		remainder = head + remainder;
		std::string remainder_hex = BinaryToHexString(remainder);
		remainder_hex = remainder_hex.substr(0, remainder_hex.length() - 1);
		CAInfo c(id_oid[id_int], remainder_hex, id_int);
		cas.push_back(c);
	}
	temp = dg14;
	while ((pos = temp.find(CADHTag)) != temp.npos)
	{
		while (pos >= 0 && (temp.substr(pos, 2) != "\x30\x81" && temp.substr(pos, 2) != "\x30\x82"))
			pos--;
		temp = temp.substr(pos);
		std::string remainder = extractValueFromTLVBinaryString(temp, temp);
		extractValueFromTLVBinaryString(remainder, remainder);
		std::string id;
		std::string head;
		if (remainder.substr(0, 2) == "\x30\x81")
			head = remainder.substr(0, 3);
		else if (remainder.substr(0, 2) == "\x30\x82")
			head = remainder.substr(0, 4);
		else
			head = remainder.substr(0, 2);
		if (Id.size() != 1)
		{
			remainder = extractValueFromTLVBinaryString(remainder, id);
			id = extractValueFromTLVBinaryString(id);
			id_int = binaryStringToInt(id);
		}
		else
			remainder = extractValueFromTLVBinaryString(remainder);
		remainder = head + remainder;
		std::string remainder_hex = BinaryToHexString(remainder);
		remainder_hex = remainder_hex.substr(0, remainder_hex.length() - 1);
		CAInfo c(id_oid[id_int], remainder_hex, id_int);
		cas.push_back(c);
	}
	CAinfo = cas;
	return true;
}
bool PCSCReader::SELECTCA(std::vector<CAInfo>& cainfo,
	std::string& cipherAlgorithm, 
	int keyLength,
	std::string SSC,
	const std::string& KSenc,
	const std::string& KSmac)
{
	bool useOneProtocal = false;
	if (cainfo.size() != 1)
		if (cainfo[0].getAlgorithmOid() == cainfo[1].getAlgorithmOid())
			useOneProtocal = true;
	std::string cmd("\x0C\x22\x41\xA4",4);
	std::string oid_binary = cainfo[0].getAlgorithmOid();
	oid_binary = oid_binary.substr(1, oid_binary.length() - 1);//去掉\x06
	std::string data = "\x80";
	data.append(oid_binary);
	if (useOneProtocal)//如果两个不同公钥使用同一个协议就用id区分
	{
		data.push_back('\x84');
		data.push_back(2);
		data.push_back(int(cainfo[0].getId() / 256));
		data.push_back(cainfo[0].getId() % 256);
	}
	LOG(INFO) << "SELECT CA DATA " << BinaryToHexString(data);
	//加密
	std::string cmdPadded = cmd;
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(cmdPadded);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(cmdPadded);
	std::string strFillData = data;
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(strFillData);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(strFillData);
	std::string strEncData;
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
		KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	}
	//构建DO97
	std::string DO97;
	DO97.push_back('\x97');
	DO97.push_back(1);
	DO97.push_back(0);
	// 构建DO87,并置cmdheader和DO87得到M
	std::string DO87;
	unsigned char L = (unsigned char)strFillData.size() + 1;
	unsigned char x87 = 0x87;
	DO87.push_back(x87);
	DO87.push_back(L);
	DO87.push_back(0x01);
	DO87.append(strEncData);
	std::string M = cmdPadded + DO87 + DO97;
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
		KmacDES(N, KSmac, CCN);
	// 用CCN构建DO8E
	std::string DO8E("\x8E\x08", 2);
	DO8E.append(CCN.data(), CCN.size());
	// 构建受保护的APDU
	std::string APDU;
	std::string cmd_secure("\x0C\x22\x41\xA4", 4);
	APDU += cmd_secure;
	unsigned char le_ = (unsigned char)DO87.size() + (unsigned char)DO8E.size() + (unsigned char)DO97.size();
	APDU.push_back(le_);//DO87+DO8E
	APDU.append(DO87.data(), DO87.size());
	APDU.append(DO97.data(), DO97.size());
	APDU.append(DO8E.data(), DO8E.size());
	/*
	 这里应该多加一个字节，中国护照可以不需要，但是国外的护照如果不加
	 这个字节，调用会失败
	 */
	APDU.push_back(0);
	LOG(INFO) << "SELECT CA SEND APDU " << BinaryToHexString(APDU);
	// 发送APDU
	int dwLen = APDU.size();
	auto APDU_hex = BinaryToHexString(APDU);
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	this->Apdusend(APDU, RecvBuff, RecvLen);
	//LOG(INFO)<< "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s((char*)&RecvBuff[0], RecvLen);
	LOG(INFO) << "SELECT CA SW: " << s.substr(s.length() - 2, 2);
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
		KmacDES(K, KSmac, CCK);
	// 从RAPDU中提取出DO8Er，验证是否等于CCK
	std::string RAPDU_DO8E = RAPDUParse(RAPDU, 0x8E);
	if (memcmp(RAPDU_DO8E.data() + 2, CCK.data(), 8) != 0) {
		return false;
	}
	
	return true;
}
bool PCSCReader::ChipAuthentication(std::string&dg14,
	std::string& cipherAlgorithm,
	int keyLength,
	std::string SSC,
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& newKSenc,
	std::string& newKSmac,
	int& newKeyLength,
	std::string& newCipherAlgorithm
	)
{
	std::vector<CAInfo> cainfo;
	CHECK_OK(GetCAPK(cainfo, dg14));
	LOG(INFO) << "GET CAPK SUCCESS";
	CHECK_OK(SELECTCA(cainfo,cipherAlgorithm,keyLength,SSC,KSenc,KSmac));
	LOG(INFO) << "SELECT CA SUCCESS";
	std::string SKmap, PKmap;//binary pk:04+x+y
	std::string PKIC;
	CHECK_OK(GetCAPKIC(PKIC, dg14,cainfo[0].getId()));
	EC_GROUP* ec_group = EC_GROUP_new(EC_GFp_mont_method());
	DH* dh = DH_new();
	if (cainfo[0].getAgreementType() == CA_ECDH)
		CHECK_OK(ComputeCAPK(cainfo, SKmap, PKmap, ec_group));
	if (cainfo[0].getAgreementType() == CA_DH)
		CHECK_OK(ComputeCAPK(cainfo, SKmap, PKmap, dh));
	LOG(INFO) << "CREATE CA SK&PK SUCCESS";
	CHECK_OK(CAGeneralAuthenticate(cainfo, cipherAlgorithm, keyLength, SSC, KSenc, KSmac, PKmap));
	std::string KA;
	if (cainfo[0].getAgreementType() == CA_ECDH)
	{
		EC_POINT* shared_secret = EC_POINT_new(ec_group);
		CHECK_OK(GetCAKA(ec_group, shared_secret, KA, SKmap, PKIC));
	}
	else if (cainfo[0].getAgreementType() == CA_DH)
	{
		BIGNUM* shared_secret = BN_new();
		CHECK_OK(GetCAKA(dh, shared_secret, KA, SKmap, PKIC));
	}
	std::string newCipherAlgorithm1 = cainfo[0].getCipherAlgorithm() == CA_CBC ? "DESede" : "AES";
	int newKeyLength1 = cainfo[0].getCipherLength();
	CHECK_OK(BuildKencandKmacPACE(KA,newKeyLength1,newCipherAlgorithm1,newKSenc,newKSmac));
	newKeyLength = newKeyLength1;
	newCipherAlgorithm = newCipherAlgorithm1;
	LOG(INFO) << "CA COMPLETE, NEW KeyLength AND NEW CIPHERALGORITHM: " << newKeyLength1 << " " << newCipherAlgorithm1 << endl;
	LOG(INFO) << "NEW KSENC AND NEW KSMAC: " << newKSenc << ' ' << newKSmac << endl;
	return true;
}
bool PCSCReader::GetCAPKIC(std::string& PKIC,std::string& dg14,int id)
{
	std::string CAECDHTag("\x06\x09\x04\x00\x7F\x00\x07\x02\x02\x01\x02", 11);
	std::string CADHTag("\x06\x09\x04\x00\x7F\x00\x07\x02\x02\x01\x01", 11);
	if (dg14.find(CAECDHTag) != dg14.npos)
	{
		std::string temp;
		std::string remainder = dg14;
		while (remainder.find(CAECDHTag) != remainder.npos)
		{
			std::string save = remainder;
			size_t pos1 = remainder.find(CAECDHTag);
			size_t pos = pos1;
			while (remainder.substr(pos, 2) != "\x30\x81" && remainder.substr(pos, 2) != "\x30\x82")
				pos--;
			temp = remainder.substr(pos);
			temp = extractValueFromTLVBinaryString(temp, remainder);
			extractValueFromTLVBinaryString(temp, temp);
			extractValueFromTLVBinaryString(temp, temp);
			int idd = 0;
			if (temp.size() != 0)
			{
				temp = extractValueFromTLVBinaryString(temp);
				idd = binaryStringToInt(temp);
			}
			if (idd == id)
			{
				pos1 += CAECDHTag.length();
				temp = save.substr(pos1);
				temp = extractValueFromTLVBinaryString(temp);
				extractValueFromTLVBinaryString(temp, temp);
				temp = extractValueFromTLVBinaryString(temp);
				if (temp[0] == '\x04')
					temp = temp.substr(1);
				PKIC=temp;
				return true;
			}
		}

	}
	else if (dg14.find(CADHTag) != dg14.npos)
	{
		std::string temp;
		std::string remainder = dg14;
		while (remainder.find(CADHTag) != remainder.npos)
		{
			std::string save = remainder;
			size_t pos1 = remainder.find(CADHTag);
			size_t pos = pos1;
			while (remainder.substr(pos, 2) != "\x30\x81" && remainder.substr(pos, 2) != "\x30\x82")
				pos--;
			temp = remainder.substr(pos);
			temp = extractValueFromTLVBinaryString(temp, remainder);
			extractValueFromTLVBinaryString(temp, temp);
			extractValueFromTLVBinaryString(temp, temp);
			int idd = 0;
			if (temp.size() != 0)
			{
				temp = extractValueFromTLVBinaryString(temp);
				idd = binaryStringToInt(temp);
			}
			if (idd == id)
			{
				pos1 += CADHTag.length();
				temp = save.substr(pos1);
				temp = extractValueFromTLVBinaryString(temp);
				extractValueFromTLVBinaryString(temp, temp);
				temp = extractValueFromTLVBinaryString(temp);
				temp = extractValueFromTLVBinaryString(temp);
				PKIC = temp;
				return true;
			}
		}
	}
	else
		return false;
}
bool PCSCReader::GetCAKA(EC_GROUP*& ec_group, EC_POINT*& shared_secret, std::string& KA_X, std::string& SKmap, std::string& PKIC)
{
	std::string SKmap_hex = BinaryToHexString(SKmap);
	std::string PKIC_hex = BinaryToHexString(PKIC);
	get_shared_secret(ec_group, SKmap_hex, PKIC_hex, shared_secret);
	EC_POINT* KA = EC_POINT_new(ec_group);
	BIGNUM* KA_bn = EC_POINT_point2bn(ec_group, shared_secret, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
	char* public_key_hex_char = BN_bn2hex(KA_bn);
	std::string KA_hex = public_key_hex_char;
	LOG(INFO) << "KA_HEX " << KA_hex << endl;
	KA_X = KA_hex.substr(2, KA_hex.size() / 2 - 1);
	LOG(INFO) << "KA_X " << KA_X << endl;
	return true;
}
bool PCSCReader::GetCAKA(DH*& dh, BIGNUM*& shared_secret, std::string& KA, std::string& SKmap, std::string& PKIC)
{
	std::string SKmap_hex = BinaryToHexString(SKmap);
	std::string PKIC_hex = BinaryToHexString(PKIC);
	BIGNUM* KA_BN = BN_new();
	get_shared_secret(dh, SKmap_hex, PKIC_hex, KA_BN);
	shared_secret = KA_BN;
	KA = BN_bn2hex(KA_BN);
	return true;
}
bool PCSCReader::CAGeneralAuthenticate(std::vector<CAInfo>& cainfo,
	std::string& cipherAlgorithm,
	int keyLength,
	std::string SSC,
	const std::string& KSenc,
	const std::string& KSmac,
	std::string& PKIFD)
{
	std::string cmd("\x0C\x86\x00\x00", 4);
	std::string data = "";
	std::string length1 = lengthtoBinary(PKIFD.length());
	data = PKIFD;
	data = length1 + data;
	data = "\x80" + data;
	std::string length2 = lengthtoBinary(data.length());
	data = "\x7c" + length2 + data;
	bool longCommand = false;
	std::string Le;
	if (data.length() >= 256)
	{
		longCommand = true;
		Le.push_back(0);
		Le.push_back(0);
	}
	else
		Le.push_back(0);
	std::string CmdHeader(cmd);
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(CmdHeader);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(CmdHeader);
	std::string strFillData = data;


	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(strFillData);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(strFillData);
	// 用SKenc加密数据
	std::string strEncData;
	//KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	//加密SSC
	std::string iv = "";
	if (cipherAlgorithm == "AES") {
		iv = "00000000000000000000000000000000";
	}
	iv = HexStringToBinary(iv);
	IncreaseSSC(SSC); //SSC += 1
	auto SSC_hex = BinaryToHexString(SSC);
	if (cipherAlgorithm == "AES")
	{
		std::string SSC_IV;
		aes_cbc_encode(KSenc, SSC, SSC_IV, iv);
		auto SSC_IV_hex = BinaryToHexString(SSC_IV);
		auto strFillData_hex = BinaryToHexString(strFillData);
		aes_cbc_encode(KSenc, strFillData, strEncData, SSC_IV, keyLength);
		//aes_cbc_encode(KSenc, strFillData, strEncData, iv);
		auto strEncData_hex = BinaryToHexString(strEncData);
	}
	else if (cipherAlgorithm == "DESede")
	{
		KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	}

	auto strEncData_hex = BinaryToHexString(strEncData);

	// 构建DO87,并置cmdheader和DO87得到M
	std::string DO87;
	int L = strFillData.size() + 1;
	std::string length3 = lengthtoBinary(L);
	unsigned char x87 = 0x87;
	DO87.push_back(x87);
	DO87 += length3;
	DO87.push_back(0x01);
	DO87 += strEncData;
	std::string DO97;
	DO97.push_back('\x97');
	if (longCommand)
	{
		DO97.push_back(2);
		DO97 += Le;
	}
	else
	{
		DO97.push_back(1);
		DO97 += Le;
	}
	std::string M = CmdHeader + DO87 + DO97;


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
		KmacDES(N, KSmac, CCN);
	// 用CCN构建DO8E
	std::string DO8E("\x8E\x08", 2);
	DO8E += CCN;
	// 构建受保护的APDU
	std::string APDU = "";
	//std::string unprotectedAPDU2("\x0C\x88\x00\x00\x00\x00", 6);
	APDU+=cmd;
	int Lc_ = DO87.size() + DO8E.size() + DO97.size() ;
	if (Lc_ >= 256)
	{
		APDU.push_back(0);
		APDU.push_back(int(Lc_ / 256));
		APDU.push_back(Lc_ % 256);
	}
	else
		APDU.push_back(Lc_);//DO87+DO8E
	APDU += DO87;
	APDU += DO97;
	APDU += DO8E;
	/*
	 这里应该多加一个字节，中国护照可以不需要，但是国外的护照如果不加
	 这个字节，调用会失败
	 */
	if (Lc_ >= 256)
	{
		APDU.push_back(0);
		APDU.push_back(0);
	}
	else
		APDU.push_back(0);
	LOG(INFO) << "CAGeneralAuthenticate SEND APDU " << BinaryToHexString(APDU);
	//APDU.push_back(0);
	// 发送APDU
	int dwLen = APDU.size();
	auto APDU_hex = BinaryToHexString(APDU);
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	this->Apdusend(APDU, RecvBuff, RecvLen);
	//LOG(INFO)<< "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s((char*)&RecvBuff[0], RecvLen);
	std::string RAPDU;//DO87+DO99+DO8E+SW1+SW2
	RAPDU.append(s);
	auto RAPDU_hex = BinaryToHexString(RAPDU);
	LOG(INFO) << "CAGeneralAuthenticate RAPDU " << RAPDU_hex;
	// ------------------------------------------------------------
	// h.通过计算DO87和DO99并置的MAC, 验证RAPDU CC
	int tlLen = 0;
	std::string RAPDU_DO87 = RAPDUParse(RAPDU, 0x87, &tlLen);
	std::string RAPDU_DO8E = RAPDUParse(RAPDU, 0x8E);
	std::string RAPDU_DO99 = RAPDUParse(RAPDU, 0x99);

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
bool PCSCReader::ComputeCAPK(std::vector<CAInfo>& cainfo, std::string& SKmap, std::string& PKmap, EC_GROUP*& ec_group)
{
	EC_KEY* ec_key = cainfo[0].getKey();
	std::string pkstr = cainfo[0].getPublicKeyString();
	size_t pos = pkstr.find("06072a8648ce3d0201") + 18;
	std::string head = pkstr.substr(pos, 4);
	std::string ecc_oid = pkstr.substr(pos);
	ecc_oid = extractValueFromTLVHexString(ecc_oid);
	ecc_oid = head + ecc_oid;
	int nid = EccOidToNid(ecc_oid);
	if (nid == 12)
		Buildsecp256r1(ec_group);
	else
		ec_group = EC_GROUP_new_by_curve_name(nid);
	if (!EC_KEY_generate_key(ec_key)) {
		cerr << "Failed to generate EC key" << endl;
		EC_KEY_free(ec_key);
		return false;
	}
	// 获取终端映射密钥对
	const BIGNUM* private_key_out = EC_KEY_get0_private_key(ec_key);
	char* private_key_hex_char = BN_bn2hex(private_key_out);
	SKmap = private_key_hex_char;
	LOG(INFO) << "CA ECDH SKMAP " << SKmap << endl;
	SKmap = HexStringToBinary(SKmap);

	const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key);
	BIGNUM* public_key_bn = EC_POINT_point2bn(ec_group, public_key, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
	char* public_key_hex_char = BN_bn2hex(public_key_bn);
	PKmap = public_key_hex_char;
	LOG(INFO) << "CA ECDH PKMAP " << PKmap << endl;
	PKmap = HexStringToBinary(PKmap);
	return true;
}
bool PCSCReader::ComputeCAPK(std::vector<CAInfo>& cainfo, std::string& SKmap, std::string& PKmap, DH*& dh)
{
	const BIGNUM* pub_key = nullptr;
	const BIGNUM* priv_key = nullptr;
	dh = cainfo[0].getDH();
	DH_get0_key(dh, &pub_key, &priv_key);
	std::string pub_key_hex="";
	std::string priv_key_hex="";
	if (pub_key && priv_key) {
		pub_key_hex = BN_bn2hex(pub_key);
		priv_key_hex = BN_bn2hex(priv_key);
		LOG(INFO) << "CA DH Public Key: " << pub_key_hex << "\n";
		LOG(INFO) << "CA DH Private Key: " << priv_key_hex << "\n";
	}
	if (priv_key_hex.length() == 0 || pub_key_hex.length() == 0)
		return false;
	SKmap = priv_key_hex;
	PKmap = pub_key_hex;
	SKmap = HexStringToBinary(SKmap);
	PKmap = HexStringToBinary(PKmap);
	return true;
}
void PCSCReader::InitalizeState()
{
	OnTimeDetectionChips = 4;
	AppStatus = 4;
	BAC = 4;
	PACE = 4;
	AA = 4;
	PA = 4;
	CA = 2;
	SODCheck = 4;
	IntegrityCheck = 4;
	DSCCheck = 4;
	IssuingCountryCheck = 4;
	DSCDateCheck = 4;
	COM = "", SOD = "", DSC = "",DG1 = "", DG1detail = "", DG2 = "", DG3 = "", DG4 = "", DG5 = "", DG6 = "", DG7 = "";
	DG8 = "", DG9 = "", DG10 = "", DG11 = "", DG12 = "", DG13 = "", DG14 = "", DG15 = "", DG16 = "";
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
	std::string CardAccess = "", CardSecurity = "";
	BAC = 1;
	OnTimeDetectionChips = 4;
	AppStatus = 4;
	PACE = 4;
	ChipAuthenticResult.BAC = 1;
	ChipAuthenticResult.PACE = 4;
	int ret = -1;
	BYTE  RecvBuff[300];
	DWORD RecvLen;
	ret = ReadCardAccessAndCardSecurity(CardAccess, CardSecurity);
	string selectAPP  ("\x00\xA4\x04\x0C\x07\xA0\x00\x00\x02\x47\x10\x01",12);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	Apdusend(selectAPP, RecvBuff, RecvLen);
	LOG(INFO) << "SELECT APP,SEND APDU: 00 A4 04 0C 07 A0 00 00 02 47 10 01" << '\n';
	LOG(INFO) << "SELECT APP, RETURN： " << BYTE2string(RecvBuff, (UINT)RecvLen) << '\n';

	if (RecvBuff[0] == 0)
	{
		OnTimeDetectionChips = 1;//无芯片
	}
	if (RecvBuff[0] != '\x90' && RecvBuff[1] != '\x00')
	{
		LOG(INFO) << "SELECT APP FAIL\n";
		OnTimeDetectionChips = 0;
		AppStatus = 1;
		return false;
	}
	else
	{
		OnTimeDetectionChips = 0;
		AppStatus = 0;
	}
	
	//2.	生成Kenc和Kmac

	CHECK_OK(BuildKencAndKmac(codetonfc, Kenc, Kmac));
	// 3.	请求随机数
	//CString m_RND_ICC = "0084000008";
	string m_RND_ICC ("\x00\x84\x00\x00\x08",5);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	Apdusend(m_RND_ICC, RecvBuff, RecvLen);
	LOG(INFO) << "REQUEST RANDOM NUMBER, APDU SEND: " << "00 84 00 00 08\n";
	if (RecvLen != 10) {
		LOG(ERROR)<< "REQUEST RANDOM NUMBER FAIL\n";
		return -1;
	}
	else {
		for (int i = 0; i < 8; ++i) {
			RND_ICC += RecvBuff[i];
		}
		LOG(INFO) << "RAPDU: " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
		LOG(INFO) << "RND_ICC: " << BinaryToHexString(RND_ICC) << endl;
	}
	// 4.	生成一个随机的8字节RNDifd和一个随机的16字节Kifd
	CHECK_OK(BuildIFD(RND_IFD, Kifd));
	LOG(INFO) << "BUILD RND_IFD AND KIFD: \nRND_IFD: " << BinaryToHexString(RND_IFD) << " KIFD: " << BinaryToHexString(Kifd) << '\n';
	//5.	发起Mutual认证
	CHECK_OK(ICCMutualAuthenticate(RND_IFD, RND_ICC, Kifd, Kenc, Kmac, KSenc, KSmac));
	LOG(INFO) << "BAC MUTUALAUTHENTICATION SUCCESS\n";
	BAC = 0;
	ChipAuthenticResult.BAC = 0;
	//6.Build SSC
	CHECK_OK(BuildSSC(RND_IFD, RND_ICC, SSC));

	// 准备好 KSenc KSmac SSC 后，开始进行安全通信
	std::string EF_COM_Data;
	LOG(INFO) << "READING EF_COM";
	// 读取EF.COM文件，并检查该护照存在哪些文件
	CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, EF_COM, EF_COM_Data));
	LOG(INFO) << "READ EF_COM SUCCESS";
	char EF_COM_Path[512];
	MakeFullPath1(EF_COM_Path, EF_COM_FILENAME);
	std::ofstream  Output(EF_COM_Path, std::ios::binary);
	if (Output) {
		Output.write(EF_COM_Data.c_str(), EF_COM_Data.size());
		Output.close();
	}
	//std::string tags = EF_COM_TagsParse(EF_COM_Data);
	std::string tags = EF_COM_TagsParse(EF_COM_Data);
	std::string tags_hex = BinaryToHexString(tags);
	//EFFileSystem efs;
	STEFFile* stFile = NULL;
	LOG(INFO)<< "READING FILE, CONTAINS:\n";
	std::unordered_map<int, std::string> DGs;
	// 读取其他文件
	for (size_t i = 0; i < tags.size(); i++) {
		unsigned char b = tags[i];
		//LOG(INFO)<< "tag" << b << endl;
		stFile = StTagFindEFFile(b, &st_efs);
		LOG(INFO)<<stFile->name << '\n';
		if (NULL == stFile|| stFile->Index == EF_COM|| stFile->Index == EF_DG3|| stFile->Index == EF_DG4) {
			continue;
		}

		std::string ef_data;
		// 如果该类型EF解析器未实现则不读该文件
		SelectFunc(stFile);
		if (!stFile->Valid()) {
			continue;
		}
		// 读取文件
		CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, stFile->Index, ef_data));
		LOG(INFO) << "READ "<<stFile->name <<" SUCCESS \n";
		// 解析文件,但是往结构体存的还是原始文件，所以长度字段还是原始文件的长度
		if (stFile->FileParse(ef_data, &st_efs)) {
			DGs.emplace(stFile->Index, ef_data);
			ChipReaderReadFileResultOperate(stFile->Index, ef_data, 2, ef_data.size());
			LOG(INFO) << "PARSE AND SAVE SUCCESS";
			/*
				if (this->cb) {
					this->cb->OnChipReaderReadFileResult(stFile->Index, stFile->result,this->GetCardType());
				}*/
		}
	}
	//read SOD 必然存在
	std::string sod_data;
	LOG(INFO) << "READING SOD";
	CHECK_OK(ICCReadEF(KSenc, KSmac, SSC, EF_SOD, sod_data));
	LOG(INFO) << "READ SOD SUCCESS";
	SODCheck = 0;
	ChipReaderReadFileResultOperate(EF_SOD, sod_data, 2, sod_data.size());
	LOG(INFO) << "SAVE SUCCESS";
	ChipAuthenticResult.BAC = 1;

	//进行主动认证
	LOG(INFO) << "STARTING AA";
	char mypath[256];
	MakeFullPath1(mypath, "USB_TEMP\\DG15.bin");
	std::string cipherAlgorithm = "DESede";
	int keyLength = 128;
	try
	{
		ret = ActiveAuthentication(mypath, KSenc, KSmac, SSC, cipherAlgorithm, 128);
	}
	catch (const std::exception& e)
	{
		LOG(ERROR) << e.what();
	}
	if(ret == 0)
	{
		LOG(WARNING)<< "ActiveAuthentication success" << std::endl;
		ChipAuthenticResult.AA = 0;
		AA = 0;
	}
	else {
		LOG(INFO) << "ActiveAuthentication fail" << std::endl;
		ChipAuthenticResult.AA = 1;
		AA = 1;
	}
	// passive auth
	char SOD_file_path[256];
	MakeFullPath1(SOD_file_path, "USB_TEMP\\SOD.bin");
	try
	{
		ret = PassiveAuthentication(SOD_file_path, DGs);
	}
	catch (const std::exception& e)
	{
		LOG(ERROR) << e.what();
	}
	if (ret) {
		LOG(INFO) << "PassiveAuthentication success" << std::endl;
		
	}
	else {
		LOG(WARNING) << "PassiveAuthentication failed" << std::endl;
	}
	std::string newKSenc, newKSmac, newCipherAlgorithm;
	int newKeyLength;
	std::string dg14data(ChipData_Doc9303_Result.pDG14, ChipData_Doc9303_Result.iDG14);
	if (dg14data.length() != 0 && dg14data.find("\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x03") != dg14data.npos)
	{
		LOG(INFO) << "SUPPORT CA";
		/*CA = 1;
		ChipAuthenticResult.CA = 1;
		bool ret = false;
		try
		{
			ret = ChipAuthentication(dg14data, cipherAlgorithm, keyLength, SSC, KSenc, KSmac, newKSenc, newKSmac, newKeyLength, newCipherAlgorithm);
		}
		catch (const std::exception& e)
		{
			LOG(ERROR) << e.what();
		}
		if (ret)
		{
			CA = 0;
			ChipAuthenticResult.CA = 0;
			cipherAlgorithm = newCipherAlgorithm;
			keyLength = newKeyLength;
			KSenc = newKSenc;
			KSmac = newKSmac;
		}*/
	}
	else
		LOG(INFO) << "CA NOT SUPPORTED";
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
		//LOG(INFO)<< "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
		
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
			LOG(INFO)<< "Post failed, SW=0x" << std::hex << std::setw(4) << std::setfill('0')
				<< HostToNetworkUINT16(*ssw) << "SW != 9000" << std::endl;
			return FALSE;
		}
		response.erase(response.size() - 2, 2);
		return TRUE;
	}
	else {
		LOG(INFO)<< "RF_14443_Apdu Return  : " << BinaryToHexString((const char*)cpAPDU) << std::endl;
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
	//LOG(INFO)<< "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
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
	////LOG(INFO)<< "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
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
	//	LOG(INFO)<< "Post failed, SW=0x" << std::hex << std::setw(4) << std::setfill('0')
	//		<< HostToNetworkUINT16(*ssw) << "\n未找到成功标志" << std::endl;
	//	return FALSE;
	//}
	//data.erase(data.size() - 2, 2);


	return true;
}



BOOL PCSCReader::SelectPACE(std::string& oid, bool byCAN)
{
	/// 选择PACE
	std::string selectPACECmd("\x00\x22\xC1\xA4\x0F\x80\x0A", 7);
	//std::string selectPACECmd("\x00\x22\xC1\xA4\x0F\x80\x0A\x04\x00\x7F\x00\x07\x02\x02\x04\x02\x04\x83\x01\x01", 20);

	selectPACECmd.append(oid);

	//std::string tail("\x83\x01\x01", 3);
	if(!byCAN)
		selectPACECmd.append("\x83\x01\x01",3);
	else
		selectPACECmd.append("\x83\x01\x02", 3);
	//00A4040C07A0000002471001
	std::string selectPACERAPDU;
	auto cmd_hex = BinaryToHexString(selectPACECmd);
	BYTE  RecvBuff[300];
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	BOOL ret = Apdusend(selectPACECmd, RecvBuff, RecvLen);
	LOG(INFO) << "selectPACECmd " << BinaryToHexString(selectPACECmd);
	//LOG(INFO)<< "选择签发者应用返回： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	if (RecvBuff[0] == 0)
		OnTimeDetectionChips = 1;
	else
		OnTimeDetectionChips = 0;
	if (ret < 0) {
		return FALSE;
	}
	AppStatus = 0;
	return TRUE;
}

BOOL PCSCReader::ICCRequestRandomNumberPACE(std::string& ICC_Z) {
	std::string randCmd("\x10\x86\x00\x00\x02\x7C\x00\x00", 8);


	std::string RAPDU;
	int ret = PostPassportCommand(randCmd, RAPDU);
	LOG(INFO) << "randCmd " << BinaryToHexString(randCmd);
	//LOG(INFO)<< "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;

	if (!ret ) {
		return FALSE;
	}
	else
	{
		ICC_Z = extractValueFromTLVBinaryString(RAPDU);
		ICC_Z = extractValueFromTLVBinaryString(ICC_Z);
	}
	//ICC_Z = RAPDU.substr(4, 16);

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
		LOG(INFO)<< "kpai"<<endl<<Kpaihex << endl;
		
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
		LOG(INFO)<< "kpai" << endl << Kpaihex << endl;
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
	LOG(INFO)<< "KSenc " << KSenc_hex << endl << "KSmac "<<KSmac_hex << endl;
	return TRUE;
}

BOOL PCSCReader::BuildMapKey(std::string& PKmap, std::string& SKmap, int ecc_id) {
	if (ecc_id > 2)
	{
		EC_GROUP* ec_group = EC_GROUP_new(EC_GFp_mont_method());
		if(ecc_id != 12)
			ec_group = EC_GROUP_new_by_curve_name(ecc_id);
		else 
			int ret = Buildsecp256r1(ec_group);
		if (!ec_group) {
			LOG(ERROR) << "Failed to create EC group" << endl;
			return false;
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
		LOG(INFO) << "SKMAP " << SKmap << ",BIT LENGTH " << SKmap.size() * 8;
		SKmap = HexStringToBinary(SKmap);

		const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key);
		BIGNUM* public_key_bn = EC_POINT_point2bn(ec_group, public_key, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
		char* public_key_hex_char = BN_bn2hex(public_key_bn);
		PKmap = public_key_hex_char;
		LOG(INFO) << "PKMAP " << PKmap << ",BIT LENGTH " << PKmap.size() * 8;
		PKmap = HexStringToBinary(PKmap);
	}
	else if (ecc_id >= 0 && ecc_id <= 2)
	{
		DH* dh = DH_new();
		int ret = BuildGFP(dh, ecc_id);
		ret = DH_generate_key(dh);
		if (!ret)
		{
			LOG(INFO) << "DH GENERATE KEY FAIL";
			return false;
		}
		const BIGNUM* priv= DH_get0_priv_key(dh);
		const BIGNUM* pub = DH_get0_pub_key(dh);
		string PKmap_hex = BN_bn2hex(pub);
		string SKmap_hex = BN_bn2hex(priv);
		LOG(INFO) << "DH PUBLIC KEY " << PKmap_hex << ",BIT LENGTH " << PKmap_hex.size() * 8;
		LOG(INFO)<<"DH PRIVATE KEY " << SKmap_hex << ",BIT LENGTH " << SKmap_hex.size() * 8;
		PKmap = HexStringToBinary(PKmap_hex);
		SKmap = HexStringToBinary(SKmap_hex);
		return ret;
	}
}

BOOL PCSCReader::RandomNumberMap(std::string& PKmap_IC, const std::string& PKmap, const std::string& SKmap,
	bool isECDH) {
	std::string sendPKmapCmd("\x10\x86\x00\x00", 4);
	//终端向芯片发送 PKmap
		
	int PKmap_len = PKmap.size();
	bool longCommand = false;
	std::string length1BinaryString = lengthtoBinary(PKmap_len);
	std::string DO81("\x81", 1);
	DO81 = DO81 + length1BinaryString + PKmap;
	std::string length2BinaryString = lengthtoBinary(DO81.length());
	std::string DO7C("\x7c", 1);
	DO7C = DO7C + length2BinaryString + DO81;
	if (DO7C.length() >= 256)
		longCommand = true;
	std::string Lc = "";
	if (longCommand)
	{
		Lc.push_back(0);
		Lc.push_back(int(DO7C.length() / 256));
		Lc.push_back(DO7C.length() % 256);
	}
	else
		Lc.push_back(DO7C.size());
	std::string Le = "";
	if (longCommand)
	{
		Le.push_back(0);
		Le.push_back(0);
	}
	else
		Le.push_back(0);
	sendPKmapCmd = sendPKmapCmd + Lc + DO7C + Le;

	auto sendPKmapCmd_str = BinaryToHexString(sendPKmapCmd);
	LOG(INFO) << "RandomNumberMap SEND APDU " << sendPKmapCmd_str;
	std::string RAPDU;

	int ret = PostPassportCommand(sendPKmapCmd, RAPDU);
	if (!ret || RAPDU.size() < DO7C.length()/2) {
		LOG(INFO) << "Failed to send PKmap,Return " << ret << endl;
		return FALSE;
	}
	LOG(INFO) << "FIRST MAP, RECEIVE RAPDU " << BinaryToHexString(RAPDU);
	PKmap_IC = RAPDU;
	PKmap_IC = extractValueFromTLVBinaryString(PKmap_IC);//去掉7C
	PKmap_IC = extractValueFromTLVBinaryString(PKmap_IC);//去掉81
	if (isECDH)
		PKmap_IC = PKmap_IC.substr(1);//去掉04
	LOG(INFO) << "PKmap_IC " << BinaryToHexString(PKmap_IC);
	return true;

	/*
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
		LOG(INFO)<< "Failed to send PKmap,Return " << ret << endl;
		return FALSE;
	}
	if (PKmap_len == 129 || PKmap_len == 133)
	{
		PKmap_IC = RAPDU.substr(7, RAPDU.size() - 7);
		return TRUE;
	}
	PKmap_IC = RAPDU.substr(5, RAPDU.size() - 5);
	return TRUE;*/
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
	BN_CTX* ctx = BN_CTX_new();
	const BIGNUM* order = EC_GROUP_get0_order(ec_group_temp);
	const BIGNUM* cofactor = EC_GROUP_get0_cofactor(ec_group_temp);
	EC_GROUP_get_curve(ec_group_temp, p, a, b, ctx);

	EC_GROUP* new_curve = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	int ret = EC_GROUP_set_generator(new_curve, G_hat, order, cofactor);
	if (ret != 1)
	{
		LOG(ERROR) << "ECDH SET G_HAT GENERATOR FAIL";
		return false;
	}
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
	LOG(INFO)<< "SK ECDHIFD " << SKDH_IFD << endl;
	SKDH_IFD = HexStringToBinary(SKDH_IFD);

	const EC_POINT* public_key = EC_KEY_get0_public_key(ec_key);
	BIGNUM* public_key_bn = EC_POINT_point2bn(new_curve, public_key, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
	char* public_key_hex_char = BN_bn2hex(public_key_bn);
	std::string PKDH_IFD_hex = public_key_hex_char;
	LOG(INFO)<< "PK ECDHIFD_HEX " << PKDH_IFD_hex << endl;
	PKDH_IFD= HexStringToBinary(PKDH_IFD_hex);

	//终端向芯片发送公钥 PKDF_IFD
	std::string sendPKmapCmd("\x10\x86\x00\x00", 4);
	unsigned int PKmap_len = PKDH_IFD.size();
	LOG(INFO) << "PKmap_len " << PKmap_len;
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
	LOG(INFO) << "sendPKmapCmd_str " << sendPKmapCmd_str;
	std::string RAPDU;

	ret = PostPassportCommand(sendPKmapCmd, RAPDU);
	if (!ret || RAPDU.size() < Auth_len) {
		LOG(INFO)<< "Failed to send PKmap,Return " << ret << endl;
		return FALSE;
	}
	LOG(INFO)<< "RAPDU " << BinaryToHexString(RAPDU) << endl;
	if (PKmap_len == 129 || PKmap_len == 133)
		PKDH_IC = RAPDU.substr(7, RAPDU.size() - 7);
	else
		PKDH_IC = RAPDU.substr(5, RAPDU.size() - 5);
	//去除头部的"\x04"字节
	PKDH_IFD = PKDH_IFD.substr(1, PKDH_IFD.size() - 1);
	LOG(INFO) << "PKDH_IC " << BinaryToHexString(PKDH_IC);
	return TRUE;
}
BOOL PCSCReader::MutualAuthenticate(BIGNUM*& G_hat, std::string& PKDH_IC, std::string& SKDH_IFD, std::string& PKDH_IFD, BIGNUM*& prime)
{
	int ret = -1;
	DH* dh_temp = DH_new();
	ret = DH_set0_pqg(dh_temp,prime,nullptr,G_hat);
	BN_CTX* ctx = BN_CTX_new();
	ret = DH_generate_key(dh_temp);
	if (!ret)
	{
		LOG(INFO) << "DH MUTUALAUTHENTICATE FAIL TO GENERATE KEY PAIR" ;
		return false;
	}
	const BIGNUM* public_key = BN_new();
	const BIGNUM* private_key = BN_new();
	public_key = DH_get0_pub_key(dh_temp);
	private_key = DH_get0_priv_key(dh_temp);
	std::string PKDH_IFD_hex, SKDH_IFD_hex;
	PKDH_IFD_hex = BN_bn2hex(public_key);
	SKDH_IFD_hex = BN_bn2hex(private_key);
	LOG(INFO)<< "PKDH_IFD_hex" << endl << PKDH_IFD_hex << endl;
	LOG(INFO)<< "SKDH_IFD_hex" << endl << SKDH_IFD_hex << endl;
	PKDH_IFD = HexStringToBinary(PKDH_IFD_hex);
	SKDH_IFD = HexStringToBinary(SKDH_IFD_hex);
	
	std::string sendPKmapCmd("\x10\x86\x00\x00", 4);
	bool longCommand = false;
	std::string length1 = lengthtoBinary(PKDH_IFD.size());
	std::string DO83("\x83", 1);
	DO83 += length1 + PKDH_IFD;
	std::string length2 = lengthtoBinary(DO83.size());
	std::string DO7C("\x7c", 1);
	DO7C += length2 + DO83;
	if (DO7C.size() >= 256)
		longCommand = true;
	std::string Lc = "";
	if (longCommand)
	{
		Lc.push_back(0);
		Lc.push_back(int(DO7C.size() / 256));
		Lc.push_back(DO7C.size() % 256);
	}
	else
		Lc.push_back(DO7C.size()) ;
	sendPKmapCmd.append(Lc, Lc.size());
	sendPKmapCmd.append(DO7C, DO7C.size());
	sendPKmapCmd.push_back(0);
	/*unsigned int PKmap_len = PKDH_IFD.size();
	LOG(INFO)<< "PKmap_len " << PKmap_len << endl;
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
	}*/
	auto sendPKmapCmd_str = BinaryToHexString(sendPKmapCmd);
	LOG(INFO) << "sendPKmapCmd_str " << sendPKmapCmd_str;
	std::string RAPDU;

	ret = PostPassportCommand(sendPKmapCmd, RAPDU);
	if (!ret) {
		LOG(INFO)<< "Failed to send PKmap,Return " << ret << endl;
		return FALSE;
	}
	LOG(INFO) << "DH MutualAuthenticate RAPDU " << BinaryToHexString(RAPDU);
	PKDH_IC = extractValueFromTLVBinaryString(RAPDU);
	PKDH_IC = extractValueFromTLVBinaryString(PKDH_IC); 
	/*if (PKmap_len == 128)
	{
		PKDH_IC = RAPDU.substr(6, RAPDU.size() - 6);
	}
	else if (PKmap_len == 256)
	{
		PKDH_IC = RAPDU.substr(8, RAPDU.size() - 8);
	}*/
	LOG(INFO)<< "PKDH_IC " << PKDH_IC << endl;
	return TRUE;
}
BOOL PCSCReader::ExchangeT(std::string& TIFD, std::string& TICC_my, std::string& RAPDU) {

	//终端向芯片发送 PKmap
	std::string sendTIFD("\x00\x86\x00\x00\x0C\x7C\x0A\x85\x08", 9);
	sendTIFD.append(TIFD);
	sendTIFD.push_back(0);

	auto sendTIFD_str = BinaryToHexString(sendTIFD);

	int ret = PostPassportCommand(sendTIFD, RAPDU);
	LOG(INFO) << "EXCHANGE TIC AND TIFD.";
	LOG(INFO) << "RAPDU " << BinaryToHexString(RAPDU);
	LOG(INFO) << "SEND TIFD " << sendTIFD_str;
	if (!ret) {
		LOG(INFO) << "Failed to send TIFD,Return " << ret << endl;
		return FALSE;
	}

	std::string temp = RAPDU;
	temp = extractValueFromTLVBinaryString(temp);
	temp = extractValueFromTLVBinaryString(temp);
	std::string TICC = temp;
	LOG(INFO) << "TIC RECEIVED " << BinaryToHexString(TICC);
	if (memcmp(TICC.data(), TICC_my.data(), 8) != 0) {
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
	//LOG(INFO)<< "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
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
	//LOG(INFO)<< "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
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
	//LOG(INFO)<< "ReadBinary RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
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
bool PCSCReader::SendAnotherRandomNumber(std::string& T_ICC, int keyLength)
{
	T_ICC.resize(keyLength / 8);//T 长度是秘钥长度
	BuildRandomData(T_ICC);
	std::string DO81("\x81", 1);
	DO81.push_back(T_ICC.size());
	DO81+=T_ICC;
	std::string DO7C("\x7c", 1);
	DO7C.push_back(DO81.size());
	DO7C+=DO81;
	std::string sendRandomNumber("\x10\x86\x00\x00", 4);
	sendRandomNumber.push_back(DO7C.size());
	sendRandomNumber+=DO7C;
	sendRandomNumber.push_back(0);
	BYTE  RecvBuff[300];
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	wlString wlstring;
	this->Apdusend(sendRandomNumber, RecvBuff, RecvLen);
	std::string s((char*)&RecvBuff[RecvLen - 2], 2);
	LOG(INFO) << "SEND IFD RANDOM NUMBER " << BinaryToHexString(T_ICC) << ", RECEIVE S:" << BinaryToHexString(s);
	if (s[0] != '\x90' && s[1] != '\x00')
		return false;
	return true;
}
bool PCSCReader::PseudoRandomNumberMapping(
	std::string& S_ICC,
	std::string& T_ICC,
	int keyLength,
	std::string& cipherAlgorithm,
	BIGNUM* p,
	BIGNUM*& mappingResult)
{
	size_t l = S_ICC.size() * 8;
	LOG(INFO) << "SICC LENGTH" << l;
	size_t k = T_ICC.size() * 8;
	LOG(INFO) << "TICC LENGTH" << k;
	BN_CTX* ctx = BN_CTX_new();
	int ret = -1;
	LOG(INFO) << "ECDH IM, P OF ECGROUP " << BN_bn2hex(p);
	int n = 0;
	std::string iv_aes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);//16字节初始向量,cbc函数内自带iv
	std::string ki="";
	std::string xi="";
	std::string x="";
	int log2 = getLog2(p);
	n = ceil((log2 + 64.0) / l);
	std::string c0_hex = keyLength == 128 ? "a668892a7c41e3ca739f40b057d85904" : "d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676";
	std::string c1_hex = keyLength == 128 ? "a4e136ac725f738b01c1f60217c188ad" : "54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517";
	std::string c0 = HexStringToBinary(c0_hex);
	std::string c1 = HexStringToBinary(c1_hex);
	if (cipherAlgorithm == "DESede")//c0 c1奇偶校验
	{
		std::string key1 = c0.substr(0, 8);
		std::string key2 = c0.substr(8, 8);
		std::string key1_check = "";
		std::string key2_check = "";
		CheckParity(key1, key1_check, 8);
		CheckParity(key2, key2_check, 8);
		c0 = key1_check + key2_check;
		key1 = c1.substr(0, 8);
		key2 = c1.substr(8, 8);
		key1_check = "";
		key2_check = "";
		CheckParity(key1, key1_check, 8);
		CheckParity(key2, key2_check, 8);
		c1 = key1_check + key2_check;
	}
	if (cipherAlgorithm == "AES")
		aes_cbc_encode(T_ICC, S_ICC, ki, iv_aes,keyLength);//AES获得ki
	else if (cipherAlgorithm == "DESede")
	{
		std::string key1 = T_ICC.substr(0, 8);
		std::string key2 = T_ICC.substr(8, 8);
		std::string key1_check = "";
		std::string key2_check = "";
		CheckParity(key1, key1_check, 8);
		CheckParity(key2, key2_check, 8);
		T_ICC = key1_check + key2_check;
		KencTDES(S_ICC, T_ICC, ki, DES_ENCRYPT);//3DES获得ki
	}
	if (keyLength == 192)
		ki = ki.substr(0, 24);//192AES截断
	for (int i = 0; i < n; i++)
	{
		if (cipherAlgorithm == "AES")
			aes_cbc_encode(ki, c1, xi, iv_aes, keyLength);//获得xi
		else if (cipherAlgorithm == "DESede")
			KencTDES(c1, ki, xi, DES_ENCRYPT);//获得xi
		xi = BinaryToHexString(xi);
		LOG(INFO) << "xi " << i << ' ' << xi;
		if (xi[xi.length() - 1] == '\0')
			xi.pop_back();
		x.append(xi.data(),xi.length());//连接xi
		if (cipherAlgorithm == "AES")
			aes_cbc_encode(ki, c0, ki, iv_aes, keyLength);//更新ki
		else if (cipherAlgorithm == "DESede")
			KencTDES(c0, ki, ki, DES_ENCRYPT);//更新ki
	}
	LOG(INFO) << "x "<<BinaryToHexString(x);
	//TODO:在DES的情况下，k被认为等于128位，R(s, t)的输出应为128位。
	if (cipherAlgorithm == "DESede")
		x.resize(16);
	//取得了x
	BIGNUM* x_bn = BN_new();

	ret = BN_hex2bn(&x_bn, x.c_str());
	ret = BN_nnmod(mappingResult, x_bn, p, ctx);//随机数映射结果
	LOG(INFO) << "MAPPING RESULT "<<BN_bn2hex(mappingResult);
	return true;
}
bool PCSCReader::NumberToECPointMapping(EC_GROUP*& ec_group, BIGNUM*& x_bn, EC_POINT*& G_hat)
{
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	BIGNUM* p = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	int ret = EC_GROUP_get_curve_GFp(ec_group, p, a, b, ctx);
	const BIGNUM* cofactor = BN_new();
	cofactor = EC_GROUP_get0_cofactor(ec_group);
	//接下来做点映射
	//step1
	BIGNUM* alpha = BN_new();
	ret = BN_mul(alpha, x_bn, x_bn, ctx);
	BIGNUM* zero = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* four = BN_new();
	ret = BN_one(one);
	ret = BN_zero(zero);
	ret = BN_hex2bn(&four, "4");
	ret = BN_sub(alpha, zero, alpha);
	ret = BN_nnmod(alpha, alpha, p, ctx);
	//step2
	BIGNUM* X2 = BN_new();
	BIGNUM* temp = BN_new();
	BIGNUM* alpha2 = BN_new();
	ret = BN_mod_mul(alpha2, alpha, alpha, p, ctx);//alpha^2
	ret = BN_mod_add(temp, alpha, alpha2,p,ctx);//alpha+alpha^2
	BN_mod_inverse(temp, temp, p, ctx);//(alpha+alpha^2)^-1 mod p 
	ret = BN_mod_add(temp, one, temp, p, ctx);//1+(alpha+alpha^2)^-1
	BIGNUM* a_inv = BN_new();
	BIGNUM* b_neg = BN_new();
	ret = BN_mod_sub(b_neg, zero, b, p, ctx);//-b
	BN_mod_inverse(a_inv, a, p, ctx);//a^-1
	ret = BN_mod_mul(temp, b_neg, temp, p, ctx);
	ret = BN_mod_mul(temp, a_inv, temp, p, ctx);
	X2 = BN_dup(temp);//X2
	BIGNUM* X3 = BN_new();
	ret = BN_mod_mul(X3, alpha, X2, p, ctx);//X3 = alpha*X2 mod p
	BIGNUM* h2 = BN_new();
	BIGNUM* h3 = BN_new();
	ret = BN_mod_mul(temp, X2, X2, p, ctx);
	ret = BN_mod_mul(temp, X2, temp, p, ctx);
	BIGNUM* aX = BN_new();
	ret = BN_mod_mul(aX, a, X2, p, ctx);
	ret = BN_mod_add(temp, temp, aX, p, ctx);
	ret = BN_mod_add(h2, temp, b, p, ctx);//h2

	//ret = BN_mod_mul(temp, X3, X3, p, ctx);
	//ret = BN_mod_mul(temp, X3, temp, p, ctx);
	//ret = BN_mod_mul(aX, a, X3, p, ctx);
	//ret = BN_mod_add(temp, temp, aX, p, ctx);
	//ret = BN_mod_add(h3, temp, b, p, ctx);//h3

	BIGNUM* U = BN_new();
	ret = BN_mod_mul(temp, x_bn, x_bn, p, ctx);
	ret = BN_mod_mul(temp, x_bn, temp, p, ctx);
	ret = BN_mod_mul(U, temp, h2, p, ctx);
	BIGNUM* exp = BN_new();
	BIGNUM* fourInverse = BN_new();
	ret = BN_add(temp, p, one);
	BN_mod_inverse(fourInverse,four,p,ctx);
	ret = BN_mod_mul(temp, temp, fourInverse, p, ctx);//(p+1)/4
	ret = BN_sub(exp, p, one);
	ret = BN_mod_sub(exp, exp, temp, p, ctx);//p-1-(p+1)/4
	BIGNUM* A = BN_new();
	ret = BN_mod_exp(A, h2, exp, p, ctx);
	BIGNUM* X = BN_new();
	BIGNUM* Y = BN_new();
	BIGNUM* judge = BN_new();
	ret = BN_mod_mul(judge, A, A, p, ctx);
	ret = BN_mod_mul(judge, judge, h2, p, ctx);
	if (BN_cmp(judge, one) == 0)
	{
		X = BN_dup(X2);
		BN_mod_mul(Y, A, h2, p, ctx);
	}
	else
	{
		X = BN_dup(X3);
		BN_mod_mul(Y, A, U, p, ctx);
	}
	if (BN_cmp(cofactor, one) != 0)
	{
		BN_mod_mul(X,X,cofactor,p,ctx);
		BN_mod_mul(Y,Y,cofactor,p,ctx);
	}
	ret = EC_POINT_set_affine_coordinates_GFp(ec_group, G_hat, X, Y, ctx);//目前曲线cofactor都是1
	if (ret == 1)
		return true;
	else return false;
}
bool PCSCReader::NumberToNumberMapping(BIGNUM* x_bn, BIGNUM* p, BIGNUM* q, BIGNUM*& mappingResult)
{
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* a = BN_new();
	BIGNUM * one = BN_new();
	BN_one(one);
	BN_sub(a, p, one);
	BN_div(a, nullptr, a, q, ctx);
	LOG(INFO) << "IM DH MAPPING, a " << BN_bn2hex(a);
	BN_mod_exp(mappingResult, x_bn, a, p, ctx);
	return true;
}
BOOL PCSCReader::ReadEChipInfoPACE(std::string& codetonfc) {
	PACE = 1, BAC = 4, OnTimeDetectionChips = 4,AppStatus = 4;
	ChipAuthenticResult.PACE = 1;
	ChipAuthenticResult.BAC = 4;
	std::string cardaccess, cardsecurity;
	ReadCardAccessAndCardSecurity(cardaccess,cardsecurity);
	if (!cardaccess.length())
	{
		return false;
	}
	LOG(INFO) << "CARDACCESS " << BinaryToHexString(cardaccess) << endl;
	std::string Access_hex = StringToHex(cardaccess);
	int oid_begin = cardaccess.find("\x30\x12\x06\x0A");
	vector<PACEInfo> paceinfo;
	PACEInfo selectedPACE;
	string oid = "";
	string oid_parse = "";
	char ecc_idx = 0;
	while (oid_begin != cardaccess.npos)
	{
		std::string oid = cardaccess.substr(oid_begin + 4, 10);
		auto oid_parse = parseOID(oid);
		char ecc_idx = cardaccess[oid_begin + 19];
		int version = cardaccess[oid_begin + 16];
		LOG(INFO) << oid_parse << ' ' << ecc_idx << ' ' << "version " << version;
		PACEInfo paceInfo(oid_parse, version, ecc_idx,oid);
		paceinfo.push_back(paceInfo);
		oid_begin = cardaccess.find("\x30\x12\x06\x0A", oid_begin + 1);
	}

	if (paceinfo.size() == 1)
	{
		selectedPACE = paceinfo[0];
		oid = selectedPACE.getOIDorigion();
		oid_parse = selectedPACE.getOID();
		ecc_idx = selectedPACE.getParameterId();
	}
	else 
		for (int i = 0; i < paceinfo.size(); i++)
		{
			if (paceinfo[i].getOIDString().find("CAM") != paceinfo[i].getOIDString().npos)
			{
				selectedPACE = paceinfo[i];
				oid = paceinfo[i].getOIDorigion();
				oid_parse = parseOID(oid);
				ecc_idx = paceinfo[i].getParameterId();
			}
		}
	if (selectedPACE.getOID() == "")
	{
		selectedPACE = paceinfo[0];
		oid = paceinfo[0].getOIDorigion();
		oid_parse = parseOID(oid);
		ecc_idx = paceinfo[0].getParameterId();
	}
	auto mappingType = selectedPACE.toMappingType(oid_parse);
	auto keyAgreementAlgorithm = selectedPACE.toKeyAgreementAlgorithm(oid_parse);
	auto cipherAlgorithm = selectedPACE.toCipherAlgorithm(oid_parse);
	auto digestAlgorithm = selectedPACE.toDigestAlgorithm(oid_parse);
	auto keyLength = selectedPACE.toKeyLength(oid_parse);
	LOG(INFO) << mappingType << ' ' << keyAgreementAlgorithm << ' ' << cipherAlgorithm << ' ' << digestAlgorithm << ' ' << keyLength << endl;
	//派生Kpai:TODO:需要传入参数 digestAlgorithm SHA-1 or SHA-256
	std::string mrzInfo(codetonfc.data());
	std::string Kpai;
	CHECK_OK(BuildKpai(mrzInfo, Kpai, digestAlgorithm));
	string selectAPP("\xA0\x00\x00\x02\x47\x10\x01", 7);
	//PACE初始化,true
	bool byCAN = false;
	if (codetonfc.size() <=10)
		byCAN = true;
	CHECK_OK(SelectPACE(oid, byCAN));
	//请求秘密随机数 true
	std::string Z_ICC;
	CHECK_OK(ICCRequestRandomNumberPACE(Z_ICC));
	LOG(INFO) << "PACE GET Z_ICC " << BinaryToHexString(Z_ICC) << endl;
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
	LOG(INFO) << "PACE DECODE SICC " << BinaryToHexString(S_ICC) << endl;
	//映射随机数：随机选择私钥，生成公钥 true
	int ecc_id = getNID(ecc_idx);
	LOG(INFO) << "PACE OPENSSL eccid "<<ecc_id << endl;
	if (ecc_id < 0) {
		LOG(INFO) << "unsupported curve nid, ecc_idx: " << ecc_idx << endl;
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
	EC_POINT* G_hat = EC_POINT_new(ec_group);
	if (ecc_id > 2) 
	{
		if (mappingType == "GM")
		{
			LOG(INFO) << "GM" << endl;
			LOG(INFO) << "PACE FIRST ECDH, BUILD IFD PUBLIC AND SECRET KEY";
			CHECK_OK(BuildMapKey(PKmap_IFD, SKmap_IFD, ecc_id));
			//随机数映射，生成共享秘密值shared_secret 
			LOG(INFO) << "PACE SENDING PKMAP AND GETTING PKIC";
			CHECK_OK(RandomNumberMap(PKmap_IC, PKmap_IFD, SKmap_IFD, true));
			//协商会话密钥
			const EC_POINT* G = EC_GROUP_get0_generator(ec_group);
			EC_POINT* shared_secret = EC_POINT_new(ec_group);
			string PKmap_IC_hex = BinaryToHexString(PKmap_IC);
			string SKmap_IFD_hex = BinaryToHexString(SKmap_IFD);
			LOG(INFO) << "PACE GET SHARED SECRET";
			get_shared_secret(ec_group, SKmap_IFD_hex, PKmap_IC_hex, shared_secret);
			//映射基点G到G_hat true
			LOG(INFO) << "PACE GET G_HAT";
			std::string S = BinaryToHexString(S_ICC);
			S.pop_back();
			get_G_hat(ec_group, shared_secret, S, G, G_hat);
		}
		else if (mappingType == "IM")
		{
			//TODO:找到土耳其护照出现的问题
			/*
			函数Rp(s,t)是将（位长度l的）八位字符串s和（位长度k的）八位字符串t 映射到GF(p)的元素int(x1||x2||...||xn) mod p的函数。
			按照[ISO/IEC 10116]，初始化向量=0，这一构造是基于CBC模式中的相应的分组密码E()构建的，其中，k是 E()的密钥长度（位）。
			必要时，结果ki必须缩短为密钥长度k。应选择最小的值n ，使得n*l ≥ log2 p + 64。
			注：只有针对AES-192时才有必要缩短：使用ki的1至24八位字节；其他的八位字节不使用。在DES的情况下，k被认为等于128位，R(s,t)的输出应为128位。
			*/
			std::string T_ICC;
			CHECK_OK(SendAnotherRandomNumber(T_ICC, keyLength));
			BIGNUM* x_bn = BN_new();
			BIGNUM* p = BN_new();
			BIGNUM* a = BN_new();
			BIGNUM* b = BN_new();
			BN_CTX* ctx = BN_CTX_new();
			int ret = EC_GROUP_get_curve_GFp(ec_group, p, a, b, ctx);
			CHECK_OK(PseudoRandomNumberMapping(S_ICC, T_ICC, keyLength, cipherAlgorithm, p, x_bn));
			CHECK_OK(NumberToECPointMapping(ec_group, x_bn, G_hat));
			LOG(INFO) << "PACE IM SET G_HAT SUCCESS";
		}
		LOG(INFO) << "PACE MUTUALAUTHENTICATE";
		CHECK_OK(MutualAuthenticate(G_hat, PKDH_IC, SKDH_IFD, PKDH_IFD, ecc_id));
		EC_POINT* KA = EC_POINT_new(ec_group);
		string PKDH_IC_hex = BinaryToHexString(PKDH_IC);
		string SKDH_IFD_hex = BinaryToHexString(SKDH_IFD);
		LOG(INFO) << "PKDH_IC_HEX " << PKDH_IC_hex << endl << "SKDH_IFD_HEX " << SKDH_IFD_hex << endl;
		get_shared_secret(ec_group, SKDH_IFD_hex, PKDH_IC_hex, KA);
		BIGNUM* KA_bn = EC_POINT_point2bn(ec_group, KA, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
		char* public_key_hex_char = BN_bn2hex(KA_bn);
		KA_hex = public_key_hex_char;
		LOG(INFO) << "KA_HEX " << KA_hex << endl;
		KA_X = KA_hex.substr(2, KA_hex.size() / 2 - 1);
		LOG(INFO) << "KA_X " << KA_X << endl;
	}
	else if(ecc_id <= 2)
	{
		BIGNUM* G_hat = BN_new();

		if (mappingType == "GM")
		{
			CHECK_OK(BuildMapKey(PKmap_IFD, SKmap_IFD, ecc_id));
			//随机数映射，生成共享秘密值shared_secret
			CHECK_OK(RandomNumberMap(PKmap_IC, PKmap_IFD, SKmap_IFD, false));
			//协商会话密钥
			const BIGNUM* G = DH_get0_g(dh);

			LOG(INFO) << "DH G" << BN_bn2hex(G) << endl;
			BIGNUM* shared_secret = BN_new();
			string PKmap_IC_hex = BinaryToHexString(PKmap_IC);
			string SKmap_IFD_hex = BinaryToHexString(SKmap_IFD);
			LOG(INFO) << "PKMAP IC " << PKmap_IC_hex << endl << "SKMAP IFD " << SKmap_IFD_hex << endl;
			get_shared_secret(dh, SKmap_IFD, PKmap_IC_hex, shared_secret);
			std::string S_ICC_hex = BinaryToHexString(S_ICC);
			S_ICC_hex.pop_back();
			get_G_hat(dh, shared_secret, S_ICC_hex, G, G_hat);
		}
		else if (mappingType == "IM")
		{
			std::string T_ICC;
			CHECK_OK(SendAnotherRandomNumber(T_ICC, keyLength));
			BIGNUM* x_bn = BN_new();
			const BIGNUM* p = BN_new();
			const BIGNUM* q = BN_new();
			const BIGNUM* g = BN_new();
			BN_CTX* ctx = BN_CTX_new();
			DH_get0_pqg(dh,&p,&q,&g);
			LOG(INFO) << "DH p " << BN_bn2hex(p);
			LOG(INFO) << "DH q " << BN_bn2hex(q);
			LOG(INFO) << "DH g " << BN_bn2hex(g);
			CHECK_OK(PseudoRandomNumberMapping(S_ICC, T_ICC, keyLength, cipherAlgorithm, BN_dup(p), x_bn));
			CHECK_OK(NumberToNumberMapping(x_bn, BN_dup(p), BN_dup(q), G_hat));
		}
		const BIGNUM* p = DH_get0_p(dh);
		BIGNUM* prime = BN_new();
		BN_copy(prime, p);
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
	LOG(INFO) << "PACE BUILD KENC AND KMAC";
	CHECK_OK(BuildKencandKmacPACE(KA_X, keyLength, cipherAlgorithm, KSenc, KSmac));

	//计算认证令牌
	std::string TIFD;
	std::string TICC_my;
	computeTIFD(KSmac, PKDH_IC, oid, keyLength, cipherAlgorithm, TIFD, ecc_id);
	computeTIFD(KSmac, PKDH_IFD, oid, keyLength, cipherAlgorithm, TICC_my,ecc_id);
	//交换令牌
	std::string TICRAPDU = "";
	LOG(INFO) << "PACE EXCHANGE TIFD AND TICC";
	CHECK_OK(ExchangeT(TIFD, TICC_my, TICRAPDU));
	LOG(INFO) << "EXCHANGE SUCCESS";
	if (mappingType == "CAM")
	{
		if (!cardsecurity.length())
		{
			LOG(INFO) << "FAIL TO READ CARDSECURITY.";
		}
		else
		{
			LOG(INFO) << "CARDSECURITY " << BinaryToHexString(cardsecurity) << endl;
			std::string CA_ECDH_OID("\x06\x09\x04\x00\x7F\x00\x07\x02\x02\x01\x02", 11);
			size_t pos = cardsecurity.find(CA_ECDH_OID);
			pos += 11;
			std::string temp = cardsecurity.substr(pos);
			temp = extractValueFromTLVBinaryString(temp);
			std::string id, bitstring;
			temp = extractValueFromTLVBinaryString(temp, bitstring);
			id = temp.substr(temp.size() - 1);
			LOG(INFO) << "CAM id " << BinaryToHexString(id);
			bitstring = extractValueFromTLVBinaryString(bitstring);
			if (bitstring[0] == '\x04')
				bitstring = bitstring.substr(1);//芯片认证公钥PKIC
			LOG(INFO) << "CAM PKIC " << BinaryToHexString(bitstring);
			//1.从相互认证编码剥离加密芯片数据
			//2.使用AESdecode解密得出CAIC，需要剥离后面的填充(removepadding)
			//3.PKIC芯片静态公钥 ，PKMAP芯片第一次ECDH认证公钥，DIC用ec_group代替(KA是getsharedsecret)
			//4.核验结果是否相等

			std::string A_IC;//加密芯片数据  寻找令牌认证数据剥出来
			std::string CA_IC="";//解密芯片数据  唯一算出来的
			//std::string SKmap;
			std::string PKIC = bitstring; //剥离出来的芯片公钥
			string iv1 = "00000000000000000000000000000000";//原始向量
			string input1 = "ffffffffffffffffffffffffffffffff";
			string iv2;//计算得出的向量
			std::string RAPDU;
			input1 = HexStringToBinary(input1);
			iv2 = HexStringToBinary(iv2);
			iv1 = HexStringToBinary(iv1);


			std::string chipData = "";
			temp = TICRAPDU;
			std::string remainder = "";
			temp = extractValueFromTLVBinaryString(temp);
			do
			{
				char tag = temp[0];
				if (tag == '\x8A')
				{
					chipData = extractValueFromTLVBinaryString(temp);
					break;
				}
				else
				{
					temp = extractValueFromTLVBinaryString(temp, remainder);
					temp = remainder;
				}
			} while (remainder.size());
			A_IC = chipData;
			LOG(INFO) << "CA CHIPDATA " << BinaryToHexString(A_IC);
			aes_cbc_encode(HexStringToBinary(KSenc), input1, iv2, iv1);//计算得出iv2
			LOG(INFO) << "CA iv2 " << BinaryToHexString(iv2);
			aes_cbc_decode(HexStringToBinary(KSenc), A_IC, CA_IC, iv2, keyLength);//解密得出CA_IC
			LOG(INFO) << "CA DECODED CA_IC " << BinaryToHexString(CA_IC);
			BN_CTX* ctx = BN_CTX_new();
			DesRemovePaddingBytes(CA_IC);
			EC_POINT* KA = EC_POINT_new(ec_group);
			string CA_IC_hex = BinaryToHexString(CA_IC);
			string PKmap_IC_hex = BinaryToHexString(PKmap_IC);
			string PKIC_hex = BinaryToHexString(PKIC);
			get_shared_secret(ec_group, CA_IC_hex, PKIC_hex, KA);
			std::string KA_hex = EC_POINT_point2hex(ec_group, KA, POINT_CONVERSION_UNCOMPRESSED, ctx);
			LOG(INFO) << "CAM SHARED SECRET KA " << KA_hex;
			PKmap_IC_hex = "04" + PKmap_IC_hex;
			if (compare_ignore_case(KA_hex, PKmap_IC_hex))
			{
				CA = 0;
				ChipAuthenticResult.CA = 0;
				LOG(INFO) << "PACE-CAM SUCCESS";
			}
			else
			{
				CA = 1;
				ChipAuthenticResult.CA = 1;
				LOG(INFO) << "PACE-CAM FAIL";
			}
		}
	}
	LOG(INFO) << "PACE SUCCESS";
	PACE = 0;
	ChipAuthenticResult.PACE = 0;
	std::string SSC;
	bool aus = false;
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
	LOG(INFO) << "READING FILES,CONTAINS:\n";
	// 读取其他文件
	std::unordered_map<int, std::string> DGs;
	for (size_t i = 0; i < tags.size(); i++) {
		unsigned char b = tags[i];
		//LOG(INFO) << "tag" << b << endl;
		stFile = StTagFindEFFile(b, &st_efs);
		if (NULL == stFile) {
			continue;
		}
		LOG(INFO) << stFile->name << '\n';

		if (NULL == stFile || stFile->Index == EF_COM || stFile->Index == EF_DG3 || stFile->Index == EF_DG4) {
			continue;
		}
		std::string ef_data;
		// 如果该类型EF解析器未实现则不读该文件
		SelectFunc(stFile);
		if (!stFile->Valid()) {
			continue;
		}
		// 读取文件
		CHECK_OK(ICCReadEFPACE(KSenc, KSmac, SSC, stFile->Index, ef_data, keyLength, cipherAlgorithm));
		LOG(INFO) << "READ " << stFile->name << " SUCCESS \n";
		// 解析文件,但是往结构体存的还是原始文件，所以长度字段还是原始文件的长度
		if (stFile->FileParse(ef_data, &st_efs)) {
			DGs.emplace(stFile->Index, ef_data);
			ChipReaderReadFileResultOperate(stFile->Index, ef_data, 2, ef_data.size());
			LOG(INFO) << "PARSE AND SAVE SUCCESS";
			/*
				if (this->cb) {
					this->cb->OnChipReaderReadFileResult(stFile->Index, stFile->result,this->GetCardType());
				}*/
		}
	}
	std::string sod_data;
	CHECK_OK(ICCReadEFPACE(KSenc, KSmac, SSC, EF_SOD, sod_data, keyLength, cipherAlgorithm));
	SODCheck = 0;
	char EF_SOD_Path[512];
	MakeFullPath1(EF_COM_Path, EF_SOD_FILENAME);
	std::ofstream  Output_sod(EF_COM_Path, std::ios::binary);
	if (Output_sod) {
		Output_sod.write(sod_data.c_str(), sod_data.size());
		Output_sod.close();
	}
	ChipAuthenticResult.PACE = 1;
	char mypath[256];
	MakeFullPath1(mypath, "USB_TEMP\\DG15.bin");
	char ret = -1;
	try
	{
		ret = ActiveAuthentication(mypath, KSenc, KSmac, SSC, cipherAlgorithm, keyLength);
	}
	catch (const std::exception& e)
	{
		LOG(ERROR) << e.what();
	}
	if (ret != 0) {
		LOG(INFO) << "ACTIVEAUTHENTICATION FAIL" << std::endl;
		ChipAuthenticResult.AA = 1;
		AA = 1;
	}
	else {
		LOG(INFO) << "ACTIVEAUTHENTICATION SUCCESS" << std::endl;
		ChipAuthenticResult.AA = 0;
		AA = 0;
	}
	// passive auth
	char SOD_file_path[256];
	MakeFullPath1(SOD_file_path, "USB_TEMP\\SOD.bin");
	if (PassiveAuthentication(SOD_file_path, DGs)) {
		LOG(INFO) << "PASSIVE AUTHENTICATION SUCCESS" << std::endl;
	}
	else {
		LOG(WARNING) << "PASSIVE AUTHENTICATION FAIL" << std::endl;
	}

	std::string newKSenc, newKSmac,newCipherAlgorithm;
	int newKeyLength;
	std::string dg14data(ChipData_Doc9303_Result.pDG14,ChipData_Doc9303_Result.iDG14);
	if (dg14data.length() != 0&& dg14data.find("\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x03")!= dg14data.npos||CA == 0)
	{
		LOG(INFO) << "SUPPORT CA";
		CA = 1;
		ChipAuthenticResult.CA = 1;
		bool ret = false;
		try
		{
			ret = ChipAuthentication(dg14data, cipherAlgorithm, keyLength, SSC, KSenc, KSmac, newKSenc, newKSmac, newKeyLength, newCipherAlgorithm);
		}
		catch (const std::exception& e)
		{
			LOG(ERROR) << e.what();
		}
		if (ret)
		{
			CA = 0;
			ChipAuthenticResult.CA = 0;
			cipherAlgorithm = newCipherAlgorithm;
			keyLength = newKeyLength;
			KSenc = newKSenc;
			KSmac = newKSmac;
		}
	}
	else
		LOG(INFO) << "CA NOT SUPPORTED";

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
	if (id == 0)
		dh = DH_get_1024_160();
	else if (id == 1)
		dh = DH_get_2048_224();
	else
		dh = DH_get_2048_256();
	return 1;
}
void PCSCReader::dumpJsonResult()
{
	nlohmann::json rfid = nlohmann::json();
	rfid["OnTimeDetectionChips"] = OnTimeDetectionChips;
	rfid["AppStatus"] = AppStatus;
	rfid["BAC"] = BAC;
	rfid["PACE"] = PACE;
	rfid["AA"] = AA;
	rfid["PA"] = PA;
	rfid["CA"] = CA;
	rfid["SODCheck"] = SODCheck;
	rfid["IntegrityCheck"] = IntegrityCheck;
	rfid["DSCCheck"] = DSCCheck;
	rfid["IssuingCountryCheck"] = IssuingCountryCheck;
	rfid["DSCDateCheck"] = DSCDateCheck;
	rfid["COM"] = COM;
	rfid["SOD"] = SOD;
	rfid["DSC"] = DSC;
	rfid["DG1"] = DG1;
	rfid["DG1detail"] = DG1detail;
	rfid["DG2"] = DG2;
	
	std::string real = DG2Details.ImageTypeReal == 2000 ? "JPEG2000" : "JPEG";
	json DG2Content = {
	{"ImageTypeDeclare",DG2Details.ImageTypeDeclare },
	{"ImageTypeReal", real},
	{"ImageBitSize",DG2Details.ImageBitSize},
	{"FaceImageHeight",DG2Details.FaceImageHeight},
	{"FaceImageWidth",DG2Details.FaceImageWidth}
	};
	rfid["DG2Details"] = DG2Content;
	rfid["DG3"] = DG3;
	rfid["DG4"] = DG4;
	rfid["DG5"] = DG5;
	rfid["DG6"] = DG6;
	rfid["DG7"] = DG7;
	real = DG7Details.ImageTypeReal == 2000 ? "JPEG2000" : "JPEG";
	json DG7Content = {
	{"ImageTypeDeclare",DG7Details.ImageTypeDeclare },
	{"ImageTypeReal", real},
	{"ImageBitSize",DG7Details.ImageBitSize},
	{"FaceImageHeight",DG7Details.FaceImageHeight},
	{"FaceImageWidth",DG7Details.FaceImageWidth}
	};
	rfid["DG7Details"] = DG7Content;
	rfid["DG8"] = DG8;
	rfid["DG9"] = DG9;
	rfid["DG10"] = DG10;
	rfid["DG11"] = DG11;
	rfid["DG12"] = DG12;
	rfid["DG13"] = DG13;
	rfid["DG14"] = DG14;
	rfid["DG15"] = DG15;
	rfid["DG16"] = DG16;
	rfid_json = rfid.dump(4);
}
