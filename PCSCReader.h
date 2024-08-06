#pragma once
#include<string>
#include<atlstr.h>
#include <unordered_map>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "STEFFile.h"
#include "EFFile.h"
#include "MRTD.h"
#include "ImageFormat.h"
#include <nlohmann/json.hpp>
#include "CAInfo.h"
using json = nlohmann::json;
#define EF_CARDACCESS_FILENAME	    "USB_TEMP\\EF_CardAccess.bin"
#define EF_COM_FILENAME	    "USB_TEMP\\COM.bin"
#define EF_SOD_FILENAME	    "USB_TEMP\\SOD.bin"

using namespace std;
std::string BYTE2string(byte* bByte, UINT iLength);
char ToLetter(byte bNum);
extern void MakeFullPath1(char* fullpath, const char* path);

class PCSCReader
{
public:
	MRTD mrtd;
	unsigned char CardType;
	struct ChipAuthenticData
	{
		int BAC;
		int PACE;
		int CA;
		int AA;
		int PA;
		int PASOD;
		int PADS;
		int PADGHash;
	} ChipAuthenticResult;

	struct ChipData_Doc9303
	{
		char pDG1[128];
		char pDG2[81920];
		char pDG3[81920];
		char pDG4[4096];
		char pDG5[4096];
		char pDG6[1024];
		char pDG7[20734];
		char pDG8[1024];
		char pDG9[1024];
		char pDG10[1024];
		char pDG11[1024];
		char pDG12[1024];
		char pDG13[1024];
		char pDG14[1024];
		char pDG15[1024];
		char pDG16[1024];
		char pCardAccess[1024];
		char pCardSecurity[1024];
		char pSOD[8192];
		int iDG1;
		int iDG2;
		int iDG3;
		int iDG4;
		int iDG5;
		int iDG6;
		int iDG7;
		int iDG8;
		int iDG9;
		int iDG10;
		int iDG11;
		int iDG12;
		int iDG13;
		int iDG14;
		int iDG15;
		int iDG16;
		int iSOD;
		int iCardAcess;
		int iCardSecurity;
	} ChipData_Doc9303_Result;
	imageDetail DG2Details,DG7Details;
	char OnTimeDetectionChips, AppStatus, BAC, PACE, AA, PA, CA, SODCheck, IntegrityCheck, DSCCheck, IssuingCountryCheck, DSCDateCheck;
	std::string COM, SOD, DSC, DG1, DG1detail, DG2, DG3, DG4, DG5, DG6, DG7, DG8, DG9, DG10, DG11, DG12, DG13, DG14, DG15, DG16;
	std::string rfid_json;
public:
	PCSCReader();
	~PCSCReader();
	char SetCardType(unsigned char type) {
		this->CardType = type;
		return true;
	}
	void InitalizeState();
	//初始化读卡器
	int Initalize();
	//连接读卡器
	int Connect(string& atr );
	//发送apdu命令
	int Apdusend(string& sendData, BYTE* RecvBuff, DWORD& RecvLen);
	//获取复位信息
	int Getatr(string& atr);
	int DissConnect();
	bool ReadCardAccessAndCardSecurity(std::string& CardAccess,std::string& CardSecurity);
	bool ChipAuthentication(std::string& CardSecurity,
		std::string& cipherAlgorithm,
		int keyLength,
		std::string SSC,
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& newKSenc,
		std::string& newKSmac,
		int& newKeyLength,
		std::string& newCipherAlgorithm);
	bool SendAnotherRandomNumber(std::string& T_ICC, int keyLength);
	bool PseudoRandomNumberMapping(std::string& S_ICC, std::string& T_ICC, int keyLength, std::string& cipherAlgorithm, BIGNUM* p, BIGNUM*& mappingResult);
	bool NumberToECPointMapping(EC_GROUP*& ec_group,BIGNUM*& x_bn,EC_POINT*& G_hat);
	bool NumberToNumberMapping(BIGNUM* x_bn, BIGNUM* p, BIGNUM* q, BIGNUM*& mappingResult);
	bool GetCAPKIC(std::string& PKIC, std::string& dg14, int id);
	bool GetCAKA(EC_GROUP*& ec_group, EC_POINT*& shared_secrete, std::string& KA_X, std::string& SKmap, std::string& PKIC);
	bool GetCAKA(DH*& dh, BIGNUM*& shared_secrete, std::string& KA, std::string& SKmap, std::string& PKIC);
	bool CAGeneralAuthenticate(std::vector<CAInfo>& cainfo,
		std::string& cipherAlgorithm,
		int keyLength,
		std::string SSC,
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& PKIFD);
	bool ComputeCAPK(std::vector<CAInfo>& cainfo, std::string& SKmap, std::string& PKmap, EC_GROUP*& ec_group);
	bool ComputeCAPK(std::vector<CAInfo>& cainfo, std::string& SKmap, std::string& PKmap, DH*& dh);
	bool SELECTCA(std::vector<CAInfo>& cainfo,
		std::string& cipherAlgorithm,
		int keyLength,
		std::string SSC,
		const std::string& KSenc,
		const std::string& KSmac);
	bool GetCAPK(std::vector<CAInfo>& CAinfo, std::string& CardSecurity);
	char BuildKencAndKmac(const std::string& mrzInfo,
		std::string& Kenc,
		std::string& Kmac);
	char BuildIFD(std::string& RND_IFD,
		std::string& Kifd);

	char ICCMutualAuthenticate(std::string& RND_IFD,
		std::string& RND_ICC,
		std::string& Kifd,
		std::string& Kenc,
		std::string& Kmac,
		std::string& KSenc,
		std::string& KSmac);

	char ActiveAuthentication(char* DG15_file_path,
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		std::string& cipherAlgorithm,
		int keyLength);

	char PassiveAuthentication(char* SOD_file_path, std::unordered_map<int, std::string>& DGs);

	char BuildSSC(std::string& RND_IFD,
		std::string& RND_ICC,
		std::string& SSC);

	char ICCReadEF(std::string& KSenc, std::string& KSmac, std::string& SSC, EF_NAME name,
		std::string& EF_Data);
	char ICCReadEFPACE(std::string& KSenc, std::string& KSmac, std::string& SSC, EF_NAME name,
		std::string& EF_Data,int keyLength,const std::string&);
	char SecureCommunicationSeletAPPPACE(
		std::string& cmdData,
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		int keyLength,
		const std::string& cipherAlgorithm);
	/**
 * 下面这一系列接口时为了增加一些护照的支持，这类护照没有安全加密，不需要根据机读码建立安全通信
 * 直接通过APDU命令读取芯片
 */
	char DirectReadEF(
		EF_NAME name,
		std::string& EF_Data);

	//STEFFile
	char DirectCommunication(
		STEFFile* file,
		std::string& data);

	//STEFFile
	char DirectSelectFile(
		STEFFile* file);

	char DirectReadFile(
		unsigned short offset,
		unsigned short len,
		std::string& data);

	char DirectReadBinary(
		unsigned short offset,
		unsigned short chunkSize,
		std::string& data);


	char SecureCommunication(
		STEFFile* file,
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		std::string& data);

	char SecureCommunicationSelectFile(
		STEFFile* file,
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC);

	char SecureCommunicationReadBinary(
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		unsigned short offset,
		unsigned short chunkSize,
		std::string& data);

	char SecureCommunicationReadFile(
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		unsigned short offset,
		unsigned short len,
		std::string& data);

	char ReadEchipInfo(std::string& codetonfc);
	BOOL ReadEChipInfoPACE(std::string& codetonfc);
	BOOL SelectPACE(std::string& oid, bool byCAN);
	BOOL ICCRequestRandomNumberPACE(__out std::string& Z_ICC);
	char PostPassportCommand(std::string& request, std::string& response);
	char SecureCommunicationInternalAuthenticate(const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		std::string& data,
		std::string& RND_IFD,
		std::string& cipherAlgorithm,
		int keyLength,
		bool longCommand);
	BOOL BuildKpai(
		__in const std::string& mrzInfo,
		__out std::string& Kpai,
		__out std::string& hash_aogorithm);

	BOOL BuildKencandKmacPACE(
		__in const std::string& KA,
		__in int keyLength,
		__in std::string cipherAlgorithm,
		__out std::string& Kenc,
		__out std::string& Kmac);

	BOOL map_G_hat(EC_POINT*& G_hat,std::string& S_ICC, std::string& cipherAlgorithm, int keyLength);

	BOOL map_G_hat(BIGNUM*& G_hat, std::string& S_ICC, std::string& cipherAlgorithm, int keyLength);

	BOOL BuildMapKey(std::string& PKmap, std::string& SKmap, int ecc_id);

	BOOL RandomNumberMap(std::string& PKmap_IC, const std::string& PKmap, const std::string& SKmap, bool isECDH);

	BOOL MutualAuthenticate(EC_POINT* G_hat, std::string& PKDH_IC, std::string& SKDH_IFD, std::string& PKDH_IFD, int ecc_id);

	BOOL MutualAuthenticate(BIGNUM*& G_hat, std::string& PKDH_IC, std::string& SKDH_IFD, std::string& PKDH_IFD, BIGNUM*& prime);

	BOOL ExchangeT(std::string& TIFD, std::string& TICC_my, std::string& RAPDU);

	void ChipReaderReadFileResultOperate(EF_NAME name, std::string& result, unsigned char type, int length);

	char GetResult(EF_NAME efName, string& retData);

	char EF_DG2_SetResultPath(string path);
	char SecureCommunicationPACE(
		STEFFile* file,
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		std::string& data,
		int keyLength,
		const std::string& cipherAlgorithm);

	char SecureCommunicationSelectFilePACE(
		STEFFile* file,
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		int keyLength,
		const std::string& cipherAlgorithm);

	char SecureCommunicationReadBinaryPACE(
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		unsigned short offset,
		unsigned short chunkSize,
		std::string& data,
		int keyLength,
		const std::string& cipher_Algorithm);

	char SecureCommunicationReadFilePACE(
		const std::string& KSenc,
		const std::string& KSmac,
		std::string& SSC,
		unsigned short offset,
		unsigned short len,
		std::string& data,
		int keyLength,
		const std::string& cipher_Algorithm);
	int Buildsecp256r1(EC_GROUP*& ec_group);
	int BuildGFP(DH*& dh,int id);
	std::string baseFolder;
	void dumpJsonResult();
private:
	//读卡器名称
	CString ReaderName;
	//与智能卡连接的句柄
	SCARDHANDLE	hCard;
	DWORD m_dAttrib;
	SCARDCONTEXT hContext;
	STEFFileSystem st_efs;
	BOOL ReadBinary_CardAccess(
		__in UINT16 offset,
		__in UINT16 chunkSize,
		__out std::string& data);


};





