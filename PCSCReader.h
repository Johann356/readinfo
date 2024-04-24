#pragma once
#include<string>
#include<atlstr.h>
#include "STEFFile.h"
#include "EFFile.h"
#include "MRTD.h"

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
		int BAC = 1;
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
		int iSod;
		int iCardAcess;
		int iCardSecurity;
	} ChipData_Doc9303_Result;
public:
	PCSCReader();
	~PCSCReader();
	char SetCardType(unsigned char type) {
		this->CardType = type;
		return true;
	}
	//初始化读卡器
	int Initalize();
	//连接读卡器
	int Connect(string& atr );
	//发送apdu命令
	int Apdusend(string& sendData, BYTE* RecvBuff, DWORD& RecvLen);
	//获取复位信息
	int Getatr(string& atr);
	int DissConnect();
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

	char ActiveAuthentication(char* DG15_file_path);

	char PassiveAuthentication(char* SOD_file_path);

	char BuildSSC(std::string& RND_IFD,
		std::string& RND_ICC,
		std::string& SSC);

	char ICCReadEF(std::string& KSenc, std::string& KSmac, std::string& SSC, EF_NAME name,
		std::string& EF_Data);

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
	char DirectCommunicationSelectFile();
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

	void ChipReaderReadFileResultOperate(EF_NAME name, char* result, unsigned char type);

	char GetResult(EF_NAME efName, string& retData);

	char EF_DG2_SetResultPath(string path);

	std::string baseFolder;

private:
	//读卡器名称
	CString ReaderName;
	//与智能卡连接的句柄
	SCARDHANDLE	hCard;
	DWORD m_dAttrib;
	SCARDCONTEXT hContext;
	STEFFileSystem st_efs;


};





