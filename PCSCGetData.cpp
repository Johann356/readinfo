#include "PCSCReader.h"
#include <iostream>
#include<sstream>
#include <iomanip>
#include<fstream>
#include <stdio.h>  
#include "EFFile.h"
#include "PCSCGetData.h"
#include <codecvt>
#include<windows.h>
#include <stdlib.h>
#include "JP2.h"
#include "Ptypes.h"
#include"utils.h"
//#include "WltRS.h"
#define CHECK_OK(x)  if(!(x)) return false;

typedef int(WINAPI* GetBmpFunc)(const char* Wlt_File, int intf);
#define ID_INFO_FILENAME	"USB_TEMP\\IDInfo.txt"
HINSTANCE phInstWltRSdll;
HANDLE hFileHid;
DWORD dwReadSize;
GetBmpFunc GetBmp;

using namespace std;

std::wstring  Nation[59] = {
	{ _T("汉族") }, { _T("蒙古族") },
	{ _T("回族") }, { _T("藏族") },
	{ _T("维吾尔族") }, { _T("苗族") },
	{ _T("彝族") }, { _T("壮族") },
	{ _T("布依族") }, { _T("朝鲜族") },
	{ _T("满族") }, { _T("侗族") },
	{ _T("瑶族") }, { _T("白族") },
	{ _T("土家族") }, { _T("哈尼族") },
	{ _T("哈萨克族") }, { _T("傣族") },
	{ _T("黎族") }, { _T("傈傈族") },
	{ _T("佤族") }, { _T("畲族") },
	{ _T("高山族") }, { _T("拉祜族") },
	{ _T("水族") }, { _T("东乡族") },
	{ _T("纳西族") }, { _T("景颇族") },
	{ _T("柯尔克孜族") }, { _T("土族") },
	{ _T("达斡尔族") }, { _T("仫佬族") },
	{ _T("羌族") }, { _T("布朗族") },
	{ _T("撒拉族") }, { _T("毛难族") },
	{ _T("仡佬族") }, { _T("锡伯族") },
	{ _T("阿昌族") }, { _T("普米族") },
	{ _T("塔吉克族") }, { _T("怒族") },
	{ _T("乌孜别克族") }, { _T("俄罗斯族") },
	{ _T("鄂温克族") }, { _T("崩龙族") },
	{ _T("保安族") }, { _T("裕固族") },
	{ _T("京族") }, { _T("塔塔尔族") },
	{ _T("独龙族") }, { _T("鄂伦春族") },
	{ _T("赫哲族") }, { _T("门巴族") },
	{ _T("珞巴族") }, { _T("基洛族") },
	{ _T("其他") }, { _T("外国血统中国籍人士") }, { _T("港澳台") }
};

static std::string ws2s(const std::wstring & wstr)
{
	if (!wstr.empty()) {
		using convert_typeX = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_typeX, wchar_t> converterX;

		return converterX.to_bytes(wstr);
	}
	else return NULL;
}

size_t getFileSize1(const char* fileName) {

	if (fileName == NULL) {
		return 0;
	}

	struct stat statbuf;

	stat(fileName, &statbuf);

	size_t filesize = statbuf.st_size;

	return filesize;
}


static HMODULE GetSelfModuleHandle()
{
	MEMORY_BASIC_INFORMATION mbi;
	return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
}


void MakeFullPath1(char* fullpath, const char* path) {

	USES_CONVERSION;
	WCHAR curDir[256] = { 0 };
	GetModuleFileName(GetSelfModuleHandle(), curDir, 256);
	(_tcsrchr(curDir, _T('\\')))[1] = 0;


	char* fp = W2A(curDir);
	int DirLen = strlen(fp);
	strncpy(fullpath, fp, DirLen);
	strncpy(fullpath + DirLen, path, strlen(path));
	fullpath[DirLen + strlen(path)] = '\0';
}


char ToLetter1(byte bNum) {
	char cTemp;
	if (bNum < 10) {
		cTemp = bNum + 0x30;
	}
	else {
		cTemp = bNum + 0x37;
	}
	return cTemp;
}

std::string BYTE2string1(byte* bByte, UINT iLength) {
	UINT iIndex;
	std::string outStr;
	for (iIndex = 0; iIndex < iLength; iIndex++)
	{
		outStr += ToLetter1(bByte[iIndex] >> 4 & 0x0F);
		outStr += ToLetter1(bByte[iIndex] & 0x0F);
	}
	return outStr;
}

BOOL covertpic(unsigned char* pDat, int picLen) {

	char path_Dll[MAX_PATH];			
	char path_Wlt[MAX_PATH];                                  
	char path_Bmp[MAX_PATH];                                  

	MakeFullPath1(path_Wlt, "DG2.wlt");
	MakeFullPath1(path_Dll, "WltRS.dll");
	MakeFullPath1(path_Bmp, "USB_TEMP\\id.bmp");
	
	int ret = -1;
	phInstWltRSdll = LoadLibraryExA((LPCSTR)path_Dll, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
	if (phInstWltRSdll != NULL)
	{
		GetBmp = (GetBmpFunc)GetProcAddress(phInstWltRSdll, "GetBmp");

		hFileHid = CreateFileA(path_Wlt, GENERIC_WRITE, FILE_SHARE_WRITE, (LPSECURITY_ATTRIBUTES)NULL, CREATE_ALWAYS, NULL, NULL);
		if (hFileHid != INVALID_HANDLE_VALUE)
		{
			WriteFile(hFileHid, pDat, picLen, &dwReadSize, NULL);
			CloseHandle(hFileHid);
			hFileHid = NULL;
			try {
				ret = GetBmp(path_Wlt, 1);
			}
			catch (std::exception& e) {
				//LOG(ERROR) << "��������" << e.what() << std::endl;
				return FALSE;
			}
			catch (...) {
				//LOG(ERROR) << "����δ֪����" << std::endl;
				return FALSE;
			}
			if (ret != 1) {
				//LOG(ERROR) << "GetBmp failure; Return: " << ret << std::endl;
				return FALSE;
			}
		}
		else
		{
			hFileHid = NULL;
			//iRet = RF_ERR_FAILURE;		// ��Ч�ļ�·��
		}
		// FreeDll
		FreeLibrary(phInstWltRSdll);
		phInstWltRSdll = NULL;
	}

	return TRUE;

}

void mainlandIDInfoSave(std::ofstream& of, t_idcardinfor* Info) {

	//std::wstring  idname(200, '\0');
	//utf16lt_to_wchar_t(sInfo.name, sizeof(sInfo.name), (wchar_t *)idname.data(), sizeof(sInfo.name));
	std::wstring idname((wchar_t*)&Info->name[0], (wchar_t*)&Info->name[30]);
	std::string name = ws2s(idname);
	of << name << std::endl;

	std::wstring  idsex((wchar_t*)&Info->sex[0], (wchar_t*)&Info->sex[2]);
	//utf16lt_to_wchar_t(Info->sex, sizeof(Info->sex), (wchar_t *)idsex.data(), sizeof(Info->sex));
	std::string sex = ws2s(idsex);
	int sexIndex = sex[0] - '0';

	std::wstring wmale = _T("��");
	std::string male = ws2s(wmale);
	std::wstring wfemale = _T("Ů");
	std::string female = ws2s(wfemale);
	if (sexIndex == 1) {
		of << male << std::endl;
	}
	else {
		of << female << std::endl;
	}

	std::wstring  idnation((wchar_t*)&Info->nation[0], (wchar_t*)&Info->nation[4]);
	//utf16lt_to_wchar_t(Info->nation, sizeof(Info->nation), (wchar_t *)idnation.data(), sizeof(Info->nation));
	std::string nation = ws2s(idnation);
	int Index = (nation[0] - '0') * 10 + (nation[1] - '0') - 1;//
	if (0 <= Index && Index < 58) {
		of << ws2s(Nation[Index]) << std::endl;
	}
	else {
		Index = 58;
		of << ws2s(Nation[Index]) << std::endl;
		//LOG(INFO) << "Nation Data: " << BinaryToHexStringChar(nation.data(), 4) << std::endl;
	}

	std::wstring  idbirthday((wchar_t*)&Info->birthday[0], (wchar_t*)&Info->birthday[16]);
	//utf16lt_to_wchar_t(sInfo.birthday, sizeof(sInfo.birthday), (wchar_t *)idbirthday.data(), sizeof(sInfo.birthday));
	std::string birthday = ws2s(idbirthday);
	of << birthday << std::endl;

	std::wstring  idaddr((wchar_t*)&Info->addr[0], (wchar_t*)&Info->addr[70]);
	//utf16lt_to_wchar_t(sInfo.addr, sizeof(sInfo.addr), (wchar_t *)idaddr.data(), sizeof(sInfo.addr));
	std::string addr = ws2s(idaddr);
	of << addr << std::endl;

	std::wstring  idIDSn((wchar_t*)&Info->IDSn[0], (wchar_t*)&Info->IDSn[36]);
	//utf16lt_to_wchar_t(sInfo.IDSn, sizeof(sInfo.IDSn), (wchar_t *)idIDSn.data(), sizeof(sInfo.IDSn));
	std::string IDSn = ws2s(idIDSn);
	of << IDSn << std::endl;

	std::wstring  idsignOrg((wchar_t*)&Info->signOrg[0], (wchar_t*)&Info->signOrg[30]);
	//utf16lt_to_wchar_t(sInfo.signOrg, sizeof(sInfo.signOrg), (wchar_t *)idsignOrg.data(), sizeof(sInfo.signOrg));
	std::string signOrg = ws2s(idsignOrg);
	of << signOrg << std::endl;

	std::wstring  idstartDate((wchar_t*)&Info->startDate[0], (wchar_t*)&Info->startDate[16]);
	//utf16lt_to_wchar_t(sInfo.startDate, sizeof(sInfo.startDate), (wchar_t *)idstartDate.data(), sizeof(sInfo.startDate));
	std::string startDate = ws2s(idstartDate);
	of << startDate << std::endl;
	//LOG(INFO) << "��ʼ����: " << BinaryToHexStringChar(startDate.data(), startDate.size()) << std::endl;

	int zeroC = 0;
	for (int i = 0; i < startDate.size(); i++) {
		if (startDate[i] == '0') {
			zeroC++;
		}
	}

	if (zeroC >= startDate.size()) {
		//LOG(ERROR) << "���֤��ȡ���ݳ���" << std::endl;
	}

	std::wstring idendDate((wchar_t*)&Info->endDate[0], (wchar_t*)&Info->endDate[16]);
	//utf16lt_to_wchar_t(sInfo.endDate, sizeof(sInfo.endDate), (wchar_t *)idendDate.data(), sizeof(sInfo.endDate));
	std::string endDate = ws2s(idendDate);
	of << endDate << std::endl;
	//LOG(INFO) << "��������: " << BinaryToHexStringChar(endDate.data(), endDate.size()) << std::endl;

	int zeroC2 = 0;
	for (int i = 0; i < endDate.size(); i++) {
		if (endDate[i] == '0') {
			zeroC2++;
		}
	}

	if (zeroC2 >= endDate.size()) {
		//LOG(ERROR) << "���֤��ȡ���ݳ���" << std::endl;
	}



	std::wstring  idCardType((wchar_t*)&Info->typeFlag[0], (wchar_t*)&Info->typeFlag[2]);
	std::string CcardType = ws2s(idCardType);
	if (CcardType[0] == 'J') {//�۰�̨��ס֤
		//of << islandCardType << std::endl;
		//of << '1' << std::endl;  // ����������ڸ۰�̨�ӿ����
	}
	else {//���֤
		//of << mainCardType << std::endl;
		of << "0" << std::endl;
	}

}


string DG1, DG11;

int PCSC_GetIDCard() {
	char path_DG2[MAX_PATH];
	MakeFullPath1(path_DG2, "DG2.bmp");
	int ret = -1;
	PCSCReader pcscReader;
	string atr;
	ret = pcscReader.Initalize();
	if (ret > 0) {
		ret = pcscReader.Connect(atr);
	}

	if (!(atr.size() >= 30 && atr.substr(26, 4) == "9000")) {
		return -1;
	}

	BYTE  RecvBuff[300];
	DWORD RecvLen;
	unsigned char sInfo[256];
	unsigned char cpPhoto[1024];
	unsigned int ipphotoLen = 1024;
	unsigned int ipInfolen;
	string s("\xFF\xB0\x00\x00\x00", 5);

	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	pcscReader.Apdusend(s, RecvBuff, RecvLen);
	if (RecvLen < 1) {
		return -1;
	}
	ipInfolen = RecvLen - 2;
	memset(sInfo, 0, sizeof(sInfo));
	memcpy(sInfo, (void*)(RecvBuff + RF_RECV_IDCARD_INFO_POS1), RF_RECV_IDCARD_INFO_LEN);
	char path[1024];
	//"ID_INFO_FILENAME"path
	MakeFullPath1(path, ID_INFO_FILENAME);
	std::ofstream idcout(path, std::ios::trunc);

	std::wstring Infomation((wchar_t*)&sInfo, (wchar_t*)((char*)&sInfo + sizeof(sInfo)));
	std::string strInfo = ws2s(Infomation);
	mainlandIDInfoSave(idcout, (t_idcardinfor*)&sInfo);
	idcout.close();

	string s1("\xFF\xB0\x01\x00\x00", 5);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	pcscReader.Apdusend(s1, RecvBuff, RecvLen);
	memcpy(cpPhoto, (void*)(RecvBuff + RF_RECV_IDCARD_INFO_POS1), 252);

	string s2("\xFF\xB0\x02\x00\x00", 5);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	pcscReader.Apdusend(s2, RecvBuff, RecvLen);
	memcpy((void*)(cpPhoto + 252), RecvBuff, 256);

	string s3("\xFF\xB0\x03\x00\x00", 5);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	pcscReader.Apdusend(s3, RecvBuff, RecvLen);
	memcpy((void*)(cpPhoto + 508), RecvBuff, 256);

	string s4("\xFF\xB0\x04\x00\x00", 5);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	pcscReader.Apdusend(s4, RecvBuff, RecvLen);
	memcpy((void*)(cpPhoto + 764), RecvBuff, 256);

	string s5("\xFF\xB0\x05\x00\x00", 5);
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	pcscReader.Apdusend(s5, RecvBuff, RecvLen);
	memcpy((void*)(cpPhoto + 1020), RecvBuff, 4);

	if (!covertpic(cpPhoto, ipphotoLen)) {
		//LOG(ERROR) << "covertpic error " << std::endl;
		ret = -1;
	}
	else {
		ret = 1;
	}
	return ret;

}
                                 
int PCSCGetChip(string& mrz, int cardType, ChipAuthenticData& chipAuthenticData, ChipData_Doc9303& chipData_9303) {
	
	char path_DG2[MAX_PATH];
	MakeFullPath1(path_DG2, "DG2.bmp");

	int ret = -1;
	PCSCReader pcscReader;
	
	string fullName, selfID;
	string atr;
	ret = pcscReader.Initalize();
	if (ret > 0) {
		ret = pcscReader.Connect(atr);
	}

	//cout << "ATR:	" << atr << endl;
	//if (atr.size() < 30) return -1;
	// ISO14443-4 Type B && Type B 

		//string codetonfc = "EJ3584648397102123301122";
	pcscReader.SetCardType(cardType);
	pcscReader.mrtd.CardType = pcscReader.CardType;
	if (!pcscReader.mrtd.Parse(mrz)) {
		//LOGE("mrtd.Parse(code) error");
		return -1;
	}
	pcscReader.EF_DG2_SetResultPath(path_DG2);
	std::string codetonfc = pcscReader.mrtd.mrzInfo.codetonfc;
	//string codetonfc = "EJ3584648397102123301122";
	//string codetonfc = "CC6354145097102123301122";
	//string codetonfc = "EJ3584649496080523301122";
	//codetonfc = "EJ3584648397102123301122";
	ret = pcscReader.ReadEchipInfo(codetonfc);
	if (ret > 0) {
		ret = pcscReader.GetResult(EF_DG1, DG1);
		if (!ret) {
			return -1;
		}
		std::cout << "DG1: " << DG1 << std::endl;
		chipData_9303.iDG1 = DG1.size();
		strcpy(chipData_9303.pDG1, DG1.c_str());
		ret = pcscReader.GetResult(EF_DG11, DG11);

		if (!ret) {
			return -1;
		}
		int DG2_size = getFileSize1(path_DG2);
		std::cout << "DG2_size: " << DG2_size << std::endl;
		getEChipDG11(fullName, selfID);
		std::cout << "DG11: " << fullName << std::endl;
		//copy data, maybe cost too much time...
		chipData_9303.iDG11 = DG11.size();
		strcpy(chipData_9303.pDG11, DG11.c_str());
		
		chipData_9303.iDG2 = pcscReader.ChipData_Doc9303_Result.iDG2;
		strncpy(chipData_9303.pDG2, pcscReader.ChipData_Doc9303_Result.pDG2, chipData_9303.iDG2);
		
		chipData_9303.iSod = pcscReader.ChipData_Doc9303_Result.iSod;
		strncpy(chipData_9303.pSOD, pcscReader.ChipData_Doc9303_Result.pSOD, chipData_9303.iSod);

		chipData_9303.iDG15 = pcscReader.ChipData_Doc9303_Result.iDG15;
		strncpy(chipData_9303.pDG15, pcscReader.ChipData_Doc9303_Result.pDG15, chipData_9303.iDG15);
		ret = 1;
	}
	else {
		ret = -1;
	}
	chipAuthenticData.AA = pcscReader.ChipAuthenticResult.AA;
	chipAuthenticData.PA = pcscReader.ChipAuthenticResult.PA;
	chipAuthenticData.BAC = pcscReader.ChipAuthenticResult.BAC;
	pcscReader.DissConnect();
	return ret;
}

int getEChipDG11(std::string& name, std::string& selfID) {

	//find second
	std::string UTF8_name_tag("\x5f\x0e", 2);
	size_t offset = DG11.find(UTF8_name_tag);
	if (offset == std::string::npos)
		return -1;
	//    LOG(INFO) << "getEChipDG11 offset " <<offset;
	offset = DG11.find(UTF8_name_tag, offset + 2);
	if (offset == std::string::npos)
		return -1;
	//    LOG(INFO) << "getEChipDG11 offset " <<offset;
	std::ostringstream out;
	for (int i = 0; i < DG11.size(); ++i) {
		out << std::hex << setiosflags(std::ios::uppercase) << std::setw(2) << std::setfill('0')
			<< static_cast<unsigned short>(DG11[i]);
	}
	//    LOG(INFO) << "getEChipDG11 DG11 " << DG11.size() << out.str();
	unsigned char size = DG11[offset + 2];
	//    LOG(INFO) << "getEChipDG11 offset " <<offset << " size: " << int(size);
	name = (DG11.substr(offset + 3, size));

	////////////////////////////////////////
	std::string flag2("\x5F\x10", 2);

	size_t it2 = DG11.find(flag2, offset + size + 3);
	if (it2 == std::string::npos) {
		return -1;
	}
	int len1 = DG11[it2 + 2] & 0xff;
	std::string ID;
	for (int i = 0; i < len1; i++) {
		if (DG11[i + it2 + 3] != '<') {
			ID.push_back(DG11[i + it2 + 3]);
		}
	}
	selfID = ID.c_str();
	return 0;
}
