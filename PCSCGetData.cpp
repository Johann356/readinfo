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
	memcpy(fullpath, fp, DirLen);
	memcpy(fullpath + DirLen, path, strlen(path));
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
	char path_Usbtemp_Bmp[MAX_PATH];
	MakeFullPath1(path_Wlt, "DG2.wlt");
	MakeFullPath1(path_Dll, "WltRS.dll");
	MakeFullPath1(path_Bmp, "DG2.bmp");
	MakeFullPath1(path_Usbtemp_Bmp, "USB_TEMP\\id.bmp");
	
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
				//LOG(ERROR) <<catch (std::exception& e)<< e.what() << std::endl;
				return FALSE;
			}
			catch (...) {
				//LOG(ERROR) << "GetBmp" << std::endl;
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
			//iRet = RF_ERR_FAILURE;		//
		}
		// FreeDll
		FreeLibrary(phInstWltRSdll);
		phInstWltRSdll = NULL;
	}
	std::ifstream sourceFile(path_Bmp, std::ios::binary);
	if (!sourceFile.is_open()) {
		LOG(ERROR) << "Unable to open source file: " << path_Bmp << std::endl;
		return false;
	}

	std::ofstream destinationFile(path_Usbtemp_Bmp, std::ios::binary);
	if (!destinationFile.is_open()) {
		LOG(ERROR) << "Unable to open destination file: " << path_Usbtemp_Bmp << std::endl;
		return false;
	}
	// 复制文件内容
	destinationFile << sourceFile.rdbuf();
	sourceFile.close();
	destinationFile.close();
	return TRUE;

}

//void mainlandIDInfoSave(std::ofstream& of, t_idcardinfor* Info) {
//
//	//std::wstring  idname(200, '\0');
//	//utf16lt_to_wchar_t(sInfo.name, sizeof(sInfo.name), (wchar_t *)idname.data(), sizeof(sInfo.name));
//	std::wstring idname((wchar_t*)&Info->name[0], (wchar_t*)&Info->name[30]);
//	std::string name = ws2s(idname);
//	of << name << std::endl;
//
//	std::wstring  idsex((wchar_t*)&Info->sex[0], (wchar_t*)&Info->sex[2]);
//	//utf16lt_to_wchar_t(Info->sex, sizeof(Info->sex), (wchar_t *)idsex.data(), sizeof(Info->sex));
//	std::string sex = ws2s(idsex);
//	int sexIndex = sex[0] - '0';
//
//	std::wstring wmale = _T("男");
//	std::string male = ws2s(wmale);
//	std::wstring wfemale = _T("女");
//	std::string female = ws2s(wfemale);
//	if (sexIndex == 1) {
//		of << male << std::endl;
//	}
//	else {
//		of << female << std::endl;
//	}
//
//	std::wstring  idnation((wchar_t*)&Info->nation[0], (wchar_t*)&Info->nation[4]);
//	//utf16lt_to_wchar_t(Info->nation, sizeof(Info->nation), (wchar_t *)idnation.data(), sizeof(Info->nation));
//	std::string nation = ws2s(idnation);
//	int Index = (nation[0] - '0') * 10 + (nation[1] - '0') - 1;//
//	if (0 <= Index && Index < 58) {
//		of << ws2s(Nation[Index]) << std::endl;
//	}
//	else {
//		Index = 58;
//		of << ws2s(Nation[Index]) << std::endl;
//		//LOG(INFO) << "Nation Data: " << BinaryToHexStringChar(nation.data(), 4) << std::endl;
//	}
//
//	std::wstring  idbirthday((wchar_t*)&Info->birthday[0], (wchar_t*)&Info->birthday[16]);
//	//utf16lt_to_wchar_t(sInfo.birthday, sizeof(sInfo.birthday), (wchar_t *)idbirthday.data(), sizeof(sInfo.birthday));
//	std::string birthday = ws2s(idbirthday);
//	of << birthday << std::endl;
//
//	std::wstring  idaddr((wchar_t*)&Info->addr[0], (wchar_t*)&Info->addr[70]);
//	//utf16lt_to_wchar_t(sInfo.addr, sizeof(sInfo.addr), (wchar_t *)idaddr.data(), sizeof(sInfo.addr));
//	std::string addr = ws2s(idaddr);
//	of << addr << std::endl;
//
//	std::wstring  idIDSn((wchar_t*)&Info->IDSn[0], (wchar_t*)&Info->IDSn[36]);
//	//utf16lt_to_wchar_t(sInfo.IDSn, sizeof(sInfo.IDSn), (wchar_t *)idIDSn.data(), sizeof(sInfo.IDSn));
//	std::string IDSn = ws2s(idIDSn);
//	of << IDSn << std::endl;
//
//	std::wstring  idsignOrg((wchar_t*)&Info->signOrg[0], (wchar_t*)&Info->signOrg[30]);
//	//utf16lt_to_wchar_t(sInfo.signOrg, sizeof(sInfo.signOrg), (wchar_t *)idsignOrg.data(), sizeof(sInfo.signOrg));
//	std::string signOrg = ws2s(idsignOrg);
//	of << signOrg << std::endl;
//
//	std::wstring  idstartDate((wchar_t*)&Info->startDate[0], (wchar_t*)&Info->startDate[16]);
//	//utf16lt_to_wchar_t(sInfo.startDate, sizeof(sInfo.startDate), (wchar_t *)idstartDate.data(), sizeof(sInfo.startDate));
//	std::string startDate = ws2s(idstartDate);
//	of << startDate << std::endl;
//	//LOG(INFO) << "startDate" << BinaryToHexStringChar(startDate.data(), startDate.size()) << std::endl;
//
//	int zeroC = 0;
//	for (int i = 0; i < startDate.size(); i++) {
//		if (startDate[i] == '0') {
//			zeroC++;
//		}
//	}
//
//	if (zeroC >= startDate.size()) {
//		//LOG(ERROR) << "zeroC >= startDate.size()" << std::endl;
//	}
//
//	std::wstring idendDate((wchar_t*)&Info->endDate[0], (wchar_t*)&Info->endDate[16]);
//	//utf16lt_to_wchar_t(sInfo.endDate, sizeof(sInfo.endDate), (wchar_t *)idendDate.data(), sizeof(sInfo.endDate));
//	std::string endDate = ws2s(idendDate);
//	of << endDate << std::endl;
//	//LOG(INFO) << "endDate" << BinaryToHexStringChar(endDate.data(), endDate.size()) << std::endl;
//
//	int zeroC2 = 0;
//	for (int i = 0; i < endDate.size(); i++) {
//		if (endDate[i] == '0') {
//			zeroC2++;
//		}
//	}
//
//	if (zeroC2 >= endDate.size()) {
//		//LOG(ERROR) << "zeroC2 >= endDate.size()" << std::endl;
//	}
//
//
//
//	std::wstring  idCardType((wchar_t*)&Info->typeFlag[0], (wchar_t*)&Info->typeFlag[2]);
//	std::string CcardType = ws2s(idCardType);
//	if (CcardType[0] == 'J') {//
//		//of << islandCardType << std::endl;
//		//of << '1' << std::endl;  //
//	}
//	else {//   ?
//		//of << mainCardType << std::endl;
//		of << "0" << std::endl;
//	}
//
//}
void foreignerIDInfoSave(std::ofstream& of, t_idforeigner* Info) {
	LOG(INFO) << "2017 FOREIGNER IDCARD PARSER";
	//姓名
	std::wstring idenglish_name((wchar_t*)&Info->name[0], (wchar_t*)&Info->name[120]);
	std::string english_name = ws2s(idenglish_name);
	of << english_name << std::endl;

	//性别
	std::wstring  idsex((wchar_t*)&Info->sex[0], (wchar_t*)&Info->sex[2]);
	std::string sex = ws2s(idsex);
	int sexIndex = sex[0] - '0';
	if (sexIndex == 1) {
		std::wstring wmale = _T("男");
		std::string male = ws2s(wmale);
		of << male << std::endl;
	}
	else {
		std::wstring wfemale = _T("女");
		std::string female = ws2s(wfemale);
		of << female << std::endl;
	}

	//民族  国籍或所在地区代码
	std::wstring idnation((wchar_t*)&Info->nation[0], (wchar_t*)&Info->nation[6]);
	std::string nation = ws2s(idnation);
	of << nation << std::endl;

	//生日
	std::wstring idbirthday((wchar_t*)&Info->birthday[0], (wchar_t*)&Info->birthday[16]);
	std::string birthday = ws2s(idbirthday);
	of << birthday << std::endl;

	//地址
	of << std::endl;

	//通行证号码  永久居留证号码
	std::wstring idIDSn((wchar_t*)&Info->IDSn[0], (wchar_t*)&Info->IDSn[30]);
	std::string IDSn = ws2s(idIDSn);
	of << IDSn << std::endl;//通行证号

	//签发机关  当次申请受理机关代码
	std::wstring idsignNum((wchar_t*)&Info->signOrg[0], (wchar_t*)&Info->signOrg[8]);
	std::string signNum = ws2s(idsignNum);
	of << signNum << std::endl;

	//签发日期
	std::wstring  idstartDate((wchar_t*)&Info->startDate[0], (wchar_t*)&Info->startDate[16]);
	std::string startDate = ws2s(idstartDate);
	of << startDate << std::endl;
	LOG(INFO) << "起始日期: " << BinaryToHexString(startDate) << std::endl;

	int zeroC = 0;
	for (int i = 0; i < startDate.size(); i++) {
		if (startDate[i] == '0') {
			zeroC++;
		}
	}

	if (zeroC >= startDate.size()) {
		LOG(ERROR) << "身份证读取数据出错" << std::endl;
	}

	//有效截止日期
	std::wstring idendDate((wchar_t*)&Info->endDate[0], (wchar_t*)&Info->endDate[16]);
	std::string endDate = ws2s(idendDate);
	of << endDate << std::endl;
	LOG(INFO) << "结束日期: " << BinaryToHexString(endDate) << std::endl;

	int zeroC2 = 0;
	for (int i = 0; i < endDate.size(); i++) {
		if (endDate[i] == '0') {
			zeroC2++;
		}
	}

	if (zeroC2 >= endDate.size()) {
		LOG(ERROR) << "身份证读取数据出错" << std::endl;
	}

	//中文名
	std::wstring idchinaese_name((wchar_t*)&Info->cnname[0], (wchar_t*)&Info->cnname[30]);
	std::string chinaese_name = ws2s(idchinaese_name);
	of << chinaese_name << std::endl;


	//证件版本号
	std::wstring idpassVersion((wchar_t*)&Info->cardver[0], (wchar_t*)&Info->cardver[4]);
	std::string passVersion = ws2s(idpassVersion);
	of << passVersion << std::endl;

	//证件类型标识
	std::wstring idtypeFlag((wchar_t*)&Info->typeFlag[0], (wchar_t*)&Info->typeFlag[2]);
	std::string typeFlag = ws2s(idtypeFlag);
	of << typeFlag << std::endl;

	//换证次数，17版无此项
	of << std::endl;

	//既往版本外国人永久居留证件号码关联项",17版证件不存在此项输出为空
	of << std::endl;

	//EngName1,英文姓名,17版证件此项输出同EnglishName，23版证件此项输出为英文姓名的1~35位
	std::wstring engname1((wchar_t*)&Info->name[0], (wchar_t*)&Info->name[120]);
	std::string engname11 = ws2s(engname1);
	of << engname11 << std::endl;

	//EngName2: 英文姓名备用（36~46位）17版证件不存在此项输出为空
	of << std::endl;

	//
	//证件类型
	//std::wstring wCardFlag = _T("外国人居留证");
	//std::string CardFlag = ws2s(wCardFlag);
	//of << CardFlag << std::endl;
	of << "2" << std::endl;	 //用2表示外国人居留证


}

void foreignerIDInfoSave_new(std::ofstream& of, t_idforeigner2023* Info) {
	LOG(INFO) << "2023 FOREIGNER IDCARD PARSER";
	//姓名
	size_t length_enNameEx = sizeof((wchar_t*)&Info->enNameEx) / sizeof((wchar_t*)&Info->enNameEx[0]);
	//size_t length_enName = sizeof((wchar_t *)&Info->enName) / sizeof((wchar_t *)&Info->enName[0]);
	std::wstring idenglish_name((wchar_t*)&Info->enName[0], (wchar_t*)&Info->enName[70]);
	if (length_enNameEx > 0) {
		std::wstring idenglish_name_Ex((wchar_t*)&Info->enNameEx[0], (wchar_t*)&Info->enNameEx[22]);
		std::string english_name = ws2s(idenglish_name + idenglish_name_Ex);
		//LOG(INFO)<< result << std::endl;
		of << english_name << std::endl;
	}
	else {
		std::string english_name = ws2s(idenglish_name);
		of << english_name << std::endl;
	}

	//性别
	std::wstring  idsex((wchar_t*)&Info->Sex[0], (wchar_t*)&Info->Sex[2]);
	std::string sex = ws2s(idsex);
	int sexIndex = sex[0] - '0';
	if (sexIndex == 1) {
		std::wstring wmale = _T("男");
		std::string male = ws2s(wmale);
		of << male << std::endl;
	}
	else {
		std::wstring wfemale = _T("女");
		std::string female = ws2s(wfemale);
		of << female << std::endl;
	}

	//民族  国籍或所在地区代码
	std::wstring idnation((wchar_t*)&Info->nation[0], (wchar_t*)&Info->nation[6]);
	std::string nation = ws2s(idnation);
	of << nation << std::endl;

	//生日
	std::wstring idbirthday((wchar_t*)&Info->birthday[0], (wchar_t*)&Info->birthday[16]);
	std::string birthday = ws2s(idbirthday);
	of << birthday << std::endl;

	//地址
	of << std::endl;

	//通行证号码  永久居留证号码
	std::wstring idIDSn((wchar_t*)&Info->IDSn[0], (wchar_t*)&Info->IDSn[36]);
	std::string IDSn = ws2s(idIDSn);
	of << IDSn << std::endl;//通行证号

	//签发机关  当次申请受理机关代码,23版没有这一项
	//std::wstring idsignNum((wchar_t *)&Info->signOrg[0], (wchar_t *)&Info->signOrg[8]);
	//std::string signNum = ws2s(idsignNum);
	std::string signNum = ws2s(L" ");
	of << signNum << std::endl;

	//签发日期
	std::wstring  idstartDate((wchar_t*)&Info->startDate[0], (wchar_t*)&Info->startDate[16]);
	std::string startDate = ws2s(idstartDate);
	of << startDate << std::endl;
	LOG(INFO) << "起始日期: " << BinaryToHexString(startDate) << std::endl;

	int zeroC = 0;
	for (int i = 0; i < startDate.size(); i++) {
		if (startDate[i] == '0') {
			zeroC++;
		}
	}

	if (zeroC >= startDate.size()) {
		LOG(ERROR) << "身份证读取数据出错" << std::endl;
	}

	//有效截止日期
	std::wstring idendDate((wchar_t*)&Info->endDate[0], (wchar_t*)&Info->endDate[16]);
	std::string endDate = ws2s(idendDate);
	of << endDate << std::endl;
	LOG(INFO) << "结束日期: " << BinaryToHexString(endDate) << std::endl;

	int zeroC2 = 0;
	for (int i = 0; i < endDate.size(); i++) {
		if (endDate[i] == '0') {
			zeroC2++;
		}
	}

	if (zeroC2 >= endDate.size()) {
		LOG(ERROR) << "身份证读取数据出错" << std::endl;
	}

	//中文名
	std::wstring idchinaese_name((wchar_t*)&Info->cnName[0], (wchar_t*)&Info->cnName[30]);
	std::string chinaese_name = ws2s(idchinaese_name);
	of << chinaese_name << std::endl;


	//证件版本号，23版不存在这一项
	//std::wstring idpassVersion((wchar_t *)&Info->cardver[0], (wchar_t *)&Info->cardver[4]);
	//std::string passVersion = ws2s(idpassVersion);
	std::string passVersion = ws2s(L" ");
	of << passVersion << std::endl;

	//证件类型标识
	std::wstring idtypeFlag((wchar_t*)&Info->typeFlag[0], (wchar_t*)&Info->typeFlag[2]);
	std::string typeFlag = ws2s(idtypeFlag);
	of << typeFlag << std::endl;

	//换证次数
	std::wstring chgNum((wchar_t*)&Info->chgNum[0], (wchar_t*)&Info->chgNum[4]);
	std::string chgNum1 = ws2s(chgNum);
	of << chgNum1 << std::endl;

	//PRCnumber_Related: "既往版本外国人永久居留证件号码关联项"
	std::wstring assID((wchar_t*)&Info->assID[0], (wchar_t*)&Info->assID[6]);
	std::string assID1 = ws2s(assID);
	of << assID1 << std::endl;

	//EngName1: 英文姓名
	std::wstring engname1((wchar_t*)&Info->enName[0], (wchar_t*)&Info->enName[70]);
	std::string engname11 = ws2s(engname1);
	of << engname11 << std::endl;

	//EngName2: 英文姓名
	std::wstring engname2((wchar_t*)&Info->enNameEx[0], (wchar_t*)&Info->enNameEx[22]);
	std::string engname21 = ws2s(engname2);
	of << engname21 << std::endl;
	//证件类型
	//std::wstring wCardFlag = _T("外国人居留证");
	//std::string CardFlag = ws2s(wCardFlag);
	//of << CardFlag << std::endl;
	of << "3" << std::endl;	 //用2表示外国人居留证


}

void mainlandIDInfoSave(std::ofstream& of, t_idcardinfor* Info) {
	LOG(INFO) << "MAINLAND IDCARD PARSER";
	//std::wstring  idname(200, '\0');
	//utf16lt_to_wchar_t(sInfo.name, sizeof(sInfo.name), (wchar_t *)idname.data(), sizeof(sInfo.name));
	std::wstring idname((wchar_t*)&Info->name[0], (wchar_t*)&Info->name[30]);
	std::string name = ws2s(idname);
	of << name << std::endl;

	std::wstring  idsex((wchar_t*)&Info->sex[0], (wchar_t*)&Info->sex[2]);
	//utf16lt_to_wchar_t(Info->sex, sizeof(Info->sex), (wchar_t *)idsex.data(), sizeof(Info->sex));
	std::string sex = ws2s(idsex);
	int sexIndex = sex[0] - '0';

	//性别
	std::wstring wmale = _T("男");
	std::string male = ws2s(wmale);
	std::wstring wfemale = _T("女");
	std::string female = ws2s(wfemale);
	if (sexIndex == 1) {
		of << male << std::endl;
	}
	else {
		of << female << std::endl;
	}

	//民族
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
		LOG(INFO) << "Nation Data: " << BinaryToHexString(nation.substr(4)) << std::endl;
	}

	//出生日期
	std::wstring  idbirthday((wchar_t*)&Info->birthday[0], (wchar_t*)&Info->birthday[16]);
	//utf16lt_to_wchar_t(sInfo.birthday, sizeof(sInfo.birthday), (wchar_t *)idbirthday.data(), sizeof(sInfo.birthday));
	std::string birthday = ws2s(idbirthday);
	of << birthday << std::endl;

	//住址
	std::wstring  idaddr((wchar_t*)&Info->addr[0], (wchar_t*)&Info->addr[70]);
	//utf16lt_to_wchar_t(sInfo.addr, sizeof(sInfo.addr), (wchar_t *)idaddr.data(), sizeof(sInfo.addr));
	std::string addr = ws2s(idaddr);
	of << addr << std::endl;

	//身份证号
	std::wstring  idIDSn((wchar_t*)&Info->IDSn[0], (wchar_t*)&Info->IDSn[36]);
	//utf16lt_to_wchar_t(sInfo.IDSn, sizeof(sInfo.IDSn), (wchar_t *)idIDSn.data(), sizeof(sInfo.IDSn));
	std::string IDSn = ws2s(idIDSn);
	of << IDSn << std::endl;

	//签发单位
	std::wstring  idsignOrg((wchar_t*)&Info->signOrg[0], (wchar_t*)&Info->signOrg[30]);
	//utf16lt_to_wchar_t(sInfo.signOrg, sizeof(sInfo.signOrg), (wchar_t *)idsignOrg.data(), sizeof(sInfo.signOrg));
	std::string signOrg = ws2s(idsignOrg);
	of << signOrg << std::endl;

	//签发日期
	std::wstring  idstartDate((wchar_t*)&Info->startDate[0], (wchar_t*)&Info->startDate[16]);
	//utf16lt_to_wchar_t(sInfo.startDate, sizeof(sInfo.startDate), (wchar_t *)idstartDate.data(), sizeof(sInfo.startDate));
	std::string startDate = ws2s(idstartDate);
	of << startDate << std::endl;
	LOG(INFO) << "起始日期: " << BinaryToHexString(startDate) << std::endl;

	int zeroC = 0;
	for (int i = 0; i < startDate.size(); i++) {
		if (startDate[i] == '0') {
			zeroC++;
		}
	}

	if (zeroC >= startDate.size()) {
		LOG(ERROR) << "身份证读取数据出错" << std::endl;
	}

	//有效日期
	std::wstring idendDate((wchar_t*)&Info->endDate[0], (wchar_t*)&Info->endDate[16]);
	//utf16lt_to_wchar_t(sInfo.endDate, sizeof(sInfo.endDate), (wchar_t *)idendDate.data(), sizeof(sInfo.endDate));
	std::string endDate = ws2s(idendDate);
	of << endDate << std::endl;
	LOG(INFO) << "结束日期: " << BinaryToHexString(endDate) << std::endl;

	int zeroC2 = 0;
	for (int i = 0; i < endDate.size(); i++) {
		if (endDate[i] == '0') {
			zeroC2++;
		}
	}

	if (zeroC2 >= endDate.size()) {
		LOG(ERROR) << "身份证读取数据出错" << std::endl;
	}

	//证件标识
	//std::wstring wCardType = _T("居民身份证");
	//std::string mainCardType = ws2s(wCardType);
	//std::wstring wwCardType = _T("港澳台居民居住证");
	//std::string islandCardType = ws2s(wwCardType);

	std::wstring  idCardType((wchar_t*)&Info->typeFlag[0], (wchar_t*)&Info->typeFlag[2]);
	std::string CcardType = ws2s(idCardType);
	if (CcardType[0] == 'J') {//港澳台居住证
		//of << islandCardType << std::endl;
		//of << '1' << std::endl;  // 不输出，留在港澳台接口输出
	}
	else {//身份证
		//of << mainCardType << std::endl;
		of << "0" << std::endl;;
	}

}

void islandIDInfoSave(std::ofstream& of, t_idcardinfor* Info) {
	
	mainlandIDInfoSave(of, Info);
	LOG(INFO) << "AND THEN CHINESE ISLAND IDCARD PARSER";
	//通行证号码
	std::wstring idpassID((wchar_t*)&Info->passID[0], (wchar_t*)&Info->passID[18]);
	std::string passID = ws2s(idpassID);
	of << passID << std::endl;

	//签发次数
	std::wstring idissuesNum((wchar_t*)&Info->issuesNum[0], (wchar_t*)&Info->issuesNum[4]);
	std::string issuesNum = ws2s(idissuesNum);
	of << issuesNum << std::endl;

	//证件标识
	std::wstring idtypeFlag((wchar_t*)&Info->typeFlag[0], (wchar_t*)&Info->typeFlag[2]);
	std::string typeFlag = ws2s(idtypeFlag);
	of << typeFlag << std::endl;

	//输出证件标识
	of << "1" << std::endl;

}

string DG1, DG11;

int PCSC_GetIDCard() {
	char path_DG2[MAX_PATH];
	MakeFullPath1(path_DG2, "USB_TEMP\\DG2.bmp");
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
	if ((*(t_idcardinfor*)&sInfo).typeFlag[0] == ' ')
		mainlandIDInfoSave(idcout, (t_idcardinfor*)&sInfo);
	else if (((*(t_idforeigner*)&sInfo).typeFlag[0] == 'I'))
		foreignerIDInfoSave(idcout, (t_idforeigner*)&sInfo);
	else if (((*(t_idforeigner2023*)&sInfo).typeFlag[0] == 'Y'))
		foreignerIDInfoSave_new(idcout, (t_idforeigner2023*)&sInfo);
	else if (((*(t_idcardinfor*)&sInfo).typeFlag[0] == 'J'))
		islandIDInfoSave(idcout,(t_idcardinfor*)&sInfo);
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

int PCSCGetChipPACE(string mrz, int cardType, ChipAuthenticData& chipAuthenticData, ChipData_Doc9303& chipData_9303, std::string& rfidJson, bool byCAN) {
	
	char path_DG2[MAX_PATH];
	MakeFullPath1(path_DG2, "USB_TEMP//DG2.bmp");

	int ret = -1;
	PCSCReader pcscReader;
	
	string fullName, selfID;
	string atr;
	ret = pcscReader.Initalize();
	if (ret > 0) {
		ret = pcscReader.Connect(atr);
	}

	//LOG(INFO)<< "ATR:	" << atr << endl;
	//if (atr.size() < 30) return -1;
	// ISO14443-4 Type B && Type B 
	std::string codetonfc;
	pcscReader.SetCardType(cardType);
	pcscReader.mrtd.CardType = pcscReader.CardType;
	if (!byCAN)
	{
		if (!pcscReader.mrtd.Parse(mrz)) {
			//LOGE("mrtd.Parse(code) error");
			return -1;
		}
		pcscReader.EF_DG2_SetResultPath(path_DG2);
		codetonfc = pcscReader.mrtd.mrzInfo.codetonfc;
	}
	//默认用BAC
	//ret = pcscReader.ReadEchipInfo(codetonfc);
	//if (!ret)
	//{
	//	LOG(INFO)<< "BAC FAIL\n";
	//}
	//
	////BAC失败再使用PACE
	//ret = pcscReader.ReadEChipInfoPACE(codetonfc);
	//if (!ret)
	//	LOG(INFO)<< "PACE FAIL\n";
	else
		codetonfc = mrz;
	ret = -1;
	ret = pcscReader.ReadEChipInfoPACE(codetonfc);
	pcscReader.dumpJsonResult();
	char mypath[256];
	MakeFullPath1(mypath, "USB_TEMP\\DG15.bin");
	char SOD_file_path[256];
	MakeFullPath1(SOD_file_path, "USB_TEMP\\SOD.bin");
	pcscReader.DissConnect();
	chipData_9303.iDG1 = pcscReader.ChipData_Doc9303_Result.iDG1;
	std::memcpy(chipData_9303.pDG1, pcscReader.ChipData_Doc9303_Result.pDG1, sizeof(chipData_9303.pDG1));
	chipData_9303.iDG2 = pcscReader.ChipData_Doc9303_Result.iDG2;
	std::memcpy(chipData_9303.pDG2, pcscReader.ChipData_Doc9303_Result.pDG2, sizeof(chipData_9303.pDG2));
	chipData_9303.iDG3 = pcscReader.ChipData_Doc9303_Result.iDG3;
	std::memcpy(chipData_9303.pDG3, pcscReader.ChipData_Doc9303_Result.pDG3, sizeof(chipData_9303.pDG3));
	chipData_9303.iDG4 = pcscReader.ChipData_Doc9303_Result.iDG4;
	std::memcpy(chipData_9303.pDG4, pcscReader.ChipData_Doc9303_Result.pDG4, sizeof(chipData_9303.pDG4));
	chipData_9303.iDG5 = pcscReader.ChipData_Doc9303_Result.iDG5;
	std::memcpy(chipData_9303.pDG5, pcscReader.ChipData_Doc9303_Result.pDG5, sizeof(chipData_9303.pDG5));
	chipData_9303.iDG6 = pcscReader.ChipData_Doc9303_Result.iDG6;
	std::memcpy(chipData_9303.pDG6, pcscReader.ChipData_Doc9303_Result.pDG6, sizeof(chipData_9303.pDG6));
	chipData_9303.iDG7 = pcscReader.ChipData_Doc9303_Result.iDG7;
	std::memcpy(chipData_9303.pDG7, pcscReader.ChipData_Doc9303_Result.pDG7, sizeof(chipData_9303.pDG7));
	chipData_9303.iDG8 = pcscReader.ChipData_Doc9303_Result.iDG8;
	std::memcpy(chipData_9303.pDG8, pcscReader.ChipData_Doc9303_Result.pDG8, sizeof(chipData_9303.pDG8));
	chipData_9303.iDG9 = pcscReader.ChipData_Doc9303_Result.iDG9;
	std::memcpy(chipData_9303.pDG9, pcscReader.ChipData_Doc9303_Result.pDG9, sizeof(chipData_9303.pDG9));
	chipData_9303.iDG10 = pcscReader.ChipData_Doc9303_Result.iDG10;
	std::memcpy(chipData_9303.pDG10, pcscReader.ChipData_Doc9303_Result.pDG10, sizeof(chipData_9303.pDG10));
	chipData_9303.iDG11 = pcscReader.ChipData_Doc9303_Result.iDG11;
	std::memcpy(chipData_9303.pDG11, pcscReader.ChipData_Doc9303_Result.pDG11, sizeof(chipData_9303.pDG11));
	chipData_9303.iDG12 = pcscReader.ChipData_Doc9303_Result.iDG12;
	std::memcpy(chipData_9303.pDG12, pcscReader.ChipData_Doc9303_Result.pDG12, sizeof(chipData_9303.pDG12));
	chipData_9303.iDG13 = pcscReader.ChipData_Doc9303_Result.iDG13;
	std::memcpy(chipData_9303.pDG13, pcscReader.ChipData_Doc9303_Result.pDG13, sizeof(chipData_9303.pDG13));
	chipData_9303.iDG14 = pcscReader.ChipData_Doc9303_Result.iDG14;
	std::memcpy(chipData_9303.pDG14, pcscReader.ChipData_Doc9303_Result.pDG14, sizeof(chipData_9303.pDG14));
	chipData_9303.iDG15 = pcscReader.ChipData_Doc9303_Result.iDG15;
	std::memcpy(chipData_9303.pDG15, pcscReader.ChipData_Doc9303_Result.pDG15, sizeof(chipData_9303.pDG15));
	chipData_9303.iDG16 = pcscReader.ChipData_Doc9303_Result.iDG16;
	std::memcpy(chipData_9303.pDG16, pcscReader.ChipData_Doc9303_Result.pDG16, sizeof(chipData_9303.pDG16));
	chipData_9303.iCardAcess = pcscReader.ChipData_Doc9303_Result.iCardAcess;
	std::memcpy(chipData_9303.pCardAccess, pcscReader.ChipData_Doc9303_Result.pCardAccess, sizeof(chipData_9303.pCardAccess));
	chipData_9303.iCardSecurity = pcscReader.ChipData_Doc9303_Result.iCardSecurity;
	std::memcpy(chipData_9303.pCardSecurity, pcscReader.ChipData_Doc9303_Result.pCardSecurity, sizeof(chipData_9303.pCardSecurity));
	chipData_9303.iSOD = pcscReader.ChipData_Doc9303_Result.iSOD;
	std::memcpy(chipData_9303.pSOD, pcscReader.ChipData_Doc9303_Result.pSOD, sizeof(chipData_9303.pSOD));
	chipAuthenticData.AA = pcscReader.ChipAuthenticResult.AA;
	chipAuthenticData.PA = pcscReader.ChipAuthenticResult.PA;
	chipAuthenticData.BAC = pcscReader.ChipAuthenticResult.BAC;
	chipAuthenticData.PACE = pcscReader.ChipAuthenticResult.PACE;
	chipAuthenticData.CA = pcscReader.ChipAuthenticResult.CA;
	chipAuthenticData.PASOD = pcscReader.ChipAuthenticResult.PASOD;
	chipAuthenticData.PADS = pcscReader.ChipAuthenticResult.PADS;
	chipAuthenticData.PADGHash = pcscReader.ChipAuthenticResult.PADGHash;
	rfidJson = pcscReader.rfid_json;

	return ret;
}

int PCSCGetChip_given_three_parts_PACE(string serialnum, string birthdate, string expiredate , int cardType, 
	ChipAuthenticData& chipAuthenticData, ChipData_Doc9303& chipData_9303,std::string& rfidJson)
{
	//compute checkbit
	int check = 0;
	int weight[3] = { 7,3,1 };
	for (; serialnum.length() < 9;)
		serialnum += "<";
	for (int i=0;i< serialnum.length();i++)
	{
		char ch = serialnum[i];
		if (ch >= '0' && ch <= '9')
			check += (ch - '0') * weight[i % 3];
		else if (ch >= 'A' && ch <= 'Z')
			check += (ch - 'A' + 10) * weight[i % 3];
		else if (ch == '<')
			continue;
	}
	check = check % 10;
	std::string serialnum_new = serialnum+to_string(check);
	check = 0;
	if (birthdate.length() != 6)
	{
		LOG(INFO)<< "birthdate.length()!=6";
		return -1;
	}
	for (int i = 0; i < birthdate.length(); i++)
	{
		char ch = birthdate[i];
		if (ch >= '0' && ch <= '9')
			check += (ch - '0') * weight[i % 3];
		else if (ch >= 'A' && ch <= 'Z')
			check += (ch - 'A' + 10) * weight[i % 3];
		else if (ch == '<')
			continue;
	}
	check = check % 10;
	std::string birthdate_new = birthdate+to_string(check);
	check = 0;
	if (expiredate.length() != 6)
	{
		LOG(INFO)<< "expiredate.length()!=6";
		return -1;
	}
	for (int i = 0; i < expiredate.length(); i++)
	{
		char ch = expiredate[i];
		if (ch >= '0' && ch <= '9')
			check += (ch - '0') * weight[i % 3];
		else if (ch >= 'A' && ch <= 'Z')
			check += (ch - 'A' + 10) * weight[i % 3];
		else if (ch == '<')
			continue;
	}
	check = check % 10;
	std::string expiredate_new = expiredate+to_string(check);
	check = 0;
	std::string codetonfc = serialnum_new+birthdate_new+expiredate_new;
	//
	char path_DG2[MAX_PATH];
	MakeFullPath1(path_DG2, "USB_TEMP//DG2.bmp");

	int ret = -1;
	PCSCReader pcscReader;

	string fullName, selfID;
	string atr;
	ret = pcscReader.Initalize();
	if (ret > 0) {
		ret = pcscReader.Connect(atr);
	}

	//LOG(INFO)<< "ATR:	" << atr << endl;
	//if (atr.size() < 30) return -1;
	// ISO14443-4 Type B && Type B 

	pcscReader.SetCardType(cardType);
	pcscReader.mrtd.CardType = pcscReader.CardType;

	//if (!pcscReader.mrtd.Parse(mrz)) {
	//	//LOGE("mrtd.Parse(code) error");
	//	return -1;
	//}
	pcscReader.EF_DG2_SetResultPath(path_DG2);
	/*std::string codetonfc = pcscReader.mrtd.mrzInfo.codetonfc;*/
	//默认用BAC
	//ret = pcscReader.ReadEchipInfo(codetonfc);
	//if (ret < 0) {
	//	//BAC失败再使用PACE
	//	ret = pcscReader.ReadEChipInfoPACE(codetonfc);
	//}
	ret = pcscReader.ReadEChipInfoPACE(codetonfc);
	pcscReader.dumpJsonResult();
	pcscReader.DissConnect();
	chipData_9303.iDG1 = pcscReader.ChipData_Doc9303_Result.iDG1;
	std::memcpy(chipData_9303.pDG1, pcscReader.ChipData_Doc9303_Result.pDG1, sizeof(chipData_9303.pDG1));
	chipData_9303.iDG2 = pcscReader.ChipData_Doc9303_Result.iDG2;
	std::memcpy(chipData_9303.pDG2, pcscReader.ChipData_Doc9303_Result.pDG2, sizeof(chipData_9303.pDG2));
	chipData_9303.iDG3 = pcscReader.ChipData_Doc9303_Result.iDG3;
	std::memcpy(chipData_9303.pDG3, pcscReader.ChipData_Doc9303_Result.pDG3, sizeof(chipData_9303.pDG3));
	chipData_9303.iDG4 = pcscReader.ChipData_Doc9303_Result.iDG4;
	std::memcpy(chipData_9303.pDG4, pcscReader.ChipData_Doc9303_Result.pDG4, sizeof(chipData_9303.pDG4));
	chipData_9303.iDG5 = pcscReader.ChipData_Doc9303_Result.iDG5;
	std::memcpy(chipData_9303.pDG5, pcscReader.ChipData_Doc9303_Result.pDG5, sizeof(chipData_9303.pDG5));
	chipData_9303.iDG6 = pcscReader.ChipData_Doc9303_Result.iDG6;
	std::memcpy(chipData_9303.pDG6, pcscReader.ChipData_Doc9303_Result.pDG6, sizeof(chipData_9303.pDG6));
	chipData_9303.iDG7 = pcscReader.ChipData_Doc9303_Result.iDG7;
	std::memcpy(chipData_9303.pDG7, pcscReader.ChipData_Doc9303_Result.pDG7, sizeof(chipData_9303.pDG7));
	chipData_9303.iDG8 = pcscReader.ChipData_Doc9303_Result.iDG8;
	std::memcpy(chipData_9303.pDG8, pcscReader.ChipData_Doc9303_Result.pDG8, sizeof(chipData_9303.pDG8));
	chipData_9303.iDG9 = pcscReader.ChipData_Doc9303_Result.iDG9;
	std::memcpy(chipData_9303.pDG9, pcscReader.ChipData_Doc9303_Result.pDG9, sizeof(chipData_9303.pDG9));
	chipData_9303.iDG10 = pcscReader.ChipData_Doc9303_Result.iDG10;
	std::memcpy(chipData_9303.pDG10, pcscReader.ChipData_Doc9303_Result.pDG10, sizeof(chipData_9303.pDG10));
	chipData_9303.iDG11 = pcscReader.ChipData_Doc9303_Result.iDG11;
	std::memcpy(chipData_9303.pDG11, pcscReader.ChipData_Doc9303_Result.pDG11, sizeof(chipData_9303.pDG11));
	chipData_9303.iDG12 = pcscReader.ChipData_Doc9303_Result.iDG12;
	std::memcpy(chipData_9303.pDG12, pcscReader.ChipData_Doc9303_Result.pDG12, sizeof(chipData_9303.pDG12));
	chipData_9303.iDG13 = pcscReader.ChipData_Doc9303_Result.iDG13;
	std::memcpy(chipData_9303.pDG13, pcscReader.ChipData_Doc9303_Result.pDG13, sizeof(chipData_9303.pDG13));
	chipData_9303.iDG14 = pcscReader.ChipData_Doc9303_Result.iDG14;
	std::memcpy(chipData_9303.pDG14, pcscReader.ChipData_Doc9303_Result.pDG14, sizeof(chipData_9303.pDG14));
	chipData_9303.iDG15 = pcscReader.ChipData_Doc9303_Result.iDG15;
	std::memcpy(chipData_9303.pDG15, pcscReader.ChipData_Doc9303_Result.pDG15, sizeof(chipData_9303.pDG15));
	chipData_9303.iDG16 = pcscReader.ChipData_Doc9303_Result.iDG16;
	std::memcpy(chipData_9303.pDG16, pcscReader.ChipData_Doc9303_Result.pDG16, sizeof(chipData_9303.pDG16));
	chipData_9303.iCardAcess = pcscReader.ChipData_Doc9303_Result.iCardAcess;
	std::memcpy(chipData_9303.pCardAccess, pcscReader.ChipData_Doc9303_Result.pCardAccess, sizeof(chipData_9303.pCardAccess));
	chipData_9303.iCardSecurity = pcscReader.ChipData_Doc9303_Result.iCardSecurity;
	std::memcpy(chipData_9303.pCardSecurity, pcscReader.ChipData_Doc9303_Result.pCardSecurity, sizeof(chipData_9303.pCardSecurity));
	chipData_9303.iSOD = pcscReader.ChipData_Doc9303_Result.iSOD;
	std::memcpy(chipData_9303.pSOD, pcscReader.ChipData_Doc9303_Result.pSOD, sizeof(chipData_9303.pSOD));
	chipAuthenticData.AA = pcscReader.ChipAuthenticResult.AA;
	chipAuthenticData.PA = pcscReader.ChipAuthenticResult.PA;
	chipAuthenticData.BAC = pcscReader.ChipAuthenticResult.BAC;
	chipAuthenticData.PACE = pcscReader.ChipAuthenticResult.PACE;
	chipAuthenticData.CA = pcscReader.ChipAuthenticResult.CA;
	chipAuthenticData.PASOD = pcscReader.ChipAuthenticResult.PASOD;
	chipAuthenticData.PADS = pcscReader.ChipAuthenticResult.PADS;
	chipAuthenticData.PADGHash = pcscReader.ChipAuthenticResult.PADGHash;
	rfidJson = pcscReader.rfid_json;

	return ret;
}
int PCSCGetChip_given_three_parts_BAC(string serialnum, string birthdate, string expiredate, int cardType,
	ChipAuthenticData& chipAuthenticData, ChipData_Doc9303& chipData_9303, std::string& rfidJson) {
	//compute checkbit
	int check = 0;
	int weight[3] = { 7,3,1 };
	for (; serialnum.length() < 9;)
		serialnum += "<";
	for (int i = 0; i < serialnum.length(); i++)
	{
		char ch = serialnum[i];
		if (ch >= '0' && ch <= '9')
			check += (ch - '0') * weight[i % 3];
		else if (ch >= 'A' && ch <= 'Z')
			check += (ch - 'A' + 10) * weight[i % 3];
		else if (ch == '<')
			continue;
	}
	check = check % 10;
	std::string serialnum_new = serialnum + to_string(check);
	check = 0;
	if (birthdate.length() != 6)
	{
		LOG(INFO)<< "birthdate.length()!=6";
		return -1;
	}
	for (int i = 0; i < birthdate.length(); i++)
	{
		char ch = birthdate[i];
		if (ch >= '0' && ch <= '9')
			check += (ch - '0') * weight[i % 3];
		else if (ch >= 'A' && ch <= 'Z')
			check += (ch - 'A' + 10) * weight[i % 3];
		else if (ch == '<')
			continue;
	}
	check = check % 10;
	std::string birthdate_new = birthdate + to_string(check);
	check = 0;
	if (expiredate.length() != 6)
	{
		LOG(INFO)<< "expiredate.length()!=6";
		return -1;
	}
	for (int i = 0; i < expiredate.length(); i++)
	{
		char ch = expiredate[i];
		if (ch >= '0' && ch <= '9')
			check += (ch - '0') * weight[i % 3];
		else if (ch >= 'A' && ch <= 'Z')
			check += (ch - 'A' + 10) * weight[i % 3];
		else if (ch == '<')
			continue;
	}
	check = check % 10;
	std::string expiredate_new = expiredate + to_string(check);
	check = 0;
	std::string codetonfc = serialnum_new + birthdate_new + expiredate_new;
	//
	char path_DG2[MAX_PATH];
	MakeFullPath1(path_DG2, "USB_TEMP//DG2.bmp");

	int ret = -1;
	PCSCReader pcscReader;

	string fullName, selfID;
	string atr;
	ret = pcscReader.Initalize();
	if (ret > 0) {
		ret = pcscReader.Connect(atr);
	}

	//LOG(INFO)<< "ATR:	" << atr << endl;
	//if (atr.size() < 30) return -1;
	// ISO14443-4 Type B && Type B 

	pcscReader.SetCardType(cardType);
	pcscReader.mrtd.CardType = pcscReader.CardType;

	//if (!pcscReader.mrtd.Parse(mrz)) {
	//	//LOGE("mrtd.Parse(code) error");
	//	return -1;
	//}
	pcscReader.EF_DG2_SetResultPath(path_DG2);
	/*std::string codetonfc = pcscReader.mrtd.mrzInfo.codetonfc;*/
	//默认用BAC
	//ret = pcscReader.ReadEchipInfo(codetonfc);
	//if (ret < 0) {
	//	//BAC失败再使用PACE
	//	ret = pcscReader.ReadEChipInfoPACE(codetonfc);
	//}
	try
	{
		ret = pcscReader.ReadEchipInfo(codetonfc);
	}
	catch (const std::exception& e)
	{
		LOG(ERROR) << e.what();
	}
	pcscReader.dumpJsonResult();
	pcscReader.DissConnect();
	chipData_9303.iDG1 = pcscReader.ChipData_Doc9303_Result.iDG1;
	std::memcpy(chipData_9303.pDG1, pcscReader.ChipData_Doc9303_Result.pDG1, sizeof(chipData_9303.pDG1));
	chipData_9303.iDG2 = pcscReader.ChipData_Doc9303_Result.iDG2;
	std::memcpy(chipData_9303.pDG2, pcscReader.ChipData_Doc9303_Result.pDG2, sizeof(chipData_9303.pDG2));
	chipData_9303.iDG3 = pcscReader.ChipData_Doc9303_Result.iDG3;
	std::memcpy(chipData_9303.pDG3, pcscReader.ChipData_Doc9303_Result.pDG3, sizeof(chipData_9303.pDG3));
	chipData_9303.iDG4 = pcscReader.ChipData_Doc9303_Result.iDG4;
	std::memcpy(chipData_9303.pDG4, pcscReader.ChipData_Doc9303_Result.pDG4, sizeof(chipData_9303.pDG4));
	chipData_9303.iDG5 = pcscReader.ChipData_Doc9303_Result.iDG5;
	std::memcpy(chipData_9303.pDG5, pcscReader.ChipData_Doc9303_Result.pDG5, sizeof(chipData_9303.pDG5));
	chipData_9303.iDG6 = pcscReader.ChipData_Doc9303_Result.iDG6;
	std::memcpy(chipData_9303.pDG6, pcscReader.ChipData_Doc9303_Result.pDG6, sizeof(chipData_9303.pDG6));
	chipData_9303.iDG7 = pcscReader.ChipData_Doc9303_Result.iDG7;
	std::memcpy(chipData_9303.pDG7, pcscReader.ChipData_Doc9303_Result.pDG7, sizeof(chipData_9303.pDG7));
	chipData_9303.iDG8 = pcscReader.ChipData_Doc9303_Result.iDG8;
	std::memcpy(chipData_9303.pDG8, pcscReader.ChipData_Doc9303_Result.pDG8, sizeof(chipData_9303.pDG8));
	chipData_9303.iDG9 = pcscReader.ChipData_Doc9303_Result.iDG9;
	std::memcpy(chipData_9303.pDG9, pcscReader.ChipData_Doc9303_Result.pDG9, sizeof(chipData_9303.pDG9));
	chipData_9303.iDG10 = pcscReader.ChipData_Doc9303_Result.iDG10;
	std::memcpy(chipData_9303.pDG10, pcscReader.ChipData_Doc9303_Result.pDG10, sizeof(chipData_9303.pDG10));
	chipData_9303.iDG11 = pcscReader.ChipData_Doc9303_Result.iDG11;
	std::memcpy(chipData_9303.pDG11, pcscReader.ChipData_Doc9303_Result.pDG11, sizeof(chipData_9303.pDG11));
	chipData_9303.iDG12 = pcscReader.ChipData_Doc9303_Result.iDG12;
	std::memcpy(chipData_9303.pDG12, pcscReader.ChipData_Doc9303_Result.pDG12, sizeof(chipData_9303.pDG12));
	chipData_9303.iDG13 = pcscReader.ChipData_Doc9303_Result.iDG13;
	std::memcpy(chipData_9303.pDG13, pcscReader.ChipData_Doc9303_Result.pDG13, sizeof(chipData_9303.pDG13));
	chipData_9303.iDG14 = pcscReader.ChipData_Doc9303_Result.iDG14;
	std::memcpy(chipData_9303.pDG14, pcscReader.ChipData_Doc9303_Result.pDG14, sizeof(chipData_9303.pDG14));
	chipData_9303.iDG15 = pcscReader.ChipData_Doc9303_Result.iDG15;
	std::memcpy(chipData_9303.pDG15, pcscReader.ChipData_Doc9303_Result.pDG15, sizeof(chipData_9303.pDG15));
	chipData_9303.iDG16 = pcscReader.ChipData_Doc9303_Result.iDG16;
	std::memcpy(chipData_9303.pDG16, pcscReader.ChipData_Doc9303_Result.pDG16, sizeof(chipData_9303.pDG16));
	chipData_9303.iCardAcess = pcscReader.ChipData_Doc9303_Result.iCardAcess;
	std::memcpy(chipData_9303.pCardAccess, pcscReader.ChipData_Doc9303_Result.pCardAccess, sizeof(chipData_9303.pCardAccess));
	chipData_9303.iCardSecurity = pcscReader.ChipData_Doc9303_Result.iCardSecurity;
	std::memcpy(chipData_9303.pCardSecurity, pcscReader.ChipData_Doc9303_Result.pCardSecurity, sizeof(chipData_9303.pCardSecurity));
	chipData_9303.iSOD = pcscReader.ChipData_Doc9303_Result.iSOD;
	std::memcpy(chipData_9303.pSOD, pcscReader.ChipData_Doc9303_Result.pSOD, sizeof(chipData_9303.pSOD));
	chipAuthenticData.AA = pcscReader.ChipAuthenticResult.AA;
	chipAuthenticData.PA = pcscReader.ChipAuthenticResult.PA;
	chipAuthenticData.BAC = pcscReader.ChipAuthenticResult.BAC;
	chipAuthenticData.PACE = pcscReader.ChipAuthenticResult.PACE;
	chipAuthenticData.CA = pcscReader.ChipAuthenticResult.CA;
	chipAuthenticData.PASOD = pcscReader.ChipAuthenticResult.PASOD;
	chipAuthenticData.PADS = pcscReader.ChipAuthenticResult.PADS;
	chipAuthenticData.PADGHash = pcscReader.ChipAuthenticResult.PADGHash;
	rfidJson = pcscReader.rfid_json;
	return ret;
}


int PCSCGetChipBAC(string mrz, int cardType, ChipAuthenticData& chipAuthenticData, ChipData_Doc9303& chipData_9303, std::string& rfidJson) {
	//char usbtemp[MAX_PATH];
	//MakeFullPath1(usbtemp, "USB_TEMP");
	//RemoveDir(usbtemp);
	char path_DG2[MAX_PATH];
	MakeFullPath1(path_DG2, "USB_TEMP//DG2.bmp"); 
	int ret = -1;
	PCSCReader pcscReader;

	string fullName, selfID;
	string atr;
	ret = pcscReader.Initalize();
	if (ret > 0) {
		ret = pcscReader.Connect(atr);
	}

	//LOG(INFO)<< "ATR:	" << atr << endl;
	//if (atr.size() < 30) return -1;
	// ISO14443-4 Type B && Type B 

	pcscReader.SetCardType(cardType);
	pcscReader.mrtd.CardType = pcscReader.CardType;
	if (!pcscReader.mrtd.Parse(mrz)) {
		//LOGE("mrtd.Parse(code) error");
		return -1;
	}
	pcscReader.EF_DG2_SetResultPath(path_DG2);
	std::string codetonfc = pcscReader.mrtd.mrzInfo.codetonfc;
	LOG(INFO) << "CODE TO NFC: " << codetonfc << endl;
	//默认用BAC
	//ret = pcscReader.ReadEchipInfo(codetonfc);
	//if (ret < 0) {
	//	//BAC失败再使用PACE
	//	ret = pcscReader.ReadEChipInfoPACE(codetonfc);
	//}
	try
	{
		ret = pcscReader.ReadEchipInfo(codetonfc);
	}
	catch (const std::exception& e)
	{
		LOG(ERROR) << e.what();
	}
	pcscReader.dumpJsonResult();
	pcscReader.DissConnect();

	chipData_9303.iDG1 = pcscReader.ChipData_Doc9303_Result.iDG1;
	std::memcpy(chipData_9303.pDG1, pcscReader.ChipData_Doc9303_Result.pDG1, sizeof(chipData_9303.pDG1));
	chipData_9303.iDG2 = pcscReader.ChipData_Doc9303_Result.iDG2;
	std::memcpy(chipData_9303.pDG2, pcscReader.ChipData_Doc9303_Result.pDG2, sizeof(chipData_9303.pDG2));
	chipData_9303.iDG3 = pcscReader.ChipData_Doc9303_Result.iDG3;
	std::memcpy(chipData_9303.pDG3, pcscReader.ChipData_Doc9303_Result.pDG3, sizeof(chipData_9303.pDG3));
	chipData_9303.iDG4 = pcscReader.ChipData_Doc9303_Result.iDG4;
	std::memcpy(chipData_9303.pDG4, pcscReader.ChipData_Doc9303_Result.pDG4, sizeof(chipData_9303.pDG4));
	chipData_9303.iDG5 = pcscReader.ChipData_Doc9303_Result.iDG5;
	std::memcpy(chipData_9303.pDG5, pcscReader.ChipData_Doc9303_Result.pDG5, sizeof(chipData_9303.pDG5));
	chipData_9303.iDG6 = pcscReader.ChipData_Doc9303_Result.iDG6;
	std::memcpy(chipData_9303.pDG6, pcscReader.ChipData_Doc9303_Result.pDG6, sizeof(chipData_9303.pDG6));
	chipData_9303.iDG7 = pcscReader.ChipData_Doc9303_Result.iDG7;
	std::memcpy(chipData_9303.pDG7, pcscReader.ChipData_Doc9303_Result.pDG7, sizeof(chipData_9303.pDG7));
	chipData_9303.iDG8 = pcscReader.ChipData_Doc9303_Result.iDG8;
	std::memcpy(chipData_9303.pDG8, pcscReader.ChipData_Doc9303_Result.pDG8, sizeof(chipData_9303.pDG8));
	chipData_9303.iDG9 = pcscReader.ChipData_Doc9303_Result.iDG9;
	std::memcpy(chipData_9303.pDG9, pcscReader.ChipData_Doc9303_Result.pDG9, sizeof(chipData_9303.pDG9));
	chipData_9303.iDG10 = pcscReader.ChipData_Doc9303_Result.iDG10;
	std::memcpy(chipData_9303.pDG10, pcscReader.ChipData_Doc9303_Result.pDG10, sizeof(chipData_9303.pDG10));
	chipData_9303.iDG11 = pcscReader.ChipData_Doc9303_Result.iDG11;
	std::memcpy(chipData_9303.pDG11, pcscReader.ChipData_Doc9303_Result.pDG11, sizeof(chipData_9303.pDG11));
	chipData_9303.iDG12 = pcscReader.ChipData_Doc9303_Result.iDG12;
	std::memcpy(chipData_9303.pDG12, pcscReader.ChipData_Doc9303_Result.pDG12, sizeof(chipData_9303.pDG12));
	chipData_9303.iDG13 = pcscReader.ChipData_Doc9303_Result.iDG13;
	std::memcpy(chipData_9303.pDG13, pcscReader.ChipData_Doc9303_Result.pDG13, sizeof(chipData_9303.pDG13));
	chipData_9303.iDG14 = pcscReader.ChipData_Doc9303_Result.iDG14;
	std::memcpy(chipData_9303.pDG14, pcscReader.ChipData_Doc9303_Result.pDG14, sizeof(chipData_9303.pDG14));
	chipData_9303.iDG15 = pcscReader.ChipData_Doc9303_Result.iDG15; 
	std::memcpy(chipData_9303.pDG15, pcscReader.ChipData_Doc9303_Result.pDG15, sizeof(chipData_9303.pDG15));
	chipData_9303.iDG16 = pcscReader.ChipData_Doc9303_Result.iDG16;
	std::memcpy(chipData_9303.pDG16, pcscReader.ChipData_Doc9303_Result.pDG16, sizeof(chipData_9303.pDG16));
	chipData_9303.iCardAcess = pcscReader.ChipData_Doc9303_Result.iCardAcess;
	std::memcpy(chipData_9303.pCardAccess, pcscReader.ChipData_Doc9303_Result.pCardAccess, sizeof(chipData_9303.pCardAccess));
	chipData_9303.iCardSecurity = pcscReader.ChipData_Doc9303_Result.iCardSecurity;
	std::memcpy(chipData_9303.pCardSecurity, pcscReader.ChipData_Doc9303_Result.pCardSecurity, sizeof(chipData_9303.pCardSecurity));
	chipData_9303.iSOD = pcscReader.ChipData_Doc9303_Result.iSOD;
	std::memcpy(chipData_9303.pSOD, pcscReader.ChipData_Doc9303_Result.pSOD, sizeof(chipData_9303.pSOD));
	chipAuthenticData.AA = pcscReader.ChipAuthenticResult.AA;
	chipAuthenticData.PA = pcscReader.ChipAuthenticResult.PA;
	chipAuthenticData.BAC = pcscReader.ChipAuthenticResult.BAC;
	chipAuthenticData.PACE = pcscReader.ChipAuthenticResult.PACE;
	chipAuthenticData.CA = pcscReader.ChipAuthenticResult.CA;
	chipAuthenticData.PASOD = pcscReader.ChipAuthenticResult.PASOD;
	chipAuthenticData.PADS = pcscReader.ChipAuthenticResult.PADS;
	chipAuthenticData.PADGHash = pcscReader.ChipAuthenticResult.PADGHash;
	rfidJson = pcscReader.rfid_json;
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