#include "WinError.h"
//#include "WinUser.h"
//#include "WINSCARD.h"
#include<iostream>
#include <fstream>
#include <sstream>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <iomanip>
#include <openssl/sha.h>
#include<map>
//#include<atlstr.h>
#include"wlString.h"
#include"PCSCGetData.h"
#include<vector>
#include <chrono>
#include<string>
#include"utils.h"
using namespace std;
using namespace std::chrono;
extern "C"
{
#include <openssl/applink.c>
};




int passive_auth() {
	string path1 = "C:\\Users\\leicx\\Desktop\\读卡\\EF_SOD.bin";
	string hex = ReadFileContentsAsHex(path1);
	if (hex.size() < 4244) {
		cout << "sod is too short" << endl;
		return -2;
	}

	string hex_key = hex.substr(1372, 588);
	string base64str = hexToBase64(hex_key);
	string pubKey1 = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";

	string encryptedData = hex.substr(hex.size() - 512 , 512);
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


int main() {

	//int res = passive_auth();
	//change char_set to utf-8
	system("chcp 65001");
	steady_clock::time_point start = steady_clock::now();
	//string mrz = "POCHNYUAN<<PEIPEI<<<<<<<<<<<<<<<<<<<<<<<<<<<\nE561240497CHN9008168F2507204NEKMMFOFMFOFA920";
	string mrz = "POCHNLEI<<CHENGXIANG<<<<<<<<<<<<<<<<<<<<<<<<\nEJ35846483CHN9710212M3301122MANHLDMMMPOIA962";
	//string mrz = "P<THATANTICHANCHAIKUN<<MINGKEEREE<<<<<<<<<<<\nS797771<<OTHA8607210M13081835102500012778<66";
	//string mrz = "POCHNDU<<SHUANG<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nE167664651CHN9004229M2405182LGMFMLKM<<<<A922";
	//string mrz = "POCHNLEI<<CHENGXIANG<<<<<<<<<<<<<<<<<<<<<<<<\nEJ35846483CHN9710212M3301122MANHLDMMMPOIA962";
	//string mrz = "CSCC63541450<3301122<9710212<6";
	//string mrz = "CSCA64615172<29003068<9109261<4";
	ChipAuthenticData chipAuthenticData{};
	ChipData_Doc9303 chip_data_9303{};
	int ret = PCSCGetChip(mrz, 2, chipAuthenticData, chip_data_9303);
	//PCSC_GetIDCard();
	steady_clock::time_point last = steady_clock::now();
	auto dt = last - start;
	cout << "read chip cost: " << dt.count() << "nano seconds" << endl;
	cout << "DG1.size: " << chip_data_9303.iDG1 << " DG2.size: " << chip_data_9303.iDG2 << " DG11.size: " << chip_data_9303.iDG11 << endl;
	system("PAUSE");
	return 0;
}