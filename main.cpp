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
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
//#include<atlstr.h>
#include"wlString.h"
#include"PCSCGetData.h"
#include<vector>
#include <chrono>
#include<string>
#include"utils.h"
#include"Ptypes.h"
#include<direct.h>
using namespace std;
using namespace std::chrono;
extern "C"
{
#include <openssl/applink.c>
};


int passive_auth() {
	string path1 = "C:\\Users\\leicx\\Desktop\\lcx\\pic\\GBR\\211118\\EF_SOD.dat";
	string hex = ReadFileContentsAsHex(path1);
	if (hex.size() < 1000) {
		return false;
	}
	std::string key_tag = "30820122";
	int key_begin = hex.find(key_tag);
	if (key_begin < 100) {
		return false;
	}
	std::string hex_key = hex.substr(key_begin, 588);
	std::string base64str = hexToBase64(hex_key);
	std::string pubKey1 = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";

	std::string encryptedData_tag = "04820100";
	int encryptedData_begin = hex.find(encryptedData_tag);
	if (encryptedData_begin < 100) {
		return false;
	}

	std::string encryptedData = hex.substr(encryptedData_begin + 8, 512);
	encryptedData = hexString2String(encryptedData);
	std::string decStr = rsa_pub_decrypt(encryptedData, pubKey1,RSA_PKCS1_PADDING);
	std::string hexDecStr = StringToHex(decStr);
	if (hexDecStr.size() < 64) {
		return false;
	}
	std::string signature_dec = hexDecStr.substr(hexDecStr.size() - 64, 64);
	//取出 signedAttrs 
	std::string messageDigest_tag = "A048";
	int messageDigest_begin = hex.find(messageDigest_tag);
	if (messageDigest_begin < 100) {
		return false;
	}
	std::string messageDigest = hex.substr(messageDigest_begin, 148);

	//复原成完整的der格式
	messageDigest[0] = '3';
	messageDigest[1] = '1';
	//计算签名
	std::string signature = sha256(hexString2String(messageDigest));
	return (compare_ignore_case(signature, signature_dec));
}


std::string aes_cbc_decode(std::string& key, std::string& data) {
	
	unsigned char iv[AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	AES_KEY aes_key;
	if (AES_set_decrypt_key((const unsigned char*)key.c_str(), key.length() * 8, &aes_key) < 0)
	{
		return "";
	}
	std::string strRet;
	unsigned char out[AES_BLOCK_SIZE];
	unsigned char* inData = ( unsigned char*)data.data();
	AES_cbc_encrypt(inData, out, AES_BLOCK_SIZE, &aes_key, iv, AES_DECRYPT);
	strRet = std::string((const char*)out, AES_BLOCK_SIZE);
	return strRet;
}

void CheckParity1(
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

char BuildKencAndKmac(const std::string& mrzInfo,
	std::string& Kenc,
	std::string& Kmac) {

	std::string Kseed(20, 0);
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

	CheckParity1(HD1, Kenc, 20);
	CheckParity1(HD2, Kmac, 20);

	auto HD1_hex = BinaryToHexString(Kenc);
	auto HD2_hex = BinaryToHexString(Kmac);

	return true;
}



int main() {

	//int res = passive_auth();
	//change char_set to utf-8
	system("chcp 65001");

	
	steady_clock::time_point start = steady_clock::now();
	//std::string mrz = "POCHNCAI<<MINGHAN<<<<<<<<<<<<<<<<<<<<<<<<<<<\nEC58444939CHN1512052M2303048LCMMMDPHLKLCA000";
	//string mrz = "POCHNYUAN<<PEIPEI<<<<<<<<<<<<<<<<<<<<<<<<<<<\nE561240497CHN9008168F2507204NEKMMFOFMFOFA920";
	//string mrz = "POCHNLEI<<CHENGXIANG<<<<<<<<<<<<<<<<<<<<<<<<\nEJ35846483CHN9710212M3301122MANHLDMMMPOIA962";
	//string mrz = "POCHNLIN<<ZERONG<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nEG60278610CHN0012142M2906173MBNGNEPDMINJA050";
	//std::string mrz = "P<SAUALHARBI<<JALAL<IBRAHIM<M<<<<<<<<<<<<<<<\nAE39833<<6SAU0406233M2801245<<<<<<<<<<<<<<02";
	//string mrz = "POCHNDU<<SHUANG<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nE167664651CHN9004229M2405182LGMFMLKM<<<<A922";
	//string mrz = "P<THATANTICHANCHAIKUN<<MINGKEEREE<<<<<<<<<<<\nS797771<<OTHA8607210M13081835102500012778<66";
	//string mrz = "CSCC63541450<3301122<9710212<6";
	//string mrz = "CSCA64615172<29003068<9109261<4";
	ChipAuthenticData chipAuthenticData{};
	ChipData_Doc9303 chip_data_9303{};
	//int ret = PCSCGetChipBAC(mrz, 2, chipAuthenticData, chip_data_9303);
	//char no[40];
	//char birthdate[40];
	//char expiredate[40];
	//memset(no, 0, sizeof(no));
	//memset(birthdate, 0, sizeof(no));
	//memset(expiredate, 0, sizeof(no));
	//ifstream infile("PACE.txt", ios::in);
	//if (!infile)
	//{
	//	cout << "fail to open" << endl;
	//}
	//else
	//{
	//	infile.getline(no, 40);
	//	infile.getline(birthdate, 40);
	//	infile.getline(expiredate, 40);
	//}
	//char buff[100];
	//_getcwd(buff, 100);
	//cout << buff << endl;
	//cout << no << endl << birthdate <<endl<< expiredate << endl;
	//cout << strlen(no) << ' ' << strlen(birthdate) << ' ' << strlen(expiredate) << endl;
	///*std::string no = "E56124049";
	//std::string birthdate = "900816";
	//std::string expiredate = "250720";*/
	//int ret = PCSCGetChip_given_three_parts_PACE(no, birthdate, expiredate, 2, chipAuthenticData, chip_data_9303);

	//string mrz = "  P<KGZASANOV<<USON<JANYBAEVICH<<<<<<<<<<<<<<<\nPE00000007KGZ9905094M30020272090519990000086";
	//
	// 
	// 
	// string mrz = "POCHNLEI<<CHENGXIANG<<<<<<<<<<<<<<<<<<<<<<<<\nEJ35846483CHN9710212M3301122MANHLDMMMPOIA962";
	//string mrz = "POCHNLIN<<ZERONG<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nEG60278610CHN0012142M2906173MBNGNEPDMINJA050";
	//std::string mrz = "P<SAUALHARBI<<JALAL<IBRAHIM<M<<<<<<<<<<<<<<<\nAE39833<<6SAU0406233M2801245<<<<<<<<<<<<<<02";
	//string mrz = "POCHNDU<<SHUANG<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nE167664651CHN9004229M2405182LGMFMLKM<<<<A922";
	//string mrz = "P<THATANTICHANCHAIKUN<<MINGKEEREE<<<<<<<<<<<\nS797771<<OTHA8607210M13081835102500012778<66";
	//string mrz = "CSCC63541450<3301122<9710212<6";
	//string mrz = "CSCA64615172<29003068<9109261<4";
	//int ret = PCSCGetChipBAC(mrz, 2, chipAuthenticData, chip_data_9303);
	char mrz[100];
	memset(mrz, 0, sizeof(mrz));
	std::string mrzstr;
	ifstream infile("PACE.txt", ios::in);
	if (!infile)
	{
		cout << "fail to open" << endl;
	}
	else
	{
		infile.getline(mrz, 100);
		mrzstr += mrz;
		mrzstr += "\n";
		infile.getline(mrz, 100);
		mrzstr += mrz;
	}
	/*std::string no = "E56124049";
	std::string birthdate = "900816";
	std::string expiredate = "250720";*/
	int ret = -1;
	//ret = PCSCGetChipPACE(mrzstr, 2, chipAuthenticData, chip_data_9303);
	ret = PCSCGetChipBAC(mrzstr, 2, chipAuthenticData, chip_data_9303);
	//PCSC_GetIDCard();
	steady_clock::time_point last = steady_clock::now();
	auto dt = last - start;
	cout << "read chip cost: " << dt.count() << "nano seconds" << endl;
	cout << "DG1.size: " << chip_data_9303.iDG1 << " DG2.size: " << chip_data_9303.iDG2 << " DG11.size: " << chip_data_9303.iDG11 << endl;
	//int ret = passive_auth();
	return 0;
}





//#include <openssl/rsa.h>
//#include <openssl/pem.h>
//#include <openssl/evp.h>
//#include <openssl/err.h>
//int main()
//{
//
//	std::string base64str = hexToBase64("30820122300D06092A864886F70D01010105000382010F003082010A0282010100F0ABD4F470CF4EDDEC9E655215297A102A53671FE0D9D3E9A6F10261059FEF4195DF2EA7463BDF3C8110E9224633FF6F8B820083C549D50A3B9FF4F69E0E0CA707EDC8FB4F081985C491CF5CFB91068534FBAA04C7E796020A4CB73982BE4498439CADF903FC04421480E095D2805F3C94AE2A16885590FBF99DE0F9673804CF3DD6CA9795B22DB2B5D6C75BDF0C40C7471F06A8272C02193D99344CB60652DE5D5931FAAE6CCE0E7A3FF7B2E2C0568AD8D9A536B8FD6A07A9936023C43632F51CAB4661B41B0AC1EAF3FD4C83A5D5BEC00B372E27EFB88ECB8EAF71F099285842FE6FE73529CF68E9388766335D156DADA8D57222B4AD56912BB8C2ECBBF8E10203010001");
//	std::string pubKey = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";
//
//	std::string enc = hexString2String("65A4313A39A83399C1914ACA2F8993567D410558C2D0B41BDE9421372CB4D526D673BDF945A953AF28800BEFC78131ED3CEDEDE9C9159D5C209992F89B6EC41CB4BE772BE64EEDC672FAC2C9F46685CB36635A86A3DF5E63E2C72B7F5E30E32BF4ACCB421EC858BD67139C3BDAB91121F5F93F7CA3184F7AD1047997E4591D78E12BF9D1382E5C44CB495C069484B77349E28850F246BF1FBE9884F9349C4385A72BDDC2ACE37BD3088C82C8806CF3B82BA2F48C4C830452CA053D9CA5080DA4281943DC674B705A07E421A6C65C67DA612E84CB69C59BF424FF87717496ED8D69CD9BF77DE96B385EF41ADC65B3803ECD5C4DAF38C671A21D9C5D62E3AFE1A6");
//	size_t enc_len = enc.length();
//	std::string message = HexStringToBinary("3148301506092A864886F70D01090331080606678108010101302F06092A864886F70D010904312204201E18160A1A12F7AAD73B6EC6C8A7AEA65FDE36ABDA2AA5CAAFEE164F7B06498F");
//	size_t message_len = message.length();
//	std::string strRet;
//	RSA* rsa = RSA_new();
//	BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
//	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
//
//	int len = RSA_size(rsa);
//	char* decryptedText = (char*)malloc(len + 1);
//	memset(decryptedText, 0, len + 1);
//	int ret = RSA_public_decrypt(enc_len, (unsigned char*)enc.c_str(), (unsigned char*)decryptedText, rsa, RSA_NO_PADDING);
//	std::string res(decryptedText, ret);
//	std::string res_hex = BinaryToHexString(res);
//	std::string message_hash(32, 0);
//	SHA256((unsigned char*)message.c_str(),message_len,(unsigned char *)message_hash.data());
//
//	ret = RSA_verify_PKCS1_PSS_mgf1(rsa, (unsigned char*)message_hash.c_str(), EVP_sha256(), EVP_sha256(), (unsigned char*)res.c_str(), 32);
//}