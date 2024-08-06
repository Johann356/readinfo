#include "WinError.h"
//#include "WinUser.h"
//#include "WINSCARD.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <iomanip>
#include <openssl/sha.h>
#include <map>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
//#include<atlstr.h>
#include "wlString.h"
#include "PCSCGetData.h"
#include <vector>
#include <chrono>
#include <string>
#include "utils.h"
#include "Ptypes.h"
#include <direct.h>
#include <regex>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <nlohmann/json.hpp>
#include <turbojpeg.h>
#include <openjpeg-2.2\openjpeg.h>
#include <Windows.h>
#include "CAInfo.h"
#include <chrono>
#include <thread>
#include "test.h"
#include <opencv2\opencv.hpp>
using namespace cv;
using namespace std;
using namespace std::chrono;
using json = nlohmann::json;
extern "C"
{
#include <openssl/applink.c>
};

int testRSA()
{
	std::string pk = "30820222300D06092A864886F70D01010105000382020F003082020A028202010088F01C22063767C95AD9598E8E164690C7D8401DDE1168EA9D01C092FAA1F833F4E3E855CA782D1638A1E8453FC153CE47937E6360B81F4E956285B279AF25D563814A1568729F2ABD3D1EF81037247BB3822051AF1691A249577BBAEDF2933CC023319C9C24DB41F487313AE02210239A5B5AEE52A0652567D552D2694B1105BB03495B5719D5439FA4AE1833897340D0BE5D24F95F1E2A3F6F6CE5D47051D877E2EB75777F03A9CC247FEF2D651E07901A5488DDAC3B47DB34809C3E4DF25E26E13A752D6FED31649E9A87EF6532FED7DC26F44174C8BF332B9F4F0EC668BEAC21272C570C7A58BA84E063219C6F973014595E7C31A4B07AE72B9D17E83DA696C27475600E2D18E40CE7B2F629C6DC1C678108F3C7808730113E75C1EB641592127BF1275825015AFB7BADCEEADFD2C416BED7041283FD447F38246A3A7F3B2A8771F792F78AD7A6C8AD249035BA9AA273C36E4D924B1323A1CBA85D0E8618FFC65901B031C988DEB77741F1B42A51B9909E71BE9A7E379C0FB0BFCFFFE1231C469D23D4E084E97C64F804DC1FE09BACA22DD6F076172768194FEA15DC38F7393DCF739B6EEC3BC0909E07C8237F7C7092EC875C9C8080CFA5213F429B807021E6354A2F4C395F492E535222D690B44A351C0FAE91921D19172CBE0E6558CC7F1BEA4F72FB5A18787A345A28FA6F850981FD59385CA38907183A279E5B545B0203010001";
	std::string message_hex = "3082038EA0030201020204545786CD300D06092A864886F70D01010B05003041310B3009060355040613024742310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479301E170D3135303930313030303030305A170D3237303130313030303030305A305C310B3009060355040613024742311B3019060355040A1312484D2050617373706F7274204F6666696365310F300D060355040B13064C6F6E646F6E311F301D06035504031316446F63756D656E74205369676E696E67204B6579203130820122300D06092A864886F70D01010105000382010F003082010A0282010100D2818FC995D2DA444AF5D89D5ED908D24210A9AA5C9DD436FBB3D762EB2FFC9AEE0F80C2C11B05117F0AE5DD5C0ADB2516B17EC24D306CE29341A0131C26F1D30D29CD2644B197D395FA86181EF6E0FE5C94FFA1A8D5C21E05BD773EB4C8A0D6FE2E3333A6C7F2BEEFD5EA2E3833D0A3DD15880D0EA15FC6C533C4ED87B3E88C0114FA0A2E4EDEBC9BB4342890A1FE2D50F52C6DB46D363729B822C884B034CD0317818CCC3DA74AEE6359DCE95F03B0B47696460EBCCB0D7C1E2D2006C642BEABE03CD5DB061372CE650F97CC035D69E85C68C26638EEC06B438CCE1709424F35873E000FC014C85B1B8A4BDAE986830C7D5257EAAD979A32B30E520765CA030203010001A38201893082018530400603551D11043930378123646F63756D656E742E746563686E6F6C6F677940686D706F2E6773692E676F762E756BA410300E310C300A06035504071303474252302B0603551D1004243022800F32303135303930313030303030305A810F32303135313230343030303030305A300E0603551D0F0101FF04040302078030400603551D1204393037A410300E310C300A060355040713034742528123646F63756D656E742E746563686E6F6C6F677940686D706F2E6773692E676F762E756B3019060767810801010602040E300C02010031071301501302505430670603551D1F0460305E305CA05AA058862A68747470733A2F2F706B64646F776E6C6F6164312E6963616F2E696E742F43524C732F4742522E63726C862A68747470733A2F2F706B64646F776E6C6F6164322E6963616F2E696E742F43524C732F4742522E63726C301F0603551D23041830168014DEC126A75D1CAD7C3420525E79EBBB0A9EB4B12D301D0603551D0E04160414C57D626D52266E62A938BE471860060CC5AF7BE4";
	std::string encrypted_message = "5A68559A0430E5AF5DDC9E21738932528C8767493D19DFEC4A71D9F4E422E83F7BA403841B84FDECE3B17E53B0C9C0DB9E6FB1F1B21FA5EDBDD80846A22EF5616E05043F7E0F819BAF1FD40809AFD118FB4274435548221D29CC70B85A8B768ED94ED344DF8CCE0DC19240F88DB7C79E3396BE3CBA4F34173D94D0F1E39D0511F4A63142DDE00B872010EBEC0D412D36EA526DC523A7A9CB0CC8698830EB8383D0E61CE7E77255EBC17E1521DF7CBE775183FBB97226489E3C5920A62C72B8E636EF40836E081D26FDACF642890DF25DF53DF276D456ADEF0E7603C4C934979C06D32F499BD15B6F6FCF3B39CFE8E413A0E62FCD7EDEAEE8597CFED88A51CBA83C321961EC776DD21C22FDE8D0CA668E482E311FC4E37C0AC1E66577118E8CE8D2584A103144F4FDA0C87D11D87E7AC92EC06F09B51BE06A9C2A26AB630A26CEEA95540268F620EC9DA19FFF75B02D59052F8DB1CFE4F16737E30C3F276E12381CF559ED08564378689E3FA23682DD0A81E6F16714A651B9F21D0536D4CFC4F3606FB8F637B65CC6BBF5CA6FB05FDB2A79E40671EDFF678A8BC90A4168815EFFE6658147AB1C5C3678667D079EE3C2B35921BF2201FB4EFF993D682EC736B7A1DD2BABE0E2C9CE71C16DCAB0E1EECD1ED5DE2400A27D3631754C8F862D1EFCA67BB3187857758DC2A43102D5D75FF869DDD915F9334266F57DF1B1FA151BD886";
	std::string base64str = hexToBase64(pk);
	std::string pubKey = "-----BEGIN PUBLIC KEY-----\n" + base64str + +"\n-----END PUBLIC KEY-----\n";
	RSA* rsa = RSA_new();
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	int len = RSA_size(rsa);
	encrypted_message = hexString2String(encrypted_message);
	std::string decStr = rsa_pub_decrypt(encrypted_message, pubKey, RSA_NO_PADDING);
	std::string dec_hex =  BinaryToHexString(decStr);
	std::string message = HexStringToBinary(message_hex);
	std::string hash(SHA256_DIGEST_LENGTH,0);
	SHA256((unsigned char*)message.c_str(),message.size(),(unsigned char*)hash.c_str());
	std::string hash_hex =  BinaryToHexString(hash) ;
	LOG(INFO)<< dec_hex << '\n' << hash_hex << endl;
	if (dec_hex.find(hash_hex) != dec_hex.npos)
		LOG(INFO)<< "found";
	else LOG(INFO)<< "not found";
	return 1;
}



std::string testaes_cbc_decode(std::string& key, std::string& data) {
	
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

void CheckParity11(
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

	CheckParity11(HD1, Kenc, 20);
	CheckParity11(HD2, Kmac, 20);

	auto HD1_hex = BinaryToHexString(Kenc);
	auto HD2_hex = BinaryToHexString(Kmac);

	return true;
}



int main1() {

	//int res = passive_auth();
	//change char_set to utf-8
	system("chcp 65001");

	
	
	//std::string mrz = "POCHNCAI<<MINGHAN<<<<<<<<<<<<<<<<<<<<<<<<<<<\nEC58444939CHN1512052M2303048LCMMMDPHLKLCA000";
	//string mrz = "POCHNYUAN<<PEIPEI<<<<<<<<<<<<<<<<<<<<<<<<<<<\nE561240497CHN9008168F2507204NEKMMFOFMFOFA920";
	//string mrz = "CSC531580954<2612199<9712087<2";
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
	//	LOG(INFO)<< "fail to open" << endl;
	//}
	//else
	//{
	//	infile.getline(no, 40);
	//	infile.getline(birthdate, 40);
	//	infile.getline(expiredate, 40);
	//}
	//char buff[100];
	//_getcwd(buff, 100);
	//LOG(INFO)<< buff << endl;
	//LOG(INFO)<< no << endl << birthdate <<endl<< expiredate << endl;
	//LOG(INFO)<< strlen(no) << ' ' << strlen(birthdate) << ' ' << strlen(expiredate) << endl;
	///*std::string no = "E56124049";
	//std::string birthdate = "900816";
	//std::string expiredate = "250720";*/
	//int ret = PCSCGetChip_given_three_parts_PACE(no, birthdate, expiredate, 2, chipAuthenticData, chip_data_9303);

	//string mrz = "  P<KGZASANOV<<USON<JANYBAEVICH<<<<<<<<<<<<<<<\nPE00000007KGZ9905094M30020272090519990000086";
	//std::string mrz = "POCHNCUI<<FUDONG<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nE574164050CHN9706176M2508119LENOLIKDLGKLA916";
	// 
	// 
	// string mrz = "POCHNLEI<<CHENGXIANG<<<<<<<<<<<<<<<<<<<<<<<<\nEJ35846483CHN9710212M3301122MANHLDMMMPOIA962";
	//string mrz = "POCHNLIN<<ZERONG<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nEG60278610CHN0012142M2906173MBNGNEPDMINJA050";
	string mrz = "P<TURORNEK<<ZEYNEP<<<<<<<<<<<<<<<<<<<<<<<<<<\nU200417972TUR9204029F280402812345678902<<<30";
	//std::string mrz = "P<SAUALHARBI<<JALAL<IBRAHIM<M<<<<<<<<<<<<<<<\nAE39833<<6SAU0406233M2801245<<<<<<<<<<<<<<02";
	//string mrz = "POCHNDU<<SHUANG<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nE167664651CHN9004229M2405182LGMFMLKM<<<<A922";
	//string mrz = "P<THATANTICHANCHAIKUN<<MINGKEEREE<<<<<<<<<<<\nS797771<<OTHA8607210M13081835102500012778<66";
	//string mrz = "CSCC63541450<3301122<9710212<6";
	//string mrz = "CSCA64615172<29003068<9109261<4";
	//int ret = PCSCGetChipBAC(mrz, 2, chipAuthenticData, chip_data_9303);
	/*char mrz[100];
	memset(mrz, 0, sizeof(mrz));
	std::string mrzstr;
	ifstream infile("PACE.txt", ios::in);
	if (!infile)
	{
		LOG(INFO)<< "fail to open" << endl;
	}
	else
	{
		infile.getline(mrz, 100);
		mrzstr += mrz;
		mrzstr += "\n";
		infile.getline(mrz, 100);
		mrzstr += mrz;
	}*/
	/*std::string no = "E56124049";
	std::string birthdate = "900816";
	std::string expiredate = "250720";*/
	int ret = -1;
	std::string mrzstr = mrz;
	std::string rfid;
	//ret = PCSCGetChipPACE(mrzstr, 2, chipAuthenticData, chip_data_9303,rfid,false);
	steady_clock::time_point start = steady_clock::now();
	//ret = PCSCGetChipPACE(mrzstr, 2, chipAuthenticData, chip_data_9303,rfid,false);
	//ret = PCSCGetChipBAC(mrzstr, 2, chipAuthenticData, chip_data_9303, rfid);
	PCSC_GetIDCard();
	steady_clock::time_point last = steady_clock::now();
	auto dt = last - start;
	auto duration_seconds = std::chrono::duration_cast<std::chrono::seconds>(dt);
	std::chrono::duration<double> duration_double = dt;
	LOG(INFO)<< "read chip cost: " << duration_double.count() << " seconds" << std::endl;
	LOG(INFO)<< "DG1.size: " << chip_data_9303.iDG1 << " DG2.size: " << chip_data_9303.iDG2 << " DG11.size: " << chip_data_9303.iDG11 << endl;
	//int ret = passive_auth();
	system("pause");
	return 0;
}
int main()
{
	LogOpen();
	testECDHIM();
	return 0;
}