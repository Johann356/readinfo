#include"utils.h"
#include <chrono>
#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <iomanip>
using namespace std;


std::string StringToHex(const std::string& data)
{
	const std::string hex = "0123456789ABCDEF";
	std::stringstream ss;

	for (std::string::size_type i = 0; i < data.size(); ++i)
		ss << hex[(unsigned char)data[i] >> 4] << hex[(unsigned char)data[i] & 0xf];
	//std::cout << ss.str() << std::endl;
	return ss.str();
}

std::string StringToHex(const unsigned char* data)
{
	const std::string hex = "0123456789ABCDEF";
	std::stringstream ss;
	size_t len = 0;
	size_t idx = 0;
	while (data[idx++] != 0) {
		++len;
	}

	for (std::string::size_type i = 0; i < len; ++i)
		ss << hex[(unsigned char)data[i] >> 4] << hex[(unsigned char)data[i] & 0xf];
	//std::cout << ss.str() << std::endl;
	return ss.str();
}

std::string hexToBase64(const std::string& hexString) {

	std::string binaryString;
	for (size_t i = 0; i < hexString.length(); i += 2) {
		unsigned char byte = static_cast<unsigned char>(std::stoi(hexString.substr(i, 2), nullptr, 16));
		binaryString.push_back(byte);
	}

	BIO* memBio = BIO_new(BIO_s_mem());
	BIO* base64Bio = BIO_new(BIO_f_base64());
	BIO* bio = BIO_push(base64Bio, memBio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	BIO_write(bio, binaryString.c_str(), static_cast<int>(binaryString.length()));
	BIO_flush(bio);

	BUF_MEM* memBuf;
	BIO_get_mem_ptr(bio, &memBuf);

	std::string base64String(memBuf->data, memBuf->length);

	BIO_free_all(bio);

	return base64String;
}

std::string HexToString(const std::string& data)
{
	const std::string hex = "0123456789ABCDEF";
	map<char, int> map_hex_int{ {'0', 0}, {'1', 1}, {'2', 2} , {'3', 3} , {'4', 4} , {'5', 5} , {'6', 6} , {'7', 7} , {'8', 8} , {'9', 9} , {'A', 10} , {'B', 11} , {'C', 12} , {'D', 13} , {'E', 14} , {'F', 15} };
	std::stringstream ss;

	for (std::string::size_type i = 0; i < data.size(); ) {
		int num = map_hex_int[data[i]] * 16 + map_hex_int[data[i+1]];
		i+=2;
		ss << (char)num;

	}
	//std::cout << ss.str() << std::endl;
	return ss.str();
}

//    
std::string rsa_pub_decrypt(std::string& cipherText, const std::string& pubKey, int padding_mod)
{
	std::string strRet;
	RSA* rsa = RSA_new();
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char* decryptedText = (char*)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	//   
	int ret = RSA_public_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, padding_mod);//RSA_NO_PADDING
	unsigned long ulErr = ERR_get_error();
	char szErrMsg[1024] = { 0 };
	char* pTmp = NULL;

	pTmp = ERR_error_string(ulErr, szErrMsg);
	//cout << pTmp << endl;
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);
 
	free(decryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

std::string sha256(const std::string& input) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256Context;

	SHA256_Init(&sha256Context);
	SHA256_Update(&sha256Context, input.c_str(), input.length());
	SHA256_Final(hash, &sha256Context);

	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
	}

	return ss.str();
}

std::string hexString2String(std::string hexString) {
	std::string rawData;
	for (std::size_t i = 0; i < hexString.length(); i += 2) {
		std::string byteString = hexString.substr(i, 2);
		char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
		rawData.push_back(byte);
	}
	return rawData;
}

std::string ReadFileContentsAsHex(const std::string& filename) {
	std::ifstream file(filename, std::ios::binary);
	if (!file) {
		std::cerr << "Failed to open file: " << filename << std::endl;
		return "";
	}

	std::ostringstream buffer;
	buffer << std::hex << std::uppercase << std::setfill('0');

	char ch;
	while (file.get(ch)) {
		buffer << std::setw(2) << static_cast<unsigned>(static_cast<unsigned char>(ch));
	}

	file.close();

	return buffer.str();
}

std::vector<unsigned char> ReadFileContents(const std::string& filename) {
	std::ifstream file(filename, std::ios::binary);
	if (!file) {
		std::cerr << "Failed to open file: " << filename << std::endl;
		return {};
	}

	std::vector<unsigned char> fileContents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();

	return fileContents;
}

EVP_PKEY* ExtractPublicKeyFromCertificate(const std::vector<unsigned char>& certificateBytes) {
	BIO* certBio = BIO_new_mem_buf(certificateBytes.data(), static_cast<int>(certificateBytes.size()));
	if (certBio == nullptr) {
		std::cerr << "Failed to create BIO for certificate" << std::endl;
		return nullptr;
	}

	X509* certificate = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
	if (certificate == nullptr) {
		std::cerr << "Failed to parse certificate" << std::endl;
		BIO_free(certBio);
		return nullptr;
	}

	EVP_PKEY* publicKey = X509_get_pubkey(certificate);
	if (publicKey == nullptr) {
		std::cerr << "Failed to extract public key from certificate" << std::endl;
		X509_free(certificate);
		BIO_free(certBio);
		return nullptr;
	}

	X509_free(certificate);
	BIO_free(certBio);

	return publicKey;
}

bool compare_ignore_case(std::string& str1, std::string& str2) {
	if (str1.size() != str2.size()) {
		return false;
	}

	for (int i = 0; i < str1.size(); ++i) {
		if (str1[i] == str2[i]) {
			continue;
		}
		int diff = abs(str1[i] - str2[i]);
		if (diff != 32) {
			return false;
		}
	}

	return true;
}

//str hex representation
void string2bignum(std::string str, BIGNUM* num)
{
	BN_hex2bn(&num, str.c_str());
}
//str hex representation
void string2ecpoint(std::string str, EC_POINT* ec_point, EC_GROUP* ec)
{
	BN_CTX* ctx = BN_CTX_new();
	int len = str.length();
	std::string x_str = str.substr(0, len / 2);
	std::string y_str = str.substr(len / 2, len / 2);
	BIGNUM* x = BN_new();
	BN_hex2bn(&x, x_str.c_str());
	BIGNUM* y = BN_new();
	BN_hex2bn(&y, y_str.c_str());
	int ret = EC_POINT_set_affine_coordinates_GFp(ec, ec_point, x, y, ctx);
	if (!ret)
	{
		cout << "set coordinate fail" << endl;
	}
	BN_CTX* ctx1 = BN_CTX_new();
	BIGNUM* x1 = BN_new();
	BIGNUM* y1 = BN_new();
	EC_POINT_get_affine_coordinates_GFp(ec, ec_point, x1, y1, ctx1);
	char* x1_char = BN_bn2hex(x1);
	char* y1_char = BN_bn2hex(y1);
	if (x1_char && y1_char)
	{
		//cout << "ecpoint" << endl << x1_char << endl << y1_char << endl;
	}
	BN_CTX_free(ctx1);
}
void get_G_hat(EC_GROUP* ec, EC_POINT* H, std::string s_str, const EC_POINT* G, EC_POINT* G_hat)
{
	BIGNUM* s = BN_new();
	string2bignum(s_str, s);
	BN_CTX* ctx = BN_CTX_new();
	int ret = -1;
	EC_POINT* temp = EC_POINT_new(ec);
	ret = EC_POINT_mul(ec, temp, NULL, G, s, ctx);
	if (ret)
	{
		BN_CTX* ctx1 = BN_CTX_new();
		BIGNUM* x1 = BN_new();
		BIGNUM* y1 = BN_new();
		EC_POINT_get_affine_coordinates_GFp(ec, temp, x1, y1, ctx1);
		char* x1_char = BN_bn2hex(x1);
		char* y1_char = BN_bn2hex(y1);
		if (x1_char && y1_char)
		{
			cout << "G mult s" << endl << x1_char << endl << y1_char << endl;
		}
		BN_CTX_free(ctx1);
	}
	else
	{
		cout << "G mult s fail" << endl;
	}
	ret = EC_POINT_add(ec, G_hat, temp, H, ctx);
	if (ret)
	{
		BN_CTX* ctx1 = BN_CTX_new();
		BIGNUM* x1 = BN_new();
		BIGNUM* y1 = BN_new();
		EC_POINT_get_affine_coordinates_GFp(ec, G_hat, x1, y1, ctx1);
		char* x1_char = BN_bn2hex(x1);
		char* y1_char = BN_bn2hex(y1);
		if (x1_char && y1_char)
		{
			cout << "G_hat" << endl << x1_char << endl << y1_char << endl;
		}
		BN_CTX_free(ctx1);
	}
	else
	{
		cout << "G_hat fail" << endl;
	}
}
//g^s*H=g_hat
void get_G_hat(DH*& dh, BIGNUM*& H, std::string s_str, const BIGNUM*& G, BIGNUM*& G_hat)
{
	cout << "get_G_hat" << endl;
	BIGNUM* s = BN_new();
	string2bignum(s_str, s);
	BN_CTX* ctx = BN_CTX_new();
	const BIGNUM* prime = BN_new();
	prime = DH_get0_p(dh);
	BIGNUM* temp = BN_new();
	int ret = -1;
	ret = BN_mod_exp(temp, G, s, prime, ctx);
	ret = BN_mod_mul(G_hat,temp,H,prime,ctx);
	cout << "temp " << BN_bn2hex(temp) << endl;

	cout <<"G hat "<< BN_bn2hex(G_hat) << endl;
	BN_free(s);
	BN_free(temp);
	BN_CTX_free(ctx);
}
void get_shared_secret(EC_GROUP* ec, std::string private_key_ifd, std::string public_key_chip, EC_POINT*& shared_secret)
{
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* private_key = BN_new();
	string2bignum(private_key_ifd, private_key);
	EC_POINT* public_key = EC_POINT_new(ec);
	string2ecpoint(public_key_chip, public_key, ec);
	int ret = -1;
	EC_POINT* public_key1_ifd = EC_POINT_new(ec);
	ret = EC_POINT_mul(ec, shared_secret, NULL, public_key, private_key, ctx);
	if (ret)
	{
		BIGNUM* x1 = BN_new();
		BIGNUM* y1 = BN_new();
		EC_POINT_get_affine_coordinates_GFp(ec, shared_secret, x1, y1, ctx);
		char* x1_char = BN_bn2hex(x1);
		char* y1_char = BN_bn2hex(y1);
		if (x1_char && y1_char)
		{
			cout << "shared_secret = public_key1_chip * private_key1_ifd" << endl << x1_char << endl << y1_char << endl;
		}
	}
	else
	{
		cout << "shared_secret fail" << endl;
	}
	BN_CTX_free(ctx);
}
void get_shared_secret(DH*& dh, std::string private_key_ifd, std::string public_key_chip, BIGNUM*& shared_secret)
{
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* private_key = BN_new();
	string2bignum(private_key_ifd, private_key);
	BIGNUM* public_key = BN_new();
	string2bignum(public_key_chip, public_key);
	int ret = -1;
	const BIGNUM* prime= DH_get0_p(dh);
	cout << BN_bn2hex(prime) << endl;
	ret = BN_mod_exp(shared_secret, public_key, private_key, prime, ctx);
	BN_CTX_free(ctx);
	cout << "shared secret " << BN_bn2hex(shared_secret) << endl;
}

void printBytes(unsigned char* buf, size_t len) {
	for (int i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}
void string2binary(std::string str, unsigned char* arr, int arr_len)
{
	if (str.length() % 2 != 0)
	{
		cout << "string length must be multiplle of 2." << endl;
		return;
	}
	int len = str.length() / 2;
	if (len > arr_len)
	{
		cout << "array size not enough." << endl;
		return;
	}
	transform(str.begin(), str.end(), str.begin(), ::tolower);
	for (int i = 0; i < str.length(); i++)
	{
		if (!(str[i] >= '0' && str[i] <= '9' || str[i] >= 'a' && str[i] <= 'f'))
		{
			cout << "can only contain 0-9, a-f,A-F" << endl;
			return;
		}
	}
	for (int i = 0; i < len; i++)
	{
		unsigned char temp = 0;
		if (str[2 * i] >= '0' && str[2 * i] <= '9')
			temp += (str[2 * i] - '0') * 16;
		else if (str[2 * i] >= 'a' && str[2 * i] <= 'f')
			temp += (str[2 * i] - 'a' + 10) * 16;
		if (str[2 * i + 1] >= '0' && str[2 * i + 1] <= '9')
			temp += (str[2 * i + 1] - '0');
		else if (str[2 * i + 1] >= 'a' && str[2 * i + 1] <= 'f')
			temp += (str[2 * i + 1] - 'a' + 10);
		arr[i] = temp;
		cout << int(arr[i]);
	}
	cout << endl;
}
std::string lengthtoHex(int length)
{
	std::string res = "";
	if (length <= 127)
	{
		res.push_back((unsigned char)length);
	}
	else if (length >= 128 && length <= 255)
	{
		res.push_back('\x81');
		res.push_back((unsigned char)length);
	}
	else if (length >= 256 && length <= 65535)
	{
		res.push_back('\x82');
		res.push_back((unsigned char)(length / 256));
		res.push_back((unsigned char)(length % 256));
	}
	return res;
}

void computeTIFD(std::string& KSmac, std::string& PKDH_ICC, std::string& oid, int keyLength, std::string& cipherAlgorithm, std::string& TIFD, int ecc_id)
{
	// 输入：
	// KSmac:会话验证密钥 Binary
	// PKDH_ICC: 芯片公钥 96字节 -> NID_secp384r1 Binary
	// oid: 客体标识符 Binary
	// 输出: 
	// TIFD: 查验端认证令牌
	std::string message("\x7F\x49", 2);
	if (ecc_id > 2)
	{
		int length1 = PKDH_ICC.length() + 1;//04 PKDH_ICC
		int length2 = length1 + lengthtoHex(length1).length() + 1 + 12;//06 0A paceinfo 86 length 04 PKDH_ICC
		message.append(lengthtoHex(length2));
		message.append("\x06\x0A", 2);
		message.append(oid);
		message.append("\x86", 1);
		message.append(lengthtoHex(length1));
		message.append("\x04", 1);
		message.append(PKDH_ICC);
	}
	else
	{
		int length1 = PKDH_ICC.length();
		int length2 = PKDH_ICC.length() + 1 + lengthtoHex(PKDH_ICC.length()).length() + 12;
		message.append(lengthtoHex(length2));
		message.append("\x06\x0A", 2);
		message.append(oid);
		message.append('\x84', 1);
		message.append(lengthtoHex(length1));
		message.append(PKDH_ICC);
	}

	unsigned char mact[32] = { 0 };
	size_t mactlen;
	CMAC_CTX* ctx = CMAC_CTX_new();
	if (cipherAlgorithm == "AES")
	{
		const EVP_CIPHER* aes_algorithm;
		switch (keyLength)
		{
		case 256:
		{
			CMAC_Init(ctx, KSmac.c_str(), KSmac.size(), EVP_aes_256_cbc(), NULL);
			CMAC_Update(ctx, message.c_str(), message.size());
			CMAC_Final(ctx, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			TIFD = s.substr(0, 8);
			CMAC_CTX_free(ctx);
			break;
		}
		case 192:
		{
			CMAC_Init(ctx, KSmac.c_str(), KSmac.size(), EVP_aes_192_cbc(), NULL);
			CMAC_Update(ctx, message.c_str(), message.size());
			CMAC_Final(ctx, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			TIFD = s.substr(0, 8);
			CMAC_CTX_free(ctx);
			break;
		}
		case 128:
		{
			CMAC_Init(ctx, KSmac.c_str(), KSmac.size(), EVP_aes_128_cbc(), NULL);
			CMAC_Update(ctx, message.c_str(), message.size());
			CMAC_Final(ctx, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			TIFD = s.substr(0, 8);
			CMAC_CTX_free(ctx);
			break;
		}
		default:
			break;
		}
	}
	else if (cipherAlgorithm == "DESede")
	{	//按照[ISO/IEC 9797-1]中带有分组密码DES和IV=0的MAC algorithm 3/padding 2，以retail-mode使用3DES [FIPS 46 - 3]。
		//https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/macs/ISO9797Alg3Mac.java
		size_t dsize = message.size();
		dsize = ((dsize + 8) & (~(8 - 1)));
		if(message.size()<dsize)
			message.push_back('\x80');
		for (size_t i = message.size(); i < dsize; i++) {
			message.push_back(0x00);
		}
		
		std::string enKey, deKey;
		int iter = message.size() / 8;
		enKey.append(KSmac.data(), 8);
		deKey.append(KSmac.data() + 8, 8);
		std::string inBuffer(8, 0), outBuffer(8, 0);

		DES_cblock IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		DES_key_schedule enSchKey, deSchKey;

		DES_set_key_unchecked((const_DES_cblock*)enKey.data(), &enSchKey);
		DES_set_key_unchecked((const_DES_cblock*)deKey.data(), &deSchKey);

		for (int i = 0; i < iter; i++) {

			inBuffer.assign(message.data() + i * 8, 8);

			for (int j = 0; j < 8; j++) {
				inBuffer[j] ^= outBuffer[j];
			}

			DES_cbc_encrypt((unsigned char*)inBuffer.data(), (unsigned char*)outBuffer.data(),
				8, &enSchKey, &IV, DES_ENCRYPT);
		}

		TIFD.resize(8);

		DES_cbc_encrypt((unsigned char*)outBuffer.data(), (unsigned char*)inBuffer.data(), 8,
			&deSchKey, &IV, DES_DECRYPT);
		DES_cbc_encrypt((unsigned char*)inBuffer.data(), (unsigned char*)TIFD.data(), 8,
			&enSchKey, &IV, DES_ENCRYPT);
	}
}

int getNID(char idx) {
	switch (idx) {
	case '\x00':
		return 0;
	case '\x01':
		return 1;
	case '\x02':
		return 2;
	case '\x08':
		return NID_X9_62_prime192v1;
	case'\x09':
		return NID_brainpoolP192r1;
	case'\x0A':
		return NID_secp224r1;
	case'\x0B':
		return NID_brainpoolP224r1;
	case'\x0C':
		return 12;
	case'\x0D':
		return NID_brainpoolP256r1;
	case'\x0E':
		return NID_brainpoolP320r1;
	case'\x0F':
		return NID_secp384r1;
	case'\x10':
		return NID_brainpoolP384r1;
	case'\x11':
		return NID_brainpoolP512r1;
	case'\x12':
		return NID_secp521r1;
	default:
		return -1;
	}
}
std::string parseOID(std::string& oid_str) {
	string oid = "0.";
	int i = 0;
	char num;
	for (; i < oid_str.size() - 1; ++i) {
		num = oid_str[i];
		oid.append(std::to_string(num));
		oid.append(".");
	}
	num = oid_str[i];
	oid.append(std::to_string(num));
	return oid;
}
int hexStringToInt(std::string& str)
{
	int res = 0;
	int base = 1;
	for (int i = str.length() - 1; i >= 0; i--)
	{
		if (str[i] >= 'a' && str[i] <= 'f')
			res += base * (str[i] - 'a' + 10);
		else if (str[i] >= 'A' && str[i] <= 'F')
			res += base * (str[i] - 'A' + 10);
		else if (str[i] >= '0' && str[i] <= '9')
			res += base * (str[i] - '0');
		base *= 16;
	}
	return res;
}
int binaryStringToInt(std::string& str)
{
	int res = 0;
	int base = 1;
	for (int i = str.length() - 1; i >= 0; i--)
	{
		res += base * ((unsigned char)str[i]);
		base *= 256;
	}
	return res;
}

//无嵌套
std::string extractValueFromTLVBinaryString(std::string str,std::string& remainder)
{
	try
	{
		unsigned char tag = str[0];
		int Llength;
		int Vlength;
		std::string temp;
		if (((unsigned char)str[1] & (unsigned char)'\x80') != 0)
		{
			Llength = (unsigned char)str[1] & (unsigned char)'\x7f';
			Llength += 1;
			temp = str.substr(2, Llength - 1);
		}
		else
		{
			temp = str[1];
			Llength = 1;
		}
		Vlength = binaryStringToInt(temp);
		string res = str.substr(1 + Llength, Vlength);
		remainder = str.substr(1 + Llength + Vlength);
		return res;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return "";
	}
}
std::string extractValueFromTLVBinaryString(std::string str)
{
	try {
		unsigned char tag = str[0];
		int Llength;
		int Vlength;
		std::string temp;
		if (((unsigned char)str[1] & (unsigned char)'\x80') != 0)
		{
			Llength = (unsigned char)str[1] & (unsigned char)'\x7f';
			Llength += 1;
			temp = str.substr(2, Llength - 1);
		}
		else
		{
			temp = str[1];
			Llength = 1;
		}
		Vlength = binaryStringToInt(temp);
		string res = str.substr(1 + Llength, Vlength);
		return res;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return "";
	}
}
std::string extractValueFromTLVHexString(std::string str)
{
	try {
		std::string tag = str.substr(0, 2);
		int Llength, Vlength;
		std::string temp;
		if (str[2] < '8')
		{
			Llength = 2;
			temp = str.substr(2, 2);
			Vlength = hexStringToInt(temp) * 2;
		}
		else
		{
			temp = str.substr(2, 2);
			Llength = hexStringToInt(temp);
			Llength -= 128;
			Llength *= 2;
			Llength += 2;
			temp = str.substr(4, Llength - 2);
			Vlength = hexStringToInt(temp) * 2;
		}
		string res = str.substr(2 + Llength, Vlength);
		return res;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return "";
	}
}
std::string extractValueFromTLVHexString(std::string str, std::string& remainder)
{
	try {
		std::string tag = str.substr(0, 2);
		int Llength, Vlength;
		std::string temp;
		if (str[2] < '8')
		{
			Llength = 2;
			temp = str.substr(2, 2);
			Vlength = hexStringToInt(temp) * 2;
		}
		else
		{
			temp = str.substr(2, 2);
			Llength = hexStringToInt(temp);
			Llength -= 128;
			Llength *= 2;
			Llength += 2;
			temp = str.substr(4, Llength - 2);
			Vlength = hexStringToInt(temp) * 2;
		}
		string res = str.substr(2 + Llength, Vlength);
		remainder = str.substr(2 + Llength + Vlength);
		return res;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return "";
	}
}
void printHash(unsigned char* md, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
	{
		printf("%02x", md[i]);
	}

	printf("\n");
}
std::string sha224(const std::string& input)
{
	SHA256_CTX c;
	unsigned char md[SHA224_DIGEST_LENGTH];
	//SHA224((unsigned char*)input.c_str(), input.length(), md);
	//printHash(md, SHA224_DIGEST_LENGTH);

	SHA224_Init(&c);
	SHA224_Update(&c, input.c_str(),input.length());
	SHA224_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	printHash(md, SHA224_DIGEST_LENGTH);
	std::stringstream ss;
	for (int i = 0; i < SHA224_DIGEST_LENGTH; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
	}

	return ss.str();
}
std::string sha384(const std::string& input)
{
	SHA512_CTX c;
	unsigned char md[SHA384_DIGEST_LENGTH];
	//SHA384((unsigned char*)input.c_str(), input.length(), md);
	//printHash(md, SHA384_DIGEST_LENGTH);

	SHA384_Init(&c);
	SHA384_Update(&c, input.c_str(), input.length());
	SHA384_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	printHash(md, SHA384_DIGEST_LENGTH);
	std::stringstream ss;
	for (int i = 0; i < SHA384_DIGEST_LENGTH; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
	}

	return ss.str();
}
std::string sha512(const std::string& input)
{
	SHA512_CTX c;
	unsigned char md[SHA512_DIGEST_LENGTH];
	//SHA512((unsigned char*)input.c_str(), input.length(), md);
	//printHash(md, SHA512_DIGEST_LENGTH);

	SHA512_Init(&c);
	SHA512_Update(&c, input.c_str(), input.length());
	SHA512_Final(md, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	printHash(md, SHA512_DIGEST_LENGTH);
	std::stringstream ss;
	for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md[i]);
	}

	return ss.str();
}
bool fileExists(const std::string& fileName) {
	std::ifstream file(fileName);
	return file.is_open();
}