#include"utils.h"
#include "Ptypes.h"
#include <chrono>
#include <string>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include <iomanip>
#include <regex>
#include "dirent.h"
#include "glog\logging.h"
using namespace std;

//enum HashAlgorithm
//{
//	SHA_1 = 0, SHA_224, SHA_256, SHA_384, SHA_512
//	/*
//	SHA1	06 05 2B 0E 03 02 1A				1.3.14.3.2.26 
//	SHA256	06 09 60 86 48 01 65 03 04 02 01	2.16.840.1.101.3.4.2.1
//	SHA384	06 09 60 86 48 01 65 03 04 02 02	2.16.840.1.101.3.4.2.2
//	SHA512	06 09 60 86 48 01 65 03 04 02 03	2.16.840.1.101.3.4.2.3
//	SHA224	06 09 60 86 48 01 65 03 04 02 04	2.16.840.1.101.3.4.2.4
//	*/
//};
//enum SignatureAlgorithm
//{
//	RSA_ = 0,RSAPSS,ECDSAwithSHA1, ECDSAwithSHA224, ECDSAwithSHA256, ECDSAwithSHA384, ECDSAwithSHA512
//	/*
//	RSA     06092A864886F70D010101 rsaEncryption (PKCS #1) 1.2.840.113549.1.1.1
//	RSAPSS  06092A864886F70D01010A rsaPSS (PKCS #1) 1.2.840.113549.1.1.10 
//	ECDSAwithSHA1			06072A8648CE3D0401		1.2.840.10045.4.1		
//	ECDSAwithSHA224			06082A8648CE3D040301	1.2.840.10045.4.3.1
//	ECDSAwithSHA256			06082A8648CE3D040302	1.2.840.10045.4.3.2
//	ECDSAwithSHA384			06082A8648CE3D040303	1.2.840.10045.4.3.3
//	ECDSAwithSHA512			06082A8648CE3D040304	1.2.840.10045.4.3.4
//	*/
//
//	/*
//	sha1-with-rsa-signature 06092A864886F70D010105 1.2.840.113549.1.1.5	
//	sha256WithRSAEncryption 06092A864886F70D01010B 1.2.840.113549.1.1.11	
//	sha384WithRSAEncryption 06092A864886F70D01010C 1.2.840.113549.1.1.12	
//	sha512WithRSAEncryption 06092A864886F70D01010D 1.2.840.113549.1.1.13	
//	sha224WithRSAEncryption 06092A864886F70D01010E 1.2.840.113549.1.1.14	
//	*/
//	
//
//};
std::string StringToHex(const std::string& data)
{
	const std::string hex = "0123456789ABCDEF";
	std::stringstream ss;

	for (std::string::size_type i = 0; i < data.size(); ++i)
		ss << hex[(unsigned char)data[i] >> 4] << hex[(unsigned char)data[i] & 0xf];
	//LOG(INFO)<< ss.str() << std::endl;
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
	//LOG(INFO)<< ss.str() << std::endl;
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
std::string base64ToHex(const std::string& base64String)
{
	BIO* bio, * b64;
	int padding = 0;
	if (base64String[base64String.size() - 1] == '=' && base64String[base64String.size() - 2] == '=')
		padding = 2;
	else if (base64String[base64String.size() - 1] == '=')
		padding = 1;
	int decodeLength = (base64String.size() * 3) / 4 - padding;

	std::vector<unsigned char> binary(decodeLength);

	bio = BIO_new_mem_buf(base64String.data(), -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	int length = BIO_read(bio, &binary[0], base64String.length());
	(void)BIO_flush(bio);
	BIO_free_all(bio);

	binary.resize(length);

	std::stringstream hexStream;
	hexStream << std::hex << std::setfill('0');
	for (unsigned char c : binary)
		hexStream << std::setw(2) << static_cast<int>(c);

	return hexStream.str();
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
	//LOG(INFO)<< ss.str() << std::endl;
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
	//LOG(INFO)<< pTmp << endl;
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
void aes_cbc_decode(const std::string& key, std::string& inputdata, std::string& dec, std::string& iv_str, int keyLength) {

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
	return;
}
void aes_cbc_encode(const std::string& key, std::string& inputdata, std::string& enc, std::string& iv_str, int keyLength) {

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
	if (AES_set_encrypt_key((const unsigned char*)key_used.c_str(), key_used.length() * 8, &aes_key) < 0)
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
		AES_cbc_encrypt((const unsigned char*)str16.c_str(), out, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
		strRet += std::string((const char*)out, AES_BLOCK_SIZE);
	}
	enc = strRet;
	return;
}
std::string int2Hex(int val) {
	std::stringstream ss;
	// 整数转换为大写的十六进制字符串，且每个字节占用两个字符的宽度
	ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << val;
	return ss.str();
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
void string2bignum(std::string& str, BIGNUM*& num)
{
	BN_hex2bn(&num, str.c_str());
}
//str hex representation
void string2ecpoint(std::string str, EC_POINT*& ec_point, EC_GROUP* ec)
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
		LOG(ERROR)<< "set coordinate fail" << endl;
	}
	BN_CTX* ctx1 = BN_CTX_new();
	BIGNUM* x1 = BN_new();
	BIGNUM* y1 = BN_new();
	EC_POINT_get_affine_coordinates_GFp(ec, ec_point, x1, y1, ctx1);
	char* x1_char = BN_bn2hex(x1);
	char* y1_char = BN_bn2hex(y1);
	if (x1_char && y1_char)
	{
		//LOG(INFO)<< "ecpoint" << endl << x1_char << endl << y1_char << endl;
	}
	BN_CTX_free(ctx1);
}
void get_G_hat(EC_GROUP*& ec, EC_POINT*& H, std::string& s_str, const EC_POINT*& G, EC_POINT*& G_hat)
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
			LOG(INFO)<< "G mult s" << endl << x1_char <<", " << y1_char << endl;
		}
		BN_CTX_free(ctx1);
	}
	else
	{
		LOG(ERROR)<< "G mult s fail" << endl;
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
			LOG(INFO)<< "G_hat" << endl << x1_char <<", " << y1_char << endl;
		}
		BN_CTX_free(ctx1);
	}
	else
	{
		LOG(ERROR)<< "G_hat fail" << endl;
	}
}
//g^s*H=g_hat
void get_G_hat(DH*& dh, BIGNUM*& H, std::string& s_str, const BIGNUM*& G, BIGNUM*& G_hat)
{
	LOG(INFO)<< "get_G_hat" << endl;
	BIGNUM* s = BN_new();
	string2bignum(s_str, s);
	BN_CTX* ctx = BN_CTX_new();
	const BIGNUM* prime = BN_new();
	prime = DH_get0_p(dh);
	BIGNUM* temp = BN_new();
	int ret = -1;
	ret = BN_mod_exp(temp, G, s, prime, ctx);
	ret = BN_mod_mul(G_hat,temp,H,prime,ctx);
	LOG(INFO)<< "G^s " << BN_bn2hex(temp);

	LOG(INFO)<<"G hat "<< BN_bn2hex(G_hat);
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
			LOG(INFO)<< "shared_secret = public_key1_chip * private_key1_ifd" << endl << x1_char <<", " << y1_char << endl;
		}
	}
	else
	{
		LOG(INFO)<< "shared_secret fail" << endl;
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
	LOG(INFO)<< BN_bn2hex(prime) << endl;
	ret = BN_mod_exp(shared_secret, public_key, private_key, prime, ctx);
	BN_CTX_free(ctx);
	LOG(INFO)<< "shared secret " << BN_bn2hex(shared_secret) << endl;
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
		LOG(INFO)<< "string length must be multiplle of 2." << endl;
		return;
	}
	int len = str.length() / 2;
	if (len > arr_len)
	{
		LOG(INFO)<< "array size not enough." << endl;
		return;
	}
	transform(str.begin(), str.end(), str.begin(), ::tolower);
	for (int i = 0; i < str.length(); i++)
	{
		if (!(str[i] >= '0' && str[i] <= '9' || str[i] >= 'a' && str[i] <= 'f'))
		{
			LOG(INFO)<< "can only contain 0-9, a-f,A-F" << endl;
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
		LOG(INFO)<< int(arr[i]);
	}
	LOG(INFO)<< endl;
}
std::string lengthtoBinary(int length)
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
std::wstring s2ws(const std::string& str) {

	setlocale(LC_ALL, "chs");
	const char* point_to_source = str.c_str();
	size_t new_size = str.size() + 1;
	wchar_t* point_to_destination = new wchar_t[new_size];
	wmemset(point_to_destination, 0, new_size);
	mbstowcs(point_to_destination, point_to_source, new_size);
	std::wstring result = point_to_destination;
	delete[]point_to_destination;
	setlocale(LC_ALL, "C");
	return result;
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
		int length2 = length1 + lengthtoBinary(length1).length() + 1 + 12;//06 0A paceinfo 86 length 04 PKDH_ICC
		message.append(lengthtoBinary(length2));
		message.append("\x06\x0A", 2);
		message.append(oid);
		message.append("\x86", 1);
		message.append(lengthtoBinary(length1));
		message.append("\x04", 1);
		message.append(PKDH_ICC);
	}
	else
	{
		int length1 = PKDH_ICC.length();
		int length2 = PKDH_ICC.length() + 1 + lengthtoBinary(PKDH_ICC.length()).length() + 12;
		message.append(lengthtoBinary(length2));
		message.append("\x06\x0A", 2);
		message.append(oid);
		message.append('\x84', 1);
		message.append(lengthtoBinary(length1));
		message.append(PKDH_ICC);
	}
	LOG(INFO) << "TIC/TIFD message " << BinaryToHexString(message);
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
	LOG(INFO) << "TIC/TIFD "<<BinaryToHexString(TIFD);
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
int EccOidToNid(std::string& ecc_oid)
{
	if (ecc_oid == "06082a8648ce3d030101")
		return NID_X9_62_prime192v1;
	else if (ecc_oid == "06092b2403030208010103")
		return NID_brainpoolP192r1;
	else if (ecc_oid == "06052b81040021")
		return NID_secp224r1;
	else if (ecc_oid == "06092b2403030208010105")
		return NID_brainpoolP224r1;
	else if (ecc_oid == "06082a8648ce3d030107")
		return 12;
	else if (ecc_oid == "06092b2403030208010107")
		return NID_brainpoolP256r1;
	else if (ecc_oid == "06092b2403030208010109")
		return NID_brainpoolP320r1;
	else if (ecc_oid == "06052b81040022")
		return NID_secp384r1;
	else if (ecc_oid == "06092b240303020801010b")
		return NID_brainpoolP384r1;
	else if (ecc_oid == "06092b240303020801010d")
		return NID_brainpoolP512r1;
	else if (ecc_oid == "06052b81040023")
		return NID_secp521r1;
	return -1;

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
		std::string res;
		if (tag == '\x03' && str[1 + Llength] == 0)
		{
			Vlength = binaryStringToInt(temp) - 1;
			res = str.substr(1 + Llength + 1, Vlength);
			remainder = str.substr(1 + Llength + 1 + Vlength);
		}
		else
		{
			Vlength = binaryStringToInt(temp);
			res = str.substr(1 + Llength, Vlength);
			remainder = str.substr(1 + Llength + Vlength);
		}
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
		std::string res;
		if (tag == '\x03' && str[1 + Llength] == 0)
		{
			Vlength = binaryStringToInt(temp) - 1;
			res = str.substr(1 + Llength + 1, Vlength);
		}
		else
		{
			Vlength = binaryStringToInt(temp);
			res = str.substr(1 + Llength, Vlength);

		}
		return res;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return "";
	}
}
/*
结构：
sequence
	sequence
		oid
		sequence
			q
			g
			阶数
	bitstring
		integer
*/
bool extractPQGPKfromCAKeyInfo(std::string& keyinfo, std::string& p, std::string& q, std::string& g, DH*& dh)
{
	std::string temp, remainder;
	temp = extractValueFromTLVHexString(keyinfo);
	temp = extractValueFromTLVHexString(temp, remainder);
	remainder = extractValueFromTLVHexString(remainder);
	remainder = extractValueFromTLVHexString(remainder);
	while (remainder[0] == '0')
		remainder = remainder.substr(1);//去掉高位0
	extractValueFromTLVHexString(temp, temp);

	temp = extractValueFromTLVHexString(temp);
	p = extractValueFromTLVHexString(temp, temp);
	g = extractValueFromTLVHexString(temp, q);
	q = extractValueFromTLVHexString(q);
	BIGNUM* bn_p = BN_new();
	BIGNUM* bn_g = BN_new();
	BIGNUM* bn_q = BN_new();
	int ret = BN_hex2bn(&bn_p, p.c_str());
	ret = BN_hex2bn(&bn_g, g.c_str());
	ret = BN_hex2bn(&bn_q, q.c_str());
	dh = DH_new();
	if (!dh) {
		LOG(ERROR) << "Failed to create DH structure\n";
		return false;
	}

	// 设置DH参数
	if (!DH_set0_pqg(dh, bn_p, nullptr, bn_g)) {
		LOG(ERROR) << "Failed to set DH parameters\n";
		return false;
	}

	// 生成DH密钥对
	if (!DH_generate_key(dh)) {
		LOG(ERROR) << "Failed to generate DH key pair\n";
		return false;
	}

	//// 获取生成的公钥和私钥
	//const BIGNUM* pub_key = nullptr;
	//const BIGNUM* priv_key = nullptr;
	//DH_get0_key(dh, &pub_key, &priv_key);
	//
	//if (pub_key && priv_key) {
	//	char* pub_key_hex = BN_bn2hex(pub_key);
	//	char* priv_key_hex = BN_bn2hex(priv_key);
	//
	//	LOG(INFO)<< "Public Key: " << pub_key_hex << "\n";
	//	LOG(INFO)<< "Private Key: " << priv_key_hex << "\n";
	//
	//	OPENSSL_free(pub_key_hex);
	//	OPENSSL_free(priv_key_hex);
	//}
	//else {
	//	std::cerr << "Failed to get DH key pair\n";
	//}
	//
	return true;
}
int ExtractECpkfromDG15(std::string dg15, EC_KEY*& ec_key)
{
	std::string ecpk = "";
	std::string dg15_tolower = "";
	ec_key = EC_KEY_new();
	for (auto ch : dg15)
		if (ch >= 'A' && ch <= 'F')
			dg15_tolower.push_back(ch - ('A' - 'a'));
		else
			dg15_tolower.push_back(ch);
	if (dg15_tolower.find("06072a8648ce3d0201") == dg15_tolower.npos)
		return 0;
	else
	{
		if (dg15_tolower.find("06072a8648ce3d0101") == dg15_tolower.npos)
			ecpk = extractValueFromTLVHexString(dg15_tolower);
		else
		{
			std::string temp = extractValueFromTLVHexString(dg15_tolower);
			temp = extractValueFromTLVHexString(temp);
			std::string bitstring;
			temp = extractValueFromTLVHexString(temp, bitstring);
			std::string oid = "";
			if (dg15_tolower.find("fffffffffffffffffffffffffffffffefffffffffffffffc") != dg15_tolower.npos)
				oid = "06082a8648ce3d030101";//1.2.840.10045.3.1.1 prime192v1 (ANSI X9.62 named elliptic curve)
			else if (dg15_tolower.find("6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef") != dg15_tolower.npos)
				oid = "06092b2403030208010103";//1.3.36.3.3.2.8.1.1.3 brainpoolP192r1 (ECC Brainpool Standard Curves and Curve Generation)
			else if (dg15_tolower.find("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe") != dg15_tolower.npos)
				oid = "06052b81040021";// 1.3.132.0.33 secp224r1 (SECG (Certicom) named elliptic curve)
			else if (dg15_tolower.find("68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43") != dg15_tolower.npos)
				oid = "06092b2403030208010105";//1.3.36.3.3.2.8.1.1.5 brainpool 224r1
			else if (dg15_tolower.find("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc") != dg15_tolower.npos)
				oid = "06082a8648ce3d030107";//secp 256r1
			else if (dg15_tolower.find("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9") != dg15_tolower.npos)
				oid = "06092b2403030208010107";//brainpool 256r1
			else if (dg15_tolower.find("3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4") != dg15_tolower.npos)
				oid = "06092b2403030208010109";//BrainpoolP320r1
			else if (dg15_tolower.find("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc") != dg15_tolower.npos)
				oid = "06052b81040022";//NIST P-384 (secp384r1)
			else if (dg15_tolower.find("7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826") != dg15_tolower.npos)
				oid = "06092b240303020801010b";//BrainpoolP384r1
			else if (dg15_tolower.find("7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca") != dg15_tolower.npos)
				oid = "06092b240303020801010d";//BrainpoolP512r1
			else if (dg15_tolower.find("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc") != dg15_tolower.npos)
				oid = "06052b81040023";//NIST P-521 (secp521r1)
			if (oid == "06082a8648ce3d030107")
			{
				const char* ec_p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
				const char* ec_a = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
				const char* ec_b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
				const char* ec_x = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
				const char* ec_y = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
				const char* ec_order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
				const char* ec_cofactor = "1";
				BIGNUM* p = BN_new(), * a = BN_new(), * b = BN_new(), * order = BN_new(), * cofactor = BN_new(), * x = BN_new(), * y = BN_new();
				int ret = -1;
				ret = BN_hex2bn(&p, ec_p);
				ret = BN_hex2bn(&a, ec_a);
				ret = BN_hex2bn(&b, ec_b);
				ret = BN_hex2bn(&order, ec_order);
				ret = BN_hex2bn(&cofactor, ec_cofactor);
				ret = BN_hex2bn(&x, ec_x);
				ret = BN_hex2bn(&y, ec_y);
				BN_CTX* ctx = BN_CTX_new();
				EC_GROUP* ec_group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
				EC_POINT* g = EC_POINT_new(ec_group);
				ret = EC_POINT_set_affine_coordinates_GFp(ec_group, g, x, y, ctx);
				ret = EC_GROUP_set_generator(ec_group, g, order, cofactor);
				ret = EC_KEY_set_group(ec_key, ec_group);
				bitstring = extractValueFromTLVHexString(bitstring);//自动去掉bitstring后面打头的00
				bitstring = bitstring.substr(2);//去掉04
				BIGNUM* pkx = BN_new(), * pky = BN_new();
				EC_POINT* pk = EC_POINT_new(ec_group);
				std::string pk_x = bitstring.substr(0, bitstring.length() / 2).c_str();
				std::string pk_y = bitstring.substr(bitstring.length() / 2).c_str();
				BN_hex2bn(&pkx, pk_x.c_str());
				BN_hex2bn(&pky, pk_y.c_str());
				ret = EC_POINT_set_affine_coordinates_GFp(ec_group, pk, pkx, pky, ctx);
				ret = EC_KEY_set_public_key(ec_key, pk);
				return 1;
			}
			std::string ecpk_oid = "06072a8648ce3d0201";
			int length1 = (ecpk_oid.length() + oid.length()) / 2;
			temp = BinaryToHexString((lengthtoBinary(length1)));//
			temp = temp.substr(0, temp.length() - 1);
			std::string sequence1 = "30" + temp + ecpk_oid + oid;
			int length2 = sequence1.length() / 2 + bitstring.length() / 2;
			temp = BinaryToHexString(lengthtoBinary(length2));
			temp = temp.substr(0, temp.length() - 1);
			ecpk = "30" + temp + sequence1 + bitstring;
		}
	}

	std::string ecpk_base64 = hexToBase64(ecpk);
	ecpk_base64 = "-----BEGIN PUBLIC KEY-----\n" + ecpk_base64 + "\n-----END PUBLIC KEY-----\n";
	BIO* bio = BIO_new_mem_buf((unsigned char*)ecpk_base64.c_str(), -1);
	if (!bio) {
		std::cerr << "Failed to create memory BIO." << std::endl;
		return -1;
	}


	ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
	if (!ec_key) {
		std::cerr << "Failed to read EC Public Key from the string." << std::endl;
		BIO_free(bio);
		return -1;
	}
	else return 1;
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
		std::string res = "";
		if (tag == "03")
		{
			std::string head = str.substr(2 + Llength, 2);
			if (head == "00")
				res = str.substr(2 + Llength + 2, Vlength - 2);
			else
				res = str.substr(2 + Llength, Vlength);
		}
		else
			res = str.substr(2 + Llength, Vlength);
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
		std::string res = "";
		if (tag == "03")
		{
			std::string head = str.substr(2 + Llength, 2);
			if (head == "00")
			{
				res = str.substr(2 + Llength + 2, Vlength - 2);
				remainder = str.substr(2 + Llength + Vlength);
				return res;
			}
			else//这种情况不太清楚
			{
				LOG(INFO) << "DER encoded bitstring doesn't begin with 00\n";
				res = str.substr(2 + Llength, Vlength);
				remainder = str.substr(2 + Llength + Vlength);
				return res;
			}
				
		}
		else
		{
			res = str.substr(2 + Llength, Vlength);
			remainder = str.substr(2 + Llength + Vlength);
			return res;
		}
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
bool TestEcdsa(std::string& signature, std::string& randomData, std::string& DG15, EC_KEY*& eckey_pub) {
	BIO* key_bio = NULL;

	int ret = 0;
	
	std::string rnd = randomData;
	std::string sig_test = signature;
	//rnd = HexStringToBinary(rnd);
	std::string r = sig_test.substr(0, sig_test.length() / 2);
	std::string s = sig_test.substr(sig_test.length() / 2);
	std::string sig_binary = HexStringToBinary(sig_test);
	BIGNUM* r_bn = BN_new();
	BIGNUM* s_bn = BN_new();
	ret = BN_hex2bn(&r_bn, r.c_str());
	ret = BN_hex2bn(&s_bn, s.c_str());
	//确定AA ECDSA使用哈希函数位数
	std::string hashres_224(SHA224_DIGEST_LENGTH, 0);
	SHA224((unsigned char*)rnd.data(), rnd.size(), (unsigned char*)hashres_224.data());
	std::string hashres_224_hex = BinaryToHexString(hashres_224);
	std::string hashres_256(SHA256_DIGEST_LENGTH, 0);
	SHA256((unsigned char*)rnd.data(), rnd.size(), (unsigned char*)hashres_256.data());
	std::string hashres_256_hex = BinaryToHexString(hashres_256);
	std::string hashres_384(SHA384_DIGEST_LENGTH, 0);
	SHA384((unsigned char*)rnd.data(), rnd.size(), (unsigned char*)hashres_384.data());
	std::string hashres_384_hex = BinaryToHexString(hashres_384);
	std::string hashres_512(SHA512_DIGEST_LENGTH, 0);
	SHA512((unsigned char*)rnd.data(), rnd.size(), (unsigned char*)hashres_512.data());
	std::string hashres_512_hex = BinaryToHexString(hashres_512);
	// 验证签名
	ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();
	if (!ecdsaSig) {
		return false;
	}
	ret = ECDSA_SIG_set0(ecdsaSig, r_bn, s_bn);
	const unsigned char* dgst_224 = (unsigned char*)hashres_224.c_str();
	std::string dgst_224_str = (char*)dgst_224;
	const unsigned char* dgst_256 = (unsigned char*)hashres_256.c_str();
	std::string dgst_256_str = (char*)dgst_256;
	const unsigned char* dgst_384 = (unsigned char*)hashres_384.c_str();
	std::string dgst_384_str = (char*)dgst_384;
	const unsigned char* dgst_512 = (unsigned char*)hashres_512.c_str();
	std::string dgst_512_str = (char*)dgst_512;
	// 验证签名
	int ret_224 = ECDSA_do_verify(dgst_224, hashres_224.size(), ecdsaSig, eckey_pub);
	int ret_256 = ECDSA_do_verify(dgst_256, hashres_256.size(), ecdsaSig, eckey_pub);
	int ret_384 = ECDSA_do_verify(dgst_384, hashres_384.size(), ecdsaSig, eckey_pub);
	int ret_512 = ECDSA_do_verify(dgst_512, hashres_512.size(), ecdsaSig, eckey_pub);
	if (ret_256 || ret_384|| ret_224|| ret_512) {
		if (ret_224)
			LOG(INFO) << "AA ECDSA SHA224";
		else if(ret_256)
			LOG(INFO) << "AA ECDSA SHA256";
		else if (ret_384)
			LOG(INFO) << "AA ECDSA SHA384";
		else 
			LOG(INFO) << "AA ECDSA SHA512";
		LOG(INFO)<< "signature matched" << std::endl;
		return true;
	}
	else {
		LOG(INFO)<< "signature dismatch" << std::endl;
		return false;
	}

}
bool getEckDirectlySODHexString(std::string sod, std::string& eck)
{
	try {
		int oid_eckry_pos = sod.find("06072a8648ce3d0201");
		int cnt_30 = 0;
		int ptr = oid_eckry_pos;
		while (cnt_30 < 2) {
			ptr = ptr - 2;
			std::string tag = sod.substr(ptr, 2);
			if (tag == "30") ++cnt_30;
		}
		std::string flag1 = sod.substr(ptr + 2, 2);
		int eck_len;
		std::string str_eck_len;
		if (flag1 == "82") {
			str_eck_len = sod.substr(ptr + 4, 4);
			eck_len = hexStringToInt(str_eck_len) * 2 + 8;
		}
		else if (flag1 == "81") {
			str_eck_len = sod.substr(ptr + 4, 2);
			eck_len = hexStringToInt(str_eck_len) * 2 + 6;
		}
		else {
			str_eck_len = sod.substr(ptr + 2, 2);
			eck_len = hexStringToInt(str_eck_len) * 2 + 4;
		}
		eck = sod.substr(ptr, eck_len);
		return true;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return false;
	}
}

bool getEckPubkeyFromSOD(std::string& sod, std::string& pubKey) {
	try {
		int oid_eckry_pos = sod.find("06072a8648ce3d0201");
		int cnt_30 = 0;
		int ptr = oid_eckry_pos;
		while (cnt_30 < 2) {
			ptr = ptr - 2;
			std::string tag = sod.substr(ptr, 2);
			if (tag == "30") ++cnt_30;
		}
		std::string flag1 = sod.substr(ptr + 2, 2);

		int eckHeader_len = 0;
		std::string flag2;
		if (flag1 == "82") {
			eckHeader_len += 8;
			flag2 = sod.substr(ptr + 10, 2);
		}
		else if (flag1 == "81") {
			eckHeader_len += 6;
			flag2 = sod.substr(ptr + 8, 2);
		}
		else {
			eckHeader_len += 4;
			flag2 = sod.substr(ptr + 6, 2);
		}

		if (flag2 == "82") {
			eckHeader_len += 8;
		}
		else if (flag2 == "81") {
			eckHeader_len += 6;
		}
		else {
			eckHeader_len += 4;
		}

		int paramter_len = 0;
		std::string paramter_len_str;
		ptr = ptr + eckHeader_len + 18;
		std::string flag3 = sod.substr(ptr + 2, 2);
		if (flag3 == "82") {
			paramter_len_str = sod.substr(ptr + 4, 4);
			paramter_len = hexStringToInt(paramter_len_str) * 2 + 8;
		}
		else if (flag3 == "81") {
			paramter_len_str = sod.substr(ptr + 4, 2);
			paramter_len = hexStringToInt(paramter_len_str) * 2 + 6;
		}
		else {
			paramter_len_str = sod.substr(ptr + 2, 2);
			paramter_len = hexStringToInt(paramter_len_str) * 2 + 4;
		}
		ptr = ptr + paramter_len;
		std::string pubKey_len_str = sod.substr(ptr + 2, 2);
		int pubKey_len = hexStringToInt(pubKey_len_str) * 2 + 4;
		pubKey = sod.substr(ptr, pubKey_len);
		return true;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return false;
	}

}
bool ExtractECpkfromSOD(std::string sod, EC_KEY*& ec_key,std::string& pk)
{
	std::string ecpk = "";
	pk = "";
	std::string ecpk_oid = "06072a8648ce3d0201";
	std::string curvename = "";
	ec_key = EC_KEY_new();
	std::transform(sod.begin(), sod.end(), sod.begin(),
		[](unsigned char c) { return std::tolower(c); });
	if (sod.find(ecpk_oid) == sod.npos)
		return false;
	else
	{
		if (sod.find("06072a8648ce3d0101") == sod.npos) {
			if (!getEckDirectlySODHexString(sod, ecpk)) {
				return false;
			}
			pk = ecpk;
		}
		else
		{
			std::string pub_string;
			/*if (!getEckPubkeyFromSOD(sod, pub_string)) {
				return false;
			}*/
			size_t p = sod.find("06072a8648ce3d0201");
			while (sod.substr(p, 3) != "308")
				p -= 2;
			p -= 2;
			while (sod.substr(p, 3) != "308")
				p -= 2;
			pub_string = sod.substr(p);
			pub_string = extractValueFromTLVHexString(pub_string);
			extractValueFromTLVHexString(pub_string, pub_string);
			LOG(INFO) << "EXTRACT PUB_STRING ";
			std::string curve_oid = "";
			if (sod.find("fffffffffffffffffffffffffffffffefffffffffffffffc") != sod.npos)
			{
				curve_oid = "06082a8648ce3d030101";//1.2.840.10045.3.1.1 prime192v1 (ANSI X9.62 named elliptic curve)
				curvename = "NIST P-192 (secp192r1)";
			}
			else if (sod.find("6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef") != sod.npos)
			{
				curve_oid = "06092b2403030208010103";//1.3.36.3.3.2.8.1.1.3 brainpoolP192r1 (ECC Brainpool Standard Curves and Curve Generation)
				curvename = "BrainpoolP192r1";
			}
			else if (sod.find("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe") != sod.npos)
			{
				curve_oid = "06052b81040021";// 1.3.132.0.33 secp224r1 (SECG (Certicom) named elliptic curve)
				curvename = "NIST P-224 (secp224r1)";
			}
			else if (sod.find("68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43") != sod.npos)
			{
				curve_oid = "06092b2403030208010105";//1.3.36.3.3.2.8.1.1.5 brainpool 224r1
				curvename = "BrainpoolP224r1";
			}
			else if (sod.find("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc") != sod.npos)
			{
				curve_oid = "06082a8648ce3d030107";//secp 256r1
				curvename = "NIST P-256 (secp256r1) ";
			}
			else if (sod.find("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9") != sod.npos)
			{
				curve_oid = "06092b2403030208010107";//brainpool 256r1
				curvename = "BrainpoolP256r1";
			}
			else if (sod.find("3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4") != sod.npos)
			{
				curve_oid = "06092b2403030208010109";
				curvename = "BrainpoolP320r1";
			}
			else if (sod.find("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc") != sod.npos)
			{
				curve_oid = "06052b81040022";
				curvename = "NIST P-384 (secp384r1)";
			}
			else if (sod.find("7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826") != sod.npos)
			{
				curve_oid = "06092b240303020801010b";
				curvename = "BrainpoolP384r1";
			}
			else if (sod.find("7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca") != sod.npos)
			{
				curve_oid = "06092b240303020801010d";
				curvename = "BrainpoolP512r1";
			}
			else if (sod.find("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc") != sod.npos)
			{
				curve_oid = "06052b81040023";
				curvename = "NIST P-521 (secp521r1)";
			}
			std::string eck_header = "30";
			int length2 = (ecpk_oid.size() + curve_oid.size()) / 2;
			std::string length2_str = BinaryToHexString(lengthtoBinary(length2));
			int length1 = pub_string.size() / 2 + length2 + 2;
			std::string length1_str = BinaryToHexString(lengthtoBinary(length1));
			eck_header += length1_str;
			eck_header.pop_back();
			eck_header.append("30");
			eck_header += length2_str;
			eck_header.pop_back();
			ecpk = eck_header + ecpk_oid + curve_oid + pub_string;
			pk = ecpk;
			LOG(INFO) << "EC CURVE NAME " << curvename << ". GOT ECPK";
		}
	}

	std::string ecpk_base64 = hexToBase64(ecpk);
	ecpk_base64 = "-----BEGIN PUBLIC KEY-----\n" + ecpk_base64 + "\n-----END PUBLIC KEY-----\n";
	LOG(INFO) << "ExtractECpkfromSOD EC PK ";
	BIO* bio = BIO_new_mem_buf((unsigned char*)ecpk_base64.c_str(), -1);
	if (!bio) {
		LOG(ERROR) << "Failed to create memory BIO." << std::endl;
		return false;
	}

	// 从内存中的 PEM 数据读取公钥
	ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
	if (!ec_key) {
		LOG(ERROR)<< "Failed to read EC Public Key from the string." << std::endl;
		BIO_free(bio);
		return false;
	}
	else return true;
}

bool getMsgfromSOD(std::string& sod, std::string& msg) {

	size_t pos = -1;
	regex msg_pattern("A0..30");
	std::vector<size_t> match_positions; // 用于存储匹配项的起始位置
	auto words_begin = std::sregex_iterator(sod.begin(), sod.end(), msg_pattern);
	auto words_end = std::sregex_iterator();

	for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
		std::smatch match = *i;
		match_positions.push_back(match.position()); // 获取匹配的起始位置并存储
	}
	for (int i = 0; i < match_positions.size(); i++)
	{
		msg = sod.substr(match_positions[i]);
		msg = extractValueFromTLVHexString(msg);
		if (msg.find("06092A864886F70D010904") != msg.npos)
		{
			pos = match_positions[i];
			msg = sod.substr(pos, 4) + msg;
			std::string temp = sod.substr(pos);
			break;
		}
	}
	if (pos < 0)
		return false;
	//复原成完整的der格式
	msg[0] = '3';
	msg[1] = '1';
	return true;
}
bool getSigfromSOD(std::string& sod, std::string& s, std::string& r) {
	size_t p = sod.find("A0");
	while (sod.substr(p + 4, 2) != "30")
		p = sod.find("A0", p + 1);
	std::string pub_string = sod.substr(p);
	extractValueFromTLVHexString(pub_string, pub_string);
	extractValueFromTLVHexString(pub_string, pub_string);
	pub_string = extractValueFromTLVHexString(pub_string);
	pub_string = extractValueFromTLVHexString(pub_string);
	r = extractValueFromTLVHexString(pub_string, s);
	s = extractValueFromTLVHexString(s);
	return true;
}
bool getSigfromSODlcx(std::string& sod, std::string& s, std::string& r) {
	int msg_pos = sod.rfind("06082A8648CE");//有问题，但是不知道是什么问题，反正字符串索引越界
	int ptr = 0;
	if (msg_pos < 0) {
		return false;
	}
	ptr = msg_pos;
	int offset_1 = sod.substr(msg_pos + 21, 1)[0] - '0';
	ptr = ptr + 20 + offset_1 * 2 + 2;
	switch (offset_1)
	{
	case 4:
		break;
	case 5: ptr += 2;
		break;
	default:
		// TODO: other case
		return false;
	}
	std::string offset_2_str = sod.substr(ptr, 2);
	int offset_2 = offset_2_str[1] - '0' + (offset_2_str[0] - '0') * 16;
	if (offset_2 % 16 != 0) {
		--offset_2;
		ptr += 4;
		r = sod.substr(ptr, offset_2 * 2);
		ptr += offset_2 * 2 + 2;
		std::string offset_3_str = sod.substr(ptr, 2);
		int offset_3 = offset_3_str[1] - '0' + (offset_3_str[0] - '0') * 16;
		if (offset_3 % 16 != 0) {
			--offset_3;
			ptr += 4;
			s = sod.substr(ptr, offset_2 * 2);
		}
		else {
			ptr += 2;
			s = sod.substr(ptr, offset_2 * 2);
		}

	}
	else {
		ptr += 2;
		r = sod.substr(ptr, offset_2 * 2);
		ptr += offset_2 * 2 + 2;
		std::string offset_3_str = sod.substr(ptr, 2);
		int offset_3 = offset_3_str[1] - '0' + (offset_3_str[0] - '0') * 16;
		if (offset_3 % 16 != 0) {
			--offset_3;
			ptr += 4;
			s = sod.substr(ptr, offset_2 * 2);
		}
		else {
			ptr += 2;
			s = sod.substr(ptr, offset_2 * 2);
		}
	}
	return true;
}
bool checkmd(std::string& hash, const EVP_MD*& md)
{
	if (hash == "SHA-1")
		md = EVP_sha1();
	else if (hash == "SHA-224")
		md = EVP_sha224();
	else if (hash == "SHA-256")
		md = EVP_sha256();
	else if (hash == "SHA-384")
		md = EVP_sha384();
	else if (hash == "SHA-512")
		md = EVP_sha512();
	else return false;
	return true;
}
bool SHA_X(std::string& sha_name, std::string& binaryInput, std::string& output) {

	if (sha_name == "SHA-1") {
		output.resize(20);
		SHA1((unsigned char*)binaryInput.c_str(), binaryInput.length(), (unsigned char*)output.data());
	}
	else if (sha_name == "SHA-256") {
		output.resize(32);
		SHA256((unsigned char*)binaryInput.c_str(), binaryInput.length(), (unsigned char*)output.data());

	}
	else if (sha_name == "SHA-384") {
		output.resize(48);
		SHA384((unsigned char*)binaryInput.c_str(), binaryInput.length(), (unsigned char*)output.data());
	}
	else if (sha_name == "SHA-512") {
		output.resize(64);
		SHA512((unsigned char*)binaryInput.c_str(), binaryInput.length(), (unsigned char*)output.data());
	}
	else if (sha_name == "SHA-224") {
		output.resize(28);
		SHA224((unsigned char*)binaryInput.c_str(), binaryInput.length(), (unsigned char*)output.data());
	}
	else {
		return false;
	}
	return true;
}

//	SHA1	06052B0E03021A				1.3.14.3.2.26 
//	SHA256	0609608648016503040201	2.16.840.1.101.3.4.2.1
//	SHA384	0609608648016503040202	2.16.840.1.101.3.4.2.2
//	SHA512	0609608648016503040203	2.16.840.1.101.3.4.2.3
//	SHA224	0609608648016503040204	2.16.840.1.101.3.4.2.4
//	RSA     06092A864886F70D010101  1.2.840.113549.1.1.1
//	RSAPSS  06092A864886F70D01010A  1.2.840.113549.1.1.10 
//	ECDSAwithSHA1			06072A8648CE3D0401		1.2.840.10045.4.1		
//	ECDSAwithSHA224			06082A8648CE3D040301	1.2.840.10045.4.3.1
//	ECDSAwithSHA256			06082A8648CE3D040302	1.2.840.10045.4.3.2
//	ECDSAwithSHA384			06082A8648CE3D040303	1.2.840.10045.4.3.3
//	ECDSAwithSHA512			06082A8648CE3D040304	1.2.840.10045.4.3.4
//	*/
//
//	/*
//	sha1-with-rsa-signature 06092A864886F70D010105 1.2.840.113549.1.1.5	
//	sha256WithRSAEncryption 06092A864886F70D01010B 1.2.840.113549.1.1.11	
//	sha384WithRSAEncryption 06092A864886F70D01010C 1.2.840.113549.1.1.12	
//	sha512WithRSAEncryption 06092A864886F70D01010D 1.2.840.113549.1.1.13	
//	sha224WithRSAEncryption 06092A864886F70D01010E 1.2.840.113549.1.1.14	
//	*/
bool checkHashAndSignature(std::string& hex, std::string& Hash, std::string& Signature, int& HashLength)
{
	Hash = "";
	Signature = "";
	bool result = false;
	//hash
	if (hex.find("06052B0E03021A")!=hex.npos|| hex.find("06072A8648CE3D0401") != hex.npos|| hex.find("06092A864886F70D010105") != hex.npos)
		Hash = "SHA-1";
	else if (hex.find("0609608648016503040201") != hex.npos || hex.find("06082A8648CE3D040302") != hex.npos || hex.find("06092A864886F70D01010B") != hex.npos)
		Hash = "SHA-256";
	else if (hex.find("0609608648016503040204") != hex.npos || hex.find("06082A8648CE3D040301") != hex.npos || hex.find("06092A864886F70D01010E") != hex.npos)
		Hash = "SHA-224";
	else if (hex.find("0609608648016503040202") != hex.npos || hex.find("06082A8648CE3D040303") != hex.npos || hex.find("06092A864886F70D01010C") != hex.npos)
		Hash = "SHA-384";
	else if (hex.find("0609608648016503040203") != hex.npos || hex.find("06082A8648CE3D040304") != hex.npos || hex.find("06092A864886F70D01010D") != hex.npos)
		Hash = "SHA-512";
	//signature
	if (hex.find("06092A864886F70D01010A") != hex.npos)
		Signature = "RSAPSS";
	else if (hex.find("06092A864886F70D010101") != hex.npos|| hex.find("06092A864886F70D010105") != hex.npos|| hex.find("06092A864886F70D01010B") != hex.npos||
		hex.find("06092A864886F70D01010C") != hex.npos|| hex.find("06092A864886F70D01010D") != hex.npos|| hex.find("06092A864886F70D01010E") != hex.npos)
		Signature = "RSA";
	else if (hex.find("06072A8648CE3D0401") != hex.npos || hex.find("06082A8648CE3D040301") != hex.npos || hex.find("06082A8648CE3D040302") != hex.npos ||
		hex.find("06082A8648CE3D040303") != hex.npos || hex.find("06082A8648CE3D040304") != hex.npos)
		Signature = "ECDSA";
	if (Hash == "SHA-1")
		HashLength = SHA_DIGEST_LENGTH;
	else if (Hash == "SHA-224")
		HashLength = SHA224_DIGEST_LENGTH;
	else if (Hash == "SHA-256")
		HashLength = SHA256_DIGEST_LENGTH;
	else if (Hash == "SHA-384")
		HashLength = SHA384_DIGEST_LENGTH;
	else if (Hash == "SHA-512")
		HashLength = SHA512_DIGEST_LENGTH;
	if (Hash.length() || Signature.length())
		return true;
	else return false;
}
bool checkDGs(std::unordered_map<int, std::string>& DGs, std::string& hash_type, std::string& sod, bool& integrity) {
	std::unordered_map<int, std::string> DGs_hash;
	int DG_cnt = DGs.size();
	DG_cnt--;//排除sod
	for (auto& DG : DGs) {
		std::string hash_res;
		SHA_X(hash_type, DG.second, hash_res);
		hash_res = BinaryToHexString(hash_res);
		hash_res.pop_back();
		DGs_hash.emplace(DG.first, hash_res);
	}
	std::string hash_flag = "06096086480165030402";
	size_t hash_pos_first = sod.find(hash_flag);
	if (hash_pos_first < 0) return false;
	//找第二个hash_flag
	hash_pos_first += hash_flag.size();
	size_t hash_pos = sod.find(hash_flag, hash_pos_first);

	int ptr = hash_pos + 22;
	// find two "30"
	std::string flag1;
	int cnt_30 = 0;
	while (cnt_30 < 2) {
		flag1 = sod.substr(ptr, 2);
		if (flag1 == "30") ++cnt_30;
		ptr += 2;
	}
	ptr += 10;
	std::string len_str = sod.substr(ptr, 2);
	int hash_len = hexStringToInt(len_str);
	ptr += 2;
	for (int i = 0; i < DG_cnt; ++i) {
		std::string index_tag = sod.substr(ptr - 6, 2);
		int index = hexStringToInt(index_tag);
		std::string curr_hash = sod.substr(ptr, hash_len * 2);
		if (DGs_hash.find(index) == DGs_hash.end())
		{
			if (index != 3 && index != 4)
			{
				integrity = false;
				return false;
			}
			else
			{
				ptr = ptr + hash_len * 2 + 14;
				continue;
			}
		}
		if (!compare_ignore_case(curr_hash, DGs_hash[index])) {
			return false;
		}
		ptr = ptr + hash_len * 2 + 14;
	}
	return true;
}
bool checkCSCA(std::string& sod, std::string& cipherFlag, std::string& hashFlag, int hashLength, std::string& country) {
	std::string signature;
	std::string toBeSigned;
	std::string publicKey;
	char CSCA_Path[512];
	MakeFullPath1(CSCA_Path, "PKDnew");
	std::string CSCA = CSCA_Path;
	CSCA += "\\";
	CSCA += country;
	if (cipherFlag == "RSA" || cipherFlag == "RSAPSS")
		CSCA += "\\RSAPK";
	else
		CSCA += "\\ECDSAPK";
	LOG(INFO) << "CSCA DIRECTORY " << CSCA;
	DIR* dir;
	std::vector<std::string> filename;
	std::vector<std::string> pks;
	std::vector<std::string> pks_hex;
	struct dirent* ent;
	if ((dir = opendir(CSCA.c_str())) != NULL)
	{
		while ((ent = readdir(dir)) != NULL)
		{
			if (ent->d_name[0] != '.')
			{
				//LOG(INFO) << ent->d_name << " ";
				filename.push_back(ent->d_name);
			}
		}
		LOG(INFO) << "FIND CSCA DIRECTORY: " << CSCA << ",PUBLICKEYS TOTAL "<<filename.size()<<'\n';
		closedir(dir);
	}
	else
	{
		LOG(ERROR)<<"CAN'T FIND CSCA DIRECTORY\n";
		return false;
	}
	for (auto fn : filename)
	{
		fstream f(CSCA+"\\"+fn, ios::in | ios::binary);
		if (f.is_open())
		{
			std::string buffer;
			f.seekg(0, f.end);
			buffer.resize(f.tellg());
			f.seekg(0, f.beg);

			// Read the data into the string
			f.read(&buffer[0], buffer.size());
			pks.push_back(buffer);
			std::string hex = BinaryToHexString(buffer);
			hex.pop_back();
			pks_hex.push_back(hex);
			// Close the file
			f.close();
		}
	}
	
	if (!pks.size())
	{
		LOG(INFO) << "COUNTRY NAME " << country << " FIND NO " << cipherFlag << " PK\n";
		return false;
	}
	//std::string base64str = hexToBase64(publicKey);
	//std::string pubKey1 = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";
	bool flag = false;
	std::string correctpk;
	if (cipherFlag == "RSA") {
		LOG(INFO) << "CSCA VERIFY RSA SIGNATURE";
		int ret = -1;
		size_t CSCAHead = sod.rfind("A082");
		std::string CSCA = sod.substr(CSCAHead);
		std::string bitstring_hex;
		CSCA = extractValueFromTLVHexString(CSCA);
		CSCA = extractValueFromTLVHexString(CSCA);
		std::string message_hex = extractValueFromTLVHexString(CSCA, bitstring_hex);
		message_hex = CSCA.substr(0, 8) + message_hex;
		LOG(INFO) << "GET DS MESSAGE ";
		std::string message = HexStringToBinary(message_hex);
		extractValueFromTLVHexString(bitstring_hex, bitstring_hex);
		bitstring_hex = extractValueFromTLVHexString(bitstring_hex);
		LOG(INFO) << "GET DS SIGNATURE BITSTRING " ;
		std::string bitstring = HexStringToBinary(bitstring_hex);
		std::string message_hash(hashLength, '\0');
		SHA_X(hashFlag, message, message_hash);
		std::string message_hash_hex = BinaryToHexString(message_hash);
		LOG(INFO) << "GET DS MESSAGE HASH RESULT ";
		message_hash_hex.pop_back();
		for (auto pk_hex : pks_hex)
		{
			std::string base64str = hexToBase64(pk_hex);
			std::string pubKey = "-----BEGIN PUBLIC KEY-----\n" + base64str + +"\n-----END PUBLIC KEY-----\n";
			RSA* rsa = RSA_new();
			BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
			rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
			int len = RSA_size(rsa);
			char* decryptedText = (char*)malloc(len + 1);
			memset(decryptedText, 0, len + 1);
			ret = RSA_public_decrypt(bitstring.length(), (unsigned char*)bitstring.c_str(), (unsigned char*)decryptedText, rsa, RSA_NO_PADDING);
			if (ret == -1)
				continue;
			std::string res(decryptedText, ret);
			std::string res_hex = BinaryToHexString(res);
			res_hex.pop_back();
			
			flag = (res_hex.find(message_hash_hex) != res_hex.npos);
			if (flag)
			{
				correctpk = pk_hex;
				break;
			}
		}
		if(flag)
		{
			LOG(INFO) << "CSCA RSA VERIFY SIGNATURE SUCCESS";
			return 1;
		}
		else
		{
			LOG(INFO) << "CSCA RSA VERIFY SIGNATURE FAIL";
			return 0;
		}
	}
	else if (cipherFlag == "RSAPSS")
	{
		LOG(INFO) << "CSCA VERIFY RSAPSS SIGNATURE";
		int ret = -1;
		size_t CSCAHead = sod.rfind("A082");
		std::string CSCA = sod.substr(CSCAHead);
		std::string bitstring_hex;
		CSCA = extractValueFromTLVHexString(CSCA);
		CSCA = extractValueFromTLVHexString(CSCA);
		std::string message_hex = extractValueFromTLVHexString(CSCA, bitstring_hex);
		message_hex = CSCA.substr(0, 8) + message_hex;
		LOG(INFO) << "GET DS MESSAGE";
		std::string message = HexStringToBinary(message_hex);
		std::string message_hash(hashLength, '\0');
		std::string message_hash_hex = BinaryToHexString(message_hash);
		LOG(INFO) << "GET DS MESSAGE HASH RESULT";
		message_hash_hex.pop_back();
		extractValueFromTLVHexString(bitstring_hex, bitstring_hex);
		bitstring_hex = extractValueFromTLVHexString(bitstring_hex);
		LOG(INFO) << "GET DS SIGNATURE BISTRING ";
		std::string bitstring = HexStringToBinary(bitstring_hex);
		const EVP_MD* md = nullptr;
		checkmd(hashFlag, md);
		for (auto pk_hex : pks_hex)
		{
			std::string base64str = hexToBase64(pk_hex);
			std::string pubKey = "-----BEGIN PUBLIC KEY-----\n" + base64str + +"\n-----END PUBLIC KEY-----\n";
			RSA* rsa = RSA_new();
			BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
			rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
			int len = RSA_size(rsa);
			char* decryptedText = (char*)malloc(len + 1);
			memset(decryptedText, 0, len + 1);
			ret = RSA_public_decrypt(bitstring.length(), (unsigned char*)bitstring.c_str(), (unsigned char*)decryptedText, rsa, RSA_NO_PADDING);
			std::string res(decryptedText, ret);
			std::string res_hex = BinaryToHexString(res);
			res_hex.pop_back();
			ret = RSA_verify_PKCS1_PSS_mgf1(rsa, (unsigned char*)message_hash.c_str(), md, md, (unsigned char*)res.c_str(), hashLength);
			if (ret == 1)
			{
				flag = true;
				correctpk = pk_hex;
				break;
			}
		}
		if (flag)
		{
			LOG(INFO) << "CSCA: RSAPSS VERIFY SUCCESS";
		}
		else
		{
			LOG(INFO) << "CSCA: RSAPSS VERIFY FAIL";
		}
		return ret;
	}
	else if (cipherFlag == "ECDSA")
	{
		LOG(INFO) << "CSCA VERIFY ECDSA SIGNATURE";
		int ret = -1;
		size_t CSCAHead = sod.rfind("A082");
		std::string CSCA = sod.substr(CSCAHead);
		std::string bitstring;
		CSCA = extractValueFromTLVHexString(CSCA);
		CSCA = extractValueFromTLVHexString(CSCA);
		std::string message_hex = extractValueFromTLVHexString(CSCA,bitstring);
		message_hex = CSCA.substr(0,8)+message_hex;
		LOG(INFO) << "GET DS MESSAGE";
		extractValueFromTLVHexString(bitstring,bitstring);
		std::string r_hex, s_hex;
		r_hex = extractValueFromTLVHexString(bitstring);
		r_hex = extractValueFromTLVHexString(r_hex);
		r_hex = extractValueFromTLVHexString(r_hex, s_hex);
		s_hex = extractValueFromTLVHexString(s_hex);
		LOG(INFO) << "GET DS ECDSA SIGNATURE R ";
		LOG(INFO) << "GET DS ECDSA SIGNATURE S ";
		std::string message = HexStringToBinary(message_hex);
		BIGNUM* r_bn = BN_new();
		BIGNUM* s_bn = BN_new();
		ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();

		ret = BN_hex2bn(&r_bn, r_hex.c_str());
		ret = BN_hex2bn(&s_bn, s_hex.c_str());
		ret = ECDSA_SIG_set0(ecdsaSig, r_bn, s_bn);

		std::string hashres(hashLength , '\0');
		SHA_X(hashFlag,message,hashres);
		std::string hashres_hex = BinaryToHexString(hashres);
		LOG(INFO) << "GET DS MESSAGE HASH RESULT ";
		EC_KEY* ec_key = EC_KEY_new();
		std::string pk_extract;
		LOG(INFO) << "CSCA START TO TEST MUNEROUS ECPKS";
		for (auto pk_hex : pks_hex)
		{
			ret = ExtractECpkfromSOD(pk_hex, ec_key, pk_extract);
			ret = ECDSA_do_verify((unsigned char*)hashres.c_str(), hashres.size(), ecdsaSig, ec_key);
			if (ret == 1)
			{
				flag = true;
				correctpk = pk_hex;
				break;
			}
		}
		if (flag)
		{
			LOG(INFO) << "CSCA: ECDSA VERIFY SUCCESS";
			return 1;
		}
		else
		{
			LOG(INFO) << "CSCA: ECDSA VERIFY FAIL";
			return 0;
		}

	}
	return false;
}
std::string hexToChar(std::string& hexstring)
{
	if (hexstring.length() % 2 != 0)
		return "";
	transform(hexstring.begin(), hexstring.end(), hexstring.begin(), ::tolower);
	std::string result = "";
	for (int i = 0; i < hexstring.length() / 2; i ++)
	{
		char ch = 0;
		if (hexstring[2 * i] >= '0' && hexstring[2 * i] <= '9')
			ch += 16 * (hexstring[2 * i] - '0');
		else
			ch += 16 * (hexstring[2 * i] - 'a' + 10);
		if (hexstring[2 * i+1] >= '0' && hexstring[2 * i+1] <= '9')
			ch += (hexstring[2 * i+1] - '0');
		else
			ch += (hexstring[2 * i+1] - 'a' + 10);
		result.push_back(ch);
	}
	return result;
}
bool createDirectory(const std::string& path) {
	// 使用CreateDirectory函数创建目录
	if (!CreateDirectoryA(path.c_str(), NULL)) {
		if (GetLastError() == ERROR_ALREADY_EXISTS) {
			// 目录已存在
			return false;
		}
		else {
			// 创建目录失败
			std::cerr << "Error creating directory: " << GetLastError() << '\n';
			return false;
		}
	}
	return true;
}
void LogOpen() {

	char path[2048];
	MakeFullPath1(path, "\\EchipLog\\");
	std::wstring PathW(s2ws(path));
	std::string logFileName(path);
	std::string logPath = logFileName;
	FLAGS_log_dir = logPath;
	createDirectory(path);
	google::SetLogDestination(google::GLOG_INFO, (logPath + "INFO").c_str());
	google::SetLogFilenameExtension(".log");
	google::InitGoogleLogging("ChipLog");
	google::SetStderrLogging(google::GLOG_INFO);
	
	google::SetLogDestination(google::GLOG_ERROR, (logPath + "INFO").c_str());
	google::SetLogDestination(google::GLOG_WARNING, (logPath + "INFO").c_str());
	
	FLAGS_minloglevel = google::GLOG_INFO;
	FLAGS_colorlogtostderr = true;  // Set log color
	FLAGS_logbufsecs = 0;  // Set log output speed(s)
	FLAGS_max_log_size = 30;  // Set max log file size
	FLAGS_stop_logging_if_full_disk = true;  // If disk is full
	
	LOG(INFO) << "Passport Echip Version：2024年08月1日17点08分. 1.0.32  x64" << std::endl;
	LOG(ERROR) << "Passport Echip Version：2024年08月1日17点08分. 1.0.32  x64" << std::endl;
	LOG(WARNING) << "Passport Echip Version：2024年08月1日17点08分. 1.0.32  x64" << std::endl;
}

void LogClose() {
	google::ShutdownGoogleLogging();
}
std::unordered_map<std::string, std::string> createCountryCodeMapReversed() {
	std::unordered_map<std::string, std::string> countryCodeMapReversed = {
		{"AND", "AD"}, {"ARE", "AE"}, {"ATG", "AG"}, {"ALB", "AL"}, {"ARM", "AM"},
		{"ARG", "AR"}, {"AUT", "AT"}, {"AUS", "AU"}, {"AZE", "AZ"}, {"BIH", "BA"},
		{"BRB", "BB"}, {"BGD", "BD"}, {"BEL", "BE"}, {"BGR", "BG"}, {"BHR", "BH"},
		{"BEN", "BJ"}, {"BMU", "BM"}, {"BRA", "BR"}, {"BHS", "BS"}, {"BWA", "BW"},
		{"BLR", "BY"}, {"BLZ", "BZ"}, {"CAN", "CA"}, {"CHE", "CH"}, {"CIV", "CI"},
		{"CHL", "CL"}, {"CMR", "CM"}, {"CHN", "CN"}, {"COL", "CO"}, {"CRI", "CR"},
		{"CYP", "CY"}, {"CZE", "CZ"}, {"DEU", "DE"}, {"DNK", "DK"}, {"DMA", "DM"},
		{"DZA", "DZ"}, {"ECU", "EC"}, {"EST", "EE"}, {"ESP", "ES"}, {"EUR", "EU"},
		{"FIN", "FI"}, {"FRA", "FR"}, {"GAB", "GA"}, {"GBR", "GB"}, {"GEO", "GE"},
		{"GHA", "GH"}, {"GMB", "GM"}, {"GRC", "GR"}, {"HRV", "HR"}, {"HUN", "HU"},
		{"IDN", "ID"}, {"IRL", "IE"}, {"ISR", "IL"}, {"IND", "IN"}, {"IRQ", "IQ"},
		{"IRN", "IR"}, {"ISL", "IS"}, {"ITA", "IT"}, {"JPN", "JP"}, {"KEN", "KE"},
		{"KNA", "KN"}, {"PRK", "KP"}, {"KOR", "KR"}, {"KOS", "KS"}, {"KWT", "KW"},
		{"KAZ", "KZ"}, {"LBN", "LB"}, {"LIE", "LI"}, {"LTU", "LT"}, {"LUX", "LU"},
		{"LVA", "LV"}, {"MAR", "MA"}, {"MCO", "MC"}, {"MDA", "MD"}, {"MNE", "ME"},
		{"MKD", "MK"}, {"MNG", "MN"}, {"MLT", "MT"}, {"MDV", "MV"}, {"MEX", "MX"},
		{"MYS", "MY"}, {"NGA", "NG"}, {"NLD", "NL"}, {"NOR", "NO"}, {"NPL", "NP"},
		{"NZL", "NZ"}, {"OMN", "OM"}, {"PAN", "PA"}, {"PER", "PE"}, {"PHL", "PH"},
		{"POL", "PL"}, {"PSE", "PS"}, {"PRT", "PT"}, {"PRY", "PY"}, {"QAT", "QA"},
		{"ROU", "RO"}, {"SRB", "RS"}, {"RUS", "RU"}, {"RWA", "RW"}, {"SYC", "SC"},
		{"SWE", "SE"}, {"SGP", "SG"}, {"SVN", "SI"}, {"SVK", "SK"}, {"SMR", "SM"},
		{"SEN", "SN"}, {"SYR", "SY"}, {"THA", "TH"}, {"TJK", "TJ"}, {"TLS", "TL"},
		{"TKM", "TM"}, {"TUR", "TR"}, {"TWN", "TW"}, {"TZA", "TZ"}, {"UKR", "UA"},
		{"UGA", "UG"}, {"UNO", "UN"}, {"USA", "US"}, {"URY", "UY"}, {"UZB", "UZ"},
		{"VAT", "VA"}, {"VCT", "VC"}, {"VEN", "VE"}, {"VNM", "VN"}, {"XOM", "XO"},
		{"ZWE", "ZW"}, {"ZZZ", "ZZ"}
	};
	return countryCodeMapReversed;
}
std::string getCurrentDateTimeFormatted() {
	// 获取当前时间
	std::time_t t = std::time(nullptr);
	std::tm* now = std::localtime(&t);

	// 格式化时间为YYYYMMDDHHMMSS
	std::ostringstream oss;
	oss << (now->tm_year + 1900)
		<< std::setw(2) << std::setfill('0') << (now->tm_mon + 1)
		<< std::setw(2) << std::setfill('0') << now->tm_mday
		<< std::setw(2) << std::setfill('0') << now->tm_hour
		<< std::setw(2) << std::setfill('0') << now->tm_min
		<< std::setw(2) << std::setfill('0') << now->tm_sec
		<<'Z';

	return oss.str();
}
std::string wcharToStr(const wchar_t* wstr) {
	// 获取wstr的长度，加一是为了获取最后的'\0'字符
	size_t wstr_len = wcslen(wstr) + 1;

	// 为转换后的字符串分配足够的空间
	char* cstr = new char[wstr_len * MB_CUR_MAX];

	// 转换宽字符到多字节字符
	std::wcstombs(cstr, wstr, wstr_len);

	// 使用cstr构造并返回std::string
	std::string result(cstr);

	// 释放内存
	delete[] cstr;

	return result;
}

void RemoveDir(const char* folderPath) {
	std::string strDir = folderPath;
	if (strDir.at(strDir.length() - 1) != '\\')
		strDir += '\\';
	WIN32_FIND_DATA wfd;
	HANDLE hFind = FindFirstFileA((LPCSTR)(strDir + "*.*").c_str(), (LPWIN32_FIND_DATAA)&wfd);
	if (hFind == INVALID_HANDLE_VALUE)
		return;
	do
	{
		if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (strcmp((char*)wfd.cFileName, ".") != 0 && strcmp((char*)wfd.cFileName, "..") != 0)
				RemoveDir((strDir + wcharToStr(wfd.cFileName)).c_str());
		}
		else
		{

			DeleteFileA((strDir + wcharToStr(wfd.cFileName)).c_str());
		}
	} while (FindNextFile(hFind,&wfd));
	FindClose(hFind);
	return;
}
int getLog2(BIGNUM* p)
{
	int log2 = 1;
	BIGNUM* num = BN_dup(p);
	BIGNUM* two = BN_new();
	BN_set_word(two, 2);

	while (BN_cmp(two, num)< 0) {
		BN_lshift1(two, two); // two = two * 2
		log2++;
	}

	BN_free(num);
	BN_free(two);
	return log2;
}