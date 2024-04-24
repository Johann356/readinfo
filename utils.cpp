#include"utils.h"
#include <chrono>
#include <string>
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

	for (std::string::size_type i = 0; i < data.size();) {
		int num = map_hex_int[data[i]] * 16 + map_hex_int[data[i+1]];
		i += 2;
		ss << (char)num;
	}
	//std::cout << ss.str() << std::endl;
	return ss.str();
}

//    
std::string rsa_pub_decrypt(std::string& cipherText, const std::string& pubKey)
{
	std::string strRet;
	RSA* rsa = RSA_new();
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char* decryptedText = (char*)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	//   
	int ret = RSA_public_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_NO_PADDING);
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