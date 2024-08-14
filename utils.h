#pragma once
#include "WinError.h"
#include <string>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <map>
#include <vector>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <algorithm>
#include <openssl/cmac.h>
#include <unordered_map>
#include <regex>
#include "glog\logging.h"
#include <windows.h>
#include "dirent.h"
#include <unordered_map>
#include <ctime>
using namespace std;


std::string StringToHex(const std::string& data);
std::string HexToString(const std::string& data);
std::string hexToBase64(const std::string& hexString);
std::string rsa_pub_decrypt(std::string& cipherText, const std::string& pubKey, int padding_mod);
std::string ReadFileContentsAsHex(const std::string& filename);
std::string hexString2String(std::string hexString);
std::string StringToHex(const unsigned char* data);
void printHash(unsigned char* md, int len);
std::string sha256(const std::string& input);
std::string sha224(const std::string& input);
std::string sha384(const std::string& input);
std::string sha512(const std::string& input);
bool compare_ignore_case(std::string& str1, std::string& str2);
void get_shared_secret(EC_GROUP* ec, std::string private_key_ifd, std::string public_key_chip, EC_POINT*& shared_secret);
void get_shared_secret(DH*& dh, std::string private_key_ifd, std::string public_key_chip, BIGNUM*& shared_secret);
void get_G_hat(EC_GROUP*& ec, EC_POINT*& H, std::string& s_str, const EC_POINT*& G, EC_POINT*& G_hat);
void get_G_hat(DH*& dh, BIGNUM*& H, std::string& s_str, const BIGNUM*& G, BIGNUM*& G_hat);
//gai le
void computeTIFD(std::string& KSmac, std::string& PKDH_ICC, std::string& oid, int keyLength, std::string& cipherAlgorithm, std::string& TIFD, int ecc_id);
void string2binary(std::string str, unsigned char* arr, int arr_len);
//gai le
int getNID(char idx);
std::string parseOID(std::string& oid_str);
std::string lengthtoHex(int length);
int hexStringToInt(std::string& str);
int binaryStringToInt(std::string& str);
std::string extractValueFromTLVBinaryString(std::string str, std::string& remainder);
std::string extractValueFromTLVBinaryString(std::string str);
std::string extractValueFromTLVHexString(std::string str);
std::string extractValueFromTLVHexString(std::string str, std::string& remainder);
bool fileExists(const std::string& fileName);
bool TestEcdsa(std::string& signature, std::string& randomData, std::string& DG15, EC_KEY*& eckey_pub);
std::wstring s2ws(const std::string& str);
extern void MakeFullPath1(char* fullpath, const char* path);
int ExtractECpkfromDG15(std::string dg15, EC_KEY*& ec_key);
bool ExtractECpkfromSOD(std::string sod, EC_KEY*& ec_key, std::string& pk);
bool getEckDirectlySODHexString(std::string sod, std::string& eck);
bool getEckPubkeyFromSOD(std::string& sod, std::string& pubKey);
bool getMsgfromSOD(std::string& sod, std::string& msg);
bool getSigfromSOD(std::string& sod, std::string& s, std::string& r);
bool SHA_X(std::string& sha_name, std::string& binaryInput, std::string& output);
bool checkDGs(std::unordered_map<int, std::string>& DGs, std::string& hash_type, std::string& sod, bool& integrity);
bool checkCSCA(std::string& sod, std::string& cipherFlag, std::string& hashFlag, int hashLength, std::string& country);
void aes_cbc_decode(const std::string& key, std::string& inputdata, std::string& dec, std::string& iv_str, int keyLength);
void aes_cbc_encode(const std::string& key, std::string& inputdata, std::string& enc, std::string& iv_str, int keyLength);
std::string hexToChar(std::string& hexstring);
std::string int2Hex(int val);
std::string lengthtoBinary(int length);
bool checkHashAndSignature(std::string& hex, std::string& Hash, std::string& Signature, int& HashLength);
bool checkmd(std::string& hash, const EVP_MD*& md);
void LogOpen();
void LogClose();
std::string base64ToHex(const std::string& base64String);
bool createDirectory(const std::string& path);
std::unordered_map<std::string, std::string> createCountryCodeMapReversed();
std::string getCurrentDateTimeFormatted();
void RemoveDir(const char* folderPath);
int EccOidToNid(std::string& ecc_oid);
bool extractPQGPKfromCAKeyInfo(std::string& keyinfo, std::string& p, std::string& q, std::string& g, DH*& dh);
int getLog2(BIGNUM* p);