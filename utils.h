#pragma once
#include "WinError.h"
#include<string>
#include<iostream>
#include <string>
#include <fstream>
#include <sstream>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <map>
#include <vector>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include<algorithm>
#include <openssl/cmac.h>


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
void get_G_hat(EC_GROUP* ec, EC_POINT* H, std::string s_str, const EC_POINT* G, EC_POINT* G_hat);
void get_G_hat(DH*& dh, BIGNUM*& H, std::string s_str, const BIGNUM*& G, BIGNUM*& G_hat);
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