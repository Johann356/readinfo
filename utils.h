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

using namespace std;

std::string StringToHex(const std::string& data);
std::string HexToString(const std::string& data);
std::string hexToBase64(const std::string& hexString);
std::string rsa_pub_decrypt(std::string& cipherText, const std::string& pubKey);
std::string ReadFileContentsAsHex(const std::string& filename);
std::string hexString2String(std::string hexString);
std::string StringToHex(const unsigned char* data);
std::string sha256(const std::string& input);
bool compare_ignore_case(std::string& str1, std::string& str2);