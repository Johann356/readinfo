#pragma once
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

class PACEInfo {
public:
	PACEInfo();
	PACEInfo(std::string oid, int version, int parameterId, std::string oid_origion);
	char getParameterId();
	std::string getOIDorigion();
	std::string getOID();
	std::string getOIDString();
	std::string toMappingType(std::string& oid);
	std::string toKeyAgreementAlgorithm(std::string& oid);
	std::string toCipherAlgorithm(std::string& oid);
	std::string toDigestAlgorithm(std::string& oid);
	int toKeyLength(std::string& oid);

private:
	std::string oid;
	int version;
	int ParameterId;
	std::string oid_origion;
public:
	
};