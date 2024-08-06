#pragma once
#include <string>
#include <openssl/ec.h>
#include <openssl/dh.h>
#define CA_CBC 0
#define CA_AES 1
#define CA_DH 0
#define CA_ECDH 1
#define CA_UNKNOWN -1
class CAInfo
{
public:
	CAInfo()
	{
		AlgorithmOid="";
		Id=-1;
		CipherAlgorithm=-1;
		CipherLength=-1;
		AgreementType=-1;
		PublicKeyString="";
		Key = EC_KEY_new();
		dh = DH_new();
	}
	CAInfo(std::string& AlgorithmOid, std::string& publicKeyString, int& Id);
	~CAInfo() {};

	int getId()
	{
		return Id;
	}
	std::string getPublicKeyString()
	{
		return PublicKeyString;
	}
	int getCipherAlgorithm()
	{
		return CipherAlgorithm;
	}
	int getCipherLength()
	{
		return CipherLength;
	}
	int getAgreementType()
	{
		return AgreementType;
	}
	std::string getAlgorithmOid()
	{
		return AlgorithmOid;
	}
	EC_KEY* getKey()
	{
		return Key;
	}
	DH* getDH()
	{
		return dh;
	}

private:
	std::string AlgorithmOid;
	int Id;
	int CipherAlgorithm;
	int CipherLength;
	int AgreementType;
	std::string PublicKeyString;
	EC_KEY* Key;
	DH* dh;
	bool ResolveOid();
	bool ResolvePublicKey();
};
