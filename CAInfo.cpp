#include "CAInfo.h"
#include <assert.h>
#include "glog\logging.h"
#include "utils.h"
CAInfo::CAInfo(std::string& AlgorithmOid, std::string& publicKeyString, int& Id)
{
	this->AlgorithmOid = AlgorithmOid;
	this->PublicKeyString = publicKeyString;
	this->Id = Id;
	ResolveOid();
	ResolvePublicKey();
}
bool CAInfo::ResolveOid()
{
	std::string oidhead("\x06\x0A\x04\x00\x7F\x00\x07\x02\x02\x03", 10);
	if (this->AlgorithmOid.substr(0, 10) != oidhead || this->AlgorithmOid.length() != 12)
	{
		LOG(ERROR) << "CA OID ERROR, ERROR OID: " << this->AlgorithmOid;
		return false;
	}
	if (this->AlgorithmOid[10] == '\x02')
		this->AgreementType = CA_ECDH;
	else if(this->AlgorithmOid[10] == '\x01')
		this->AgreementType = CA_DH;
	else
	{
		this->AgreementType = CA_UNKNOWN;
	}
	if(this->AlgorithmOid[11] == '\01')
	{
		this->CipherAlgorithm = CA_CBC;
		this->CipherLength = 128;
	}
	else if (this->AlgorithmOid[11] == '\02')
	{
		this->CipherAlgorithm = CA_AES;
		this->CipherLength = 128;
	}
	else if (this->AlgorithmOid[11] == '\03')
	{
		this->CipherAlgorithm = CA_AES;
		this->CipherLength = 192;
	}
	else if (this->AlgorithmOid[11] == '\04')
	{
		this->CipherAlgorithm = CA_AES;
		this->CipherLength = 256;
	}
	else
	{
		this->CipherAlgorithm = CA_UNKNOWN;
		this->CipherLength = CA_UNKNOWN;
	}
}
bool CAInfo::ResolvePublicKey()
{
	if (this->AgreementType == CA_ECDH)
	{
		EC_KEY* key = EC_KEY_new();
		std::string pk;
		int ret = ExtractECpkfromSOD(PublicKeyString, key, pk);
		this->Key = key;
		this->PublicKeyString = pk;
		return ret;
	}
	if (this->AgreementType == CA_DH)
	{
		std::string p, q, g;
		int ret = extractPQGPKfromCAKeyInfo(PublicKeyString, p, q, g, dh);
		if (!ret)
		{
			LOG(ERROR) << "RESOLVE CA DH ERROR";
			return false;
		}
		LOG(INFO) << "RESOLVE P " << p << endl << "RESOLVE Q " << q << endl << "RESOLVE G " << g << endl;
		return true;
	}
	
}