#include"PACEInfo.h"

PACEInfo::PACEInfo(std::string oid, int version, int parameterId)
{
	this->oid = oid;
	this->version = version;
	this->ParameterId = parameterId;
}

std::string PACEInfo::getOID()
{
	return this->oid;
}

std::string PACEInfo::getOIDString()
{
    if ("0.4.0.127.0.7.2.2.4.1.1" == (oid)) {
        return "id-PACE-DH-GM-3DES-CBC-CBC";
    }
    else if ("0.4.0.127.0.7.2.2.4.1.2" == (oid)) {
        return "id-PACE-DH-GM-AES-CBC-CMAC-128";
    }
    else if ("0.4.0.127.0.7.2.2.4.1.3" == (oid)) {
        return "id-PACE-DH-GM-AES-CBC-CMAC-192";
    }
    else if ("0.4.0.127.0.7.2.2.4.1.4" == (oid)) {
        return "id-PACE-DH-GM-AES-CBC-CMAC-256";
    }
    else if ("0.4.0.127.0.7.2.2.4.3.1" == (oid)) {
        return "id-PACE-DH-IM-3DES-CBC-CBC";
    }
    else if ("0.4.0.127.0.7.2.2.4.3.2" == (oid)) {
        return "id-PACE-DH-IM-AES-CBC-CMAC-128";
    }
    else if ("0.4.0.127.0.7.2.2.4.3.3" == (oid)) {
        return "id-PACE-DH-IM-AES-CBC-CMAC-192";
    }
    else if ("0.4.0.127.0.7.2.2.4.3.4" == (oid)) {
        return "id-PACE_DH-IM-AES-CBC-CMAC-256";
    }
    else if ("0.4.0.127.0.7.2.2.4.2.1" == (oid)) {
        return "id-PACE-ECDH-GM-3DES-CBC-CBC";
    }
    else if ("0.4.0.127.0.7.2.2.4.2.2" == (oid)) {
        return "id-PACE-ECDH-GM-AES-CBC-CMAC-128";
    }
    else if ("0.4.0.127.0.7.2.2.4.2.3" == (oid)) {
        return "id-PACE-ECDH-GM-AES-CBC-CMAC-192";
    }
    else if ("0.4.0.127.0.7.2.2.4.2.4" == (oid)) {
        return "id-PACE-ECDH-GM-AES-CBC-CMAC-256";
    }
    else if ("0.4.0.127.0.7.2.2.4.4.1" == (oid)) {
        return "id-PACE-ECDH-IM_3DES-CBC-CBC";
    }
    else if ("0.4.0.127.0.7.2.2.4.4.2" == (oid)) {
        return "id-PACE-ECDH-IM-AES-CBC-CMAC-128";
    }
    else if ("0.4.0.127.0.7.2.2.4.4.3" == (oid)) {
        return "id-PACE-ECDH-IM-AES-CBC-CMAC-192";
    }
    else if ("0.4.0.127.0.7.2.2.4.4.4" == (oid)) {
        return "id-PACE-ECDH-IM-AES-CBC-CMAC-256";
    }
    else if ("0.4.0.127.0.7.2.2.4.6.2" == (oid)) {
        return "id-PACE-ECDH-CAM-AES-CBC-CMAC-128";
    }
    else if ("0.4.0.127.0.7.2.2.4.6.3" == (oid)) {
        return "id-PACE-ECDH-CAM-AES-CBC-CMAC-192";
    }
    else {
        return "0.4.0.127.0.7.2.2.4.6.4" == (oid) ? "id-PACE-ECDH-CAM-AES-CBC-CMAC-256" : oid;
    }
}

std::string PACEInfo::toMappingType(std::string& oid)
{
    if ((!("0.4.0.127.0.7.2.2.4.1.1" == (oid))) && (!("0.4.0.127.0.7.2.2.4.1.2" == (oid))) && (!("0.4.0.127.0.7.2.2.4.1.3" == (oid))) && (!("0.4.0.127.0.7.2.2.4.1.4" == (oid))) && (!("0.4.0.127.0.7.2.2.4.2.1" == (oid))) && (!("0.4.0.127.0.7.2.2.4.2.2" == (oid))) && (!("0.4.0.127.0.7.2.2.4.2.3" == (oid))) && (!("0.4.0.127.0.7.2.2.4.2.4" == (oid)))) {
        if ((!("0.4.0.127.0.7.2.2.4.3.1" == (oid))) && (!("0.4.0.127.0.7.2.2.4.3.2" == (oid))) && (!("0.4.0.127.0.7.2.2.4.3.3" == (oid))) && (!("0.4.0.127.0.7.2.2.4.3.4" == (oid))) && (!("0.4.0.127.0.7.2.2.4.4.1" == (oid))) && (!("0.4.0.127.0.7.2.2.4.4.2" == (oid))) && (!("0.4.0.127.0.7.2.2.4.4.3" == (oid))) && (!("0.4.0.127.0.7.2.2.4.4.4" == (oid)))) {
            if ((!("0.4.0.127.0.7.2.2.4.6.2" == (oid))) && (!("0.4.0.127.0.7.2.2.4.6.3" == (oid))) && (!("0.4.0.127.0.7.2.2.4.6.4" == (oid)))) {
                std::cout << "Unknown OID: \"" + oid + "\"" << std::endl;
            }
            else {
                return "CAM";
            }
        }
        else {
            return "IM";
        }
    }
    else {
        return "GM";
    }
}

std::string PACEInfo::toKeyAgreementAlgorithm(std::string& oid) {
    if (!("0.4.0.127.0.7.2.2.4.1.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.1.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.1.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.1.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.4" == (oid))) {
        if (!("0.4.0.127.0.7.2.2.4.2.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.4" == (oid))) {
            std::cout << "Unknown OID: \"" + oid + "\"" << std::endl;
        }
        else {
            return "ECDH";
        }
    }
    else {
        return "DH";
    }
}

std::string PACEInfo::toCipherAlgorithm(std::string& oid) {
    if (!("0.4.0.127.0.7.2.2.4.1.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.1" == (oid))) {
        if (!("0.4.0.127.0.7.2.2.4.1.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.1.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.1.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.4" == (oid))) {
            std::cout << "Unknown OID: \"" + oid + "\"" << std::endl;
        }
        else {
            return "AES";
        }
    }
    else {
        return "DESede";
    }
}

std::string PACEInfo::toDigestAlgorithm(std::string& oid) {
    if (!("0.4.0.127.0.7.2.2.4.1.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.1.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.2" == (oid))) {
        if (!("0.4.0.127.0.7.2.2.4.1.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.1.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.4" == (oid))) {
            std::cout << "Unknown OID: \"" + oid + "\"" << std::endl;
        }
        else {
            return "SHA-256";
        }
    }
    else {
        return "SHA-1";
    }
}

int PACEInfo::toKeyLength(std::string& oid) {
    if (!("0.4.0.127.0.7.2.2.4.1.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.1" == (oid)) && !("0.4.0.127.0.7.2.2.4.1.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.2" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.2" == (oid))) {
        if (!("0.4.0.127.0.7.2.2.4.1.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.3" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.3" == (oid))) {
            if (!("0.4.0.127.0.7.2.2.4.1.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.3.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.2.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.4.4" == (oid)) && !("0.4.0.127.0.7.2.2.4.6.4" == (oid))) {
                std::cout << "Unknown OID: \"" + oid + "\"" << std::endl;
            }
            else {
                return 256;
            }
        }
        else {
            return 192;
        }
    }
    else {
        return 128;
    }
}