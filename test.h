#pragma once
#include <string>
#include "utils.h"
#include "Ptypes.h"
#include <iostream>
#include <set>
#include "JP2.h"
#include <fstream>
#include <chrono>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/dh.h>
#include "CAInfo.h"
int Buildsecp256r11(EC_GROUP*& ec_group);
int testCA();
int testRSAPSS();
int testAAECDSA();
int testECDSA();
int testPA();
int testJP2(std::string& data, std::string filename, int& width, int& height, int& size, int& version);
void testIM();
int testDH();
void testECDHIM();