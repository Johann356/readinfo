char PCSCReader::SecureCommunicationInternalAuthenticate(const std::string& KSenc,
	const std::string& KSmac,
	std::string& SSC,
	std::string& data,
	std::string& RND_IFD,
	std::string& cipherAlgorithm,
	int keyLength) {
	// 对未受保护的APDU命令进行填充
	std::string unprotectedAPDU("\x0C\x88\x00\x00", 4);
	std::string CmdHeader(unprotectedAPDU);
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(CmdHeader);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(CmdHeader);
	std::string strFillData = RND_IFD;


	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(strFillData);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(strFillData);
	// 用SKenc加密数据
	std::string strEncData;
	//KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	//加密SSC
	std::string iv = "";
	if (cipherAlgorithm == "AES")
		iv = "00000000000000000000000000000000";
	iv = HexStringToBinary(iv);
	IncreaseSSC(SSC); //SSC += 1
	auto KSenc_hex = BinaryToHexString(KSenc);
	if (cipherAlgorithm == "AES")
	{
		std::string SSC_IV;
		aes_cbc_encode(KSenc, SSC, SSC_IV, iv);
		auto SSC_IV_hex = BinaryToHexString(SSC_IV);
		auto strFillData_hex = BinaryToHexString(strFillData);
		aes_cbc_encode(KSenc, strFillData, strEncData, SSC_IV);
		auto strEncData_hex = BinaryToHexString(strEncData);
	}
	else if (cipherAlgorithm == "DESede")
	{
		KencTDES(strFillData, KSenc, strEncData, DES_ENCRYPT);
	}

	//构建d097
	std::string DO97;
	unsigned char x97 = 0x97;
	DO97.push_back(x97);
	DO97.push_back(1);
	DO97.push_back(0);

	// 构建DO87,并置cmdheader和DO87得到M
	std::string DO87;
	unsigned char L = (unsigned char)strFillData.size() + 1;
	unsigned char x87 = 0x87;
	DO87.push_back(x87);
	DO87.push_back(L);
	DO87.push_back(0x01);
	DO87.append(strEncData);
	std::string M = CmdHeader + DO87 + DO97;


	// 连接SSC和M，并增加填充得到N
	std::string N;
	N.append(SSC.data(), SSC.size());
	N.append(M.data(), M.size());
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(N);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(N);
	// 用SKmac计算N的消息认证码MAC
	std::string CCN;
	//KmacDES(N, KSmac, CCN);
	if (cipherAlgorithm == "AES")
		AESmac(KSmac, N, CCN, keyLength);
	else if (cipherAlgorithm == "DESede")
		KmacDES(N, KSmac, CCN);
	// 用CCN构建DO8E
	std::string DO8E("\x8E\x08", 2);
	DO8E.append(CCN.data(), CCN.size());

	// 构建受保护的APDU
	std::string APDU;
	std::string unprotectedAPDU2("\x0C\x88\x00\x00", 4);
	APDU.append(unprotectedAPDU2.data(), unprotectedAPDU2.size());
	unsigned char le_ = (unsigned char)DO87.size() + (unsigned char)DO8E.size() + (unsigned char)DO97.size();
	APDU.push_back(le_);//DO87+DO8E
	APDU.append(DO87.data(), DO87.size());
	APDU.append(DO97.data(), DO97.size());
	APDU.append(DO8E.data(), DO8E.size());
	/*
	 这里应该多加一个字节，中国护照可以不需要，但是国外的护照如果不加
	 这个字节，调用会失败
	 */
	APDU.push_back(0);
	// 发送APDU
	int dwLen = APDU.size();
	auto APDU_hex = BinaryToHexString(APDU);
	BYTE  RecvBuff[300];
	UINT SendLen;
	DWORD RecvLen;
	memset(RecvBuff, 0, sizeof(RecvBuff));
	RecvLen = sizeof(RecvBuff);
	this->Apdusend(APDU, RecvBuff, RecvLen);
	//cout << "SelectFile RAPDU： " << BYTE2string(RecvBuff, (UINT)RecvLen) << endl;
	std::string s((char*)&RecvBuff[0], RecvLen);
	std::string RAPDU;//无响应数据，只有SW1 SW2，DO99+8E+08+CC+SW1+SW2
	RAPDU.append(s);
	auto RAPDU_hex = BinaryToHexString(RAPDU);
#define DO99_COMPATIBLE 1
	// ------------------------------------------------------------
	// h.通过计算DO87和DO99并置的MAC, 验证RAPDU CC
	int tlLen = 0;
	std::string RAPDU_DO87 = RAPDUParse(RAPDU, 0x87, &tlLen);
	//    LOGI("SecureCommunicationReadBinary tlLen:%d", tlLen);
		/* 有时候请求200字节的大包时，读写器返回的数据包里没有DO99 TLV标签，
		   只有DO87和DO8E，目前看来DO99是固定的4个字节\x99\E02\x90\x00，这里
		   直接使用4字节常量，而不去RAPDU中取DO99，以免失败。
		   按规范Doc9303 Part1 Vol2.PDF之第IV节公钥基础设施IV-45的描述，DO99
		   应该是必须强制存在的，这里提供兼容性处理
		   */
#ifdef DO99_COMPATIBLE
	std::string RAPDU_DO99("\x99\x02\x90\x00", 4);
#else
	std::string RAPDU_DO99 = RAPDUParse(RAPDU, 0x99);
#endif
	std::string RAPDU_DO8E = RAPDUParse(RAPDU, 0x8E);
	RAPDU_DO99 = RAPDUParse(RAPDU, 0x99);

	// h.1 用1为SSC增值
	IncreaseSSC(SSC);

	// h.2 并置SSC, DO87和DO99，并增加填充
	std::string K(SSC);
	K += RAPDU_DO87;
	K += RAPDU_DO99;
	if (cipherAlgorithm == "AES")
		AesAddPaddingBytes(K);
	else if (cipherAlgorithm == "DESede")
		DesAddPaddingBytes(K);
	// h.3 用KSmac计算MAC
	std::string CC2;
	if (cipherAlgorithm == "AES")
		AESmac(KSmac, K, CC2, keyLength);
	else if (cipherAlgorithm == "DESede")
		KmacDES(K, KSmac, CC2);
	// h.4 将CC与RAPDU的DO8E数据作比较
	if (memcmp(CC2.data(), RAPDU_DO8E.data() + 2, 8) != 0) {
#if USE_LOG_LEVEL1
		LOGV("DO8E and CC2 mismatch in Reading binary");
#endif
		return false;
	}
	// i. 用KSenc解密DO87数据
	std::string RAPDU_DO87_DATA = RAPDU_DO87.substr(tlLen + 1);
	//KencTDES(RAPDU_DO87_DATA, KSenc, data, DES_DECRYPT);
	std::string iv_hex = "";
	std::string SSC_IV;
	if (cipherAlgorithm == "AES")
	{
		iv_hex = "00000000000000000000000000000000";
		auto iv = HexStringToBinary(iv_hex);
		aes_cbc_encode(KSenc, SSC, SSC_IV, iv);
		auto RAPDU_DO87_DATA_hex = BinaryToHexString(RAPDU_DO87_DATA);
		auto KSenc_hex = BinaryToHexString(KSenc);
		auto SSC_IV_hex = BinaryToHexString(SSC_IV);
		aes_cbc_decode(KSenc, RAPDU_DO87_DATA, data, SSC_IV, keyLength);
	}

	else if (cipherAlgorithm == "DESede")
	{
		auto RAPDU_DO87_DATA_hex = BinaryToHexString(RAPDU_DO87_DATA);
		auto KSenc_hex = BinaryToHexString(KSenc);
		KencTDES(RAPDU_DO87_DATA, KSenc, data, DES_DECRYPT);
	}
	DesRemovePaddingBytes(data);

	return true;

}