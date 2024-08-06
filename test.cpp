#include "test.h"
#include <opencv2\opencv.hpp>

int Buildsecp256r11(EC_GROUP*& ec_group)
{
	int ret = -1;
	ec_group = EC_GROUP_new(EC_GFp_mont_method());
	// 设置椭圆曲线的参数
	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	ret = BN_hex2bn(&p, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
	ret = BN_hex2bn(&a, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
	ret = BN_hex2bn(&b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
	ec_group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	EC_POINT* G = EC_POINT_new(ec_group);
	BIGNUM* xG = BN_new();
	BIGNUM* yG = BN_new();
	ret = BN_hex2bn(&xG, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
	ret = BN_hex2bn(&yG, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
	ret = EC_POINT_set_affine_coordinates_GFp(ec_group, G, xG, yG, ctx);

	BIGNUM* order = BN_new();
	ret = BN_hex2bn(&order, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
	BIGNUM* cofactor = BN_new();
	ret = BN_hex2bn(&cofactor, "1");
	ret = EC_GROUP_set_generator(ec_group, G, order, cofactor);
	return 1;
}
int testCA()
{
	std::string dg14path = "D:\\projects\\PCSC\\data\\DG14\\D.dat";
	fstream f(dg14path, std::ios::in | std::ios::binary);
	std::string dg14binary;
	if (f.is_open())
	{
		;
	}
	return 0;
}
int testRSAPSS()
{

	int ret;
	auto start = std::chrono::high_resolution_clock::now();

	//std::string write = "308201A0300D06092A864886F70D01010105000382018D00308201880282018100BCCA84C12AAABDC2371193537DBE6DD9D9E81ECABCD32054487DF6A9EF1DCDA021FCAAEA028ECE0FF135A70F97B49F280DB497F8FF54E21977F024014B049DEE0E1DFF1302DDFCC2EC9DE97B69C3202E2E89285C8C8874F03F562F14015A0652A6B7ACA5849354592141DC6129E7537DADB091164BF1F3FB1199807A08D80B917B8369B0C7A435CCCCAB894BBD4C7A539443500E2A6F83F017C364506E3C28AE5DB07DACC683A1EEEA6EAD7D591845E9935589216E7DFEE6980FFE99DF534F54DC7B17673D7343D44FD0B943D0DE74E4762DA0F8C77ABCB37DBE328EF8C0E42DC68EF87D1BE4DFBF7601FECF5A63985B6566F5D1DE1F65A143CC438A6E9E563E5AC97C09876BC1608B9B7DBB613B3F687F52A79BBD3A442362C916410F976749BD129BE46DB6386BAF357F1B489DA21F51E600A93B0A4CCEACEC2580CCB5D1E13F99D753B66237992A05437DC652E11F99B41DD0A00EFF59EA4DFC009D72046FA712A69D0F951F906D5466FAC78525CB0125D11485A0F735EF0356958ED9678B020103";
	//std::string wb = HexStringToBinary(write);
	//fstream f("D:\\projects\\PCSC\\data\\CA\\PKD\\KR\\CSCA.dat", ios::out | ios::binary);
	//if (!f)
	//{
	//	LOG(INFO)<< "not opened";
	//}
	//else
	//{
	//	f.write(wb.data(), wb.size());
	//	f.close();
	//}
	//30820120300D06092A864886F70D01010105000382010D00308201080282010100C79F5FD47D70742BAB99573D379CD41B069C5E0AF454374F8C766CDFDFB6BEEB35FB5BA6193E04FAD242D2AF7DF227FA9221C1E49DAEAB1D3DE8557FDC4FF15F9CCD33F2C450F5C3A682A4C8096028B38CC0A755F8A517546436515235C421D9620E8AAD3AAEE916FB28EFE4D102640D92F358DBE843AE4B0D210CDF3CB68642CDA4D2521D566F9CDE402E84CDAF98BE16FFA4E59F570C5CF57AF846F26DE0A80AC157EDC139478A58B3CB89983BFB1EABA032A1D2B89A15831963060D54D920B3A10F153A52C461F247BD337F8E9738EC3BCD2DB12BD4ECDACE3B8201D47C19BD0E129AFF5811BEC468A6C6D7CC1737E4276521E593FF495A8B4B90D4A12927020103
	//C4A8159BA971B5DD7E181F71E9D3F21CDA7F6E0E6132052299076780A53C38C2813E6D6E0D071F3D2334298BB8691ADF724668D9A8A4744952C3D5CB9C4C9687BF80B64B9CD088CE18A1ECD51AE5F4506D95DBE86DF7F7BCBC364A7EFB75FB33F2DBAFDE4D8465D5F62A91F770C98614286EBFD41A68A25A89D7124D8D676A15BB6028BB40F4F9B5F1DF8FEF6B929A27ADEA417B410E2DB90761C392811D49C7DF6220067B5E2495ABB2FF61359FE954AE796D03F0BE247E5024BDC8450C18A9551014DFEFB9AE3EC5F6F8795DDB3E5A25C791FB78BAA56157C08BED3D048132C116BEA654E7FE07C8FEE63D3AC862634D81ADCA9EA803BB94517501F52F0387
	//3148301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420B3F1D672FCB4699FB70D8F29D05C67354B0CE58BDE382E047F1D992F9C1792C7
	std::string base64str = hexToBase64("308201A2300D06092A864886F70D01010105000382018F003082018A0282018100CA34E3D2C981022D770A870E0F9AD8EC78EF6944FB605187767A489DECD16ACD21D30CBFE4E2EBD3F0EDDE293D44099D99D9FDF6016D95AE716D7E6E23327A6864C513D0B4B376A37E4889BB9608F8AF72DCC25B7A59828320871CCE8BB08010920BE9FC2367E1D390C5CB0B94E194D3358D5A42501542B340DF80675C429D06CCCEB530FA958D3D5E4EF951A89B38686D13F49F99D04FB621660107F94153D67433FB5159732772414F976C1B7AB15BBF57A4F2D532E513919D1C96D93D3EE2C881D8320AAA9966DB9ADE054294A64A307968FCFDB8B0BF121AE40D0CA0AE73D0D1F43995DDC57E6627E62153CACB70E122A0E8960939897D9ED9A5D0D993C2C8DF4505879BAE46240667C9255C1A5C01B64BAA9AA1E599D2F069B366FB3921FB2F8133DB27D216E7B7B4634407FB3F4BA3090D33689DDEDE329E3E96658201AAC6260EE8831D6B8A8A7EAF2D1512F4B8C3BBC475303F83745DD4BCC5FA735BE3E3BA6BEE1425A52C3E05C0421D6D5DBDB3D37B97AFB3768C6512B0FAE536850203010001");
	std::string pubKey = "-----BEGIN PUBLIC KEY-----\n" + base64str + "\n" + "-----END PUBLIC KEY-----\n";

	std::string enc = hexString2String("2A26D35F5ECF27A4951AADF43A6EA160C2221D750BF679D9DF8AB61BDFDFB76651A6D22C6DF34A82F4E5714C579761331E4C39188D4CD5C0B4A4E1C736FD57A0A6663AA4BA81BD13A2EE64FD8C6B7D03EA38FFF7AF8463F855435330C76C1F9E4C6EBF920125ADAA8779646D591570B43FAA710DE45FE622241E0FD29A6BB1172667067C92A3DF0B739700F3C970B3BDDD7E6CE28CA2FE922CCF4B0AC14E7FD780D222B52E8F8C13E14DCBDC5CB14A586DF05C40A94A3652C91DE9160A489A80378A1DB14AF67FF115C48EB70DFC8B70A5AFF71541E76F2D266638E3EB87D8238AA7A0D8FCFB9699178C3B9C0F8BCDA63D4B8C4D640023C481A8379E554B30D1EDF92B5CF52BF8822730B3F020103C288B9AD4C74367A7F74831D071EAEE738F37A0A956F22D3D6C0A714DFC72871A8AA4C9E79B36AD440FE4108BF1613E0B8DFD5094F7380AE20896E5E0DEA9F1E3C3A12366FA79C8E954EC5597B930FBAC0D64EFC1AD2000C3B357997E65F0EFCBE68177A1B56857BD9FD649AF3AA44F9114");
	size_t enc_len = enc.length();
	std::string message = HexStringToBinary("30820358A00302010202044F280191304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203081A0310B3009060355040613024D5931233021060355040A0C1A4A61626174616E20496D6967726573656E204D616C6179736961310B300906035504080C0257503112301006035504070C0950757472616A61796131293027060355040B0C20426168616769616E204B6573656C616D6174616E2064616E20506173706F72743120301E06035504030C174D616C617973696120436F756E747279205369676E6572301E170D3136303432313130343332305A170D3232303432313131313332305A3081BC310B3009060355040613024D5931233021060355040A0C1A4A61626174616E20496D6967726573656E204D616C6179736961311C301A06035504080C1357696C617961682050657273656B757475616E3121301F06035504070C184B75616C61204C756D70757220262050757472616A61796131293027060355040B0C20426168616769616E204B6573656C616D6174616E2064616E20506173706F7274311C301A06035504030C134D616C617973696120446F63205369676E657230820122300D06092A864886F70D01010105000382010F003082010A02820101009AF360581B0A16F67256F8833C3EFCEC9D71F1EAEC0EC5EAEAE16844D28D6AE8DB770FCBAE497B5E834C496694361344764D7745350DD494E550B424011F7E7F5AB85C218B96F7BC0AE2A9FB9F60EDAD2F24ABA15D9C546AD2E741718DA8268B69FB1F6590FFC362DA9A5F6F8092E81EB9AE69EE35983A2039AF7C42D1074A92F44D772103FE3DD6F968910C16CEB6C8C96240868B4EBD5C2311133A977B7A8B2516D482806A390BE8FDC03016DF67B547656782AC018EE8AAEE881DFF94CF4747A081D6D12F60F941A0CF518783714361D966169851A28F0B8E35F2CBF0DEC3437116F7C77FEB57DBD0661F45883B0CF70285D60AD2393341126AB3619C155F0203010001A360305E300E0603551D0F0101FF040403020780302B0603551D1004243022800F32303136303432313130343332305A810F32303137303432383232313332305A301F0603551D23041830168014B0507E0BF633066293F749B9392C4B2C4A38D2FE");
	size_t message_len = message.length();
	std::string strRet;
	RSA* rsa = RSA_new();
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char* decryptedText = (char*)malloc(len + 1);
	memset(decryptedText, 0, len + 1);
	ret = RSA_public_decrypt(enc_len, (unsigned char*)enc.c_str(), (unsigned char*)decryptedText, rsa, RSA_NO_PADDING);
	std::string res(decryptedText, ret);
	std::string message_hash(32, 0);
	SHA256((unsigned char*)message.c_str(), message_len, (unsigned char*)message_hash.data());
	std::string res_hex = BinaryToHexString(res);


	ret = RSA_verify_PKCS1_PSS_mgf1(rsa, (unsigned char*)message_hash.c_str(), EVP_sha256(), EVP_sha256(), (unsigned char*)res.c_str(), 32);

	auto end = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

	LOG(INFO)<< duration.count() << "milliseconds";
	return ret;
}
void CheckParity1(
	const std::string& srcChar,
	std::string& dstChar,
	int nLen) {
	unsigned char sinChar;
	short minBit = 0;
	short count = 0;

	if (dstChar.size() != srcChar.size())
		dstChar.resize(nLen);//分配内存

	for (int i = 0; i < nLen; i++) {
		count = 0;
		sinChar = srcChar[i];
		minBit = sinChar % 2;
		for (int j = 0; j < 8; j++) {
			if (sinChar % 2 == 1)
				count++;

			sinChar >>= 1;
		}
		if (count % 2 == 1)
			dstChar[i] = srcChar[i];
		else if (minBit == 1)
			dstChar[i] = srcChar[i] - 1;
		else
			dstChar[i] = srcChar[i] + 1;
	}
}
int testECDSA()
{


	auto start = std::chrono::high_resolution_clock::now();

	system("chcp 65001");
	LogOpen();
	int ret = -1;
	EC_KEY* ec_key = EC_KEY_new();
	std::string pk = "308201B53082014D06072A8648CE3D020130820140020101303C06072A8648CE3D0101023100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF30640430FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC0430B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF046104AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F023100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC5297302010103620004D839C3EB261454194984679F06E269A89479A85C24998DDF32CD52AB1DCE287CF3EAE5C57BCCF4A819F88F6B1B9977656C0CB60ED8D3A10CEF81BE68EBE2326FD9BED31CAD0765A584ABE53B91477EFDE925A684CBCBA9B61FCA6E77AAC66E47";
	std::string ss;
	ret = ExtractECpkfromSOD(pk, ec_key, ss);
	std::string sig = "03690030660231009D7C4377C7276BC48360343ED98D7B5512E07582F8E46C677FA9CFF0EF0A5E58CF53453FC8E32E96838FC2DC710A0AA6023100AD3BC2F8CD9354251CF79C86CBEEE997803D4F1E3ABAE1A175493D77526B908FAFCEE64C8D18E19968C0ED0AE268A7C9";
	std::string message_hex = "30820457A003020102020868CA1355D6143B39300A06082A8648CE3D0403023072310B3009060355040613024E5A31223020060355040A0C19476F7665726E6D656E74206F66204E6577205A65616C616E6431273025060355040B0C1E4964656E7469747920616E642050617373706F72742053657276696365733116301406035504030C0D50617373706F72742043534341301E170D3230313032373032303733315A170D3331303232323032303733315A308197310B3009060355040613024E5A31223020060355040A0C19476F7665726E6D656E74206F66204E6577205A65616C616E6431273025060355040B0C1E4964656E7469747920616E642050617373706F727420536572766963657331143012060355040B0C0B50617373706F72742043413125302306035504030C1C446F63756D656E74205369676E657220323032303130323730303236308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF30440420FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC04205AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B0441046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5022100FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551020101034200048CEB664ECCF6524CD52890CE12067D94AF839FC14428267E5305061E526B8D4950FA7D18B21D9385776E63BED399142B7A27384F79ABC3903FA1C1BAFE836CD9A38201D3308201CF3015060767810801010602040A30080201003103130150301F0603551D23041830168014D69E153BDF94986C1AD2E981ADADC331AF71BE71303A0603551D1204333031A410300E310C300A06035504070C034E5A4C861D68747470733A2F2F7777772E70617373706F7274732E676F76742E6E7A303A0603551D1104333031A410300E310C300A06035504070C034E5A4C861D68747470733A2F2F7777772E70617373706F7274732E676F76742E6E7A30520603551D20044B30493047060860842A6508010103303B303906082B06010505070201162D68747470733A2F2F7777772E706B692E676F76742E6E7A2F706F6C6963792F6550617373706F7274735F435053306D0603551D1F046630643030A02EA02C862A68747470733A2F2F706B64646F776E6C6F6164312E6963616F2E696E742F43524C732F4E5A4C2E63726C3030A02EA02C862A68747470733A2F2F706B64646F776E6C6F6164322E6963616F2E696E742F43524C732F4E5A4C2E63726C301D0603551D0E04160414499BBD75FEF1BC2AFC99B39D819804F980AD6A59302B0603551D1004243022800F32303230313032373032303733315A810F32303231303232343032303733315A300E0603551D0F0101FF040403020780";
	std::string message = HexStringToBinary(message_hex);
	std::string temp = extractValueFromTLVHexString(sig);
	temp = extractValueFromTLVHexString(temp);
	std::string r, s;
	r = extractValueFromTLVHexString(temp, s);
	s = extractValueFromTLVHexString(s);
	BIGNUM* r_bn = BN_new();
	BIGNUM* s_bn = BN_new();
	ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();

	ret = BN_hex2bn(&r_bn, r.c_str());
	ret = BN_hex2bn(&s_bn, s.c_str());
	ret = ECDSA_SIG_set0(ecdsaSig, r_bn, s_bn);

	std::string hashres(SHA256_DIGEST_LENGTH, '\0');
	SHA256((BYTE*)message.data(), message.size(), (BYTE*)hashres.data());
	std::string hashres_hex = BinaryToHexString(hashres);
	ret = ECDSA_do_verify((unsigned char*)hashres.c_str(), hashres.size(), ecdsaSig, ec_key);

	LogClose();
	auto end = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

	LOG(INFO)<< duration.count() << "milliseconds";
	return 1;
}
int testAAECDSA()
{


	int ret;
	std::string pk = "307A301406072A8648CE3D020106092B240303020801010B036200045E9476FA91B20B5C2BCEFC426CAF551643C2E8FC304ED34C75EC8AC366DDB8AB78B01C07021254CCBA7BB60EB4EE6A2B5EFFE8CB8498B593B1885EF16CDB0F60FD703D1C9C35FCAE3FBD5F2ADAE53757DFF2A8B0A363B587DD3790D1B1385F4E";
	pk = hexToBase64(pk);
	pk = "-----BEGIN PUBLIC KEY-----\n" + pk + "\n-----END PUBLIC KEY-----\n";
	BIO* bio = BIO_new_mem_buf((unsigned char*)pk.c_str(), -1);
	if (!bio) {
		std::cerr << "Failed to create memory BIO." << std::endl;
		return -1;
	}

	// 从内存中的 PEM 数据读取公钥
	EC_KEY* ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
	if (!ec_key) {
		std::cerr << "Failed to read EC Public Key from the string." << std::endl;
		BIO_free(bio);
		return -1;
	}
	EC_GROUP* ec_group = EC_GROUP_new(EC_GFp_mont_method());
	ec_group = EC_GROUP_new_by_curve_name(NID_brainpoolP384r1);
	const EC_POINT* g = EC_GROUP_get0_generator(ec_group);
	BIGNUM* p = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	ret = EC_GROUP_get_curve(ec_group, p, nullptr, nullptr, ctx);
	const BIGNUM* order = BN_new();
	order = EC_GROUP_get0_order(ec_group);
	LOG(INFO)<< "order " << BN_bn2hex(order) << "\n";
	const EC_POINT* pkk = EC_POINT_new(ec_group);
	pkk = EC_KEY_get0_public_key(ec_key);
	ret = EC_KEY_check_key(ec_key);
	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group, pkk, x, y, NULL);

	LOG(INFO)<< "EC Point: (" << BN_bn2hex(x) << ", " << BN_bn2hex(y) << ")\n";
	std::string sig = "34421e45d16a11773caaccd1b9f27910a66fbad2f35f5d3300e8358d6aa8b1084ff6b18350f471999d2016038a6c1e843c561db12f09d752614503cebb63597154b61a0eb09d28b20e9374f4386c4dd4cfdef07e462ec4523193bea679c1bb72";
	std::string rnd = "ba698198149cabe9";
	rnd = HexStringToBinary(rnd);
	std::string r = sig.substr(0, sig.length() / 2);
	std::string s = sig.substr(sig.length() / 2);
	std::string sig_binary = HexStringToBinary(sig);
	BIGNUM* r_bn = BN_new();
	BIGNUM* s_bn = BN_new();

	ret = BN_hex2bn(&r_bn, r.c_str());
	ret = BN_hex2bn(&s_bn, s.c_str());
	BIGNUM* s1 = BN_new();
	BN_mod_inverse(s1, s_bn, order, ctx);
	LOG(INFO)<< "s1 " << BN_bn2hex(s1) << "\n";
	std::string hashres(SHA384_DIGEST_LENGTH, '\0');
	SHA384((BYTE*)rnd.data(), rnd.size(), (BYTE*)hashres.data());
	std::string hashres_hex = BinaryToHexString(hashres);
	BIGNUM* Hm = BN_new();
	BN_hex2bn(&Hm, hashres_hex.c_str());
	LOG(INFO)<< "Hm " << BN_bn2hex(Hm) << "\n";
	BIGNUM* Hms1 = BN_new();
	ret = BN_mod_mul(Hms1, Hm, s1, order, ctx);
	LOG(INFO)<< "Hm*s1 " << BN_bn2hex(Hms1) << "\n";
	BIGNUM* rs1 = BN_new();
	ret = BN_mod_mul(rs1, r_bn, s1, order, ctx);
	LOG(INFO)<< "r*s1 " << BN_bn2hex(rs1) << "\n";
	EC_POINT* R = EC_POINT_new(ec_group);
	EC_POINT_mul(ec_group, R, Hms1, pkk, rs1, ctx);
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group, R, x, y, ctx);

	LOG(INFO)<< "R Point: (" << BN_bn2hex(x) << ", " << BN_bn2hex(y) << ")\n";
	ret = BN_mod(x, x, order, ctx);
	ret = BN_mod(r_bn, r_bn, order, ctx);

	LOG(INFO)<< "rx " << BN_bn2hex(x) << "\n";
	LOG(INFO)<< "r " << BN_bn2hex(r_bn) << "\n";
	// 验证签名
	ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();
	if (!ecdsaSig) {
		// 错误处理
		EC_KEY_free(ec_key);
		return false;
	}
	ret = ECDSA_SIG_set0(ecdsaSig, r_bn, s_bn);

	ret = ECDSA_do_verify((unsigned char*)hashres.c_str(), hashres.size(), ecdsaSig, ec_key);
	ECDSA_SIG_free(ecdsaSig);
	EC_KEY_free(ec_key);

	// 清理错误栈
	ERR_free_strings();
}
int testPA() {
	std::string SOD_file_path = "D:\\projects\\PCSC\\data\\SOD\\MYS\\EF_SOD4.dat";
	std::string country;
	std::string hash, signature;
	int hashLength;
	//std::unordered_map<int, std::string>& DGs;
	//if (!checkDGs(DGs, hash, hex)) {
	//return false;
	//}
	//std::string data = DGs[EF_DG1];
	//std::string flag("\x5F\x1F", 2);
	//size_t it = data.find(flag);
	//if (it == std::string::npos) {
	//	//LOGE("EF_DG1_FileParse:it == std::string::npos\n");
	//	return false;
	//}
	//std::string mrz = data.substr(it + 3);
	//std::string country = mrz.substr(2, 3);
	////country = "IDN";
	//for (int i = 2; i >= 0; i--)
	//{
	//	if (country[i] == '<')
	//		country = country.substr(0, i + 1);
	//}
	std::string hex = ReadFileContentsAsHex(SOD_file_path);
	if (!hex.length())
	{
		LOG(INFO) << "READ EF_SOD EMPTY.\n";
		return -1;
	}
	std::string countrynameTag = "0603550406";
	size_t pos = hex.find(countrynameTag);
	std::string temp = hex.substr(pos);
	std::string countryname;
	extractValueFromTLVHexString(temp, temp);
	country = extractValueFromTLVHexString(temp);
	char ch = 0;
	std::string name = "";
	for (int i = 0; i < country.length(); i++)
		country[i] = country[i] >= 'A' && country[i] <= 'Z' ? country[i] + 'a' - 'A' : country[i];
	for (int i = 0; i < country.length() / 2; i++)
	{
		if (country[i * 2] >= '0' && country[i * 2] <= '9')
			ch += (country[i * 2] - '0') * 16;
		else
			ch += (country[i * 2] - 'a' + 10) * 16;
		if (country[i * 2 + 1] >= '0' && country[i * 2 + 1] <= '9')
			ch += (country[i * 2 + 1] - '0');
		else
			ch += (country[i * 2 + 1] - 'a' + 10);
		name.push_back(ch);
		ch = 0;
	}
	for (int i = 0; i < name.size(); i++)
		if (name[i] >= 'a' && name[i] <= 'z')
			name[i] = name[i] + ('A' - 'a');
	country = name;
	size_t DGHashHead = hex.find("A082");
	size_t CSCAHead = hex.rfind("A082");
	size_t SODSignatureHead = hex.rfind("3182");
	if (SODSignatureHead == hex.npos)
		SODSignatureHead = hex.rfind("3181");
	//check DGs hash
	std::string hex_temp = hex.substr(DGHashHead, CSCAHead - DGHashHead);
	checkHashAndSignature(hex_temp, hash, signature, hashLength);
	LOG(INFO) << "DGs hash algorithm:" << hash << '\n';
	/*if (!checkDGs(DGs, hash, hex)) {
		return false;
	}*/
	hex_temp = hex.substr(SODSignatureHead);
	checkHashAndSignature(hex_temp, hash, signature, hashLength);
	if (hex.size() < 1000) {
		return false;
	}
	LOG(INFO) << "PA, HASH ALGORITHM " << hash << ",SIGNATURE ALGORITHM " << signature << endl;


	if (signature == "RSA" || signature == "RSAPSS")
	{
		//get pk
		std::string RSA_Encryption_tag = "300D06092A864886F70D010101";
		size_t pos = hex.find(RSA_Encryption_tag);
		std::string temp = hex.substr(0, pos);
		if (pos - temp.rfind("3082") == 8)
			pos = temp.rfind("3082");
		else if (pos - temp.rfind("3081") == 6)
			pos = temp.rfind("3081");
		else
		{
			while (pos - temp.rfind("30") != 4)
				temp = hex.substr(0, temp.rfind("30"));
			pos = temp.rfind("30");
		}//insure structure:sequence,sequence,objectidentifier,...
		std::string RSA_public_key = hex.substr(pos);

		std::string head;
		if (RSA_public_key.substr(2, 2) == "82")
			head = RSA_public_key.substr(0, 8);
		else if (RSA_public_key.substr(2, 2) == "81")
			head = RSA_public_key.substr(0, 6);
		else
			head = RSA_public_key.substr(0, 4);//insure head is right

		RSA_public_key = extractValueFromTLVHexString(RSA_public_key);
		RSA_public_key = head + RSA_public_key;
		std::string base64str = hexToBase64(RSA_public_key);
		std::string pubKey = "-----BEGIN PUBLIC KEY-----\n" + base64str + +"\n-----END PUBLIC KEY-----\n";
		RSA* rsa = RSA_new();
		BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
		int len = RSA_size(rsa);

		//get signature
		std::string encryptedData = hex.substr(hex.length() - len * 2, len * 2);
		encryptedData = hexString2String(encryptedData);
		std::string decStr = rsa_pub_decrypt(encryptedData, pubKey, RSA_NO_PADDING);


		//get message
		std::string messageDigest;
		if (!getMsgfromSOD(hex, messageDigest))
		{
			LOG(INFO) << "MESSAGE DIGEST EXTRACTION FAIL\n";
			return false;
		}
		bool result = false;
		if (signature == "RSAPSS")
		{
			const EVP_MD* md = nullptr;
			checkmd(hash, md);
			std::string decStr_hex = BinaryToHexString(decStr);
			std::string message_hash(hashLength, 0);
			std::string binary_messageDigest = HexToString(messageDigest);
			SHA_X(hash, binary_messageDigest, message_hash);
			result = RSA_verify_PKCS1_PSS_mgf1(rsa, (unsigned char*)message_hash.c_str(), md, md, (unsigned char*)decStr.c_str(), hashLength);
		}
		else
		{
			std::string hexDecStr = StringToHex(decStr);
			std::string signature_dec = hexDecStr.substr(hexDecStr.size() - 2 * hashLength, 2 * hashLength);
			std::string signature;
			std::string hashResult(hashLength, 0);
			std::string binary_messageDigest = HexToString(messageDigest);
			SHA_X(hash, binary_messageDigest, hashResult);
			signature = StringToHex(hashResult);
			result = compare_ignore_case(signature, signature_dec);
		}
		if (result)
			LOG(INFO) << "SOD VERIFY SIGNATURE SUCCESS\n";
		else
			LOG(INFO) << "SOD VERIFY SIGNATURE FAIL\n";
	}
	else if (signature == "ECDSA")
	{
		EC_KEY* ec_key = EC_KEY_new();
		std::string pk;
		if (!ExtractECpkfromSOD(hex, ec_key, pk)) {
			return false;
		}

		std::string messageDigest;
		if (!getMsgfromSOD(hex, messageDigest)) {
			return false;
		}

		//get hash of messageDigest
		messageDigest = HexStringToBinary(messageDigest);
		std::string hash_res;
		SHA_X(hash, messageDigest, hash_res);

		std::string ecdsa_sig;
		std::string r, s;
		if (!getSigfromSOD(hex, s, r)) {
			return false;
		}
		BIGNUM* r_bn = BN_new();
		BIGNUM* s_bn = BN_new();
		int ret = BN_hex2bn(&r_bn, r.c_str());
		ret = BN_hex2bn(&s_bn, s.c_str());

		ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();
		ret = ECDSA_SIG_set0(ecdsaSig, r_bn, s_bn);
		if (!ecdsaSig) {
			return false;
		}
		// 验证签名
		ret = ECDSA_do_verify((const unsigned char*)hash_res.c_str(), hash_res.size(), ecdsaSig, ec_key);
		if (ret == 1) {
			LOG(INFO) << "PA SUCCESS" << std::endl;
		}
		else {
			LOG(INFO) << "PA FAIL" << std::endl;
		}
	}
	hex_temp = hex.substr(CSCAHead, SODSignatureHead - CSCAHead);
	checkHashAndSignature(hex_temp, hash, signature, hashLength);
	bool f1 = false, f2 = false, f3 = false;
	if (!checkCSCA(hex, signature, hash, hashLength, country)) {
		LOG(INFO) << "ISSUER CERTIFICATE VERIFY FAIL\n";

	}
	else
	{
		LOG(INFO) << "ISSUER CERTIFICATE VERIFY SUCCESS\n";
	}
}
//全都转成bmp了
//可能有多张图，每张图数据开头5F2E或7F2E，然后找图片格式标识符
int testJP2(std::string& data, std::string filename, int& width, int& height, int& size, int& version)
{
	version = -1;
	size_t offset;
	int Jpeg_Version = 97, Jpeg2000_Version = 2000, PNG_Version = 1, BMP_Version = 2, UNKNOWN_Version = -1;
	if (data.length() <= 84) {
		LOG(INFO) << "data.length() <= 84" << std::endl;
		return FALSE;
	}
	std::string magic_jpeg("\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46", 10);
	std::string magic_jpeg2k("\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a", 10);
	std::string magic_jpeg2k_other("\xff\x4f\xff\x51", 4);
	std::string magic_png("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 8);
	std::string magic_bmp("\x42\x4d", 2);
	std::string two_reserved_item("\x00\x00\x00\x00", 4);
	int cnt = 0;
	std::string temp = data;
	size_t p = 0;
	std::string flag1("\x5f\x2e", 2);
	std::string flag2("\x7f\x2e", 2);
	while ((data.find(flag1,p) != data.npos || data.find(flag2,p) != data.npos))
	{
		if (data.find(flag1,p) != data.npos)
			p = data.find(flag1,p);
		else
			p = data.find(flag2,p);
		int l = 0;
		std::string l_binary;
		if (data[p + 2] == '\x83')
			l_binary = data.substr(p + 3, 3);
		else if (data[p + 2] == '\x82')
			l_binary = data.substr(p + 3, 2);
		else if (data[p + 2] == '\x81')
			l_binary = data.substr(p + 3, 1);
		else 
			l_binary = data.substr(p + 2, 1);
		l = binaryStringToInt(l_binary);
		std::string data_temp = data.substr(p + 2 + l_binary.length(), l);
		size_t offset = data_temp.npos;
		if ((offset = data_temp.find(magic_jpeg2k_other.data(), 0, magic_jpeg2k_other.size())) != data_temp.npos)
			version = Jpeg2000_Version;
		else if ((offset = data_temp.find(magic_jpeg2k.data(), 0, magic_jpeg2k.size())) != data_temp.npos)
			version = Jpeg2000_Version;
		else if ((offset = data_temp.find(magic_jpeg.data(), 0, magic_jpeg.size())) != data_temp.npos)
			version = Jpeg_Version;
		else if ((offset = data_temp.find(magic_png.data(), 0, magic_png.size())) != data_temp.npos)
			version = PNG_Version;
		else if ((offset = data_temp.find(magic_bmp.data(), 0, magic_bmp.size())) != data_temp.npos)
			version = BMP_Version;
		else version = UNKNOWN_Version;
		size_t pos;
		pos = filename.rfind(".");
		std::string dest_name = filename.substr(0,pos);
		if (cnt != 0)
			dest_name += to_string(cnt);
		dest_name += ".bmp";
		if (version == Jpeg_Version) {
			Jpeg2DIB_DeCompress((char*)data_temp.data() + offset, data_temp.size() - offset, dest_name, width, height, size);
		}
		else if (version == Jpeg2000_Version) {
			Jpeg2000_DeCompress((char*)data_temp.data() + offset, data_temp.size() - offset, dest_name, width, height, size);
		}
		else
		{
			std::string to_write = data_temp.substr(offset);
			pos = filename.rfind("\\");
			std::string temp_name = filename.substr(0, pos);
			if (version == BMP_Version)
			{
				if (cnt != 0)
					temp_name += "\\temp" + to_string(cnt) + ".bmp";
				else
					temp_name += "\\temp.bmp";
			}
			else
			{
				if (cnt != 0)
					temp_name += "\\temp" + to_string(cnt) + ".png";
				else
					temp_name += "\\temp.png";
			}
			fstream f(temp_name, ios::out | ios::binary);
			if (f.is_open())
			{
				f.write(to_write.c_str(), to_write.size());
				f.close();
			}
			cv::Mat img = cv::imread(temp_name);
			width = img.cols;
			height = img.rows;
			size = data_temp.size() - offset;
			pos = filename.rfind(".");
			std::string dest_name = filename.substr(0,pos);
			if (cnt != 0)
				dest_name += to_string(cnt);
			dest_name += ".bmp";
			cv::imwrite(dest_name, img);
		}
		p+= 2 + l;
		cnt++;
	}
	BOOL ret = FALSE;
	ret = 1;
	return true;
}
void aes_cbc_encode1(const std::string& key, std::string& data, std::string& enc, std::string& iv_str) {

	unsigned char iv[AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	for (int i = 0; i < 16; ++i) {
		iv[i] = iv_str[i];
	}

	AES_KEY aes_key;
	if (AES_set_encrypt_key((const unsigned char*)key.c_str(), key.length() * 8, &aes_key) < 0)
	{
		return;
	}
	unsigned char out[AES_BLOCK_SIZE];
	unsigned char* inData = (unsigned char*)data.data();
	AES_cbc_encrypt(inData, out, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
	enc = std::string((const char*)out, AES_BLOCK_SIZE);
}
void testIM()
{
	int keyLength = 128;
	std::string T_ICC = "\x5D\xD4\xCB\xFC\x96\xF5\x45\x3B\x13\x0D\x89\x0A\x1C\xDB\xAE\x32";
	std::string S_ICC = "\x29\x23\xBE\x84\xE1\x6C\xD6\xAE\x52\x90\x49\xF1\xF1\xBB\xE9\xEB";
	size_t l = S_ICC.size()*8;
	LOG(INFO) << "SICC LENGTH" << l;
	size_t k = T_ICC.size()*8;
	LOG(INFO) << "TICC LENGTH" << k;
	EC_GROUP* ec_group = EC_GROUP_new(EC_GFp_mont_method());
	ec_group = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);
	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();

	BN_CTX* ctx = BN_CTX_new();
	std::string ps, as, bs, os, cs;


	int ret = EC_GROUP_get_curve_GFp(ec_group, p, a, b, ctx);
	const BIGNUM* order = EC_GROUP_get0_order(ec_group);
	const BIGNUM* cofactor = EC_GROUP_get0_cofactor(ec_group);
	ps = BN_bn2hex(p);
	as = BN_bn2hex(a);
	bs = BN_bn2hex(b);
	os = BN_bn2hex(order);
	cs = BN_bn2hex(cofactor);
	LOG(INFO) << "P "<<ps;
	LOG(INFO) << "A " << as;
	LOG(INFO) << "B " << bs;
	LOG(INFO) << "ORDER " << os;
	LOG(INFO)<< "COFACTOR " << cs;
	LOG(INFO) << "ECDH IM, P OF ECGROUP " << BN_bn2hex(p);
	int n = 0;
	std::string iv_aes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);//16字节初始向量,cbc函数内自带iv
	std::string ki;
	std::string xi;
	std::string x;
	int log2 = getLog2(p);
	n = ceil((log2 + 64.0) / l);
	std::string c0_hex = keyLength == 128 ? "a668892a7c41e3ca739f40b057d85904" : "d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676";
	std::string c1_hex = keyLength == 128 ? "a4e136ac725f738b01c1f60217c188ad" : "54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517";
	std::string c0 = HexStringToBinary(c0_hex);
	std::string c1 = HexStringToBinary(c1_hex);
	std::string cipherAlgorithm = "AES";

	//if (cipherAlgorithm == "DESede")//c0 c1奇偶校验
	//{
	//	std::string key1 = c0.substr(0, 8);
	//	std::string key2 = c0.substr(8, 8);
	//	std::string key1_check = "";
	//	std::string key2_check = "";
	//	CheckParity(key1, key1_check, 8);
	//	CheckParity(key2, key2_check, 8);
	//	c0 = key1_check + key2_check;
	//	key1 = c1.substr(0, 8);
	//	key2 = c1.substr(8, 8);
	//	key1_check = "";
	//	key2_check = "";
	//	CheckParity(key1, key1_check, 8);
	//	CheckParity(key2, key2_check, 8);
	//	c1 = key1_check + key2_check;
	//}
	if (cipherAlgorithm == "AES")
		aes_cbc_encode1(T_ICC, S_ICC, ki, iv_aes);//AES获得ki
	//else if (cipherAlgorithm == "DESede")
	//{
	//	std::string key1 = S_ICC.substr(0, 8);
	//	std::string key2 = S_ICC.substr(8, 8);
	//	std::string key1_check = "";
	//	std::string key2_check = "";
	//	CheckParity(key1, key1_check, 8);
	//	CheckParity(key2, key2_check, 8);
	//	S_ICC = key1_check + key2_check;
	//	KencTDES(T_ICC, S_ICC, ki, DES_ENCRYPT);//3DES获得ki
	//}
	if (keyLength == 192)
		ki = ki.substr(0, 24);//192AES截断
	for (int i = 0; i < n; i++)
	{
		//if (keyLength == 192)
		//	AesAddPaddingBytes(ki);//192AES填充
		if (cipherAlgorithm == "AES")
			aes_cbc_encode1(ki, c1, xi, iv_aes);//获得xi
		//else if (cipherAlgorithm == "DESede")
		//	KencTDES(ki, c1, xi, DES_ENCRYPT);//获得xi
		xi = BinaryToHexString(xi);
		if (xi[xi.length() - 1] == '\0')
			xi.pop_back();
		x = x + xi;//连接xi
		if (cipherAlgorithm == "AES")
			aes_cbc_encode1(ki, c0, ki, iv_aes);//更新ki
		//else if (cipherAlgorithm == "DESese")
		//	KencTDES(ki, c0, ki, DES_ENCRYPT);//更新ki
	}
	LOG(INFO) << "x " << x<<'\n';
	//TODO:在DES的情况下，k被认为等于128位，R(s, t)的输出应为128位。
	//if (cipherAlgorithm == "DESede")
	//	x.resize(16);
	//取得了x
	BIGNUM* x_bn = BN_new();
	BIGNUM* map = BN_new();//结果

	ret = BN_hex2bn(&x_bn, x.c_str());
	ret = BN_nnmod(map, x_bn, p, ctx);//随机数映射结果
	//接下来做点映射
	//step1
	BIGNUM* alpha = BN_new();
	ret = BN_mul(alpha, x_bn, x_bn, ctx);
	BIGNUM* zero = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* four = BN_new();
	ret = BN_one(one);
	ret = BN_zero(zero);
	ret = BN_hex2bn(&four, "4");
	ret = BN_sub(alpha, zero, alpha);
	ret = BN_nnmod(alpha, alpha, p, ctx);
	//step2
	BIGNUM* X2 = BN_new();
	BIGNUM* temp = BN_new();
	BIGNUM* alpha2 = BN_new();
	ret = BN_mod_mul(alpha2, alpha, alpha, p, ctx);//alpha^2
	ret = BN_mod_add(temp, alpha, alpha2, p, ctx);//alpha+alpha^2
	BN_mod_inverse(temp, temp, p, ctx);//(alpha+alpha^2)^-1 mod p 
	ret = BN_mod_add(temp, one, temp, p, ctx);//1+(alpha+alpha^2)^-1
	BIGNUM* a_inv = BN_new();
	BIGNUM* b_neg = BN_new();
	ret = BN_mod_sub(b_neg, zero, b, p, ctx);//-b
	BN_mod_inverse(a_inv, a, p, ctx);//a^-1
	ret = BN_mod_mul(temp, b_neg, temp, p, ctx);
	ret = BN_mod_mul(temp, a_inv, temp, p, ctx);
	X2 = BN_dup(temp);//X2
	BIGNUM* X3 = BN_new();
	ret = BN_mod_mul(X3, alpha, X2, p, ctx);//X3 = alpha*X2 mod p
	BIGNUM* h2 = BN_new();
	BIGNUM* h3 = BN_new();
	ret = BN_mod_mul(temp, X2, X2, p, ctx);
	ret = BN_mod_mul(temp, X2, temp, p, ctx);
	BIGNUM* aX = BN_new();
	ret = BN_mod_mul(aX, a, X2, p, ctx);
	ret = BN_mod_add(temp, temp, aX, p, ctx);
	ret = BN_mod_add(h2, temp, b, p, ctx);//h2

	//ret = BN_mod_mul(temp, X3, X3, p, ctx);
	//ret = BN_mod_mul(temp, X3, temp, p, ctx);
	//ret = BN_mod_mul(aX, a, X3, p, ctx);
	//ret = BN_mod_add(temp, temp, aX, p, ctx);
	//ret = BN_mod_add(h3, temp, b, p, ctx);//h3

	BIGNUM* U = BN_new();
	ret = BN_mod_mul(temp, x_bn, x_bn, p, ctx);
	ret = BN_mod_mul(temp, x_bn, temp, p, ctx);
	ret = BN_mod_mul(U, temp, h2, p, ctx);
	BIGNUM* exp = BN_new();
	BIGNUM* fourInverse = BN_new();
	ret = BN_add(temp, p, one);
	BN_mod_inverse(fourInverse, four, p, ctx);
	ret = BN_mod_mul(temp, temp, fourInverse, p, ctx);//(p+1)/4
	ret = BN_sub(exp, p, one);
	ret = BN_mod_sub(exp, exp, temp, p, ctx);//p-1-(p+1)/4
	BIGNUM* A = BN_new();
	ret = BN_mod_exp(A, h2, exp, p, ctx);
	BIGNUM* X = BN_new();
	BIGNUM* Y = BN_new();
	BIGNUM* judge = BN_new();
	ret = BN_mod_mul(judge, A, A, p, ctx);
	ret = BN_mod_mul(judge, judge, h2, p, ctx);
	if (BN_cmp(judge, one) == 0)
	{
		X = BN_dup(X2);
		BN_mod_mul(Y, A, h2, p, ctx);
	}
	else
	{
		X = BN_dup(X3);
		BN_mod_mul(Y, A, U, p, ctx);
	}
	if (BN_cmp(cofactor, one) != 0)
	{
		BN_mod_mul(X, X, cofactor, p, ctx);
		BN_mod_mul(Y, Y, cofactor, p, ctx);
	}
	std::string xx, yy;
	xx = BN_bn2hex(X);
	yy = BN_bn2hex(Y);
	LOG(INFO)<< "XX " << xx << '\n' << "YY " << yy;
	EC_POINT* G_hat = EC_POINT_new(ec_group);
	ret = EC_POINT_set_affine_coordinates_GFp(ec_group, G_hat, X, Y, ctx);
	//ret = EC_GROUP_set_generator(ec_group,G_hat,order,cofactor);
	std::string pri = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";
	BIGNUM* prib = BN_new();
	BN_hex2bn(&prib,pri.c_str());
	EC_POINT* res=EC_POINT_new(ec_group);
	if (EC_POINT_mul(ec_group, res, nullptr, G_hat, prib, ctx))
	{
		BIGNUM* x = BN_new();
		BIGNUM* y = BN_new();
		ret = EC_POINT_get_affine_coordinates_GFp(ec_group, res, x, y, NULL);
		string x1, y1;
		x1 = BN_bn2hex(x);
		y1 = BN_bn2hex(y);
		LOG(INFO) << x1 << '\n' << y1;
	}
	std::string PKDH_IC_hex= "67F78E5F7F7686082B293E8D087E056916D0F74BC01A5F8957D0DE45691E51E8932B69A962B52A0985AD2C0A271EE6A13A8ADDDCD1A3A994B9DED257F4D22753";
	
	EC_POINT* KA = EC_POINT_new(ec_group);
	string SKDH_IFD_hex = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";
	LOG(INFO) << "PKDH_IC_HEX " << PKDH_IC_hex << endl << "SKDH_IFD_HEX " << SKDH_IFD_hex << endl;
	get_shared_secret(ec_group, SKDH_IFD_hex, PKDH_IC_hex, KA);

	BIGNUM* KA_bn = EC_POINT_point2bn(ec_group, KA, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
	char* public_key_hex_char = BN_bn2hex(KA_bn);
	std::string KA_hex = public_key_hex_char;
	LOG(INFO) << "KA_HEX " << KA_hex << endl;
	std::string KA_X = KA_hex.substr(2, KA_hex.size() / 2 - 1);
	LOG(INFO) << "KA_X " << KA_X << endl;
	std::string c11("\x00\x00\x00\x01", 4);
	std::string c2("\x00\x00\x00\x02", 4);
	std::string D1, D2;
	std::string Kseed = HexStringToBinary(KA_X);
	std::string KSenc, KSmac;
	// Kseed concat c3 into D3 
	D1.append(Kseed.data(), Kseed.size());
	D1.append(c11.data(), c11.size());
	D2.append(Kseed.data(), Kseed.size());
	D2.append(c2.data(), c2.size());
	if (keyLength == 256 || keyLength == 192)
	{
		std::string HD1(32, 0), HD2(32, 0);
		// SHA256 HD1,HD2
		SHA256((BYTE*)D1.data(), D1.size(), (BYTE*)HD1.data());
		SHA256((BYTE*)D2.data(), D2.size(), (BYTE*)HD2.data());

		if (keyLength == 256)
		{
			KSenc = HD1;
			KSmac = HD2;
		}
		else if (keyLength == 192)
		{
			KSenc = HD1.substr(0, 24);
			KSmac = HD2.substr(0, 24);
		}

	}
	else if (keyLength == 128)
	{
		std::string HD1(20, 0), HD2(20, 0);
		// SHA-1 HD1,HD2
		SHA1((BYTE*)D1.data(), D1.size(), (BYTE*)HD1.data());
		SHA1((BYTE*)D2.data(), D2.size(), (BYTE*)HD2.data());
		if (cipherAlgorithm == "AES")
		{
			KSenc = HD1.substr(0, 16);
			KSmac = HD2.substr(0, 16);
		}
		else if (cipherAlgorithm == "DESede")
		{
			std::string HD11 = HD1.substr(0, 8);
			std::string HD12 = HD1.substr(8, 8);
			std::string HD21 = HD2.substr(0, 8);
			std::string HD22 = HD2.substr(8, 8);
			std::string HD11_checked = "";
			std::string HD12_checked = "";
			std::string HD21_checked = "";
			std::string HD22_checked = "";
			CheckParity1(HD11, HD11_checked, 8);
			CheckParity1(HD12, HD12_checked, 8);
			CheckParity1(HD21, HD21_checked, 8);
			CheckParity1(HD22, HD22_checked, 8);
			KSenc = HD11_checked + HD12_checked;
			KSmac = HD21_checked + HD22_checked;
		}
	}
	auto KSenc_hex = BinaryToHexString(KSenc);
	auto KSmac_hex = BinaryToHexString(KSmac);
	LOG(INFO) << "KSenc " << KSenc_hex << endl << "KSmac " << KSmac_hex << endl;
}
void testDHIM()
{
	DH* dh = DH_get_1024_160();
	const BIGNUM* p = BN_new();
	const BIGNUM* q = BN_new();
	const BIGNUM* g = BN_new();
	DH_get0_pqg(dh,&p,&q,&g);
	LOG(INFO) << BN_bn2hex(p) << '\n' << BN_bn2hex(q) << '\n' << BN_bn2hex(g);
	string S_ICC = "FA5B7E3E49753A0DB9178B7B9BD898C8";
	S_ICC = HexStringToBinary(S_ICC);
	string T_ICC = "B3A6DB3C870C3E99245E0D1C06B747DE";
	T_ICC = HexStringToBinary(T_ICC);
	int n = 0;
	std::string iv_aes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);//16字节初始向量,cbc函数内自带iv
	std::string ki;
	std::string xi;
	std::string x;
	int log2 = getLog2(BN_dup(p));
	int k = 128, l = 128;
	int keyLength = 128;
	n = ceil((log2 + 64.0) / l);
	std::string c0_hex = keyLength == 128 ? "a668892a7c41e3ca739f40b057d85904" : "d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676";
	std::string c1_hex = keyLength == 128 ? "a4e136ac725f738b01c1f60217c188ad" : "54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517";
	std::string c0 = HexStringToBinary(c0_hex);
	std::string c1 = HexStringToBinary(c1_hex);
	std::string cipherAlgorithm = "AES";

	//if (cipherAlgorithm == "DESede")//c0 c1奇偶校验
	//{
	//	std::string key1 = c0.substr(0, 8);
	//	std::string key2 = c0.substr(8, 8);
	//	std::string key1_check = "";
	//	std::string key2_check = "";
	//	CheckParity(key1, key1_check, 8);
	//	CheckParity(key2, key2_check, 8);
	//	c0 = key1_check + key2_check;
	//	key1 = c1.substr(0, 8);
	//	key2 = c1.substr(8, 8);
	//	key1_check = "";
	//	key2_check = "";
	//	CheckParity(key1, key1_check, 8);
	//	CheckParity(key2, key2_check, 8);
	//	c1 = key1_check + key2_check;
	//}
	if (cipherAlgorithm == "AES")
		aes_cbc_encode1(T_ICC, S_ICC, ki, iv_aes);//AES获得ki
	//else if (cipherAlgorithm == "DESede")
	//{
	//	std::string key1 = S_ICC.substr(0, 8);
	//	std::string key2 = S_ICC.substr(8, 8);
	//	std::string key1_check = "";
	//	std::string key2_check = "";
	//	CheckParity(key1, key1_check, 8);
	//	CheckParity(key2, key2_check, 8);
	//	S_ICC = key1_check + key2_check;
	//	KencTDES(T_ICC, S_ICC, ki, DES_ENCRYPT);//3DES获得ki
	//}
	if (keyLength == 192)
		ki = ki.substr(0, 24);//192AES截断
	for (int i = 0; i < n; i++)
	{
		//if (keyLength == 192)
		//	AesAddPaddingBytes(ki);//192AES填充
		if (cipherAlgorithm == "AES")
			aes_cbc_encode1(ki, c1, xi, iv_aes);//获得xi
		//else if (cipherAlgorithm == "DESede")
		//	KencTDES(ki, c1, xi, DES_ENCRYPT);//获得xi
		xi = BinaryToHexString(xi);
		if (xi[xi.length() - 1] == '\0')
			xi.pop_back();
		x = x + xi;//连接xi
		if (cipherAlgorithm == "AES")
			aes_cbc_encode1(ki, c0, ki, iv_aes);//更新ki
		//else if (cipherAlgorithm == "DESese")
		//	KencTDES(ki, c0, ki, DES_ENCRYPT);//更新ki
	}
	LOG(INFO) << "x " << x << '\n';
	//TODO:在DES的情况下，k被认为等于128位，R(s, t)的输出应为128位。
	if (cipherAlgorithm == "DESede")
		x.resize(16);
	//取得了x
	BIGNUM* x_bn = BN_new();
	BIGNUM* map = BN_new();//结果
	BN_CTX* ctx = BN_CTX_new();
	int ret = BN_hex2bn(&x_bn, x.c_str());
	ret = BN_nnmod(map, x_bn, p, ctx);//随机数映射结果
	LOG(INFO) << "MAP " << BN_bn2hex(map);
	BIGNUM* mappingResult = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* one = BN_new();
	BN_one(one);
	BN_sub(a, p, one);
	BN_div(a, nullptr, a, q, ctx);
	LOG(INFO) << "IM DH MAPPING, a " << BN_bn2hex(a);
	BN_mod_exp(mappingResult, x_bn, a, p, ctx);
	LOG(INFO) << "mappingresult " << BN_bn2hex(mappingResult);
	DH* dh1 = DH_new();
	DH_set0_pqg(dh1,BN_dup(p),BN_dup(q),mappingResult);
	DH_generate_key(dh1);
	const BIGNUM* generate_pri = BN_new();
	const BIGNUM* generate_pub = BN_new();
	DH_get0_key(dh1, &generate_pub, &generate_pri);

	BIGNUM* PKIC = BN_new();
	BIGNUM* SKIC = BN_new();
	BIGNUM* PKIFD = BN_new();
	BIGNUM* SKIFD = BN_new();
	BN_hex2bn(&SKIC,"020F018C7284B047FA7721A337EFB7ACB1440BB30C5252BD41C97C30C994BB78E9F0C5B32744D84017D21FFA6878396A6469CA283EF5C000DAF7D261A39AB8860ED4610AB5343390897AAB5A7787E4FAEFA0649C6A94FDF82D991E8E3FC332F5142729E7040A3F7D5A4D3CD75CBEE1F043C1CAD2DD484FEB4ED22B597D36688E");
	BN_hex2bn(&SKIFD,"4BD0E54740F9A028E6A515BFDAF967848C4F5F5FFF65AA0915947FFD1A0DF2FA6981271BC905F3551457B7E03AC3B8066DE4AA406C1171FB43DD939C4BA16175103BA3DEE16419AA248118F90CC36A3D6F4C373652E0C3CCE7F0F1D0C5425B3600F0F0D6A67F004C8BBA33F2B4733C7252445C1DFC4F1107203F71D2EFB28161");
	BN_mod_exp(PKIC,mappingResult,SKIC,p,ctx);
	BN_mod_exp(PKIFD,mappingResult,SKIFD,p,ctx);
	LOG(INFO) << BN_bn2hex(PKIC);
	LOG(INFO) << BN_bn2hex(PKIFD);
	BIGNUM* K = BN_new();
	BN_mod_exp(K,PKIC,SKIFD,p,ctx);
	LOG(INFO) << BN_bn2hex(K);
	string KK = BN_bn2hex(K);
	KK = HexStringToBinary(KK);
	string enc = KK;
	string mac = KK;
	enc.append("\x00\x00\x00\x01", 4);
	mac.append("\x00\x00\x00\x02", 4);
	string senc, smac;
	senc.resize(20);
	smac.resize(20);
	SHA1((BYTE*)enc.data(), enc.size(), (BYTE*)senc.data());
	LOG(INFO) << "KSENC " << BinaryToHexString(senc);
	SHA1((BYTE*)mac.data(), mac.size(), (BYTE*)smac.data());
	LOG(INFO) << "KSmac " << BinaryToHexString(smac);
	senc.resize(16);
	smac.resize(16);
	string TIC = "", TIFD = "";
	TIC.append("\x7f\x49", 2);
	string pkicc = BN_bn2hex(PKIC);
	pkicc = HexStringToBinary(pkicc);
	string pkifd = BN_bn2hex(PKIFD);
	pkifd = HexStringToBinary(pkifd);
	int length1 = pkifd.length();
	int length2 = pkifd.length() + 1 + lengthtoBinary(pkifd.length()).length() + 12;
	TIC.append(lengthtoBinary(length2));
	TIC.append("\x06\x0A", 2);
	TIC.append("\x04\x00\x7F\x00\x07\x02\x02\x04\x03\x02", 10);
	TIC.push_back('\x84');
	TIC.append(lengthtoBinary(length1));
	TIC.append(pkifd);
	string tic = BinaryToHexString(TIC);
	LOG(INFO) << tic;
	TIFD.append("\x7f\x49", 2);
	length1 = pkicc.length();
	length2 = pkicc.length() + 1 + lengthtoBinary(pkicc.length()).length() + 12;
	TIFD.append(lengthtoBinary(length2));
	TIFD.append("\x06\x0A", 2);
	TIFD.append("\x04\x00\x7F\x00\x07\x02\x02\x04\x03\x02", 10);
	TIFD.push_back('\x84');
	TIFD.append(lengthtoBinary(length1));
	TIFD.append(pkicc);
	string tifd = BinaryToHexString(TIFD);
	LOG(INFO) << tifd;
	unsigned char mact[32] = { 0 };
	size_t mactlen;
	CMAC_CTX* ctx1 = CMAC_CTX_new();
	string resic, resifd;
	if (cipherAlgorithm == "AES")
	{
		const EVP_CIPHER* aes_algorithm;
		switch (keyLength)
		{
		case 256:
		{
			CMAC_Init(ctx1, smac.c_str(), smac.size(), EVP_aes_256_cbc(), NULL);
			CMAC_Update(ctx1, TIC.c_str(), TIC.size());
			CMAC_Final(ctx1, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			resic = s.substr(0, 8);
			CMAC_CTX_free(ctx1);
			break;
		}
		case 192:
		{
			CMAC_Init(ctx1, smac.c_str(), smac.size(), EVP_aes_192_cbc(), NULL);
			CMAC_Update(ctx1, TIC.c_str(), TIC.size());
			CMAC_Final(ctx1, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			resic = s.substr(0, 8);
			CMAC_CTX_free(ctx1);
			break;
		}
		case 128:
		{
			CMAC_Init(ctx1, smac.c_str(), smac.size(), EVP_aes_128_cbc(), NULL);
			CMAC_Update(ctx1, TIC.c_str(), TIC.size());
			CMAC_Final(ctx1, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			resic = s.substr(0, 8);
			CMAC_CTX_free(ctx1);
			break;
		}
		default:
			break;
		}
	}
	ctx1 = CMAC_CTX_new();
	if (cipherAlgorithm == "AES")
	{
		const EVP_CIPHER* aes_algorithm;
		switch (keyLength)
		{
		case 256:
		{
			CMAC_Init(ctx1, smac.c_str(), smac.size(), EVP_aes_256_cbc(), NULL);
			CMAC_Update(ctx1, TIFD.c_str(), TIFD.size());
			CMAC_Final(ctx1, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			resifd = s.substr(0, 8);
			CMAC_CTX_free(ctx1);
			break;
		}
		case 192:
		{
			CMAC_Init(ctx1, smac.c_str(), smac.size(), EVP_aes_192_cbc(), NULL);
			CMAC_Update(ctx1, TIFD.c_str(), TIFD.size());
			CMAC_Final(ctx1, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			resifd = s.substr(0, 8);
			CMAC_CTX_free(ctx1);
			break;
		}
		case 128:
		{
			CMAC_Init(ctx1, smac.c_str(), smac.size(), EVP_aes_128_cbc(), NULL);
			CMAC_Update(ctx1, TIFD.c_str(), TIFD.size());
			CMAC_Final(ctx1, mact, &mactlen);
			std::string s((char*)&mact[0], mactlen);
			resifd = s.substr(0, 8);
			CMAC_CTX_free(ctx1);
			break;
		}
		default:
			break;
		}
	}
	LOG(INFO) << BinaryToHexString(resic);
	LOG(INFO) << BinaryToHexString(resifd);
}
void KencTDES1(
	const std::string& strInputData,
	const std::string& Kenc,
	std::string& strOutputData,
	int enc) {
	DES_cblock IV = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	DES_cblock key1, key2, key3;
	DES_key_schedule schKey1, schKey2, schKey3;
	int byteNum = strInputData.size(), r = 0;
	unsigned char* inputData = (unsigned char*)strInputData.c_str();
	std::string hexKa1, hexKb1;

	hexKa1.append(Kenc.data(), 8);
	hexKb1.append(Kenc.data() + 8, 8);

	memcpy(key1, hexKa1.data(), hexKa1.size());
	memcpy(key2, hexKb1.data(), hexKb1.size());
	memcpy(key3, hexKa1.data(), hexKa1.size());

	if (-2 == (
		DES_set_key_checked(&key1, &schKey1) |
		DES_set_key_checked(&key2, &schKey2) |
		DES_set_key_checked(&key3, &schKey3))) {
		//throw std::exception("weak key");
	}

	strOutputData.resize(byteNum);
	//    LOGI("strOutputData byteNum:%d", byteNum);
	DES_ede3_cbc_encrypt(inputData, (unsigned char*)strOutputData.data(), strOutputData.size(),
		&schKey1, &schKey2, &schKey3, &IV, enc);
}
int testDH()
{
	int ecc_id = 0;
	std::string PKmap = "";
	std::string SKmap = "";
	DH* dh = DH_new();
	if (ecc_id >= 0 && ecc_id <= 2)
	{
		
		if (ecc_id == 0)
			dh = DH_get_1024_160();
		else if (ecc_id == 1)
			dh = DH_get_2048_224();
		else
			dh = DH_get_2048_256();
		int ret = DH_generate_key(dh);
		const BIGNUM* priv = DH_get0_priv_key(dh);
		const BIGNUM* pub = DH_get0_pub_key(dh);
		char* PKmap_hex = BN_bn2hex(pub);
		char* SKmap_hex = BN_bn2hex(priv);
		LOG(INFO) << "DH PUBLIC KEY " << PKmap_hex;
		LOG(INFO) << "DH PRIVATE KEY " << SKmap_hex;
		PKmap = HexStringToBinary(PKmap_hex);
		SKmap = HexStringToBinary(SKmap_hex);
	}
	const BIGNUM* p = BN_new();
	const BIGNUM*  q = BN_new();
	const BIGNUM*  g = BN_new();
	p = DH_get0_p(dh);
	q = DH_get0_q(dh);
	g = DH_get0_g(dh);
	LOG(INFO) << BN_bn2hex(p) << '\n' << BN_bn2hex(q) << '\n' << BN_bn2hex(g);
	string s1 = "78879F57225AA8080D52ED0FC890A4B25336F699AA89A2D3A189654AF70729E623EA5738B26381E4DA19E004706FACE7B235C2DBF2F38748312F3C98C2DD4882A41947B324AA1259AC22579DB93F7085655AF30889DBB845D9E6783FE42C9F2449400306254C8AE8EE9DD812A804C0B66E8CAFC14F84D8258950A91B44126EE6";
	string s2 = "5265030F751F4AD18B08AC565FC7AC952E41618D";
	BIGNUM* chippublic = BN_new();
	BIGNUM* ifdprivate = BN_new();
	BN_hex2bn(&chippublic, s1.c_str());
	BN_hex2bn(&ifdprivate, s2.c_str());
	BIGNUM* res = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	BN_mod_exp(res, chippublic, ifdprivate,p, ctx);
	LOG(INFO) << BN_bn2hex(res);
	string s = "FA5B7E3E49753A0DB9178B7B9BD898C8";
	BIGNUM* S = BN_new();
	BN_hex2bn(&S,s.c_str());
	BIGNUM* temp = BN_new();
	BN_mod_exp(temp, g, S, p, ctx);
	BN_mod_mul(temp, temp, res, p, ctx);
	LOG(INFO) << BN_bn2hex(temp);
	int ret = DH_set0_pqg(dh,BN_dup(p), nullptr, temp);//
	ret = DH_generate_key(dh);
	const BIGNUM* priv = DH_get0_priv_key(dh);
	const BIGNUM* pub = DH_get0_pub_key(dh);
	BN_mod_exp(temp, temp, priv, p, ctx);
	LOG(INFO) << BN_bn2hex(temp);
	LOG(INFO) << BN_bn2hex(pub);
	string s4 = "A5B780126B7C980E9FCEA1D4539DA1D27C342DFA";
	BIGNUM* S4 = BN_new();
	BN_hex2bn(&S4, s4.c_str());
	string s5 = "00907D89E2D425A178AA81AF4A7774EC8E388C115CAE67031E85EECE520BD911551B9AE4D04369F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA80A08FA8D61B76D3A154AD8A5A51786B0BC07147057871A922212C5F67F43173172236B7747D1671E6D692A3C7D40A0C3C5CE397545D015C175EB5130551EDBC2EE5D4";
	BIGNUM* S5 = BN_new();
	BN_hex2bn(&S5, s5.c_str());
	BIGNUM* res1 = BN_new();
	BN_mod_exp(res1, S5, S4, p, ctx);
	LOG(INFO) << BN_bn2hex(res1); 
	return 0;
}
void AesAddPaddingBytes1(std::string& data) {
	size_t dsize = data.size();
	dsize = DES_ALIGN(dsize, 16);
	data.push_back('\x80');
	for (size_t i = data.size(); i < dsize; i++) {
		data.push_back(0x00);
	}
}
void testECDHIM()
{
	EC_GROUP* ec_group = EC_GROUP_new(EC_GFp_mont_method());
	ec_group = EC_GROUP_new_by_curve_name( NID_brainpoolP256r1);
	int keyLength = 128;
	string cipherAlgorithm = "AES";
	BIGNUM* p = BN_new();
	BIGNUM* a = BN_new();
	BIGNUM* b = BN_new();
	const BIGNUM* order = BN_new();
	BIGNUM* xx = BN_new();
	BIGNUM* yy = BN_new();
	EC_POINT* g = EC_POINT_new(ec_group);
	string s = HexStringToBinary("2923BE84E16CD6AE529049F1F1BBE9EB");
	string t = HexStringToBinary("5DD4CBFC96F5453B130D890A1CDBAE32");
	BN_CTX* ctx = BN_CTX_new();
	int ret = EC_GROUP_get_curve_GFp(ec_group, p, a, b, ctx);
	LOG(INFO) << BN_bn2hex(p);
	size_t l = s.size() * 8;
	LOG(INFO) << "SICC LENGTH" << l;
	size_t k = t.size() * 8;
	LOG(INFO) << "TICC LENGTH" << k;
	ret = -1;
	LOG(INFO) << "ECDH IM, P OF ECGROUP " << BN_bn2hex(p);

	int n = 0;
	std::string iv_aes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16);//16字节初始向量,cbc函数内自带iv
	std::string ki = "";
	std::string xi = "";
	std::string x = "";
	int log2 = getLog2(p);
	n = ceil((log2 + 64.0) / l);
	std::string c0_hex = keyLength == 128 ? "a668892a7c41e3ca739f40b057d85904" : "d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676";
	std::string c1_hex = keyLength == 128 ? "a4e136ac725f738b01c1f60217c188ad" : "54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517";
	std::string c0 = HexStringToBinary(c0_hex);
	std::string c1 = HexStringToBinary(c1_hex);
	if (cipherAlgorithm == "DESede")//c0 c1奇偶校验
	{
		std::string key1 = c0.substr(0, 8);
		std::string key2 = c0.substr(8, 8);
		std::string key1_check = "";
		std::string key2_check = "";
		CheckParity1(key1, key1_check, 8);
		CheckParity1(key2, key2_check, 8);
		c0 = key1_check + key2_check;
		key1 = c1.substr(0, 8);
		key2 = c1.substr(8, 8);
		key1_check = "";
		key2_check = "";
		CheckParity1(key1, key1_check, 8);
		CheckParity1(key2, key2_check, 8);
		c1 = key1_check + key2_check;
	}
	if (cipherAlgorithm == "AES")
		aes_cbc_encode1(t, s, ki, iv_aes);//AES获得ki
	else if (cipherAlgorithm == "DESede")
	{
		std::string key1 = t.substr(0, 8);
		std::string key2 = t.substr(8, 8);
		std::string key1_check = "";
		std::string key2_check = "";
		CheckParity1(key1, key1_check, 8);
		CheckParity1(key2, key2_check, 8);
		t = key1_check + key2_check;
		KencTDES1(s, t, ki, DES_ENCRYPT);//3DES获得ki
	}
	if (keyLength == 192)
		ki = ki.substr(0, 24);//192AES截断
	for (int i = 0; i < n; i++)
	{
		if (keyLength == 192)
			AesAddPaddingBytes1(ki);//192AES填充
		if (cipherAlgorithm == "AES")
			aes_cbc_encode1(ki, c1, xi, iv_aes);//获得xi
		else if (cipherAlgorithm == "DESede")
			KencTDES1(c1, ki, xi, DES_ENCRYPT);//获得xi
		xi = BinaryToHexString(xi);
		if (xi[xi.length() - 1] == '\0')
			xi.pop_back();
		x.append(xi.data(), xi.length());//连接xi
		if (cipherAlgorithm == "AES")
			aes_cbc_encode1(ki, c0, ki, iv_aes);//更新ki
		else if (cipherAlgorithm == "DESese")
			KencTDES1(c0, ki, ki, DES_ENCRYPT);//更新ki
	}
	//TODO:在DES的情况下，k被认为等于128位，R(s, t)的输出应为128位。
	if (cipherAlgorithm == "DESede")
		x.resize(16);
	LOG(INFO) << x;
	//取得了x
	BIGNUM* x_bn = BN_new();

	ret = BN_hex2bn(&x_bn, x.c_str());
	ret = BN_nnmod(x_bn, x_bn, p, ctx);//随机数映射结果
	LOG(INFO) << BN_bn2hex(x_bn);
	const BIGNUM* cofactor = BN_new();
	cofactor = EC_GROUP_get0_cofactor(ec_group);
	order = EC_GROUP_get0_order(ec_group);
	LOG(INFO) << BN_bn2hex(order);
	LOG(INFO) << BN_bn2hex(cofactor);
	//接下来做点映射
	//step1
	BIGNUM* alpha = BN_new();
	ret = BN_mul(alpha, x_bn, x_bn, ctx);
	BIGNUM* zero = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* four = BN_new();
	ret = BN_one(one);
	ret = BN_zero(zero);
	ret = BN_hex2bn(&four, "4");
	ret = BN_sub(alpha, zero, alpha);
	ret = BN_nnmod(alpha, alpha, p, ctx);
	//step2
	BIGNUM* X2 = BN_new();
	BIGNUM* temp = BN_new();
	BIGNUM* alpha2 = BN_new();
	ret = BN_mod_mul(alpha2, alpha, alpha, p, ctx);//alpha^2
	ret = BN_mod_add(temp, alpha, alpha2, p, ctx);//alpha+alpha^2
	BN_mod_inverse(temp, temp, p, ctx);//(alpha+alpha^2)^-1 mod p 
	ret = BN_mod_add(temp, one, temp, p, ctx);//1+(alpha+alpha^2)^-1
	BIGNUM* a_inv = BN_new();
	BIGNUM* b_neg = BN_new();
	ret = BN_mod_sub(b_neg, zero, b, p, ctx);//-b
	BN_mod_inverse(a_inv, a, p, ctx);//a^-1
	ret = BN_mod_mul(temp, b_neg, temp, p, ctx);
	ret = BN_mod_mul(temp, a_inv, temp, p, ctx);
	X2 = BN_dup(temp);//X2
	BIGNUM* X3 = BN_new();
	ret = BN_mod_mul(X3, alpha, X2, p, ctx);//X3 = alpha*X2 mod p
	BIGNUM* h2 = BN_new();
	BIGNUM* h3 = BN_new();
	ret = BN_mod_mul(temp, X2, X2, p, ctx);
	ret = BN_mod_mul(temp, X2, temp, p, ctx);
	BIGNUM* aX = BN_new();
	ret = BN_mod_mul(aX, a, X2, p, ctx);
	ret = BN_mod_add(temp, temp, aX, p, ctx);
	ret = BN_mod_add(h2, temp, b, p, ctx);//h2

	//ret = BN_mod_mul(temp, X3, X3, p, ctx);
	//ret = BN_mod_mul(temp, X3, temp, p, ctx);
	//ret = BN_mod_mul(aX, a, X3, p, ctx);
	//ret = BN_mod_add(temp, temp, aX, p, ctx);
	//ret = BN_mod_add(h3, temp, b, p, ctx);//h3

	BIGNUM* U = BN_new();
	ret = BN_mod_mul(temp, x_bn, x_bn, p, ctx);
	ret = BN_mod_mul(temp, x_bn, temp, p, ctx);
	ret = BN_mod_mul(U, temp, h2, p, ctx);
	BIGNUM* exp = BN_new();
	BIGNUM* fourInverse = BN_new();
	ret = BN_add(temp, p, one);
	BN_mod_inverse(fourInverse, four, p, ctx);
	ret = BN_mod_mul(temp, temp, fourInverse, p, ctx);//(p+1)/4
	ret = BN_sub(exp, p, one);
	ret = BN_mod_sub(exp, exp, temp, p, ctx);//p-1-(p+1)/4
	BIGNUM* A = BN_new();
	ret = BN_mod_exp(A, h2, exp, p, ctx);
	BIGNUM* X = BN_new();
	BIGNUM* Y = BN_new();
	BIGNUM* judge = BN_new();
	ret = BN_mod_mul(judge, A, A, p, ctx);
	ret = BN_mod_mul(judge, judge, h2, p, ctx);
	if (BN_cmp(judge, one) == 0)
	{
		X = BN_dup(X2);
		BN_mod_mul(Y, A, h2, p, ctx);
	}
	else
	{
		X = BN_dup(X3);
		BN_mod_mul(Y, A, U, p, ctx);
	}
	if (BN_cmp(cofactor, one) != 0)
	{
		BN_mod_mul(X, X, cofactor, p, ctx);
		BN_mod_mul(Y, Y, cofactor, p, ctx);
	}
	LOG(INFO) << BN_bn2hex(X);
	LOG(INFO) << BN_bn2hex(Y);
	EC_POINT* G_hat = EC_POINT_new(ec_group);
	ret = EC_POINT_set_affine_coordinates_GFp(ec_group, G_hat, X, Y, ctx);//目前曲线cofactor都是1
	LOG(INFO) << ret;
	ret = EC_GROUP_set_generator(ec_group,G_hat,order,nullptr);
	LOG(INFO) << ret;
	EC_KEY* ec_key = EC_KEY_new();
	if (!ec_key) {
		LOG(ERROR) << "Failed to create EC key" << endl;
		EC_GROUP_free(ec_group);
	}
	// 设置椭圆曲线参数
	if (!EC_KEY_set_group(ec_key, ec_group)) {
		LOG(ERROR) << "Failed to set EC group" << endl;
		EC_KEY_free(ec_key);
	}
	// 生成本地密钥
	if (!EC_KEY_generate_key(ec_key)) {
		LOG(ERROR) << "Failed to generate EC key" << endl;
		EC_KEY_free(ec_key);
	}
	const BIGNUM* pri1 = EC_KEY_get0_private_key(ec_key);
	const EC_POINT* pub1 = EC_KEY_get0_public_key(ec_key);
	BIGNUM* x1 = BN_new();
	BIGNUM* y1 = BN_new();
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group,pub1,x1,y1,ctx);
	LOG(INFO) << ret << ' ' << BN_bn2hex(x1) << endl << BN_bn2hex(y1);
	EC_POINT* pub11 = EC_POINT_new(ec_group);
	EC_POINT* pub2 = EC_POINT_new(ec_group);
	ret = EC_POINT_mul(ec_group,pub11,nullptr,G_hat,pri1,ctx);
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group, pub11, x1, y1, ctx);
	LOG(INFO) << ret << ' ' << BN_bn2hex(x1) << endl << BN_bn2hex(y1);
	BIGNUM* pri11 = BN_new();
	BIGNUM* pri2 = BN_new();
	BN_hex2bn(&pri11,"107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A");
	ret = EC_POINT_mul(ec_group, pub11, nullptr, G_hat, pri11, ctx);
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group, pub11, x1, y1, ctx);
	LOG(INFO) << ret << ' ' << BN_bn2hex(x1) << endl << BN_bn2hex(y1);
	BN_hex2bn(&pri2, "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595");
	ret = EC_POINT_mul(ec_group, pub2, nullptr, G_hat, pri2, ctx);
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group, pub2, x1, y1, ctx);
	LOG(INFO) << ret << ' ' << BN_bn2hex(x1) << endl << BN_bn2hex(y1);
	EC_POINT* K = EC_POINT_new(ec_group);
	ret = EC_POINT_mul(ec_group,K,nullptr,pub11,pri2,ctx);
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group, K, x1, y1, ctx);
	LOG(INFO) << BN_bn2hex(x1);
	ret = EC_POINT_mul(ec_group, K, nullptr, pub2, pri11, ctx);
	ret = EC_POINT_get_affine_coordinates_GFp(ec_group, K, x1, y1, ctx);
	LOG(INFO) << BN_bn2hex(x1);
}