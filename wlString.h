#pragma once
#include<atlstr.h>

class wlString
{
public:
	wlString(void);
	~wlString(void);

public:
	//byte ToByte(byte a, byte b);
	// byte to string
	CString ToLetter(byte bNum);
	CString ByteToString(byte *bByte, UINT iLength);

	// String to byte
	byte toByte(char a, char b);
	int  StringToByte(CString inStr, byte *pByte, UINT *pLen);


	// Format
	CString PrintStyle(CString inStr);

};

