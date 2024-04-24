
#include "wlString.h"


wlString::wlString(void)
{

}


wlString::~wlString(void)
{
}

CString wlString::ToLetter(byte bNum)
{
	char cTemp;
	if (bNum < 10)
	{
		cTemp = bNum + 0x30;
	}
	else
	{
		cTemp = bNum + 0x37;
	}
	return (CString)cTemp;
}
CString wlString::ByteToString(byte *bByte, UINT iLength)
{
	UINT iIndex;
	CString outStr;

	for (iIndex=0; iIndex<iLength; iIndex++)
	{
		outStr += ToLetter(bByte[iIndex]>>4 & 0x0F);
		outStr += ToLetter(bByte[iIndex]    & 0x0F);
	}

	return this->PrintStyle(outStr);
}


byte wlString::toByte(char a, char b)
{
	byte bTempA;
	byte bTempB;

	if (a < 0x3A)
	{
		bTempA = a - 0x30;
	}
	else
	{
		bTempA = a - 0x37;
	}

	if (b < 0x3A)
	{
		bTempB = b - 0x30;
	}
	else
	{
		bTempB = b - 0x37;
	}
	return byte(bTempA * 0x10 + bTempB);
}

int wlString::StringToByte(CString inStr, byte *pByte, UINT *pLen)
{
	UINT iIndex,iLength;

	inStr.Remove(' ');
	inStr.Remove('	');
	inStr.MakeUpper();
	iLength = inStr.GetLength();

	// length check 
	if ( inStr.IsEmpty() || iLength%2 == 0x01)
	{
		pByte = 0x00;
		return 0x00000001;
	}

	// change
	for (iIndex=0; iIndex<iLength/2; iIndex++)
	{
		pByte[iIndex] = this->toByte(inStr.GetAt(iIndex*2), inStr.GetAt(iIndex*2+1));
	}

	*pLen = iIndex;
	return 0x00000000;
}


CString wlString::PrintStyle(CString inStr)
{
	UINT iIndex,iLength;
	CString outStr;

	inStr.Remove(' ');
	inStr.Remove('	');
	inStr.MakeUpper();
	iLength = inStr.GetLength();

	for (iIndex=0; iIndex<iLength/2; iIndex++)
	{
		inStr.Insert(iIndex*3+2, ' ');
	}
	return inStr;
}