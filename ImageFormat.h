#pragma once
#include <turbojpeg.h>
#include <openjpeg-2.2\openjpeg.h>
#include <jpeglib.h>
#include <Windows.h>
#include <string>
struct imageDetail
{
	std::string ImageTypeDeclare;
	int ImageTypeReal;
	int ImageBitSize;
	int FaceImageHeight;
	int FaceImageWidth;
};
//bool getImageFormat(imageDetail& D, std::string& data, char* path);