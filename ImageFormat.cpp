#include "ImageFormat.h"
#include <vector>
#include <iostream>
#include <fstream>
#include "glog\logging.h"
#include "utils.h"
using namespace std;

// Function to get PNG dimensions
void getPngDimensions(const std::vector<unsigned char>& pngData, size_t& imageSize, int& width, int& height) {
	// Check the PNG file signature
	const unsigned char pngSignature[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };
	if (pngData.size() < 8 || memcmp(pngData.data(), pngSignature, 8) != 0) {
		throw std::runtime_error("Not a valid PNG file");
	}
	imageSize = pngData.size();
	size_t index = 8; // Skip the signature

	// Search for the IHDR chunk
	while (index < pngData.size()) {
		// Read the length of the chunk (4 bytes, big-endian)
		unsigned int chunkLength = (pngData[index] << 24) |
			(pngData[index + 1] << 16) |
			(pngData[index + 2] << 8) |
			pngData[index + 3];
		index += 4;

		// Read the chunk type (4 bytes)
		std::string chunkType(reinterpret_cast<const char*>(&pngData[index]), 4);
		index += 4;

		if (chunkType == "IHDR") {
			if (chunkLength != 13 || index + chunkLength > pngData.size()) {
				throw std::runtime_error("Invalid IHDR chunk");
			}

			// Read the width (4 bytes, big-endian)
			width = (pngData[index] << 24) |
				(pngData[index + 1] << 16) |
				(pngData[index + 2] << 8) |
				pngData[index + 3];

			// Read the height (4 bytes, big-endian)
			height = (pngData[index + 4] << 24) |
				(pngData[index + 5] << 16) |
				(pngData[index + 6] << 8) |
				pngData[index + 7];

			return;
		}

		// Skip the chunk data and CRC (chunkLength + 4 bytes)
		index += chunkLength + 4;
	}

	throw std::runtime_error("IHDR chunk not found in the PNG file");
}
void error_callback1(const char* msg, void* client_data) {
	(void)client_data;
	LOG(ERROR)  << msg;
}

void warning_callback1(const char* msg, void* client_data) {
	(void)client_data;
	LOG(WARNING) << msg;
}

void info_callback1(const char* msg, void* client_data) {
	(void)client_data;
	LOG(INFO)  << msg;
}
struct BMPFileHeader {
	uint16_t fileType;     // File type, always 'BM'
	uint32_t fileSize;     // Size of the file (in bytes)
	uint16_t reserved1;    // Reserved, always 0
	uint16_t reserved2;    // Reserved, always 0
	uint32_t offsetData;   // Offset to the beginning of the image data
};

struct BMPInfoHeader {
	uint32_t size;         // Size of this header (in bytes)
	int32_t width;         // Width of the image (in pixels)
	int32_t height;        // Height of the image (in pixels)
	uint16_t planes;       // Number of color planes (must be 1)
	uint16_t bitCount;     // Number of bits per pixel
	uint32_t compression;  // Compression type
	uint32_t imageSize;    // Size of the image data (in bytes)
	int32_t xPixelsPerMeter; // Horizontal resolution (pixels per meter)
	int32_t yPixelsPerMeter; // Vertical resolution (pixels per meter)
	uint32_t colorsUsed;   // Number of colors in the color palette
	uint32_t colorsImportant; // Number of important colors
};
bool getImageFormat(imageDetail& D, std::string& data, char* path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		LOG(ERROR)<< "Error opening file: " << path << std::endl;
		return false;
	}

	// Get file size
	std::streamsize fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	// Read file content into string
	data.resize(fileSize);
	if (!file.read(&data[0], fileSize)) {
		LOG(ERROR) << "Error reading file: " << path << std::endl;
	}
	size_t pos = -1;
	size_t pos1 = -1;
	std::string temp;
	std::string magic_jpeg("\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46", 10);
	std::string magic_jpeg2k("\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a", 10);
	std::string magic_jpeg2k_other("\xff\x4f\xff\x51", 4);
	std::string magic_png("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 8);
	std::string magic_bmp("\x42\x4d", 2);
	if ((pos = data.find(magic_jpeg)) != data.npos)
	{
		temp = data.substr(pos);
		D.ImageTypeDeclare = "JPEG";
		D.ImageTypeReal = 97;
		FILE* file = fopen(path, "rb");
		if (!file) {
			LOG(ERROR) << "Error opening file: " << path << std::endl;
		}
		else
		{
			// Get file size
			fseek(file, 0, SEEK_END);
			long file_size = ftell(file);
			fseek(file, 0, SEEK_SET);

			// Read file data into memory
			/*unsigned char* jpegData = new unsigned char[file_size];
			fread(jpegData, 1, file_size, file);
			fclose(file);*/
			const unsigned char* jpegData = reinterpret_cast<const unsigned char*>(temp.c_str());
			// Initialize TurboJPEG decompressor
			tjhandle tjInstance = tjInitDecompress();
			if (!tjInstance) {
				LOG(ERROR) << "Error initializing TurboJPEG decompressor: " << tjGetErrorStr() << std::endl;
			}

			// Get JPEG dimensions
			int width, height, jpegSubsamp, jpegColorspace;
			if (tjDecompressHeader3(tjInstance, jpegData, file_size, &width, &height, &jpegSubsamp, &jpegColorspace) < 0) {
				LOG(ERROR) << "Error reading JPEG header: " << tjGetErrorStr() << std::endl;
				tjDestroy(tjInstance);
			}

			// Print the image information
			LOG(INFO) << "Width: " << width << " pixels" << std::endl;
			LOG(INFO) << "Height: " << height << " pixels" << std::endl;
			LOG(INFO) << "Estimated image size: " << file_size << " bytes" << std::endl;
			D.FaceImageHeight = height;
			D.FaceImageWidth = width;
			D.ImageBitSize = file_size;
			// Clean up
			tjDestroy(tjInstance);
		}
	}
	else if (((pos = data.find(magic_jpeg2k)) != data.npos) || ((pos1 = data.find(magic_jpeg2k_other)) != data.npos))
	{
		if (pos != data.npos)
			temp = data.substr(pos);
		else
			temp = data.substr(pos1);
		D.ImageTypeReal = 2000;
		D.ImageTypeDeclare = "JPEG";
		FILE* file = fopen(path, "rb");
		if (!file) {
			LOG(ERROR) << "Error opening file: " << path << std::endl;
		}
		char mypath[255];
		MakeFullPath1(mypath, "USB_TEMP\\TEMP.bin");
		ofstream f(mypath, ios::out | ios::binary);
		if (f.is_open())
		{
			f.write(temp.c_str(),temp.size());
			f.close();
		}
		// Read the file into a buffer
		fseek(file, 0, SEEK_END);
		size_t file_size = ftell(file);
		fseek(file, 0, SEEK_SET);
		//unsigned char* file_data = new unsigned char[file_size];
		//fread(file_data, 1, file_size, file);
		//fclose(file);
		const unsigned char* file_data = reinterpret_cast<const unsigned char*>(temp.c_str());
		// Set up the stream
		opj_stream_t* stream = opj_stream_create_default_file_stream(mypath, true);
		if (!stream) {
			LOG(ERROR) << "Error creating stream" << std::endl;
		}

		// Set up the codec
		opj_codec_t* codec = opj_create_decompress(OPJ_CODEC_JP2);
		if (!codec) {
			LOG(ERROR) << "Error creating codec" << std::endl;
			opj_stream_destroy(stream);
		}

		// Set up the decoder
		opj_set_info_handler(codec, info_callback1, nullptr);
		opj_set_warning_handler(codec, warning_callback1, nullptr);
		opj_set_error_handler(codec, error_callback1, nullptr);

		// Read the header
		opj_image_t* image = nullptr;
		if (!opj_read_header(stream, codec, &image)) {
			LOG(ERROR) << "Error reading header" << std::endl;
			opj_destroy_codec(codec);
			opj_stream_destroy(stream);
		}

		// Decode the image
		if (!opj_decode(codec, stream, image)) {
			LOG(ERROR) << "Error decoding image" << std::endl;
			opj_destroy_codec(codec);
			opj_stream_destroy(stream);
			opj_image_destroy(image);
		}

		// Get image dimensions
		int width = image->x1 - image->x0;
		int height = image->y1 - image->y0;

		// Print image information
		LOG(INFO) << "Width: " << width << " pixels" << std::endl;
		LOG(INFO) << "Height: " << height << " pixels" << std::endl;
		LOG(INFO) << "Estimated image size: " << file_size << " bytes" << std::endl;
		D.FaceImageHeight = height;
		D.FaceImageWidth = width;
		D.ImageBitSize = file_size;
		// Clean up
		opj_destroy_codec(codec);
		opj_stream_destroy(stream);
		opj_image_destroy(image);
	}
	else if ((pos = data.find(magic_png)) != data.npos)
	{
		temp = data.substr(pos);
		D.ImageTypeReal = 0;
		D.ImageTypeDeclare = "PNG";
		//std::ifstream file(path, std::ios::binary | std::ios::ate);
		//if (!file) {
		//	throw std::runtime_error("Could not open file");
		//}
		//
		//std::ifstream::pos_type fileSize = file.tellg();
		std::vector<unsigned char> fileData(temp.begin(), temp.end());

		//file.seekg(0, std::ios::beg);
		//file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
		size_t imageSize;
		int width, height;

		getPngDimensions(fileData, imageSize, width, height);
		D.ImageBitSize = imageSize;
		D.FaceImageWidth = width;
		D.FaceImageHeight = height;
	}
	else if ((pos = data.find(magic_bmp)) != data.npos)
	{
		D.ImageTypeReal = 1;
		D.ImageTypeDeclare = "BMP";
		FILE* pf;
		pf = fopen(path, "rb");
		if (NULL == pf)
		{
			LOG(ERROR) << "文件打开失败!"<<path << endl;
			fclose(pf);
			return false;
		}
		BITMAPFILEHEADER bitMapFileHeader;
		BITMAPINFOHEADER bitMapInfoHeader;
		fread(&bitMapFileHeader, sizeof(BITMAPFILEHEADER), 1, pf);
		if (0x4D42 != bitMapFileHeader.bfType)
		{
			LOG(ERROR)<< path << "此文件不是BMP文件！" << endl;
			return false;
		}
		fread(&bitMapInfoHeader, sizeof(BITMAPINFOHEADER), 1, pf);
		/*LOG(INFO)<< "位图文件头：" << endl;
		LOG(INFO)<< "位图文件类型: " << bitMapFileHeader.bfType << endl;
		LOG(INFO)<< "位图文件大小: " << bitMapFileHeader.bfSize << endl;
		LOG(INFO)<< "偏移的字节数: " << bitMapFileHeader.bfOffBits << endl;*/

		/*
		LOG(INFO)<< "\n位图信息头：" << endl;
		LOG(INFO)<< "信息头占用字节数：" << bitMapInfoHeader.biSize << endl;
		LOG(INFO)<< "位图宽度： " << bitMapInfoHeader.biWidth << endl;
		LOG(INFO)<< "位图高度： " << bitMapInfoHeader.biHeight << endl;
		LOG(INFO)<< "位图压缩类型： " << bitMapInfoHeader.biCompression << endl;
		LOG(INFO)<< "位图每像素占用位数： " << bitMapInfoHeader.biBitCount << endl;
		LOG(INFO)<< "位图数据占用字节数： " << bitMapInfoHeader.biSizeImage << endl;*/

		D.FaceImageHeight = bitMapInfoHeader.biHeight;
		D.FaceImageWidth = bitMapInfoHeader.biWidth;
		D.ImageBitSize = bitMapFileHeader.bfSize;
	}
	else
	{
		D.ImageTypeReal = -1;
		D.ImageTypeDeclare = "UNKNOWN";
		D.FaceImageHeight = -1;
		D.FaceImageWidth = -1;
		D.ImageBitSize = -1;
		LOG(INFO) << "未知的图片类型";
	}
	return true;
}
