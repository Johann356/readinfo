/*
 * jp2.cpp
 *
 *  Created on: Sep 11, 2018
 *      Author: echo
 */

#include "JP2.h"
#include "Ptypes.h"
#include <vector>
#include <opencv2/opencv.hpp>
#include <fstream>
#include "jconfig.h"
#include "jerror.h"
#include "jmorecfg.h"
#include "jpeglib.h"
#include "turbojpeg.h"
#include <windows.h>
#if USE_OPENJPEG
#include <openjpeg-2.2\openjpeg.h>
#endif

#if USE_OPENJPEG

#ifdef DEBUG
static void info_callback(const char* msg, void* client_data)
{
	LOG(INFO) << msg << std::endl;
}

static void warning_callback(const char* msg, void* client_data)
{
	LOG(INFO) << msg << std::endl;
}

static void error_callback(const char* msg, void* client_data)
{
	LOG(INFO) << msg << std::endl;
}
#endif

struct opj_stream_memory
{
	char* input;
	OPJ_SIZE_T input_len;
	OPJ_SIZE_T read_offset;
};

static void opj_stream_free_memory(void* p_user_data)
{
	if (p_user_data) {
		struct opj_stream_memory* posm = (struct opj_stream_memory*)p_user_data;
		if (posm->input) {
			free(posm->input);
			posm->input = NULL;
		}
		free(p_user_data);
	}
}

static OPJ_SIZE_T opj_stream_read_memory(void* p_buffer, OPJ_SIZE_T p_nb_bytes,
	void* p_user_data)
{
	struct opj_stream_memory* osm = (struct opj_stream_memory*)p_user_data;
	OPJ_SIZE_T left = osm->input_len - osm->read_offset;
	OPJ_SIZE_T cpySize = MIN(left, p_nb_bytes);
	if (p_buffer && cpySize) {
		memcpy(p_buffer, osm->input + osm->read_offset, cpySize);
		osm->read_offset += cpySize;
		return cpySize;
	}
	return (OPJ_SIZE_T)-1;
}

static opj_stream_t* opj_stream_create_memory_stream(char* buf, size_t size)
{
	opj_stream_t* s = NULL;
	struct opj_stream_memory* posm = NULL;

	if (!buf || !size) {
		return NULL;
	}

	posm = (struct opj_stream_memory*)calloc(1, sizeof(struct opj_stream_memory));
	if (!posm) {
		return NULL;
	}
	posm->input = (char*)calloc(size, 1);
	if (!posm->input) {
		opj_stream_free_memory(posm);
		return NULL;
	}
	memcpy(posm->input, buf, size);
	posm->input_len = size;
	posm->read_offset = 0;

	s = opj_stream_default_create(OPJ_TRUE);
	if (!s) {
		opj_stream_free_memory(posm);
		return NULL;
	}

	opj_stream_set_user_data(s, posm, opj_stream_free_memory);
	opj_stream_set_user_data_length(s, size);
	opj_stream_set_read_function(s, opj_stream_read_memory);
	return s;
}

BOOL imagetobmp(opj_image_t* image, const char* outfile)
{
	int w, h;
	int i, pad;
	FILE* fdest = NULL;
	int adjustR, adjustG, adjustB;

	if (image->comps[0].prec < 8) {
		fprintf(stderr, "imagetobmp: Unsupported precision: %d\n",
			image->comps[0].prec);
		std::cout << "image->comps[0].prec < 8" << std::endl;
		return FALSE;
	}
	if (image->numcomps >= 3 && image->comps[0].dx == image->comps[1].dx
		&& image->comps[1].dx == image->comps[2].dx
		&& image->comps[0].dy == image->comps[1].dy
		&& image->comps[1].dy == image->comps[2].dy
		&& image->comps[0].prec == image->comps[1].prec
		&& image->comps[1].prec == image->comps[2].prec
		&& image->comps[0].sgnd == image->comps[1].sgnd
		&& image->comps[1].sgnd == image->comps[2].sgnd) {

		/* -->> -->> -->> -->>
		24 bits color
		<<-- <<-- <<-- <<-- */

		fdest = fopen(outfile, "wb+");//wb
		if (!fdest) {
			fprintf(stderr, "ERROR -> failed to open %s for writing\n", outfile);
			return 1;
		}

		w = (int)image->comps[0].w;
		h = (int)image->comps[0].h;

		fprintf(fdest, "BM");

		/* FILE HEADER */
		/* ------------- */
		fprintf(fdest, "%c%c%c%c",
			(OPJ_UINT8)(h * w * 3 + 3 * h * (w % 2) + 54) & 0xff,
			(OPJ_UINT8)((h * w * 3 + 3 * h * (w % 2) + 54) >> 8) & 0xff,
			(OPJ_UINT8)((h * w * 3 + 3 * h * (w % 2) + 54) >> 16) & 0xff,
			(OPJ_UINT8)((h * w * 3 + 3 * h * (w % 2) + 54) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
			((0) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (54) & 0xff, ((54) >> 8) & 0xff, ((54) >> 16) & 0xff,
			((54) >> 24) & 0xff);

		/* INFO HEADER   */
		/* ------------- */
		fprintf(fdest, "%c%c%c%c", (40) & 0xff, ((40) >> 8) & 0xff, ((40) >> 16) & 0xff,
			((40) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (OPJ_UINT8)((w) & 0xff),
			(OPJ_UINT8)((w) >> 8) & 0xff,
			(OPJ_UINT8)((w) >> 16) & 0xff,
			(OPJ_UINT8)((w) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (OPJ_UINT8)((h) & 0xff),
			(OPJ_UINT8)((h) >> 8) & 0xff,
			(OPJ_UINT8)((h) >> 16) & 0xff,
			(OPJ_UINT8)((h) >> 24) & 0xff);
		fprintf(fdest, "%c%c", (1) & 0xff, ((1) >> 8) & 0xff);
		fprintf(fdest, "%c%c", (24) & 0xff, ((24) >> 8) & 0xff);
		fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
			((0) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (OPJ_UINT8)(3 * h * w + 3 * h * (w % 2)) & 0xff,
			(OPJ_UINT8)((h * w * 3 + 3 * h * (w % 2)) >> 8) & 0xff,
			(OPJ_UINT8)((h * w * 3 + 3 * h * (w % 2)) >> 16) & 0xff,
			(OPJ_UINT8)((h * w * 3 + 3 * h * (w % 2)) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (7834) & 0xff, ((7834) >> 8) & 0xff,
			((7834) >> 16) & 0xff, ((7834) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (7834) & 0xff, ((7834) >> 8) & 0xff,
			((7834) >> 16) & 0xff, ((7834) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
			((0) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
			((0) >> 24) & 0xff);

		if (image->comps[0].prec > 8) {
			adjustR = (int)image->comps[0].prec - 8;
			//printf("BMP CONVERSION: Truncating component 0 from %d bits to 8 bits\n",
			//	image->comps[0].prec);
		}
		else {
			adjustR = 0;
		}
		if (image->comps[1].prec > 8) {
			adjustG = (int)image->comps[1].prec - 8;
			/*		printf("BMP CONVERSION: Truncating component 1 from %d bits to 8 bits\n",
						image->comps[1].prec);*/
		}
		else {
			adjustG = 0;
		}
		if (image->comps[2].prec > 8) {
			adjustB = (int)image->comps[2].prec - 8;
			/*printf("BMP CONVERSION: Truncating component 2 from %d bits to 8 bits\n",
				image->comps[2].prec);*/
		}
		else {
			adjustB = 0;
		}

		for (i = 0; i < w * h; i++) {
			OPJ_UINT8 rc, gc, bc;
			int r, g, b;

			r = image->comps[0].data[w * h - ((i) / (w)+1) * w + (i) % (w)];
			r += (image->comps[0].sgnd ? 1 << (image->comps[0].prec - 1) : 0);
			if (adjustR > 0) {
				r = ((r >> adjustR) + ((r >> (adjustR - 1)) % 2));
			}
			if (r > 255) {
				r = 255;
			}
			else if (r < 0) {
				r = 0;
			}
			rc = (OPJ_UINT8)r;

			g = image->comps[1].data[w * h - ((i) / (w)+1) * w + (i) % (w)];
			g += (image->comps[1].sgnd ? 1 << (image->comps[1].prec - 1) : 0);
			if (adjustG > 0) {
				g = ((g >> adjustG) + ((g >> (adjustG - 1)) % 2));
			}
			if (g > 255) {
				g = 255;
			}
			else if (g < 0) {
				g = 0;
			}
			gc = (OPJ_UINT8)g;

			b = image->comps[2].data[w * h - ((i) / (w)+1) * w + (i) % (w)];
			b += (image->comps[2].sgnd ? 1 << (image->comps[2].prec - 1) : 0);
			if (adjustB > 0) {
				b = ((b >> adjustB) + ((b >> (adjustB - 1)) % 2));
			}
			if (b > 255) {
				b = 255;
			}
			else if (b < 0) {
				b = 0;
			}
			bc = (OPJ_UINT8)b;

			fprintf(fdest, "%c%c%c", bc, gc, rc);

			if ((i + 1) % w == 0) {
				for (pad = ((3 * w) % 4) ? (4 - (3 * w) % 4) : 0; pad > 0; pad--) { /* ADD */
					fprintf(fdest, "%c", 0);
				}
			}
		}
		fclose(fdest);
	}
	else {            /* Gray-scale */

					  /* -->> -->> -->> -->>
					  8 bits non code (Gray scale)
					  <<-- <<-- <<-- <<-- */
		fdest = fopen(outfile, "wb+");
		if (!fdest) {
			fprintf(stderr, "ERROR -> failed to open %s for writing\n", outfile);
			std::cout << "fdest = fopen(outfile, wb + );" << std::endl;
			return FALSE;
		}
		if (image->numcomps > 1) {
			fprintf(stderr, "imagetobmp: only first component of %d is used.\n",
				image->numcomps);
		}
		w = (int)image->comps[0].w;
		h = (int)image->comps[0].h;

		fprintf(fdest, "BM");

		/* FILE HEADER */
		/* ------------- */
		fprintf(fdest, "%c%c%c%c", (OPJ_UINT8)(h * w + 54 + 1024 + h * (w % 2)) & 0xff,
			(OPJ_UINT8)((h * w + 54 + 1024 + h * (w % 2)) >> 8) & 0xff,
			(OPJ_UINT8)((h * w + 54 + 1024 + h * (w % 2)) >> 16) & 0xff,
			(OPJ_UINT8)((h * w + 54 + 1024 + w * (w % 2)) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
			((0) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (54 + 1024) & 0xff, ((54 + 1024) >> 8) & 0xff,
			((54 + 1024) >> 16) & 0xff,
			((54 + 1024) >> 24) & 0xff);

		/* INFO HEADER */
		/* ------------- */
		fprintf(fdest, "%c%c%c%c", (40) & 0xff, ((40) >> 8) & 0xff, ((40) >> 16) & 0xff,
			((40) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (OPJ_UINT8)((w) & 0xff),
			(OPJ_UINT8)((w) >> 8) & 0xff,
			(OPJ_UINT8)((w) >> 16) & 0xff,
			(OPJ_UINT8)((w) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (OPJ_UINT8)((h) & 0xff),
			(OPJ_UINT8)((h) >> 8) & 0xff,
			(OPJ_UINT8)((h) >> 16) & 0xff,
			(OPJ_UINT8)((h) >> 24) & 0xff);
		fprintf(fdest, "%c%c", (1) & 0xff, ((1) >> 8) & 0xff);
		fprintf(fdest, "%c%c", (8) & 0xff, ((8) >> 8) & 0xff);
		fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
			((0) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (OPJ_UINT8)(h * w + h * (w % 2)) & 0xff,
			(OPJ_UINT8)((h * w + h * (w % 2)) >> 8) & 0xff,
			(OPJ_UINT8)((h * w + h * (w % 2)) >> 16) & 0xff,
			(OPJ_UINT8)((h * w + h * (w % 2)) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (7834) & 0xff, ((7834) >> 8) & 0xff,
			((7834) >> 16) & 0xff, ((7834) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (7834) & 0xff, ((7834) >> 8) & 0xff,
			((7834) >> 16) & 0xff, ((7834) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (256) & 0xff, ((256) >> 8) & 0xff,
			((256) >> 16) & 0xff, ((256) >> 24) & 0xff);
		fprintf(fdest, "%c%c%c%c", (256) & 0xff, ((256) >> 8) & 0xff,
			((256) >> 16) & 0xff, ((256) >> 24) & 0xff);

		if (image->comps[0].prec > 8) {
			adjustR = (int)image->comps[0].prec - 8;
			/*	printf("BMP CONVERSION: Truncating component 0 from %d bits to 8 bits\n",
					image->comps[0].prec);*/
		}
		else {
			adjustR = 0;
		}

		for (i = 0; i < 256; i++) {
			fprintf(fdest, "%c%c%c%c", i, i, i, 0);
		}

		for (i = 0; i < w * h; i++) {
			int r;

			r = image->comps[0].data[w * h - ((i) / (w)+1) * w + (i) % (w)];
			r += (image->comps[0].sgnd ? 1 << (image->comps[0].prec - 1) : 0);
			if (adjustR > 0) {
				r = ((r >> adjustR) + ((r >> (adjustR - 1)) % 2));
			}
			if (r > 255) {
				r = 255;
			}
			else if (r < 0) {
				r = 0;
			}

			fprintf(fdest, "%c", (OPJ_UINT8)r);

			if ((i + 1) % w == 0) {
				for (pad = (w % 4) ? (4 - w % 4) : 0; pad > 0; pad--) { /* ADD */
					fprintf(fdest, "%c", 0);
				}
			}
		}
		fclose(fdest);
	}

	return TRUE;
}

int Jpeg2DIB_DeCompress(void* lpJpegBuffer, unsigned long nInSize, std::string filename, int& width, int& height, int& size)
{
	jpeg_decompress_struct cInfo;
	jpeg_create_decompress(&cInfo);
	jpeg_error_mgr errorMgr;
	cInfo.err = jpeg_std_error(&errorMgr);
	jpeg_mem_src(&cInfo, (const unsigned char*)lpJpegBuffer, nInSize);
	jpeg_read_header(&cInfo, TRUE);
	jpeg_start_decompress(&cInfo);
	width = cInfo.image_width;
	height = cInfo.image_height;
	size = nInSize;
	JSAMPROW row_pointer[1];
	int nBitCounts = cInfo.num_components * 8;
	int nWidthBits = cInfo.image_width * cInfo.num_components;
	unsigned long lOutSize = nWidthBits * cInfo.image_height;
	unsigned char* pOutBuffer = (unsigned char*)malloc(lOutSize);
	row_pointer[0] = pOutBuffer;
	while (cInfo.output_scanline < cInfo.output_height)
	{
		row_pointer[0] = pOutBuffer + (cInfo.image_height - cInfo.output_scanline - 1) * nWidthBits;
		jpeg_read_scanlines(&cInfo, row_pointer, 1);
	}
	jpeg_finish_decompress(&cInfo);
	jpeg_destroy_decompress(&cInfo);

	unsigned long nDestSize = abs((int)cInfo.image_width) * 4 * abs((int)cInfo.image_height);
	DWORD* pArgbData = (DWORD*)malloc(nDestSize);
	DWORD* pArgbDataTemp = pArgbData;
	unsigned char* pRgbData = (unsigned char*)pOutBuffer;
	int nOffset = 0, i = 0;
	while (nOffset < lOutSize)
	{
		/*注意，在window系统中内存以little-endian存储，即低字节存放在内存的低位 0xARGB -- 0xBGRA
		/除去忽略的A 即alpha通道位  读取内存中的数据为 BGR 需要转换成 RGB
		/bmp位图会忽略掉alpha通道位，设置成任意数值都可以以
		*/
		DWORD dwColor = 0x00000000 + RGB(pRgbData[nOffset + 2], pRgbData[nOffset + 1], pRgbData[nOffset]);
		*pArgbDataTemp = dwColor;
		pArgbDataTemp++;
		nOffset += 3;
	}

	BITMAPFILEHEADER fHeader;
	int nStructSize1 = sizeof(BITMAPFILEHEADER);
	int nStructSize2 = sizeof(BITMAPINFO) - sizeof(RGBQUAD);
	memset(&fHeader, 0, nStructSize1);
	memcpy(&fHeader, "BM", 2);
	fHeader.bfSize = nStructSize1 + nStructSize2 + nDestSize;
	fHeader.bfOffBits = nStructSize1 + nStructSize2;
	BITMAPINFO bmpInfo = { nStructSize2 };
	bmpInfo.bmiHeader.biWidth = abs((int)cInfo.image_width);
	bmpInfo.bmiHeader.biHeight = abs((int)cInfo.image_height);
	bmpInfo.bmiHeader.biPlanes = 1;
	bmpInfo.bmiHeader.biBitCount = 32;
	bmpInfo.bmiHeader.biCompression = BI_RGB;
	bmpInfo.bmiHeader.biSizeImage = 0;
	FILE* fp = NULL;
	fopen_s(&fp, filename.c_str(), "wb+");
	if (NULL == fp) {
		std::cout << "can't not open: " << filename << std::endl;
		return FALSE;
	}
	fwrite(&fHeader, 1, nStructSize1, fp);
	fwrite(&bmpInfo, 1, nStructSize2, fp);
	fwrite(pArgbData, 1, nDestSize, fp);
	fclose(fp);

	free(pOutBuffer);
	free(pArgbData);
	return TRUE;
}

int Jpeg2000_DeCompress(void* lpJpegBuffer, unsigned long nInSize, std::string filename, int& width, int& height ,int& size)
{
	BOOL ret = FALSE;
	opj_codec_t* c = NULL;
	opj_stream_t* s = NULL;
	opj_image_t* image = NULL;
	opj_dparameters_t param;

	//jpeg2000
	do {
		opj_set_default_decoder_parameters(&param);

		s = opj_stream_create_memory_stream((char*)lpJpegBuffer, nInSize);
		if (!s) {
			break;
		}
		c = opj_create_decompress(OPJ_CODEC_J2K);
		if (!c) {
			break;
		}
#ifdef DEBUG
		opj_set_info_handler(c, info_callback, 00);
		opj_set_warning_handler(c, warning_callback, 00);
		opj_set_error_handler(c, error_callback, 00);
#endif
		if (!opj_setup_decoder(c, &param)) {
			break;
		}
		if (!opj_read_header(s, c, &image)) {
			break;
		}
		if (!param.nb_tile_to_decode) {
			/* Optional if you want decode the entire image */
			if (!opj_set_decode_area(c, image, (OPJ_INT32)(param.DA_x0), (OPJ_INT32)(param.DA_y0),
				(OPJ_INT32)(param.DA_x1), (OPJ_INT32)(param.DA_y1))) {
				break;
			}
			/* Get the decoded image */
			if (!(opj_decode(c, s, image) && opj_end_decompress(c, s))) {
				break;
			}
		}
		else {
			if (!opj_get_decoded_tile(c, s, image, param.tile_index)) {
				break;
			}
		}

	} while (0);

	if (image) {
		width = image->x1;
		height = image->y1;
		size = nInSize;
		ret = imagetobmp(image, filename.c_str());
	}

	if (c) {
		opj_destroy_codec(c);
	}
	if (s) {
		opj_stream_destroy(s);
	}
	if (image) {
		opj_image_destroy(image);
	}
	return ret;
}



//char jp2_to_bmp(std::string& data, std::string filename, int& width, int& height, int& size, int& version)
//{
//	version = -1;
//	BOOL ret = FALSE;
//#if USE_OPENJPEG
//
//	size_t offset;
//	int Jpeg_Version = 2000;
//	if (data.length() <= 84) {
//		std::cout << "data.length() <= 84" << std::endl;
//		return FALSE;
//	}
//
//	std::string magic_jpeg("\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46", 10);
//	std::string magic_jpeg2k("\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a", 10);
//	std::string magic_jpeg2k_other("\xff\x4f\xff\x51", 4);
//
//
//	offset = data.find(magic_jpeg2k_other.data(), 0, magic_jpeg2k_other.size());
//	if (offset == std::string::npos) {
//		offset = data.find(magic_jpeg2k.data(), 0, magic_jpeg2k.size());
//		if (offset == std::string::npos) {
//			offset = data.find(magic_jpeg.data(), 0, magic_jpeg.size());
//			if (offset == std::string::npos) {
//				// invalid jpeg files
//				std::cout << "offset == std::string::npos" << std::endl;
//				return FALSE;
//			}
//			Jpeg_Version = 97;
//		}
//	}
//	version = Jpeg_Version;
//	if (Jpeg_Version == 97) {
//		ret = Jpeg2DIB_DeCompress((char*)data.data() + offset, data.size() - offset, filename, width, height, size);
//	}
//	else {
//		ret = Jpeg2000_DeCompress((char*)data.data() + offset, data.size() - offset, filename, width, height, size);
//	}
//
//#endif
//	return ret;
//}
char jp2_to_bmp(std::string& data, std::string filename, int& width, int& height, int& size, int& version)
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
	while ((data.find(flag1, p) != data.npos || data.find(flag2, p) != data.npos))
	{
		if (data.find(flag1, p) != data.npos)
			p = data.find(flag1, p);
		else
			p = data.find(flag2, p);
		int l = 0;
		std::string l_binary;
		if (data[p + 2] == '\x83')
			l_binary = data.substr(p + 3, 3);
		else if (data[p + 2] == '\x82')
			l_binary = data.substr(p + 3, 2);
		else if (data[p + 2] == '\x81')
			l_binary = data.substr(p + 3, 1);
		l = binaryStringToInt(l_binary);
		
		std::string data_temp = data.substr(p + 2 + 1 + l_binary.length(), l);
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
		std::string dest_name = filename.substr(0, pos);
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
			std::string dest_name = filename.substr(0, pos);
			if (cnt != 0)
				dest_name += to_string(cnt);
			dest_name += ".bmp";
			cv::imwrite(dest_name, img);
		}
		p += 2 + l_binary.length() + l;
		cnt++;
	}
	return true;
}

#endif