/*
 * JP2.h
 *
 *  Created on: Sep 11, 2018
 *      Author: echo
 */

#ifndef JP2_H_
#define JP2_H_

#include "Ptypes.h"
#include "utils.h"
char jp2_to_bmp(std::string &data, std::string filename, int& width, int& height, int& size,int& version);
int Jpeg2DIB_DeCompress(void* lpJpegBuffer, unsigned long nInSize, std::string filename, int& width, int& height, int& size);
int Jpeg2000_DeCompress(void* lpJpegBuffer, unsigned long nInSize, std::string filename, int& width, int& height, int& size);
#endif /* JP2_H_ */
