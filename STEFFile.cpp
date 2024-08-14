/*
 * STEFFile.cpp
 *
 *  Created on: Sep 17, 2018
 *      Author: echo
 */

//#include <iostream>
#include <string>
#include <map>
#include "Ptypes.h"
#include "STEFFile.h"
#include "EFFile.h"

#if USE_OPENJPEG

#include <openjpeg-2.2\openjpeg.h>
#include "JP2.h"

#endif

void EF_Default_File_Init(STEFFile *file) {

    file->Tag = 0;
    file->Index = EF_UNKNOWN;
    file->name[0] = '\0';
    file->Id[0] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}

void EF_COM_File_Init(STEFFile *file) {
    file->Tag = 0x60;
    file->Index = EF_COM;
    file->Id[0] = 0x01;
    file->Id[1] = 0x1E;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.COM", sizeof("EF.COM"));
    file->name[sizeof("EF.COM")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}

void EF_DG1_File_Init(STEFFile *file) {
    file->Tag = 0x61;
    file->Index = EF_DG1;
    file->Id[0] = 0x01;
    file->Id[1] = 0x01;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG1", sizeof("EF.DG1"));
    file->name[sizeof("EF.DG1")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}

void EF_DG2_File_Init(STEFFile *file) {
    file->Tag = 0x75;
    file->Index = EF_DG2;
    file->Id[0] = 0x01;
    file->Id[1] = 0x02;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG2", sizeof("EF.DG2"));
    file->name[sizeof("EF.DG2")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG3_File_Init(STEFFile* file) {
    file->Tag = 0x63;
    file->Index = EF_DG3;
    file->Id[0] = 0x01;
    file->Id[1] = 0x03;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG3", sizeof("EF.DG3"));
    file->name[sizeof("EF.DG3")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
//
void EF_DG4_File_Init(STEFFile* file) {
    file->Tag = 0x76;
    file->Index = EF_DG4;
    file->Id[0] = 0x01;
    file->Id[1] = 0x04;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG4", sizeof("EF.DG4"));
    file->name[sizeof("EF.DG4")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG5_File_Init(STEFFile* file) {
    file->Tag = 0x65;
    file->Index = EF_DG5;
    file->Id[0] = 0x01;
    file->Id[1] = 0x05;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG5", sizeof("EF.DG5"));
    file->name[sizeof("EF.DG5")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG6_File_Init(STEFFile* file) {
    file->Tag = 0x66;
    file->Index = EF_DG6;
    file->Id[0] = 0x01;
    file->Id[1] = 0x06;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG6", sizeof("EF.DG6"));
    file->name[sizeof("EF.DG6")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG7_File_Init(STEFFile* file) {
    file->Tag = 0x67;
    file->Index = EF_DG7;
    file->Id[0] = 0x01;
    file->Id[1] = 0x07;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG7", sizeof("EF.DG7"));
    file->name[sizeof("EF.DG7")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG8_File_Init(STEFFile* file) {
    file->Tag = 0x68;
    file->Index = EF_DG8;
    file->Id[0] = 0x01;
    file->Id[1] = 0x08;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG8", sizeof("EF.DG8"));
    file->name[sizeof("EF.DG8")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG9_File_Init(STEFFile* file) {
    file->Tag = 0x69;
    file->Index = EF_DG9;
    file->Id[0] = 0x01;
    file->Id[1] = 0x09;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG9", sizeof("EF.DG9"));
    file->name[sizeof("EF.DG9")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG10_File_Init(STEFFile* file) {
    file->Tag = 0x6A;
    file->Index = EF_DG10;
    file->Id[0] = 0x01;
    file->Id[1] = 0x0A;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG10", sizeof("EF.DG10"));
    file->name[sizeof("EF.DG10")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG11_File_Init(STEFFile* file) {
    file->Tag = 0x6b;
    file->Index = EF_DG11;
    file->Id[0] = 0x01;
    file->Id[1] = 0x0B;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG11", sizeof("EF.DG11"));
    file->name[sizeof("EF.DG11")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG12_File_Init(STEFFile* file) {
    file->Tag = 0x6c;
    file->Index = EF_DG12;
    file->Id[0] = 0x01;
    file->Id[1] = 0x0C;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG12", sizeof("EF.DG12"));
    file->name[sizeof("EF.DG12")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG13_File_Init(STEFFile* file) {
    file->Tag = 0x6D;
    file->Index = EF_DG13;
    file->Id[0] = 0x01;
    file->Id[1] = 0x0D;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG13", sizeof("EF.DG13"));
    file->name[sizeof("EF.DG13")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG14_File_Init(STEFFile* file) {
    file->Tag = 0x6E;
    file->Index = EF_DG14;
    file->Id[0] = 0x01;
    file->Id[1] = 0x0E;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG14", sizeof("EF.DG14"));
    file->name[sizeof("EF.DG14")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG15_File_Init(STEFFile* file) {
    file->Tag = 0x6f;
    file->Index = EF_DG15;
    file->Id[0] = 0x01;
    file->Id[1] = 0x0F;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG15", sizeof("EF.DG15"));
    file->name[sizeof("EF.DG15")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_DG16_File_Init(STEFFile* file) {
    file->Tag = 0x70;
    file->Index = EF_DG16;
    file->Id[0] = 0x01;
    file->Id[1] = 0x10;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.DG16", sizeof("EF.DG16"));
    file->name[sizeof("EF.DG16")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
//
void EF_SOD_File_Init(STEFFile* file) {
    file->Tag = 0x77;
    file->Index = EF_SOD;
    file->Id[0] = 0x01;
    file->Id[1] = 0x1D;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.SOD", sizeof("EF.SOD"));
    file->name[sizeof("EF.SOD")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}

void EF_CARDACCESS_File_Init(STEFFile* file) {
    file->Tag = 0;
    file->Index = EF_CardAccess;
    file->Id[0] = 0x01;
    file->Id[1] = 0x1C;
    file->Id[2] = '\0';
    memcpy(file->name, "EF_CardAccess", sizeof("EF_CardAccess"));
    file->name[sizeof("EF_CardAccess")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_ART_INFO_File_Init(STEFFile* file) {
    file->Tag = 0;
    file->Index = EF_ATR_INFO;
    file->Id[0] = 0x2f;
    file->Id[1] = 0x01;
    file->Id[2] = '\0';
    memcpy(file->name, "EF_ART_INFO", sizeof("EF_ART_INFO"));
    file->name[sizeof("EF_ART_INFO")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}

void EF_CARDSECURITY_File_Init(STEFFile* file) {
    file->Tag = 0;
    file->Index = EF_CARDSECURITY;
    file->Id[0] = 0x01;
    file->Id[1] = 0x1D;
    file->Id[2] = '\0';
    memcpy(file->name, "EF_CardSecurity", sizeof("EF_CardSecurity"));
    file->name[sizeof("EF_CardSecurity")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}

void EF_IDINFO_File_Init(STEFFile *file) {
    file->Tag = 0;
    file->Index = EF_IDINFO;
    file->Id[0] = '\0';
    memcpy(file->name, "EF.IDINFO", sizeof("EF.IDINFO"));

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}

void EF_IDPIC_File_Init(STEFFile *file) {
    file->Tag = 0;
    file->Index = EF_IDPIC;
    file->Id[0] = '\0';
    memcpy(file->name, "EF.IDPIC", sizeof("EF.IDPIC"));
    file->name[sizeof("EF.IDPIC")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}

void STEFilesInit(STEFFileSystem *fileSystem) {

    EF_COM_File_Init(&(fileSystem->stEFFiles[0]));
    EF_DG1_File_Init(&(fileSystem->stEFFiles[1]));
    EF_DG2_File_Init(&(fileSystem->stEFFiles[2]));
    EF_DG3_File_Init(&(fileSystem->stEFFiles[3]));
    EF_DG4_File_Init(&(fileSystem->stEFFiles[4]));
    EF_DG5_File_Init(&(fileSystem->stEFFiles[5]));
    EF_DG6_File_Init(&(fileSystem->stEFFiles[6]));
    EF_DG7_File_Init(&(fileSystem->stEFFiles[7]));
    EF_DG8_File_Init(&(fileSystem->stEFFiles[8]));
    EF_DG9_File_Init(&(fileSystem->stEFFiles[9]));
    EF_DG10_File_Init(&(fileSystem->stEFFiles[10]));
    EF_DG11_File_Init(&(fileSystem->stEFFiles[11]));
    EF_DG12_File_Init(&(fileSystem->stEFFiles[12]));
    EF_DG13_File_Init(&(fileSystem->stEFFiles[13]));
    EF_DG14_File_Init(&(fileSystem->stEFFiles[14]));
    EF_DG15_File_Init(&(fileSystem->stEFFiles[15]));
    EF_DG16_File_Init(&(fileSystem->stEFFiles[16]));
    EF_SOD_File_Init(&(fileSystem->stEFFiles[17]));
    EF_IDINFO_File_Init(&(fileSystem->stEFFiles[18]));
    EF_IDPIC_File_Init(&(fileSystem->stEFFiles[19]));
    EF_CARDACCESS_File_Init(&(fileSystem->stEFFiles[20]));
    EF_ART_INFO_File_Init(&(fileSystem->stEFFiles[21]));
    EF_CARDSECURITY_File_Init(&(fileSystem->stEFFiles[22]));
    fileSystem->count = 23;

    /*for (int i = 21; i < MAX_ST_EFFILE; i++) {
        EF_Default_File_Init(&(fileSystem->stEFFiles[i]));
    }*/
}

STEFFile *StIndexFindEFFile(EF_NAME name, STEFFileSystem *fileSystem) {
    return &(fileSystem->stEFFiles[name]);
}

STEFFile *StTagFindEFFile(unsigned char tag, STEFFileSystem *fileSystem) {
    for (int i = 0; i < MAX_ST_EFFILE - 1; i++) {
        if (tag == fileSystem->stEFFiles[i].Tag) {
            return &(fileSystem->stEFFiles[i]);
        }
    }

    return &(fileSystem->stEFFiles[MAX_ST_EFFILE - 1]);
}

