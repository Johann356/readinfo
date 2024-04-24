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

#include <openjpeg.h>
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

void EF_DG11_File_Init(STEFFile *file) {
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

void EF_CARDACCESS_File_Init(STEFFile* file)
{
    file->Tag = 0;
    file->Index = EF_CARDACCESS;
    file->Id[0] = 0x01;
    file->Id[1] = 0x1C;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.ARDACCESS", sizeof("EF.ARDACCESS"));
    file->name[sizeof("EF.ARDACCESS")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_ATR_INFO_File_Init(STEFFile* file)
{
    file->Tag = 0;
    file->Index = EF_ATR_INFO;
    file->Id[0] = 0x2F;
    file->Id[1] = 0x01;
    file->Id[2] = '\0';
    memcpy(file->name, "EF.ART/INFO", sizeof("EF.ART/INFO"));
    file->name[sizeof("EF.ART/INFO")] = '\0';

    file->resultLen = 0;
    file->result[0] = '\0';
    file->resultPath[0] = '\0';

    file->FileParse = NULL;
    file->Valid = NULL;
}
void EF_CARDSECURITY_File_Init(STEFFile* file)
{
    file->Tag = 0;
    file->Index = EF_CARDSECURITY;
    file->Id[0] = 0x01;
    file->Id[1] = 0x1D;
    file->Id[2] = '\0';
    memcpy(file->name, "EF_CARDSECURITY", sizeof("EF_CARDSECURITY"));
    file->name[sizeof("EF_CARDSECURITY")] = '\0';

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
    EF_DG11_File_Init(&(fileSystem->stEFFiles[11]));
    EF_DG15_File_Init(&(fileSystem->stEFFiles[15]));
    EF_SOD_File_Init(&(fileSystem->stEFFiles[17]));
    EF_IDINFO_File_Init(&(fileSystem->stEFFiles[18]));
    EF_IDPIC_File_Init(&(fileSystem->stEFFiles[19]));
    EF_CARDACCESS_File_Init(&(fileSystem->stEFFiles[20]));
    EF_ATR_INFO_File_Init(&(fileSystem->stEFFiles[21]));
    EF_CARDSECURITY_File_Init(&(fileSystem->stEFFiles[22]));
    fileSystem->count = 8;

    for (int i = 3; i < MAX_ST_EFFILE; i++) {
        if (i == 22|| i == 21|| i == 20|| i == 18 || i == 19 || i == 11 || i == 15 || i == 17) {
            continue;
        }
        EF_Default_File_Init(&(fileSystem->stEFFiles[i]));
    }
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
    return NULL;
    //return &(fileSystem->stEFFiles[MAX_ST_EFFILE - 1]);
}

