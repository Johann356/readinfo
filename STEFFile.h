/*
 * STEFFile.h
 *
 *  Created on: Sep 17, 2018
 *      Author: echo
 */

#ifndef STEFFILE_H_
#define STEFFILE_H_

#include "Ptypes.h"
#include "EFFile.h"
#define MAX_ST_EFFILE 22

typedef struct STEFFileSystem;

class STEFFileClass {

};

typedef struct STEFFile {
  unsigned char Tag;
  EF_NAME Index;
  int resultLen;
  char Id[3];
  char name[10];
  char result[1024 + 1];
  char resultPath[1024 + 1];
  char (*FileParse)(std::string &data, STEFFileSystem *fileSystem);
  char (*Valid)(void);

} STEFFile;

typedef struct STEFFileSystem {

  STEFFile stEFFiles[MAX_ST_EFFILE];
  //std::map<std::string , std::string> result;
  int count;

} STEFFileSystem;

extern void STEFilesInit(STEFFileSystem *fileSystem);
extern STEFFile *StIndexFindEFFile(EF_NAME name, STEFFileSystem *fileSystem);
extern STEFFile *StTagFindEFFile(unsigned char tag, STEFFileSystem *fileSystem);

extern char EFFileDummyParse(std::string &data, STEFFileSystem *fileSystem);
extern char EF_COM_FileParse(std::string &data, STEFFileSystem *fileSystem);
extern char EF_DG1_FileParse(std::string &data, STEFFileSystem *fileSystem);
extern char EF_DG2_FileParse(std::string &data, STEFFileSystem *fileSystem);
extern char EFFileDummyValid();
extern char STDefaultValid();

#endif /* STEFFILE_H_ */
