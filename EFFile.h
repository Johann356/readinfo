/*
 * EFFile.h
 *
 *  Created on: Sep 16, 2018
 *      Author: echo
 */

#ifndef EFFILE_H_
#define EFFILE_H_

#include <map>
#include "Ptypes.h"
#include <string>

#include <vector>

enum EF_NAME {
    EF_UNKNOWN = -1,
    EF_COM = 0,
    EF_DG1 = 1,
    EF_DG2 = 2,
    EF_DG3 = 3,
    EF_DG4 = 4,
    EF_DG5 = 5,
    EF_DG6 = 6,
    EF_DG7 = 7,
    EF_DG8 = 8,
    EF_DG9 = 9,
    EF_DG10 = 10,
    EF_DG11 = 11,
    EF_DG12 = 12,
    EF_DG13 = 13,
    EF_DG14 = 14,
    EF_DG15 = 15,
    EF_DG16 = 16,
    EF_SOD = 17,
    EF_IDINFO = 18,
    EF_IDPIC = 19,
    EF_CARDACCESS = 20,
    EF_ATR_INFO = 21,
    EF_CARDSECURITY = 22
};

class EFFile {
 public:
  std::map<std::string, std::string> result;
 public:
  unsigned char Tag;
  EF_NAME Index;
  char Id[3];
  char name[100];

  EFFile() {
      this->Tag = 0;
      this->Index = EF_UNKNOWN;
      this->name[0] = '\0';
      this->Id[0] = '\0';
  }

  virtual char FileParse(std::string &data) = 0;
  virtual char Valid() { return true; }
};

class EFFileDummy : public EFFile {
 public:
  char FileParse(std::string &data) { return false; }
  char Valid() { return false; }
};

class EFFileSystem {
 private:
  std::map<unsigned char, EFFile *> tagFiles;
  std::map<EF_NAME, EFFile *> indexFiles;
  EFFileDummy dummy;

 public:
  EFFileSystem();
  ~EFFileSystem();

 private:
  void AddEFFile(EFFile *pfile);

 public:
  EFFile &operator[](EF_NAME name);
  EFFile &operator[](unsigned char tag);
};

class EF_COM_File : public EFFile {
 public:
  EF_COM_File();
  virtual char FileParse(std::string &data);
};

class EF_DG1_File : public EFFile {
 public:
  EF_DG1_File();
  virtual char FileParse(std::string &data);
};

class EF_DG2_File : public EFFile {
 public:
  EF_DG2_File();
  virtual char FileParse(std::string &data);
};

class EF_DG11_File : public EFFile {
 public:
  EF_DG11_File();
  virtual char FileParse(std::string &data);
};

#endif /* EFFILE_H_ */
