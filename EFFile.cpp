//#include <iostream>
#include <string>
#include <map>
#include <vector>
#include "Ptypes.h"
#include "EFFile.h"

#if USE_OPENJPEG
#include <openjpeg.h>
#include "JP2.h"
#endif

EFFileSystem::EFFileSystem() {
    this->AddEFFile(new EF_COM_File());
    this->AddEFFile(new EF_DG1_File());
    this->AddEFFile(new EF_DG2_File());
}

EFFileSystem::~EFFileSystem() {
    std::map<EF_NAME, EFFile *>::iterator it = this->indexFiles.begin();
    while (it != this->indexFiles.end()) {
        delete it->second;
        ++it;
    }

//	this->indexFiles.clear();
//	this->tagFiles.clear();
}

void EFFileSystem::AddEFFile(EFFile *pfile) {
    if (NULL == pfile) {
        return;
    }

    this->indexFiles[pfile->Index] = pfile;
    this->tagFiles[pfile->Tag] = pfile;
}

EFFile &EFFileSystem::operator[](EF_NAME name) {
    std::map<EF_NAME, EFFile *>::iterator it = this->indexFiles.find(name);
    if (it == this->indexFiles.end()) {
        return dummy;
    }

    return *((*it).second);
}

EFFile &EFFileSystem::operator[](unsigned char tag) {
    std::map<unsigned char, EFFile *>::iterator it = this->tagFiles.find(tag);
    if (it == this->tagFiles.end()) {
        return dummy;
    }

    return *((*it).second);
}

//-------------------------------------------------------------------

EF_COM_File::EF_COM_File() {
    this->Tag = 0x60;
    this->Index = EF_COM;

    this->Id[0] = 0x01;
    this->Id[1] = 0x1E;
    this->Id[2] = 0;
    memcpy(this->name, "EF.COM", sizeof("EF.COM"));
    this->name[sizeof("EF.COM")] = '\0';
}

char EF_COM_File::FileParse(std::string &data) {
    return true;
}

EF_DG1_File::EF_DG1_File() {
    this->Tag = 0x61;
    //this->Id.assign("\x01\x01",2);
    //this->name.assign("EF_DG1",sizeof("EF_DG1"));
    this->Index = EF_DG1;

    this->Id[0] = 0x01;
    this->Id[1] = 0x01;
    this->Id[2] = 0;
    memcpy(this->name, "EF.DG1", sizeof("EF.DG1"));
    this->name[sizeof("EF.DG1")] = '\0';
}

char EF_DG1_File::FileParse(std::string &data) {
    std::string flag("\x5F\x1F", 2);
    size_t it = data.find(flag);
    if (it == std::string::npos) {
        return false;
    }

    std::string mrz = data.substr(it + 3);
//#if USE_LOG_LEVEL1
//    std::cout << "EF_DG1_File::FileParse: " << mrz << std::endl;
//#endif
    return true;
}

EF_DG2_File::EF_DG2_File() {
    this->Tag = 0x75;
    //this->Id.assign("\x01\x02",2);
    //this->name.assign("EF_DG2",sizeof("EF_DG2"));
    this->Index = EF_DG2;

    this->Id[0] = 0x01;
    this->Id[1] = 0x02;
    this->Id[2] = 0;
    memcpy(this->name, "EF.DG2", sizeof("EF.DG2"));
    this->name[sizeof("EF.DG2")] = '\0';

}

char EF_DG2_File::FileParse(std::string &data) {
//    char path[256];
//    MakeFullPath(path, DG2_FILE_NAME);
//
//#if USE_OPENJPEG
//    result["head"] = path;
//    return jp2_to_bmp(data,path);
//#else
    return true;
//#endif
}

//CardAccess
EF_CardAccess_File::EF_CardAccess_File() {
    this->Tag = 0;
    //this->Id.assign("\x01\x02",2);
    //this->name.assign("EF_DG2",sizeof("EF_DG2"));
    this->Id[0] = 0x01;
    this->Id[1] = 0x1C;
    this->Id[2] = 0;
    memcpy(this->name, "EF_CardAccess", sizeof("EF_CardAccess"));
    this->Index = EF_CardAccess;
    this->name[sizeof("EF.DG2")] = '\0';
}

char EF_CardAccess_File::FileParse(__in std::string& data) {

    result["EF_CardAccess"] = data;
    return true;
}




