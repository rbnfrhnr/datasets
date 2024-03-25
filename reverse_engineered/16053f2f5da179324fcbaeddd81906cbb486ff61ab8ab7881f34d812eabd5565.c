typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned long    ulong;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef unsigned short    word;
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef ulong DWORD;

typedef DWORD *PDWORD;

typedef int BOOL;

typedef int (*FARPROC)(void);

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_16 IMAGE_RESOURCE_DIR_STRING_U_16, *PIMAGE_RESOURCE_DIR_STRING_U_16;

struct IMAGE_RESOURCE_DIR_STRING_U_16 {
    word Length;
    wchar16 NameString[8];
};




// WARNING: Control flow encountered bad instruction data

void entry(int param_1,int param_2)

{
  HMODULE pHVar1;
  int iVar2;
  int *piVar3;
  int extraout_ECX;
  byte *extraout_ECX_00;
  byte *extraout_ECX_01;
  byte *extraout_ECX_02;
  byte *pbVar4;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_ECX_05;
  undefined2 extraout_DX;
  undefined2 extraout_DX_00;
  undefined2 extraout_DX_01;
  undefined2 uVar5;
  byte *extraout_EDX;
  byte *pbVar6;
  byte *extraout_EDX_00;
  undefined4 extraout_EDX_01;
  int extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 *puVar7;
  int *lpModuleName;
  undefined4 unaff_EDI;
  int iVar8;
  undefined8 uVar9;
  code *pcVar10;
  
  FUN_004b95ca();
  FUN_004bb7b8();
  FUN_004bd6d1();
  if (param_2 == 1) {
    DAT_004bdab1 = param_1;
  }
  else {
    DAT_004bdab1 = DAT_004bdaad;
  }
  FUN_004ba07d(extraout_ECX,extraout_DX);
  pcVar10 = FUN_004b964a;
  pbVar4 = extraout_ECX_00;
  pbVar6 = extraout_EDX;
  for (iVar8 = 0; *(int *)((int)&DAT_004be8a8 + iVar8) != 0; iVar8 = iVar8 + 8) {
    uVar9 = FUN_004b964a(pbVar4,pbVar6,(byte *)(*(int *)((int)&DAT_004be8a8 + iVar8) + DAT_004bdab1)
                         ,(byte *)(*(int *)((int)&DAT_004be8ac + iVar8) + DAT_004bdab1));
    pbVar6 = (byte *)((ulonglong)uVar9 >> 0x20);
    pbVar4 = extraout_ECX_01;
  }
  if ((DAT_004be888 != 0) && (DAT_004be88c != 0)) {
    FUN_004b9fbc(pbVar4,pbVar6);
    pbVar4 = extraout_ECX_02;
    pbVar6 = extraout_EDX_00;
  }
  FUN_004b9f38((int)pbVar4,(short)pbVar6);
  if (DAT_004be107 != 0) {
    FUN_004b97a9();
  }
  puVar7 = (undefined4 *)((int)&DAT_004be8ac + iVar8);
  if (DAT_004be30d == 1) {
    for (; DAT_004be311 = (undefined4 *)((int)&DAT_004be8ac + iVar8), puVar7[-1] != -1;
        puVar7 = puVar7 + 1) {
    }
  }
  else {
    puVar7 = (undefined4 *)((int)&DAT_004be8b4 + iVar8);
  }
  DAT_004bdad1 = *puVar7;
  FUN_004bd450();
  DAT_004be8a4 = (int *)VirtualAlloc((LPVOID)0x0,0x3af,0x1000,0x40);
  (*pcVar10)(puVar7 + 2,DAT_004be8a4);
  FUN_004bc8dc();
  piVar3 = DAT_004be8a4;
  uVar5 = extraout_DX_00;
  if ((DAT_004be3b6 != 0) && (DAT_004be1d6 != 0)) {
    FUN_004bc79a();
    FUN_004bc0b6();
    piVar3 = DAT_004be8a4;
    uVar5 = extraout_DX_01;
  }
  for (; lpModuleName = DAT_004be8a4, *(char *)piVar3 != '\x01'; piVar3 = (int *)((int)piVar3 + 1))
  {
  }
  iVar8 = *(int *)((int)piVar3 + 1);
  if (((DAT_004bdaad != DAT_004bdab1) && (DAT_004be113 != 0)) && (DAT_004be12b == 0)) {
    iVar8 = (iVar8 + DAT_004bdaad) - DAT_004bdab1;
  }
  iVar8 = iVar8 + DAT_004bdab1;
  DAT_004be8a0 = (int *)((int)piVar3 + 5);
  FUN_004ba0db(DAT_004bdaad,uVar5);
  FUN_004ba1d6(extraout_ECX_03,extraout_EDX_01,unaff_EDI);
  FUN_004ba573(extraout_ECX_04,extraout_EDX_02);
  FUN_004bcea1();
  while (*(char *)lpModuleName != '\x01') {
    FUN_004bb540();
    pHVar1 = GetModuleHandleA((LPCSTR)lpModuleName);
    piVar3 = lpModuleName;
    if (pHVar1 == (HMODULE)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    while (DAT_004be89c = pHVar1, *piVar3 != 0) {
      FUN_004bcb0b();
      iVar2 = FUN_004bd5ea();
      if (iVar2 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      FUN_004bca98();
      iVar8 = iVar8 + 4;
      *DAT_004be8a0 = iVar8;
      DAT_004be8a0 = DAT_004be8a0 + 1;
      pHVar1 = DAT_004be89c;
      piVar3 = DAT_004be8a0;
    }
    for (; *(char *)lpModuleName != '\0'; lpModuleName = (int *)((int)lpModuleName + 1)) {
    }
    lpModuleName = (int *)((int)lpModuleName + 1);
    iVar8 = piVar3[1];
    if (((DAT_004bdaad != DAT_004bdab1) && (DAT_004be113 != 0)) && (DAT_004be12b == 0)) {
      iVar8 = (iVar8 + DAT_004bdaad) - DAT_004bdab1;
    }
    iVar8 = iVar8 + DAT_004bdab1;
    piVar3[1] = -1;
    DAT_004be8a0 = piVar3 + 2;
  }
  FUN_004bcb39();
  VirtualFree(DAT_004be8a4,0x3af,0x4000);
  FUN_004bca75();
  FUN_004ba18d();
  FUN_004ba038();
  if (DAT_004be13f == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  FUN_004ba5d1(extraout_ECX_05,extraout_EDX_03);
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_00401005(int param_1,int param_2)

{
  HMODULE pHVar1;
  int iVar2;
  int *piVar3;
  int extraout_ECX;
  byte *extraout_ECX_00;
  byte *extraout_ECX_01;
  byte *extraout_ECX_02;
  byte *pbVar4;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_ECX_05;
  undefined2 extraout_DX;
  undefined2 extraout_DX_00;
  undefined2 extraout_DX_01;
  undefined2 uVar5;
  byte *extraout_EDX;
  byte *pbVar6;
  byte *extraout_EDX_00;
  undefined4 extraout_EDX_01;
  int extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 *puVar7;
  int *lpModuleName;
  undefined4 unaff_EDI;
  int iVar8;
  undefined8 uVar9;
  code *pcVar10;
  
  FUN_004b95ca();
  FUN_004bb7b8();
  FUN_004bd6d1();
  if (param_2 == 1) {
    DAT_004bdab1 = param_1;
  }
  else {
    DAT_004bdab1 = DAT_004bdaad;
  }
  FUN_004ba07d(extraout_ECX,extraout_DX);
  pcVar10 = FUN_004b964a;
  pbVar4 = extraout_ECX_00;
  pbVar6 = extraout_EDX;
  for (iVar8 = 0; *(int *)((int)&DAT_004be8a8 + iVar8) != 0; iVar8 = iVar8 + 8) {
    uVar9 = FUN_004b964a(pbVar4,pbVar6,(byte *)(*(int *)((int)&DAT_004be8a8 + iVar8) + DAT_004bdab1)
                         ,(byte *)(*(int *)((int)&DAT_004be8ac + iVar8) + DAT_004bdab1));
    pbVar6 = (byte *)((ulonglong)uVar9 >> 0x20);
    pbVar4 = extraout_ECX_01;
  }
  if ((DAT_004be888 != 0) && (DAT_004be88c != 0)) {
    FUN_004b9fbc(pbVar4,pbVar6);
    pbVar4 = extraout_ECX_02;
    pbVar6 = extraout_EDX_00;
  }
  FUN_004b9f38((int)pbVar4,(short)pbVar6);
  if (DAT_004be107 != 0) {
    FUN_004b97a9();
  }
  puVar7 = (undefined4 *)((int)&DAT_004be8ac + iVar8);
  if (DAT_004be30d == 1) {
    for (; DAT_004be311 = (undefined4 *)((int)&DAT_004be8ac + iVar8), puVar7[-1] != -1;
        puVar7 = puVar7 + 1) {
    }
  }
  else {
    puVar7 = (undefined4 *)((int)&DAT_004be8b4 + iVar8);
  }
  DAT_004bdad1 = *puVar7;
  FUN_004bd450();
  DAT_004be8a4 = (int *)VirtualAlloc((LPVOID)0x0,0x3af,0x1000,0x40);
  (*pcVar10)(puVar7 + 2,DAT_004be8a4);
  FUN_004bc8dc();
  piVar3 = DAT_004be8a4;
  uVar5 = extraout_DX_00;
  if ((DAT_004be3b6 != 0) && (DAT_004be1d6 != 0)) {
    FUN_004bc79a();
    FUN_004bc0b6();
    piVar3 = DAT_004be8a4;
    uVar5 = extraout_DX_01;
  }
  for (; lpModuleName = DAT_004be8a4, *(char *)piVar3 != '\x01'; piVar3 = (int *)((int)piVar3 + 1))
  {
  }
  iVar8 = *(int *)((int)piVar3 + 1);
  if (((DAT_004bdaad != DAT_004bdab1) && (DAT_004be113 != 0)) && (DAT_004be12b == 0)) {
    iVar8 = (iVar8 + DAT_004bdaad) - DAT_004bdab1;
  }
  iVar8 = iVar8 + DAT_004bdab1;
  DAT_004be8a0 = (int *)((int)piVar3 + 5);
  FUN_004ba0db(DAT_004bdaad,uVar5);
  FUN_004ba1d6(extraout_ECX_03,extraout_EDX_01,unaff_EDI);
  FUN_004ba573(extraout_ECX_04,extraout_EDX_02);
  FUN_004bcea1();
  while (*(char *)lpModuleName != '\x01') {
    FUN_004bb540();
    pHVar1 = GetModuleHandleA((LPCSTR)lpModuleName);
    piVar3 = lpModuleName;
    if (pHVar1 == (HMODULE)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    while (DAT_004be89c = pHVar1, *piVar3 != 0) {
      FUN_004bcb0b();
      iVar2 = FUN_004bd5ea();
      if (iVar2 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      FUN_004bca98();
      iVar8 = iVar8 + 4;
      *DAT_004be8a0 = iVar8;
      DAT_004be8a0 = DAT_004be8a0 + 1;
      pHVar1 = DAT_004be89c;
      piVar3 = DAT_004be8a0;
    }
    for (; *(char *)lpModuleName != '\0'; lpModuleName = (int *)((int)lpModuleName + 1)) {
    }
    lpModuleName = (int *)((int)lpModuleName + 1);
    iVar8 = piVar3[1];
    if (((DAT_004bdaad != DAT_004bdab1) && (DAT_004be113 != 0)) && (DAT_004be12b == 0)) {
      iVar8 = (iVar8 + DAT_004bdaad) - DAT_004bdab1;
    }
    iVar8 = iVar8 + DAT_004bdab1;
    piVar3[1] = -1;
    DAT_004be8a0 = piVar3 + 2;
  }
  FUN_004bcb39();
  VirtualFree(DAT_004be8a4,0x3af,0x4000);
  FUN_004bca75();
  FUN_004ba18d();
  FUN_004ba038();
  if (DAT_004be13f == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  FUN_004ba5d1(extraout_ECX_05,extraout_EDX_03);
  return;
}



undefined8 FUN_004b95ca(void)

{
  undefined *puVar1;
  int iVar2;
  char *pcVar3;
  int unaff_EBP;
  undefined4 unaff_EDI;
  undefined *puVar4;
  undefined *puVar5;
  undefined4 uVar6;
  
  uVar6 = 0x1000;
  puVar1 = (undefined *)(**(code **)(unaff_EBP + 0x3fd))(0,0x80000,0x1000,0x40);
  puVar5 = puVar1;
  iVar2 = (*(code *)(unaff_EBP + 0x317))(unaff_EBP + 0x476,puVar1,puVar1);
  for (pcVar3 = puVar1 + iVar2; *pcVar3 == '\0'; pcVar3 = pcVar3 + -1) {
  }
  pcVar3 = pcVar3 + (1 - (int)puVar1);
  puVar4 = (undefined *)(unaff_EBP + 0x476);
  for (; pcVar3 != (char *)0x0; pcVar3 = pcVar3 + -1) {
    *puVar4 = *puVar1;
    puVar1 = puVar1 + 1;
    puVar4 = puVar4 + 1;
  }
  (**(code **)(unaff_EBP + 0x405))(puVar5,0x80000,0x4000);
  return CONCAT44(uVar6,unaff_EDI);
}



undefined8 __fastcall
FUN_004b964a(undefined4 param_1,undefined4 param_2,byte *param_3,byte *param_4)

{
  char cVar1;
  undefined4 uVar3;
  byte *pbVar4;
  int extraout_ECX;
  int extraout_ECX_00;
  int extraout_ECX_01;
  int extraout_ECX_02;
  int extraout_ECX_03;
  int iVar5;
  int iVar6;
  byte *unaff_EBP;
  byte *pbVar7;
  byte *pbVar8;
  undefined uVar9;
  bool bVar10;
  byte bVar11;
  byte bVar2;
  
  uVar9 = 0;
  pbVar8 = param_4;
  do {
    pbVar7 = param_3 + 1;
    *pbVar8 = *param_3;
    iVar6 = 2;
    pbVar8 = pbVar8 + 1;
    while (FUN_004b96cd(), param_3 = pbVar7, (bool)uVar9) {
      bVar10 = false;
      FUN_004b96cd();
      if (bVar10) {
        bVar11 = false;
        uVar3 = FUN_004b96cd();
        if (!(bool)bVar11) {
          pbVar4 = (byte *)(CONCAT31((int3)((uint)uVar3 >> 8),*pbVar7) >> 1);
          if (pbVar4 == (byte *)0x0) {
            return CONCAT44(param_2,(int)pbVar8 - (int)param_4);
          }
          iVar5 = extraout_ECX * 2 + (uint)((*pbVar7 & 1) != 0);
          goto LAB_004b96bc;
        }
        iVar6 = 2;
        do {
          uVar3 = FUN_004b96cd();
          bVar2 = (byte)uVar3;
          bVar10 = CARRY1(bVar2 * '\x02',bVar11);
          uVar9 = CARRY1(bVar2,bVar2) || bVar10;
          cVar1 = bVar2 * '\x02' + bVar11;
          pbVar4 = (byte *)CONCAT31((int3)((uint)uVar3 >> 8),cVar1);
          bVar11 = uVar9;
        } while (!CARRY1(bVar2,bVar2) && !bVar10);
        iVar5 = extraout_ECX_00;
        if (cVar1 != '\0') goto LAB_004b96c3;
        *pbVar8 = 0;
        pbVar8 = pbVar8 + 1;
      }
      else {
        FUN_004b96d9();
        if (extraout_ECX_01 == iVar6) {
          FUN_004b96d7();
          iVar5 = extraout_ECX_02;
          pbVar4 = unaff_EBP;
        }
        else {
          pbVar4 = (byte *)FUN_004b96d7();
          iVar5 = extraout_ECX_03;
          if (pbVar4 < (byte *)0x7d00) {
            if (4 < (byte)((uint)pbVar4 >> 8)) goto LAB_004b96bd;
            if (pbVar4 < (byte *)0x80) goto LAB_004b96bc;
          }
          else {
LAB_004b96bc:
            iVar5 = iVar5 + 1;
LAB_004b96bd:
            iVar5 = iVar5 + 1;
          }
          pbVar7 = pbVar7 + 1;
        }
        iVar6 = 1;
        unaff_EBP = pbVar4;
LAB_004b96c3:
        uVar9 = pbVar8 < pbVar4;
        pbVar4 = pbVar8 + -(int)pbVar4;
        for (; iVar5 != 0; iVar5 = iVar5 + -1) {
          *pbVar8 = *pbVar4;
          pbVar4 = pbVar4 + 1;
          pbVar8 = pbVar8 + 1;
        }
      }
    }
  } while( true );
}



void FUN_004b96cd(void)

{
  return;
}



void FUN_004b96d7(void)

{
  uint extraout_ECX;
  byte bVar1;
  
  bVar1 = 0;
  do {
    FUN_004b96cd();
    bVar1 = CARRY4(extraout_ECX,extraout_ECX) || CARRY4(extraout_ECX * 2,(uint)bVar1);
    FUN_004b96cd();
  } while ((bool)bVar1);
  return;
}



void FUN_004b96d9(void)

{
  uint extraout_ECX;
  byte in_CF;
  
  do {
    FUN_004b96cd();
    in_CF = CARRY4(extraout_ECX,extraout_ECX) || CARRY4(extraout_ECX * 2,(uint)in_CF);
    FUN_004b96cd();
  } while ((bool)in_CF);
  return;
}



void FUN_004b97a9(void)

{
  return;
}



// WARNING: Control flow encountered bad instruction data

void __fastcall FUN_004b9a79(int param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 in_EAX;
  undefined unaff_BL;
  undefined4 *puVar3;
  undefined **ppuVar4;
  int unaff_EDI;
  undefined *apuStack_c [2];
  
  puVar3 = (undefined4 *)&stack0xfffffffc;
  ppuVar4 = apuStack_c + 1;
  apuStack_c[1] = &stack0xfffffffc;
  cVar2 = '\a';
  do {
    puVar3 = puVar3 + -1;
    ppuVar4 = ppuVar4 + -1;
    *ppuVar4 = (undefined *)*puVar3;
    cVar2 = cVar2 + -1;
  } while ('\0' < cVar2);
  piVar1 = (int *)(CONCAT31((int3)((uint)in_EAX >> 8),DAT_e88a4be8) + -0x476776e7);
  *piVar1 = *piVar1 + param_1;
  LOCK();
  *(undefined *)(unaff_EDI + -0x47) = unaff_BL;
  UNLOCK();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack

void __fastcall FUN_004b9f38(int param_1,undefined2 param_2)

{
  byte *pbVar1;
  byte bVar2;
  undefined uVar3;
  code *pcVar4;
  int in_EAX;
  byte unaff_BL;
  int unaff_EBP;
  
  pbVar1 = (byte *)(in_EAX + 0x49);
  bVar2 = *pbVar1;
  *pbVar1 = *pbVar1 - (byte)in_EAX;
  in(0xb0);
  if ((byte)in_EAX <= bVar2 && *pbVar1 != 0) {
    uVar3 = in((short)*(undefined4 *)(unaff_EBP + 0x18));
    **(undefined **)(unaff_EBP + 4) = uVar3;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uRam00000000 = in(param_2);
  *(byte *)(param_1 + -0x80) = *(byte *)(param_1 + -0x80) ^ unaff_BL;
  pcVar4 = (code *)swi(3);
  (*pcVar4)();
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004b9fce) overlaps instruction at (ram,0x004b9fcd)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_004b9fbc(byte *param_1,byte *param_2)

{
  uint *puVar1;
  byte *pbVar2;
  uint uVar3;
  undefined uVar4;
  undefined4 uVar5;
  char cVar6;
  byte bVar9;
  byte *in_EAX;
  char *pcVar7;
  int iVar8;
  int extraout_ECX;
  byte bVar10;
  undefined2 uVar11;
  int unaff_EBX;
  undefined4 *unaff_EBP;
  float *unaff_ESI;
  undefined4 *puVar13;
  bool bVar14;
  bool bVar15;
  float10 in_ST0;
  undefined4 uStack_17;
  byte bVar12;
  
  do {
    out(*unaff_ESI,(short)param_2);
    pcVar7 = (char *)((uint)param_1 & 0xffffff94);
    out(unaff_ESI[1],(short)param_2);
    pcVar7[0x7f] = '\0';
    LOCK();
    bVar12 = in_EAX[unaff_EBX + 0x12];
    in_EAX[unaff_EBX + 0x12] = (byte)((uint)param_2 >> 8);
    bVar10 = (byte)param_2;
    UNLOCK();
    puVar1 = (uint *)(pcVar7 + -0x79);
    uVar3 = *puVar1;
    *puVar1 = *puVar1 + 0x6a;
    *pcVar7 = *pcVar7 + bVar12 + (uVar3 < 0xffffff96);
    bVar12 = bVar12 & pcVar7[-0x7ec7c3f2];
    uVar11 = CONCAT11(bVar12,bVar10);
    param_2 = (byte *)CONCAT22((short)((uint)param_2 >> 0x10),uVar11);
    unaff_ESI = (float *)((int)unaff_ESI + *(int *)(param_2 + -0x7e) + 8);
    bVar14 = 0x50 < *in_EAX;
    bVar15 = *in_EAX == 0x50;
    puVar13 = (undefined4 *)(in_EAX + 1);
    while( true ) {
      uVar5 = in(uVar11);
      *puVar13 = uVar5;
      bVar9 = (byte)((uint)pcVar7 >> 8);
      if (!bVar15) {
        *(byte *)(puVar13 + 3) = bVar9;
        _DAT_2444c0f9 = (*(code *)(param_2 + (int)unaff_EBP + 0x26))();
        pbVar2 = (byte *)((int)unaff_EBP + extraout_ECX * 4 + -0x17f498b9);
        *pbVar2 = *pbVar2 | (byte)((uint)_DAT_2444c0f9 >> 8);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      param_1 = in_EAX + -1;
      if (param_1 == (byte *)0x0 || !bVar15) {
        bVar12 = (byte)((uint)(in_EAX + -2) >> 8);
        iVar8 = CONCAT22((short)((uint)pcVar7 >> 0x10),CONCAT11(bVar9 - bVar12,0x35));
        *unaff_ESI = (float)in_ST0;
        puVar1 = (uint *)(iVar8 + 0x147d9844);
        uVar3 = *puVar1;
        *puVar1 = (uint)(CONCAT14(bVar9 < bVar12,uVar3) >> 0x14) | uVar3 << 0xd;
        uVar4 = *(undefined *)unaff_ESI;
        puVar13 = (undefined4 *)&stack0xffffffed;
        cVar6 = '\x03';
        do {
          unaff_EBP = unaff_EBP + -1;
          puVar13 = puVar13 + -1;
          *puVar13 = *unaff_EBP;
          cVar6 = cVar6 + -1;
        } while ('\0' < cVar6);
        _DAT_63810621 =
             _DAT_63810621 -
             CONCAT31((int3)((uint)param_2 >> 8),
                      bVar10 | *(byte *)(CONCAT31((int3)((uint)iVar8 >> 8),uVar4) | 0x30));
        func_0xd27e682b();
        do {
                    // WARNING: Do nothing block with infinite loop
        } while( true );
      }
      if (!bVar15) break;
      bVar14 = *param_2 < 0x19;
      bVar15 = *param_2 == 0x19;
      in_EAX = param_1;
      puVar13 = puVar13 + 1;
    }
    in_EAX = (byte *)CONCAT31((int3)((uint)pcVar7 >> 8),cRam74178db8 + '5' + bVar14);
    unaff_EBX = CONCAT31(0x638106,bVar12 ^ 0x50);
  } while( true );
}



void FUN_004ba038(void)

{
  func_0xd27e682b();
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



int __fastcall FUN_004ba07d(int param_1,undefined2 param_2)

{
  int in_EAX;
  char *unaff_EBX;
  int unaff_EBP;
  undefined *unaff_ESI;
  uint *unaff_EDI;
  char in_CF;
  
  *unaff_EBX = (*unaff_EBX + '#') - in_CF;
  if (param_1 == 1 || unaff_EBP + *(int *)(unaff_ESI + -0x29) != 0) {
    return CONCAT31((int3)((uint)in_EAX >> 8),*unaff_ESI) + -0x1db85d5c +
           (uint)(param_1 - 1U < *unaff_EDI);
  }
  out(*unaff_ESI,param_2);
  return in_EAX;
}



// WARNING: Control flow encountered bad instruction data

void __fastcall FUN_004ba0db(undefined4 param_1,undefined2 param_2)

{
  in(param_2);
  in(param_2);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void FUN_004ba18d(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __fastcall FUN_004ba1d6(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  code *pcVar1;
  byte bVar2;
  undefined4 in_EAX;
  uint3 uVar4;
  uint *unaff_EBX;
  int unaff_ESI;
  undefined2 in_CS;
  int *piVar3;
  
  bVar2 = in(0x75);
  piVar3 = (int *)CONCAT31((int3)((uint)in_EAX >> 8),bVar2);
  *(undefined4 *)((int)unaff_EBX + -0x66) = 0x4b8b4281;
  uVar4 = (uint3)((uint)param_2 >> 8);
  *piVar3 = *piVar3 + (int)piVar3;
  *(undefined2 *)(unaff_ESI + 1) = in_CS;
  *unaff_EBX = CONCAT31(uVar4,(byte)param_2 | bVar2) << 10 | (uint)(uVar4 >> 0xe);
  pcVar1 = (code *)swi(1);
  (*pcVar1)();
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_004ba573(undefined4 param_1,int param_2)

{
  code *pcVar1;
  undefined uVar2;
  undefined4 in_EAX;
  int *piVar3;
  int extraout_ECX;
  uint extraout_EDX;
  undefined4 unaff_EBX;
  int unaff_EBP;
  undefined4 *unaff_ESI;
  int *unaff_EDI;
  int in_GS_OFFSET;
  
  if (0 < param_2) {
    *(char *)(in_GS_OFFSET + -0x3d3bf753) = (char)in_EAX;
    pcVar1 = (code *)swi(1);
    (*pcVar1)();
    return;
  }
  *(BADSPACEBASE **)(param_2 + -1) = register0x00000010;
  _DAT_71292154 = (undefined2)*unaff_ESI;
  piVar3 = (int *)CONCAT22((short)((uint)in_EAX >> 0x10),
                           CONCAT11((char)((uint)in_EAX >> 8) - (char)((uint)unaff_EBX >> 8),
                                    (char)in_EAX));
  *piVar3 = *piVar3 - (int)&stack0x00000000;
  uVar2 = func_0xc9ac54db();
  out(4,uVar2);
  *(uint *)(unaff_EBP + 0x6f9f591e) = *(uint *)(unaff_EBP + 0x6f9f591e) ^ extraout_EDX;
  if ((int)unaff_ESI + (4 - *unaff_EDI) < 0) {
                    // WARNING: Could not recover jumptable at 0x004ba616. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(&stack0x0000002e + extraout_ECX * 2))();
    return;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004ba5f1) overlaps instruction at (ram,0x004ba5ed)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_004ba5d1(undefined4 param_1,undefined4 param_2)

{
  uint **ppuVar1;
  code *pcVar2;
  undefined uVar3;
  char cVar4;
  uint in_EAX;
  int *piVar5;
  int extraout_ECX;
  uint *extraout_ECX_00;
  uint *puVar6;
  char cVar7;
  uint extraout_EDX;
  int unaff_EBX;
  int unaff_EBP;
  uint *unaff_ESI;
  int *unaff_EDI;
  byte bVar8;
  bool bVar9;
  uint *unaff_retaddr;
  
  bVar8 = 0;
  *(byte *)(unaff_EBP + 0x3461348a) = *(byte *)(unaff_EBP + 0x3461348a) & (byte)((uint)param_1 >> 8)
  ;
  uVar3 = *(undefined *)(unaff_EBX + (in_EAX & 0xff));
  LOCK();
  ppuVar1 = (uint **)(CONCAT31((int3)(in_EAX >> 8),uVar3) + -0x69914997);
  puVar6 = *ppuVar1;
  *ppuVar1 = unaff_retaddr;
  UNLOCK();
  cVar4 = (char)(in_EAX >> 8);
  cVar7 = (char)((uint)param_2 >> 8);
  bVar9 = SBORROW1(cVar4,cVar7) == false;
  if (bVar9) {
    if (bVar9) {
      *(undefined *)unaff_ESI = 0;
      pcVar2 = (code *)swi(4);
      if (SBORROW4(unaff_EBP + -1,unaff_EBX) == true) {
        (*pcVar2)();
        puVar6 = extraout_ECX_00;
      }
      *puVar6 = *puVar6 & (uint)puVar6;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    puVar6[10] = puVar6[10] - (int)unaff_ESI;
    bVar8 = 1;
  }
  *unaff_ESI = *unaff_ESI << 1 | (uint)((int)*unaff_ESI < 0);
  *(undefined **)param_2 = &stack0x00000004;
  _DAT_71292154 = (undefined2)*unaff_ESI;
  piVar5 = (int *)CONCAT22((short)(in_EAX >> 0x10),
                           CONCAT11((cVar4 - cVar7) - (char)((uint)unaff_EBX >> 8),uVar3));
  *piVar5 = *piVar5 - (int)&stack0x00000004;
  uVar3 = func_0xc9ac54db();
  out(4,uVar3);
  *(uint *)(unaff_EBP + 0x6f9f591e) = *(uint *)(unaff_EBP + 0x6f9f591e) ^ extraout_EDX;
  if ((int)((int)unaff_ESI + (((uint)bVar8 * -8 + 4) - *unaff_EDI)) < 0) {
                    // WARNING: Could not recover jumptable at 0x004ba616. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(&stack0x00000032 + extraout_ECX * 2))();
    return;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


