typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned long    ulong;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
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

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef void *PVOID;

typedef WCHAR *LPCWSTR;

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

typedef struct _CRYPTOAPI_BLOB _CRYPTOAPI_BLOB, *P_CRYPTOAPI_BLOB;

typedef struct _CRYPTOAPI_BLOB DATA_BLOB;

typedef ulong DWORD;

typedef uchar BYTE;

struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE *pbData;
};

typedef struct _CRYPTPROTECT_PROMPTSTRUCT _CRYPTPROTECT_PROMPTSTRUCT, *P_CRYPTPROTECT_PROMPTSTRUCT;

typedef struct _CRYPTPROTECT_PROMPTSTRUCT CRYPTPROTECT_PROMPTSTRUCT;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct _CRYPTPROTECT_PROMPTSTRUCT {
    DWORD cbSize;
    DWORD dwPromptFlags;
    HWND hwndApp;
    LPCWSTR szPrompt;
};

struct HWND__ {
    int unused;
};

typedef struct HKL__ HKL__, *PHKL__;

struct HKL__ {
    int unused;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HKL__ *HKL;

typedef HINSTANCE HMODULE;

typedef int INT;

typedef DWORD *LPDWORD;

typedef int BOOL;

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




// WARNING: Restarted to delay deadcode elimination for space: stack

int entry(byte *param_1,undefined4 param_2,byte *param_3)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  int iVar6;
  uint unaff_EBP;
  byte *pbVar7;
  byte *pbVar8;
  bool bVar9;
  bool bVar10;
  bool bVar11;
  bool bVar12;
  bool bVar13;
  
  FUN_00863308();
  bVar5 = 0x80;
  pbVar8 = param_3;
  do {
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    *pbVar8 = bVar1;
    pbVar8 = pbVar8 + 1;
    iVar6 = 2;
LAB_008631d5:
    bVar9 = CARRY1(bVar5,bVar5);
    bVar5 = bVar5 * '\x02';
    bVar10 = bVar9;
    if (bVar5 == 0) {
      bVar5 = *param_1;
      param_1 = param_1 + 1;
      bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
      bVar5 = bVar5 * '\x02' + bVar9;
    }
  } while (!bVar10);
  bVar9 = CARRY1(bVar5,bVar5);
  bVar5 = bVar5 * '\x02';
  bVar10 = bVar9;
  if (bVar5 == 0) {
    bVar5 = *param_1;
    param_1 = param_1 + 1;
    bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
    bVar5 = bVar5 * '\x02' + bVar9;
  }
  if (bVar10) {
    bVar9 = CARRY1(bVar5,bVar5);
    bVar5 = bVar5 * '\x02';
    bVar10 = bVar9;
    if (bVar5 == 0) {
      bVar5 = *param_1;
      param_1 = param_1 + 1;
      bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
      bVar5 = bVar5 * '\x02' + bVar9;
    }
    if (bVar10) {
      bVar9 = CARRY1(bVar5,bVar5);
      bVar5 = bVar5 * '\x02';
      bVar10 = bVar9;
      if (bVar5 == 0) {
        bVar5 = *param_1;
        param_1 = param_1 + 1;
        bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
        bVar5 = bVar5 * '\x02' + bVar9;
      }
      bVar11 = CARRY1(bVar5,bVar5);
      bVar5 = bVar5 * '\x02';
      bVar9 = bVar11;
      if (bVar5 == 0) {
        bVar5 = *param_1;
        param_1 = param_1 + 1;
        bVar9 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar11);
        bVar5 = bVar5 * '\x02' + bVar11;
      }
      bVar12 = CARRY1(bVar5,bVar5);
      bVar5 = bVar5 * '\x02';
      bVar11 = bVar12;
      if (bVar5 == 0) {
        bVar5 = *param_1;
        param_1 = param_1 + 1;
        bVar11 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar12);
        bVar5 = bVar5 * '\x02' + bVar12;
      }
      bVar13 = CARRY1(bVar5,bVar5);
      bVar5 = bVar5 * '\x02';
      bVar12 = bVar13;
      if (bVar5 == 0) {
        bVar5 = *param_1;
        param_1 = param_1 + 1;
        bVar12 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar13);
        bVar5 = bVar5 * '\x02' + bVar13;
      }
      uVar3 = (((uint)bVar10 * 2 + (uint)bVar9) * 2 + (uint)bVar11) * 2 + (uint)bVar12;
      if (uVar3 != 0) {
        uVar3 = (uint)pbVar8[-uVar3];
      }
      *pbVar8 = (byte)uVar3;
      pbVar8 = pbVar8 + 1;
      iVar6 = 2;
    }
    else {
      bVar1 = *param_1;
      param_1 = param_1 + 1;
      bVar2 = bVar1 >> 1;
      unaff_EBP = (uint)bVar2;
      if (bVar2 == 0) {
        return (int)pbVar8 - (int)param_3;
      }
      pbVar7 = pbVar8 + -unaff_EBP;
      for (iVar6 = ((bVar1 & 1) != 0) + 2; iVar6 != 0; iVar6 = iVar6 + -1) {
        *pbVar8 = *pbVar7;
        pbVar7 = pbVar7 + 1;
        pbVar8 = pbVar8 + 1;
      }
      iVar6 = 1;
    }
  }
  else {
    iVar4 = 1;
    do {
      bVar9 = CARRY1(bVar5,bVar5);
      bVar5 = bVar5 * '\x02';
      bVar10 = bVar9;
      if (bVar5 == 0) {
        bVar5 = *param_1;
        param_1 = param_1 + 1;
        bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
        bVar5 = bVar5 * '\x02' + bVar9;
      }
      iVar4 = iVar4 * 2 + (uint)bVar10;
      bVar9 = CARRY1(bVar5,bVar5);
      bVar5 = bVar5 * '\x02';
      bVar10 = bVar9;
      if (bVar5 == 0) {
        bVar5 = *param_1;
        param_1 = param_1 + 1;
        bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
        bVar5 = bVar5 * '\x02' + bVar9;
      }
    } while (bVar10);
    iVar4 = iVar4 - iVar6;
    iVar6 = 1;
    if (iVar4 != 0) {
      unaff_EBP = CONCAT31((int3)iVar4 + -1,*param_1);
      param_1 = param_1 + 1;
      iVar4 = 1;
      do {
        bVar9 = CARRY1(bVar5,bVar5);
        bVar5 = bVar5 * '\x02';
        bVar10 = bVar9;
        if (bVar5 == 0) {
          bVar5 = *param_1;
          param_1 = param_1 + 1;
          bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
          bVar5 = bVar5 * '\x02' + bVar9;
        }
        iVar4 = iVar4 * 2 + (uint)bVar10;
        bVar9 = CARRY1(bVar5,bVar5);
        bVar5 = bVar5 * '\x02';
        bVar10 = bVar9;
        if (bVar5 == 0) {
          bVar5 = *param_1;
          param_1 = param_1 + 1;
          bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
          bVar5 = bVar5 * '\x02' + bVar9;
        }
      } while (bVar10);
      if (unaff_EBP < 32000) {
        if (0x4ff < unaff_EBP) {
          pbVar7 = pbVar8 + -unaff_EBP;
          for (iVar4 = iVar4 + 1; iVar4 != 0; iVar4 = iVar4 + -1) {
            *pbVar8 = *pbVar7;
            pbVar7 = pbVar7 + 1;
            pbVar8 = pbVar8 + 1;
          }
          goto LAB_008631d5;
        }
        if (unaff_EBP < 0x80) goto LAB_008632cd;
      }
      else {
LAB_008632cd:
        iVar4 = iVar4 + 2;
      }
      pbVar7 = pbVar8 + -unaff_EBP;
      for (; iVar4 != 0; iVar4 = iVar4 + -1) {
        *pbVar8 = *pbVar7;
        pbVar7 = pbVar7 + 1;
        pbVar8 = pbVar8 + 1;
      }
      goto LAB_008631d5;
    }
    iVar4 = 1;
    do {
      bVar9 = CARRY1(bVar5,bVar5);
      bVar5 = bVar5 * '\x02';
      bVar10 = bVar9;
      if (bVar5 == 0) {
        bVar5 = *param_1;
        param_1 = param_1 + 1;
        bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
        bVar5 = bVar5 * '\x02' + bVar9;
      }
      iVar4 = iVar4 * 2 + (uint)bVar10;
      bVar9 = CARRY1(bVar5,bVar5);
      bVar5 = bVar5 * '\x02';
      bVar10 = bVar9;
      if (bVar5 == 0) {
        bVar5 = *param_1;
        param_1 = param_1 + 1;
        bVar10 = CARRY1(bVar5,bVar5) || CARRY1(bVar5 * '\x02',bVar9);
        bVar5 = bVar5 * '\x02' + bVar9;
      }
    } while (bVar10);
    pbVar7 = pbVar8 + -unaff_EBP;
    for (; iVar4 != 0; iVar4 = iVar4 + -1) {
      *pbVar8 = *pbVar7;
      pbVar7 = pbVar7 + 1;
      pbVar8 = pbVar8 + 1;
    }
  }
  goto LAB_008631d5;
}



void FUN_00863308(void)

{
  code *unaff_retaddr;
  
  if (*(int *)(unaff_retaddr + -0x3de86d) == 0) {
    (*unaff_retaddr)(unaff_retaddr + 0x192,0,unaff_retaddr + -0x41a1bd,0);
  }
                    // WARNING: Could not recover jumptable at 0x0086334d. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(unaff_retaddr + -0x3de86d))();
  return;
}


