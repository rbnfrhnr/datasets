typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
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

typedef ulong DWORD;

typedef int (*FARPROC)(void);

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef int INT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef struct HKEY__ *HKEY;

typedef uchar BYTE;

typedef struct HICON__ *HICON;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef int BOOL;

typedef HICON HCURSOR;

typedef BYTE *LPBYTE;

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

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
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

typedef long LONG;

typedef LONG LSTATUS;

typedef wchar_t WCHAR;

typedef char CHAR;

typedef CHAR *LPCSTR;

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

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[61];
};




void __fastcall entry(undefined4 param_1,undefined4 param_2)

{
  FUN_004343a8(param_1,param_2);
  return;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

int FUN_004341b6(short *param_1,int *param_2)

{
  undefined uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int extraout_ECX;
  int extraout_ECX_00;
  int extraout_ECX_01;
  int extraout_ECX_02;
  undefined *puVar5;
  int *piVar6;
  int *piVar7;
  undefined uVar8;
  char local_d;
  
  piVar7 = param_2;
  if (*param_1 == 0x434a) {
LAB_004341e3:
    while( true ) {
      uVar8 = false;
      FUN_0043434c();
      if (!(bool)uVar8) break;
      iVar2 = FUN_00434364();
      uVar3 = (uint)(byte)((char)iVar2 + local_d);
LAB_004341f7:
      *(char *)piVar7 = (char)uVar3;
      piVar7 = (int *)((int)piVar7 + 1);
    }
    FUN_0043434c();
    if ((bool)uVar8) {
      FUN_00434370();
      if (extraout_ECX_00 == 2) {
        uVar3 = FUN_00434370();
        iVar2 = extraout_ECX_01;
        goto LAB_004342e7;
      }
      FUN_00434364();
      uVar3 = FUN_00434370();
      iVar2 = extraout_ECX_02;
      if (uVar3 < 0x10000) {
        if (uVar3 < 0x37ff) {
          if (0x27e < uVar3) goto LAB_004342e6;
          if (0x7f < uVar3) goto LAB_004342e7;
          iVar2 = extraout_ECX_02 + 1;
          goto LAB_004342e4;
        }
      }
      else {
LAB_004342e4:
        iVar2 = iVar2 + 1;
      }
      iVar2 = iVar2 + 1;
LAB_004342e6:
      iVar2 = iVar2 + 1;
LAB_004342e7:
      puVar5 = (undefined *)((int)piVar7 - uVar3);
      for (; iVar2 != 0; iVar2 = iVar2 + -1) {
        *(undefined *)piVar7 = *puVar5;
        puVar5 = puVar5 + 1;
        piVar7 = (int *)((int)piVar7 + 1);
      }
      goto LAB_004341e3;
    }
    FUN_0043434c();
    if ((bool)uVar8) {
      iVar2 = FUN_00434364();
      uVar3 = iVar2 - 1;
      if (uVar3 == 0) goto LAB_004341f7;
      iVar2 = extraout_ECX;
      if (-1 < (int)uVar3) goto LAB_004342e6;
      FUN_0043434c();
      if ((bool)uVar8) {
        do {
          iVar2 = 0x100;
          do {
            uVar1 = FUN_00434359();
            *(undefined *)piVar7 = uVar1;
            piVar7 = (int *)((int)piVar7 + 1);
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
          FUN_0043434c();
        } while ((bool)uVar8);
      }
      else {
        iVar2 = FUN_00434364();
        local_d = '\0';
        if (iVar2 != 1) {
          local_d = FUN_00434359();
        }
      }
      goto LAB_004341e3;
    }
    uVar3 = FUN_00434364();
    iVar2 = FUN_00434364();
    iVar2 = iVar2 + 2;
    if (uVar3 != 0) goto LAB_004342e7;
    if (iVar2 != 2) {
      FUN_00434364();
      goto LAB_004341e3;
    }
  }
  if (*(int *)(param_1 + 3) != 0) {
    uVar3 = *(uint *)(param_1 + 1);
    uVar4 = 0;
    piVar6 = param_2;
    if (3 < uVar3) {
      while( true ) {
        iVar2 = *piVar6;
        uVar4 = uVar4 + iVar2 ^ iVar2 * 2 + 1 + (uint)(iVar2 < 0);
        piVar6 = piVar6 + 1;
        uVar3 = uVar3 - 4;
        if (uVar3 == 0) break;
        if (uVar3 < 4) {
          iVar2 = 4 - uVar3;
          uVar3 = 4;
          piVar6 = (int *)((int)piVar6 - iVar2);
        }
      }
    }
    if (uVar4 != *(uint *)(param_1 + 3)) {
      return 0;
    }
  }
  return (int)piVar7 - (int)param_2;
}



void FUN_0043434c(void)

{
  return;
}



void FUN_00434359(void)

{
  FUN_00434364();
  return;
}



int FUN_00434364(void)

{
  uint uVar1;
  uint uVar2;
  int extraout_ECX;
  byte bVar3;
  
  bVar3 = false;
  do {
    uVar2 = FUN_0043434c();
    uVar1 = (uint)bVar3;
    bVar3 = CARRY4(uVar2,uVar2) || CARRY4(uVar2 * 2,uVar1);
  } while (extraout_ECX != 1);
  return uVar2 * 2 + uVar1;
}



void FUN_00434370(void)

{
  uint extraout_ECX;
  byte bVar1;
  
  bVar1 = 0;
  do {
    FUN_0043434c();
    bVar1 = CARRY4(extraout_ECX,extraout_ECX) || CARRY4(extraout_ECX * 2,(uint)bVar1);
    FUN_0043434c();
  } while ((bool)bVar1);
  return;
}



void __fastcall FUN_004343a8(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar1 = (**(code **)(PTR_IMAGE_DOS_HEADER_0043439c + DAT_00434394))
                    (0,DAT_00434388,0x1000,0x40,PTR_IMAGE_DOS_HEADER_0043439c,param_2);
  DAT_004343a4 = *(undefined4 *)(DAT_004343a4 + iVar4);
  DAT_004343a0 = *(undefined4 *)(DAT_004343a0 + iVar4);
  iVar3 = DAT_00434384 + iVar4;
  (*(code *)(DAT_00434390 + iVar4))(iVar3,iVar1,&DAT_004343a0,iVar4,iVar1);
  pcVar2 = (code *)(iVar1 + DAT_0043438c);
  iVar1 = *(int *)(pcVar2 + -4);
  *(int *)(pcVar2 + (8 - (iVar1 + 4))) = iVar3;
  *(int *)(pcVar2 + (0x14 - (iVar1 + 4))) = DAT_00434390;
  DAT_0043443f = (code *)(*pcVar2)(iVar3);
                    // WARNING: Could not recover jumptable at 0x0043443d. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0043443f)();
  return;
}


