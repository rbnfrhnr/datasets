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

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
};




void entry(void)

{
  int iVar1;
  int *piVar2;
  ushort uVar3;
  int *piVar4;
  uint uVar5;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  int **ppiVar6;
  int iVar7;
  int *piVar8;
  uint *puVar9;
  int *piVar10;
  undefined8 uVar11;
  code **ppcVar12;
  int *piStack_5c;
  int *piStack_58;
  int iStack_54;
  int *piStack_50;
  int *piStack_4c;
  int iStack_48;
  int *piStack_44;
  int **ppiStack_40;
  int *piStack_3c;
  int iStack_38;
  int iStack_34;
  int iStack_30;
  undefined4 uStack_2c;
  uint uStack_28;
  int iStack_24;
  
  do {
    iVar1 = (int)&DAT_0044c563 + DAT_0044c563;
    iStack_30 = 8;
    piVar4 = &DAT_0044c577;
    DAT_0044c563 = iVar1;
    do {
      piVar10 = piVar4;
      *piVar10 = *piVar10 + iVar1;
      iVar7 = *piVar10;
      iStack_30 = iStack_30 + -1;
      piVar4 = piVar10 + 1;
    } while (iStack_30 != 0);
    *(undefined *)(piVar10 + 1) = 0xe9;
    *(undefined4 *)((int)piVar10 + 5) = DAT_0044c56f;
    iStack_24 = 4;
    uStack_28 = 0x1000;
    uStack_2c = DAT_0044c56b;
    iStack_34 = 0x44c5ca;
    piVar4 = (int *)(**(code **)(iVar7 + 8))();
    iStack_34 = (int)piVar4 + DAT_0044c567;
    iStack_38 = extraout_ECX;
    piStack_3c = DAT_0044c57b;
    ppiVar6 = (int **)&DAT_0044c563;
    while( true ) {
      iVar1 = *piStack_3c;
      if (iVar1 == 0) break;
      piStack_58 = (int *)(iVar1 + (int)*ppiVar6);
      piStack_5c = piVar4;
      iStack_54 = iStack_34;
      piStack_50 = piStack_58;
      piStack_4c = piVar4;
      iStack_48 = iVar7;
      piStack_44 = &iStack_30;
      ppiStack_40 = ppiVar6;
      uVar5 = (*(code *)ppiVar6[5])();
      piVar4 = piStack_4c;
      piVar10 = piStack_50;
      for (uVar5 = uVar5 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
        *piVar10 = *piVar4;
        piVar4 = piVar4 + 1;
        piVar10 = piVar10 + 1;
      }
      piStack_3c = piStack_3c + 1;
      iStack_38 = 0;
      ppiVar6 = ppiStack_40;
      iVar7 = iStack_48;
      piVar4 = piStack_4c;
    }
    iStack_34 = 0x8000;
    ppiStack_40 = (int **)0x44c5fc;
    piStack_3c = piVar4;
    iStack_38 = iVar1;
    (**(code **)(iVar7 + 0xc))();
    ppiStack_40 = ppiVar6 + 3;
    piStack_44 = (int *)0x4;
    iStack_48 = 1;
    piStack_4c = *ppiVar6;
    piStack_50 = (int *)0x44c609;
    (**(code **)(iVar7 + 0x10))();
    piStack_58 = (int *)((int)ppiVar6[2] - (int)ppiVar6[1]);
    piStack_50 = (int *)0x4;
    iStack_54 = 0x1000;
    piStack_5c = (int *)0x0;
    uVar11 = (**(code **)(iVar7 + 8))();
    ppcVar12 = (code **)uVar11;
    (*(code *)ppiVar6[5])
              (*ppiVar6,ppiVar6[7],ppcVar12,0,piVar4,iVar7,&piStack_5c,ppiVar6,
               (int)((ulonglong)uVar11 >> 0x20),extraout_ECX_00,ppcVar12);
    (*ppcVar12[3])(ppiVar6,0,0x8000);
    (*ppcVar12[4])(*piVar4,1,piVar4[3],piVar4 + 3);
    piVar10 = (int *)piVar4[8];
    while( true ) {
      if (*piVar10 == 0) break;
      iStack_24 = *piVar10 + *piVar4;
      uStack_28 = 0x44c64b;
      iStack_24 = (**ppcVar12)();
      for (puVar9 = (uint *)(piVar10[1] + *piVar4); uVar5 = *puVar9, uVar5 != 0; puVar9 = puVar9 + 1
          ) {
        uStack_28 = uVar5 & 0x7fffffff;
        if (-1 < (int)uVar5) {
          uStack_28 = uStack_28 + *piVar4 + 2;
        }
        iStack_30 = 0x44c661;
        uStack_2c = iStack_24;
        uVar5 = (*ppcVar12[1])();
        *puVar9 = uVar5;
      }
      piVar10 = piVar10 + 5;
    }
    iVar1 = piVar4[0xb];
    if (iVar1 != 0) {
      piVar10 = (int *)piVar4[9];
      while( true ) {
        iVar7 = *piVar10;
        piVar8 = piVar10 + 2;
        piVar10 = (int *)((int)piVar10 + piVar10[1]);
        if (iVar7 == 0) break;
        while (piVar8 != piVar10) {
          piVar2 = (int *)((int)piVar8 + 2);
          uVar3 = *(ushort *)piVar8;
          piVar8 = piVar2;
          if (uVar3 != 0) {
            piVar2 = (int *)(iVar7 + (uVar3 & 0xffff0fff) + *piVar4);
            *piVar2 = *piVar2 + iVar1;
          }
        }
      }
    }
  } while( true );
}



int FUN_0044c6a3(byte *param_1,byte *param_2)

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
  pbVar8 = param_1;
  do {
    pbVar7 = param_2 + 1;
    *pbVar8 = *param_2;
    iVar6 = 2;
    pbVar8 = pbVar8 + 1;
    while (func_0x0044c723(), param_2 = pbVar7, (bool)uVar9) {
      bVar10 = false;
      func_0x0044c723();
      if (bVar10) {
        bVar11 = false;
        uVar3 = func_0x0044c723();
        if (!(bool)bVar11) {
          pbVar4 = (byte *)(CONCAT31((int3)((uint)uVar3 >> 8),*pbVar7) >> 1);
          if (pbVar4 == (byte *)0x0) {
            return (int)pbVar8 - (int)param_1;
          }
          iVar5 = extraout_ECX * 2 + (uint)((*pbVar7 & 1) != 0);
          goto code_r0x0044c712;
        }
        iVar6 = 2;
        do {
          uVar3 = func_0x0044c723();
          bVar2 = (byte)uVar3;
          bVar10 = CARRY1(bVar2 * '\x02',bVar11);
          uVar9 = CARRY1(bVar2,bVar2) || bVar10;
          cVar1 = bVar2 * '\x02' + bVar11;
          pbVar4 = (byte *)CONCAT31((int3)((uint)uVar3 >> 8),cVar1);
          bVar11 = uVar9;
        } while (!CARRY1(bVar2,bVar2) && !bVar10);
        iVar5 = extraout_ECX_00;
        if (cVar1 != '\0') goto code_r0x0044c719;
        *pbVar8 = 0;
        pbVar8 = pbVar8 + 1;
      }
      else {
        func_0x0044c72f();
        if (extraout_ECX_01 == iVar6) {
          func_0x0044c72d();
          iVar5 = extraout_ECX_02;
          pbVar4 = unaff_EBP;
        }
        else {
          pbVar4 = (byte *)func_0x0044c72d();
          iVar5 = extraout_ECX_03;
          if (pbVar4 < (byte *)0x7d00) {
            if (4 < (byte)((uint)pbVar4 >> 8)) goto code_r0x0044c713;
            if (pbVar4 < (byte *)0x80) goto code_r0x0044c712;
          }
          else {
code_r0x0044c712:
            iVar5 = iVar5 + 1;
code_r0x0044c713:
            iVar5 = iVar5 + 1;
          }
          pbVar7 = pbVar7 + 1;
        }
        iVar6 = 1;
        unaff_EBP = pbVar4;
code_r0x0044c719:
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


