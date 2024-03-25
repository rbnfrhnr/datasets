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
    byte e_program[60]; // Actual DOS program
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
  uint uVar4;
  undefined4 extraout_ECX;
  int **ppiVar5;
  int iVar6;
  int *piVar7;
  int *unaff_EDI;
  uint *puVar8;
  int *piVar9;
  undefined8 uVar10;
  code **ppcVar11;
  int *piVar12;
  int *piStack_5c;
  int *piStack_58;
  undefined4 uStack_54;
  int *piStack_50;
  int *piStack_4c;
  int iStack_48;
  int *piStack_44;
  int **ppiStack_40;
  undefined4 uStack_3c;
  int iStack_38;
  int iStack_34;
  int iStack_30;
  undefined4 uStack_2c;
  uint uStack_28;
  int iStack_24;
  int *piStack_20;
  
  do {
    iVar1 = (int)&DAT_0043c9b8 + DAT_0043c9b8;
    iStack_30 = 8;
    piVar9 = &DAT_0043c9cc;
    DAT_0043c9b8 = iVar1;
    do {
      piVar12 = piVar9;
      *piVar12 = *piVar12 + iVar1;
      iVar6 = *piVar12;
      iStack_30 = iStack_30 + -1;
      piVar9 = piVar12 + 1;
    } while (iStack_30 != 0);
    *(undefined *)(piVar12 + 1) = 0xe9;
    *(undefined4 *)((int)piVar12 + 5) = DAT_0043c9c4;
    iStack_24 = 4;
    uStack_28 = 0x1000;
    uStack_2c = DAT_0043c9c0;
    iStack_34 = 0x43ca1f;
    piStack_20 = unaff_EDI;
    uStack_3c = (**(code **)(iVar6 + 8))();
    ppiVar5 = (int **)&DAT_0043c9b8;
    piVar9 = DAT_0043c9d0;
    while( true ) {
      piVar12 = piVar9 + 1;
      iStack_38 = *piVar9;
      if (iStack_38 == 0) break;
      uVar4 = iStack_38 + (int)*ppiVar5;
      piVar9 = piVar9 + 2;
      iStack_38 = *piVar12;
      unaff_EDI = (int *)(uVar4 & 0x7fffffff);
      if ((int)uVar4 < 0) {
        for (; iStack_38 != 0; iStack_38 = iStack_38 + -1) {
          *unaff_EDI = *piVar9;
          piVar9 = piVar9 + 1;
          unaff_EDI = unaff_EDI + 1;
        }
      }
      else {
        piStack_5c = unaff_EDI;
        piStack_58 = piVar9;
        uStack_54 = uStack_3c;
        piStack_50 = unaff_EDI;
        piStack_4c = piVar9;
        iStack_48 = iVar6;
        piStack_44 = &iStack_30;
        ppiStack_40 = ppiVar5;
        iStack_34 = iStack_38;
        (*(code *)ppiVar5[5])();
        piVar9 = (int *)((int)piStack_4c + iStack_38);
        ppiVar5 = ppiStack_40;
        iVar6 = iStack_48;
        unaff_EDI = piStack_50;
      }
    }
    iStack_34 = 0x8000;
    ppiStack_40 = (int **)0x43ca50;
    (**(code **)(iVar6 + 0xc))();
    ppiStack_40 = ppiVar5 + 3;
    piStack_44 = (int *)0x4;
    iStack_48 = 1;
    piStack_4c = *ppiVar5;
    piStack_50 = (int *)0x43ca5d;
    (**(code **)(iVar6 + 0x10))();
    piStack_58 = (int *)((int)ppiVar5[2] - (int)ppiVar5[1]);
    piStack_50 = (int *)0x4;
    uStack_54 = 0x1000;
    piStack_5c = (int *)0x0;
    uVar10 = (**(code **)(iVar6 + 8))();
    ppcVar11 = (code **)uVar10;
    (*(code *)ppiVar5[5])
              (*ppiVar5,ppiVar5[7],ppcVar11,unaff_EDI,piVar12,iVar6,&piStack_5c,ppiVar5,
               (int)((ulonglong)uVar10 >> 0x20),extraout_ECX,ppcVar11);
    (*ppcVar11[3])(ppiVar5,0,0x8000);
    (*ppcVar11[4])(*piVar12,1,piVar12[3],piVar12 + 3);
    piVar9 = (int *)piVar12[8];
    while( true ) {
      if (*piVar9 == 0) break;
      iStack_24 = *piVar9 + *piVar12;
      uStack_28 = 0x43ca9f;
      iStack_24 = (**ppcVar11)();
      for (puVar8 = (uint *)(piVar9[1] + *piVar12); uVar4 = *puVar8, uVar4 != 0; puVar8 = puVar8 + 1
          ) {
        uStack_28 = uVar4 & 0x7fffffff;
        if (-1 < (int)uVar4) {
          uStack_28 = uStack_28 + *piVar12 + 2;
        }
        iStack_30 = 0x43cab5;
        uStack_2c = iStack_24;
        uVar4 = (*ppcVar11[1])();
        *puVar8 = uVar4;
      }
      piVar9 = piVar9 + 5;
    }
    iVar1 = piVar12[0xb];
    unaff_EDI = piStack_20;
    if (iVar1 != 0) {
      piVar9 = (int *)piVar12[9];
      while( true ) {
        iVar6 = *piVar9;
        piVar7 = piVar9 + 2;
        piVar9 = (int *)((int)piVar9 + piVar9[1]);
        if (iVar6 == 0) break;
        while (piVar7 != piVar9) {
          piVar2 = (int *)((int)piVar7 + 2);
          uVar3 = *(ushort *)piVar7;
          piVar7 = piVar2;
          if (uVar3 != 0) {
            piVar2 = (int *)(iVar6 + (uVar3 & 0xffff0fff) + *piVar12);
            *piVar2 = *piVar2 + iVar1;
          }
        }
      }
    }
  } while( true );
}



int FUN_0043caf7(byte *param_1,byte *param_2)

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
    while (func_0x0043cb77(), param_2 = pbVar7, (bool)uVar9) {
      bVar10 = false;
      func_0x0043cb77();
      if (bVar10) {
        bVar11 = false;
        uVar3 = func_0x0043cb77();
        if (!(bool)bVar11) {
          pbVar4 = (byte *)(CONCAT31((int3)((uint)uVar3 >> 8),*pbVar7) >> 1);
          if (pbVar4 == (byte *)0x0) {
            return (int)pbVar8 - (int)param_1;
          }
          iVar5 = extraout_ECX * 2 + (uint)((*pbVar7 & 1) != 0);
          goto code_r0x0043cb66;
        }
        iVar6 = 2;
        do {
          uVar3 = func_0x0043cb77();
          bVar2 = (byte)uVar3;
          bVar10 = CARRY1(bVar2 * '\x02',bVar11);
          uVar9 = CARRY1(bVar2,bVar2) || bVar10;
          cVar1 = bVar2 * '\x02' + bVar11;
          pbVar4 = (byte *)CONCAT31((int3)((uint)uVar3 >> 8),cVar1);
          bVar11 = uVar9;
        } while (!CARRY1(bVar2,bVar2) && !bVar10);
        iVar5 = extraout_ECX_00;
        if (cVar1 != '\0') goto code_r0x0043cb6d;
        *pbVar8 = 0;
        pbVar8 = pbVar8 + 1;
      }
      else {
        func_0x0043cb83();
        if (extraout_ECX_01 == iVar6) {
          func_0x0043cb81();
          iVar5 = extraout_ECX_02;
          pbVar4 = unaff_EBP;
        }
        else {
          pbVar4 = (byte *)func_0x0043cb81();
          iVar5 = extraout_ECX_03;
          if (pbVar4 < (byte *)0x7d00) {
            if (4 < (byte)((uint)pbVar4 >> 8)) goto code_r0x0043cb67;
            if (pbVar4 < (byte *)0x80) goto code_r0x0043cb66;
          }
          else {
code_r0x0043cb66:
            iVar5 = iVar5 + 1;
code_r0x0043cb67:
            iVar5 = iVar5 + 1;
          }
          pbVar7 = pbVar7 + 1;
        }
        iVar6 = 1;
        unaff_EBP = pbVar4;
code_r0x0043cb6d:
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


