typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
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
  int *piVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  undefined4 extraout_ECX;
  int **ppiVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  int *unaff_EDI;
  uint uVar10;
  uint *puVar11;
  int *piVar12;
  undefined8 uVar13;
  code **ppcVar14;
  int *piVar15;
  int *piStack_5c;
  int *piStack_58;
  int iStack_54;
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
    iVar8 = (int)&DAT_00435191 + DAT_00435191;
    iStack_30 = 8;
    piVar12 = &DAT_004351a5;
    DAT_00435191 = iVar8;
    do {
      piVar15 = piVar12;
      *piVar15 = *piVar15 + iVar8;
      iVar6 = *piVar15;
      iStack_30 = iStack_30 + -1;
      piVar12 = piVar15 + 1;
    } while (iStack_30 != 0);
    *(undefined *)(piVar15 + 1) = 0xe9;
    *(undefined4 *)((int)piVar15 + 5) = DAT_0043519d;
    iStack_24 = 4;
    uStack_28 = 0x1000;
    uStack_2c = DAT_00435199;
    iStack_34 = 0x4351f8;
    piStack_20 = unaff_EDI;
    uStack_3c = (**(code **)(iVar6 + 8))();
    ppiVar5 = (int **)&DAT_00435191;
    piVar12 = DAT_004351a9;
    while( true ) {
      piVar15 = piVar12 + 1;
      iStack_38 = *piVar12;
      if (iStack_38 == 0) break;
      uVar4 = iStack_38 + (int)*ppiVar5;
      piVar12 = piVar12 + 2;
      iStack_38 = *piVar15;
      unaff_EDI = (int *)(uVar4 & 0x7fffffff);
      if ((int)uVar4 < 0) {
        for (; iStack_38 != 0; iStack_38 = iStack_38 + -1) {
          *unaff_EDI = *piVar12;
          piVar12 = piVar12 + 1;
          unaff_EDI = unaff_EDI + 1;
        }
      }
      else {
        piStack_5c = unaff_EDI;
        piStack_58 = piVar12;
        iStack_54 = uStack_3c;
        piStack_50 = unaff_EDI;
        piStack_4c = piVar12;
        iStack_48 = iVar6;
        piStack_44 = &iStack_30;
        ppiStack_40 = ppiVar5;
        iStack_34 = iStack_38;
        iVar3 = (*(code *)ppiVar5[5])();
        piStack_44 = &iStack_30;
        piVar12 = *ppiStack_40;
        iStack_54 = -4;
        iVar8 = -4;
        for (iVar6 = 0; iVar6 < iVar3 + -5; iVar6 = iVar6 + 1) {
          iVar7 = iVar6;
          if ((*(byte *)(iVar6 + (int)piStack_50) & 0xfe) == 0xe8) {
LAB_00435249:
            uVar4 = iVar7 - iVar8 ^ 3;
            iVar6 = iVar7;
            if ((byte)(*(char *)(iVar7 + 4 + (int)piStack_50) + 1U) >> 1 == 0) {
              iVar8 = iVar7 + 1;
              uVar10 = *(uint *)(iVar8 + (int)piStack_50);
              do {
                *(uint *)(iVar8 + (int)piStack_50) =
                     (uVar10 - ((int)piStack_50 - (int)piVar12)) - iVar8;
                if (3 < uVar4) break;
                uVar10 = 0xff << ((byte)(uVar4 << 3) & 0x1f) ^ *(uint *)(iVar8 + (int)piStack_50);
              } while ((byte)(*(char *)(uVar4 + iVar8 + (int)piStack_50) + 1U) >> 1 == 0);
              iVar6 = iVar7 + 4;
              *(char *)(iVar6 + (int)piStack_50) =
                   !(bool)(*(byte *)(iVar6 + (int)piStack_50) & 1) + -1;
              iStack_54 = iVar3 + -5;
            }
          }
          else {
            iVar7 = iVar8;
            if (((ushort)*(undefined4 *)(iVar6 + (int)piStack_50) & 0xf0ff) == 0x800f) {
              iVar7 = iVar6 + 1;
              goto LAB_00435249;
            }
          }
          iVar8 = iVar7;
        }
        piVar12 = (int *)((int)piStack_4c + iStack_38);
        ppiVar5 = ppiStack_40;
        iVar6 = iStack_48;
        unaff_EDI = piStack_50;
      }
    }
    iStack_34 = 0x8000;
    ppiStack_40 = (int **)0x4352b1;
    (**(code **)(iVar6 + 0xc))();
    ppiStack_40 = ppiVar5 + 3;
    piStack_44 = (int *)0x4;
    iStack_48 = 1;
    piStack_4c = *ppiVar5;
    piStack_50 = (int *)0x4352be;
    (**(code **)(iVar6 + 0x10))();
    piStack_58 = (int *)((int)ppiVar5[2] - (int)ppiVar5[1]);
    piStack_50 = (int *)0x4;
    iStack_54 = 0x1000;
    piStack_5c = (int *)0x0;
    uVar13 = (**(code **)(iVar6 + 8))();
    ppcVar14 = (code **)uVar13;
    (*(code *)ppiVar5[5])
              (*ppiVar5,ppiVar5[7],ppcVar14,unaff_EDI,piVar15,iVar6,&piStack_5c,ppiVar5,
               (int)((ulonglong)uVar13 >> 0x20),extraout_ECX,ppcVar14);
    (*ppcVar14[3])(ppiVar5,0,0x8000);
    (*ppcVar14[4])(*piVar15,1,piVar15[3],piVar15 + 3);
    piVar12 = (int *)piVar15[8];
    while( true ) {
      if (*piVar12 == 0) break;
      iStack_24 = *piVar12 + *piVar15;
      uStack_28 = 0x435300;
      iStack_24 = (**ppcVar14)();
      for (puVar11 = (uint *)(piVar12[1] + *piVar15); uVar4 = *puVar11, uVar4 != 0;
          puVar11 = puVar11 + 1) {
        uStack_28 = uVar4 & 0x7fffffff;
        if (-1 < (int)uVar4) {
          uStack_28 = uStack_28 + *piVar15 + 2;
        }
        iStack_30 = 0x435316;
        uStack_2c = iStack_24;
        uVar4 = (*ppcVar14[1])();
        *puVar11 = uVar4;
      }
      piVar12 = piVar12 + 5;
    }
    iVar8 = piVar15[0xb];
    unaff_EDI = piStack_20;
    if (iVar8 != 0) {
      piVar12 = (int *)piVar15[9];
      while( true ) {
        iVar6 = *piVar12;
        piVar9 = piVar12 + 2;
        piVar12 = (int *)((int)piVar12 + piVar12[1]);
        if (iVar6 == 0) break;
        while (piVar9 != piVar12) {
          piVar1 = (int *)((int)piVar9 + 2);
          uVar2 = *(ushort *)piVar9;
          piVar9 = piVar1;
          if (uVar2 != 0) {
            piVar1 = (int *)(iVar6 + (uVar2 & 0xffff0fff) + *piVar15);
            *piVar1 = *piVar1 + iVar8;
          }
        }
      }
    }
  } while( true );
}



uint FUN_00435358(int param_1,byte *param_2,undefined4 *param_3)

{
  byte *pbVar1;
  byte *pbVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  uint uVar9;
  uint uVar10;
  int local_30;
  int local_2c;
  uint local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  uint local_14;
  int local_10;
  byte *local_c;
  byte local_5;
  
  local_18 = 1;
  local_20 = 1;
  local_1c = 1;
  local_2c = 1;
  puVar8 = param_3;
  for (iVar4 = 0x30736; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar8 = 0x400;
    puVar8 = puVar8 + 1;
  }
  local_c = param_2;
  local_14 = 0;
  local_5 = 0;
  local_10 = 0;
  param_2 = (byte *)0x0;
  pbVar1 = (byte *)0xffffffff;
  iVar4 = 5;
  do {
    param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
    local_c = local_c + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
LAB_004353ad:
  iVar4 = local_2c;
  uVar9 = local_14 & 3;
  puVar5 = param_3 + local_10 * 0x10 + uVar9;
  pbVar2 = pbVar1;
  if (pbVar1 < (byte *)0x1000000) {
    param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
    pbVar2 = (byte *)((int)pbVar1 << 8);
    local_c = local_c + 1;
  }
  uVar10 = *puVar5;
  pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
  if (param_2 < pbVar1) {
    *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
    iVar4 = 1;
    pbVar2 = pbVar1;
    if (local_10 < 7) goto LAB_004354c5;
    local_28 = (uint)*(byte *)(param_1 + (local_14 - local_18));
    do {
      local_28 = local_28 << 1;
      uVar9 = local_28 & 0x100;
      puVar5 = param_3 + (uint)local_5 * 0x300 + iVar4 + uVar9 + 0x836;
      pbVar2 = pbVar1;
      if (pbVar1 < (byte *)0x1000000) {
        param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
        pbVar2 = (byte *)((int)pbVar1 << 8);
        local_c = local_c + 1;
      }
      uVar10 = *puVar5;
      pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
      if (param_2 < pbVar1) {
        iVar4 = iVar4 * 2;
        *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
        if (uVar9 != 0) goto LAB_0043551e;
      }
      else {
        param_2 = param_2 + -(int)pbVar1;
        pbVar1 = pbVar2 + -(int)pbVar1;
        *puVar5 = uVar10 - (uVar10 >> 5);
        iVar4 = iVar4 * 2 + 1;
        if (uVar9 == 0) goto LAB_0043551e;
      }
    } while (iVar4 < 0x100);
    goto LAB_00435526;
  }
  param_2 = param_2 + -(int)pbVar1;
  uVar3 = (int)pbVar2 - (int)pbVar1;
  *puVar5 = uVar10 - (uVar10 >> 5);
  puVar5 = param_3 + local_10 + 0xc0;
  if (uVar3 < 0x1000000) {
    param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
    uVar3 = uVar3 * 0x100;
    local_c = local_c + 1;
  }
  uVar10 = *puVar5;
  pbVar2 = (byte *)((uVar3 >> 0xb) * uVar10);
  if (param_2 < pbVar2) {
    local_2c = local_1c;
    local_1c = local_20;
    *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
    local_20 = local_18;
    if (local_10 < 7) {
      local_10 = 0;
    }
    else {
      local_10 = 3;
    }
    puVar5 = param_3 + 0x332;
  }
  else {
    param_2 = param_2 + -(int)pbVar2;
    uVar3 = uVar3 - (int)pbVar2;
    *puVar5 = uVar10 - (uVar10 >> 5);
    puVar5 = param_3 + local_10 + 0xcc;
    if (uVar3 < 0x1000000) {
      param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
      uVar3 = uVar3 * 0x100;
      local_c = local_c + 1;
    }
    uVar10 = *puVar5;
    pbVar2 = (byte *)((uVar3 >> 0xb) * uVar10);
    if (param_2 < pbVar2) {
      *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
      puVar5 = param_3 + (local_10 + 0xf) * 0x10 + uVar9;
      if (pbVar2 < (byte *)0x1000000) {
        pbVar2 = (byte *)((int)pbVar2 * 0x100);
        param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
        local_c = local_c + 1;
      }
      uVar10 = *puVar5;
      pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
      if (param_2 < pbVar1) {
        *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
        local_10 = (uint)(6 < local_10) * 2 + 9;
        local_5 = *(byte *)(param_1 + (local_14 - local_18));
        *(byte *)(param_1 + local_14) = local_5;
        local_14 = local_14 + 1;
        goto LAB_004353ad;
      }
      param_2 = param_2 + -(int)pbVar1;
      pbVar2 = pbVar2 + -(int)pbVar1;
      *puVar5 = uVar10 - (uVar10 >> 5);
    }
    else {
      param_2 = param_2 + -(int)pbVar2;
      uVar3 = uVar3 - (int)pbVar2;
      *puVar5 = uVar10 - (uVar10 >> 5);
      puVar5 = param_3 + local_10 + 0xd8;
      if (uVar3 < 0x1000000) {
        param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
        uVar3 = uVar3 * 0x100;
        local_c = local_c + 1;
      }
      uVar10 = *puVar5;
      pbVar2 = (byte *)((uVar3 >> 0xb) * uVar10);
      if (param_2 < pbVar2) {
        *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
        iVar4 = local_20;
      }
      else {
        param_2 = param_2 + -(int)pbVar2;
        uVar3 = uVar3 - (int)pbVar2;
        *puVar5 = uVar10 - (uVar10 >> 5);
        puVar5 = param_3 + local_10 + 0xe4;
        if (uVar3 < 0x1000000) {
          param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
          uVar3 = uVar3 * 0x100;
          local_c = local_c + 1;
        }
        uVar10 = *puVar5;
        pbVar2 = (byte *)((uVar3 >> 0xb) * uVar10);
        if (param_2 < pbVar2) {
          *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
          iVar4 = local_1c;
        }
        else {
          param_2 = param_2 + -(int)pbVar2;
          pbVar2 = (byte *)(uVar3 - (int)pbVar2);
          *puVar5 = uVar10 - (uVar10 >> 5);
          local_2c = local_1c;
        }
        local_1c = local_20;
      }
      local_20 = local_18;
      local_18 = iVar4;
    }
    local_10 = ((6 < local_10) - 1 & 0xfffffffd) + 0xb;
    puVar5 = param_3 + 0x534;
  }
  if (pbVar2 < (byte *)0x1000000) {
    param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
    pbVar2 = (byte *)((int)pbVar2 << 8);
    local_c = local_c + 1;
  }
  uVar10 = *puVar5;
  pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
  if (param_2 < pbVar1) {
    local_28 = 0;
    *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
    iVar4 = uVar9 * 8 + 2;
LAB_00435878:
    puVar5 = puVar5 + iVar4;
    local_24 = 3;
  }
  else {
    param_2 = param_2 + -(int)pbVar1;
    uVar3 = (int)pbVar2 - (int)pbVar1;
    *puVar5 = uVar10 - (uVar10 >> 5);
    if (uVar3 < 0x1000000) {
      param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
      uVar3 = uVar3 * 0x100;
      local_c = local_c + 1;
    }
    uVar10 = puVar5[1];
    pbVar1 = (byte *)((uVar3 >> 0xb) * uVar10);
    if (param_2 < pbVar1) {
      puVar5[1] = (0x800 - uVar10 >> 5) + uVar10;
      iVar4 = uVar9 * 8 + 0x82;
      local_28 = 8;
      goto LAB_00435878;
    }
    param_2 = param_2 + -(int)pbVar1;
    pbVar1 = (byte *)(uVar3 - (int)pbVar1);
    puVar5[1] = uVar10 - (uVar10 >> 5);
    puVar5 = puVar5 + 0x102;
    local_28 = 0x10;
    local_24 = 8;
  }
  local_30 = local_24;
  iVar4 = 1;
  do {
    pbVar2 = pbVar1;
    if (pbVar1 < (byte *)0x1000000) {
      param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
      pbVar2 = (byte *)((int)pbVar1 << 8);
      local_c = local_c + 1;
    }
    uVar9 = puVar5[iVar4];
    pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar9);
    if (param_2 < pbVar1) {
      puVar5[iVar4] = (0x800 - uVar9 >> 5) + uVar9;
      iVar4 = iVar4 * 2;
    }
    else {
      param_2 = param_2 + -(int)pbVar1;
      pbVar1 = pbVar2 + -(int)pbVar1;
      puVar5[iVar4] = uVar9 - (uVar9 >> 5);
      iVar4 = iVar4 * 2 + 1;
    }
    local_30 = local_30 + -1;
  } while (local_30 != 0);
  iVar7 = 1;
  iVar4 = iVar4 + (local_28 - (1 << (sbyte)local_24));
  if (local_10 < 4) {
    local_10 = local_10 + 7;
    iVar6 = iVar4;
    if (3 < iVar4) {
      iVar6 = 3;
    }
    local_30 = 6;
    do {
      pbVar2 = pbVar1;
      if (pbVar1 < (byte *)0x1000000) {
        param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
        pbVar2 = (byte *)((int)pbVar1 << 8);
        local_c = local_c + 1;
      }
      uVar9 = param_3[iVar6 * 0x40 + iVar7 + 0x1b0];
      pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar9);
      if (param_2 < pbVar1) {
        param_3[iVar6 * 0x40 + iVar7 + 0x1b0] = (0x800 - uVar9 >> 5) + uVar9;
        iVar7 = iVar7 * 2;
      }
      else {
        param_2 = param_2 + -(int)pbVar1;
        pbVar1 = pbVar2 + -(int)pbVar1;
        param_3[iVar6 * 0x40 + iVar7 + 0x1b0] = uVar9 - (uVar9 >> 5);
        iVar7 = iVar7 * 2 + 1;
      }
      local_30 = local_30 + -1;
    } while (local_30 != 0);
    uVar9 = iVar7 - 0x40;
    if (3 < (int)uVar9) {
      local_18 = ((int)uVar9 >> 1) + -1;
      uVar10 = uVar9 & 1 | 2;
      if ((int)uVar9 < 0xe) {
        uVar10 = uVar10 << ((byte)local_18 & 0x1f);
        puVar8 = param_3 + (uVar10 - uVar9) + 0x2af;
      }
      else {
        iVar7 = ((int)uVar9 >> 1) + -5;
        do {
          if (pbVar1 < (byte *)0x1000000) {
            param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
            pbVar1 = (byte *)((int)pbVar1 << 8);
            local_c = local_c + 1;
          }
          pbVar1 = (byte *)((uint)pbVar1 >> 1);
          uVar10 = uVar10 * 2;
          if (pbVar1 <= param_2) {
            param_2 = param_2 + -(int)pbVar1;
            uVar10 = uVar10 | 1;
          }
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
        puVar8 = param_3 + 0x322;
        uVar10 = uVar10 << 4;
        local_18 = 4;
      }
      iVar7 = 1;
      local_28 = 1;
      uVar9 = uVar10;
      do {
        pbVar2 = pbVar1;
        if (pbVar1 < (byte *)0x1000000) {
          param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
          pbVar2 = (byte *)((int)pbVar1 << 8);
          local_c = local_c + 1;
        }
        uVar10 = puVar8[iVar7];
        pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
        if (param_2 < pbVar1) {
          puVar8[iVar7] = (0x800 - uVar10 >> 5) + uVar10;
          iVar7 = iVar7 * 2;
        }
        else {
          param_2 = param_2 + -(int)pbVar1;
          pbVar1 = pbVar2 + -(int)pbVar1;
          uVar9 = uVar9 | local_28;
          puVar8[iVar7] = uVar10 - (uVar10 >> 5);
          iVar7 = iVar7 * 2 + 1;
        }
        local_28 = local_28 << 1;
        local_18 = local_18 + -1;
      } while (local_18 != 0);
    }
    local_18 = uVar9 + 1;
    if (local_18 == 0) {
      return local_14;
    }
  }
  iVar4 = iVar4 + 2;
  pbVar2 = (byte *)((local_14 - local_18) + param_1);
  do {
    local_5 = *pbVar2;
    iVar4 = iVar4 + -1;
    uVar9 = local_14 + 1;
    pbVar2 = pbVar2 + 1;
    *(byte *)(param_1 + local_14) = local_5;
    local_14 = uVar9;
  } while (iVar4 != 0);
  goto LAB_004353ad;
LAB_0043551e:
  while (pbVar2 = pbVar1, iVar4 < 0x100) {
LAB_004354c5:
    puVar5 = param_3 + (uint)local_5 * 0x300 + iVar4 + 0x736;
    if (pbVar2 < (byte *)0x1000000) {
      param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
      pbVar2 = (byte *)((int)pbVar2 << 8);
      local_c = local_c + 1;
    }
    uVar9 = *puVar5;
    pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar9);
    if (param_2 < pbVar1) {
      *puVar5 = (0x800 - uVar9 >> 5) + uVar9;
      iVar4 = iVar4 * 2;
    }
    else {
      param_2 = param_2 + -(int)pbVar1;
      pbVar1 = pbVar2 + -(int)pbVar1;
      *puVar5 = uVar9 - (uVar9 >> 5);
      iVar4 = iVar4 * 2 + 1;
    }
  }
LAB_00435526:
  uVar9 = local_14 + 1;
  local_5 = (byte)iVar4;
  *(byte *)(param_1 + local_14) = local_5;
  local_14 = uVar9;
  if (local_10 < 4) {
    local_10 = 0;
  }
  else if (local_10 < 10) {
    local_10 = local_10 + -3;
  }
  else {
    local_10 = local_10 + -6;
  }
  goto LAB_004353ad;
}


