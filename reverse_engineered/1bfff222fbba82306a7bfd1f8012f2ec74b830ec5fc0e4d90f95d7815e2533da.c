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
  int *piVar3;
  uint uVar4;
  uint uVar5;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  int **ppiVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  uint uVar11;
  uint *puVar12;
  int *piVar13;
  undefined8 uVar14;
  code **ppcVar15;
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
    iVar9 = (int)&DAT_0042971c + DAT_0042971c;
    iStack_30 = 8;
    piVar3 = &DAT_00429730;
    DAT_0042971c = iVar9;
    do {
      piVar13 = piVar3;
      *piVar13 = *piVar13 + iVar9;
      iVar7 = *piVar13;
      iStack_30 = iStack_30 + -1;
      piVar3 = piVar13 + 1;
    } while (iStack_30 != 0);
    *(undefined *)(piVar13 + 1) = 0xe9;
    *(undefined4 *)((int)piVar13 + 5) = DAT_00429728;
    iStack_24 = 4;
    uStack_28 = 0x1000;
    uStack_2c = DAT_00429724;
    iStack_34 = 0x429783;
    piVar3 = (int *)(**(code **)(iVar7 + 8))();
    iStack_34 = (int)piVar3 + DAT_00429720;
    iStack_38 = extraout_ECX;
    piStack_3c = DAT_00429734;
    ppiVar6 = (int **)&DAT_0042971c;
    while( true ) {
      iVar9 = *piStack_3c;
      if (iVar9 == 0) break;
      piStack_58 = (int *)(iVar9 + (int)*ppiVar6);
      piStack_5c = piVar3;
      iStack_54 = iStack_34;
      piStack_50 = piStack_58;
      piStack_4c = piVar3;
      iStack_48 = iVar7;
      piStack_44 = &iStack_30;
      ppiStack_40 = ppiVar6;
      uVar5 = (*(code *)ppiVar6[5])();
      piStack_44 = &iStack_30;
      piVar3 = *ppiStack_40;
      iStack_54 = -4;
      iVar9 = -4;
      for (iVar7 = 0; iVar7 < (int)(uVar5 - 5); iVar7 = iVar7 + 1) {
        iVar8 = iVar7;
        if ((*(byte *)(iVar7 + (int)piStack_4c) & 0xfe) == 0xe8) {
LAB_004297c5:
          uVar4 = iVar8 - iVar9 ^ 3;
          iVar7 = iVar8;
          if ((byte)(*(char *)(iVar8 + 4 + (int)piStack_4c) + 1U) >> 1 == 0) {
            iVar9 = iVar8 + 1;
            uVar11 = *(uint *)(iVar9 + (int)piStack_4c);
            do {
              *(uint *)(iVar9 + (int)piStack_4c) =
                   (uVar11 - ((int)piStack_50 - (int)piVar3)) - iVar9;
              if (3 < uVar4) break;
              uVar11 = 0xff << ((byte)(uVar4 << 3) & 0x1f) ^ *(uint *)(iVar9 + (int)piStack_4c);
            } while ((byte)(*(char *)(uVar4 + iVar9 + (int)piStack_4c) + 1U) >> 1 == 0);
            iVar7 = iVar8 + 4;
            *(char *)(iVar7 + (int)piStack_4c) =
                 !(bool)(*(byte *)(iVar7 + (int)piStack_4c) & 1) + -1;
            iStack_54 = uVar5 - 5;
          }
        }
        else {
          iVar8 = iVar9;
          if (((ushort)*(undefined4 *)(iVar7 + (int)piStack_4c) & 0xf0ff) == 0x800f) {
            iVar8 = iVar7 + 1;
            goto LAB_004297c5;
          }
        }
        iVar9 = iVar8;
      }
      piVar3 = piStack_4c;
      piVar13 = piStack_50;
      for (uVar5 = uVar5 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
        *piVar13 = *piVar3;
        piVar3 = piVar3 + 1;
        piVar13 = piVar13 + 1;
      }
      piStack_3c = piStack_3c + 1;
      iStack_38 = 0;
      ppiVar6 = ppiStack_40;
      iVar7 = iStack_48;
      piVar3 = piStack_4c;
    }
    iStack_34 = 0x8000;
    ppiStack_40 = (int **)0x429836;
    piStack_3c = piVar3;
    iStack_38 = iVar9;
    (**(code **)(iVar7 + 0xc))();
    ppiStack_40 = ppiVar6 + 3;
    piStack_44 = (int *)0x4;
    iStack_48 = 1;
    piStack_4c = *ppiVar6;
    piStack_50 = (int *)0x429843;
    (**(code **)(iVar7 + 0x10))();
    piStack_58 = (int *)((int)ppiVar6[2] - (int)ppiVar6[1]);
    piStack_50 = (int *)0x4;
    iStack_54 = 0x1000;
    piStack_5c = (int *)0x0;
    uVar14 = (**(code **)(iVar7 + 8))();
    ppcVar15 = (code **)uVar14;
    (*(code *)ppiVar6[5])
              (*ppiVar6,ppiVar6[7],ppcVar15,0,piVar3,iVar7,&piStack_5c,ppiVar6,
               (int)((ulonglong)uVar14 >> 0x20),extraout_ECX_00,ppcVar15);
    (*ppcVar15[3])(ppiVar6,0,0x8000);
    (*ppcVar15[4])(*piVar3,1,piVar3[3],piVar3 + 3);
    piVar13 = (int *)piVar3[8];
    while( true ) {
      if (*piVar13 == 0) break;
      iStack_24 = *piVar13 + *piVar3;
      uStack_28 = 0x429885;
      iStack_24 = (**ppcVar15)();
      for (puVar12 = (uint *)(piVar13[1] + *piVar3); uVar5 = *puVar12, uVar5 != 0;
          puVar12 = puVar12 + 1) {
        uStack_28 = uVar5 & 0x7fffffff;
        if (-1 < (int)uVar5) {
          uStack_28 = uStack_28 + *piVar3 + 2;
        }
        iStack_30 = 0x42989b;
        uStack_2c = iStack_24;
        uVar5 = (*ppcVar15[1])();
        *puVar12 = uVar5;
      }
      piVar13 = piVar13 + 5;
    }
    iVar9 = piVar3[0xb];
    if (iVar9 != 0) {
      piVar13 = (int *)piVar3[9];
      while( true ) {
        iVar7 = *piVar13;
        piVar10 = piVar13 + 2;
        piVar13 = (int *)((int)piVar13 + piVar13[1]);
        if (iVar7 == 0) break;
        while (piVar10 != piVar13) {
          piVar1 = (int *)((int)piVar10 + 2);
          uVar2 = *(ushort *)piVar10;
          piVar10 = piVar1;
          if (uVar2 != 0) {
            piVar1 = (int *)(iVar7 + (uVar2 & 0xffff0fff) + *piVar3);
            *piVar1 = *piVar1 + iVar9;
          }
        }
      }
    }
  } while( true );
}



uint FUN_004298dd(int param_1,byte *param_2,undefined4 *param_3)

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
LAB_00429932:
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
    if (local_10 < 7) goto LAB_00429a4a;
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
        if (uVar9 != 0) goto LAB_00429aa3;
      }
      else {
        param_2 = param_2 + -(int)pbVar1;
        pbVar1 = pbVar2 + -(int)pbVar1;
        *puVar5 = uVar10 - (uVar10 >> 5);
        iVar4 = iVar4 * 2 + 1;
        if (uVar9 == 0) goto LAB_00429aa3;
      }
    } while (iVar4 < 0x100);
    goto LAB_00429aab;
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
        goto LAB_00429932;
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
LAB_00429dfd:
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
      goto LAB_00429dfd;
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
  goto LAB_00429932;
LAB_00429aa3:
  while (pbVar2 = pbVar1, iVar4 < 0x100) {
LAB_00429a4a:
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
LAB_00429aab:
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
  goto LAB_00429932;
}


