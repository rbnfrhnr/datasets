typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
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

typedef struct tagPAINTSTRUCT tagPAINTSTRUCT, *PtagPAINTSTRUCT;

typedef struct tagPAINTSTRUCT PAINTSTRUCT;

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

typedef int BOOL;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

typedef uchar BYTE;

typedef long LONG;

struct HDC__ {
    int unused;
};

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

struct tagPAINTSTRUCT {
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    BYTE rgbReserved[32];
};

typedef ulong DWORD;

typedef int (*FARPROC)(void);

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef int INT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef struct HKEY__ *HKEY;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef uint UINT;

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




// WARNING: Instruction at (ram,0x0042cec4) overlaps instruction at (ram,0x0042cec3)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Heritage AFTER dead removal. Example location: s0xffffffdc : 0x0042ce5b
// WARNING: Restarted to delay deadcode elimination for space: stack

void entry(void)

{
  char cVar1;
  char cVar2;
  byte bVar3;
  ushort uVar4;
  code *pcVar5;
  ushort *puVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  undefined4 uVar11;
  int iVar12;
  byte *pbVar13;
  byte *pbVar14;
  int *piVar15;
  uint *puVar16;
  undefined *puVar18;
  undefined4 *puVar20;
  undefined4 *puVar21;
  undefined4 *puVar22;
  undefined *puVar23;
  byte *pbVar25;
  uint uVar26;
  int *piVar27;
  int *piVar28;
  int *piVar29;
  uint local_3ea4;
  byte *local_3ea0;
  undefined4 local_3e9c;
  ushort local_3e98 [192];
  ushort auStack_3d18 [12];
  ushort auStack_3d00 [12];
  ushort auStack_3ce8 [12];
  ushort auStack_3cd0 [12];
  ushort auStack_3cb8 [192];
  ushort auStack_3b38 [370];
  ushort auStack_3854 [16];
  ushort local_3834 [514];
  ushort auStack_3430 [514];
  ushort auStack_302c [6002];
  undefined local_148 [116];
  uint local_d4;
  ushort *local_d0;
  ushort *local_cc;
  int local_c8;
  ushort *local_c4;
  ushort *local_c0;
  int local_bc;
  uint local_b8;
  int local_b4;
  int local_b0;
  int local_ac;
  int local_a8;
  int local_a4;
  int local_a0;
  ushort *local_9c;
  uint local_98;
  uint local_94;
  undefined4 local_90;
  uint local_8c;
  undefined *local_88;
  uint local_84;
  uint local_80;
  uint local_7c;
  uint local_78;
  uint local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  byte local_61;
  uint local_60;
  ushort *local_5c;
  undefined4 *puStack_58;
  undefined1 *puStack_54;
  undefined1 *puStack_50;
  uint *puStack_4c;
  undefined4 uStack_48;
  undefined4 *local_44;
  byte *local_40;
  undefined4 local_3c;
  byte **local_38;
  undefined1 *local_34;
  undefined4 local_30;
  uint *local_2c;
  uint local_28 [2];
  undefined *puVar17;
  undefined4 *puVar19;
  undefined *puVar24;
  
  puStack_4c = local_28 + 1;
  local_2c = &local_3ea4;
  do {
    local_28[1] = 0;
  } while (local_28 + 1 != local_2c);
  local_30 = 0x2a88f;
  local_34 = &DAT_00401000;
  local_38 = &local_3ea0;
  local_3c = 0xa37d;
  local_40 = &DAT_00422002;
  puStack_58 = &local_3e9c;
  uStack_48 = 0;
  local_3e9c = 3;
  puStack_50 = &DAT_00401000;
  puStack_54 = &DAT_00422002;
  local_60 = 0;
  local_61 = 0;
  local_5c = local_3e98;
  local_68 = 0;
  local_6c = 0;
  local_70 = 3;
  local_3ea0 = (byte *)0x0;
  local_74 = 0;
  local_3ea4 = 0;
  local_78 = 1;
  local_7c = 1;
  local_80 = 1;
  local_84 = 1;
  iVar12 = 0x1f36;
  puVar6 = local_5c;
  do {
    *puVar6 = 0x400;
    puVar6 = puVar6 + 1;
    iVar12 = iVar12 + -1;
  } while (iVar12 != 0);
  uVar26 = 0;
  local_8c = 0xffffffff;
  local_88 = &DAT_0042c37f;
  iVar12 = 0;
  pbVar14 = local_40;
  do {
    if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
    bVar3 = *pbVar14;
    iVar12 = iVar12 + 1;
    pbVar14 = pbVar14 + 1;
    uVar26 = uVar26 << 8 | (uint)bVar3;
  } while (iVar12 < 5);
LAB_0042c4b7:
  uVar8 = local_84;
  local_90 = 0;
  puVar6 = local_5c + local_74 * 0x10;
  if (local_8c < 0x1000000) {
    if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
    local_8c = local_8c << 8;
    bVar3 = *pbVar14;
    pbVar14 = pbVar14 + 1;
    uVar26 = uVar26 << 8 | (uint)bVar3;
  }
  uVar4 = *puVar6;
  uVar7 = (local_8c >> 0xb) * (uint)uVar4;
  if (uVar26 < uVar7) {
    *puVar6 = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
    local_c0 = auStack_302c + ((int)(uint)local_61 >> 5) * 0x300;
    iVar12 = 1;
    local_8c = uVar7;
    if ((int)local_74 < 7) goto LAB_0042c632;
    local_94 = (uint)(byte)(&DAT_00401000)[local_60 - local_78];
    do {
      local_94 = local_94 << 1;
      iVar10 = iVar12 * 2;
      local_98 = local_94 & 0x100;
      if (local_8c < 0x1000000) {
        if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
        local_8c = local_8c << 8;
        bVar3 = *pbVar14;
        pbVar14 = pbVar14 + 1;
        uVar26 = uVar26 << 8 | (uint)bVar3;
      }
      uVar4 = local_c0[local_98 + iVar12 + 0x100];
      uVar8 = (local_8c >> 0xb) * (uint)uVar4;
      if (uVar26 < uVar8) {
        local_c0[local_98 + iVar12 + 0x100] = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
        local_8c = uVar8;
        if (local_98 != 0) goto LAB_0042c62a;
      }
      else {
        local_8c = local_8c - uVar8;
        uVar26 = uVar26 - uVar8;
        iVar10 = iVar10 + 1;
        local_c0[local_98 + iVar12 + 0x100] = uVar4 - (uVar4 >> 5);
        if (local_98 == 0) goto LAB_0042c62a;
      }
      iVar12 = iVar10;
    } while (iVar10 < 0x100);
    goto LAB_0042c6a3;
  }
  uVar26 = uVar26 - uVar7;
  uVar7 = local_8c - uVar7;
  *puVar6 = uVar4 - (uVar4 >> 5);
  local_9c = local_5c + local_74;
  if (uVar7 < 0x1000000) {
    if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
    bVar3 = *pbVar14;
    uVar7 = uVar7 * 0x100;
    pbVar14 = pbVar14 + 1;
    uVar26 = uVar26 * 0x100 | (uint)bVar3;
  }
  uVar4 = auStack_3d18[local_74];
  uVar9 = (uVar7 >> 0xb) * (uint)uVar4;
  if (uVar26 < uVar9) {
    local_84 = local_80;
    auStack_3d18[local_74] = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
    local_80 = local_7c;
    local_7c = local_78;
    puVar6 = local_3834;
    local_74 = (uint)(6 < (int)local_74) * 3;
LAB_0042ca0e:
    if (uVar9 < 0x1000000) {
      if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
      bVar3 = *pbVar14;
      uVar9 = uVar9 << 8;
      pbVar14 = pbVar14 + 1;
      uVar26 = uVar26 << 8 | (uint)bVar3;
    }
    uVar4 = *puVar6;
    uVar8 = (uVar9 >> 0xb) * (uint)uVar4;
    if (uVar26 < uVar8) {
      local_a8 = 0;
      *puVar6 = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
      local_c4 = puVar6 + 2;
      local_8c = uVar8;
LAB_0042cadf:
      local_a4 = 3;
    }
    else {
      uVar9 = uVar9 - uVar8;
      uVar26 = uVar26 - uVar8;
      *puVar6 = uVar4 - (uVar4 >> 5);
      if (uVar9 < 0x1000000) {
        if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
        bVar3 = *pbVar14;
        uVar9 = uVar9 * 0x100;
        pbVar14 = pbVar14 + 1;
        uVar26 = uVar26 * 0x100 | (uint)bVar3;
      }
      uVar4 = puVar6[1];
      uVar8 = (uVar9 >> 0xb) * (uint)uVar4;
      if (uVar26 < uVar8) {
        local_a8 = 8;
        puVar6[1] = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
        local_c4 = puVar6 + 0x82;
        local_8c = uVar8;
        goto LAB_0042cadf;
      }
      local_8c = uVar9 - uVar8;
      uVar26 = uVar26 - uVar8;
      local_a8 = 0x10;
      local_a4 = 8;
      puVar6[1] = uVar4 - (uVar4 >> 5);
      local_c4 = puVar6 + 0x102;
    }
    local_90 = 0;
    local_ac = local_a4;
    iVar12 = 1;
    do {
      iVar10 = iVar12 * 2;
      puVar6 = local_c4 + iVar12;
      if (local_8c < 0x1000000) {
        if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
        local_8c = local_8c << 8;
        bVar3 = *pbVar14;
        pbVar14 = pbVar14 + 1;
        uVar26 = uVar26 << 8 | (uint)bVar3;
      }
      uVar4 = *puVar6;
      uVar8 = (local_8c >> 0xb) * (uint)uVar4;
      if (uVar26 < uVar8) {
        *puVar6 = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
        local_8c = uVar8;
      }
      else {
        local_8c = local_8c - uVar8;
        uVar26 = uVar26 - uVar8;
        *puVar6 = uVar4 - (uVar4 >> 5);
        iVar10 = iVar10 + 1;
      }
      local_ac = local_ac + -1;
      iVar12 = iVar10;
    } while (local_ac != 0);
    local_c8 = (iVar10 - (1 << (sbyte)local_a4)) + local_a8;
    if (local_74 < 4) {
      local_74 = local_74 + 7;
      iVar12 = local_c8;
      if (3 < local_c8) {
        iVar12 = 3;
      }
      local_b0 = 6;
      local_cc = auStack_3b38 + iVar12 * 0x40;
      iVar12 = 1;
      do {
        iVar10 = iVar12 * 2;
        puVar6 = local_cc + iVar12;
        if (local_8c < 0x1000000) {
          if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
          local_8c = local_8c << 8;
          bVar3 = *pbVar14;
          pbVar14 = pbVar14 + 1;
          uVar26 = uVar26 << 8 | (uint)bVar3;
        }
        uVar4 = *puVar6;
        uVar8 = (local_8c >> 0xb) * (uint)uVar4;
        if (uVar26 < uVar8) {
          *puVar6 = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
          local_8c = uVar8;
        }
        else {
          local_8c = local_8c - uVar8;
          uVar26 = uVar26 - uVar8;
          iVar10 = iVar10 + 1;
          *puVar6 = uVar4 - (uVar4 >> 5);
        }
        local_b0 = local_b0 + -1;
        iVar12 = iVar10;
      } while (local_b0 != 0);
      uVar8 = iVar10 - 0x40;
      local_d4 = uVar8;
      if (3 < (int)uVar8) {
        local_b4 = ((int)uVar8 >> 1) + -1;
        uVar7 = uVar8 & 1 | 2;
        if ((int)uVar8 < 0xe) {
          local_d4 = uVar7 << ((byte)local_b4 & 0x1f);
          local_d0 = local_5c + local_d4 + (0x2af - uVar8);
        }
        else {
          iVar12 = ((int)uVar8 >> 1) + -5;
          do {
            if (local_8c < 0x1000000) {
              if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
              local_8c = local_8c << 8;
              bVar3 = *pbVar14;
              pbVar14 = pbVar14 + 1;
              uVar26 = uVar26 << 8 | (uint)bVar3;
            }
            local_8c = local_8c >> 1;
            uVar7 = uVar7 * 2;
            if (local_8c <= uVar26) {
              uVar26 = uVar26 - local_8c;
              uVar7 = uVar7 | 1;
            }
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
          local_d4 = uVar7 << 4;
          local_d0 = auStack_3854;
          local_b4 = 4;
        }
        local_b8 = 1;
        iVar12 = 1;
        do {
          local_bc = iVar12 * 2;
          puVar6 = local_d0 + iVar12;
          if (local_8c < 0x1000000) {
            if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
            local_8c = local_8c << 8;
            bVar3 = *pbVar14;
            pbVar14 = pbVar14 + 1;
            uVar26 = uVar26 << 8 | (uint)bVar3;
          }
          uVar4 = *puVar6;
          uVar8 = (local_8c >> 0xb) * (uint)uVar4;
          if (uVar26 < uVar8) {
            *puVar6 = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
            iVar12 = local_bc;
            local_8c = uVar8;
          }
          else {
            local_8c = local_8c - uVar8;
            uVar26 = uVar26 - uVar8;
            *puVar6 = uVar4 - (uVar4 >> 5);
            iVar12 = local_bc + 1;
            local_d4 = local_d4 | local_b8;
          }
          local_b8 = local_b8 << 1;
          local_b4 = local_b4 + -1;
        } while (local_b4 != 0);
      }
      local_78 = local_d4 + 1;
      if (local_78 == 0) goto LAB_0042cdfc;
    }
    iVar12 = local_c8 + 2;
    if (local_78 <= local_60) {
      pbVar13 = &DAT_00401000 + local_60;
      pbVar25 = &DAT_00401000 + (local_60 - local_78);
      while( true ) {
        local_61 = *pbVar25;
        pbVar25 = pbVar25 + 1;
        *pbVar13 = local_61;
        pbVar13 = pbVar13 + 1;
        local_60 = local_60 + 1;
        iVar12 = iVar12 + -1;
        if (iVar12 == 0) break;
        if (0x2a88e < local_60) goto LAB_0042cdfc;
      }
      goto LAB_0042cdeb;
    }
    goto LAB_0042ce3a;
  }
  uVar26 = uVar26 - uVar9;
  uVar7 = uVar7 - uVar9;
  auStack_3d18[local_74] = uVar4 - (uVar4 >> 5);
  if (uVar7 < 0x1000000) {
    if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
    bVar3 = *pbVar14;
    uVar7 = uVar7 * 0x100;
    pbVar14 = pbVar14 + 1;
    uVar26 = uVar26 * 0x100 | (uint)bVar3;
  }
  uVar4 = auStack_3d00[local_74];
  uVar9 = (uVar7 >> 0xb) * (uint)uVar4;
  if (uVar9 <= uVar26) {
    uVar7 = uVar7 - uVar9;
    uVar26 = uVar26 - uVar9;
    auStack_3d00[local_74] = uVar4 - (uVar4 >> 5);
    if (uVar7 < 0x1000000) {
      if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
      bVar3 = *pbVar14;
      uVar7 = uVar7 * 0x100;
      pbVar14 = pbVar14 + 1;
      uVar26 = uVar26 * 0x100 | (uint)bVar3;
    }
    uVar4 = auStack_3ce8[local_74];
    uVar9 = (uVar7 >> 0xb) * (uint)uVar4;
    if (uVar26 < uVar9) {
      auStack_3ce8[local_74] = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
      uVar8 = local_7c;
    }
    else {
      uVar26 = uVar26 - uVar9;
      uVar7 = uVar7 - uVar9;
      auStack_3ce8[local_74] = uVar4 - (uVar4 >> 5);
      if (uVar7 < 0x1000000) {
        if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
        bVar3 = *pbVar14;
        uVar7 = uVar7 * 0x100;
        pbVar14 = pbVar14 + 1;
        uVar26 = uVar26 * 0x100 | (uint)bVar3;
      }
      uVar4 = auStack_3cd0[local_74];
      uVar9 = (uVar7 >> 0xb) * (uint)uVar4;
      if (uVar26 < uVar9) {
        auStack_3cd0[local_74] = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
        uVar8 = local_80;
      }
      else {
        uVar26 = uVar26 - uVar9;
        uVar9 = uVar7 - uVar9;
        auStack_3cd0[local_74] = uVar4 - (uVar4 >> 5);
        local_84 = local_80;
      }
      local_80 = local_7c;
    }
    local_7c = local_78;
    local_78 = uVar8;
LAB_0042c9f2:
    puVar6 = auStack_3430;
    local_74 = (uint)(6 < (int)local_74) * 3 + 8;
    goto LAB_0042ca0e;
  }
  local_a0 = 0x800;
  auStack_3d00[local_74] = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
  if (uVar9 < 0x1000000) {
    if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
    bVar3 = *pbVar14;
    uVar9 = uVar9 * 0x100;
    pbVar14 = pbVar14 + 1;
    uVar26 = uVar26 << 8 | (uint)bVar3;
  }
  uVar4 = auStack_3cb8[local_74 * 0x10];
  uVar8 = (uVar9 >> 0xb) * (uint)uVar4;
  if (uVar8 <= uVar26) {
    uVar9 = uVar9 - uVar8;
    uVar26 = uVar26 - uVar8;
    auStack_3cb8[local_74 * 0x10] = uVar4 - (uVar4 >> 5);
    goto LAB_0042c9f2;
  }
  local_a0 = (int)(0x800 - (uint)uVar4) >> 5;
  auStack_3cb8[local_74 * 0x10] = uVar4 + (short)local_a0;
  local_8c = uVar8;
  if (local_60 == 0) goto LAB_0042ce3a;
  local_74 = (uint)(6 < (int)local_74) * 2 + 9;
  local_61 = (&DAT_00401000)[local_60 - local_78];
  (&DAT_00401000)[local_60] = local_61;
  local_60 = local_60 + 1;
LAB_0042cdeb:
  if (0x2a88e < local_60) goto LAB_0042cdfc;
  goto LAB_0042c4b7;
LAB_0042c62a:
  iVar12 = iVar10;
  if (iVar10 < 0x100) {
LAB_0042c632:
    iVar10 = iVar12 * 2;
    puVar6 = local_c0 + iVar12;
    if (local_8c < 0x1000000) {
      if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
      local_8c = local_8c << 8;
      bVar3 = *pbVar14;
      pbVar14 = pbVar14 + 1;
      uVar26 = uVar26 << 8 | (uint)bVar3;
    }
    uVar4 = *puVar6;
    uVar8 = (local_8c >> 0xb) * (uint)uVar4;
    if (uVar26 < uVar8) {
      *puVar6 = uVar4 + (short)((int)(0x800 - (uint)uVar4) >> 5);
      local_8c = uVar8;
    }
    else {
      uVar26 = uVar26 - uVar8;
      iVar10 = iVar10 + 1;
      *puVar6 = uVar4 - (uVar4 >> 5);
      local_8c = local_8c - uVar8;
    }
    goto LAB_0042c62a;
  }
LAB_0042c6a3:
  local_61 = (byte)iVar10;
  (&DAT_00401000)[local_60] = local_61;
  local_60 = local_60 + 1;
  if ((int)local_74 < 4) {
    local_74 = 0;
  }
  else if ((int)local_74 < 10) {
    local_74 = local_74 - 3;
  }
  else {
    local_74 = local_74 - 6;
  }
  goto LAB_0042cdeb;
LAB_0042cdfc:
  local_90 = 0;
  if (local_8c < 0x1000000) {
    if (pbVar14 == &DAT_0042c37f) goto LAB_0042ce3a;
    pbVar14 = pbVar14 + 1;
  }
  local_3ea0 = pbVar14 + -0x422002;
  local_3ea4 = local_60;
LAB_0042ce3a:
  puVar16 = local_28 + 1;
  do {
    puVar17 = (undefined *)((int)puVar16 + -4);
    *(undefined4 *)((int)puVar16 + -4) = 0;
    puVar16 = (uint *)((int)puVar16 + -4);
  } while (puVar17 != local_148);
  piVar27 = (int *)0x0;
  puVar18 = &stack0xffffffe0;
  iVar12 = 0x6b7;
  do {
    cVar2 = *(char *)piVar27;
    piVar27 = (int *)((int)piVar27 + 1);
    while (((byte)(cVar2 + 0x18U) < 2 && (*(char *)piVar27 == '\x05'))) {
      iVar10 = *piVar27;
      cVar2 = *(char *)(piVar27 + 1);
      *piVar27 = CONCAT31(CONCAT21((ushort)iVar10 >> 8,(char)((uint)iVar10 >> 0x10)),
                          (char)((uint)iVar10 >> 0x18)) - (int)piVar27;
      piVar27 = (int *)((int)piVar27 + 5);
      iVar12 = iVar12 + -1;
      if (iVar12 == 0) {
        piVar27 = (int *)0x2a000;
        local_44 = puStack_58;
        do {
          pcVar5 = pcRam00037eb8;
          if (*piVar27 == 0) {
            *(undefined4 *)(puVar18 + -4) = 0;
            *(undefined **)(puVar18 + -8) = puVar18 + -4;
            *(undefined4 *)(puVar18 + -0xc) = 4;
            *(undefined4 *)(puVar18 + -0x10) = 0x1000;
            *(undefined4 *)(puVar18 + -0x14) = 0xfffff000;
            puVar21 = (undefined4 *)(puVar18 + -0x18);
            *(undefined4 *)(puVar18 + -0x18) = 0x42cef9;
            (*pcRam00037eb8)();
            bRamfffff207 = bRamfffff207 & 0x7f;
            bRamfffff22f = bRamfffff22f & 0x7f;
            uVar11 = *puVar21;
            *puVar21 = uVar11;
            puVar21[-1] = puVar21;
            puVar21[-2] = uVar11;
            puVar21[-3] = 0x1000;
            puVar21[-4] = 0xfffff000;
            puVar22 = puVar21 + -5;
            puVar21[-5] = 0x42cf0e;
            (*pcVar5)();
            puVar23 = (undefined *)((int)puVar22 + 0x24);
            do {
              puVar24 = puVar23 + -4;
              *(undefined4 *)(puVar23 + -4) = 0;
              puVar23 = puVar23 + -4;
            } while (puVar24 != (undefined *)((int)puVar22 + -0x5c));
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          piVar15 = (int *)piVar27[1];
          *(int *)(puVar18 + -4) = *piVar27 + 0x37e24;
          piVar29 = piVar27 + 2;
          puVar19 = (undefined4 *)(puVar18 + -8);
          puVar18 = puVar18 + -8;
          *puVar19 = 0x42ceb1;
          uVar11 = (*pcRam00037eb0)();
          while( true ) {
            cVar2 = *(char *)piVar29;
            piVar27 = (int *)((int)piVar29 + 1);
            if (cVar2 == '\0') break;
            if (cVar2 < '\0') {
              *(uint *)(puVar18 + -4) = (uint)*(ushort *)piVar27;
              piVar29 = (int *)((int)piVar29 + 3);
            }
            else {
              *(int **)(puVar18 + -4) = piVar27;
              piVar28 = piVar27;
              do {
                piVar29 = piVar28;
                if (piVar27 == (int *)0x0) break;
                piVar27 = (int *)((int)piVar27 + -1);
                piVar29 = (int *)((int)piVar28 + 1);
                cVar1 = *(char *)piVar28;
                piVar28 = piVar29;
              } while ((char)(cVar2 + -1) != cVar1);
            }
            *(undefined4 *)(puVar18 + -8) = uVar11;
            puVar20 = (undefined4 *)(puVar18 + -0xc);
            puVar18 = puVar18 + -0xc;
            *puVar20 = 0x42cecf;
            iVar12 = (*pcRam00037eb4)();
            if (iVar12 == 0) {
              *(undefined4 *)(puVar18 + -4) = 0x42cee0;
              (*pcRam00037ec4)();
              return;
            }
            *piVar15 = iVar12;
            piVar15 = piVar15 + 1;
          }
        } while( true );
      }
    }
  } while( true );
}


