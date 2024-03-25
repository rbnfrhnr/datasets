typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    word;
typedef unsigned short    wchar16;
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

typedef int (*FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef int INT;

typedef struct HKEY__ *HKEY;

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

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_20 IMAGE_RESOURCE_DIR_STRING_U_20, *PIMAGE_RESOURCE_DIR_STRING_U_20;

struct IMAGE_RESOURCE_DIR_STRING_U_20 {
    word Length;
    wchar16 NameString[10];
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef LONG LSTATUS;

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
};




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0041de66) overlaps instruction at (ram,0x0041de65)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 __fastcall FUN_0041de65(int param_1,uint param_2,uint param_3)

{
  int *piVar1;
  undefined *puVar2;
  code *pcVar3;
  byte *pbVar4;
  undefined uVar5;
  char cVar6;
  char cVar7;
  byte bVar8;
  byte bVar13;
  undefined4 uVar9;
  undefined4 *puVar10;
  uint uVar11;
  undefined3 uVar14;
  uint in_EAX;
  uint uVar12;
  undefined unaff_BL;
  undefined4 *unaff_ESI;
  uint *unaff_EDI;
  undefined2 in_CS;
  bool bVar15;
  byte in_AF;
  bool bVar16;
  undefined2 in_FPUStatusWord;
  float10 fVar17;
  uint unaff_retaddr;
  undefined *puStack_20;
  undefined *puStack_1c;
  int *piStack_10;
  uint uStack_c;
  int iStack_8;
  undefined4 uStack_4;
  
  uVar12 = in_EAX & 0xc03482ec;
  bVar13 = (byte)(uVar12 >> 8);
  cVar7 = *(char *)(param_2 - 0xb) - bVar13;
  uStack_4 = CONCAT22(uStack_4._2_2_,in_CS);
  cVar6 = (char)uVar12;
  if ((POPCOUNT(cVar7) & 1U) == 0) {
    if (cVar7 < '\0') {
      out((short)param_2,cVar6);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    cVar7 = cVar6 * '\x02' + '\x01';
    uVar11 = CONCAT31((int3)(uVar12 >> 8),cVar7);
    _DAT_4fd84fc1 = uVar12;
    if (cVar7 != '\0' && (SCARRY1(cVar6,cVar6) != SCARRY1(cVar6 * '\x02','\x01')) == cVar7 < '\0') {
      piVar1 = (int *)(param_1 + 0x42 + uVar11 * 4);
      *piVar1 = *piVar1 + param_2;
      out(*unaff_ESI,(short)param_2);
      bVar15 = (byte)((uint)param_1 >> 8) < bVar13;
      unaff_ESI = unaff_ESI + 1;
      goto code_r0x0041de8b;
    }
  }
  else {
    bVar15 = false;
    bVar16 = cVar6 == -0x68;
    pcVar3 = (code *)swi(0xf);
    fVar17 = (float10)(*pcVar3)();
    if (!bVar15 && !bVar16) {
      LOCK();
      puVar2 = *(undefined **)(undefined4 *)(uStack_4 + 0x662cdcee);
      *(undefined4 *)(uStack_4 + 0x662cdcee) = puStack_20;
      UNLOCK();
      puStack_20 = puVar2;
    }
    puVar10 = (undefined4 *)(uStack_4 | 0x5e);
    uVar12 = iStack_8 - 1U | uStack_c;
    if (uVar12 == 0) {
      *(char *)(piStack_10 + 0x1a) = *(char *)(piStack_10 + 0x1a) << 7;
      *puStack_20 = *puStack_1c;
      bVar8 = DAT_2c159126;
      *(undefined2 *)(uStack_c + 0xe8aa363a) = in_FPUStatusWord;
      bVar13 = 9 < (bVar8 & 0xf) | in_AF;
      uVar12 = CONCAT31((int3)((uStack_4 | 0xede8467e) >> 8),bVar8 + bVar13 * '\x06') & 0xffffff0f;
      return CONCAT44(uStack_c,CONCAT22((short)(uVar12 >> 0x10),
                                        CONCAT11((char)((uStack_4 | 0xede8467e) >> 8) + bVar13,
                                                 (char)uVar12)));
    }
    unaff_EDI = puVar10 + 1;
    uVar9 = in((short)uStack_c);
    *puVar10 = uVar9;
    *(int *)((short)puStack_20 + 0xb) = (int)ROUND(fVar17);
    *(byte *)((int)puVar10 + -0x73) = *(byte *)((int)puVar10 + -0x73) & (byte)(uVar12 >> 8);
    if ((unaff_retaddr & 1) == 0 && (unaff_retaddr & 0x40) == 0) {
      pcVar3 = (code *)swi(200);
      uVar9 = (*pcVar3)();
      uVar12 = CONCAT22((short)((uint)uVar9 >> 0x10),
                        (ushort)(byte)((char)uVar9 + (char)((uint)uVar9 >> 8) * -0x1f)) + 0xd563fe69
      ;
      return CONCAT44((int)uVar12 >> 0x1f,
                      CONCAT22((short)(uVar12 >> 0x10),
                               CONCAT11(((uVar12 & 0x8000) != 0) << 7 |
                                        ((uVar12 & 0x4000) != 0) << 6 |
                                        ((uVar12 & 0x1000) != 0) << 4 | ((uVar12 & 0x400) != 0) << 2
                                        | 2U | (uVar12 & 0x100) != 0,(char)uVar12)));
    }
    in_AF = (param_3 & 0x10) != 0;
    puStack_1c[-0x79959393] = (char)puStack_1c[-0x79959393] >> 1;
    *piStack_10 = *piStack_10 << ((byte)uVar12 & 0x1f);
    uVar11 = 0x496f1c29;
    unaff_BL = SUB41(piStack_10,0);
    unaff_ESI = (undefined4 *)(puStack_1c + -1);
  }
  uVar14 = (undefined3)(uVar11 >> 8);
  uVar5 = in(0x73);
  uVar11 = CONCAT31(uVar14,uVar5);
  bVar15 = uVar11 < *unaff_EDI;
  if (-1 < (int)(uVar11 - *unaff_EDI)) {
    uVar5 = in(CONCAT11(0x60,unaff_BL));
    pbVar4 = (byte *)(CONCAT31(uVar14,uVar5) * 9);
    *pbVar4 = *pbVar4 ^ 0x38;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
code_r0x0041de8b:
  bVar13 = 9 < ((byte)uVar11 & 0xf) | in_AF;
  bVar8 = (byte)uVar11 + bVar13 * -6;
  _DAT_2e413bf4 =
       (_DAT_2e413bf4 - (int)unaff_ESI) - (uint)(byte)(0x9f < bVar8 | bVar15 | bVar13 * (bVar8 < 6))
  ;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Unable to track spacebase fully for stack

undefined8 __fastcall entry(undefined4 param_1,undefined4 param_2)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint unaff_ESI;
  uint *puVar9;
  byte *pbVar10;
  uint *puVar11;
  undefined8 uVar12;
  byte *apbStackY_ec4 [3];
  int iStackY_eb8;
  int *apiStackY_eb4 [2];
  uint uStackY_eac;
  uint *puStackY_ea8;
  undefined4 uStackY_ea4;
  undefined4 uStackY_ea0;
  uint auStackY_e9c [923];
  uint uStackY_30;
  int iStackY_2c;
  uint *puStackY_28;
  int iStackY_24;
  int iVar5;
  
  puVar9 = (uint *)((int)&DAT_004d0d1e + DAT_004d0d1e);
  iStackY_24 = (uint)*(ushort *)puVar9 * 0x1000;
  iVar2 = *(int *)((int)&DAT_004d0d1e + DAT_004d0d1e + 2);
  pbVar10 = (byte *)(DAT_004d0d1e + 0x4d0d24 + ((uint)*(ushort *)puVar9 * 0x1000 - iVar2));
  puStackY_28 = puVar9;
  iStackY_2c = iVar2;
  iVar5 = iVar2;
  do {
    iVar4 = iVar5 + -1;
    pbVar10[iVar4] = *(byte *)(iVar5 + 5 + (int)puVar9);
    iVar5 = iVar4;
  } while (iVar4 != 0);
  bVar1 = *pbVar10;
  uStackY_30 = (CONCAT21((short)(((bVar1 & 0xfffffff0) << 0xc) >> 0x10),bVar1) & 0xffff0f) << 8 |
               (uint)pbVar10[1];
  iVar5 = (-0x300 << (pbVar10[1] + (bVar1 & 0xf) & 0x1f)) * 2;
  *(uint *)((int)auStackY_e9c + iVar5) = uStackY_30;
  *(undefined4 *)((int)&uStackY_ea0 + iVar5) = 0;
  *(undefined4 *)((int)&uStackY_ea4 + iVar5) = 0;
  *(int *)((int)&puStackY_ea8 + iVar5) = (int)&uStackY_ea4 + iVar5;
  *(int *)((int)&uStackY_eac + iVar5) =
       CONCAT22((short)((uint)param_2 >> 0x10),*(ushort *)puVar9) << 0xc;
  *(uint **)((int)apiStackY_eb4 + iVar5 + 4) = puVar9;
  *(int *)((int)apiStackY_eb4 + iVar5) = (int)&uStackY_ea0 + iVar5;
  *(int *)((int)&iStackY_eb8 + iVar5) = iVar2;
  *(byte **)((int)apbStackY_ec4 + iVar5 + 8) = pbVar10 + 2;
  *(int *)((int)apbStackY_ec4 + iVar5 + 4) = (int)auStackY_e9c + iVar5;
  *(undefined4 *)((int)apbStackY_ec4 + iVar5) = 0x4d0233;
  FUN_004d0291(*(byte **)((int)apbStackY_ec4 + iVar5 + 4),*(byte **)((int)apbStackY_ec4 + iVar5 + 8)
               ,*(int *)((int)&iStackY_eb8 + iVar5),*(int **)((int)apiStackY_eb4 + iVar5),
               *(int *)((int)apiStackY_eb4 + iVar5 + 4),*(uint *)((int)&uStackY_eac + iVar5),
               *(uint **)((int)&puStackY_ea8 + iVar5));
  *(undefined4 *)(iStackY_24 + (int)puStackY_28) = 0;
  uVar8 = iStackY_24 - 0x1000;
  uVar7 = 0;
  puVar9 = puStackY_28;
LAB_004d0242:
  do {
    do {
      puVar11 = puVar9;
      uVar6 = uVar7;
      if (uVar8 <= uVar6) {
        entry = (code)0xe9;
        uRam004d01bf = 0xb56;
        iStackY_24 = 0x4d0286;
        uVar12 = thunk_FUN_0041de65(uVar6,uVar8,unaff_ESI);
        return uVar12;
      }
      uVar7 = uVar6 + 1;
      puVar9 = (uint *)((int)puVar11 + 1);
    } while ((*(byte *)puVar11 & 0xfe) != 0xe8);
    uVar7 = uVar6 + 5;
    puVar9 = (uint *)((int)puVar11 + 5);
    uVar3 = *(uint *)((int)puVar11 + 1);
    if ((int)uVar3 < 0) goto LAB_004d025f;
  } while (uVar8 <= uVar3);
  goto LAB_004d0265;
LAB_004d025f:
  iVar2 = uVar3 + uVar6 + 1;
  if (-1 < iVar2) {
    uVar3 = iVar2 + uVar8;
LAB_004d0265:
    *(uint *)((int)puVar11 + 1) = uVar3 - (uVar6 + 1);
  }
  goto LAB_004d0242;
}



undefined4 __cdecl
FUN_004d0291(byte *param_1,byte *param_2,int param_3,int *param_4,int param_5,uint param_6,
            uint *param_7)

{
  undefined2 *puVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  ushort uVar6;
  undefined2 *puVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  byte *pbVar13;
  byte *pbVar14;
  byte *pbVar15;
  ushort *puVar16;
  uint uVar17;
  byte *pbVar18;
  uint uVar19;
  uint local_8c;
  undefined2 *local_88;
  ushort *local_7c;
  uint local_70;
  int local_6c;
  int local_68;
  int local_64;
  int local_60;
  int local_5c;
  uint local_4c;
  uint local_44;
  uint local_3c;
  uint local_38;
  uint local_34;
  uint local_30;
  uint local_2c;
  byte local_19;
  uint local_18;
  
  local_18 = 0;
  local_19 = 0;
  puVar1 = (undefined2 *)(param_1 + 4);
  bVar2 = param_1[2];
  bVar3 = param_1[1];
  bVar4 = *param_1;
  *param_4 = 0;
  local_2c = 0;
  *param_7 = 0;
  local_30 = 1;
  local_34 = 1;
  local_38 = 1;
  local_3c = 1;
  puVar7 = puVar1;
  for (iVar11 = (0x300 << (param_1[1] + bVar4 & 0x1f)) + 0x736; iVar11 != 0; iVar11 = iVar11 + -1) {
    *puVar7 = 0x400;
    puVar7 = puVar7 + 1;
  }
  uVar19 = 0;
  local_44 = 0xffffffff;
  pbVar13 = param_2 + param_3;
  iVar11 = 0;
  pbVar15 = param_2;
  do {
    if (pbVar15 == pbVar13) {
      return 1;
    }
    bVar5 = *pbVar15;
    iVar11 = iVar11 + 1;
    pbVar15 = pbVar15 + 1;
    uVar19 = uVar19 << 8 | (uint)bVar5;
  } while (iVar11 < 5);
  if (param_6 != 0) {
LAB_004d038d:
    uVar12 = local_3c;
    uVar17 = local_18 & (1 << (bVar2 & 0x1f)) - 1U;
    puVar16 = puVar1 + local_2c * 0x10 + uVar17;
    if (local_44 < 0x1000000) {
      if (pbVar15 == pbVar13) {
        return 1;
      }
      local_44 = local_44 << 8;
      bVar5 = *pbVar15;
      pbVar15 = pbVar15 + 1;
      uVar19 = uVar19 << 8 | (uint)bVar5;
    }
    uVar6 = *puVar16;
    uVar8 = (local_44 >> 0xb) * (uint)uVar6;
    if (uVar19 < uVar8) {
      *puVar16 = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
      iVar9 = ((local_18 & (1 << (bVar3 & 0x1f)) - 1U) << (bVar4 & 0x1f)) +
              ((int)(uint)local_19 >> (8 - bVar4 & 0x1f));
      iVar11 = 1;
      local_44 = uVar8;
      if ((int)local_2c < 7) goto LAB_004d0508;
      local_4c = (uint)*(byte *)((local_18 - local_30) + param_5);
      do {
        local_4c = local_4c << 1;
        iVar10 = iVar11 * 2;
        uVar12 = local_4c & 0x100;
        if (local_44 < 0x1000000) {
          if (pbVar15 == pbVar13) {
            return 1;
          }
          local_44 = local_44 << 8;
          bVar5 = *pbVar15;
          pbVar15 = pbVar15 + 1;
          uVar19 = uVar19 << 8 | (uint)bVar5;
        }
        uVar6 = puVar1[iVar9 * 0x300 + uVar12 + iVar11 + 0x836];
        uVar17 = (local_44 >> 0xb) * (uint)uVar6;
        if (uVar19 < uVar17) {
          puVar1[iVar9 * 0x300 + uVar12 + iVar11 + 0x836] =
               (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
          local_44 = uVar17;
          if (uVar12 != 0) goto LAB_004d0500;
        }
        else {
          local_44 = local_44 - uVar17;
          uVar19 = uVar19 - uVar17;
          iVar10 = iVar10 + 1;
          puVar1[iVar9 * 0x300 + uVar12 + iVar11 + 0x836] = uVar6 - (uVar6 >> 5);
          if (uVar12 == 0) goto LAB_004d0500;
        }
        iVar11 = iVar10;
      } while (iVar10 < 0x100);
      goto LAB_004d0579;
    }
    uVar19 = uVar19 - uVar8;
    local_44 = local_44 - uVar8;
    *puVar16 = uVar6 - (uVar6 >> 5);
    if (local_44 < 0x1000000) {
      if (pbVar15 == pbVar13) {
        return 1;
      }
      bVar5 = *pbVar15;
      local_44 = local_44 * 0x100;
      pbVar15 = pbVar15 + 1;
      uVar19 = uVar19 * 0x100 | (uint)bVar5;
    }
    uVar6 = puVar1[local_2c + 0xc0];
    uVar8 = (local_44 >> 0xb) * (uint)uVar6;
    if (uVar19 < uVar8) {
      local_3c = local_38;
      puVar1[local_2c + 0xc0] = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
      local_38 = local_34;
      local_34 = local_30;
      local_7c = (ushort *)(param_1 + 0x668);
      local_2c = (uint)(6 < (int)local_2c) * 3;
LAB_004d08e4:
      if (uVar8 < 0x1000000) {
        if (pbVar15 == pbVar13) {
          return 1;
        }
        bVar5 = *pbVar15;
        uVar8 = uVar8 << 8;
        pbVar15 = pbVar15 + 1;
        uVar19 = uVar19 << 8 | (uint)bVar5;
      }
      uVar6 = *local_7c;
      local_44 = (uVar8 >> 0xb) * (uint)uVar6;
      if (uVar19 < local_44) {
        local_60 = 0;
        *local_7c = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
        iVar11 = uVar17 * 0x10 + 4;
LAB_004d09b5:
        local_7c = (ushort *)(iVar11 + (int)local_7c);
        local_5c = 3;
      }
      else {
        uVar8 = uVar8 - local_44;
        uVar19 = uVar19 - local_44;
        *local_7c = uVar6 - (uVar6 >> 5);
        if (uVar8 < 0x1000000) {
          if (pbVar15 == pbVar13) {
            return 1;
          }
          bVar5 = *pbVar15;
          uVar8 = uVar8 * 0x100;
          pbVar15 = pbVar15 + 1;
          uVar19 = uVar19 * 0x100 | (uint)bVar5;
        }
        uVar6 = local_7c[1];
        uVar12 = (uVar8 >> 0xb) * (uint)uVar6;
        if (uVar19 < uVar12) {
          local_60 = 8;
          local_7c[1] = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
          iVar11 = uVar17 * 0x10 + 0x104;
          local_44 = uVar12;
          goto LAB_004d09b5;
        }
        local_44 = uVar8 - uVar12;
        uVar19 = uVar19 - uVar12;
        local_60 = 0x10;
        local_5c = 8;
        local_7c[1] = uVar6 - (uVar6 >> 5);
        local_7c = local_7c + 0x102;
      }
      local_64 = local_5c;
      iVar11 = 1;
      do {
        iVar9 = iVar11 * 2;
        puVar16 = local_7c + iVar11;
        if (local_44 < 0x1000000) {
          if (pbVar15 == pbVar13) {
            return 1;
          }
          local_44 = local_44 << 8;
          bVar5 = *pbVar15;
          pbVar15 = pbVar15 + 1;
          uVar19 = uVar19 << 8 | (uint)bVar5;
        }
        uVar6 = *puVar16;
        uVar12 = (local_44 >> 0xb) * (uint)uVar6;
        if (uVar19 < uVar12) {
          *puVar16 = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
          local_44 = uVar12;
        }
        else {
          local_44 = local_44 - uVar12;
          uVar19 = uVar19 - uVar12;
          *puVar16 = uVar6 - (uVar6 >> 5);
          iVar9 = iVar9 + 1;
        }
        local_64 = local_64 + -1;
        iVar11 = iVar9;
      } while (local_64 != 0);
      local_60 = (iVar9 - (1 << (sbyte)local_5c)) + local_60;
      if (local_2c < 4) {
        local_2c = local_2c + 7;
        iVar11 = local_60;
        if (3 < local_60) {
          iVar11 = 3;
        }
        local_68 = 6;
        iVar9 = 1;
        do {
          iVar10 = iVar9 * 2;
          puVar16 = puVar1 + iVar11 * 0x40 + iVar9 + 0x1b0;
          if (local_44 < 0x1000000) {
            if (pbVar15 == pbVar13) {
              return 1;
            }
            local_44 = local_44 << 8;
            bVar5 = *pbVar15;
            pbVar15 = pbVar15 + 1;
            uVar19 = uVar19 << 8 | (uint)bVar5;
          }
          uVar6 = *puVar16;
          uVar12 = (local_44 >> 0xb) * (uint)uVar6;
          if (uVar19 < uVar12) {
            *puVar16 = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
            local_44 = uVar12;
          }
          else {
            local_44 = local_44 - uVar12;
            uVar19 = uVar19 - uVar12;
            iVar10 = iVar10 + 1;
            *puVar16 = uVar6 - (uVar6 >> 5);
          }
          local_68 = local_68 + -1;
          iVar9 = iVar10;
        } while (local_68 != 0);
        uVar12 = iVar10 - 0x40;
        local_8c = uVar12;
        if (3 < (int)uVar12) {
          local_6c = ((int)uVar12 >> 1) + -1;
          local_8c = uVar12 & 1 | 2;
          if ((int)uVar12 < 0xe) {
            local_8c = local_8c << ((byte)local_6c & 0x1f);
            local_88 = puVar1 + local_8c + (0x2af - uVar12);
          }
          else {
            iVar11 = ((int)uVar12 >> 1) + -5;
            do {
              if (local_44 < 0x1000000) {
                if (pbVar15 == pbVar13) {
                  return 1;
                }
                local_44 = local_44 << 8;
                bVar5 = *pbVar15;
                pbVar15 = pbVar15 + 1;
                uVar19 = uVar19 << 8 | (uint)bVar5;
              }
              local_44 = local_44 >> 1;
              local_8c = local_8c * 2;
              if (local_44 <= uVar19) {
                uVar19 = uVar19 - local_44;
                local_8c = local_8c | 1;
              }
              iVar11 = iVar11 + -1;
            } while (iVar11 != 0);
            local_8c = local_8c << 4;
            local_88 = (undefined2 *)(param_1 + 0x648);
            local_6c = 4;
          }
          local_70 = 1;
          iVar11 = 1;
          do {
            iVar9 = iVar11 * 2;
            puVar16 = local_88 + iVar11;
            if (local_44 < 0x1000000) {
              if (pbVar15 == pbVar13) {
                return 1;
              }
              local_44 = local_44 << 8;
              bVar5 = *pbVar15;
              pbVar15 = pbVar15 + 1;
              uVar19 = uVar19 << 8 | (uint)bVar5;
            }
            uVar6 = *puVar16;
            uVar12 = (local_44 >> 0xb) * (uint)uVar6;
            if (uVar19 < uVar12) {
              *puVar16 = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
              local_44 = uVar12;
            }
            else {
              local_44 = local_44 - uVar12;
              uVar19 = uVar19 - uVar12;
              *puVar16 = uVar6 - (uVar6 >> 5);
              iVar9 = iVar9 + 1;
              local_8c = local_8c | local_70;
            }
            local_70 = local_70 << 1;
            local_6c = local_6c + -1;
            iVar11 = iVar9;
          } while (local_6c != 0);
        }
        local_30 = local_8c + 1;
        if (local_30 == 0) goto LAB_004d0cd3;
      }
      local_60 = local_60 + 2;
      if (local_18 < local_30) {
        return 1;
      }
      pbVar14 = (byte *)(local_18 + param_5);
      pbVar18 = (byte *)(local_18 + (param_5 - local_30));
      while( true ) {
        local_19 = *pbVar18;
        pbVar18 = pbVar18 + 1;
        *pbVar14 = local_19;
        pbVar14 = pbVar14 + 1;
        local_18 = local_18 + 1;
        local_60 = local_60 + -1;
        if (local_60 == 0) break;
        if (param_6 <= local_18) goto LAB_004d0cd3;
      }
      goto LAB_004d0cc2;
    }
    uVar19 = uVar19 - uVar8;
    local_44 = local_44 - uVar8;
    puVar1[local_2c + 0xc0] = uVar6 - (uVar6 >> 5);
    if (local_44 < 0x1000000) {
      if (pbVar15 == pbVar13) {
        return 1;
      }
      bVar5 = *pbVar15;
      local_44 = local_44 * 0x100;
      pbVar15 = pbVar15 + 1;
      uVar19 = uVar19 * 0x100 | (uint)bVar5;
    }
    uVar6 = puVar1[local_2c + 0xcc];
    uVar8 = (local_44 >> 0xb) * (uint)uVar6;
    if (uVar8 <= uVar19) {
      local_44 = local_44 - uVar8;
      uVar19 = uVar19 - uVar8;
      puVar1[local_2c + 0xcc] = uVar6 - (uVar6 >> 5);
      if (local_44 < 0x1000000) {
        if (pbVar15 == pbVar13) {
          return 1;
        }
        bVar5 = *pbVar15;
        local_44 = local_44 * 0x100;
        pbVar15 = pbVar15 + 1;
        uVar19 = uVar19 * 0x100 | (uint)bVar5;
      }
      uVar6 = puVar1[local_2c + 0xd8];
      uVar8 = (local_44 >> 0xb) * (uint)uVar6;
      if (uVar19 < uVar8) {
        puVar1[local_2c + 0xd8] = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
        uVar12 = local_34;
      }
      else {
        uVar19 = uVar19 - uVar8;
        local_44 = local_44 - uVar8;
        puVar1[local_2c + 0xd8] = uVar6 - (uVar6 >> 5);
        if (local_44 < 0x1000000) {
          if (pbVar15 == pbVar13) {
            return 1;
          }
          bVar5 = *pbVar15;
          local_44 = local_44 * 0x100;
          pbVar15 = pbVar15 + 1;
          uVar19 = uVar19 * 0x100 | (uint)bVar5;
        }
        uVar6 = puVar1[local_2c + 0xe4];
        uVar8 = (local_44 >> 0xb) * (uint)uVar6;
        if (uVar19 < uVar8) {
          puVar1[local_2c + 0xe4] = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
          uVar12 = local_38;
        }
        else {
          uVar19 = uVar19 - uVar8;
          uVar8 = local_44 - uVar8;
          puVar1[local_2c + 0xe4] = uVar6 - (uVar6 >> 5);
          local_3c = local_38;
        }
        local_38 = local_34;
      }
      local_34 = local_30;
      local_30 = uVar12;
LAB_004d08c8:
      local_7c = (ushort *)(param_1 + 0xa6c);
      local_2c = (uint)(6 < (int)local_2c) * 3 + 8;
      goto LAB_004d08e4;
    }
    puVar1[local_2c + 0xcc] = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
    if (uVar8 < 0x1000000) {
      if (pbVar15 == pbVar13) {
        return 1;
      }
      bVar5 = *pbVar15;
      uVar8 = uVar8 * 0x100;
      pbVar15 = pbVar15 + 1;
      uVar19 = uVar19 << 8 | (uint)bVar5;
    }
    uVar6 = puVar1[local_2c * 0x10 + uVar17 + 0xf0];
    local_44 = (uVar8 >> 0xb) * (uint)uVar6;
    if (local_44 <= uVar19) {
      uVar8 = uVar8 - local_44;
      uVar19 = uVar19 - local_44;
      puVar1[local_2c * 0x10 + uVar17 + 0xf0] = uVar6 - (uVar6 >> 5);
      goto LAB_004d08c8;
    }
    puVar1[local_2c * 0x10 + uVar17 + 0xf0] = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
    if (local_18 == 0) {
      return 1;
    }
    local_2c = (uint)(6 < (int)local_2c) * 2 + 9;
    local_19 = *(byte *)((local_18 - local_30) + param_5);
    *(byte *)(param_5 + local_18) = local_19;
    local_18 = local_18 + 1;
    goto LAB_004d0cc2;
  }
  goto LAB_004d0cf2;
LAB_004d0500:
  while (iVar11 = iVar10, iVar10 < 0x100) {
LAB_004d0508:
    iVar10 = iVar11 * 2;
    puVar16 = puVar1 + iVar9 * 0x300 + iVar11 + 0x736;
    if (local_44 < 0x1000000) {
      if (pbVar15 == pbVar13) {
        return 1;
      }
      local_44 = local_44 << 8;
      bVar5 = *pbVar15;
      pbVar15 = pbVar15 + 1;
      uVar19 = uVar19 << 8 | (uint)bVar5;
    }
    uVar6 = *puVar16;
    uVar12 = (local_44 >> 0xb) * (uint)uVar6;
    if (uVar19 < uVar12) {
      *puVar16 = (short)((int)(0x800 - (uint)uVar6) >> 5) + uVar6;
      local_44 = uVar12;
    }
    else {
      uVar19 = uVar19 - uVar12;
      iVar10 = iVar10 + 1;
      *puVar16 = uVar6 - (uVar6 >> 5);
      local_44 = local_44 - uVar12;
    }
  }
LAB_004d0579:
  local_19 = (byte)iVar10;
  *(byte *)(param_5 + local_18) = local_19;
  local_18 = local_18 + 1;
  if ((int)local_2c < 4) {
    local_2c = 0;
  }
  else if ((int)local_2c < 10) {
    local_2c = local_2c - 3;
  }
  else {
    local_2c = local_2c - 6;
  }
LAB_004d0cc2:
  if (param_6 <= local_18) goto LAB_004d0cd3;
  goto LAB_004d038d;
LAB_004d0cd3:
  if (local_44 < 0x1000000) {
    if (pbVar15 == pbVar13) {
      return 1;
    }
    pbVar15 = pbVar15 + 1;
  }
LAB_004d0cf2:
  *param_4 = (int)pbVar15 - (int)param_2;
  *param_7 = local_18;
  return 0;
}



undefined8 __fastcall thunk_FUN_0041de65(int param_1,uint param_2,uint param_3)

{
  undefined8 uVar1;
  
  uVar1 = FUN_0041de65(param_1,param_2,param_3);
  return uVar1;
}


