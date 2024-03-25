typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned long    ulong;
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

typedef int (*FARPROC)(void);

typedef int BOOL;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPVOID;

typedef ulong DWORD;

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




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0040c593) overlaps instruction at (ram,0x0040c590)
// 
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall entry(char *param_1,int param_2,char *param_3,undefined8 param_4)

{
  byte *pbVar1;
  code **ppcVar2;
  ushort *puVar3;
  int iVar4;
  int **ppiVar5;
  undefined4 uVar6;
  undefined *puVar7;
  undefined uVar8;
  byte bVar12;
  int *piVar9;
  undefined *puVar10;
  undefined3 uVar13;
  char **ppcVar11;
  char cVar16;
  char *pcVar14;
  char *pcVar15;
  int iVar17;
  byte bVar18;
  byte bVar21;
  char *unaff_EBX;
  char *pcVar19;
  code **ppcVar20;
  char **unaff_EBP;
  char **ppcVar22;
  undefined4 *unaff_ESI;
  undefined4 *puVar23;
  undefined4 *puVar24;
  undefined *puVar25;
  undefined4 *unaff_EDI;
  undefined4 *puVar26;
  int **ppiVar27;
  undefined2 in_ES;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  bool bVar28;
  byte in_NT;
  ushort uVar29;
  float10 in_ST0;
  uint uVar30;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  do {
    puVar26 = unaff_EDI;
    ppcVar11 = unaff_EBP;
    ExceptionList = &uStack_8;
    piVar9 = (int *)0x0;
    uVar30 = 0;
    unaff_EBP = (char **)((int)ppcVar11 + 1);
    bVar28 = SCARRY4((int)unaff_EBX,1);
    unaff_EBX = unaff_EBX + 1;
    puVar24 = unaff_ESI + 1;
    out(*unaff_ESI,(short)param_2);
    unaff_EDI = puVar26 + 1;
    uVar6 = in((short)param_2);
    pcRam00000000 = param_1;
    *puVar26 = uVar6;
    cVar16 = (char)param_1;
    if (bVar28) goto LAB_0040c60a;
    puVar3 = (ushort *)(param_2 + (int)puVar24);
    uVar29 = *puVar3;
    *puVar3 = *puVar3;
    unaff_ESI = puVar24;
  } while ((short)(((ushort)puVar24 & 3) - (uVar29 & 3)) < 1);
  do {
    puVar23 = puVar24;
    param_1[0x42aae015] = param_1[0x42aae015] + cVar16;
    *(char *)((int)puVar26 + 0x465adc6b) = *(char *)((int)puVar26 + 0x465adc6b) + (char)unaff_EBX;
    param_1[0x42aae835] = param_1[0x42aae835] + cVar16;
    *(char *)((int)puVar26 + 0x465ad44b) = *(char *)((int)puVar26 + 0x465ad44b) + (char)unaff_EBX;
    *(char *)((int)puVar23 + -0x73) = *(char *)((int)puVar23 + -0x73) + (char)((uint)piVar9 >> 8);
    puVar10 = (undefined *)((int)piVar9 - *piVar9);
    *(char *)((int)puVar23 + -0x550bf273) = *(char *)((int)puVar23 + -0x550bf273) + (char)param_3;
    pbVar1 = (byte *)(uVar30 - 10);
    bVar18 = *pbVar1;
    bVar12 = (byte)((uint)param_3 >> 8);
    *pbVar1 = *pbVar1 + bVar12;
    puVar25 = (undefined *)(uint)CARRY1(bVar18,bVar12);
    puVar7 = puVar10 + -0x426ed0;
    bVar28 = SBORROW4((int)puVar10,0x426ed0) != SBORROW4((int)puVar7,(int)puVar25);
    piVar9 = (int *)(puVar7 + -(int)puVar25);
    uVar29 = (ushort)(in_NT & 1) * 0x4000 | (ushort)bVar28 * 0x800 | (ushort)(in_IF & 1) * 0x200 |
             (ushort)(in_TF & 1) * 0x100 | (ushort)((int)piVar9 < 0) * 0x80 |
             (ushort)(piVar9 == (int *)0x0) * 0x40 | (ushort)(in_AF & 1) * 0x10 |
             (ushort)((POPCOUNT((uint)piVar9 & 0xff) & 1U) == 0) * 4 |
             (ushort)(puVar10 < &DAT_00426ed0 || puVar7 < puVar25);
    uVar30 = (uint)uVar29;
    unaff_EBX = param_3;
    puVar24 = (undefined4 *)((int)puVar23 + 1);
  } while (piVar9 != (int *)0x0 && bVar28 == (int)piVar9 < 0);
  *(char *)((int)puVar23 + -0x72) = *(char *)((int)puVar23 + -0x72) + (char)((uint)piVar9 >> 8);
  *(char *)((int)puVar23 + -0x553bd272) =
       *(char *)((int)puVar23 + -0x553bd272) + (char)((ulonglong)param_4 >> 0x10);
  param_1[(int)(undefined *)((int)puVar23 + 2) * 8 + 0x426ef805] =
       param_1[(int)(undefined *)((int)puVar23 + 2) * 8 + 0x426ef805] + (char)((uint)param_1 >> 8);
  param_4._2_4_[-0x135cffa5] = param_4._2_4_[-0x135cffa5] + cVar16;
  out(*(undefined *)((int)puVar23 + 2),uVar29 + 2);
  param_4._2_4_[-0xf5c83a5] = param_4._2_4_[-0xf5c83a5] + cVar16;
  puVar24 = puVar23 + 1;
  out(*(undefined *)((int)puVar23 + 3),uVar29 + 3);
  param_2 = uVar30 + 4;
  unaff_EBX = param_4._2_4_;
LAB_0040c60a:
  ppcVar11 = ppcVar11 + -0xd721e9;
  *(char *)ppcVar11 = *(char *)ppcVar11 + cVar16;
  out(*(undefined *)puVar24,(short)param_2);
  unaff_EBX[-0x2df65] = unaff_EBX[-0x2df65] + cVar16;
  *piVar9 = *piVar9 + (int)unaff_EDI;
  uStack_4 = CONCAT22(0x43,in_ES);
  cVar16 = (char)piVar9;
  *param_1 = *param_1 + cVar16;
  *unaff_EBX = *unaff_EBX + cVar16;
  pbVar1 = (byte *)(param_1 + 0x42aaf0);
  bVar18 = *pbVar1;
  bVar12 = (byte)((uint)piVar9 >> 8);
  *pbVar1 = *pbVar1 + bVar12;
  *unaff_EDI = *(undefined4 *)((int)puVar24 + 1);
  uVar13 = (undefined3)((uint)piVar9 >> 8);
  bVar21 = (byte)((uint)unaff_EBX >> 8);
  *param_1 = *param_1 + bVar21;
  pcVar14 = param_1 + -1;
  if (pcVar14 != (char *)0x0 && *param_1 != '\0') {
    _DAT_f56bff8c = (longlong)ROUND(in_ST0);
    uVar8 = in((short)param_2 + 2);
    _DAT_00426304 = CONCAT31(uVar13,uVar8);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *pcVar14 = *pcVar14 + (char)pcVar14;
  pcVar19 = (char *)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                             CONCAT11(bVar21 << 3 | bVar21 >> 5,(char)unaff_EBX));
  ppcVar11 = (char **)CONCAT31(uVar13,(cVar16 + CARRY1(bVar18,bVar12)) - ((bVar21 >> 5 & 1) != 0));
  iVar17 = param_2 + 3;
  puVar25 = (undefined *)((int)puVar24 + 5);
  ppiVar27 = (int **)(puVar26 + 2);
  do {
    ppcVar22 = unaff_EBP;
    *pcVar19 = *pcVar19 + (char)ppcVar11;
    *(char *)ppcVar11 = *(char *)ppcVar11 + (char)ppcVar11;
    bVar18 = (char)pcVar19 + (char)((uint)ppcVar11 >> 8);
    pcVar19 = (char *)CONCAT31((int3)((uint)pcVar19 >> 8),bVar18);
    unaff_EBP = (char **)((int)ppcVar11 + 1);
    pcVar14[0x4e885] = pcVar14[0x4e885] + (char)pcVar14;
    *(char *)(ppiVar27 + 0x10902e) = *(char *)(ppiVar27 + 0x10902e) + (char)((uint)unaff_EBP >> 8);
    *(char *)unaff_EBP = *(char *)unaff_EBP + (char)unaff_EBP;
    pcVar15 = pcVar14 + (1 - *(int *)((int)ppcVar11 + -0x3e));
    cVar16 = (char)((uint)pcVar15 >> 8) + bVar18;
    pcVar14 = (char *)CONCAT22((short)((uint)pcVar15 >> 0x10),CONCAT11(cVar16,(char)pcVar15));
    *(byte *)(iVar17 + 0x47) = *(byte *)(iVar17 + 0x47) ^ bVar18;
    *(char *)(iVar17 + 2) = *(char *)(iVar17 + 2) + cVar16;
    *ppcVar22 = *ppcVar22 + (int)unaff_EBP;
    ppiVar5 = ppiVar27 + 1;
    *ppiVar27 = (int *)ppcVar22;
    uStack_8 = 0;
    piVar9 = (int *)(puVar25 + 0x35);
    *piVar9 = *piVar9 + (int)unaff_EBP;
    iVar4 = *piVar9;
    *ppiVar5 = (int *)((int)*ppiVar5 << 8 | (uint)*ppiVar5 >> 0x18);
    ppcVar11 = ppcVar22;
    iVar17 = iVar17 + 1;
    puVar25 = puVar25 + 1;
    ppiVar27 = ppiVar5;
  } while (iVar4 < 0);
  pcVar19 = pcVar19 + 1;
  ppcVar20 = (code **)CONCAT22((short)((uint)pcVar19 >> 0x10),
                               CONCAT11((char)((uint)pcVar19 >> 8) * '\x02',(char)pcVar19));
  ppcVar2 = ppcVar20 + -0x1ffa562;
  *(char *)ppcVar2 = *(char *)ppcVar2 + (char)pcVar15 + '\x01';
  *unaff_EBP = *unaff_EBP + (int)ppcVar22;
  *ppiVar5 = (int *)unaff_EBP;
                    // WARNING: Could not recover jumptable at 0x0040c693. Too many branches
                    // WARNING: Treating indirect jump as call
  (**ppcVar20)();
  return;
}


