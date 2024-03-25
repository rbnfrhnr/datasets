typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned long    ulong;
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

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[64];
};




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004063a1) overlaps instruction at (ram,0x0040639f)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall entry(undefined4 param_1,int param_2)

{
  ushort *puVar1;
  code *pcVar2;
  short sVar3;
  undefined uVar4;
  char cVar7;
  byte *pbVar5;
  char *pcVar6;
  byte bVar8;
  byte bVar10;
  uint *puVar9;
  char *extraout_ECX;
  int iVar11;
  undefined4 uVar12;
  byte bVar13;
  int unaff_EBX;
  undefined2 *puVar14;
  undefined4 *puVar15;
  int unaff_EBP;
  int **ppiVar16;
  int iVar17;
  undefined4 *unaff_ESI;
  int *piVar18;
  undefined4 *unaff_EDI;
  byte *pbVar19;
  byte *pbVar20;
  int iVar21;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_GS;
  byte bVar22;
  char cVar23;
  byte in_AF;
  bool bVar24;
  float10 extraout_ST0;
  undefined8 uVar25;
  undefined8 uVar26;
  void *pvStack_8;
  undefined *puStack_4;
  
  puStack_4 = &LAB_00438660;
  pvStack_8 = ExceptionList;
  bVar22 = 0;
  pbVar5 = (byte *)0x0;
  ppiVar16 = (int **)(unaff_EBP + 1);
  puVar14 = (undefined2 *)(unaff_EBX + 1);
  piVar18 = unaff_ESI + 1;
  out(*unaff_ESI,(short)param_2);
  uRam00000000 = param_1;
  ExceptionList = &pvStack_8;
  while( true ) {
    uVar12 = in((short)param_2);
    *unaff_EDI = uVar12;
    if (SCARRY4(unaff_EBX,1)) break;
    puVar1 = (ushort *)(param_2 + (int)piVar18);
    sVar3 = ((ushort)piVar18 & 3) - (*puVar1 & 3);
    *puVar1 = *puVar1 + (ushort)bVar22 * sVar3;
    bVar22 = 9 < (byte)pbVar5 | in_AF;
    pbVar5 = (byte *)(uint)(CONCAT11((char)((uint)pbVar5 >> 8) + bVar22,
                                     (byte)pbVar5 + bVar22 * '\x06') & 0xff0f);
    unaff_EDI = unaff_EDI + 1;
    in_AF = bVar22;
    if (!(bool)bVar22 && sVar3 < 1) {
      func_0x780c4df5(in_CS,0);
      return;
    }
  }
  *(byte *)(unaff_EBP + 0x1e) = *(byte *)(unaff_EBP + 0x1e) | (byte)((uint)param_2 >> 8);
  iVar11 = 0;
                    // WARNING: Ignoring partial resolution of indirect
  uRam00000000._0_2_ = in_SS;
  pbVar19 = (byte *)((int)unaff_EDI + 5);
  if ((POPCOUNT((uint)pbVar19 & 0xff) & 1U) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    puVar9 = *(uint **)(puVar14 + (int)piVar18);
    bVar13 = (byte)puVar14 ^ *pbVar5;
    pbVar19[0x69226b29] = pbVar19[0x69226b29] + bVar13;
    bVar22 = in((short)iVar11);
    piVar18 = ppiVar16[0x1c];
    puVar14 = (undefined2 *)CONCAT22((short)((uint)puVar14 >> 0x10),CONCAT11(0x83,bVar13));
    *(byte *)((int)puVar14 + 0x74c9fa0b) = *(byte *)((int)puVar14 + 0x74c9fa0b) | (byte)puVar9;
    ppiVar16 = (int **)*ppiVar16;
    cVar7 = (char)((uint)pbVar5 >> 8) + *(char *)((int)piVar18 + -0x47);
    pbVar5 = (byte *)(CONCAT11(cVar7,bVar22) | 0x33);
    pbVar20 = pbVar19 + 1;
    if (-1 < cVar7) break;
    bVar24 = SCARRY4((int)(pbVar19 + 1),1);
    pbVar19 = pbVar19 + 2;
    if (pbVar19 != (byte *)0x0 && bVar24 == (int)pbVar19 < 0) {
      *puVar14 = in_ES;
      puVar9 = (uint *)((int)puVar9 + -1);
      *(undefined2 *)(pbVar5 + 0x49) = in_GS;
      if (puVar9 != (uint *)0x0) {
        *pbVar19 = *pbVar19 >> 3 | *pbVar19 << 5;
        pbVar5 = (byte *)(iVar11 + 0xb111ec1 + (int)pbVar5 * 8);
        *pbVar5 = *pbVar5 ^ (byte)puVar9;
        *pbVar19 = *pbVar19 + 1;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
LAB_0040641a:
      pbVar5 = (byte *)(uint)(byte)((bVar22 | 0x33) ^ 3);
      pbVar20 = pbVar19;
      break;
    }
    pbVar19 = (byte *)0x85390d3c;
    if (bVar24) {
      *puVar9 = *puVar9 << 9 | *puVar9 >> 0x17;
      goto LAB_0040641a;
    }
    iVar11 = 0x4900;
  }
  do {
    if (puVar9 == (uint *)0x0) break;
    puVar9 = (uint *)((int)puVar9 + -1);
    bVar22 = *pbVar20;
    pbVar20 = pbVar20 + 1;
  } while ((byte)pbVar5 == bVar22);
  *(undefined2 *)((int)puVar14 + (int)piVar18) = in_ES;
  iVar17 = (int)*ppiVar16;
  pcVar2 = (code *)piVar18[-0x12de5fd];
  *ppiVar16 = (int *)0x40643a;
  uVar25 = (*pcVar2)();
  iVar11 = 0x3b380239;
  do {
    uVar12 = (undefined4)((ulonglong)uVar25 >> 0x20);
    pcVar6 = (char *)uVar25;
    bVar24 = SCARRY1(*pcVar6,(char)puVar14);
    *pcVar6 = *pcVar6 + (char)puVar14;
    cVar7 = *pcVar6;
    uVar4 = in(0);
    uVar26 = CONCAT44(uVar12,CONCAT31((int3)((ulonglong)uVar25 >> 8),uVar4));
    iVar21 = iVar11;
    if (*pcVar6 == '\0') {
      iVar21 = iVar11 + 1;
      bVar24 = SBORROW4((int)puVar14,1);
      puVar14 = (undefined2 *)((int)puVar14 + -1);
      uVar26 = CONCAT44(uVar12,*ppiVar16);
      puVar15 = ppiVar16 + 1;
      pcVar2 = (code *)swi(4);
      ppiVar16 = ppiVar16 + 1;
      if (bVar24 == true) {
        uVar26 = (*pcVar2)();
        ppiVar16 = (int **)puVar15;
      }
      pcVar6 = (char *)(iVar11 + 0x23);
      cVar7 = (char)((ulonglong)uVar26 >> 0x28);
      bVar24 = SCARRY1(*pcVar6,cVar7);
      *pcVar6 = *pcVar6 + cVar7;
      cVar7 = *pcVar6;
    }
    uVar25 = CONCAT44((int)((ulonglong)uVar26 >> 0x20),piVar18);
    piVar18 = (int *)uVar26;
    iVar11 = iVar21;
  } while (bVar24 != cVar7 < '\0');
  cVar23 = CARRY1((byte)((ulonglong)uVar26 >> 0x20),(byte)puVar14);
  pcVar2 = (code *)swi(0x59);
  pcVar6 = (char *)(*pcVar2)();
  cVar7 = (char)pcVar6;
  _DAT_6a00fc9b = CONCAT31(DAT_6a00fc9b_1,(DAT_6a00fc9b - cVar7) - cVar23);
  bVar8 = (byte)extraout_ECX;
  *extraout_ECX = *extraout_ECX << (bVar8 & 0x1f);
  iVar11 = (int)*ppiVar16;
  *(undefined **)(iVar17 + 0x1c) = &DAT_6a00fc9b;
  *ppiVar16 = (int *)iVar17;
  ((int *)ppiVar16)[-1] = (int)ppiVar16;
  *pcVar6 = *pcVar6 + cVar7;
  pbVar5 = (byte *)((iVar11 + _DAT_6a00fc9b) * 5 + -0x75);
  bVar22 = *pbVar5;
  bVar10 = (byte)((uint)extraout_ECX >> 8);
  *pbVar5 = *pbVar5 + bVar10;
  puVar14 = puVar14 + 0x1e3561e6;
  bVar13 = *(byte *)puVar14;
  *(byte *)puVar14 = *(byte *)puVar14 + bVar8;
  cVar7 = DAT_6a00fc9d - ((cVar7 + -0x17) - CARRY1(bVar22,bVar10));
  _DAT_01b7c35a = (longlong)extraout_ST0;
  *(int *)((int)ppiVar16 + -0x44d) = (int)(int *)uVar26 + 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


