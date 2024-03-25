typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long    ulong;
typedef unsigned int    undefined4;
typedef unsigned short    word;
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

typedef unsigned short    wchar16;
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
    byte e_program[160]; // Actual DOS program
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

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};




// WARNING: Instruction at (ram,0x0040c80a) overlaps instruction at (ram,0x0040c808)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x0040c826)
// WARNING: Removing unreachable block (ram,0x0040c82e)
// WARNING: Removing unreachable block (ram,0x0040c830)
// WARNING: Removing unreachable block (ram,0x0040c83c)
// WARNING: Removing unreachable block (ram,0x0040c857)
// WARNING: Removing unreachable block (ram,0x0040c866)
// WARNING: Removing unreachable block (ram,0x0040c7f7)
// WARNING: Removing unreachable block (ram,0x0040c80a)

void __fastcall entry(byte *param_1,int param_2)

{
  ushort *puVar1;
  undefined4 *puVar2;
  ushort uVar3;
  char *pcVar4;
  int unaff_EBX;
  undefined4 *unaff_ESI;
  char **unaff_EDI;
  char **ppcVar5;
  undefined4 unaff_FS_OFFSET;
  bool bVar6;
  undefined auStack_8 [8];
  
  while( true ) {
    *(undefined **)unaff_FS_OFFSET = auStack_8;
    bVar6 = SCARRY4(unaff_EBX,1);
    unaff_EBX = unaff_EBX + 1;
    puVar2 = unaff_ESI + 1;
    out(*unaff_ESI,(short)param_2);
    pcVar4 = (char *)in((short)param_2);
    pbRam00000000 = param_1;
    *unaff_EDI = pcVar4;
    if (bVar6) {
      pbRam00000000 = (byte *)CONCAT31(pbRam00000000._1_3_,(char)pbRam00000000 - (char)param_2);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    puVar1 = (ushort *)(param_2 + (int)puVar2);
    uVar3 = *puVar1;
    *puVar1 = *puVar1;
    if (0 < (short)(((ushort)puVar2 & 3) - (uVar3 & 3))) break;
    param_1[0x38fcfcfd] = param_1[0x38fcfcfd] + (char)unaff_EBX + 1;
    *(undefined2 *)(param_1 + 0x2036f8b4) = *(undefined2 *)(param_1 + 0x2036f8b4);
    param_1 = param_1 + 1;
    unaff_ESI = puVar2;
    unaff_EDI = unaff_EDI + 1;
  }
  pcVar4 = (char *)0x0;
  ppcVar5 = unaff_EDI + 1;
  do {
    *pcVar4 = *pcVar4 << 2;
    *ppcVar5 = (char *)((uint)*ppcVar5 | CONCAT31((int3)((uint)param_1 >> 8),0xac));
    *ppcVar5 = pcVar4;
    pcVar4 = pcRam3702acb1;
    ppcVar5 = ppcVar5 + 1;
  } while( true );
}



// WARNING: Variable defined which should be unmapped: param_9
// WARNING: Type propagation algorithm not settling

void __fastcall
FUN_0046c1b2(int param_1,int param_2,undefined param_3,undefined param_4,undefined param_5,
            undefined param_6,undefined4 param_7,undefined param_8,undefined4 param_9)

{
  longlong lVar1;
  code *pcVar2;
  undefined6 uVar3;
  char cVar4;
  byte *pbVar6;
  byte *pbVar8;
  byte **ppbVar9;
  int unaff_EBX;
  undefined4 *unaff_ESI;
  int *unaff_EDI;
  undefined2 uVar10;
  byte bVar5;
  char *pcVar7;
  
  out(*unaff_ESI,(short)param_2);
  uVar3 = *(undefined6 *)(param_1 + -0x147ea41b);
  uVar10 = (undefined2)((uint6)uVar3 >> 0x20);
  pbVar6 = (byte *)((int)uVar3 + 0x21d0848b + (uint)((undefined *)0x3 < &stack0xfffffffc));
  *(undefined *)(unaff_EBX + 0x51cb030e) = 0xff;
  bVar5 = (byte)((uint6)uVar3 >> 0x20);
  cVar4 = bVar5 + 0x8b;
  pcVar7 = (char *)CONCAT31((int3)(CONCAT22((short)((uint)unaff_EBX >> 0x10),uVar10) >> 8),cVar4);
  if (cVar4 == '\0' || SCARRY1(bVar5,-0x75) != cVar4 < '\0') {
    *pcVar7 = *pcVar7 + cVar4 + (0x74 < bVar5);
    return;
  }
  ppbVar9 = (byte **)(param_2 + *unaff_EDI);
  while (*ppbVar9 + ((uint)pcVar7 | 0xc033fb00) != (byte *)0x0) {
    pbVar8 = *ppbVar9;
    do {
      pbVar8 = pbVar8 + (int)pbVar6;
    } while (pbVar8 != (byte *)0x0);
    LOCK();
    *pbVar6 = *pbVar6 | (byte)((uint)ppbVar9 >> 8);
    UNLOCK();
    *unaff_EDI = 0;
    pcVar7 = (char *)0x0;
    unaff_EDI = unaff_EDI + 1;
    ppbVar9 = (byte **)&DAT_00000006;
  }
  lVar1 = (longlong)*(int *)((int)ppbVar9 + -0x363a8afa) * -0x67;
  cVar4 = (int)lVar1 != lVar1;
  if (-1 < (int)(pbVar6 + -1)) {
    DAT_3b085f47 = (char)lVar1 + (char)((uint)(pbVar6 + -1) >> 8);
    return;
  }
  pcVar2 = (code *)swi(4);
  if ((bool)cVar4) {
    (*pcVar2)(uVar10);
  }
  *(char *)(unaff_ESI + -0x128cd998) = *(char *)(unaff_ESI + -0x128cd998) + -0x80 + cVar4;
  return;
}


