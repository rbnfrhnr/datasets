typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
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




// WARNING: Instruction at (ram,0x004176b2) overlaps instruction at (ram,0x004176b1)
// 
// WARNING: Removing unreachable block (ram,0x004176bc)
// WARNING: Removing unreachable block (ram,0x00417604)

undefined4 __fastcall entry(int param_1,uint *param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  char cVar3;
  byte bVar4;
  undefined2 uVar5;
  byte bVar8;
  int unaff_EBX;
  byte *pbVar6;
  int iVar7;
  int unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 *puVar9;
  bool bVar10;
  bool bVar11;
  undefined auStack_b [3];
  undefined auStack_8 [8];
  
  ExceptionList = auStack_8;
  bVar10 = false;
  cVar3 = '\0';
  pbVar6 = (byte *)(unaff_EBX + 1);
  bVar11 = pbVar6 == (byte *)0x0;
  puVar1 = unaff_ESI + 1;
  uVar5 = SUB42(param_2,0);
  out(*unaff_ESI,uVar5);
  uVar2 = in(uVar5);
  iRam00000000 = param_1;
  *unaff_EDI = uVar2;
  if (!SCARRY4(unaff_EBX,1)) {
    *(undefined2 *)((int)param_2 + (int)puVar1) = *(undefined2 *)((int)param_2 + (int)puVar1);
    uVar2 = in(uVar5);
    unaff_EDI[1] = uVar2;
    param_2 = (uint *)CONCAT31((int3)((uint)param_2 >> 8),*(undefined *)(param_1 + 0x76));
    iVar7 = unaff_EBX + 2;
    *param_2 = *param_2 >> 0x17 | *param_2 << 9;
    iRamfffffffc = *(int *)((int)unaff_ESI + (unaff_EBP + 1) * 8 + -0x72) * 0x2f506163;
    cVar3 = (char)auStack_b;
    bVar8 = (byte)((uint)iVar7 >> 8);
    bVar10 = CARRY1(bVar8,*(byte *)(unaff_ESI + 0x10));
    pbVar6 = (byte *)(CONCAT22((short)((uint)iVar7 >> 0x10),
                               CONCAT11(bVar8 + *(char *)(unaff_ESI + 0x10),(char)iVar7)) + 1);
    uRamfffffff9 = (undefined3)((uint)auStack_b >> 8);
    param_1 = CONCAT31((int3)((uint)(param_1 + -1) >> 8),0x18) + 1;
    uRamfffffff5 = 0xfffffff9;
    bVar11 = iRamfffffffc == -1;
  }
  puVar9 = (undefined4 *)0x0;
  if (bVar11) {
    if (bVar10) {
      pbVar6 = (byte *)(CONCAT31((int3)((uint)pbVar6 >> 8),(char)pbVar6 - cVar3) + -0x69);
      *pbVar6 = *pbVar6 & 0xe2;
      return 0xe42301af;
    }
    iVar7 = 0x3e668183 - (uint)bVar10;
  }
  else {
    bVar8 = *pbVar6;
    bVar4 = (byte)((uint)param_1 >> 8);
    *pbVar6 = *pbVar6 + bVar4;
    *(char *)(unaff_ESI + 0xb1dc1cd) = *(char *)(unaff_ESI + 0xb1dc1cd) + 'a' + CARRY1(bVar8,bVar4);
    bVar4 = (byte)param_1;
    *(byte *)puVar1 = *(char *)puVar1 + bVar4;
    out(CONCAT11(9,(char)param_2),0);
    param_2 = (uint *)0x19990951;
    puVar9 = (undefined4 *)uRam007eb1e9 + 0xd5c1abd;
    bVar8 = *(byte *)puVar9;
    *(byte *)puVar9 = *(byte *)puVar9 + bVar4;
    *(undefined4 *)uRam007eb1e9 = *puVar1;
    pbVar6[0x329e6495] = pbVar6[0x329e6495];
    *(undefined *)((undefined4 *)uRam007eb1e9 + 1) = *(undefined *)(unaff_ESI + 2);
    bVar4 = (bVar4 + CARRY1(bVar8,bVar4) * -(bVar4 & 3) & 0x1f) % 9;
    bVar8 = *(byte *)((int)(undefined4 *)uRam007eb1e9 + -0x49b3d4fb);
    *(byte *)((int)(undefined4 *)uRam007eb1e9 + -0x49b3d4fb) = bVar8 << bVar4 | bVar8 >> 9 - bVar4;
    iVar7 = -0x3a73e6fc;
    puVar9 = (undefined4 *)&DAT_10641d90;
    pbVar6 = (byte *)((uint)pbVar6 & 0xff);
  }
  *(byte *)(iVar7 + 0x71486a) = *(byte *)(iVar7 + 0x71486a) & (byte)((uint)param_2 >> 8);
  in(0xdd);
  uVar2 = in((short)CONCAT31((int3)((uint)param_2 >> 8),(char)param_2 + (char)pbVar6));
  *puVar9 = uVar2;
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}


