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




// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall
entry(char *param_1,char *param_2,undefined param_3,undefined param_4,undefined param_5,
     undefined param_6,undefined param_7,undefined param_8,undefined param_9,undefined param_10,
     undefined4 param_11)

{
  int *piVar1;
  int *piVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  char cVar5;
  int *piVar6;
  int iVar7;
  int extraout_EDX;
  int unaff_EBX;
  undefined4 *puVar8;
  code **ppcVar9;
  void **ppvVar11;
  int unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 in_stack_ffffd784;
  byte bVar12;
  void *apvStack_14 [4];
  undefined *puStack_4;
  char cVar10;
  
  bVar12 = (byte)((uint)in_stack_ffffd784 >> 0x18);
  puStack_4 = &LAB_00469f3c;
  apvStack_14[3] = ExceptionList;
  piVar6 = (int *)0x0;
  apvStack_14[2] = (void *)0x0;
  apvStack_14[1] = (void *)(unaff_EBP + 1);
  puVar8 = (undefined4 *)(unaff_EBX + 1);
  piVar1 = unaff_ESI + 1;
  out(*unaff_ESI,(short)param_2);
  piVar2 = unaff_EDI + 1;
  uVar3 = in((short)param_2);
  pcRam00000000 = param_1;
  ExceptionList = apvStack_14 + 3;
  *unaff_EDI = uVar3;
  if (!SCARRY4(unaff_EBX,1)) {
    *(undefined2 *)(param_2 + (int)piVar1) = *(undefined2 *)(param_2 + (int)piVar1);
    piVar6 = (int *)&DAT_004246c4;
    *puVar8 = apvStack_14[1];
    *param_2 = *param_2 >> 2;
    cVar5 = (char)param_1;
    *(char *)(unaff_EBX + 0x4246bc1e) = *(char *)(unaff_EBX + 0x4246bc1e) + cVar5;
    param_1[0x423ab84b] = param_1[0x423ab84b] + cVar5;
    *(char *)(unaff_EBX + 0x4246b43e) = *(char *)(unaff_EBX + 0x4246b43e) + cVar5;
    puVar4 = unaff_ESI + -0x12;
    *(char *)puVar4 = *(char *)puVar4 + 'F';
    param_1 = param_1 + -1;
    if (param_1 == (char *)0x0 || *(char *)puVar4 == '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    param_2 = param_2 + 1;
  }
  *(char *)(unaff_EBX + -0x1b5cf7b0) =
       *(char *)(unaff_EBX + -0x1b5cf7b0) + (char)((uint)param_2 >> 8);
  cVar5 = (char)piVar6;
  do {
    iVar7 = CONCAT22((short)((uint)param_1 >> 0x10),CONCAT11(0x8f,(char)param_1));
    param_1 = (char *)(iVar7 + -1);
  } while (param_1 != (char *)0x0 && cVar5 != *param_2);
  *piVar6 = (int)(*piVar6 + (int)piVar6);
  ppvVar11 = apvStack_14 + 1;
  cVar10 = '\x19';
  puVar4 = (undefined4 *)apvStack_14[1];
  do {
    puVar4 = puVar4 + -1;
    ppvVar11 = ppvVar11 + -1;
    *ppvVar11 = (void *)*puVar4;
    cVar10 = cVar10 + -1;
  } while ('\0' < cVar10);
  cVar10 = (char)((uint)puVar8 >> 8);
  *(char *)piVar2 = *(char *)piVar2 + cVar10;
  *param_1 = *param_1 + cVar5;
  cVar10 = cVar10 + (char)puVar8;
  ppcVar9 = (code **)CONCAT22((short)((uint)puVar8 >> 0x10),CONCAT11(cVar10,(char)puVar8));
  param_2[1] = param_2[1] >> 1;
  _DAT_00423bc0 = 0xc0000c37;
  *param_1 = *param_1 + cVar5;
  *(char *)piVar6 = *(char *)piVar6 + cVar5;
  (&DAT_00422043)[iVar7] = (&DAT_00422043)[iVar7] + (char)((uint)piVar6 >> 8);
  ppcVar9[0x7fff36] = (code *)piVar2;
  DAT_007e2048 = cVar5;
  *piVar1 = *piVar1 + (int)ppcVar9;
  iVar7 = *piVar2;
  *piVar2 = *piVar2 >> 3;
  *(char *)((int)unaff_ESI + 0x46) =
       *(char *)((int)unaff_ESI + 0x46) + cVar5 + -1 + ((iVar7 >> 2 & 1U) != 0);
  param_2[0x41] = param_2[0x41] + (char)((uint)param_1 >> 8);
  func_0xd797cbae();
  *piVar1 = *piVar1 + extraout_EDX;
  *ppcVar9 = *ppcVar9 + 1;
  *piVar1 = *piVar1 + (int)ppcVar9;
  *piVar2 = *piVar2 >> 3;
  *(char *)(unaff_EDI + 3) = *(char *)(unaff_EDI + 3) + cVar10;
  func_0xd797cbd2(0x3f,&DAT_0041c2b8,(uint)bVar12 << 0x18);
  *piVar1 = *piVar1 + (int)ppcVar9;
                    // WARNING: Could not recover jumptable at 0x0040ca9b. Too many branches
                    // WARNING: Treating indirect jump as call
  (**ppcVar9)(0xc0000c37);
  return;
}


