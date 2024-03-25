typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned long    ulong;
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_6 IMAGE_RESOURCE_DIR_STRING_U_6, *PIMAGE_RESOURCE_DIR_STRING_U_6;

struct IMAGE_RESOURCE_DIR_STRING_U_6 {
    word Length;
    wchar16 NameString[3];
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

void entry(void)

{
                    // WARNING: Call to offcut address within same function
  func_0x00401009();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Type propagation algorithm not settling
// WARNING: Restarted to delay deadcode elimination for space: stack

void __fastcall FUN_00499b39(int param_1,char *param_2)

{
  int *piVar1;
  undefined uVar2;
  char cVar3;
  char *in_EAX;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  code **unaff_ESI;
  int unaff_EDI;
  char in_CF;
  byte in_AF;
  undefined8 uVar8;
  undefined unaff_retaddr;
  undefined auStack_3 [3];
  
  auStack_3[0] = (undefined)((uint)unaff_EBP >> 8);
  auStack_3[1] = (undefined)((uint)unaff_EBP >> 0x10);
  auStack_3[2] = (undefined)((uint)unaff_EBP >> 0x18);
  *(char *)((int)unaff_ESI + -0x42) = *(char *)((int)unaff_ESI + -0x42) + (char)param_2 + in_CF;
  *(int *)(param_1 + 0x49e95fba) = (int)(auStack_3 + *(int *)(param_1 + 0x49e95fba));
  iVar7 = CONCAT22((short)((uint)(param_1 + 1) >> 0x10),CONCAT11((char)in_EAX,(char)(param_1 + 1)));
  *(int *)(in_EAX + -0x476776e7) = *(int *)(in_EAX + -0x476776e7) + iVar7;
  LOCK();
  uVar2 = *(undefined *)(unaff_EDI + -0x47);
  *(undefined *)(unaff_EDI + -0x47) = (char)unaff_EBX;
  UNLOCK();
  uVar4 = CONCAT31((int3)((uint)unaff_EBX >> 8),uVar2) & 0xc421c647;
  uVar4 = CONCAT31((int3)(uVar4 >> 8),(char)uVar4 + 'c') & 0xffffff23;
  iVar5 = CONCAT22((short)(uVar4 >> 0x10),CONCAT11(0xbc,(char)uVar4));
  piVar1 = (int *)(iVar5 + 0x78);
  *piVar1 = *piVar1 + -0x36;
  if (*piVar1 == 0) {
    in(0x3b);
    auStack_3[0] = 0x92;
    auStack_3[1] = 0x9b;
    auStack_3[2] = 0x49;
    uVar8 = func_0x431b9ee7();
    in_AF = 9 < ((byte)uVar8 & 0xf) | in_AF;
    uVar4 = CONCAT31((int3)((ulonglong)uVar8 >> 8),(byte)uVar8 + in_AF * '\x06') & 0xffffff0f;
    puVar6 = (uint *)CONCAT22((short)(uVar4 >> 0x10),
                              CONCAT11((char)((ulonglong)uVar8 >> 8) + in_AF,(char)uVar4));
    *puVar6 = *puVar6 | (uint)CONCAT12(unaff_retaddr,(short)((uint)unaff_EBP >> 0x10)) << 8;
    puVar6 = (uint *)((int)((ulonglong)uVar8 >> 0x20) + -0x2d7feeb9);
    *puVar6 = *puVar6 | (uint)&stack0x00000001;
    *(char **)(unaff_EDI + -0x26) = *(char **)(unaff_EDI + -0x26) + (int)in_EAX;
    return;
  }
  iVar5 = iVar5 + 1;
  out((short)param_2,(char)iVar5);
  LOCK();
  cVar3 = *in_EAX;
  *in_EAX = (char)((uint)iVar5 >> 8);
  UNLOCK();
  if (iVar7 != 0) {
    *(byte *)((int)unaff_ESI + -0x7b) =
         *(byte *)((int)unaff_ESI + -0x7b) | (byte)((uint)param_2 >> 8);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *param_2 = *param_2 - cVar3;
                    // WARNING: Could not recover jumptable at 0x00499b20. Too many branches
                    // WARNING: Treating indirect jump as call
  (**unaff_ESI)();
  return;
}


