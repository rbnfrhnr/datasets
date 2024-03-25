typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
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




void DllFunctionCall(void)

{
                    // WARNING: Could not recover jumptable at 0x00401060. Too many branches
                    // WARNING: Treating indirect jump as call
  DllFunctionCall();
  return;
}



void Ordinal_100(void)

{
                    // WARNING: Could not recover jumptable at 0x004010de. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_100();
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0040121a) overlaps instruction at (ram,0x00401219)
// 
// WARNING: Removing unreachable block (ram,0x00401106)
// WARNING: Removing unreachable block (ram,0x00401126)
// WARNING: Removing unreachable block (ram,0x0040115e)
// WARNING: Removing unreachable block (ram,0x0040112c)
// WARNING: Removing unreachable block (ram,0x0040113c)
// WARNING: Removing unreachable block (ram,0x004011a9)

void entry(int param_1,undefined4 param_2,char *param_3,char *param_4,int *param_5,byte **param_6)

{
  byte **ppbVar1;
  int iVar2;
  undefined uVar3;
  undefined4 uVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  char cVar8;
  char cVar11;
  byte *pbVar9;
  int *piVar10;
  byte bVar12;
  int extraout_ECX;
  byte bVar13;
  undefined2 uVar14;
  uint *puVar15;
  uint unaff_EBX;
  char *pcVar16;
  int *unaff_ESI;
  uint *unaff_EDI;
  undefined4 *puVar17;
  bool bVar18;
  undefined8 uVar19;
  undefined4 *unaff_retaddr;
  char acStack_1a [18];
  undefined4 uStack_8;
  undefined4 *puStack_4;
  
  puStack_4 = (undefined4 *)&DAT_004032f0;
  uStack_8 = 0x4010ee;
  uVar19 = Ordinal_100();
  puVar15 = (uint *)((ulonglong)uVar19 >> 0x20);
  pbVar9 = (byte *)uVar19;
  bVar5 = (byte)uVar19;
  *pbVar9 = *pbVar9 + bVar5;
  *pbVar9 = *pbVar9 + bVar5;
  *pbVar9 = *pbVar9 + bVar5;
  *pbVar9 = *pbVar9 ^ bVar5;
  *pbVar9 = *pbVar9 + bVar5;
  pbVar9 = pbVar9 + 1;
  cVar8 = (char)pbVar9;
  *pbVar9 = *pbVar9 + cVar8;
  *pbVar9 = *pbVar9 + cVar8;
  *pbVar9 = *pbVar9 + cVar8;
  acStack_1a[(int)puVar15 * 2] = acStack_1a[(int)puVar15 * 2] + (char)(unaff_EBX >> 8);
  *pbVar9 = *pbVar9 + cVar8;
  bVar5 = *pbVar9;
  *pbVar9 = *pbVar9 + cVar8;
  if (SCARRY1(bVar5,cVar8) == (char)*pbVar9 < '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *puVar15 = *puVar15 & (uint)unaff_EDI;
  iVar2 = *unaff_ESI;
  pcVar16 = (char *)(unaff_EBX ^ *(uint *)(extraout_ECX + -0x48ee309a));
  *(char *)((int)unaff_EDI + -1) = (char)iVar2;
  *(char *)(iVar2 + -0x2d) = *(char *)(iVar2 + -0x2d) + (char)((uint)iVar2 >> 8);
  cVar8 = (char)pcVar16;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  pbVar9 = (byte *)((uint)pcVar16 & 0xffffff20);
  bVar5 = *pbVar9;
  bVar6 = (byte)pbVar9;
  *pbVar9 = *pbVar9 + bVar6;
  bVar12 = (byte)extraout_ECX & 0x1f;
  *unaff_EDI = (uint)(CONCAT14(CARRY1(bVar5,bVar6),*unaff_EDI) >> bVar12) |
               *unaff_EDI << 0x21 - bVar12;
  *pbVar9 = *pbVar9 + bVar6;
  *(char *)((int)pbVar9 * 2) = *(char *)((int)pbVar9 * 2) + (byte)extraout_ECX;
  uVar3 = in((short)((ulonglong)uVar19 >> 0x20));
  *(undefined *)unaff_EDI = uVar3;
  uVar14 = SUB42(param_4,0);
  uVar4 = in(uVar14);
  *puStack_4 = uVar4;
  if (SBORROW4(iVar2,1)) {
    bVar5 = (byte)param_6;
    *(byte *)param_6 = *(char *)param_6 + bVar5;
    *(byte *)param_6 = *(byte *)param_6 & bVar5;
    *(byte *)param_6 = *(char *)param_6 + bVar5;
    *param_6 = *param_6 + (int)param_6;
    puVar17 = puStack_4 + 1;
  }
  else {
    iVar2 = *(int *)(param_3 + 0x68);
    param_6 = (byte **)(iVar2 * 0x69);
    puVar17 = (undefined4 *)((int)puStack_4 + 5);
    uVar3 = in(uVar14);
    *(undefined *)(puStack_4 + 1) = uVar3;
    bVar5 = (byte)param_5;
    bVar18 = CARRY1(DAT_45dff501,bVar5);
    DAT_45dff501 = DAT_45dff501 + bVar5;
    out(*unaff_retaddr,uVar14);
    cVar8 = (char)param_6;
    if (bVar18) {
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      *(byte *)param_6 = *(byte *)param_6 + cVar8;
      param_4[0x4a] = param_4[0x4a] + bVar5;
      goto code_r0x00401235;
    }
    *param_6 = (byte *)((uint)*param_6 ^ (uint)param_6);
    *param_5 = *param_5 + iVar2 * -0x69;
    *param_4 = *param_4 + cVar8;
    param_5 = (int *)((uint)param_5 & *(uint *)((int)unaff_retaddr + 0x6c000023));
    unaff_retaddr = unaff_retaddr + 1;
  }
  bVar7 = (byte)param_6;
  *(char *)((int)unaff_retaddr + 0x1f) = *(char *)((int)unaff_retaddr + 0x1f) + bVar7;
  *(byte *)param_5 = *(char *)param_5 + bVar7;
  pbVar9 = (byte *)((int)param_6 * 2);
  bVar5 = *pbVar9;
  *pbVar9 = *pbVar9 + bVar7;
  bVar12 = *(byte *)param_6;
  bVar13 = (byte)param_4;
  bVar6 = *(byte *)param_6;
  *(byte *)param_6 = bVar6 + bVar13 + CARRY1(bVar5,bVar7);
  *(byte *)param_6 =
       *(byte *)param_6 + bVar7 +
       (CARRY1(bVar12,bVar13) || CARRY1(bVar6 + bVar13,CARRY1(bVar5,bVar7)));
  *param_6 = *param_6 + (int)param_6;
  *(byte *)param_5 = *(char *)param_5 - bVar7;
  *(byte *)param_6 = *(byte *)param_6 + bVar7;
  *(byte *)param_6 = *(byte *)param_6 + bVar7;
  *(byte *)param_6 = *(byte *)param_6 + (char)((uint)param_4 >> 8);
  *(byte *)param_6 = *(byte *)param_6 ^ bVar7;
  *(byte *)param_5 = *(char *)param_5 + bVar7;
  cVar8 = (char)param_5;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  bVar12 = (byte)((uint)param_5 >> 8);
  *(byte *)((int)param_6 + 0x6e00000e) = *(byte *)((int)param_6 + 0x6e00000e) + bVar12;
  *param_6 = *param_6 + (int)param_6;
  cVar11 = (char)((uint)param_6 >> 8);
  *(byte *)param_6 = *(byte *)param_6 + cVar11;
  *(byte *)param_6 = *(byte *)param_6 & bVar7;
  *(byte *)param_5 = *(char *)param_5 + bVar7;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  ppbVar1 = param_6 + 0x5800002;
  bVar5 = *(byte *)ppbVar1;
  *(byte *)ppbVar1 = *(byte *)ppbVar1 + bVar12;
  *(byte *)param_6 = *(byte *)param_6 + bVar7 + CARRY1(bVar5,bVar12);
  bVar5 = *(byte *)param_6;
  *(byte *)param_6 = *(byte *)param_6 + (byte)param_3;
  *(byte *)param_6 = (*(byte *)param_6 - bVar7) - CARRY1(bVar5,(byte)param_3);
  *(byte *)param_5 = *(char *)param_5 + bVar7;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  cVar8 = bVar7 + cVar8;
  param_6 = (byte **)CONCAT31((int3)((uint)param_6 >> 8),cVar8);
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + bVar13;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar11;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(char *)param_5 = *(char *)param_5 + cVar8;
  *(char *)((int)param_6 * 2) = *(char *)((int)param_6 * 2) + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  *(byte *)param_6 = *(byte *)param_6 + cVar8;
  param_4 = param_4 + -2;
code_r0x00401235:
  *(char *)(param_1 + 0x6d) = *(char *)(param_1 + 0x6d) + (char)((uint)param_5 >> 8);
  uVar4 = in((short)param_4 + -1);
  *puVar17 = uVar4;
  *param_3 = *param_3 + (char)param_6;
  pcVar16 = (char *)(*(int *)(param_3 + -0x5789f000) * -0x4b7ee400);
  *pcVar16 = *pcVar16 + (char)((uint)param_6 >> 8);
  cVar8 = (char)((uint)pcVar16 >> 8);
  pcVar16[-0x396cd200] = cVar8;
  *pcVar16 = *pcVar16 + cVar8;
  piVar10 = (int *)in(0);
  pcVar16[-0x20] = pcVar16[-0x20] + cVar8;
  *piVar10 = *piVar10 + 1;
  *(char *)(piVar10 + -0x21bbfde) = (char)param_5;
  *piVar10 = *piVar10 + 1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


