typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
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

typedef ulong DWORD;

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

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef DWORD *PDWORD;

typedef int BOOL;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_42 IMAGE_RESOURCE_DIR_STRING_U_42, *PIMAGE_RESOURCE_DIR_STRING_U_42;

struct IMAGE_RESOURCE_DIR_STRING_U_42 {
    word Length;
    wchar16 NameString[21];
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_34 IMAGE_RESOURCE_DIR_STRING_U_34, *PIMAGE_RESOURCE_DIR_STRING_U_34;

struct IMAGE_RESOURCE_DIR_STRING_U_34 {
    word Length;
    wchar16 NameString[17];
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

typedef struct CWinApp CWinApp, *PCWinApp;

struct CWinApp { // PlaceHolder Structure
};

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

typedef longlong __time64_t;

typedef __time64_t time_t;

typedef ushort wctype_t;




// WARNING: Control flow encountered bad instruction data

void __fastcall FUN_0044a010(undefined4 *param_1)

{
  char *pcVar1;
  undefined4 *puVar2;
  uint uVar3;
  byte bVar4;
  undefined4 extraout_ECX;
  int unaff_EBX;
  int unaff_EDI;
  ulonglong uVar5;
  
  uVar5 = func_0xe085a121();
  *param_1 = 0x15ff2068;
  bVar4 = (byte)extraout_ECX | *(byte *)(unaff_EBX + 0x1404700e);
  pcVar1 = (char *)((int)uVar5 + -0x3a);
  *pcVar1 = *pcVar1 + (char)(uVar5 >> 0x28);
  uVar3 = *(uint *)(&DAT_0044bffb + unaff_EDI);
  pcVar1 = (char *)(CONCAT31((int3)((uint)extraout_ECX >> 8),bVar4) + -0xb);
  *pcVar1 = *pcVar1 + (bVar4 - 1);
  uVar3 = (uint)(uVar5 / uVar3) & 0xffffff08;
  puVar2 = (undefined4 *)(unaff_EDI + 0x56 + uVar3);
  *puVar2 = *puVar2;
  out(0x59,(char)uVar3);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Instruction at (ram,0x0045551b) overlaps instruction at (ram,0x0045551a)
// 
// WARNING: Control flow encountered bad instruction data

void entry(void)

{
  char cVar1;
  undefined uVar2;
  char cVar3;
  byte bVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  HMODULE hModule;
  FARPROC pFVar8;
  int *piVar9;
  undefined4 *puVar10;
  uint uVar11;
  uint uVar12;
  FARPROC *ppFVar13;
  uint uVar14;
  uint *puVar15;
  UINT unaff_EDI;
  undefined4 *puVar16;
  int *piVar17;
  int *piVar18;
  int *piVar19;
  bool bVar20;
  bool bVar21;
  undefined local_80 [72];
  undefined4 uStackY_38;
  
  puVar15 = &DAT_0044a000;
  puVar16 = (undefined4 *)&DAT_00401000;
  uVar14 = 0xffffffff;
LAB_004553e2:
  uVar11 = *puVar15;
  bVar20 = puVar15 < (uint *)0xfffffffc;
  puVar15 = puVar15 + 1;
  bVar21 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar20);
  uVar11 = uVar11 * 2 + (uint)bVar20;
LAB_004553e9:
  if (!bVar21) {
    iVar6 = 1;
    do {
      bVar20 = CARRY4(uVar11,uVar11);
      uVar12 = uVar11 * 2;
      if (uVar12 == 0) {
        uVar11 = *puVar15;
        bVar21 = puVar15 < (uint *)0xfffffffc;
        puVar15 = puVar15 + 1;
        bVar20 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar21);
        uVar12 = uVar11 * 2 + (uint)bVar21;
      }
      uVar7 = iVar6 * 2 + (uint)bVar20;
      uVar11 = uVar12 * 2;
      if (CARRY4(uVar12,uVar12)) {
        if (uVar11 != 0) goto LAB_0045542b;
        uVar12 = *puVar15;
        bVar20 = puVar15 < (uint *)0xfffffffc;
        puVar15 = puVar15 + 1;
        uVar11 = uVar12 * 2 + (uint)bVar20;
        if (CARRY4(uVar12,uVar12) || CARRY4(uVar12 * 2,(uint)bVar20)) goto LAB_0045542b;
      }
      bVar20 = CARRY4(uVar11,uVar11);
      uVar11 = uVar11 * 2;
      if (uVar11 == 0) {
        uVar11 = *puVar15;
        bVar21 = puVar15 < (uint *)0xfffffffc;
        puVar15 = puVar15 + 1;
        bVar20 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar21);
        uVar11 = uVar11 * 2 + (uint)bVar21;
      }
      iVar6 = (uVar7 - 1) * 2 + (uint)bVar20;
    } while( true );
  }
  uVar2 = *(undefined *)puVar15;
  puVar15 = (uint *)((int)puVar15 + 1);
  *(undefined *)puVar16 = uVar2;
  puVar16 = (undefined4 *)((int)puVar16 + 1);
  goto LAB_004553de;
LAB_0045542b:
  iVar6 = 0;
  if (uVar7 < 3) {
    bVar20 = CARRY4(uVar11,uVar11);
    uVar11 = uVar11 * 2;
    if (uVar11 == 0) {
      uVar11 = *puVar15;
      bVar21 = puVar15 < (uint *)0xfffffffc;
      puVar15 = puVar15 + 1;
      bVar20 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar21);
      uVar11 = uVar11 * 2 + (uint)bVar21;
    }
  }
  else {
    uVar2 = *(undefined *)puVar15;
    puVar15 = (uint *)((int)puVar15 + 1);
    uVar14 = CONCAT31((int3)uVar7 + -3,uVar2) ^ 0xffffffff;
    if (uVar14 == 0) {
      puVar16 = (undefined4 *)&DAT_00401000;
      iVar6 = 0x92b;
      do {
        cVar3 = *(char *)puVar16;
        puVar16 = (undefined4 *)((int)puVar16 + 1);
        while (((byte)(cVar3 + 0x18U) < 2 && (*(char *)puVar16 == '\a'))) {
          uVar5 = *puVar16;
          cVar3 = *(char *)(puVar16 + 1);
          *puVar16 = &DAT_00401000 +
                     (CONCAT31(CONCAT21((ushort)uVar5 >> 8,(char)((uint)uVar5 >> 0x10)),
                               (char)((uint)uVar5 >> 0x18)) - (int)puVar16);
          puVar16 = (undefined4 *)((int)puVar16 + 5);
          iVar6 = iVar6 + -1;
          if (iVar6 == 0) {
            piVar17 = &DAT_00454000;
            do {
              if (*piVar17 == 0) {
                puVar16 = (undefined4 *)&DAT_00400ffc;
                piVar17 = piVar17 + 1;
                while( true ) {
                  bVar4 = *(byte *)piVar17;
                  uVar14 = (uint)bVar4;
                  piVar19 = (int *)((int)piVar17 + 1);
                  if (uVar14 == 0) break;
                  if (0xef < bVar4) {
                    uVar14 = CONCAT12(bVar4,*(undefined2 *)piVar19) & 0xff0fffff;
                    piVar19 = (int *)((int)piVar17 + 3);
                  }
                  puVar16 = (undefined4 *)((int)puVar16 + uVar14);
                  uVar5 = *puVar16;
                  *puVar16 = &DAT_00401000 +
                             CONCAT31(CONCAT21(CONCAT11((char)uVar5,(char)((uint)uVar5 >> 8)),
                                               (char)((uint)uVar5 >> 0x10)),
                                      (char)((uint)uVar5 >> 0x18));
                  piVar17 = piVar19;
                }
                uStackY_38 = 0x455581;
                VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,4,(PDWORD)&stack0xffffffdc);
                    // WARNING: Read-only address (ram,0x004001ff) is written
                IMAGE_SECTION_HEADER_004001d8.Characteristics._3_1_ = 0x60;
                    // WARNING: Read-only address (ram,0x00400227) is written
                IMAGE_SECTION_HEADER_00400200.Characteristics._3_1_ = 0x60;
                uStackY_38 = 0x455596;
                VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,uVar14,(PDWORD)&stack0xffffffdc);
                do {
                } while (&stack0x00000000 != local_80);
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              ppFVar13 = (FARPROC *)(&DAT_00401000 + piVar17[1]);
              piVar19 = piVar17 + 2;
              hModule = LoadLibraryA((LPCSTR)((int)&DWORD_0048a084 + *piVar17));
              while( true ) {
                cVar3 = *(char *)piVar19;
                piVar17 = (int *)((int)piVar19 + 1);
                if (cVar3 == '\0') break;
                if (cVar3 < '\0') {
                  piVar17 = (int *)(uint)*(ushort *)piVar17;
                  piVar19 = (int *)((int)piVar19 + 3);
                }
                else {
                  piVar9 = piVar17;
                  piVar18 = piVar17;
                  do {
                    piVar19 = piVar18;
                    if (piVar9 == (int *)0x0) break;
                    piVar9 = (int *)((int)piVar9 + -1);
                    piVar19 = (int *)((int)piVar18 + 1);
                    cVar1 = *(char *)piVar18;
                    piVar18 = piVar19;
                  } while ((char)(cVar3 + -1) != cVar1);
                }
                pFVar8 = GetProcAddress(hModule,(LPCSTR)piVar17);
                if (pFVar8 == (FARPROC)0x0) {
                    // WARNING: Subroutine does not return
                  ExitProcess(unaff_EDI);
                }
                *ppFVar13 = pFVar8;
                ppFVar13 = ppFVar13 + 1;
              }
            } while( true );
          }
        }
      } while( true );
    }
    bVar20 = (uVar14 & 1) != 0;
    uVar14 = (int)uVar14 >> 1;
  }
  if (!bVar20) {
    iVar6 = 1;
    bVar20 = CARRY4(uVar11,uVar11);
    uVar11 = uVar11 * 2;
    if (uVar11 == 0) {
      uVar11 = *puVar15;
      bVar21 = puVar15 < (uint *)0xfffffffc;
      puVar15 = puVar15 + 1;
      bVar20 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar21);
      uVar11 = uVar11 * 2 + (uint)bVar21;
    }
    if (!bVar20) {
      do {
        do {
          bVar20 = CARRY4(uVar11,uVar11);
          uVar12 = uVar11 * 2;
          if (uVar12 == 0) {
            uVar11 = *puVar15;
            bVar21 = puVar15 < (uint *)0xfffffffc;
            puVar15 = puVar15 + 1;
            bVar20 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar21);
            uVar12 = uVar11 * 2 + (uint)bVar21;
          }
          iVar6 = iVar6 * 2 + (uint)bVar20;
          uVar11 = uVar12 * 2;
        } while (!CARRY4(uVar12,uVar12));
        if (uVar11 != 0) break;
        uVar12 = *puVar15;
        bVar20 = puVar15 < (uint *)0xfffffffc;
        puVar15 = puVar15 + 1;
        uVar11 = uVar12 * 2 + (uint)bVar20;
      } while (!CARRY4(uVar12,uVar12) && !CARRY4(uVar12 * 2,(uint)bVar20));
      iVar6 = iVar6 + 2;
      goto LAB_0045547d;
    }
  }
  bVar20 = CARRY4(uVar11,uVar11);
  uVar11 = uVar11 * 2;
  if (uVar11 == 0) {
    uVar11 = *puVar15;
    bVar21 = puVar15 < (uint *)0xfffffffc;
    puVar15 = puVar15 + 1;
    bVar20 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar21);
    uVar11 = uVar11 * 2 + (uint)bVar21;
  }
  iVar6 = iVar6 * 2 + (uint)bVar20;
LAB_0045547d:
  uVar12 = iVar6 + 2 + (uint)(uVar14 < 0xfffffb00);
  puVar10 = (undefined4 *)((int)puVar16 + uVar14);
  if (uVar14 < 0xfffffffd) {
    do {
      uVar5 = *puVar10;
      puVar10 = puVar10 + 1;
      *puVar16 = uVar5;
      puVar16 = puVar16 + 1;
      bVar20 = 3 < uVar12;
      uVar12 = uVar12 - 4;
    } while (bVar20 && uVar12 != 0);
    puVar16 = (undefined4 *)((int)puVar16 + uVar12);
  }
  else {
    do {
      uVar2 = *(undefined *)puVar10;
      puVar10 = (undefined4 *)((int)puVar10 + 1);
      *(undefined *)puVar16 = uVar2;
      puVar16 = (undefined4 *)((int)puVar16 + 1);
      uVar12 = uVar12 - 1;
    } while (uVar12 != 0);
  }
LAB_004553de:
  bVar21 = CARRY4(uVar11,uVar11);
  uVar11 = uVar11 * 2;
  if (uVar11 == 0) goto LAB_004553e2;
  goto LAB_004553e9;
}


