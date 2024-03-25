typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
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

typedef ulong DWORD;

typedef int (*FARPROC)(void);

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef int INT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef struct HKEY__ *HKEY;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

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

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
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
    byte e_program[64]; // Actual DOS program
};

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;




// WARNING: Control flow encountered bad instruction data

void __fastcall FUN_00453071(undefined4 param_1,undefined2 param_2,int param_3)

{
  char *pcVar1;
  code *pcVar2;
  char cVar3;
  undefined4 in_EAX;
  byte bVar4;
  int unaff_EBX;
  int unaff_ESI;
  
  bVar4 = (byte)((uint)unaff_EBX >> 8);
  cVar3 = (byte)in_EAX - bVar4;
  sysexit();
  pcVar1 = (char *)(CONCAT31((int3)((uint)in_EAX >> 8),cVar3) + 0x33);
  *pcVar1 = *pcVar1 + cVar3 + ((byte)in_EAX < bVar4);
  if (1 < unaff_ESI) {
    do {
    } while (param_3 == unaff_EBX);
    in(param_2);
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Instruction at (ram,0x00467207) overlaps instruction at (ram,0x00467206)
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
  uint unaff_EBP;
  uint *puVar14;
  UINT unaff_EDI;
  undefined4 *puVar15;
  int *piVar16;
  int *piVar17;
  int *piVar18;
  bool bVar19;
  bool bVar20;
  bool bVar21;
  undefined local_80 [72];
  undefined4 uStackY_38;
  
  puVar14 = &DAT_00453000;
  puVar15 = (undefined4 *)&DAT_00401000;
LAB_004670da:
  uVar11 = *puVar14;
  bVar19 = puVar14 < (uint *)0xfffffffc;
  puVar14 = puVar14 + 1;
  bVar20 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar19);
  uVar11 = uVar11 * 2 + (uint)bVar19;
LAB_004670e1:
  if (!bVar20) {
    iVar6 = 1;
    do {
      bVar19 = CARRY4(uVar11,uVar11);
      uVar11 = uVar11 * 2;
      if (uVar11 == 0) {
        uVar11 = *puVar14;
        bVar20 = puVar14 < (uint *)0xfffffffc;
        puVar14 = puVar14 + 1;
        bVar19 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar20);
        uVar11 = uVar11 * 2 + (uint)bVar20;
      }
      uVar7 = iVar6 * 2 + (uint)bVar19;
      uVar12 = uVar11 * 2;
      if (CARRY4(uVar11,uVar11)) {
        if (uVar12 != 0) goto LAB_00467114;
        uVar11 = *puVar14;
        bVar19 = puVar14 < (uint *)0xfffffffc;
        puVar14 = puVar14 + 1;
        uVar12 = uVar11 * 2 + (uint)bVar19;
        if (CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar19)) goto LAB_00467114;
      }
      bVar19 = CARRY4(uVar12,uVar12);
      uVar11 = uVar12 * 2;
      if (uVar11 == 0) {
        uVar11 = *puVar14;
        bVar20 = puVar14 < (uint *)0xfffffffc;
        puVar14 = puVar14 + 1;
        bVar19 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar20);
        uVar11 = uVar11 * 2 + (uint)bVar20;
      }
      iVar6 = (uVar7 - 1) * 2 + (uint)bVar19;
    } while( true );
  }
  uVar2 = *(undefined *)puVar14;
  puVar14 = (uint *)((int)puVar14 + 1);
  *(undefined *)puVar15 = uVar2;
  puVar15 = (undefined4 *)((int)puVar15 + 1);
  goto LAB_004670d6;
LAB_00467114:
  if (uVar7 < 3) {
    bVar19 = CARRY4(uVar12,uVar12);
    uVar12 = uVar12 * 2;
    if (uVar12 == 0) {
      uVar11 = *puVar14;
      bVar20 = puVar14 < (uint *)0xfffffffc;
      puVar14 = puVar14 + 1;
      bVar19 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar20);
      uVar12 = uVar11 * 2 + (uint)bVar20;
    }
  }
  else {
    uVar2 = *(undefined *)puVar14;
    puVar14 = (uint *)((int)puVar14 + 1);
    uVar11 = CONCAT31((int3)uVar7 + -3,uVar2) ^ 0xffffffff;
    if (uVar11 == 0) {
      puVar15 = (undefined4 *)&DAT_00401000;
      iVar6 = 0x915;
      do {
        cVar3 = *(char *)puVar15;
        puVar15 = (undefined4 *)((int)puVar15 + 1);
        while (((byte)(cVar3 + 0x18U) < 2 && (*(char *)puVar15 == '\x11'))) {
          uVar5 = *puVar15;
          cVar3 = *(char *)(puVar15 + 1);
          *puVar15 = &DAT_00401000 +
                     (CONCAT31(CONCAT21((ushort)uVar5 >> 8,(char)((uint)uVar5 >> 0x10)),
                               (char)((uint)uVar5 >> 0x18)) - (int)puVar15);
          puVar15 = (undefined4 *)((int)puVar15 + 5);
          iVar6 = iVar6 + -1;
          if (iVar6 == 0) {
            piVar16 = &DAT_00465000;
            do {
              if (*piVar16 == 0) {
                puVar15 = (undefined4 *)&DAT_00400ffc;
                piVar16 = piVar16 + 1;
                while( true ) {
                  bVar4 = *(byte *)piVar16;
                  uVar11 = (uint)bVar4;
                  piVar18 = (int *)((int)piVar16 + 1);
                  if (uVar11 == 0) break;
                  if (0xef < bVar4) {
                    uVar11 = CONCAT12(bVar4,*(undefined2 *)piVar18) & 0xff0fffff;
                    piVar18 = (int *)((int)piVar16 + 3);
                  }
                  puVar15 = (undefined4 *)((int)puVar15 + uVar11);
                  uVar5 = *puVar15;
                  *puVar15 = &DAT_00401000 +
                             CONCAT31(CONCAT21(CONCAT11((char)uVar5,(char)((uint)uVar5 >> 8)),
                                               (char)((uint)uVar5 >> 0x10)),
                                      (char)((uint)uVar5 >> 0x18));
                  piVar16 = piVar18;
                }
                uStackY_38 = 0x46726d;
                VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,4,(PDWORD)&stack0xffffffdc);
                    // WARNING: Read-only address (ram,0x00400207) is written
                IMAGE_SECTION_HEADER_004001e0.Characteristics._3_1_ = 0x60;
                    // WARNING: Read-only address (ram,0x0040022f) is written
                IMAGE_SECTION_HEADER_00400208.Characteristics._3_1_ = 0x60;
                uStackY_38 = 0x467282;
                VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,uVar11,(PDWORD)&stack0xffffffdc);
                do {
                } while (&stack0x00000000 != local_80);
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              ppFVar13 = (FARPROC *)(&DAT_00401000 + piVar16[1]);
              piVar18 = piVar16 + 2;
              hModule = LoadLibraryA((LPCSTR)((int)&DWORD_004a3318 + *piVar16));
              while( true ) {
                cVar3 = *(char *)piVar18;
                piVar16 = (int *)((int)piVar18 + 1);
                if (cVar3 == '\0') break;
                if (cVar3 < '\0') {
                  piVar16 = (int *)(uint)*(ushort *)piVar16;
                  piVar18 = (int *)((int)piVar18 + 3);
                }
                else {
                  piVar9 = piVar16;
                  piVar17 = piVar16;
                  do {
                    piVar18 = piVar17;
                    if (piVar9 == (int *)0x0) break;
                    piVar9 = (int *)((int)piVar9 + -1);
                    piVar18 = (int *)((int)piVar17 + 1);
                    cVar1 = *(char *)piVar17;
                    piVar17 = piVar18;
                  } while ((char)(cVar3 + -1) != cVar1);
                }
                pFVar8 = GetProcAddress(hModule,(LPCSTR)piVar16);
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
    bVar19 = (uVar11 & 1) != 0;
    unaff_EBP = (int)uVar11 >> 1;
  }
  bVar20 = CARRY4(uVar12,uVar12);
  uVar11 = uVar12 * 2;
  if (uVar11 == 0) {
    uVar11 = *puVar14;
    bVar21 = puVar14 < (uint *)0xfffffffc;
    puVar14 = puVar14 + 1;
    bVar20 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar21);
    uVar11 = uVar11 * 2 + (uint)bVar21;
  }
  iVar6 = (uint)bVar19 * 2 + (uint)bVar20;
  if (iVar6 == 0) {
    iVar6 = 1;
    do {
      do {
        bVar19 = CARRY4(uVar11,uVar11);
        uVar12 = uVar11 * 2;
        if (uVar12 == 0) {
          uVar11 = *puVar14;
          bVar20 = puVar14 < (uint *)0xfffffffc;
          puVar14 = puVar14 + 1;
          bVar19 = CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar20);
          uVar12 = uVar11 * 2 + (uint)bVar20;
        }
        iVar6 = iVar6 * 2 + (uint)bVar19;
        uVar11 = uVar12 * 2;
      } while (!CARRY4(uVar12,uVar12));
      if (uVar11 != 0) break;
      uVar12 = *puVar14;
      bVar19 = puVar14 < (uint *)0xfffffffc;
      puVar14 = puVar14 + 1;
      uVar11 = uVar12 * 2 + (uint)bVar19;
    } while (!CARRY4(uVar12,uVar12) && !CARRY4(uVar12 * 2,(uint)bVar19));
    iVar6 = iVar6 + 2;
  }
  uVar12 = iVar6 + 1 + (uint)(unaff_EBP < 0xfffffb00);
  puVar10 = (undefined4 *)((int)puVar15 + unaff_EBP);
  if (unaff_EBP < 0xfffffffd) {
    do {
      uVar5 = *puVar10;
      puVar10 = puVar10 + 1;
      *puVar15 = uVar5;
      puVar15 = puVar15 + 1;
      bVar19 = 3 < uVar12;
      uVar12 = uVar12 - 4;
    } while (bVar19 && uVar12 != 0);
    puVar15 = (undefined4 *)((int)puVar15 + uVar12);
  }
  else {
    do {
      uVar2 = *(undefined *)puVar10;
      puVar10 = (undefined4 *)((int)puVar10 + 1);
      *(undefined *)puVar15 = uVar2;
      puVar15 = (undefined4 *)((int)puVar15 + 1);
      uVar12 = uVar12 - 1;
    } while (uVar12 != 0);
  }
LAB_004670d6:
  bVar20 = CARRY4(uVar11,uVar11);
  uVar11 = uVar11 * 2;
  if (uVar11 == 0) goto LAB_004670da;
  goto LAB_004670e1;
}


