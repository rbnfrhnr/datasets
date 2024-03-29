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

typedef void *PVOID;

typedef PVOID LSA_HANDLE;

typedef ushort WORD;

typedef ulong DWORD;

typedef int (*FARPROC)(void);

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

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

typedef long LONG;

typedef LONG NTSTATUS;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_18 IMAGE_RESOURCE_DIR_STRING_U_18, *PIMAGE_RESOURCE_DIR_STRING_U_18;

struct IMAGE_RESOURCE_DIR_STRING_U_18 {
    word Length;
    wchar16 NameString[9];
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

typedef long HRESULT;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef CHAR *LPSTR;

typedef struct tWAVEFORMATEX tWAVEFORMATEX, *PtWAVEFORMATEX;

typedef struct tWAVEFORMATEX WAVEFORMATEX;

typedef WAVEFORMATEX *LPCWAVEFORMATEX;

struct tWAVEFORMATEX {
    WORD wFormatTag;
    WORD nChannels;
    DWORD nSamplesPerSec;
    DWORD nAvgBytesPerSec;
    WORD nBlockAlign;
    WORD wBitsPerSample;
    WORD cbSize;
};

typedef struct HWAVEIN__ HWAVEIN__, *PHWAVEIN__;

typedef struct HWAVEIN__ *HWAVEIN;

typedef HWAVEIN *LPHWAVEIN;

struct HWAVEIN__ {
    int unused;
};

typedef UINT MMRESULT;

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

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;




// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_004ea594(ushort *param_1)

{
  byte *pbVar1;
  byte extraout_AH;
  int extraout_ECX;
  int extraout_EDX;
  char unaff_BL;
  int unaff_EBP;
  int unaff_ESI;
  char *pcVar2;
  byte in_CF;
  
  *param_1 = *param_1 + (ushort)in_CF * (((ushort)param_1 & 3) - (*param_1 & 3));
  func_0xa39cdc0c();
  pcVar2 = (char *)(unaff_ESI + _DAT_8c7769a4 +
                   (uint)CARRY1(extraout_AH,*(byte *)(unaff_EBP + 0x6a247555 + extraout_ECX * 8)));
  *pcVar2 = *pcVar2 - unaff_BL;
  pbVar1 = (byte *)(extraout_EDX * 2 + -0x16e5f30);
  *pbVar1 = *pbVar1 ^ (byte)((uint)extraout_ECX >> 8);
  in(0x50);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Instruction at (ram,0x004f17cc) overlaps instruction at (ram,0x004f17cb)
// 

void __fastcall entry(ushort *param_1)

{
  char cVar1;
  undefined uVar2;
  char cVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  HMODULE hModule;
  FARPROC pFVar7;
  DWORD *pDVar8;
  undefined4 *puVar9;
  uint uVar10;
  uint uVar11;
  FARPROC *ppFVar12;
  uint uVar13;
  uint *puVar14;
  UINT unaff_EDI;
  undefined4 *puVar15;
  DWORD *lpProcName;
  DWORD *pDVar16;
  DWORD *pDVar17;
  bool bVar18;
  bool bVar19;
  undefined local_80 [72];
  undefined4 uStackY_38;
  DWORD flNewProtect;
  
  puVar14 = &DAT_004ca000;
  puVar15 = (undefined4 *)&DAT_00401000;
  Rsrc_GroupIcon_68_804._4_2_ = Rsrc_GroupIcon_68_804._4_2_ + 1;
  uVar13 = 0xffffffff;
LAB_004f169a:
  uVar10 = *puVar14;
  bVar18 = puVar14 < (uint *)0xfffffffc;
  puVar14 = puVar14 + 1;
  bVar19 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
  uVar10 = uVar10 * 2 + (uint)bVar18;
LAB_004f16a1:
  if (!bVar19) {
    iVar5 = 1;
    do {
      bVar18 = CARRY4(uVar10,uVar10);
      uVar11 = uVar10 * 2;
      if (uVar11 == 0) {
        uVar10 = *puVar14;
        bVar19 = puVar14 < (uint *)0xfffffffc;
        puVar14 = puVar14 + 1;
        bVar18 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar19);
        uVar11 = uVar10 * 2 + (uint)bVar19;
      }
      uVar6 = iVar5 * 2 + (uint)bVar18;
      uVar10 = uVar11 * 2;
      if (CARRY4(uVar11,uVar11)) {
        if (uVar10 != 0) goto LAB_004f16e3;
        uVar11 = *puVar14;
        bVar18 = puVar14 < (uint *)0xfffffffc;
        puVar14 = puVar14 + 1;
        uVar10 = uVar11 * 2 + (uint)bVar18;
        if (CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar18)) goto LAB_004f16e3;
      }
      bVar18 = CARRY4(uVar10,uVar10);
      uVar10 = uVar10 * 2;
      if (uVar10 == 0) {
        uVar10 = *puVar14;
        bVar19 = puVar14 < (uint *)0xfffffffc;
        puVar14 = puVar14 + 1;
        bVar18 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar19);
        uVar10 = uVar10 * 2 + (uint)bVar19;
      }
      iVar5 = (uVar6 - 1) * 2 + (uint)bVar18;
    } while( true );
  }
  uVar2 = *(undefined *)puVar14;
  puVar14 = (uint *)((int)puVar14 + 1);
  *(undefined *)puVar15 = uVar2;
  puVar15 = (undefined4 *)((int)puVar15 + 1);
  goto LAB_004f1696;
LAB_004f16e3:
  iVar5 = 0;
  if (uVar6 < 3) {
    bVar18 = CARRY4(uVar10,uVar10);
    uVar10 = uVar10 * 2;
    if (uVar10 == 0) {
      uVar10 = *puVar14;
      bVar19 = puVar14 < (uint *)0xfffffffc;
      puVar14 = puVar14 + 1;
      bVar18 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar19);
      uVar10 = uVar10 * 2 + (uint)bVar19;
    }
  }
  else {
    uVar2 = *(undefined *)puVar14;
    puVar14 = (uint *)((int)puVar14 + 1);
    uVar13 = CONCAT31((int3)uVar6 + -3,uVar2) ^ 0xffffffff;
    if (uVar13 == 0) {
      puVar15 = (undefined4 *)&DAT_00401000;
      iVar5 = 0xf;
      do {
        cVar3 = *(char *)puVar15;
        puVar15 = (undefined4 *)((int)puVar15 + 1);
        while ((byte)(cVar3 + 0x18U) < 2) {
          uVar4 = *puVar15;
          cVar3 = *(char *)(puVar15 + 1);
          *puVar15 = &DAT_00401000 +
                     (CONCAT31(CONCAT21(CONCAT11((char)uVar4,(char)((uint)uVar4 >> 8)),
                                        (char)((uint)uVar4 >> 0x10)),(char)((uint)uVar4 >> 0x18)) -
                     (int)puVar15);
          puVar15 = (undefined4 *)((int)puVar15 + 5);
          iVar5 = iVar5 + -1;
          if (iVar5 == 0) {
            lpProcName = &DAT_004f0000;
            do {
              flNewProtect = *lpProcName;
              if (flNewProtect == 0) {
                uStackY_38 = 0x4f1801;
                VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,4,(PDWORD)&stack0xffffffdc);
                    // WARNING: Read-only address (ram,0x00400237) is written
                IMAGE_SECTION_HEADER_00400210.Characteristics._3_1_ = 0x60;
                    // WARNING: Read-only address (ram,0x0040025f) is written
                IMAGE_SECTION_HEADER_00400238.Characteristics._3_1_ = 0x60;
                uStackY_38 = 0x4f1816;
                VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,flNewProtect,
                               (PDWORD)&stack0xffffffdc);
                do {
                } while (&stack0x00000000 != local_80);
                FUN_004ea594(param_1);
                return;
              }
              ppFVar12 = (FARPROC *)(&DAT_00401000 + lpProcName[1]);
              pDVar17 = lpProcName + 2;
              hModule = LoadLibraryA((LPCSTR)((int)&DWORD_004f4a34 + flNewProtect));
              while( true ) {
                cVar3 = *(char *)pDVar17;
                lpProcName = (DWORD *)((int)pDVar17 + 1);
                if (cVar3 == '\0') break;
                if (cVar3 < '\0') {
                  lpProcName = (DWORD *)(uint)*(ushort *)lpProcName;
                  pDVar17 = (DWORD *)((int)pDVar17 + 3);
                }
                else {
                  pDVar8 = lpProcName;
                  pDVar16 = lpProcName;
                  do {
                    pDVar17 = pDVar16;
                    if (pDVar8 == (DWORD *)0x0) break;
                    pDVar8 = (DWORD *)((int)pDVar8 + -1);
                    pDVar17 = (DWORD *)((int)pDVar16 + 1);
                    cVar1 = *(char *)pDVar16;
                    pDVar16 = pDVar17;
                  } while ((char)(cVar3 + -1) != cVar1);
                }
                pFVar7 = GetProcAddress(hModule,(LPCSTR)lpProcName);
                if (pFVar7 == (FARPROC)0x0) {
                    // WARNING: Subroutine does not return
                  ExitProcess(unaff_EDI);
                }
                *ppFVar12 = pFVar7;
                ppFVar12 = ppFVar12 + 1;
              }
            } while( true );
          }
        }
      } while( true );
    }
    bVar18 = (uVar13 & 1) != 0;
    uVar13 = (int)uVar13 >> 1;
  }
  if (!bVar18) {
    iVar5 = 1;
    bVar18 = CARRY4(uVar10,uVar10);
    uVar10 = uVar10 * 2;
    if (uVar10 == 0) {
      uVar10 = *puVar14;
      bVar19 = puVar14 < (uint *)0xfffffffc;
      puVar14 = puVar14 + 1;
      bVar18 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar19);
      uVar10 = uVar10 * 2 + (uint)bVar19;
    }
    if (!bVar18) {
      do {
        do {
          bVar18 = CARRY4(uVar10,uVar10);
          uVar11 = uVar10 * 2;
          if (uVar11 == 0) {
            uVar10 = *puVar14;
            bVar19 = puVar14 < (uint *)0xfffffffc;
            puVar14 = puVar14 + 1;
            bVar18 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar19);
            uVar11 = uVar10 * 2 + (uint)bVar19;
          }
          iVar5 = iVar5 * 2 + (uint)bVar18;
          uVar10 = uVar11 * 2;
        } while (!CARRY4(uVar11,uVar11));
        if (uVar10 != 0) break;
        uVar11 = *puVar14;
        bVar18 = puVar14 < (uint *)0xfffffffc;
        puVar14 = puVar14 + 1;
        uVar10 = uVar11 * 2 + (uint)bVar18;
      } while (!CARRY4(uVar11,uVar11) && !CARRY4(uVar11 * 2,(uint)bVar18));
      iVar5 = iVar5 + 2;
      goto LAB_004f1735;
    }
  }
  bVar18 = CARRY4(uVar10,uVar10);
  uVar10 = uVar10 * 2;
  if (uVar10 == 0) {
    uVar10 = *puVar14;
    bVar19 = puVar14 < (uint *)0xfffffffc;
    puVar14 = puVar14 + 1;
    bVar18 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar19);
    uVar10 = uVar10 * 2 + (uint)bVar19;
  }
  iVar5 = iVar5 * 2 + (uint)bVar18;
LAB_004f1735:
  uVar11 = iVar5 + 2 + (uint)(uVar13 < 0xfffffb00);
  puVar9 = (undefined4 *)((int)puVar15 + uVar13);
  if (uVar13 < 0xfffffffd) {
    do {
      uVar4 = *puVar9;
      puVar9 = puVar9 + 1;
      *puVar15 = uVar4;
      puVar15 = puVar15 + 1;
      bVar18 = 3 < uVar11;
      uVar11 = uVar11 - 4;
    } while (bVar18 && uVar11 != 0);
    puVar15 = (undefined4 *)((int)puVar15 + uVar11);
  }
  else {
    do {
      uVar2 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      *(undefined *)puVar15 = uVar2;
      puVar15 = (undefined4 *)((int)puVar15 + 1);
      uVar11 = uVar11 - 1;
    } while (uVar11 != 0);
  }
LAB_004f1696:
  bVar19 = CARRY4(uVar10,uVar10);
  uVar10 = uVar10 * 2;
  if (uVar10 == 0) goto LAB_004f169a;
  goto LAB_004f16a1;
}


