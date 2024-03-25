typedef unsigned char   undefined;

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
typedef unsigned short    word;
typedef struct _BLENDFUNCTION _BLENDFUNCTION, *P_BLENDFUNCTION;

typedef uchar BYTE;

struct _BLENDFUNCTION {
    BYTE BlendOp;
    BYTE BlendFlags;
    BYTE SourceConstantAlpha;
    BYTE AlphaFormat;
};

typedef struct _BLENDFUNCTION BLENDFUNCTION;

typedef struct _GUID _GUID, *P_GUID;

typedef struct _GUID GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef GUID IID;

typedef ulong DWORD;

typedef int (*FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef void *LPVOID;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef DWORD *PDWORD;

typedef int BOOL;

typedef struct HKEY__ *HKEY;

typedef uint UINT;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

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

typedef long LONG;

typedef LONG LSTATUS;

typedef char CHAR;

typedef long HRESULT;

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

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct HDROP__ HDROP__, *PHDROP__;

struct HDROP__ {
    int unused;
};

typedef struct HDROP__ *HDROP;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IUnknown IUnknown, *PIUnknown;

typedef DWORD ULONG;

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(struct IUnknown *, IID *, void **);
    ULONG (*AddRef)(struct IUnknown *);
    ULONG (*Release)(struct IUnknown *);
};

struct IUnknown {
    struct IUnknownVtbl *lpVtbl;
};

typedef struct IUnknown *LPUNKNOWN;




// WARNING: Instruction at (ram,0x00469363) overlaps instruction at (ram,0x00469362)
// 
// WARNING: Control flow encountered bad instruction data

void entry(void)

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
  uint unaff_EBP;
  uint *puVar13;
  UINT unaff_EDI;
  undefined4 *puVar14;
  DWORD *lpProcName;
  DWORD *pDVar15;
  DWORD *pDVar16;
  bool bVar17;
  bool bVar18;
  undefined local_80 [72];
  undefined4 uStackY_38;
  DWORD flNewProtect;
  
  puVar13 = &DAT_00456000;
  puVar14 = (undefined4 *)&LAB_00401000;
LAB_0046922a:
  uVar10 = *puVar13;
  bVar17 = puVar13 < (uint *)0xfffffffc;
  puVar13 = puVar13 + 1;
  bVar18 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar17);
  uVar10 = uVar10 * 2 + (uint)bVar17;
LAB_00469231:
  if (!bVar18) {
    iVar5 = 1;
    do {
      bVar17 = CARRY4(uVar10,uVar10);
      uVar11 = uVar10 * 2;
      if (uVar11 == 0) {
        uVar10 = *puVar13;
        bVar18 = puVar13 < (uint *)0xfffffffc;
        puVar13 = puVar13 + 1;
        bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
        uVar11 = uVar10 * 2 + (uint)bVar18;
      }
      uVar6 = iVar5 * 2 + (uint)bVar17;
      uVar10 = uVar11 * 2;
      if (CARRY4(uVar11,uVar11)) {
        if (uVar10 != 0) goto LAB_00469273;
        uVar11 = *puVar13;
        bVar17 = puVar13 < (uint *)0xfffffffc;
        puVar13 = puVar13 + 1;
        uVar10 = uVar11 * 2 + (uint)bVar17;
        if (CARRY4(uVar11,uVar11) || CARRY4(uVar11 * 2,(uint)bVar17)) goto LAB_00469273;
      }
      bVar17 = CARRY4(uVar10,uVar10);
      uVar10 = uVar10 * 2;
      if (uVar10 == 0) {
        uVar10 = *puVar13;
        bVar18 = puVar13 < (uint *)0xfffffffc;
        puVar13 = puVar13 + 1;
        bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
        uVar10 = uVar10 * 2 + (uint)bVar18;
      }
      iVar5 = (uVar6 - 1) * 2 + (uint)bVar17;
    } while( true );
  }
  uVar2 = *(undefined *)puVar13;
  puVar13 = (uint *)((int)puVar13 + 1);
  *(undefined *)puVar14 = uVar2;
  puVar14 = (undefined4 *)((int)puVar14 + 1);
  goto LAB_00469226;
LAB_00469273:
  iVar5 = 0;
  if (uVar6 < 3) {
    bVar17 = CARRY4(uVar10,uVar10);
    uVar10 = uVar10 * 2;
    if (uVar10 == 0) {
      uVar10 = *puVar13;
      bVar18 = puVar13 < (uint *)0xfffffffc;
      puVar13 = puVar13 + 1;
      bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
      uVar10 = uVar10 * 2 + (uint)bVar18;
    }
  }
  else {
    uVar2 = *(undefined *)puVar13;
    puVar13 = (uint *)((int)puVar13 + 1);
    uVar11 = CONCAT31((int3)uVar6 + -3,uVar2) ^ 0xffffffff;
    if (uVar11 == 0) {
      puVar14 = (undefined4 *)&LAB_00401000;
      iVar5 = 0x1f53;
      do {
        cVar3 = *(char *)puVar14;
        puVar14 = (undefined4 *)((int)puVar14 + 1);
        while (((byte)(cVar3 + 0x18U) < 2 && (*(char *)puVar14 == '\b'))) {
          uVar4 = *puVar14;
          cVar3 = *(char *)(puVar14 + 1);
          *puVar14 = &LAB_00401000 +
                     (CONCAT31(CONCAT21((ushort)uVar4 >> 8,(char)((uint)uVar4 >> 0x10)),
                               (char)((uint)uVar4 >> 0x18)) - (int)puVar14);
          puVar14 = (undefined4 *)((int)puVar14 + 5);
          iVar5 = iVar5 + -1;
          if (iVar5 == 0) {
            lpProcName = &DAT_00467000;
            do {
              flNewProtect = *lpProcName;
              if (flNewProtect == 0) {
                uStackY_38 = 0x469398;
                VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,4,(PDWORD)&stack0xffffffdc);
                    // WARNING: Read-only address (ram,0x00400217) is written
                IMAGE_SECTION_HEADER_004001f0.Characteristics._3_1_ = 0x60;
                    // WARNING: Read-only address (ram,0x0040023f) is written
                IMAGE_SECTION_HEADER_00400218.Characteristics._3_1_ = 0x60;
                uStackY_38 = 0x4693ad;
                VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,flNewProtect,
                               (PDWORD)&stack0xffffffdc);
                do {
                } while (&stack0x00000000 != local_80);
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              ppFVar12 = (FARPROC *)(&LAB_00401000 + lpProcName[1]);
              pDVar16 = lpProcName + 2;
              hModule = LoadLibraryA((LPCSTR)((int)&DWORD_0046a000 + flNewProtect));
              while( true ) {
                cVar3 = *(char *)pDVar16;
                lpProcName = (DWORD *)((int)pDVar16 + 1);
                if (cVar3 == '\0') break;
                if (cVar3 < '\0') {
                  lpProcName = (DWORD *)(uint)*(ushort *)lpProcName;
                  pDVar16 = (DWORD *)((int)pDVar16 + 3);
                }
                else {
                  pDVar8 = lpProcName;
                  pDVar15 = lpProcName;
                  do {
                    pDVar16 = pDVar15;
                    if (pDVar8 == (DWORD *)0x0) break;
                    pDVar8 = (DWORD *)((int)pDVar8 + -1);
                    pDVar16 = (DWORD *)((int)pDVar15 + 1);
                    cVar1 = *(char *)pDVar15;
                    pDVar15 = pDVar16;
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
    bVar17 = (uVar11 & 1) != 0;
    unaff_EBP = (int)uVar11 >> 1;
  }
  if (!bVar17) {
    iVar5 = 1;
    bVar17 = CARRY4(uVar10,uVar10);
    uVar10 = uVar10 * 2;
    if (uVar10 == 0) {
      uVar10 = *puVar13;
      bVar18 = puVar13 < (uint *)0xfffffffc;
      puVar13 = puVar13 + 1;
      bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
      uVar10 = uVar10 * 2 + (uint)bVar18;
    }
    if (!bVar17) {
      do {
        do {
          bVar17 = CARRY4(uVar10,uVar10);
          uVar11 = uVar10 * 2;
          if (uVar11 == 0) {
            uVar10 = *puVar13;
            bVar18 = puVar13 < (uint *)0xfffffffc;
            puVar13 = puVar13 + 1;
            bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
            uVar11 = uVar10 * 2 + (uint)bVar18;
          }
          iVar5 = iVar5 * 2 + (uint)bVar17;
          uVar10 = uVar11 * 2;
        } while (!CARRY4(uVar11,uVar11));
        if (uVar10 != 0) break;
        uVar11 = *puVar13;
        bVar17 = puVar13 < (uint *)0xfffffffc;
        puVar13 = puVar13 + 1;
        uVar10 = uVar11 * 2 + (uint)bVar17;
      } while (!CARRY4(uVar11,uVar11) && !CARRY4(uVar11 * 2,(uint)bVar17));
      iVar5 = iVar5 + 2;
      goto LAB_004692c5;
    }
  }
  bVar17 = CARRY4(uVar10,uVar10);
  uVar10 = uVar10 * 2;
  if (uVar10 == 0) {
    uVar10 = *puVar13;
    bVar18 = puVar13 < (uint *)0xfffffffc;
    puVar13 = puVar13 + 1;
    bVar17 = CARRY4(uVar10,uVar10) || CARRY4(uVar10 * 2,(uint)bVar18);
    uVar10 = uVar10 * 2 + (uint)bVar18;
  }
  iVar5 = iVar5 * 2 + (uint)bVar17;
LAB_004692c5:
  uVar11 = iVar5 + 2 + (uint)(unaff_EBP < 0xfffffb00);
  puVar9 = (undefined4 *)((int)puVar14 + unaff_EBP);
  if (unaff_EBP < 0xfffffffd) {
    do {
      uVar4 = *puVar9;
      puVar9 = puVar9 + 1;
      *puVar14 = uVar4;
      puVar14 = puVar14 + 1;
      bVar17 = 3 < uVar11;
      uVar11 = uVar11 - 4;
    } while (bVar17 && uVar11 != 0);
    puVar14 = (undefined4 *)((int)puVar14 + uVar11);
  }
  else {
    do {
      uVar2 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      *(undefined *)puVar14 = uVar2;
      puVar14 = (undefined4 *)((int)puVar14 + 1);
      uVar11 = uVar11 - 1;
    } while (uVar11 != 0);
  }
LAB_00469226:
  bVar18 = CARRY4(uVar10,uVar10);
  uVar10 = uVar10 * 2;
  if (uVar10 == 0) goto LAB_0046922a;
  goto LAB_00469231;
}


