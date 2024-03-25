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
typedef short    wchar_t;
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

typedef struct _devicemodeW _devicemodeW, *P_devicemodeW;

typedef wchar_t WCHAR;

typedef ushort WORD;

typedef ulong DWORD;

typedef union _union_660 _union_660, *P_union_660;

typedef union _union_663 _union_663, *P_union_663;

typedef struct _struct_661 _struct_661, *P_struct_661;

typedef struct _struct_662 _struct_662, *P_struct_662;

typedef struct _POINTL _POINTL, *P_POINTL;

typedef struct _POINTL POINTL;

typedef long LONG;

struct _POINTL {
    LONG x;
    LONG y;
};

union _union_663 {
    DWORD dmDisplayFlags;
    DWORD dmNup;
};

struct _struct_662 {
    POINTL dmPosition;
    DWORD dmDisplayOrientation;
    DWORD dmDisplayFixedOutput;
};

struct _struct_661 {
    short dmOrientation;
    short dmPaperSize;
    short dmPaperLength;
    short dmPaperWidth;
    short dmScale;
    short dmCopies;
    short dmDefaultSource;
    short dmPrintQuality;
};

union _union_660 {
    struct _struct_661 field0;
    struct _struct_662 field1;
};

struct _devicemodeW {
    WCHAR dmDeviceName[32];
    WORD dmSpecVersion;
    WORD dmDriverVersion;
    WORD dmSize;
    WORD dmDriverExtra;
    DWORD dmFields;
    union _union_660 field6_0x4c;
    short dmColor;
    short dmDuplex;
    short dmYResolution;
    short dmTTOption;
    short dmCollate;
    WCHAR dmFormName[32];
    WORD dmLogPixels;
    DWORD dmBitsPerPel;
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    union _union_663 field17_0xb4;
    DWORD dmDisplayFrequency;
    DWORD dmICMMethod;
    DWORD dmICMIntent;
    DWORD dmMediaType;
    DWORD dmDitherType;
    DWORD dmReserved1;
    DWORD dmReserved2;
    DWORD dmPanningWidth;
    DWORD dmPanningHeight;
};

typedef struct _devicemodeW *LPDEVMODEW;


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef int (*FARPROC)(void);

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef void *HANDLE;

typedef HANDLE *LPHANDLE;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef int INT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef long LONG_PTR;

typedef LONG_PTR LRESULT;

typedef DWORD *PDWORD;

typedef struct HKEY__ *HKEY;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

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

typedef long HRESULT;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef DWORD ACCESS_MASK;

typedef WCHAR *LPCWSTR;

typedef WCHAR *LPWSTR;

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

typedef struct _PRINTER_DEFAULTSW _PRINTER_DEFAULTSW, *P_PRINTER_DEFAULTSW;

struct _PRINTER_DEFAULTSW {
    LPWSTR pDatatype;
    LPDEVMODEW pDevMode;
    ACCESS_MASK DesiredAccess;
};

typedef struct _PRINTER_DEFAULTSW *LPPRINTER_DEFAULTSW;




// WARNING: Instruction at (ram,0x0047c2ea) overlaps instruction at (ram,0x0047c2e9)
// 
// WARNING: Control flow encountered bad instruction data

void entry(void)

{
  char cVar1;
  undefined uVar2;
  char cVar3;
  undefined4 uVar4;
  byte bVar5;
  uint uVar6;
  HMODULE hModule;
  FARPROC pFVar7;
  int iVar8;
  int iVar9;
  DWORD *pDVar10;
  undefined4 *puVar11;
  uint uVar12;
  uint uVar13;
  FARPROC *ppFVar14;
  uint unaff_EBP;
  uint *puVar15;
  UINT unaff_EDI;
  undefined4 *puVar16;
  DWORD *lpProcName;
  DWORD *pDVar17;
  DWORD *pDVar18;
  bool bVar19;
  bool bVar20;
  bool bVar21;
  undefined local_80 [72];
  undefined4 uStackY_38;
  DWORD flNewProtect;
  
  puVar15 = &DAT_00431000;
  puVar16 = (undefined4 *)&DAT_00401000;
  do {
    uVar12 = *puVar15;
    bVar19 = puVar15 < (uint *)0xfffffffc;
    puVar15 = puVar15 + 1;
    bVar20 = CARRY4(uVar12,uVar12) || CARRY4(uVar12 * 2,(uint)bVar19);
    uVar12 = uVar12 * 2 + (uint)bVar19;
    do {
      if (bVar20) {
        uVar2 = *(undefined *)puVar15;
        puVar15 = (uint *)((int)puVar15 + 1);
        *(undefined *)puVar16 = uVar2;
        puVar16 = (undefined4 *)((int)puVar16 + 1);
      }
      else {
        uVar6 = 1;
        do {
          do {
            bVar19 = CARRY4(uVar12,uVar12);
            uVar13 = uVar12 * 2;
            if (uVar13 == 0) {
              uVar12 = *puVar15;
              bVar20 = puVar15 < (uint *)0xfffffffc;
              puVar15 = puVar15 + 1;
              bVar19 = CARRY4(uVar12,uVar12) || CARRY4(uVar12 * 2,(uint)bVar20);
              uVar13 = uVar12 * 2 + (uint)bVar20;
            }
            uVar6 = uVar6 * 2 + (uint)bVar19;
            uVar12 = uVar13 * 2;
          } while (!CARRY4(uVar13,uVar13));
          if (uVar12 != 0) break;
          uVar13 = *puVar15;
          bVar19 = puVar15 < (uint *)0xfffffffc;
          puVar15 = puVar15 + 1;
          uVar12 = uVar13 * 2 + (uint)bVar19;
        } while (!CARRY4(uVar13,uVar13) && !CARRY4(uVar13 * 2,(uint)bVar19));
        if (2 < uVar6) {
          uVar2 = *(undefined *)puVar15;
          puVar15 = (uint *)((int)puVar15 + 1);
          unaff_EBP = CONCAT31((int3)uVar6 + -3,uVar2) ^ 0xffffffff;
          if (unaff_EBP == 0) {
            puVar16 = (undefined4 *)&DAT_00401000;
            iVar8 = 0x27c00;
            goto LAB_0047c2a6;
          }
        }
        bVar19 = CARRY4(uVar12,uVar12);
        uVar12 = uVar12 * 2;
        if (uVar12 == 0) {
          uVar12 = *puVar15;
          bVar20 = puVar15 < (uint *)0xfffffffc;
          puVar15 = puVar15 + 1;
          bVar19 = CARRY4(uVar12,uVar12) || CARRY4(uVar12 * 2,(uint)bVar20);
          uVar12 = uVar12 * 2 + (uint)bVar20;
        }
        bVar20 = CARRY4(uVar12,uVar12);
        uVar12 = uVar12 * 2;
        if (uVar12 == 0) {
          uVar12 = *puVar15;
          bVar21 = puVar15 < (uint *)0xfffffffc;
          puVar15 = puVar15 + 1;
          bVar20 = CARRY4(uVar12,uVar12) || CARRY4(uVar12 * 2,(uint)bVar21);
          uVar12 = uVar12 * 2 + (uint)bVar21;
        }
        iVar8 = (uint)bVar19 * 2 + (uint)bVar20;
        if (iVar8 == 0) {
          iVar8 = 1;
          do {
            do {
              bVar19 = CARRY4(uVar12,uVar12);
              uVar6 = uVar12 * 2;
              if (uVar6 == 0) {
                uVar12 = *puVar15;
                bVar20 = puVar15 < (uint *)0xfffffffc;
                puVar15 = puVar15 + 1;
                bVar19 = CARRY4(uVar12,uVar12) || CARRY4(uVar12 * 2,(uint)bVar20);
                uVar6 = uVar12 * 2 + (uint)bVar20;
              }
              iVar8 = iVar8 * 2 + (uint)bVar19;
              uVar12 = uVar6 * 2;
            } while (!CARRY4(uVar6,uVar6));
            if (uVar12 != 0) break;
            uVar6 = *puVar15;
            bVar19 = puVar15 < (uint *)0xfffffffc;
            puVar15 = puVar15 + 1;
            uVar12 = uVar6 * 2 + (uint)bVar19;
          } while (!CARRY4(uVar6,uVar6) && !CARRY4(uVar6 * 2,(uint)bVar19));
          iVar8 = iVar8 + 2;
        }
        uVar6 = iVar8 + 1 + (uint)(unaff_EBP < 0xfffff300);
        puVar11 = (undefined4 *)((int)puVar16 + unaff_EBP);
        if (unaff_EBP < 0xfffffffd) {
          do {
            uVar4 = *puVar11;
            puVar11 = puVar11 + 1;
            *puVar16 = uVar4;
            puVar16 = puVar16 + 1;
            bVar19 = 3 < uVar6;
            uVar6 = uVar6 - 4;
          } while (bVar19 && uVar6 != 0);
          puVar16 = (undefined4 *)((int)puVar16 + uVar6);
        }
        else {
          do {
            uVar2 = *(undefined *)puVar11;
            puVar11 = (undefined4 *)((int)puVar11 + 1);
            *(undefined *)puVar16 = uVar2;
            puVar16 = (undefined4 *)((int)puVar16 + 1);
            uVar6 = uVar6 - 1;
          } while (uVar6 != 0);
        }
      }
      bVar20 = CARRY4(uVar12,uVar12);
      uVar12 = uVar12 * 2;
    } while (uVar12 != 0);
  } while( true );
LAB_0047c2a6:
  bVar5 = *(byte *)puVar16;
  puVar16 = (undefined4 *)((int)puVar16 + 1);
  iVar8 = iVar8 + -5;
  iVar9 = iVar8;
  puVar11 = puVar16;
  if (iVar8 != 0) goto LAB_0047c287;
LAB_0047c2b0:
  do {
    iVar8 = iVar9 + -1;
    if (iVar8 == 0 || iVar9 < 1) {
      lpProcName = &DAT_0047a000;
      do {
        flNewProtect = *lpProcName;
        if (flNewProtect == 0) {
          uStackY_38 = 0x47c31f;
          VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,4,(PDWORD)&stack0xffffffdc);
                    // WARNING: Read-only address (ram,0x0040020f) is written
          IMAGE_SECTION_HEADER_004001e8.Characteristics._3_1_ = 0x60;
                    // WARNING: Read-only address (ram,0x00400237) is written
          IMAGE_SECTION_HEADER_00400210.Characteristics._3_1_ = 0x60;
          uStackY_38 = 0x47c334;
          VirtualProtect(&IMAGE_DOS_HEADER_00400000,0x1000,flNewProtect,(PDWORD)&stack0xffffffdc);
          do {
          } while (&stack0x00000000 != local_80);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        ppFVar14 = (FARPROC *)(&DAT_00401000 + lpProcName[1]);
        pDVar18 = lpProcName + 2;
        hModule = LoadLibraryA((LPCSTR)((int)&DWORD_0047d5f0 + flNewProtect));
        while( true ) {
          cVar3 = *(char *)pDVar18;
          lpProcName = (DWORD *)((int)pDVar18 + 1);
          if (cVar3 == '\0') break;
          if (cVar3 < '\0') {
            lpProcName = (DWORD *)(uint)*(ushort *)lpProcName;
            pDVar18 = (DWORD *)((int)pDVar18 + 3);
          }
          else {
            pDVar10 = lpProcName;
            pDVar17 = lpProcName;
            do {
              pDVar18 = pDVar17;
              if (pDVar10 == (DWORD *)0x0) break;
              pDVar10 = (DWORD *)((int)pDVar10 + -1);
              pDVar18 = (DWORD *)((int)pDVar17 + 1);
              cVar1 = *(char *)pDVar17;
              pDVar17 = pDVar18;
            } while ((char)(cVar3 + -1) != cVar1);
          }
          pFVar7 = GetProcAddress(hModule,(LPCSTR)lpProcName);
          if (pFVar7 == (FARPROC)0x0) {
                    // WARNING: Subroutine does not return
            ExitProcess(unaff_EDI);
          }
          *ppFVar14 = pFVar7;
          ppFVar14 = ppFVar14 + 1;
        }
      } while( true );
    }
    bVar5 = *(byte *)puVar11;
    puVar16 = (undefined4 *)((int)puVar11 + 1);
    if (((bVar5 < 0x80) || (0x8f < bVar5)) || (*(char *)((int)puVar11 + -1) != '\x0f')) {
LAB_0047c287:
      iVar9 = iVar8;
      puVar11 = puVar16;
      if (1 < (byte)(bVar5 + 0x18)) goto LAB_0047c2b0;
    }
    iVar9 = iVar8;
    puVar11 = puVar16;
  } while (*(char *)puVar16 != '\x11');
  uVar4 = *puVar16;
  *puVar16 = &DAT_00401000 +
             (CONCAT31(CONCAT21((ushort)uVar4 >> 8,(char)((uint)uVar4 >> 0x10)),
                       (char)((uint)uVar4 >> 0x18)) - (int)puVar16);
  puVar16 = puVar16 + 1;
  goto LAB_0047c2a6;
}


