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

typedef long HRESULT;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef DWORD ACCESS_MASK;

typedef WCHAR *LPCWSTR;

typedef void *HANDLE;

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

typedef uint UINT_PTR;

typedef ulong ULONG_PTR;

typedef ULONG_PTR SIZE_T;

typedef long LONG_PTR;

typedef DWORD ULONG;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[64];
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

typedef HANDLE *LPHANDLE;

typedef UINT_PTR WPARAM;

typedef int INT;

typedef struct HMENU__ HMENU__, *PHMENU__;

struct HMENU__ {
    int unused;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef LONG_PTR LRESULT;

typedef struct HKEY__ *HKEY;

typedef uchar BYTE;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef int BOOL;

typedef struct HMENU__ *HMENU;

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

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
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

typedef LONG LSTATUS;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IUnknown IUnknown, *PIUnknown;

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




// WARNING: Instruction at (ram,0x0040f526) overlaps instruction at (ram,0x0040f525)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Restarted to delay deadcode elimination for space: ram

void __fastcall
entry(uint param_1,int param_2,int param_3,undefined4 param_4,int param_5,uint param_6)

{
  char *pcVar1;
  ushort *puVar2;
  byte *pbVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  code *pcVar6;
  void *pvVar7;
  float10 fVar8;
  byte bVar9;
  int iVar11;
  int iVar12;
  int unaff_EBX;
  int unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  bool bVar13;
  byte in_AF;
  float10 in_ST0;
  float10 in_ST1;
  float10 in_ST2;
  float10 fVar14;
  float10 in_ST3;
  float10 in_ST4;
  float10 in_ST5;
  float10 in_ST6;
  float10 in_ST7;
  void *pvStack_8;
  undefined *puStack_4;
  char cVar10;
  
  do {
    pvVar7 = ExceptionList;
    puStack_4 = &LAB_0044924c;
    pvStack_8 = ExceptionList;
    out(*unaff_ESI,(short)param_2);
    uVar5 = in((short)param_2);
    uRam00000000 = param_1;
    ExceptionList = &pvStack_8;
    *unaff_EDI = uVar5;
    if (SCARRY4(unaff_EBX,1)) {
      unaff_ESI[-0x1e25060a] = unaff_ESI[-0x1e25060a] + param_2 + 1;
      *(int *)(unaff_EBP + 0x5bd4a7c0) = (int)ROUND(in_ST0);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    puVar4 = (undefined2 *)((int)unaff_ESI + param_2 + 4);
    *puVar4 = *puVar4;
    pcVar1 = (char *)(param_2 + 0x62);
    *pcVar1 = *pcVar1;
    bVar13 = *pcVar1 < '\0';
    fVar8 = in_ST0;
    in_ST0 = in_ST2;
    fVar14 = in_ST3;
    in_ST2 = in_ST4;
    in_ST3 = in_ST5;
    in_ST4 = in_ST6;
    in_ST6 = in_ST7;
    while( true ) {
      in_ST5 = in_ST4;
      in_ST4 = in_ST3;
      in_ST3 = in_ST2;
      in_ST2 = fVar14;
      fVar14 = in_ST0;
      in_ST0 = in_ST1;
      in_ST1 = fVar8;
      *(char *)(param_5 + -0x67fbbfa2) = (*(char *)(param_5 + -0x67fbbfa2) - (byte)param_4) - bVar13
      ;
                    // WARNING: Load size is inaccurate
      iVar11 = param_5 + -1;
      if (iVar11 != 0 && (byte)((byte)param_4 | *pvVar7) == 0) break;
      pbVar3 = (byte *)(param_3 + 0x6f107552);
      bVar13 = *pbVar3 < (byte)param_3;
      *pbVar3 = *pbVar3 - (byte)param_3;
      fVar8 = fVar14;
      in_ST6 = in_ST5;
      if (!bVar13) {
        pcVar6 = (code *)swi(3);
        (*pcVar6)();
        return;
      }
    }
    unaff_EDI = (undefined4 *)((int)&uRam00000000 + 1);
    LOCK();
    unaff_EBP = *(int *)(param_3 + -0x79d137d6);
    *(int *)(param_3 + -0x79d137d6) = (int)&LAB_0044924c;
    UNLOCK();
    unaff_EBX = CONCAT31((int3)((uint)param_3 >> 8),0xd0);
    param_1 = param_6 | 0x91f0d21b;
    iVar12 = CONCAT31(CONCAT21((short)((uint)param_4 >> 0x10),
                               ((char)((uint)param_4 >> 8) - *(char *)(unaff_EBP + 8 + iVar11 * 4))
                               - ((byte)((byte)param_6 | 0x1a) < (byte)uRam00000000)),0x65);
    in_AF = 9 < ((byte)iVar11 & 0xf) | in_AF;
    bVar9 = (byte)iVar11 + in_AF * -6;
    cVar10 = bVar9 + (0x9f < bVar9 | in_AF * (bVar9 < 6)) * -0x60;
    param_2 = CONCAT31((int3)((uint)iVar11 >> 8),cVar10);
    fRamd2abafe7 = (float)in_ST1;
                    // WARNING: Load size is inaccurate
    *(byte *)pvVar7 = *pvVar7 << 3 | *pvVar7 >> 5;
                    // WARNING: Load size is inaccurate
    unaff_ESI = (undefined4 *)((int)pvVar7 + 1);
    out(*pvVar7,(short)iVar12);
    in_ST1 = in_ST0 - fVar14;
    puVar2 = (ushort *)(param_1 + 0xb8ddfcaa);
    *puVar2 = *puVar2 + (ushort)((*pvVar7 & 1) != 0) * (((ushort)param_1 & 3) - (*puVar2 & 3));
    pcVar1 = (char *)(iVar12 + 100);
    *pcVar1 = *pcVar1 + cVar10;
    in_ST7 = in_ST6;
  } while( true );
}



// WARNING: Restarted to delay deadcode elimination for space: stack

int FUN_0044905a(short *param_1,int *param_2)

{
  undefined uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int extraout_ECX;
  int extraout_ECX_00;
  int extraout_ECX_01;
  int extraout_ECX_02;
  undefined *puVar5;
  int *piVar6;
  int *piVar7;
  undefined uVar8;
  char local_d;
  
  piVar7 = param_2;
  if (*param_1 == 0x434a) {
LAB_00449087:
    while( true ) {
      uVar8 = false;
      FUN_004491f0();
      if (!(bool)uVar8) break;
      iVar2 = FUN_00449208();
      uVar3 = (uint)(byte)((char)iVar2 + local_d);
LAB_0044909b:
      *(char *)piVar7 = (char)uVar3;
      piVar7 = (int *)((int)piVar7 + 1);
    }
    FUN_004491f0();
    if ((bool)uVar8) {
      FUN_00449214();
      if (extraout_ECX_00 == 2) {
        uVar3 = FUN_00449214();
        iVar2 = extraout_ECX_01;
        goto LAB_0044918b;
      }
      FUN_00449208();
      uVar3 = FUN_00449214();
      iVar2 = extraout_ECX_02;
      if (uVar3 < 0x10000) {
        if (uVar3 < 0x37ff) {
          if (0x27e < uVar3) goto LAB_0044918a;
          if (0x7f < uVar3) goto LAB_0044918b;
          iVar2 = extraout_ECX_02 + 1;
          goto LAB_00449188;
        }
      }
      else {
LAB_00449188:
        iVar2 = iVar2 + 1;
      }
      iVar2 = iVar2 + 1;
LAB_0044918a:
      iVar2 = iVar2 + 1;
LAB_0044918b:
      puVar5 = (undefined *)((int)piVar7 - uVar3);
      for (; iVar2 != 0; iVar2 = iVar2 + -1) {
        *(undefined *)piVar7 = *puVar5;
        puVar5 = puVar5 + 1;
        piVar7 = (int *)((int)piVar7 + 1);
      }
      goto LAB_00449087;
    }
    FUN_004491f0();
    if ((bool)uVar8) {
      iVar2 = FUN_00449208();
      uVar3 = iVar2 - 1;
      if (uVar3 == 0) goto LAB_0044909b;
      iVar2 = extraout_ECX;
      if (-1 < (int)uVar3) goto LAB_0044918a;
      FUN_004491f0();
      if ((bool)uVar8) {
        do {
          iVar2 = 0x100;
          do {
            uVar1 = FUN_004491fd();
            *(undefined *)piVar7 = uVar1;
            piVar7 = (int *)((int)piVar7 + 1);
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
          FUN_004491f0();
        } while ((bool)uVar8);
      }
      else {
        iVar2 = FUN_00449208();
        local_d = '\0';
        if (iVar2 != 1) {
          local_d = FUN_004491fd();
        }
      }
      goto LAB_00449087;
    }
    uVar3 = FUN_00449208();
    iVar2 = FUN_00449208();
    iVar2 = iVar2 + 2;
    if (uVar3 != 0) goto LAB_0044918b;
    if (iVar2 != 2) {
      FUN_00449208();
      goto LAB_00449087;
    }
  }
  if (*(int *)(param_1 + 3) != 0) {
    uVar3 = *(uint *)(param_1 + 1);
    uVar4 = 0;
    piVar6 = param_2;
    if (3 < uVar3) {
      while( true ) {
        iVar2 = *piVar6;
        uVar4 = uVar4 + iVar2 ^ iVar2 * 2 + 1 + (uint)(iVar2 < 0);
        piVar6 = piVar6 + 1;
        uVar3 = uVar3 - 4;
        if (uVar3 == 0) break;
        if (uVar3 < 4) {
          iVar2 = 4 - uVar3;
          uVar3 = 4;
          piVar6 = (int *)((int)piVar6 - iVar2);
        }
      }
    }
    if (uVar4 != *(uint *)(param_1 + 3)) {
      return 0;
    }
  }
  return (int)piVar7 - (int)param_2;
}



void FUN_004491f0(void)

{
  return;
}



void FUN_004491fd(void)

{
  FUN_00449208();
  return;
}



int FUN_00449208(void)

{
  uint uVar1;
  uint uVar2;
  int extraout_ECX;
  byte bVar3;
  
  bVar3 = false;
  do {
    uVar2 = FUN_004491f0();
    uVar1 = (uint)bVar3;
    bVar3 = CARRY4(uVar2,uVar2) || CARRY4(uVar2 * 2,uVar1);
  } while (extraout_ECX != 1);
  return uVar2 * 2 + uVar1;
}



void FUN_00449214(void)

{
  uint extraout_ECX;
  byte bVar1;
  
  bVar1 = 0;
  do {
    FUN_004491f0();
    bVar1 = CARRY4(extraout_ECX,extraout_ECX) || CARRY4(extraout_ECX * 2,(uint)bVar1);
    FUN_004491f0();
  } while ((bool)bVar1);
  return;
}


