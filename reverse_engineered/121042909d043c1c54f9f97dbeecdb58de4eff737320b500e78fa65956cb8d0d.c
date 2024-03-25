typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG MSG;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef ulong DWORD;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

typedef long LONG;

struct tagPOINT {
    LONG x;
    LONG y;
};

struct tagMSG {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
};

struct HWND__ {
    int unused;
};

typedef struct tagWNDCLASSA tagWNDCLASSA, *PtagWNDCLASSA;

typedef struct tagWNDCLASSA WNDCLASSA;

typedef LONG_PTR LRESULT;

typedef LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HICON__ HICON__, *PHICON__;

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

typedef struct HBRUSH__ *HBRUSH;

typedef char CHAR;

typedef CHAR *LPCSTR;

struct HBRUSH__ {
    int unused;
};

struct tagWNDCLASSA {
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCSTR lpszMenuName;
    LPCSTR lpszClassName;
};

struct HICON__ {
    int unused;
};

struct HINSTANCE__ {
    int unused;
};

typedef struct tagMSG *LPMSG;

typedef void (*TIMERPROC)(HWND, UINT, UINT_PTR, DWORD);

typedef struct tagLOGBRUSH tagLOGBRUSH, *PtagLOGBRUSH;

typedef struct tagLOGBRUSH LOGBRUSH;

typedef DWORD COLORREF;

typedef ulong ULONG_PTR;

struct tagLOGBRUSH {
    UINT lbStyle;
    COLORREF lbColor;
    ULONG_PTR lbHatch;
};

typedef struct _devicemodeA _devicemodeA, *P_devicemodeA;

typedef uchar BYTE;

typedef ushort WORD;

typedef union _union_655 _union_655, *P_union_655;

typedef union _union_658 _union_658, *P_union_658;

typedef struct _struct_656 _struct_656, *P_struct_656;

typedef struct _struct_657 _struct_657, *P_struct_657;

typedef struct _POINTL _POINTL, *P_POINTL;

typedef struct _POINTL POINTL;

struct _POINTL {
    LONG x;
    LONG y;
};

struct _struct_657 {
    POINTL dmPosition;
    DWORD dmDisplayOrientation;
    DWORD dmDisplayFixedOutput;
};

struct _struct_656 {
    short dmOrientation;
    short dmPaperSize;
    short dmPaperLength;
    short dmPaperWidth;
    short dmScale;
    short dmCopies;
    short dmDefaultSource;
    short dmPrintQuality;
};

union _union_655 {
    struct _struct_656 field0;
    struct _struct_657 field1;
};

union _union_658 {
    DWORD dmDisplayFlags;
    DWORD dmNup;
};

struct _devicemodeA {
    BYTE dmDeviceName[32];
    WORD dmSpecVersion;
    WORD dmDriverVersion;
    WORD dmSize;
    WORD dmDriverExtra;
    DWORD dmFields;
    union _union_655 field6_0x2c;
    short dmColor;
    short dmDuplex;
    short dmYResolution;
    short dmTTOption;
    short dmCollate;
    BYTE dmFormName[32];
    WORD dmLogPixels;
    DWORD dmBitsPerPel;
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    union _union_658 field17_0x74;
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

typedef struct _devicemodeA DEVMODEA;

typedef struct _GUID _GUID, *P_GUID;

typedef struct _GUID GUID;

typedef GUID CLSID;

typedef CLSID *LPCLSID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef GUID IID;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef CHAR *LPSTR;

typedef BYTE *LPBYTE;

typedef void *HANDLE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _MEMORYSTATUS _MEMORYSTATUS, *P_MEMORYSTATUS;

typedef ULONG_PTR SIZE_T;

struct _MEMORYSTATUS {
    DWORD dwLength;
    DWORD dwMemoryLoad;
    SIZE_T dwTotalPhys;
    SIZE_T dwAvailPhys;
    SIZE_T dwTotalPageFile;
    SIZE_T dwAvailPageFile;
    SIZE_T dwTotalVirtual;
    SIZE_T dwAvailVirtual;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef union _union_518 _union_518, *P_union_518;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _MEMORYSTATUS *LPMEMORYSTATUS;

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef wchar_t WCHAR;

typedef PVOID PSECURITY_DESCRIPTOR;

typedef long HRESULT;

typedef struct _MEMORY_BASIC_INFORMATION *PMEMORY_BASIC_INFORMATION;

typedef LONG *PLONG;

typedef struct _ACL _ACL, *P_ACL;

struct _ACL {
    BYTE AclRevision;
    BYTE Sbz1;
    WORD AclSize;
    WORD AceCount;
    WORD Sbz2;
};

typedef struct _ACL ACL;

typedef ACL *PACL;

typedef struct _OSVERSIONINFOA _OSVERSIONINFOA, *P_OSVERSIONINFOA;

struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
};

typedef struct _OSVERSIONINFOA *LPOSVERSIONINFOA;

typedef PVOID PSID;

typedef DWORD SECURITY_INFORMATION;

typedef DWORD ACCESS_MASK;

typedef WCHAR *LPCWSTR;

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

typedef WCHAR OLECHAR;

typedef OLECHAR *BSTR;

typedef DWORD ULONG;

typedef OLECHAR *LPCOLESTR;

typedef struct HFONT__ HFONT__, *PHFONT__;

typedef struct HFONT__ *HFONT;

struct HFONT__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef struct HDESK__ HDESK__, *PHDESK__;

struct HDESK__ {
    int unused;
};

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ *HMENU;

struct HMENU__ {
    int unused;
};

typedef int (*FARPROC)(void);

typedef struct HDC__ *HDC;

typedef struct tagRECT tagRECT, *PtagRECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef WORD ATOM;

typedef struct tagRECT *LPRECT;

typedef BOOL *LPBOOL;

typedef void *HGDIOBJ;

typedef void *LPCVOID;

typedef struct HDESK__ *HDESK;

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

typedef enum _TRUSTEE_FORM {
    TRUSTEE_IS_SID=0,
    TRUSTEE_IS_NAME=1,
    TRUSTEE_BAD_FORM=2,
    TRUSTEE_IS_OBJECTS_AND_SID=3,
    TRUSTEE_IS_OBJECTS_AND_NAME=4
} _TRUSTEE_FORM;

typedef enum _MULTIPLE_TRUSTEE_OPERATION {
    NO_MULTIPLE_TRUSTEE=0,
    TRUSTEE_IS_IMPERSONATE=1
} _MULTIPLE_TRUSTEE_OPERATION;

typedef enum _TRUSTEE_FORM TRUSTEE_FORM;

typedef enum _SE_OBJECT_TYPE {
    SE_UNKNOWN_OBJECT_TYPE=0,
    SE_FILE_OBJECT=1,
    SE_SERVICE=2,
    SE_PRINTER=3,
    SE_REGISTRY_KEY=4,
    SE_LMSHARE=5,
    SE_KERNEL_OBJECT=6,
    SE_WINDOW_OBJECT=7,
    SE_DS_OBJECT=8,
    SE_DS_OBJECT_ALL=9,
    SE_PROVIDER_DEFINED_OBJECT=10,
    SE_WMIGUID_OBJECT=11,
    SE_REGISTRY_WOW64_32KEY=12
} _SE_OBJECT_TYPE;

typedef enum _ACCESS_MODE {
    NOT_USED_ACCESS=0,
    GRANT_ACCESS=1,
    SET_ACCESS=2,
    DENY_ACCESS=3,
    REVOKE_ACCESS=4,
    SET_AUDIT_SUCCESS=5,
    SET_AUDIT_FAILURE=6
} _ACCESS_MODE;

typedef struct _EXPLICIT_ACCESS_A _EXPLICIT_ACCESS_A, *P_EXPLICIT_ACCESS_A;

typedef enum _ACCESS_MODE ACCESS_MODE;

typedef struct _TRUSTEE_A _TRUSTEE_A, *P_TRUSTEE_A;

typedef struct _TRUSTEE_A TRUSTEE_A;

typedef enum _MULTIPLE_TRUSTEE_OPERATION MULTIPLE_TRUSTEE_OPERATION;

typedef enum _TRUSTEE_TYPE {
    TRUSTEE_IS_UNKNOWN=0,
    TRUSTEE_IS_USER=1,
    TRUSTEE_IS_GROUP=2,
    TRUSTEE_IS_DOMAIN=3,
    TRUSTEE_IS_ALIAS=4,
    TRUSTEE_IS_WELL_KNOWN_GROUP=5,
    TRUSTEE_IS_DELETED=6,
    TRUSTEE_IS_INVALID=7,
    TRUSTEE_IS_COMPUTER=8
} _TRUSTEE_TYPE;

typedef enum _TRUSTEE_TYPE TRUSTEE_TYPE;

struct _TRUSTEE_A {
    struct _TRUSTEE_A *pMultipleTrustee;
    MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
    TRUSTEE_FORM TrusteeForm;
    TRUSTEE_TYPE TrusteeType;
    LPSTR ptstrName;
};

struct _EXPLICIT_ACCESS_A {
    DWORD grfAccessPermissions;
    ACCESS_MODE grfAccessMode;
    DWORD grfInheritance;
    TRUSTEE_A Trustee;
};

typedef struct _EXPLICIT_ACCESS_A *PEXPLICIT_ACCESS_A;

typedef enum _SE_OBJECT_TYPE SE_OBJECT_TYPE;

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef char *va_list;

typedef uint size_t;

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




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004014c2) overlaps instruction at (ram,0x004014bf)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x004012bf)
// WARNING: Removing unreachable block (ram,0x004014ca)
// WARNING: Removing unreachable block (ram,0x00401576)
// WARNING: Removing unreachable block (ram,0x00401489)
// WARNING: Removing unreachable block (ram,0x0040149a)
// WARNING: Removing unreachable block (ram,0x0040149c)
// WARNING: Removing unreachable block (ram,0x004014c7)
// WARNING: Removing unreachable block (ram,0x004014c9)
// WARNING: Removing unreachable block (ram,0x00401471)
// WARNING: Removing unreachable block (ram,0x004014e6)
// WARNING: Removing unreachable block (ram,0x00401475)
// WARNING: Removing unreachable block (ram,0x00401477)
// WARNING: Removing unreachable block (ram,0x004014cb)
// WARNING: Removing unreachable block (ram,0x00401492)
// WARNING: Removing unreachable block (ram,0x00401494)
// WARNING: Removing unreachable block (ram,0x004014ce)
// WARNING: Removing unreachable block (ram,0x004014de)
// WARNING: Removing unreachable block (ram,0x004014aa)
// WARNING: Removing unreachable block (ram,0x00401478)
// WARNING: Removing unreachable block (ram,0x004014ad)
// WARNING: Removing unreachable block (ram,0x0040149e)
// WARNING: Removing unreachable block (ram,0x004014a4)
// WARNING: Removing unreachable block (ram,0x004014ba)
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint * __fastcall
FUN_00401219(int param_1,uint param_2,uint **param_3,undefined2 *param_4,undefined *param_5)

{
  char *pcVar1;
  ushort *puVar2;
  byte *pbVar3;
  double *pdVar4;
  code *pcVar5;
  char cVar6;
  undefined uVar7;
  int in_EAX;
  undefined3 uVar13;
  undefined4 uVar8;
  byte **ppbVar9;
  uint *puVar10;
  uint uVar11;
  undefined *puVar12;
  int iVar14;
  int extraout_ECX;
  undefined2 uVar15;
  byte bVar17;
  uint unaff_EBX;
  undefined2 uVar19;
  uint uVar18;
  uint unaff_EBP;
  uint uVar20;
  uint *unaff_ESI;
  uint *puVar21;
  byte **unaff_EDI;
  byte bVar22;
  byte bVar23;
  bool bVar24;
  char in_SF;
  char in_OF;
  float10 extraout_ST0;
  float10 extraout_ST0_00;
  unkbyte10 in_ST1;
  unkbyte10 in_ST2;
  unkbyte10 in_ST3;
  unkbyte10 in_ST4;
  unkbyte10 in_ST5;
  unkbyte10 in_ST6;
  unkbyte10 in_ST7;
  undefined8 uVar25;
  undefined6 uVar26;
  float in_stack_82d14fdf;
  undefined4 local_4;
  char cVar16;
  
  if (in_OF == in_SF) {
    local_4._0_2_ = 0x1834;
    local_4._2_1_ = 0xe1;
    local_4._3_1_ = 0x3d;
    unaff_EBP = 0x5c978bfd;
    uVar13 = (undefined3)((uint)in_EAX >> 8);
    cVar6 = (char)in_EAX + '!';
    uVar20 = CONCAT31(uVar13,cVar6);
    pbVar3 = (byte *)(uVar20 + (int)unaff_ESI * 2);
    bVar17 = (byte)(param_2 >> 8);
    uVar7 = (undefined)param_2;
    cVar16 = bVar17 - *pbVar3;
    uVar15 = CONCAT11(cVar16,uVar7);
    param_2 = CONCAT22((short)(param_2 >> 0x10),uVar15);
    ppbVar9 = unaff_EDI;
    if ((POPCOUNT(cVar16) & 1U) == 0) {
      if (cVar16 != '\0') {
        *(char *)(param_2 - 0x7c) =
             (*(char *)(param_2 - 0x7c) - (char)((uint)in_EAX >> 8)) - (bVar17 < *pbVar3);
        uVar20 = CONCAT31(uVar13,cVar6) & 0xffffff41;
      }
      uVar20 = (uint)*(undefined6 *)(uVar20 + 0x37);
      unaff_EBP = uVar20 >> 0xc | uVar20 << 0x14;
    }
    else {
      while( true ) {
        unaff_EDI = (byte **)CONCAT22((short)(unaff_EBX >> 0x10),CONCAT11(0x3f,(byte)unaff_EBX));
        bVar17 = (byte)unaff_EBX & *(byte *)(param_1 + 0x187fce0e);
        unaff_EBX = CONCAT31((int3)((uint)unaff_EDI >> 8),bVar17);
        bVar24 = bVar17 == 0;
        if (param_1 == 1 || !bVar24) {
          cVar6 = (char)ppbVar9;
          ppbVar9 = (byte **)((uint)ppbVar9 ^ 0x72);
          bVar24 = cVar6 == 'r';
        }
        cVar6 = (char)ppbVar9;
        if (param_1 != 2 && bVar24) break;
        param_1 = param_1 + -3;
        ppbVar9 = unaff_EDI;
        in_ST1 = in_ST2;
        in_ST2 = in_ST3;
        in_ST3 = in_ST4;
        in_ST4 = in_ST5;
        in_ST5 = in_ST6;
        in_ST6 = in_ST7;
        if (param_1 != 0 && (cVar6 + 6U & 4) != 0) {
          *(undefined *)(unaff_EBX + 0x2a) = uVar7;
          pcVar5 = (code *)swi(3);
          puVar21 = (uint *)(*pcVar5)();
          return puVar21;
        }
      }
      if (param_1 == 3 || !bVar24) {
        ppbVar9 = (byte **)((uint)ppbVar9 ^ 0x70);
        bVar24 = cVar6 == 'p';
      }
      bVar23 = 1;
      iVar14 = param_1 + -4;
      if (iVar14 != 0 && bVar24) {
        pcVar1 = (char *)(param_1 + 0x1856f912);
        *pcVar1 = *pcVar1 + bVar17;
        if (iVar14 == 1 || *pcVar1 != '\0') {
          param_2 = param_2 | unaff_EBX;
          ffree(in_ST1);
          *unaff_EDI = (byte *)ppbVar9;
          puVar21 = (uint *)((int)unaff_ESI + 1);
          bVar17 = (byte)(unaff_EDI + 1);
          puVar10 = (uint *)CONCAT31((int3)(CONCAT22((short)((uint)(unaff_EDI + 1) >> 0x10),
                                                     CONCAT11(bVar17 / 0xd0,bVar17)) >> 8),
                                     bVar17 % 0xd0);
          do {
            bVar24 = unaff_EBX < *puVar10;
            unaff_EBX = unaff_EBX - *puVar10;
            if ((int)param_3 + -1 != 0 && unaff_EBX == 0) {
              return puVar21;
            }
            bVar17 = (byte)((int)param_3 + -1) & 0x1f;
            uVar20 = *(uint *)((int)param_3 + -0x1978679d);
            *(uint *)((int)param_3 + -0x1978679d) =
                 uVar20 << bVar17 | (uint)(CONCAT14(bVar24,uVar20) >> 0x21 - bVar17);
            param_3 = (uint **)((int)param_3 + -2);
          } while (param_3 != (uint **)0x0 && unaff_EBX == 0);
          unaff_EDI = (byte **)&DAT_b4dbfd33;
          iVar14 = iRam16991083;
          if (param_3 == (uint **)0x1 || ppbVar9 != (byte **)0xffffffff) {
            cVar6 = ((uint)puVar10 | 0x5e4f6278) == 0;
            uVar26 = func_0xe18dfa57();
            puVar12 = _DAT_22d16a37;
            uVar15 = (undefined2)((uint6)uVar26 >> 0x20);
            if (extraout_ECX == 1 || cVar6 == '\0') {
              in(uVar15);
              return &local_4;
            }
            bVar24 = _DAT_22d16a37 < (undefined *)0x3eb0fdbd;
            while( true ) {
              puVar2 = (ushort *)((int)unaff_EDI + 0x25683c1f);
              *puVar2 = *puVar2 + (ushort)bVar24 * -(*puVar2 & 3);
              local_4._0_2_ = 0x590;
              local_4._2_1_ = 0xe0;
              local_4._3_1_ = 0x68;
              unaff_EDI = unaff_EDI + 1;
              bVar17 = (byte)unaff_EBX;
              uVar19 = (undefined2)(unaff_EBX >> 0x10);
              if (&local_4 < (undefined *)0xa3c7e2a3) break;
              bVar24 = false;
              unaff_EBX = CONCAT22(uVar19,(ushort)bVar17);
            }
            uVar7 = in(uVar15);
            *puVar12 = uVar7;
            uVar8 = in(uVar15);
            *(undefined4 *)(puVar12 + 1) = uVar8;
            *(byte *)puVar21 = *(byte *)puVar21 | bVar17;
            uVar20 = ((uint)(puVar12 + 5) | 0x1e) + 0x535a9d10 ^ 0x18;
            iVar14 = uVar20 + 0x5630ad8;
            cVar6 = (char)((uint)iVar14 >> 8);
            bVar23 = 9 < ((byte)iVar14 & 0xf) | bVar23;
            bVar22 = (byte)iVar14 + bVar23 * '\x06';
            uVar11 = CONCAT31((int3)((uint)iVar14 >> 8),bVar22) & 0xffffff0f;
            uVar7 = (undefined)uVar11;
            uVar11 = CONCAT31((int3)(CONCAT22((short)(uVar11 >> 0x10),CONCAT11(cVar6 + bVar23,uVar7)
                                             ) >> 8),uVar7) & 0xffffff4b;
            bVar24 = (bVar22 & 0xb) == 0;
            uVar18 = CONCAT22(uVar19,CONCAT11(0x3f,bVar17));
            iVar14 = CONCAT31((int3)((uint)&stack0x5c381d5c >> 8),
                              ((char)&stack0x5c381d5c - cVar6) - (0xfa9cf527 < uVar20)) + -1;
            puVar10 = (uint *)&DAT_71afed6d;
            if (iVar14 != 0 && !bVar24) {
              for (; iVar14 != 0; iVar14 = iVar14 + -1) {
                *puVar10 = *puVar21;
                puVar21 = puVar21 + 1;
                puVar10 = puVar10 + 1;
              }
              if (bVar24) {
                cVar6 = (byte)uVar11 + (char)((uint6)uVar26 >> 0x28);
                uVar13 = (undefined3)(uVar11 >> 8);
                if (cVar6 != '\0') {
                  return (uint *)CONCAT31(uVar13,cVar6);
                }
                uVar7 = in(0x6a);
                out(0xa1,CONCAT31(uVar13,uVar7) + 0x14df6ec4);
                func_0x1e212df4();
                pcVar5 = (code *)swi(0x21);
                (*pcVar5)();
                *(byte *)puVar10 = *(byte *)puVar21;
                return (uint *)((int)puVar10 + 1);
              }
              uVar20 = *puVar21;
              pdVar4 = (double *)((int)puVar10 + 1);
              *(byte *)puVar10 = *(byte *)puVar21;
              *(uint *)pdVar4 =
                   (*(int *)pdVar4 - (int)(byte *)((int)puVar21 + 1)) - (uint)(uVar20 < 0xffffff93);
              *(char *)(uVar11 + 0xd0049161) = *(char *)(uVar11 + 0xd0049161) + '\x01';
              puVar12 = (undefined *)(uVar18 ^ 0x18);
              if (bVar17 == 0x18) {
                if (bVar17 == 0x18) {
                  pcVar5 = (code *)swi(1);
                  puVar21 = (uint *)(*pcVar5)();
                  return puVar21;
                }
                out(*puVar12,uVar15);
                *(int *)(puVar12 + 1) =
                     (int)ROUND((extraout_ST0 - (float10)in_stack_82d14fdf) * (float10)*pdVar4);
                _DAT_03d3ed6d = in(uVar15);
                bVar22 = 0;
                out(0xa1,CONCAT31((int3)((uint)(byte *)((int)puVar21 + 1) >> 8),0xbd));
                func_0x1e212e4c();
                pcVar5 = (code *)swi(0x21);
                uVar25 = (*pcVar5)();
                bVar23 = 9 < ((byte)uVar25 & 0xf) | bVar23;
                bVar17 = (byte)uVar25 + bVar23 * '\x06';
                bVar17 = bVar17 + (0x90 < (bVar17 & 0xf0) | bVar22 | bVar23 * (0xf9 < bVar17)) * '`'
                ;
                uVar20 = CONCAT31((int3)((ulonglong)uVar25 >> 8),bVar17);
                out(0x1e,uVar20);
                *(short *)((ulonglong)uVar25 >> 0x20) = (short)extraout_ST0_00;
                out(0x1e,uVar20);
                bVar23 = 9 < (bVar17 & 0xf) | bVar23;
                bVar17 = bVar17 + bVar23 * -6;
                puVar21 = (uint *)CONCAT22((short)((ulonglong)uVar25 >> 0x10),
                                           CONCAT11((byte)((ulonglong)uVar25 >> 8) & (byte)uVar11,
                                                    bVar17 + (0x9f < bVar17 |
                                                             uVar20 < 0x52f5923c |
                                                             bVar23 * (bVar17 < 6)) * -0x5f + -0x23)
                                          );
              }
              else {
                puVar21 = (uint *)(uVar18 ^ 0xff);
              }
              return puVar21;
            }
            in(0x10);
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
        else {
          iVar14 = 0x5c978bfd;
        }
        do {
          pbVar3 = (byte *)in((short)param_2);
          *unaff_EDI = pbVar3;
          param_2 = iVar14 + 0x1083a1d8 >> 0x1f;
          iVar14 = iRam16991083;
          unaff_EDI = unaff_EDI + 1;
        } while( true );
      }
      while( true ) {
        *(int *)(((uint)ppbVar9 ^ 0x98) - 0x6c) = iVar14;
        uVar20 = CONCAT13(0x3d,CONCAT12(local_4._2_1_,(undefined2)local_4));
        iVar14 = iVar14 + -1;
        if (iVar14 != 0 && (char)ppbVar9 == -0x68) break;
        local_4._0_2_ = 0x68db;
        local_4._2_1_ = 0x90;
        if (iVar14 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        ppbVar9 = (byte **)((uVar20 + 0xc52f6df0) - (uint)(uVar20 < 0xb7af68e0));
        if (0x8321292f < uVar20 + 0x48509720 && (uint)(uVar20 < 0xb7af68e0) <= uVar20 + 0xc52f6df0)
        {
          in(0xb1);
          in(uVar15);
          return unaff_ESI;
        }
      }
    }
    uVar8 = in(2);
    in_EAX = CONCAT31((int3)((uint)uVar8 >> 8),((byte)uVar8 ^ 0x72) + 0x28);
  }
  puVar21 = (uint *)CONCAT22((short)(param_2 >> 0x10),
                             CONCAT11((char)(param_2 >> 8) - *(char *)(in_EAX + (int)unaff_ESI * 2),
                                      (char)param_2));
  *(uint *)(in_EAX + 0x75091876) = *(uint *)(in_EAX + 0x75091876) >> 10;
  *unaff_EDI = *unaff_EDI + (int)unaff_ESI;
  *puVar21 = *puVar21 & unaff_EBP;
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __fastcall
entry(int param_1,uint param_2,uint **param_3,undefined2 *param_4,undefined *param_5)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x68e11834;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x40915c);
  puVar1 = &DAT_0042c000;
  do {
    *puVar1 = *puVar1 ^ 0x6f174a02;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42f3f8);
  FUN_00401219(param_1,param_2,param_3,param_4,param_5);
  return;
}


