typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
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




// WARNING: Instruction at (ram,0x00401233) overlaps instruction at (ram,0x00401231)
// 
// WARNING: Control flow encountered bad instruction data

char ** __fastcall FUN_00401219(int param_1,uint *param_2)

{
  uint **ppuVar1;
  int *piVar2;
  byte *pbVar3;
  uint *puVar4;
  longlong lVar5;
  code *pcVar6;
  undefined uVar7;
  undefined2 uVar8;
  char **in_EAX;
  uint uVar9;
  char **ppcVar10;
  char **ppcVar11;
  int iVar12;
  char **ppcVar13;
  char *pcVar14;
  char **ppcVar15;
  int **ppiVar16;
  char cVar18;
  uint *extraout_ECX;
  int extraout_ECX_00;
  uint *puVar17;
  char cVar20;
  byte bVar21;
  uint *unaff_EBX;
  undefined *puVar22;
  uint unaff_EBP;
  int **ppiVar23;
  int **ppiVar24;
  char **unaff_ESI;
  undefined4 *puVar25;
  char *unaff_EDI;
  char **ppcVar26;
  char **ppcVar27;
  undefined2 in_SS;
  int in_GS_OFFSET;
  byte in_CF;
  byte bVar28;
  byte in_AF;
  bool bVar29;
  bool bVar30;
  bool bVar31;
  undefined8 uVar32;
  undefined4 uStack_9;
  undefined4 uStack_5;
  undefined uStack_1;
  char cVar19;
  
  bVar31 = SBORROW4((int)&stack0x00000000,1);
  puVar22 = &uStack_1;
  do {
    bVar30 = (int)puVar22 < 0;
    bVar29 = puVar22 == (undefined *)0x0;
    uVar9 = CONCAT22((short)((uint)in_EAX >> 0x10),
                     CONCAT11(bVar30 << 7 | bVar29 << 6 | in_AF << 4 |
                              ((POPCOUNT((uint)puVar22 & 0xff) & 1U) == 0) << 2 | 2 | in_CF,
                              (byte)in_EAX));
    cVar18 = (char)((uint)unaff_EBX >> 8);
    if (!bVar29 && bVar31 == bVar30) {
      *(char *)unaff_ESI = *(char *)unaff_ESI - cVar18;
      unaff_EBX = (uint *)((int)unaff_EBX - *(int *)(unaff_EDI + 0x7e8154cd));
      *unaff_EDI = *(char *)unaff_ESI;
      uStack_5 = (int)unaff_ESI + 2;
      out(*(char *)((int)unaff_ESI + 1),(short)param_2);
      *(char *)(unaff_ESI + 7) = *(char *)(unaff_ESI + 7) - (char)((uint)param_1 >> 8);
      uVar9 = (byte)(((byte)in_EAX ^ 0x8e) + 1) | 0x28167e3e;
      unaff_EDI = unaff_EDI + 1;
code_r0x0040123b:
      ppuVar1 = (uint **)(unaff_EDI + -0x30d129b3);
      puVar17 = *ppuVar1;
      *ppuVar1 = (uint *)((int)*ppuVar1 - (int)unaff_EBX);
      unaff_EDI[0x157e1a24] =
           (unaff_EDI[0x157e1a24] - (char)param_2) -
           (0xe5 < (byte)uVar9 || CARRY1((byte)uVar9 + 0x1a,puVar17 < unaff_EBX));
      pcVar6 = (code *)swi(1);
      ppcVar10 = (char **)(*pcVar6)();
      return ppcVar10;
    }
    if (!bVar29 && bVar31 == bVar30) {
      *(char *)(unaff_EBP + 0x687b0692) = *(char *)(unaff_EBP + 0x687b0692) - cVar18;
      goto code_r0x0040123b;
    }
    uVar7 = in((short)_uStack_1);
    param_2 = (uint *)(_uStack_1 + 1);
    if (SCARRY4(_uStack_1,1) != (int)param_2 < 0) {
      return (char **)(int)(short)CONCAT31((int3)(unaff_EBP >> 8),uVar7);
    }
    if (param_2 != (uint *)0x0 && SCARRY4(_uStack_1,1) == (int)param_2 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *unaff_EBX = *unaff_EBX & 0x163c8e00;
    unaff_EBX = (uint *)((uint)unaff_EBX | *(uint *)(_uStack_1 + -0x59));
    _uStack_1 = 0x3e;
    in_CF = 0;
    bVar31 = false;
    *unaff_EBX = *unaff_EBX & 0x163c8e08;
    puVar22 = (undefined *)*unaff_EBX;
    uStack_9 = (char **)CONCAT22(uStack_9._2_2_,in_SS);
    in_EAX = unaff_ESI;
    unaff_EBP = uVar9;
    unaff_ESI = uStack_9;
    if (0 < (int)*unaff_EBX) {
      in((short)param_2);
      ppcVar26 = (char **)(unaff_EDI + -1);
      from_bcd(*(unkbyte10 *)(param_1 + -0x3fb97d8d));
      in(4);
      ppcVar10 = uStack_9;
      do {
        uStack_5 = CONCAT22(uStack_5._2_2_,in_SS);
        cVar20 = (char)((uint)unaff_EBX >> 8) - (char)((uint)param_2 >> 8);
        unaff_EBX = (uint *)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                                     CONCAT11(cVar20,(char)unaff_EBX));
        ppiVar23 = (int **)0x7e3e8b72;
        uStack_9 = (char **)CONCAT22(uStack_9._2_2_,in_SS);
        cVar19 = (char)((uint)param_1 >> 8);
        cVar18 = cVar19 - cVar20;
        puVar17 = (uint *)CONCAT22((short)((uint)param_1 >> 0x10),CONCAT11(cVar18,(char)param_1));
        if (cVar18 == '\0' || cVar19 < cVar20) goto code_r0x004012db;
        in_AF = 9 < ((byte)uRam6406c6db & 0xf) | in_AF;
        uVar9 = CONCAT31((int3)((uint)uRam6406c6db >> 8),(byte)uRam6406c6db + in_AF * -6) &
                0xffffff0f;
        iVar12 = CONCAT22((short)(uVar9 >> 0x10),
                          CONCAT11((char)((uint)uRam6406c6db >> 8) - in_AF,(char)uVar9));
        do {
        } while (cVar18 == '\0' || cVar19 < cVar20);
        ppcVar11 = (char **)(iVar12 + -1);
        if (ppcVar11 == (char **)0x0 || iVar12 < 1) {
          ppcVar11 = (char **)CONCAT31((int3)((uint)ppcVar11 >> 8),(char)ppcVar11 + '\x16' + in_AF);
        }
        else {
          ppcVar13 = ppcVar11;
          if ((POPCOUNT((uint)ppcVar11 & 0xff) & 1U) != 0) goto code_r0x00401313;
        }
        while( true ) {
          *(int *)((int)puVar17 + 0x661d417d) = *(int *)((int)puVar17 + 0x661d417d) - (int)ppiVar23;
          bVar28 = (byte)ppcVar11;
          param_2 = (uint *)((int)param_2 + 2);
          iVar12 = CONCAT31((int3)((uint)ppcVar11 >> 8),
                            bVar28 + 0x2b + (0xe9 < bVar28) + '\x16' +
                            (0xea < (byte)(bVar28 + 0x16) || CARRY1(bVar28 + 0x2b,0xe9 < bVar28)));
          if (iVar12 != -1 && SCARRY4(iVar12,1) == iVar12 + 1 < 0) break;
code_r0x004012db:
          uVar32 = (*(code *)puVar17)();
          ppcVar11 = (char **)uVar32;
          pbVar3 = (byte *)((int)ppcVar10 + in_GS_OFFSET + 0x16);
          bVar28 = *pbVar3;
          bVar21 = (byte)((uint)unaff_EBX >> 8);
          *pbVar3 = *pbVar3 + bVar21;
          param_2 = (uint *)((int)((ulonglong)uVar32 >> 0x20) + 1);
          if (CARRY1(bVar28,bVar21) || param_2 == (uint *)0x0) {
            puVar17 = (uint *)0xb7657649;
            ppcVar15 = (char **)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                                         (ushort)(byte)((char)unaff_EBX + bVar21 * '}'));
            unaff_EBX = (uint *)CONCAT22((short)((ulonglong)uVar32 >> 0x10),
                                         CONCAT11(0x9b,(char)uVar32));
            ppcVar11 = ppcVar10;
code_r0x00401350:
            ppcVar26 = (char **)((int)ppcVar26 + 1);
            if ((int)ppcVar26 < 0) {
              param_2 = (uint *)((uint)param_2 | *puVar17);
              bVar28 = (byte)((uint)puVar17 >> 8);
              bVar31 = bVar28 < (byte)param_2;
              bVar28 = bVar28 - (byte)param_2;
              puVar17 = (uint *)CONCAT22((short)((uint)puVar17 >> 0x10),
                                         CONCAT11(bVar28,(char)puVar17));
              bVar29 = bVar28 == 0;
              if (bVar31 || bVar29) {
code_r0x004013c5:
                bVar30 = *(char *)ppcVar26 < '\0';
                *(char *)ppcVar26 = *(char *)ppcVar26 << 1 | bVar31;
                LOCK();
                cVar18 = *(char *)((int)ppcVar26 + 0x56be0fef);
                *(char *)((int)ppcVar26 + 0x56be0fef) = (char)unaff_EBX;
                UNLOCK();
                uVar8 = (undefined2)((uint)unaff_EBX >> 0x10);
                if (!bVar30 && !bVar29) {
                  lVar5 = (longlong)(int)ppcVar15 * (longlong)(int)ppcVar11;
                  ppcVar10 = (char **)lVar5;
                  puVar17 = (uint *)~(uint)puVar17;
                  if (ppcVar11 < ppcVar10 ||
                      (undefined *)((int)ppcVar11 - (int)ppcVar10) == (undefined *)0x0) {
                    uVar9 = CONCAT22(uVar8,CONCAT11(0xd5,cVar18));
                    ppiVar24 = ppiVar23;
                    if ((int)ppcVar11 < (int)ppcVar10) goto code_r0x0040143c;
                    // WARNING: Bad instruction - Truncating control flow here
                    halt_baddata();
                  }
                  out(*(undefined *)((int)ppcVar11 - (int)ppcVar10),
                      (short)((ulonglong)lVar5 >> 0x20));
                    // WARNING: Bad instruction - Truncating control flow here
                  halt_baddata();
                }
                uVar9 = CONCAT22(uVar8,CONCAT11(0xd5,cVar18));
                if ((bVar30 != *(char *)ppcVar26 < '\0') == (char)bVar28 < '\0') {
                  return ppcVar15;
                }
                pcVar14 = (char *)((int)ppcVar26 + 1);
                if (pcVar14 != (char *)0x0 && SCARRY4((int)ppcVar26,1) == (int)pcVar14 < 0) {
                  piVar2 = (int *)((int)param_2 + (int)ppcVar11 * 2);
                  iVar12 = *piVar2;
                  *piVar2 = *piVar2 << 0x1b;
                  *(char *)((int)ppcVar26 + -0x6079c02f) =
                       *(char *)((int)ppcVar26 + -0x6079c02f) + cVar18 + (iVar12 << 0x1a < 0);
                  out((short)param_2,ppcVar15);
                    // WARNING: Bad instruction - Truncating control flow here
                  halt_baddata();
                }
                ppiVar16 = (int **)((int)ppcVar15 + 1);
                if (ppiVar16 == (int **)0x0 || SCARRY4((int)ppcVar15,1) != (int)ppiVar16 < 0) {
                  while( true ) {
                    bVar28 = (byte)(uVar9 | *param_2);
                    in_AF = 9 < (bVar28 & 0xf) | in_AF;
                    bVar28 = bVar28 + in_AF * '\x06';
                    uVar9 = CONCAT31((int3)((uVar9 | *param_2) >> 8),
                                     bVar28 + (0x90 < (bVar28 & 0xf0) | in_AF * (0xf9 < bVar28)) *
                                              '`');
                    lVar5 = CONCAT44(param_2,uVar9);
                    if ('\0' < (char)((byte)((uint)ppiVar16 >> 8) ^ pcVar14[0x3e249e95])) break;
                    uVar9 = CONCAT22((short)((uint)ppiVar16 >> 0x10),
                                     CONCAT11(0x9b,(char)ppiVar16 - *(char *)puVar17));
                    ppiVar24 = ppiVar23;
code_r0x0040143c:
                    ppiVar23 = (int **)lVar5;
                    ppcVar11 = (char **)*(undefined6 *)((ulonglong)lVar5 >> 0x20);
                    ppiVar16 = ppiVar24 + -0x2ed5fd0;
                    param_2 = (uint *)CONCAT31((int3)((ulonglong)lVar5 >> 0x28),
                                               ((char)((ulonglong)lVar5 >> 0x20) -
                                               *(char *)(uVar9 + 0x32192a27)) -
                                               (ppiVar24 < (int **)0xbb57f40));
                    pcVar14 = (char *)0x3e249e95;
                  }
                  pcVar14 = (char *)((-(uint)(uVar9 < 0x2854ca4a) - (int)ppcVar11) + 0x54a7a468);
                  *pcVar14 = (*pcVar14 - (byte)param_2) -
                             ((byte)((uint)puVar17 >> 8) < (byte)param_2);
                  return (char **)(uVar9 + 0xd7ab35b6);
                }
                out((short)param_2,(byte)ppiVar16);
                *(byte *)(param_2 + 0xb) =
                     (((int)ppiVar16 < 0) << 7 | (ppiVar16 == (int **)0x0) << 6 | in_AF << 4 |
                      ((POPCOUNT((uint)ppiVar16 & 0xff) & 1U) == 0) << 2 | 2 | bVar30) +
                     (9 < ((byte)ppiVar16 & 0xf) | in_AF);
                param_2 = (uint *)CONCAT31((int3)((uint)param_2 >> 8),
                                           (byte)param_2 & *(byte *)((int)ppcVar11 + (int)param_2));
code_r0x0040140e:
                out(*(undefined *)ppcVar11,(short)param_2);
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
            }
            else {
              *(int *)((int)puVar17 + 0x3bdc503a) =
                   *(int *)((int)puVar17 + 0x3bdc503a) - (int)ppiVar23;
              ppcVar15 = ppcRama1ee7fc6;
              pbVar3 = (byte *)((int)ppcVar11 + -0xd);
              bVar31 = (bool)(*pbVar3 & 1);
              *pbVar3 = *pbVar3 >> 1;
            }
            bVar28 = (byte)ppcVar15;
            ppcVar15 = (char **)CONCAT31((int3)(CONCAT22((short)((uint)ppcVar15 >> 0x10),
                                                         CONCAT11(bVar28 / 0x6e,bVar28)) >> 8),
                                         bVar28 % 0x6e + 0x16 + bVar31);
            ppcVar13 = ppcVar11;
code_r0x00401369:
            do {
              *(int *)((int)ppcVar13 + 0x19) = *(int *)((int)ppcVar13 + 0x19) + (int)ppcVar26;
              pcVar14 = (char *)((int)ppcVar13 + (int)ppcVar26 * 2 + 0x7c);
              *pcVar14 = *pcVar14 - (char)param_2;
              pcVar14 = (char *)((int)ppcVar13 + (int)ppcVar26 * 2 + -0x17);
              *pcVar14 = *pcVar14 - (char)param_2;
              bVar28 = *(byte *)((int)puVar17 + 0x23d62063);
              ppcVar10 = ppcVar13 + 1;
              out(*ppcVar13,(short)param_2);
              *(char *)ppcVar10 = *(char *)ppcVar10 - (char)((uint)unaff_EBX >> 8);
              ppcVar15 = (char **)~CONCAT31((int3)((uint)((int)ppcVar15 + 1) >> 8),
                                            (byte)((int)ppcVar15 + 1) ^ bVar28);
              ppcVar13 = ppcVar10;
            } while (((uint)ppcVar15 & 0x284077f9) != 0);
            return ppcVar15;
          }
          *ppcVar10 = *ppcVar10 + -(int)ppcVar26;
          ppiVar24 = ppiVar23 + 0x1b5e3a60;
          *(byte *)ppiVar24 = *(byte *)ppiVar24 >> 1 | *(byte *)ppiVar24 << 7;
          cVar18 = ((*(byte *)ppiVar24 & 0x40) != 0) != (char)*(byte *)ppiVar24 < '\0';
          in_AF = ((uint)ppcVar10 & 0x1000) != 0;
          bVar28 = ((uint)ppcVar10 & 0x100) != 0;
          puVar17 = extraout_ECX;
          ppcVar27 = uStack_9;
          if (((uint)ppcVar10 & 0x4000) != 0 || (bool)cVar18 != (((uint)ppcVar10 & 0x8000) != 0))
          goto code_r0x00401342;
          while( true ) {
            pbVar3 = (byte *)((int)ppcVar10 + -0x77f0d7ea + (int)puVar17);
            *pbVar3 = *pbVar3 << 1 | bVar28;
            ppuVar1 = (uint **)((int)ppcVar11 + -0x12);
            puVar4 = *ppuVar1;
            *ppuVar1 = (uint *)((int)*ppuVar1 - (int)param_2);
            uVar9 = (uint)ppcVar10 >> 0x10;
            uVar8 = CONCAT11(0x6a,(char)ppcVar10);
            ppcVar13 = (char **)((int)param_2 + (0x2817323a - (uint)(puVar4 < param_2)));
            ppcVar10 = (char **)((int)ppcVar11 + 1);
            out(*(undefined *)ppcVar11,uVar8);
            param_2 = (uint *)CONCAT22((short)uVar9,uVar8);
            ppcVar26 = ppcVar27;
code_r0x00401313:
            in_AF = 9 < ((byte)ppcVar10 & 0xf) | in_AF;
            uVar9 = CONCAT31((int3)((uint)ppcVar10 >> 8),(byte)ppcVar10 + in_AF * '\x06') &
                    0xffffff0f;
            uVar9 = CONCAT22((short)(uVar9 >> 0x10),
                             CONCAT11((char)((uint)ppcVar10 >> 8) + in_AF,(char)uVar9));
            ppcVar10 = (char **)*ppcVar13;
            pcVar14 = *ppcVar13;
            *ppcVar13 = *ppcVar13 + -(int)ppcVar26;
            if (*ppcVar13 == (char *)0x0 ||
                SBORROW4((int)pcVar14,(int)ppcVar26) != (int)*ppcVar13 < 0) break;
            bVar28 = in((short)param_2);
            bVar31 = false;
            bVar28 = bVar28 ^ *(byte *)((int)unaff_EBX + -0x17);
            bVar29 = bVar28 == 0;
            ppcVar15 = (char **)CONCAT31((int3)(uVar9 >> 8),
                                         *(undefined *)((int)unaff_EBX + (uint)bVar28));
            if ((char)bVar28 < '\x01') {
              ppcVar11 = ppcVar13;
              if (!bVar29) goto code_r0x004013c5;
              bVar28 = *(byte *)ppcVar13;
              bVar21 = (byte)((uint)unaff_EBX >> 8);
              *(byte *)ppcVar13 = *(char *)ppcVar13 - bVar21;
              if (bVar28 < bVar21 || *(char *)ppcVar13 == '\0') {
                return ppcVar15;
              }
              goto code_r0x00401369;
            }
            lVar5 = (longlong)((int)ppcVar15 + 0x3ca941f1) * (longlong)(int)ppcVar13;
            pcVar14 = (char *)lVar5;
            puVar25 = (undefined4 *)
                      ((int)ppcVar13 + (-(uint)((int)pcVar14 != lVar5) - (int)pcVar14));
            ppcVar27 = ppcVar26 + 1;
            *ppcVar26 = pcVar14;
            out(*puVar25,(short)((ulonglong)lVar5 >> 0x20));
            bVar28 = pcVar14 < (char *)0xe8cdca9d;
            cVar18 = SBORROW4((int)&uStack_9,1);
            func_0xd0df8613();
            ppiVar23 = (int **)*ppiVar23;
            ppcVar11 = (char **)(puVar25 + 2);
code_r0x00401342:
            pcVar6 = (code *)swi(4);
            if (cVar18 == '\x01') {
              (*pcVar6)();
            }
            pcVar6 = (code *)swi(0xe8);
            uVar32 = (*pcVar6)();
            param_2 = (uint *)((ulonglong)uVar32 >> 0x20);
            uVar7 = *(undefined *)((int)unaff_EBX + ((uint)uVar32 & 0xff));
            ppcVar10 = (char **)CONCAT31((int3)((ulonglong)uVar32 >> 8),uVar7);
            puVar17 = (uint *)(extraout_ECX_00 + -1);
            if ((bool)bVar28 || puVar17 == (uint *)0x0) {
              if (puVar17 < (uint *)0x2) {
                return ppcVar10;
              }
              goto code_r0x0040140e;
            }
            unaff_EBX = (uint *)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                                         CONCAT11(0xd5,(char)unaff_EBX));
            ppcVar15 = ppcVar10;
            ppcVar26 = ppcVar27;
            if (extraout_ECX_00 < 1) goto code_r0x00401350;
            out((short)((ulonglong)uVar32 >> 0x20),uVar7);
          }
          puVar17 = (uint *)((int)puVar17 + 1);
          ppcVar11 = (char **)((uVar9 + 0xc36569a) - (uint)(ppcVar10 < ppcVar26));
          ppiVar23 = (int **)((int)ppiVar23 +
                             (-(uint)(uVar9 < 0xf3c9a966 ||
                                     uVar9 + 0xc36569a < (uint)(ppcVar10 < ppcVar26)) -
                             (int)*ppcVar11));
          ppcVar10 = ppcVar13;
        }
        LOCK();
        uVar7 = *(undefined *)(iVar12 + 0x3f);
        *(undefined *)(iVar12 + 0x3f) = (char)((uint)puVar17 >> 8);
        param_1 = CONCAT22((short)((uint)puVar17 >> 0x10),CONCAT11(uVar7,(char)puVar17));
        UNLOCK();
        ppcVar10 = (char **)0x9f7e3e5f;
      } while( true );
    }
  } while( true );
}



void __fastcall entry(int param_1,uint *param_2)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x7e3e2816;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x64e3b3d;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2);
  return;
}


