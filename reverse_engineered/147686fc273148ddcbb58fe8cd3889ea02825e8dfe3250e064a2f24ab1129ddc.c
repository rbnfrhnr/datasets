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




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004012be) overlaps instruction at (ram,0x004012ba)
// 
// WARNING: Removing unreachable block (ram,0x004011f4)
// WARNING: Removing unreachable block (ram,0x004011af)
// WARNING: Removing unreachable block (ram,0x004011f6)
// WARNING: Removing unreachable block (ram,0x004011f5)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __fastcall entry(int *param_1,char *param_2)

{
  undefined4 uVar1;
  char cVar2;
  uint uVar3;
  byte bVar4;
  undefined6 uVar5;
  uint uVar6;
  double *pdVar7;
  uint uVar8;
  double *in_EAX;
  int iVar9;
  uint *puVar10;
  byte bVar11;
  char cVar13;
  undefined2 uVar15;
  int *piVar12;
  char cVar14;
  int unaff_EBX;
  int unaff_EBP;
  undefined4 *puVar16;
  char *pcVar17;
  char *unaff_ESI;
  byte *pbVar18;
  double **ppdVar19;
  undefined4 *puVar20;
  char *pcVar21;
  double **unaff_EDI;
  ushort in_ES;
  bool bVar22;
  bool bVar23;
  bool bVar24;
  byte in_AF;
  bool bVar25;
  bool bVar26;
  bool bVar27;
  bool bVar28;
  float10 in_ST0;
  float10 in_ST1;
  float10 in_ST2;
  float10 in_ST3;
  float10 in_ST4;
  float10 in_ST5;
  float10 fVar29;
  float10 in_ST6;
  float10 in_ST7;
  uint unaff_retaddr;
  double *pdStack_4;
  
  bVar26 = false;
  iVar9 = 0x1fb3;
  puVar10 = &DAT_00401000;
  do {
    *puVar10 = *puVar10 ^ 0x3e2d55f5;
    puVar10 = puVar10 + 1;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  iVar9 = 0xc74;
  puVar10 = &DAT_0042b000;
  do {
    *puVar10 = *puVar10 ^ 0x5b0e7dbe;
    puVar10 = puVar10 + 1;
    iVar9 = iVar9 + -1;
    pdStack_4 = in_EAX;
  } while (iVar9 != 0);
  while( true ) {
    puVar10 = (uint *)(unaff_ESI + 0x6b2d55f5 + (int)unaff_EDI);
    *puVar10 = *puVar10 ^ (uint)param_1;
    if (-1 < (int)*puVar10) break;
    bVar26 = (unaff_retaddr & 0x80) != 0;
    uVar6 = unaff_retaddr & 0x10;
    bVar23 = (unaff_retaddr & 0x800) != 0;
    while (bVar11 = (byte)in_EAX, bVar23 != bVar26) {
      in_EAX = (double *)
               CONCAT22((short)((uint)in_EAX >> 0x10),
                        (ushort)(byte)(bVar11 + (char)((uint)in_EAX >> 8) * -0x3f));
      bVar26 = *(int *)((int)unaff_EDI + 0x7d) + 0x62ba3f3f < 0;
      bVar23 = SBORROW4(*(int *)((int)unaff_EDI + 0x7d),-0x62ba3f3f);
    }
    pbVar18 = (byte *)((int)unaff_EDI + (uint)((unaff_retaddr & 0x400) != 0) * -2 + 1);
    bVar4 = *(byte *)unaff_EDI;
    bVar26 = true;
    ppdVar19 = (double **)(pbVar18 + -1);
    *pbVar18 = bVar11;
    *unaff_ESI = (*unaff_ESI - (char)((uint)param_1 >> 8)) - (bVar11 < bVar4);
    unaff_EBP = 0x55f542c0;
    pdVar7 = (double *)((int)in_EAX + -0x2d2999d6);
    if (in_EAX < (double *)0x2d2999d6 || pdVar7 == (double *)0x0) {
      sysexit();
      *ppdVar19 = pdVar7;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(int *)(unaff_ESI + 0x3e2d55f4) = *(int *)(unaff_ESI + 0x3e2d55f4) - (int)pdVar7;
    bVar23 = false;
    bVar28 = false;
    bVar25 = false;
    bVar22 = ((uint)pdVar7 & 10) == 0;
    piVar12 = param_1;
    while (in_AF = uVar6 != 0, bVar28) {
      if (bVar28 == bVar25) goto LAB_00401262;
LAB_00401252:
      pdVar7 = (double *)((int)pdVar7 + -0x6fe5dd56);
      bVar28 = ((uint)pdStack_4 & 0x800) != 0;
      bVar26 = ((uint)pdStack_4 & 0x400) != 0;
      bVar25 = ((uint)pdStack_4 & 0x80) != 0;
      bVar22 = ((uint)pdStack_4 & 0x40) != 0;
      uVar6 = (uint)pdStack_4 & 0x10;
      bVar23 = ((uint)pdStack_4 & 1) != 0;
    }
    if (!bVar23 && !bVar22) {
      *(int *)(unaff_ESI + 0x4b2d55b7) = *(int *)(unaff_ESI + 0x4b2d55b7) + (int)piVar12;
      in((short)param_2);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
LAB_00401262:
    unaff_ESI = (char *)*(undefined6 *)(unaff_EBX + -0x3ed2aa72);
    pcVar17 = (char *)(unaff_EBP + -99);
    cVar13 = *pcVar17;
    *pcVar17 = *pcVar17 >> 0x1c;
    bVar23 = (cVar13 >> 0x1b & 1U) == 0;
    unaff_EDI = (double **)((int)ppdVar19 + (uint)bVar26 * -2 + 1);
    *(char *)ppdVar19 = (char)pdVar7;
    in_EAX = pdVar7;
LAB_0040126e:
    do {
      iVar9 = unaff_EBP;
      *param_2 = (*param_2 - (char)unaff_EBX) - bVar23;
      unaff_EBP = iVar9 + 1;
      bVar23 = in_EAX < (double *)0x9d75c0c1;
      pdVar7 = (double *)((int)in_EAX + 0x628a3f3f);
      bVar22 = (int)in_EAX < -0x628a3f3f;
      in_EAX = pdVar7;
    } while (bVar22);
    in_ST0 = in_ST0 * (float10)*pdVar7;
    uVar6 = CONCAT31((int3)((uint)pdVar7 >> 8),(char)pdVar7 - *(char *)(iVar9 + 0x18));
    in_EAX = (double *)(uVar6 + 0xd2dcb22a);
    if (0x2d234dd5 < uVar6 && in_EAX != (double *)0x0) goto code_r0x00401286;
    in_EAX = (double *)
             CONCAT22((short)((uint)in_EAX >> 0x10),
                      (ushort)(byte)((char)in_EAX + (char)((uint)in_EAX >> 8) * '\"'));
    param_1 = piVar12;
  }
  ppdVar19 = (double **)((int)unaff_EDI + 1);
  uVar6 = *(uint *)(unaff_EBP + -0xa8362b7);
  *(uint *)(unaff_EBP + -0xa8362b7) = uVar6 >> 0x1d | uVar6 << 4;
  unaff_EBX = CONCAT22((short)((uint)unaff_EBX >> 0x10),CONCAT11(0x2e,(char)unaff_EBX));
  uVar15 = (undefined2)((uint)param_1 >> 0x10);
  bVar11 = (byte)param_1;
  piVar12 = (int *)CONCAT22(uVar15,CONCAT11(0x55,bVar11));
  if (SCARRY4((int)unaff_EDI,1) != (int)ppdVar19 < 0) {
    if (SCARRY4((int)unaff_EDI,1) == (int)ppdVar19 < 0) {
      bVar22 = in_EAX < (double *)0xae55f53e;
      bVar27 = SBORROW4((int)in_EAX,-0x51aa0ac2);
      in_EAX = (double *)((int)in_EAX + 0x51aa0ac2);
      bVar24 = (POPCOUNT((uint)in_EAX & 0xff) & 1U) == 0;
      bVar4 = bVar11 & 0x1f;
      cVar13 = 'U' << bVar4;
      piVar12 = (int *)CONCAT22(uVar15,CONCAT11(cVar13,bVar11));
      bVar23 = ((uint)param_1 & 0x1f) != 0;
      bVar23 = !bVar23 && bVar22 || bVar23 && (char)('U' << bVar4 - 1) < '\0';
      bVar25 = ((uint)param_1 & 0x1f) != 0;
      bVar28 = (POPCOUNT(cVar13) & 1U) == 0;
      bVar22 = !bVar25 && bVar24 || bVar25 && bVar28;
      pdStack_4 = (double *)(uint)in_ES;
      if (!bVar25 && bVar24 || bVar25 && bVar28) {
        unaff_EDI = ppdVar19;
        if ((bool)(bVar4 != 1 & bVar27 | (bVar4 == 1 && bVar23 != cVar13 < '\0')) ==
            (!bVar25 && (int)in_EAX < 0 || bVar25 && cVar13 < '\0')) {
          unaff_EBP = (int)*(undefined6 *)(unaff_ESI + 0x2c);
          piVar12 = (int *)(*piVar12 * 0x9597458);
          bVar11 = 9 < ((byte)in_EAX & 0xf) | in_AF;
          uVar6 = CONCAT31((int3)((uint)in_EAX >> 8),(byte)in_EAX + bVar11 * -6) & 0xffffff0f;
          pdVar7 = (double *)
                   CONCAT22((short)(uVar6 >> 0x10),
                            CONCAT11((char)((uint)in_EAX >> 8) - bVar11,(char)uVar6));
          goto LAB_00401252;
        }
        goto LAB_0040126e;
      }
    }
    else {
      uVar8 = CONCAT31((int3)((uint)in_EAX >> 8),(byte)in_EAX - 0x3e);
      uVar6 = (uint)((byte)in_EAX < 0x3e);
      uVar3 = uVar8 + 0xac1a45e;
      bVar23 = uVar8 < 0xf53e5ba2 || uVar3 < uVar6;
      in_EAX = (double *)(uVar3 - uVar6);
      bVar22 = (POPCOUNT((uint)in_EAX & 0xff) & 1U) == 0;
    }
    uRam06f53e5b = SUB41(in_EAX,0);
    if (!bVar22) {
      *(uint *)in_EAX = *(uint *)in_EAX >> 1 | (uint)bVar23 << 0x1f;
      unaff_ESI[-0x55] = -0x2e;
      out(*unaff_ESI,(short)param_2);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar9 = (int)in_EAX >> 0x1f;
    pcVar17 = (char *)(iVar9 + 0x7110edaa);
    cVar13 = *pcVar17;
    cVar14 = (char)((uint)piVar12 >> 8);
    cVar2 = *pcVar17 + cVar14;
    *pcVar17 = cVar2 + bVar23;
    if ((POPCOUNT(*pcVar17) & 1U) == 0) {
      in_ST0 = in_ST1;
    }
    if ((SCARRY1(cVar13,cVar14) != SCARRY1(cVar2,bVar23)) == *pcVar17 < '\0') {
      while( true ) {
        *(longlong *)(unaff_EBP + -0x65b55f5) = (longlong)in_ST0;
        puVar16 = (undefined4 *)(unaff_ESI + (uint)bVar26 * -8 + 4);
        puVar20 = (undefined4 *)((int)ppdVar19 + (uint)bVar26 * -8 + 6);
        uVar1 = in((short)iVar9);
        *(undefined4 *)((int)ppdVar19 + 2) = uVar1;
        uVar5 = _DAT_f4cd0bd4;
        fVar29 = in_ST7 - in_ST1;
        unaff_EBP = 0x3a58aa0e;
        iVar9 = (int)_DAT_f4cd0bd4;
        *puVar20 = *puVar16;
        pcVar17 = (char *)((int)(puVar16 + (uint)bVar26 * -2 + 1) + (uint)bVar26 * -2 + 1);
        out(*(char *)(puVar16 + (uint)bVar26 * -2 + 1),(short)uVar5);
        pcVar21 = (char *)((int)puVar20 + (uint)bVar26 * -8 + 5);
        if (-1 < (int)pcVar21) break;
        ppdVar19 = (double **)((int)puVar20 + (uint)bVar26 * -2 + (uint)bVar26 * -8 + 6);
        unaff_ESI = pcVar17 + (uint)bVar26 * -2 + 1;
        *pcVar21 = *pcVar17;
        in_ST0 = in_ST1;
        in_ST1 = in_ST2;
        in_ST2 = in_ST3;
        in_ST3 = in_ST4;
        in_ST4 = in_ST5;
        in_ST5 = in_ST6;
        in_ST6 = fVar29;
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
code_r0x00401286:
  return (uint)in_EAX ^ 0x60dc3c0f;
}


