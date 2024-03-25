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




// WARNING: Instruction at (ram,0x004012ad) overlaps instruction at (ram,0x004012ab)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __thiscall FUN_00401219(void *this)

{
  byte *pbVar1;
  char *pcVar2;
  code *pcVar3;
  byte bVar4;
  byte bVar8;
  int in_EAX;
  uint *puVar5;
  undefined4 uVar6;
  int iVar7;
  byte bVar10;
  uint extraout_ECX;
  int extraout_ECX_00;
  uint uVar9;
  byte *unaff_EBX;
  int iVar11;
  uint *unaff_EBP;
  uint uVar12;
  uint *unaff_ESI;
  int unaff_EDI;
  int *piVar13;
  char cVar14;
  byte in_AF;
  bool bVar15;
  undefined8 uVar16;
  uint *puStack00000020;
  uint *puStack00000024;
  uint uStack00000028;
  undefined *puStack0000002c;
  int iStack00000030;
  undefined4 uStack00000034;
  int iStack00000038;
  undefined4 uStack0000003c;
  byte *pbStack00000044;
  undefined *puStack00000048;
  undefined4 *puStack00000050;
  byte *in_stack_00000054;
  undefined4 uStack00000058;
  undefined4 uStack00000060;
  byte *in_stack_00000064;
  byte in_stack_00000068;
  int in_stack_0000006c;
  undefined *puStack00000070;
  byte *in_stack_00000074;
  void *in_stack_0000007c;
  undefined4 in_stack_00000080;
  
  while( true ) {
    piVar13 = (int *)(unaff_EDI + 1);
    *unaff_EBP = *unaff_EBP << 3 | *unaff_EBP >> 0x1d;
    *(char *)((int)this + 0x68ba0ac6) =
         *(char *)((int)this + 0x68ba0ac6) + (char)this + ((*unaff_EBP & 1) != 0);
    bVar10 = 9 < ((byte)in_EAX & 0xf) | in_AF;
    uVar9 = CONCAT31((int3)((uint)in_EAX >> 8),(byte)in_EAX + bVar10 * -6) & 0xffffff0f;
    *(char *)piVar13 = *(char *)piVar13 << 1 | *(char *)piVar13 < '\0';
    unaff_EBX[-6] = unaff_EBX[-6] + (char)this;
    puVar5 = (uint *)(CONCAT22((short)(uVar9 >> 0x10),
                               CONCAT11((char)((uint)in_EAX >> 8) - bVar10,(char)uVar9)) + 1);
    uVar9 = *puVar5;
    *(uint *)((int)this + 0x456006) = *(uint *)((int)this + 0x456006) & (uint)this;
    *(uint **)(((uint)unaff_ESI & uVar9) - 0x78) = puVar5;
    *piVar13 = *piVar13 + 0x5fcbabc;
    in_AF = 9 < (in_stack_00000068 & 0xf) | bVar10;
    in_stack_00000064[0x60] = in_stack_00000064[0x60] + (char)in_stack_00000064;
    _DAT_85aa5545 = _DAT_0007d007;
    in_stack_00000064 = in_stack_00000054;
    puStack00000070 = &stack0x00000084;
    uStack00000060 = CONCAT31((int3)((uint)in_stack_00000080 >> 8),0x61);
    _in_stack_00000068 = &DAT_0007d007;
    puStack00000050 = &stack0x00000064;
    DAT_6980547a = DAT_6980547a + (char)((uint)in_stack_0000007c >> 8);
    uStack00000058 = 0x7d00335;
    puStack00000048 = &DAT_0007d007;
    pbStack00000044 = in_stack_00000054;
    unaff_ESI = (uint *)&DAT_0007d00b;
    in_EAX = _DAT_0007d007 + 1;
    puStack0000002c = &stack0x00000040;
    uStack00000034 = 0x7d00335;
    puStack00000020 = (uint *)in_stack_00000054;
    unaff_EBP = (uint *)(in_stack_0000006c + 1);
    in_stack_00000080 = uStack00000060;
    if ((undefined *)((uint)in_stack_00000054 & 0x78) != (undefined *)0x0) break;
    unaff_EDI = 0;
    this = in_stack_0000007c;
    unaff_EBX = in_stack_00000074;
    in_stack_00000054 = in_stack_00000074;
    in_stack_00000068 = 7;
  }
  *(undefined *)((uint)in_stack_00000054 & 0x78) = (char)in_EAX;
  _DAT_85aa5545 = _DAT_85aa5545 + -0x7acb50b8;
  bVar8 = (byte)((uint)_DAT_85aa5545 >> 8);
  *in_stack_00000074 = *in_stack_00000074 + bVar8;
  bVar10 = *in_stack_00000074;
  *in_stack_00000074 = *in_stack_00000074 + bVar8;
  cVar14 = 0x90 < (byte)_DAT_85aa5545 || CARRY1((byte)_DAT_85aa5545 + 0x6f,CARRY1(bVar10,bVar8));
  bVar15 = SCARRY4(in_stack_0000006c,1);
  uVar12 = in_stack_0000006c + 1;
  uStack0000003c = 0x4012a9;
  puStack00000024 = unaff_ESI;
  uVar16 = func_0x00852905();
  uVar9 = (uint)((ulonglong)uVar16 >> 0x20);
  if (!bVar15) {
    cVar14 = (char)((uint)in_stack_00000074 >> 8) + in_stack_00000054[0x543368bd] + cVar14;
    iVar11 = CONCAT22((short)((uint)in_stack_00000074 >> 0x10),
                      CONCAT11(cVar14,(char)in_stack_00000074));
    *in_stack_00000054 = (byte)uVar16;
    iVar7 = (int)uVar16;
    while (uVar16 = CONCAT44(uVar9,(int)(short)iVar7), cVar14 == '\0') {
      uVar12 = 0xaa543368;
      iVar7 = (int)(short)iVar7;
    }
    in_stack_00000054[-1] = (byte)iVar7;
    uVar9 = extraout_ECX;
    puVar5 = (uint *)(in_stack_00000054 + -2);
    do {
      uStack00000034 = (undefined4)((ulonglong)uVar16 >> 0x20);
      puStack0000002c = &stack0x00000040;
      puStack00000024 = unaff_ESI + -1;
      bVar8 = 9 < ((byte)uVar16 & 0xf) | in_AF;
      bVar4 = (byte)uVar16 + bVar8 * -6;
      bVar4 = bVar4 + (0x9f < bVar4 | *unaff_ESI < *puVar5 | bVar8 * (bVar4 < 6)) * -0x60;
      pbVar1 = (byte *)(uVar9 + 0x60);
      bVar10 = *pbVar1;
      *pbVar1 = *pbVar1 + (byte)uVar9;
      bVar8 = 9 < (bVar4 & 0xf) | bVar8;
      bVar4 = bVar4 + bVar8 * -6;
      bVar4 = bVar4 + (0x9f < bVar4 | CARRY1(bVar10,(byte)uVar9) | bVar8 * (bVar4 < 6)) * -0x60;
      iStack00000038 = uVar9 + *(uint *)(uVar9 + 0x60);
      in_AF = 9 < (bVar4 & 0xf) | bVar8;
      bVar4 = bVar4 + in_AF * -6;
      uStack0000003c =
           CONCAT31((int3)((ulonglong)uVar16 >> 8),
                    bVar4 + (0x9f < bVar4 |
                            CARRY4(uVar9,*(uint *)(uVar9 + 0x60)) | in_AF * (bVar4 < 6)) * -0x60);
      *(char *)(iVar11 + 0x60) = *(char *)(iVar11 + 0x60) + (char)iStack00000038;
      uVar12 = uVar12 + 1;
      pcVar2 = (char *)(iVar11 + 0x63906508);
      *pcVar2 = *pcVar2 + (char)((ulonglong)uVar16 >> 8);
      cVar14 = *pcVar2 == '\0';
      unaff_ESI = unaff_ESI + -2;
      puStack00000020 = puVar5 + -1;
      uStack00000028 = uVar12;
      iStack00000030 = iVar11;
      uVar16 = func_0x89857325();
      uVar9 = extraout_ECX_00 - 1;
      puVar5 = puVar5 + -1;
    } while (uVar9 != 0 && cVar14 == '\0');
    pcVar3 = (code *)swi(3);
    uVar6 = (*pcVar3)();
    return uVar6;
  }
  bVar10 = (byte)(extraout_ECX >> 8);
  bVar15 = CARRY1(DAT_ddbb81f0,bVar10);
  DAT_ddbb81f0 = DAT_ddbb81f0 + bVar10;
  iVar7 = CONCAT22((short)((ulonglong)uVar16 >> 0x10),
                   CONCAT11(((char)DAT_ddbb81f0 < '\0') << 7 | (DAT_ddbb81f0 == '\0') << 6 |
                            in_AF << 4 | ((POPCOUNT(DAT_ddbb81f0) & 1U) == 0) << 2 | 2 | bVar15,
                            (byte)uVar16)) + 0x442c2b68 + (uint)bVar15;
  bVar15 = CARRY1(DAT_ddbb8df0,bVar10);
  DAT_ddbb8df0 = DAT_ddbb8df0 + bVar10;
  iVar7 = CONCAT22((short)((uint)iVar7 >> 0x10),
                   CONCAT11(((char)DAT_ddbb8df0 < '\0') << 7 | (DAT_ddbb8df0 == '\0') << 6 |
                            in_AF << 4 | ((POPCOUNT(DAT_ddbb8df0) & 1U) == 0) << 2 | 2 | bVar15,
                            (char)iVar7)) + 0x32a2cb53 + (uint)bVar15;
  DAT_2fa7aaff = DAT_2fa7aaff + (char)((uint)iVar7 >> 8);
  return CONCAT31((int3)((uint)iVar7 >> 8),
                  (byte)iVar7 |
                  *(byte *)(iVar7 + -0x4d +
                           (uVar12 ^ *(uint *)(in_stack_0000006c + 0x456055e5) ^ uVar9) * 2));
}



void __fastcall entry(void *param_1)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x1f95;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x45602300;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xc74;
  puVar2 = &DAT_0042b000;
  do {
    *puVar2 = *puVar2 ^ 0x45e67523;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219(param_1);
  return;
}


