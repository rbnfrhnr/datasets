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
// WARNING: Instruction at (ram,0x004012c9) overlaps instruction at (ram,0x004012c6)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x004014b3)
// WARNING: Removing unreachable block (ram,0x004014c2)
// WARNING: Removing unreachable block (ram,0x004014d6)
// WARNING: Removing unreachable block (ram,0x004014e2)
// WARNING: Removing unreachable block (ram,0x004014e8)
// WARNING: Removing unreachable block (ram,0x004014ea)
// WARNING: Removing unreachable block (ram,0x004014ec)
// WARNING: Removing unreachable block (ram,0x00401561)
// WARNING: Removing unreachable block (ram,0x00401504)
// WARNING: Removing unreachable block (ram,0x004014f1)
// WARNING: Removing unreachable block (ram,0x004014a1)
// WARNING: Removing unreachable block (ram,0x00401507)
// WARNING: Removing unreachable block (ram,0x004014f3)
// WARNING: Removing unreachable block (ram,0x00401475)
// WARNING: Removing unreachable block (ram,0x004014f5)
// WARNING: Removing unreachable block (ram,0x004014f9)
// WARNING: Removing unreachable block (ram,0x004014ff)
// WARNING: Removing unreachable block (ram,0x0040150b)
// WARNING: Removing unreachable block (ram,0x00401514)
// WARNING: Removing unreachable block (ram,0x004014b9)
// WARNING: Removing unreachable block (ram,0x00401517)
// WARNING: Removing unreachable block (ram,0x0040151a)
// WARNING: Removing unreachable block (ram,0x0040152a)
// WARNING: Removing unreachable block (ram,0x00401522)
// WARNING: Removing unreachable block (ram,0x0040153d)
// WARNING: Removing unreachable block (ram,0x0040153a)
// WARNING: Removing unreachable block (ram,0x0040154e)
// WARNING: Removing unreachable block (ram,0x0040155e)
// WARNING: Removing unreachable block (ram,0x00401566)
// WARNING: Removing unreachable block (ram,0x00401549)
// WARNING: Removing unreachable block (ram,0x0040154c)
// WARNING: Removing unreachable block (ram,0x00401524)
// WARNING: Removing unreachable block (ram,0x00401479)
// WARNING: Removing unreachable block (ram,0x004014ca)
// WARNING: Removing unreachable block (ram,0x3ad435d5)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall
FUN_00401219(uint **param_1,uint **param_2,undefined4 param_3,uint **param_4,undefined4 param_5,
            uint **param_6,uint **param_7,uint **param_8,uint **param_9,uint **param_10,
            uint **param_11,uint **param_12,uint **param_13,uint **param_14)

{
  ushort *puVar1;
  char *pcVar2;
  byte *pbVar3;
  uint *puVar4;
  uint uVar5;
  uint uVar6;
  code *pcVar7;
  byte bVar8;
  undefined uVar9;
  byte bVar10;
  short sVar11;
  ushort uVar12;
  int in_EAX;
  int iVar13;
  uint **ppuVar14;
  undefined2 uVar18;
  undefined4 uVar16;
  undefined4 *puVar17;
  int extraout_ECX;
  byte *pbVar19;
  int iVar20;
  byte extraout_DL;
  undefined4 extraout_EDX;
  uint **ppuVar21;
  float *pfVar22;
  uint **unaff_EBX;
  int *piVar23;
  double *pdVar24;
  undefined4 *puVar25;
  uint **unaff_EBP;
  uint **unaff_ESI;
  uint **ppuVar26;
  uint uVar27;
  uint **ppuVar28;
  uint **unaff_EDI;
  uint **ppuVar29;
  undefined2 in_CS;
  bool bVar30;
  byte bVar31;
  bool bVar32;
  byte in_AF;
  bool bVar33;
  bool bVar34;
  char cVar35;
  byte in_TF;
  byte in_IF;
  char cVar36;
  bool bVar37;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined2 in_FPUControlWord;
  undefined2 in_FPUStatusWord;
  undefined2 in_FPUTagWord;
  undefined2 in_FPULastInstructionOpcode;
  undefined4 in_FPUDataPointer;
  undefined4 in_FPUInstructionPointer;
  float10 in_ST0;
  float10 extraout_ST0;
  float10 extraout_ST0_00;
  float10 in_ST2;
  int *piVar15;
  
  iVar13 = in_EAX + 0x617f1f74;
  ppuVar14 = (uint **)CONCAT22((short)((uint)iVar13 >> 0x10),
                               (ushort)(byte)((char)iVar13 + (char)((uint)iVar13 >> 8) * 'J'));
  bVar30 = false;
  bVar34 = false;
  bVar33 = (*(byte *)((int)unaff_EDI * 5 + 0x157d17e0) & 0x5d) == 0;
  if (bVar33) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (bVar33) {
    while (param_1 != (uint **)0x0) {
      param_1 = (uint **)((int)param_1 + -1);
      out(*unaff_ESI,(short)param_2);
      unaff_ESI = unaff_ESI + 1;
    }
    pcVar7 = (code *)swi(1);
    (*pcVar7)();
    return;
  }
code_r0x00401298:
  if (bVar33 || bVar34) {
    iVar13 = CONCAT22((short)((uint)param_1 >> 0x10),
                      CONCAT11((char)((uint)param_1 >> 8) - (char)ppuVar14,(char)param_1));
    pcVar2 = (char *)((int)unaff_EDI + 0x1fd42d6f);
    bVar31 = 0;
    cVar36 = '\0';
    *pcVar2 = *pcVar2;
    bVar30 = *pcVar2 < '\0';
    bVar34 = *pcVar2 == '\0';
    bVar8 = POPCOUNT(*pcVar2);
    out(0xac,(char)unaff_EDI);
    ppuVar26 = unaff_ESI;
    while( true ) {
      if (!bVar34 && (bool)cVar36 == bVar30) break;
      ppuVar29 = unaff_EDI + -0x10;
      bVar31 = false;
      cVar36 = false;
      *ppuVar29 = (uint *)((uint)*ppuVar29 | 0xffffffba);
      cVar35 = (int)*ppuVar29 < 0;
      puVar4 = *ppuVar29;
      bVar34 = puVar4 == (uint *)0x0;
      ppuVar29 = (uint **)((int)ppuVar14 + 1);
      *(char *)ppuVar14 = (char)unaff_EDI;
      pbVar19 = (byte *)(iVar13 + -1);
      if (pbVar19 != (byte *)0x0 && !bVar34) goto code_r0x00401312;
      iVar20 = iVar13 + -2;
      ppuVar14 = ppuVar29;
      if (iVar20 != 0 && !bVar34) goto LAB_004012ed;
      iVar13 = 0x75d56134;
      if ((int)puVar4 < 1) {
        iVar20 = CONCAT22((short)((uint)unaff_EDI >> 0x10),
                          (ushort)(byte)((char)unaff_EDI + (char)((uint)unaff_EDI >> 8) * 'u'));
        cVar35 = '\0';
        ppuVar21 = ppuVar26;
      }
      else {
        if (!bVar34) {
          from_bcd(Ram75d56133);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        while( true ) {
          ppuVar14 = ppuVar29 + 1;
          ppuVar21 = ppuVar26 + 1;
          *ppuVar29 = *ppuVar26;
          pcVar7 = (code *)swi(0x2e);
          sVar11 = (*pcVar7)();
          param_2 = (uint **)CONCAT22((short)((uint)extraout_EDX >> 0x10),
                                      CONCAT11(0xe8,(char)extraout_EDX));
          iVar20 = (int)sVar11;
          iVar13 = extraout_ECX;
          in_ST0 = extraout_ST0;
          if (extraout_ECX == 0) break;
          unaff_EBX = param_11;
          if (bVar34 || cVar36 != cVar35) {
            bVar8 = (byte)param_14 + 0x24;
            ppuVar14 = (uint **)CONCAT31((int3)((uint)param_14 >> 8),bVar8 - bVar31);
            uVar27 = (uint)((byte)param_14 < 0xdc || bVar8 < bVar31);
            uVar6 = (int)ppuVar14 - (int)param_12;
            bVar30 = ppuVar14 < param_12 || uVar6 < uVar27;
            bVar34 = SBORROW4((int)ppuVar14,(int)param_12) != SBORROW4(uVar6,uVar27);
            iVar13 = uVar6 - uVar27;
            uVar12 = (ushort)(byte)((char)iVar13 + (char)((uint)iVar13 >> 8) * '\x1f');
            ppuVar14 = (uint **)CONCAT22((short)((uint)iVar13 >> 0x10),uVar12);
            bVar33 = uVar12 == 0;
            param_1 = param_13;
            param_2 = param_12;
            unaff_EBP = param_9;
            unaff_ESI = param_8;
            unaff_EDI = param_7;
            goto code_r0x00401298;
          }
          param_1 = (uint **)((int)param_13 + -1);
          ppuVar29 = param_14;
          ppuVar21 = param_12;
          param_2 = param_9;
          ppuVar26 = param_8;
          ppuVar14 = param_7;
          if (param_1 == (uint **)0x0 || bVar34 == false) goto code_r0x004012f5;
LAB_00401275:
          ppuVar29 = (uint **)((uint)ppuVar14 | *(uint *)((int)ppuVar14 + 0x37f7d523));
          bVar8 = (byte)((uint)((int)param_1 + 1) >> 8);
          bVar10 = (byte)ppuVar21;
          bVar31 = bVar8 < bVar10;
          cVar36 = SBORROW1(bVar8,bVar10) != false;
          cVar35 = (char)(bVar8 - bVar10) < '\0';
          bVar34 = bVar8 == bVar10;
          unaff_EBP = param_2;
        }
      }
      if (cVar36 != cVar35) goto LAB_004012cb;
      bVar8 = (char)iVar20 + (char)((uint)iVar20 >> 8) * 'u';
      if (bVar8 != 0 && cVar36 == '\0') goto LAB_004012cb;
      uVar12 = (ushort)bVar8;
      unaff_EDI = (uint **)CONCAT22((short)((uint)iVar20 >> 0x10),uVar12);
      bVar30 = false;
      bVar34 = uVar12 == 0;
      bVar8 = POPCOUNT(uVar12);
      ppuVar26 = ppuVar21;
      if (bVar34 || cVar36 != '\0') {
LAB_004012cb:
        *(undefined2 *)(param_7 + -1) = in_CS;
        param_7[-2] = (uint *)0x4012e0;
        func_0x507b6a2a();
        do {
          invalidInstructionException();
        } while( true );
      }
    }
    if ((bVar8 & 1) != 0) {
      *(undefined *)unaff_EBX = 0;
      uVar18 = SUB42(param_2,0);
      if (*(char *)unaff_EBX != '\0') {
        out(uVar18,unaff_EDI);
        pcVar7 = (code *)swi(3);
        (*pcVar7)();
        return;
      }
      uVar9 = in(0xdf);
      piVar15 = (int *)CONCAT31((int3)((uint)*ppuVar26 >> 8),uVar9);
      out(*(undefined *)(ppuVar26 + 1),uVar18);
      puVar4 = (uint *)in(uVar18);
      *ppuVar14 = puVar4;
      iVar13 = *piVar15;
      uVar27 = piVar15[1];
      unaff_EBP = (uint **)piVar15[2];
      unaff_EBX = (uint **)piVar15[4];
      piVar23 = piVar15 + 7;
      piVar15[7] = 0x40134e;
      uVar16 = func_0xa00d029e();
      bVar34 = extraout_DL < *(byte *)(uVar27 + 0x448b3eb8);
      bVar10 = *(byte *)(uVar27 + 0x448b3eb8);
      pbVar19 = (byte *)(uVar27 + 0xf39e29a);
      bVar31 = *pbVar19;
      bVar8 = *pbVar19;
      *pbVar19 = bVar8 + 0x29 + bVar34;
      *(undefined4 *)((int)piVar23 + -4) = 0xffffffed;
      pbVar19 = (byte *)0x32968796;
      ppuVar14 = *(uint ***)((int)piVar23 + -4);
      in_ST0 = extraout_ST0_00 / in_ST2;
      uVar27 = uVar27 & 0xffffff29;
      ppuVar29 = (uint **)(iVar13 + -2);
      bVar30 = 0x80df429e < uVar27;
      iVar13 = uVar27 + 0x7f20bd61;
      bVar33 = SCARRY4(uVar27,0x7f20bd61) == SCARRY4(iVar13,0);
      out(*(undefined *)
           CONCAT31((int3)((uint)uVar16 >> 8),
                    ((char)uVar16 + '}') - (0xd6 < bVar31 || CARRY1(bVar8 + 0x29,bVar34))),
          CONCAT11(0xa2,extraout_DL - bVar10));
      bVar8 = (char)iVar13 + (char)((uint)iVar13 >> 8) * 'u';
      uVar18 = (undefined2)((uint)iVar13 >> 0x10);
      iVar13 = CONCAT22(uVar18,(ushort)bVar8);
      if (bVar8 != 0 && bVar33) goto code_r0x0040138d;
      uVar12 = (ushort)bVar8;
      uVar27 = CONCAT22(uVar18,uVar12);
      if (uVar12 == 0 || !bVar33) goto code_r0x00401386;
      if (uVar12 == 0 || !bVar33) {
        do {
                    // WARNING: Do nothing block with infinite loop
        } while( true );
      }
      uVar6 = (uint)bVar30;
      uVar5 = uVar27 + *(uint *)(uVar27 + 0xebf7dd14);
      bVar30 = CARRY4(uVar27,*(uint *)(uVar27 + 0xebf7dd14)) || CARRY4(uVar5,uVar6);
      iVar13 = uVar5 + uVar6;
      goto code_r0x0040138d;
    }
    unaff_EDI = (uint **)((int)unaff_EDI + bVar31 + 0xd50b0ff4);
    in_IF = 0;
    iVar20 = iVar13 + -1;
    if (iVar20 != 0 && unaff_EDI == (uint **)0x0) {
      param_1 = (uint **)(iVar13 + -2);
      ppuVar21 = unaff_EDI;
      goto LAB_00401275;
    }
    *(uint *)((int)param_2 + -0x2a9fcce9) = *(uint *)((int)param_2 + -0x2a9fcce9) ^ (uint)ppuVar14;
    unaff_EBP = param_2;
LAB_004012ed:
    param_2 = unaff_EBP;
    sVar11 = (short)((uint)unaff_EDI >> 0x10);
    uVar12 = (ushort)(byte)((char)unaff_EDI + (char)((uint)unaff_EDI >> 8) * -0x6e);
    ppuVar29 = (uint **)CONCAT22(sVar11,uVar12);
    in_IF = 0;
    ppuVar21 = (uint **)((int)sVar11 >> 0xf);
    param_1 = (uint **)(iVar20 + -1);
    param_4 = unaff_EDI;
    param_7 = ppuVar14;
    if (param_1 != (uint **)0x0 && uVar12 == 0) goto LAB_00401275;
code_r0x004012f5:
    *(uint *)((int)ppuVar26 + -0x2ae45009) = *(uint *)((int)ppuVar26 + -0x2ae45009) ^ (uint)ppuVar29
    ;
    ppuVar14 = ppuVar29;
    param_2 = ppuVar21;
    unaff_ESI = ppuVar26;
    unaff_EDI = param_7;
    bVar30 = false;
  }
  while( true ) {
    *(char *)((int)unaff_ESI + 0x617f6a47) = *(char *)((int)unaff_ESI + 0x617f6a47) + '\x01';
    bVar10 = (byte)param_2;
    param_2 = (uint **)CONCAT22((short)((uint)param_2 >> 0x10),
                                CONCAT11((char)((uint)unaff_EBX >> 8),bVar10));
    bVar31 = (byte)((uint)param_1 >> 8);
    bVar8 = bVar31 - bVar10;
    pbVar19 = (byte *)CONCAT22((short)((uint)param_1 >> 0x10),CONCAT11(bVar8 - bVar30,(char)param_1)
                              );
    ppuVar26 = (uint **)((int)unaff_ESI + -1);
    ppuVar29 = (uint **)&DAT_67f1171e;
    unaff_EBX = ppuVar14;
    unaff_EBP = param_6;
    param_4._0_2_ = (undefined2)param_5;
    if (ppuVar26 == (uint **)0x0 || (int)unaff_ESI < 1) break;
    param_6 = (uint **)0x7f;
    ppuVar14 = param_13;
    param_1 = param_12;
    param_2 = param_11;
    unaff_EBX = param_10;
    unaff_ESI = param_7;
    unaff_EDI = param_6;
    bVar30 = bVar31 < bVar10 || bVar8 < bVar30;
  }
code_r0x00401312:
  pbVar3 = (byte *)((int)ppuVar29 + 0x2fe02bd2);
  bVar31 = (byte)unaff_EDI;
  bVar34 = bVar31 < *pbVar3;
  bVar37 = SBORROW1(bVar31,*pbVar3);
  cVar36 = bVar31 - *pbVar3;
  uVar27 = CONCAT31((int3)((uint)unaff_EDI >> 8),cVar36);
  bVar33 = cVar36 < '\0';
  bVar30 = cVar36 == '\0';
  bVar8 = POPCOUNT(cVar36);
  ppuVar14 = ppuVar29 + -1;
  *(undefined2 *)(ppuVar29 + -1) = param_4._0_2_;
  if (bVar30 || (char)bVar31 < (char)*pbVar3) {
    ppuVar29[-2] = (uint *)ppuVar26;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  ppuVar21 = ppuVar29 + -1;
  if (!bVar30) goto LAB_00401400;
  bVar34 = false;
  bVar37 = false;
  param_2 = (uint **)((uint)param_2 | (uint)unaff_EBP);
  bVar33 = (int)param_2 < 0;
  bVar30 = param_2 == (uint **)0x0;
  bVar32 = (POPCOUNT((uint)param_2 & 0xff) & 1U) == 0;
  ppuVar21 = ppuVar29 + -1;
  ppuVar28 = ppuVar26;
  if (bVar30) {
code_r0x00401386:
    uVar27 = CONCAT31((int3)(uVar27 >> 8),DAT_dd148013);
LAB_0040138b:
    iVar13 = (int)((longlong)(int)uVar27 * (longlong)(int)unaff_EBX);
    bVar30 = (longlong)iVar13 != (longlong)(int)uVar27 * (longlong)(int)unaff_EBX;
code_r0x0040138d:
    iVar13 = (iVar13 + 0x5809e02b) - (uint)bVar30;
    pdVar24 = (double *)((uint)ppuVar14 | (uint)unaff_EBP[-7]);
    *(short *)(iVar13 + -0x619895d6) = (short)ROUND(in_ST0);
    piVar15 = (int *)CONCAT31((int3)((uint)iVar13 >> 8),DAT_c914800b);
    if (pdVar24 == (double *)0x0) {
      *(undefined4 *)(-0x239e809d - (int)unaff_EBX) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if ((int)pdVar24 < 1) {
code_r0x00401450:
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    *pdVar24 = (double)in_ST0;
    *(int *)((int)unaff_EBP + -0x29) = *(int *)((int)unaff_EBP + -0x29) << 0x10;
    *(int *)((int)unaff_EBP + -0x15) = *(int *)((int)unaff_EBP + -0x15) << 6;
    bVar34 = pdVar24 < *ppuVar29;
  }
  else {
    do {
      ppuVar14 = ppuVar21;
      if (!bVar30 && bVar37 == bVar33) break;
      puVar17 = *ppuVar14;
      *(undefined2 *)((int)ppuVar28 + -0x69) = in_FPUControlWord;
      *(undefined2 *)((int)ppuVar28 + -0x65) = in_FPUStatusWord;
      *(undefined2 *)((int)ppuVar28 + -0x61) = in_FPUTagWord;
      *(undefined4 *)((int)ppuVar28 + -0x55) = in_FPUDataPointer;
      *(undefined4 *)((int)ppuVar28 + -0x5d) = in_FPUInstructionPointer;
      *(undefined2 *)((int)ppuVar28 + -0x57) = in_FPULastInstructionOpcode;
      bVar8 = (byte)_DAT_3ea14e1b;
      cVar36 = bVar8 + 0x4d + (bVar8 < 0x80);
      iVar13 = CONCAT31((int3)((uint)_DAT_3ea14e1b >> 8),cVar36);
      if (pbVar19 != (byte *)0x1 && cVar36 != '\0') {
        puVar17[-1] = 0xffffff83;
        puVar1 = (ushort *)((int)ppuVar28 + 0x61);
        *puVar1 = *puVar1 + (ushort)(0x32 < (byte)(bVar8 + 0x80) ||
                                    CARRY1(bVar8 + 0x4d,bVar8 < 0x80)) *
                            (((ushort)ppuVar28 & 3) - (*puVar1 & 3));
        goto code_r0x00401450;
      }
      if (cVar36 != '\0') {
        ppuVar29 = (uint **)*puVar17;
        ppuVar26 = (uint **)puVar17[1];
        unaff_EBP = (uint **)puVar17[2];
        unaff_EBX = (uint **)puVar17[4];
        pfVar22 = (float *)puVar17[5];
        pbVar19 = (byte *)puVar17[6];
        uVar16 = puVar17[7];
        iVar13 = CONCAT22((short)((uint)uVar16 >> 0x10),
                          (ushort)(byte)((char)uVar16 + (char)((uint)uVar16 >> 8) * '@'));
        *(uint *)(iVar13 + -0x7b09b5ea) = *(uint *)(iVar13 + -0x7b09b5ea) & (uint)unaff_EBP;
        puVar25 = puVar17 + 7;
        puVar17[7] = ppuVar26;
        while (pbVar19 != (byte *)0x0) {
          pbVar19 = pbVar19 + -1;
          out(*ppuVar26,(short)pfVar22);
          ppuVar26 = ppuVar26 + 1;
        }
      }
      else {
        puVar25 = puVar17 + -1;
        puVar17[-1] = 99;
        pfVar22 = (float *)((uint)param_2 | (uint)unaff_EBP);
        pbVar19 = pbVar19 + -2;
        if (pbVar19 != (byte *)0x0 && pfVar22 != (float *)0x0) goto code_r0x00401450;
        ppuVar26 = ppuVar28 + 1;
        out(*ppuVar28,(short)pfVar22);
      }
      in_ST0 = (float10)*pfVar22 / in_ST0;
      bVar8 = (byte)((uint)unaff_EBX >> 8);
      bVar34 = bVar8 < *(byte *)ppuVar29;
      iVar20 = CONCAT22((short)((uint)unaff_EBX >> 0x10),
                        CONCAT11(bVar8 - *(char *)ppuVar29,(char)unaff_EBX));
      uVar27 = CONCAT31((int3)((uint)iVar13 >> 8),
                        *(undefined *)
                         (iVar20 + (uint)(byte)((byte)iVar13 ^ *(byte *)(unaff_EBX + -0x9bac2ee))));
      bVar37 = SCARRY4((int)unaff_EBP,1);
      unaff_EBP = (uint **)((int)unaff_EBP + 1);
      bVar33 = (int)unaff_EBP < 0;
      bVar30 = unaff_EBP == (uint **)0x0;
      bVar8 = POPCOUNT((uint)unaff_EBP & 0xff);
      *(undefined4 **)((int)puVar25 + -4) = puVar25;
      param_2 = *(uint ***)((int)puVar25 + -4);
      LOCK();
      unaff_EBX = *(uint ***)(pbVar19 + -99);
      *(int *)(pbVar19 + -99) = iVar20;
      UNLOCK();
      ppuVar14 = (uint **)((int)puVar25 + 4);
      ppuVar21 = (uint **)((int)puVar25 + 4);
      if (bVar30 || bVar37 != bVar33) {
        *(char *)((int)ppuVar29 + -0x45) = *(char *)((int)ppuVar29 + -0x45) << 1;
        bVar34 = false;
        bVar37 = false;
        param_2 = (uint **)((uint)param_2 & (uint)unaff_EBP);
        bVar33 = (int)param_2 < 0;
        bVar30 = param_2 == (uint **)0x0;
        bVar32 = (POPCOUNT((uint)param_2 & 0xff) & 1U) == 0;
        ppuVar28 = ppuVar26;
        break;
      }
LAB_00401400:
      ppuVar14 = ppuVar21;
      bVar32 = (bVar8 & 1) == 0;
      if (!bVar34 && !bVar30) goto LAB_0040138b;
      ppuVar21 = ppuVar14;
      ppuVar28 = ppuVar26;
    } while (pbVar19 != (byte *)0x0);
    pdVar24 = (double *)((int)ppuVar14 + -4);
    *(uint *)((int)ppuVar14 + -4) =
         (uint)(in_NT & 1) * 0x4000 | (uint)bVar37 * 0x800 | (uint)(in_IF & 1) * 0x200 |
         (uint)(in_TF & 1) * 0x100 | (uint)bVar33 * 0x80 | (uint)bVar30 * 0x40 |
         (uint)(in_AF & 1) * 0x10 | (uint)bVar32 * 4 | (uint)bVar34 | (uint)(in_ID & 1) * 0x200000 |
         (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
    bVar8 = *(byte *)((int)unaff_EBP + -0x62e5632b);
    bVar31 = (byte)param_2 - *(byte *)((int)unaff_EBP + -0x62e5632b);
    puVar17 = (undefined4 *)
              CONCAT22((short)(uVar27 >> 0x10),
                       (ushort)(byte)((char)uVar27 + (char)(uVar27 >> 8) * -0xc));
    cVar36 = *(char *)((int)puVar17 + 0xe);
    piVar15 = (int *)*puVar17;
    LOCK();
    puVar4 = ppuVar28[0x8eed9f4];
    ppuVar28[0x8eed9f4] = (uint *)unaff_EBX;
    UNLOCK();
    do {
      uVar27 = CONCAT22((short)((uint)pdVar24 >> 0x10),
                        (ushort)(byte)((char)pdVar24 + (char)((uint)pdVar24 >> 8) * '.'));
      pbVar3 = (byte *)(CONCAT31((int3)((uint)param_2 >> 8),
                                 (bVar31 - bVar34) + cVar36 +
                                 ((byte)param_2 < bVar8 || bVar31 < bVar34)) + -0x62c56b70);
      *pbVar3 = *pbVar3 | 0xd4;
      out(0xf4,uVar27);
      bVar10 = (byte)(uVar27 ^ 0xdd);
      cVar35 = *(char *)((int)puVar4 + ((uVar27 ^ 0xdd) & 0xff));
      pdVar24 = (double *)CONCAT31((int3)(uVar27 >> 8),cVar35);
      cVar35 = (byte)pbVar19 + bVar10 + cVar35 + CARRY1((byte)pbVar19,bVar10);
      pbVar19 = (byte *)CONCAT31((int3)((uint)pbVar19 >> 8),cVar35);
    } while (cVar35 != '\0');
    bVar34 = pdVar24 < *ppuVar29;
  }
  iVar13 = *piVar15;
  pbVar3 = (byte *)(CONCAT31((int3)((uint)pdVar24 >> 8),(char)pdVar24 + -0x2c + bVar34) + 0x2180d756
                   );
  *pbVar3 = ~*pbVar3;
  *(uint ***)(iVar13 + -4) = unaff_EBP;
  do {
    *pbVar19 = *pbVar19 & 0x55;
  } while( true );
}



// WARNING: Unable to track spacebase fully for stack

void entry(void)

{
  uint *puVar1;
  uint *puVar2;
  undefined4 *puVar3;
  uint **ppuVar4;
  uint *puVar5;
  short sVar6;
  undefined2 in_SS;
  int *piVar7;
  
  sVar6 = (short)&stack0xffffffe0 + -4;
  piVar7 = (int *)CONCAT22((short)((uint)&stack0xffffffe0 >> 0x10),sVar6);
  puVar3 = (undefined4 *)segment(in_SS,sVar6);
  *puVar3 = 0x43100c;
  ppuVar4 = (uint **)(*piVar7 + 0x5a);
  do {
    puVar5 = *ppuVar4;
    puVar1 = ppuVar4[1];
    puVar2 = ppuVar4[2];
    do {
      *puVar5 = *puVar5 ^ (uint)puVar2;
      puVar5 = puVar5 + 1;
    } while ((int)puVar5 < (int)puVar1);
    ppuVar4 = ppuVar4 + 3;
  } while (*ppuVar4 != (uint *)0x0);
  FUN_00401219((uint **)piVar7[7],(uint **)piVar7[6],piVar7[10],(uint **)piVar7[0xb],piVar7[0xc],
               (uint **)piVar7[0xd],(uint **)piVar7[0xe],(uint **)piVar7[0xf],(uint **)piVar7[0x10],
               (uint **)piVar7[0x11],(uint **)piVar7[0x12],(uint **)piVar7[0x13],
               (uint **)piVar7[0x14],(uint **)piVar7[0x15]);
  return;
}


