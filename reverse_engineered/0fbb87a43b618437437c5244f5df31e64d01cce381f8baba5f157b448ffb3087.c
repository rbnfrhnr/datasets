typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
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
// WARNING: Instruction at (ram,0x00401232) overlaps instruction at (ram,0x00401231)
// 
// WARNING: Removing unreachable block (ram,0x00401236)
// WARNING: Removing unreachable block (ram,0x00401244)
// WARNING: Removing unreachable block (ram,0x0040124a)
// WARNING: Removing unreachable block (ram,0x004011cb)
// WARNING: Removing unreachable block (ram,0x00401164)
// WARNING: Removing unreachable block (ram,0x004011cf)
// WARNING: Removing unreachable block (ram,0x004011da)
// WARNING: Removing unreachable block (ram,0x00401232)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall
FUN_00401219(int param_1,undefined6 *param_2,uint *param_3,uint *param_4,undefined4 *param_5,
            uint *param_6)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  code *pcVar4;
  undefined6 uVar5;
  uint uVar6;
  ushort uVar7;
  short sVar8;
  int iVar9;
  uint uVar10;
  uint *puVar11;
  uint uVar12;
  undefined2 uVar13;
  byte bVar14;
  byte bVar15;
  int unaff_EBX;
  uint unaff_EBP;
  uint **unaff_ESI;
  int iVar16;
  uint *puVar17;
  undefined2 in_ES;
  bool bVar18;
  char in_AF;
  undefined2 in_FPUControlWord;
  undefined2 in_FPUStatusWord;
  undefined2 in_FPUTagWord;
  undefined2 in_FPULastInstructionOpcode;
  undefined4 in_FPUDataPointer;
  undefined4 in_FPUInstructionPointer;
  undefined in_XMM0 [16];
  undefined in_YMM5 [32];
  int unaff_retaddr;
  undefined2 in_stack_00000024;
  
  while( true ) {
    if (param_1 != 1) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    cVar1 = *(char *)(unaff_EBP + 0x1a + unaff_retaddr);
    if ((int)_DAT_a7afbd6b == 1) break;
    param_1 = (int)_DAT_a7afbd6b + -2;
    if (param_1 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    unaff_ESI = (uint **)*(undefined6 *)(unaff_EBX + 0x58643c35);
  }
  DAT_6b3c9558 = cVar1 + -1;
  if (0 < CONCAT31((int3)((uint)unaff_retaddr >> 8),cVar1)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  puVar11 = param_4;
  iVar9 = -1;
  do {
    out(0x26,puVar11);
    if (iVar9 != 1) {
      puVar11 = *unaff_ESI;
      puVar17 = (uint *)((int)param_3 + 1);
      bVar18 = (byte)puVar11 < *(byte *)param_3;
      param_4 = puVar11;
      break;
    }
    uVar5 = *(undefined6 *)(((uint)puVar11 | 0x9b) - 0x1e);
    param_5 = (undefined4 *)CONCAT22(param_5._2_2_,in_ES);
    unaff_EBX = CONCAT22((short)((uint6)uVar5 >> 0x10),CONCAT11(0xd1,(char)uVar5));
    iVar9 = 0;
    do {
      bVar15 = (byte)((uint)unaff_EBX >> 8);
      bVar14 = (byte)unaff_EBX | bVar15;
      in_XMM0 = minps(in_XMM0,*(undefined (*) [16])
                               (CONCAT31((int3)((uint)unaff_EBX >> 8),bVar14) + -0x260b5846));
      unaff_EBX = CONCAT22((short)((uint)unaff_EBX >> 0x10),
                           CONCAT11(bVar15 - (char)((uint)param_2 >> 8),bVar14));
      bVar18 = false;
      bVar14 = (byte)((uint)iVar9 >> 8) ^ (byte)param_6;
      iVar9 = CONCAT22((short)((uint)iVar9 >> 0x10),CONCAT11(bVar14,(char)iVar9)) + -1;
    } while (iVar9 != 0);
    puVar11 = *unaff_ESI;
    puVar17 = param_3;
    if ((char)bVar14 < '\0') break;
    _DAT_69e62d3a = _DAT_930be27c;
    bVar18 = 0x3acd6d4c < _DAT_930be27c;
    iVar9 = _DAT_930be27c + 0xc53292b3;
    uVar7 = (ushort)(byte)((char)iVar9 + (char)((uint)iVar9 >> 8) * 'g');
    unaff_ESI = (uint **)(_DAT_930be264 + 1);
    puVar11 = (uint *)CONCAT31((int3)(CONCAT22((short)((uint)iVar9 >> 0x10),uVar7) >> 8),
                               *_DAT_930be264);
    iVar9 = _DAT_930be278;
    param_2 = _DAT_930be274;
    unaff_EBX = _DAT_930be270;
    unaff_EBP = _DAT_930be268;
    param_3 = _DAT_930be260;
    puVar17 = _DAT_930be260;
  } while (bVar18 || uVar7 == 0);
  do {
    iVar9 = (int)puVar11 + (0x51af52f8 - (uint)bVar18);
    vpackuswb_avx2(in_YMM5,*(undefined (*) [32])(iVar9 + 0x81da676));
    *(undefined2 *)((int)puVar17 + 0x58e22d57) = *(undefined2 *)((int)puVar17 + 0x58e22d57);
    unaff_EBP = unaff_EBP & CONCAT31((int3)((uint)iVar9 >> 8),0xe);
    puVar11 = (uint *)((int)param_5 + -0x3775a651);
    bVar14 = (byte)param_4 & 0x1f;
    uVar10 = *puVar11;
    *puVar11 = *puVar11 >> bVar14;
    bVar2 = ((uint)param_4 & 0x1f) != 0;
    bVar3 = (uVar10 >> bVar14 - 1 & 1) != 0;
    bVar18 = ((uint)param_4 & 0x1f) != 0;
    if ((!bVar2 || !bVar3) && ((bVar18 || unaff_EBP != 0) && (!bVar18 || *puVar11 != 0))) {
      bVar18 = false;
code_r0x00401330:
      *(char *)((int)param_6 + -0x3b) = (*(char *)((int)param_6 + -0x3b) + '%') - bVar18;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (param_4 == (uint *)0x1) {
      puVar11 = puVar17 + 1;
      uVar13 = SUB42(param_2,0);
      uVar10 = in(uVar13);
      *puVar17 = uVar10;
      uVar10 = CONCAT11(-(bVar2 && bVar3) - (char)unaff_EBX,(byte)param_4) - 1;
      if (uVar10 == 0) {
        out(uVar13,(byte)param_6);
        *(undefined4 *)((int)param_6 + -0x26394c7b) = *(undefined4 *)((int)param_6 + -0x26394c7b);
        bVar18 = false;
        goto code_r0x00401330;
      }
      bVar18 = *param_6 < uVar10;
      *(char *)((int)param_6 + -0x53) = (char)unaff_EBX;
      sVar8 = (short)uVar10 + -1;
      iVar9 = CONCAT22((short)(uVar10 >> 0x10),sVar8);
      if (sVar8 != 0) {
        while( true ) {
          uVar6 = CONCAT22((short)((uint)param_6 >> 0x10),
                           CONCAT11((((uint)param_6 & 0x4c) == 0) << 6 | in_AF << 4 |
                                    ((POPCOUNT((byte)param_6 & 0x4c) & 1U) == 0) << 2,(byte)param_6)
                          );
          puVar17 = (uint *)((uVar6 | 0x200) + 0x91bc0785);
          bVar14 = (byte)iVar9 & 0x1f;
          uVar10 = *puVar17;
          *puVar17 = uVar10 >> bVar14 | uVar10 << 0x21 - bVar14;
          uVar12 = CONCAT22((short)((uint)iVar9 >> 0x10),CONCAT11(0xe7,(byte)iVar9));
          out(*param_5,uVar13);
          uVar10 = ((CONCAT31((int3)(uVar6 >> 8),DAT_9f4ca0d3) | 0xe94bf00) + 0xbe75f7c7) -
                   (uint)(uVar12 < (uint)param_5[(int)puVar11]) ^ 0xe7;
          if (uVar12 != 1) break;
          iVar9 = -1;
          *(char *)param_2 = *(char *)param_2 + '\x01';
          in_AF = (*(uint6 *)(uVar10 + 0x2d3a4897) & 0x100000000000) != 0;
          puVar11 = (uint *)(*(int *)(unaff_EBP + 0xe7b50e94) * 0x3b);
          param_6 = (uint *)(CONCAT22(in_stack_00000024,in_ES) | 0xbe);
          param_5 = param_5 + 2;
        }
        *(byte *)(puVar11 + 1) = *(byte *)(puVar11 + 1) << 6;
        *(undefined *)(uVar10 + 4) = *(undefined *)(param_5 + 3);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      iVar16 = (int)*param_2;
      puVar11 = (uint *)(iVar9 + -1);
      if (puVar11 == (uint *)0x0) {
        iVar16 = (int)*param_2;
        puVar11 = (uint *)(iVar9 + -2);
        if (puVar11 != (uint *)0x0) {
          *(undefined2 *)param_2 = in_FPUControlWord;
          *(undefined2 *)((int)param_2 + 4) = in_FPUStatusWord;
          *(undefined2 *)(param_2 + 1) = in_FPUTagWord;
          *(undefined4 *)((int)param_2 + 0x14) = in_FPUDataPointer;
          *(undefined4 *)((int)param_2 + 0xc) = in_FPUInstructionPointer;
          *(undefined2 *)((int)param_2 + 0x12) = in_FPULastInstructionOpcode;
          goto code_r0x00401330;
        }
      }
      *puVar11 = *puVar11 | *(int *)(iVar16 + 0x5c96aecc) * -0xc;
      pcVar4 = (code *)swi(3);
      (*pcVar4)();
      return;
    }
    bVar18 = *(byte *)param_5 < *(byte *)puVar17;
    puVar11 = param_6;
    puVar17 = (uint *)((int)puVar17 + 1);
  } while( true );
}



void __fastcall
entry(int param_1,undefined6 *param_2,uint *param_3,uint *param_4,undefined4 *param_5,uint *param_6)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x58c558e2;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x40915c);
  puVar1 = &DAT_0042c000;
  do {
    *puVar1 = *puVar1 ^ 0x24c307a9;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42f3f8);
  FUN_00401219(param_1,param_2,param_3,param_4,param_5,param_6);
  return;
}


