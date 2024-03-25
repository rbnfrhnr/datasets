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




// WARNING: Instruction at (ram,0x0040133a) overlaps instruction at (ram,0x00401338)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00401219(int param_1)

{
  char *pcVar1;
  undefined6 uVar2;
  byte bVar3;
  int in_EAX;
  undefined4 *puVar4;
  int *piVar5;
  int extraout_ECX;
  int iVar6;
  uint uVar7;
  undefined4 **ppuVar8;
  int iVar9;
  undefined *puVar10;
  undefined *puVar11;
  undefined *puVar12;
  int *piVar13;
  int iVar15;
  undefined4 *puVar16;
  int unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  bool bVar17;
  char cVar18;
  undefined2 in_FPUControlWord;
  undefined8 uVar19;
  undefined4 *puStack_3ae0;
  undefined4 *puStack_3adc;
  undefined4 uStack_3ad4;
  uint uStack_3ad0;
  int *piStack_3acc;
  int aiStack_3ac8 [3738];
  undefined4 **ppuStack_60;
  int local_24;
  undefined4 *apuStack_8 [2];
  undefined4 *puVar14;
  
  apuStack_8[1] = (undefined4 *)(in_EAX + 0x614108f1);
  ppuStack_60 = apuStack_8 + 1;
  ppuVar8 = apuStack_8 + 1;
  cVar18 = '\x16';
  puVar4 = apuStack_8[1];
  do {
    puVar4 = puVar4 + -1;
    ppuVar8 = ppuVar8 + -1;
    *ppuVar8 = (undefined4 *)*puVar4;
    cVar18 = cVar18 + -1;
  } while ('\0' < cVar18);
  local_24 = local_24 - unaff_EDI;
  *(char *)(param_1 + 1) = *(char *)(param_1 + 1) - (char)apuStack_8[1];
  pcVar1 = (char *)(aiStack_3ac8[0] + 0x44 + (int)piStack_3acc * 8);
  *pcVar1 = *pcVar1 + (char)((uint)piStack_3acc >> 8);
  *(byte *)((int)piStack_3acc + 0x61) = *(byte *)((int)piStack_3acc + 0x61) | (byte)aiStack_3ac8[0];
  iVar9 = (int)aiStack_3ac8 << ((byte)piStack_3acc & 0x1f);
  *(int **)(iVar9 + -4) = piStack_3acc;
  bVar3 = (byte)aiStack_3ac8[0] ^ *(byte *)puStack_3ae0;
  puVar14 = *(undefined4 **)(iVar9 + -4);
  puVar4 = (undefined4 *)(iVar9 + -4);
  *(undefined4 **)(iVar9 + -4) = puStack_3adc;
  cVar18 = '\x17';
  do {
    puStack_3adc = puStack_3adc + -1;
    puVar4 = puVar4 + -1;
    *puVar4 = *puStack_3adc;
    cVar18 = cVar18 + -1;
  } while ('\0' < cVar18);
  *(int *)(iVar9 + -100) = iVar9 + -4;
  puVar4 = (undefined4 *)(int)(short)CONCAT31((int3)((uint)aiStack_3ac8[0] >> 8),bVar3);
  iVar15 = *(int *)(iVar9 + -0xb868);
  piVar13 = (int *)(iVar9 + -0xb864);
  if (bVar3 == 0) {
    piStack_3acc = (int *)0x416297e8;
code_r0x004012b9:
    uVar7 = (uStack_3ad0 | *(uint *)((int)puVar4 + 0x62)) + 1 | *(uint *)((int)puVar4 + 0x62);
    puVar4[2] = puVar4[2] | uVar7;
    iVar6 = (int)piStack_3acc + 1;
    if (iVar6 != 0 && piStack_3acc == (int *)0xfffffffe) {
      if (piStack_3acc != (int *)0xfffffffe &&
          SCARRY4((int)piStack_3acc + 1,1) == (int)piStack_3acc + 2 < 0) goto code_r0x00401342;
      puStack_3ae0 = *(undefined4 **)((int)piVar13 + 4);
      iVar15 = *(int *)((int)piVar13 + 8);
      piStack_3acc = *(int **)((int)piVar13 + 0x18);
      puVar4 = *(undefined4 **)((int)piVar13 + 0x1c);
      piVar13 = (int *)((int)piVar13 + 0x20);
    }
    else {
      piStack_3acc = (int *)CONCAT31((int3)((uint)iVar6 >> 8),(char)iVar6 - (char)uVar7);
      puVar4[-8] = puVar4[-8] & uVar7;
    }
  }
  else {
    *(undefined *)(iVar15 + 0x74) = 0;
    iVar6 = uStack_3ad0 + 1;
    *(int *)(iVar9 + -0xb868) = iVar9 + -0xb864;
    *(undefined4 *)(iVar9 + -0xb86c) = 0xa5c22c7c;
    *(undefined4 *)(iVar9 + -0xb870) = 0xa5c22c7c;
    *(int **)(iVar9 + -0xb874) = piStack_3acc;
    *(int *)(iVar9 + -0xb878) = iVar6;
    *(undefined4 *)(iVar9 + -0xb87c) = uStack_3ad4;
    *(int *)(iVar9 + -0xb880) = iVar9 + -0xb86c;
    *(int *)(iVar9 + -0xb884) = iVar15;
    *(undefined4 **)(iVar9 + -0xb888) = puStack_3ae0;
    *(undefined4 **)(iVar9 + -0xb88c) = puVar14;
    uStack_3ad0 = (int)piStack_3acc * 0x45290812;
    if (piStack_3acc != (int *)0x1 && iVar6 != 0) {
      *(byte *)((int)piStack_3acc + 0x31) = *(byte *)((int)piStack_3acc + 0x31) | 0x7c;
      *(undefined2 *)(iVar9 + -0xb890) = in_ES;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    _DAT_a5c22c34 = _DAT_a5c22c34 | (uint)puStack_3ae0;
    uVar7 = piStack_3acc[-0x12];
    piVar13 = (int *)(iVar9 + -0xb88c + uVar7);
    puVar10 = (undefined *)(iVar9 + -0xb88c + uVar7);
    puVar4 = (undefined4 *)(-0x518e34be - (uint)CARRY4(iVar9 - 0xb88c,piStack_3acc[-0x12]));
    if (puVar4 == (undefined4 *)0x0) {
      puVar4 = (undefined4 *)0x0;
      goto code_r0x004012b9;
    }
    piVar5 = (int *)((int)piStack_3acc + -1);
    puVar16 = puVar14;
    if (piVar5 != (int *)0x0 && puVar4 != (undefined4 *)0x0) {
LAB_004012b4_3:
      *(undefined4 **)(iVar9 + uVar7 + -0xb890) = puVar16;
      puVar12 = (undefined *)(iVar9 + uVar7 + -0xb894);
      *(undefined4 **)(iVar9 + uVar7 + -0xb894) = puVar16;
      goto LAB_004012c1_1;
    }
    puVar16 = (undefined4 *)CONCAT31((int3)((uint)puVar4 >> 8),(char)puVar4 + '\x0f');
    bVar17 = (uStack_3ad0 & *(uint *)((int)puVar16 + -9)) == 0;
    piVar5 = piStack_3acc;
    puVar4 = puVar14;
    if (bVar17) goto LAB_004012b4_3;
    do {
      piVar5 = (int *)((int)piStack_3acc + -1);
      puVar12 = puVar10;
      if (piVar5 == (int *)0x0 || bVar17) {
        cVar18 = piVar5 == (int *)0xffffffff;
        puVar11 = puVar10 + -4;
        *(undefined4 *)(puVar10 + -4) = 0x40127e;
        uVar19 = func_0x24312ef3();
        *(int *)(puVar11 + -4) = (int)uVar19;
        puVar12 = puVar11 + -4;
        if (extraout_ECX + -1 == 0 || cVar18 != '\0') {
          puVar12 = puVar11;
        }
        *(int *)(puVar12 + -4) = (int)uVar19;
        *puVar4 = *puStack_3ae0;
        *(int *)(CONCAT31((int3)((ulonglong)uVar19 >> 0x28),
                          (byte)((ulonglong)uVar19 >> 0x20) | (byte)uVar19) + 0x73) =
             extraout_ECX + -1;
        return;
      }
LAB_004012c1_1:
      *(undefined4 **)(puVar12 + -4) = puVar16;
      *(byte *)((int)piVar5 + -0x1f) = *(byte *)((int)piVar5 + -0x1f) | (byte)puVar16;
      *piVar5 = *piVar5 << 1;
      bVar17 = *piVar5 == 0;
      puVar10 = puVar12 + -8;
      *(undefined4 **)(puVar12 + -8) = puVar16;
      piStack_3acc = (int *)((int)piVar5 + -1);
    } while (piStack_3acc != (int *)0x0 && !bVar17);
    *(undefined2 *)(puVar12 + -0xc) = in_SS;
    piVar13 = (int *)(puVar12 + -0x10);
    *(undefined4 **)(puVar12 + -0x10) = puVar16;
    puVar4 = (undefined4 *)CONCAT31((int3)((uint)puVar16 >> 8),(byte)puVar16 | (byte)piStack_3acc);
  }
  DAT_14bef3d3 = SUB41(puVar4,0);
  piVar13[-1] = (int)piVar13;
  uVar2 = *(undefined6 *)((int)piStack_3acc + -0x1741091d);
  uVar7 = piVar13[-1];
  piStack_3acc[7] = piStack_3acc[7] - iVar15;
  piStack_3acc[-5] = piStack_3acc[-5] | uVar7;
  iVar6 = *piVar13;
  puStack_3ae0[2] = *puVar4;
  *(int *)((int)piVar13 + iVar6 + 4) = iVar6;
  *(byte *)(iVar6 + -0x69) = *(byte *)(iVar6 + -0x69) | (byte)((uint6)uVar2 >> 8);
  in((short)uVar2 + -1);
  *(undefined4 *)(iVar15 + 9) = 0x11f7aed2;
  bVar3 = (byte)*(undefined4 *)((int)piVar13 + iVar6 + 0x1c) & 0x1f;
  iVar15 = *(int *)((uint)((int)piVar13 + iVar6 + 0x24) >> bVar3 |
                   (int)piVar13 + iVar6 + 0x24 << 0x20 - bVar3);
  *(undefined2 *)(*(int *)((int)piVar13 + iVar6 + 4) + 0x3c) = in_FPUControlWord;
  puVar16 = *(undefined4 **)(iVar15 + 0xc);
  uStack_3ad4 = *(undefined4 *)(iVar15 + 0x14);
  uVar7 = *(uint *)(iVar15 + 0x18);
  iVar6 = *(int *)(iVar15 + 0x1c);
  out((short)uVar7,*(undefined4 *)(iVar15 + 0x20));
  puVar14 = (undefined4 *)(iVar15 + 0x20);
  puVar4 = (undefined4 *)(iVar15 + 0x20);
  *(undefined4 **)(iVar15 + 0x20) = puVar16;
  cVar18 = '\x1a';
  do {
    puVar16 = puVar16 + -1;
    puVar14 = puVar14 + -1;
    *puVar14 = *puVar16;
    cVar18 = cVar18 + -1;
  } while ('\0' < cVar18);
  *(int *)(iVar15 + -0x4c) = iVar15 + 0x20;
  piVar13 = (int *)(iVar15 + -0xbd30);
  iVar6 = iVar6 + 1;
code_r0x00401342:
  if (iVar6 == 0) {
    return;
  }
  *(undefined2 *)((int)piVar13 + -4) = in_CS;
  *(undefined4 *)((int)piVar13 + -8) = uStack_3ad4;
  *(char *)(uVar7 + 0xe2a48105) = (char)((uint)puVar4 >> 8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void __fastcall entry(int param_1)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x1f95;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x8506141;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xc74;
  puVar2 = &DAT_0042b000;
  do {
    *puVar2 = *puVar2 ^ 0x28e234c8;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219(param_1);
  return;
}


