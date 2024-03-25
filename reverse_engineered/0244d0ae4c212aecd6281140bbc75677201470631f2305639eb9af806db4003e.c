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




// WARNING: Instruction at (ram,0x00401331) overlaps instruction at (ram,0x0040132c)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x004012c2)
// WARNING: Removing unreachable block (ram,0x00401332)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __fastcall FUN_00401219(int param_1,undefined4 param_2)

{
  int *piVar1;
  uint **ppuVar2;
  code *pcVar3;
  char cVar4;
  int iVar5;
  uint uVar6;
  undefined4 extraout_ECX;
  int **ppiVar7;
  int **ppiVar8;
  byte bVar10;
  uint *puVar9;
  undefined2 uVar11;
  byte bVar12;
  uint *unaff_EBX;
  int ***pppiVar13;
  undefined *puVar14;
  undefined *puVar15;
  undefined *puVar16;
  int unaff_EBP;
  int iVar17;
  undefined4 *unaff_ESI;
  int *piVar18;
  uint *unaff_EDI;
  int **ppiVar19;
  uint *puVar20;
  uint uVar21;
  undefined2 in_ES;
  undefined2 in_SS;
  bool bVar22;
  byte in_AF;
  bool bVar23;
  undefined8 uVar24;
  uint *puStack_94;
  int iStack_90;
  int ***pppiStack_8c;
  undefined *puStack_88;
  int iStack_84;
  uint *puStack_80;
  undefined4 uStack_7c;
  int **ppiStack_78;
  int **ppiStack_74;
  int **ppiStack_70;
  undefined *puStack_6c;
  uint uStack_68;
  byte *pbStack_64;
  int **ppiStack_60;
  int iStack_5c;
  int **ppiStack_58;
  int **ppiStack_54;
  int **ppiStack_50;
  undefined *puStack_4c;
  uint uStack_48;
  byte *pbStack_44;
  int **ppiStack_40;
  int iStack_3c;
  int **ppiStack_38;
  int **ppiStack_34;
  int **ppiStack_30;
  undefined *puStack_2c;
  uint uStack_28;
  byte *pbStack_24;
  int **ppiStack_20;
  int iStack_1c;
  int **ppiStack_18;
  int iStack_14;
  undefined *puStack_10;
  uint *puStack_c;
  undefined4 uStack_8;
  
  puVar20 = unaff_EBX;
  if (param_1 == 1) {
    *unaff_EDI = *unaff_EDI ^ (uint)unaff_ESI;
    unaff_ESI = (undefined4 *)((int)unaff_ESI - (int)(uint *)((int)unaff_EBX + 1));
    puVar20 = (uint *)((int)unaff_EBX + 1);
    unaff_EDI = unaff_EBX;
  }
  *(uint *)((int)unaff_EDI + -0x27) = *(uint *)((int)unaff_EDI + -0x27) ^ (uint)puVar20;
  iVar17 = unaff_EBP + unaff_ESI[-0x12] +
           (uint)((byte)((uint)param_2 >> 8) < *(byte *)(param_1 + 0x36));
  *unaff_EDI = *unaff_EDI ^ (uint)unaff_ESI;
  uVar24 = func_0xb0ac7950();
  ppiVar7 = (int **)CONCAT22((short)((uint)extraout_ECX >> 0x10),
                             CONCAT11((byte)((uint)extraout_ECX >> 8) ^
                                      (byte)((ulonglong)uVar24 >> 0x28),(char)extraout_ECX));
  ppiStack_34 = (int **)(unaff_ESI + 1);
  out(*unaff_ESI,(short)((ulonglong)uVar24 >> 0x20));
  ppiStack_30 = (int **)((int)unaff_EDI + 1);
  uStack_8 = CONCAT31((int3)((ulonglong)uVar24 >> 0x28),0xf3);
  puStack_c = puVar20;
  puStack_10 = &stack0x00000004;
  iStack_14 = iVar17;
  ppiStack_18 = ppiStack_34;
  *(uint *)(iVar17 + 0x43) = *(uint *)(iVar17 + 0x43) ^ (uint)puVar20;
  LOCK();
  piVar18 = *ppiVar7;
  *ppiVar7 = (int *)uVar24;
  UNLOCK();
  uVar21 = CONCAT31((int3)((uint)puVar20 >> 8),(byte)puVar20 | *(byte *)((int)ppiVar7 + 0x13));
  iVar5 = (int)piVar18 + -1;
  unaff_EDI[0x19] = unaff_EDI[0x19] ^ uVar21;
  pbStack_24 = (byte *)0xdfab3773;
  in_AF = 9 < ((byte)iVar5 & 0xf) | in_AF;
  uVar6 = CONCAT31((int3)((uint)iVar5 >> 8),(byte)iVar5 + in_AF * '\x06') & 0xffffff0f;
  cVar4 = (char)uVar6;
  uVar6 = CONCAT31((int3)(CONCAT22((short)(uVar6 >> 0x10),
                                   CONCAT11((char)((uint)iVar5 >> 8) + in_AF,cVar4)) >> 8),
                   cVar4 + '\x1f') - 1U ^ (uint)ppiVar7;
  if (uVar6 == 0) {
    cVar4 = *(char *)ppiStack_34;
    pbStack_24 = (byte *)0xdfab3721;
    ppiVar8 = ppiVar7;
    uVar6 = uVar21;
    ppiStack_34 = (int **)((int)unaff_ESI + 5);
    ppiVar19 = (int **)((int)unaff_EDI + 2);
    if ((POPCOUNT(cVar4 - *(char *)ppiStack_30) & 1U) != 0) {
      return 0;
    }
  }
  else {
    *(uint *)(iVar17 + 0x43) = *(uint *)(iVar17 + 0x43) ^ 0xf31704f5;
    iVar5 = uVar6 - 1;
    *(uint *)((int)unaff_ESI + 0x75811e6a) =
         *(uint *)((int)unaff_ESI + 0x75811e6a) ^ (uint)ppiStack_30;
    uVar6 = uVar21 + 1;
    ppiVar8 = (int **)((int)ppiVar7 + -1);
    ppiVar19 = ppiStack_30;
    if (ppiVar8 == (int **)0x0) {
      in_AF = 9 < ((byte)iVar5 & 0xf) | in_AF;
      bVar10 = (byte)(iVar5 >> 0x1f);
      pbStack_24 = (byte *)CONCAT22((short)(iVar5 >> 0x1f),
                                    CONCAT11(bVar10 | *(byte *)ppiVar7,bVar10));
      *pbStack_24 = *pbStack_24 | 100;
      pbStack_24 = pbStack_24 + 1;
      ppiVar8 = ppiVar7;
      uVar6 = uVar21 + 3;
      ppiStack_34 = (int **)&DAT_7b21b2a6;
    }
  }
  bVar10 = (byte)((uint)pbStack_24 >> 8);
  DAT_1564310a = DAT_1564310a | bVar10;
  iStack_1c = *(int *)((int)ppiVar8 + -0x4a) * 0x373c87b4;
  uStack_28 = CONCAT31((int3)(uVar6 >> 8),(byte)uVar6 | (byte)ppiVar8) + 1;
  ppiStack_20 = ppiVar8;
  puStack_2c = (undefined *)&ppiStack_18;
  ppiStack_38 = ppiVar19;
  unaff_EDI[0x11] = unaff_EDI[0x11] ^ uStack_28;
  iStack_3c = iStack_1c;
  ppiStack_40 = ppiVar8;
  pbStack_44 = pbStack_24;
  uStack_48 = uStack_28;
  puStack_4c = (undefined *)&ppiStack_38;
  ppiStack_50 = ppiStack_30;
  ppiStack_54 = ppiStack_34;
  ppiStack_58 = ppiVar19;
  bVar12 = (byte)uStack_28 ^ *(byte *)(unaff_EDI + 0x11);
  uStack_68 = CONCAT31((int3)(uStack_28 >> 8),bVar12);
  iStack_5c = iStack_1c;
  ppiStack_60 = ppiVar8;
  pbStack_64 = pbStack_24;
  puStack_6c = (undefined *)&ppiStack_58;
  ppiStack_70 = ppiStack_30;
  ppiStack_74 = ppiStack_34;
  ppiStack_78 = ppiVar19;
  *(uint *)((int)ppiVar19 + 0x43) = *(uint *)((int)ppiVar19 + 0x43) ^ uStack_68;
  iVar5 = CONCAT22((short)((uint)iStack_1c >> 0x10),
                   CONCAT11((char)((uint)iStack_1c >> 8) - *(char *)((int)ppiVar8 + -0x661dbc89),
                            (char)iStack_1c));
  uVar6 = iVar5 + 1;
  iVar17 = CONCAT22((short)(uStack_28 >> 0x10),CONCAT11(0x2b,bVar12)) + 1;
  uVar21 = CONCAT22((short)((uint)iVar17 >> 0x10),
                    CONCAT11((byte)((uint)iVar17 >> 8) | *(byte *)(iVar5 + -0x310e3f0b),(char)iVar17
                            ));
  puVar9 = (uint *)(CONCAT22((short)((uint)pbStack_24 >> 0x10),
                             CONCAT11(bVar10 | *(byte *)ppiVar8,(char)pbStack_24)) + 1);
  puVar20 = (uint *)((int)ppiVar19 + 1);
  if ((POPCOUNT((int)ppiStack_34 - (int)ppiVar8 & 0xff) & 1U) == 0) {
    puVar14 = (undefined *)((int)unaff_EDI + 5);
    piVar18 = (int *)0xcf748784;
    iVar5 = uVar6 + *(int *)((int)ppiVar19 + 0x6013cb75) + (uint)(ppiStack_34 < ppiVar8);
    *(uint *)((int)ppiVar19 + 0x7d) = *(uint *)((int)ppiVar19 + 0x7d) ^ uVar21;
    in_AF = 9 < ((byte)iVar5 & 0xf) | in_AF;
    uVar6 = CONCAT31((int3)((uint)iVar5 >> 8),(byte)iVar5 + in_AF * '\x06') & 0xffffff0f;
    iVar5 = CONCAT22((short)(uVar6 >> 0x10),CONCAT11((char)((uint)iVar5 >> 8) + in_AF,(char)uVar6));
  }
  else {
    cVar4 = (char)puVar9;
    puVar9 = (uint *)CONCAT22((short)((uint)puVar9 >> 0x10),
                              CONCAT11((byte)((uint)puVar9 >> 8) | *(byte *)ppiVar8,cVar4));
    LOCK();
    ppiVar7 = (int **)(uVar21 + 0x67cef4f1 + uVar6 * 8);
    piVar1 = *ppiVar7;
    *ppiVar7 = (int *)ppiStack_34;
    UNLOCK();
    bVar22 = uVar6 < *puVar9;
    bVar23 = SBORROW4(uVar6,*puVar9);
    iVar5 = uVar6 - *puVar9;
    pppiStack_8c = (int ***)ppiVar19;
    piVar18 = piVar1;
    if ((int)*puVar9 <= (int)uVar6) goto LAB_00401324;
    LOCK();
    ppiVar7 = (int **)((int)ppiVar19 + (int)ppiVar8 * 8 + 0x67cef4f1);
    piVar18 = *ppiVar7;
    *ppiVar7 = piVar1;
    UNLOCK();
    puVar9 = (uint *)CONCAT31((int3)((uint)puVar9 >> 8),cVar4 + (char)((uint)iVar5 >> 8) + bVar22);
    ppiVar8 = (int **)0x620a4340;
    bVar22 = 9 < ((byte)iVar5 & 0xf);
    ppiVar7 = ppiVar19;
    in_AF = bVar22;
    do {
      while( true ) {
        pppiVar13 = &ppiStack_74;
        pppiStack_8c = &ppiStack_74;
        if (!bVar22) break;
        bVar22 = false;
        *puVar20 = *puVar20 ^ (uint)piVar18;
      }
      if (CONCAT22((short)((uint)ppiVar8 >> 0x10),CONCAT11(2,(char)ppiVar8)) != 1) {
        pppiStack_8c = (int ***)*ppiVar7;
        *(undefined2 *)ppiVar7 = in_ES;
        goto LAB_0040132c_5;
      }
      uVar11 = (undefined2)((uint)puVar9 >> 0x10);
      bVar10 = (byte)((uint)puVar9 >> 8) | *(byte *)((int)puVar9 + -0x31c8b00d);
      ppiStack_74 = ppiVar7;
      cVar4 = '\x04';
      do {
        ppiVar7 = ppiVar7 + -1;
        pppiVar13 = (int ***)((int **)pppiVar13 + -1);
        *pppiVar13 = (int **)*ppiVar7;
        cVar4 = cVar4 + -1;
      } while ('\0' < cVar4);
      puStack_88 = (undefined *)&ppiStack_74;
      bVar22 = false;
      bVar23 = false;
      puVar9 = (uint *)CONCAT22(uVar11,CONCAT11(bVar10 ^ *(byte *)(CONCAT22(uVar11,CONCAT11(bVar10,(
                                                  char)puVar9)) + -0x36),(char)puVar9));
      ppiVar8 = (int **)0x0;
LAB_00401324:
      ppiVar7 = (int **)pppiStack_8c;
    } while (!bVar23);
    while( true ) {
      puVar9 = (uint *)CONCAT31((int3)((uint)puVar9 >> 8),0xb3);
      ppiVar8 = (int **)0xcdcac8cf;
      out(*(undefined *)piVar18,(short)puVar9);
      iStack_84 = (int)((longlong)_DAT_b8edb4cf * -0x359d0d3d);
      out((short)puVar9,0xb8edb4cf);
      ppiStack_78 = (int **)&DAT_b8edb4cf;
      uStack_7c = 0xcdcac8cf;
      puStack_80 = puVar9;
      puStack_88 = (undefined *)&ppiStack_74;
      iStack_90 = (int)piVar18 + 1;
      puStack_94 = puVar20;
      uVar6 = (uint)((longlong)iStack_84 != (longlong)_DAT_b8edb4cf * -0x359d0d3d);
      iVar5 = uVar6 + 0xe613432c;
      piVar18 = (int *)0xbec90bbb;
      if ((*(byte *)((int)ppiVar19 + -0x78ec308b) & (byte)iVar5) != 0) break;
LAB_0040132c_5:
      *(byte *)((int)ppiVar19 + 0x31c8cfba) = *(byte *)((int)ppiVar19 + 0x31c8cfba) ^ 0xc6;
    }
    piVar1 = (int *)(uVar6 + 0xe613435d);
    iVar17 = *piVar1;
    ppuVar2 = (uint **)((int)&puStack_94 + iVar17);
    puVar20 = *ppuVar2;
    puVar14 = (undefined *)((int)&iStack_90 + iVar17);
    puVar16 = (undefined *)((int)&iStack_90 + iVar17);
    if ((SCARRY4((int)&puStack_94,*piVar1) != SCARRY4((int)ppuVar2,0)) != (int)ppuVar2 < 0)
    goto LAB_00401376;
  }
  bVar10 = 9 < ((byte)iVar5 & 0xf) | in_AF;
  bVar12 = (byte)iVar5 + bVar10 * '\x06' & 0xf;
  *puVar9 = *puVar9 - (int)ppiVar8;
  puVar15 = puVar14 + 4;
  in_AF = 9 < bVar12 | bVar10;
  uVar6 = CONCAT31((int3)((uint)iVar5 >> 8),bVar12 + in_AF * '\x06') & 0xffff000f;
  iVar5 = CONCAT22((short)(uVar6 >> 0x10),
                   CONCAT11((char)((uint)iVar5 >> 8) + bVar10 + in_AF,(char)uVar6));
  uVar6 = *puVar9;
  *puVar9 = *puVar9 - (int)ppiVar8;
  pcVar3 = (code *)swi(4);
  puVar16 = puVar14 + 4;
  if (SBORROW4(uVar6,(int)ppiVar8) == true) {
    iVar5 = (*pcVar3)();
    puVar16 = puVar15;
  }
LAB_00401376:
  in_AF = 9 < ((byte)iVar5 & 0xf) | in_AF;
  uVar6 = CONCAT31((int3)((uint)iVar5 >> 8),(byte)iVar5 + in_AF * -6) & 0xffffff0f;
  iVar5 = CONCAT22((short)(uVar6 >> 0x10),CONCAT11((char)((uint)iVar5 >> 8) - in_AF,(char)uVar6));
  *(int *)((int)puVar20 + -1) = iVar5;
  *(undefined **)(puVar16 + -3) = (undefined *)((int)puVar20 + 3);
  iVar5 = iVar5 + -1;
  in_AF = 9 < ((byte)iVar5 & 0xf) | in_AF;
  bVar12 = (byte)iVar5 + in_AF * '\x06' & 0xf;
  uVar21 = (uint)(undefined *)((int)puVar20 + 3) ^ 0xffffffb6;
  bVar10 = 9 < bVar12 | in_AF;
  uVar6 = CONCAT31((int3)((uint)iVar5 >> 8),bVar12 + bVar10 * '\x06') & 0xffff000f;
  iVar5 = CONCAT22((short)(uVar6 >> 0x10),
                   CONCAT11((char)((uint)iVar5 >> 8) + in_AF + bVar10,(char)uVar6)) + uVar21;
  bVar10 = 9 < ((byte)iVar5 & 0xf) | bVar10;
  bVar12 = (byte)iVar5 + bVar10 * -6;
  bVar10 = 9 < (bVar12 & 0xf) | bVar10;
  uVar6 = CONCAT31((int3)((uint)iVar5 >> 8),bVar12 + bVar10 * '\x06') & 0xffffff0f;
  iVar5 = CONCAT22((short)(uVar6 >> 0x10),CONCAT11((char)((uint)iVar5 >> 8) + bVar10,(char)uVar6));
  _DAT_36c8217b = iVar5;
  _DAT_36c8257b = in_SS;
  *(uint *)((int)piVar18 + -0x34bb0a7b) =
       *(uint *)((int)piVar18 + -0x34bb0a7b) ^ (uint)(int *)(uVar21 + 1);
  *(int *)(uVar21 + 1) = iVar5;
  return iVar5 + uVar21 + 5;
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
  *puVar3 = 0x43000c;
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
  FUN_00401219(piVar7[7],piVar7[6]);
  return;
}


