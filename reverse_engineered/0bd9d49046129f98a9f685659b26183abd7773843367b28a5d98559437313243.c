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
// WARNING: Instruction at (ram,0x0040121b) overlaps instruction at (ram,0x00401219)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined __fastcall FUN_00401219(int param_1,int *param_2)

{
  byte *pbVar1;
  uint *puVar2;
  byte bVar3;
  ulonglong uVar4;
  undefined3 uVar5;
  ushort uVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  undefined uVar10;
  char cVar11;
  char cVar14;
  char cVar15;
  uint in_EAX;
  uint uVar12;
  uint uVar13;
  undefined3 uVar16;
  byte extraout_CL;
  undefined *puVar17;
  int extraout_ECX;
  int *piVar18;
  int extraout_EDX;
  int *unaff_EBX;
  undefined4 *puVar19;
  int unaff_EBP;
  int iVar20;
  int *unaff_ESI;
  int *unaff_EDI;
  char *pcVar21;
  int *piVar22;
  int iVar23;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 uVar24;
  int in_GS_OFFSET;
  bool bVar25;
  bool bVar26;
  byte in_AF;
  undefined8 uVar27;
  int *unaff_retaddr;
  undefined2 uVar28;
  undefined2 uStack_4;
  
  bVar26 = false;
code_r0x00401219:
  while( true ) {
    puVar2 = (uint *)((int)param_2 + 0x3652a53);
    bVar25 = CARRY4(*puVar2,(uint)&stack0x00000000);
    *puVar2 = (uint)(&stack0x00000000 + *puVar2);
    unaff_retaddr = (int *)CONCAT22((short)((uint)unaff_retaddr >> 0x10),in_ES);
    uVar16 = (undefined3)((uint)unaff_EBX >> 8);
    if (-1 < (int)*puVar2) break;
    *param_2 = *param_2 + unaff_EBP + (uint)bVar25;
    uVar12 = in_EAX | 0x656a4399;
    bVar8 = 9 < ((byte)uVar12 & 0xf) | in_AF;
    uVar13 = CONCAT31((int3)(uVar12 >> 8),(byte)uVar12 + bVar8 * '\x06') & 0xffffff0f;
    bVar9 = (byte)uVar13;
    _DAT_2a530340 = CONCAT22((short)(uVar13 >> 0x10),CONCAT11((char)(uVar12 >> 8) + bVar8,bVar9));
    puVar19 = (undefined4 *)CONCAT31(uVar16,(byte)unaff_EBX + (char)((uint)param_1 >> 8));
    bVar26 = CARRY4((uint)unaff_ESI,(uint)puVar19);
    unaff_ESI = (int *)((int)unaff_ESI + (int)puVar19);
    in_AF = 9 < bVar9 | bVar8;
    bVar9 = bVar9 + in_AF * '\x06';
    in_EAX = CONCAT31((int3)((uint)_DAT_2a530340 >> 8),
                      bVar9 + (0x90 < (bVar9 & 0xf0) | bVar26 | in_AF * (0xf9 < bVar9)) * '`') ^
             0x532769ab;
    piVar18 = (int *)((int)unaff_EDI + unaff_EBP + 0x7a1a977);
    *piVar18 = *piVar18 - (int)unaff_EDI;
    uVar5 = SegmentLimit(*puVar19);
    unaff_EDI = (int *)(uint)(ushort)uVar5;
    param_2 = (int *)(CONCAT31((int3)((uint)param_2 >> 8),
                               (char)param_2 + (char)((uint)unaff_EBX >> 8)) + 1);
    puVar17 = (undefined *)((int)unaff_EBX + 2);
    unaff_EBX = (int *)CONCAT31(uVar16,0x11);
    param_1 = CONCAT31((int3)((uint)puVar17 >> 8),(char)puVar17 - DAT_6568e323);
    in_ES = SUB42(puVar19,0);
    bVar26 = true;
  }
  pbVar1 = (byte *)((int)unaff_EDI + 0x43369a22);
  bVar8 = *pbVar1;
  bVar9 = *pbVar1;
  _DAT_42ac6980 = in_EAX;
  *pbVar1 = bVar9 + 0x9a + bVar25;
  bVar3 = 9 < ((byte)in_EAX & 0xf) | in_AF;
  bVar7 = (byte)in_EAX + bVar3 * '\x06';
  _DAT_a9905e89 =
       CONCAT31((int3)(in_EAX >> 8),
                bVar7 + (0x90 < (bVar7 & 0xf0) |
                        (0x65 < bVar8 || CARRY1(bVar9 + 0x9a,bVar25)) | bVar3 * (0xf9 < bVar7)) *
                        '`');
  iVar23 = *(int *)((int)unaff_EBX + 0x53031e9e);
  in_AF = 9 < ((byte)in_ES & 0xf) | bVar3;
  bVar8 = (byte)in_ES + in_AF * -6;
  if (param_1 != 0) {
    bVar8 = CONCAT31((int3)((uint)unaff_retaddr >> 8),
                     bVar8 + (0x9f < bVar8 |
                             (byte)unaff_EBX < *(byte *)(unaff_EBP + 8) | in_AF * (bVar8 < 6)) *
                             -0x60) < 0x2a5302dd;
    *(undefined4 *)((int)&uStack_4 + *(int *)(in_GS_OFFSET + (int)unaff_ESI)) = 0x40120b;
    uVar27 = func_0xb3899dc6();
    piVar18 = (int *)((ulonglong)uVar27 >> 0x20);
    *piVar18 = *piVar18 + unaff_EBP + (uint)bVar8;
    return *(undefined *)unaff_ESI;
  }
  iVar20 = unaff_EBP +
           *(int *)((int)unaff_EBX + (int)unaff_EDI + in_GS_OFFSET + iVar23 + 0x2a11b34d);
  uVar24 = 0xac03;
  uStack_4 = in_CS;
  func_0x279a7736();
  unaff_EBP = iVar20 + 1;
  unaff_EBX = (int *)CONCAT31(uVar16,0x11);
  unaff_EDI = (int *)((int)unaff_EDI + iVar23 + 1);
  in_CS = 0x313;
  uStack_4 = uVar24;
  uVar27 = func_0x2abb0327();
  param_2 = (int *)((ulonglong)uVar27 >> 0x20);
  uVar10 = in((short)((ulonglong)uVar27 >> 0x20));
  iVar23 = CONCAT31((int3)((ulonglong)uVar27 >> 8),uVar10);
  param_1 = extraout_ECX;
  do {
    unaff_ESI = (int *)((int)unaff_ESI + -1);
    piVar18 = unaff_EBX;
    piVar22 = unaff_EDI;
    while( true ) {
      unaff_EBX = piVar18;
      unaff_EDI = piVar22 + (uint)bVar26 * -2 + 1;
      cVar11 = (char)iVar23;
      cVar14 = (char)((uint)iVar23 >> 8);
      uVar24 = (undefined2)((uint)iVar23 >> 0x10);
      if ((POPCOUNT(iVar23 - *piVar22 & 0xff) & 1U) == 0) {
        in_EAX = CONCAT22(uVar24,CONCAT11(cVar14 - *(char *)(iVar20 + 4),cVar11));
        unaff_retaddr = unaff_EBX;
        goto code_r0x00401219;
      }
      cVar14 = cVar14 - *(char *)(iVar20 + -0x35);
      unaff_ESI = (int *)((int)unaff_ESI + -1);
      *(undefined *)unaff_EBX = 0x53;
      cVar15 = cVar14 - *(char *)(iVar20 + -0x3f);
      iVar23 = CONCAT22(uVar24,CONCAT11(cVar15,cVar11));
      if (cVar15 != '\0' && *(char *)(iVar20 + -0x3f) <= cVar14) break;
      out(0xeb,cVar11);
      cVar14 = (char)param_2 + *(char *)((int)unaff_EBX + -0x3e);
      bVar25 = cVar14 < '\0';
      piVar18 = unaff_EBX;
      if (cVar14 == '\0') {
        uVar16 = (undefined3)((uint)iVar23 >> 8);
        pbVar1 = (byte *)(CONCAT31(uVar16,cVar11 + -0x6b) + 0x5a + (int)unaff_ESI);
        *pbVar1 = *pbVar1 ^ (byte)((uint)unaff_EBX >> 8);
        cVar11 = in(0xf4);
        _DAT_d5a880a6 = CONCAT31(uVar16,cVar11);
        pcVar21 = (char *)((int)unaff_EDI + *(int *)(in_GS_OFFSET + param_1));
        piVar18 = (int *)CONCAT31((int3)((uint)param_1 >> 8),(char)param_1 - *pcVar21);
        piVar22 = (int *)(pcVar21 + *piVar18);
        *piVar22 = *piVar22 - (int)piVar18;
        pcVar21 = (char *)((int)piVar22 + *piVar18 + *(uint *)((int)unaff_EBX + 0x53031282));
        *pcVar21 = *pcVar21 + cVar11 +
                   CARRY4((int)piVar22 + *piVar18,*(uint *)((int)unaff_EBX + 0x53031282));
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      while (param_2 = unaff_EBX, piVar22 = unaff_EDI, bVar25) {
        uVar12 = (uint)bVar26;
        *unaff_EDI = *unaff_ESI;
        uVar4 = (longlong)(int)piVar18 * -0x78;
        bVar8 = 9 < ((byte)uVar4 & 0xf) | in_AF;
        bVar9 = (byte)uVar4 + bVar8 * '\x06';
        bVar9 = bVar9 + (0x90 < (bVar9 & 0xf0) |
                        (longlong)(int)uVar4 != uVar4 | bVar8 * (0xf9 < bVar9)) * '`';
        puVar17 = (undefined *)((int)piVar18 + (int)(unaff_ESI + uVar12 * -2 + 1));
        iVar23 = (int)(unaff_EDI + (uint)bVar26 * -2 + 1) + (uint)bVar26 * -2 + 1;
        if (param_1 + -1 == 0 || bVar9 == *(byte *)(unaff_EDI + (uint)bVar26 * -2 + 1)) {
          uVar24 = 0x5303;
          uVar28 = 0x40;
          uStack_4 = in_CS;
          func_0x640bbb53();
          func_0x605e5303(CONCAT22(uVar28,uVar24));
          pbVar1 = (byte *)(CONCAT31((int3)((uint)puVar17 >> 8),(byte)puVar17 & (byte)extraout_EDX)
                            + -0x26 + iVar23 * 8);
          bVar9 = (extraout_CL & 0x1f) % 9;
          bVar8 = *pbVar1;
          uVar6 = (ushort)bVar8 << bVar9;
          *pbVar1 = (byte)uVar6 | bVar8 >> 9 - bVar9;
          iVar23 = in((short)extraout_EDX);
          out(0xc5,(char)iVar23);
          uVar12 = iVar23 + extraout_EDX + 1 + (uint)((uVar6 & 0x100) != 0);
          if ((int)((ulonglong)uVar12 * (ulonglong)uVar12 >> 0x20) == 0) {
            return;
          }
          do {
                    // WARNING: Do nothing block with infinite loop
          } while( true );
        }
        unaff_EDI = (int *)(iVar23 + 4 + (uint)bVar26 * -8);
        bVar26 = (uVar4 & 0x400) != 0;
        in_AF = (bVar9 & 0x10) != 0;
        iVar23 = CONCAT22((short)((uint)(param_1 + -1) >> 0x10),0xad);
        bVar25 = false;
        param_1 = CONCAT31((int3)(uVar4 >> 8),bVar9);
        piVar18 = (int *)0x530312a2;
        unaff_ESI = unaff_ESI + uVar12 * -2 + 1;
      }
    }
  } while( true );
}



void __fastcall entry(int param_1,int *param_2)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x5303652a;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x1e375f7b;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2);
  return;
}


