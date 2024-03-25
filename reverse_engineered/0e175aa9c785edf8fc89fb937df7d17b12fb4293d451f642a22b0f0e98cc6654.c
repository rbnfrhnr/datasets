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




// WARNING: Instruction at (ram,0x0040121a) overlaps instruction at (ram,0x00401219)
// 
// WARNING: Unable to track spacebase fully for stack

int ** __fastcall
FUN_00401219(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,uint param_5)

{
  byte *pbVar1;
  longlong lVar2;
  code *pcVar3;
  byte bVar4;
  byte bVar5;
  byte bVar10;
  char *pcVar6;
  uint uVar7;
  undefined3 uVar11;
  undefined4 *in_EAX;
  undefined4 *puVar8;
  int **ppiVar9;
  char cVar14;
  int iVar12;
  undefined4 uVar13;
  undefined2 uVar15;
  short sVar16;
  byte bVar17;
  uint unaff_EBX;
  int **unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 *puVar18;
  byte in_CF;
  bool bVar19;
  bool bVar20;
  byte in_AF;
  bool in_ZF;
  char in_SF;
  bool bVar21;
  char in_OF;
  int **unaff_retaddr;
  
  bVar21 = false;
  puVar8 = param_1;
  if (in_ZF) goto LAB_0040122f;
code_r0x0040121b:
  if (in_OF == in_SF) {
    if (!in_ZF) goto LAB_00401213;
    goto code_r0x004011d4;
  }
  ppiVar9 = unaff_EBP + -0x802b0f6;
  bVar4 = (byte)((uint)param_2 >> 8);
  bVar5 = *(byte *)ppiVar9 + bVar4;
  bVar19 = CARRY1(*(byte *)ppiVar9,bVar4) || CARRY1(bVar5,in_CF);
  *(byte *)ppiVar9 = bVar5 + in_CF;
  puVar8 = in_EAX;
LAB_00401223:
  bVar4 = (byte)((uint)param_1 >> 8);
  bVar5 = bVar4 - 0xc;
  bVar20 = bVar4 < 0xc || bVar5 < bVar19;
  cVar14 = bVar5 - bVar19;
  uVar7 = CONCAT22((short)((uint)param_1 >> 0x10),CONCAT11(cVar14,(char)param_1));
  puVar18 = unaff_EDI;
  if (cVar14 != '\0') {
    puVar18 = puVar8 + -0x12b022b2;
    bVar5 = 0x10 < *(byte *)puVar18;
    *(byte *)puVar18 = *(byte *)puVar18 - 0x11;
    goto code_r0x0040126e;
  }
code_r0x00401228:
  in_AF = 9 < ((byte)puVar8 & 0xf) | in_AF;
  bVar5 = (byte)puVar8 + in_AF * -6;
  bVar4 = 0x9f < bVar5 | bVar20 | in_AF * (bVar5 < 6);
  in_EAX = (undefined4 *)CONCAT31((int3)((uint)puVar8 >> 8),bVar5 + bVar4 * -0x60);
  unaff_EDI = puVar18 + (uint)bVar21 * -2 + 1;
  uVar13 = in((short)param_2);
  *puVar18 = uVar13;
  bVar10 = (byte)((uint)puVar8 >> 8);
  bVar5 = bVar10 + 0x78;
  in_CF = 0x87 < bVar10 || CARRY1(bVar5,bVar4 == 0);
  puVar8 = (undefined4 *)CONCAT22((short)(uVar7 >> 0x10),CONCAT11(bVar5 + (bVar4 == 0),(char)uVar7))
  ;
LAB_0040122f:
  *(int *)((int)unaff_ESI + 0x10b57db5) =
       (*(int *)((int)unaff_ESI + 0x10b57db5) - (int)unaff_EDI) - (uint)in_CF;
  puVar18 = unaff_EDI;
LAB_00401236:
  do {
    unaff_EDI = puVar18 + (uint)bVar21 * -2 + 1;
    *puVar18 = *unaff_ESI;
    unaff_EBX = unaff_EBX + 1;
    sVar16 = (short)unaff_EBX;
    bVar4 = (byte)in_EAX;
    if (in_EAX == (undefined4 *)0x0) {
      bVar5 = 9 < ((byte)puVar8 & 0xf) | in_AF;
      uVar7 = CONCAT31((int3)((uint)puVar8 >> 8),(byte)puVar8 + bVar5 * -6) & 0xffffff0f;
      puVar8 = (undefined4 *)
               CONCAT22((short)(uVar7 >> 0x10),
                        CONCAT11((char)((uint)puVar8 >> 8) - bVar5,(char)uVar7));
      uVar7 = (uint)CONCAT11(0xef,bVar4);
      in_AF = bVar5;
code_r0x0040126e:
      *(char *)(uVar7 + 0x75) = (*(char *)(uVar7 + 0x75) + -0x52) - bVar5;
      *(byte *)puVar8 = *(byte *)puVar8 ^ 0x75;
      in_AF = 9 < ((byte)puVar8 & 0xf) | in_AF;
      lVar2 = (longlong)*(int *)((int)unaff_EBP + 0x52) * 0x69fd95b5;
      unaff_ESI = (undefined4 *)lVar2;
      bVar19 = (int)unaff_ESI != lVar2;
      param_1 = (undefined4 *)CONCAT22((short)(uVar7 >> 0x10),CONCAT11(0x7d,(char)uVar7));
      puVar8 = (undefined4 *)
               (CONCAT31((int3)((uint)puVar8 >> 8),((byte)puVar8 + in_AF * -6 & 0xf) % 0xad) &
               0xffff00ff);
      if ((int)&stack0x00000000 < 1) goto LAB_00401223;
      unaff_EBP = (int **)((uint)unaff_EBP & 0xb50397f8);
      pbVar1 = (byte *)((int)unaff_ESI + (int)unaff_EDI * 4 + -0x2f);
      bVar5 = *pbVar1;
      bVar17 = (byte)(unaff_EBX >> 8);
      bVar10 = *pbVar1;
      bVar4 = *pbVar1;
      *pbVar1 = bVar4 + bVar17;
      unaff_EBX = CONCAT31((int3)(unaff_EBX >> 8),0xb5);
      sVar16 = (short)unaff_EBX;
      if ((SCARRY1(bVar10,bVar17) != SCARRY1(bVar4 + bVar17,'\0')) != (char)*pbVar1 < '\0') {
        pcVar6 = (char *)((int)unaff_ESI + 0x7d);
        *pcVar6 = *pcVar6 + (char)((uint)param_2 >> 8) + CARRY1(bVar5,bVar17);
        in_EAX = (undefined4 *)((int)param_1 + -1);
        puVar18 = unaff_EDI;
        if (in_EAX == (undefined4 *)0x0 || *pcVar6 == '\0') {
          pcVar3 = (code *)swi(3);
          ppiVar9 = (int **)(*pcVar3)();
          return ppiVar9;
        }
        goto LAB_00401236;
      }
      uVar13 = CONCAT31((int3)((uint)param_1 >> 8),0x17);
      in_EAX = puVar8;
    }
    else {
      bVar5 = (byte)(puVar8 + -0x6e44b1b);
      if ((char)(bVar5 ^ 0x1c) < '\0') {
        param_2 = (int)in_EAX >> 0x1f;
        unaff_EBP = (int **)*unaff_retaddr;
      }
      else {
        *(byte *)(param_2 + -0x4a824b58) =
             *(byte *)(param_2 + -0x4a824b58) | (byte)((uint)param_2 >> 8);
        pbVar1 = (byte *)((int)(unaff_ESI + (uint)bVar21 * -2 + 1) + -0x6b);
        bVar19 = CARRY1(*pbVar1,(byte)unaff_EBX);
        *pbVar1 = *pbVar1 + (byte)unaff_EBX;
        bVar10 = bVar4 + 0x3c;
        in_CF = 0xc3 < bVar4 || CARRY1(bVar10,bVar19);
        in_OF = SCARRY1(bVar4,'<') != SCARRY1(bVar10,bVar19);
        cVar14 = bVar10 + bVar19;
        in_EAX = (undefined4 *)CONCAT31((int3)((uint)in_EAX >> 8),cVar14);
        in_SF = cVar14 < '\0';
        unaff_EBP = unaff_retaddr;
        if (cVar14 == '\0') break;
      }
      bVar5 = (byte)in_EAX;
      in_EAX = (undefined4 *)
               CONCAT31((int3)(CONCAT22((short)((uint)in_EAX >> 0x10),CONCAT11(bVar5 / 0xb1,bVar5))
                              >> 8),bVar5 % 0xb1);
      uVar13 = param_3;
      unaff_ESI = unaff_ESI + (uint)bVar21 * -2 + 1;
    }
    puVar8 = (undefined4 *)CONCAT22((short)((uint)uVar13 >> 0x10),CONCAT11(0x15,(char)uVar13));
    bVar21 = (param_5 & 0x400) != 0;
    in_AF = (param_5 & 0x10) != 0;
    cVar14 = (char)((ushort)sVar16 >> 8) << 1;
    unaff_EBX = (uint)CONCAT11(cVar14,(char)sVar16);
    puVar18 = unaff_EDI;
    if ((sVar16 < 0 != cVar14 < '\0') != cVar14 < '\0') {
      return unaff_EBP;
    }
  } while( true );
  param_1 = (undefined4 *)
            CONCAT22((short)((uint)(puVar8 + -0x6e44b1b) >> 0x10),CONCAT11(0x7a,bVar5 ^ 0x1c));
  unaff_ESI = (undefined4 *)0xd485582;
LAB_00401213:
  if (in_OF == in_SF) {
    pbVar1 = (byte *)((int)unaff_EBP + 0x14746296);
    bVar5 = *pbVar1;
    bVar10 = (byte)((uint)param_2 >> 8);
    bVar4 = *pbVar1 + bVar10;
    in_OF = SCARRY1(*pbVar1,bVar10) != SCARRY1(bVar4,in_CF);
    *pbVar1 = bVar4 + in_CF;
    in_SF = (char)*pbVar1 < '\0';
    in_ZF = *pbVar1 == 0;
    in_CF = CARRY1(bVar5,bVar10) || CARRY1(bVar4,in_CF);
    goto code_r0x0040121b;
  }
  unaff_EBP = (int **)((int)unaff_EBP + -1);
  param_1 = (undefined4 *)CONCAT31((int3)((uint)param_1 >> 8),(char)param_1 + ':');
  pcVar6 = (char *)in(0x82);
  *pcVar6 = *pcVar6 + 'u';
  in_AF = 9 < ((byte)pcVar6 & 0xf) | in_AF;
  uVar7 = CONCAT31((int3)((uint)pcVar6 >> 8),(byte)pcVar6 + in_AF * -6) & 0xffffff0f;
  in_EAX = (undefined4 *)
           CONCAT22((short)(uVar7 >> 0x10),CONCAT11((char)((uint)pcVar6 >> 8) - in_AF,(char)uVar7));
code_r0x004011d4:
  uVar15 = CONCAT11((char)((uint)param_2 >> 8) + *(char *)(unaff_EBP + -0x1091b27c),(char)param_2);
  param_2 = CONCAT22((short)((uint)param_2 >> 0x10),uVar15);
  out(uVar15,unaff_EDI);
  pbVar1 = (byte *)((int)unaff_EBP + 0x75);
  bVar5 = *pbVar1;
  *pbVar1 = *pbVar1 + 0xae;
  iVar12 = CONCAT22((short)((uint)param_1 >> 0x10),CONCAT11(0x95,(char)param_1)) + -1;
  out(*(undefined *)unaff_ESI,uVar15);
  bVar4 = (byte)unaff_EDI;
  uVar11 = (undefined3)
           (CONCAT22((short)((uint)unaff_EDI >> 0x10),CONCAT11(bVar4 / 0xb1,bVar4)) >> 8);
  unaff_ESI = (undefined4 *)*(undefined6 *)(CONCAT31(uVar11,bVar4 % 0xb1) + 0x4fe87db5 + param_2);
  bVar5 = bVar4 % 0xb1 + 0x7d + (bVar5 < 0x52);
  puVar8 = (undefined4 *)CONCAT31(uVar11,bVar5);
  uVar7 = CONCAT22((short)((uint)iVar12 >> 0x10),(ushort)(byte)iVar12);
  bVar20 = bVar5 < 0xf5;
  puVar18 = in_EAX;
  goto code_r0x00401228;
}



void __fastcall
entry(undefined4 *param_1,int param_2,undefined4 param_3,undefined4 param_4,uint param_5)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x2057;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x7db510b5;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xcfe;
  puVar2 = &DAT_0042c000;
  do {
    *puVar2 = *puVar2 ^ 0x2ea3220e;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219(param_1,param_2,param_3,param_4,param_5);
  return;
}


