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
// WARNING: Instruction at (ram,0x004013b7) overlaps instruction at (ram,0x004013b5)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int ** __fastcall FUN_00401219(int **param_1,int **param_2,int **param_3,int **param_4)

{
  byte *pbVar1;
  uint *puVar2;
  code *pcVar3;
  byte bVar4;
  uint in_EAX;
  undefined3 uVar8;
  int **ppiVar5;
  int **ppiVar6;
  uint uVar7;
  int **ppiVar9;
  int iVar10;
  int *piVar11;
  int *piVar12;
  byte bVar13;
  uint uVar14;
  char cVar15;
  undefined uVar16;
  int **unaff_EBX;
  undefined2 uVar17;
  int **unaff_EBP;
  int **unaff_ESI;
  int **ppiVar18;
  undefined4 *puVar19;
  int **unaff_EDI;
  int **ppiVar20;
  undefined2 in_DS;
  bool bVar21;
  byte in_AF;
  bool bVar22;
  int ***unaff_retaddr;
  undefined4 uStack_c;
  int **ppiStack_4;
  
  ppiVar6 = (int **)(in_EAX | 0xf0);
  if ((byte)((byte)in_EAX | 0xf0) == 0) {
    ppiVar5 = (int **)((uint)unaff_ESI | 0x54c624b9);
    ppiVar20 = ppiVar5;
    ppiVar9 = param_1;
    ppiVar18 = ppiVar6;
    goto code_r0x00401242;
  }
  ppiStack_4 = (int **)0x8d962151;
  ppiVar5 = param_2;
  ppiVar20 = (int **)unaff_retaddr;
code_r0x00401228:
  unaff_EDI = param_4;
  unaff_retaddr = &param_3;
  cVar15 = (char)unaff_EBX + (char)param_1;
  unaff_EBX = (int **)CONCAT31((int3)((uint)unaff_EBX >> 8),cVar15);
  bVar22 = cVar15 == '\0';
  param_4 = (int **)0x4d961001;
  ppiVar9 = param_1;
  in_DS = param_3._0_2_;
  if (!bVar22) {
    param_2 = (int **)((uint)ppiVar5 & *(uint *)((int)unaff_ESI + -0x39db46f3));
    ppiVar20 = ppiVar6;
    ppiVar18 = unaff_ESI;
    ppiVar5 = param_2;
    param_3 = param_1;
code_r0x00401242:
    ppiVar6 = ppiVar20;
    if (ppiVar5 != (int **)0x0) {
      unaff_ESI = (int **)((int)ppiVar18 + *(int *)((int)unaff_EDI + (int)ppiVar18 * 2 + 0x4c));
      ppiVar5 = unaff_ESI;
      goto code_r0x0040125a;
    }
    bVar22 = ((uint)ppiVar6 & 0x4000) != 0;
    in_AF = ((uint)ppiVar6 & 0x1000) != 0;
    bVar21 = ((uint)ppiVar6 & 0x100) != 0;
    unaff_ESI = ppiVar18;
    if (!bVar22) {
      ppiVar9 = (int **)((int)ppiVar9 + -1);
      if (ppiVar9 == (int **)0x0 || !bVar22) {
        ppiVar5 = unaff_EBX;
        ppiVar20 = unaff_EDI;
        if (bVar22) goto code_r0x004012ca;
        goto code_r0x00401332;
      }
      goto code_r0x00401255;
    }
    bVar4 = (byte)ppiVar6;
    bVar13 = bVar4 + 0x4f;
    bVar22 = bVar4 < 0xb1 || bVar13 < bVar21;
    uVar8 = (undefined3)((uint)ppiVar6 >> 8);
    ppiVar5 = (int **)CONCAT31(uVar8,bVar13 - bVar21);
    ppiVar20 = (int **)unaff_retaddr;
    if ((SBORROW1(bVar4,-0x4f) != SBORROW1(bVar13,bVar21)) == (char)(bVar13 - bVar21) < '\0')
    goto LAB_0040129c;
    unaff_ESI = (int **)((int)ppiVar18 + 1);
    ppiVar6 = (int **)CONCAT31(uVar8,*(undefined *)ppiVar18);
    uStack_c = (int **)CONCAT22(uStack_c._2_2_,in_DS);
    cVar15 = (char)param_2 + *(char *)(ppiVar9 + 7);
    ppiVar5 = (int **)CONCAT31((int3)((uint)param_2 >> 8),cVar15);
    bVar22 = cVar15 == '\0';
  }
  in_AF = 9 < ((byte)ppiVar6 & 0xf) | in_AF;
  uVar7 = CONCAT31((int3)((uint)ppiVar6 >> 8),(byte)ppiVar6 + in_AF * '\x06') & 0xffffff0f;
  ppiVar6 = (int **)CONCAT22((short)(uVar7 >> 0x10),
                             CONCAT11((char)((uint)ppiVar6 >> 8) + in_AF,(char)uVar7));
  param_2 = ppiVar5;
  unaff_retaddr = (int ***)ppiVar20;
code_r0x00401255:
  do {
    ppiVar5 = (int **)register0x00000010;
    if (bVar22) {
      in_AF = 9 < ((byte)ppiVar6 & 0xf) | in_AF;
      uVar7 = CONCAT31((int3)((uint)ppiVar6 >> 8),(byte)ppiVar6 + in_AF * -6) & 0xffffff0f;
      ppiVar6 = (int **)CONCAT22((short)(uVar7 >> 0x10),
                                 CONCAT11((char)((uint)ppiVar6 >> 8) - in_AF,(char)uVar7));
      ppiVar5 = unaff_EBX;
      goto code_r0x004012ca;
    }
code_r0x0040125a:
    param_1 = (int **)((int)ppiVar9 + -1);
    if (param_1 != (int **)0x0 && ppiVar5 == (int **)0x0) {
      ppiVar5 = (int **)(int)(short)ppiVar6;
code_r0x0040128b:
      *(char *)(unaff_EDI + -0x20) = (char)param_1;
      return ppiVar5;
    }
    in_DS = SUB42(unaff_retaddr,0);
    pbVar1 = (byte *)((int)ppiVar9 + -0x3d);
    bVar13 = (byte)((uint)param_2 >> 8);
    bVar22 = CARRY1(*pbVar1,bVar13);
    *pbVar1 = *pbVar1 + bVar13;
    ppiVar20 = (int **)unaff_retaddr;
    while( true ) {
      unaff_EBP = (int **)*param_2;
      ppiVar5 = (int **)((int)ppiVar6 + 1);
      bVar21 = ppiVar5 == (int **)0x0;
      unaff_retaddr = (int ***)((int)param_1 + -1);
      if (unaff_retaddr != (int ***)0x0 && bVar21) break;
      while( true ) {
        ppiVar6 = unaff_EDI;
        unaff_EDI = ppiVar5 + 1;
        bVar13 = (char)param_2 - *(char *)((int)unaff_retaddr + -0x75);
        cVar15 = (char)unaff_retaddr - *(char *)((int)ppiVar6 + -0x1f);
        iVar10 = CONCAT31((int3)((uint)unaff_retaddr >> 8),cVar15);
        in_DS = SUB42(ppiVar6,0);
        param_3 = (int **)(iVar10 + -1);
        if (param_3 != (int **)0x0 && cVar15 == '\0') {
          return;
        }
        pbVar1 = (byte *)(iVar10 + -0x65);
        bVar22 = bVar13 < *pbVar1;
        ppiVar5 = (int **)CONCAT31((int3)((uint)param_2 >> 8),bVar13 - *pbVar1);
        bVar21 = (byte)(bVar13 - *pbVar1) == '\0';
        param_2 = ppiVar5;
        uStack_c = unaff_EBX;
        if (bVar21) break;
        unaff_ESI = (int **)((int)unaff_ESI + 1);
        unaff_EBP = (int **)((int)unaff_EBP + 1);
        bVar21 = unaff_EBP == (int **)0x0;
        ppiVar5 = (int **)CONCAT31((int3)((uint)ppiVar6 >> 8),-bVar22);
        unaff_retaddr = (int ***)(iVar10 + -3);
        param_1 = (int **)unaff_retaddr;
        if (unaff_retaddr == (int ***)0x0 || !bVar21) goto code_r0x0040128b;
LAB_004012a7:
        if (bVar21) {
          ppiVar6 = ppiVar5;
          ppiVar9 = (int **)unaff_retaddr;
          ppiVar5 = unaff_EBX;
          ppiVar18 = unaff_ESI;
          ppiVar20 = unaff_EDI;
          if (!bVar21) goto code_r0x00401332;
          goto code_r0x004012ca;
        }
code_r0x004012a9:
        DAT_a6681f51 = DAT_a6681f51 << 1 | (char)DAT_a6681f51 < '\0';
        in((short)param_2);
        ppiVar6 = _DAT_d897e1c7;
        ppiVar9 = (int **)unaff_retaddr;
        ppiVar5 = (int **)CONCAT31((int3)((uint)ppiVar5 >> 8),0x75);
        unaff_ESI = unaff_EBX;
code_r0x004012ca:
        unaff_EBX = ppiVar5;
        unaff_retaddr = (int ***)ppiVar9;
        *(uint *)((int)unaff_EDI * 2) =
             *(uint *)((int)unaff_EDI * 2) >> 1 |
             (uint)(*(int ***)((int)(unaff_EDI + 0x1a) + (int)unaff_EBX) < unaff_ESI) << 0x1f;
        piVar11 = (int *)((int)unaff_EDI + (int)unaff_ESI * 8 + -0x49);
        *piVar11 = *piVar11 + (int)unaff_ESI;
        if (*piVar11 == 0) {
          uVar7 = in((short)ppiVar6);
          in_AF = 9 < ((byte)uVar7 & 0xf) | in_AF;
          bVar13 = (byte)uVar7 + in_AF * '\x06';
          ppiVar5 = (int **)CONCAT31((int3)(uVar7 >> 8),
                                     bVar13 + (0x90 < (bVar13 & 0xf0) | in_AF * (0xf9 < bVar13)) *
                                              '`');
          unaff_EDI = (int **)~(uint)unaff_EDI;
          if ((uVar7 & 0x197e1c7) != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          uVar16 = in((short)ppiVar6);
          *(undefined *)unaff_EDI = uVar16;
          param_2 = ppiVar6;
          do {
            ppiVar6 = ppiVar5;
            ppiVar18 = unaff_ESI;
            ppiVar20 = (int **)((int)unaff_EDI + 1);
code_r0x00401332:
            uVar8 = (undefined3)((uint)param_2 >> 8);
            param_2 = (int **)CONCAT31(uVar8,0xe);
            in(0x80);
            unaff_ESI = (int **)CONCAT31((int3)((uint)unaff_retaddr >> 8),*(undefined *)ppiVar18);
            unaff_EDI = (int **)((int)ppiVar20 + 1);
            bVar13 = *(byte *)ppiVar20;
            bVar4 = (byte)((int)ppiVar18 + 1);
            cVar15 = bVar4 - *(char *)ppiVar20;
            ppiVar6[-0x1c] = (int *)(float)*(float10 *)((int)ppiVar20 + -0x2d506975);
            iVar10 = (int)ppiVar6 + ((-1 - (int)&ppiStack_4) - (uint)(bVar4 < bVar13));
            ppiVar5 = (int **)(CONCAT22((short)((uint)((int)ppiVar18 + 1) >> 0x10),
                                        CONCAT11((cVar15 < '\0') << 7 | (cVar15 == '\0') << 6 |
                                                 in_AF << 4 | ((POPCOUNT(cVar15) & 1U) == 0) << 2 |
                                                 2 | bVar4 < bVar13,bVar4)) -
                              *(int *)(iVar10 + 0x33));
            bVar22 = ppiVar5 == (int **)0x0;
            do {
              uVar17 = (undefined2)((uint)unaff_EBX >> 0x10);
              uVar16 = SUB41(unaff_EBX,0);
              unaff_EBX = (int **)CONCAT22(uVar17,CONCAT11(0x4a,uVar16));
              piVar11 = (int *)(iVar10 + -1);
              if (piVar11 == (int *)0x0 || !bVar22) {
                uVar7 = (int)(short)ppiVar5 & 0xcb063e4f;
                puVar19 = (undefined4 *)((int)unaff_ESI - 1);
                LOCK();
                piVar12 = *unaff_EDI;
                *unaff_EDI = piVar11;
                UNLOCK();
                *unaff_EDI = (int *)((uint)*unaff_EDI | (uint)unaff_EBX);
                if (piVar12 == (int *)0x0) {
                  iVar10 = 0;
                }
                else {
                  if ((POPCOUNT((int)puVar19 - *(int *)((int)ppiVar20 + (int)puVar19 * 2 + 0x58) &
                                0xff) & 1U) == 0) {
                    uVar14 = CONCAT31(uVar8,*(char *)((int)piVar12 + 0x1e) + '\x0e' +
                                            *(char *)((int)piVar12 + -0x75));
                    puVar2 = (uint *)((int)ppiVar20 + 2);
                    uVar7 = *puVar2;
                    *puVar2 = *puVar2 + uVar14;
                    cVar15 = '=' - CARRY4(uVar7,uVar14);
                    unaff_EBX = (int **)CONCAT22(uVar17,CONCAT11(cVar15,uVar16));
                    uVar7 = (int)(short)ppiVar5 & 0x8a002e40;
                    param_2 = (int **)(uVar14 - 1);
                    piVar12 = (int *)((int)piVar12 + -1);
                    if (piVar12 != (int *)0x0 && param_2 != (int **)0x0) {
                      if (param_2 != (int **)0x0) {
                        return;
                      }
                      out(0xe1,uVar7);
                      *puVar2 = (uint)puVar19;
                      *(char *)((int)ppiVar20 + 6) = cVar15;
                    // WARNING: Bad instruction - Truncating control flow here
                      halt_baddata();
                    }
                  }
                  iVar10 = (int)piVar12 + -1;
                  *unaff_EBX = (int *)((int)*unaff_EBX + uVar7);
                  param_2 = (int **)CONCAT31((int3)((uint)param_2 >> 8),
                                             (char)param_2 + *(char *)((int)piVar12 + -0x76));
                  puVar19 = (undefined4 *)((int)unaff_ESI + 3);
                }
                out(*puVar19,(short)param_2);
                *(int *)(iVar10 + 0x74) = *(int *)(iVar10 + 0x74) + (int)param_2;
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              uStack_c = (int **)CONCAT22(uStack_c._2_2_,in_DS);
              cVar15 = (byte)piVar11 + (byte)ppiVar5;
              iVar10 = CONCAT31((int3)((uint)piVar11 >> 8),cVar15);
              bVar22 = cVar15 == '\0';
              ppiVar5 = (int **)CONCAT31((int3)(char)((uint)ppiVar5 >> 8),
                                         -CARRY1((byte)piVar11,(byte)ppiVar5));
              unaff_retaddr = (int ***)(iVar10 + -1);
              unaff_EBP = uStack_c;
              if (unaff_retaddr != (int ***)0x0) goto code_r0x004012a9;
              iVar10 = iVar10 + -2;
            } while (iVar10 != 0 && !bVar22);
            unaff_retaddr = (int ***)0x51681e6b;
            unaff_EBX = (int **)-(int)unaff_EBX;
            uVar16 = in((short)param_2);
            *(undefined *)unaff_EDI = uVar16;
          } while( true );
        }
        unaff_retaddr = (int ***)((int)unaff_retaddr + -1);
        ppiVar5 = ppiVar6;
        if (unaff_retaddr == (int ***)0x0 || *piVar11 != 0) {
          out(0x59,ppiVar6);
          unaff_EBX = unaff_EDI;
          goto code_r0x004012e7;
        }
      }
      unaff_ESI = (int **)unaff_EBX[0x1d];
      param_1 = param_3;
      while( true ) {
        param_1 = (int **)((int)param_1 + -1);
        ppiVar20 = ppiVar6;
        ppiStack_4 = param_3;
        if (param_1 == (int **)0x0 || !bVar21) goto code_r0x00401228;
        unaff_EDI = unaff_EBX;
        if (SBORROW1(bVar13,*pbVar1)) break;
        if (!bVar22 && !bVar21) {
          param_2 = ppiVar6;
          unaff_retaddr = (int ***)ppiVar6;
          if (bVar21) {
code_r0x004012e7:
            *unaff_EBX = *unaff_ESI;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          goto code_r0x0040129d;
        }
      }
    }
    ppiVar9 = (int **)unaff_retaddr;
    param_3 = param_1;
    ppiStack_4 = ppiVar5;
    if (!bVar21) {
      in_AF = 9 < ((byte)ppiVar5 & 0xf) | in_AF;
      bVar13 = (byte)ppiVar5 + in_AF * '\x06';
      ppiVar5 = (int **)CONCAT31((int3)((uint)ppiVar5 >> 8),
                                 bVar13 + (0x90 < (bVar13 & 0xf0) | bVar22 | in_AF * (0xf9 < bVar13)
                                          ) * '`');
      goto LAB_004012a7;
    }
LAB_0040129c:
    unaff_retaddr = (int ***)ppiVar20;
    param_1 = ppiVar9;
    param_2 = (int **)((int)param_2 + -1);
    bVar21 = param_2 == (int **)0x0;
code_r0x0040129d:
    ppiVar9 = (int **)((int)param_1 + -1);
    if (ppiVar9 == (int **)0x0 || !bVar21) {
      pcVar3 = (code *)swi(3);
      ppiVar6 = (int **)(*pcVar3)();
      return ppiVar6;
    }
    cVar15 = ((char)ppiVar5 + -0x37) - bVar22;
    ppiVar6 = (int **)CONCAT31((int3)((uint)ppiVar5 >> 8),cVar15);
    bVar22 = cVar15 == '\0';
  } while( true );
}



void __fastcall entry(int **param_1,int **param_2,int **param_3,int **param_4)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x7451681f;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e54);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0xb92668d;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e1d0);
  FUN_00401219(param_1,param_2,param_3,param_4);
  return;
}


