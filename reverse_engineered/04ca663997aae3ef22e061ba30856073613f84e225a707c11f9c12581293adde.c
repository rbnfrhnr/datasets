typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
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
// WARNING: Instruction at (ram,0x004012ec) overlaps instruction at (ram,0x004012e6)
// 

void __fastcall FUN_0040120a(int param_1)

{
  uint uVar1;
  longlong lVar2;
  code *pcVar3;
  int iVar4;
  int unaff_EBP;
  uint unaff_ESI;
  bool bVar5;
  bool in_ZF;
  char in_SF;
  char in_OF;
  
  if (in_ZF || in_OF != in_SF) {
    return;
  }
  if (in_ZF || in_OF != in_SF) {
    pcVar3 = (code *)swi(1);
    (*pcVar3)();
    return;
  }
  iVar4 = -0x68169df6;
  lVar2 = (longlong)*(int *)(unaff_EBP + 0x68) * -0x1ac27488;
  bVar5 = (int)lVar2 != lVar2;
  while( true ) {
    LOCK();
    uVar1 = *(uint *)(param_1 + -0x66b07f92);
    *(uint *)(param_1 + -0x66b07f92) = iVar4 + -0x4e786972 + (uint)bVar5 ^ 0xe0;
    UNLOCK();
    bVar5 = unaff_ESI < 0x64092b68;
    if (-1 < (int)(unaff_ESI + 0x9bf6d498)) break;
    iVar4 = in(0xfd);
    unaff_ESI = uVar1;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004011a8) overlaps instruction at (ram,0x004011a7)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint * __fastcall FUN_00401219(uint *param_1,uint *param_2)

{
  char *pcVar1;
  undefined6 *puVar2;
  byte *pbVar3;
  uint *puVar4;
  uint uVar5;
  code *pcVar6;
  byte bVar7;
  byte bVar8;
  char cVar9;
  undefined3 uVar13;
  uint **ppuVar10;
  uint *in_EAX;
  uint *puVar11;
  uint uVar12;
  uint *puVar14;
  int iVar15;
  int extraout_ECX;
  uint **ppuVar16;
  uint *puVar17;
  uint *unaff_EBX;
  uint **ppuVar18;
  uint **unaff_ESI;
  uint *unaff_EDI;
  char in_CF;
  bool bVar19;
  bool bVar20;
  bool bVar21;
  bool bVar22;
  byte bVar23;
  bool bVar24;
  int iStack_3db3;
  uint *puStack_8;
  uint *puStack_4;
  
  bVar23 = 0;
code_r0x00401219:
  ppuVar10 = (uint **)CONCAT31((int3)((uint)in_EAX >> 8),((char)in_EAX + -0x40) - in_CF);
  bVar19 = ppuVar10 < (uint *)0x68e17868;
  puVar11 = (uint *)((int)param_1 + -1);
  puVar14 = param_2;
  ppuVar18 = unaff_ESI;
  if ((uint *)((int)param_1 + -1) != (uint *)0x0 && ppuVar10 == (uint **)0x68e17868)
  goto LAB_004011bf;
  pbVar3 = (byte *)((int)param_1 + (int)param_2 * 2 + 0x7e);
  bVar8 = (byte)((uint)param_2 >> 8);
  bVar19 = CARRY1(*pbVar3,bVar8);
  *pbVar3 = *pbVar3 + bVar8;
  bVar21 = *pbVar3 == 0;
  puStack_4 = (uint *)0x282d7b10;
  in_EAX = param_2;
  puVar11 = unaff_EDI;
  if ((char)*pbVar3 < '\0') goto LAB_004011df_1;
  goto code_r0x0040122f;
LAB_004011df_1:
  param_1 = (uint *)((int)param_1 + -2);
  ppuVar16 = (uint **)param_2;
  if (param_1 != (uint *)0x0 && bVar21) {
    if ((char)*pbVar3 < '\0') goto code_r0x0040119c;
    ppuVar18 = (uint **)0xfde870ac;
    goto code_r0x004011c0;
  }
  while( true ) {
    ppuVar10 = &puStack_4;
    bVar8 = (byte)param_2;
    bVar19 = 0xfb < bVar8;
    cVar9 = bVar8 + 4;
    in_EAX = (uint *)CONCAT31((int3)((uint)param_2 >> 8),cVar9);
    bVar22 = cVar9 < '\0';
    bVar21 = cVar9 == '\0';
    bVar20 = (POPCOUNT(cVar9) & 1U) == 0;
    param_1 = (uint *)((int)param_1 + -1);
    param_2 = (uint *)ppuVar16;
    if (param_1 != (uint *)0x0 && bVar21) break;
LAB_004011a7:
    bVar8 = (byte)ppuVar10 - 2;
    in_CF = (byte)ppuVar10 < 2 || bVar8 < bVar19;
    cVar9 = bVar8 - bVar19;
    in_EAX = (uint *)CONCAT31((int3)((uint)ppuVar10 >> 8),cVar9);
    puVar14 = param_2;
    unaff_ESI = ppuVar18;
    if (-1 < cVar9) {
      do {
        bVar21 = in_EAX < (uint *)0x8c097002;
        bVar7 = (byte)in_EAX;
        bVar8 = bVar7 + 0x78;
        bVar19 = 0x87 < bVar7 || CARRY1(bVar8,bVar21);
        uVar13 = (undefined3)((uint)in_EAX >> 8);
        param_1 = (uint *)((int)param_1 + -1);
        if (param_1 == (uint *)0x0 || (byte)(bVar8 + bVar21) != '\0') {
          ppuVar18 = (uint **)((int)unaff_ESI + (uint)bVar23 * -2 + 1);
          ppuVar10 = (uint **)CONCAT31(uVar13,*(undefined *)unaff_ESI);
          puVar11 = param_1;
          param_2 = puVar14;
          _DAT_e178603d = in_EAX;
          if (SCARRY1(bVar7,'x') != SCARRY1(bVar8,bVar21)) goto LAB_004011a7;
LAB_004011bf:
          param_1 = puVar11;
          bVar23 = 1;
          param_2 = (uint *)ppuVar10;
code_r0x004011c0:
          bVar21 = param_2 < (uint *)0x683c597f || (int)param_2 + 0x97c3a681U < (uint)bVar19;
          in_EAX = (uint *)(((int)param_2 + 0x97c3a681U) - (uint)bVar19);
          unaff_ESI = ppuVar18;
          if (-1 < (int)in_EAX) {
            uVar13 = (undefined3)((uint)in_EAX >> 8);
            bVar8 = -bVar21;
            puVar11 = (uint *)CONCAT31(uVar13,bVar8);
            unaff_EDI = (uint *)((int)unaff_EDI + -1);
            uVar12 = (uint)bVar21;
            uVar5 = (int)puVar14 - (int)puVar11;
            bVar19 = puVar14 < puVar11 || uVar5 < uVar12;
            param_2 = (uint *)(uVar5 - uVar12);
            in_CF = bVar8 < 0x52 || (byte)(bVar8 + 0xae) < bVar19;
            in_EAX = (uint *)CONCAT31(uVar13,(bVar8 + 0xae) - bVar19);
            param_1 = (uint *)CONCAT31((int3)((uint)param_1 >> 8),0xc2);
            break;
          }
        }
        else {
          puStack_8 = (uint *)0x57f113e5;
          puVar11 = unaff_EBX;
          puVar17 = (uint *)(CONCAT31(uVar13,bVar8 + bVar21) | 0xa8);
          while( true ) {
            do {
              param_2 = unaff_EDI;
              param_1 = (uint *)((int)param_1 - *param_1);
              LOCK();
              unaff_EBX = *unaff_ESI;
              *unaff_ESI = puVar17;
              UNLOCK();
              unaff_ESI = (uint **)0x3d8b74ac;
              unaff_EDI = puVar11 + (uint)bVar23 * -2 + 1;
              puVar4 = (uint *)*puVar11;
              uVar12 = *puVar11;
              puVar11 = param_2;
              puVar17 = unaff_EBX;
            } while ((int)uVar12 <= (int)param_2);
            if (-1 < (int)((int)param_2 - uVar12)) break;
            unaff_ESI = (uint **)((int)param_1 + (param_2 < puVar4) + 0x3d8b74ac);
            puStack_8 = unaff_EDI;
          }
code_r0x0040119c:
          *(byte *)((int)unaff_EBX + -0x497c263) = *(byte *)((int)unaff_EBX + -0x497c263) ^ 0x25;
          in_EAX = (uint *)((uint)param_2 ^ 0x1c94b861);
        }
        unaff_EBX = (uint *)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                                     CONCAT11((char)((uint)unaff_EBX >> 8) +
                                              *(char *)((int)in_EAX + 0x26),(char)unaff_EBX));
      } while( true );
    }
    if (!(bool)in_CF) goto code_r0x00401219;
    ppuVar16 = &puStack_8;
    puStack_8 = (uint *)0x60f96278;
    param_2 = in_EAX + 0xa87b14a;
    ppuVar18 = unaff_ESI;
  }
  puStack_4 = param_1;
  if (!bVar21 && SCARRY1(bVar8,'\x04') == bVar22) {
    if (bVar22) {
      puVar14 = param_1;
      bVar24 = SCARRY1(bVar8,'\x04');
      if (!bVar22) goto code_r0x004012d1;
      goto code_r0x0040124e;
    }
    pcVar1 = (char *)((int)unaff_EBX * 9);
    *pcVar1 = *pcVar1 + -1;
    if (param_1 == (uint *)0x1 || *pcVar1 != '\0') {
      pcVar6 = (code *)swi(1);
      puVar11 = (uint *)(*pcVar6)();
      return puVar11;
    }
    goto code_r0x004012d1;
  }
  cVar9 = (char)((uint)unaff_EBX >> 8);
  *(char *)((int)unaff_EBX + 0x2d) = *(char *)((int)unaff_EBX + 0x2d) + cVar9 + bVar19;
  pcVar1 = (char *)((int)in_EAX + -0x4f);
  *pcVar1 = *pcVar1 - cVar9;
  bVar21 = *pcVar1 == '\0';
  puVar11 = unaff_EDI;
code_r0x0040122f:
  puVar14 = (uint *)((int)puStack_4 + -1);
  if (puVar14 != (uint *)0x0 && bVar21) {
    iVar15 = (int)ppuVar18 + 1;
    puStack_4 = (uint *)0xcfe2878;
    puStack_8 = (uint *)0xd76ab72b;
    unaff_EDI = puVar11;
    goto code_r0x004012af;
  }
  iVar15 = (int)puStack_4 + -2;
  if (iVar15 != 0 && bVar21) {
    return in_EAX;
  }
  puStack_4 = (uint *)0x78d16278;
  unaff_EDI = puVar11 + (uint)bVar23 * -2 + 1;
  uVar12 = in((short)param_2);
  *puVar11 = uVar12;
  param_1 = (uint *)CONCAT31((int3)((uint)iVar15 >> 8),0x44);
  puVar2 = (undefined6 *)((int)unaff_EBX + -0x17);
  unaff_EBX = (uint *)*puVar2;
  if (ppuVar18 != *(uint ***)((int)puVar11 + 0x91de16a)) {
    puVar11 = (uint *)FUN_0040120a((int)param_1);
    return puVar11;
  }
  puStack_8 = (uint *)0x88c2ea12;
  in_CF = '\0';
  *(byte *)(param_1 + 0xf) = *(byte *)(param_1 + 0xf) & (byte)*puVar2;
  unaff_ESI = (uint **)0x0;
  goto code_r0x00401219;
code_r0x0040124e:
  while (puVar11 = (uint *)in(0x57), bVar21 || bVar24 != bVar22) {
    cVar9 = (char)puVar14 + (char)puVar11 + bVar19;
    puVar14 = (uint *)CONCAT31((int3)((uint)puVar14 >> 8),cVar9);
    bVar22 = cVar9 < '\0';
    bVar21 = cVar9 == '\0';
    bVar20 = (POPCOUNT(cVar9) & 1U) == 0;
    if (bVar22) {
      *(undefined4 *)(iStack_3db3 + -8) = 0xd819d487;
      return puVar11;
    }
    if (!bVar22) {
      return (uint *)CONCAT31((int3)((uint)puVar11 >> 8),0x13);
    }
    bVar19 = (longlong)(int)&puStack_4 != (longlong)*(int *)((int)puVar14 + -0x4314e633) * -0x1b;
    bVar24 = bVar19;
  }
  puStack_8 = puVar14;
  if (bVar20) goto code_r0x004012d1;
  puVar14 = (uint *)((int)puVar14 + -1);
  if (puVar14 != (uint *)0x0 && bVar21) {
    iVar15 = (int)ppuVar18 - *(int *)((int)unaff_EDI + -0x234b2896);
code_r0x004012af:
    *(int *)(iVar15 + -0x597786a) = *(int *)(iVar15 + -0x597786a) + (int)puVar14;
code_r0x004012d1:
    iVar15 = func_0x2fc05077();
    LOCK();
    *(int *)(extraout_ECX + 0x620ab859 + (int)unaff_EDI) = iVar15 >> 0x1f;
    UNLOCK();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar24 = SCARRY4((int)puVar11,1);
  uVar12 = (int)puVar11 + 1;
  bVar22 = (int)uVar12 < 0;
  bVar21 = uVar12 == 0;
  bVar20 = (POPCOUNT(uVar12 & 0xff) & 1U) == 0;
  goto code_r0x0040124e;
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
  FUN_00401219((uint *)piVar7[7],(uint *)piVar7[6]);
  return;
}


