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
// WARNING: Instruction at (ram,0x00401239) overlaps instruction at (ram,0x00401238)
// 
// WARNING: This function may have set the stack pointer
// WARNING: Removing unreachable block (ram,0x004011ff)
// WARNING: Removing unreachable block (ram,0x0040125c)
// WARNING: Removing unreachable block (ram,0x00401200)
// WARNING: Removing unreachable block (ram,0x00401205)
// WARNING: Removing unreachable block (ram,0x00401207)
// WARNING: Removing unreachable block (ram,0x00401208)
// WARNING: Removing unreachable block (ram,0x00401215)
// WARNING: Removing unreachable block (ram,0x00401217)
// WARNING: Removing unreachable block (ram,0x004011b0)
// WARNING: Removing unreachable block (ram,0x00401228)
// WARNING: Removing unreachable block (ram,0x004011b7)
// WARNING: Removing unreachable block (ram,0x004011bb)
// WARNING: Removing unreachable block (ram,0x00401279)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

char ** __fastcall FUN_00401219(uint *param_1,int **param_2)

{
  byte *pbVar1;
  char **ppcVar2;
  char cVar4;
  code *pcVar5;
  undefined6 uVar6;
  byte bVar7;
  undefined uVar8;
  char **ppcVar10;
  char **in_EAX;
  int3 iVar12;
  uint uVar11;
  undefined3 uVar13;
  byte bVar14;
  char cVar15;
  short sVar16;
  byte bVar17;
  byte bVar19;
  int *unaff_EBX;
  int iVar18;
  char **unaff_EBP;
  char **unaff_ESI;
  char **ppcVar20;
  char **ppcVar21;
  char **unaff_EDI;
  bool bVar22;
  bool bVar23;
  char in_AF;
  bool bVar24;
  bool bVar25;
  undefined2 in_FPUControlWord;
  undefined2 in_FPUStatusWord;
  undefined2 in_FPUTagWord;
  undefined2 in_FPULastInstructionOpcode;
  undefined4 in_FPUDataPointer;
  undefined4 in_FPUInstructionPointer;
  char *pcVar3;
  uint uVar9;
  
  bVar17 = *(byte *)((int)unaff_EDI + -0x4d);
  bVar19 = (byte)((uint)unaff_EBX >> 8);
  bVar14 = (byte)param_1;
  if (bVar19 <= bVar17) {
    cVar4 = '\x1b';
    ppcVar10 = unaff_EBP;
    do {
      ppcVar10 = ppcVar10 + -1;
      register0x00000010 = (BADSPACEBASE *)((int)register0x00000010 + -4);
      *(char **)register0x00000010 = *ppcVar10;
      cVar4 = cVar4 + -1;
    } while ('\0' < cVar4);
    if (bVar19 < bVar17) {
      bVar19 = bVar19 & bVar14;
      bVar25 = SBORROW1(*(char *)param_2,bVar19);
      *(byte *)param_2 = *(char *)param_2 - bVar19;
      bVar24 = *(char *)param_2 < '\0';
      bVar22 = *(char *)param_2 == '\0';
      ppcVar10 = (char **)CONCAT22((short)((uint)unaff_EBX >> 0x10),CONCAT11(bVar19,(char)unaff_EBX)
                                  );
      ppcVar20 = unaff_ESI;
      goto code_r0x00401237;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
code_r0x0040121f:
  bVar17 = (byte)((uint)unaff_EBX >> 8);
  uVar13 = (undefined3)
           (CONCAT22((short)((uint)unaff_EBX >> 0x10),
                     CONCAT11(bVar17 - *(char *)param_2,(char)unaff_EBX)) >> 8);
  bVar17 = ((char)unaff_EBX + -0x6f) - (bVar17 < *(byte *)param_2);
  ppcVar10 = (char **)CONCAT31(uVar13,bVar17);
  bVar22 = _DAT_6f031bb3 < unaff_EDI;
  _DAT_6f031bb3 = (char **)((int)_DAT_6f031bb3 - (int)unaff_EDI);
  if (bVar22) {
    uVar9 = (uint)bVar22;
    bVar23 = unaff_EDI < *param_2;
    uVar11 = (int)unaff_EDI - (int)*param_2;
    bVar25 = SBORROW4((int)unaff_EDI,(int)*param_2) != SBORROW4(uVar11,uVar9);
    unaff_EDI = (char **)(uVar11 - uVar9);
    bVar24 = (int)unaff_EDI < 0;
    bVar22 = unaff_EDI == (char **)0x0;
    param_2 = (int **)((int)unaff_ESI >> 0x1f);
    iVar12 = (int3)((uint)unaff_ESI >> 8);
    bVar19 = (byte)((int)unaff_ESI >> 0x1f);
    if (bVar22 || bVar25 != bVar24) {
      ppcVar20 = in_EAX;
      unaff_EBP = in_EAX;
      if (bVar23 || uVar11 < uVar9) {
code_r0x00401237:
        unaff_ESI = ppcVar10;
        in_EAX = (char **)((uint)unaff_EBP & 0xffff0000);
        _DAT_3a28cf20 = unaff_ESI;
      }
      else {
        ppcVar21 = (char **)((int)param_1 + -0x243c64e9);
        uVar9 = (uint)(bVar23 || uVar11 < uVar9);
        ppcVar2 = (char **)*ppcVar21;
        pcVar3 = *ppcVar21;
        uVar11 = (int)*ppcVar21 - (int)ppcVar10;
        *ppcVar21 = (char *)(uVar11 - uVar9);
        if (*ppcVar21 == (char *)0x0 ||
            (SBORROW4((int)pcVar3,(int)ppcVar10) != SBORROW4(uVar11,uVar9)) != (int)*ppcVar21 < 0) {
          iRamcfb91bb3 = iRamcfb91bb3 - (int)unaff_EDI;
          pcVar5 = (code *)swi(1);
          ppcVar10 = (char **)(*pcVar5)();
          return ppcVar10;
        }
        cVar15 = (bVar19 - *(char *)(CONCAT31(uVar13,0x73) + 0x28cf20a3)) -
                 (ppcVar2 < ppcVar10 || uVar11 < uVar9);
        param_2 = (int **)CONCAT31(iVar12 >> 0x17,cVar15);
        cVar4 = *(char *)in_EAX;
        bVar25 = SBORROW1(cVar15,cVar4);
        bVar24 = (char)(cVar15 - cVar4) < '\0';
        bVar22 = cVar15 == cVar4;
      }
      ppcVar10 = unaff_EDI;
      if (bVar25) {
        if (!bVar22 && bVar25 == bVar24) {
          pcVar5 = (code *)swi(1);
          ppcVar10 = (char **)(*pcVar5)();
          return ppcVar10;
        }
code_r0x00401249:
        *(char *)unaff_EDI = (char)unaff_ESI;
        *(byte *)((int)unaff_EDI + 0x19b3159e) =
             *(byte *)((int)unaff_EDI + 0x19b3159e) ^ (byte)((uint)param_2 >> 8);
        return unaff_ESI;
      }
      do {
        unaff_EDI = unaff_ESI;
        uVar9 = *param_1;
        pbVar1 = (byte *)((int)(char **)((int)ppcVar20 + uVar9) + -0x4cc2d6ad);
        bVar22 = 5 < *pbVar1;
        bVar23 = SCARRY1(*pbVar1,-6);
        *pbVar1 = *pbVar1 - 6;
        bVar25 = (char)*pbVar1 < '\0';
        bVar24 = *pbVar1 == 0;
        iVar18 = CONCAT31((int3)((uint)in_EAX >> 8),5);
        param_2 = (int **)((int)ppcVar10 >> 0x1f);
        unaff_ESI = ppcVar10;
        ppcVar21 = (char **)((int)ppcVar20 + uVar9);
        do {
          ppcVar20 = ppcVar21;
          if (!bVar24 && bVar23 == bVar25) {
            if (bVar22) {
              pcVar5 = (code *)swi(1);
              ppcVar10 = (char **)(*pcVar5)();
              return ppcVar10;
            }
            goto code_r0x00401249;
          }
          unaff_EBX = (int *)CONCAT22((short)((uint)iVar18 >> 0x10),CONCAT11(0x81,(char)iVar18));
          ppcVar21 = (char **)((int)ppcVar20 + -1);
          if ((POPCOUNT((uint)ppcVar21 & 0xff) & 1U) == 0) {
            bVar22 = false;
            *(byte *)((int)unaff_EDI + -0x585b17f) =
                 *(byte *)((int)unaff_EDI + -0x585b17f) ^ (byte)((int)ppcVar10 >> 0x1f);
          }
          bVar17 = (byte)unaff_ESI;
          uVar9 = CONCAT31((int3)(CONCAT22((short)((uint)unaff_ESI >> 0x10),
                                           CONCAT11(bVar17 / 0x83,bVar17)) >> 8),bVar17 % 0x83);
          sVar16 = (short)((int)ppcVar10 >> 0x1f);
          if (param_1 == (uint *)0x0) {
            in_EAX = (char **)((uVar9 - *unaff_EBX) - (uint)bVar22);
            unaff_ESI = (char **)((int)ppcVar20 + 3);
            out(*ppcVar21,sVar16);
            goto code_r0x0040121f;
          }
          iVar18 = (int)unaff_EBX + 1;
          uVar11 = uVar9 + 0xbc5073b3;
          bVar25 = (int)uVar11 < 0;
          bVar24 = uVar11 == 0;
          uVar13 = (undefined3)(uVar11 >> 8);
          uVar8 = *(undefined *)(iVar18 + (uVar11 & 0xff));
          unaff_ESI = (char **)CONCAT31(uVar13,uVar8);
          pbVar1 = (byte *)((int)param_1 + 0x5a73b37f);
          bVar17 = *pbVar1;
          bVar22 = (*pbVar1 & 1) != 0;
          *pbVar1 = *pbVar1 >> 1 | (0x43af8c4c < uVar9) << 7;
          bVar23 = (char)bVar17 < '\0' != (char)*pbVar1 < '\0';
        } while (!bVar24 && bVar23 == bVar25);
        if (bVar23 == bVar25) {
          out(sVar16,unaff_ESI);
          _DAT_5b7f983f = unaff_ESI;
          *(byte *)ppcVar21 = *(char *)ppcVar21 - bVar14;
          out(0x1c,uVar8);
          return unaff_ESI;
        }
        *(char *)((int)ppcVar20 + -0x4cc2d6a6) = *(char *)((int)ppcVar20 + -0x4cc2d6a6) + -0x74;
        unaff_ESI = (char **)CONCAT31(uVar13,*(char *)ppcVar21);
        ppcVar10 = unaff_EDI;
      } while( true );
    }
    pbVar1 = (byte *)((int)unaff_EDI + 0x73b2c79d);
    *pbVar1 = *pbVar1 ^ (byte)((int)unaff_ESI >> 0x1f);
    if ('\0' < (char)*pbVar1) {
      out(*in_EAX,(undefined2)((int)unaff_ESI >> 0x1f));
      *(byte *)((int)param_1 + -0x6248cf81) = *(byte *)((int)param_1 + -0x6248cf81) | bVar17;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    bVar17 = (char)unaff_ESI + 0x39;
    bVar7 = bVar17 & 0x3a;
    uVar9 = CONCAT31(iVar12,bVar17) & 0xffffff3a;
    bVar24 = bVar7 == 0;
    bVar22 = (POPCOUNT(bVar7) & 1U) == 0;
    unaff_ESI = (char **)(CONCAT22((short)(uVar9 >> 0x10),
                                   CONCAT11(bVar24 << 6 | in_AF << 4 | bVar22 << 2,(char)uVar9)) |
                         0x200);
    uVar6 = *(undefined6 *)((int)unaff_ESI + 0xf1cfb54eU + (int)in_EAX);
    if (!bVar24) {
      ppcVar10 = (char **)in(0x7f);
      if (bVar24) {
        iVar18 = CONCAT31(uVar13,0xec);
        *(undefined2 *)(iVar18 + 0x5e) = in_FPUControlWord;
        *(undefined2 *)(iVar18 + 0x62) = in_FPUStatusWord;
        *(undefined2 *)(iVar18 + 0x66) = in_FPUTagWord;
        *(undefined4 *)(iVar18 + 0x72) = in_FPUDataPointer;
        *(undefined4 *)(iVar18 + 0x6a) = in_FPUInstructionPointer;
        *(undefined2 *)(iVar18 + 0x70) = in_FPULastInstructionOpcode;
        if (!bVar22) {
          return ppcVar10;
        }
        pbVar1 = (byte *)((int)uVar6 + 0x63d8f29d);
        *pbVar1 = *pbVar1 ^ bVar19;
        return ppcVar10;
      }
      if (!bVar24) {
        if (bVar24) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        goto code_r0x00401157;
      }
      if (!bVar24) {
code_r0x00401157:
        do {
          ppcVar10 = (char **)CONCAT31((int3)((uint)ppcVar10 >> 8),0x67);
          pbVar1 = (byte *)((int)ppcVar10 + (int)in_EAX * 8 + 0x5d);
          *pbVar1 = *pbVar1 | 0x77;
        } while ('\0' < (char)*pbVar1);
      }
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
  }
  *(byte *)((int)in_EAX + -0x4b) = *(byte *)((int)in_EAX + -0x4b) ^ bVar14;
  return unaff_ESI;
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
  FUN_00401219((uint *)piVar7[7],(int **)piVar7[6]);
  return;
}


