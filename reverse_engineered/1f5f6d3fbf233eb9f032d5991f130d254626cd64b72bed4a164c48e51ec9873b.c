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
// WARNING: Instruction at (ram,0x004011e9) overlaps instruction at (ram,0x004011e8)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x004012c7)
// WARNING: Removing unreachable block (ram,0x004012d0)
// WARNING: Removing unreachable block (ram,0x004012d1)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall entry(int *param_1,byte **param_2)

{
  byte *pbVar1;
  char cVar2;
  undefined4 *puVar3;
  byte bVar4;
  code *pcVar5;
  undefined uVar6;
  byte bVar7;
  byte bVar8;
  uint uVar9;
  uint *puVar10;
  uint in_EAX;
  int iVar11;
  int *extraout_ECX;
  byte bVar12;
  undefined3 uVar13;
  byte bVar15;
  undefined4 uVar14;
  int *unaff_EBX;
  uint *puVar16;
  uint *puVar17;
  uint *puVar18;
  int *piVar19;
  uint *puVar20;
  int *piVar21;
  undefined *puVar22;
  int *piVar23;
  int unaff_EBP;
  undefined4 *puVar24;
  undefined4 *unaff_ESI;
  uint uVar25;
  uint *unaff_EDI;
  undefined2 in_SS;
  bool bVar26;
  byte in_AF;
  bool bVar27;
  bool bVar28;
  undefined8 uVar29;
  
  iVar11 = 0x2057;
  puVar10 = &DAT_00401000;
  do {
    *puVar10 = *puVar10 ^ 0x3f327147;
    puVar10 = puVar10 + 1;
    iVar11 = iVar11 + -1;
  } while (iVar11 != 0);
  iVar11 = 0xcfe;
  puVar10 = &DAT_0042c000;
  do {
    *puVar10 = *puVar10 ^ 0x3e4a0142;
    bVar26 = (uint *)0xfffffffb < puVar10;
    puVar10 = puVar10 + 1;
    iVar11 = iVar11 + -1;
  } while (iVar11 != 0);
  while( true ) {
    puVar10 = (uint *)(in_EAX + 0x71473f93 + (uint)bVar26);
    param_1 = (int *)CONCAT22((short)((uint)param_1 >> 0x10),
                              CONCAT11((byte)((uint)param_1 >> 8) ^ *(byte *)((int)param_2 + -0x32),
                                       (char)param_1));
    uVar9 = *puVar10;
    uVar29 = CONCAT44(param_2,uVar9);
    puVar20 = puVar10 + 1;
    *(byte *)unaff_EDI = 0;
    if (-1 < (char)*(byte *)unaff_EDI) {
      LOCK();
      puVar24 = (undefined4 *)*unaff_EBX;
      *unaff_EBX = (int)unaff_ESI;
      UNLOCK();
      bVar26 = false;
      bVar28 = false;
      uVar9 = uVar9 & 0xffffff00;
      bVar27 = false;
      puVar10 = unaff_EDI;
      goto code_r0x00401276;
    }
    piVar23 = (int *)(uVar9 + 0x6271072f);
    iVar11 = *piVar23;
    *piVar23 = *piVar23 - unaff_EBP;
    uVar14 = puVar10[1];
    puVar17 = puVar10 + 2;
    pcVar5 = (code *)swi(4);
    puVar18 = puVar10 + 2;
    if (SBORROW4(iVar11,unaff_EBP) != false) {
      uVar29 = (*pcVar5)();
      param_1 = extraout_ECX;
      puVar18 = puVar17;
    }
    puVar16 = (uint *)((int)puVar18 + -4);
    *(uint **)((int)puVar18 + -4) = puVar18;
    uVar14 = CONCAT22((short)((uint)uVar14 >> 0x10),
                      CONCAT11((byte)((uint)uVar14 >> 8) ^ *(byte *)unaff_EDI,(char)uVar14));
    puVar10 = (uint *)((int)unaff_EDI + 1);
    piVar23 = (int *)unaff_EBP;
    if (SCARRY4((int)unaff_EDI,1)) {
      bVar12 = (byte)param_1 & 0x1f;
      uVar9 = *(uint *)((int)unaff_EDI + 0x23);
      *(uint *)((int)unaff_EDI + 0x23) = uVar9 << bVar12 | uVar9 >> 0x21 - bVar12;
      *(undefined4 *)((int)puVar18 + -8) = 0x6fda14ce;
      *(undefined2 *)((int)puVar18 + -0xc) = in_SS;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    while( true ) {
      puVar24 = (undefined4 *)*(undefined6 *)((int)piVar23 + 0x71468736);
      bVar15 = (byte)((uint)uVar14 >> 8) ^ *(byte *)puVar10;
      unaff_EBX = (int *)CONCAT22((short)((uint)uVar14 >> 0x10),CONCAT11(bVar15,(char)uVar14));
      cVar2 = *(char *)puVar24;
      bVar12 = in((short)((ulonglong)uVar29 >> 0x20));
      *(byte *)puVar10 = bVar12;
      pcVar5 = (code *)swi(4);
      if (SBORROW1((char)((uint)param_1 >> 8),cVar2) != false) {
        uVar29 = (*pcVar5)();
      }
      param_2 = (byte **)((ulonglong)uVar29 >> 0x20);
      in_AF = (*puVar16 & 0x10) != 0;
      unaff_ESI = puVar24 + (uint)((*puVar16 & 0x400) != 0) * -2 + 1;
      out(*puVar24,(short)((ulonglong)uVar29 >> 0x20));
      param_1 = (int *)*(undefined6 *)((int)unaff_ESI + -1 + (int)unaff_EBX);
      uVar9 = (int)uVar29 + 0x404a3271;
      unaff_EBP = *piVar23;
      puVar16 = (uint *)(piVar23 + 1);
      piVar19 = piVar23 + 1;
      uVar25 = (uint)(uint *)((int)puVar10 + 1) ^ *(uint *)((int)puVar10 + 1);
      bVar27 = SCARRY4(uVar25,1);
      puVar10 = (uint *)(uVar25 + 1);
      bVar26 = (int)puVar10 < 0;
      bVar12 = (byte)((ulonglong)uVar29 >> 0x20);
      uVar13 = (undefined3)((ulonglong)uVar29 >> 0x28);
      if (bVar27) break;
      LOCK();
      iVar11 = *unaff_EBX;
      *unaff_EBX = (int)unaff_ESI;
      UNLOCK();
      uVar14 = 0xc43f320f;
      param_1 = (int *)0x3600;
      LOCK();
      uVar29 = CONCAT44(CONCAT31(uVar13,bVar12 ^ bVar15),*(uint *)(iVar11 + 0x71));
      *(uint *)(iVar11 + 0x71) = uVar9;
      UNLOCK();
      piVar23 = (int *)unaff_EBP;
    }
    uVar6 = *(undefined *)((int)unaff_EBX + (uVar9 & 0xff));
    in_EAX = CONCAT31((int3)(uVar9 >> 8),uVar6);
    out(0x5d,uVar6);
    if (bVar27 == bVar26) break;
    unaff_EDI = (uint *)((int)puVar10 - *param_1);
    *(byte *)((int)unaff_EDI + 0x473e8a29) = 0;
    bVar26 = false;
    param_2 = (byte **)CONCAT31(uVar13,bVar12 ^ (byte)(uVar9 >> 8));
  }
  while( true ) {
    puVar24 = unaff_ESI + 1;
    out(*unaff_ESI,(short)param_2);
    param_1 = (int *)CONCAT31((int3)((uint)param_1 >> 8),0x70);
    bVar12 = 9 < ((byte)in_EAX & 0xf) | in_AF;
    uVar9 = CONCAT31((int3)(in_EAX >> 8),(byte)in_EAX + bVar12 * -6) & 0xffffff0f;
    bVar7 = (byte)uVar9;
    bVar15 = 9 < bVar7 | bVar12;
    bVar8 = bVar7 + bVar15 * -6;
    bVar4 = 0x9f < bVar8 | bVar12 | bVar15 * (bVar8 < 6);
    in_EAX = CONCAT31((int3)(CONCAT22((short)(uVar9 >> 0x10),
                                      CONCAT11((char)(in_EAX >> 8) - bVar12,bVar7)) >> 8),
                      bVar8 + bVar4 * -0x60);
    piVar21 = (int *)((int)piVar19 + -4);
    *(int *)((int)piVar19 + -4) = unaff_EBP;
    puVar22 = (undefined *)((int)piVar19 + -4);
    if (bVar27 == bVar26) break;
    in_AF = *param_2 < param_2 || (uint)((int)*param_2 - (int)param_2) < (uint)bVar4;
    *param_2 = (byte *)(((int)*param_2 - (int)param_2) - (uint)bVar4);
    bVar26 = SCARRY4(_DAT_3922da71,1);
    _DAT_3922da71 = _DAT_3922da71 + 1;
    if (!bVar26) goto LAB_00401299;
    *(char *)((int)param_2 + 0x59) = '\0';
    puVar22 = (undefined *)((int)piVar19 + -4);
    if (bVar26 == *(char *)((int)param_2 + 0x59) < '\0') goto LAB_004012b4;
    puVar18 = (uint *)((int)puVar10 + 0x72c03233);
    bVar26 = in_EAX < *puVar18;
    uVar9 = in_EAX - *puVar18;
    bVar28 = SBORROW4(in_EAX,*puVar18) != false;
    bVar27 = (int)uVar9 < 0;
    puVar20 = (uint *)((int)piVar19 + -8);
    *(int **)((int)piVar19 + -8) = param_1;
    in_AF = bVar15;
code_r0x00401276:
    if (bVar28 == bVar27) goto LAB_004012c0;
    piVar21 = (int *)puVar20 + 1;
    iVar11 = uVar9 - *(int *)((int)puVar10 + 0xfd73233);
    *(byte *)param_2 = *(byte *)param_2 | (byte)((uint)param_2 >> 8);
    in_AF = 9 < ((byte)iVar11 & 0xf) | in_AF;
    uVar9 = CONCAT31((int3)((uint)iVar11 >> 8),(byte)iVar11 + in_AF * -6) & 0xffffff0f;
    in_EAX = CONCAT22((short)(uVar9 >> 0x10),CONCAT11((char)((uint)iVar11 >> 8) - in_AF,(char)uVar9)
                     );
    puVar24 = (undefined4 *)*(undefined6 *)(unaff_EBP + -0x771f1d6);
    bVar15 = in_AF;
    if ((char)*(byte *)param_2 < '\x01') goto LAB_0040128c;
    *puVar20 = unaff_EBP;
    puVar10 = (uint *)((int)puVar10 + 1);
    bVar27 = SBORROW4((int)puVar24,(int)*param_2) !=
             SBORROW4((int)puVar24 - (int)*param_2,(uint)in_AF);
    unaff_ESI = (undefined4 *)(((int)puVar24 - (int)*param_2) - (uint)in_AF);
    bVar26 = (int)unaff_ESI < 0;
    piVar19 = (int *)puVar20 + -1;
    ((int *)puVar20)[-1] = (int)puVar10;
  }
LAB_004012a4:
  *(byte *)(puVar10 + 1) = (byte)in_EAX;
  unaff_EBP = unaff_EBP + -1;
  bVar12 = *(byte *)(param_1 + -4);
  *(byte *)(param_1 + -4) = bVar12 << 2 | bVar12 >> 7;
  param_2 = (byte **)((int)(short)(in_EAX >> 0x10) >> 0xf);
LAB_004012b4:
  param_2 = (byte **)CONCAT31((int3)((uint)param_2 >> 8),(byte)param_2 ^ *(byte *)(unaff_EBP + 0x47)
                             );
  puVar3 = (undefined4 *)*param_2;
  pbVar1 = *param_2;
  *(int *)(puVar22 + -4) = unaff_EBP;
  uVar9 = (int)(byte *)((int)puVar24 - (int)pbVar1) - (int)*param_2;
  bVar26 = (byte *)((int)puVar24 - (int)pbVar1) < *param_2 || uVar9 < (puVar24 < puVar3);
  puVar24 = (undefined4 *)(uVar9 - (puVar24 < puVar3));
  *(int *)(puVar22 + -7) = unaff_EBP;
LAB_004012c0:
  *param_2 = *param_2 + (-(uint)bVar26 - (int)puVar24);
  pcVar5 = (code *)swi(1);
  (*pcVar5)();
  return;
LAB_0040128c:
  do {
    piVar21 = (int *)((int)piVar21 + 4);
    param_2 = (byte **)((int)in_EAX >> 0x1f);
    do {
      pbVar1 = (byte *)((int)param_1 + 0x47);
      bVar12 = *pbVar1;
      bVar8 = (byte)in_EAX;
      bVar4 = *pbVar1;
      bVar7 = *pbVar1 + bVar8;
      bVar26 = SCARRY1(bVar7,in_AF);
      *pbVar1 = bVar7 + in_AF;
      in_AF = CARRY1(bVar12,bVar8) || CARRY1(bVar7,in_AF);
    } while (SCARRY1(bVar4,bVar8) == bVar26);
    in_AF = false;
    unaff_EBX = (int *)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                                CONCAT11((byte)((uint)unaff_EBX >> 8) ^ *(byte *)puVar10,
                                         (char)unaff_EBX));
    bVar26 = SCARRY4((int)puVar10,1);
    puVar10 = (uint *)((int)puVar10 + 1);
LAB_00401299:
  } while (!bVar26);
  bVar15 = 9 < ((byte)in_EAX & 0xf) | bVar15;
  bVar12 = (byte)in_EAX + bVar15 * -6;
  in_EAX = CONCAT31((int3)(in_EAX >> 8),
                    *(undefined *)
                     (CONCAT22((short)((uint)unaff_EBX >> 0x10),
                               CONCAT11((char)((uint)unaff_EBX >> 8) + (bVar12 & 0xf) + bVar15,
                                        (char)unaff_EBX)) + (bVar12 & 0xf))) & 0xffff00ff;
  LOCK();
  *(byte ***)((int)puVar10 + 0x3d) = param_2;
  UNLOCK();
  puVar10 = (uint *)((uint)puVar10 ^ *puVar10);
  puVar22 = (undefined *)piVar21;
  goto LAB_004012a4;
}


