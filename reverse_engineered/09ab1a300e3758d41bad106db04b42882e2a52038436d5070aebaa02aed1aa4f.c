typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
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
// WARNING: Instruction at (ram,0x004012fb) overlaps instruction at (ram,0x004012f8)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 __fastcall entry(uint param_1,short *param_2)

{
  int *piVar1;
  char unaff_00021000;
  int **unaff_00021200;
  byte bVar2;
  byte bVar3;
  undefined uVar4;
  ushort uVar5;
  uint uVar6;
  uint uVar7;
  char cVar12;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 in_EAX;
  int iVar10;
  uint *puVar11;
  byte bVar14;
  byte bVar15;
  int unaff_EBX;
  int **ppiVar16;
  int **unaff_EBP;
  byte **ppbVar17;
  byte **unaff_ESI;
  int *unaff_EDI;
  undefined2 in_FS;
  bool bVar18;
  byte bVar19;
  byte in_AF;
  bool bVar20;
  float10 in_ST0;
  undefined in_YMM4 [32];
  undefined4 uStack_48;
  undefined4 uStack_41;
  undefined auStack_39 [17];
  int *apiStack_28 [2];
  undefined2 uVar13;
  
  iVar10 = 0x1f95;
  puVar11 = &DAT_00401000;
  do {
    *puVar11 = *puVar11 ^ 0x609f7537;
    puVar11 = puVar11 + 1;
    iVar10 = iVar10 + -1;
  } while (iVar10 != 0);
  iVar10 = 0xc74;
  puVar11 = &DAT_0042b000;
  do {
    *puVar11 = *puVar11 ^ 0x45417b0e;
    bVar18 = (uint *)0xfffffffb < puVar11;
    puVar11 = puVar11 + 1;
    iVar10 = iVar10 + -1;
  } while (iVar10 != 0);
  do {
    *unaff_ESI = (byte *)((int)unaff_EDI + (int)(*unaff_ESI + bVar18));
    bVar14 = 9 < ((byte)in_EAX & 0xf) | in_AF;
    uVar7 = CONCAT31((int3)((uint)in_EAX >> 8),(byte)in_EAX + bVar14 * '\x06') & 0xffffff0f;
    uVar7 = CONCAT22((short)(uVar7 >> 0x10),CONCAT11((char)((uint)in_EAX >> 8) + bVar14,(char)uVar7)
                    );
    if (*unaff_ESI != (byte *)0x0) {
      bVar14 = 9 < (DAT_61277242 & 0xf) | bVar14;
      uVar6 = CONCAT31((int3)((uint)unaff_ESI >> 8),DAT_61277242 + bVar14 * '\x06') & 0xffffff0f;
      uVar13 = (undefined2)(uVar6 >> 0x10);
      bVar15 = (byte)uVar6;
      if (*unaff_ESI == (byte *)0x0) {
        return CONCAT44(*(undefined4 *)
                         CONCAT22(uVar13,CONCAT11((char)((uint)unaff_ESI >> 8) + bVar14,bVar15)),
                        CONCAT22(uVar13,(ushort)bVar15 * (ushort)*(byte *)((int)unaff_EDI + -0x61)))
        ;
      }
      in(0x68);
      if (*(uint *)((int)param_2 + -0x1c01035) < param_1) {
        unaff_00021000 = '\x11';
        unaff_00021200 = apiStack_28 + 1;
        ppiVar16 = apiStack_28 + 1;
        cVar12 = '\x10';
        do {
          unaff_EBP = unaff_EBP + -1;
          ppiVar16 = ppiVar16 + -1;
          *ppiVar16 = *unaff_EBP;
          cVar12 = cVar12 + -1;
        } while ('\0' < cVar12);
      }
      (&uStack_48)[-(uint)(byte)(unaff_00021000 - 1)] = unaff_00021200;
      piVar1 = (int *)(uVar7 + 0x1eba35ee);
      *piVar1 = -*piVar1;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar7 = uVar7 ^ 0x9ff590be;
    unaff_EBP = (int **)((longlong)*unaff_EDI * 0x51d3722);
    bVar18 = (longlong)(int)unaff_EBP != (longlong)*unaff_EDI * 0x51d3722;
    if (bVar18) {
      *param_2 = (short)in_ST0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    bVar15 = (byte)uVar7;
    uVar5 = (ushort)(uVar7 >> 0x10);
    if (uVar7 == 0) {
      bVar2 = bVar15 + 0xbe;
      uStack_41._1_3_ = SUB43(unaff_EDI,0);
      bVar19 = 9 < (bVar2 & 0xf) | bVar14;
      uVar7 = CONCAT31((int3)(((uint)uVar5 << 0x10) >> 8),bVar2 + bVar19 * '\x06') & 0xffffff0f;
      bVar3 = (byte)uVar7;
      cVar12 = (((char)bVar2 < '\0') << 7 | (bVar2 == 0) << 6 | bVar14 << 4 |
                ((POPCOUNT(bVar2) & 1U) == 0) << 2 | 2 | 0x41 < bVar15) + bVar19;
      uVar7 = CONCAT22((short)(uVar7 >> 0x10),CONCAT11(cVar12,bVar3));
      ppiVar16 = unaff_EBP;
      ppbVar17 = unaff_ESI;
      if (bVar2 == 0) {
        *(undefined2 *)unaff_EDI = in_FS;
        ppiVar16 = (int **)*unaff_EBP;
        bVar19 = 9 < bVar3 | bVar19;
        uVar7 = CONCAT31((int3)(uVar7 >> 8),bVar3 + bVar19 * '\x06') & 0xffffff0f;
        uVar13 = (undefined2)(uVar7 >> 0x10);
        uVar4 = (undefined)uVar7;
        ppbVar17 = (byte **)0x0;
        param_1 = param_1 - 1;
        *unaff_EBP = (int *)CONCAT22(uVar13,CONCAT11(cVar12 + bVar19,uVar4));
        unaff_EBP[-1] = (int *)param_1;
        unaff_EBP[-2] = (int *)param_2;
        unaff_EBP[-3] = (int *)0xbb79b606;
        unaff_EBP[-4] = (int *)(unaff_EBP + 1);
        unaff_EBP[-5] = (int *)ppiVar16;
        uStack_41._1_3_ = 0x307710;
        unaff_EBP[-7] = unaff_EDI;
        unaff_EBX = -0x448649bc;
        bVar14 = (byte)((uint)param_2 >> 8) | *(byte *)unaff_EDI;
        param_2 = (short *)CONCAT22((short)((uint)param_2 >> 0x10),CONCAT11(bVar14,(char)param_2));
        uVar7 = CONCAT22(uVar13,CONCAT11(((char)bVar14 < '\0') << 7 | (bVar14 == 0) << 6 |
                                         bVar19 << 4 | ((POPCOUNT(bVar14) & 1U) == 0) << 2,uVar4)) ^
                0xac | 0x200;
      }
      *(byte *)unaff_EDI = *(byte *)unaff_EDI | (byte)unaff_EBX;
      vpunpcklbw_avx2(in_YMM4,*(undefined (*) [32])((int)unaff_EDI + 0x51));
      bVar19 = 9 < ((byte)uVar7 & 0xf) | bVar19;
      bVar14 = (byte)uVar7 + bVar19 * -6;
      uVar7 = CONCAT31((int3)(uVar7 >> 8),bVar14 + (0x9f < bVar14 | bVar19 * (bVar14 < 6)) * -0x60);
      uVar13 = (undefined2)((uint)param_2 >> 0x10);
      uVar4 = SUB41(param_2,0);
      bVar15 = (byte)((uint)param_2 >> 8) & *(byte *)unaff_EDI;
      param_2 = (short *)CONCAT22(uVar13,CONCAT11(bVar15,uVar4));
      unaff_ESI = (byte **)(uVar7 + 0x8a8a2f41);
      if (0x7575d0be < uVar7 && unaff_ESI != (byte **)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (&stack0x00000000 == (undefined *)0x41) {
code_r0x00401267:
        bVar2 = (byte)unaff_ESI;
        bVar14 = (byte)((uint)param_2 >> 8) & *(byte *)unaff_EDI;
        uVar4 = *(undefined *)
                 (CONCAT22((short)((uint)param_2 >> 0x10),CONCAT11(bVar14,(char)param_2)) +
                 -0x60c878bc);
        bVar18 = (bVar14 & *(byte *)unaff_EDI) != 0;
        *(byte *)((int)unaff_EDI + 3) = 0x87;
        uVar8 = CONCAT22((short)((uint)unaff_ESI >> 0x10),CONCAT11(0xb1,bVar2));
        LOCK();
        *(undefined4 *)(CONCAT22((short)(param_1 >> 0x10),CONCAT11(uVar4,(byte)param_1)) + -2) =
             0x9f378774;
        UNLOCK();
        bVar15 = ((byte)param_1 & 0x1f) % 9;
        bVar14 = *(byte *)((int)unaff_EDI + 0x371b859d);
        *(byte *)((int)unaff_EDI + 0x371b859d) = bVar14 >> bVar15 | bVar14 << 9 - bVar15;
        if (bVar18) {
          *(byte *)unaff_EDI = *(byte *)unaff_EDI | (byte)((uint)unaff_EBX >> 8);
          uVar9 = uVar8;
        }
        else {
          _DAT_609fd653 = uVar8;
          bVar19 = 9 < (bVar2 & 0xf) | bVar19;
          uVar7 = CONCAT31((int3)((uint)uVar8 >> 8),bVar2 + bVar19 * '\x06') & 0xffffff0f;
          uVar9 = CONCAT22((short)(uVar7 >> 0x10),CONCAT11(bVar19 + 0xb1,(char)uVar7));
          if (!bVar18) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
        return CONCAT44(0xc9d367f0,uVar9);
      }
      if (&stack0x00000000 == (undefined *)0x41) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar14 = 0;
      bVar15 = bVar15 & *(byte *)unaff_EDI;
      param_2 = (short *)CONCAT22(uVar13,CONCAT11(bVar15,uVar4));
      bVar20 = (char)bVar15 < '\0';
      bVar18 = bVar15 == 0;
      bVar15 = POPCOUNT(bVar15);
      param_1 = uStack_41;
      unaff_EBP = ppiVar16;
      in_AF = 9 < ((byte)ppbVar17 & 0xf) | bVar19;
    }
    else {
      uVar7 = CONCAT22(uVar5,CONCAT11(((int)uVar7 < 0) << 7 | (uVar7 == 0) << 6 | bVar14 << 4 |
                                      ((POPCOUNT(uVar7 & 0xff) & 1U) == 0) << 2 | 2 | bVar18,bVar15)
                      ) + 0x609ecd30 + (uint)bVar18;
      bVar20 = (int)uVar7 < 0;
      bVar18 = uVar7 == 0;
      bVar15 = POPCOUNT(uVar7 & 0xff);
      while( true ) {
        bVar14 = 9 < ((byte)uVar7 & 0xf) | bVar14;
        uVar7 = CONCAT31((int3)(uVar7 >> 8),(byte)uVar7 + bVar14 * '\x06') & 0xffffff0f;
        bVar2 = (byte)uVar7;
        uVar7 = CONCAT22((short)(uVar7 >> 0x10),(ushort)bVar2);
        if (bVar18) break;
        if (!bVar18) {
          bVar19 = 9 < bVar2 | bVar14;
          uVar7 = CONCAT31((int3)(uVar7 >> 8),bVar2 + bVar19 * '\x06') & 0xffffff0f;
          unaff_ESI = (byte **)CONCAT22((short)(uVar7 >> 0x10),(ushort)(byte)uVar7);
          goto code_r0x00401267;
        }
      }
      *(char *)((int)unaff_ESI + 0x37222f59) = (char)param_2;
      in_AF = bVar14;
    }
    uVar5 = CONCAT11(bVar20 << 7 | bVar18 << 6 | in_AF << 4 | ((bVar15 & 1) == 0) << 2 | 2 | bVar14,
                     (char)auStack_39);
    uVar7 = CONCAT31((int3)(CONCAT22((short)((uint)auStack_39 >> 0x10),uVar5) >> 8),
                     *(undefined *)(unaff_EBX + (uVar5 & 0xff)));
    bVar18 = uVar7 < 0x75376127;
    uVar7 = uVar7 + 0x8ac89ed9;
    in_EAX = CONCAT22((short)(uVar7 >> 0x10),
                      CONCAT11(((int)uVar7 < 0) << 7 | (uVar7 == 0) << 6 | in_AF << 4 |
                               ((POPCOUNT(uVar7 & 0xff) & 1U) == 0) << 2 | 2 | bVar18,(char)uVar7));
  } while( true );
}


