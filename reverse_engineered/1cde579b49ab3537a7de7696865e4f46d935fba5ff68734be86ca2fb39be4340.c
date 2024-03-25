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
// WARNING: Instruction at (ram,0x00401324) overlaps instruction at (ram,0x00401323)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall
entry(int *param_1,uint *param_2,undefined param_3,undefined param_4,undefined param_5,byte param_6,
     undefined param_7,undefined param_8,undefined param_9,undefined param_10,int *param_11)

{
  byte *pbVar1;
  uint uVar2;
  ushort uVar3;
  undefined4 uVar4;
  byte bVar5;
  undefined uVar6;
  byte bVar7;
  int *piVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  char *pcVar13;
  int *in_EAX;
  uint *puVar14;
  char cVar16;
  uint uVar15;
  int *piVar17;
  int *unaff_ESI;
  int *unaff_EDI;
  undefined2 uVar18;
  undefined2 in_CS;
  undefined2 uVar19;
  undefined2 in_DS;
  int unaff_FS_OFFSET;
  char cVar20;
  bool bVar21;
  byte in_AF;
  bool bVar22;
  float10 extraout_ST0;
  float10 in_ST0;
  undefined8 uVar23;
  undefined6 uVar24;
  int unaff_retaddr;
  undefined3 in_stack_00000021;
  int *in_stack_00000024;
  int *in_stack_00000028;
  int *in_stack_0000002c;
  undefined4 *in_stack_00000030;
  int *in_stack_00000034;
  uint *in_stack_00000038;
  int *in_stack_0000003c;
  int *in_stack_00000040;
  undefined2 uStack00000044;
  undefined4 in_stack_00000050;
  int in_stack_00000054;
  int in_stack_00000058;
  int *in_stack_00000068;
  int *in_stack_0000006c;
  int *in_stack_00000074;
  uint *in_stack_00000078;
  int *in_stack_0000007c;
  int *in_stack_00000080;
  int *in_stack_00000084;
  int *in_stack_00000088;
  int *in_stack_0000008c;
  uint *in_stack_00000090;
  int *in_stack_00000094;
  int *in_stack_00000098;
  uint in_stack_0000009c;
  int *in_stack_000000a0;
  short sStack000000b8;
  undefined2 uStack000000c0;
  undefined2 uStack000000c4;
  int *in_stack_000000c8;
  int *in_stack_000000cc;
  uint in_stack_000000d0;
  int in_stack_000000d8;
  uint *in_stack_000000dc;
  uint *in_stack_000000e0;
  int *in_stack_000000e4;
  undefined2 uStack000000e8;
  undefined4 in_stack_000000f8;
  undefined4 in_stack_000000fc;
  int in_stack_00000100;
  undefined4 in_stack_00000104;
  undefined4 in_stack_00000108;
  int in_stack_0000011c;
  undefined4 in_stack_00000120;
  undefined2 in_stack_00000124;
  int in_stack_0000012c;
  uint *in_stack_00000138;
  byte bStack00000140;
  int *piVar12;
  
  puVar14 = &DAT_00401000;
  do {
    *puVar14 = *puVar14 ^ 0x61611712;
    puVar14 = puVar14 + 1;
  } while (puVar14 != (uint *)0x408e14);
  puVar14 = &DAT_0042b000;
  do {
    *puVar14 = *puVar14 ^ 0x552e3500;
    puVar14 = puVar14 + 1;
    bVar21 = puVar14 < (uint *)0x42e3d0;
  } while (puVar14 != (uint *)0x42e3d0);
LAB_00401219:
  if (!bVar21) goto LAB_004011db;
  piVar8 = (int *)((uint)in_stack_0000003c ^ 0x9b);
  uVar15 = (uint)in_stack_00000030 | *(uint *)((int)in_stack_00000024 + 0x23d10b7a);
  pbVar1 = (byte *)((int)_param_10 + -5);
  bVar7 = (byte)(uVar15 >> 8);
  bVar21 = CARRY1(bVar7,*pbVar1);
  piVar12 = (int *)CONCAT22((short)(uVar15 >> 0x10),CONCAT11(bVar7 + *pbVar1,(char)uVar15));
  if (SCARRY1(bVar7,*pbVar1) == SCARRY1(bVar7 + *pbVar1,'\0')) goto LAB_0040127f;
  _DAT_6161329b = _DAT_6161329b ^ (uint)piVar8;
  bVar21 = CARRY1((byte)in_stack_00000034,*(byte *)_param_10);
  puVar14 = (uint *)CONCAT31((int3)((uint)in_stack_00000034 >> 8),
                             (byte)in_stack_00000034 + *(char *)_param_10);
  param_1 = (int *)((int)in_stack_00000038 + -1);
  piVar17 = in_stack_00000028;
  unaff_ESI = in_stack_00000024;
  unaff_EDI = _param_10;
  if (param_1 != (int *)0x0) goto code_r0x004011b6;
  uVar15 = CONCAT31((int3)((uint)in_stack_0000003c >> 8),
                    (byte)piVar8 + ((undefined *)((int)_param_10 + 0x36))[(int)in_stack_00000024]);
  if (CARRY1((byte)piVar8,((undefined *)((int)_param_10 + 0x36))[(int)in_stack_00000024])) {
    in_EAX = (int *)(uVar15 ^ 0x669e9994);
    param_2 = puVar14;
    do {
      iVar9 = *piVar12;
      *piVar12 = *piVar12 << 1;
      bVar7 = (byte)((uint)piVar12 >> 8);
      bVar21 = CARRY1(bVar7,bVar7) || CARRY1(bVar7 * '\x02',iVar9 < 0);
LAB_004011db:
      while( true ) {
        *unaff_EDI = *unaff_ESI;
        cVar20 = (char)((uint)param_1 >> 8);
        if (SBORROW1(cVar20,(char)in_EAX) != SBORROW1(cVar20 - (char)in_EAX,bVar21)) {
          *(int *)(unaff_retaddr + -0x27) = *(int *)(unaff_retaddr + -0x27) << (param_6 & 0x1f);
          iVar9 = in_stack_00000054 + -1;
          bVar7 = 9 < ((byte)iVar9 & 0xf) | in_AF;
          uVar15 = CONCAT31((int3)((uint)iVar9 >> 8),(byte)iVar9 + bVar7 * -6) & 0xffffff0f;
          in_stack_00000054 =
               CONCAT22((short)(uVar15 >> 0x10),
                        CONCAT11((char)((uint)iVar9 >> 8) - bVar7,(char)uVar15));
          param_11 = (int *)&stack0x00000078;
          in_stack_00000058 = in_stack_00000058 + 4;
          in_AF = ((uint)in_stack_00000074 & 0x1000) != 0;
          bVar21 = ((uint)in_stack_00000074 & 0x100) != 0;
          in_EAX = (int *)((uint)in_stack_00000094 >> 8 & 0xff);
          param_1 = in_stack_00000094;
          param_2 = in_stack_00000090;
          unaff_ESI = in_stack_00000080;
          unaff_EDI = in_stack_0000007c;
          in_stack_00000074 =
               (int *)CONCAT31((int3)((uint)in_stack_00000074 >> 8),
                               (char)in_stack_00000074 + '\x15' +
                               ((byte)in_stack_00000050 < *(byte *)((int)in_stack_00000040 + -0x2f))
                              );
          goto LAB_00401219;
        }
        in((short)param_2);
        *unaff_ESI = 0x40118e;
        bVar5 = func_0x1c16f42c();
        in_stack_00000024 = (int *)&DAT_00000061;
        unaff_EDI = (int *)&DAT_00000061;
        bVar7 = (byte)in_stack_00000038 + *(byte *)((int)in_stack_0000002c + 0x14d71b69);
        bVar22 = CARRY1((byte)in_stack_00000038,*(byte *)((int)in_stack_0000002c + 0x14d71b69)) ||
                 CARRY1(bVar7,0xe2 < bVar5);
        puVar14 = (uint *)CONCAT31((int3)((uint)in_stack_00000038 >> 8),bVar7 + (0xe2 < bVar5));
        piVar8 = (int *)((int)in_stack_00000040 + 1);
        in_ST0 = extraout_ST0;
        if ((int)piVar8 < 0) break;
        bVar7 = (byte)((uint)piVar8 >> 8);
        bVar21 = CARRY1(bVar7,*(byte *)(unaff_FS_OFFSET + 0x171a6185));
        piVar8 = in_stack_00000080;
        param_1 = in_stack_0000007c;
        puVar14 = in_stack_00000078;
        piVar12 = in_stack_00000074;
        piVar17 = in_stack_0000006c;
        unaff_ESI = in_stack_00000068;
        unaff_EDI = param_11;
        if (-1 < (char)(bVar7 + *(byte *)(unaff_FS_OFFSET + 0x171a6185))) goto code_r0x004011b6;
        *(int *)((int)in_stack_00000074 + -0x1de8ede6) =
             *(int *)((int)in_stack_00000074 + -0x1de8ede6) + 1;
        in_EAX = in_stack_00000080;
        param_2 = in_stack_00000078;
      }
      bVar7 = (byte)in_stack_0000003c + (byte)in_stack_00000034;
      bVar21 = CARRY1((byte)in_stack_0000003c,(byte)in_stack_00000034) || CARRY1(bVar7,bVar22);
      param_1 = (int *)CONCAT31((int3)((uint)in_stack_0000003c >> 8),bVar7 + bVar22);
      piVar12 = in_stack_00000034;
      piVar17 = in_stack_0000002c;
      unaff_ESI = in_stack_00000028;
code_r0x004011b6:
      in_stack_00000030 = (undefined4 *)&stack0x00000044;
      *(int **)((int)piVar8 + -0x1d9ee897) = piVar12;
      in_EAX = (int *)CONCAT31((int3)((uint)piVar8 >> 8),-bVar21);
      in_DS = uStack00000044;
      _uStack00000044 = 0xd91067a1;
      param_2 = (uint *)(uint)CONCAT11(DAT_669e9994,(char)puVar14);
      in_stack_00000024 = unaff_EDI;
      in_stack_00000028 = unaff_ESI;
      in_stack_0000002c = piVar17;
      in_stack_00000034 = piVar12;
      in_stack_00000038 = puVar14;
      in_stack_0000003c = param_1;
      in_stack_00000040 = in_EAX;
    } while( true );
  }
  iVar10 = uVar15 - *(uint *)((int)in_stack_00000028 + 7);
  uVar15 = (uint)(uVar15 < *(uint *)((int)in_stack_00000028 + 7));
  uVar2 = (int)piVar12 - (int)*(int **)((int)in_stack_00000028 + 0x61);
  uVar11 = uVar2 - uVar15;
  uVar15 = (uint)(piVar12 < *(int **)((int)in_stack_00000028 + 0x61) || uVar2 < uVar15);
  piVar8 = (int *)((int)in_stack_00000028 + 0xb);
  bVar7 = (byte)uVar11 & 0x1f;
  iVar9 = *piVar8;
  *piVar8 = *piVar8 << bVar7;
  bVar21 = (uVar11 & 0x1f) != 0;
  bVar5 = (byte)iVar10;
  piVar8 = (int *)CONCAT22((short)((uint)iVar10 >> 0x10),
                           CONCAT11((char)((uint)iVar10 >> 8) +
                                    *(char *)((int)in_stack_00000028 + 0x61) +
                                    (!bVar21 && CARRY4((uint)in_stack_00000024,uVar15) ||
                                    bVar21 && iVar9 << bVar7 - 1 < 0),bVar5));
  *puVar14 = *puVar14 | (uint)_param_10;
  if ((int)((uint)(uint *)((uint)puVar14 ^ uVar11) & *(uint *)((uint)puVar14 ^ uVar11)) < 1) {
    *(int *)((int)in_stack_00000038 + 0x16) = *(int *)((int)in_stack_00000038 + 0x16) << 1;
    *(undefined **)((int)in_stack_00000038 + (int)in_stack_00000028 * 2 + 0x279e6116) =
         (undefined *)((int)in_stack_00000024 + uVar15 + 4);
    DAT_279e6155 = in_AF * -6 & 0xf;
    *piVar8 = *piVar8 << 1;
    iVar9 = *piVar8;
    *piVar8 = *piVar8 << 1;
    pbVar1 = (byte *)((int)in_stack_00000024 + uVar15 + 0x55a27548);
    bVar21 = CARRY1(bVar5,*pbVar1) || CARRY1(bVar5 + *pbVar1,iVar9 < 0);
    in_stack_00000034 = in_stack_00000094;
    in_stack_00000080 = (int *)&stack0x00000084;
LAB_0040127f:
    piVar12 = in_stack_000000a0;
    *in_stack_00000034 = (int)in_stack_00000034;
    piVar8 = (int *)(in_stack_0000009c + 0x50);
    bVar7 = (byte)in_stack_0000009c & 0x1f;
    iVar9 = *piVar8;
    *piVar8 = *piVar8 >> bVar7;
    bVar22 = (in_stack_0000009c & 0x1f) != 0;
    in_stack_00000084[-0x2f58b5] = (int)ROUND(in_ST0);
    DAT_6161b476 = SUB41(in_stack_00000098,0);
    cVar20 = (char)in_stack_00000094;
    uVar15 = (uint)in_stack_00000094 >> 8;
    in_stack_00000090 = (uint *)&stack0x000000a4;
    in_stack_000000a0 = in_stack_00000098;
    in_stack_00000094 = piVar12;
    in_stack_0000008c = in_stack_00000088;
    in_stack_00000088 = in_stack_00000084;
    in_stack_00000084 = in_stack_00000080;
    DAT_849e4761 = DAT_6161b476;
    in_stack_00000098 =
         (int *)CONCAT31((int3)uVar15,
                         cVar20 + *(char *)in_stack_00000080 +
                         (!bVar22 & bVar21 | (bVar22 && (iVar9 >> bVar7 - 1 & 1U) != 0)));
  }
  *(char *)in_stack_00000084 = *(char *)in_stack_00000084 - (char)in_stack_00000098;
  in(sStack000000b8 + 1);
  bVar22 = false;
  bVar21 = (int)(uint *)((uint)in_stack_000000dc | *in_stack_000000dc) < 0;
  piVar8 = in_stack_000000e4;
  puVar14 = (uint *)((uint)in_stack_000000dc | *in_stack_000000dc);
  iVar9 = in_stack_000000d8;
  piVar12 = in_stack_000000c8;
  uVar19 = uStack000000c4;
  uStack000000c0 = in_DS;
  do {
    uVar4 = _uStack000000e8;
    if (bVar22 == bVar21) {
LAB_0040131c:
      _uStack000000e8 = uVar4;
      in((short)puVar14);
      in_stack_000000e4 = (int *)0x401322;
      func_0x12a67483();
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    puVar14 = (uint *)((uint)puVar14 | *in_stack_000000e0);
    if (-1 < (int)puVar14) {
      uVar15 = CONCAT31((int3)((uint)puVar14 >> 8),(char)puVar14 + *(char *)((int)piVar8 + -0x5f));
LAB_00401324:
      in_stack_000000e0 = (uint *)0x40132c;
      in_stack_000000e4 = (int *)uVar15;
      uVar24 = func_0xe8d93a16();
      bVar7 = (char)uVar24 + (char)((uint6)uVar24 >> 8) * -0x6c;
      if (!SBORROW4(*in_stack_000000cc,*piVar12)) {
        out((short)((uint6)uVar24 >> 0x20),CONCAT22((short)((uint6)uVar24 >> 0x10),(ushort)bVar7));
        LOCK();
        DAT_e8ecd295 = bVar7;
        *(char *)(iVar9 + -0x132d6e6e) = (char)iVar9;
        UNLOCK();
        in_stack_000000e0 = (uint *)0x40134a;
        func_0x498dba32();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar15 = (uint)puVar14 | *puVar14;
    if (0 < (int)uVar15) goto LAB_00401324;
    *(undefined4 *)(in_stack_0000011c + -0x649e9ea0) = in_stack_00000108;
    uVar18 = 0xfcd2;
    in_stack_00000120 = 0x4012da;
    in_stack_00000124 = in_CS;
    func_0x506562ed();
    cVar16 = (char)((uint)in_stack_000000d8 >> 8);
    cVar20 = cVar16 + *(char *)(in_stack_000000d0 + 0x61);
    bVar22 = SCARRY1(cVar16,*(char *)(in_stack_000000d0 + 0x61)) != SCARRY1(cVar20,'\0');
    iVar9 = CONCAT22((short)((uint)in_stack_000000d8 >> 0x10),
                     CONCAT11(cVar20,(char)in_stack_000000d8));
    bVar21 = cVar20 < '\0';
    uVar6 = in((short)in_stack_000000dc);
    piVar12 = (int *)CONCAT31((int3)((uint)in_stack_000000e4 >> 8),uVar6);
    piVar8 = in_stack_000000c8;
    puVar14 = in_stack_000000dc;
    in_CS = uVar18;
    if (in_stack_000000e0 != (uint *)0x0) {
      in((short)in_stack_000000dc);
      *(uint *)((int)in_stack_000000e0 + 0x5e) =
           *(uint *)((int)in_stack_000000e0 + 0x5e) | in_stack_000000d0;
      in_stack_000000e4 = (int *)CONCAT22(in_stack_000000e4._2_2_,uVar19);
      uVar6 = in((short)in_stack_000000f8);
      pcVar13 = (char *)CONCAT31((int3)((uint)in_stack_00000100 >> 8),uVar6);
      out((short)in_stack_000000f8,in_stack_000000e4);
      pbVar1 = (byte *)(pcVar13 + -0x76cdb813);
      bVar5 = ((byte)in_stack_000000fc & 0x1f) % 9;
      bVar7 = *pbVar1;
      uVar3 = (ushort)bVar7 << 9 - bVar5;
      *pbVar1 = bVar7 >> bVar5 | (byte)uVar3;
      cVar20 = (uVar3 & 0x100) != 0;
      in_stack_00000100 = CONCAT22(in_stack_00000100._2_2_,uVar18);
      in_stack_000000fc = 0x4012ff;
      uVar23 = func_0x41616160();
      cVar20 = (char)((ulonglong)uVar23 >> 0x20) + *pcVar13 + cVar20;
      puVar14 = (uint *)CONCAT31((int3)((ulonglong)uVar23 >> 0x28),cVar20);
      uVar4 = (int)uVar23;
      if (-1 < cVar20) {
        uVar6 = in((short)in_stack_000000fc);
        *(uint *)CONCAT31((int3)((uint)in_stack_000000f8 >> 8),
                          (byte)in_stack_000000f8 & *(byte *)(in_stack_00000100 + 0x31e8ecd2)) =
             CONCAT31((int3)((uint)in_stack_00000104 >> 8),uVar6);
        in_stack_00000104 = CONCAT22(in_stack_00000104._2_2_,uStack000000e8);
        *(uint *)(in_stack_0000012c + 0x5c) =
             *(uint *)(in_stack_0000012c + 0x5c) >> (bStack00000140 & 0x1f);
        puVar14 = in_stack_00000138;
      }
      goto LAB_0040131c;
    }
  } while( true );
}


