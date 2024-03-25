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
// WARNING: Instruction at (ram,0x00401381) overlaps instruction at (ram,0x0040137f)
// 
// WARNING (jumptable): Unable to track spacebase fully for stack
// WARNING: Unable to track spacebase fully for stack
// WARNING: This function may have set the stack pointer
// WARNING: Removing unreachable block (ram,0x0040138c)
// WARNING: Removing unreachable block (ram,0x004013a7)
// WARNING: Removing unreachable block (ram,0x0040132a)
// WARNING: Removing unreachable block (ram,0x00401315)
// WARNING: Removing unreachable block (ram,0x00401309)
// WARNING: Removing unreachable block (ram,0x00401317)
// WARNING: Removing unreachable block (ram,0x00401326)
// WARNING: Removing unreachable block (ram,0x0040133f)
// WARNING: Removing unreachable block (ram,0x0040137f)
// WARNING: Removing unreachable block (ram,0x00401383)
// WARNING: Removing unreachable block (ram,0x00401382)
// WARNING: Removing unreachable block (ram,0x0040137b)
// WARNING: Removing unreachable block (ram,0x004013f1)
// WARNING: Removing unreachable block (ram,0x00401380)
// WARNING: Removing unreachable block (ram,0x004013f5)
// WARNING: Removing unreachable block (ram,0x0040138a)
// WARNING: Removing unreachable block (ram,0x004012cf)
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * entry(void)

{
  char *pcVar1;
  int *piVar2;
  byte *pbVar3;
  ushort *puVar4;
  int iVar5;
  unkbyte10 Var6;
  undefined2 uVar7;
  undefined4 uVar8;
  uint uVar9;
  ushort uVar10;
  float10 fVar11;
  float10 fVar12;
  float10 fVar13;
  float10 fVar14;
  float10 fVar15;
  byte bVar16;
  undefined uVar17;
  byte bVar18;
  char cVar19;
  undefined *puVar20;
  undefined3 uVar28;
  uint uVar21;
  uint uVar22;
  undefined4 uVar23;
  undefined *puVar24;
  int iVar25;
  int3 iVar29;
  undefined4 *puVar26;
  uint **ppuVar27;
  int *extraout_ECX;
  int *piVar30;
  char *extraout_ECX_00;
  uint extraout_ECX_01;
  code *extraout_ECX_02;
  code *extraout_ECX_03;
  code *pcVar31;
  uint *extraout_ECX_04;
  uint *puVar32;
  undefined2 uVar33;
  uint uVar34;
  uint **ppuVar35;
  undefined4 extraout_EDX;
  uint uVar36;
  uint extraout_EDX_00;
  undefined4 *puVar37;
  uint **ppuVar38;
  byte *pbVar39;
  short sVar40;
  undefined4 *puVar41;
  byte **ppbVar42;
  byte **ppbVar43;
  int *piVar44;
  uint **ppuVar45;
  uint **ppuVar46;
  uint **ppuVar47;
  undefined *puVar48;
  undefined4 *puVar49;
  undefined *puVar50;
  undefined *puVar51;
  undefined4 *puVar52;
  undefined4 *puVar53;
  uint *puVar54;
  uint **ppuVar56;
  uint *puVar57;
  uint *puVar58;
  uint *puVar59;
  uint *puVar60;
  undefined *puVar61;
  undefined *puVar62;
  undefined4 *puVar63;
  undefined4 *puVar64;
  uint *puVar65;
  undefined2 uVar66;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  byte bVar67;
  bool bVar68;
  byte in_AF;
  bool bVar69;
  byte in_TF;
  byte in_IF;
  bool bVar70;
  char cVar71;
  bool bVar72;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  float10 fVar73;
  float10 extraout_ST0;
  unkbyte10 extraout_ST0_00;
  float10 extraout_ST0_01;
  float10 fVar74;
  float10 extraout_ST1;
  float10 fVar75;
  float10 extraout_ST1_00;
  float10 in_ST2;
  float10 in_ST3;
  float10 in_ST4;
  float10 in_ST5;
  float10 in_ST6;
  float10 in_ST7;
  longlong lVar76;
  undefined8 uVar77;
  undefined8 uVar78;
  int *piVar55;
  
  sVar40 = (short)&stack0xffffffe0 + -4;
  piVar55 = (int *)CONCAT22((short)((uint)&stack0xffffffe0 >> 0x10),sVar40);
  puVar64 = (undefined4 *)segment(in_SS,sVar40);
  *puVar64 = 0x43000c;
  ppuVar27 = (uint **)(*piVar55 + 0x5a);
  do {
    puVar32 = *ppuVar27;
    puVar59 = ppuVar27[1];
    puVar65 = ppuVar27[2];
    do {
      *puVar32 = *puVar32 ^ (uint)puVar65;
      puVar32 = puVar32 + 1;
    } while ((int)puVar32 < (int)puVar59);
    ppuVar27 = ppuVar27 + 3;
    bVar72 = false;
    bVar69 = (int)*ppuVar27 < 0;
  } while (*ppuVar27 != (uint *)0x0);
  puVar65 = (uint *)piVar55[1];
  ppuVar56 = (uint **)piVar55[3];
  pbVar39 = (byte *)piVar55[5];
  ppuVar38 = (uint **)piVar55[6];
  puVar32 = (uint *)piVar55[7];
  ppuVar27 = (uint **)piVar55[8];
  piVar44 = piVar55 + 9;
  puVar59 = (uint *)piVar55[2];
  do {
    if (bVar72 == bVar69) {
LAB_004011de:
      *(uint **)((int)piVar44 + -4) = puVar65;
code_r0x004011df:
      pcVar31 = (code *)swi(3);
      puVar20 = (undefined *)(*pcVar31)();
      return puVar20;
    }
    ppbVar43 = (byte **)*piVar44;
    if (bVar72 == bVar69) {
      pbVar3 = pbVar39 + 0x1ed20514;
      *pbVar3 = *pbVar3 | (byte)((uint)ppuVar27 >> 8);
      if ((char)*pbVar3 < '\0') {
        ppuVar35 = (uint **)*ppbVar43;
        piVar30 = (int *)((int)ppuVar27 + 0x5568e487);
        bVar72 = (uint **)*piVar30 < ppuVar38;
        *piVar30 = *piVar30 - (int)ppuVar38;
        goto code_r0x004012a2;
      }
      pbVar39 = (byte *)CONCAT22((short)((uint)pbVar39 >> 0x10),
                                 CONCAT11((byte)((uint)pbVar39 >> 8) ^ *(byte *)ppuVar27,
                                          (char)pbVar39));
      bVar18 = (byte)ppuVar27;
      bVar72 = bVar18 < 0x62;
      ppuVar46 = *(uint ***)((int)ppbVar43 + -1);
      if ('a' < (char)bVar18) {
        puVar32 = (uint *)((int)puVar32 + -1);
        if (puVar32 != (uint *)0x0 && bVar18 == 0x62) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        uVar17 = in((short)ppuVar38);
        *(undefined *)puVar65 = uVar17;
        ppbVar43 = (byte **)ppuVar46;
        puVar65 = (uint *)((int)puVar65 + 1);
        goto code_r0x00401239;
      }
      ppuVar35 = ppuVar38;
      if ('a' < (char)bVar18) goto code_r0x00401252;
LAB_004012c5:
      bVar18 = *(byte *)ppuVar27;
      bVar67 = (byte)puVar32;
      bVar16 = bVar67 - *(char *)ppuVar27;
      puVar32 = (uint *)CONCAT31((int3)((uint)puVar32 >> 8),bVar16 - bVar72);
      iVar25 = (int)*ppuVar46;
      *(undefined2 *)(iVar25 + -4) = in_SS;
      uVar36 = (uint)(bVar67 < bVar18 || bVar16 < bVar72);
      uVar21 = (int)*ppuVar38 - (int)puVar32;
      bVar72 = *ppuVar38 < puVar32 || uVar21 < uVar36;
      bVar70 = SBORROW4((int)*ppuVar38,(int)puVar32) != SBORROW4(uVar21,uVar36);
      *ppuVar38 = (uint *)(uVar21 - uVar36);
      bVar69 = (int)*ppuVar38 < 0;
      puVar58 = *ppuVar38;
      ppuVar35 = *(uint ***)(iVar25 + -4);
      if (bVar70 != bVar69) {
        ppuVar46 = ppuVar35 + -1;
        ppuVar35[-1] = (uint *)((uint)(in_NT & 1) * 0x4000 | (uint)bVar70 * 0x800 |
                                (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 |
                                (uint)bVar69 * 0x80 | (uint)(puVar58 == (uint *)0x0) * 0x40 |
                                (uint)(in_AF & 1) * 0x10 |
                                (uint)((POPCOUNT((uint)*ppuVar38 & 0xff) & 1U) == 0) * 4 |
                                (uint)bVar72 | (uint)(in_ID & 1) * 0x200000 |
                                (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
                               (uint)(in_AC & 1) * 0x40000);
        if (puVar58 != (uint *)0x0) {
          pcVar31 = (code *)swi(1);
          puVar20 = (undefined *)(*pcVar31)();
          return puVar20;
        }
        bVar72 = false;
LAB_004012f5:
        ppuVar35 = (uint **)((int)ppuVar46 + -4);
        *(uint ***)((int)ppuVar46 + -4) = ppuVar56;
        goto code_r0x004012f6;
      }
      puVar32 = (uint *)((int)puVar32 + -1);
      if (puVar32 == (uint *)0x0) {
        *ppuVar38 = *ppuVar35;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (bVar70 == bVar69) goto code_r0x004012f6;
      ppuVar45 = ppuVar35 + -1;
      ppuVar35 = ppuVar35 + -1;
      *ppuVar45 = (uint *)0x945c6355;
      bVar16 = (byte)ppuVar27;
      bVar18 = bVar16 + 0x5c;
      bVar67 = 0xa3 < bVar16 || CARRY1(bVar18,bVar72);
      bVar69 = SCARRY1(bVar16,'\\') != SCARRY1(bVar18,bVar72);
      uVar28 = (undefined3)((uint)ppuVar27 >> 8);
      cVar19 = bVar18 + bVar72;
code_r0x004012a8:
      if (bVar69 == cVar19 < '\0') {
        return (undefined *)(CONCAT31(uVar28,cVar19) ^ 0xb);
      }
      bVar72 = (bool)bVar67;
      if (cVar19 != '\0') {
code_r0x004012f6:
        puVar32 = puVar32 + (int)puVar59 * 2 + -0x19;
        *(ushort *)puVar32 =
             *(short *)puVar32 + (ushort)bVar72 * (((ushort)pbVar39 & 3) - (*(ushort *)puVar32 & 3))
        ;
        *(undefined2 *)(ppuVar35 + -1) = in_CS;
        ppuVar47 = ppuVar35 + -2;
        ppuVar35[-2] = (uint *)0x401301;
        func_0x32e682ef();
        *(undefined4 *)((int)ppuVar47 + -4) = extraout_EDX;
        return (undefined *)((int)ppuVar47 + -4);
      }
      *(undefined2 *)((int)ppuVar35 + -4) = in_CS;
      uVar66 = 0x2203;
      puVar48 = (undefined *)((int)ppuVar35 + -8);
      *(undefined4 *)((int)ppuVar35 + -8) = 0x401359;
      uVar77 = func_0xa590846d();
      iVar25 = (int)((ulonglong)uVar77 >> 0x20);
      uVar36 = iVar25 + 1;
      puVar32 = puVar65 + 1;
      *puVar65 = (uint)uVar77;
      uVar21 = CONCAT22((short)((ulonglong)uVar77 >> 0x10),
                        CONCAT11(((int)uVar36 < 0) << 7 | (uVar36 == 0) << 6 | in_AF << 4 |
                                 ((POPCOUNT(uVar36 & 0xff) & 1U) == 0) << 2 | 2 | bVar67,
                                 (char)uVar77));
      piVar30 = (int *)(uVar21 + 0x4f2c0d87);
      *piVar30 = *piVar30 - uVar36;
      uVar21 = uVar21 ^ 0x577db8e3;
      uVar22 = CONCAT22((short)(uVar21 >> 0x10),
                        CONCAT11((char)((short)uVar21 % (short)*extraout_ECX_00),
                                 (char)((short)uVar21 / (short)*extraout_ECX_00)));
      if ((int)uVar21 < 0) {
        *(int *)(extraout_ECX_00 + (int)puVar59 * 8 + -0x14) =
             *(int *)(extraout_ECX_00 + (int)puVar59 * 8 + -0x14) - (int)puVar59;
        uVar22 = uVar22 & 0x9aeb197c;
        if (uVar22 == 0) {
          *(undefined2 *)(puVar48 + -4) = in_SS;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      else {
        out((short)uVar36,uVar22);
        piVar30 = (int *)((int)extraout_ECX_00 * 3 + 0x498019ef);
        *piVar30 = *piVar30 - uVar22;
        puVar48[iVar25 + 0x27] = puVar48[iVar25 + 0x27] | (byte)pbVar39;
        puVar32 = (uint *)((int)puVar65 + 3);
        puVar59 = (uint *)((int)puVar59 + -1);
        pbVar39 = (byte *)0xeb727d17;
      }
      *(undefined *)puVar32 = *(undefined *)puVar59;
      *(undefined *)((int)puVar59 + -1) = *(undefined *)((int)puVar59 + -1);
      *(uint ***)(puVar48 + -4) = ppuVar56;
      uVar23 = in((short)uVar36);
      *(undefined4 *)((int)puVar59 + -2) = uVar23;
      puVar20 = (undefined *)((int)puVar59 + -2);
      puVar62 = (undefined *)((int)puVar59 + -6);
      goto code_r0x0040140c;
    }
    ppuVar27 = (uint **)CONCAT31((int3)((uint)ppuVar27 >> 8),0x6c);
code_r0x00401239:
    ppuVar38 = (uint **)((int)ppuVar38 + -1);
    bVar70 = false;
    bVar18 = (byte)ppuVar27;
    ppuVar27 = (uint **)((uint)ppuVar27 ^ 0xb);
    bVar69 = (char)(bVar18 ^ 0xb) < '\0';
    do {
      if (bVar70 != bVar69) goto LAB_004011c9;
      bVar72 = false;
      ppuVar27 = (uint **)(((uint)ppuVar27 | 0xa5) & 0x15fd3a46);
      bVar70 = SCARRY4((int)puVar59,1);
      puVar58 = (uint *)((int)puVar59 + 1);
      bVar69 = (int)puVar58 < 0;
      ppuVar46 = (uint **)*ppbVar43;
      puVar57 = puVar58;
      puVar60 = puVar65;
      if (puVar58 != (uint *)0x0 && bVar70 == bVar69) goto LAB_0040120a;
      if ((int)puVar59 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      in_ST2 = *(float10 *)((int)puVar59 + 0x66);
      in_ST3 = *(float10 *)(puVar59 + 0x1c);
      in_ST4 = *(float10 *)((int)puVar59 + 0x7a);
      in_ST5 = *(float10 *)(puVar59 + 0x21);
      in_ST6 = *(float10 *)((int)puVar59 + 0x8e);
      in_ST7 = *(float10 *)(puVar59 + 0x26);
      ppuVar35 = ppuVar38;
      if ((int)puVar58 < 1) goto LAB_004012c5;
code_r0x00401252:
      while( true ) {
        bVar18 = ((byte)puVar32 & 0x1f) % 9;
        uVar10 = (ushort)*(byte *)puVar59 << 9 - bVar18;
        *(byte *)puVar59 = *(byte *)puVar59 >> bVar18 | (byte)uVar10;
        ppuVar38 = (uint **)((int)ppuVar35 + 1);
        uVar17 = in((short)ppuVar38);
        ppuVar27 = (uint **)CONCAT31((int3)((uint)ppuVar27 >> 8),uVar17);
        ppuVar35 = (uint **)((int)ppuVar35 + 0x6219074a);
        uVar36 = (uint)((uVar10 & 0x100) != 0);
        uVar21 = (int)*ppuVar35 - (int)puVar32;
        bVar72 = *ppuVar35 < puVar32 || uVar21 < uVar36;
        bVar70 = SBORROW4((int)*ppuVar35,(int)puVar32) != SBORROW4(uVar21,uVar36);
        *ppuVar35 = (uint *)(uVar21 - uVar36);
        bVar69 = (int)*ppuVar35 < 0;
        puVar58 = *ppuVar35;
        if (bVar70 == bVar69) break;
        *(uint ***)((int)ppuVar46 + -4) = ppuVar46;
        ppuVar35 = ppuVar38;
        ppuVar46 = (uint **)((int)ppuVar46 + -4);
      }
      ppbVar43 = (byte **)((int)ppuVar46 + -4);
      _DAT_1ed23149 = ppuVar27;
      *(uint **)((int)ppuVar46 + -4) = puVar65;
    } while (bVar69);
    pbVar39 = *(byte **)((int)ppuVar46 + -4);
    puVar57 = puVar59;
    puVar60 = puVar65;
    if (bVar70 == bVar69) {
      pcVar31 = (code *)swi(3);
      puVar20 = (undefined *)(*pcVar31)();
      return puVar20;
    }
LAB_0040120a:
    bVar18 = ((byte)puVar32 & 0x1f) % 9;
    uVar10 = CONCAT11(bVar72,*(undefined *)puVar57) >> bVar18 |
             CONCAT11(bVar72,*(undefined *)puVar57) << 9 - bVar18;
    *(char *)puVar57 = (char)uVar10;
    ppuVar35 = ppuRam197c7936;
    bVar72 = (uVar10 & 0x100) != 0;
    if (bVar70 != bVar69) {
      puVar59 = puVar57 + 1;
      out(*puVar57,(short)ppuVar38);
      if ((POPCOUNT((uint)puVar58 & 0xff) & 1U) == 0) goto LAB_004012f5;
      puVar32 = (uint *)CONCAT22((short)((uint)puVar32 >> 0x10),CONCAT11(0x90,(byte)puVar32));
      in_AF = 9 < ((byte)ppuVar27 & 0xf) | in_AF;
      bVar18 = (byte)ppuVar27 + in_AF * -6;
      bVar18 = 0x9f < bVar18 | bVar72 | in_AF * (bVar18 < 6);
      uVar36 = CONCAT31((int3)((uint)ppuVar27 >> 8),DAT_2778f12c);
      if (bVar70 != bVar69) {
        if (puVar32 != (uint *)0x1 && (uVar36 | (uint)pbVar39) != 0) {
          return (undefined *)ppuVar46;
        }
        puVar32 = (uint *)((int)puVar32 + -2);
        iVar25 = (int)*ppuVar46;
        pbVar39 = (byte *)0xef929cf5;
        ppuVar38 = (uint **)((uint)ppuVar38 & 0xffffebff);
        *(undefined2 *)(iVar25 + -4) = in_SS;
        bVar72 = *ppuVar56 < puVar32;
        *ppuVar56 = (uint *)((int)*ppuVar56 - (int)puVar32);
        iVar25 = *(int *)(iVar25 + -4);
        ppuVar46 = (uint **)(iVar25 + -4);
        *(undefined2 *)(iVar25 + -4) = in_SS;
        ppuVar27 = ppuVar56;
        ppuVar56 = ppuVar35;
        puVar65 = puVar60;
        goto LAB_004012c5;
      }
      puVar65 = puVar60 + 1;
      *puVar60 = uVar36;
      pbVar3 = (byte *)((int)ppuVar38 + 0x197c5c62);
      bVar67 = (byte)((uint)pbVar39 >> 8);
      bVar16 = *pbVar3 - bVar67;
      bVar72 = *pbVar3 < bVar67 || bVar16 < bVar18;
      *pbVar3 = bVar16 - bVar18;
      uVar17 = in(0x68);
      ppuVar27 = (uint **)CONCAT31((int3)((uint)_DAT_8790295c >> 8),uVar17);
      ppuVar35 = (uint **)((int *)ppuVar46 + -1);
      ((int *)ppuVar46)[-1] = (int)ppuVar56;
code_r0x004012a2:
      puVar4 = (ushort *)((int)ppuVar35 + (int)ppuVar38 * 4 + 0x66);
      *puVar4 = *puVar4 + (ushort)bVar72 * (((ushort)pbVar39 & 3) - (*puVar4 & 3));
      bVar16 = (byte)ppuVar27;
      bVar18 = bVar16 + 0x5c;
      bVar67 = 0xa3 < bVar16 || CARRY1(bVar18,bVar72);
      bVar69 = SCARRY1(bVar16,'\\') != SCARRY1(bVar18,bVar72);
      uVar28 = (undefined3)((uint)ppuVar27 >> 8);
      cVar19 = bVar18 + bVar72;
      goto code_r0x004012a8;
    }
    piVar44 = (int *)((longlong)*(int *)(pbVar39 + 0x5dda419c) * -0x489de684);
    bVar72 = (longlong)(int)piVar44 != (longlong)*(int *)(pbVar39 + 0x5dda419c) * -0x489de684;
    puVar65 = puVar60 + 1;
    *puVar60 = (uint)ppuVar27;
    puVar59 = puVar57;
  } while( true );
LAB_004011c9:
  *(undefined2 *)((int)ppbVar43 + -4) = in_CS;
  in_CS = 0xa332;
  puVar20 = (undefined *)((int)ppbVar43 + -8);
  *(undefined4 *)((int)ppbVar43 + -8) = 0x4011d0;
  lVar76 = func_0x3308a39a();
  piVar30 = extraout_ECX;
  fVar74 = extraout_ST0;
  fVar75 = extraout_ST1;
  uVar36 = uRama3323308;
  do {
    uRama3323308 = uVar36;
    uVar21 = (uint)((ulonglong)lVar76 >> 0x20);
    uVar36 = (uint)lVar76;
    piVar30 = (int *)((int)piVar30 + -1);
    bVar69 = lVar76 < 0;
    bVar72 = uVar21 == 0;
    ppbVar43 = (byte **)(puVar20 + -4);
    piVar44 = (int *)(puVar20 + -4);
    *(undefined2 *)(puVar20 + -4) = in_DS;
    while( true ) {
      if (bVar69) {
        pbVar39 = (byte *)CONCAT22((short)((uint)pbVar39 >> 0x10),CONCAT11(0x5b,(char)pbVar39));
        goto LAB_004011c9;
      }
      if ((bVar69) || (bVar69)) {
                    // WARNING: Could not recover jumptable at 0x004011f8. Too many branches
                    // WARNING: Treating indirect jump as call
        puVar20 = (undefined *)(**(code **)((int)puVar59 + (int)piVar30 * 2))();
        return puVar20;
      }
      piVar30 = (int *)((int)piVar30 + -1);
      fVar73 = fVar74;
      fVar11 = fVar75;
      fVar12 = in_ST2;
      fVar13 = in_ST3;
      fVar14 = in_ST4;
      fVar15 = in_ST5;
      if (piVar30 != (int *)0x0 && bVar72) break;
      if (!bVar72) goto LAB_004011de;
      if (bVar69) goto code_r0x004011df;
      *pbVar39 = *pbVar39 | (byte)((ulonglong)lVar76 >> 0x28);
      bVar18 = (byte)(uVar36 >> 8) ^ pbVar39[0x1ed20949];
      uVar36 = CONCAT22((short)(uVar36 >> 0x10),CONCAT11(bVar18,(char)uVar36));
      bVar69 = (char)bVar18 < '\0';
      bVar72 = bVar18 == 0;
    }
    while( true ) {
      in_ST5 = in_ST6;
      in_ST4 = fVar15;
      in_ST3 = fVar14;
      in_ST2 = fVar13;
      fVar75 = fVar12;
      fVar74 = fVar11;
      puVar64 = *(undefined4 **)(undefined4 *)(uVar36 - 1);
      puVar57 = (uint *)((uint)(undefined4 *)(uVar36 - 1) & 0xffffff9d);
      puVar58 = puVar64 + 1;
      uVar23 = in((short)uVar21);
      *puVar64 = uVar23;
      *(uint *)(uVar21 - 0x76) = *(uint *)(uVar21 - 0x76) | 0xffffffc9;
      uVar34 = uVar21 & 0xffff9dff;
      *(longlong *)((int)puVar59 + -0x44a3f7eb) = (longlong)ROUND(fVar73);
      bVar18 = in((short)uVar34);
      uVar36 = CONCAT31((int3)((uint)puVar59 >> 8),bVar18);
      puVar32 = (uint *)(piVar30 + 0x17);
      uVar22 = (uint)((byte)puVar59 < 0x72);
      ppuVar27 = (uint **)*puVar32;
      uVar21 = *puVar32;
      uVar9 = *puVar32 - (int)ppuVar56;
      *puVar32 = uVar9 - uVar22;
      in_ST6 = in_ST7;
      if ((SBORROW4(uVar21,(int)ppuVar56) != SBORROW4(uVar9,uVar22)) != (int)*puVar32 < 0) {
        puVar20 = (undefined *)(iRamf10913f2 + -4);
        *(undefined2 *)(iRamf10913f2 + -4) = in_SS;
        puVar32 = (uint *)(uVar34 + 0x62190065);
        uVar21 = (uint)(ppuVar27 < ppuVar56 || uVar9 < uVar22);
        bVar72 = CARRY4(*puVar32,(uint)piVar30) || CARRY4(*puVar32 + (int)piVar30,uVar21);
        *puVar32 = *puVar32 + (int)piVar30 + uVar21;
        *(longlong *)(uVar36 + 0x99c6b11) = (longlong)ROUND(fVar74);
        in_ST3 = in_ST4;
        in_ST4 = in_ST5;
        in_ST5 = in_ST7;
        goto code_r0x004011c1;
      }
      *(byte *)(puVar64 + -0x1a) = *(byte *)(puVar64 + -0x1a) | (byte)uVar34;
      uVar21 = uVar34 - 1;
      lVar76 = CONCAT44(uVar21,uVar36);
      _DAT_f10913ee = (undefined4 *)CONCAT22(DAT_f10913ee_2,in_DS);
      puVar37 = _DAT_f10913ee;
      if ((int)uVar34 < 1) {
        *(uint *)((int)puVar64 + -0x13) = *(uint *)((int)puVar64 + -0x13) & uVar36;
        puVar32 = (uint *)(uVar36 + 0x10);
        uVar36 = *puVar32;
        *puVar32 = *puVar32 + (int)puVar57;
        bVar16 = pbVar39[bVar18];
        DAT_56615428 = bVar18;
        *piVar30 = (int)puVar57 + (uint)CARRY4(uVar36,(uint)puVar57) + *piVar30;
        _DAT_d166ddff = CONCAT22((short)((uint)puVar59 >> 0x10),CONCAT11(0x56,bVar16));
        out(0x9d,bVar16);
        *(uint *)((int)puVar58 + (int)piVar30) =
             *(uint *)((int)puVar58 + (int)piVar30) | (uint)puVar57;
        pcVar31 = (code *)swi(1);
        puVar20 = (undefined *)(*pcVar31)();
        return puVar20;
      }
      puVar65 = (uint *)((int)puVar64 + 5);
      puVar59 = (uint *)((int)puVar57 + 1);
      bVar16 = *(byte *)puVar58;
      bVar18 = *(byte *)puVar57;
      cVar19 = bVar18 - bVar16;
      puVar41 = _DAT_f10913ee + -1;
      _DAT_f10913ee[-1] = _DAT_f10913ee;
      if (cVar19 == '\0') break;
      piVar30 = (int *)((uint)piVar30 | (uint)puVar59);
      fVar73 = fVar74;
      fVar11 = fVar75;
      fVar12 = in_ST2;
      fVar13 = in_ST3;
      fVar14 = in_ST4;
      fVar15 = in_ST5;
    }
    in_SS = *(undefined2 *)puVar41;
    if ((char)bVar16 <= (char)bVar18) {
      ppbVar42 = (byte **)(puVar37 + -1);
      puVar37[-1] = (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW1(bVar18,bVar16) * 0x800 |
                    (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 |
                    (uint)(cVar19 < '\0') * 0x80 | (uint)(cVar19 == '\0') * 0x40 |
                    (uint)(in_AF & 1) * 0x10 | (uint)((POPCOUNT(cVar19) & 1U) == 0) * 4 |
                    (uint)(bVar18 < bVar16) | (uint)(in_ID & 1) * 0x200000 |
                    (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
                    (uint)(in_AC & 1) * 0x40000;
      bVar72 = false;
      *puVar59 = *puVar59 | (uint)pbVar39;
      in_ST2 = in_ST3;
      in_ST3 = in_ST4;
      in_ST4 = in_ST5;
      goto code_r0x004011c2;
    }
    piVar2 = (int *)((int)ppuVar56 + 0x20a96c59);
    uVar22 = (uint)(bVar18 < bVar16);
    puVar64 = (undefined4 *)*piVar2;
    iVar25 = *piVar2;
    *piVar2 = (iVar25 - (int)puVar37) - uVar22;
    puVar20 = (undefined *)*puVar37;
  } while (*piVar2 == 0);
  piVar30 = (int *)(uVar34 - 0x22);
  uVar36 = (uint)(puVar64 < puVar37 || (uint)(iVar25 - (int)puVar37) < uVar22);
  bVar72 = (undefined *)*piVar30 < puVar20 || (uint)(*piVar30 - (int)puVar20) < uVar36;
  *piVar30 = (*piVar30 - (int)puVar20) - uVar36;
  uVar34 = uVar21;
  puVar57 = puVar59;
  puVar58 = puVar65;
code_r0x004011c1:
  ppbVar42 = (byte **)(puVar20 + -4);
  *(undefined2 *)(puVar20 + -4) = in_DS;
  uVar21 = uVar34;
  puVar59 = puVar57;
  puVar65 = puVar58;
  in_ST2 = in_ST3;
  in_ST3 = in_ST4;
  in_ST4 = in_ST5;
code_r0x004011c2:
  *(int *)(uVar21 - 0x49) = (*(int *)(uVar21 - 0x49) - (int)ppbVar42) - (uint)bVar72;
  pbVar39 = *ppbVar42;
  ppbVar43 = ppbVar42 + 1;
  in_ST5 = in_ST7;
  goto LAB_004011c9;
code_r0x0040140c:
  puVar61 = puVar62;
  puVar24 = puVar20;
  ppbVar43 = (byte **)((int)ppuVar56 + 0x17e66829);
  pbVar3 = *ppbVar43;
  *ppbVar43 = *ppbVar43 + (int)pbVar39;
  piVar30 = (int *)((int)ppuVar56 + 0x17e66c29);
  iVar25 = *piVar30;
  iVar5 = *piVar30;
  uRam09a351ee = in_SS;
  *piVar30 = (iVar5 - (int)pbVar39) - (uint)CARRY4((uint)pbVar3,(uint)pbVar39);
  cVar19 = cRam5c1b0294;
  uVar23 = CONCAT31((int3)(uVar22 + 1 >> 8),cRam5c1b0294);
  if ((SBORROW4(iVar25,(int)pbVar39) !=
      SBORROW4(iVar5 - (int)pbVar39,(uint)CARRY4((uint)pbVar3,(uint)pbVar39))) != *piVar30 < 0) {
    uRam09a351ea = in_SS;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *puVar61 = *puVar24;
  uVar33 = (undefined2)uVar36;
  uVar8 = in(uVar33);
  uRama58ae509 = uVar23;
  *(undefined4 *)(puVar61 + -1) = uVar8;
  uVar7 = in(uVar33);
  *(undefined2 *)(puVar61 + -5) = uVar7;
  *(byte **)(uVar36 - 3) = pbVar39;
  out(uVar33,cVar19 + '\x19');
  uRambc6d69f2 = CONCAT22(uRambc6d69f2._2_2_,uVar66);
  uVar66 = 0xd735;
  puVar49 = (undefined4 *)0xbc6d69ee;
  uRambc6d69ee = 0x401450;
  uVar77 = func_0x4f2f7c8e();
  uRamd28419a5 = uRamd28419a5 | (uint)((ulonglong)uVar77 >> 0x20);
  uVar23 = *puVar49;
  bVar18 = (byte)uVar23;
  in_AF = 9 < (bVar18 & 0xf) | in_AF;
  bVar18 = bVar18 + in_AF * '\x06';
  puVar62 = puVar61 + -8;
  puVar20 = puVar24 + -2;
  puVar61[-7] = puVar24[-1];
  iVar25 = puVar49[1];
  uVar36 = *(uint *)((int)ppuVar56 +
                    CONCAT31((int3)((uint)uVar23 >> 8),
                             bVar18 + (0x90 < (bVar18 & 0xf0) |
                                      (byte)((ulonglong)uVar77 >> 0x28) < (byte)((uint)pbVar39 >> 8)
                                      | in_AF * (0xf9 < bVar18)) * '`') * 4 + 0x5cf5b427);
  cVar19 = uVar36 < extraout_ECX_01;
  cVar71 = SBORROW4(uVar36,extraout_ECX_01);
  uVar17 = (int)(uVar36 - extraout_ECX_01) < 0;
  *(undefined2 *)(iVar25 + -4) = uVar66;
  uVar66 = 0x7c1e;
  puVar50 = (undefined *)(iVar25 + -8);
  *(undefined4 *)(iVar25 + -8) = 0x401471;
  func_0xd66d79a3();
  *(undefined2 *)(puVar50 + -4) = uVar66;
  uVar66 = 0xa007;
  puVar51 = puVar50 + -8;
  *(undefined4 *)(puVar50 + -8) = 0x401478;
  uVar78 = func_0x9a7ca807();
  uVar36 = (uint)((ulonglong)uVar78 >> 0x20);
  if (cVar71 == uVar17) goto code_r0x0040147a;
  if (!(bool)uVar17) {
    Var6 = to_bcd(extraout_ST0_00);
    *(unkbyte10 *)(puVar24 + 0x1840dc20) = Var6;
    pcVar31 = extraout_ECX_02;
    in_ST3 = in_ST4;
    in_ST4 = in_ST5;
    in_ST5 = in_ST6;
    in_ST6 = in_ST7;
    goto code_r0x0040149e;
  }
  uVar22 = CONCAT31((int3)((ulonglong)uVar78 >> 8),-cVar19);
  *(undefined2 *)(puVar51 + -4) = in_DS;
  ppuVar56 = (uint **)CONCAT22((short)((ulonglong)uVar77 >> 0x10),
                               (ushort)(byte)((char)uVar77 + (char)((ulonglong)uVar77 >> 8) * '9'));
  if (cVar71 == uVar17) {
    *(undefined2 *)(puVar51 + -4) = uVar66;
    uVar66 = 0x6d13;
    puVar52 = (undefined4 *)(puVar51 + -8);
    puVar51 = puVar51 + -8;
    *puVar52 = 0x40147c;
    func_0xf27ca007();
    puVar62 = puVar61 + -0xc;
    puVar20 = puVar24 + -6;
code_r0x0040147a:
    iVar25 = iRam197c4e11;
    *(undefined2 *)(puVar51 + -4) = uVar66;
    puVar53 = (undefined4 *)(puVar51 + -8);
    puVar51 = puVar51 + -8;
    *puVar53 = 0x401491;
    func_0xd66d79a3();
    *(char *)(iVar25 + 0x279238b7) = *(char *)(iVar25 + 0x279238b7) - (char)pbVar39;
    pcVar31 = extraout_ECX_03;
    uVar36 = extraout_EDX_00;
code_r0x0040149e:
    *(undefined2 *)(puVar51 + -4) = in_SS;
    *(byte *)(uVar36 + 0xeb5a7d29) = *(byte *)(uVar36 + 0xeb5a7d29) & (byte)(uVar36 >> 8);
    puVar20 = puVar20 + -4;
    puVar54 = (uint *)(puVar51 + -8);
    *(undefined4 *)(puVar51 + -8) = 0x4014ae;
    fVar75 = in_ST7;
    uVar77 = (*pcVar31)();
    bVar18 = ((char)uVar77 + '\x04') - ((*puVar54 & 1) != 0);
    uVar21 = CONCAT31((int3)((ulonglong)uVar77 >> 8),bVar18) & 0xe0095c63;
    uVar36 = puVar54[1];
    puVar24 = (undefined *)
              (CONCAT22((short)(uVar21 >> 0x10),
                        CONCAT11(((int)uVar21 < 0) << 7 | (uVar21 == 0) << 6 |
                                 ((*puVar54 & 0x10) != 0) << 4 |
                                 ((POPCOUNT(bVar18 & 99) & 1U) == 0) << 2,(char)uVar21)) | 0x200);
    *extraout_ECX_04 = *extraout_ECX_04 | (uint)extraout_ECX_04;
    uVar21 = puVar54[2];
    bVar69 = (uVar21 & 0x400) != 0;
    *(uint *)(puVar24 + 0x454c2792) =
         (*(int *)(puVar24 + 0x454c2792) - (int)extraout_ECX_04) - (uint)((uVar21 & 1) != 0);
    puVar32 = (uint *)puVar54[3];
    *(int *)((int)extraout_ECX_04 + -0x6e) = *(int *)((int)extraout_ECX_04 + -0x6e) - (int)puVar62;
    bVar18 = bRam4bda5297;
    bVar72 = 9 < ((byte)puVar20 & 0xf) || (uVar21 & 0x10) != 0;
    uVar36 = uVar36 | *extraout_ECX_04;
    puVar32[-1] = (uint)((uVar21 & 0x4000) != 0) * 0x4000 | (uint)bVar69 * 0x400 |
                  (uint)((uVar21 & 0x200) != 0) * 0x200 | (uint)((uVar21 & 0x100) != 0) * 0x100 |
                  (uint)((int)uVar36 < 0) * 0x80 | (uint)(uVar36 == 0) * 0x40 | (uint)bVar72 * 0x10
                  | (uint)((POPCOUNT(uVar36 & 0xff) & 1U) == 0) * 4 |
                  (uint)((uVar21 & 0x200000) != 0) * 0x200000 |
                  (uint)((uVar21 & 0x40000) != 0) * 0x40000;
    bVar72 = 9 < (bVar18 & 0xf) || bVar72;
    bVar18 = bVar18 + bVar72 * '\x06';
    *puVar62 = *puVar24;
    iVar25 = CONCAT31((int3)((uint)puVar20 >> 8),
                      bVar18 + (0x90 < (bVar18 & 0xf0) | bVar72 * (0xf9 < bVar18)) * '`') + 1;
    pcVar1 = (char *)((int)((ulonglong)uVar77 >> 0x20) + 0x29);
    *pcVar1 = *pcVar1 - (char)((uint)iVar25 >> 8);
    puVar63 = (undefined4 *)((int)(puVar62 + (uint)bVar69 * -2 + 1) + ((uint)bVar69 * -2 + 1) * 4);
    *(undefined4 *)(puVar62 + (uint)bVar69 * -2 + 1) =
         *(undefined4 *)(puVar24 + (uint)bVar69 * -2 + 1);
    uVar17 = uRamd56a5cf7;
    cVar71 = (char)((ulonglong)uVar77 >> 0x28);
    cVar19 = cVar71 << 1;
    bVar72 = 9 < ((byte)iVar25 & 0xf) || bVar72;
    iVar29 = (int3)((uint)iVar25 >> 8);
    puVar64 = (undefined4 *)CONCAT31(iVar29,uRamd56a5cf7);
    puVar37 = (undefined4 *)((int)iVar29 >> 0x17);
    puVar62 = (undefined *)puVar32[-1];
    uVar21 = *puVar32;
    puVar65 = puVar32 + 1;
    puVar59 = extraout_ECX_04;
    puVar26 = puVar63;
    fVar74 = extraout_ST0_01;
    if ((cVar71 < '\0' != cVar19 < '\0') == cVar19 < '\0') {
      do {
        puVar63 = puVar26 + (uint)bVar69 * -2 + 1;
        uVar23 = in((short)(char)((uint)iVar25 >> 0x18) >> 7);
        *puVar26 = uVar23;
        fVar74 = fVar74 * (float10)*(short *)CONCAT31((int3)(uVar36 >> 8),
                                                      (byte)uVar36 & (byte)((uint)puVar20 >> 8));
        out(0x9d,uVar17);
        puVar26 = puVar63;
      } while ((int)uVar21 < (int)(puVar32 + 1));
      puRam5c9de6c4 = puVar64;
      *puVar32 = 0xebe139d7;
      uVar21 = uVar21 - 1;
      bVar72 = false;
      puVar65 = puVar32;
    }
    while( true ) {
      *(uint *)(puVar62 + (int)puVar64 * 2 + -0x254af8c4) =
           *(uint *)(puVar62 + (int)puVar64 * 2 + -0x254af8c4) | (uint)puVar64;
      iVar25 = iRam197d5c66;
      bVar18 = 9 < ((byte)puVar64 & 0xf) | bVar72;
      *(int *)((int)puVar37 + 0xf) = (*(int *)((int)puVar37 + 0xf) - (int)puVar65) - (uint)bVar18;
      uVar22 = CONCAT31((int3)((uint)puVar59 >> 8),(char)puVar59 - puVar62[-0x17]);
      *(int *)(iVar25 + -0x6e) = *(int *)(iVar25 + -0x6e) - (int)puVar62;
      bVar72 = (bool)(9 < ((byte)iVar25 & 0xf) | bVar18);
      uVar36 = CONCAT31((int3)((uint)iVar25 >> 8),(byte)iVar25 + bVar72 * -6) & 0xffffff0f;
      uVar17 = (undefined)uVar36;
      puVar26 = (undefined4 *)
                CONCAT22((short)(uVar36 >> 0x10),CONCAT11((char)((uint)iVar25 >> 8) - bVar72,uVar17)
                        );
      out(0x78,uVar17);
      cVar19 = *(char *)(uVar21 + 0x42);
      if (uVar22 != 0) break;
      puVar59 = (uint *)0x0;
      puVar64 = puVar37;
      puVar37 = puVar26;
      puVar65 = (uint *)((int)puVar65 + -1);
    }
    uVar36 = (uint)puVar37 & 0xffff9cff;
    puVar32 = (uint *)(puVar62 + uVar36);
    bVar70 = *puVar32 < 0xffffffe8;
    puRam5c624757 = puVar26;
    *puVar32 = *puVar32 + 0x18;
    fVar73 = extraout_ST1_00;
    do {
      bVar68 = uVar22 < uVar21;
      uVar9 = uVar22 - uVar21;
      uVar22 = uVar9 - bVar70;
      piVar30 = (int *)((int)puVar26 + uVar36 * 4 + -0x5d);
      *piVar30 = (*piVar30 - (int)puVar62) - (uint)(bVar68 || uVar9 < bVar70);
      Var6 = to_bcd(fVar74);
      *(unkbyte10 *)(puVar62 + 0x1840dc22) = Var6;
      puVar64 = (undefined4 *)((int)puVar63 + (uint)bVar69 * -2 + 1);
      puVar20 = puVar62 + (uint)bVar69 * -2 + 1;
      *(undefined *)puVar63 = *puVar62;
      bVar16 = (byte)(uVar36 >> 8);
      bVar70 = bVar16 < *(byte *)(uVar21 - 0x21);
      bVar18 = *(byte *)(uVar21 - 0x21);
      uVar36 = CONCAT22((short)(uVar36 >> 0x10),CONCAT11(bVar16 - bVar18,(char)uVar36));
      out(0x5d,puVar26);
      puVar62 = puVar20;
      puVar63 = puVar64;
      fVar74 = fVar73;
      fVar73 = in_ST3;
      in_ST3 = in_ST4;
      in_ST4 = in_ST5;
      in_ST5 = in_ST6;
      in_ST6 = in_ST7;
      in_ST7 = fVar75;
    } while ((char)bVar16 < (char)bVar18);
    iVar25 = *(int *)((int)puVar65 + 3);
    *puVar26 = puVar64;
    *(undefined *)puVar64 = *puVar20;
    *(uint *)(iVar25 + -4) =
         uVar21 | CONCAT22(0x82a3,CONCAT11(cVar19 + -0x62 + bVar72,0x9c)) - uVar21;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  goto code_r0x0040140c;
}


