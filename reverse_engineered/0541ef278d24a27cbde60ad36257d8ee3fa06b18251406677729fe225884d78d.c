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
// WARNING: Instruction at (ram,0x004012b1) overlaps instruction at (ram,0x004012b0)
// 
// WARNING (jumptable): Unable to track spacebase fully for stack
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x004013f4)
// WARNING: Removing unreachable block (ram,0x00401470)
// WARNING: Removing unreachable block (ram,0x00401401)
// WARNING: Removing unreachable block (ram,0x00401419)
// WARNING: Removing unreachable block (ram,0x004013bc)
// WARNING: Removing unreachable block (ram,0x00401421)
// WARNING: Removing unreachable block (ram,0x00401425)
// WARNING: Removing unreachable block (ram,0x0040142d)
// WARNING: Removing unreachable block (ram,0x00401427)
// WARNING: Removing unreachable block (ram,0x00401433)
// WARNING: Removing unreachable block (ram,0x0040144e)
// WARNING: Removing unreachable block (ram,0x0040148c)
// WARNING: Removing unreachable block (ram,0x004013cb)
// WARNING: Removing unreachable block (ram,0x0040144b)
// WARNING: Removing unreachable block (ram,0x004014eb)
// WARNING: Removing unreachable block (ram,0x004014ed)
// WARNING: Removing unreachable block (ram,0x0040147a)
// WARNING: Removing unreachable block (ram,0x0040147b)
// WARNING: Removing unreachable block (ram,0x00401493)
// WARNING: Removing unreachable block (ram,0x0040148b)
// WARNING: Removing unreachable block (ram,0x00401494)
// WARNING: Removing unreachable block (ram,0x00401497)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __fastcall
FUN_00401219(undefined4 param_1,undefined2 param_2,undefined4 param_3,undefined4 param_4,
            char *param_5,undefined4 *param_6)

{
  byte *pbVar1;
  ushort *puVar2;
  uint *puVar3;
  int *piVar4;
  char *pcVar5;
  undefined2 *puVar6;
  code *pcVar7;
  undefined6 uVar8;
  undefined uVar9;
  undefined in_AL;
  byte bVar12;
  byte bVar13;
  int iVar10;
  undefined4 *puVar11;
  uint *extraout_ECX;
  uint extraout_ECX_00;
  undefined2 uVar14;
  undefined2 uVar15;
  uint uVar16;
  uint uVar17;
  undefined6 *puVar18;
  undefined6 *unaff_EBX;
  short sVar19;
  int unaff_EBP;
  undefined4 *unaff_ESI;
  uint *puVar20;
  uint *unaff_EDI;
  undefined4 *puVar21;
  char **ppcVar22;
  char **ppcVar23;
  undefined2 in_SS;
  undefined2 in_FS;
  byte in_CF;
  bool bVar24;
  byte in_AF;
  bool bVar25;
  bool bVar26;
  char cVar27;
  byte bVar28;
  bool bVar29;
  bool bVar30;
  char cVar31;
  float10 extraout_ST0;
  ulonglong uVar32;
  undefined8 uVar33;
  uint uStack_24;
  uint *puStack_20;
  undefined4 *puStack_1c;
  undefined2 uStack_c;
  undefined4 *puStack_4;
  
  bVar28 = 0;
  bVar12 = (byte)((uint)param_1 >> 8);
  bVar13 = bVar12 - *(char *)unaff_ESI;
  bVar24 = bVar12 < *(byte *)unaff_ESI || bVar13 < in_CF;
  cVar31 = SBORROW1(bVar12,*(char *)unaff_ESI) != SBORROW1(bVar13,in_CF);
  cVar27 = (char)(bVar13 - in_CF) < '\0';
  bVar25 = bVar13 == in_CF;
  if (bVar25 || cVar31 != cVar27) {
    while( true ) {
      pcVar7 = (code *)swi(7);
      uVar32 = (*pcVar7)();
      uVar16 = (uint)(uVar32 >> 0x20);
      puVar11 = (undefined4 *)uVar32;
      puStack_1c = unaff_ESI + 1;
      uVar14 = (undefined2)(uVar32 >> 0x20);
      out(*unaff_ESI,uVar14);
      if (!bVar25 && cVar31 == cVar27) break;
      puVar20 = (uint *)((int)unaff_EDI + -1);
      if (bVar24) {
        unaff_EBX = (undefined6 *)0xdc761c8c;
        out(uVar14,puVar11);
        goto LAB_00401146_4;
      }
      if ((uVar32 & 0x6707847e) == 0) {
        return;
      }
      unaff_EBX = (undefined6 *)((int)unaff_EBX + -1);
      pbVar1 = (byte *)((int)unaff_EDI + -0x43);
      bVar13 = (byte)(uVar32 >> 0x28);
      bVar24 = CARRY1(bVar13,*pbVar1);
      cVar31 = SCARRY1(bVar13,*pbVar1);
      cVar27 = (char)(bVar13 + *pbVar1) < '\0';
      bVar25 = (byte)(bVar13 + *pbVar1) == '\0';
      unaff_ESI = puStack_1c;
      unaff_EDI = puVar20;
    }
    puVar11 = (undefined4 *)((uint)puVar11 | 0x18466776);
    puVar20 = unaff_EDI;
    if ((int)puVar11 < 1) {
LAB_00401146_4:
      puVar11[-2] = puVar11[-2] ^ 0x8a8bbae4;
      do {
        bVar29 = false;
LAB_00401156:
        *(float *)((int)puVar20 + (int)extraout_ECX * 4 + -0x43) = (float)extraout_ST0;
      } while (!bVar29);
      *(undefined2 *)(unaff_EBX + -2) = in_FS;
      iVar10 = *(int *)((int)extraout_ECX + -0xa907725) * -0xc;
      *(undefined2 *)(unaff_EBX + -2) = in_SS;
      puVar20 = (uint *)(CONCAT22((short)((uint)iVar10 >> 0x10),(short)(char)iVar10) + 0x36);
      *puVar20 = *puVar20 ^ 0x52fe95a7;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    bVar24 = false;
    bVar29 = false;
    bVar13 = *(byte *)((int)unaff_EBX + 0x12c78676) & (byte)((uint)puVar11 >> 8);
    bVar26 = (char)bVar13 < '\0';
    bVar25 = bVar13 == 0;
    puVar18 = unaff_EBX;
    if (!bVar26) goto LAB_004011fa;
    do {
      if (bVar25 || bVar29 != bVar26) goto LAB_00401156;
      uVar9 = in(uVar14);
      iVar10 = CONCAT31((int3)((uint)puVar11 >> 8),uVar9);
      bVar29 = SCARRY4(iVar10,1);
      puVar11 = (undefined4 *)(iVar10 + 1);
      bVar26 = (int)puVar11 < 0;
      bVar25 = puVar11 == (undefined4 *)0x0;
      bVar28 = 1;
    } while (!bVar25);
    bVar24 = CARRY4(uVar16,unaff_EDI[(int)unaff_EBX * 2 + -2]);
    uVar16 = uVar16 + unaff_EDI[(int)unaff_EBX * 2 + -2];
    uStack_c = (undefined2)uVar16;
    out(*(char *)puStack_1c,uStack_c);
    puVar20 = (uint *)((int)unaff_EDI + -1);
    bVar29 = SCARRY4(unaff_EBP,1);
    unaff_EBP = unaff_EBP + 1;
    bVar26 = unaff_EBP < 0;
    bVar25 = unaff_EBP == 0;
    puStack_1c = (undefined4 *)(iVar10 + -3);
    if (bVar26) {
      puStack_1c = (undefined4 *)0xe661ab42;
      puVar11 = puRam00000000;
      puStack_4 = puRam00000000;
      if (!bVar24) goto code_r0x00401247;
    }
    else {
      if (!bVar25 && bVar29 == bVar26) {
        return puRam00000000;
      }
      in(0xba);
      puVar20 = *(uint **)((int)unaff_EDI + 0x78f7e65);
      bVar13 = *(byte *)extraout_ECX;
      bVar12 = (byte)((uint)puRam00000000 >> 8);
      bVar24 = bVar12 < bVar13;
      bVar26 = (char)(bVar12 - bVar13) < '\0';
      bVar25 = bVar12 == bVar13;
      puVar11 = (undefined4 *)((uint)puRam00000000 & 0xffffff00);
    }
    puVar3 = (uint *)((int)puStack_1c + unaff_EBP * 8 + -0x6e);
    uVar17 = *puVar3;
    bVar29 = (*puVar3 & 1) != 0;
    *puVar3 = *puVar3 >> 1 | (uint)bVar24 << 0x1f;
    bVar30 = (int)uVar17 < 0 != (int)*puVar3 < 0;
    do {
      bVar13 = (byte)extraout_ECX & 7;
      bVar12 = (byte)((uint)puVar11 >> 8);
      bVar13 = bVar12 << bVar13 | bVar12 >> 8 - bVar13;
      bVar24 = ((uint)extraout_ECX & 0x1f) != 0;
      bVar24 = (bool)(!bVar24 & bVar29 | (bVar24 && (bVar13 & 1) != 0));
      bVar29 = ((byte)extraout_ECX & 0x1f) == 1;
      bVar29 = (bool)(!bVar29 & bVar30 | bVar29 & (bVar24 ^ (short)((ushort)bVar13 << 8) < 0));
      uVar9 = in(0x43);
      puVar11 = (undefined4 *)CONCAT31(CONCAT21((short)((uint)puVar11 >> 0x10),bVar13),uVar9);
      puVar18 = unaff_EBX;
LAB_004011fa:
      _DAT_8f7e25c7 = puVar11;
      if (!bVar24) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (bVar25 || bVar29 != bVar26) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar12 = (byte)puVar18;
      bVar13 = bVar12 - *(char *)extraout_ECX;
      bVar29 = bVar12 < *(byte *)extraout_ECX || bVar13 < bVar24;
      bVar30 = SBORROW1(bVar12,*(char *)extraout_ECX) != SBORROW1(bVar13,bVar24);
      cVar27 = bVar13 - bVar24;
      unaff_EBX = (undefined6 *)CONCAT31((int3)((uint)puVar18 >> 8),cVar27);
      bVar26 = cVar27 < '\0';
      bVar25 = cVar27 == '\0';
    } while (bVar25 || bVar30 != bVar26);
    segment(in_SS,(short)unaff_EBP + (short)puStack_1c + -0x58dc);
    puVar21 = (undefined4 *)((int)puVar20 + -2);
    piVar4 = (int *)segment(in_SS,(short)unaff_EBP + (short)puStack_1c + -0x58eb);
    uVar32 = (longlong)(int)puVar11 * (longlong)*piVar4;
    uVar17 = (uint)(uVar32 >> 0x20);
    out((short)(uVar32 >> 0x20),(int)uVar32);
    in_AF = 9 < ((byte)uVar32 & 0xf) | in_AF;
    uVar14 = (undefined2)uVar16;
    *puVar21 = param_3;
    uVar9 = in(0xba);
    ppcVar22 = (char **)(CONCAT31((int3)(uVar32 >> 8),uVar9) + 1 + (uint)bVar28 * -2);
    bVar24 = false;
    puVar11 = puStack_1c;
    if ((longlong)uVar32 >= 0) goto LAB_004012f8;
    puVar20 = extraout_ECX;
    if ((uVar32 & 0xad9637fb00000000) == 0 || (longlong)uVar32 < 0) {
      bVar24 = false;
    }
    else {
      uVar8 = *unaff_EBX;
      *(longlong *)((int)ppcVar22 + 0x4c7e6707) = (longlong)extraout_ST0;
      uVar14 = (undefined2)param_4;
      bVar13 = (byte)(uVar32 >> 0x28) ^ (byte)((uint)puVar18 >> 8);
      uVar17 = (uint)CONCAT11(bVar13,(char)(uVar32 >> 0x20));
      param_4 = 0xffffffbf;
      if (bVar13 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar25 = SBORROW4((int)puStack_1c,1);
      puStack_1c = (undefined4 *)((int)puStack_1c + -1);
      LOCK();
      *(char *)puStack_1c = (char)uVar8;
      UNLOCK();
      bVar24 = (char)((char)((uint6)uVar8 >> 8) << 4) < '\0';
      if (bVar25) {
        if (!bVar25) {
          puVar21 = (undefined4 *)CONCAT31((uint3)(ushort)((uint6)uVar8 >> 0x10) << 8,DAT_ae5cd121);
          goto code_r0x00401355;
        }
        ppcVar22 = (char **)((int)ppcVar22 + -1);
      }
    }
    while( true ) {
      puVar2 = (ushort *)((int)ppcVar22 + 0x4f);
      *puVar2 = *puVar2 + (ushort)bVar24 * (((ushort)puVar20 & 3) - (*puVar2 & 3));
      cVar27 = in((short)uVar17);
      cVar27 = cVar27 + -0x71 + bVar24;
      out(0xf,(int)CONCAT11((char)uVar17,cVar27));
      bVar24 = ppcVar22 < *(char ***)(int *)((int)ppcVar22 + -0x71);
      ppcVar23 = (char **)((int)ppcVar22 - *(int *)((int)ppcVar22 + -0x71));
      LOCK();
      *(undefined *)(puVar20 + (int)ppcVar23 * 2) = *(undefined *)(puVar20 + (int)ppcVar22 * 2);
      UNLOCK();
      puVar21 = (undefined4 *)(int)CONCAT11((char)uVar17,cVar27);
      puVar11 = puStack_1c;
      ppcVar22 = ppcVar23;
LAB_004012f8:
      while( true ) {
        *ppcVar22 = param_5;
        out(0x89,(char)puVar21);
        uVar15 = (undefined2)uVar17;
        out(uVar15,(undefined *)((int)puVar21 + (0x2381988e - (uint)bVar24)));
        pcVar5 = *ppcVar22;
        *ppcVar22 = (char *)param_6;
        param_5 = (char *)CONCAT22(param_5._2_2_,uVar14);
        ppcVar23 = (char **)((int)ppcVar22 + (uint)bVar28 * -2 + 1);
        puVar21 = (undefined4 *)(pcVar5 + (uint)bVar28 * -2 + 1);
        param_4 = CONCAT22(param_4._2_2_,uVar14);
        if (*(char *)ppcVar22 < *pcVar5) {
          return puVar11;
        }
        uVar9 = in(uVar15);
        piVar4 = (int *)(CONCAT31((int3)((uint)puVar11 >> 8),uVar9) + -0x6a);
        *piVar4 = *piVar4 + 1;
        puStack_1c = puVar21 + (uint)bVar28 * -2 + 1;
        out(*puVar21,uVar15);
        pcVar7 = (code *)swi(0x71);
        param_6 = puVar11;
        uVar33 = (*pcVar7)();
        uVar17 = (uint)((ulonglong)uVar33 >> 0x20);
        uVar16 = (uint)uVar33;
        puVar21 = (undefined4 *)(uVar16 + 0x8cc7beb2);
        bVar24 = SCARRY4(uVar16,-0x7338414e) != SCARRY4((int)puVar21,0);
        if (bVar24) break;
        out(0x38,puVar21);
        if (bVar24) {
          uVar14 = (undefined2)((ulonglong)uVar33 >> 0x20);
          pcVar5 = (char *)in(uVar14);
          *ppcVar23 = pcVar5;
          pcVar5 = (char *)in(uVar14);
          ppcVar23[(uint)bVar28 * -2 + 1] = pcVar5;
          out(uVar14,CONCAT31((int3)((uint)puVar21 >> 8),
                              (byte)puVar21 + 0x8f + (0x7338414d < uVar16)));
          pcVar7 = (code *)swi(1);
          puVar11 = (undefined4 *)(*pcVar7)();
          return puVar11;
        }
        bVar24 = puVar21 < &DAT_0bf36745;
        puVar11 = puStack_1c;
        ppcVar22 = ppcVar23;
      }
      param_4 = 0xf08f7e78;
      *(byte *)(uVar16 + 0x8cc7be40) = *(byte *)(uVar16 + 0x8cc7be40) ^ 0xa0;
      puVar20 = (uint *)(extraout_ECX_00 & uVar17);
      ppcVar22 = (char **)((int)ppcVar23 + (uint)bVar28 * -2 + 1);
      bVar24 = (byte)puVar21 < *(byte *)ppcVar23;
code_r0x00401355:
      *(ushort *)ppcVar22 =
           *(short *)ppcVar22 + (ushort)bVar24 * (((ushort)uVar17 & 3) - (*(ushort *)ppcVar22 & 3));
      *puVar20 = *puVar20 ^ 0xfd828eda;
      bVar13 = (byte)puVar21 + 0x9c;
      if (CONCAT22((short)((uint)puVar20 >> 0x10),
                   CONCAT11((byte)((uint)puVar20 >> 8) ^ (byte)(uVar17 >> 8),(char)puVar20)) != 0)
      break;
      bVar24 = bVar13 < 0xf9;
      puVar20 = (uint *)0x0;
    }
    *(undefined4 *)
     (CONCAT22((short)((uint)puVar21 >> 0x10),
               CONCAT11(((char)bVar13 < '\0') << 7 | (bVar13 == 0) << 6 | in_AF << 4 |
                        ((POPCOUNT(bVar13) & 1U) == 0) << 2 | 2 | 99 < (byte)puVar21,bVar13)) +
     -0x72) = 0xfd828eda;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  out(param_2,in_AL);
  iVar10 = in(0xf8);
  puVar6 = (undefined2 *)segment(in_SS,(short)&stack0x00000000 + -2);
  *puVar6 = in_SS;
  bVar25 = SCARRY4(iVar10,-0x2081d8e9) != SCARRY4(iVar10 + -0x2081d8e9,(uint)bVar24);
  iVar10 = iVar10 + -0x2081d8e9 + (uint)bVar24;
  *unaff_EDI = uStack_24;
  if ((short)(((ushort)unaff_EBP & 3) - ((ushort)unaff_ESI & 3)) < 1 && bVar25 == iVar10 < 0) {
    if (!bVar25) {
                    // WARNING: Could not recover jumptable at 0x004012b1. Too many branches
                    // WARNING: Treating indirect jump as call
      puVar11 = (undefined4 *)(**(code **)(iVar10 + -0x5f))();
      return puVar11;
    }
    uVar16 = in(param_2);
    *unaff_EDI = uVar16;
    uVar16 = in(param_2);
    unaff_EDI[1] = uVar16;
    sVar19 = (short)&stack0xffffffc0 + -2;
    puVar6 = (undefined2 *)segment(in_SS,sVar19);
    *puVar6 = in_SS;
    unaff_EDI[2] = *(uint *)CONCAT22((short)((uint)&stack0xffffffc0 >> 0x10),sVar19);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  out(0x72,(char)puStack_4);
  puVar20 = puStack_20 + 1;
  *puStack_20 = (uint)puStack_4;
code_r0x00401247:
  uVar16 = in(uStack_c);
  _DAT_8bbae423 = puStack_4;
  puVar20[(uint)bVar28 * -2 + 1] = uVar16;
  out(puStack_1c[(uint)bVar28 * -2 + 1],uStack_c);
  puVar6 = (undefined2 *)segment(in_SS,(short)&param_3 + -2);
  *puVar6 = in_SS;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void entry(void)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x2057;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x78f7e67;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xcfe;
  puVar2 = &DAT_0042c000;
  do {
    *puVar2 = *puVar2 ^ 0x55515390;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219();
  return;
}


