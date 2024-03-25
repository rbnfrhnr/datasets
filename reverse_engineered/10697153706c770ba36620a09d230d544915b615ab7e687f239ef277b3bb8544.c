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
// WARNING: Instruction at (ram,0x004012ff) overlaps instruction at (ram,0x004012fd)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x004012e6)
// WARNING: Removing unreachable block (ram,0x0040134c)
// WARNING: Removing unreachable block (ram,0x00401358)
// WARNING: Removing unreachable block (ram,0x004013d2)
// WARNING: Removing unreachable block (ram,0x00401367)
// WARNING: Removing unreachable block (ram,0x00401371)
// WARNING: Removing unreachable block (ram,0x00401375)
// WARNING: Removing unreachable block (ram,0x0040139a)
// WARNING: Removing unreachable block (ram,0x004013b8)
// WARNING: Removing unreachable block (ram,0x004013d4)
// WARNING: Removing unreachable block (ram,0x004013f8)
// WARNING: Removing unreachable block (ram,0x004013dc)
// WARNING: Removing unreachable block (ram,0x004013e7)
// WARNING: Removing unreachable block (ram,0x004013f1)
// WARNING: Removing unreachable block (ram,0x0040145c)
// WARNING: Removing unreachable block (ram,0x0040142a)
// WARNING: Removing unreachable block (ram,0x00401463)
// WARNING: Removing unreachable block (ram,0x00401465)
// WARNING: Removing unreachable block (ram,0x004014d5)
// WARNING: Removing unreachable block (ram,0x00401462)
// WARNING: Removing unreachable block (ram,0x004014d8)
// WARNING: Removing unreachable block (ram,0x0040146d)
// WARNING: Removing unreachable block (ram,0x004014e2)
// WARNING: Removing unreachable block (ram,0x00401470)
// WARNING: Removing unreachable block (ram,0x00401402)
// WARNING: Removing unreachable block (ram,0x004013f6)
// WARNING: Removing unreachable block (ram,0x0040140a)
// WARNING: Removing unreachable block (ram,0x00401475)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __fastcall
FUN_00401219(uint param_1,uint param_2,undefined4 param_3,uint *param_4,int param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 *puVar1;
  int iVar2;
  byte bVar3;
  uint uVar4;
  code *pcVar5;
  ushort uVar6;
  undefined4 *in_EAX;
  undefined3 uVar11;
  int *piVar7;
  undefined4 uVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  char cVar12;
  uint extraout_EDX;
  byte bVar14;
  uint *unaff_EBX;
  uint *puVar15;
  int unaff_EBP;
  int *unaff_ESI;
  int *piVar16;
  undefined4 *unaff_EDI;
  undefined2 in_CS;
  undefined2 uVar17;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  bool in_CF;
  bool bVar18;
  bool bVar19;
  undefined uVar20;
  bool in_PF;
  char in_AF;
  undefined2 in_FPUStatusWord;
  float10 in_ST0;
  float10 extraout_ST0;
  undefined8 uVar21;
  int *unaff_retaddr;
  byte bVar13;
  
  uVar21 = CONCAT44(param_2,unaff_EBP);
  if (in_PF) {
    puVar15 = (uint *)((int)unaff_EBX + -0xec4e199);
    bVar14 = (byte)param_1 & 0x1f;
    *puVar15 = *puVar15 >> bVar14 | *puVar15 << 0x20 - bVar14;
    return (undefined4 *)0xee114b6;
  }
  puVar9 = unaff_EDI;
  if (in_CF) {
    puVar10 = (undefined4 *)(unaff_EBP + -1);
    puVar9 = unaff_EDI + 1;
    uVar8 = in((short)param_2);
    *unaff_EDI = uVar8;
    goto code_r0x00401235;
  }
  do {
    param_2 = (uint)((ulonglong)uVar21 >> 0x20);
    unaff_ESI = (int *)((param_2 - 0x75) + (int)uVar21);
    *(byte *)((int)unaff_ESI * 3) = *(byte *)((int)unaff_ESI * 3) ^ (byte)unaff_EBX;
    puVar10 = _DAT_6b1e5c62;
    uVar6 = (ushort)((uint)unaff_retaddr >> 0x10);
    piVar16 = (int *)CONCAT22(uVar6,in_SS);
    puVar1 = (undefined4 *)*unaff_EBX;
    bVar18 = puVar9 < puVar1;
    unaff_retaddr = piVar16;
    if (bVar18) {
      uVar11 = (undefined3)((uint)in_EAX >> 8);
      bVar14 = (byte)in_EAX;
      if (puVar9 == puVar1) {
        param_1 = param_1 - 1;
        if (param_1 != 0 && puVar9 == puVar1) {
          in_EAX = (undefined4 *)CONCAT31(uVar11,(bVar14 - 0x1e) - bVar18);
          goto code_r0x0040129a;
        }
        uVar8 = CONCAT31(uVar11,(bVar14 - 0x1e) - bVar18);
code_r0x0040128c:
        in_EAX = (undefined4 *)
                 CONCAT22((short)((uint)uVar8 >> 0x10),(ushort)(byte)uVar8 * (ushort)(byte)param_1);
        *(byte *)((int)unaff_ESI + (int)unaff_EBX) =
             *(byte *)((int)unaff_ESI + (int)unaff_EBX) | (byte)unaff_EBX;
        param_1 = CONCAT31((int3)(param_1 >> 8),0x78);
        puVar10 = (undefined4 *)0x1e1c723b;
code_r0x0040129a:
        *(uint *)((int)puVar10 + 0x72) = *(uint *)((int)puVar10 + 0x72) & param_1;
        uVar8 = in((short)param_2);
        *in_EAX = uVar8;
        uVar20 = in((short)param_2);
        *(undefined *)(in_EAX + 1) = uVar20;
        pcVar5 = (code *)swi(3);
        puVar9 = (undefined4 *)(*pcVar5)();
        return puVar9;
      }
      while( true ) {
        bVar13 = (byte)(param_2 >> 8);
        bVar3 = bVar13 - *(char *)(unaff_ESI + (int)_DAT_6b1e5c62);
        bVar19 = bVar13 < *(byte *)(unaff_ESI + (int)_DAT_6b1e5c62) || bVar3 < bVar18;
        cVar12 = bVar3 - bVar18;
        param_2 = CONCAT22((short)(param_2 >> 0x10),CONCAT11(cVar12,(char)param_2));
        if (-1 < cVar12) {
          uVar20 = unaff_EBX < *(uint **)(param_2 + 0x723b69b4);
          *(undefined2 *)((int)_DAT_6b1e5c62 + 0x3f6be389) = in_FPUStatusWord;
          do {
            puVar15 = (uint *)((int)unaff_EBX + 1);
            *(int *)((int)unaff_EBX + 6) = (int)ROUND(in_ST0);
            uVar17 = in_CS;
            piVar16 = unaff_ESI;
            if (!(bool)uVar20) {
              if (puVar15 == (uint *)0x0) {
                uVar20 = in(0x2f);
                return (undefined4 *)CONCAT31((int3)((uint)puVar10 >> 8),uVar20);
              }
              puVar9 = (undefined4 *)(*(code *)(param_1 + 0xe38c88ea))(in_CS);
              if ((POPCOUNT((int)unaff_ESI - 1U & 0xff) & 1U) == 0) {
                out(0xcc,(char)puVar9);
                return puVar9;
              }
              in_DS = SUB42(puVar15,0);
              param_2 = (int)puVar9 >> 0x1f;
              out(0x88,(char)puVar9);
              puVar15 = (uint *)CONCAT22((short)((uint)puVar15 >> 0x10),in_FS);
              unaff_ESI = (int *)((int)unaff_ESI + -2);
              param_1 = extraout_ECX_01;
              uVar17 = in_CS;
              piVar16 = (int *)0x3b69949a;
            }
            *(byte *)(param_1 + 0xa1e1c04) = ~*(byte *)(param_1 + 0xa1e1c04);
                    // WARNING: Do nothing block with infinite loop
            uVar20 = 0;
            if (param_1 == 1) {
              do {
              } while( true );
            }
            *(undefined2 *)((int)unaff_ESI + 0x3b) = in_DS;
            in_CS = 0xdd95;
            in_ST0 = (float10)func_0x723b69b4(uVar17,param_2,puVar15,piVar16);
            puVar10 = (undefined4 *)0x3f6be389;
            param_1 = extraout_ECX_00;
            param_2 = extraout_EDX;
            unaff_EBX = puVar15;
          } while( true );
        }
        if (cVar12 != '\0') break;
        bVar18 = bVar19;
        if (-1 < cVar12) goto code_r0x0040129a;
      }
      piVar7 = (int *)((CONCAT31(uVar11,(bVar14 + 0x8a) - bVar19) - param_2) -
                      (uint)(bVar14 < 0x76 || (byte)(bVar14 + 0x8a) < bVar19));
      unaff_retaddr = (int *)((uint)uVar6 << 0x10);
      *(int *)((int)puVar9 + -0x72c4e19a) =
           *(int *)((int)puVar9 + -0x72c4e19a) << ((byte)param_1 & 0x1f);
    }
    else {
code_r0x00401235:
      piVar16 = unaff_ESI;
      piVar7 = (int *)0x20410831;
      bVar14 = (byte)unaff_EBX;
      cVar12 = bVar14 + *(char *)puVar9;
      unaff_EBX = (uint *)CONCAT31((int3)((uint)unaff_EBX >> 8),cVar12 + '\x01');
      if (!CARRY1(bVar14,*(byte *)puVar9) && cVar12 != -1) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    *piVar16 = *piVar16 - (int)piVar16;
    iVar2 = *piVar7;
    *(undefined2 *)(iVar2 + -4) = in_DS;
    unaff_ESI = (int *)(iVar2 + 2);
    puVar15 = *(uint **)(param_2 + 0x723b681c);
    bVar18 = unaff_EBX < puVar15;
    uVar4 = (int)unaff_EBX - (int)puVar15;
    unaff_EBX = (uint *)((int)unaff_EBX + 1);
    uVar6 = (ushort)(byte)(*(char *)(iVar2 + 1) +
                          (((int)uVar4 < 0) << 7 | (uVar4 == 0) << 6 | in_AF << 4 |
                           ((POPCOUNT(uVar4 & 0xff) & 1U) == 0) << 2 | 2U | bVar18) * -0x69);
    uVar8 = CONCAT22((short)((uint)piVar7 >> 0x10),uVar6);
    if (!bVar18 && uVar6 != 0) goto code_r0x0040128c;
    *(undefined2 *)(*(int *)(iVar2 + -4) + -4) = in_CS;
    in_CS = 0x9527;
    uVar21 = func_0x3b1e1c72();
    param_1 = extraout_ECX;
    in_EAX = puVar10;
    in_ST0 = extraout_ST0;
  } while( true );
}



void __fastcall
entry(uint param_1,uint param_2,undefined4 param_3,uint *param_4,int param_5,undefined4 param_6,
     undefined4 param_7,undefined4 param_8)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x723b1e1c;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x3cb73728;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}


