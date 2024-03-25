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
// WARNING: Instruction at (ram,0x004012b5) overlaps instruction at (ram,0x004012b1)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x0040128a)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 __thiscall
FUN_00401219(void *this,uint *param_2,undefined param_3,undefined param_4,undefined param_5,
            undefined param_6,undefined param_7,undefined param_8,undefined param_9,
            undefined param_10,undefined4 param_11)

{
  int *piVar1;
  ushort *puVar2;
  char *pcVar3;
  int iVar4;
  byte *pbVar5;
  undefined uVar6;
  undefined2 *puVar7;
  undefined4 *puVar8;
  code *pcVar9;
  uint uVar10;
  char cVar11;
  byte bVar12;
  uint *in_EAX;
  double *pdVar13;
  uint *puVar14;
  uint uVar15;
  int iVar16;
  uint *puVar17;
  uint *extraout_ECX;
  byte bVar19;
  double *pdVar18;
  double *unaff_EBX;
  undefined4 *unaff_EBP;
  undefined4 *puVar20;
  uint *unaff_ESI;
  uint *puVar21;
  undefined4 *unaff_EDI;
  undefined4 *puVar22;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_GS;
  bool bVar23;
  bool in_PF;
  bool bVar24;
  byte in_AF;
  float10 in_ST0;
  float10 fVar25;
  ulonglong uVar26;
  double *unaff_retaddr;
  undefined4 uVar27;
  double *pdStack_dede;
  double *pdStack_deda;
  undefined4 *puStack_20;
  uint *puStack_1c;
  int iStack_18;
  double *pdStack_10;
  uint *puStack_8;
  double *pdStack_4;
  
  fVar25 = in_ST0 * (float10)*(int *)((int)in_EAX + 0x21);
  pdVar18 = unaff_retaddr;
  if (!in_PF) {
    bVar19 = 9 < ((byte)in_EAX & 0xf) | in_AF;
    uVar15 = CONCAT31((int3)((uint)in_EAX >> 8),(byte)in_EAX + bVar19 * -6) & 0xffffff0f;
    pdVar13 = (double *)
              CONCAT22((short)(uVar15 >> 0x10),
                       CONCAT11((char)((uint)in_EAX >> 8) - bVar19,(char)uVar15));
    puVar17 = (uint *)this;
    puVar14 = unaff_ESI;
    goto code_r0x00401233;
  }
LAB_00401220:
  *(int *)((int)unaff_EDI + 0xabb4649) = *(int *)((int)unaff_EDI + 0xabb4649) + (int)unaff_ESI;
  *(uint *)pdVar18 = *(uint *)pdVar18 & (uint)unaff_ESI;
  this = (void *)((int)this + -1);
  if ((uint *)this != (uint *)0x0 && *(uint *)pdVar18 == 0) {
    uRame879639e = SUB41(in_EAX,0);
    goto code_r0x00401289;
  }
code_r0x0040122c:
  do {
    uVar15 = *(uint *)((int)pdStack_4 + iStack_18 * 4);
    unaff_EBP = (undefined4 *)(iStack_18 - uVar15);
    unaff_EBX = pdStack_4;
    puVar17 = puStack_8;
    pdVar13 = pdStack_10;
    puVar14 = puStack_1c;
    unaff_EDI = puStack_20;
    if (unaff_EBP != (undefined4 *)0x0 && (int)uVar15 <= iStack_18) {
      bVar12 = (char)pdStack_4 + 0xb7;
      bVar19 = 9 < (bVar12 & 0xf) | in_AF;
      uVar15 = CONCAT31((int3)((uint)pdStack_4 >> 8),bVar12 + bVar19 * '\x06') & 0xffffff0f;
      puVar14 = (uint *)CONCAT22((short)(uVar15 >> 0x10),
                                 CONCAT11((char)((uint)pdStack_4 >> 8) + bVar19,(char)uVar15));
      unaff_ESI = puStack_1c;
      puVar22 = puStack_20;
      goto code_r0x004012af;
    }
code_r0x00401233:
    *(uint *)(unaff_retaddr + -1) = *(uint *)(unaff_retaddr + -1) & (uint)pdVar13;
    unaff_ESI = (uint *)((int)puVar14 + 1);
    *(undefined *)unaff_EDI = *(undefined *)puVar14;
    *puVar17 = *puVar17 ^ (uint)puVar17;
    pdVar18 = unaff_EBX + 0xd980afc;
    bVar19 = (byte)((uint)pdVar13 >> 8);
    uVar10 = (uint)pdVar18 >> 8;
    uVar6 = (undefined)((uint)pdVar18 >> 8);
    puVar7 = (undefined2 *)segment(in_SS,(short)&param_2);
    unaff_EDI = (undefined4 *)CONCAT22((short)((uint)((int)unaff_EDI + 1) >> 0x10),*puVar7);
    puVar14 = (uint *)CONCAT31((int3)((uint)pdVar18 >> 8),DAT_22485f56);
    piVar1 = unaff_EDI + 0x1b;
    uVar15 = (uint)((byte)pdVar18 < bVar19 ||
                   (byte)((byte)pdVar18 - bVar19) <
                   ((undefined *)((int)unaff_EBX + -1) < (undefined *)0x933fa81f));
    iVar16 = *piVar1;
    iVar4 = *piVar1;
    *piVar1 = iVar4 + -0x5e + uVar15;
    in_AF = (uVar10 & 0x10) != 0;
    bVar24 = (uVar10 & 4) != 0;
    bVar23 = (uVar10 & 1) != 0;
    pdVar18 = unaff_retaddr;
    if ((uVar10 & 0x40) != 0 ||
        (SCARRY4(iVar16,-0x5e) != SCARRY4(iVar4 + -0x5e,uVar15)) != ((uVar10 & 0x80) != 0)) {
      bVar23 = false;
      *puVar14 = *puVar14 & (uint)unaff_ESI;
      if ((POPCOUNT(*puVar14 & 0xff) & 1U) != 0) break;
      puVar14 = (uint *)((int)unaff_retaddr + 0x7e494839);
      *puVar14 = *puVar14 | (uint)pdVar13;
      DAT_5b322164 = uVar6;
      if ((POPCOUNT(*puVar14 & 0xff) & 1U) != 0) goto code_r0x0040122c;
      bVar23 = false;
      puVar14 = (uint *)0x5b32217c;
      bVar24 = false;
      unaff_EDI = (undefined4 *)((int)unaff_EBP + 1);
      uVar6 = in((short)pdStack_dede);
      *(undefined *)unaff_EBP = uVar6;
      puVar17 = (uint *)((int)puVar17 + -1);
      pdVar18 = pdStack_dede;
    }
  } while (!bVar24);
  do {
    cVar11 = (char)puVar14 + 'z' + bVar23;
    in_EAX = (uint *)CONCAT31((int3)((uint)puVar14 >> 8),cVar11);
    bVar23 = (POPCOUNT(cVar11) & 1U) == 0;
    unaff_EBX = (double *)&DAT_5ed3210a;
    this = (void *)((int)puVar17 + -1);
    if ((uint *)this == (uint *)0x0 || cVar11 != '\0') {
      if (!bVar23) goto LAB_00401220;
      puVar2 = (ushort *)((int)puVar17 + -0x19);
      *puVar2 = *puVar2 + (ushort)((longlong)(int)&pdStack_dede !=
                                  (longlong)_DAT_5ed3210a * -0x615db785) *
                          (((ushort)unaff_EDI & 3) - (*puVar2 & 3));
code_r0x00401289:
      *unaff_ESI = *unaff_ESI << ((byte)this & 0x1f);
      pdVar18 = (double *)CONCAT31((int3)((uint)pdVar18 >> 8),0x59);
      puVar17 = (uint *)((int)pdVar18 + -0x4e);
      *puVar17 = *puVar17 & (uint)unaff_EBX;
      bVar23 = (POPCOUNT(*puVar17 & 0xff) & 1U) == 0;
      in_EAX = *(uint **)((int)unaff_EBP + -7);
    }
    puVar17 = (uint *)this;
    puVar14 = in_EAX;
    puVar22 = unaff_EDI;
    if (!bVar23) goto LAB_004012e0;
    *(uint *)(pdVar18 + -9) = *(uint *)(pdVar18 + -9) & (uint)unaff_EBX;
    puVar14 = (uint *)((int)in_EAX + -1);
    if (puVar14 != (uint *)0x0) {
      LOCK();
      bVar23 = false;
      *unaff_ESI = *unaff_ESI ^ (uint)pdVar18;
      UNLOCK();
      if ((POPCOUNT(*unaff_ESI & 0xff) & 1U) == 0) {
        puVar22 = unaff_EDI + 1;
        uVar27 = in((short)pdVar18);
        *unaff_EDI = uVar27;
        goto code_r0x004012ea;
      }
      unaff_EBP = (undefined4 *)*unaff_EBP;
      fVar25 = (float10)*pdVar18;
      *puVar17 = *puVar17 & (uint)puVar17;
      puVar14 = (uint *)((int)in_EAX + -0x4819e21);
      puStack_8 = puVar17;
      unaff_retaddr = pdVar18;
      pdStack_10 = unaff_EBX;
code_r0x004012af:
      do {
        pdStack_10 = (double *)
                     CONCAT22((short)((uint)pdStack_10 >> 0x10),CONCAT11(0x37,(char)pdStack_10));
        *(int *)((int)unaff_ESI + (int)unaff_EBP * 8 + 0x227b5a6a) = (int)ROUND(fVar25);
        puVar17 = puStack_8;
        while( true ) {
          bVar23 = false;
          *puVar14 = *puVar14 & (uint)unaff_ESI;
          if ((POPCOUNT(*puVar14 & 0xff) & 1U) != 0) goto code_r0x004012ea;
          bVar19 = (byte)((uint)unaff_retaddr >> 8) & *(byte *)puVar14;
          unaff_retaddr =
               (double *)
               CONCAT22((short)((uint)unaff_retaddr >> 0x10),CONCAT11(bVar19,(char)unaff_retaddr));
          bVar23 = (POPCOUNT(bVar19) & 1U) != 0;
          if (bVar23) break;
          *(uint *)unaff_retaddr = *(uint *)unaff_retaddr & (uint)unaff_ESI;
          if ((POPCOUNT(*(uint *)unaff_retaddr & 0xff) & 1U) != 0) {
            return CONCAT44(unaff_retaddr,puVar14);
          }
          bVar23 = CARRY4((uint)unaff_EBP,*(uint *)((int)puVar14 + -0x7f));
          unaff_EBP = (undefined4 *)((int)unaff_EBP + *(uint *)((int)puVar14 + -0x7f));
          unaff_EBX = (double *)
                      CONCAT22((short)((uint)pdStack_10 >> 0x10),
                               CONCAT11(((char)((uint)pdStack_10 >> 8) -
                                        *(char *)(pdStack_10 + -0xc)) - bVar23,(char)pdStack_10));
          while( true ) {
            uVar15 = *puVar14;
            *puVar14 = *puVar14 << 1;
            if ((POPCOUNT(*puVar14 & 0xff) & 1U) == 0) break;
            if ((int)uVar15 < 0 != (int)*puVar14 < 0) {
              puVar17 = (uint *)(((uint)unaff_retaddr & (uint)pdStack_10) - 8);
              *puVar17 = *puVar17 & (uint)unaff_EBX;
              uVar27 = CONCAT22((short)(((uint)unaff_retaddr & (uint)pdStack_10) >> 0x10),in_CS);
              uRam21b78467 = in_GS;
              uVar15 = func_0xdb05a33b();
              if ((POPCOUNT((uint)((int)unaff_EBX + 1) & 0xff) & 1U) == 0) {
                out(0x4b,uVar15);
                iVar16 = uVar15 + 1;
                return CONCAT44(uVar27,CONCAT22((short)((uint)iVar16 >> 0x10),
                                                (ushort)(byte)((char)iVar16 +
                                                              (char)((uint)iVar16 >> 8) * -0x17)));
              }
              cVar11 = uVar15 < 0xa0285a21;
              bVar23 = (POPCOUNT(uVar15 + 0x5fd7a5df & 0xff) & 1U) == 0;
              pcVar9 = (code *)swi(0x23);
              uVar26 = (*pcVar9)();
              pdStack_deda = (double *)(uVar26 >> 0x20);
              puVar17 = extraout_ECX;
              if (!bVar23) {
                out(5,(char)uVar26);
                if ((uVar26 & 0x2e99e813) != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
                  halt_baddata();
                }
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              goto code_r0x00401308;
            }
          }
          puVar14 = (uint *)CONCAT31((int3)((uint)puVar14 >> 8),8);
          DAT_a1a28ff2 = 8;
LAB_004012e0:
          do {
            *(byte *)((int)unaff_EBX + -0x3b) =
                 *(byte *)((int)unaff_EBX + -0x3b) ^ (byte)((uint)unaff_EBX >> 8);
            puVar20 = unaff_EBP;
            puVar21 = unaff_ESI;
            param_2 = puVar17;
code_r0x004012e4:
            pbVar5 = (byte *)((int)puVar22 + 1);
            unaff_ESI = (uint *)((int)puVar21 + 1);
            *(undefined *)puVar22 = *(undefined *)puVar21;
            puVar22 = (undefined4 *)((int)puVar22 + 2);
            bVar23 = (byte)puVar14 < *pbVar5;
            cVar11 = '\t';
            puVar8 = (undefined4 *)register0x00000010;
            do {
              puVar20 = puVar20 + -1;
              puVar8 = puVar8 + -1;
              *puVar8 = *puVar20;
              cVar11 = cVar11 + -1;
              unaff_EBP = (undefined4 *)register0x00000010;
            } while ('\0' < cVar11);
code_r0x004012ea:
            puVar14 = (uint *)((int)puVar14 + (uint)bVar23 + *(int *)((int)puVar14 + 0x6d));
            bVar23 = (POPCOUNT((uint)puVar14 & 0xff) & 1U) != 0;
            if (!bVar23) {
              *(undefined *)puVar22 = *(undefined *)unaff_ESI;
              DAT_0adeb6c8 = SUB41(puVar14,0);
              bVar19 = (byte)((uint)puVar14 >> 8);
              *(char *)((int)puVar14 + 0x487b20f1) = *(char *)((int)puVar14 + 0x487b20f1) - bVar19;
              pbVar5 = (byte *)(CONCAT31((int3)((uint)puVar14 >> 8),DAT_213de9ad) + 0x487b23cd);
              cVar11 = *pbVar5 < bVar19;
              *pbVar5 = *pbVar5 - bVar19;
code_r0x00401308:
              pcVar3 = (char *)((int)puVar17 + -0x3635b6b7 + (int)pdStack_deda);
              *pcVar3 = *pcVar3 + (char)((uint)puVar17 >> 8) + cVar11;
              *(int *)((int)unaff_EBP + -0x27) = *(int *)((int)unaff_EBP + -0x27) + 1;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            unaff_retaddr = pdStack_deda;
            unaff_EBX = pdStack_dede;
            pdStack_10 = pdStack_dede;
          } while (bVar23);
        }
        puVar20 = unaff_EBP;
        puVar21 = unaff_ESI;
        if (!bVar23) goto code_r0x004012e4;
        uRam04819e1f = uRam04819e1f | (uint)unaff_EBP;
        puStack_8 = puVar17;
      } while( true );
    }
    pbVar5 = (byte *)((int)unaff_EBX + -0x49);
    bVar19 = (byte)((uint)unaff_EBX >> 8);
    bVar23 = *pbVar5 < bVar19;
    *pbVar5 = *pbVar5 - bVar19;
    puVar14 = (uint *)0x0;
  } while( true );
}



undefined8 __thiscall entry(void *this,uint *param_1)

{
  int iVar1;
  uint *puVar2;
  undefined8 uVar3;
  undefined in_stack_00000008;
  undefined in_stack_0000000c;
  undefined in_stack_00000010;
  undefined in_stack_00000014;
  undefined in_stack_00000018;
  undefined in_stack_0000001c;
  undefined in_stack_00000020;
  undefined in_stack_00000024;
  undefined4 in_stack_0000002e;
  
  iVar1 = 0x2057;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x487b5a21;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xcfe;
  puVar2 = &DAT_0042c000;
  do {
    *puVar2 = *puVar2 ^ 0x64e74300;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  uVar3 = FUN_00401219(this,param_1,in_stack_00000008,in_stack_0000000c,in_stack_00000010,
                       in_stack_00000014,in_stack_00000018,in_stack_0000001c,in_stack_00000020,
                       in_stack_00000024,in_stack_0000002e);
  return uVar3;
}


