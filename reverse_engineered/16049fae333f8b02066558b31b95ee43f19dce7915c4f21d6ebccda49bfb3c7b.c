typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned short    undefined2;
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
// WARNING: Instruction at (ram,0x004012e3) overlaps instruction at (ram,0x004012e0)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x0040123f)
// WARNING: Variable defined which should be unmapped: param_11
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall
FUN_00401219(int param_1,undefined4 param_2,undefined2 param_3,undefined4 param_4,
            undefined4 *param_5,int param_6,undefined4 param_7,int param_8,undefined4 param_9,
            int param_10,undefined *param_11)

{
  int *piVar1;
  code *pcVar2;
  longlong lVar3;
  undefined *puVar4;
  byte bVar5;
  byte bVar6;
  undefined4 in_EAX;
  int iVar7;
  uint *puVar8;
  undefined4 *puVar9;
  uint uVar10;
  uint uVar11;
  char cVar13;
  uint uVar12;
  uint extraout_ECX;
  byte bVar14;
  byte *unaff_EBX;
  uint uVar15;
  char *pcVar16;
  uint **ppuVar17;
  uint *puVar19;
  undefined4 *unaff_EBP;
  undefined4 uVar20;
  uint *puVar21;
  undefined4 *unaff_ESI;
  undefined4 *puVar22;
  undefined4 *puVar23;
  undefined4 unaff_EDI;
  undefined *puVar24;
  undefined2 in_SS;
  bool in_CF;
  bool bVar25;
  byte in_AF;
  bool bVar26;
  char cVar27;
  char cVar28;
  unkbyte10 in_ST0;
  undefined6 uVar29;
  undefined4 *puVar18;
  
  if (!in_CF) {
    out(*unaff_ESI,(short)param_2);
    unaff_ESI[1] = param_2;
    iVar7 = CONCAT31((int3)((uint)in_EAX >> 8),-in_CF) + -0x7f4c7e89;
    uVar20 = *unaff_EBP;
    *(undefined2 *)unaff_EBP = in_SS;
    LOCK();
    bVar6 = *unaff_EBX;
    *unaff_EBX = (byte)param_1;
    uVar11 = CONCAT31((int3)((uint)param_1 >> 8),bVar6);
    UNLOCK();
    bVar6 = *unaff_EBX;
    bVar14 = (byte)((uint)param_2 >> 8);
    *unaff_EBX = *unaff_EBX + bVar14;
    bVar5 = -CARRY1(bVar6,bVar14);
    out(unaff_ESI[1],(short)param_2);
    unaff_ESI[2] = param_2;
    unaff_EBP[-1] = uVar20;
    piVar1 = (int *)(uVar11 + 0x388045);
    *piVar1 = (*piVar1 + -0x73) - (uint)CARRY1(bVar6,bVar14);
    bVar6 = 9 < (bVar5 & 0xf) | in_AF;
    uVar15 = CONCAT31((int3)((uint)iVar7 >> 8),bVar5 + bVar6 * -6) & 0xffffff0f;
    puVar8 = (uint *)CONCAT22((short)(uVar15 >> 0x10),
                              CONCAT11((char)((uint)iVar7 >> 8) - bVar6,(char)uVar15));
    unaff_EBP[-2] = puVar8;
    *puVar8 = *puVar8 | uVar11;
    out(unaff_ESI[2],CONCAT11(bVar14 + (char)param_2 * -2,(char)param_2));
    bVar6 = (byte)((uint)unaff_EBX >> 8) & 7;
    DAT_07d67c89 = DAT_07d67c89 << bVar6 | DAT_07d67c89 >> 8 - bVar6;
    *(undefined4 *)((int)unaff_ESI + 2) = unaff_EDI;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    puVar4 = param_11;
    in((short)param_2);
    out(*(undefined4 *)((int)unaff_ESI + 1),(short)param_2);
    *(undefined4 *)((int)unaff_ESI + 5) = param_2;
    out(*(undefined4 *)((int)unaff_ESI + 5),param_3);
    *(int *)(param_11 + -0x7fba7691) = *(int *)(param_11 + -0x7fba7691) - (int)&stack0x00000000;
    if (param_10 + -1 == 0) break;
    LOCK();
    iVar7 = *(int *)(param_10 + 0xa6fd65f);
    *(int *)(param_10 + 0xa6fd65f) = param_10 + -1;
    UNLOCK();
    bVar6 = (byte)iVar7 & 7;
    bVar5 = (byte)((uint)param_9 >> 8);
    param_2 = CONCAT22((short)((uint)param_9 >> 0x10),
                       CONCAT11(bVar5 >> bVar6 | bVar5 << 8 - bVar6,(char)param_9));
    in_ST0 = fsin(in_ST0);
    unaff_ESI = (undefined4 *)register0x00000010;
    param_11 = (undefined *)register0x00000010;
  }
  param_11 = (undefined *)CONCAT22(param_11._2_2_,in_SS);
  *(undefined4 *)((int)param_5 + -0x2a) = param_4;
  out(*param_5,(short)param_9);
  *(undefined4 *)((int)param_5 + 0x56194fc2) = param_9;
  LOCK();
  UNLOCK();
  puVar24 = *ppuRam00000000;
  puVar21 = (uint *)ppuRam00000000[2];
  uVar15 = (uint)ppuRam00000000[4];
  iVar7 = (int)ppuRam00000000[5];
  uVar20 = ppuRam00000000[6];
  puVar8 = (uint *)CONCAT31((int3)((uint)ppuRam00000000[7] >> 8),
                            -(0xfa298376 < ((uint)puVar4 & 0xffffff00)));
  puVar23 = (undefined4 *)((int)ppuRam00000000[1] + 4);
  out(*(undefined4 *)ppuRam00000000[1],(short)iVar7);
  bVar6 = (byte)((uint)uVar20 >> 8);
  bVar25 = CARRY1(bVar6,(byte)iVar7);
  cVar13 = bVar6 + (byte)iVar7;
  ppuVar17 = (uint **)(ppuRam00000000 + 7);
  puVar9 = ppuRam00000000 + 7;
  puVar18 = ppuRam00000000 + 7;
  ppuRam00000000 = &param_11;
  *ppuVar17 = puVar21;
  uVar11 = CONCAT22((short)((uint)uVar20 >> 0x10),CONCAT11(cVar13,(char)uVar20));
  puVar22 = puVar23;
  if (bVar25 || cVar13 == '\0') {
    pcVar16 = (char *)CONCAT31((int3)((uint)puVar18 >> 8),-bVar25);
    *pcVar16 = -bVar25;
code_r0x00401346:
    puVar24 = (undefined *)*puVar8;
    bVar6 = (char)uVar15 - 1;
    puVar19 = (uint *)((int)puVar23 + -0x75a0bcb6);
  }
  else {
    while( true ) {
      bVar5 = ((byte)uVar11 & 0x1f) % 9;
      bVar6 = *(byte *)((int)puVar22 + 0x49);
      *(byte *)((int)puVar22 + 0x49) = (byte)(CONCAT11(bVar25,bVar6) >> bVar5) | bVar6 << 9 - bVar5;
      pcVar16 = (char *)0xe85b4eee;
      out(*puVar22,(short)iVar7);
      *(undefined **)((int)puVar22 + iVar7 * 8 + -0x22) = puVar24;
      uVar10 = (uint)puVar9 | 0xe2;
      bVar26 = (byte)((byte)puVar9 | 0xe2) == 0;
      if (bVar26) break;
      puVar23 = (undefined4 *)&DAT_d617c567;
      uVar12 = uVar10 - 1;
      puVar19 = puVar8;
      if (uVar12 != 0) goto LAB_004012fd;
      do {
        lVar3 = CONCAT44(iVar7,puVar21);
        out((short)iVar7,(char)uVar11);
        uVar15 = uVar12;
        uVar10 = uVar11;
        if (!bVar26) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        while( true ) {
          puVar21 = (uint *)lVar3;
          iVar7 = CONCAT22((short)((ulonglong)lVar3 >> 0x30),
                           CONCAT11((char)((ulonglong)lVar3 >> 0x28) + (char)(uVar10 >> 8),
                                    (char)((ulonglong)lVar3 >> 0x20)));
          lVar3 = CONCAT44(iVar7,puVar21);
          puVar19 = (uint *)(uVar15 + 0xdc269300);
          bVar25 = false;
          *puVar19 = *puVar19 & uVar10;
          bVar26 = *puVar19 == 0;
          if (bVar26) goto code_r0x00401346;
          uVar12 = uVar15;
          if ((int)*puVar19 < 1) break;
code_r0x00401336:
          uRame977dc22 = uVar15;
          *puVar24 = *(undefined *)puVar23;
          uVar15 = uVar12;
          puVar23 = (undefined4 *)((int)puVar23 + -1);
          puVar24 = puVar24 + -1;
          _DAT_633dd6b8 = uVar12;
        }
        uVar12 = uVar10 - 1;
        uVar11 = uVar15;
      } while (uVar12 != 0);
      if (uVar10 != 2) {
        puVar24 = (undefined *)*puVar8;
        puVar19 = puVar8 + 1;
        pcVar16 = (char *)CONCAT31((int3)((uint)(pcVar16 + 1) >> 8),(char)uVar15);
        goto code_r0x00401351;
      }
      puVar9 = (undefined4 *)0x0;
      puVar22 = puVar23;
    }
    uVar20 = CONCAT31((int3)((uint)iVar7 >> 8),0xa3);
    lVar3 = CONCAT44(uVar20,puVar21);
    pcVar16 = (char *)CONCAT31(0xe85b4e,(byte)(uVar11 >> 8) & 0xee);
    uVar12 = uVar11;
    puVar23 = puVar22 + -1;
    uVar15 = uRame977dc22;
    if ((uVar11 & 0xee00) == 0) goto code_r0x00401336;
    puVar23 = puVar22 + -2;
    out(puVar22[-1],(short)uVar20);
    puVar24 = puVar24 + -4;
    uVar12 = *puVar21;
    puVar19 = puVar21 + 1;
    puVar8 = puVar21 + 1;
    lVar3 = (ulonglong)uVar11 * ZEXT48(puVar23);
    bVar25 = (int)((ulonglong)lVar3 >> 0x20) != 0;
    uVar15 = (uint)lVar3;
    if (bVar25) {
      out(0x4e,(char)lVar3);
      *(char *)((int)puVar22 + -0x56) = *(char *)((int)puVar22 + -0x56) + 'N' + bVar25;
      uVar15 = uVar12;
      goto code_r0x00401336;
    }
code_r0x00401351:
    bVar6 = (byte)uVar15;
    puVar23 = (undefined4 *)((int)puVar23 + 1);
  }
  bVar5 = 0x47 < bVar6;
  bVar25 = SCARRY1(bVar6,-0x48);
  cVar13 = bVar6 + 0xb8;
  cVar28 = cVar13 < '\0';
  cVar27 = cVar13 == '\0';
  cVar13 = (POPCOUNT(cVar13) & 1U) == 0;
  pcVar2 = (code *)swi(0xa4);
  uVar29 = (*pcVar2)();
  uVar11 = CONCAT22((short)((uint6)uVar29 >> 0x10),
                    CONCAT11(cVar28 << 7 | cVar27 << 6 | in_AF << 4 | cVar13 << 2 | 2 | bVar5,
                             (char)uVar29));
  out(*(undefined *)puVar23,(short)((uint6)uVar29 >> 0x20));
  uVar12 = extraout_ECX;
  if (bVar25) {
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
LAB_004012fd:
  pcVar16[uVar12 - 0x77] = pcVar16[uVar12 - 0x77] + '\x01';
  *(undefined2 *)((int)puVar19 + -4) = in_SS;
  out(0x99,uVar11);
  if ((uVar12 != 0) && (uVar12 == 1)) {
    LOCK();
    puVar24[0x6fd617a8] = (char)uVar11;
    UNLOCK();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void __fastcall
entry(int param_1,undefined4 param_2,undefined2 param_3,undefined4 param_4,undefined4 *param_5,
     int param_6,undefined4 param_7,int param_8,undefined4 param_9,int param_10,undefined *param_11)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x1f85;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x6fd61689;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xcf4;
  puVar2 = &DAT_0042b000;
  do {
    *puVar2 = *puVar2 ^ 0x62ed09b6;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
               param_11);
  return;
}


