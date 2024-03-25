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




// WARNING: Instruction at (ram,0x00401333) overlaps instruction at (ram,0x00401331)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall entry(int param_1,undefined4 param_2)

{
  byte *pbVar1;
  undefined4 *puVar2;
  byte bVar3;
  uint uVar4;
  char cVar6;
  code *pcVar7;
  undefined6 uVar8;
  byte bVar9;
  byte bVar10;
  byte bVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  int in_EAX;
  uint *puVar16;
  undefined uVar18;
  undefined4 extraout_ECX;
  short sVar19;
  undefined4 uVar20;
  int iVar21;
  undefined uVar22;
  undefined2 uVar24;
  undefined3 uVar23;
  uint unaff_EBX;
  uint unaff_EBP;
  char *pcVar25;
  char *pcVar26;
  undefined4 *unaff_ESI;
  undefined *puVar27;
  uint *puVar28;
  uint *unaff_EDI;
  undefined2 in_SS;
  bool bVar29;
  bool bVar30;
  byte in_AF;
  undefined8 uVar31;
  undefined4 *puStack_4;
  uint uVar5;
  char cVar17;
  
  puVar16 = &DAT_00401000;
  do {
    *puVar16 = *puVar16 ^ 0x14866d7d;
    puVar16 = puVar16 + 1;
  } while (puVar16 != (uint *)0x408e14);
  puVar16 = &DAT_0042b000;
  do {
    *puVar16 = *puVar16 ^ 0x59662d2c;
    puVar16 = puVar16 + 1;
  } while (puVar16 != (uint *)0x42e3d0);
LAB_00401219:
  *unaff_EDI = *unaff_EDI | (uint)&stack0x00000000;
  uVar14 = in((short)param_2);
  *unaff_EDI = uVar14;
  LOCK();
  DAT_a261fc72 = *(byte *)(param_1 + -0xc);
  *(byte *)(param_1 + -0xc) = (char)in_EAX + 0x7d;
  UNLOCK();
  in_EAX = CONCAT22((short)((uint)in_EAX >> 0x10),(ushort)DAT_a261fc72);
  pbVar1 = (byte *)(unaff_EBX - 0xc);
  *pbVar1 = *pbVar1 << 1 | (char)*pbVar1 < '\0';
  bVar29 = false;
  *(byte *)(unaff_ESI + 0x11) = *(byte *)(unaff_ESI + 0x11) | (byte)((uint)param_1 >> 8);
  puVar16 = (uint *)((int)unaff_EDI + 5);
  pcVar25 = (char *)((int)unaff_ESI + 1);
  *(char *)(unaff_EDI + 1) = *(char *)unaff_ESI;
  uVar20 = param_2;
  do {
    uVar15 = unaff_EBP;
    uVar14 = CONCAT22((short)((uint)in_EAX >> 0x10),CONCAT11(0xaa,(char)in_EAX + '~' + bVar29));
    iVar21 = CONCAT22((short)((uint)uVar20 >> 0x10),
                      CONCAT11((byte)((uint)uVar20 >> 8) ^ (byte)(unaff_EBX >> 8),(char)uVar20));
    puVar28 = puVar16;
    while( true ) {
      puVar16 = puVar28;
      pcVar26 = pcVar25;
      LOCK();
      pbVar1 = (byte *)((uVar15 - 0x23) + iVar21 * 2);
      bVar3 = *pbVar1;
      *pbVar1 = (byte)(unaff_EBX >> 8);
      uVar24 = (undefined2)(unaff_EBX >> 0x10);
      uVar22 = (undefined)unaff_EBX;
      UNLOCK();
      uVar8 = *(undefined6 *)(iVar21 + 0x7d563649);
      uVar20 = (undefined4)uVar8;
      unaff_ESI = (undefined4 *)(pcVar26 + 1);
      out(*pcVar26,(short)uVar8);
      *puVar16 = *puVar16 << 0xd | *puVar16 >> 0x13;
      bVar29 = (*puVar16 & 1) != 0;
      uVar18 = (undefined)((uint)param_1 >> 8);
      uVar23 = (undefined3)(CONCAT22(uVar24,CONCAT11(bVar3,uVar22)) >> 8);
      unaff_EBX = CONCAT31(uVar23,uVar18);
      param_1 = CONCAT22((short)((uint)param_1 >> 0x10),CONCAT11(uVar22,(char)param_1));
      in_EAX = uVar14 + 0x6d3fa4a5;
      unaff_EBP = uVar15 + 1;
      if (SCARRY4(uVar15,1) == (int)unaff_EBP < 0) break;
      pcVar7 = (code *)swi(0x2f);
      puStack_4 = unaff_ESI;
      uVar31 = (*pcVar7)();
      iVar21 = (int)((ulonglong)uVar31 >> 0x20);
      uVar18 = (undefined)((uint)extraout_ECX >> 8);
      unaff_EBX = CONCAT31(uVar23,uVar18);
      bVar11 = (byte)extraout_ECX;
      param_1 = CONCAT22((short)((uint)extraout_ECX >> 0x10),CONCAT11(0x30,bVar11));
      iVar12 = (int)uVar31 + -1;
      uVar23 = (undefined3)((uint)iVar12 >> 8);
      uVar24 = (undefined2)((ulonglong)uVar31 >> 0x20);
      if ((int)unaff_EBP < 1) {
        bVar29 = false;
        _DAT_862fcd00 = iVar12;
        if (SBORROW4(unaff_EBP,1) != (int)uVar15 < 0) {
          LOCK();
          *(char *)(unaff_ESI + (int)puVar16 * 2) = (char)((ulonglong)uVar31 >> 0x20);
          UNLOCK();
          return;
        }
        in(99);
        cVar6 = *(char *)unaff_ESI;
        puVar28 = puVar16 + 1;
        uVar14 = in(uVar24);
        *puVar16 = uVar14;
        puVar16[-0x3eb5aba] = puVar16[-0x3eb5aba] & CONCAT31(uVar23,cVar6);
        uVar14 = CONCAT31(uVar23,cVar6 + '}');
        pbVar1 = (byte *)(unaff_EBX - 0x3e);
        *pbVar1 = *pbVar1 << 1 | (char)*pbVar1 < '\0';
        if (bVar3 < bVar11) goto LAB_004012be;
        bVar10 = in(uVar24);
        uVar14 = CONCAT31(uVar23,bVar10);
        pcVar25 = pcVar26 + 2;
        if (SBORROW1(bVar11,bVar3)) {
          if (SBORROW1(bVar11,bVar3)) {
            LOCK();
            bVar3 = *(byte *)((int)puVar16 + 0x7e5c85a1);
            *(byte *)((int)puVar16 + 0x7e5c85a1) = bVar10 / 0x3d;
            uVar14 = CONCAT22((short)((uint)iVar12 >> 0x10),CONCAT11(bVar3,bVar10 % 0x3d));
            UNLOCK();
            bVar29 = ((uint)unaff_ESI & 0x400) != 0;
            in_AF = ((uint)unaff_ESI & 0x10) != 0;
          }
          else {
            LOCK();
            bVar11 = pcVar26[0x7f];
            pcVar26[0x7f] = bVar3;
            UNLOCK();
            LOCK();
            bVar3 = pcVar26[0x80];
            pcVar26[0x80] = bVar11;
            unaff_EBX = (uint)CONCAT11(bVar3,uVar18);
            UNLOCK();
          }
LAB_004012be:
          while( true ) {
            LOCK();
            pcVar26[0x7f] = (char)(unaff_EBX >> 8);
            UNLOCK();
            out((short)iVar21,(char)(uVar14 + 0xed7d1486));
            LOCK();
            *(char *)(&puStack_4 + (int)(pcVar26 + 2) * 2) = (char)iVar21;
            UNLOCK();
            puVar27 = (undefined *)((int)puVar28 + (uint)bVar29 * -2 + 1);
            uVar13 = (uVar14 + 0xed7d1486 ^ 0xed) + 0x67428669;
            uVar14 = uVar13 & 0x95eb86bd;
            LOCK();
            uVar18 = *(undefined *)(param_1 + -0x15ca6608);
            *(undefined *)(param_1 + -0x15ca6608) = (char)unaff_EBX;
            UNLOCK();
            bVar11 = ((char)(uVar15 ^ 0xd53d82ea) - pcVar26[0x2c852e16]) - 1;
            sVar19 = (short)((int)uVar13 >> 0x1f);
            uVar22 = in(sVar19);
            *puVar27 = uVar22;
            out(sVar19,bVar11);
            bVar3 = 9 < (bVar11 & 0xf) | in_AF;
            bVar11 = bVar11 + bVar3 * -6;
            bVar3 = 0x9f < bVar11 | bVar3 * (bVar11 < 6);
            LOCK();
            uVar22 = *(undefined *)(param_1 + -0x5881a707);
            *(undefined *)(param_1 + -0x5881a707) = uVar18;
            unaff_EBX = (uint)CONCAT11(0xe2,uVar22);
            UNLOCK();
            puVar16 = (uint *)(((int)uVar13 >> 0x1f) + 0x6c5cfcd6);
            uVar4 = *puVar16;
            uVar5 = *puVar16;
            *puVar16 = (uVar5 - 0x7a) + (uint)bVar3;
            LOCK();
            *(char *)(param_1 * 2) = (char)((int)uVar13 >> 0x1f);
            UNLOCK();
            bVar29 = true;
            in_AF = 1;
            iVar21 = 0x460540ee;
            bVar30 = 0xffffff92 < _DAT_f35219e2;
            _DAT_f35219e2 = _DAT_f35219e2 + 0x6d;
            cVar17 = (char)((uVar15 ^ 0xd53d82ea) >> 8);
            cVar6 = cVar17 + -0x40;
            uVar15 = (uint)CONCAT11(cVar6 - bVar30,
                                    bVar11 + bVar3 * -0x60 + -2 +
                                    (0x79 < uVar4 || CARRY4(uVar5 - 0x7a,(uint)bVar3)));
            if (SBORROW1(cVar17,'@') != SBORROW1(cVar6,bVar30)) break;
            puVar28 = (uint *)(puVar27 + 1);
          }
          do {
                    // WARNING: Do nothing block with infinite loop
          } while( true );
        }
      }
      else {
        *(char *)((int)puVar16 + 1) = pcVar26[2];
        in_AF = 9 < ((byte)iVar12 & 0xf) | in_AF;
        uVar14 = CONCAT31(uVar23,(byte)iVar12 + in_AF * -6) & 0xffffff0f;
        uVar14 = CONCAT22((short)(uVar14 >> 0x10),
                          CONCAT11((char)((uint)iVar12 >> 8) - in_AF,(char)uVar14));
        uVar20 = in(uVar24);
        *(undefined4 *)((int)puVar16 + 2) = uVar20;
        pcVar25 = pcVar26 + 3;
        puVar28 = (uint *)((int)puVar16 + 6);
      }
    }
    if ((POPCOUNT(unaff_EBP & 0xff) & 1U) != 0) break;
    pcVar25 = pcVar26 + 5;
    out(*unaff_ESI,(short)uVar8);
    if (SCARRY4(uVar15,1) != (int)unaff_EBP < 0) {
      bVar10 = (byte)(uVar14 + 0x20d21a75);
      bVar9 = bVar10 - 0x33;
      bVar11 = 9 < (bVar9 & 0xf) | in_AF;
      bVar9 = bVar9 + bVar11 * -6;
      *(undefined2 *)(uVar15 + 1) = in_SS;
      LOCK();
      cVar6 = pcVar25[(int)puVar16 * 8];
      pcVar25[(int)puVar16 * 8] = (char)uVar8;
      UNLOCK();
      LOCK();
      *(char *)CONCAT22((short)(uVar14 + 0x20d21a75 >> 0x10),
                        CONCAT11(bVar3,bVar9 + (0x9f < bVar9 | 0x32 < bVar10 | bVar11 * (bVar9 < 6))
                                               * -0x60)) = cVar6;
      UNLOCK();
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
  } while( true );
  LOCK();
  puVar2 = (undefined4 *)((int)puVar16 * 2 + -0x23039293);
  param_2 = *puVar2;
  *puVar2 = uVar20;
  UNLOCK();
  bVar29 = SCARRY4(param_1,1);
  param_1 = param_1 + 1;
  if (bVar29 != param_1 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar14 = in((short)param_2);
  *puVar16 = uVar14;
  unaff_EBX = CONCAT22(uVar24,CONCAT11(bVar3,uVar18));
  unaff_EDI = (uint *)((int)puVar16 + 5);
  *(char *)(puVar16 + 1) = (char)in_EAX;
  goto LAB_00401219;
}


