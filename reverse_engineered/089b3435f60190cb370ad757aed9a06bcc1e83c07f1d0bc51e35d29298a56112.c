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
// WARNING: Instruction at (ram,0x00401289) overlaps instruction at (ram,0x00401288)
// 
// WARNING: Unable to track spacebase fully for stack

void __fastcall FUN_00401219(int param_1)

{
  char *pcVar1;
  int **ppiVar2;
  undefined *puVar3;
  longlong lVar4;
  ushort *puVar5;
  undefined uVar6;
  char cVar7;
  byte bVar8;
  ushort uVar9;
  undefined4 in_EAX;
  uint *puVar10;
  byte *pbVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  undefined3 uVar18;
  int3 iVar19;
  undefined *puVar15;
  undefined4 *puVar16;
  undefined4 uVar17;
  char cVar21;
  uint uVar20;
  uint extraout_ECX;
  uint extraout_ECX_00;
  int extraout_ECX_01;
  uint extraout_ECX_02;
  short sVar22;
  byte *pbVar23;
  int iVar24;
  int iVar25;
  uint extraout_EDX;
  byte bVar26;
  byte bVar29;
  undefined4 unaff_EBX;
  byte *pbVar27;
  int *piVar28;
  undefined4 *unaff_EBP;
  undefined4 *puVar30;
  undefined4 *puVar31;
  undefined4 *puVar32;
  uint unaff_EDI;
  uint uVar33;
  int *piVar34;
  undefined2 in_CS;
  undefined2 in_DS;
  undefined2 in_GS;
  int unaff_FS_OFFSET;
  bool bVar35;
  bool bVar36;
  byte bVar37;
  char cVar38;
  byte in_AF;
  byte bVar39;
  undefined8 uVar40;
  uint unaff_retaddr;
  undefined4 *puStack_c;
  undefined4 *puStack_4;
  
  bVar26 = (byte)in_EAX | 0xbc;
  bVar39 = 9 < (bVar26 & 0xf) | in_AF;
  uVar12 = CONCAT31((int3)((uint)in_EAX >> 8),bVar26 + bVar39 * -6) & 0xffffff0f;
  iVar24 = CONCAT22((short)(uVar12 >> 0x10),
                    CONCAT11((char)((uint)in_EAX >> 8) - bVar39,(char)uVar12));
  pcVar1 = (char *)(iVar24 + 0x1d);
  cVar38 = *pcVar1;
  cVar21 = (char)((uint)param_1 >> 8);
  cVar7 = *pcVar1 + cVar21;
  *pcVar1 = cVar7 + bVar39;
  if (*pcVar1 < '\0') {
    while( true ) {
      unaff_EBP = (undefined4 *)((int)unaff_EBP + 1);
      param_1 = param_1 + -1;
      if (param_1 == 0 || unaff_EBP != (undefined4 *)0x0) break;
      bVar39 = 9 < (byte)iVar24 | bVar39;
      uVar12 = CONCAT31((int3)((uint)iVar24 >> 8),(byte)iVar24 + bVar39 * -6) & 0xffffff0f;
      bVar26 = (byte)uVar12;
      cVar38 = (char)((uint)iVar24 >> 8) - bVar39;
      iVar24 = CONCAT22((short)(uVar12 >> 0x10),CONCAT11(cVar38,bVar26));
      pcVar1 = (char *)(iVar24 + -0x22);
      *pcVar1 = *pcVar1 + (char)((uint)param_1 >> 8) + bVar39;
      bVar39 = 9 < bVar26 | bVar39;
      uVar12 = CONCAT31((int3)((uint)iVar24 >> 8),bVar26 + bVar39 * -6) & 0xffffff0f;
      iVar24 = CONCAT22((short)(uVar12 >> 0x10),CONCAT11(cVar38 - bVar39,(char)uVar12));
    }
    LOCK();
    *(int *)iVar24 = iVar24;
    UNLOCK();
  }
  else {
    puVar10 = *(uint **)(unaff_EDI - 0x40);
    if ((SCARRY1(cVar38,cVar21) != SCARRY1(cVar7,bVar39)) != *pcVar1 < '\0') {
      pbVar11 = (byte *)(unaff_EDI + 0x4d68502f);
      bVar26 = *pbVar11;
      *pbVar11 = *pbVar11 + (byte)puVar10;
      unaff_EBX = 0xffffff99;
      unaff_EBP = (undefined4 *)((int)unaff_EBP + -1);
      puVar10 = (uint *)((int)puVar10 + (0x6197efc1 - (uint)CARRY1(bVar26,(byte)puVar10)));
      bVar26 = (byte)param_1 & 0x1f;
      *puVar10 = *puVar10 << bVar26 | *puVar10 >> 0x20 - bVar26;
    }
    pbVar23 = (byte *)((int)puVar10 >> 0x1f);
    uVar12 = (uint)(*(uint *)(unaff_FS_OFFSET + unaff_EDI) < unaff_EDI);
    uVar33 = (unaff_EDI - 0x3c) + *(uint *)(param_1 + -0x536ce4cf);
    puVar32 = (undefined4 *)(uVar33 + uVar12);
    unaff_EBP[4] = (unaff_EBP[4] - (int)pbVar23) -
                   (uint)(CARRY4(unaff_EDI - 0x3c,*(uint *)(param_1 + -0x536ce4cf)) ||
                         CARRY4(uVar33,uVar12));
    bVar26 = (char)unaff_EBX + DAT_5fd83857;
    pbVar11 = (byte *)CONCAT31((int3)((uint)unaff_EBX >> 8),bVar26);
    bVar39 = 9 < (((byte)puVar10 | 0xf5) & 0xf) | bVar39;
    if ((char)bVar26 >= '\0') {
      puVar30 = (undefined4 *)*puVar32;
      if (SCARRY1((char)unaff_EBX,DAT_5fd83857) != (char)bVar26 < '\0') {
        DAT_f568528f = DAT_f568528f + (char)((uint)unaff_EBX >> 8);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      bVar35 = *pbVar11 < bVar26;
      *pbVar11 = *pbVar11 - bVar26;
      iVar24 = CONCAT31((int3)(unaff_EDI >> 8),DAT_25c01d2a);
      uVar12 = puVar32[1];
      if (iVar24 < 1) {
        if (param_1 != 1 && iVar24 == 1) {
LAB_004012b2_1:
          bVar36 = uVar12 < 0x1d021355 || uVar12 + 0xe2fdecab < (uint)bVar35;
          pbVar11 = (byte *)((uVar12 + 0xe2fdecab) - (uint)bVar35);
          bVar39 = *pbVar11;
          bVar26 = *pbVar11 + (byte)pbVar11;
          *pbVar11 = bVar26 + bVar36;
          pbVar11[-0x75e8103f - (uint)(CARRY1(bVar39,(byte)pbVar11) || CARRY1(bVar26,bVar36))] =
               pbVar11[-0x75e8103f - (uint)(CARRY1(bVar39,(byte)pbVar11) || CARRY1(bVar26,bVar36))]
               - 0x1d;
          *puVar30 = 0x993f1d1f;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        puVar15 = *(undefined **)(uint *)(uVar12 + 0x10d71d2a);
        iVar24 = -*(uint *)(uVar12 + 0x10d71d2a);
        *(undefined2 *)((int)&puStack_4 + iVar24) = in_DS;
        *(undefined2 *)(&stack0xfffffff8 + iVar24) = in_CS;
        *(uint *)((int)&puStack_c + iVar24) =
             (uVar12 + 0xfa536cc1) - (uint)(&stack0x00000000 < puVar15);
      }
      else if (param_1 != 1 && iVar24 == 1) {
        puVar32 = (undefined4 *)0x3f2325d7;
        bVar26 = *pbVar23;
        bVar37 = *pbVar23 + (byte)uVar12;
        *pbVar23 = bVar37 + bVar35;
        uVar12 = (uVar12 + 0x51636a4e) -
                 (uint)(CARRY1(bVar26,(byte)uVar12) || CARRY1(bVar37,bVar35));
        uVar33 = (uint)puVar30 >> 0x18;
        if (uVar33 != 0) goto code_r0x00401323;
        pbVar27 = (byte *)((longlong)iRamae9095b2 * 0x4e38efc1);
        uVar13 = (uint)(short)CONCAT31((int3)(uVar12 >> 8),pbVar27[uVar12 & 0xff]);
        uVar20 = (uint)((longlong)(int)pbVar27 != (longlong)iRamae9095b2 * 0x4e38efc1);
        uVar12 = uVar13 + 0x487fbcc1;
        bVar35 = uVar13 < 0xb780433f || uVar12 < uVar20;
        uVar12 = uVar12 - uVar20;
        uVar20 = param_1 - 2;
        pbVar11 = (byte *)(uVar12 + 0x2c);
        bVar37 = (byte)(uVar20 >> 8);
        bVar26 = *pbVar11 + bVar37;
        bVar37 = CARRY1(*pbVar11,bVar37) || CARRY1(bVar26,bVar35);
        *pbVar11 = bVar26 + bVar35;
        bVar35 = (POPCOUNT(*pbVar11) & 1U) == 0;
        puVar30 = (undefined4 *)*unaff_EBP;
        bVar26 = (byte)uVar12;
        if (bVar35) {
          bVar39 = 9 < (bVar26 & 0xf) | bVar39;
          uVar33 = CONCAT31((int3)(uVar12 >> 8),bVar26 + bVar39 * -6) & 0xffffff0f;
          puVar31 = (undefined4 *)
                    CONCAT22((short)(uVar33 >> 0x10),
                             CONCAT11((char)(uVar12 >> 8) - bVar39,(char)uVar33));
          uVar12 = unaff_retaddr;
          piVar34 = (int *)0x0;
          cVar38 = bVar39;
          uVar33 = uVar20;
          if (bVar35) goto code_r0x004013de;
          if ((bool)bVar39 || *pbVar11 == 0) {
            out((short)((int)puVar10 >> 0x1f),puVar31);
            uVar14 = (int)(undefined *)((int)puVar31 + -0x6065c011) - (int)(undefined *)(uint)bVar39
            ;
            uVar33 = (uint)((undefined *)0x6065c010 < puVar31 &&
                           (undefined *)(uint)bVar39 <= (undefined *)((int)puVar31 + -0x6065c011));
            uVar13 = uVar14 + 0x2516294a;
            uVar12 = uVar13 - uVar33;
            puVar32 = (undefined4 *)0x3f2325d8;
            *unaff_EBP = 0x1ce6361d;
            iRam3f2325d8 = (iRam3f2325d8 - uVar20) - (uint)(uVar14 < 0xdae9d6b6 || uVar13 < uVar33);
            pbVar11 = pbVar27 + 0x7065c023;
            bVar26 = *pbVar11;
            *pbVar11 = *pbVar11 << 1 | (char)bVar26 < '\0';
            uVar20 = param_1 - 3;
            cVar38 = (char)bVar26 < '\0';
            uVar33 = unaff_retaddr;
            if (uVar20 != 0) goto code_r0x004013de;
            puVar31 = unaff_EBP + -1;
            unaff_EBP[-1] = 0xe2687a23;
            cRam0ff8c368 = cRam0ff8c368 + (char)((int)puVar10 >> 0x1f) + -1;
            bVar39 = 9 < ((char)uVar12 + 0x97U & 0xf) | bVar39;
            uVar20 = uVar12 >> 8 & 0xff;
            puVar30 = (undefined4 *)(*(int *)((int)unaff_EBP + 0x19) * 0x191ce636);
          }
          pbVar27 = pbVar27 + -0x6f9243f5;
          bVar35 = (char)*pbVar27 < '\0';
          *pbVar27 = *pbVar27 << 1 | bVar35;
          bVar26 = (byte)puVar31 + 0xb6;
          bVar37 = bVar26 - bVar35;
          bRam00000000 = bRam00000000 >> 1 | ((byte)puVar31 < 0x4a || bVar26 < bVar35) << 7;
          bVar39 = 9 < (bVar37 & 0xf) | bVar39;
          uVar12 = CONCAT31((int3)((uint)puVar31 >> 8),bVar37 + bVar39 * -6) & 0xffffff0f;
          uVar6 = (undefined)uVar12;
          iVar24 = CONCAT22((short)(uVar12 >> 0x10),
                            CONCAT11((char)((uint)puVar31 >> 8) - bVar39,uVar6));
          pcVar1 = (char *)(iVar24 + -10);
          *pcVar1 = *pcVar1 + (char)(uVar20 >> 8) + bVar39;
          uVar18 = (undefined3)((uint)iVar24 >> 8);
          uVar12 = CONCAT31(uVar18,uVar6) ^ 199;
          iVar24 = (int)uVar12 >> 0x1f;
          piVar28 = (int *)0x4;
          bVar26 = (char)uVar12 + 1;
          bVar39 = 9 < (bVar26 & 0xf) | bVar39;
          uVar12 = CONCAT31(uVar18,bVar26);
          do {
            cVar38 = '\0';
            *(byte *)(iVar24 + -1) = *(byte *)(iVar24 + -1) ^ 0x32;
            piVar34 = piVar28;
            uVar33 = uVar20;
code_r0x004013de:
            iVar19 = (int3)(uVar12 >> 8);
            uVar13 = CONCAT31(iVar19,((char)uVar12 + '9') - cVar38);
            iVar24 = (int)iVar19 >> 0x17;
            piVar28 = piVar34 + 1;
            uVar12 = uVar33;
          } while ((POPCOUNT(uVar13 - *piVar34 & 0xff) & 1U) == 0);
          bVar35 = *(byte *)((int)puVar30 + 0x26) < (byte)(iVar19 >> 7);
          pbVar11 = (byte *)(iVar24 + 0x1d);
          bVar37 = (byte)(uVar20 >> 8);
          bVar26 = *pbVar11 + bVar37;
          bVar36 = CARRY1(*pbVar11,bVar37) || CARRY1(bVar26,bVar35);
          *pbVar11 = bVar26 + bVar35;
          do {
            piVar34 = piVar28 + 0x77bccda;
            bVar26 = *(byte *)piVar34;
            bVar37 = *(byte *)piVar34 + (byte)iVar24;
            *(byte *)piVar34 = bVar37 + bVar36;
            iVar24 = uVar13 + 0x1d10ecd7 +
                     (uint)(CARRY1(bVar26,(byte)iVar24) || CARRY1(bVar37,bVar36));
            bVar39 = 9 < ((byte)iVar24 & 0xf) | bVar39;
            uVar12 = CONCAT31((int3)((uint)iVar24 >> 8),(byte)iVar24 + bVar39 * -6) & 0xffffff0f;
            sVar22 = (short)(uVar12 >> 0x10);
            bVar26 = (byte)uVar12;
            iVar25 = (int)sVar22 >> 0xf;
            cVar38 = (bVar26 - 0x37) + (bVar26 < *(byte *)piVar28);
            piVar34 = (int *)((int)piVar28 + 2);
            uVar6 = in((short)iVar25);
            *(undefined *)((int)piVar28 + 1) = uVar6;
            puVar15 = (undefined *)
                      CONCAT31((int3)(CONCAT22(sVar22,CONCAT11((char)((uint)iVar24 >> 8) - bVar39,
                                                               bVar26)) >> 8),cVar38 + '\x01');
            if (uVar20 != 1) {
              puVar3 = (undefined *)(uint)(cVar38 != -1);
              bVar26 = puVar15 < (undefined *)0x696def3f || puVar15 + -0x696def3f < puVar3;
              uVar13 = (int)(puVar15 + -0x696def3f) - (int)puVar3;
              puVar31 = puVar30;
              puStack_4 = puVar30;
              goto code_r0x0040144b;
            }
            *(byte *)((int)piVar28 + 0x1def2b6a) =
                 *(byte *)((int)piVar28 + 0x1def2b6a) | (byte)iVar25;
            puVar30[4] = puVar30[4] + iVar25;
            puStack_4 = (undefined4 *)0xe11def2f;
            uVar18 = (undefined3)((uint)piVar34 >> 8);
            bVar26 = (byte)puVar30;
            bVar35 = CARRY1(bRame2ae993f,bVar26);
            bRame2ae993f = bRame2ae993f + bVar26;
            sVar22 = (short)iVar25 + -1;
            cVar38 = in(sVar22);
            piVar28 = (int *)CONCAT31((int3)((uint)puVar30 >> 8),(bVar26 + 0xb9) - bVar35);
            pcVar1 = (char *)(CONCAT31(uVar18,cVar38) + 0x14);
            *pcVar1 = *pcVar1 + (bVar26 < 0x47 || (byte)(bVar26 + 0xb9) < bVar35);
            puVar31 = (undefined4 *)*puVar30;
            piVar34 = (int *)(puVar15 + 1);
            uVar6 = in(sVar22);
            *puVar15 = uVar6;
            puVar5 = (ushort *)((int)piVar34 * 9);
            *puVar5 = *puVar5 + (ushort)(cVar38 != -1) * (((ushort)puVar31 & 3) - (*puVar5 & 3));
            *puVar30 = CONCAT31(uVar18,cVar38 + '\x01');
            *piVar28 = (*piVar28 + 0x4a) - (uint)(cVar38 != -1);
            uVar40 = func_0xd7f6f99e();
            uVar12 = (uint)((ulonglong)uVar40 >> 0x20);
            bVar39 = 9 < ((byte)uVar40 & 0xf) | bVar39;
            uVar33 = CONCAT31((int3)((ulonglong)uVar40 >> 8),(byte)uVar40 + bVar39 * '\x06') &
                     0xffffff0f;
            puVar16 = (undefined4 *)
                      CONCAT22((short)(uVar33 >> 0x10),
                               CONCAT11((char)((ulonglong)uVar40 >> 8) + bVar39,(char)uVar33));
            puVar30 = (undefined4 *)
                      CONCAT31((int3)((uint)((int)piVar28 + 1) >> 8),~(byte)((int)piVar28 + 1));
            puVar10 = (uint *)((int)puVar32 + (int)puVar16 * 2 + 0x3f);
            bVar37 = CARRY4(*puVar10,(uint)puVar31) ||
                     CARRY4(*puVar10 + (int)puVar31,(uint)(puVar16 < (undefined4 *)0x8493da94));
            *puVar10 = *puVar10 + (int)puVar31 + (uint)(puVar16 < (undefined4 *)0x8493da94);
            uVar20 = extraout_ECX_00;
code_r0x00401442:
            iVar24 = uVar12 - 1;
            bVar37 = ((char)puVar32 + '-') - bVar37;
            bVar26 = 0x94 < bVar37;
            uVar13 = CONCAT31((int3)((uint)puVar32 >> 8),bVar37 + 0x6b);
            puVar32 = puVar16;
            if (!(bool)bVar26) {
code_r0x0040144b:
              in(0x68);
              bVar39 = ((CONCAT11((byte)uVar13 / 0x98,(byte)uVar13 % 0x98) + 0x969210c1) -
                        (uint)bVar26 >> 8 & 0x10) != 0;
              uVar12 = func_0x939a0ac9();
              bVar26 = 0;
              *(uint *)((int)piVar34 + 0x2d9b00f6) =
                   *(uint *)((int)piVar34 + 0x2d9b00f6) & (int)(uVar12 | 0x83913fe1) >> 0x1f;
              in(0x3e);
              uVar40 = func_0x1f775d60();
              uVar12 = (uint)((ulonglong)uVar40 >> 0x20);
              puVar16 = (undefined4 *)CONCAT31((int3)((ulonglong)uVar40 >> 8),-bVar26);
              iRam0109d61f = (iRam0109d61f - (int)piVar34) - (uint)bVar26;
              ppiVar2 = (int **)(puVar16 + 0xb7bcf1a);
              bVar37 = *ppiVar2 < piVar34;
              *ppiVar2 = (int *)((int)*ppiVar2 - (int)piVar34);
              cVar38 = *ppiVar2 == (int *)0x0;
              bVar26 = POPCOUNT((uint)*ppiVar2 & 0xff);
              uVar20 = extraout_ECX_01 - 1;
              if (uVar20 == 0 || !(bool)cVar38) {
                do {
                  bVar35 = (bVar26 & 1) == 0;
                  if (uVar20 == 1 || (bool)cVar38 == false) {
                    while( true ) {
                      uVar9 = (ushort)(byte)((char)puVar16 + (char)((uint)puVar16 >> 8) * -0x40);
                      bVar36 = false;
                      cVar38 = uVar9 == 0;
                      bVar35 = (POPCOUNT(uVar9) & 1U) == 0;
                      puStack_c = (undefined4 *)0x401496;
                      func_0x1d5052b7();
                      in(6);
                      puStack_4 = (undefined4 *)0xe92def2f;
                      puVar16 = (undefined4 *)
                                CONCAT22((short)((uint)&puStack_c >> 0x10),
                                         CONCAT11(0x55,(char)&puStack_c));
                      uVar20 = extraout_ECX_02;
                      uVar12 = extraout_EDX;
                      puStack_c = puVar31;
                      if (bVar36) break;
                      if (!bVar35) goto code_r0x004014a5;
                      bVar37 = puVar16 < (undefined4 *)0xebe1b6e1;
                      puVar16 = (undefined4 *)((int)puVar16 + 0x141e491f);
                    }
                  }
                  else {
                    if (uVar20 != 1) goto code_r0x0040147b;
                    bVar26 = *(byte *)(puVar31 + -0x1c);
                    *(byte *)(puVar31 + -0x1c) = bVar26 << 4 | (byte)(CONCAT11(bVar37,bVar26) >> 5);
                    bVar37 = (bVar26 & 0x10) != 0;
                    uVar20 = 0;
                  }
                  if (bVar35) {
                    do {
                      uVar12 = uVar12 ^ (uint)&puStack_4;
                      while( true ) {
                        if (uVar20 - 1 != 0 && (undefined4 *)((int)puVar31 + 1) == (undefined4 *)0x0
                           ) break;
                        LOCK();
                        uVar17 = *puVar16;
                        *puVar16 = puVar16;
                        UNLOCK();
                        out(*(undefined *)puVar32,(short)uVar12);
                        bVar39 = 9 < ((byte)uVar17 & 0xf) | bVar39;
                        bVar8 = (byte)uVar17 + bVar39 * -6 & 0xf;
                        bVar26 = *(byte *)puVar30;
                        bVar29 = (byte)((uint)puVar30 >> 8);
                        bVar37 = *(char *)puVar30 + bVar29;
                        *(byte *)puVar30 = bVar37 + bVar39;
                        if ((int)puVar31 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
                          halt_baddata();
                        }
                        uVar12 = 0xc0e397ec;
                        cRamc0e397ec = cRamc0e397ec + (char)puVar30 + -1 +
                                       (CARRY1(bVar26,bVar29) || CARRY1(bVar37,bVar39));
                        iVar24 = in(0x97ec);
                        iVar25 = uVar20 - 2;
                        if (iVar25 == 0 || bVar8 != 0x91) {
                          out(0x97ec,(char)iVar24);
                          sVar22 = 1 - (*(ushort *)piVar34 & 3);
                          *(ushort *)piVar34 = *(short *)piVar34 + (ushort)(bVar8 < 0x91) * sVar22;
                          uVar17 = in(0x97ed);
                          if (iVar25 != 1 && 0 < sVar22) {
                    // WARNING: Bad instruction - Truncating control flow here
                            halt_baddata();
                          }
                          out(0x97ed,(char)uVar17);
                          in((short)((int)&puStack_4 >> 0x1f));
                    // WARNING: Bad instruction - Truncating control flow here
                          halt_baddata();
                        }
                        uVar20 = CONCAT31((int3)((uint)iVar25 >> 8),
                                          ((char)iVar25 - (char)((uint)iVar24 >> 8)) -
                                          (bVar8 < 0x91));
                        lVar4 = (longlong)iRam5851e94a * -0x5a119d39;
                        puVar30 = (undefined4 *)
                                  CONCAT22((short)((ulonglong)lVar4 >> 0x10),(ushort)(byte)lVar4);
                        puVar16 = (undefined4 *)
                                  ((iVar24 + 0x2bccb1a0) -
                                  (uint)((char)((ulonglong)lVar4 >> 8) < '\0'));
                        puVar32 = (undefined4 *)((int)puVar32 + 1);
                      }
                      puVar32 = (undefined4 *)((int)puVar32 + -1);
                      uVar20 = uVar20 - 1;
                      puVar31 = (undefined4 *)((int)puVar31 + 1);
                    } while( true );
                  }
                  uVar20 = uVar20 - 1;
                  if (uVar20 == 0 || cVar38 == '\0') {
                    return;
                  }
                  puVar16 = (undefined4 *)
                            CONCAT22((short)((uint)puVar16 >> 0x10),CONCAT11(0x55,(char)puVar16));
code_r0x004014a5:
                  iVar24 = (int)puVar16 + (0x6faa4be8 - (uint)bVar37);
                  bVar26 = (byte)iVar24;
                  bVar37 = bVar26 < 0xe7;
                  cVar7 = bVar26 + 0x19;
                  puVar16 = (undefined4 *)CONCAT31((int3)((uint)iVar24 >> 8),cVar7);
                  cVar38 = cVar7 == '\0';
                  bVar26 = POPCOUNT(cVar7);
                  *piVar34 = (int)puVar16;
                  uVar12 = (uint)CONCAT11(0xe1,(char)puStack_4);
                  piVar34 = piVar34 + 1;
                } while( true );
              }
              goto code_r0x00401442;
            }
            pbVar11 = (byte *)(uVar12 + 0x1c);
            bVar8 = (byte)(uVar20 >> 8);
            bVar37 = *pbVar11 + bVar8;
            bVar36 = CARRY1(*pbVar11,bVar8) || CARRY1(bVar37,bVar26);
            *pbVar11 = bVar37 + bVar26;
            puVar30 = puVar31;
            piVar28 = piVar34;
          } while( true );
        }
        if (*pbVar11 == 0) {
          uVar40 = CONCAT44(CONCAT31((int3)((int)puVar10 >> 0x1f),0x2a),uVar12);
          unaff_EBP = puVar30;
          do {
            puVar10 = (uint *)((ulonglong)uVar40 >> 0x20);
            puVar15 = (undefined *)CONCAT22((short)((uint)puVar32 >> 0x10),in_GS);
            unaff_EBP = (undefined4 *)((int)unaff_EBP + -1);
            bVar26 = pbVar27[uVar33 & 0xff];
            *(uint *)(uVar20 + 0x1d) = *(uint *)(uVar20 + 0x1d) ^ (uint)unaff_EBP;
            bVar39 = 9 < (bVar26 & 0xf) | bVar39;
            uVar12 = CONCAT31((int3)(uVar33 >> 8),bVar26 + bVar39 * -6) & 0xffffff0f;
            pbVar11 = (byte *)CONCAT22((short)(uVar12 >> 0x10),
                                       CONCAT11((char)(uVar33 >> 8) - bVar39,(char)uVar12));
            puVar32 = (undefined4 *)(puVar15 + 1);
            uVar33 = CONCAT31((int3)((uint)pbVar27 >> 8),*puVar15);
            uVar12 = *puVar10;
            uVar20 = *puVar10;
            *puVar10 = uVar20 + uVar33 + (uint)bVar39;
            out((short)((ulonglong)uVar40 >> 0x20),uVar33);
            uVar12 = (((int)uVar40 - (uint)bVar37) + -0x11caf8f1) -
                     (uint)(CARRY4(uVar12,uVar33) || CARRY4(uVar20 + uVar33,(uint)bVar39));
code_r0x00401323:
            puStack_4 = (undefined4 *)0x401326;
            bVar26 = (**(code **)(uVar12 - 0x7d))();
            bVar37 = bVar26 < 0xb6;
            puStack_4 = (undefined4 *)0x40132d;
            uVar40 = func_0xd7f6f886();
            uVar20 = extraout_ECX;
            pbVar27 = pbVar11;
          } while( true );
        }
        *unaff_EBP = puVar30;
        bVar35 = CARRY1(*pbVar23,bVar26) || CARRY1(*pbVar23 + bVar26,bVar37);
        *pbVar23 = *pbVar23 + bVar26 + bVar37;
        puVar30 = (undefined4 *)0x0;
        goto LAB_004012b2_1;
      }
      return;
    }
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
code_r0x0040147b:
  bVar26 = 9 < ((byte)puVar16 & 0xf) | bVar39;
  uVar13 = (uint)((byte)puVar16 + bVar26 * '\x06' & 0xf);
  goto code_r0x0040144b;
}



void __fastcall entry(int param_1)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x1f85;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x3f1d6810;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xcf4;
  puVar2 = &DAT_0042b000;
  do {
    *puVar2 = *puVar2 ^ 0x6214192a;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219(param_1);
  return;
}


