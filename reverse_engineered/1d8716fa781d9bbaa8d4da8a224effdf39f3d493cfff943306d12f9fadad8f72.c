typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
float10
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
// WARNING: Instruction at (ram,0x004013fe) overlaps instruction at (ram,0x004013fc)
// 
// WARNING (jumptable): Unable to track spacebase fully for stack
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x00401360)

float10 * __fastcall FUN_00401219(float10 *__return_storage_ptr__,undefined4 param_1)

{
  byte **ppbVar1;
  byte *pbVar2;
  longlong lVar3;
  code *pcVar4;
  byte bVar5;
  char cVar6;
  undefined uVar7;
  char cVar8;
  short sVar9;
  float10 *in_EAX;
  undefined4 *puVar10;
  undefined3 uVar13;
  float10 *pfVar12;
  byte bVar14;
  byte bVar17;
  int iVar15;
  uint *extraout_ECX;
  uint *puVar16;
  undefined2 uVar18;
  uint uVar19;
  uint uVar20;
  uint *puVar21;
  undefined4 uVar22;
  int *unaff_EBX;
  undefined *puVar23;
  int iVar24;
  int *piVar25;
  undefined *puVar26;
  int *piVar27;
  int *piVar28;
  int *piVar29;
  undefined4 *puVar30;
  undefined4 *unaff_EBP;
  undefined4 *puVar31;
  undefined4 *puVar32;
  undefined4 *puVar33;
  undefined4 *unaff_ESI;
  int iVar34;
  undefined4 *unaff_EDI;
  byte *pbVar35;
  byte *pbVar36;
  undefined2 in_SS;
  undefined2 in_DS;
  byte in_CF;
  bool bVar37;
  byte in_AF;
  bool bVar38;
  undefined8 uVar39;
  uint *puVar11;
  
  bVar14 = (byte)__return_storage_ptr__;
  bVar17 = (byte)((uint)__return_storage_ptr__ >> 8);
  bVar5 = bVar17 - bVar14;
  iVar24 = CONCAT22((short)((uint)__return_storage_ptr__ >> 0x10),CONCAT11(bVar5 - in_CF,bVar14));
  iVar15 = iVar24 + 1;
  if (SCARRY4(iVar24,1) != iVar15 < 0) {
    return in_EAX;
  }
  sVar9 = (short)((uint)in_EAX >> 0x10);
  pfVar12 = (float10 *)
            CONCAT22(sVar9,(ushort)in_EAX +
                           (ushort)(bVar17 < bVar14 || bVar5 < in_CF) *
                           (((ushort)iVar15 & 3) - ((ushort)in_EAX & 3)));
  uVar19 = (int)sVar9 >> 0xf;
  puVar31 = (undefined4 *)*unaff_EBP;
  piVar27 = unaff_EBP + 1;
  piVar25 = (int *)((int)pfVar12 + -0x24);
  bVar37 = (undefined *)*piVar25 < unaff_EBP + 1;
  *piVar25 = *piVar25 - (int)(unaff_EBP + 1);
  uVar20 = uVar19;
  puVar33 = unaff_EBP + 1;
  if (*piVar25 == 0) {
LAB_0040126a:
    uVar22 = *piVar27;
    bVar5 = (char)(uVar20 >> 8) + (char)uVar22 + bVar37;
    uVar18 = CONCAT11(bVar5,(char)uVar20);
    puVar33 = (undefined4 *)((int)unaff_EDI + 1);
    uVar7 = in(uVar18);
    *(undefined *)unaff_EDI = uVar7;
    puVar32 = (undefined4 *)*puVar31;
    puVar31 = puVar31 + 1;
    if (bVar5 != 0) {
      uVar18 = CONCAT11(bVar5 & (char)uVar22 - 1U,(char)uVar20);
      uVar7 = in(uVar18);
      *(undefined *)puVar33 = uVar7;
      uVar7 = in(uVar18);
      *(undefined *)((int)unaff_EDI + 2) = uVar7;
      return pfVar12;
    }
    out(uVar18,pfVar12);
  }
  else {
    while( true ) {
      piVar27 = puVar33;
      bVar5 = (char)pfVar12 + -10 + bVar37;
      iVar24 = CONCAT31((int3)((uint)pfVar12 >> 8),bVar5);
      *(undefined **)((undefined *)((int)piVar27 + 0x52) + (int)unaff_EDI) =
           (undefined *)
           (*(int *)((undefined *)((int)piVar27 + 0x52) + (int)unaff_EDI) + (int)unaff_EDI);
      puVar33 = (undefined4 *)((int)piVar27 + -4);
      puVar32 = (undefined4 *)((int)piVar27 + -4);
      *(undefined4 **)((int)piVar27 + -4) = puVar31;
      cVar6 = '\x15';
      do {
        puVar31 = puVar31 + -1;
        puVar33 = puVar33 + -1;
        *puVar33 = *puVar31;
        cVar6 = cVar6 + -1;
      } while ('\0' < cVar6);
      *(undefined **)((int)piVar27 + -0x5c) = (undefined *)((int)piVar27 + -4);
      if (SCARRY4(iVar15,1) == iVar15 + 1 < 0) break;
      pfVar12 = (float10 *)
                CONCAT22((short)((uint)pfVar12 >> 0x10),(ushort)bVar5 * (ushort)*(byte *)unaff_ESI);
      puVar21 = (uint *)((undefined *)((int)piVar27 + -0x6c63) + (int)unaff_EDI);
      bVar37 = CARRY4(*puVar21,(uint)unaff_EDI);
      *puVar21 = (uint)(*puVar21 + (int)unaff_EDI);
      iVar15 = iVar15 + 1;
      puVar33 = (undefined4 *)((int)piVar27 + -0x6cb5);
      puVar31 = (undefined4 *)((int)piVar27 + -4);
    }
    unaff_ESI[0x14121026] =
         (unaff_ESI[0x14121026] - iVar24) -
         (uint)((byte)((uint)pfVar12 >> 8) < *(byte *)(iVar15 + -0x37));
    *(undefined *)(iVar24 + 0x48) = 0;
    uVar20 = uVar19 + 1;
    *unaff_EDI = *unaff_ESI;
    puVar33 = (undefined4 *)((int)unaff_EDI + 5);
    uVar7 = in((short)uVar20);
    *(undefined *)(unaff_EDI + 1) = uVar7;
    iVar15 = *(int *)((int)piVar27 + -0x6cb5);
    lVar3 = (longlong)(int)((int)piVar27 + -0x6cb1) * 0x5829362e;
    bVar37 = (int)lVar3 != lVar3;
    puVar31 = (undefined4 *)((int)piVar27 + -0x6cb2);
    LOCK();
    bVar5 = *(byte *)unaff_EBX;
    *(byte *)unaff_EBX = 0x68;
    pfVar12 = (float10 *)CONCAT31(0x16415c,bVar5);
    UNLOCK();
    if ((int)((int)piVar27 + -0x6cb1) < 1) {
      return pfVar12;
    }
    if ((int)lVar3 == 0) {
      *(undefined4 *)((int)piVar27 + -0x6cb6) = 0;
      *(byte *)((int)piVar27 + 0x32) =
           *(byte *)((int)piVar27 + 0x32) ^ (byte)((ulonglong)lVar3 >> 8);
      in_AF = 9 < (bVar5 & 0xf) | in_AF;
      *unaff_EBX = *unaff_EBX - uVar20;
      *(undefined **)((int)piVar27 + -0x6cba) = (undefined *)((int)piVar27 + -4);
      puVar31 = (undefined4 *)((uint)((int)piVar27 + -4) ^ (uint)puVar33);
      piVar28 = (int *)((int)piVar27 + -0x6cbe);
      *(undefined2 *)((int)piVar27 + -0x6cbe) = in_SS;
      puVar32 = (undefined4 *)((int)unaff_EDI + 6);
      uVar7 = in((short)uVar20);
      *(undefined *)puVar33 = uVar7;
      uVar20 = uVar19 + 2;
      piVar27 = (int *)(*piVar28 + -4);
      *(undefined2 *)(*piVar28 + -4) = in_SS;
    }
    else {
      if (SBORROW4((int)((int)piVar27 + -0x6cb1),1) != (int)((int)piVar27 + -0x6cb2) < 0)
      goto LAB_004012d1_2;
      puVar31 = *(undefined4 **)((int)piVar27 + -4);
      puVar32 = puVar33;
      unaff_EDI = puVar33;
      if (piVar27 != (int *)0x6cb2) goto LAB_0040126a;
    }
    uVar7 = in((short)uVar20);
    *(undefined *)puVar32 = uVar7;
    iVar24 = *piVar27;
    piVar25 = (int *)(iVar24 + (int)puVar31 * 2);
    *piVar25 = *piVar25 >> 1;
    puVar32 = (undefined4 *)((uint)puVar31 | *(uint *)(iVar15 * 2 + -0x38));
    puVar33 = (undefined4 *)&DAT_09becdef;
    *(undefined4 *)(iVar24 + -4) = 0x1978107;
    *(uint *)(uVar20 + 0x36) = *(uint *)(uVar20 + 0x36) ^ uVar20;
    puVar31 = (undefined4 *)(iVar24 + -8);
    *(undefined2 *)(iVar24 + -8) = in_SS;
  }
LAB_004012d1_2:
  pcVar4 = (code *)swi(0xbe);
  uVar39 = (*pcVar4)();
  puVar21 = (uint *)((ulonglong)uVar39 >> 0x20);
  puVar10 = (undefined4 *)uVar39;
  *(uint *)((int)puVar10 + 7) = *(uint *)((int)puVar10 + 7) | (uint)puVar32;
  piVar25 = (int *)((int)puVar33 + 0x3186b701);
  iVar15 = *piVar25;
  iVar24 = *piVar25;
  *piVar25 = iVar24 + 0x16413652;
  pbVar35 = (byte *)((int)puVar33 + 1);
  uVar7 = in((short)((ulonglong)uVar39 >> 0x20));
  *(undefined *)puVar33 = uVar7;
  puVar23 = (undefined *)0xc8df88c4;
  iVar34 = 0xd3e042c;
  piVar29 = puVar31;
  if ((SCARRY4(iVar15,0x16413652) != SCARRY4(iVar24 + 0x16413652,0)) == *piVar25 < 0)
  goto LAB_0040135b;
  puVar23 = &DAT_c8df84c4;
  iVar15 = -0x3621c0d4;
  *(undefined *)((int)puVar31 + 0x41) = 0x7c;
  puVar32 = (undefined4 *)*puVar10;
  piVar29 = puVar10 + 1;
  puVar16 = extraout_ECX;
code_r0x00401303:
  *puVar23 = 0;
  bVar37 = SCARRY1((char)puVar31,-0x5a);
  uVar13 = (undefined3)((uint)puVar31 >> 8);
  bVar5 = (char)puVar31 + 0xa6;
  bVar38 = (char)bVar5 < '\0';
  if (puVar16 == (uint *)0x0) {
    puVar31 = (undefined4 *)((int)piVar29 + -4);
    *(undefined2 *)((int)piVar29 + -4) = in_DS;
    puVar21 = (uint *)CONCAT22((short)((uint)puVar21 >> 0x10),
                               CONCAT11((byte)((uint)puVar21 >> 8) & *pbVar35,(char)puVar21));
    goto code_r0x0040134b;
  }
  bVar14 = in((short)puVar21);
  *pbVar35 = bVar14;
  pbVar35 = (byte *)0x60de3c83;
  if (bVar37 != bVar38) {
    return (float10 *)CONCAT31(uVar13,bVar5);
  }
  in_AF = 9 < (bVar5 & 0xf) | in_AF;
  uVar20 = CONCAT31(uVar13,bVar5 + in_AF * -6) & 0xffffff0f;
  puVar11 = (uint *)CONCAT22((short)(uVar20 >> 0x10),
                             CONCAT11((char)((uint)puVar31 >> 8) - in_AF,(char)uVar20));
  puVar26 = (undefined *)0x859449c5;
  do {
    bVar5 = (byte)puVar11;
    if (bVar37 != bVar38) {
      puVar21 = (uint *)0x7835c065;
      puVar31 = (undefined4 *)piVar29[1];
      puVar30 = piVar29 + 2;
      sVar9 = (short)(char)bVar5 * (short)cRamd17953b4;
      puVar23 = (undefined *)CONCAT22((short)((uint)puVar11 >> 0x10),sVar9);
      bVar37 = (char)sVar9 != sVar9;
      goto code_r0x00401405;
    }
    bVar14 = 9 < (bVar5 & 0xf) | in_AF;
    uVar20 = CONCAT31((int3)((uint)puVar11 >> 8),bVar5 + bVar14 * -6) & 0xffffff0f;
    uVar7 = (undefined)uVar20;
    bVar5 = (byte)puVar26;
    *piVar29 = 0x52978107;
    puVar31 = (undefined4 *)*puVar32;
    uVar20 = CONCAT31((int3)(CONCAT22((short)(uVar20 >> 0x10),
                                      CONCAT11((char)((uint)puVar11 >> 8) - bVar14,uVar7)) >> 8),
                      uVar7) ^ 100;
    iVar24 = uVar20 + 1;
    *puVar32 = puVar31;
    *puVar16 = *puVar16 - 0x2a;
    ppbVar1 = (byte **)(uVar20 + 0x44 + (int)puVar21 * 4);
    pbVar2 = *ppbVar1;
    pbVar36 = pbVar35 + -(int)*ppbVar1;
    puVar32[-1] = puVar16;
    *puVar16 = (*puVar16 + 0x36) - (uint)(pbVar35 < pbVar2);
    pbVar35 = pbVar36 + 1;
    *pbVar36 = bVar5;
    uVar18 = (undefined2)((uint)iVar24 >> 0x10);
    bVar17 = (byte)iVar24;
    piVar25 = (int *)CONCAT22(uVar18,CONCAT11(8,bVar17));
    *puVar31 = 0x7a978107;
    iVar24 = CONCAT22((short)((uint)puVar16 >> 0x10),CONCAT11(0x3c,(char)puVar16));
    puVar33 = (undefined4 *)*(undefined6 *)(iVar15 + 0x37);
    puVar16 = (uint *)(iVar24 + 1);
    if (SCARRY4(iVar24,1) == (int)puVar16 < 0) {
      bVar14 = 9 < (bVar5 & 0xf) | bVar14;
      uVar20 = CONCAT31((int3)((uint)puVar26 >> 8),bVar5 + bVar14 * -6) & 0xffff000f;
      uVar7 = (undefined)uVar20;
      puVar11 = (uint *)CONCAT22((short)(uVar20 >> 0x10),CONCAT11('\b' - bVar14,uVar7));
      puVar32 = puVar31 + -1;
      puVar10 = puVar31 + -1;
      puVar31[-1] = puVar33;
      cVar6 = '\r';
      do {
        puVar33 = puVar33 + -1;
        puVar32 = puVar32 + -1;
        *puVar32 = *puVar33;
        cVar6 = cVar6 + -1;
      } while ('\0' < cVar6);
      puVar31[-0xf] = puVar31 + -1;
      puVar33 = puVar31 + -0x1171;
      puVar32 = puVar31 + -0x1171;
      puVar31[-0x1171] = puVar31 + -1;
      cVar6 = '\x15';
      do {
        puVar10 = puVar10 + -1;
        puVar33 = puVar33 + -1;
        *puVar33 = *puVar10;
        cVar6 = cVar6 + -1;
      } while ('\0' < cVar6);
      puVar31[-0x1187] = puVar31 + -0x1171;
      *piVar25 = (int)((int)puVar31 + *piVar25 + -0xa3d7);
      bVar5 = *(byte *)puVar16;
      *(char *)puVar16 = *(char *)puVar16 + '\x1b';
      bVar14 = (byte)puVar16 & 0x1f;
      *puVar11 = *puVar11 << bVar14 | (uint)(CONCAT14(bVar5 < 0xe5,*puVar11) >> 0x21 - bVar14);
      puVar23 = (undefined *)
                CONCAT22(uVar18,CONCAT11(-*(char *)CONCAT22(uVar18,(ushort)bVar17),bVar17));
      *(undefined **)(puVar23 + 0x26) = (undefined *)((int)puVar31 + -0xa3d7);
      puVar11[-0xe] = puVar11[-0xe] - (int)puVar23;
      bVar5 = *(byte *)((int)puVar31 + -0x45f6);
      puVar33 = (undefined4 *)((int)puVar31 + -0xa3db);
      *(undefined4 **)((int)puVar31 + -0xa3db) = puVar31 + -0x1171;
      cVar6 = '\x12';
      do {
        puVar32 = puVar32 + -1;
        puVar33 = puVar33 + -1;
        *puVar33 = *puVar32;
        cVar6 = cVar6 + -1;
      } while ('\0' < cVar6);
      *(undefined **)((int)puVar31 + -0xa427) = (undefined *)((int)puVar31 + -0xa3db);
      piVar29 = (int *)((int)puVar31 + -0x185e2);
      puVar32 = (undefined4 *)0x412f042c;
      if ((bVar5 & (byte)((uint)puVar16 >> 8)) == 0) {
        *(undefined **)((int)puVar31 + -0x185e6) = puVar23;
        out((short)puVar21,puVar11);
        *(undefined **)((int)puVar31 + -0x185ea) = puVar23;
        *(int *)((int)puVar11 + -0x17683fca) = *(int *)((int)puVar11 + -0x17683fca) - (int)puVar21;
        *(int *)(pbVar36 + -0x6bc635f6) = *(int *)(pbVar36 + -0x6bc635f6) + 0x37;
        return (float10 *)(CONCAT31((int3)((uint)puVar11 >> 8),uVar7) ^ 0x41);
      }
code_r0x004013eb:
      iVar15 = *piVar29;
      *(int *)((int)puVar16 + 1) = *(int *)((int)puVar16 + 1) + -0x3a;
      puVar31 = (undefined4 *)(iVar15 + -4);
      *(undefined4 **)(iVar15 + -4) = puVar32;
      bVar37 = false;
      pbVar35 = pbVar35 + -1;
      puVar26 = (undefined *)
                ((CONCAT31((int3)((uint)puVar11 >> 8),(char)puVar11 + 'l') ^ 0xaaf65d78) + 1);
      puVar16 = *(uint **)(iVar15 + -0x65be);
      puVar30 = (undefined4 *)(iVar15 + -0x65ba);
code_r0x00401405:
      uVar20 = *puVar16;
      uVar19 = *puVar16;
      *puVar16 = (uVar19 - 0x22) - (uint)bVar37;
      *puVar16 = (*puVar16 - 0x26) - (uint)(uVar20 < 0x22 || uVar19 - 0x22 < (uint)bVar37);
      cVar8 = (char)puVar23 + 'l';
      puVar33 = (undefined4 *)((int)puVar30 + -4);
      *(undefined4 **)((int)puVar30 + -4) = puVar31;
      cVar6 = '\x02';
      do {
        puVar31 = puVar31 + -1;
        puVar33 = puVar33 + -1;
        *puVar33 = *puVar31;
        cVar6 = cVar6 + -1;
      } while ('\0' < cVar6);
      *(undefined **)((int)puVar30 + -0x10) = (undefined *)((int)puVar30 + -4);
      if (SCARRY1((char)puVar23,'l') != cVar8 < '\0') {
                    // WARNING: Could not recover jumptable at 0x0040148d. Too many branches
                    // WARNING: Treating indirect jump as call
        pfVar12 = (float10 *)(**(code **)((int)puVar16 * 9 + 0x3750fc01))();
        return pfVar12;
      }
      DAT_aaf65d78 = 0;
      uVar22 = *(undefined4 *)((int)puVar30 + -0x93ca);
      *(undefined4 *)((int)puVar30 + -0x93ca) = 0xffffffbf;
      uVar20 = *puVar21;
      *(int *)((int)puVar21 + -0x3d2c1ad7) = *(int *)((int)puVar21 + -0x3d2c1ad7) + 1;
      *(uint *)((int)puVar30 + -0x93ce) = CONCAT31((int3)((uint)puVar23 >> 8),cVar8);
      *(undefined4 *)((int)puVar30 + -0x93d2) = 0x86bf947d;
      *(uint **)((int)puVar30 + -0x93d6) = puVar21;
      *(undefined **)((int)puVar30 + -0x93da) = puVar26;
      *(undefined **)((int)puVar30 + -0x93de) = (undefined *)((int)puVar30 + -0x93ca);
      *(undefined4 *)((int)puVar30 + -0x93e2) = uVar22;
      *(uint *)((int)puVar30 + -0x93e6) = uVar20 & 0xa9de9009;
      *(byte **)((int)puVar30 + -0x93ea) = pbVar35;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    in_AF = 9 < (bVar5 & 0xf) | bVar14;
code_r0x0040134b:
    *(int *)((int)puVar21 + 0x10d3e529) = *(int *)((int)puVar21 + 0x10d3e529) + 1;
    puVar26 = (undefined *)*puVar31;
    iVar34 = puVar31[1];
    puVar32 = (undefined4 *)puVar31[2];
    puVar23 = (undefined *)puVar31[4];
    uVar22 = puVar31[5];
    uVar39 = CONCAT44(uVar22,puVar31[7]);
    piVar29 = puVar31 + 8;
    *(char *)(iVar34 + 2) = *(char *)(iVar34 + 2) + '\x01';
    pbVar35 = puVar26 + 1;
    uVar7 = in((short)uVar22);
    *puVar26 = uVar7;
LAB_0040135b:
    puVar21 = (uint *)((ulonglong)uVar39 >> 0x20);
    in_AF = 9 < ((byte)uVar39 & 0xf) | in_AF;
    uVar20 = CONCAT31((int3)((ulonglong)uVar39 >> 8),(byte)uVar39 + in_AF * '\x06') & 0xffffff0f;
    cVar6 = (char)uVar20;
    uVar13 = (undefined3)
             (CONCAT22((short)(uVar20 >> 0x10),
                       CONCAT11((char)((ulonglong)uVar39 >> 8) + in_AF,cVar6)) >> 8);
    puVar16 = (uint *)&DAT_04bbabf6;
    cVar6 = cVar6 + -0x2d + ((byte)(cVar6 + 0x80U) < 0x5c);
    puVar11 = (uint *)CONCAT31(uVar13,cVar6);
    iVar15 = iVar34 + -1;
    if (iVar34 < 1) {
      *(uint *)((int)puVar11 + -0x37) = *(uint *)((int)puVar11 + -0x37) | (uint)piVar29;
      puVar11 = (uint *)(CONCAT31(uVar13,cVar6) ^ 0x74);
      bVar37 = false;
      bVar38 = (char)puVar23[0x38] < '\0';
      if (bVar38) goto code_r0x004013eb;
    }
    else {
      pbVar2 = *(byte **)(iVar34 + 0x35 + (int)puVar11);
      bVar38 = (int)pbVar35 - (int)pbVar2 < 0;
      iVar15 = 0x34c96009;
      if (pbVar35 == pbVar2) break;
      puVar26 = (undefined *)((longlong)(int)*puVar11 * 0x7c);
      bVar37 = (longlong)(int)puVar26 != (longlong)(int)*puVar11 * 0x7c;
      uVar7 = in((short)((ulonglong)uVar39 >> 0x20));
      *puVar26 = uVar7;
    }
    pbVar35 = (byte *)0x3fabfd87;
    puVar26 = puVar23;
  } while( true );
  puVar31 = (undefined4 *)((int)puVar11 + 1);
  puVar16 = (uint *)0x4bbabf7;
  pbVar35 = (byte *)0x0;
  goto code_r0x00401303;
}



void __fastcall entry(float10 *param_1,undefined4 param_2)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x366c7c41;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x3b262cc4;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2);
  return;
}


