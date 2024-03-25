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




// WARNING: Instruction at (ram,0x00401225) overlaps instruction at (ram,0x0040121f)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __fastcall FUN_00401219(byte *param_1,int param_2,int param_3,uint *param_4)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  longlong lVar5;
  longlong lVar6;
  byte bVar7;
  byte bVar8;
  char cVar9;
  int in_EAX;
  uint *puVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  int extraout_ECX;
  int extraout_ECX_00;
  byte *pbVar15;
  undefined4 unaff_EBX;
  int iVar16;
  byte *pbVar17;
  int unaff_EBP;
  uint uVar18;
  uint *unaff_ESI;
  uint *puVar19;
  uint *puVar20;
  int *unaff_EDI;
  byte in_CF;
  bool bVar21;
  byte bVar22;
  byte in_AF;
  float10 in_ST0;
  float10 extraout_ST0;
  float10 extraout_ST0_00;
  undefined8 uVar23;
  ulonglong uVar24;
  byte *unaff_retaddr;
  byte *pbStack_8;
  int iStack_4;
  undefined3 uVar14;
  
  bVar8 = 0;
  puVar10 = (uint *)(in_EAX + -1);
  LOCK();
  *(char *)unaff_ESI = (char)((uint)unaff_EBX >> 8);
  UNLOCK();
  *unaff_EDI = *unaff_EDI + unaff_EBP + (uint)in_CF;
  lVar5 = (longlong)*(int *)(in_EAX + 0x79c14dc8) * 0x30;
  iVar16 = (int)lVar5;
  bVar21 = iVar16 != lVar5;
  if (bVar21 != *unaff_EDI < 0) {
    if (bVar21) {
      return (int)(short)unaff_EDI;
    }
    iStack_4 = iVar16;
    puVar19 = (uint *)(in_EAX + 0x70);
    *puVar19 = (int)puVar10 + (uint)bVar21 + *puVar19;
    lVar6 = (longlong)*(int *)((int)unaff_ESI + 0x45482fb2) * -0x16f0205b;
    uVar18 = (uint)lVar6;
    bVar8 = (int)uVar18 != lVar6;
    puVar20 = unaff_ESI + 1;
    *puVar10 = *unaff_ESI;
    pbVar15 = param_1 + -1;
    uVar12 = *puVar19;
    pbStack_8 = param_1;
    if (pbVar15 != (byte *)0x0 && *puVar19 != 0) {
      while( true ) {
        uVar14 = (undefined3)((uint)unaff_EDI >> 8);
        bVar7 = (byte)unaff_EDI;
        if (-1 < (int)uVar12) break;
        puVar10 = (uint *)(param_1 + -0x3d);
        piRamd99fe90b = unaff_EDI;
        *puVar10 = *puVar10 << 0x1a | *puVar10 >> 6;
        bVar8 = 9 < (bVar7 & 0xf) | in_AF;
        uVar12 = CONCAT31(uVar14,bVar7 + bVar8 * -6) & 0xffffff0f;
        bVar21 = CARRY4((uint)pbStack_8,uVar18);
        pbVar17 = pbStack_8 + uVar18;
        pbStack_8 = pbVar17 + bVar8;
        iVar13 = (CONCAT22((short)(uVar12 >> 0x10),
                           CONCAT11((char)((uint)unaff_EDI >> 8) - bVar8,(char)uVar12)) +
                 -0x11c1d811) - (uint)(bVar21 || CARRY4((uint)pbVar17,(uint)bVar8));
        cVar9 = in((short)param_2);
        *(byte *)puVar20 = *(byte *)puVar20 | (byte)pbVar15;
        (&pbStack_8)[param_2 * 2] = (&pbStack_8)[param_2 * 2] + uVar18;
        *(uint *)((int)puVar20 + 0x36ea92f9) =
             *(uint *)((int)puVar20 + 0x36ea92f9) >> ((byte)pbVar15 & 0x1f);
        out((short)param_2,(char)&stack0xc094d89c);
        puVar20 = *(uint **)CONCAT22((short)((uint)iVar13 >> 0x10),
                                     (ushort)(byte)(cVar9 + (char)((uint)iVar13 >> 8) * '\r'));
        bVar7 = in(0xf);
        piVar1 = (int *)(iVar16 + 0x79);
        iVar13 = *piVar1;
        *piVar1 = *piVar1 << 1;
        if (-1 < iVar13) {
          do {
                    // WARNING: Do nothing block with infinite loop
          } while( true );
        }
        param_2 = CONCAT31((int3)((uint)param_2 >> 8),(byte)param_2 & (byte)lVar5);
        uVar18 = uVar18 - 1;
        bVar8 = 9 < (bVar7 & 0xf) | bVar8;
        uVar12 = CONCAT31((int3)((uint)&stack0xc094d89c >> 8),bVar7 + bVar8 * -6) & 0xffffff0f;
        unaff_EDI = (int *)CONCAT22((short)(uVar12 >> 0x10),
                                    CONCAT11((char)((uint)&stack0xc094d89c >> 8) - bVar8,
                                             (char)uVar12));
        in_AF = bVar8;
        uVar12 = uVar18;
      }
      in_AF = 9 < (bVar7 & 0xf) | in_AF;
      bVar7 = bVar7 + in_AF * '\x06';
      bVar8 = 0x90 < (bVar7 & 0xf0) | bVar8 | in_AF * (0xf9 < bVar7);
      unaff_EDI = (int *)CONCAT31(uVar14,bVar7 + bVar8 * '`');
    }
    puVar10 = (uint *)((int)puVar20 + 0x27);
    bVar21 = CARRY4(*puVar10,(uint)unaff_EDI) || CARRY4(*puVar10 + (int)unaff_EDI,(uint)bVar8);
    *puVar10 = *puVar10 + (int)unaff_EDI + (uint)bVar8;
    bVar8 = (byte)unaff_EDI + *(byte *)((int)puVar20 + 0x27);
    uVar14 = (undefined3)((uint)unaff_EDI >> 8);
    uVar11 = CONCAT31(uVar14,bVar8 + bVar21);
    puVar10 = (uint *)(in_EAX + 0x41);
    uVar2 = (uint)(CARRY1((byte)unaff_EDI,*(byte *)((int)puVar20 + 0x27)) || CARRY1(bVar8,bVar21));
    uVar12 = *puVar10;
    uVar3 = *puVar10 + uVar11;
    *puVar10 = uVar3 + uVar2;
    puVar10 = (uint *)(in_EAX + 0x276c8121 + (int)pbVar15 * 2);
    uVar3 = (uint)(CARRY4(uVar12,uVar11) || CARRY4(uVar3,uVar2));
    uVar12 = *puVar10;
    uVar2 = *puVar10;
    *puVar10 = uVar2 + uVar18 + uVar3;
    bVar7 = -(CARRY4(uVar12,uVar18) || CARRY4(uVar2 + uVar18,uVar3));
    bVar8 = 9 < (bVar7 & 0xf) | in_AF;
    bVar7 = bVar7 + bVar8 * '\x06';
    out((short)param_2,
        (int)(short)CONCAT31(uVar14,bVar7 + (0x90 < (bVar7 & 0xf0) | bVar8 * (0xf9 < bVar7) | 1) *
                                            '`'));
    *(byte *)(in_EAX + 3) = *(byte *)puVar20;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while( true ) {
    *puVar10 = *puVar10 | (int)&param_3 + 1U;
    uVar12 = CONCAT13(param_4._0_1_,param_3._1_3_);
    iVar13 = CONCAT13(param_4._0_1_,param_3._1_3_);
    iVar16 = CONCAT13(param_4._0_1_,param_3._1_3_) + 0x772c512e;
    param_4._0_1_ = (undefined)((uint)iVar16 >> 0x18);
    bVar7 = (byte)param_1 & 7;
    *param_1 = *param_1 << bVar7 | *param_1 >> 8 - bVar7;
    bVar21 = ((uint)param_1 & 0x1f) != 0;
    bVar4 = ((byte)param_1 & 0x1f) == 1;
    if (iVar16 != 0 &&
        (!bVar4 && SCARRY4(iVar13,0x772c512e) != SCARRY4(iVar16,0) ||
        bVar4 && (!bVar21 && 0x88d3aed1 < uVar12 || bVar21 && (*param_1 & 1) != 0) !=
                 (char)*param_1 < '\0') == iVar16 < 0) {
      puVar10 = (uint *)((int)puVar10 + (uint)bVar8 * -2 + 1);
      *puVar10 = *unaff_ESI;
      *(short *)(puVar10 + (uint)bVar8 * -2 + 1) = (short)in_ST0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    pbVar17 = (byte *)(*(int *)((short)unaff_EDI + -0x379130b7) * -0x6fa7fcf0);
    *pbVar17 = *pbVar17 & (byte)unaff_EDI;
    bVar22 = 0;
    uVar12 = *(uint *)CONCAT22((short)(CONCAT13((undefined)param_3,(int3)((uint)unaff_retaddr >> 8))
                                      >> 0x10),
                               CONCAT11((char)((uint)unaff_retaddr >> 0x10) +
                                        (char)((uint)param_1 >> 8),(char)((uint)unaff_retaddr >> 8))
                              );
    param_3 = iVar16 * 0x100;
    uVar23 = func_0x46516675();
    pbVar15 = (byte *)((ulonglong)uVar23 >> 0x20);
    in_AF = 9 < ((byte)uVar23 & 0xf) | in_AF;
    bVar7 = (byte)uVar23 + in_AF * '\x06';
    if ((int)((uint)pbVar17 | uVar12) <= _DAT_0e34ca6c) break;
    bVar7 = 0;
    uVar24 = CONCAT44(pbVar15,_DAT_24c1276e) | 0x97;
    iVar16 = extraout_ECX;
    puVar19 = unaff_ESI;
    in_ST0 = extraout_ST0;
    param_4 = unaff_ESI;
    if (-1 < (char)((byte)_DAT_24c1276e | 0x97)) {
      puVar19 = unaff_ESI + (uint)bVar8 * -2 + 1;
      *puVar10 = *unaff_ESI;
      in_AF = 9 < ((byte)_DAT_51d6276e & 0xf) | in_AF;
      bVar8 = (byte)_DAT_51d6276e + in_AF * '\x06';
      bVar7 = 0x90 < (bVar8 & 0xf0) |
              CARRY1((byte)((uint)extraout_ECX >> 8),*pbVar15) | in_AF * (0xf9 < bVar8);
      param_4 = (uint *)0x40128a;
      uVar24 = func_0xa61821c9();
      iVar16 = extraout_ECX_00;
      in_ST0 = extraout_ST0_00;
    }
    param_3 = -0x3e;
    param_1 = (byte *)(iVar16 + 1);
    puVar10 = (uint *)_DAT_ee2c1145;
    bVar8 = 1;
    bVar22 = (byte)uVar24;
    uVar14 = (undefined3)(uVar24 >> 8);
    if (param_1 == (byte *)0x0) {
      bVar8 = 9 < (bVar22 & 0xf) | in_AF;
      bVar22 = bVar22 + bVar8 * '\x06';
      *puVar10 = *puVar19;
      return CONCAT31(uVar14,bVar22 + (0x90 < (bVar22 & 0xf0) | bVar7 | bVar8 * (0xf9 < bVar22)) *
                                      '`');
    }
    *(byte *)(puVar10 + -0x10aefba1) = *(byte *)(puVar10 + -0x10aefba1) ^ (byte)(uVar24 >> 0x20);
    unaff_EDI = (int *)CONCAT31(uVar14,bVar22 + 0x89);
    unaff_ESI = puVar19;
    unaff_retaddr = param_1;
  }
  return CONCAT31((int3)((ulonglong)uVar23 >> 8),
                  bVar7 + (0x90 < (bVar7 & 0xf0) | bVar22 | in_AF * (0xf9 < bVar7)) * '`');
}



void __fastcall entry(byte *param_1,int param_2,int param_3,uint *param_4)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x1f95;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x3e272c11;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xc74;
  puVar2 = &DAT_0042b000;
  do {
    *puVar2 = *puVar2 ^ 0x3f283e95;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219(param_1,param_2,param_3,param_4);
  return;
}


