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
// WARNING: Instruction at (ram,0x00401334) overlaps instruction at (ram,0x00401333)
// 
// WARNING: Unable to track spacebase fully for stack

undefined4 * __fastcall FUN_00401219(int param_1,uint param_2)

{
  byte *pbVar1;
  int *piVar2;
  ushort *puVar3;
  char *pcVar4;
  short sVar5;
  char cVar6;
  longlong lVar7;
  code *pcVar8;
  ulonglong uVar9;
  uint5 uVar10;
  byte bVar11;
  byte bVar12;
  undefined4 *in_EAX;
  undefined4 *puVar13;
  undefined2 uVar16;
  uint uVar14;
  undefined *puVar15;
  int iVar17;
  int extraout_ECX;
  int iVar18;
  undefined4 *puVar19;
  undefined4 *extraout_ECX_00;
  uint extraout_EDX;
  int unaff_EBX;
  undefined4 **unaff_EBP;
  undefined4 *puVar20;
  undefined4 *puVar21;
  uint *unaff_ESI;
  uint *puVar22;
  uint *puVar23;
  uint *puVar24;
  undefined4 **ppuVar25;
  undefined2 in_SS;
  char cVar26;
  byte bVar27;
  bool bVar28;
  byte in_AF;
  undefined uVar29;
  bool bVar30;
  char cVar31;
  bool bVar32;
  bool bVar33;
  undefined2 in_FPUControlWord;
  undefined8 uVar34;
  undefined4 *unaff_retaddr;
  undefined4 *apuStack_1c166 [2];
  undefined4 *puStack_1c15e;
  undefined2 uStack_1c15c;
  undefined4 uStack_1c15a;
  uint *puStack_1c156;
  undefined4 *puStack_1c152;
  undefined *puStack_1c14e;
  int iStack_1c14a;
  undefined4 uStack_1c146;
  undefined4 *puStack_1c142;
  undefined4 *puStack_1c13e;
  undefined auStack_1c13a [57431];
  undefined4 **ppuStack_e0e3;
  undefined4 *apuStack_e0a3 [14369];
  undefined4 uStack_5;
  
  bVar33 = false;
  cVar31 = (int)(in_EAX + -0x1a1e1638) < 0;
  uVar29 = in_EAX == (undefined4 *)0x687858e0;
  lVar7 = (longlong)*(int *)((int)unaff_EBP + 0x4488c212) * 0x30e07fc8;
  puVar23 = (uint *)lVar7;
  cVar26 = (int)puVar23 != lVar7;
  do {
    param_1 = param_1 + -1;
    if (param_1 == 0) {
      if (cVar26 == cVar31) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (cVar26 != cVar31) {
      return in_EAX;
    }
    if (!(bool)uVar29 && cVar26 == cVar31) goto LAB_0040123d;
    pbVar1 = (byte *)((int)in_EAX + -0x73);
    bVar27 = 0;
    cVar26 = '\0';
    *pbVar1 = *pbVar1 ^ (byte)unaff_EBX;
    cVar31 = (char)*pbVar1 < '\0';
    uVar29 = *pbVar1 == 0;
    DAT_9ae89058 = SUB41(in_EAX,0);
    in_EAX = unaff_retaddr;
    while (puVar19 = apuStack_1c166[1], unaff_retaddr = in_EAX, !(bool)cVar31) {
      bVar11 = (char)in_EAX + (char)((uint)in_EAX >> 8) * 'p';
      uVar16 = (undefined2)((uint)in_EAX >> 0x10);
      cVar26 = '\x06';
      puVar20 = (undefined4 *)register0x00000010;
      puVar13 = unaff_EBP;
      do {
        puVar13 = puVar13 + -1;
        puVar20 = puVar20 + -1;
        *puVar20 = *puVar13;
        cVar26 = cVar26 + -1;
      } while ('\0' < cVar26);
      apuStack_e0a3[1] = (undefined4 *)&stack0xffffffff;
      piVar2 = (int *)(CONCAT22(uVar16,(ushort)bVar11) + 0x1a);
      *piVar2 = (*piVar2 - param_2) - (uint)bVar27;
      if (*piVar2 < 0) {
        apuStack_e0a3[1] = (undefined4 *)0x69;
        unaff_retaddr = unaff_EBP;
LAB_0040123d:
        puVar23 = (uint *)unaff_retaddr[1];
        unaff_ESI = (uint *)unaff_retaddr[2];
        puVar20 = (undefined4 *)unaff_retaddr[3];
        unaff_EBX = unaff_retaddr[5];
        param_2 = unaff_retaddr[6];
        iVar17 = unaff_retaddr[7];
        puVar13 = (undefined4 *)unaff_retaddr[8];
        unaff_retaddr[8] = unaff_retaddr + 9;
        iVar18 = unaff_retaddr[8];
        bVar27 = puVar13 < (undefined4 *)0x195481e3;
        cVar26 = SBORROW4((int)puVar13,0x195481e3);
        cVar31 = (int)((int)puVar13 + -0x195481e3) < 0;
        puVar3 = (ushort *)(iVar18 + 0x7832e057 + (int)puVar23 * 2);
        sVar5 = ((ushort)unaff_EBX & 3) - (*puVar3 & 3);
        uVar29 = 0 < sVar5;
        *puVar3 = *puVar3 + (ushort)bVar27 * sVar5;
        *(undefined4 **)(iVar18 + -4) = puVar20;
        puVar19 = (undefined4 *)(iVar18 + -8);
        unaff_EBP = (undefined4 **)(iVar18 + -8);
        puVar21 = (undefined4 *)(iVar18 + -8);
        *(undefined4 **)(iVar18 + -8) = puVar20;
        cVar6 = '\x1c';
        do {
          puVar20 = puVar20 + -1;
          puVar19 = puVar19 + -1;
          *puVar19 = *puVar20;
          cVar6 = cVar6 + -1;
        } while ('\0' < cVar6);
        *(int *)(iVar18 + -0x7c) = iVar18 + -8;
        *(char *)((int)puVar13 + iVar17 * 8 + 0x7f) = (char)((uint)unaff_EBX >> 8);
        param_1 = iVar17 + -1;
        in_EAX = unaff_retaddr;
        if (param_1 != 0 && !(bool)uVar29) {
          uRamb158e047 = SUB41(puVar13,0);
          pcVar4 = (char *)(unaff_EBX + 0x58e03d78 + (int)puVar23 * 8);
          *pcVar4 = *pcVar4 + '\x01';
          goto code_r0x0040129a;
        }
      }
      else {
        puVar13 = (undefined4 *)CONCAT22(uVar16,(ushort)bVar11);
        ppuStack_e0e3 = apuStack_e0a3 + 1;
        ppuVar25 = apuStack_e0a3 + 1;
        cVar26 = '\x10';
        puVar20 = apuStack_e0a3[1];
        do {
          puVar20 = puVar20 + -1;
          ppuVar25 = ppuVar25 + -1;
          *ppuVar25 = (undefined4 *)*puVar20;
          cVar26 = cVar26 + -1;
        } while ('\0' < cVar26);
        puVar22 = (uint *)((int)puVar13 + 0x1a);
        bVar27 = *puVar22 < param_2;
        cVar26 = SBORROW4(*puVar22,param_2);
        *puVar22 = *puVar22 - param_2;
        cVar31 = (int)*puVar22 < 0;
        uVar29 = *puVar22 == 0;
        if (!(bool)cVar31) {
          iVar18 = param_1 + -1;
          if (iVar18 != 0 && !(bool)uVar29) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          bVar11 = (byte)((uint)unaff_EBX >> 8);
          puVar21 = apuStack_1c166[1];
          if ((bool)cVar31) {
            pbVar1 = (byte *)((int)puVar13 + 0x3d);
            bVar28 = false;
            *pbVar1 = *pbVar1 ^ bVar11;
            bVar30 = *pbVar1 == 0;
            ppuStack_e0e3 = apuStack_e0a3 + 1;
            goto code_r0x004012c4;
          }
          puVar19 = puVar13 + 0xd744a43;
          *(ushort *)puVar19 =
               *(ushort *)puVar19 +
               (ushort)bVar27 * (((ushort)unaff_EBX & 3) - (*(ushort *)puVar19 & 3));
          puVar13[-0x7ee1754] = puVar13[-0x7ee1754] << 0x18;
          bVar11 = (byte)unaff_EBX & bVar11;
          if (-1 < (char)bVar11) {
            param_1 = CONCAT31((int3)((uint)iVar18 >> 8),0xfe) + -1;
            ppuStack_e0e3 = apuStack_e0a3 + 1;
            if (param_1 != 0 && bVar11 != 0) {
              return puVar13;
            }
            goto code_r0x0040129a;
          }
          ppuVar25 = (undefined4 **)(puVar13 + 0x1337fce1);
          goto code_r0x004012d0;
        }
        apuStack_1c166[1] = (undefined4 *)0x40125a;
        in_EAX = unaff_EBP;
        func_0x7cc84f94();
        ppuVar25 = apuStack_1c166 + 1;
        unaff_EBP = apuStack_1c166 + 1;
        apuStack_1c166[1] = puVar19;
        cVar6 = '\x0f';
        do {
          puVar19 = puVar19 + -1;
          ppuVar25 = ppuVar25 + -1;
          *ppuVar25 = (undefined4 *)*puVar19;
          cVar6 = cVar6 + -1;
          param_1 = extraout_ECX;
          param_2 = extraout_EDX;
        } while ('\0' < cVar6);
      }
    }
  } while( true );
code_r0x0040129a:
  uVar34 = CONCAT44(param_2,puStack_1c15e);
  unaff_EBX = -0x622e4ac3;
  uVar14 = CONCAT31((int3)((uint)puVar13 >> 8),(char)puVar13 + 'y');
  bVar28 = uVar14 < 0x3d0e6708;
  bVar32 = (int)(uVar14 + 0xc2f198f8) < 0;
  bVar30 = uVar14 == 0x3d0e6708;
  iVar18 = param_1 + -1;
  if (iVar18 == 0 || bVar30) {
    return;
  }
  if (bVar32) {
    puVar22 = unaff_ESI + (uint)bVar33 * -2 + 1;
    bVar27 = (byte)((uint)iVar18 >> 8);
    puVar23 = (uint *)(CONCAT22((short)((uint)iVar18 >> 0x10),
                                CONCAT11(bVar27 - (byte)param_2,(char)iVar18)) + 0x78);
    uVar10 = CONCAT14(bVar27 < (byte)param_2,*puVar23);
    uVar9 = (ulonglong)uVar10 << 4;
    *puVar23 = (uint)(uVar10 >> 0x1d) | (uint)uVar9;
    bVar30 = (uVar9 & 0x100000000) != 0;
    ppuVar25 = (undefined4 **)puStack_1c15e;
    goto code_r0x00401318;
  }
  puVar19 = (undefined4 *)(param_1 + -2);
  if (puVar19 != (undefined4 *)0x0 && !bVar30) {
    unaff_ESI = (uint *)((int)unaff_ESI + (uint)bVar33 * -2 + 1);
    puVar20 = (undefined4 *)((uint)puStack_1c15e & 0xffffff00);
    puVar19 = puStack_1c15e;
    if (bVar32) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
LAB_004012f0:
    puStack_1c142 = (undefined4 *)0xb33d782f;
    puVar20 = (undefined4 *)CONCAT31((int3)((uint)puVar20 >> 8),0xd2);
    uVar34 = CONCAT44(param_2 - (int)puVar21,puVar20);
    unaff_EBX = -0x622e4ac4;
    puVar19 = (undefined4 *)((int)puVar19 + -1);
    puVar22 = unaff_ESI;
    if (puVar19 == (undefined4 *)0x0) {
      return puVar20;
    }
LAB_0040135a:
    puVar24 = (uint *)&DAT_28a0a5b0;
code_r0x00401363:
    uVar16 = puStack_1c13e._0_2_;
    ppuVar25 = (undefined4 **)((int)puVar24 + (uint)bVar33 * -2 + 1);
    puStack_1c156 = (uint *)((int)puVar22 + (uint)bVar33 * -2 + 1);
    *(undefined *)puVar24 = *(undefined *)puVar22;
    *(char *)(ppuVar25 + -8) = *(char *)(ppuVar25 + -8) - (char)((ulonglong)uVar34 >> 0x20);
    *(byte *)((int)ppuVar25 + 0x3d) = *(byte *)((int)ppuVar25 + 0x3d) ^ 0xa5;
    out((short)((ulonglong)uVar34 >> 0x20),CONCAT31((int3)((ulonglong)uVar34 >> 8),0xa5));
    unaff_EBX = CONCAT22((short)((uint)unaff_EBX >> 0x10),
                         CONCAT11((char)((uint)unaff_EBX >> 8) + DAT_3d12588a,(char)unaff_EBX));
    bVar30 = puStack_1c142 < (undefined4 *)0x5095c274;
    puStack_1c13e = puStack_1c142 + -0x1425709d;
    puStack_1c142 = puVar19;
    uStack_1c146 = (int)((ulonglong)uVar34 >> 0x20);
    iStack_1c14a = unaff_EBX;
    puStack_1c14e = auStack_1c13a;
    puStack_1c152 = puVar21;
    if (-1 < (int)puStack_1c13e) {
      *(undefined2 *)(ppuVar25 + 0x1e162d8d) = in_FPUControlWord;
      return (undefined4 *)
             (CONCAT31((int3)((uint)ppuVar25 >> 8),((byte)ppuVar25 ^ 0x16) + 0x84) | 0x20);
    }
    uStack_1c15a = CONCAT22((short)((uint)ppuVar25 >> 0x10),uVar16);
    puVar22 = puStack_1c156;
code_r0x00401318:
    puVar3 = (ushort *)(&stack0x78a55da6 + (int)puVar22 * 2);
    *puVar3 = *puVar3 + (ushort)bVar30 * (((ushort)unaff_EBX & 3) - (*puVar3 & 3));
    puVar23 = (uint *)(*(int *)(CONCAT31((int3)((uint)ppuVar25 >> 8),DAT_18b459b3) + -0x4124d84c) *
                       -0x731224d4 + -0x5f96ce6d);
    *puVar23 = *puVar23 >> 1;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (bVar32) {
    ppuVar25 = (undefined4 **)((uint)puStack_1c15e & 0xffff0000);
LAB_0040130d:
    uVar14 = in((short)param_2);
    *puVar23 = uVar14;
    pbVar1 = (byte *)((int)unaff_ESI + -0x2ad758e2);
    bVar30 = false;
    *pbVar1 = *pbVar1 | 0xc1;
    puVar22 = unaff_ESI;
    if (-1 < (char)*pbVar1) goto code_r0x00401318;
    puStack_1c15e = (undefined4 *)CONCAT22(uStack_1c15c,in_SS);
    pcVar8 = (code *)swi(0xd1);
    uVar34 = (*pcVar8)();
    puVar19 = extraout_ECX_00;
    goto LAB_0040135a;
  }
  puVar20 = puStack_1c15e;
  if (puVar19 == (undefined4 *)0x0) goto LAB_004012f0;
  if (bVar32) {
    ppuVar25 = &puStack_1c142;
    puVar24 = puVar23 + (uint)bVar33 * -2 + 1;
    puVar22 = unaff_ESI + (uint)bVar33 * -2 + 1;
    bVar30 = *unaff_ESI < *puVar23;
    if (-1 < (int)(*unaff_ESI - *puVar23)) goto code_r0x00401318;
    puVar24[0xa28296c] = (int)puVar24[0xa28296c] >> 1;
    goto code_r0x00401363;
  }
  iVar18 = param_1 + -3;
  if (iVar18 != 0 && !bVar30) {
    return puStack_1c15e;
  }
  puVar13 = puStack_1c15e;
  if (bVar32) {
    return puStack_1c15e;
  }
code_r0x004012c4:
  param_1 = iVar18 + -1;
  if (param_1 == 0 || bVar30) {
    bVar30 = CARRY1(DAT_d5781870,(byte)unaff_EBX);
    bVar27 = DAT_d5781870 + (byte)unaff_EBX;
    DAT_d5781870 = bVar27 + bVar28;
    puVar15 = (undefined *)((int)puVar13 + -1);
    bVar11 = 9 < ((byte)puVar15 & 0xf) | in_AF;
    bVar12 = (byte)puVar15 + bVar11 * -6;
    ppuVar25 = (undefined4 **)
               CONCAT31((int3)((uint)puVar15 >> 8),
                        bVar12 + (0x9f < bVar12 |
                                 (bVar30 || CARRY1(bVar27,bVar28)) | bVar11 * (bVar12 < 6)) * -0x60)
    ;
    if (-1 < (int)puVar15) {
code_r0x004012d0:
      lVar7 = (longlong)*(int *)(unaff_EBX + 0x2d1fc6fb) * -0x4cdff384;
      return (undefined4 *)
             CONCAT31((int3)((uint)((int)ppuVar25 + ((int)lVar7 != lVar7) + 0x461527bc) >> 8),
                      *(undefined *)unaff_ESI);
    }
    goto LAB_0040130d;
  }
  bVar33 = ((uint)puStack_1c15e & 0x400) != 0;
  in_AF = ((uint)puStack_1c15e & 0x10) != 0;
  goto code_r0x0040129a;
}



void __fastcall entry(int param_1,uint param_2)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x3d7858e0;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x7a7e5e49;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2);
  return;
}


