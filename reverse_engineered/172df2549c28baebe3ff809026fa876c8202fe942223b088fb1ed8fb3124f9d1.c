typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
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
// WARNING: Instruction at (ram,0x004012cd) overlaps instruction at (ram,0x004012cb)
// 
// WARNING: Removing unreachable block (ram,0x0040130c)
// WARNING: Removing unreachable block (ram,0x0040131c)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

longlong FUN_00401219(uint **param_1,uint **param_2,uint **param_3,undefined4 param_4,uint param_5,
                     uint **param_6,uint *param_7,uint **param_8)

{
  char *pcVar1;
  uint **ppuVar2;
  uint uVar3;
  char cVar4;
  byte bVar6;
  uint **ppuVar7;
  uint **in_EAX;
  int iVar8;
  undefined3 uVar12;
  uint uVar10;
  uint **ppuVar11;
  uint *puVar13;
  char cVar15;
  uint **ppuVar14;
  uint extraout_EDX;
  uint unaff_EBX;
  uint **unaff_EBP;
  uint **ppuVar16;
  uint **ppuVar17;
  uint **ppuVar18;
  uint **ppuVar19;
  int in_GS_OFFSET;
  byte in_AF;
  bool bVar20;
  bool bVar21;
  bool bVar22;
  char cVar5;
  uint **ppuVar9;
  
LAB_0040121c:
  do {
    ppuVar7 = param_8;
    puVar13 = (uint *)((int)unaff_EBP + 0x71);
    uVar10 = *puVar13;
    *puVar13 = *puVar13 - unaff_EBX;
    iVar8 = CONCAT31((int3)((uint)in_EAX >> 8),DAT_41e01bb8);
    uVar3 = *(uint *)((int)unaff_EBP + 0x29);
    *(uint *)((int)unaff_EBP + 0x29) =
         (uint)(CONCAT14(uVar10 < unaff_EBX,uVar3) >> 0x15) | uVar3 << 0xc;
    bVar22 = SBORROW4(iVar8,1);
    bVar21 = iVar8 + -1 < 0;
    bVar20 = iVar8 == 1;
    param_8 = param_3;
    ppuVar14 = param_6;
    unaff_EBX = param_5;
    ppuVar16 = param_3;
    ppuVar17 = param_2;
    ppuVar9 = param_1;
LAB_00401243:
    ppuVar19 = ppuVar9;
    cVar15 = (char)((uint)ppuVar14 >> 8);
    if (!bVar21) {
      puVar13 = param_7;
      uVar10 = unaff_EBX;
      ppuVar9 = param_3;
      ppuVar16 = ppuVar19;
      if (!bVar22) {
        puVar13 = (uint *)((int)param_7 + -1);
        unaff_EBP = param_3;
        if (puVar13 == (uint *)0x0 || bVar20) goto code_r0x00401211;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      do {
        if (!bVar20) {
          in_AF = 9 < ((byte)ppuVar7 & 0xf) | in_AF;
          ppuVar7 = (uint **)((uint)ppuVar7 & 0xffffff00);
        }
        param_8 = (uint **)CONCAT31((int3)((uint)ppuVar7 >> 8),DAT_aadc2cb1);
        ppuVar19 = ppuVar16 + 1;
        unaff_EBX = *(int *)((int)ppuVar16 + 0x71) * 0x6a;
        ppuVar7 = (uint **)in(0x70);
        *(int *)((int)ppuVar16 + -0x66) =
             *(int *)((int)ppuVar16 + -0x66) + *(int *)((int)ppuVar16 + 0x71) * -0x6a;
        unaff_EBP = ppuVar16;
        param_1 = ppuVar16;
        param_2 = ppuVar17;
        param_3 = ppuVar9;
        param_5 = uVar10;
        param_6 = ppuVar14;
        param_7 = puVar13;
code_r0x00401211:
        while( true ) {
          bVar20 = (uint **)0xa2d6e136 < ppuVar7;
          bVar22 = SCARRY4((int)ppuVar7,0x5d291ec9);
          ppuVar7 = (uint **)((int)ppuVar7 + 0x5d291ec9);
          if (bVar22) {
            *(char *)puVar13 = *(char *)puVar13 + '\x01';
            *(byte *)ppuVar19 = *(byte *)ppuVar19 >> 1 | bVar20 << 7;
            in_EAX = ppuVar7;
            goto LAB_0040121c;
          }
          *ppuVar19 = (uint *)((int)*ppuVar19 - (int)ppuVar17);
          bVar20 = *ppuVar19 == (uint *)0x0;
          uVar10 = unaff_EBX;
          ppuVar9 = unaff_EBP;
          ppuVar16 = ppuVar19;
          if ((POPCOUNT((uint)*ppuVar19 & 0xff) & 1U) == 0) break;
          unaff_EBP = (uint **)*unaff_EBP;
        }
      } while( true );
    }
    pcVar1 = (char *)((int)ppuVar16 + unaff_EBX * 2 + 0x7599aa3b);
    cVar5 = (char)ppuVar7;
    uVar12 = (undefined3)((uint)ppuVar7 >> 8);
    cVar4 = cVar5 - *pcVar1;
    ppuVar9 = (uint **)CONCAT31(uVar12,cVar4);
    if (cVar4 != '\0') {
      do {
        param_6 = &param_7;
        unaff_EBX = unaff_EBX | *(uint *)((int)param_7 + 0x29f7711f);
        ppuVar17 = (uint **)((int)ppuVar17 - *(int *)((int)param_7 + 0x1f));
        ppuVar11 = ppuVar9;
        ppuVar2 = ppuVar17;
code_r0x00401284:
        ppuVar7 = ppuVar11;
        bVar20 = ppuVar2 == (uint **)0x0;
        bVar21 = (int)ppuVar2 < 0;
        ppuVar9 = (uint **)((int)ppuVar19 + 1);
        bVar6 = (byte)ppuVar7;
        *(byte *)ppuVar19 = bVar6;
        ppuVar14 = (uint **)((int)ppuVar7 >> 0x1f);
        ppuVar16 = (uint **)((longlong)(int)*ppuVar17 * -0x1cc32b20);
        bVar22 = (longlong)(int)ppuVar16 != (longlong)(int)*ppuVar17 * -0x1cc32b20;
        if (!bVar21) goto LAB_00401243;
        ppuVar19 = (uint **)((int)ppuVar19 + 5);
        *ppuVar9 = (uint *)ppuVar7;
        puVar13 = (uint *)((int)ppuVar16 + in_GS_OFFSET + -0x48);
        bVar20 = *puVar13 < unaff_EBX;
        bVar21 = SBORROW4(*puVar13,unaff_EBX);
        *puVar13 = *puVar13 - unaff_EBX;
        bVar22 = *puVar13 == 0;
        ppuVar9 = ppuVar7;
        ppuVar18 = ppuVar17;
        if (!bVar21) goto LAB_004012b7;
        puVar13 = (uint *)((int)ppuVar16 + -0x4e);
        uVar10 = *puVar13;
        uVar3 = *puVar13;
        *puVar13 = *puVar13 - unaff_EBX;
        if (SBORROW4(uVar3,unaff_EBX) == (int)*puVar13 < 0) {
          while( true ) {
            ppuVar11 = &param_7;
            ppuVar19 = ppuVar19 + 1;
            ppuVar18 = ppuVar17 + 1;
            ppuVar9 = ppuVar18;
            if (SBORROW4(*param_7,(int)ppuVar14)) break;
            while( true ) {
              *(int *)((int)ppuVar14 + 7) = *(int *)((int)ppuVar14 + 7) << 0x1f;
              puVar13 = *ppuVar9;
              *ppuVar9 = (uint *)((int)*ppuVar9 - (int)param_7);
              in_AF = 9 < ((byte)ppuVar11 & 0xf) | in_AF;
              bVar6 = (byte)ppuVar11 + in_AF * '\x06';
              ppuVar17 = (uint **)(CONCAT31((int3)((uint)ppuVar11 >> 8),
                                            bVar6 + (0x90 < (bVar6 & 0xf0) |
                                                    puVar13 < param_7 | in_AF * (0xf9 < bVar6)) *
                                                    '`') + -1);
              bVar20 = false;
              bVar21 = false;
              *(byte *)ppuVar17 = *(byte *)ppuVar17 | (byte)param_7;
              bVar22 = *(byte *)ppuVar17 == 0;
              ppuVar18 = ppuVar17;
              if ((char)*(byte *)ppuVar17 < '\0') break;
LAB_004012b7:
              if (bVar22) {
                if (bVar21) {
                  cVar15 = (char)((int)ppuVar7 >> 0x1f);
                  ppuVar14 = (uint **)((uint)(byte)(cVar15 - *(char *)ppuVar19) << 8);
                  if (SBORROW1(cVar15,*(char *)ppuVar19)) goto code_r0x004012c0;
                  DAT_9d18d303 = (byte)ppuVar9 + (9 < ((byte)ppuVar9 & 0xf) | in_AF) * '\x06' & 0xf;
                  func_0x86a5a013();
                }
                else {
                  func_0xa317bfbb();
                  *(char *)((int)ppuVar16 + -0x5a5fec66) =
                       (*(char *)((int)ppuVar16 + -0x5a5fec66) - (char)unaff_EBX) -
                       CARRY4(extraout_EDX,unaff_EBX);
                  uRam0376d8f8 = uRamd7ac81d8;
                }
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              ppuVar17 = ppuVar18;
              if (!bVar21) goto LAB_00401276;
              ppuVar17 = (uint **)((int)ppuVar18 + 1);
              uVar12 = (undefined3)((uint)ppuVar9 >> 8);
              ppuVar11 = (uint **)CONCAT31(uVar12,*(byte *)ppuVar18);
              bVar20 = SBORROW4((int)*ppuVar19,(int)ppuVar14) != false;
              *ppuVar19 = (uint *)((int)*ppuVar19 - (int)ppuVar14);
              ppuVar2 = (uint **)*ppuVar19;
              if (bVar20) {
                bVar6 = *(byte *)ppuVar17;
                *ppuVar19 = *(uint **)((int)ppuVar18 + 2);
                return CONCAT44(ppuVar14,CONCAT31(uVar12,bVar6));
              }
              ppuVar9 = ppuVar17;
              if (bVar20) goto code_r0x00401284;
            }
          }
          ppuVar16 = (uint **)((int)ppuVar16 - unaff_EBX);
code_r0x004012c0:
          bVar20 = _DAT_dd291f71 < ppuVar18;
          _DAT_dd291f71 = (uint **)((int)_DAT_dd291f71 - (int)ppuVar18);
          *ppuVar19 = (uint *)((int)*ppuVar19 + (-(uint)bVar20 - (int)ppuVar19));
          cVar15 = (char)((uint)ppuVar14 >> 8) - DAT_81f7713c;
          goto LAB_004012c8_3;
        }
        param_6 = &param_7;
        if (!SBORROW4(uVar3,unaff_EBX)) goto LAB_00401254;
        bVar20 = bVar6 < 0x7d || (byte)(bVar6 + 0x83) < (uVar10 < unaff_EBX);
        ppuVar9 = (uint **)CONCAT31((int3)((uint)ppuVar7 >> 8),(bVar6 + 0x83) - (uVar10 < unaff_EBX)
                                   );
LAB_00401276:
        uVar10 = *(uint *)((int)ppuVar16 + 0x29);
        *(uint *)((int)ppuVar16 + 0x29) = (uint)(CONCAT14(bVar20,uVar10) >> 0x14) | uVar10 << 0xd;
      } while( true );
    }
    uVar10 = CONCAT31(uVar12,in_AF * '\x06') & 0xffffff0f;
    ppuVar7 = (uint **)CONCAT22((short)(uVar10 >> 0x10),
                                CONCAT11((char)((uint)ppuVar7 >> 8) + in_AF,(char)uVar10));
    param_6 = ppuVar16;
    if (!SBORROW1(cVar5,*pcVar1)) {
LAB_004012c8_3:
      *(char *)((int)ppuVar16 + 0x2e) = *(char *)((int)ppuVar16 + 0x2e) - cVar15;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
LAB_00401254:
    unaff_EBP = (uint **)((int)ppuVar16 * 2);
    unaff_EBX = unaff_EBX ^ (uint)*ppuVar19;
    in_EAX = ppuVar7;
    if ((int)param_7 + 1 < 0) {
      _DAT_5d6baf51 = _DAT_5d6baf51 - (int)ppuVar17;
      return (longlong)(int)ppuVar7;
    }
  } while( true );
}



longlong entry(uint **param_1,uint **param_2,uint **param_3,undefined4 param_4,uint param_5,
              uint **param_6,uint *param_7,uint **param_8)

{
  int iVar1;
  uint *puVar2;
  longlong lVar3;
  
  iVar1 = 0x1f85;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x1f715d29;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xcf4;
  puVar2 = &DAT_0042b000;
  do {
    *puVar2 = *puVar2 ^ 0x5a834b81;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  lVar3 = FUN_00401219(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return lVar3;
}


