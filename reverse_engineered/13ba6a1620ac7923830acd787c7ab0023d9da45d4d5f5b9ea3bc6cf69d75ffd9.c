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
// WARNING: Instruction at (ram,0x00401222) overlaps instruction at (ram,0x0040121d)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte * __fastcall FUN_00401219(uint param_1,char *param_2)

{
  byte *pbVar1;
  char *pcVar2;
  uint *puVar3;
  byte bVar4;
  uint uVar6;
  undefined4 uVar7;
  uint uVar8;
  byte bVar9;
  byte bVar10;
  byte *in_EAX;
  undefined3 uVar14;
  uint uVar11;
  int *piVar12;
  byte *pbVar13;
  ushort uVar15;
  char cVar16;
  int unaff_EBX;
  int iVar17;
  int **unaff_EBP;
  uint *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 *puVar18;
  byte in_CF;
  byte bVar19;
  bool bVar20;
  undefined in_PF;
  byte in_AF;
  char in_ZF;
  bool bVar21;
  undefined in_SF;
  bool bVar22;
  byte bVar5;
  
  if ((bool)in_CF || (bool)in_ZF) {
    while( true ) {
      in_AF = 9 < ((byte)in_EAX & 0xf) | in_AF;
      uVar14 = (undefined3)((uint)in_EAX >> 8);
      bVar10 = (byte)in_EAX + in_AF * -6;
      bVar19 = 0x9f < bVar10 | in_CF | in_AF * (bVar10 < 6);
      bVar10 = bVar10 + bVar19 * -0x60;
      pbVar13 = (byte *)CONCAT31(uVar14,bVar10);
      if ((bool)in_SF) break;
      if ((bool)in_PF) {
        uVar11 = CONCAT22((short)((uint)in_EAX >> 0x10),(ushort)bVar10);
        out(*unaff_ESI,(short)param_2);
        in_EAX = (byte *)(CONCAT44(param_2,param_1) / ZEXT48(unaff_EBP));
        param_2 = (char *)(CONCAT44(param_2,param_1) % ZEXT48(unaff_EBP));
        goto code_r0x00401223;
      }
      unaff_EBX = CONCAT31((int3)((uint)unaff_EBX >> 8),param_2[0x12]);
      if ((bool)bVar19 || (bool)in_ZF) {
        uVar11 = in((short)param_2);
        bVar19 = (byte)uVar11;
        *(byte *)unaff_EDI = bVar19;
        bVar22 = false;
        bVar21 = (uVar11 & 0x50) == 0;
        bVar20 = (POPCOUNT(bVar19 & 0x50) & 1U) == 0;
        pbVar13 = (byte *)(CONCAT22((short)(uVar11 >> 0x10),
                                    CONCAT11(bVar21 << 6 | in_AF << 4 | bVar20 << 2,bVar19)) | 0x200
                          );
        unaff_EBP = (int **)_DAT_18782f32;
        unaff_EDI = (undefined4 *)((int)unaff_EDI + 1);
        goto code_r0x0040127a;
      }
      pbVar13 = (byte *)(param_2 + 0x36703add);
      *pbVar13 = *pbVar13 ^ (byte)((uint)in_EAX >> 8);
      in_SF = (char)*pbVar13 < '\0';
      in_ZF = *pbVar13 == 0;
      in_PF = (POPCOUNT(*pbVar13) & 1U) == 0;
      in_AF = 9 < (bVar10 & 0xf) | in_AF;
      bVar10 = bVar10 + in_AF * -6;
      in_CF = 0x9f < bVar10 | in_AF * (bVar10 < 6);
      in_EAX = (byte *)CONCAT31(uVar14,bVar10 + in_CF * -0x60);
    }
    bVar19 = (byte)(param_1 >> 8) ^ *(byte *)unaff_EDI;
    param_1 = CONCAT22((short)(param_1 >> 0x10),CONCAT11(bVar19,(char)param_1));
    bVar22 = (char)bVar19 < '\0';
    bVar21 = bVar19 == 0;
    bVar20 = (POPCOUNT(bVar19) & 1U) == 0;
    if (bVar22) {
      pbVar1 = (byte *)((int)unaff_ESI + -7);
      bVar19 = (byte)param_2;
      bVar20 = CARRY1(bVar19,*pbVar1);
      cVar16 = bVar19 + *pbVar1;
      bVar21 = SCARRY1(bVar19,*pbVar1) != SCARRY1(cVar16,'\0');
      param_2 = (char *)CONCAT31((int3)((uint)param_2 >> 8),cVar16);
      uVar11 = param_1;
      iVar17 = unaff_EBX;
    }
    else {
code_r0x0040127a:
      bVar19 = ((byte)param_1 & 0x1f) % 9;
      uVar15 = (ushort)*pbVar13 << 9 - bVar19;
      *pbVar13 = *pbVar13 >> bVar19 | (byte)uVar15;
      pbVar13 = (byte *)CONCAT22((short)((uint)pbVar13 >> 0x10),
                                 CONCAT11(bVar22 << 7 | bVar21 << 6 | in_AF << 4 | bVar20 << 2 | 2 |
                                          (uVar15 & 0x100) != 0,(char)pbVar13));
      bVar19 = (byte)param_1 & 7;
      uVar15 = CONCAT11(-0x58 << bVar19 | 0xa8U >> 8 - bVar19,0x2e);
      param_2 = (char *)CONCAT22(0x9f50,uVar15);
      bVar20 = (param_1 & 0x1f) != 0;
      bVar20 = !bVar20 && (byte)unaff_EBX < *(byte *)(unaff_EBX + -0x2ef4782a) ||
               bVar20 && (uVar15 & 0x100) != 0;
      unaff_EBP = (int **)((int)unaff_EBP + 1);
      bVar21 = SBORROW1(*param_2,'.') != SBORROW1(*param_2 + -0x2e,bVar20);
      *param_2 = (*param_2 + -0x2e) - bVar20;
      cVar16 = *param_2;
      bVar20 = true;
      uVar11 = param_1;
      iVar17 = unaff_EBX;
    }
    if (bVar21 != cVar16 < '\0') {
      return pbVar13;
    }
    in_EAX = (byte *)CONCAT22((short)((uint)pbVar13 >> 0x10),
                              CONCAT11((cVar16 < '\0') << 7 | (cVar16 == '\0') << 6 | in_AF << 4 |
                                       ((POPCOUNT(cVar16) & 1U) == 0) << 2 | 2 | bVar20,
                                       (char)pbVar13));
    bVar10 = (byte)iVar17;
    bVar19 = bVar10 + (param_2 + 0x4d)[(int)unaff_EDI];
    bVar9 = bVar19 + (bVar10 < *in_EAX);
    unaff_EBX = CONCAT31((int3)((uint)iVar17 >> 8),bVar9);
    in_SF = (char)bVar9 < '\0';
    in_ZF = bVar9 == 0;
    in_PF = (POPCOUNT(bVar9) & 1U) == 0;
    if (!(bool)in_PF) {
      *(byte *)((int)unaff_ESI + -0x62) = *(byte *)((int)unaff_ESI + -0x62) | bVar9;
      piVar12 = (int *)(in_EAX + -0x41183ae9);
      uVar7 = in((short)param_2);
      *unaff_EDI = uVar7;
      uVar8 = unaff_EDI[1];
      uVar6 = *unaff_ESI;
      puVar18 = (undefined4 *)((int)unaff_EDI + 9);
      uVar11 = uVar11 - 1;
      if (uVar11 != 0 && puVar18 != (undefined4 *)0x0) {
        *unaff_EBP = piVar12;
        pbVar13 = (byte *)in((short)param_2);
        return pbVar13;
      }
      *unaff_EBP = (int *)0x15b76893;
      bVar20 = CARRY1(bVar9,*(byte *)((int)unaff_EDI + -0x6087e7a7)) ||
               CARRY1(bVar9 + *(byte *)((int)unaff_EDI + -0x6087e7a7),uVar6 < uVar8);
      bVar19 = (byte)((uint)iVar17 >> 8);
      goto code_r0x004012bb;
    }
    bVar19 = !CARRY1(bVar10,(param_2 + 0x4d)[(int)unaff_EDI]) && !CARRY1(bVar19,bVar10 < *in_EAX);
  }
  else {
    bVar9 = (byte)unaff_EBX;
    bVar10 = bVar9 + *(byte *)((int)unaff_EDI + -0xa086e91);
    bVar19 = CARRY1(bVar9,*(byte *)((int)unaff_EDI + -0xa086e91)) || CARRY1(bVar10,bVar9 < *in_EAX);
    cVar16 = bVar10 + (bVar9 < *in_EAX);
    unaff_EBX = CONCAT31((int3)((uint)unaff_EBX >> 8),cVar16);
    in_SF = cVar16 < '\0';
    in_ZF = cVar16 == '\0';
    in_PF = (POPCOUNT(cVar16) & 1U) == 0;
    uVar11 = param_1;
  }
code_r0x00401223:
  bVar10 = 9 < ((byte)in_EAX & 0xf) | in_AF;
  bVar9 = (byte)in_EAX + bVar10 * -6;
  cVar16 = bVar9 + (0x9f < bVar9 | bVar19 | bVar10 * (bVar9 < 6)) * -0x60;
  pbVar13 = (byte *)CONCAT31((int3)((uint)in_EAX >> 8),cVar16);
  if (!(bool)in_SF) {
    if (!(bool)in_PF) {
      return pbVar13;
    }
    bVar10 = 9 < ((byte)uVar11 & 0xf) | bVar10;
    uVar11 = CONCAT31((int3)(uVar11 >> 8),(byte)uVar11 + bVar10 * '\x06') & 0xffffff0f;
    bVar9 = (byte)uVar11;
    uVar11 = CONCAT22((short)(uVar11 >> 0x10),
                      CONCAT11(in_SF << 7 | in_ZF << 6 | bVar10 << 4 | in_PF << 2 | 2 | bVar10,bVar9
                              ));
    bVar19 = (byte)((uint)unaff_EBX >> 8);
    pbVar1 = pbVar13 + -0x37;
    *pbVar1 = *pbVar1 | bVar9;
    bVar4 = *pbVar1;
    bVar9 = *pbVar1;
    bVar5 = *pbVar1;
    puVar18 = unaff_EDI + 1;
    uVar7 = in((short)param_2);
    *unaff_EDI = uVar7;
    if (bVar9 != 0) {
      piVar12 = (int *)(CONCAT22((short)((uint)in_EAX >> 0x10),
                                 CONCAT11(((char)bVar4 < '\0') << 7 | (bVar9 == 0) << 6 |
                                          bVar10 << 4 | ((POPCOUNT(bVar5) & 1U) == 0) << 2,cVar16))
                       | 0x200);
      pbVar13 = (byte *)((int)piVar12 + -0x61);
      bVar20 = *pbVar13 < bVar19;
      *pbVar13 = *pbVar13 - bVar19;
code_r0x004012bb:
      param_2[-0x61] =
           (param_2[-0x61] - bVar19) -
           (puVar18 < *(undefined4 **)(int *)((int)piVar12 + -0x61) ||
           (uint)((int)puVar18 - *(int *)((int)piVar12 + -0x61)) < (uint)bVar20);
      iVar17 = *piVar12;
      *piVar12 = -*piVar12;
      *(char *)((int)piVar12 + -0x61) = (char)piVar12;
      pcVar2 = param_2 + -0x6ec5609b;
      bVar19 = (byte)uVar11 & 0x1f;
      cVar16 = *pcVar2;
      *pcVar2 = *pcVar2 << bVar19;
      bVar20 = (uVar11 & 0x1f) != 0;
      puVar3 = (uint *)(uVar11 + (int)param_2 * 8);
      *puVar3 = *puVar3 >> 1 |
                (uint)(!bVar20 && iVar17 != 0 || bVar20 && (char)(cVar16 << bVar19 - 1) < '\0') <<
                0x1f;
      out(0x67,param_2);
      param_2[-0x61] = param_2[-0x61] + -0x60;
      out(0x2c,(char)param_2);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  return pbVar13;
}



void __fastcall entry(uint param_1,char *param_2)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x3a9f1218;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x777050d8;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2);
  return;
}


