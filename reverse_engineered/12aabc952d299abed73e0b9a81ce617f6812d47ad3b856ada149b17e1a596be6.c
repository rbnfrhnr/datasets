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
// WARNING: Instruction at (ram,0x004011b7) overlaps instruction at (ram,0x004011b6)
// 
// WARNING: Removing unreachable block (ram,0x00401198)
// WARNING: Removing unreachable block (ram,0x0040114e)
// WARNING: Removing unreachable block (ram,0x004010df)
// WARNING: Removing unreachable block (ram,0x00401150)
// WARNING: Removing unreachable block (ram,0x004010eb)
// WARNING: Removing unreachable block (ram,0x004010fd)
// WARNING: Removing unreachable block (ram,0x004011ff)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00401219(char *param_1,byte *param_2)

{
  code **ppcVar1;
  byte *pbVar2;
  uint *puVar3;
  unkbyte10 Var4;
  char cVar5;
  byte bVar6;
  int iVar7;
  code *pcVar8;
  uint uVar9;
  uint in_EAX;
  uint uVar10;
  uint extraout_ECX;
  uint uVar11;
  char *extraout_ECX_00;
  char *extraout_ECX_01;
  byte bVar12;
  byte *extraout_EDX;
  double *unaff_EBX;
  undefined4 *puVar13;
  undefined *puVar14;
  undefined4 *unaff_EBP;
  char *pcVar15;
  char *pcVar16;
  char *unaff_ESI;
  uint uVar17;
  char *unaff_EDI;
  undefined2 in_CS;
  undefined2 in_SS;
  bool bVar18;
  byte bVar19;
  char in_CF;
  char in_SF;
  undefined uVar20;
  bool in_OF;
  float10 fVar21;
  float10 extraout_ST0;
  float10 in_ST0;
  undefined8 uVar22;
  char *pcStack_18c9;
  undefined auStack_18c5 [6288];
  undefined *puStack_35;
  char *pcStack_31;
  char *pcStack_29;
  char *pcStack_25;
  
  uVar22 = CONCAT44(param_2,in_EAX);
  if (in_OF == (bool)in_SF) {
    if (!in_OF) {
code_r0x0040121d:
      param_2[-0x1702e3db] = (param_2[-0x1702e3db] - (char)in_EAX) - in_CF;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    bVar18 = false;
    *(byte *)(in_EAX - 1) = *(byte *)(in_EAX - 1) ^ 0x10;
    out((short)param_2,(char)in_EAX);
LAB_004011b9:
    iVar7 = (int)((ulonglong)uVar22 >> 0x20);
    pcVar15 = (char *)(iVar7 + -0x74efae0d);
    *pcVar15 = (*pcVar15 - (char)uVar22) - bVar18;
    pcVar15 = (char *)(iVar7 + 0x7a9bb29b);
    *pcVar15 = (*pcVar15 + ' ') - ((byte)((ulonglong)uVar22 >> 0x28) < (byte)param_1[-0x6b]);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar9 = CONCAT31((int3)((in_EAX & 0xffffffa6) >> 8),(char)(in_EAX & 0xffffffa6) + '\x14');
  pcStack_29 = unaff_EDI + 1;
  pcVar15 = unaff_ESI + 1;
  if (!SBORROW1(*unaff_ESI,*unaff_EDI)) {
    puVar3 = (uint *)(unaff_ESI + -0x7923e9ab);
    uVar11 = *puVar3;
    *puVar3 = *puVar3 >> 0x1a;
    bVar18 = (uVar11 >> 0x19 & 1) != 0;
    if (!bVar18) {
      *(char *)(uVar9 + 0xfd70c0a8) =
           (*(char *)(uVar9 + 0xfd70c0a8) - (char)((uint)unaff_EBX >> 8)) - bVar18;
      iVar7 = CONCAT31((int3)((uint)param_2 >> 8),(byte)param_2 ^ *(byte *)(uVar9 + 0xd7c0a270));
      pbVar2 = (byte *)(iVar7 + -0x5b);
      bVar12 = *pbVar2;
      bVar6 = (byte)((uint)param_1 >> 8);
      *pbVar2 = *pbVar2 - bVar6;
      out((short)iVar7,unaff_EBP);
      *(char *)(iVar7 + 0x3230a08f) =
           (*(char *)(iVar7 + 0x3230a08f) - (char)unaff_EBP) - (bVar12 < bVar6);
      unaff_EDI[0x323238a1] = unaff_EDI[0x323238a1] | 0x95;
      out(unaff_ESI[5],in_SS);
      pbVar2 = (byte *)(((uint)param_1 & 0x9598825a) + 0x16);
      *pbVar2 = *pbVar2 ^ 0xdc;
      func_0xcf915c41();
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar9 = uVar9 & 0x2198825a;
  *(undefined2 *)(param_2 + -0x7923e990) = *(undefined2 *)(param_2 + -0x7923e990);
  puStack_35 = &stack0xffffffd3;
  puVar13 = (undefined4 *)&stack0xffffffd3;
  puVar14 = &stack0xffffffd3;
  cVar5 = '\x01';
  do {
    unaff_EBP = unaff_EBP + -1;
    puVar13 = puVar13 + -1;
    *puVar13 = *unaff_EBP;
    cVar5 = cVar5 + -1;
    pcStack_25 = pcVar15;
  } while ('\0' < cVar5);
  do {
    bVar18 = (byte)uVar9 < 0xf4;
    Var4 = to_bcd((float10)*unaff_EBX - in_ST0);
    *(unkbyte10 *)((int)unaff_EBX + -0x3f51daea) = Var4;
    bVar6 = *(byte *)((int)unaff_EBX + (uint)(byte)((byte)uVar9 + 0xc));
    pbVar2 = param_2 + -0x7c5f6dfb;
    bVar12 = *pbVar2 - bVar6;
    bVar19 = *pbVar2 < bVar6 || bVar12 < bVar18;
    uVar20 = SBORROW1(*pbVar2,bVar6) != SBORROW1(bVar12,bVar18);
    *pbVar2 = bVar12 - bVar18;
    if (!(bool)uVar20) {
      param_1[-0x68] = (param_1[-0x68] - (char)((uint)param_1 >> 8)) - bVar19;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar22 = func_0xfe4b8f1a();
    param_1 = extraout_ECX_00;
    pcVar16 = pcVar15;
    fVar21 = extraout_ST0;
    while( true ) {
      pcVar8 = (code *)uVar22;
      if ((bool)uVar20) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (-1 < (int)(pcVar16 + 1)) {
        uVar22 = (*pcVar8)((char)in_CS);
        if (puVar14 != (undefined *)0xffffffff) {
          return;
        }
        pbVar2 = (byte *)((int)((ulonglong)uVar22 >> 0x20) + 0x6a10ff70);
        bVar18 = *pbVar2 < (byte)uVar22;
        *pbVar2 = *pbVar2 - (byte)uVar22;
        param_1 = extraout_ECX_01;
        goto LAB_004011b9;
      }
      ppcVar1 = (code **)((int)((ulonglong)uVar22 >> 0x20) + 4);
      *ppcVar1 = pcVar8 + (int)(*ppcVar1 + bVar19);
      bVar12 = (byte)((ulonglong)uVar22 >> 0x20) ^ puVar14[0x6a2edd41];
      param_2 = (byte *)CONCAT31((int3)((ulonglong)uVar22 >> 0x28),bVar12);
      uVar10 = CONCAT31((int3)((uint)param_1 >> 8),
                        (char)param_1 + bVar12 + (((uint)pcVar8 | 0x946c874) < 0x4421199));
      puVar14 = (undefined *)0xeefbb660;
      fVar21 = fVar21 + (float10)*(double *)(pcVar16 + -0x2bf70102);
      uVar17 = uRameefbb63b & 0x168f7de7;
      pcVar15 = pcVar16 + 2;
      uVar9 = (int)(short)((short)((uint)pcVar8 | 0x946c874) + -0x1199);
      uVar11 = uVar10;
      if (-1 < (int)pcVar15) {
        *(uint *)unaff_EBX = *(uint *)unaff_EBX | (uint)pcVar15;
        out(0xd6,uVar17);
        fVar21 = (float10)(*(code *)0x774aff3)((char)in_CS,0xffffff9b);
        uVar9 = _DAT_6a126b97;
        uVar11 = extraout_ECX;
        param_2 = extraout_EDX;
        uVar17 = uVar10;
      }
      out(0x7d,uVar9);
      param_1 = (char *)(uVar11 + 1);
      bVar18 = (longlong)(int)auStack_18c5 != (longlong)(int)uVar17 * 0x7d;
      bVar6 = (byte)(uVar9 & 0x1a927318);
      bVar12 = bVar6 - 0x18;
      uVar9 = CONCAT31((int3)((uVar9 & 0x1a927318) >> 8),bVar12 + bVar18);
      pcStack_18c9 = param_1;
      if (SCARRY1(bVar6,-0x18) != SCARRY1(bVar12,bVar18)) break;
      uVar11 = (uint)(0x17 < bVar6 || CARRY1(bVar12,bVar18));
      iVar7 = (uVar9 + 0xe7283f6e) - uVar11;
      *(char **)(iVar7 + -0x6b) = pcVar15;
      puVar14 = (undefined *)0xeefbb660;
      cVar5 = ((char)iVar7 - (char)((uint)param_1 >> 8)) -
              (uVar9 < 0x18d7c092 || uVar9 + 0xe7283f6e < uVar11);
      in_EAX = CONCAT31((int3)((uint)iVar7 >> 8),cVar5);
      uVar22 = CONCAT44(param_2,in_EAX);
      if ((POPCOUNT(cVar5) & 1U) != 0) {
        in_CF = '\0';
        goto code_r0x0040121d;
      }
      bVar19 = 0;
      uVar20 = false;
      pcVar16 = pcVar15;
    }
    uVar9 = (uint)(short)uVar9;
    *(uint *)((int)unaff_EBX + -0x7e) = *(uint *)((int)unaff_EBX + -0x7e) & (uint)&pcStack_18c9;
    in_ST0 = fVar21 + (float10)*(double *)(pcVar16 + -0x7de76b36);
  } while( true );
}



void __fastcall entry(char *param_1,byte *param_2)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x1f85;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x70821895;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xcf4;
  puVar2 = &DAT_0042b000;
  do {
    *puVar2 = *puVar2 ^ 0x38527f2b;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219(param_1,param_2);
  return;
}


