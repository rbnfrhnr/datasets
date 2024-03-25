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
// WARNING: Instruction at (ram,0x0040129f) overlaps instruction at (ram,0x0040129d)
// 
// WARNING (jumptable): Unable to track spacebase fully for stack
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x004013a7)
// WARNING: Removing unreachable block (ram,0x00401270)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __fastcall FUN_00401219(int param_1,uint param_2)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  byte bVar5;
  undefined uVar6;
  uint in_EAX;
  uint uVar7;
  uint uVar8;
  int extraout_ECX;
  uint uVar9;
  uint **ppuVar10;
  uint **extraout_ECX_00;
  uint *puVar11;
  undefined2 uVar12;
  byte *pbVar13;
  uint extraout_EDX;
  uint unaff_EBX;
  undefined *puVar14;
  byte **ppbVar15;
  byte **ppbVar16;
  uint *puVar17;
  uint *puVar18;
  int *piVar19;
  uint unaff_EBP;
  int unaff_ESI;
  uint *puVar20;
  uint *puVar21;
  undefined4 *puVar22;
  undefined4 *puVar23;
  byte *unaff_EDI;
  byte *pbVar24;
  uint *puVar25;
  undefined4 *puVar26;
  undefined4 *puVar27;
  undefined2 in_CS;
  byte bVar28;
  byte in_AF;
  bool bVar29;
  float10 in_ST0;
  float10 extraout_ST0;
  unkbyte10 in_ST1;
  unkbyte10 extraout_ST1;
  unkbyte10 extraout_ST1_00;
  undefined in_XMM6 [16];
  undefined auVar30 [16];
  undefined8 uVar31;
  
  bVar28 = in_EAX < 0x597b3126;
  LOCK();
  puVar27 = (undefined4 *)((param_2 - 0x44) + unaff_ESI * 8);
  puVar14 = (undefined *)*puVar27;
  *puVar27 = register0x00000010;
  UNLOCK();
  uVar7 = in((short)param_2);
  pcVar1 = (code *)swi(4);
  if (SBORROW4(in_EAX,0x597b3126) == true) {
    uVar31 = (*pcVar1)();
    param_2 = (uint)((ulonglong)uVar31 >> 0x20);
    uVar7 = (uint)uVar31;
    param_1 = extraout_ECX;
    in_ST0 = extraout_ST0;
    in_ST1 = extraout_ST1;
  }
  uVar9 = uVar7 + *(uint *)(unaff_EBP + 0x37);
  uVar8 = uVar9 + bVar28;
  if (!CARRY4(uVar7,*(uint *)(unaff_EBP + 0x37)) && !CARRY4(uVar9,(uint)bVar28))
  goto LAB_004012a0_4;
  _DAT_d7593b21 = _DAT_d7593b21 ^ unaff_EBX;
  bVar29 = (int)_DAT_d7593b21 < 0;
  ppbVar16 = (byte **)(puVar14 + -4);
  *(uint *)(puVar14 + -4) = unaff_EBP;
  uVar7 = unaff_EBX;
  if (bVar29) {
    LOCK();
    *(int *)(param_2 + 0xf18e51bf) = unaff_ESI;
    UNLOCK();
    *(undefined2 *)(puVar14 + -8) = in_CS;
    iVar2 = *(int *)(puVar14 + -8);
    bVar28 = 9 < ((byte)uVar8 & 0xf) | in_AF;
    bVar5 = (byte)uVar8 + bVar28 * -6 & 0xf;
    *(byte *)(unaff_EBX + 0x59) = *(byte *)(unaff_EBX + 0x59) ^ (byte)(unaff_EBX >> 8);
    ppbVar16 = *(byte ***)(puVar14 + -4);
    in_ST0 = (float10)*(int *)(unaff_EDI + -0x32) / in_ST0;
    puVar20 = (uint *)(iVar2 + -1);
    uVar9 = param_1 - 1;
    bVar29 = (bool)(9 < bVar5 | bVar28);
    uVar7 = CONCAT31((int3)(uVar8 >> 8),bVar5 + bVar29 * '\x06') & 0xffff000f;
    bVar5 = (byte)uVar7;
    uVar8 = CONCAT22((short)(uVar7 >> 0x10),CONCAT11(((char)(uVar8 >> 8) - bVar28) + bVar29,bVar5));
    uVar7 = uVar9;
    if (bVar29) {
      uVar7 = param_2;
      if ((POPCOUNT(unaff_EBX - 1 & 0xff) & 1U) == 0) {
        if (bVar5 < 0xb) {
          uVar12 = (undefined2)(unaff_EBX - 1);
          out(*puVar20,uVar12);
          *unaff_EDI = *(byte *)(iVar2 + 3);
          in(uVar12);
          *(uint *)((int)ppbVar16 + param_2 * 2 + 0x59398197) =
               *(uint *)((int)ppbVar16 + param_2 * 2 + 0x59398197) ^ (uint)(unaff_EDI + 1);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        return CONCAT31((int3)(uVar8 >> 8),bVar5 - 0xb);
      }
      goto LAB_00401233;
    }
  }
  else {
LAB_00401233:
    *(uint *)(uVar7 + 0x59) = *(uint *)(uVar7 + 0x59) ^ (uint)unaff_EDI;
    unaff_EDI = *ppbVar16;
    puVar20 = (uint *)ppbVar16[1];
    unaff_EBP = (uint)ppbVar16[2];
    param_2 = (uint)ppbVar16[4];
    unaff_EBX = (uint)ppbVar16[5];
    uVar9 = (uint)ppbVar16[6];
    _DAT_ab807831 = (int)ppbVar16[7];
    DAT_fa57a365 = (undefined)_DAT_ab807831;
    ppbVar15 = ppbVar16 + 7;
    ppbVar16 = ppbVar16 + 7;
    *ppbVar15 = (byte *)unaff_EBP;
    uVar8 = _DAT_ab807831 + 0x5b839df8 + (uint)((byte)((char)uVar8 - 0x23U) < 0x6f);
    uVar7 = uVar8;
  }
  if ((POPCOUNT(uVar7 & 0xff) & 1U) == 0) {
    LOCK();
    *(uint *)(uVar9 + 0x53) = param_2;
    UNLOCK();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar7 = (uint)*ppbVar16;
  puVar17 = (uint *)(ppbVar16 + 1);
  uVar7 = CONCAT22((short)(uVar8 >> 0x10),
                   CONCAT11(((uVar7 & 0x80) != 0) << 7 | ((uVar7 & 0x40) != 0) << 6 |
                            ((uVar7 & 0x10) != 0) << 4 | ((uVar7 & 4) != 0) << 2 | 2U |
                            (uVar7 & 1) != 0,(char)uVar8));
  *(char *)(unaff_EBX + 0x2bcdcad0) = *(char *)(unaff_EBX + 0x2bcdcad0) + (char)(unaff_EBX >> 8);
  ppuVar10 = (uint **)CONCAT31((int3)(uVar9 >> 8),0x5d);
  uVar9 = param_2 - 1;
  if ((POPCOUNT(uVar9 & 0xff) & 1U) != 0) {
LAB_004012eb:
    iVar2 = *puVar17;
    LOCK();
    ppbVar16 = (byte **)((int)puVar20 + (int)unaff_EDI * 8 + -0x7b30cb5f);
    pbVar13 = *ppbVar16;
    *ppbVar16 = unaff_EDI;
    UNLOCK();
    fpatan(in_ST1,in_ST0);
    LOCK();
    *ppuVar10 = puVar20;
    UNLOCK();
    pbVar24 = (byte *)((int)ppuVar10 + 0x597b472d);
    bVar28 = *pbVar24;
    bVar5 = (byte)(unaff_EBX >> 8);
    *pbVar24 = *pbVar24 - bVar5;
    *(int *)(iVar2 + -0x11) = *(int *)(iVar2 + -0x11) + uVar9 + (uint)(bVar28 < bVar5);
                    // WARNING: Could not recover jumptable at 0x0040130c. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar7 = (**(code **)((int)pbVar13 * 3 + -0x7e))();
    return uVar7;
  }
  LOCK();
  puVar21 = *ppuVar10;
  *ppuVar10 = (uint *)((int)puVar20 + -1);
  UNLOCK();
  if ((POPCOUNT((uint)(uint *)((int)puVar20 + -1) & 0xff) & 1U) == 0) {
    *puVar21 = *puVar21 ^ unaff_EBP;
    *(char *)(unaff_EBX - 0x77) = *(char *)(unaff_EBX - 0x77) << 1;
    pbVar13 = (byte *)(_DAT_66933186 * -0xf);
    *(uint *)(param_2 + 9) = *(uint *)(param_2 + 9) ^ (uint)unaff_EDI;
    puVar21[-0xf] = puVar21[-0xf] << 1;
    uVar7 = CONCAT31((int3)(uVar7 >> 8),(char)uVar8) | 0xf8;
    puVar18 = (uint *)((int)ppbVar16 + 5);
    *(byte **)((int)ppbVar16 + 5) = pbVar13;
    uVar9 = uVar9 | uVar7;
    uVar12 = SUB42(pbVar13,0);
    pbVar24 = unaff_EDI;
    if (uVar9 == 0) {
      *(char *)(unaff_EBP + 0x5ad9d7a6) = *(char *)(unaff_EBP + 0x5ad9d7a6) + 'X';
      LOCK();
      puVar20 = *ppuVar10;
      *ppuVar10 = puVar21;
      UNLOCK();
      bVar29 = (*(uint *)((int)ppbVar16 + 5) & 0x400) != 0;
      ppuVar10 = *(uint ***)((int)ppbVar16 + uVar7 * 4 + 9);
      pbVar24 = unaff_EDI + (uint)bVar29 * -2 + 1;
      bVar5 = *unaff_EDI;
      bVar28 = *(byte *)puVar20;
      LOCK();
      puVar21 = *ppuVar10;
      *ppuVar10 = (uint *)((int)puVar20 + (uint)bVar29 * -2 + 1);
      UNLOCK();
      auVar30._0_4_ = in_XMM6._0_4_ - *(float *)((int)puVar21 + -0x594dc40f);
      auVar30._4_4_ = in_XMM6._4_4_ - *(float *)((int)puVar21 + -0x594dc40b);
      auVar30._8_4_ = in_XMM6._8_4_ - *(float *)((int)puVar21 + -0x594dc407);
      auVar30._12_4_ = in_XMM6._12_4_ - *(float *)((int)puVar21 + -0x594dc403);
      puVar18 = (uint *)0x402041da;
      uVar6 = in(uVar12);
      uVar7 = CONCAT31(0xb87f68,uVar6);
      if (bVar28 < bVar5) {
        puVar25 = (uint *)(pbVar24 + (uint)bVar29 * -2 + 1);
        bVar28 = in(uVar12);
        *pbVar24 = bVar28;
        puVar11 = (uint *)CONCAT22((ushort)((uint)ppuVar10 >> 0x10) |
                                   (ushort)((uint)pbVar13 >> 0x10),(short)uRamffffffe9);
        puVar20 = puVar25 + 0xc;
        bVar28 = *(byte *)puVar20;
        puRam402041d6 = puVar21;
        *(char *)puVar20 = *(char *)puVar20 >> 1;
        puVar20 = puVar21 + (uint)bVar29 * -2 + 1;
        *puVar25 = *puVar21;
        uVar4 = uRambcd7a13e;
        piVar19 = (int *)0xbcd7a142;
        if ((POPCOUNT((bVar28 & 1) + 0x40) & 1U) != 0) {
          piVar19 = (int *)0xbcd7a143;
        }
        *puVar11 = *puVar11 ^ (uint)pbVar13;
        iVar3 = *piVar19;
        uVar7 = in(uVar12);
        *(uint *)((int)piVar19 + unaff_EBP + 0x510ece8f) =
             *(uint *)((int)piVar19 + unaff_EBP + 0x510ece8f) ^ uVar7;
        out(*puVar20,uVar12);
        uVar6 = in(uVar12);
        *(undefined *)(puVar25 + (uint)bVar29 * -2 + 1) = uVar6;
        out(puVar20[(uint)bVar29 * -2 + 1],uVar12);
        puVar26 = (undefined4 *)
                  ((int)(puVar25 + (uint)bVar29 * -2 + 1) +
                  (uint)bVar29 * -2 + (uint)bVar29 * -2 + 2);
        puVar22 = (undefined4 *)
                  ((int)(puVar20 + (uint)bVar29 * -2 + 1) +
                  (uint)bVar29 * -2 + (uint)bVar29 * -8 + 5);
        iVar2 = *(int *)((int)puVar22 + 0x3e93cdf2);
        puVar20 = (uint *)(CONCAT31((int3)((uint)uVar4 >> 8),(char)uVar4 + *(char *)(iVar3 + -0x79))
                          + -0x30);
        *puVar20 = *puVar20 ^ (uint)puVar26;
        swi(4);
        *(undefined2 *)(iVar2 * -2 + -4) = in_CS;
        puVar27 = puVar26 + (uint)bVar29 * -2 + 1;
        puVar23 = puVar22 + (uint)bVar29 * -2 + 1;
        *puVar26 = *puVar22;
        out(*puVar23,uVar12);
        *pbVar13 = *pbVar13 | 0xd0;
        LOCK();
        UNLOCK();
        if ((POPCOUNT((uint)puVar27 & (uint)(puVar23 + (uint)bVar29 * -2 + 1) & 0xff) & 1U) != 0) {
          LOCK();
          UNLOCK();
          minps(auVar30,*(undefined (*) [16])((int)puRam0d504111 + -0x49ad6f0f));
          pcVar1 = (code *)swi(1);
          puRam0d504111 = puVar23 + (uint)bVar29 * -2 + 1;
          puRamb3d4f7d0 = puVar27;
          uVar7 = (*pcVar1)();
          return uVar7;
        }
        uVar6 = in((short)CONCAT31((int3)((uint)pbVar13 >> 8),6));
        *(undefined *)puRamb3d4f7d0 = uVar6;
        puRamb3d4f7d0 = puVar27;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    LOCK();
    *(uint *)(uVar9 + 0x7b) = uVar9;
    UNLOCK();
    uVar7 = uVar7 ^ *(uint *)(pbVar24 + -0x78cc87a5);
    bVar29 = (POPCOUNT(uVar7 & 0xff) & 1U) != 0;
    uVar9 = *puVar18;
    if (!bVar29) {
      LOCK();
      puVar20 = *ppuVar10;
      *ppuVar10 = puVar21;
      UNLOCK();
      if (bVar29) {
        *(uint *)(uVar9 + 0x15) = unaff_EBP;
        LOCK();
        *(char *)ppuVar10 = (char)((uint)pbVar13 >> 8);
        UNLOCK();
LAB_004012a0_4:
        pcVar1 = (code *)swi(1);
        uVar7 = (*pcVar1)();
        return uVar7;
      }
      out(uVar12,uVar7);
      *(uint *)(pbVar24 + -0x78d12c27) =
           (*(int *)(pbVar24 + -0x78d12c27) - uVar7) - (uint)CARRY4(uVar9,unaff_EBP);
      *(undefined2 *)puVar18 = in_CS;
      puVar17 = puVar18 + -1;
      puVar18[-1] = 0x4012d8;
      in_ST0 = (float10)func_0x2c84ca04();
      uVar9 = 0xbcb0eab2;
      _DAT_bcb0eae5 = _DAT_bcb0eae5 ^ (uint)pbVar24;
      LOCK();
      ppbVar16 = (byte **)((int)puVar20 + (int)pbVar24 * 8 + -0x7b30cb53);
      pbVar13 = *ppbVar16;
      *ppbVar16 = pbVar24;
      UNLOCK();
      unaff_EDI = (byte *)((uint)pbVar13 | unaff_EBP);
      ppuVar10 = extraout_ECX_00;
      unaff_EBX = extraout_EDX;
      in_ST1 = extraout_ST1_00;
      goto LAB_004012eb;
    }
  }
  return uVar7;
}



void __fastcall entry(int param_1,uint param_2)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x3187597b;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x1e9718b9;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2);
  return;
}


