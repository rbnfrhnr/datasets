typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
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




// WARNING: Instruction at (ram,0x0040121a) overlaps instruction at (ram,0x00401219)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00401219(int param_1,int param_2)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  code *pcVar4;
  byte bVar5;
  byte bVar6;
  byte bVar12;
  int in_EAX;
  byte *pbVar7;
  uint uVar8;
  int iVar9;
  undefined *puVar10;
  undefined *puVar11;
  byte bVar13;
  char cVar14;
  undefined2 extraout_DX;
  int unaff_EBX;
  undefined4 *puVar15;
  undefined4 *unaff_EBP;
  byte *unaff_ESI;
  byte *pbVar16;
  byte *unaff_EDI;
  byte in_CF;
  bool bVar17;
  bool bVar18;
  bool bVar19;
  undefined in_SF;
  bool bVar20;
  byte in_TF;
  byte in_IF;
  bool in_OF;
  bool bVar21;
  bool bVar22;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined auStack_1644 [5612];
  undefined *puStack_58;
  undefined4 uStack_c;
  
  if (!in_OF) {
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  do {
    if ((bool)in_SF) {
code_r0x004011c5:
      *unaff_EDI = *unaff_ESI;
      LOCK();
      *(int *)(param_2 + -0x51c5bbfb) = param_2;
      UNLOCK();
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    pbVar7 = (byte *)(in_EAX + -0xfd8d20c + (uint)in_CF);
    bVar18 = ((uint)pbVar7 & 0x1000) != 0;
    puVar1 = (uint *)(unaff_EDI + param_2 + -0x52);
    *puVar1 = *puVar1 | (uint)unaff_ESI;
    if (-1 < (int)*puVar1) {
      iVar9 = (int)(unaff_ESI + -0x630487c9) * 2 + (uint)((byte *)0x630487c8 < unaff_ESI);
      uVar8 = 0x4678f559;
      bVar5 = (byte)iVar9;
      bVar12 = bVar5 - *(byte *)(param_2 + -0x5db95188);
      bVar18 = 9 < (bVar12 & 0xf) || bVar18;
      bVar12 = bVar12 + bVar18 * -6;
      bVar5 = 0x9f < bVar12 | bVar5 < *(byte *)(param_2 + -0x5db95188) | bVar18 * (bVar12 < 6);
      puVar10 = (undefined *)CONCAT31((int3)((uint)iVar9 >> 8),bVar12 + bVar5 * -0x60);
      puVar1 = (uint *)(puVar10 + -0x75);
      bVar17 = CARRY4(*puVar1,(uint)puVar10) || CARRY4((uint)(puVar10 + *puVar1),(uint)bVar5);
      *puVar1 = (uint)(puVar10 + *puVar1 + bVar5);
      break;
    }
    bVar18 = 9 < ((byte)unaff_ESI & 0xf) || bVar18;
    bVar5 = (byte)unaff_ESI + bVar18 * '\x06';
    bVar13 = (byte)((uint)param_2 >> 8);
    bVar12 = (byte)((uint)unaff_ESI >> 8) ^ bVar13;
    iVar9 = CONCAT22((short)((uint)unaff_ESI >> 0x10),
                     CONCAT11(bVar12,bVar5 + (0x90 < (bVar5 & 0xf0) | bVar18 * (0xf9 < bVar5)) * '`'
                             ));
    if ((char)bVar12 < '\0') {
      bVar5 = (char)((uint)param_1 >> 8) - pbVar7[-0xc];
      param_1 = (uint)bVar5 << 8;
      if ((short)((ushort)bVar5 << 8) < 0) {
        do {
                    // WARNING: Do nothing block with infinite loop
        } while( true );
      }
      uVar8 = iVar9 << 1;
      unaff_EDI[-0xc870beb] = 0;
      pbVar16 = unaff_EDI + 1;
      *unaff_EDI = (byte)uVar8;
    }
    else {
      iVar9 = iVar9 + 0x46be9477;
      bVar6 = (byte)iVar9;
      pbVar16 = unaff_EDI + 0x29;
      bVar5 = *pbVar16;
      DAT_1c70272f = bVar6;
      *pbVar16 = *pbVar16 - bVar13;
      bVar12 = *pbVar7;
      *pbVar7 = *pbVar7 >> 1 | (bVar5 < bVar13) << 7;
      bVar18 = 9 < (bVar6 & 0xf) || bVar18;
      bVar6 = bVar6 + bVar18 * -6;
      bVar5 = 0x9f < bVar6 | (bVar12 & 1) != 0 | bVar18 * (bVar6 < 6);
      uVar8 = (CONCAT31((int3)((uint)iVar9 >> 8),bVar6 + bVar5 * -0x60) - param_2) - (uint)bVar5;
      pbVar16 = unaff_EDI;
      if (-1 < (int)uVar8) {
        pcVar4 = (code *)swi(3);
        (*pcVar4)();
        return;
      }
    }
    puStack_58 = &stack0xfffffff8;
    puVar15 = (undefined4 *)&stack0xfffffff8;
    cVar14 = '\x13';
    do {
      unaff_EBP = unaff_EBP + -1;
      puVar15 = puVar15 + -1;
      *puVar15 = *unaff_EBP;
      cVar14 = cVar14 + -1;
    } while ('\0' < cVar14);
    unaff_EDI = pbVar16 + 1;
    uVar8 = (uVar8 | 0x78f5ada9) + 0x390f901f + (uint)((byte)(uVar8 | 0x78f5ada9) < *pbVar16);
    unaff_EBP = (undefined4 *)((int)&uStack_c + 3);
    unaff_ESI = pbVar7;
    if (-1 < (int)auStack_1644) {
      param_2 = unaff_EBX;
      if (-1 < (int)auStack_1644) {
        func_0x511a1d9a();
        out(*pbVar7,extraout_DX);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      goto code_r0x004011c5;
    }
    uVar2 = (uint)((byte)((uint)param_1 >> 8) < pbVar7[0x4e87ff7f]);
    uVar3 = uVar8 + 0x717993f4;
    in_CF = 0x8e866c0b < uVar8 || CARRY4(uVar3,uVar2);
    in_EAX = uVar3 + uVar2;
    in_SF = in_EAX < 0;
    puStack_58 = &stack0xfffffff8;
  } while( true );
LAB_004012af:
  do {
    puVar11 = puVar10;
    unaff_EBX = (unaff_EBX - uVar8) - (uint)bVar17;
    bVar17 = CARRY4(uVar8,(uint)unaff_EBP);
    bVar21 = SCARRY4(uVar8,(int)unaff_EBP);
    uVar8 = uVar8 + (int)unaff_EBP;
    puVar10 = (undefined *)register0x00000010;
  } while (uVar8 != 0 && bVar21 == (int)uVar8 < 0);
  pbVar7 = (byte *)((int)unaff_EBP + -0x51ed0b81);
  bVar12 = (byte)((uint)param_1 >> 8);
  bVar5 = bVar12 + *pbVar7;
  bVar21 = CARRY1(bVar12,*pbVar7) || CARRY1(bVar5,bVar17);
  bVar22 = SCARRY1(bVar12,*pbVar7) != SCARRY1(bVar5,bVar17);
  bVar5 = bVar5 + bVar17;
  bVar20 = (char)bVar5 < '\0';
  bVar19 = bVar5 == 0;
  bVar17 = (POPCOUNT(bVar5) & 1U) == 0;
  if (bVar22 != bVar20) {
    if (bVar20) {
      LOCK();
      iVar9 = *(int *)(unaff_EBX + -0x51c5bbcb);
      *(int *)(unaff_EBX + -0x51c5bbcb) = unaff_EBX;
      UNLOCK();
      *(uint *)(puVar11 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)bVar22 * 0x800 | (uint)(in_IF & 1) * 0x200 |
           (uint)(in_TF & 1) * 0x100 | (uint)bVar20 * 0x80 | (uint)bVar19 * 0x40 |
           (uint)bVar18 * 0x10 | (uint)bVar17 * 4 | (uint)bVar21 | (uint)(in_ID & 1) * 0x200000 |
           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
           (uint)(in_AC & 1) * 0x40000;
      puVar1 = (uint *)(uVar8 + 0x57 + iVar9);
      *puVar1 = *puVar1 >> 1;
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    goto code_r0x004012c5;
  }
  pbVar7 = (byte *)(uVar8 + 0xad12f47f);
  bVar12 = bVar5 + *pbVar7;
  bVar17 = CARRY1(bVar5,*pbVar7) || CARRY1(bVar12,bVar21);
  bVar13 = bVar12 + bVar21;
  param_1 = (uint)bVar13 << 8;
  if (bVar13 == 0 ||
      (SCARRY1(bVar5,*pbVar7) != SCARRY1(bVar12,bVar21)) != (short)((ushort)bVar13 << 8) < 0) {
    pbVar7 = (byte *)(uVar8 + 0xae78f47d);
    bVar5 = bVar13 + *pbVar7;
    bVar21 = CARRY1(bVar13,*pbVar7) || CARRY1(bVar5,bVar17);
    bVar22 = SCARRY1(bVar13,*pbVar7) != SCARRY1(bVar5,bVar17);
    cVar14 = bVar5 + bVar17;
    bVar20 = cVar14 < '\0';
    bVar19 = cVar14 == '\0';
    bVar17 = (POPCOUNT(cVar14) & 1U) == 0;
code_r0x004012c5:
    *(uint *)(puVar11 + -4) =
         (uint)(in_NT & 1) * 0x4000 | (uint)bVar22 * 0x800 | (uint)(in_IF & 1) * 0x200 |
         (uint)(in_TF & 1) * 0x100 | (uint)bVar20 * 0x80 | (uint)bVar19 * 0x40 | (uint)bVar18 * 0x10
         | (uint)bVar17 * 4 | (uint)bVar21 | (uint)(in_ID & 1) * 0x200000 |
         (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
    *(BADSPACEBASE **)(puVar11 + -4) = register0x00000010;
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  bVar17 = !CARRY1(bVar5,*pbVar7) && !CARRY1(bVar12,bVar21);
  goto LAB_004012af;
}



// WARNING: Unable to track spacebase fully for stack

void entry(void)

{
  uint *puVar1;
  uint *puVar2;
  undefined4 *puVar3;
  uint **ppuVar4;
  uint *puVar5;
  short sVar6;
  undefined2 in_SS;
  int *piVar7;
  
  sVar6 = (short)&stack0xffffffe0 + -4;
  piVar7 = (int *)CONCAT22((short)((uint)&stack0xffffffe0 >> 0x10),sVar6);
  puVar3 = (undefined4 *)segment(in_SS,sVar6);
  *puVar3 = 0x43000c;
  ppuVar4 = (uint **)(*piVar7 + 0x5a);
  do {
    puVar5 = *ppuVar4;
    puVar1 = ppuVar4[1];
    puVar2 = ppuVar4[2];
    do {
      *puVar5 = *puVar5 ^ (uint)puVar2;
      puVar5 = puVar5 + 1;
    } while ((int)puVar5 < (int)puVar1);
    ppuVar4 = ppuVar4 + 3;
  } while (*ppuVar4 != (uint *)0x0);
  FUN_00401219(piVar7[7],piVar7[6]);
  return;
}


