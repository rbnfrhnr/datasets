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
// WARNING: Instruction at (ram,0x004011d0) overlaps instruction at (ram,0x004011cf)
// 
// WARNING: Removing unreachable block (ram,0x004013c2)
// WARNING: Removing unreachable block (ram,0x00401348)
// WARNING: Removing unreachable block (ram,0x004012ed)
// WARNING: Removing unreachable block (ram,0x00401149)
// WARNING: Removing unreachable block (ram,0x0040114f)
// WARNING: Removing unreachable block (ram,0x00401156)
// WARNING: Removing unreachable block (ram,0x004013b1)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __fastcall FUN_00401219(uint param_1,uint **param_2)

{
  byte *pbVar1;
  uint *puVar2;
  uint uVar3;
  longlong lVar4;
  code *pcVar5;
  byte bVar6;
  byte bVar7;
  undefined uVar8;
  byte bVar12;
  undefined3 uVar13;
  int iVar9;
  uint **in_EAX;
  uint **ppuVar10;
  int *piVar11;
  char cVar14;
  uint uVar16;
  uint uVar17;
  int *extraout_ECX;
  uint **ppuVar18;
  uint **ppuVar19;
  uint **extraout_EDX;
  uint **unaff_EBX;
  uint uVar20;
  uint **unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 *puVar21;
  uint *puVar22;
  uint *puVar23;
  uint **ppuVar24;
  uint **unaff_EDI;
  undefined2 in_CS;
  undefined2 in_DS;
  bool bVar25;
  bool in_PF;
  byte in_AF;
  bool bVar26;
  bool bVar27;
  undefined in_SF;
  bool bVar28;
  bool bVar29;
  undefined2 in_FPUStatusWord;
  undefined2 uVar30;
  uint **unaff_retaddr;
  undefined4 uStack_1ea9;
  uint *puStack_c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  char cVar15;
  
  bVar28 = false;
  if (in_PF) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  while (!(bool)in_SF) {
    uStack_4 = (uint **)CONCAT22(uStack_4._2_2_,in_DS);
    ppuVar10 = in_EAX;
code_r0x0040121e:
    in_EAX = (uint **)((int)ppuVar10 + 0x786d040a);
    ppuVar24 = unaff_EBP;
    puVar21 = unaff_ESI;
    do {
      uVar30 = SUB42(unaff_retaddr,0);
      cVar15 = (char)param_1;
      cVar14 = cVar15 + *(char *)((int)in_EAX + 0x3a);
      param_1 = CONCAT31((int3)(param_1 >> 8),cVar14);
      if (cVar14 != '\0' && SCARRY1(cVar15,*(char *)((int)in_EAX + 0x3a)) == cVar14 < '\0') {
        unaff_ESI = puVar21 + (uint)bVar28 * -2 + 1;
        out(*puVar21,(short)param_2);
        unaff_retaddr = param_2;
        goto code_r0x0040129a;
      }
      bVar6 = (byte)((short)in_EAX / (short)*(char *)unaff_EBX);
      ppuVar10 = (uint **)CONCAT22((short)((uint)in_EAX >> 0x10),
                                   CONCAT11((char)((short)in_EAX % (short)*(char *)unaff_EBX),bVar6)
                                  );
      unaff_retaddr = (uint **)CONCAT22((short)((uint)unaff_retaddr >> 0x10),in_DS);
      uVar17 = param_1;
      param_2 = param_2;
      unaff_EBP = ppuVar24;
      unaff_ESI = puVar21;
      if ((POPCOUNT((byte)in_EAX & 0x1c) & 1U) == 0) {
        unaff_ESI = puVar21 + (uint)bVar28 * -2 + 1;
        out(*puVar21,(short)param_2);
        bVar12 = 9 < (bVar6 & 0xf) | in_AF;
        bVar7 = bVar6 + bVar12 * -6;
        ppuVar10 = (uint **)CONCAT31((int3)((uint)ppuVar10 >> 8),
                                     bVar7 + (0x9f < bVar7 |
                                             bVar6 < *(byte *)unaff_EDI | bVar12 * (bVar7 < 6)) *
                                             -0x60);
        goto LAB_0040123c;
      }
LAB_004011cc:
      unaff_ESI = (undefined4 *)((uint)unaff_ESI | (uint)ppuVar10[(int)unaff_EBP]);
      LOCK();
      param_1 = *(uint *)((int)param_2 + 0xe);
      *(uint *)((int)param_2 + 0xe) = uVar17;
      UNLOCK();
      bVar25 = false;
      bVar29 = false;
      uVar13 = (undefined3)((uint)(undefined *)((int)ppuVar10 + -1) >> 8);
      bVar6 = (byte)(undefined *)((int)ppuVar10 + -1) & *(byte *)unaff_EBX;
      param_2 = (uint **)CONCAT31(uVar13,bVar6);
      bVar27 = (char)bVar6 < '\0';
      bVar26 = bVar6 == 0;
      if ((char)bVar6 < '\x01') {
        if ((POPCOUNT(bVar6) & 1U) != 0) {
          if ((char)bVar6 < '\x01') {
            do {
              if (bVar25) {
                param_2 = (uint **)((uint)param_2 | 0x9d7f7884);
                bVar6 = (byte)param_2;
                ppuVar10 = _DAT_12e875f2;
                if (0x70 < bVar6) goto code_r0x004011a6;
              }
              else {
                ppuVar10 = unaff_EBP;
                if (bVar26 || bVar29 != bVar27) {
                  *(byte *)((int)param_2 + 0x77) = *(byte *)((int)param_2 + 0x77) | 0x7c;
                  pcVar5 = (code *)swi(3);
                  iVar9 = (*pcVar5)();
                  return iVar9;
                }
              }
              _DAT_12e875f2 = ppuVar10;
              *(byte *)(unaff_EBP + 4) = *(byte *)(unaff_EBP + 4) | 0xed;
              param_1 = param_1 & 0x12bbfb07;
              bVar25 = unaff_EBP < param_2;
              unaff_retaddr = (uint **)((int)unaff_EBP - (int)param_2);
              bVar29 = SBORROW4((int)unaff_EBP,(int)param_2) != false;
              bVar27 = (int)unaff_retaddr < 0;
              bVar26 = unaff_retaddr == (uint **)0x0;
              cVar14 = '\x12';
              ppuVar10 = (uint **)register0x00000010;
              ppuVar24 = unaff_retaddr;
              do {
                ppuVar24 = ppuVar24 + -1;
                ppuVar10 = ppuVar10 + -1;
                *ppuVar10 = *ppuVar24;
                cVar14 = cVar14 + -1;
              } while ('\0' < cVar14);
              ppuVar10 = (uint **)register0x00000010;
              unaff_EBP = (uint **)register0x00000010;
              if (bVar27) goto code_r0x00401218;
            } while( true );
          }
          ppuVar10 = (uint **)CONCAT31(uVar13,bVar6 + 0x1e);
          bVar25 = false;
          goto code_r0x004011b5;
        }
        ppuVar24 = unaff_EDI;
        if (bVar26) {
          pcVar5 = (code *)swi(0x68);
          iVar9 = (*pcVar5)();
          return iVar9;
        }
        goto LAB_004011bc_3;
      }
      bVar28 = false;
      ppuVar18 = (uint **)((uint)param_2 & (uint)&uStack_4);
      ppuVar19 = (uint **)&uStack_8;
      ppuVar24 = (uint **)&uStack_8;
      ppuVar10 = (uint **)&uStack_8;
      uStack_8 = unaff_EBP;
      cVar14 = '\x17';
      do {
        unaff_EBP = unaff_EBP + -1;
        ppuVar19 = ppuVar19 + -1;
        *ppuVar19 = *unaff_EBP;
        cVar14 = cVar14 + -1;
      } while ('\0' < cVar14);
      in_EAX = (uint **)((uint)param_2 | 0x78f9a678);
      param_2 = ppuVar18;
      puVar21 = unaff_ESI;
    } while (0 < (int)in_EAX);
    param_2 = (uint **)((int)ppuVar18 + *(int *)((int)in_EAX + 0x3a4832de));
    if (param_2 != (uint **)0x0 &&
        (SCARRY4((int)ppuVar18,*(int *)((int)in_EAX + 0x3a4832de)) != SCARRY4((int)param_2,0)) ==
        (int)param_2 < 0) {
      if ((int)param_2 >= 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      unaff_retaddr = (uint **)0xdafc78f8;
      iVar9 = param_1 - 1;
      if (iVar9 != 0 && param_2 != (uint **)0x0) {
        *(undefined2 *)((int)unaff_EBX + -0x7d) = in_FPUStatusWord;
        goto LAB_004012d3_1;
      }
      param_2 = (uint **)CONCAT22((short)((uint)param_2 >> 0x10),CONCAT11(0x97,(char)param_2));
      param_1 = CONCAT22((short)((uint)iVar9 >> 0x10),CONCAT11(0x84,(char)iVar9));
      in_AF = 9 < ((byte)in_EAX & 0xf) | in_AF;
      bVar6 = (byte)in_EAX + in_AF * -6;
      in_EAX = (uint **)CONCAT22((short)((uint)in_EAX >> 0x10),
                                 (ushort)(byte)(bVar6 + (0x9f < bVar6 | in_AF * (bVar6 < 6)) * -0x60
                                               ) * (ushort)*(byte *)param_2);
      unaff_EBX = (uint **)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                                    CONCAT11((char)((uint)unaff_EBX >> 8) +
                                             *(char *)((int)unaff_EDI + 0x1e),(char)unaff_EBX));
      puVar23 = (uint *)((int)unaff_EBX + 0x78f8bd1b);
      *puVar23 = *puVar23 ^ (uint)unaff_EDI;
      uVar17 = *puVar23;
      if ((int)uVar17 < 1) goto code_r0x0040129a;
      ppuVar10 = in_EAX;
      if ((int)uVar17 < 1) goto code_r0x004012ba;
      uVar8 = (undefined)((longlong)(int)unaff_EBX[(int)&uStack_8 + 3] * -0x751e7e35);
      if (uVar17 == 0) {
        return CONCAT22((short)((ulonglong)
                                ((longlong)(int)unaff_EBX[(int)&uStack_8 + 3] * -0x751e7e35) >> 0x10
                               ),CONCAT11(0x4e,uVar8));
      }
      out(0xf,uVar8);
      *(char *)(unaff_EBX + -0x79f8d3e) = -*(char *)(unaff_EBX + -0x79f8d3e);
      piVar11 = (int *)func_0xf6386fe9();
      goto code_r0x0040130c;
    }
    XRELEASE();
    LOCK();
    param_2 = *(uint ***)(undefined4 *)((int)unaff_EDI + 0x7f794046);
    *(undefined4 *)((int)unaff_EDI + 0x7f794046) = unaff_EBX;
    UNLOCK();
    uStack_1ea9 = CONCAT22(uStack_1ea9._2_2_,in_DS);
    unaff_EBX = in_EAX;
code_r0x00401218:
    in_EAX = param_2;
    param_1 = uStack_1ea9;
    param_2 = param_2;
    unaff_EBP = ppuVar10;
    in_SF = false;
  }
  param_2 = (uint **)CONCAT31((int3)((uint)param_2 >> 8),
                              (char)param_2 - *(char *)((int)unaff_EDI + 0x526fc01d));
code_r0x0040129a:
  ppuVar10 = (uint **)((int)unaff_EDI +
                      (0x6ad9040 - (uint)(unaff_EDI < *(uint ***)((int)in_EAX + 0x2a))));
  if ((int)ppuVar10 < 0) {
LAB_0040123c:
    bVar12 = (byte)((short)ppuVar10 % (short)*(char *)(unaff_EBX + 4));
    pbVar1 = (byte *)((int)unaff_ESI + -0x1e123de);
    bVar6 = *pbVar1;
    *pbVar1 = *pbVar1 - bVar12;
    cVar14 = (char)unaff_EBX + bVar12 + (bVar6 < bVar12);
    puVar23 = (uint *)CONCAT31((int3)((uint)unaff_EBX >> 8),cVar14);
    if (-1 < cVar14) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    puVar23 = unaff_ESI + -0x146ca022;
    *puVar23 = *puVar23 & param_1;
    uVar17 = *puVar23;
    bVar12 = 9 < ((byte)ppuVar10 & 0xf) | in_AF;
    bVar7 = (byte)ppuVar10 + bVar12 * -6;
    pbVar1 = (byte *)((int)unaff_EBX + -0x79);
    *pbVar1 = *pbVar1 >> 3 | *pbVar1 << 5;
    bVar6 = *pbVar1;
    *(bool *)in_EAX = 0 < (int)uVar17;
    if (-1 < (char)bVar6) {
LAB_004012d3_1:
      *(char *)(unaff_EBX + -1) = *(char *)(unaff_EBX + -1) + -0x49;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    unaff_EBX = (uint **)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                                  CONCAT11((char)((uint)unaff_EBX >> 8) + *(char *)(in_EAX + 0x1d),
                                           (char)unaff_EBX));
    ppuVar10 = (uint **)CONCAT31((int3)((uint)ppuVar10 >> 8),
                                 bVar7 + (0x9f < bVar7 | bVar12 * (bVar7 < 6)) * -0x60);
    unaff_EDI = in_EAX;
code_r0x004012ba:
    pbVar1 = (byte *)((int)&uStack_8 + (int)unaff_ESI * 2);
    bVar6 = (byte)((uint)unaff_EBX >> 8);
    cVar14 = bVar6 + *pbVar1 + *(char *)((int)unaff_EDI + 0x76) + CARRY1(bVar6,*pbVar1);
    puVar23 = (uint *)CONCAT22((short)((uint)unaff_EBX >> 0x10),CONCAT11(cVar14,(char)unaff_EBX));
    if (cVar14 < '\0') {
LAB_00401344:
      uVar16 = param_1 & 0x4020bf71;
      bVar25 = ((uint)unaff_retaddr & 0x400) != 0;
      puVar22 = (uint *)((int)unaff_ESI + -1);
      unaff_EDI = (uint **)((int)unaff_EDI + (uint)bVar25 * -2 + 1);
      bVar28 = 9 < ((byte)ppuVar10 & 0xf) || ((uint)unaff_retaddr & 0x10) != 0;
      bVar12 = (byte)ppuVar10 + bVar28 * -6;
      puVar2 = puVar22 + (int)param_2;
      _DAT_714bbcb1 = ppuVar10;
      *(byte *)puVar2 = *(byte *)puVar2 >> 2 | *(char *)puVar2 << 6;
      *(char *)(uVar16 - 0x79) = *(char *)(uVar16 - 0x79) + (char)((uint)puVar23 >> 8);
      bVar6 = 9 < (bVar12 & 0xf) || bVar28;
      bVar12 = bVar12 + bVar6 * -6;
      uVar17 = CONCAT31((int3)((uint)ppuVar10 >> 8),bVar12) & 0xffffff0f;
      ppuVar10 = (uint **)CONCAT22((short)(uVar17 >> 0x10),
                                   CONCAT11((char)((uint)ppuVar10 >> 8) - bVar6,(char)uVar17));
      unaff_retaddr = param_2;
      if ((bVar12 & 2) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
LAB_004013e0:
      uVar13 = (undefined3)(uVar16 >> 8);
      bVar7 = -(char)uVar16;
      uVar17 = CONCAT31(uVar13,bVar7);
      bVar12 = bVar7;
      do {
        if (bVar12 != 0) {
          uStack_4 = (uint **)CONCAT22(uStack_4._2_2_,in_DS);
code_r0x00401422:
          pcVar5 = (code *)swi(1);
          iVar9 = (*pcVar5)();
          return iVar9;
        }
        puVar2 = puVar22 + -0x1c;
        *puVar2 = *puVar2 | 0x61;
        bVar28 = (int)*puVar2 < 0;
        uVar16 = *puVar2;
        if ((int)uVar16 < 1) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        ppuVar24 = (uint **)((int)ppuVar10 * 5 + 0x6b);
        uVar8 = in(0x12);
        ppuVar10 = (uint **)CONCAT31((int3)((uint)ppuVar10 >> 8),uVar8);
        bVar12 = (byte)((uint)param_2 >> 8);
        ppuVar19 = ppuVar10;
        if (0 < (int)uVar16) {
          if (uVar16 != 0) {
            puVar23 = (uint *)((int)ppuVar10 * -0x70 + -8);
            *puVar23 = *puVar23 & 0x78;
            pcVar5 = (code *)swi(1);
            iVar9 = (*pcVar5)();
            return iVar9;
          }
          goto LAB_00401371;
        }
        while( true ) {
          ppuVar24 = ppuVar19 + -0x20;
          ppuVar10 = (uint **)((int)ppuVar19[(int)param_2] * -0x69);
          if (!bVar28) break;
          unaff_retaddr = (uint **)0x0;
          ppuVar19 = unaff_EDI;
          unaff_EDI = ppuVar10;
        }
        if ((int)((uint)ppuVar10 | 0x3ef683) < 1) goto code_r0x00401422;
        *(int *)(uVar17 + 0x73) = *(int *)(uVar17 + 0x73) - uVar17;
        ppuVar10 = (uint **)((uint)ppuVar10 | 0x2cfff7f3);
        if ((int)ppuVar10 < 0) goto code_r0x0040144c;
        bVar12 = bVar12 ^ 0xd9;
        param_2 = (uint **)((uint)param_2 ^ 0xd900);
      } while( true );
    }
  }
  out((short)param_2,unaff_retaddr);
  piVar11 = (int *)(CONCAT31((int3)((uint)unaff_retaddr >> 8),
                             *(undefined *)((int)puVar23 + ((uint)unaff_retaddr & 0xff))) +
                   -0x40b60395);
  *piVar11 = *piVar11 + -0xb;
  do {
  } while (*piVar11 == 0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
code_r0x004011a6:
  unaff_EBX = (uint **)(param_1 + 0x15);
  unaff_retaddr = (uint **)CONCAT22((short)((uint)unaff_retaddr >> 0x10),in_DS);
  in_AF = 9 < (bVar6 & 0xf) | in_AF;
  uVar17 = CONCAT31((int3)((uint)param_2 >> 8),bVar6 + in_AF * -6) & 0xffffff0f;
  bVar12 = (byte)uVar17;
  ppuVar10 = (uint **)CONCAT22((short)(uVar17 >> 0x10),
                               CONCAT11((char)((uint)param_2 >> 8) - in_AF,bVar12));
  if ('o' < (char)bVar6) {
    if ((char)bVar6 < 'q') goto code_r0x0040121e;
    goto LAB_0040123c;
  }
  ppuVar24 = (uint **)((int)unaff_EDI + (uint)bVar28 * -2 + 1);
  bVar25 = bVar12 < *(byte *)unaff_EDI;
  cVar14 = *(char *)unaff_EDI;
  param_2 = (uint **)0xf81e7778;
  unaff_EDI = ppuVar24;
  if (-1 < (char)(bVar12 - cVar14)) {
code_r0x004011b5:
    uStack_4 = (uint **)CONCAT22(uStack_4._2_2_,uVar30);
    pbVar1 = (byte *)(param_1 + 0xfbf81e04);
    bVar6 = *pbVar1;
    bVar12 = *pbVar1 + (byte)ppuVar10;
    *pbVar1 = bVar12 + bVar25;
    piVar11 = (int *)((int)ppuVar10 + 0x79);
    uVar17 = (uint)(CARRY1(bVar6,(byte)ppuVar10) || CARRY1(bVar12,bVar25));
    bVar29 = SBORROW4(*piVar11,(int)ppuVar10) != SBORROW4(*piVar11 - (int)ppuVar10,uVar17);
    *piVar11 = (*piVar11 - (int)ppuVar10) - uVar17;
    bVar27 = *piVar11 < 0;
    bVar26 = *piVar11 == 0;
    ppuVar24 = unaff_EDI;
LAB_004011bc_3:
    if (!bVar26 && bVar29 == bVar27) {
      return 0x7940190a;
    }
    unaff_EBX = (uint **)0x7940190a;
    bVar28 = ((uint)unaff_retaddr & 0x400) != 0;
    in_AF = ((uint)unaff_retaddr & 0x10) != 0;
    ppuVar10 = uStack_4;
  }
  *(char *)((int)ppuVar24 + -0x7857cbf5) = *(char *)((int)ppuVar24 + -0x7857cbf5) + (char)ppuVar10;
  param_2 = (uint **)((int)param_2 + -1);
  uStack_4 = (uint **)CONCAT22(uStack_4._2_2_,in_CS);
  uVar17 = param_1;
  unaff_EDI = ppuVar24;
  goto LAB_004011cc;
code_r0x0040144c:
  *param_2 = (uint *)~(uint)*param_2;
  if ((int)ppuVar10 >= 0) {
    puVar23 = (uint *)(&stack0x1d7b1e3d + uVar17 * 8);
    uVar16 = *puVar23;
    piVar11 = (int *)(uVar17 - *puVar23);
    ppuVar24 = param_2;
    if ((POPCOUNT((uint)piVar11 & 0xff) & 1U) != 0) {
      if (SBORROW4(uVar17,*puVar23) != false) {
        return;
      }
      in((short)param_2);
      puVar23 = (uint *)((int)puVar22 + (uint)bVar25 * -8 + 5);
      goto LAB_00401481_3;
    }
    LOCK();
    uVar3 = *puVar22;
    *puVar22 = *puVar22;
    UNLOCK();
    uVar17 = (uint)(uVar17 < uVar16);
    uVar16 = uVar3 + *puVar22;
    bVar27 = SCARRY4(uVar3,*puVar22) != SCARRY4(uVar16,uVar17);
    uVar20 = uVar16 + uVar17;
    bVar26 = (int)uVar20 < 0;
    bVar28 = (POPCOUNT(uVar20 & 0xff) & 1U) == 0;
    bVar25 = false;
    if (bVar28) goto LAB_00401463;
    if (bVar28) goto code_r0x004014e8;
    uStack_4 = (uint **)((uint)uStack_4._2_2_ << 0x10);
    goto code_r0x0040146a;
  }
  bVar26 = SBORROW4((int)puVar23,1);
  puVar23 = (uint *)((int)puVar23 + -1);
  bVar28 = (int)puVar23 < 0;
  if (bVar26) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_00401371:
  uStack_4 = (uint **)CONCAT22(uStack_4._2_2_,in_DS);
  if (bVar28) {
    puVar22 = (uint *)((int)puVar22 + -1);
    ppuVar10 = unaff_EDI + (uint)bVar25 * -2 + 1;
    *unaff_EDI = (uint *)param_2;
    lVar4 = (longlong)(int)param_2 * (longlong)*(int *)(uVar17 - 8);
    ppuVar19 = (uint **)((ulonglong)lVar4 >> 0x20);
    piVar11 = (int *)lVar4;
    if (((int)puVar22 >= 0) &&
       (*(byte *)((int)ppuVar19 + 0xe) = ~*(byte *)((int)ppuVar19 + 0xe),
       puVar22 == (uint *)0x0 || ((int)piVar11 != lVar4) != (int)puVar22 < 0)) {
code_r0x0040130c:
      return (int)piVar11 - *piVar11;
    }
    puVar23 = (uint *)((uint)puVar23 | *puVar23);
    LOCK();
    *ppuVar10 = *ppuVar24;
    UNLOCK();
    uVar17 = CONCAT31(uVar13,bVar7 + (char)((ulonglong)lVar4 >> 0x28));
  }
  else {
    puVar22 = (uint *)((int)&uStack_4 * -0x79);
    ppuVar19 = (uint **)CONCAT31((int3)((uint)ppuVar10 >> 8),(byte)ppuVar10 | *(byte *)puVar22);
    bVar28 = SCARRY1(DAT_f1f81e06,bVar12);
    DAT_f1f81e06 = DAT_f1f81e06 + bVar12;
    uStack_8 = (uint **)CONCAT22(uStack_8._2_2_,in_DS);
    if (bVar28 == SCARRY1(DAT_f1f81e06,'\0')) {
      do {
      } while ((char)param_2 < '\0');
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    ppuVar10 = (uint **)&DAT_0a87c6f5;
    unaff_EDI = (uint **)(((uint)param_2 | 0x648de16b) + 0x6f0d071e);
    uVar17 = 0x29713f9d;
    if (unaff_EDI != (uint **)0x0) {
      LOCK();
      puVar2 = *ppuVar19;
      *ppuVar19 = (uint *)0x29713f9d;
      UNLOCK();
      if (puVar2 == (uint *)0x1) goto code_r0x004013ab;
      uVar16 = (int)puVar2 - 1;
      ppuVar10 = (uint **)0x7affe6fd;
      param_2 = ppuVar19;
      goto LAB_004013e0;
    }
  }
  unaff_EDI = ppuVar10 + (uint)bVar25 * -2 + 1;
  *ppuVar10 = (uint *)0x44693e9d;
  ppuVar10 = (uint **)0x44693edf;
  param_1 = uVar17 & 0xde4eb48a;
  goto LAB_0040133a;
code_r0x004013ab:
  param_1 = 1;
LAB_0040133a:
  piVar11 = (int *)((int)puVar22 * 9 + -0x1a);
  unaff_ESI = (undefined4 *)((int)puVar22 + *piVar11);
  param_2 = (uint **)CONCAT22((short)((uint)ppuVar19 >> 0x10),
                              CONCAT11(unaff_ESI != (undefined4 *)0x0 &&
                                       (SCARRY4((int)puVar22,*piVar11) != SCARRY4((int)unaff_ESI,0))
                                       == (int)unaff_ESI < 0,(char)ppuVar19));
  puVar23 = (uint *)CONCAT31((int3)((uint)puVar23 >> 8),(byte)puVar23 | (byte)param_1);
  goto LAB_00401344;
LAB_00401463:
  do {
  } while (bVar26);
  if (bVar27 != bVar26) {
    puVar23 = (uint *)(uVar20 + 0xc01d972a);
    *puVar23 = *puVar23 ^ (uint)unaff_EDI;
    bVar26 = (int)*puVar23 < 0;
    goto code_r0x004014e8;
  }
  if (uVar20 == 0 || bVar27 != bVar26) {
code_r0x0040146a:
    if (bVar27 != bVar26) {
      *(char *)unaff_EDI = (char)ppuVar10;
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    LOCK();
    ppuVar24 = *(uint ***)(uint **)((int)ppuVar19 + -0x5f8f8fd3);
    *(uint **)((int)ppuVar19 + -0x5f8f8fd3) = (uint *)param_2;
    UNLOCK();
    bVar25 = false;
    if (bVar28) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
  }
  else {
    *(char *)(uVar20 + 4) =
         (*(char *)(uVar20 + 4) + '\x0f') - (!CARRY4(uVar3,*puVar22) && !CARRY4(uVar16,uVar17));
  }
  while( true ) {
    iVar9 = *piVar11 * 0x41;
    _DAT_f3fd6b8b = _DAT_f3fd6b8b >> 0x1a;
    out(0x13,(byte)iVar9 | 0xf3);
    in_DS = *(undefined2 *)(iVar9 + -0x61c07950);
    out(0x73,0x6c);
    bVar6 = bVar6 | 1;
    bVar12 = bVar6 * '\x06' - 2;
    puVar23 = (uint *)(iVar9 + -0x4f);
    *puVar23 = *puVar23 &
               CONCAT31(0xf8bf67,bVar12 + (0x90 < (bVar12 & 0xf0) | bVar6 * (0xf9 < bVar12)) * '`');
    bVar26 = (int)*puVar23 < 0;
    param_2 = ppuVar24;
code_r0x004014e8:
    puVar23 = puVar22 + (uint)bVar25 * -2 + 1;
    out(*puVar22,(short)param_2);
    uStack_4 = (uint **)CONCAT22(uStack_4._2_2_,in_DS);
    ppuVar24 = param_2;
    if (!bVar26) break;
LAB_00401481_3:
    puVar22 = (uint *)((int)puVar23 + 1);
    pcVar5 = (code *)swi(4);
    if (SCARRY4((int)puVar23,1) == true) {
      (*pcVar5)();
      piVar11 = extraout_ECX;
      ppuVar24 = extraout_EDX;
    }
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void __fastcall entry(uint param_1,uint **param_2)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x78f81e7f;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x40d22870;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2);
  return;
}


