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
// WARNING: Instruction at (ram,0x00401286) overlaps instruction at (ram,0x00401285)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall
FUN_00401219(double *param_1,double *param_2,undefined4 param_3,uint param_4,undefined param_5,
            undefined4 param_6)

{
  int *piVar1;
  uint *puVar2;
  undefined4 uVar3;
  code *pcVar4;
  ulonglong uVar5;
  uint5 uVar6;
  undefined uVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  int in_EAX;
  byte *pbVar11;
  uint uVar12;
  int iVar14;
  undefined3 uVar17;
  char *pcVar15;
  int iVar16;
  byte bVar18;
  undefined2 uVar19;
  undefined4 unaff_EBX;
  uint uVar20;
  int *unaff_EBP;
  int *piVar21;
  undefined *unaff_ESI;
  undefined *puVar22;
  undefined4 *unaff_EDI;
  undefined4 *puVar23;
  undefined4 *puVar24;
  byte in_CF;
  bool bVar25;
  bool bVar26;
  byte in_AF;
  char in_SF;
  bool bVar27;
  bool bVar28;
  char in_OF;
  float10 in_ST0;
  float10 in_ST1;
  float10 in_ST2;
  float10 in_ST3;
  float10 in_ST4;
  float10 in_ST5;
  float10 in_ST6;
  float10 in_ST7;
  int unaff_retaddr;
  undefined in_stack_0000000d;
  double *pdVar13;
  
  bVar28 = false;
  bVar10 = (byte)((uint)unaff_EBX >> 8);
  bVar18 = (byte)param_2;
  if (in_OF != in_SF) {
    bVar8 = (byte)in_EAX + bVar18;
    pcVar15 = (char *)CONCAT31((int3)((uint)in_EAX >> 8),bVar8 + in_CF);
    *pcVar15 = (*pcVar15 - bVar10) - (CARRY1((byte)in_EAX,bVar18) || CARRY1(bVar8,in_CF));
    return;
  }
  pbVar11 = (byte *)(in_EAX + -1);
  puVar23 = unaff_EDI + 1;
  uVar19 = SUB42(param_2,0);
  uVar3 = in(uVar19);
  *unaff_EDI = uVar3;
  bVar9 = *pbVar11;
  bVar8 = *pbVar11;
  *pbVar11 = (bVar8 - bVar10) - in_CF;
  if (SCARRY4((in_EAX + 0x48ad021b) - (uint)(bVar9 < bVar10 || (byte)(bVar8 - bVar10) < in_CF),
              0x6d0a8804)) {
    *(byte *)(unaff_retaddr + -0x1d0f92f6) = *(byte *)(unaff_retaddr + -0x1d0f92f6) | (byte)param_1;
    param_2[7] = (double)in_ST0;
    pcVar15 = (char *)CONCAT31((int3)((uint)param_3 >> 8),DAT_483863d9);
    out(uVar19,DAT_483863d9);
    uVar7 = in(uVar19);
    *(undefined *)puVar23 = uVar7;
    *pcVar15 = *pcVar15 + -0x65;
    *(byte *)((int)unaff_EDI + 0x6b) = *(byte *)((int)unaff_EDI + 0x6b) ^ DAT_483863d9 - 1U;
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  uVar12 = unaff_retaddr + 0x1bd397e8;
  bVar25 = uVar12 < 0x186d4838;
  uVar20 = 0x6e4b7da4;
  do {
    uVar7 = in(0x7d);
    pdVar13 = (double *)CONCAT31((int3)(uVar12 >> 8),uVar7);
    bVar26 = (*(byte *)pdVar13 & 1) != 0;
    *(byte *)pdVar13 = *(byte *)pdVar13 >> 1 | bVar25 << 7;
    puVar22 = unaff_ESI;
    puVar24 = puVar23;
    while( true ) {
      bVar10 = (byte)pdVar13;
      bVar25 = bVar10 < 0x2e || (byte)(bVar10 - 0x2e) < bVar26;
      bVar8 = in(uVar19);
      iVar16 = CONCAT31((int3)(CONCAT22((short)((uint)pdVar13 >> 0x10),CONCAT11(0x24,bVar10)) >> 8),
                        bVar8 + 0x1c + bVar25);
      iVar14 = iVar16 + -1;
      unaff_ESI = puVar22 + (uint)bVar28 * -2 + 1;
      out(*puVar22,uVar19);
      puVar2 = (uint *)((int)&param_4 + (int)unaff_EBP * 2);
      uVar6 = CONCAT14(0xe3 < bVar8 || CARRY1(bVar8 + 0x1c,bVar25),*puVar2);
      uVar5 = (ulonglong)uVar6 << 0xe;
      *puVar2 = (uint)uVar5 | (uint)(uVar6 >> 0x13);
      in_ST0 = (float10)*param_2 / in_ST0;
      puVar23 = puVar24 + (uint)bVar28 * -2 + 1;
      uVar3 = in(uVar19);
      *puVar24 = uVar3;
      if ((uVar5 & 0x100000000) != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      piVar1 = unaff_EBP + -0x16;
      *(byte *)piVar1 = *(byte *)piVar1 & (byte)iVar14;
      pdVar13 = param_1;
      if ((POPCOUNT(*(byte *)piVar1) & 1U) == 0) {
        piVar21 = unaff_EBP;
        puVar24 = puVar23;
        if ((char)*(byte *)piVar1 < '\0') goto code_r0x004012a2;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      uVar12 = iVar16 + 0x6d0a883b;
      bVar10 = (byte)param_1;
      if (SCARRY4(iVar14,0x6d0a883c)) {
        pdVar13 = (double *)
                  CONCAT22((short)((uint)param_1 >> 0x10),
                           CONCAT11((byte)((uint)param_1 >> 8) | *(byte *)((int)unaff_EBP + -0x6f),
                                    bVar10));
        bVar26 = uVar12 < 0x385add5c;
        pcVar15 = (char *)(iVar16 + 0x34afaadf);
        bVar27 = (int)pcVar15 < 0;
        bVar25 = pcVar15 == (char *)0x0;
      }
      else {
        bVar8 = 9 < ((byte)uVar12 & 0xf) | in_AF;
        bVar9 = (byte)uVar12 + bVar8 * -6;
        pcVar15 = (char *)CONCAT31((int3)(uVar12 >> 8),
                                   (bVar9 + (0x9f < bVar9 | bVar8 * (bVar9 < 6)) * -0x61) - bVar18);
        bVar28 = (param_4 & 0x400) != 0;
        in_AF = (param_4 & 0x10) != 0;
        *pcVar15 = (*pcVar15 - (char)(uVar20 >> 8)) - ((param_4 & 1) != 0);
        pcVar15[0xde76d0a] = pcVar15[0xde76d0a] ^ bVar10;
        uVar7 = in(uVar19);
        *(undefined *)puVar23 = uVar7;
        param_2[7] = (double)in_ST0;
        uVar20 = CONCAT22((short)(uVar20 >> 0x10),CONCAT11(0x58,(char)uVar20));
        bVar8 = pcVar15[0x1d916d0a];
        bVar26 = bVar8 < bVar10;
        bVar27 = (char)(bVar8 - bVar10) < '\0';
        bVar25 = bVar8 == bVar10;
        param_2[7] = (double)in_ST1;
        puVar23 = (undefined4 *)((int)puVar23 + (uint)bVar28 * -2 + 1);
        in_ST0 = in_ST2;
        in_ST1 = in_ST3;
        in_ST2 = in_ST4;
        in_ST3 = in_ST5;
        in_ST4 = in_ST6;
        in_ST5 = in_ST7;
        in_ST6 = in_ST7;
      }
      uVar17 = (undefined3)((uint)pcVar15 >> 8);
      param_1 = (double *)CONCAT31(uVar17,DAT_48386e6d);
      out(uVar19,DAT_48386e6d);
      in_ST0 = in_ST0 - (float10)*param_1;
      if (!bVar27) break;
      while (puVar22 = unaff_ESI, puVar24 = puVar23, bVar25) {
        uVar20 = 0x186d4838;
        iVar14 = (int)pdVar13 + -1;
        pdVar13 = *(double **)
                   CONCAT31((int3)((uint)param_1 >> 8),
                            ((char)param_1 - (char)((uint)param_2 >> 8)) -
                            (pdVar13 < (double *)0x6d32e2f0));
        piVar21 = unaff_EBP;
code_r0x004012a2:
        in_AF = 9 < ((byte)iVar14 & 0xf) | in_AF;
        bVar10 = (byte)iVar14 + in_AF * '\x06';
        pcVar15 = (char *)(CONCAT31((int3)((uint)iVar14 >> 8),
                                    bVar10 + (0x90 < (bVar10 & 0xf0) |
                                             *(double **)(iVar14 + -0x7b) < pdVar13 |
                                             in_AF * (0xf9 < bVar10)) * '`') + -1);
        puVar23 = puVar24 + (uint)bVar28 * -2 + 1;
        uVar3 = in(uVar19);
        *puVar24 = uVar3;
        uVar20 = uVar20 - 1;
        out(unaff_ESI[-1],uVar19);
        pbVar11 = (byte *)((int)piVar21 + 0x47);
        bVar10 = (byte)pdVar13 & 7;
        *pbVar11 = *pbVar11 >> bVar10 | *pbVar11 << 8 - bVar10;
        puVar22 = unaff_ESI + (uint)bVar28 * -2;
        while( true ) {
          *pcVar15 = (*pcVar15 - (char)(uVar20 - _DAT_60c5cf99 >> 8)) - (uVar20 < _DAT_60c5cf99);
          bVar10 = (byte)pdVar13;
          unaff_ESI = puVar22 + (uint)bVar28 * -2 + 1;
          out(*puVar22,uVar19);
          if (*(byte *)param_2 < (byte)((uint)pcVar15 >> 8)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          pdVar13 = (double *)
                    CONCAT22((short)((uint)pdVar13 >> 0x10),
                             CONCAT11((byte)((uint)pdVar13 >> 8) & *(byte *)((int)piVar21 + 0x72) &
                                      *(byte *)(piVar21 + 0x1c),bVar10));
          bVar8 = pcVar15[0x6d];
          param_4 = (int)(short)pcVar15;
          unaff_EBP = (int *)*(undefined6 *)(puVar23 + 0xe);
          iVar16 = (int)(short)pcVar15 - 1;
          uVar7 = in(0xdb);
          param_1 = (double *)CONCAT31((int3)((uint)iVar16 >> 8),uVar7);
          uVar20 = 0x3c6d92b3;
          if (-1 < iVar16) break;
          piVar21 = (int *)*unaff_EBP;
          puVar24 = (undefined4 *)((int)puVar23 + (uint)bVar28 * -2 + 1);
          *(undefined *)puVar23 = uVar7;
          *unaff_EBP = (int)piVar21;
          pcVar15 = (char *)((int)param_1 + -1);
          puVar23 = puVar24 + (uint)bVar28 * -2 + 1;
          uVar3 = in(uVar19);
          *puVar24 = uVar3;
          if (bVar8 >= bVar10) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          puVar22 = unaff_ESI;
          if (pcVar15 == (char *)0x0) {
            out(0x38,0);
            _DAT_f32d8809 = (_DAT_f32d8809 + -0x3c6d92b3) - (uint)(bVar8 < bVar10);
            *(uint *)((int)param_2 + 0x5659fe9b) = *(uint *)((int)param_2 + 0x5659fe9b) >> 0xd;
            pcVar4 = (code *)swi(3);
            (*pcVar4)();
            return;
          }
        }
        pbVar11 = (byte *)((int)pdVar13 + -0x5c);
        bVar26 = false;
        *pbVar11 = *pbVar11 & 0x92;
        bVar25 = *pbVar11 == 0;
      }
    }
    *(char *)((int)param_1 + 0x2c) =
         (*(char *)((int)param_1 + 0x2c) - (char)((uint)pdVar13 >> 8)) - bVar26;
    uVar7 = in(0x3d);
    uVar12 = CONCAT31(uVar17,uVar7);
    bVar26 = *(byte *)(uVar12 + 0x6d) < (byte)pdVar13;
    pbVar11 = (byte *)(uVar20 + 0x6e4b7da4);
    bVar8 = (byte)(uVar20 >> 8);
    bVar10 = *pbVar11 - bVar8;
    bVar25 = *pbVar11 < bVar8 || bVar10 < bVar26;
    *pbVar11 = bVar10 - bVar26;
    param_1 = pdVar13;
  } while( true );
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
  FUN_00401219((double *)piVar7[7],(double *)piVar7[6],piVar7[10],piVar7[0xb],
               *(undefined *)(piVar7 + 0xc),piVar7[0xd]);
  return;
}


