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
// WARNING: Instruction at (ram,0x00401234) overlaps instruction at (ram,0x00401231)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint * __fastcall entry(uint *param_1,uint *param_2,undefined4 param_3,uint *param_4)

{
  uint uVar1;
  uint *puVar2;
  ulonglong uVar3;
  code *pcVar4;
  longlong lVar5;
  undefined uVar6;
  uint *puVar7;
  uint uVar8;
  uint *in_EAX;
  uint *puVar9;
  undefined3 uVar11;
  int iVar10;
  byte bVar13;
  int iVar12;
  int *extraout_EDX;
  uint *unaff_EBX;
  undefined *puVar14;
  uint *unaff_EBP;
  uint *puVar15;
  uint *puVar16;
  int *piVar17;
  uint *unaff_ESI;
  uint *unaff_EDI;
  ushort in_DS;
  bool bVar18;
  bool bVar19;
  byte in_AF;
  bool bVar20;
  undefined2 in_FPUControlWord;
  float10 fVar21;
  float10 in_ST0;
  float10 in_ST1;
  float10 in_ST2;
  float10 in_ST3;
  float10 in_ST4;
  float10 in_ST5;
  float10 in_ST6;
  float10 in_ST7;
  uint *unaff_retaddr;
  
  puVar9 = &DAT_00401000;
  do {
    *puVar9 = *puVar9 ^ 0x1fb11f2e;
    puVar9 = puVar9 + 1;
  } while (puVar9 != (uint *)0x408e54);
  puVar9 = &DAT_0042b000;
  do {
    *puVar9 = *puVar9 ^ 0x63c551e4;
    bVar20 = puVar9 == (uint *)0x42e1cc;
    puVar9 = puVar9 + 1;
  } while (!bVar20);
  uVar8 = 0;
  puVar9 = in_EAX;
  while( true ) {
    puVar16 = puVar9;
    if ((POPCOUNT(uVar8 & 0xff) & 1U) == 0) {
      param_1 = (uint *)CONCAT31((int3)((uint)param_1 >> 8),0x4a);
      unaff_EDI = unaff_EDI + 1;
      unaff_ESI = (uint *)((int)unaff_ESI + 5);
      puVar7 = (uint *)((int)puVar9 + *param_1);
      bVar20 = puVar7 == (uint *)0x0;
      puVar16 = puVar7;
      unaff_EBP = param_4;
      in_DS = (ushort)param_3;
      if (!CARRY4((uint)puVar9,*param_1) && !bVar20) goto LAB_00401256;
    }
    in_ST3 = (float10)CONCAT28((short)((unkuint10)in_ST3 >> 0x40),(ulonglong)*unaff_EDI);
    puVar7 = (uint *)((int)param_1 + -1);
    param_1 = puVar7;
    puVar9 = unaff_EDI;
    if (puVar7 == (uint *)0x0 || !bVar20) goto code_r0x00401230;
    puVar15 = (uint *)((int)puVar16 + -1);
    uVar3 = CONCAT44(param_2,puVar7);
    bVar18 = puVar16[0x12659e9a] < 0x7696d62e;
    bVar20 = puVar16[0x12659e9a] == 0x7696d62e;
    if (!bVar20) break;
    param_1 = puVar15;
    if (bVar20) goto LAB_004012bb;
    param_1 = (uint *)((int)puVar16 + -2);
    if (param_1 == (uint *)0x0 || bVar20) {
code_r0x0040126f:
      in_AF = 9 < ((byte)puVar7 & 0xf) | in_AF;
      uVar8 = CONCAT31((int3)((uint)puVar7 >> 8),(byte)puVar7 + in_AF * -6) & 0xffffff0f;
      iVar12 = CONCAT22((short)(uVar8 >> 0x10),
                        CONCAT11((char)((uint)puVar7 >> 8) - in_AF,(char)uVar8));
      while( true ) {
        *(int *)((int)unaff_EBP + 0x2e) = *(int *)((int)unaff_EBP + 0x2e) + (int)unaff_EBX;
        unaff_EBX = (uint *)((uint)unaff_EBX | *(uint *)(iVar12 + 0x6ef7b15d));
        bVar19 = (POPCOUNT((uint)unaff_EBX & 0xff) & 1U) == 0;
        puVar15 = (uint *)(*(int *)((int)param_1 + -0x562452e1) * -0x36918d2);
        if (param_1 == (uint *)0x0) {
          *(ushort *)(unaff_ESI + -1) = in_DS;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        uVar3 = (longlong)(int)&stack0x00000000 * (longlong)(int)unaff_EBX[0x1e07cb99];
        bVar18 = (longlong)(int)uVar3 != uVar3;
        in_ST0 = in_ST0 * (float10)*(double *)((int)(uVar3 >> 0x20) + -0x44);
        param_1 = (uint *)CONCAT31((int3)((uint)param_1 >> 8),0x1f);
        puVar2 = unaff_EBX;
        while( true ) {
          bVar20 = puVar2 == (uint *)0x0;
          in_DS = (ushort)in_EAX;
          unaff_ESI = puVar15;
          puVar9 = unaff_EDI;
          if (bVar18) break;
          if (bVar19) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          while( true ) {
            puVar16 = (uint *)uVar3;
            param_2 = (uint *)CONCAT22((short)(uVar3 >> 0x30),
                                       CONCAT11((byte)(uVar3 >> 0x28) ^ (byte)unaff_EBX,
                                                (char)(uVar3 >> 0x20)));
            puVar9 = unaff_EDI;
code_r0x00401230:
            puVar7 = unaff_EBP;
            uVar3 = CONCAT44(param_2,puVar16);
            puVar15 = unaff_ESI + 1;
            out(0x48,puVar16);
            unaff_EDI = puVar9 + 2;
            unaff_ESI = unaff_ESI + 2;
            bVar18 = *puVar15 < puVar9[1];
            puVar2 = (uint *)(*puVar15 - puVar9[1]);
            bVar19 = (POPCOUNT((uint)puVar2 & 0xff) & 1U) == 0;
            unaff_EBP = puVar7;
            puVar15 = unaff_ESI;
            if (bVar19) break;
            unaff_EDI = (uint *)((int)puVar9 + 7);
            lVar5 = ZEXT48(puVar16) * (ulonglong)*unaff_EBX;
            iVar12 = (int)((ulonglong)lVar5 >> 0x20);
            uVar8 = (uint)lVar5;
            if (-1 < (int)unaff_EDI) goto LAB_004011f4;
            param_2 = (uint *)(iVar12 + *(int *)(uVar8 + 0x9dc62d1f) + (uint)(iVar12 != 0));
            lVar5 = CONCAT44(param_2,uVar8);
            uVar1 = *(uint *)(uVar8 + 0x2e75b5db);
            bVar20 = uVar8 < uVar1;
            bVar18 = uVar8 == uVar1;
            if (!bVar18) goto LAB_004011f4;
            if (uVar8 <= uVar1) {
              unaff_EDI = (uint *)((int)puVar9 + 0xb);
LAB_00401256:
              unaff_ESI = (uint *)((int)unaff_ESI + 1);
              bVar20 = puVar7 < (uint *)*param_1;
              bVar18 = puVar7 == (uint *)*param_1;
            }
            uVar3 = CONCAT44(param_2,puVar7);
            unaff_EBP = in_EAX;
            if (bVar20 || bVar18) {
              puVar9 = unaff_EDI + 1;
              unaff_EDI = (uint *)((int)unaff_EDI + 5);
              uVar6 = in((short)param_2);
              *(undefined *)puVar9 = uVar6;
              in_DS = (ushort)unaff_retaddr;
              param_2 = (uint *)CONCAT31((int3)((uint)param_2 >> 8),
                                         (byte)param_2 | *(byte *)((int)in_EAX + 0x1f));
              unaff_ESI = (uint *)((int)unaff_ESI - *unaff_EDI);
              piVar17 = (int *)((int)in_EAX + 0x2e);
              *piVar17 = *piVar17 + (int)unaff_EBX;
              param_1 = (uint *)(CONCAT31((int3)((uint)param_3 >> 8),0xe0) + -1);
              if (param_1 != (uint *)0x0 && *piVar17 != 0) goto LAB_004011f3;
              goto code_r0x0040126f;
            }
            if (bVar20) {
              out((short)param_2,puVar7);
              goto LAB_004011f3;
            }
            param_1 = (uint *)CONCAT31((int3)((uint)param_1 >> 8),0x1f);
          }
        }
LAB_004012bb:
        iVar12 = (int)uVar3;
        puVar15 = param_1;
        if (!bVar20) break;
        if (bVar20) {
          if (!bVar20) goto LAB_004012ef;
          if (bVar18 || bVar20) {
            *(undefined2 *)puVar9 = in_FPUControlWord;
            puVar9 = (uint *)((int)(uVar3 >> 0x20) + -0x4b);
            *puVar9 = *puVar9 >> 1;
            out((short)(uVar3 >> 0x20),(char)uVar3);
            do {
                    // WARNING: Do nothing block with infinite loop
            } while( true );
          }
        }
        else {
          in_AF = (uVar3 & 0x1000) != 0;
          bVar18 = (uVar3 & 0x100) != 0;
          param_1 = (uint *)CONCAT31((int3)((uint)param_1 >> 8),0xe0);
          unaff_EBP = unaff_retaddr;
        }
        unaff_EDI = (uint *)((int)puVar9 + (-(uint)bVar18 - *puVar9));
      }
LAB_004012ea:
      param_2 = (uint *)(uVar3 >> 0x20);
      puVar7 = (uint *)((uint)uVar3 ^ 0xeb);
      uVar3 = uVar3 ^ 0xeb;
      bVar19 = ((uint)unaff_retaddr & 0x400) != 0;
      bVar18 = ((uint)unaff_retaddr & 0x40) == 0;
      bVar20 = ((uint)unaff_retaddr & 1) != 0;
      param_1 = (uint *)((int)puVar15 + -1);
      if (param_1 != (uint *)0x0 && !bVar18) {
        puVar15 = (uint *)((int)puVar15 + -2);
        if (puVar15 == (uint *)0x0 || bVar18) goto code_r0x00401345;
        unaff_EDI = (uint *)((int)puVar9 + -1);
        bVar20 = unaff_EDI == (uint *)0x0;
        goto LAB_00401317;
      }
      goto LAB_004012ef;
    }
LAB_004011f3:
    lVar5 = CONCAT44(param_2,unaff_EBP);
LAB_004011f4:
    unaff_EBP = (uint *)lVar5;
    unaff_ESI = unaff_ESI + 1;
    uVar6 = in((short)((ulonglong)lVar5 >> 0x20));
    puVar9 = (uint *)CONCAT31((int3)((uint)puVar7 >> 8),uVar6);
    in_ST0 = (float10)*(double *)((int)unaff_EBP + 0x6caf9d22) - in_ST0;
    unaff_EDI[0x7cb87ed] = unaff_EDI[0x7cb87ed] - (int)&stack0x00000000;
    unaff_EDI = (uint *)((int)unaff_EDI + 5);
    *unaff_ESI = *unaff_ESI | (uint)unaff_EBX;
    bVar20 = *unaff_ESI == 0;
    uVar8 = *unaff_ESI;
    param_1 = (uint *)CONCAT31((int3)((uint)param_1 >> 8),0xf4);
    param_2 = unaff_retaddr;
    in_DS = (ushort)param_3;
  }
  if (bVar20) {
    uVar3 = CONCAT44(puVar7,param_2);
    goto LAB_004012ea;
  }
LAB_00401317:
  iVar12 = (int)puVar15 + -1;
  puVar9 = puVar7;
  if (iVar12 == 0 || bVar20) {
    if (iVar12 != 1 && unaff_ESI != (uint *)0x1) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
LAB_00401397:
  iVar10 = iVar12 + -1;
  if (iVar10 == 0 || bVar20) {
    puVar9 = (uint *)((int)param_2 + -0x5f);
    *puVar9 = *puVar9 >> 1;
    iVar12 = iVar12 + -2;
    if (iVar12 == 0 || *puVar9 == 0) {
code_r0x004013a1:
      if (iVar12 != 0) {
        func_0xc723d88d();
        if ((longlong)(int)((longlong)*extraout_EDX * 0x2e) != (longlong)*extraout_EDX * 0x2e) {
          pcVar4 = (code *)swi(3);
          puVar9 = (uint *)(*pcVar4)();
          return puVar9;
        }
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_004013f4:
  uVar1 = *unaff_EDI;
  *(short *)(param_2 + 0xb) = (short)ROUND(in_ST0);
  puVar16 = (uint *)((int)param_2 + -0x57);
  bVar20 = (*puVar16 & 1) != 0;
  *puVar16 = *puVar16 >> 1;
  uVar8 = iVar10 - 1;
  if (uVar8 == 0 || *puVar16 == 0) {
    uVar8 = uVar8 | *(uint *)((int)unaff_ESI + 0x6a);
    bVar13 = (byte)((uint)param_2 >> 8) ^ *(byte *)((int)unaff_EBP + -0x4f);
    puVar16 = (uint *)CONCAT22((short)((uint)param_2 >> 0x10),CONCAT11(bVar13,(char)param_2));
    if (uVar8 != 1 && bVar13 != 0) {
      bVar20 = (*puVar16 & 1) != 0;
      *puVar16 = *puVar16 >> 1;
      uVar8 = uVar8 - 2;
      if ((POPCOUNT(uVar8 & 0xff) & 1U) != 0) {
        *(short *)(CONCAT31((int3)((uint)puVar9 >> 8),-bVar20) + -4) =
             (short)((uint6)*(undefined6 *)
                             ((int)*(undefined6 *)((int)unaff_EBX + (-0x1f7fe094 - uVar1)) + 0x3a)
                    >> 0x20);
        do {
                    // WARNING: Do nothing block with infinite loop
        } while( true );
      }
code_r0x0040147e:
      bVar13 = ((byte)uVar8 & 0x1f) % 9;
      DAT_9f03c6e1 = DAT_9f03c6e1 << bVar13 |
                     (byte)(CONCAT11((byte)_DAT_cf88213a < 0x4e ||
                                     (byte)((byte)_DAT_cf88213a + 0xb2) < bVar20,DAT_9f03c6e1) >>
                           9 - bVar13);
      pcVar4 = (code *)swi(1);
      puVar9 = (uint *)(*pcVar4)();
      return puVar9;
    }
code_r0x00401411:
    *(uint *)((int)unaff_EDI + 0x381f2e66) = ~*(uint *)((int)unaff_EDI + 0x381f2e66);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_00401463_1:
  bVar13 = ((byte)uVar8 & 0x1f) % 9;
  *(byte *)unaff_EDI =
       (byte)(CONCAT11(bVar20,*(char *)unaff_EDI) >> bVar13) | *(char *)unaff_EDI << 9 - bVar13;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
LAB_004012ef:
  param_2 = (uint *)CONCAT22((short)((uint)unaff_retaddr >> 0x10),in_DS);
  puVar7 = (uint *)((uint)(uVar3 >> 0x20) ^ 0xe7);
  bVar19 = (in_DS & 0x400) != 0;
  bVar20 = (in_DS & 1) != 0;
  param_1 = (uint *)((int)param_1 + -1);
  puVar16 = (uint *)uVar3;
  puVar15 = (uint *)((int)puVar9 + -1);
  if (param_1 != (uint *)0x0 && (in_DS & 0x40) != 0) goto LAB_00401349;
  while( true ) {
    puVar9 = (uint *)((int)puVar15 + -1);
    if (0 < (int)puVar15) break;
    if (!bVar20) {
      uVar11 = (undefined3)((uint)param_1 >> 8);
      if (puVar9 != (uint *)0x0 && 0 < (int)puVar15) {
        puVar15 = (uint *)CONCAT31(uVar11,0x77);
        *puVar9 = (int)unaff_EBX + (uint)bVar20 + *puVar9;
        unaff_ESI = (uint *)0xdb1f441f;
        param_2 = (uint *)uVar3;
        unaff_EDI = puVar9;
        goto LAB_00401376;
      }
      unaff_EBP = (uint *)((int)unaff_EBP + -1);
      iVar12 = CONCAT31(uVar11,0x1d);
      if (unaff_ESI != (uint *)0xfffffffe) goto code_r0x004013a1;
      uVar8 = iVar12 - 1;
      if (uVar8 == 0 || unaff_ESI == (uint *)0xfffffffe) {
        iVar10 = uVar8 + iRam0000006a + (uint)(puVar9 < (uint *)0xa37e5e9c);
        unaff_ESI = (uint *)0x0;
        unaff_EDI = (uint *)((int)puVar7 + -1);
        goto LAB_004013f4;
      }
      unaff_EDI = (uint *)((int)puVar7 + (uint)bVar19 * -8 + 3);
      iVar12 = (uint)bVar19 * -8 + 4;
      uVar1 = *(uint *)((int)puVar7 + -1);
      bVar20 = uRam00000000 < uVar1;
      puVar14 = (undefined *)(uRam00000000 - uVar1);
      goto code_r0x0040144d;
    }
    param_1 = (uint *)((int)param_1 + -1);
    puVar15 = puVar9;
    if (param_1 == (uint *)0x0) {
      return puVar7;
    }
  }
  uVar3 = uVar3 ^ 0xe700000000;
  unaff_ESI = (uint *)((int)unaff_ESI + 1);
  unaff_retaddr = param_2;
  goto LAB_004012ef;
LAB_00401376:
  puVar16 = (uint *)((int)unaff_ESI + -1);
  param_4._0_1_ = 0;
  puVar9 = (uint *)((int)puVar15 + -1);
  if (puVar9 == (uint *)0x0 || puVar16 == (uint *)0x0) {
    param_4._1_2_ = 0x22;
    *(undefined *)((int)puVar7 + (int)puVar9 * 8 + 0x77962e1f) = 0x9e;
    fVar21 = in_ST0;
    do {
      in_ST0 = in_ST1;
      *(float *)((int)unaff_EBX + -0x25) = (float)fVar21;
      unaff_EDI = (uint *)((int)unaff_EDI + 1);
      unaff_EBP = (uint *)((longlong)(int)*param_2 * 0x2e);
      fVar21 = in_ST0;
      in_ST1 = in_ST2;
      in_ST2 = in_ST3;
      in_ST3 = in_ST4;
      in_ST4 = in_ST5;
      in_ST5 = in_ST6;
      in_ST6 = in_ST7;
    } while ((longlong)(int)unaff_EBP == (longlong)(int)*param_2 * 0x2e);
    unaff_ESI = (uint *)((int)unaff_ESI + (uint)bVar19 * -8 + 3);
    out(*puVar16,(short)param_2);
    iVar12 = (int)puVar15 + -2;
    if (iVar12 != 0 && unaff_EDI != (uint *)0x0) {
      return;
    }
    puVar9 = (uint *)((int)param_2 + -0x5b);
    *puVar9 = *puVar9 >> 1;
    bVar20 = *puVar9 == 0;
    puVar9 = puVar7;
    goto LAB_00401397;
  }
  bVar20 = false;
  puVar7 = (uint *)((uint)puVar7 & 0xffffff9b);
  puVar15 = puVar9;
  unaff_ESI = puVar16;
  puVar9 = unaff_EDI;
code_r0x00401345:
  unaff_EDI = puVar9 + (uint)bVar19 * -2 + 1;
  uVar8 = in((short)param_2);
  *puVar9 = uVar8;
  if (!bVar20) {
    out((short)param_2,(char)puVar7);
    puVar16 = param_2;
LAB_00401349:
    iVar12 = (int)puVar7 + 1;
    out((short)puVar16,iVar12);
    out(0xdc,iVar12);
    uVar6 = in(0x96);
    return (uint *)CONCAT31((int3)((uint)iVar12 >> 8),uVar6);
  }
  goto LAB_00401376;
code_r0x0040144d:
  bVar18 = (POPCOUNT((uint)puVar14 & 0xff) & 1U) == 0;
  *(undefined4 *)((int)puVar9 + 0x4edca7c7) = 0xf3ab5a1a;
  piVar17 = (int *)(iVar12 + 4 + (uint)bVar19 * -8);
  if (bVar18) {
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  iVar12 = *piVar17;
  if (bVar18) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (!bVar18) goto LAB_00401463_1;
  puVar9 = (uint *)(iVar12 + 1);
  if (SCARRY4(iVar12,1)) goto code_r0x00401411;
  if (bVar20) goto code_r0x0040147e;
  puVar16 = (uint *)((int)*(undefined6 *)((int)piVar17 + (uint)bVar19 * -8 + 0x36) + 4 +
                    (uint)bVar19 * -8);
  bVar20 = false;
  puVar14 = (undefined *)((int)&param_4 + 3);
  out(0x48,puVar9);
  puVar7 = puVar16 + (uint)bVar19 * -2 + 1;
  unaff_EDI[(uint)bVar19 * -2 + 1] = *puVar16;
  iVar12 = (int)puVar7 + (uint)bVar19 * -2 + 1;
  *(undefined *)(unaff_EDI + (uint)bVar19 * -2 + 1 + (uint)bVar19 * -2 + 1) = *(undefined *)puVar7;
  unaff_EDI = (uint *)0xa7577f27;
  goto code_r0x0040144d;
}


