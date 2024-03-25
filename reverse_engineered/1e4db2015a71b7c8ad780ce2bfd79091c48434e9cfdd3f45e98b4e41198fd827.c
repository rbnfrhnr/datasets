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




// WARNING: Instruction at (ram,0x00401222) overlaps instruction at (ram,0x00401221)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x0040121d)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * __fastcall FUN_00401219(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  code *pcVar3;
  ushort uVar4;
  byte bVar5;
  byte bVar6;
  short sVar7;
  uint *puVar8;
  undefined4 uVar9;
  uint *puVar10;
  uint *in_EAX;
  undefined *puVar11;
  uint *puVar12;
  uint *puVar13;
  uint *puVar14;
  uint *puVar15;
  uint uVar16;
  uint *puVar17;
  undefined2 extraout_DX;
  uint *unaff_EBX;
  uint *unaff_EBP;
  uint *puVar18;
  uint *unaff_ESI;
  byte *pbVar19;
  uint *unaff_EDI;
  uint *puVar20;
  uint *puVar21;
  undefined2 in_CS;
  bool bVar22;
  byte in_AF;
  bool bVar23;
  bool bVar24;
  uint *puVar25;
  
  *unaff_ESI = *unaff_ESI ^ (uint)in_EAX;
  do {
    puVar10 = in_EAX;
    puVar20 = (uint *)((int)unaff_EDI + 1);
    puVar14 = (uint *)((int)unaff_ESI + 1);
    bVar6 = *(byte *)unaff_EDI;
    bVar5 = *(byte *)unaff_ESI;
    bVar22 = bVar5 < bVar6;
    bVar24 = SBORROW1(bVar5,bVar6);
    bVar23 = bVar5 == bVar6;
    if (bVar24) {
      if ((int)&stack0xfffffffc < 0) {
        func_0x71063132();
      }
      else {
        pcVar3 = (code *)swi(0x8e);
        (*pcVar3)();
      }
      _DAT_71a7706c = ~_DAT_71a7706c;
      in(0x55);
      pcVar3 = (code *)swi(1);
      puVar11 = (undefined *)(*pcVar3)();
      return puVar11;
    }
    while (puVar8 = puVar10, puVar15 = param_1, puVar21 = unaff_EBP, _DAT_a755e4c9 = puVar10,
          puVar10 = unaff_EBP, !bVar24) {
      do {
        while (puVar18 = puVar20, puVar25 = puVar21, puVar11 = &stack0xfffffffc, puVar12 = puVar15,
              puVar21 = puVar8, bVar23) {
          puVar20 = puVar12 + -5;
          sVar7 = ((ushort)puVar18 & 3) - (*(ushort *)puVar20 & 3);
          bVar23 = 0 < sVar7;
          *(ushort *)puVar20 = *(short *)puVar20 + (ushort)bVar22 * sVar7;
          bVar5 = ((byte)puVar12 & 0x1f) % 9;
          uVar4 = CONCAT11(bVar22,*(byte *)((int)puVar25 + -0x71));
          uVar4 = uVar4 << bVar5 | uVar4 >> 9 - bVar5;
          *(byte *)((int)puVar25 + -0x71) = (byte)uVar4;
          bVar22 = (uVar4 & 0x100) != 0;
          puVar8 = puVar25;
          puVar15 = puVar12;
          puVar20 = puVar18;
          puVar10 = puVar21;
        }
        puVar8 = (uint *)in(0xe5);
        if (!bVar24) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        puVar20 = puVar18 + 1;
        if (!SBORROW4(*puVar14,*puVar18)) {
          pcVar3 = (code *)swi(0x2d);
          (*pcVar3)();
          do {
                    // WARNING: Do nothing block with infinite loop
          } while( true );
        }
        pbVar19 = (byte *)((int)puVar18 + 3);
        *(char *)((int)puVar14 + 0x21f2a759) = (char)unaff_EBX;
        bVar5 = (byte)puVar8;
        bVar22 = bVar5 < *pbVar19;
        bVar24 = SBORROW1(bVar5,*pbVar19);
        bVar23 = bVar5 == *pbVar19;
        puVar15 = (uint *)CONCAT31((int3)((uint)puVar12 >> 8),0x90);
        puVar21 = puVar18;
        puVar14 = puVar14 + 1;
        param_1 = puVar18;
        unaff_EBP = unaff_EBX;
      } while (bVar24);
      while( true ) {
        unaff_EBX = (uint *)CONCAT22((short)((uint)puVar12 >> 0x10),in_CS);
        in_CS = 0x7f91;
        func_0x8e5fd6c2(unaff_EBX,puVar18);
        in(0x55);
        uVar9 = in(extraout_DX);
        *(byte *)(puVar20 + 1) = (byte)uVar9;
        param_2 = (uint *)((int)param_1 >> 0x1f);
        puVar20 = puVar25 + 2;
        puVar14 = (uint *)(puVar11 + 8);
        uVar1 = puVar25[1];
        uVar16 = *(uint *)(puVar11 + 4);
        bVar22 = uVar16 < uVar1;
        bVar24 = SBORROW4(uVar16,uVar1);
        bVar23 = uVar16 == uVar1;
        if (bVar24) break;
        in_AF = 9 < ((byte)param_1 & 0xf) | in_AF;
        puVar8 = (uint *)(puVar11 + 0xc);
        bVar22 = *puVar14 < *puVar20;
        puVar14 = puVar10;
        puVar18 = unaff_EBP;
        puVar20 = puVar25 + 3;
        puVar15 = puRama73fe51b;
        puVar21 = puVar10;
        while( true ) {
          puRama73fe51b = puVar15;
          puVar15 = puVar14;
          bVar23 = SBORROW4((int)puVar18,(int)puVar15) ==
                   SBORROW4((int)puVar18 - (int)puVar15,(uint)bVar22);
          puVar18 = (uint *)(((int)puVar18 - (int)puVar15) - (uint)bVar22);
          puVar12 = (uint *)in(0xe5);
          if (bVar23) break;
          puVar14 = puVar12;
          puVar13 = param_2;
          puVar17 = puVar8;
          if (!bVar23) {
            pbVar19 = (byte *)((int)puVar20 + -1);
            *pbVar19 = *(byte *)puVar8;
            puVar13 = (uint *)CONCAT22((short)((uint)puVar12 >> 0x10),
                                       CONCAT11(((int)pbVar19 < 0) << 7 |
                                                (pbVar19 == (byte *)0x0) << 6 | in_AF << 4 |
                                                ((POPCOUNT((uint)pbVar19 & 0xff) & 1U) == 0) << 2 |
                                                2 | puVar12 < (uint *)0x55a7c187,(byte)puVar12));
            puVar21 = puVar20 + 1;
            puVar17 = (uint *)((int)puVar8 + 5);
            puVar14 = puVar13;
            puVar10 = puVar18;
            if ((int)*puVar20 <= *(int *)((int)puVar8 + 1)) goto LAB_00401282;
            puVar20 = (uint *)((int)puVar20 + 5);
            *(byte *)puVar21 = (byte)puVar12;
            puVar14 = param_2;
            puVar21 = puVar18;
          }
          puVar12 = puVar20 + 1;
          puVar8 = puVar17 + 1;
          uVar2 = *puVar20;
          uVar1 = *puVar17;
          bVar22 = uVar1 < uVar2;
          bVar23 = SBORROW4(uVar1,uVar2);
          uVar16 = uVar1 - uVar2;
          puVar17 = puVar15;
          if (uVar1 != uVar2) goto LAB_0040128b_3;
          while( true ) {
            param_2 = (uint *)((int)puVar14 >> 0x1f);
            puVar14 = (uint *)in(0x23);
            puVar17 = puVar8;
            puVar21 = puVar12;
LAB_00401282:
            puVar13 = param_2;
            if (SBORROW4(*puVar17,*puVar21)) {
              puVar12 = (uint *)0xeadc2c40;
              puVar8 = (uint *)((int)puVar18 + -0x1af48243);
              puVar17 = puVar14;
              puVar21 = puVar18;
              goto code_r0x00401292;
            }
            if ((int)(*puVar17 - *puVar21) < 0) {
              if (SBORROW4(puVar17[3],puVar21[2])) {
                LOCK();
                puVar21[0x11f873d8] = (uint)puVar15;
                UNLOCK();
                return &stack0x00000000;
              }
              uVar9 = func_0xe55bba0e(puVar21 + 2,puVar17 + 2,puVar18,&stack0xfffffffc,unaff_EBX,
                                      puVar13,puVar15,puVar14);
              in_AF = 9 < ((byte)uVar9 & 0xf) | in_AF;
              bVar6 = (byte)uVar9 + in_AF * -6 & 0xf;
              bVar5 = 9 < bVar6 | in_AF;
              uVar16 = CONCAT31((int3)((uint)uVar9 >> 8),bVar6 + bVar5 * -6) & 0xffff000f;
              return (undefined *)
                     CONCAT22((short)(uVar16 >> 0x10),
                              CONCAT11(((char)((uint)uVar9 >> 8) - in_AF) - bVar5,(char)uVar16));
            }
            puVar12 = puVar21 + 2;
            puVar8 = puVar17 + 2;
            bVar22 = puVar17[1] < puVar21[1];
            bVar23 = SBORROW4(puVar17[1],puVar21[1]);
            if (bVar23) break;
            puVar12 = puVar21 + 3;
            puVar8 = puVar17 + 3;
          }
          param_2 = puVar13;
          puVar20 = puVar12;
          puVar21 = puVar18;
          if (bVar23) {
            do {
              puVar20 = (uint *)((int)puVar8 + -0x2e95f28f);
              uVar16 = (uint)(bVar22 == false);
              uVar1 = *puVar20 - (int)&stack0xfffffffc;
              bVar22 = (undefined *)*puVar20 < &stack0xfffffffc || uVar1 < uVar16;
              bVar23 = SBORROW4(*puVar20,(int)&stack0xfffffffc) != SBORROW4(uVar1,uVar16);
              *puVar20 = uVar1 - uVar16;
              uVar16 = *puVar20;
              puVar17 = puVar15;
              if (bVar23) {
                pcVar3 = (code *)swi(1);
                puVar11 = (undefined *)(*pcVar3)();
                return puVar11;
              }
LAB_0040128b_3:
              if (bVar23 != (int)uVar16 < 0) {
                puVar15 = (uint *)in(0x55);
code_r0x00401292:
                out(*(undefined *)puVar8,(short)puVar13);
                puVar13 = (uint *)CONCAT31((int3)((uint)puVar13 >> 8),0x81);
                sVar7 = (ushort)(byte)puVar15 * (ushort)*(byte *)((int)puVar12 + 0x6455e571);
                puVar14 = (uint *)CONCAT22((short)((uint)puVar15 >> 0x10),sVar7);
                bVar22 = (char)((ushort)sVar7 >> 8) != '\0';
                puVar8 = (uint *)((int)puVar8 + 1);
                bVar23 = bVar22;
              }
              puVar15 = puVar17;
              param_2 = puVar13;
              puVar20 = puVar12;
            } while (bVar23);
          }
        }
        puVar20 = puVar20 + 1;
        param_1 = puVar10;
        puVar12 = unaff_EBX;
        puVar10 = puVar21;
      }
    }
    unaff_EBX = (uint *)CONCAT22((short)((uint)unaff_EBX >> 0x10),
                                 CONCAT11((byte)((uint)unaff_EBX >> 8) | (byte)param_1,
                                          (char)unaff_EBX));
    param_1 = (uint *)CONCAT22((short)((uint)param_1 >> 0x10),
                               CONCAT11((char)((uint)param_1 >> 8) -
                                        *(byte *)((int)param_1 + (int)puVar20 * 4 + -6),
                                        (byte)param_1));
    param_2 = (uint *)CONCAT31((int3)((uint)param_2 >> 8),0x66);
    unaff_EDI = puVar20 + 1;
    unaff_ESI = puVar14 + 1;
    in_EAX = (uint *)in((short)param_2);
  } while( true );
}



void __fastcall entry(uint *param_1,uint *param_2)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x71a755e5;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x189a2ae2;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2);
  return;
}


