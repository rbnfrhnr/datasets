typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
float10
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
// WARNING: Instruction at (ram,0x0040124f) overlaps instruction at (ram,0x0040124e)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x00401427)
// WARNING: Removing unreachable block (ram,0x0040142a)
// WARNING: Removing unreachable block (ram,0x00401250)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

float10 * __fastcall
FUN_00401219(float10 *__return_storage_ptr__,int param_1,int param_2,int param_3,int param_4)

{
  int *piVar1;
  undefined uVar2;
  code *pcVar3;
  undefined6 uVar4;
  byte bVar5;
  byte bVar6;
  char cVar7;
  byte bVar8;
  ushort uVar9;
  undefined4 in_EAX;
  uint uVar10;
  undefined6 *puVar11;
  undefined3 uVar19;
  undefined4 uVar12;
  uint uVar13;
  undefined4 *puVar14;
  int iVar15;
  float10 *pfVar16;
  float10 *pfVar17;
  int iVar18;
  char extraout_DL;
  int iVar20;
  uint unaff_EBX;
  uint *puVar21;
  int unaff_EBP;
  undefined4 *unaff_ESI;
  undefined6 *puVar22;
  undefined6 *puVar23;
  undefined6 *puVar24;
  undefined4 *unaff_EDI;
  undefined4 *puVar25;
  undefined4 *puVar26;
  char in_CF;
  bool bVar27;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  bool bVar28;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  
  bVar6 = (char)in_EAX + -0x2c + in_CF;
  iVar20 = param_1 + -1;
  puVar14 = unaff_EDI + 1;
  puVar24 = (undefined6 *)(unaff_ESI + 1);
  *unaff_EDI = *unaff_ESI;
  if (SBORROW4(param_1,1)) {
    bVar27 = SBORROW4(iVar20,1);
  }
  else {
    bVar27 = bVar6 < 0x95;
    puVar11 = (undefined6 *)CONCAT31((int3)((uint)in_EAX >> 8),bVar6 + 0x6b);
    puVar23 = puVar24;
    puVar26 = puVar14;
    do {
      uVar2 = in((short)iVar20);
      *(undefined *)puVar26 = uVar2;
      uVar4 = *puVar11;
      *(undefined4 *)((int)puVar26 + 1) = *(undefined4 *)puVar23;
      unaff_EBX = CONCAT22((short)(unaff_EBX >> 0x10),
                           CONCAT11(((char)(unaff_EBX >> 8) - (char)((uint6)uVar4 >> 8)) - bVar27,
                                    (char)unaff_EBX));
      uVar10 = in(0x70);
      puVar11 = (undefined6 *)(uVar10 & 0x75552c2e);
      bVar28 = SBORROW4(param_3,1);
      iVar20 = param_3 + -1;
      puVar22 = (undefined6 *)((int)puVar23 + 4);
      puVar25 = (undefined4 *)((int)puVar26 + 5);
      do {
        puVar26 = puVar25 + 1;
        puVar23 = (undefined6 *)((int)puVar22 + 4);
        *puVar25 = *(undefined4 *)puVar22;
        bVar6 = (byte)puVar11;
        uVar19 = (undefined3)((uint)puVar11 >> 8);
        if (!bVar28) {
          puVar26 = (undefined4 *)((int)puVar25 + 5);
          puVar23 = (undefined6 *)((int)puVar22 + 5);
          puVar21 = (uint *)(unaff_EBX & _DAT_1a9d152c);
          if ((int)puVar21 < 0) {
            out(0x31,puVar11);
            goto code_r0x00401289;
          }
          bVar27 = SBORROW1(bVar6,'$');
          iVar18 = CONCAT31(uVar19,bVar6 - 0x24);
          puVar24 = puVar23;
          puVar14 = puVar26;
          if ((char)bVar6 < '$') goto LAB_00401298;
          iVar20 = param_3 + -2;
          puVar23 = (undefined6 *)(iVar18 + -0x6f4a8ace);
          uVar4 = *puVar23;
          puVar26 = (undefined4 *)((int)puVar25 + 10);
          *(undefined4 *)((int)puVar25 + 6) = *(undefined4 *)((int)puVar22 + 6);
          uVar13 = iVar18 + 0xae57ea65;
          uVar10 = uVar13;
          if (uVar13 != 0) {
            bVar8 = (byte)uVar13 & *(byte *)(unaff_EBP + 0x4d4a35e0);
            bVar6 = 9 < (bVar8 & 0xf) | in_AF;
            bVar8 = bVar8 + bVar6 * '\x06';
            puVar14 = (undefined4 *)
                      (CONCAT31((int3)(uVar13 >> 8),
                                bVar8 + (0x90 < (bVar8 & 0xf0) | bVar6 * (0xf9 < bVar8)) * '`') |
                      0xb6f9a54a);
            iVar18 = *(int *)(unaff_EBP + 4);
            *puVar14 = *(undefined4 *)(unaff_EBP + 8);
            iVar15 = CONCAT31((int3)((uint)(unaff_EBP + 0xc) >> 8),0x9e);
            pfVar16 = (float10 *)(iVar15 + 0x1afd9f24);
            puVar25 = (undefined4 *)((int)puVar25 + 0xe);
            *puVar26 = *(undefined4 *)(iVar18 + -1);
            if (SCARRY4(iVar15,0x1afd9f24) == SCARRY4((int)pfVar16,0)) {
              return;
            }
            if (pfVar16 != (float10 *)0x0) {
              do {
                *(char *)(iVar20 + 0x5a) = *(char *)(iVar20 + 0x5a) + (char)puVar21;
                pfVar17 = (float10 *)((int)pfVar16 + 0x9a26c2f2);
                if (pfVar17 != (float10 *)0x0) {
                  if ((int)pfVar17 < 0) {
                    *(char *)((int)pfVar16 + 0x9a26c28fU) =
                         *(char *)((int)pfVar16 + 0x9a26c28fU) >> 1;
                    return pfVar17;
                  }
                  iVar20 = CONCAT22((short)((uint)iVar20 >> 0x10),CONCAT11(0x8a,(char)iVar20));
                  bVar6 = 9 < ((byte)pfVar17 & 0xf) | bVar6;
                  pfVar17 = (float10 *)
                            (uint)(CONCAT11((char)((uint)pfVar17 >> 8) - bVar6,
                                            (byte)pfVar17 + bVar6 * -6) & 0xff0f);
                }
                puVar21 = (uint *)CONCAT22((short)((uint)puVar21 >> 0x10),
                                           CONCAT11(*(undefined *)puVar25,(char)puVar21));
                iVar18 = (int)(short)CONCAT31((int3)((uint)pfVar17 >> 8),(char)pfVar17 + 'J');
                *puVar21 = *puVar21 ^ 0xffffffa5;
                while( true ) {
                  uVar10 = CONCAT22((short)((uint)iVar18 >> 0x10),
                                    CONCAT11((char)((ushort)iVar18 % (ushort)*(byte *)puVar25),
                                             (char)((ushort)iVar18 / (ushort)*(byte *)puVar25)));
                  pfVar16 = (float10 *)(uVar10 + 0x5ab58a8e);
                  bVar27 = SBORROW4(uVar10,-0x5ab58a8e) != false;
                  if (bVar27 != (int)pfVar16 < 0) break;
                  if (bVar27) {
                    return pfVar16;
                  }
                  _DAT_8a4474d5 =
                       (uint)(in_NT & 1) * 0x4000 | (uint)bVar27 * 0x800 | (uint)(in_IF & 1) * 0x200
                       | (uint)(in_TF & 1) * 0x100 | (uint)((int)pfVar16 < 0) * 0x80 |
                       (uint)(pfVar16 == (float10 *)0x0) * 0x40 | (uint)(bVar6 & 1) * 0x10 |
                       (uint)((POPCOUNT((uint)pfVar16 & 0xff) & 1U) == 0) * 4 |
                       (uint)(uVar10 < 0xa54a7572) | (uint)(in_ID & 1) * 0x200000 |
                       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
                       (uint)(in_AC & 1) * 0x40000;
                  puVar21 = (uint *)((int)puVar21 + 1);
                  uVar9 = (ushort)((uint)pfVar16 & 0xffffffb7);
                  iVar18 = CONCAT22((short)(((uint)pfVar16 & 0xffffffb7) >> 0x10),
                                    CONCAT11((char)(uVar9 % (ushort)*(byte *)puVar25),
                                             (char)(uVar9 / *(byte *)puVar25)));
                }
              } while( true );
            }
            puVar14[-1] = puVar21;
            *(char *)puVar25 = *(char *)puVar25 << ((byte)uVar4 & 0x1f);
            *puVar25 = *(undefined4 *)(iVar18 + 3);
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          goto code_r0x00401284;
        }
        if (bVar28) {
          return;
        }
        bVar27 = bVar6 < 0x55;
        bVar28 = SBORROW1(bVar6,'U');
        cVar7 = bVar6 + 0xab;
        puVar11 = (undefined6 *)CONCAT31(uVar19,cVar7);
        puVar22 = puVar23;
        puVar25 = puVar26;
      } while (cVar7 == '\0');
    } while (cVar7 != '\0');
    uVar10 = (int)puVar11 + (-0x264a7506 - (uint)bVar27);
    uVar13 = uVar10 & 0xff;
code_r0x00401284:
    puVar11 = (undefined6 *)(uint)CONCAT11(0x6d,(char)uVar13);
    if ((POPCOUNT(uVar10 & 0xff) & 1U) != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
code_r0x00401289:
    bVar6 = *(byte *)((int)puVar23 + 0x31e798f5);
    bVar8 = (byte)((uint)iVar20 >> 8);
    bVar27 = SBORROW1(bVar6,bVar8);
    puVar14 = puVar26 + 1;
    puVar24 = (undefined6 *)((int)puVar23 + 4);
    *puVar26 = *(undefined4 *)puVar23;
    if (bVar27) {
      *(byte *)(unaff_EBP + -0x72dd8ae6) =
           *(byte *)(unaff_EBP + -0x72dd8ae6) & (byte)((uint)puVar11 >> 8);
      *(undefined *)puVar14 = 0;
      cVar7 = '\0';
      pcVar3 = (code *)swi(0x54);
      uVar12 = (*pcVar3)();
      *puVar14 = *(undefined4 *)puVar24;
      *(char *)(unaff_EBP + -6) = (*(char *)(unaff_EBP + -6) - extraout_DL) - cVar7;
      out(0x70,uVar12);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    piVar1 = (int *)(unaff_EBP + 0x4a);
    bVar5 = (byte)puVar11 & 0x1f;
    iVar20 = *piVar1;
    *piVar1 = *piVar1 << bVar5;
    bVar28 = ((uint)puVar11 & 0x1f) != 0;
    bVar27 = (bool)(bVar5 != 1 & bVar27 |
                   (bVar5 == 1 &&
                   (!bVar28 && bVar6 < bVar8 || bVar28 && iVar20 << bVar5 - 1 < 0) != *piVar1 < 0));
  }
LAB_00401298:
  *puVar14 = *(undefined4 *)puVar24;
  if (bVar27) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
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
  FUN_00401219((float10 *)piVar7[7],piVar7[6],piVar7[10],piVar7[0xb],piVar7[0xc]);
  return;
}


