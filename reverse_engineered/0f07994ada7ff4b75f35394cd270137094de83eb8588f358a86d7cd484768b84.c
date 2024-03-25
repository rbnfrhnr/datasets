typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
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




// WARNING: Instruction at (ram,0x004012a2) overlaps instruction at (ram,0x004012a0)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 __fastcall
FUN_00401219(uint param_1,char *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6)

{
  byte *pbVar1;
  uint *puVar2;
  int iVar3;
  byte bVar4;
  byte bVar5;
  char cVar6;
  code *pcVar7;
  undefined6 uVar8;
  byte bVar9;
  byte bVar10;
  char cVar11;
  ushort uVar12;
  char cVar15;
  undefined *in_EAX;
  byte bVar14;
  uint uVar13;
  uint extraout_ECX;
  undefined2 uVar17;
  int iVar18;
  uint unaff_EBX;
  undefined4 *puVar19;
  undefined4 *unaff_EBP;
  undefined4 *puVar20;
  undefined4 *unaff_ESI;
  char *pcVar21;
  uint unaff_EDI;
  uint uVar22;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_DS;
  char in_CF;
  byte bVar23;
  bool bVar24;
  byte in_AF;
  bool in_ZF;
  bool bVar25;
  undefined uVar26;
  bool bVar27;
  bool bVar28;
  byte in_TF;
  byte in_IF;
  bool bVar29;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined8 uVar30;
  char *unaff_retaddr;
  undefined2 auStack_8 [2];
  undefined4 uStack_4;
  byte bVar16;
  
  uVar17 = SUB42(param_2,0);
  out(*unaff_ESI,uVar17);
  pcVar21 = (char *)((int)unaff_ESI + 5);
  out(*(undefined *)(unaff_ESI + 1),uVar17);
  if (in_ZF) {
    *(char *)(unaff_EBX + 0x1274cf2e) = *(char *)(unaff_EBX + 0x1274cf2e) + (char)unaff_EBX + in_CF;
code_r0x00401235:
    param_1 = param_1 | *(uint *)(in_EAX + unaff_EBX * 4 + 2);
    param_2 = (char *)((int)unaff_retaddr >> 0x1f);
    unaff_EBX = unaff_EBX & *(uint *)(unaff_EBX + 0xcb24276e);
    bVar25 = unaff_EBX == 0;
    bVar23 = 9 < ((byte)unaff_retaddr & 0xf) | in_AF;
    uVar22 = CONCAT31((int3)((uint)unaff_retaddr >> 8),(byte)unaff_retaddr + bVar23 * '\x06') &
             0xffffff0f;
    in_EAX = (undefined *)
             CONCAT22((short)(uVar22 >> 0x10),
                      CONCAT11((char)((uint)unaff_retaddr >> 8) + bVar23,(char)uVar22));
    pcVar21 = param_2 + unaff_EDI * 2 + 0x2f;
    in_AF = bVar23;
  }
  else {
    param_1 = param_1 | unaff_EDI;
    puVar2 = (uint *)(unaff_EBX + 0x7a8ba5ee);
    bVar23 = 0;
    *puVar2 = *puVar2 & unaff_EBX;
    if (0 < (int)*puVar2) {
      out(uVar17,in_EAX);
      goto code_r0x0040125c;
    }
    in_EAX = (undefined *)
             CONCAT22((short)((uint)in_EAX >> 0x10),
                      CONCAT11((char)((uint)in_EAX >> 8) + *(char *)(unaff_EBX + 0x55),(char)in_EAX)
                     );
    bVar23 = 0;
    unaff_EBX = unaff_EBX | *(uint *)(unaff_EDI + 0xcf2e9b10);
    bVar25 = unaff_EBX == 0;
    unaff_retaddr = param_2;
    if (!bVar25) goto code_r0x00401235;
    unaff_EBX = 0;
    if (!bVar25) {
      return CONCAT44(param_2,param_1);
    }
  }
  if (!bVar25 && -1 < (int)unaff_EBX) {
    uStack_4 = (undefined *)CONCAT22(uStack_4._2_2_,in_ES);
    iVar18 = CONCAT22((short)(unaff_EBX >> 0x10),CONCAT11(0x76,(char)unaff_EBX));
    uVar22 = unaff_EDI;
    if (((uint)in_EAX & 0xcf) == 0) goto LAB_004012ab;
    param_1 = param_1 | *(uint *)((int)&uStack_4 + (int)pcVar21 * 2);
    uVar22 = unaff_EDI + 1;
    *param_2 = *param_2 + '4';
    cVar11 = (char)in_EAX + *(char *)(unaff_EDI - 0x31);
    uVar13 = CONCAT31((int3)((uint)in_EAX >> 8),cVar11);
    uVar26 = cVar11 == '\0';
    while( true ) {
      if ((bool)uVar26) {
        pcVar7 = (code *)swi(3);
        uVar30 = (*pcVar7)();
        return uVar30;
      }
      bVar25 = false;
      uVar12 = (ushort)uVar13 ^ 0xb9;
      in_EAX = uStack_4;
      if ((char)uVar13 != -0x47) {
LAB_004012ab:
        unaff_EBP = (undefined4 *)((uint)unaff_EBP & *(uint *)((int)unaff_EBP + 0x6217b05e));
        iVar18 = CONCAT22((short)((uint)iVar18 >> 0x10),CONCAT11(*in_EAX,(char)iVar18));
        param_1 = param_1 | uVar22;
        bVar23 = (byte)((uint)in_EAX >> 8);
        bVar25 = CARRY1(bVar23,*(byte *)(param_1 - 0x31));
        uVar12 = CONCAT11(bVar23 + *(byte *)(param_1 - 0x31),(char)in_EAX);
        in_DS = (undefined2)uStack_4;
      }
      puVar2 = (uint *)(param_1 - 0x31);
      bVar24 = CARRY4(*puVar2,(uint)auStack_8) || CARRY4((int)auStack_8 + *puVar2,(uint)bVar25);
      *puVar2 = (int)auStack_8 + *puVar2 + (uint)bVar25;
      pbVar1 = (byte *)(iVar18 + -0x31);
      bVar16 = (byte)(uVar12 >> 8);
      bVar23 = bVar16 + *pbVar1;
      bVar25 = CARRY1(bVar16,*pbVar1) || CARRY1(bVar23,bVar24);
      bVar29 = SCARRY1(bVar16,*pbVar1) != SCARRY1(bVar23,bVar24);
      cVar11 = (char)uVar12;
      cVar15 = bVar23 + bVar24;
      uVar13 = (uint)CONCAT11(cVar15,cVar11);
      uVar26 = cVar15 == '\0';
      puVar20 = unaff_EBP;
      auStack_8[0] = in_DS;
      if ((bool)uVar26) break;
      iVar3 = *(int *)(uVar22 + 0xcf4b8254);
      *(uint *)(iVar3 + -4) =
           (uint)(in_NT & 1) * 0x4000 | (uint)bVar29 * 0x800 | (uint)(in_IF & 1) * 0x200 |
           (uint)(in_TF & 1) * 0x100 | (uint)(cVar15 < '\0') * 0x80 | (uint)(byte)uVar26 * 0x40 |
           (uint)(in_AF & 1) * 0x10 | (uint)((POPCOUNT(cVar15) & 1U) == 0) * 4 | (uint)bVar25 |
           (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
           (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
      puVar19 = (undefined4 *)(iVar3 + -8);
      puVar20 = (undefined4 *)(iVar3 + -8);
      *(undefined4 **)(iVar3 + -8) = unaff_EBP;
      cVar6 = '\f';
      do {
        unaff_EBP = unaff_EBP + -1;
        puVar19 = puVar19 + -1;
        *puVar19 = *unaff_EBP;
        cVar6 = cVar6 + -1;
      } while ('\0' < cVar6);
      *(int *)(iVar3 + -0x3c) = iVar3 + -8;
      if (!(bool)uVar26 && bVar29 == cVar15 < '\0') break;
      pcVar7 = (code *)swi(4);
      unaff_EBP = (undefined4 *)(iVar3 + -8);
      if (bVar29) {
        uVar13 = (*pcVar7)();
        param_1 = extraout_ECX;
        unaff_EBP = (undefined4 *)(iVar3 + -8);
      }
    }
    uVar22 = (int)puVar20 + 1;
    bVar23 = (byte)param_1 & 0x1f;
    DAT_f146d5f5 = cVar11 << bVar23;
    bVar24 = (param_1 & 0x1f) != 0;
    bVar24 = !bVar24 && bVar25 || bVar24 && (char)(cVar11 << bVar23 - 1) < '\0';
    bVar23 = bVar23 != 1 & SCARRY4((int)puVar20,1) | (bVar23 == 1 && bVar24 != DAT_f146d5f5 < '\0');
    bVar25 = (param_1 & 0x1f) != 0;
    bVar28 = !bVar25 && (int)uVar22 < 0 || bVar25 && DAT_f146d5f5 < '\0';
    bVar27 = !bVar25 && uVar22 == 0 || bVar25 && DAT_f146d5f5 == '\0';
    bVar29 = !bVar25 && (POPCOUNT(uVar22 & 0xff) & 1U) == 0 ||
             bVar25 && (POPCOUNT(DAT_f146d5f5) & 1U) == 0;
    if (!bVar25 && uVar22 == 0 || bVar25 && DAT_f146d5f5 == '\0') {
      uVar30 = func_0x4174cf7c(in_CS,(uint)(in_NT & 1) * 0x4000 | (uint)bVar23 * 0x800 |
                                     (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 |
                                     (uint)bVar28 * 0x80 | (uint)bVar27 * 0x40 |
                                     (uint)(in_AF & 1) * 0x10 | (uint)bVar29 * 4 | (uint)bVar24 |
                                     (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
                                     (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000,
                               (uint)(in_NT & 1) * 0x4000 | (uint)bVar23 * 0x800 |
                               (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 |
                               (uint)bVar28 * 0x80 | (uint)bVar27 * 0x40 | (uint)(in_AF & 1) * 0x10
                               | (uint)bVar29 * 4 | (uint)bVar24 | (uint)(in_ID & 1) * 0x200000 |
                               (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
                               (uint)(in_AC & 1) * 0x40000);
      uVar26 = in(0xb0);
      return CONCAT44(CONCAT31((int3)((ulonglong)uVar30 >> 0x28),
                               (char)((ulonglong)uVar30 >> 0x20) +
                               *(char *)((ulonglong)uVar30 >> 0x20)),
                      CONCAT31((int3)((ulonglong)uVar30 >> 8),uVar26));
    }
    return CONCAT44(param_4,param_6);
  }
code_r0x0040125c:
  bVar14 = (byte)((uint)in_EAX >> 8);
  bVar16 = bVar14 + *(byte *)(unaff_EBX - 0x11);
  bVar9 = (byte)in_EAX;
  uVar8 = *(undefined6 *)
           (CONCAT22((short)((uint)in_EAX >> 0x10),CONCAT11(bVar16 + bVar23,bVar9)) + 0xb);
  bVar4 = 9 < (bVar9 & 0xf) | in_AF;
  bVar9 = bVar9 + bVar4 * '\x06';
  bVar5 = 9 < ((byte)_DAT_8bcf0b68 & 0xf) | bVar4;
  bVar10 = (byte)_DAT_8bcf0b68 + bVar5 * '\x06';
  DAT_278bcf49 = bVar10 + (0x90 < (bVar10 & 0xf0) |
                          0x90 < (bVar9 & 0xf0) |
                          (CARRY1(bVar14,*(byte *)(unaff_EBX - 0x11)) || CARRY1(bVar16,bVar23)) |
                          bVar4 * (0xf9 < bVar9) | bVar5 * (0xf9 < bVar10)) * '`';
  uVar22 = unaff_EDI & *(uint *)(unaff_EDI + 0x36);
  iVar18 = CONCAT22((short)((uint6)uVar8 >> 0x10),
                    CONCAT11((char)((uint6)uVar8 >> 8) + (char)((uint)_DAT_8bcf0b68 >> 8),
                             (char)uVar8));
  return CONCAT44(iVar18,CONCAT31((int3)((uint)_DAT_8bcf0b68 >> 8),
                                  DAT_278bcf49 + *(char *)(iVar18 + 0x49a260ea) +
                                  (uVar22 < *(uint *)(uVar22 + 0x36))));
}



// WARNING: Unable to track spacebase fully for stack

undefined8 entry(void)

{
  uint *puVar1;
  uint *puVar2;
  undefined4 *puVar3;
  uint **ppuVar4;
  uint *puVar5;
  short sVar6;
  undefined2 in_SS;
  undefined8 uVar8;
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
  uVar8 = FUN_00401219(piVar7[7],(char *)piVar7[6],piVar7[10],piVar7[0xb],piVar7[0xc],piVar7[0xd]);
  return uVar8;
}


