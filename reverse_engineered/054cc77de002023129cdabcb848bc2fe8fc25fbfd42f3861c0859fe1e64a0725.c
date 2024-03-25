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




// WARNING: Instruction at (ram,0x0040126e) overlaps instruction at (ram,0x0040126d)
// 
// WARNING: Control flow encountered bad instruction data
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x004012b5)
// WARNING: Removing unreachable block (ram,0x00401328)
// WARNING: Removing unreachable block (ram,0x00401162)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __fastcall FUN_00401219(uint param_1,uint *param_2,byte param_3)

{
  uint *puVar1;
  short *psVar2;
  int *piVar3;
  char cVar4;
  code *pcVar5;
  undefined *puVar6;
  undefined4 uVar7;
  undefined uVar8;
  short sVar9;
  short **ppsVar10;
  uint in_EAX;
  uint uVar11;
  uint uVar13;
  byte bVar16;
  undefined4 uVar14;
  undefined3 uVar17;
  byte *pbVar15;
  uint extraout_ECX;
  byte bVar20;
  byte bVar23;
  int iVar18;
  uint unaff_EBX;
  char cVar22;
  uint uVar19;
  uint *puVar24;
  short **ppsVar25;
  uint **ppuVar26;
  uint **ppuVar27;
  uint **ppuVar28;
  short **ppsVar29;
  undefined *puVar30;
  uint **unaff_EBP;
  uint **ppuVar31;
  undefined4 *puVar32;
  uint unaff_ESI;
  undefined2 in_CS;
  undefined2 in_DS;
  bool bVar33;
  bool bVar34;
  byte bVar35;
  byte in_AF;
  bool bVar36;
  bool bVar37;
  byte in_TF;
  byte in_IF;
  bool bVar38;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined2 in_FPUControlWord;
  float10 in_ST0;
  float10 extraout_ST0;
  undefined8 uVar39;
  undefined4 *unaff_retaddr;
  uint uVar12;
  byte bVar21;
  
  bVar33 = unaff_EBX < unaff_ESI;
  bVar35 = (byte)(in_EAX >> 8);
  bVar16 = (byte)(unaff_EBX >> 8);
  bVar23 = bVar16 - bVar35;
  bVar34 = bVar16 < bVar35 || bVar23 < bVar33;
  cVar22 = bVar23 - bVar33;
  uVar19 = CONCAT22((short)(unaff_EBX >> 0x10),CONCAT11(cVar22,(char)unaff_EBX));
  if (cVar22 == '\0' || (SBORROW1(bVar16,bVar35) != SBORROW1(bVar23,bVar33)) != cVar22 < '\0') {
    if (cVar22 != '\0') {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    bVar33 = (POPCOUNT(in_EAX + 0xcf4394e5 + (uint)bVar34 & 0xff) & 1U) == 0;
    bVar23 = 9 < (param_3 & 0xf) | in_AF;
code_r0x0040122a:
    in_EAX = in(10);
    ppuVar26 = (uint **)&DAT_757e2f5f;
    bVar35 = bVar23;
    if (!bVar33) {
      cVar22 = (char)(in_EAX >> 8);
      uVar19 = CONCAT22((short)(uVar19 >> 0x10),
                        CONCAT11(((char)(uVar19 >> 8) - cVar22) - bVar23,(char)uVar19));
      ppuVar27 = (uint **)&DAT_757e2f63;
      sVar9 = (short)(char)in_EAX * (short)cVar22;
      bVar35 = 0;
      puVar32 = (undefined4 *)
                (CONCAT31((int3)(CONCAT22((short)(in_EAX >> 0x10),sVar9) >> 8),(char)sVar9) | 0x29);
      ppuVar31 = (uint **)((int)unaff_EBP - 1);
      unaff_retaddr = _DAT_757e2f5f;
      if (ppuVar31 != (uint **)0x0) goto LAB_00401278;
      param_2 = (uint *)((int)param_2 + -1);
      bVar35 = false;
      in_EAX = (uint)_DAT_757e2f5f & 0x7d7c5b63;
      ppuVar26 = ppuVar27;
      ppuVar31 = (uint **)0x0;
      unaff_retaddr = puVar32;
      do {
        ppuVar28 = (uint **)((int)ppuVar26 + -4);
        *(uint *)((int)ppuVar26 + -4) = uVar19;
LAB_00401246:
        uVar7 = *ppuVar28;
        ppuVar26 = ppuVar28 + 1;
        ppsVar25 = (short **)(ppuVar28 + 1);
        cVar22 = (char)((uint)uVar7 >> 8);
        bVar34 = bVar35 != '\0';
        bVar38 = SBORROW1(cVar22,cVar22) != false;
        cVar22 = -bVar35;
        uVar19 = CONCAT22((short)((uint)uVar7 >> 0x10),CONCAT11(cVar22,(char)uVar7));
        bVar37 = '\0' < (char)bVar35;
        bVar36 = cVar22 == '\0';
        bVar33 = (POPCOUNT(cVar22) & 1U) == 0;
        LOCK();
        uVar8 = *(undefined *)(uVar19 + 0x3e);
        *(undefined *)(uVar19 + 0x3e) = (char)param_2;
        param_2 = (uint *)CONCAT31((int3)((uint)param_2 >> 8),uVar8);
        UNLOCK();
        bVar35 = bVar23;
        if (!bVar36 && bVar38 == bVar37) {
          while( true ) {
            puVar1 = _DAT_75412100;
            if (!bVar33) {
              iVar18 = in_EAX + 0x6f5a3b1a + (uint)bVar34;
              *(char *)unaff_retaddr = (char)iVar18;
              uVar19 = iVar18 + 0x34c1411 +
                       (uint)(0x90a5c4e5 < in_EAX || CARRY4(in_EAX + 0x6f5a3b1a,(uint)bVar34));
              out((short)param_2,uVar19);
              cVar22 = (char)param_2 - cRam83fe0bb6;
              bVar36 = SBORROW1((char)param_2,cRam83fe0bb6) != SBORROW1(cVar22,uVar19 < 0x7f5ff41a);
              cVar22 = cVar22 - (uVar19 < 0x7f5ff41a);
              bVar34 = cVar22 < '\0';
              bVar33 = cVar22 == '\0';
              ppsVar10 = ppsVar25 + 1;
              do {
                while (puVar24 = (uint *)ppsVar10, iVar18 = *puVar24, bVar33 || bVar36 != bVar34) {
                  cVar4 = *(char *)(iVar18 + 0x76);
                  bVar36 = SBORROW1(cVar4,cVar22);
                  bVar34 = (char)(cVar4 - cVar22) < '\0';
                  bVar33 = cVar4 == cVar22;
                  ppsVar10 = (short **)(puVar24 + 2);
                  if (cVar4 <= cVar22) {
                    *(char *)((int)puVar24 + 0x37) = (char)((uint)param_2 >> 8);
                    uVar19 = in(0xc9);
                    return uVar19;
                  }
                }
                puVar1 = (uint *)(param_1 + 0x14);
                uVar12 = *puVar1;
                uVar19 = *puVar1;
                *puVar1 = *puVar1 - param_1;
                *puVar24 = (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4(uVar19,param_1) * 0x800 |
                           (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 |
                           (uint)((int)*puVar1 < 0) * 0x80 | (uint)(*puVar1 == 0) * 0x40 |
                           (uint)(bVar23 & 1) * 0x10 |
                           (uint)((POPCOUNT(*puVar1 & 0xff) & 1U) == 0) * 4 |
                           (uint)(uVar12 < param_1) | (uint)(in_ID & 1) * 0x200000 |
                           (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
                           (uint)(in_AC & 1) * 0x40000;
                bVar36 = false;
                ppuVar31 = (uint **)((uint)ppuVar31 & 0x12bbdc03);
                bVar34 = false;
                bVar33 = ppuVar31 == (uint **)0x0;
                puVar24[-1] = iVar18 + -1;
                ppsVar10 = (short **)(puVar24 + -1);
              } while (param_1 != 0);
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            puVar6 = (undefined *)*ppsVar25;
            ppsVar10 = ppsVar25 + 1;
            if (!bVar36 && bVar38 == bVar37) break;
            *(undefined2 *)(puVar6 + 0x62) = in_FPUControlWord;
            *ppsVar25 = (short *)CONCAT31((int3)(uVar19 >> 8),0x22);
            *puVar6 = (char)puVar1;
            puVar32 = (undefined4 *)0xfb6f7f5f;
            out(0x7e,puVar1);
            bVar16 = (byte)((uint)puVar1 >> 8);
            bVar21 = (byte)(uVar19 >> 8);
            bVar35 = bVar21 - bVar16;
            bVar20 = bVar35 - bVar34;
            iVar18 = (uint)CONCAT21((short)(uVar19 >> 0x10),bVar20) << 8;
            unaff_retaddr = (undefined4 *)*ppsVar25;
            ppuVar31 = (uint **)*puVar1;
            ppsVar25 = (short **)(puVar1 + 1);
            if (bVar21 < bVar16 || bVar35 < bVar34) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            while (bVar20 != 0 &&
                   (SBORROW1(bVar21,bVar16) != SBORROW1(bVar35,bVar34)) ==
                   (short)((ushort)bVar20 << 8) < 0) {
              *unaff_retaddr = *puVar32;
              puVar32 = *(undefined4 **)((int)ppsVar25 + 4);
              ppuVar31 = *(uint ***)((int)ppsVar25 + 8);
              iVar18 = *(int *)((int)ppsVar25 + 0x10);
              param_2 = *(uint **)((int)ppsVar25 + 0x14);
              param_1 = *(uint *)((int)ppsVar25 + 0x18);
              ppsVar10 = *(short ***)((int)ppsVar25 + 0x1c);
              unaff_retaddr = *(undefined4 **)((int)ppsVar25 + 0x20);
              ppsVar25 = (short **)((int)ppsVar25 + 0x24);
            }
            in_EAX = CONCAT31((int3)((uint)ppsVar10 >> 8),uRam1d4c0a4a) - 1U & 0xffffff7f;
            pbVar15 = (byte *)((int)unaff_retaddr + -0x65);
            bVar16 = (byte)((uint)iVar18 >> 8);
            bVar34 = bVar16 < *pbVar15;
            bVar35 = bVar16 - *pbVar15;
            bVar38 = SBORROW1(bVar16,*pbVar15) != false;
            uVar19 = (uint)CONCAT21((short)((uint)iVar18 >> 0x10),bVar35) << 8;
            bVar37 = (short)((ushort)bVar35 << 8) < 0;
            bVar36 = bVar35 == 0;
            bVar33 = (POPCOUNT(bVar35) & 1U) == 0;
          }
          return in_EAX;
        }
code_r0x0040124e:
        if (!bVar33) goto LAB_004012c0;
        uVar11 = in_EAX ^ 0xefd4727f;
        bVar38 = SBORROW4(uVar11,-0x30846be6);
        uVar12 = uVar11 + 0x30846be6;
        bVar37 = (int)uVar12 < 0;
        bVar36 = uVar12 == 0;
        bVar33 = (POPCOUNT(uVar12 & 0xff) & 1U) == 0;
code_r0x0040125b:
        uVar7 = *ppuVar26;
        bVar35 = 9 < ((byte)uVar7 & 0xf) | bVar35;
        uVar12 = CONCAT31((int3)((uint)uVar7 >> 8),(byte)uVar7 + bVar35 * '\x06') & 0xffffff0f;
        uVar8 = (undefined)uVar12;
        in_EAX = CONCAT22((short)(uVar12 >> 0x10),CONCAT11((char)((uint)uVar7 >> 8) + bVar35,uVar8))
        ;
        *(undefined *)ppuVar26[1] = uVar8;
        unaff_ESI = 0x86cf975f;
        unaff_retaddr = ppuVar26[2];
        ppuVar26 = ppuVar26 + 3;
        if (!bVar36 && -0x30846be7 < (int)uVar11) goto code_r0x0040124e;
        unaff_EBP = (uint **)*ppuVar31;
        ppuVar26 = ppuVar31 + 1;
        bVar23 = bVar35;
        if ((bool)bVar35 || bVar36) {
          ppuVar26 = ppuVar31 + 2;
          in_EAX = CONCAT31((int3)((uint)ppuVar31[1] >> 8),DAT_1d4c3e4a);
          if (!bVar36 && -0x30846be7 < (int)uVar11) goto LAB_00401256_3;
          ppuVar31 = (uint **)*unaff_EBP;
          ppuVar28 = unaff_EBP + 1;
          if (!bVar36 && -0x30846be7 < (int)uVar11) goto LAB_00401246;
          puVar32 = unaff_EBP[1];
          ppuVar27 = unaff_EBP + 2;
LAB_00401278:
          uVar13 = CONCAT31((int3)((uint)puVar32 >> 8),-bVar35);
          uVar7 = *ppuVar27;
          *(undefined2 *)ppuVar27 = in_CS;
          uVar12 = (uint)bVar35;
          uVar11 = uVar13 + 0xd6030d81;
          cVar22 = uVar13 < 0x29fcf27f || uVar11 < uVar12;
          bVar33 = SBORROW4(uVar13,0x29fcf27f) != SBORROW4(uVar11,uVar12);
          uVar11 = uVar11 - uVar12;
          if (uVar11 == 0 || bVar33 != (int)uVar11 < 0) {
            if (uVar11 != 0 && bVar33 == (int)uVar11 < 0) {
              return uVar11;
            }
            piVar3 = (int *)segment(in_DS,(short)unaff_retaddr);
            iVar18 = *piVar3;
            cVar22 = '\0';
            bVar16 = (byte)(uVar11 >> 8) ^ (byte)((uint)uVar7 >> 8);
            uVar14 = CONCAT31(CONCAT21((short)(uVar11 >> 0x10),bVar16),
                              *(undefined *)(unaff_ESI - iVar18));
            uVar19 = CONCAT22((short)(uVar19 >> 0x10),CONCAT11(0xa5,(char)uVar19));
            *(undefined4 *)((int)ppuVar27 + -5) = uVar14;
            *(uint *)((int)ppuVar27 + -9) = param_1;
            *(undefined4 *)((int)ppuVar27 + -0xd) = uVar7;
            *(uint *)((int)ppuVar27 + -0x11) = uVar19;
            *(undefined **)((int)ppuVar27 + -0x15) = (undefined *)((int)ppuVar27 + -1);
            *(uint ***)((int)ppuVar27 + -0x19) = ppuVar31;
            ppsVar29 = (short **)((int)ppuVar27 + -0x1d);
            ppuVar26 = (uint **)((int)ppuVar27 + -0x1d);
            *(undefined **)((int)ppuVar27 + -0x1d) = (undefined *)(unaff_ESI - iVar18) + 1;
            *(undefined4 **)((int)ppuVar27 + -0x21) = unaff_retaddr;
            unaff_retaddr = *(undefined4 **)((int)ppuVar27 + -0x21);
            param_2 = (uint *)CONCAT22((short)((uint)uVar7 >> 0x10),CONCAT11(0xd9,(char)uVar7));
            in_EAX = (uint)(short)uVar14;
            uVar39 = CONCAT44(param_2,in_EAX);
            bVar35 = bVar23;
            if (bVar16 == 0 || (short)((ushort)bVar16 << 8) < 0) goto code_r0x00401298;
            break;
          }
          *(undefined2 *)((int)ppuVar27 + -5) = in_CS;
          in_CS = 0x141a;
          puVar30 = (undefined *)((int)ppuVar27 + -9);
          *(undefined4 *)((int)ppuVar27 + -9) = 0x4012a5;
          uVar39 = func_0x7e13eca2();
          *(int *)(puVar30 + -4) = (int)uVar39;
          *(uint *)(puVar30 + -8) = extraout_ECX;
          *(int *)(puVar30 + -0xc) = (int)((ulonglong)uVar39 >> 0x20);
          *(uint *)(puVar30 + -0x10) = uVar19;
          *(undefined **)(puVar30 + -0x14) = puVar30;
          *(uint ***)(puVar30 + -0x18) = ppuVar31;
          *(uint *)(puVar30 + -0x1c) = unaff_ESI;
          ppsVar29 = (short **)(puVar30 + -0x20);
          *(undefined4 **)(puVar30 + -0x20) = unaff_retaddr;
          param_1 = extraout_ECX;
          in_ST0 = extraout_ST0;
code_r0x00401298:
          param_2 = (uint *)((ulonglong)uVar39 >> 0x20);
          unaff_retaddr = (undefined4 *)*ppsVar29;
          ppuVar26 = (uint **)0x9ad6a91a;
          DAT_1a7e13ec = (char)uVar39;
          cVar4 = DAT_1a7e13ec + '`';
          uVar17 = (undefined3)((ulonglong)uVar39 >> 8);
          *param_2 = *param_2 | uVar19;
          pbVar15 = (byte *)(CONCAT31(uVar17,cVar4 + cVar22) | 0x29);
          unaff_EBP = (uint **)((int)ppuVar31 - 1);
          uVar19 = uVar19 + 1;
          bVar35 = (byte)pbVar15 | *pbVar15;
          in_EAX = CONCAT31(uVar17,bVar35);
          if ((char)bVar35 < '\0') {
            in_ST0 = in_ST0 * (float10)*(short *)(in_EAX + 0x7f5ff197);
            bVar35 = bVar23;
            goto code_r0x004012b9;
          }
        }
        else {
          *(int *)((int)unaff_EBP + 0x75U) = *(int *)((int)unaff_EBP + 0x75U) - param_1;
        }
        bVar16 = *(byte *)((int)unaff_retaddr + 0x5b63254a);
        bVar20 = (byte)param_2;
        bVar35 = bVar20 < bVar16;
        bVar38 = SBORROW1(bVar20,bVar16);
        bVar37 = (char)(bVar20 - bVar16) < '\0';
        bVar36 = bVar20 == bVar16;
        ppuVar31 = unaff_EBP;
        if ((char)bVar20 < (char)bVar16) goto code_r0x004012c2;
      } while( true );
    }
    *(char *)((int)unaff_retaddr + 0x707f5ff1) = (char)param_2;
code_r0x004012b9:
    bVar38 = false;
    in_EAX = in_EAX ^ 0x35ff707f;
    bVar37 = (int)in_EAX < 0;
    bVar36 = in_EAX == 0;
    if (0 < (int)in_EAX) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
LAB_004012c0:
    bVar35 = 9 < ((byte)in_EAX & 0xf) | bVar35;
    uVar12 = CONCAT31((int3)(in_EAX >> 8),(byte)in_EAX + bVar35 * '\x06') & 0xffffff0f;
    in_EAX = CONCAT22((short)(uVar12 >> 0x10),CONCAT11((char)(in_EAX >> 8) + bVar35,(char)uVar12));
code_r0x004012c2:
    if (!bVar36 && bVar38 == bVar37) {
code_r0x004012e1:
      pcVar5 = (code *)swi(3);
      uVar19 = (*pcVar5)();
      return uVar19;
    }
    *(short *)unaff_retaddr = (short)ROUND(in_ST0);
    *(uint ***)((int)ppuVar26 + -4) = ppuVar26;
    psVar2 = (short *)((int)unaff_retaddr + 0x1a);
    bVar23 = (byte)(uVar19 >> 8);
    bVar34 = *(byte *)psVar2 < bVar23;
    *(byte *)psVar2 = *(byte *)psVar2 - bVar23;
    if (*(byte *)psVar2 == 0) goto code_r0x004012e1;
  }
  return (in_EAX + 0x80361a81) - (uint)bVar34;
LAB_00401256_3:
  ppuVar31 = unaff_EBP;
  if (!bVar33) goto code_r0x0040122a;
  goto code_r0x0040125b;
}



void __fastcall entry(uint param_1,uint *param_2,byte param_3)

{
  uint *puVar1;
  
  puVar1 = &DAT_00401000;
  do {
    *puVar1 = *puVar1 ^ 0x1a7f5ffc;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x408e14);
  puVar1 = &DAT_0042b000;
  do {
    *puVar1 = *puVar1 ^ 0x17fb7cd1;
    puVar1 = puVar1 + 1;
  } while (puVar1 != (uint *)0x42e3d0);
  FUN_00401219(param_1,param_2,param_3);
  return;
}


