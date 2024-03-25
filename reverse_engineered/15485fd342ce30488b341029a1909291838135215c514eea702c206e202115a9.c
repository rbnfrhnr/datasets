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
// WARNING: Instruction at (ram,0x00401245) overlaps instruction at (ram,0x00401244)
// 
// WARNING (jumptable): Unable to track spacebase fully for stack
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x00401172)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __fastcall entry(undefined **param_1,undefined *param_2)

{
  byte *pbVar1;
  char *pcVar2;
  code *pcVar3;
  char cVar4;
  code *pcVar5;
  uint uVar6;
  byte bVar8;
  byte bVar9;
  int iVar10;
  uint uVar11;
  code **ppcVar12;
  undefined4 uVar13;
  uint in_EAX;
  uint *puVar14;
  code **extraout_ECX;
  code **ppcVar15;
  char cVar16;
  byte bVar17;
  byte bVar18;
  byte *unaff_EBX;
  undefined *puVar19;
  undefined *puVar20;
  undefined *puVar22;
  code **unaff_EBP;
  code **ppcVar23;
  code **unaff_ESI;
  code **ppcVar24;
  code **unaff_EDI;
  ushort uVar25;
  ushort in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 uVar26;
  undefined2 in_DS;
  bool bVar27;
  bool bVar28;
  byte in_AF;
  bool bVar29;
  undefined8 uVar30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  uint uVar7;
  undefined4 *puVar21;
  
  puVar14 = &DAT_00401000;
  do {
    *puVar14 = *puVar14 ^ 0x3bde7cfe;
    puVar14 = puVar14 + 1;
  } while (puVar14 != (uint *)0x40915c);
  puVar14 = &DAT_0042c000;
  do {
    *puVar14 = *puVar14 ^ 0x21436434;
    puVar14 = puVar14 + 1;
    bVar28 = puVar14 < (uint *)0x42f3f8;
  } while (puVar14 != (uint *)0x42f3f8);
  do {
    pbVar1 = (byte *)((int)unaff_EDI + 0x3b);
    bVar8 = *pbVar1;
    bVar18 = (byte)((uint)unaff_EBX >> 8);
    bVar9 = *pbVar1 - bVar18;
    bVar27 = bVar8 < bVar18 || bVar9 < bVar28;
    *pbVar1 = bVar9 - bVar28;
    pbVar1 = (byte *)((int)unaff_ESI + (int)unaff_EBX * 8 + 0x6e);
    *pbVar1 = *pbVar1 + 1;
    bVar17 = (byte)((uint)param_2 >> 8);
    if ((bVar8 >= bVar18 && bVar9 >= bVar28) && *pbVar1 != 0) {
LAB_004011bb:
      pcVar5 = *(code **)(unaff_EBX + 0x66);
      bVar28 = bVar18 < bVar17;
      puVar19 = (undefined *)0xfbd7743a;
      if ((char)bVar17 <= (char)bVar18) {
                    // WARNING: Could not recover jumptable at 0x004011c9. Too many branches
                    // WARNING: Treating indirect jump as call
        iVar10 = (**unaff_ESI)();
        return iVar10;
      }
      do {
        uVar11 = (uint)bVar28;
        uVar6 = (int)*unaff_ESI - (int)pcVar5;
        bVar28 = *unaff_ESI < pcVar5 || uVar6 < uVar11;
        bVar29 = SBORROW4((int)*unaff_ESI,(int)pcVar5) != SBORROW4(uVar6,uVar11);
        *unaff_ESI = (code *)(uVar6 - uVar11);
        bVar27 = (int)*unaff_ESI < 0;
        pcVar3 = *unaff_ESI;
        out((short)param_2,(char)puVar19);
        puVar22 = (undefined *)0x7cf63b9c;
        if (pcVar3 == (code *)0x0) {
          if (bVar29 == bVar27) {
            return;
          }
          *(code ***)(puVar19 + -4) = unaff_ESI;
          return 0x7cf63b9c;
        }
        if ((POPCOUNT((uint)*unaff_ESI & 0xff) & 1U) == 0) {
          puVar20 = puVar19 + -4;
          *(undefined ***)(puVar19 + -4) = param_1;
          in_AF = in_AF | 1;
          uVar11 = CONCAT31(0x7cf63b,in_AF * -6 + -100) & 0xffffff0f;
          _DAT_f2665522 = CONCAT22((short)(uVar11 >> 0x10),CONCAT11(';' - in_AF,(char)uVar11));
          if (pcVar3 == (code *)0x0) {
            puVar22 = (undefined *)0x85;
            if ((byte)-in_AF == 0x16) {
              pcVar5 = (code *)swi(1);
              iVar10 = (*pcVar5)();
              return iVar10;
            }
            bVar8 = (byte)param_1 & 0x1f;
            puVar19 = (undefined *)
                      ((int)(puVar19 + -4) << bVar8 |
                      (uint)(CONCAT14(0x15 < (byte)-in_AF,puVar19 + -4) >> 0x21 - bVar8));
            bVar28 = false;
            *param_1 = (code *)((uint)*param_1 & 0xffffffc4);
            if (-1 < (int)*param_1) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            goto code_r0x00401152;
          }
          do {
            if (!bVar29) goto code_r0x00401165;
            puVar22 = (undefined *)0xbc;
            if (!bVar27) {
              return;
            }
            pcVar3 = (code *)*param_1;
            bVar28 = pcVar5 < pcVar3;
            bVar29 = SBORROW4((int)pcVar5,(int)pcVar3);
            bVar27 = (int)pcVar5 - (int)pcVar3 < 0;
          } while (!bVar27);
          puVar19 = (undefined *)0xfe3bd57c;
        }
        else if (bVar29 == bVar27) goto LAB_004011bb;
        if (bVar29 != bVar27) {
code_r0x00401152:
          puVar20 = puVar19 + -4;
          *(undefined2 *)(puVar19 + -4) = in_SS;
          cVar16 = (bVar17 - *unaff_EBX) - bVar28;
          puVar14 = (uint *)CONCAT22((short)((uint)param_2 >> 0x10),CONCAT11(cVar16,(byte)param_2));
          uVar30 = CONCAT44(puVar14,puVar22);
          if (*unaff_EBX <= bVar17 && bVar28 <= (byte)(bVar17 - *unaff_EBX)) {
            *(undefined2 *)(puVar19 + -8) = in_DS;
            do {
            } while (-1 < cVar16);
            pcVar2 = (char *)((int)unaff_EBP + (int)unaff_EBX * 2 + -1);
            *pcVar2 = *pcVar2 + '\x01';
            bVar8 = (byte)param_1 & 0x1f;
            *puVar14 = *puVar14 << bVar8 | *puVar14 >> 0x20 - bVar8;
            _DAT_77608023 = puVar19 + -8;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          while( true ) {
            param_2 = (undefined *)((ulonglong)uVar30 >> 0x20);
            bVar27 = (char)uVar30 < '\0';
code_r0x00401165:
            *(code ***)(puVar20 + -4) = unaff_EBP;
            if (!bVar27) break;
            *(undefined2 *)(puVar20 + -8) = in_CS;
            puVar21 = (undefined4 *)(puVar20 + -0xc);
            puVar20 = puVar20 + -0xc;
            *puVar21 = 0x40115f;
            uVar30 = (*(code *)param_2)();
          }
          *(uint *)((code *)param_2 + -0x5a08094c) = *(uint *)((code *)param_2 + -0x5a08094c) | 0x33
          ;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        *(byte *)unaff_ESI = *(byte *)unaff_ESI ^ (byte)param_2;
        in_AF = 9 < ((byte)puVar22 & 0xf) | in_AF;
        bVar28 = false;
        unaff_ESI = (code **)((uint)unaff_ESI ^ (uint)pcVar5);
        puVar19 = _DAT_1afffe3b;
      } while( true );
    }
    ppcVar12 = (code **)CONCAT22((short)(in_EAX >> 0x10),CONCAT11(0xc4,(char)in_EAX));
    uStack_24 = (code **)CONCAT22(uStack_24._2_2_,in_DS);
    do {
    } while (-1 < (char)*pbVar1);
code_r0x00401229:
    param_1 = uStack_24;
    bVar8 = (char)unaff_ESI + 'D' + bVar27;
    ppcVar15 = (code **)ppcVar12[0x1dd7e39f];
    ppcVar24 = (code **)((int)unaff_EDI - (int)ppcVar12[0x1dd7e39f]);
    pcVar2 = (char *)((int)unaff_EBP + (int)unaff_EBX * 2 + -0x29);
    *pcVar2 = *pcVar2 + '\x01';
    cVar16 = *pcVar2;
    cVar4 = *pcVar2;
    out((short)param_2,bVar8);
    in_AF = 9 < (bVar8 & 0xf) | in_AF;
    bVar8 = bVar8 + in_AF * -6;
    uVar11 = CONCAT31((int3)((uint)unaff_ESI >> 8),
                      bVar8 + (0x9f < bVar8 | unaff_EDI < ppcVar15 | in_AF * (bVar8 < 6)) * -0x60);
    *(char *)((int)ppcVar24 + (int)ppcVar12 * 2 + 0x19) = (char)((uint)uStack_24 >> 8);
    bVar28 = (longlong)(int)&uStack_28 != (longlong)(int)*ppcVar24 * 0x40;
    ppcVar15 = uStack_24;
    ppcVar23 = ppcVar12;
    if (cVar4 != '\0' && bVar28 == cVar16 < '\0') {
      while( true ) {
        uStack_28 = (code **)CONCAT22(uStack_28._2_2_,in_SS);
        uStack_2c = (uint *)CONCAT22(uStack_2c._2_2_,in_SS);
        puVar14 = uStack_2c;
        bVar9 = (char)uVar11 + -0x22 + bVar28;
        iVar10 = CONCAT31((int3)(uVar11 >> 8),bVar9);
        bVar8 = (byte)ppcVar15 & 0x1f;
        *uStack_2c = *uStack_2c >> bVar8 | *uStack_2c << 0x20 - bVar8;
        bVar28 = ((uint)ppcVar15 & 0x1f) == 0;
        uVar11 = *uStack_2c;
        uVar6 = *uStack_2c;
        uVar7 = *uStack_2c;
        uStack_2c = (uint *)CONCAT22(uStack_2c._2_2_,in_ES);
        if ((bVar28 && bVar9 < 0xde || !bVar28 && (int)uVar11 < 0) || bVar9 == 0xde) break;
        uVar25 = in_ES;
        uVar26 = in_CS;
        if ((bool)(bVar8 != 1 & SBORROW1(bVar9,-0x22) |
                  (bVar8 == 1 && (int)uVar6 < 0 != (int)(uVar7 << 1) < 0)) ==
            (char)(bVar9 + 0x22) < '\0') {
          uVar26 = 0x1d7c;
          uVar13 = func_0xfe3bdedf(in_CS);
          ppcVar24 = ppcVar24 + 1;
          bVar8 = 9 < ((byte)uVar13 & 0xf) | in_AF;
          bVar9 = (byte)uVar13 + bVar8 * -6;
          iVar10 = CONCAT31((int3)((uint)uVar13 >> 8),
                            bVar9 + (0x9f < bVar9 | ppcVar24 < puVar14 + 1 | bVar8 * (bVar9 < 6)) *
                                    -0x60);
          ppcVar15 = extraout_ECX;
        }
        *(char *)((int)ppcVar15 + iVar10 * 2 + -0x59) = (char)((uint)ppcVar15 >> 8);
        in_AF = (in_ES & 0x10) != 0;
        bVar28 = (in_ES & 1) != 0;
        ppcVar15 = (code **)CONCAT22((short)((uint)ppcVar15 >> 0x10),CONCAT11(0x7c,(char)ppcVar15));
        uVar11 = _DAT_31fde8c4;
        in_ES = uVar25;
        in_CS = uVar26;
      }
      return iVar10;
    }
    while( true ) {
      bVar28 = ppcVar24 < uStack_28;
      unaff_EDI = ppcVar24 + 1;
      ppcVar12 = ppcVar23 + 1;
      *ppcVar24 = *ppcVar23;
      in_DS = (undefined2)uStack_24;
      uVar26 = (undefined2)uStack_24;
      unaff_EBP = uStack_28;
      if ((int)uStack_28 <= (int)ppcVar24) break;
      uStack_24 = (code **)CONCAT22(uStack_24._2_2_,in_SS);
      _DAT_58963b98 = in_DS;
      do {
      } while (-1 < (int)ppcVar24 - (int)uStack_28);
      bVar9 = (byte)uVar11;
      bVar8 = bVar9 - 2;
      bVar27 = 1 < bVar9 || CARRY1(bVar8,bVar28);
      bVar29 = SCARRY1(bVar9,-2) != SCARRY1(bVar8,bVar28);
      uVar11 = CONCAT31((int3)(uVar11 >> 8),bVar8 + bVar28);
      if (bVar29 == (char)(bVar8 + bVar28) < '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      ppcVar23 = ppcVar12;
      ppcVar24 = unaff_EDI;
      _DAT_58963b98 = uVar26;
      if (bVar29) goto code_r0x00401241;
    }
    uVar11 = uVar11 ^ 0x1e505fd3;
    do {
    } while (-1 < (int)uVar11);
    uStack_24 = (code **)CONCAT22(uStack_24._2_2_,in_SS);
    in_EAX = CONCAT31((int3)(uVar11 >> 8),(char)uVar11 + (char)(uVar11 >> 8) * -0x3c) & 0xffff0066;
    if ((char)bVar18 < (char)bVar17) {
      return;
    }
    bVar28 = (bool)(*(byte *)param_1 & 1);
    *(byte *)param_1 = *(byte *)param_1 >> 1;
    unaff_ESI = ppcVar12;
  } while( true );
code_r0x00401241:
  unaff_ESI = (code **)(uVar11 + 1);
  goto code_r0x00401229;
}


