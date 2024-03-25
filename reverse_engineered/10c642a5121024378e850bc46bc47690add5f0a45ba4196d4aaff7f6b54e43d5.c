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
// WARNING: Instruction at (ram,0x00401469) overlaps instruction at (ram,0x00401468)
// 
// WARNING (jumptable): Unable to track spacebase fully for stack
// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x00401312)
// WARNING: Removing unreachable block (ram,0x00401380)
// WARNING: Removing unreachable block (ram,0x0040138a)
// WARNING: Removing unreachable block (ram,0x004013e5)
// WARNING: Removing unreachable block (ram,0x00401371)
// WARNING: Removing unreachable block (ram,0x00401375)
// WARNING: Removing unreachable block (ram,0x004013e7)
// WARNING: Removing unreachable block (ram,0x004013e9)
// WARNING: Removing unreachable block (ram,0x004013f2)
// WARNING: Removing unreachable block (ram,0x0040144c)
// WARNING: Removing unreachable block (ram,0x0040145e)
// WARNING: Removing unreachable block (ram,0x00401462)
// WARNING: Removing unreachable block (ram,0x00401509)
// WARNING: Removing unreachable block (ram,0x0040148d)
// WARNING: Removing unreachable block (ram,0x00401498)
// WARNING: Removing unreachable block (ram,0x00401508)
// WARNING: Removing unreachable block (ram,0x004014da)
// WARNING: Removing unreachable block (ram,0x004014de)
// WARNING: Removing unreachable block (ram,0x004014e0)
// WARNING: Removing unreachable block (ram,0x0040150d)
// WARNING: Removing unreachable block (ram,0x0040150a)
// WARNING: Removing unreachable block (ram,0x0040150f)
// WARNING: Removing unreachable block (ram,0x00401512)
// WARNING: Removing unreachable block (ram,0x00401517)
// WARNING: Removing unreachable block (ram,0x00401518)
// WARNING: Removing unreachable block (ram,0x004014ea)
// WARNING: Removing unreachable block (ram,0x00401554)
// WARNING: Removing unreachable block (ram,0x004014ec)
// WARNING: Removing unreachable block (ram,0x0040151a)
// WARNING: Removing unreachable block (ram,0x004014f6)
// WARNING: Removing unreachable block (ram,0x004014c9)
// WARNING: Removing unreachable block (ram,0x004014f9)
// WARNING: Removing unreachable block (ram,0x00401526)
// WARNING: Removing unreachable block (ram,0x00401536)
// WARNING: Removing unreachable block (ram,0x0040153d)
// WARNING: Removing unreachable block (ram,0x004014fa)
// WARNING: Removing unreachable block (ram,0x00401589)
// WARNING: Removing unreachable block (ram,0x00401592)
// WARNING: Removing unreachable block (ram,0x00401562)
// WARNING: Removing unreachable block (ram,0x00401568)
// WARNING: Removing unreachable block (ram,0x0040156a)
// WARNING: Removing unreachable block (ram,0x004015d2)
// WARNING: Removing unreachable block (ram,0x004015ec)
// WARNING: Removing unreachable block (ram,0x00401623)
// WARNING: Removing unreachable block (ram,0x0040162a)
// WARNING: Removing unreachable block (ram,0x0040169a)
// WARNING: Removing unreachable block (ram,0x004016a8)
// WARNING: Removing unreachable block (ram,0x0040173e)
// WARNING: Removing unreachable block (ram,0x00401740)
// WARNING: Removing unreachable block (ram,0x00401797)
// WARNING: Removing unreachable block (ram,0x004017d7)
// WARNING: Removing unreachable block (ram,0x00401827)
// WARNING: Removing unreachable block (ram,0x004017a0)
// WARNING: Removing unreachable block (ram,0x004017ac)
// WARNING: Removing unreachable block (ram,0x004017b9)
// WARNING: Removing unreachable block (ram,0x004017cf)
// WARNING: Removing unreachable block (ram,0x004017d1)
// WARNING: Removing unreachable block (ram,0x004017d8)
// WARNING: Removing unreachable block (ram,0x004017d9)
// WARNING: Removing unreachable block (ram,0x004017dd)
// WARNING: Removing unreachable block (ram,0x004017de)
// WARNING: Removing unreachable block (ram,0x00401779)
// WARNING: Removing unreachable block (ram,0x004017db)
// WARNING: Removing unreachable block (ram,0x00401782)
// WARNING: Removing unreachable block (ram,0x00401784)
// WARNING: Removing unreachable block (ram,0x004017ef)
// WARNING: Removing unreachable block (ram,0x004017f4)
// WARNING: Removing unreachable block (ram,0x00401807)
// WARNING: Removing unreachable block (ram,0x004017f6)
// WARNING: Removing unreachable block (ram,0x004017f8)
// WARNING: Removing unreachable block (ram,0x00401817)
// WARNING: Removing unreachable block (ram,0x004017a8)
// WARNING: Removing unreachable block (ram,0x004017a9)
// WARNING: Removing unreachable block (ram,0x0040181d)
// WARNING: Removing unreachable block (ram,0x00401821)
// WARNING: Removing unreachable block (ram,0x004017b2)
// WARNING: Removing unreachable block (ram,0x00401825)
// WARNING: Removing unreachable block (ram,0x00401890)
// WARNING: Removing unreachable block (ram,0x00401893)
// WARNING: Removing unreachable block (ram,0x00401900)
// WARNING: Removing unreachable block (ram,0x00401898)
// WARNING: Removing unreachable block (ram,0x004018a5)
// WARNING: Removing unreachable block (ram,0x004018a8)
// WARNING: Removing unreachable block (ram,0x004018bb)
// WARNING: Removing unreachable block (ram,0x004018bd)
// WARNING: Removing unreachable block (ram,0x00401912)
// WARNING: Removing unreachable block (ram,0x00401828)
// WARNING: Removing unreachable block (ram,0x0040182e)
// WARNING: Removing unreachable block (ram,0x00401830)
// WARNING: Removing unreachable block (ram,0x0040181e)
// WARNING: Removing unreachable block (ram,0x0040184e)
// WARNING: Removing unreachable block (ram,0x0040185f)
// WARNING: Removing unreachable block (ram,0x004018ca)
// WARNING: Removing unreachable block (ram,0x004018dc)
// WARNING: Removing unreachable block (ram,0x004018e6)
// WARNING: Removing unreachable block (ram,0x00401925)
// WARNING: Removing unreachable block (ram,0x004018f6)
// WARNING: Removing unreachable block (ram,0x004018f8)
// WARNING: Removing unreachable block (ram,0x00401903)
// WARNING: Removing unreachable block (ram,0x00401910)
// WARNING: Removing unreachable block (ram,0x00401914)
// WARNING: Removing unreachable block (ram,0x00401915)
// WARNING: Removing unreachable block (ram,0x0040191c)
// WARNING: Removing unreachable block (ram,0x0040191e)
// WARNING: Removing unreachable block (ram,0x00401996)
// WARNING: Removing unreachable block (ram,0x00401944)
// WARNING: Removing unreachable block (ram,0x0040194c)
// WARNING: Removing unreachable block (ram,0x0040194e)
// WARNING: Removing unreachable block (ram,0x00401978)
// WARNING: Removing unreachable block (ram,0x00401920)
// WARNING: Removing unreachable block (ram,0x00401926)
// WARNING: Removing unreachable block (ram,0x00401955)
// WARNING: Removing unreachable block (ram,0x0040195c)
// WARNING: Removing unreachable block (ram,0x004019d7)
// WARNING: Removing unreachable block (ram,0x004019da)
// WARNING: Removing unreachable block (ram,0x00401a15)
// WARNING: Removing unreachable block (ram,0x00401989)
// WARNING: Removing unreachable block (ram,0x00401991)
// WARNING: Removing unreachable block (ram,0x00401999)
// WARNING: Removing unreachable block (ram,0x004019a5)
// WARNING: Removing unreachable block (ram,0x004019a9)
// WARNING: Removing unreachable block (ram,0x00401947)
// WARNING: Removing unreachable block (ram,0x004019ac)
// WARNING: Removing unreachable block (ram,0x004019b4)
// WARNING: Removing unreachable block (ram,0x004019f5)
// WARNING: Removing unreachable block (ram,0x004019c6)
// WARNING: Removing unreachable block (ram,0x004019d1)
// WARNING: Removing unreachable block (ram,0x004019e0)
// WARNING: Removing unreachable block (ram,0x004019ec)
// WARNING: Removing unreachable block (ram,0x004019fb)
// WARNING: Removing unreachable block (ram,0x00401a54)
// WARNING: Removing unreachable block (ram,0x00401ac0)
// WARNING: Removing unreachable block (ram,0x00401a91)
// WARNING: Removing unreachable block (ram,0x00401a58)
// WARNING: Removing unreachable block (ram,0x00401a5a)
// WARNING: Removing unreachable block (ram,0x00401a6f)
// WARNING: Removing unreachable block (ram,0x00401a7c)
// WARNING: Removing unreachable block (ram,0x00401a7e)
// WARNING: Removing unreachable block (ram,0x00401af0)
// WARNING: Removing unreachable block (ram,0x00401af2)
// WARNING: Removing unreachable block (ram,0x00401b18)
// WARNING: Removing unreachable block (ram,0x00401a88)
// WARNING: Removing unreachable block (ram,0x00401a9c)
// WARNING: Removing unreachable block (ram,0x00401b08)
// WARNING: Removing unreachable block (ram,0x00401aa0)
// WARNING: Removing unreachable block (ram,0x00401ab9)
// WARNING: Removing unreachable block (ram,0x00401ac9)
// WARNING: Removing unreachable block (ram,0x00401ad5)
// WARNING: Removing unreachable block (ram,0x00401ae5)
// WARNING: Removing unreachable block (ram,0x00401b2f)
// WARNING: Removing unreachable block (ram,0x00401a82)
// WARNING: Removing unreachable block (ram,0x00401a24)
// WARNING: Removing unreachable block (ram,0x00401a26)
// WARNING: Removing unreachable block (ram,0x004019f7)
// WARNING: Removing unreachable block (ram,0x004019fc)
// WARNING: Removing unreachable block (ram,0x00401a53)
// WARNING: Removing unreachable block (ram,0x00401a09)
// WARNING: Removing unreachable block (ram,0x00401a1c)
// WARNING: Removing unreachable block (ram,0x00401a23)
// WARNING: Removing unreachable block (ram,0x00401a25)
// WARNING: Removing unreachable block (ram,0x00401a2b)
// WARNING: Removing unreachable block (ram,0x004019c1)
// WARNING: Removing unreachable block (ram,0x00401959)
// WARNING: Removing unreachable block (ram,0x0040197a)
// WARNING: Removing unreachable block (ram,0x004017be)
// WARNING: Removing unreachable block (ram,0x004017a1)
// WARNING: Removing unreachable block (ram,0x004017a3)
// WARNING: Removing unreachable block (ram,0x004017ce)
// WARNING: Removing unreachable block (ram,0x0040174d)
// WARNING: Removing unreachable block (ram,0x00401763)
// WARNING: Removing unreachable block (ram,0x004016c9)
// WARNING: Removing unreachable block (ram,0x0040162f)
// WARNING: Removing unreachable block (ram,0x0040164c)
// WARNING: Removing unreachable block (ram,0x00401652)
// WARNING: Removing unreachable block (ram,0x00401658)
// WARNING: Removing unreachable block (ram,0x0040165f)
// WARNING: Removing unreachable block (ram,0x00401667)
// WARNING: Removing unreachable block (ram,0x00401607)
// WARNING: Removing unreachable block (ram,0x00401671)
// WARNING: Removing unreachable block (ram,0x00401674)
// WARNING: Removing unreachable block (ram,0x00401684)
// WARNING: Removing unreachable block (ram,0x00401686)
// WARNING: Removing unreachable block (ram,0x0040164a)
// WARNING: Removing unreachable block (ram,0x00401615)
// WARNING: Removing unreachable block (ram,0x0040164d)
// WARNING: Removing unreachable block (ram,0x00401621)
// WARNING: Removing unreachable block (ram,0x00401659)
// WARNING: Removing unreachable block (ram,0x00401665)
// WARNING: Removing unreachable block (ram,0x004016d0)
// WARNING: Removing unreachable block (ram,0x004016d2)
// WARNING: Removing unreachable block (ram,0x004016e2)
// WARNING: Removing unreachable block (ram,0x004016e9)
// WARNING: Removing unreachable block (ram,0x004016d9)
// WARNING: Removing unreachable block (ram,0x004016fc)
// WARNING: Removing unreachable block (ram,0x00401707)
// WARNING: Removing unreachable block (ram,0x00401717)
// WARNING: Removing unreachable block (ram,0x004014ff)
// WARNING: Removing unreachable block (ram,0x00401505)
// WARNING: Removing unreachable block (ram,0x00401506)
// WARNING: Removing unreachable block (ram,0x0040149e)
// WARNING: Removing unreachable block (ram,0x00401469)
// WARNING: Removing unreachable block (ram,0x004014a1)
// WARNING: Removing unreachable block (ram,0x004014a8)
// WARNING: Removing unreachable block (ram,0x004014b6)
// WARNING: Removing unreachable block (ram,0x004014c4)
// WARNING: Removing unreachable block (ram,0x004014d3)
// WARNING: Removing unreachable block (ram,0x00401376)
// WARNING: Removing unreachable block (ram,0x00401309)
// WARNING: Removing unreachable block (ram,0x004012f1)
// WARNING: Removing unreachable block (ram,0x00401369)

uint __fastcall
FUN_00401219(int param_1,undefined (*param_2) [16],uint *param_3,uint *param_4,undefined *param_5,
            int param_6,uint *param_7,uint **param_8,int param_9)

{
  uint *puVar1;
  uint uVar2;
  undefined4 uVar3;
  code *pcVar4;
  byte bVar5;
  byte bVar6;
  undefined uVar7;
  byte *pbVar8;
  byte *pbVar9;
  uint in_EAX;
  undefined4 *puVar10;
  int extraout_ECX;
  int iVar11;
  uint unaff_EBX;
  byte *unaff_EBP;
  undefined4 *unaff_ESI;
  byte *unaff_EDI;
  int in_GS_OFFSET;
  byte bVar12;
  bool bVar13;
  bool bVar14;
  byte in_AF;
  unkbyte10 in_ST7;
  undefined in_XMM5 [16];
  undefined8 uVar15;
  int iStack_24;
  undefined uStack_20;
  undefined uStack_14;
  
  do {
    bVar6 = (byte)in_EAX;
    bVar12 = 0x35 < bVar6;
    unaff_EDI[0x2a5233e5] = (byte)param_2;
    pbVar9 = unaff_EDI + 0x78;
    uVar15 = CONCAT44(param_2,pbVar9);
    if (-1 < (char)(bVar6 - 0x36)) {
      bVar6 = 9 < ((byte)pbVar9 & 0xf) | in_AF;
      bVar5 = (byte)pbVar9 + bVar6 * -6;
      bVar5 = bVar5 + (0x9f < bVar5 | bVar12 | bVar6 * (bVar5 < 6)) * -0x60;
      param_2 = (undefined (*) [16])CONCAT31((int3)((uint)param_2 >> 8),0xc);
      bVar13 = 0xf5 < bVar5;
      puVar10 = (undefined4 *)CONCAT31((int3)((uint)pbVar9 >> 8),bVar5 + 10);
      iVar11 = param_1 + -1;
      if (iVar11 != 0) {
        pbVar9 = unaff_EBP;
        if (iVar11 == 0) {
          *(uint *)*param_2 = *(uint *)*param_2 | unaff_EBX;
          iVar11 = -1;
          out(*unaff_ESI,(short)param_2);
        }
        else {
code_r0x004012a4:
          *(char *)((int)puVar10 + in_GS_OFFSET + (int)pbVar9 * 2 + 0x3fb47c8d) =
               *(char *)((int)puVar10 + in_GS_OFFSET + (int)pbVar9 * 2 + 0x3fb47c8d) + (char)param_2
               + bVar13;
          iVar11 = CONCAT31((int3)((uint)iVar11 >> 8),(char)iVar11 + pbVar9[-0x71fd1dbb]);
          if (iVar11 == 1) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          iVar11 = iVar11 + -2;
          if (iVar11 != 0) {
            return;
          }
        }
        if (iVar11 == 1) {
          bVar6 = in((short)param_2);
          if (0x13 < bVar6) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          do {
            uVar7 = uStack_14;
            out(0x59,uVar7);
            uStack_14 = uStack_20;
            uStack_20 = uVar7;
          } while ((int)*(undefined6 *)(iStack_24 + -0x239db517) != 1);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    pcVar4 = (code *)swi(4);
    if (SCARRY1(bVar6,-0x36) == true) {
      uVar15 = (*pcVar4)();
      param_1 = extraout_ECX;
    }
    param_2 = (undefined (*) [16])((ulonglong)uVar15 >> 0x20);
    bVar6 = 9 < ((byte)uVar15 & 0xf) | in_AF;
    bVar5 = (byte)uVar15 + bVar6 * -6;
    bVar12 = 0x9f < bVar5 | bVar12 | bVar6 * (bVar5 < 6);
    pbVar8 = (byte *)CONCAT31((int3)((ulonglong)uVar15 >> 8),bVar5 + bVar12 * -0x60);
    iVar11 = param_1 + -1;
    pbVar9 = pbVar8;
    if (iVar11 == 0) {
      while( true ) {
        pbVar8 = unaff_EDI;
        bVar12 = pbVar8[0x2f8d68e3];
        param_2 = (undefined (*) [16])CONCAT31((int3)((uint)param_2 >> 8),bVar12);
        puVar1 = (uint *)(pbVar9 + 0x2a52032c);
        *puVar1 = *puVar1 | (uint)pbVar9;
        uVar2 = *puVar1;
        unaff_EDI = unaff_EBP + -0x13;
        uVar3 = in((short)param_2);
        *(undefined4 *)(unaff_EBP + -0x17) = uVar3;
        if (uVar2 == 0) break;
        unaff_EBX = CONCAT22((short)(unaff_EBX >> 0x10),
                             CONCAT11((char)(unaff_EBX >> 8) << 1,(char)unaff_EBX));
        in_XMM5 = rsqrtps(in_XMM5,*param_2);
        iVar11 = iVar11 + -1;
        pbVar9 = pbVar8;
        if (iVar11 == 0) {
          *(undefined4 *)((int)unaff_ESI + 0x6d3d7cc3) = 0x59faeb0e;
          puVar10 = unaff_ESI + 0x1b4f5f31;
          pbVar9 = unaff_EBP + -0xe;
          ffree(in_ST7);
          unaff_ESI[0x1b4f5f27] = unaff_ESI[0x1b4f5f27] & (uint)pbVar9;
          pbVar8 = unaff_EBP + 0x6568e355;
          bVar14 = (*pbVar8 & 1) != 0;
          *pbVar8 = *pbVar8 >> 1 | (*(byte *)((int)unaff_ESI + 1) < *pbVar9) << 7;
          pbVar8 = (byte *)((int)unaff_ESI + (int)pbVar9 * 2 + -0x530e06af);
          bVar13 = CARRY1(*pbVar8,bVar12) || CARRY1(*pbVar8 + bVar12,bVar14);
          *pbVar8 = *pbVar8 + bVar12 + bVar14;
          iVar11 = 0;
          goto code_r0x004012a4;
        }
      }
      iVar11 = (int)((longlong)*(int *)(unaff_EBP + 0x5a83e22f) * -0x7297bcb5);
      bVar12 = (longlong)iVar11 != (longlong)*(int *)(unaff_EBP + 0x5a83e22f) * -0x7297bcb5;
    }
    in_AF = 9 < ((byte)pbVar8 & 0xf) | bVar6;
    bVar6 = (byte)pbVar8 + in_AF * -6;
    in_EAX = CONCAT31((int3)((uint)pbVar8 >> 8),
                      bVar6 + (0x9f < bVar6 | bVar12 | in_AF * (bVar6 < 6)) * -0x60);
    param_1 = iVar11 + -1;
    if (param_1 != 0) {
      return in_EAX;
    }
  } while( true );
}



void __fastcall
entry(int param_1,undefined (*param_2) [16],uint *param_3,uint *param_4,undefined *param_5,
     int param_6,uint *param_7,uint **param_8,int param_9)

{
  int iVar1;
  uint *puVar2;
  
  iVar1 = 0x1f85;
  puVar2 = &DAT_00401000;
  do {
    *puVar2 = *puVar2 ^ 0x68e22f8d;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0xcf4;
  puVar2 = &DAT_0042b000;
  do {
    *puVar2 = *puVar2 ^ 0x51fe78f3;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  FUN_00401219(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  return;
}


